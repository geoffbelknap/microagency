// Package portal serves microagency's account portal: the page a signed-in user
// of a shared gateway uses to connect a provider to their own account, see the
// connections they own, and disconnect them.
//
// It is delivered only to a caller holding a valid principal token. That is the
// whole of its access control, and it is why the page may describe itself
// plainly: what the gateway does with a credential, who can see a connection,
// what the operator fixed, what is recorded. A person about to hand over a
// provider grant should read exactly that. Nobody who has not signed in does.
//
// It is deliberately a *client* of the public HTTP surface, not a second way
// in. The token was obtained by the sign-in page at the root, which runs the
// gateway's own OAuth flow the way an MCP client does; this page receives that
// token from the tab and calls the principal-authenticated /connections API
// with it. There is no server-side session, no cookie, and no route here that
// changes state; every mutation is an authenticated request the user's own
// token authorizes and the existing API gates.
//
// Like the operator console this is a self-contained web asset with no
// framework, no CDN, and no build step, which is why it lives in its own package
// rather than in the gateway core. Unlike the console it carries no operator
// authority whatsoever: it never touches /admin, and a user's token cannot.
package portal

import (
	_ "embed"
	"errors"
	"net/http"

	"microagency/internal/authui"
)

//go:embed portal.css
var portalCSS string

//go:embed portal.html
var portalBody string

// Path is the route the portal is served on.
const Path = "/account"

// Config is what the page needs from the process serving it. Everything else it
// discovers at runtime from the gateway's own OAuth metadata, so the portal
// cannot drift from the endpoints the gateway actually advertises.
type Config struct {
	// ResourceMetadata is the RFC 9728 protected-resource metadata URL this
	// gateway advertises on a 401 — an absolute URL or an origin-relative path.
	// The page reads the authorization server from it to revoke a token on sign
	// out, exactly as an MCP client does.
	ResourceMetadata string `json:"resource_metadata"`
}

// Authenticate reports whether a request carries a principal this gateway
// accepts. It is the same check the /connections routes make; the portal takes
// it as a function so this package stays a page and does not grow a second
// opinion about who is authenticated.
type Authenticate func(*http.Request) error

// Handler serves the account portal at Path to authenticated callers only.
//
// The application markup describes what this gateway does with a credential, so
// releasing it to an anonymous caller would publish that description to anyone
// who asked for the route. It is not a page with a signed-out state any more:
// signing in happens at the root, and reaching this route without a token
// returns nothing to render.
//
// A nil authenticate is a wiring mistake and is refused here rather than
// defaulting to serving the page, because the failure would be silent and the
// thing it fails open on is the whole point of the route.
func Handler(cfg Config, authenticate Authenticate) (http.Handler, error) {
	if authenticate == nil {
		return nil, errors.New("account portal needs an authenticator; it must not be served unauthenticated")
	}
	page := render(cfg)
	metadata := cfg.ResourceMetadata
	if metadata == "" {
		metadata = "/.well-known/oauth-protected-resource"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Two refusals, because two different callers arrive here without a
		// token and they need different answers.
		//
		// A caller offering no credential at all is a browser: someone typed
		// the address, followed a bookmark, or crawled it. A 401 is a dead end
		// in a browser window, so it is sent to the one page that can sign it
		// in. The redirect discloses nothing the root does not.
		//
		// A caller whose credential was refused is the sign-in page's own fetch
		// with an expired or revoked token. It gets the protocol answer every
		// other guarded route on this gateway gives, so it can tell "my session
		// ended" from "I was never signed in" and say so.
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		if err := authenticate(r); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+metadata+`"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(page))
	}), nil
}

func render(cfg Config) string {
	island := authui.JSONIsland("portal-config", struct {
		ResourceMetadata string             `json:"resource_metadata"`
		Keys             authui.SessionKeys `json:"keys"`
	}{cfg.ResourceMetadata, authui.SharedKeys()})
	return authui.Shell("microagency — account",
		`<style>`+portalCSS+`</style>`+island, portalBody)
}
