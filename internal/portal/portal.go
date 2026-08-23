// Package portal serves microagency's account portal: the page a signed-in user
// of a shared gateway uses to connect a provider to their own account, see the
// connections they own, and disconnect them.
//
// It is deliberately a *client* of the public HTTP surface, not a second way in.
// The page signs in with the gateway's own OAuth authorization server the same
// way an MCP client does — dynamic client registration, PKCE, an access token
// held in the browser tab — and then calls the principal-authenticated
// /connections API with that token. There is no server-side session, no cookie,
// and no route here that changes state; every mutation is an authenticated
// request the user's own token authorizes and the existing API gates.
//
// Like the operator console this is a self-contained web asset with no
// framework, no CDN, and no build step, which is why it lives in its own package
// rather than in the gateway core. Unlike the console it carries no operator
// authority whatsoever: it never touches /admin, and a user's token cannot.
package portal

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"

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
	// The page reads the resource identifier and the authorization server from
	// it, exactly as an MCP client does.
	ResourceMetadata string `json:"resource_metadata"`
	// Version is the gateway build serving this page.
	Version string `json:"version"`
}

// Handler serves the account portal at Path. It answers GET only, returns the
// same static document to every caller, and reads nothing from the request:
// the page is unauthenticated markup, and the token that authorizes any actual
// data is obtained by the browser and never seen here.
func Handler(cfg Config) http.Handler {
	page := render(cfg)
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// The page holds an access token in the tab. Deny it a framing context
		// and a referrer so neither the token nor the gateway origin leaks.
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(page))
	})
}

func render(cfg Config) string {
	return authui.Shell("microagency — account",
		`<style>`+portalCSS+`</style>`+configScript(cfg), portalBody)
}

// configScript emits the config as an inert JSON island the page parses. A value
// containing "</script" would otherwise end the element early, so every
// HTML-significant character is escaped to its \u form. encoding/json already
// does that for <, >, & and for the line and paragraph separators; the replacer
// states the requirement here so it survives a switch to another encoder.
func configScript(cfg Config) string {
	b, err := json.Marshal(cfg)
	if err != nil {
		b = []byte(`{}`)
	}
	return `<script type="application/json" id="portal-config">` +
		jsonInScript.Replace(string(b)) + `</script>`
}

var jsonInScript = strings.NewReplacer(
	"<", `\u003c`, ">", `\u003e`, "&", `\u0026`,
	"\u2028", `\u2028`, "\u2029", `\u2029`,
)
