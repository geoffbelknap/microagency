// Package landing serves the root of microagency's public listener.
//
// That route used to answer 404. A gateway is a URL people paste into clients
// and, sooner or later, open in a browser — and a 404 tells them nothing: not
// what they reached, not whether it is working, not where to sign in. This page
// answers exactly those and stops.
//
// What it deliberately does not carry is anything about THIS deployment. No
// version, no connected providers, no user or connection counts, no operator
// identity, no tunnel or issuer URL. Everything here is true of every
// microagency gateway, so reaching it before signing in reveals only that a
// microagency gateway is listening — which the OAuth metadata a client must be
// able to discover already says.
package landing

import (
	"net/http"

	"microagency/internal/authui"
)

// Config is what the page needs from the process serving it.
type Config struct {
	// PortalPath is the account portal's route, or empty when this deployment
	// serves no portal. A gateway using an external issuer, a static bearer, or
	// one that refuses client registration has no sign-in surface of its own,
	// and a button pointing at a route that answers 404 is worse than no button.
	PortalPath string
}

// Handler serves the landing page at "/" and 404s everything else.
//
// It is mounted on the catch-all pattern, which every unmatched path falls
// through to, so it has to answer only for the root itself.
func Handler(cfg Config) http.Handler {
	page := render(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
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
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(page))
	})
}

// linkButton renders an anchor with the shared button shape. The shell styles
// buttons, not links, and this page's one action is a navigation.
const linkButton = `<style>
.actions a.btn{display:block;text-align:center;text-decoration:none;line-height:1.2}
</style>`

func render(cfg Config) string {
	body := `
<div class="card">
 <div class="head"><span class="mark"><i></i><i></i><i></i><i></i></span>` +
		`<div><div class="word">microagency</div><div class="sub">MCP gateway</div></div></div>
 <div class="body">
  <div class="title">This is a microagency gateway.</div>
  <p class="lead">It connects an agent to the tools you have authorized, holds the credentials
   itself, and records every call. Point an MCP client at this address to connect.</p>`
	if cfg.PortalPath != "" {
		body += `
  <div class="actions"><a class="btn primary" href="` + cfg.PortalPath + `">Sign in</a></div>
  <p class="note">sign in to connect a provider to your own account</p>`
	}
	body += `
 </div>
</div>`
	return authui.Shell("microagency", linkButton, body)
}
