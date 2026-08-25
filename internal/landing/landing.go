// Package landing serves the root of microagency's public listener: the one
// page this gateway hands to a caller that has not authenticated.
//
// It is a sign-in control and nothing else. It does not name the product, say
// what the software does, describe what it holds, or explain how to connect a
// client. A person who belongs here was sent here by their operator or by their
// client configuration and does not need to be told what this is; a person who
// does not belong learns nothing by asking.
//
// Sign-in lives here because it has to live somewhere unauthenticated, and
// everything that is unauthenticated is published. It used to live on the
// account page, which is why that page was served to anyone who asked: the page
// WAS the sign-in mechanism, so it could not require the token it produced.
// Moving the flow here breaks that circularity, and the account application can
// now be released only to a caller holding a token.
package landing

import (
	_ "embed"
	"net/http"

	"microagency/internal/authui"
)

//go:embed signin.js
var signInJS string

// Config is what the page needs from the process serving it.
//
// The page is published to whoever asks for it, so a field here is a field
// published to the unauthenticated internet. Both of these are addresses a
// client discovers anyway: one is this gateway's own RFC 9728 metadata URL,
// which discovery must expose for any client to find where to authenticate, and
// the other is a route on this origin. Neither describes the deployment.
type Config struct {
	// PortalPath is the account application's route, or empty when this
	// deployment serves no account application. A gateway using an external
	// issuer, a static bearer, or one that refuses client registration runs no
	// sign-in of its own, and there is then no page to serve at all.
	PortalPath string
	// ResourceMetadata is the RFC 9728 protected-resource metadata URL this
	// gateway advertises on a 401 — an absolute URL or an origin-relative path.
	// The page reads the resource identifier and the authorization server from
	// it, exactly as an MCP client does, so it cannot drift from the endpoints
	// the gateway actually advertises.
	ResourceMetadata string
}

// Handler serves the sign-in page at "/" and 404s everything else.
//
// It is mounted on the catch-all pattern, which every unmatched path falls
// through to, so it has to answer only for the root itself.
//
// A deployment with no sign-in of its own has no page to serve, and answers 404
// at the root as well. A card with no control on it is not an improvement on
// that, and it would be one more document published to anyone who asks.
func Handler(cfg Config) http.Handler {
	page := render(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || page == "" {
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
		// The page obtains an access token and holds it in the tab. Deny it a
		// framing context and a referrer so neither the token nor the code in
		// the redirect back here leaks to anyone.
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(page))
	})
}

// style extends the shared shell for a card whose whole content is one control.
//
// The primary button is restyled here rather than in the shell because this is
// the only control on the page and it has to be legible on its own: the shell's
// teal on white clears 3:1, which is enough for a button sitting beside a
// second one and not enough for text at this size. The darker teal in light
// mode and dark ink on teal in dark mode both clear 4.5:1.
const style = `<style>
.gate{padding:38px 28px 32px}
.gate .mark{margin:0 auto 22px}
.gate .btn.primary{flex:none;width:100%;padding:12px;font-size:15px;
 background:var(--teal-dark);border-color:var(--teal-dark);color:#fff}
.gate .btn.primary:hover:enabled{filter:brightness(1.08)}
.gate .btn.primary:disabled{opacity:.65;cursor:default}
.gate .btn.primary:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.gate .notice{font-size:13px;line-height:1.5;text-align:left;color:var(--ink);
 background:var(--amber-tint);border:.5px solid var(--amber);border-radius:8px;padding:10px 12px;margin:0 0 18px}
.vh{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;
 clip:rect(0 0 0 0);white-space:nowrap;border:0}
@media (prefers-color-scheme:dark){
 .gate .btn.primary{background:var(--teal);border-color:var(--teal);color:#0B1F1A}
}
</style>`

// render builds the page, or "" when this deployment has no sign-in to offer.
func render(cfg Config) string {
	if cfg.PortalPath == "" {
		return ""
	}
	cfgIsland := authui.JSONIsland("gate-config", struct {
		ResourceMetadata string             `json:"resource_metadata"`
		PortalPath       string             `json:"portal_path"`
		Keys             authui.SessionKeys `json:"keys"`
	}{cfg.ResourceMetadata, cfg.PortalPath, authui.SignInKeys()})

	// The mark carries no text. The heading is in the accessibility tree and
	// not on the screen: a visible heading over a button reading the same word
	// is noise, and a page with no heading at all is one a screen reader cannot
	// describe.
	body := `
<div class="card" id="gate">
 <div class="body center gate">
  <h1 class="vh">Sign in</h1>
  <span class="mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
  <div id="notice" role="status" aria-live="polite"></div>
  <button class="btn primary" id="signin" type="button">Sign in</button>
 </div>
</div>
<script>` + signInJS + `</script>`

	return authui.Shell("Sign in", style+cfgIsland, body)
}
