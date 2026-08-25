package portal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const goodToken = "Bearer valid-principal-token"

// accepts is the gateway's own principal check, stubbed. The real one is the
// same function the /connections routes use, so the page and the API it drives
// cannot disagree about who is signed in.
func accepts(r *http.Request) error {
	if r.Header.Get("Authorization") == goodToken {
		return nil
	}
	return errors.New("unauthenticated")
}

func handler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	h, err := Handler(cfg, accepts)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return h
}

func do(t *testing.T, h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// signedIn returns the page as an authenticated caller receives it.
func signedIn(t *testing.T) string {
	t.Helper()
	rec := do(t, handler(t, Config{ResourceMetadata: "/.well-known/oauth-protected-resource"}), http.MethodGet, Path, goodToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated GET %s = %d, want 200", Path, rec.Code)
	}
	return rec.Body.String()
}

// ---------------------------------------------------------------------------
// The gate. This whole document used to be served to anyone who asked for the
// route, which published a written description of what this gateway holds, who
// can see it, and what is recorded. It is now released only to a principal.
// ---------------------------------------------------------------------------

// A browser arriving with no credential is not shown a 401, which is a dead end
// in a window. It is sent to the one page that can sign it in.
func TestAnonymousBrowserIsSentToSignIn(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := do(t, handler(t, Config{}), method, Path, "")
		if rec.Code != http.StatusSeeOther {
			t.Errorf("anonymous %s %s = %d, want 303", method, Path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/" {
			t.Errorf("anonymous %s %s redirected to %q, want %q", method, Path, got, "/")
		}
		if body := rec.Body.String(); body != "" {
			t.Errorf("anonymous %s %s returned a body (%d bytes); it must return nothing", method, Path, len(body))
		}
	}
}

// A caller whose token was refused gets the protocol answer every other guarded
// route on this gateway gives, so the sign-in page can tell "my session ended"
// from "I was never signed in" and say the right thing.
func TestRefusedTokenGetsTheProtocolAnswer(t *testing.T) {
	rec := do(t, handler(t, Config{ResourceMetadata: "/.well-known/oauth-protected-resource"}),
		http.MethodGet, Path, "Bearer expired")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("refused token = %d, want 401", rec.Code)
	}
	want := `Bearer resource_metadata="/.well-known/oauth-protected-resource"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// The refusals must return nothing of the application: not the markup, not the
// posture copy, not the vocabulary of what a user can do here. This is the
// assertion the change exists for, and it reads the prose rather than trusting
// the status code.
func TestRefusalsDiscloseNothing(t *testing.T) {
	h := handler(t, Config{})
	for _, auth := range []string{"", "Bearer expired", "Bearer ", "Basic Zm9vOmJhcg=="} {
		body := do(t, h, http.MethodGet, Path, auth).Body.String()
		for _, forbidden := range []string{
			"microagency",
			"The credential stays in the gateway",
			"The connection is private to you",
			"The operator chose what is connectable",
			"Every call is recorded",
			"Connect a provider to your own account",
			"Loading your account",
			"Sign out",
			"Your connections",
			"Available providers",
			"/connections", "reauthorize", "disconnect", "quota",
			"max_per_user", "read_only", "find_tools", "call_tool",
		} {
			if strings.Contains(body, forbidden) {
				t.Errorf("refusal for Authorization %q leaked %q", auth, forbidden)
			}
		}
	}
}

// The prose is not deleted, it is moved behind the gate. Someone about to hand
// over a provider grant should read exactly this before they do.
func TestSignedInPageStillStatesThePosture(t *testing.T) {
	body := signedIn(t)
	for _, want := range []string{
		"The credential stays in the gateway",
		"Your provider grant is stored by",
		"The connection is private to you",
		"The operator chose what is connectable",
		"Every call is recorded",
		"written to the gateway's audit log",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("signed-in page no longer states %q; the posture belongs to the person granting access", want)
		}
	}
}

// A nil authenticator is a wiring mistake, and the thing it would fail open on
// is the whole point of the route.
func TestRefusesToBeServedUnauthenticated(t *testing.T) {
	if _, err := Handler(Config{}, nil); err == nil {
		t.Fatal("Handler accepted a nil authenticator; it must refuse to serve the page unguarded")
	}
}

// ---------------------------------------------------------------------------
// The page itself, as a signed-in caller receives it.
// ---------------------------------------------------------------------------

func TestServesPage(t *testing.T) {
	rec := do(t, handler(t, Config{ResourceMetadata: "/.well-known/oauth-protected-resource"}), http.MethodGet, Path, goodToken)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	// Assert the portal↔API contract: the routes it drives. Internal JS
	// identifiers are free to change with a redesign.
	for _, want := range []string{
		"/connections/templates",                // the template list the portal renders
		"/connections/",                         // refresh, reauthorize, disconnect
		"/.well-known/oauth-protected-resource", // where sign-out finds the revocation endpoint
	} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page missing %q", want)
		}
	}
}

// Sign-in moved to the root. This page must not carry a second copy of the
// flow: two implementations of it is how the account route ends up needing to
// be served anonymously again.
func TestPortalNoLongerSignsAnyoneIn(t *testing.T) {
	body := signedIn(t)
	for _, gone := range []string{
		"code_challenge", "registration_endpoint", "grant_type",
		"client_name", "authorization_endpoint",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("portal page still runs the sign-in flow (%q); it belongs on the anonymous page", gone)
		}
	}
	if strings.Contains(body, `id="signedout"`) {
		t.Error("portal page still carries a signed-out state; it is not served to anyone signed out")
	}
}

// The portal carries no operator authority. A user's token cannot reach /admin,
// and the page must not imply otherwise by referring to that plane at all.
func TestPortalNeverReferencesOperatorPlane(t *testing.T) {
	body := signedIn(t)
	for _, forbidden := range []string{"/admin", "/console"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("portal page references the operator plane %q — the account surface must not route there", forbidden)
		}
	}
}

// The page must be self-contained: no CDN, no external stylesheet or script, no
// remote font. Everything it needs is embedded, like the operator console.
func TestPortalHasNoExternalAssets(t *testing.T) {
	if m := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`).FindString(signedIn(t)); m != "" {
		t.Errorf("portal page loads an external asset (%q); it must be self-contained", m)
	}
}

// The token lives in the tab, never in a cookie, and no long-lived refresh token
// is kept in the browser.
func TestPortalKeepsNoServerSessionOrRefreshToken(t *testing.T) {
	rec := do(t, handler(t, Config{}), http.MethodGet, Path, goodToken)
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("portal set a cookie; it must hold no server-side session")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "sessionStorage") {
		t.Error("portal does not read its access token from sessionStorage")
	}
	if strings.Contains(body, "refresh_token") {
		t.Error("portal handles a refresh token; a long-lived credential must not be kept in the browser")
	}
	if strings.Contains(body, "document.cookie") {
		t.Error("portal touches document.cookie")
	}
}

// The shared design system comes from authui, so the portal, the consent screen,
// and the sign-in page cannot drift into three different-looking pages.
func TestPortalUsesSharedShell(t *testing.T) {
	body := signedIn(t)
	for _, want := range []string{"--teal-tint", "--ink-hairline", "<!doctype html>", "microagency — account"} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page missing shared shell marker %q", want)
		}
	}
}

// A destructive action must name its consequence and what survives it, not just
// the object it acts on.
func TestDisconnectPromptNamesConsequence(t *testing.T) {
	body := signedIn(t)
	for _, want := range []string{
		"deletes the connection and the credential",
		"is deleted, and the record of your authorization stays",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("disconnect prompt missing %q", want)
		}
	}
}

func TestConfigIsInertJSON(t *testing.T) {
	// An operator-supplied metadata URL must not be able to close the script
	// element or inject markup into the page.
	body := do(t, handler(t, Config{ResourceMetadata: `</script><img src=x onerror=alert(1)>`}),
		http.MethodGet, Path, goodToken).Body.String()
	if strings.Contains(body, "</script><img") {
		t.Fatalf("config injected raw markup into the page:\n%s", body)
	}
	if !strings.Contains(body, `\u003c/script\u003e`) {
		t.Errorf("config was not escaped for a script context:\n%s", body)
	}
}

func TestNotFoundElsewhere(t *testing.T) {
	if rec := do(t, handler(t, Config{}), http.MethodGet, Path+"/nope", goodToken); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// The portal changes nothing by itself: every mutation is an authenticated API
// call the browser makes. The route answers reads only, and refuses a write
// before it looks at any credential.
func TestRejectsNonReadMethods(t *testing.T) {
	h := handler(t, Config{})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := do(t, h, method, Path, goodToken)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", method, Path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow == "" {
			t.Errorf("%s %s: no Allow header on the refusal", method, Path)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	// Set on every answer, including the two refusals, so a cached or framed
	// redirect cannot become a way to probe the route.
	for _, auth := range []string{"", "Bearer expired", goodToken} {
		rec := do(t, handler(t, Config{}), http.MethodGet, Path, auth)
		for header, want := range map[string]string{
			"X-Frame-Options": "DENY",
			"Referrer-Policy": "no-referrer",
			"Cache-Control":   "no-store",
		} {
			if got := rec.Header().Get(header); got != want {
				t.Errorf("Authorization %q: %s = %q, want %q", auth, header, got, want)
			}
		}
	}
}

// A refused connection must be reported where the person is looking. The page
// reads the gateway's failure envelope, so the field names it branches on are
// part of the portal↔API contract and belong here beside the routes.
func TestPortalReadsTheFailureEnvelope(t *testing.T) {
	body := signedIn(t)
	for _, want := range []string{
		"actor",     // who can act on the failure
		"retryable", // whether repeating it could work
		"operator",  // the branch that withholds an operator's remediation
	} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page does not read %q from a refusal; it cannot tell a user's problem from an operator's", want)
		}
	}
}

// The connect dialog must not close before its request resolves.
func TestConnectDialogReportsItsOwnFailure(t *testing.T) {
	body := signedIn(t)
	for _, want := range []string{"modal-notice", "Starting…"} {
		if !strings.Contains(body, want) {
			t.Errorf("connect dialog missing %q; a refused connection has nowhere to render", want)
		}
	}
}

// A remediation only an operator can perform must not be handed to a user as if
// it were theirs.
func TestOperatorOnlyFailureDoesNotReadAsRetryable(t *testing.T) {
	body := signedIn(t)
	for _, want := range []string{
		"This provider is not ready to connect",
		"your operator's to finish",
		"The attempt was recorded",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page missing operator-fault wording %q", want)
		}
	}
}
