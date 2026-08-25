package portal

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServesPage(t *testing.T) {
	rec := get(t, Handler(Config{ResourceMetadata: "/.well-known/oauth-protected-resource", Version: "1.2.3"}), Path)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	// Assert the portal↔API contract: the routes it drives and the config it is
	// handed. Internal JS identifiers are free to change with a redesign.
	for _, want := range []string{
		"/connections/templates",                // the template list the portal renders
		"/connections/",                         // refresh, reauthorize, disconnect
		"code_challenge_method",                 // PKCE, not an implicit or hybrid flow
		"S256",                                  // and the only method this gateway accepts
		"authorization_code",                    // exchanged in the browser for an access token
		"/.well-known/oauth-protected-resource", // where discovery starts
		"1.2.3",                                 // the build serving the page
	} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page missing %q", want)
		}
	}
}

// The portal carries no operator authority. A user's token cannot reach /admin,
// and the page must not imply otherwise by referring to that plane at all.
func TestPortalNeverReferencesOperatorPlane(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
	for _, forbidden := range []string{"/admin", "/console"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("portal page references the operator plane %q — the account surface must not route there", forbidden)
		}
	}
}

// The page must be self-contained: no CDN, no external stylesheet or script, no
// remote font. Everything it needs is embedded, like the operator console.
func TestPortalHasNoExternalAssets(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
	if m := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`).FindString(body); m != "" {
		t.Errorf("portal page loads an external asset (%q); it must be self-contained", m)
	}
}

// The token lives in the tab, never in a cookie, and no long-lived refresh token
// is kept in the browser. These are the properties that make the portal safe to
// serve on the public listener beside /mcp.
func TestPortalKeepsNoServerSessionOrRefreshToken(t *testing.T) {
	rec := get(t, Handler(Config{}), Path)
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("portal set a cookie; it must hold no server-side session")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "sessionStorage") {
		t.Error("portal does not keep its access token in sessionStorage")
	}
	if strings.Contains(body, "refresh_token") {
		t.Error("portal handles a refresh token; a long-lived credential must not be kept in the browser")
	}
	if strings.Contains(body, "document.cookie") {
		t.Error("portal touches document.cookie")
	}
}

// The shared design system comes from authui, so the portal, the consent screen,
// and the connected screen cannot drift into three different-looking pages.
func TestPortalUsesSharedShell(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
	for _, want := range []string{"--teal-tint", "--ink-hairline", "<!doctype html>", "microagency — account"} {
		if !strings.Contains(body, want) {
			t.Errorf("portal page missing shared shell marker %q", want)
		}
	}
}

// A destructive action must name its consequence and what survives it, not just
// the object it acts on.
func TestDisconnectPromptNamesConsequence(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
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
	rec := get(t, Handler(Config{ResourceMetadata: `</script><img src=x onerror=alert(1)>`}), Path)
	body := rec.Body.String()
	if strings.Contains(body, "</script><img") {
		t.Fatalf("config injected raw markup into the page:\n%s", body)
	}
	if !strings.Contains(body, `\u003c/script\u003e`) {
		t.Errorf("config was not escaped for a script context:\n%s", body)
	}
}

func TestNotFoundElsewhere(t *testing.T) {
	if rec := get(t, Handler(Config{}), Path+"/nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// The portal changes nothing by itself: every mutation is an authenticated API
// call the browser makes. The route answers reads only.
func TestRejectsNonReadMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		Handler(Config{}).ServeHTTP(rec, httptest.NewRequest(method, Path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", method, Path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow == "" {
			t.Errorf("%s %s: no Allow header on the refusal", method, Path)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := get(t, Handler(Config{}), Path)
	for header, want := range map[string]string{
		"X-Frame-Options": "DENY",
		"Referrer-Policy": "no-referrer",
		"Cache-Control":   "no-store",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// A refused connection must be reported where the person is looking. The page
// reads the gateway's failure envelope, so the field names it branches on are
// part of the portal↔API contract and belong here beside the routes.
func TestPortalReadsTheFailureEnvelope(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
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

// The connect dialog must not close before its request resolves. Closing first
// and writing the outcome elsewhere on the page is indistinguishable from the
// button doing nothing, which is the failure this page is written to avoid.
func TestConnectDialogReportsItsOwnFailure(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
	for _, want := range []string{
		"modal-notice", // the dialog's own notice slot
		"Starting…",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("connect dialog missing %q; a refused connection has nowhere to render", want)
		}
	}
}

// A remediation only an operator can perform must not be handed to a user as if
// it were theirs. The page says the provider is not ready and that the attempt
// was recorded, rather than repeating the gateway's operator-facing sentence.
func TestOperatorOnlyFailureDoesNotReadAsRetryable(t *testing.T) {
	body := get(t, Handler(Config{}), Path).Body.String()
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
