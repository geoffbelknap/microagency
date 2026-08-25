package landing

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

// The root used to answer 404, which told someone who reached this gateway in a
// browser nothing at all.
func TestServesTheRoot(t *testing.T) {
	rec := get(t, Handler(Config{PortalPath: "/account"}), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"microagency", "/account", "Sign in"} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}
}

// A deployment with no account portal has no sign-in surface of its own, and a
// button pointing at a 404 is worse than no button.
func TestNoSignInWithoutAPortal(t *testing.T) {
	body := get(t, Handler(Config{}), "/").Body.String()
	if !strings.Contains(body, "microagency") {
		t.Error("landing page does not name the product")
	}
	if strings.Contains(body, "/account") || strings.Contains(body, "Sign in") {
		t.Error("landing page offers sign-in on a deployment that serves no portal")
	}
}

// The page is served before any sign-in, so everything on it is published to
// whoever reaches the gateway. Nothing on it may describe THIS deployment.
func TestCarriesNothingAboutThisDeployment(t *testing.T) {
	body := get(t, Handler(Config{PortalPath: "/account"}), "/").Body.String()
	for _, forbidden := range []string{
		"version", "issuer", "tunnel", "audience", "upstream", "operator token",
		"/admin", "/console", "connections", "providers",
	} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("landing page leaks deployment detail %q before sign-in", forbidden)
		}
	}
}

// It is mounted on the catch-all pattern, so every unmatched path falls through
// to it. Only the root may answer.
func TestOtherPathsStillNotFound(t *testing.T) {
	for _, path := range []string{"/nope", "/admin", "/.well-known/nothing"} {
		if rec := get(t, Handler(Config{}), path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestRejectsNonReadMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		Handler(Config{}).ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / = %d, want 405", method, rec.Code)
		}
	}
}

// Self-contained, like every other page this gateway serves: no CDN, no remote
// stylesheet, no external font.
func TestNoExternalAssets(t *testing.T) {
	body := get(t, Handler(Config{PortalPath: "/account"}), "/").Body.String()
	if m := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`).FindString(body); m != "" {
		t.Errorf("landing page loads an external asset (%q)", m)
	}
}

// The shared design system comes from authui, so this page cannot drift into
// looking like a different product than the consent and account screens.
func TestUsesSharedShell(t *testing.T) {
	body := get(t, Handler(Config{}), "/").Body.String()
	for _, want := range []string{"<!doctype html>", "--teal-tint", "--ink-hairline"} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing shared shell marker %q", want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := get(t, Handler(Config{}), "/")
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
