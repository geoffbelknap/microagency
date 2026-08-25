package landing

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"microagency/internal/authui"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func page(t *testing.T) string {
	t.Helper()
	rec := get(t, Handler(Config{PortalPath: "/account", ResourceMetadata: "/.well-known/oauth-protected-resource"}), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

var (
	headBlock  = regexp.MustCompile(`(?is)<head\b[^>]*>.*?</head>`)
	styleBlock = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
	scriptTags = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	anyTag     = regexp.MustCompile(`(?s)<[^>]*>`)
	spaces     = regexp.MustCompile(`\s+`)
)

// visibleText is what a person actually reads in the window: no head, no
// stylesheet, no script, no tags. The two disclosures this page was built to
// stop were both found by reading rendered prose rather than by grepping for
// identifiers, so the test that guards it reads the prose too. The <title> is
// checked separately, because it is read in a tab strip and not in the page.
func visibleText(html string) string {
	s := headBlock.ReplaceAllString(html, " ")
	s = scriptTags.ReplaceAllString(s, " ")
	s = anyTag.ReplaceAllString(s, " ")
	return strings.TrimSpace(spaces.ReplaceAllString(s, " "))
}

// prose is everything served except the stylesheet: markup, copy, and script
// with its comments. CSS property names are not prose, and `grid-template-
// columns` is not this gateway announcing that it has connection templates.
func prose(html string) string { return styleBlock.ReplaceAllString(html, " ") }

// THE requirement: the one page served without authentication says nothing.
// Its entire readable content is the label on its one control.
func TestVisibleTextIsOnlyTheControl(t *testing.T) {
	if got := visibleText(page(t)); got != "Sign in Sign in" {
		t.Errorf("anonymous page reads %q; it must read only its sign-in control\n"+
			"(the heading is the same word, in the accessibility tree only)", got)
	}
}

// Everything in this document is published to whoever asks for it — markup,
// copy, and script alike, comments included. None of it may name the product or
// describe what runs here. The list is the vocabulary that actually leaked: the
// product name, what it holds, what it can do, and who it answers to.
//
// Whole words only, so the Fetch API's own `credentials: "omit"` and the OAuth
// parameter names this flow must send are not mistaken for prose.
func TestNamesNothingAndDescribesNothing(t *testing.T) {
	body := prose(page(t))
	for _, forbidden := range []string{
		// identity
		"microagency", "MCP gateway",
		// what it holds and what it does with it
		"credential", "audit", "records every call", "holds the keys",
		// the capability surface
		"find_tools", "call_tool", "connections", "provider", "template",
		"reauthorize", "disconnect", "quota", "read_only", "max_per_user", "tool",
		// planes that are not this one
		"/admin", "/console", "operator", "agent",
		// deployment specifics
		"version", "tunnel", "upstream",
	} {
		re := regexp.MustCompile(`(?i)` + `\b` + regexp.QuoteMeta(forbidden) + `\b`)
		if m := re.FindString(body); m != "" {
			t.Errorf("anonymous page carries %q — it must disclose nothing about this deployment", m)
		}
	}
}

// The tab title is served with the document and reads in a browser's tab list
// and history. It named the product; it must not.
func TestTitleNamesNothing(t *testing.T) {
	title := regexp.MustCompile(`(?i)<title>(.*?)</title>`).FindStringSubmatch(page(t))
	if title == nil {
		t.Fatal("page has no <title>")
	}
	if got := title[1]; got != "Sign in" {
		t.Errorf("<title> = %q, want %q", got, "Sign in")
	}
}

// It is still a sign-in page: one real, focusable, keyboard-operable control.
// A div with a click handler would satisfy every test above and none of the
// people who reach this page without a mouse.
func TestOffersARealSignInControl(t *testing.T) {
	body := page(t)
	if !strings.Contains(body, `<button class="btn primary" id="signin" type="button">Sign in</button>`) {
		t.Error("page does not offer a native button as its sign-in control")
	}
	if !strings.Contains(body, `<h1 class="vh">Sign in</h1>`) {
		t.Error("page has no heading in the accessibility tree")
	}
	if !strings.Contains(body, `aria-live="polite"`) {
		t.Error("the notice slot does not announce itself to a screen reader")
	}
	if !strings.Contains(body, ":focus-visible") {
		t.Error("the control has no visible focus indicator")
	}
}

// Sign-in MOVED here. This is the assertion that the circularity is gone: the
// flow that used to force the account page to be served anonymously now runs on
// the page that is anonymous by design.
func TestRunsTheSignInFlow(t *testing.T) {
	body := page(t)
	for _, want := range []string{
		"/.well-known/oauth-protected-resource", // where discovery starts
		"code_challenge_method",                 // PKCE, not an implicit or hybrid flow
		"S256",                                  // and the only method this gateway accepts
		"authorization_code",                    // exchanged in the browser for an access token
		"registration_endpoint",                 // the client this page obtains for itself
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-in page missing %q", want)
		}
	}
}

// The token this page obtains is read by the account application, so both
// documents are handed the same key by the server rather than each spelling a
// string that can drift.
func TestSharesTheStorageKeyWithTheAccountPage(t *testing.T) {
	body := page(t)
	if !strings.Contains(body, authui.TokenKey) {
		t.Errorf("sign-in page does not carry the shared token key %q", authui.TokenKey)
	}
	if !strings.Contains(body, authui.NoticeKey) {
		t.Errorf("sign-in page does not read the shared notice key %q", authui.NoticeKey)
	}
	// A key naming the product would identify the deployment from the page
	// source as surely as a heading would.
	for _, k := range []string{authui.TokenKey, authui.NoticeKey, authui.PKCEKey, authui.ClientKey} {
		if strings.Contains(strings.ToLower(k), "microagency") {
			t.Errorf("storage key %q names the product", k)
		}
	}
}

// The token never becomes a cookie, and no long-lived credential is kept.
func TestKeepsNoCookieOrRefreshToken(t *testing.T) {
	rec := get(t, Handler(Config{PortalPath: "/account"}), "/")
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("sign-in set a cookie; it must hold no server-side session")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "sessionStorage") {
		t.Error("sign-in does not keep its access token in sessionStorage")
	}
	if strings.Contains(body, "refresh_token") {
		t.Error("a refresh token is kept in the browser")
	}
	if strings.Contains(body, "document.cookie") {
		t.Error("sign-in touches document.cookie")
	}
}

// A deployment that runs no sign-in of its own has no page to serve. A card
// with no control on it is not an improvement, and it would be one more
// document published to anyone who asks.
func TestNoPageWithoutASignIn(t *testing.T) {
	if rec := get(t, Handler(Config{}), "/"); rec.Code != http.StatusNotFound {
		t.Errorf("GET / with no portal = %d, want 404", rec.Code)
	}
}

// It is mounted on the catch-all pattern, so every unmatched path falls through
// to it. Only the root may answer.
func TestOtherPathsStillNotFound(t *testing.T) {
	h := Handler(Config{PortalPath: "/account"})
	for _, path := range []string{"/nope", "/admin", "/.well-known/nothing", "/index.html"} {
		if rec := get(t, h, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestRejectsNonReadMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		Handler(Config{PortalPath: "/account"}).ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / = %d, want 405", method, rec.Code)
		}
	}
}

// Self-contained, like every other page this gateway serves: no CDN, no remote
// stylesheet, no external font.
func TestNoExternalAssets(t *testing.T) {
	if m := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`).FindString(page(t)); m != "" {
		t.Errorf("sign-in page loads an external asset (%q)", m)
	}
}

// The shared design system comes from authui, so this page stays coherent with
// the screens on the other side of sign-in without carrying their words.
func TestUsesSharedShell(t *testing.T) {
	body := page(t)
	for _, want := range []string{"<!doctype html>", "--teal-tint", "--ink-hairline"} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-in page missing shared shell marker %q", want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := get(t, Handler(Config{PortalPath: "/account"}), "/")
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

// The metadata URL is operator-influenced and lands inside a script element.
func TestConfigIsInertJSON(t *testing.T) {
	body := get(t, Handler(Config{
		PortalPath:       "/account",
		ResourceMetadata: `</script><img src=x onerror=alert(1)>`,
	}), "/").Body.String()
	if strings.Contains(body, "</script><img") {
		t.Fatal("config injected raw markup into the page")
	}
	if !strings.Contains(body, `\u003c/script\u003e`) {
		t.Error("config was not escaped for a script context")
	}
}
