package authui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The sign-in page writes the token and the account application reads it, so a
// name that drifts silently signs nobody in. Both take it from here.
func TestSharedKeysAreTheOnesBothPagesNeed(t *testing.T) {
	shared := SharedKeys()
	if shared.Token != TokenKey || shared.Notice != NoticeKey {
		t.Fatalf("SharedKeys() = %+v, want the token and notice constants", shared)
	}
	// The account application runs no authorization code exchange any more, so
	// it is handed none of the keys for one.
	if shared.PKCE != "" || shared.Attempt != "" || shared.Client != "" {
		t.Errorf("SharedKeys() carries sign-in state %+v; only the sign-in page runs that flow", shared)
	}
	signIn := SignInKeys()
	if signIn.PKCE != PKCEKey || signIn.Attempt != AttemptKey || signIn.Client != ClientKey {
		t.Errorf("SignInKeys() = %+v, want the exchange keys", signIn)
	}
}

// Every key is rendered into a page served before sign-in, so a key naming the
// product would identify the deployment from the page source.
func TestKeysNameNothing(t *testing.T) {
	for _, k := range []string{TokenKey, NoticeKey, PKCEKey, AttemptKey, ClientKey} {
		if strings.Contains(strings.ToLower(k), "microagency") {
			t.Errorf("storage key %q names the product", k)
		}
	}
}

// A value that could close the script element would let operator-supplied
// configuration inject markup into a page.
func TestJSONIslandIsInert(t *testing.T) {
	got := JSONIsland("cfg", map[string]string{"u": `</script><img src=x onerror=alert(1)>`})
	if strings.Contains(got, "</script><img") {
		t.Fatalf("island injected raw markup: %s", got)
	}
	if !strings.Contains(got, `\u003c/script\u003e`) {
		t.Errorf("island was not escaped for a script context: %s", got)
	}
	if !strings.HasPrefix(got, `<script type="application/json" id="cfg">`) {
		t.Errorf("island is not an inert JSON element: %s", got)
	}
}

// The one notice an unauthenticated caller can reach must identify nothing:
// reaching any other branch means holding a single-use state this gateway
// issued to someone who had already signed in.
func TestUnknownRequestIdentifiesNothing(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteUnknownRequest(rec, "This request is unknown or has expired. Start again.")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{
		"microagency", "gateway", "credential", "audit", "account portal",
		"authorization", "MCP", "provider", "class=\"word\"",
	} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Errorf("the unknown-request notice carries %q", forbidden)
		}
	}
	if !strings.Contains(body, "This request is unknown or has expired.") {
		t.Error("the notice does not carry the caller's sentence")
	}
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

// The message is caller-supplied and lands in markup.
func TestUnknownRequestEscapesItsMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteUnknownRequest(rec, `<img src=x onerror=alert(1)>`)
	if strings.Contains(rec.Body.String(), "<img src=x") {
		t.Fatal("the notice rendered its message as markup")
	}
}
