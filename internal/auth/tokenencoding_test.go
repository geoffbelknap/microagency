package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// RFC 6749 says a token response is JSON. Not every authorization server
// volunteers it: at least one major provider answers in form encoding unless
// the request asks for JSON, and historically this client did not ask — so a
// perfectly valid grant failed with an unparseable body.
func TestPostTokenAsksForJSONAndAcceptsFormEncoding(t *testing.T) {
	var sawAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAccept = r.Header.Get("Accept")
		// Answer in form encoding regardless, as a server that ignores Accept would.
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=gho_example&refresh_token=r1&expires_in=3600"))
	}))
	defer srv.Close()

	tok, err := postToken(context.Background(), srv.Client(), srv.URL, "cid", "secret", url.Values{})
	if err != nil {
		t.Fatalf("form-encoded token response refused: %v", err)
	}
	if !strings.Contains(sawAccept, "application/json") {
		t.Errorf("Accept = %q, want it to ask for application/json", sawAccept)
	}
	if tok.AccessToken != "gho_example" || tok.RefreshToken != "r1" {
		t.Errorf("token = %+v, want the form-encoded values", tok)
	}
	if tok.Expiry.IsZero() {
		t.Error("expires_in from a form-encoded response was dropped")
	}
}

func TestPostTokenStillReadsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a1","refresh_token":"r1","expires_in":600}`))
	}))
	defer srv.Close()
	tok, err := postToken(context.Background(), srv.Client(), srv.URL, "cid", "", url.Values{})
	if err != nil || tok.AccessToken != "a1" {
		t.Fatalf("token = %+v, err = %v; want the JSON values", tok, err)
	}
}

// A refusal can arrive with a 200 and the error in the body. Reporting "no
// access_token" hides what the server actually said, which is the one thing
// that tells an operator what to fix.
func TestPostTokenReportsAnErrorReturnedWithStatus200(t *testing.T) {
	for _, tc := range []struct{ name, ctype, body string }{
		{"form encoded", "application/x-www-form-urlencoded", "error=bad_verification_code&error_description=The+code+expired."},
		{"json", "application/json", `{"error":"bad_verification_code","error_description":"The code expired."}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := postToken(context.Background(), srv.Client(), srv.URL, "cid", "", url.Values{})
			if err == nil {
				t.Fatal("a 200 carrying an OAuth error was accepted")
			}
			if !strings.Contains(err.Error(), "bad_verification_code") || !strings.Contains(err.Error(), "The code expired.") {
				t.Errorf("error = %v; want the server's own error and description", err)
			}
		})
	}
}
