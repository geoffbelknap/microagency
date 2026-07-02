package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// TestAcquireInteractive runs the whole operator-in-the-loop flow against our own
// AS, with a fake "browser" that approves the consent and follows the redirect to
// the loopback callback — exactly what a real browser does.
func TestAcquireInteractive(t *testing.T) {
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	issuer := "http://" + ts.Listener.Addr().String()
	mux := http.NewServeMux()
	NewAuthServer(signer, issuer, "microagency", time.Hour).Register(mux)
	mux.Handle("/.well-known/oauth-protected-resource", ProtectedResourceMetadata("microagency", issuer))
	ts.Config.Handler = mux
	ts.Start()
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// The "browser": approve the consent, then follow the 302 to the loopback
	// callback (which microagency's listener is waiting on).
	browser := func(authURL string) error {
		u, _ := url.Parse(authURL)
		form := u.Query()
		form.Set("approve", "yes")
		r, err := noRedirect.PostForm(u.Scheme+"://"+u.Host+u.Path, form)
		if err != nil {
			return err
		}
		resp, err := http.Get(r.Header.Get("Location")) // the loopback callback
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := AcquireInteractive(ctx, noRedirect, issuer+"/.well-known/oauth-protected-resource", "microagency", "mcp", browser)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", tok)
	}
	rs := &ResourceServer{Issuer: issuer, Audience: "microagency", Keys: signer.KeySet()}
	if _, err := rs.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("acquired token invalid: %v", err)
	}
}

// TestAcquireInteractiveDenied: if the operator denies, AcquireInteractive errors
// rather than hanging.
func TestAcquireInteractiveDenied(t *testing.T) {
	signer, _ := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	ts := httptest.NewUnstartedServer(nil)
	issuer := "http://" + ts.Listener.Addr().String()
	mux := http.NewServeMux()
	NewAuthServer(signer, issuer, "microagency", time.Hour).Register(mux)
	mux.Handle("/.well-known/oauth-protected-resource", ProtectedResourceMetadata("microagency", issuer))
	ts.Config.Handler = mux
	ts.Start()
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deny := func(authURL string) error {
		u, _ := url.Parse(authURL)
		form := u.Query()
		form.Set("approve", "no")
		r, err := noRedirect.PostForm(u.Scheme+"://"+u.Host+u.Path, form)
		if err != nil {
			return err
		}
		resp, err := http.Get(r.Header.Get("Location"))
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := AcquireInteractive(ctx, noRedirect, issuer+"/.well-known/oauth-protected-resource", "microagency", "mcp", deny); err == nil {
		t.Fatal("expected an error when the operator denies consent")
	}
}
