package auth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
)

// AcquireInteractive runs the full operator-in-the-loop OAuth flow to obtain a
// token microagency will hold for an upstream: discover the AS, register (DCR),
// open the operator's browser to log in + consent, catch the loopback redirect,
// and exchange the code. It binds a loopback listener for the callback (so the
// redirect_uri is unguessable and local) and blocks until the operator approves,
// ctx is done, or the deadline fires. openBrowser is injected for testability;
// production passes OpenBrowser.
func AcquireInteractive(ctx context.Context, hc *http.Client, resourceMetadataURL, clientName, scope string, openBrowser func(url string) error) (*UpstreamToken, error) {
	meta, err := DiscoverAS(ctx, hc, resourceMetadataURL)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback callback: %w", err)
	}
	defer ln.Close()
	redirectURI := "http://" + ln.Addr().String() + "/callback"

	clientID, clientSecret, err := RegisterClient(ctx, hc, meta.RegistrationEndpoint, redirectURI, clientName)
	if err != nil {
		return nil, err
	}

	p := NewPKCE()
	state := randToken(16)

	type result struct {
		code string
		err  error
	}
	resCh := make(chan result, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("error") != "":
			resCh <- result{err: fmt.Errorf("authorization denied: %s", q.Get("error"))}
			io.WriteString(w, "microagency: authorization failed — you can close this tab.")
		case q.Get("state") != state:
			resCh <- result{err: fmt.Errorf("state mismatch on callback")}
			io.WriteString(w, "microagency: state mismatch — you can close this tab.")
		default:
			resCh <- result{code: q.Get("code")}
			io.WriteString(w, "microagency: connected. You can close this tab and return to your terminal.")
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	if err := openBrowser(AuthorizeURL(meta, clientID, redirectURI, p, scope, state)); err != nil {
		return nil, fmt.Errorf("open browser: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		if res.code == "" {
			return nil, fmt.Errorf("no authorization code in callback")
		}
		return ExchangeCode(ctx, hc, meta, clientID, clientSecret, redirectURI, res.code, p)
	}
}

// OpenBrowser opens target in the operator's default browser (non-blocking).
func OpenBrowser(target string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", target).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}
