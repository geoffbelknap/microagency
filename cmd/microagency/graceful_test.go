package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// The listeners must carry a ReadHeaderTimeout (slowloris defense on the public
// tunneled bind) and an IdleTimeout — but NOT Read/WriteTimeout, which would sever
// a legitimately slow reduce or upstream tool mid-response.
func TestNewHTTPServerTimeouts(t *testing.T) {
	s := newHTTPServer("127.0.0.1:0", http.NewServeMux())
	if s.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout must be set (slowloris defense)")
	}
	if s.IdleTimeout == 0 {
		t.Error("IdleTimeout must be set (reap idle keep-alives)")
	}
	if s.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay unset (slow reduces stream for minutes), got %v", s.WriteTimeout)
	}
	if s.ReadTimeout != 0 {
		t.Errorf("ReadTimeout must stay unset, got %v", s.ReadTimeout)
	}
}

// Graceful shutdown drains an in-flight request instead of dropping it — the
// behavior that replaced the old os.Exit(0) on SIGTERM.
func TestGracefulShutdownDrainsInFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release // hold the request open until the test lets it finish
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("done"))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newHTTPServer(ln.Addr().String(), mux)
	go func() { _ = srv.Serve(ln) }()

	type result struct {
		code int
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/slow")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer resp.Body.Close()
		resCh <- result{code: resp.StatusCode}
	}()

	<-started // the handler is now in-flight

	// Let the handler finish while Shutdown is draining.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned %v (in-flight request was not drained in time)", err)
	}

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("in-flight request was dropped by shutdown: %v", r.err)
		}
		if r.code != http.StatusOK {
			t.Fatalf("in-flight request got %d, want 200", r.code)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight request never completed")
	}
}
