package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"microagency/internal/gateway"
)

// blockingUpstream advertises one tool whose tools/call blocks until release is
// closed (or the upstream-side request is canceled), counting how many calls it saw.
func blockingUpstream(t *testing.T, toolName string, release <-chan struct{}, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"`+toolName+`","description":"x","inputSchema":{}}]}}`)
		case "tools/call":
			atomic.AddInt32(calls, 1)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"OK"}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
}

func callCtx(t *testing.T, s *Server, ctx context.Context, tool string, args map[string]any) map[string]any {
	t.Helper()
	argsB, _ := json.Marshal(args)
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": json.RawMessage(argsB)})
	line, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
	resp, write := s.Handle(ctx, line)
	if !write {
		t.Fatal("expected a response")
	}
	if resp.Error != nil {
		t.Fatalf("protocol error: %+v", resp.Error)
	}
	return resp.Result.(map[string]any)
}

func waitFor(t *testing.T, want int32, got *int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(got) >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for count %d (got %d)", want, atomic.LoadInt32(got))
}

// Two identical concurrent READS share a single upstream execution (single-flight).
func TestInflightSingleFlightsIdenticalReads(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	up := blockingUpstream(t, "get-data", release, &calls)
	defer up.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := make(chan map[string]any, 2)
	go func() { out <- callCtx(t, s, context.Background(), "u__get-data", map[string]any{}) }()
	waitFor(t, 1, &calls)                                                                       // first call reached the upstream
	go func() { out <- callCtx(t, s, context.Background(), "u__get-data", map[string]any{}) }() // must JOIN, not re-dial
	time.Sleep(30 * time.Millisecond)
	close(release)

	for i := 0; i < 2; i++ {
		if blob, _ := json.Marshal(<-out); !strings.Contains(string(blob), "OK") {
			t.Fatalf("caller %d did not get the result: %s", i, blob)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("identical reads were not single-flighted: %d upstream calls", n)
	}
}

// A READ whose caller cancels mid-flight is NOT aborted: the detached call finishes,
// its result is cached, and an identical retry collects it — one upstream call total.
func TestInflightDecouplesReadFromCallerCancel(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	up := blockingUpstream(t, "get-data", release, &calls)
	defer up.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan map[string]any, 1)
	go func() { out <- callCtx(t, s, ctx, "u__get-data", map[string]any{}) }()
	waitFor(t, 1, &calls) // upstream call in flight
	cancel()              // caller gives up (client timeout)

	first, _ := json.Marshal(<-out)
	if !strings.Contains(string(first), "still running") {
		t.Fatalf("a canceled read should report the detached call, got: %s", first)
	}

	close(release) // the detached call completes and caches
	// An identical retry joins the (now completing) call or its cached result — no re-dial.
	retry, _ := json.Marshal(callCtx(t, s, context.Background(), "u__get-data", map[string]any{}))
	if !strings.Contains(string(retry), "OK") {
		t.Fatalf("retry did not collect the recovered result: %s", retry)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("the read was re-dialed instead of recovered: %d upstream calls", n)
	}
}

// Writes are never cached/decoupled: two identical writes each hit the upstream.
func TestInflightDoesNotCacheWrites(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	up := blockingUpstream(t, "create-thing", release, &calls)
	defer up.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := make(chan map[string]any, 2)
	go func() { out <- callCtx(t, s, context.Background(), "u__create-thing", map[string]any{}) }()
	waitFor(t, 1, &calls)
	go func() { out <- callCtx(t, s, context.Background(), "u__create-thing", map[string]any{}) }()
	waitFor(t, 2, &calls) // the second write must ALSO reach the upstream (no dedup)
	close(release)
	<-out
	<-out
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("writes must not be single-flighted: %d upstream calls (want 2)", n)
	}
}

// A failed read is delivered to its waiters but NOT cached: an identical retry
// re-runs instead of being served the stale failure for the rest of the TTL.
func TestInflightDoesNotCacheErrors(t *testing.T) {
	f := newInflight()
	var runs int32
	fail := func(context.Context) (json.RawMessage, error) {
		atomic.AddInt32(&runs, 1)
		return nil, errBoom
	}
	if _, err, _ := f.do(context.Background(), "k", fail); err == nil {
		t.Fatal("first call should surface the failure")
	}
	res, err, canceled := f.do(context.Background(), "k", func(context.Context) (json.RawMessage, error) {
		atomic.AddInt32(&runs, 1)
		return json.RawMessage(`"ok"`), nil
	})
	if err != nil || canceled {
		t.Fatalf("retry must RE-RUN, not replay the cached failure: err=%v canceled=%v", err, canceled)
	}
	if string(res) != `"ok"` {
		t.Fatalf("retry result: %s", res)
	}
	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Fatalf("expected 2 executions (no error caching), got %d", got)
	}
	// A success IS cached: a third identical call is served without re-running.
	if _, err, _ := f.do(context.Background(), "k", fail); err != nil {
		t.Fatal("a cached success must be served, not re-run")
	}
	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Fatalf("cached success should not re-run; got %d executions", got)
	}
}

var errBoom = errors.New("boom")
