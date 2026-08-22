package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// scopeRecordingServer assigns a fresh Mcp-Session-Id per initialize and
// records the session id presented on every tools/call.
type scopeRecordingServer struct {
	mu           sync.Mutex
	initializes  int
	callSessions []string
}

func (s *scopeRecordingServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			s.mu.Lock()
			s.initializes++
			id := fmt.Sprintf("sess-%d", s.initializes)
			s.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/call":
			s.mu.Lock()
			s.callSessions = append(s.callSessions, r.Header.Get("Mcp-Session-Id"))
			s.mu.Unlock()
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
		default: // notifications/initialized
			w.WriteHeader(http.StatusAccepted)
		}
	}
}

// Upstream MCP session state is keyed by caller scope: each scope runs its own
// initialize handshake and presents only its own Mcp-Session-Id, so server-side
// session state never spans callers multiplexed over one shared connection.
func TestUpstreamSessionsAreScopedPerCaller(t *testing.T) {
	rec := &scopeRecordingServer{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	u := &Upstream{Name: "x", URL: srv.URL}
	if err := u.Initialize(context.Background()); err != nil { // baseline (wiring)
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, scope := range []string{"issuer#alice", "issuer#bob", "issuer#alice", ""} {
		if _, err := u.CallTool(WithSessionScope(ctx, scope), "search", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("call under scope %q: %v", scope, err)
		}
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	// baseline initialize + one lazy handshake per caller scope, and no third
	// handshake for alice's second call.
	if rec.initializes != 3 {
		t.Fatalf("initializes = %d, want 3 (baseline + alice + bob)", rec.initializes)
	}
	got := rec.callSessions
	if len(got) != 4 {
		t.Fatalf("recorded %d calls, want 4: %v", len(got), got)
	}
	alice1, bob, alice2, baseline := got[0], got[1], got[2], got[3]
	if alice1 == "" || bob == "" || baseline == "" {
		t.Fatalf("every call must carry a session id: %v", got)
	}
	if alice1 != alice2 {
		t.Fatalf("one caller's session must be stable: %q vs %q", alice1, alice2)
	}
	if alice1 == bob || alice1 == baseline || bob == baseline {
		t.Fatalf("sessions crossed caller scopes: alice=%q bob=%q baseline=%q", alice1, bob, baseline)
	}
	if baseline != "sess-1" {
		t.Fatalf("unscoped calls must use the wiring-time baseline session, got %q", baseline)
	}
}

// A transiently failing per-scope handshake is retried on the caller's next
// request rather than leaving that caller permanently sessionless.
func TestScopeHandshakeRetriesAfterFailure(t *testing.T) {
	rec := &scopeRecordingServer{}
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if fail && strings.Contains(string(body), `"initialize"`) {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		rec.handler()(w, r)
	}))
	defer srv.Close()

	u := &Upstream{Name: "x", URL: srv.URL}
	ctx := WithSessionScope(context.Background(), "issuer#alice")
	fail = true
	_, _ = u.CallTool(ctx, "search", json.RawMessage(`{}`)) // handshake fails; call proceeds sessionless
	fail = false
	if _, err := u.CallTool(ctx, "search", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.callSessions) != 2 || rec.callSessions[0] != "" || rec.callSessions[1] == "" {
		t.Fatalf("second call must carry the retried handshake's session: %v", rec.callSessions)
	}
}
