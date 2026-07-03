package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/gateway"
	"microagency/internal/minimize"
)

const (
	secretCard  = "4111111111111111"
	cardTokenPH = "[[mtok_card]]" // JSON-safe delimiters ([[ ]] aren't escaped, unlike < >)
)

// cardTokenizer is a Go-native minimizer that tokenizes a known card value and
// alerts on it. The wasm path is covered in internal/minimize; this exercises the
// gateway WIRING (policy gating, scrub-on-egress, token round-trip, alerts).
func cardTokenizer() minimize.Func {
	return minimize.Func{N: "cardtok", F: func(_ context.Context, in minimize.ScanInput) (minimize.ScanResult, error) {
		s := string(in.Payload)
		if !strings.Contains(s, secretCard) {
			return minimize.ScanResult{Transformed: in.Payload}, nil
		}
		s = strings.ReplaceAll(s, secretCard, cardTokenPH)
		return minimize.ScanResult{
			Transformed: []byte(s),
			Tokens:      []minimize.Token{{Placeholder: cardTokenPH, Value: secretCard, Type: "card"}},
			Alerts:      []minimize.Alert{{Type: "card", Note: "detected card"}},
		}, nil
	}}
}

// upstreamEchoingCard serves a tool whose result embeds a card number and records
// the arguments of the most recent tools/call (to prove token resolution).
func upstreamEchoingCard(t *testing.T, gotArgs *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		switch req.Method {
		case "initialize":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"acct","description":"get account","inputSchema":{"type":"object"}}]}}`)
		case "tools/call":
			*gotArgs = string(req.Params.Arguments)
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": `{"account":"` + secretCard + `"}`}}, "isError": false,
			}})
			w.Write(b)
		}
	}))
}

// With a policy set, a sensitive value is tokenized out of the inline result before
// it reaches the model, the placeholder resolves back on the next call, and the
// detection is audited.
func TestMinimizeTokenizesAndRoundTrips(t *testing.T) {
	var gotArgs string
	ts := upstreamEchoingCard(t, &gotArgs)
	defer ts.Close()

	s := newTestServer(t, fakeRunner{}, WithMinimizer(cardTokenizer(), minimize.NewMemTokenStore()))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "acme", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}
	s.SetMinimizePolicy("acme", []byte(`{"card":"tokenize"}`))

	out := call(t, s, "call_tool", map[string]any{"name": "acme__acct", "arguments": map[string]any{}})
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), secretCard) {
		t.Fatalf("the card leaked into the model-facing result: %s", raw)
	}
	if !strings.Contains(string(raw), "mtok_card") {
		t.Fatalf("expected the placeholder in the result, got %s", raw)
	}

	// The detection is on the run's audit record.
	if !hasMinimizeAlert(s) {
		t.Error("expected a minimize_alert audit event on the proxy run")
	}

	// The model echoes the placeholder in a follow-up call; the upstream must receive
	// the REAL value, resolved on the way out.
	call(t, s, "call_tool", map[string]any{"name": "acme__acct", "arguments": map[string]any{"account": cardTokenPH}})
	if !strings.Contains(gotArgs, secretCard) {
		t.Fatalf("placeholder was not resolved before dialing the upstream; upstream saw %q", gotArgs)
	}
	if strings.Contains(gotArgs, cardTokenPH) {
		t.Fatalf("the upstream received the placeholder instead of the real value: %q", gotArgs)
	}
}

// Without a policy for the upstream, minimization is inactive and the result passes
// through untouched — the feature is strictly opt-in.
func TestMinimizeInactiveWithoutPolicy(t *testing.T) {
	var gotArgs string
	ts := upstreamEchoingCard(t, &gotArgs)
	defer ts.Close()

	s := newTestServer(t, fakeRunner{}, WithMinimizer(cardTokenizer(), minimize.NewMemTokenStore()))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "acme", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}
	// no SetMinimizePolicy

	out := call(t, s, "call_tool", map[string]any{"name": "acme__acct", "arguments": map[string]any{}})
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), secretCard) {
		t.Fatalf("with no policy the result should pass through unchanged, got %s", raw)
	}
}

// A minimizer error withholds the result rather than emitting it un-minimized.
func TestMinimizeFailsClosed(t *testing.T) {
	var gotArgs string
	ts := upstreamEchoingCard(t, &gotArgs)
	defer ts.Close()

	boom := minimize.Func{N: "boom", F: func(_ context.Context, _ minimize.ScanInput) (minimize.ScanResult, error) {
		return minimize.ScanResult{}, io.ErrUnexpectedEOF
	}}
	s := newTestServer(t, fakeRunner{}, WithMinimizer(boom, minimize.NewMemTokenStore()))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "acme", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}
	s.SetMinimizePolicy("acme", []byte(`{"card":"tokenize"}`))

	out := call(t, s, "call_tool", map[string]any{"name": "acme__acct", "arguments": map[string]any{}})
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), secretCard) {
		t.Fatalf("fail-closed violated — raw result leaked on minimizer error: %s", raw)
	}
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatalf("a minimizer error must surface as a tool error, got %s", raw)
	}
	if !strings.Contains(string(raw), "withheld") {
		t.Fatalf("the error should say the result was withheld, got %s", raw)
	}
}

// The admin endpoint sets, clears, and validates a per-upstream policy.
func TestAdminSetMinimizePolicy(t *testing.T) {
	s := newTestServer(t, fakeRunner{}, WithMinimizer(cardTokenizer(), minimize.NewMemTokenStore()))
	admin := httptest.NewServer(s.AdminHandler("op"))
	defer admin.Close()

	post := func(body string) int {
		req, _ := http.NewRequest(http.MethodPost, admin.URL+"/admin/upstreams/acme/minimize", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer op")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := post(`{"policy":{"account":"tokenize","ssn":"alert"}}`); code != 200 {
		t.Fatalf("set policy: status %d", code)
	}
	if s.minimizePolicyFor("acme") == nil {
		t.Fatal("policy was not applied")
	}
	if code := post(`{"policy":{}}`); code != 200 {
		t.Fatalf("clear policy: status %d", code)
	}
	if s.minimizePolicyFor("acme") != nil {
		t.Fatal("policy was not cleared")
	}
	if code := post(`{"policy":"not-an-object"}`); code != 400 {
		t.Fatalf("a non-object policy must be rejected, got %d", code)
	}
}

func hasMinimizeAlert(s *Server) bool {
	for _, r := range s.RunLog() {
		for _, a := range r.Audit {
			if a.Event == "minimize_alert" {
				return true
			}
		}
	}
	return false
}
