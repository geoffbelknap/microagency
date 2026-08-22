package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/gateway"
)

func TestCanonicalJSONNormalizesEncodingNotContent(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sorts keys", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"strips whitespace", "{\n  \"a\": [1, 2]\n}", `{"a":[1,2]}`},
		{"preserves number literals", `{"n":1e2}`, `{"n":1e2}`},
		{"no html escaping", `{"q":"a<b&c"}`, `{"q":"a<b&c"}`},
		{"nested sort", `{"z":{"y":1,"x":2},"a":true}`, `{"a":true,"z":{"x":2,"y":1}}`},
	}
	for _, tc := range cases {
		if got := string(canonicalJSON([]byte(tc.in))); got != tc.want {
			t.Fatalf("%s: canonicalJSON(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
	// Non-JSON input passes through unchanged, so the digest is still defined.
	if got := string(canonicalJSON([]byte("not json"))); got != "not json" {
		t.Fatalf("non-JSON input should pass through, got %q", got)
	}
}

func TestArgsSHA256EqualForEquivalentEncodings(t *testing.T) {
	a := argsSHA256([]byte(`{"b": 1, "a": "x"}`))
	b := argsSHA256([]byte(`{"a":"x","b":1}`))
	if a != b {
		t.Fatalf("equivalent encodings should digest identically: %s vs %s", a, b)
	}
	if c := argsSHA256([]byte(`{"a":"y","b":1}`)); c == a {
		t.Fatal("a changed value must change the digest")
	}
	// The digest is recomputable from the documented canonical form.
	sum := sha256.Sum256([]byte(`{"a":"x","b":1}`))
	if want := hex.EncodeToString(sum[:]); a != want {
		t.Fatalf("digest %s is not SHA-256 of the canonical form (want %s)", a, want)
	}
}

func TestArgShapeCarriesStructureNotValues(t *testing.T) {
	raw := []byte(`{"query":"secret text","limit":20,"nested":{"flag":true,"ids":[1,2,3]},"note":null}`)
	shape := string(argShape(raw))
	for _, want := range []string{`"query":"string(11B)"`, `"limit":"number"`, `"flag":"bool"`, `"ids":["number","+2 more"]`, `"note":"null"`} {
		if !strings.Contains(shape, want) {
			t.Fatalf("shape %s missing %s", shape, want)
		}
	}
	for _, leak := range []string{"secret", "20", "true"} {
		if strings.Contains(shape, leak) {
			t.Fatalf("shape %s leaks value %q", shape, leak)
		}
	}
}

func TestArgShapeCollapsesDataLikeKeys(t *testing.T) {
	// Keys that look like data (an email) must not be emitted — a shape that
	// mirrors a data-keyed map would leak values through its keys.
	shape := string(argShape([]byte(`{"alice@example.com":{"role":"admin"}}`)))
	if strings.Contains(shape, "alice") {
		t.Fatalf("shape %s leaks a data-like key", shape)
	}
	if !strings.Contains(shape, "object(1 keys)") {
		t.Fatalf("data-keyed object should collapse to a count, got %s", shape)
	}
}

func TestArgShapeBoundsAndEdgeCases(t *testing.T) {
	if got := argShape(nil); got != nil {
		t.Fatalf("empty args should have no shape, got %s", got)
	}
	if got := string(argShape([]byte("not json"))); got != `"opaque(8B)"` {
		t.Fatalf("non-JSON args should report size only, got %s", got)
	}
	// Nesting past the depth cap collapses to a count instead of recursing.
	deep := []byte(`{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":"v"}}}}}}}}}}`)
	if shape := string(argShape(deep)); !strings.Contains(shape, "object(1 keys)") {
		t.Fatalf("deep nesting should collapse to a count descriptor, got %s", shape)
	}
}

// A single-principal gateway records full arguments, unchanged.
func TestSinglePrincipalAuditKeepsFullArgs(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing"}}, false)
	call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{"q": "hello"}})
	rec := s.RunLog()[0]
	if !strings.Contains(rec.Args, "hello") {
		t.Fatalf("single-principal record should keep full args, got %q", rec.Args)
	}
	if rec.ArgsCapture != "" || rec.ArgsSHA256 != "" || rec.ArgsShape != nil {
		t.Fatalf("single-principal record should carry no capture fields: %+v", rec)
	}
}

// A multi-principal gateway records structure + digest instead of values.
func TestMultiPrincipalAuditRecordsStructureAndDigest(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing"}}, false)
	s.SetMultiPrincipalAuth(true)
	args := map[string]any{"q": "confidential-value", "limit": 3}
	call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": args})
	rec := s.RunLog()[0]
	if rec.Args != "" {
		t.Fatalf("multi-principal record must not carry argument values, got %q", rec.Args)
	}
	if rec.ArgsCapture != argsCaptureStructure {
		t.Fatalf("args_capture = %q, want %q", rec.ArgsCapture, argsCaptureStructure)
	}
	if !strings.Contains(string(rec.ArgsShape), `"q"`) || strings.Contains(string(rec.ArgsShape), "confidential") {
		t.Fatalf("shape should carry keys, never values: %s", rec.ArgsShape)
	}
	raw, _ := json.Marshal(args)
	if want := argsSHA256(raw); rec.ArgsSHA256 != want {
		t.Fatalf("digest %s does not verify against the claimed arguments (want %s)", rec.ArgsSHA256, want)
	}
	if rec.InputBytes == 0 {
		t.Fatal("byte count should still be recorded")
	}
}

// Refusal outcomes on a multi-principal gateway are minimized the same way —
// the capture decision covers every proxy record, not just successes.
func TestMultiPrincipalAuditMinimizesRefusalRecordsToo(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "create-thing"}}, false)
	s.SetMultiPrincipalAuth(true)
	if err := s.SetUpstreamReadOnly("u", true); err != nil {
		t.Fatal(err)
	}
	call(t, s, "call_tool", map[string]any{"name": "u__create-thing", "arguments": map[string]any{"payload": "private"}})
	rec := s.RunLog()[0]
	if rec.Args != "" || strings.Contains(string(rec.ArgsShape), "private") {
		t.Fatalf("refusal record leaks argument values: args=%q shape=%s", rec.Args, rec.ArgsShape)
	}
	if rec.ArgsCapture != argsCaptureStructure || rec.ArgsSHA256 == "" {
		t.Fatalf("refusal record should still be provable: %+v", rec)
	}
}

// An opted-up connection returns to full capture, and the record says so.
func TestAuditFullArgsOptUpRestoresFullCapture(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing"}}, false)
	s.SetMultiPrincipalAuth(true)
	if err := s.SetUpstreamAuditFullArgs("u", true); err != nil {
		t.Fatal(err)
	}
	call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{"q": "hello"}})
	rec := s.RunLog()[0]
	if !strings.Contains(rec.Args, "hello") {
		t.Fatalf("opted-up connection should record full args, got %q", rec.Args)
	}
	if rec.ArgsCapture != argsCaptureFull {
		t.Fatalf("args_capture = %q, want %q (the opt-up must be visible per record)", rec.ArgsCapture, argsCaptureFull)
	}
	// The opt-up is disclosed on the operator's upstream list.
	if !s.UpstreamList()[0].AuditFullArgs {
		t.Fatal("UpstreamList should disclose the opt-up")
	}
	// And opting back down restores structure capture.
	if err := s.SetUpstreamAuditFullArgs("u", false); err != nil {
		t.Fatal(err)
	}
	call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{"q": "hello"}})
	if rec := s.RunLog()[0]; rec.ArgsCapture != argsCaptureStructure || rec.Args != "" {
		t.Fatalf("opt-down should restore structure capture: %+v", rec)
	}
}

func TestSetUpstreamAuditFullArgsUnknownUpstream(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	if err := s.SetUpstreamAuditFullArgs("nope", true); err == nil {
		t.Fatal("unknown upstream should error")
	}
}

// The admin route toggles the opt-up and persists it, so it survives restart
// and is readable by doctor's posture disclosure.
func TestAdminAuditCapturePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	var hit int32
	up := guardUpstream(t, []upTool{{name: "get-thing"}}, false, &hit)
	t.Cleanup(up.Close)
	newServer := func() *Server {
		s := newTestServer(t, fakeRunner{}, WithStateDir(dir), WithUpstreamClient(&http.Client{}))
		return s
	}
	s := newServer()
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatal(err)
	}
	s.persistRegistration("u", up.URL, false, authNone, "")

	admin := s.AdminHandler("tok")
	req := httptest.NewRequest("POST", "/admin/upstreams/u/audit-capture", bytes.NewBufferString(`{"full_args":true}`))
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	admin.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit-capture returned %d: %s", rr.Code, rr.Body)
	}
	if !s.UpstreamList()[0].AuditFullArgs {
		t.Fatal("opt-up not applied to the live registry")
	}

	// The persisted registration carries it (this is what doctor reads) …
	regs := ReadUpstreamRegistrations(dir)
	if len(regs) != 1 || !regs[0].AuditFullArgs {
		t.Fatalf("opt-up not persisted: %+v", regs)
	}
	// … and a restart restores it.
	s2 := newServer()
	s2.ReloadUpstreams(context.Background())
	if !s2.UpstreamList()[0].AuditFullArgs {
		t.Fatal("opt-up did not survive reload")
	}

	// Unknown connections 404 instead of silently succeeding.
	req = httptest.NewRequest("POST", "/admin/upstreams/nope/audit-capture", bytes.NewBufferString(`{"full_args":true}`))
	req.Header.Set("Authorization", "Bearer tok")
	rr = httptest.NewRecorder()
	admin.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown upstream returned %d, want 404", rr.Code)
	}
}
