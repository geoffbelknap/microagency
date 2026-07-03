package minimize

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The pipeline threads each module's transformed output into the next and
// accumulates tokens + alerts across the chain.
func TestPipelineChainsAndAccumulates(t *testing.T) {
	upper := Func{N: "upper", F: func(_ context.Context, in ScanInput) (ScanResult, error) {
		return ScanResult{Transformed: []byte(strings.ToUpper(string(in.Payload))), Tokens: []Token{{Placeholder: "<a>", Value: "1"}}}, nil
	}}
	tagger := Func{N: "tagger", F: func(_ context.Context, in ScanInput) (ScanResult, error) {
		return ScanResult{Transformed: append([]byte("["), append(in.Payload, ']')...), Alerts: []Alert{{Type: "x"}}}, nil
	}}
	res, err := Pipeline{Modules: []Module{upper, tagger}}.Scan(context.Background(), ScanInput{Payload: []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Transformed) != "[HI]" {
		t.Fatalf("transformed = %q, want [HI]", res.Transformed)
	}
	if len(res.Tokens) != 1 || len(res.Alerts) != 1 {
		t.Fatalf("want 1 token + 1 alert, got %d/%d", len(res.Tokens), len(res.Alerts))
	}
}

// A module error aborts the chain with no payload — mediation must fail closed
// (never emit un-minimized data).
func TestPipelineFailsClosed(t *testing.T) {
	boom := Func{N: "boom", F: func(_ context.Context, _ ScanInput) (ScanResult, error) {
		return ScanResult{}, fmt.Errorf("detector crashed")
	}}
	res, err := Pipeline{Modules: []Module{boom}}.Scan(context.Background(), ScanInput{Payload: []byte("secret")})
	if err == nil {
		t.Fatal("expected an error so the caller withholds the payload")
	}
	if res.Transformed != nil {
		t.Fatalf("no payload may be returned on failure, got %q", res.Transformed)
	}
}

// Tokenized placeholders round-trip: what a minimizer swapped out on the way to
// the model is restored on the way back to the upstream.
func TestResolvePlaceholders(t *testing.T) {
	store := NewMemTokenStore()
	_ = store.Put([]Token{{Placeholder: "<mtok_ab>", Value: "5PY89921"}, {Placeholder: "<mtok_abcd>", Value: "long"}})
	// Longest-first: <mtok_abcd> must not be clobbered by the <mtok_ab> prefix.
	got := ResolvePlaceholders([]byte(`{"acct":"<mtok_ab>","other":"<mtok_abcd>"}`), store.Snapshot())
	if want := `{"acct":"5PY89921","other":"long"}`; string(got) != want {
		t.Fatalf("resolved = %q, want %q", got, want)
	}
	if v, ok := store.Resolve("<mtok_ab>"); !ok || v != "5PY89921" {
		t.Fatalf("Resolve = %q,%v", v, ok)
	}
}

// End-to-end against the real default module in the warm-pool WasmModule: redact
// email, tokenize + round-trip a card, alert on an SSN — run concurrently to
// exercise the cluster.
func TestWasmRedactorWarmPool(t *testing.T) {
	mod := buildWasip1(t, "../../minimizers/redactor")
	ctx := context.Background()
	m, err := LoadWasm(ctx, "redactor", mod, Options{Instances: 4, Timeout: 5 * time.Second, MaxMemoryPages: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)

	policy := []byte(`{"email":"redact","card":"tokenize","ssn":"alert"}`)
	// A Luhn-valid test card (Visa test number) + an email + an SSN.
	const card = "4111111111111111"
	payload := []byte(fmt.Sprintf(`{"email":"a@b.com","card":"%s","ssn":"123-45-6789"}`, card))

	store := NewMemTokenStore()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := m.Scan(ctx, ScanInput{Payload: payload, Upstream: "acme", Tool: "get", Direction: ToModel, Policy: policy})
			if err != nil {
				t.Errorf("scan: %v", err)
				return
			}
			out := string(res.Transformed)
			if strings.Contains(out, "a@b.com") {
				t.Errorf("email not redacted: %s", out)
			}
			if strings.Contains(out, card) {
				t.Errorf("card not tokenized (raw value leaked): %s", out)
			}
			if !strings.Contains(out, "123-45-6789") {
				t.Errorf("alerted SSN must remain in place: %s", out)
			}
			if len(res.Tokens) != 1 || res.Tokens[0].Value != card {
				t.Errorf("want 1 card token for %s, got %+v", card, res.Tokens)
			}
			if len(res.Alerts) != 1 || res.Alerts[0].Type != "ssn" {
				t.Errorf("want 1 ssn alert, got %+v", res.Alerts)
			}
			_ = store.Put(res.Tokens)
		}()
	}
	wg.Wait()

	// The tokenized card resolves back to the raw value on the return path.
	res, _ := m.Scan(ctx, ScanInput{Payload: payload, Direction: ToModel, Policy: policy})
	restored := ResolvePlaceholders(res.Transformed, store.Snapshot())
	if !strings.Contains(string(restored), card) {
		t.Fatalf("card did not round-trip back: %s", restored)
	}
}

// A non-Luhn 16-digit sequence (e.g. an order id) must NOT be treated as a card.
func TestWasmRedactorLuhnGuardsCards(t *testing.T) {
	mod := buildWasip1(t, "../../minimizers/redactor")
	ctx := context.Background()
	m, err := LoadWasm(ctx, "redactor", mod, Options{Instances: 2, Timeout: 5 * time.Second, MaxMemoryPages: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)

	res, err := m.Scan(ctx, ScanInput{Payload: []byte(`{"order":"1234567890123456"}`), Direction: ToModel, Policy: []byte(`{"card":"tokenize"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tokens) != 0 {
		t.Fatalf("a non-Luhn number must not be tokenized as a card: %+v", res.Tokens)
	}
	if !strings.Contains(string(res.Transformed), "1234567890123456") {
		t.Fatalf("order id should pass through untouched: %s", res.Transformed)
	}
}

// Field-name-driven enforcement (the Robinhood case): the VALUE of a field the
// schema NAMES as an account is tokenized even though it has no detectable format,
// while a reference key (account_id) under the same policy is left alone, and a
// formatted value in an unrelated field is still caught by content patterns.
func TestWasmRedactorFieldNameEnforcement(t *testing.T) {
	mod := buildWasip1(t, "../../minimizers/redactor")
	ctx := context.Background()
	m, err := LoadWasm(ctx, "redactor", mod, Options{Instances: 2, Timeout: 5 * time.Second, MaxMemoryPages: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)

	const acct = "5PY89921" // opaque — no content signature a detector could catch
	payload := []byte(`{"account_number":"` + acct + `","account_id":"cf-tenant-123","note":"reach me at a@b.com"}`)
	res, err := m.Scan(ctx, ScanInput{Payload: payload, Direction: ToModel, Policy: []byte(`{"account":"tokenize","email":"redact"}`)})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Transformed)
	if strings.Contains(out, acct) {
		t.Errorf("account_number VALUE must be tokenized by its field name (no content pattern): %s", out)
	}
	if !strings.Contains(out, "cf-tenant-123") {
		t.Errorf("account_id is a reference key — must be left alone: %s", out)
	}
	if strings.Contains(out, "a@b.com") {
		t.Errorf("email in free text should still be caught by content patterns: %s", out)
	}
	if len(res.Tokens) != 1 || res.Tokens[0].Value != acct {
		t.Fatalf("want exactly one account token for %q, got %+v", acct, res.Tokens)
	}
}

// --- wasip1 build helper (mirrors internal/wasmexec) ---

type buildResult struct {
	mod []byte
	err error
	env bool // true when the failure is a missing toolchain (skip, don't fail)
}

var (
	buildMu    sync.Mutex
	buildCache = map[string]buildResult{}
)

func buildWasip1(t *testing.T, srcDir string) []byte {
	t.Helper()
	buildMu.Lock()
	c, done := buildCache[srcDir]
	if !done {
		c = compileWasip1(srcDir)
		buildCache[srcDir] = c
	}
	buildMu.Unlock()
	if c.err != nil {
		if c.env {
			t.Skip(c.err.Error())
		}
		t.Fatalf("%v", c.err)
	}
	return c.mod
}

func compileWasip1(srcDir string) buildResult {
	if _, err := exec.LookPath("go"); err != nil {
		return buildResult{err: fmt.Errorf("go toolchain unavailable"), env: true}
	}
	dir, err := os.MkdirTemp("", "minimize-wasm-")
	if err != nil {
		return buildResult{err: err, env: true}
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "m.wasm")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		return buildResult{err: fmt.Errorf("wasip1 build failed (%s): %v\n%s", srcDir, err, b)}
	}
	mod, err := os.ReadFile(out)
	return buildResult{mod: mod, err: err}
}
