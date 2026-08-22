package wasmexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/geoffbelknap/microagent/pkg/sandbox"
)

// SandboxEngine must satisfy the Engine seam the reduce path consumes.
var _ Engine = SandboxEngine{}

// TestMain creates one throwaway sandbox runtime while the process is still
// single-threaded.
//
// wazero caches its own version string in an unsynchronized package-level
// variable, populated the first time a runtime is created
// (internal/version.GetWazeroVersion). Two goroutines creating a runtime
// concurrently before that cache is warm race on it, inside the dependency —
// and every Run here builds a runtime. Touching it once up front closes that
// window for the parallel tests below.
//
// It is a one-shot lazy init, so this suppresses nothing else: every other race,
// in this package or in wazero's engine, is still reported normally.
func TestMain(m *testing.M) {
	// The 8-byte header is the smallest well-formed module. Only runtime
	// creation matters here, so a compile failure is fine to ignore.
	if rt, err := sandbox.Compile(context.Background(), []byte("\x00asm\x01\x00\x00\x00"), sandbox.RuntimeOptions{}); err == nil {
		_ = rt.Close(context.Background())
	}
	os.Exit(m.Run())
}

// buildResult caches one engine compile. env marks failures that are genuine
// environment limitations (no Go toolchain, no temp dir) — those skip; anything
// else is a build error in our own engine source and must fail loudly.
type buildResult struct {
	mod []byte
	err error
	env bool
}

var (
	engMu    sync.Mutex
	engCache = map[string]buildResult{}
)

// buildWasip1 compiles the module in srcDir to a wasip1 module once (cached by
// dir). Environment limitations skip so `go test ./...` stays green everywhere;
// a compile error in the engine source itself fails the test — the engine is
// broken, not the environment.
func buildWasip1(t *testing.T, srcDir string) []byte {
	t.Helper()
	// Held across the compile so concurrent tests wait for the first builder
	// rather than each spawning a duplicate `go build` for the same engine.
	engMu.Lock()
	c, done := engCache[srcDir]
	if !done {
		c = compileWasip1(srcDir)
		engCache[srcDir] = c
	}
	engMu.Unlock()
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
	dir, err := os.MkdirTemp("", "engine-wasm-")
	if err != nil {
		return buildResult{err: err, env: true}
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "m.wasm")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	cmd.Dir = srcDir
	// GOWORK=off matches the Makefile: the engines are standalone modules and
	// must not resolve through a co-development go.work at the repo root.
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		return buildResult{err: fmt.Errorf("wasip1 build failed (%s): %v\n%s", srcDir, err, b)}
	}
	mod, err := os.ReadFile(out)
	return buildResult{mod: mod, err: err}
}

func TestSandboxEngineRunsWasip1Module(t *testing.T) {
	t.Parallel()
	eng := SandboxEngine{Module: buildWasip1(t, "testdata/rowcount")}
	summary, err := eng.Run(context.Background(), "count", []byte("alpha\nbeta\ngamma\n"))
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}
	// Both inputs reached the module and the summary came back.
	if !strings.Contains(string(summary), "rows=3") {
		t.Fatalf("data did not reach the module: %q", summary)
	}
	if !strings.Contains(string(summary), `query="count"`) {
		t.Fatalf("query did not reach the module: %q", summary)
	}
}

// An engine's stderr can echo the referenced data it was processing, so the
// error MESSAGE must never carry it — Error() is content-free; the bytes ride
// only on the ExitError field, bound for the operator's audit record.
func TestExitErrorMessageOmitsStderr(t *testing.T) {
	t.Parallel()
	err := &ExitError{ExitCode: 3, Stderr: `jq: error: cannot index "MRN-8675309"`}
	if strings.Contains(err.Error(), "MRN-8675309") {
		t.Fatalf("guest stderr leaked into the error message: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "exited 3") {
		t.Fatalf("error message must carry the exit code: %q", err.Error())
	}
}

// A real module that exits non-zero must surface as *ExitError: stderr captured
// on the field (for the operator), absent from the message (agent-bound).
func TestSandboxEngineNonZeroExitReturnsExitError(t *testing.T) {
	t.Parallel()
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/jq")}
	_, err := eng.Run(context.Background(), `.[] | bogus_fn_zz`, []byte(`[1]`))
	if err == nil {
		t.Fatal("an invalid jq program must fail")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("want *ExitError, got %T: %v", err, err)
	}
	if exitErr.Stderr == "" {
		t.Fatal("the module's stderr must be captured for the operator")
	}
	if strings.Contains(err.Error(), strings.TrimSpace(exitErr.Stderr)) {
		t.Fatalf("stderr leaked into the error message: %q", err.Error())
	}
}

func TestSandboxEngineRunsJqQuery(t *testing.T) {
	t.Parallel()
	// jq: a real jq program executes over fetched JSON.
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/jq")}
	data := []byte(`[{"email":"ana@x.io","active":true},{"email":"bo@x.io","active":false},{"email":"cy@x.io","active":true}]`)
	summary, err := eng.Run(context.Background(), `[.[] | select(.active) | .email]`, data)
	if err != nil {
		t.Fatalf("jq run: %v", err)
	}
	if got := strings.TrimSpace(string(summary)); got != `["ana@x.io","cy@x.io"]` {
		t.Fatalf("jq result = %q, want the two active emails", got)
	}
}

func TestSandboxEngineRunsTextQuery(t *testing.T) {
	t.Parallel()
	// text: the query is a regular expression; matching lines come back (grep).
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/text")}
	summary, err := eng.Run(context.Background(), "ERROR|WARN", []byte("INFO ok\nERROR boom\nDEBUG x\nWARN careful\n"))
	if err != nil {
		t.Fatalf("text run: %v", err)
	}
	if got := strings.TrimSpace(string(summary)); got != "ERROR boom\nWARN careful" {
		t.Fatalf("text result = %q", got)
	}
}

func TestSandboxEngineRunsHtmlQuery(t *testing.T) {
	t.Parallel()
	// html: the query is a CSS selector; "@attr" extracts an attribute.
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/html")}
	html := []byte("<html><head><title>Hi There</title></head><body><a href='/a'>One</a><a href='/b'>Two</a></body></html>")
	title, err := eng.Run(context.Background(), "title", html)
	if err != nil {
		t.Fatalf("html run: %v", err)
	}
	if got := strings.TrimSpace(string(title)); got != "Hi There" {
		t.Fatalf("html title = %q", got)
	}
	hrefs, err := eng.Run(context.Background(), "a@href", html)
	if err != nil {
		t.Fatalf("html attr run: %v", err)
	}
	if got := strings.TrimSpace(string(hrefs)); got != "/a\n/b" {
		t.Fatalf("html hrefs = %q, want both", got)
	}
}

func TestHtmlEngineRejectsInvalidSelector(t *testing.T) {
	t.Parallel()
	// A malformed CSS selector must be a bad-query error (exit 2), not a silent
	// zero-match success — otherwise the agent can't tell a typo from no matches.
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/html")}
	_, err := eng.Run(context.Background(), "a[href", []byte("<a href='/x'>x</a>"))
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("want *ExitError for a bad selector, got %T: %v", err, err)
	}
	if exitErr.ExitCode != 2 {
		t.Fatalf("bad selector exit = %d, want 2", exitErr.ExitCode)
	}
}

func TestTextEngineFailsClosedOnOversizedLine(t *testing.T) {
	t.Parallel()
	// A line past the 16 MiB scanner cap stops the scan with an error; the engine
	// must fail closed (non-zero exit) rather than exit 0 with truncated matches.
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/text")}
	huge := bytes.Repeat([]byte("a"), 17*1024*1024)
	_, err := eng.Run(context.Background(), "a", huge)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("want *ExitError for an oversized line, got %T: %v", err, err)
	}
	if exitErr.ExitCode != 1 {
		t.Fatalf("oversized-line exit = %d, want 1", exitErr.ExitCode)
	}
}

func TestSandboxEngineRunsSqlQuery(t *testing.T) {
	t.Parallel()
	// sql: a real SELECT with WHERE + GROUP BY + aggregate over JSON rows.
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/sql")}
	data := []byte(`[{"dept":"eng","active":true},{"dept":"eng","active":false},{"dept":"sales","active":true}]`)
	summary, err := eng.Run(context.Background(), `SELECT dept, count(*) AS n FROM data WHERE active = 1 GROUP BY dept`, data)
	if err != nil {
		t.Fatalf("sql run: %v", err)
	}
	// encoding/json sorts map keys; groups keep first-seen order.
	if got := strings.TrimSpace(string(summary)); got != `[{"dept":"eng","n":1},{"dept":"sales","n":1}]` {
		t.Fatalf("sql result = %q", got)
	}
}
