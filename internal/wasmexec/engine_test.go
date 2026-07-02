package wasmexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// SandboxEngine must satisfy the Engine seam the reduce path consumes.
var _ Engine = SandboxEngine{}

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
	engMu.Lock()
	c, done := engCache[srcDir]
	engMu.Unlock()
	if !done {
		c = compileWasip1(srcDir)
		engMu.Lock()
		engCache[srcDir] = c
		engMu.Unlock()
	}
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

func TestSandboxEngineRunsSqlQuery(t *testing.T) {
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
