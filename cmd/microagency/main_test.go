package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"microagency/internal/mcp"
)

// testServer builds a gateway the way a test needs one: its own state
// directory, because buildServer resolves ~/.microagency and a test must never
// read or overwrite a real deployment's credential state; and the unencrypted
// local store accepted out loud, because a test brings up no vault and the
// gateway now refuses that store without an explicit opt-in.
func testServer(t *testing.T, consoleAddr string) *mcp.Server {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return buildServer(
		upOptions{wasmMaxMemMB: 512, maxInlineBytes: 2048},
		consoleAddr,
		credentialIntent{allowPlaintext: true},
	)
}

func TestServeInitializeAndToolsList(t *testing.T) {
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
	)
	var out bytes.Buffer
	if err := testServer(t, "127.0.0.1:8765").Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 response lines, got %d: %q", len(lines), out.String())
	}
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &resp); err != nil {
		t.Fatalf("decode tools/list: %v\n%s", err, lines[1])
	}
	got := map[string]bool{}
	for _, tl := range resp.Result.Tools {
		got[tl.Name] = true
	}
	for _, want := range []string{"reduce", "find_tools", "call_tool"} {
		if !got[want] {
			t.Fatalf("tools/list missing %q", want)
		}
	}
}

func TestParseRegisteredURL(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "present",
			out: "microagency:\n  Scope: Local config (private to you in this project)\n" +
				"  Status: ! Needs authentication\n  Type: http\n  URL: http://127.0.0.1:8765/mcp\n",
			want: "http://127.0.0.1:8765/mcp",
		},
		{"absent", "", ""},
		{"no url line", "microagency:\n  Type: http\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRegisteredURL([]byte(tc.out)); got != tc.want {
				t.Fatalf("parseRegisteredURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
