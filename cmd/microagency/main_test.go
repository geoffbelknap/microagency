package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeInitializeAndToolsList(t *testing.T) {
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
	)
	var out bytes.Buffer
	if err := buildServer(nil, 512, 2048, false, false, "127.0.0.1:8765").Serve(context.Background(), in, &out); err != nil {
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
