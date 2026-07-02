package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"servers":[
		{"name":"github","url":"https://gh/mcp","tools":[
			{"name":"create_issue","description":"open an issue","inputSchema":{"type":"object"}}]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	servers, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(servers) != 1 || servers[0].Name != "github" || servers[0].URL != "https://gh/mcp" {
		t.Fatalf("servers wrong: %+v", servers)
	}
	if len(servers[0].Tools) != 1 || servers[0].Tools[0].Name != "create_issue" {
		t.Fatalf("tools wrong: %+v", servers[0].Tools)
	}
	if len(servers[0].Tools[0].InputSchema) == 0 {
		t.Fatal("inputSchema not preserved")
	}
}

func TestLoadRejectsBadServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"servers":[{"name":"","url":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a server without a name must be rejected")
	}
}
