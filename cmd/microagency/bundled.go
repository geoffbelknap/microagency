package main

import (
	"embed"
	"io/fs"
	"strings"
)

// bundledFS holds the wasip1 engine modules baked into the binary. `make engines`
// builds them into ./bundled/ before `go build`, so a released binary ships with
// the declarative engines and `microagency up` works with nothing to install.
// When built without running `make engines`, only README.txt is present and
// bundledEngines() returns empty (the code path still works).
//
//go:embed bundled
var bundledFS embed.FS

// bundledEngines returns the embedded engine modules by name (the .wasm filename
// without its extension), e.g. {"jq": ..., "sql": ...}.
func bundledEngines() map[string][]byte {
	out := map[string][]byte{}
	entries, err := fs.ReadDir(bundledFS, "bundled")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".wasm") {
			continue
		}
		b, err := bundledFS.ReadFile("bundled/" + name)
		if err != nil {
			continue
		}
		out[strings.TrimSuffix(name, ".wasm")] = b
	}
	return out
}
