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
// without its extension), e.g. {"jq": ..., "sql": ...}. The minimizers subdir is
// skipped (it isn't a .wasm entry), so the two module kinds never cross-load.
func bundledEngines() map[string][]byte {
	return bundledWasm("bundled")
}

// bundledMinimizers returns the embedded field-minimizer modules by name, built
// into bundled/minimizers/ by `make minimizers`.
func bundledMinimizers() map[string][]byte {
	return bundledWasm("bundled/minimizers")
}

// bundledWasm reads every *.wasm in dir, keyed by filename without the extension.
func bundledWasm(dir string) map[string][]byte {
	out := map[string][]byte{}
	entries, err := fs.ReadDir(bundledFS, dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".wasm") {
			continue
		}
		b, err := bundledFS.ReadFile(dir + "/" + name)
		if err != nil {
			continue
		}
		out[strings.TrimSuffix(name, ".wasm")] = b
	}
	return out
}
