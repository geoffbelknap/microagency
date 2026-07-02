Built wasip1 engine modules (jq.wasm, text.wasm, html.wasm, sql.wasm) are placed
here by `make engines` and embedded into the binary (see bundled.go), so
`microagency up` has the declarative query engines with nothing to install.
The .wasm files are gitignored; this README keeps the directory present for
//go:embed.
