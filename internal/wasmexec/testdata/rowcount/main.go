// Command rowcount is a trivial wasip1 "query engine" used to prove the
// wasm-compute wiring: it reads the host-fetched data on stdin and the query as
// argv[1], and writes a summary to stdout. It stands in for a real query engine
// (e.g. a wasip1 SQL/dataframe engine) so the SandboxEngine ↔ pkg/sandbox path
// can be tested end-to-end without that engine's build toolchain.
//
// Built into a module at test time with: GOOS=wasip1 GOARCH=wasm go build.
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	query := ""
	if len(os.Args) > 1 {
		query = os.Args[1]
	}
	rows, n := 0, 0
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		rows++
		n += len(sc.Bytes()) + 1
	}
	fmt.Printf("query=%q rows=%d bytes=%d\n", query, rows, n)
}
