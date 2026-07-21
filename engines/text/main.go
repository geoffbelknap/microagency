// Command text is a wasip1 query engine for microagency's wasm-compute substrate:
// it treats the query as a Go regular expression and writes the matching lines of
// stdin to stdout (grep). Stdlib only, so it compiles to a tiny wasip1 module and
// runs in pkg/sandbox — pure compute over bytes the host fetched cred-blind.
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "text: missing query (a regular expression)")
		os.Exit(2)
	}
	re, err := regexp.Compile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "text: bad regular expression: %v\n", err)
		os.Exit(2)
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		if re.Match(in.Bytes()) {
			fmt.Fprintln(out, in.Text())
		}
	}
	// A Scan that stops on an error (e.g. a line longer than the 16 MiB buffer)
	// otherwise looks identical to clean EOF, so the engine would exit 0 with
	// silently-truncated matches. The contract says a runtime failure is a
	// non-zero exit; fail closed and discard the partial output.
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "text: read: %v\n", err)
		os.Exit(1)
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "text: write: %v\n", err)
		os.Exit(1)
	}
}
