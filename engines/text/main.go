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
	defer out.Flush()
	for in.Scan() {
		if re.Match(in.Bytes()) {
			fmt.Fprintln(out, in.Text())
		}
	}
}
