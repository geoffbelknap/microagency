// Command html is a wasip1 query engine for microagency's wasm-compute substrate:
// it treats the query as a CSS selector over HTML read from stdin and writes each
// match to stdout, one per line. The default emits each match's trimmed text; a
// "selector@attr" form emits that attribute instead (e.g. "a@href" → every link).
// Pure Go (goquery), so it compiles to wasip1 and runs in pkg/sandbox — pure
// compute over bytes the host fetched cred-blind.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/andybalholm/cascadia"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "html: missing query (a CSS selector)")
		os.Exit(2)
	}
	sel, attr := os.Args[1], ""
	if i := strings.LastIndex(os.Args[1], "@"); i >= 0 {
		sel, attr = os.Args[1][:i], os.Args[1][i+1:]
	}
	// Compile the selector explicitly. goquery's Find tolerates an invalid
	// selector by matching nothing and succeeding, which is indistinguishable
	// from "no matches" to the agent; the contract says a bad query is exit 2.
	matcher, err := cascadia.Compile(sel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "html: bad CSS selector: %v\n", err)
		os.Exit(2)
	}
	doc, err := goquery.NewDocumentFromReader(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "html: parse: %v\n", err)
		os.Exit(1)
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	doc.FindMatcher(matcher).Each(func(_ int, s *goquery.Selection) {
		if attr != "" {
			if v, ok := s.Attr(attr); ok {
				fmt.Fprintln(out, v)
			}
			return
		}
		fmt.Fprintln(out, strings.TrimSpace(s.Text()))
	})
}
