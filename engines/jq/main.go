// Command jq is a wasip1 query engine for microagency's wasm-compute substrate.
// It runs a jq program (argv[1]) over JSON read from stdin and writes each result
// as compact JSON to stdout. Pure Go (gojq), so it compiles to wasip1 and runs in
// pkg/sandbox — no network, no credentials: pure compute over bytes the host has
// already fetched cred-blind.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/itchyny/gojq"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "jq: missing query (argv[1])")
		os.Exit(2)
	}
	// INVARIANT: exit 2 must happen before the first stdin read. The host
	// returns exit-2 stderr to the caller as their own query text; anything
	// emitted after data has been read must exit 1, whose stderr stays
	// operator-only.
	query, err := gojq.Parse(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "jq: parse query: %v\n", err)
		os.Exit(2)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "jq: read input: %v\n", err)
		os.Exit(1)
	}
	var input any
	if err := json.Unmarshal(data, &input); err != nil {
		fmt.Fprintf(os.Stderr, "jq: input is not valid JSON: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	iter := query.Run(input)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			fmt.Fprintf(os.Stderr, "jq: %v\n", err)
			os.Exit(1)
		}
		if err := enc.Encode(v); err != nil {
			fmt.Fprintf(os.Stderr, "jq: encode: %v\n", err)
			os.Exit(1)
		}
	}
}
