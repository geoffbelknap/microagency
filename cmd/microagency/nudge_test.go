package main

import "testing"

func TestParseFormulaVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"class MicroagencyLatest < Formula\n  version \"0.1.2-latest.8\"\n  depends_on \"openbao\"\n", "0.1.2-latest.8"},
		{"  version \"1.2.3\"\n", "1.2.3"},
		{"no version line here", ""},
		{"version \"unterminated", ""},
	}
	for _, c := range cases {
		if got := parseFormulaVersion(c.in); got != c.want {
			t.Errorf("parseFormulaVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
