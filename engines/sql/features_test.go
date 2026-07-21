package main

import (
	"strings"
	"testing"
)

// HAVING filters groups by their aggregate — previously parsed and silently ignored.
func TestHavingFiltersGroups(t *testing.T) {
	in := `[{"u":"a"},{"u":"a"},{"u":"b"},{"u":"c"},{"u":"c"},{"u":"c"}]`
	if got := run(t, `SELECT u, count(*) AS n FROM data GROUP BY u HAVING count(*) > 2`, in); got != `[{"n":3,"u":"c"}]` {
		t.Fatalf("HAVING: got %s", got)
	}
	// HAVING can compare an aggregate on both sides and reference a group column.
	if got := run(t, `SELECT u, count(*) AS n FROM data GROUP BY u HAVING count(*) >= 2`, in); got != `[{"n":2,"u":"a"},{"n":3,"u":"c"}]` {
		t.Fatalf("HAVING >=: got %s", got)
	}
}

// SELECT DISTINCT dedupes rows — previously parsed and ignored.
func TestSelectDistinct(t *testing.T) {
	in := `[{"host":"a"},{"host":"b"},{"host":"a"},{"host":"a"}]`
	if got := run(t, `SELECT DISTINCT host FROM data`, in); got != `[{"host":"a"},{"host":"b"}]` {
		t.Fatalf("DISTINCT: got %s", got)
	}
	// DISTINCT over multiple projected columns dedupes on the whole row.
	in2 := `[{"a":1,"b":1},{"a":1,"b":1},{"a":1,"b":2}]`
	if got := run(t, `SELECT DISTINCT a, b FROM data`, in2); got != `[{"a":1,"b":1},{"a":1,"b":2}]` {
		t.Fatalf("DISTINCT multi: got %s", got)
	}
}

// count(DISTINCT col) counts distinct non-null values — previously the DISTINCT
// was ignored and it counted every non-null.
func TestCountDistinct(t *testing.T) {
	in := `[{"u":"a"},{"u":"a"},{"u":"b"},{"u":null}]`
	if got := run(t, `SELECT count(DISTINCT u) AS n, count(u) AS cnt FROM data`, in); got != `[{"cnt":3,"n":2}]` {
		t.Fatalf("count DISTINCT: got %s", got)
	}
}

// OFFSET skips rows before LIMIT — previously parsed and ignored.
func TestLimitOffset(t *testing.T) {
	in := `[{"x":1},{"x":2},{"x":3},{"x":4},{"x":5}]`
	if got := run(t, `SELECT x FROM data ORDER BY x LIMIT 2 OFFSET 1`, in); got != `[{"x":2},{"x":3}]` {
		t.Fatalf("LIMIT OFFSET: got %s", got)
	}
	// OFFSET past the end yields no rows.
	if got := run(t, `SELECT x FROM data ORDER BY x LIMIT 2 OFFSET 99`, in); got != `[]` {
		t.Fatalf("OFFSET past end: got %s", got)
	}
}

// A comparison against a NULL/absent column is UNKNOWN, so `col != 'x'` excludes
// rows lacking col (SQL three-valued logic) — previously they were wrongly kept
// because a missing column stringified to "<nil>" and compared unequal to 'x'.
func TestNullComparisonThreeValued(t *testing.T) {
	in := `[{"c":"x"},{"c":"y"},{"other":1},{"c":null}]`
	if got := run(t, `SELECT c FROM data WHERE c != 'x'`, in); got != `[{"c":"y"}]` {
		t.Fatalf("c != 'x' with nulls: got %s", got)
	}
	if got := run(t, `SELECT c FROM data WHERE c = 'x'`, in); got != `[{"c":"x"}]` {
		t.Fatalf("c = 'x' with nulls: got %s", got)
	}
	// NOT over UNKNOWN stays UNKNOWN (not TRUE): the null-c rows are not resurrected.
	if got := run(t, `SELECT c FROM data WHERE NOT (c = 'x')`, in); got != `[{"c":"y"}]` {
		t.Fatalf("NOT(c='x') with nulls: got %s", got)
	}
	// UNKNOWN in AND/OR follows Kleene logic: FALSE AND UNKNOWN = FALSE.
	if got := run(t, `SELECT c FROM data WHERE c = 'x' AND c != 'x'`, in); got != `[]` {
		t.Fatalf("contradiction: got %s", got)
	}
}

// Constructs that are parsed but can't be executed faithfully are rejected, not
// silently mis-run.
func TestNewlyRejectedConstructs(t *testing.T) {
	people := `[{"dept":"eng"}]`
	if _, err := exec(`SELECT DISTINCT dept, count(*) FROM data GROUP BY dept`, people); err == nil {
		t.Fatal("SELECT DISTINCT with GROUP BY must be rejected")
	}
	if _, err := exec(`SELECT dept FROM data HAVING count(*) > 0`, people); err == nil || !strings.Contains(err.Error(), "HAVING requires GROUP BY") {
		t.Fatalf("HAVING without GROUP BY must be rejected, got %v", err)
	}
}
