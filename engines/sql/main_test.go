package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xwb1989/sqlparser"
)

// run parses query, executes it over the JSON rows, and returns the result
// re-encoded as canonical JSON (encoding/json sorts object keys, row order is
// preserved) for compact comparison.
func run(t *testing.T, query, rowsJSON string) string {
	t.Helper()
	out, err := exec(query, rowsJSON)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(b)
}

func exec(query, rowsJSON string) ([]map[string]any, error) {
	stmt, err := sqlparser.Parse(query)
	if err != nil {
		return nil, err
	}
	rows, err := loadRows([]byte(rowsJSON))
	if err != nil {
		return nil, err
	}
	return execSelect(stmt.(*sqlparser.Select), rows)
}

const people = `[
	{"name":"ana","dept":"eng","age":30,"active":true},
	{"name":"bo","dept":"eng","age":25,"active":false},
	{"name":"cy","dept":"sales","age":40,"active":true},
	{"name":"di","dept":"sales","age":35,"active":true},
	{"name":"ed","dept":"ops","age":25,"active":false}
]`

func TestLoadRows(t *testing.T) {
	rows, err := loadRows([]byte(`{"a":1}`))
	if err != nil || len(rows) != 1 {
		t.Fatalf("single object → one row, got %v, %v", rows, err)
	}
	rows, err = loadRows([]byte("  \n"))
	if err != nil || rows != nil {
		t.Fatalf("blank input → no rows, got %v, %v", rows, err)
	}
	if _, err = loadRows([]byte(`"scalar"`)); err == nil {
		t.Fatal("scalar input must be rejected")
	}
	if _, err = loadRows([]byte(`[1,2]`)); err == nil {
		t.Fatal("array of non-objects must be rejected")
	}
}

func TestSelectWhereBasic(t *testing.T) {
	got := run(t, `SELECT name FROM data WHERE dept = 'eng'`, people)
	if got != `[{"name":"ana"},{"name":"bo"}]` {
		t.Fatalf("got %s", got)
	}
}

func TestSelectStarAndAlias(t *testing.T) {
	got := run(t, `SELECT * FROM data WHERE name = 'ed'`, people)
	if got != `[{"active":false,"age":25,"dept":"ops","name":"ed"}]` {
		t.Fatalf("got %s", got)
	}
	got = run(t, `SELECT name AS who FROM data WHERE age > 35`, people)
	if got != `[{"who":"cy"}]` {
		t.Fatalf("alias: got %s", got)
	}
}

func TestWhereOperators(t *testing.T) {
	for _, tc := range []struct{ query, want string }{
		{`SELECT name FROM data WHERE age != 25`, `[{"name":"ana"},{"name":"cy"},{"name":"di"}]`},
		{`SELECT name FROM data WHERE age < 30`, `[{"name":"bo"},{"name":"ed"}]`},
		{`SELECT name FROM data WHERE age >= 35`, `[{"name":"cy"},{"name":"di"}]`},
		{`SELECT name FROM data WHERE age <= 25`, `[{"name":"bo"},{"name":"ed"}]`},
		// JSON booleans compare against 1/0 numerically.
		{`SELECT name FROM data WHERE active = 1`, `[{"name":"ana"},{"name":"cy"},{"name":"di"}]`},
	} {
		if got := run(t, tc.query, people); got != tc.want {
			t.Errorf("%s\n got %s\nwant %s", tc.query, got, tc.want)
		}
	}
}

func TestWhereBoolPrecedence(t *testing.T) {
	// AND binds tighter than OR: eng-rows OR (sales AND age>35) → ana, bo, cy.
	got := run(t, `SELECT name FROM data WHERE dept = 'eng' OR dept = 'sales' AND age > 35`, people)
	if got != `[{"name":"ana"},{"name":"bo"},{"name":"cy"}]` {
		t.Fatalf("AND-over-OR precedence: got %s", got)
	}
	// Parens override: (eng OR sales) AND age>35 → cy only.
	got = run(t, `SELECT name FROM data WHERE (dept = 'eng' OR dept = 'sales') AND age > 35`, people)
	if got != `[{"name":"cy"}]` {
		t.Fatalf("parens: got %s", got)
	}
	// NOT negates its operand.
	got = run(t, `SELECT name FROM data WHERE NOT (dept = 'eng' OR dept = 'sales')`, people)
	if got != `[{"name":"ed"}]` {
		t.Fatalf("NOT: got %s", got)
	}
}

// Rows with nulls and non-numeric junk for the aggregate null-handling paths.
const sparse = `[
	{"g":"a","v":10},
	{"g":"a","v":null},
	{"g":"a","v":20},
	{"g":"b","v":null},
	{"g":"b"},
	{"g":"b","v":"junk"}
]`

func TestAggregatesNullHandling(t *testing.T) {
	// count(*) counts rows; count(col) counts non-null values (a JSON "junk"
	// string is a value, so it counts).
	got := run(t, `SELECT count(*) AS all_rows, count(v) AS vals FROM data`, sparse)
	if got != `[{"all_rows":6,"vals":3}]` {
		t.Fatalf("count: got %s", got)
	}
	// sum/avg fold only numeric values; nulls and non-numeric strings are skipped.
	got = run(t, `SELECT sum(v) AS s, avg(v) AS a FROM data`, sparse)
	if got != `[{"a":15,"s":30}]` {
		t.Fatalf("sum/avg: got %s", got)
	}
	// min/max skip nulls ("junk" still participates via compareVals string order).
	got = run(t, `SELECT min(v) AS lo, max(v) AS hi FROM data WHERE g = 'a'`, sparse)
	if got != `[{"hi":20,"lo":10}]` {
		t.Fatalf("min/max: got %s", got)
	}
	// avg over zero numeric values is null, min/max over all-null is null,
	// sum over nothing is 0.
	got = run(t, `SELECT avg(v) AS a, min(v) AS lo, sum(v) AS s FROM data WHERE g = 'zzz'`, sparse)
	if got != `[{"a":null,"lo":null,"s":0}]` {
		t.Fatalf("empty group: got %s", got)
	}
}

func TestGroupBy(t *testing.T) {
	// Groups keep first-seen order; unaliased aggregates are named by their SQL text.
	got := run(t, `SELECT dept, count(*) FROM data GROUP BY dept`, people)
	if got != `[{"count(*)":2,"dept":"eng"},{"count(*)":2,"dept":"sales"},{"count(*)":1,"dept":"ops"}]` {
		t.Fatalf("group by: got %s", got)
	}
	// Aggregate without GROUP BY collapses to a single row.
	got = run(t, `SELECT count(*) AS n, sum(age) AS total FROM data`, people)
	if got != `[{"n":5,"total":155}]` {
		t.Fatalf("no group by: got %s", got)
	}
}

func TestGroupByCompositeKey(t *testing.T) {
	got := run(t, `SELECT dept, active, count(*) AS n FROM data GROUP BY dept, active`, people)
	want := `[{"active":true,"dept":"eng","n":1},{"active":false,"dept":"eng","n":1},{"active":true,"dept":"sales","n":2},{"active":false,"dept":"ops","n":1}]`
	if got != want {
		t.Fatalf("composite key:\n got %s\nwant %s", got, want)
	}
	// The key separator must keep ("ab","c") and ("a","bc") in distinct groups —
	// naive concatenation would merge them.
	rows := `[{"a":"ab","b":"c"},{"a":"a","b":"bc"}]`
	got = run(t, `SELECT a, b, count(*) AS n FROM data GROUP BY a, b`, rows)
	if got != `[{"a":"ab","b":"c","n":1},{"a":"a","b":"bc","n":1}]` {
		t.Fatalf("key collision: got %s", got)
	}
}

func TestOrderByAndLimit(t *testing.T) {
	// ORDER BY resolves against the PROJECTED row (ordering runs after
	// projection), so the sort column must appear in the SELECT list — that is
	// what lets aggregate aliases sort below. Equal keys keep input order
	// (stable sort): bo before ed at age 25.
	got := run(t, `SELECT name, age FROM data ORDER BY age`, people)
	if got != `[{"age":25,"name":"bo"},{"age":25,"name":"ed"},{"age":30,"name":"ana"},{"age":35,"name":"di"},{"age":40,"name":"cy"}]` {
		t.Fatalf("asc: got %s", got)
	}
	got = run(t, `SELECT name, age FROM data ORDER BY age DESC`, people)
	if got != `[{"age":40,"name":"cy"},{"age":35,"name":"di"},{"age":30,"name":"ana"},{"age":25,"name":"bo"},{"age":25,"name":"ed"}]` {
		t.Fatalf("desc: got %s", got)
	}
	got = run(t, `SELECT name, age FROM data ORDER BY age DESC LIMIT 2`, people)
	if got != `[{"age":40,"name":"cy"},{"age":35,"name":"di"}]` {
		t.Fatalf("limit: got %s", got)
	}
	// Pin the flip side of output-row resolution: ordering by a column that was
	// NOT selected finds no key and leaves input order untouched.
	got = run(t, `SELECT name FROM data ORDER BY age DESC`, people)
	if got != `[{"name":"ana"},{"name":"bo"},{"name":"cy"},{"name":"di"},{"name":"ed"}]` {
		t.Fatalf("unprojected order key: got %s", got)
	}
	got = run(t, `SELECT name FROM data LIMIT 0`, people)
	if got != `[]` {
		t.Fatalf("limit 0: got %s", got)
	}
	// ORDER BY sees the projected output row, so aggregate aliases sort.
	got = run(t, `SELECT dept, count(*) AS n FROM data GROUP BY dept ORDER BY n DESC, dept`, people)
	if got != `[{"dept":"eng","n":2},{"dept":"sales","n":2},{"dept":"ops","n":1}]` {
		t.Fatalf("order by alias: got %s", got)
	}
}

func TestSelectStarWithGroupByRejected(t *testing.T) {
	_, err := exec(`SELECT * FROM data GROUP BY dept`, people)
	if err == nil || !strings.Contains(err.Error(), "SELECT * is not allowed") {
		t.Fatalf("want SELECT*+GROUP BY rejection, got %v", err)
	}
	_, err = exec(`SELECT *, count(*) FROM data`, people)
	if err == nil || !strings.Contains(err.Error(), "SELECT * is not allowed") {
		t.Fatalf("want SELECT*+aggregate rejection, got %v", err)
	}
}

func TestUnsupportedConstructs(t *testing.T) {
	if _, err := exec(`SELECT name FROM data WHERE name LIKE 'a%'`, people); err == nil {
		t.Fatal("LIKE is unsupported and must error")
	}
	if _, err := exec(`SELECT dept FROM data GROUP BY dept ORDER BY count(*)`, people); err == nil {
		t.Fatal("ORDER BY on an expression must error")
	}
}

// Numeric-string coercion: compareVals compares numerically whenever BOTH sides
// parse as numbers (JSON numbers, numeric strings, bools). This is intended,
// SQLite-affinity-like behavior — pin it, including the leading-zero
// consequence: '02134' and 2134 are the same key.
func TestNumericStringCoercion(t *testing.T) {
	rows := `[{"name":"a","zip":"02134"},{"name":"b","zip":"2134"},{"name":"c","zip":2134},{"name":"d","zip":"90210"}]`
	// A string literal against numeric strings compares numerically: all three
	// spellings of 2134 match.
	got := run(t, `SELECT name FROM data WHERE zip = '02134'`, rows)
	if got != `[{"name":"a"},{"name":"b"},{"name":"c"}]` {
		t.Fatalf("zip = '02134': got %s", got)
	}
	// A numeric literal matches numeric strings too.
	got = run(t, `SELECT name FROM data WHERE zip = 2134`, rows)
	if got != `[{"name":"a"},{"name":"b"},{"name":"c"}]` {
		t.Fatalf("zip = 2134: got %s", got)
	}
	// Ordering of numeric strings is numeric, not lexicographic
	// ("90210" > "02134" numerically; lexicographically "0..." < "9...").
	// Stable sort keeps a before b (both 2134).
	got = run(t, `SELECT name, zip FROM data WHERE name != 'c' ORDER BY zip DESC`, rows)
	if got != `[{"name":"d","zip":"90210"},{"name":"a","zip":"02134"},{"name":"b","zip":"2134"}]` {
		t.Fatalf("numeric order: got %s", got)
	}
}

func TestCompareVals(t *testing.T) {
	for _, tc := range []struct {
		a, b any
		want int
	}{
		{float64(1), float64(2), -1},
		{float64(2), float64(2), 0},
		{"02134", float64(2134), 0}, // leading-zero string coerces numerically
		{"10", "9", 1},              // both numeric strings → numeric order
		{true, float64(1), 0},       // bools coerce to 1/0
		{false, true, -1},
		{"abc", float64(1), 1}, // non-numeric side → string compare ("abc" > "1")
		{"a", "b", -1},
		{nil, nil, 0}, // both print "<nil>" → equal as strings
	} {
		if got := compareVals(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVals(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestToFloat(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want float64
		ok   bool
	}{
		{float64(1.5), 1.5, true},
		{int(3), 3, true},
		{int64(4), 4, true},
		{true, 1, true},
		{false, 0, true},
		{json.Number("2.5"), 2.5, true},
		{"02134", 2134, true},
		{"1e3", 1000, true},
		{"junk", 0, false},
		{"", 0, false},
		{nil, 0, false},
	} {
		got, ok := toFloat(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("toFloat(%#v) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
