// Command sql is a wasip1 query engine for microagency's wasm-compute substrate.
// It runs a SELECT (argv[1]) over JSON rows read from stdin and writes the result
// rows as JSON to stdout. The fetched data is the table — name it anything in
// FROM (e.g. `FROM data`); the engine ignores the table name and uses stdin.
//
// Real SQL engines don't compile to wasip1 (sqlite's transpiled libc, and the
// pure-Go engines' dep trees, exclude the target), so this parses with
// xwb1989/sqlparser and executes a focused subset itself — pure compute over the
// bytes the host fetched cred-blind, with no storage backend.
//
// Supported: SELECT (columns, *, DISTINCT, and the aggregates
// count/sum/avg/min/max, including count(DISTINCT col)), WHERE (= != < > <= >=
// with AND/OR/NOT/parens and SQL three-valued NULL logic), GROUP BY, HAVING,
// ORDER BY, LIMIT, and OFFSET. Input is a JSON array of objects (or a single
// object). Value comparison uses numeric affinity: numbers, bools, and
// numeric-looking strings compare numerically (see compareVals). A clause the
// parser accepts but this engine can't execute faithfully is rejected, never
// silently ignored.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/xwb1989/sqlparser"
)

func main() {
	if len(os.Args) < 2 {
		die(2, "sql: missing query (argv[1])")
	}
	stmt, err := sqlparser.Parse(os.Args[1])
	if err != nil {
		die(2, "sql: parse: %v", err)
	}
	sel, ok := stmt.(*sqlparser.Select)
	if !ok {
		die(2, "sql: only SELECT is supported")
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		die(1, "sql: read input: %v", err)
	}
	rows, err := loadRows(raw)
	if err != nil {
		die(1, "sql: %v", err)
	}
	result, err := execSelect(sel, rows)
	if err != nil {
		die(2, "sql: %v", err) // an execSelect error is a bad/unsupported query
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		die(1, "sql: encode: %v", err)
	}
}

func die(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(code)
}

func loadRows(raw []byte) ([]map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	switch raw[0] {
	case '[':
		var arr []map[string]any
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("input must be a JSON array of objects: %v", err)
		}
		return arr, nil
	case '{':
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("input must be a JSON object: %v", err)
		}
		return []map[string]any{obj}, nil
	}
	return nil, fmt.Errorf("input must be JSON (an array of objects, or an object)")
}

func execSelect(sel *sqlparser.Select, rows []map[string]any) ([]map[string]any, error) {
	if sel.Where != nil {
		kept := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			t, err := evalBoolWith(sel.Where.Expr, rowResolver(r))
			if err != nil {
				return nil, err
			}
			if t == triTrue { // NULL/UNKNOWN rows are excluded, per SQL
				kept = append(kept, r)
			}
		}
		rows = kept
	}

	var out []map[string]any
	var err error
	if selectHasAggregate(sel.SelectExprs) || len(sel.GroupBy) > 0 {
		if out, err = aggregate(sel, rows); err != nil { // includes HAVING
			return nil, err
		}
	} else {
		if sel.Having != nil {
			return nil, fmt.Errorf("HAVING requires GROUP BY or an aggregate")
		}
		if out, err = project(sel.SelectExprs, rows); err != nil {
			return nil, err
		}
		if sel.Distinct != "" {
			out = distinctRows(out)
		}
	}

	// ORDER BY resolves against the projected output row (ordering runs after
	// projection), so the sort column must be one the query produced.
	if len(sel.OrderBy) > 0 {
		if err := orderBy(out, sel.OrderBy); err != nil {
			return nil, err
		}
	}
	return applyLimit(sel.Limit, out)
}

// applyLimit applies OFFSET then LIMIT: skip the first Offset rows, then keep at
// most Rowcount. Both are optional and must be non-negative integers. (OFFSET was
// previously parsed and ignored — a silently wrong window.)
func applyLimit(limit *sqlparser.Limit, out []map[string]any) ([]map[string]any, error) {
	if limit == nil {
		return out, nil
	}
	if limit.Offset != nil {
		off, err := intVal(limit.Offset)
		if err != nil {
			return nil, err
		}
		if off < 0 {
			return nil, fmt.Errorf("OFFSET must be non-negative")
		}
		if off >= len(out) {
			return []map[string]any{}, nil
		}
		out = out[off:]
	}
	if limit.Rowcount != nil {
		n, err := intVal(limit.Rowcount)
		if err != nil {
			return nil, err
		}
		if n >= 0 && n < len(out) {
			out = out[:n]
		}
	}
	return out, nil
}

func project(exprs sqlparser.SelectExprs, rows []map[string]any) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		o := map[string]any{}
		for _, se := range exprs {
			switch e := se.(type) {
			case *sqlparser.StarExpr:
				for k, v := range r {
					o[k] = v
				}
			case *sqlparser.AliasedExpr:
				col, ok := e.Expr.(*sqlparser.ColName)
				if !ok {
					return nil, fmt.Errorf("SELECT supports column names, *, and aggregates")
				}
				name := col.Name.String()
				key := name
				if !e.As.IsEmpty() {
					key = e.As.String()
				}
				o[key] = r[name]
			default:
				return nil, fmt.Errorf("unsupported SELECT expression")
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// distinctRows drops duplicate projected rows, keeping first-seen order. Canonical
// JSON (encoding/json sorts map keys) makes the identity comparison exact.
// (SELECT DISTINCT was previously parsed and ignored.)
func distinctRows(rows []map[string]any) []map[string]any {
	seen := make(map[string]bool, len(rows))
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		b, _ := json.Marshal(r)
		if !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, r)
		}
	}
	return out
}

func aggregate(sel *sqlparser.Select, rows []map[string]any) ([]map[string]any, error) {
	if sel.Distinct != "" {
		return nil, fmt.Errorf("SELECT DISTINCT with GROUP BY/aggregates is not supported")
	}
	groupCols := make([]string, 0, len(sel.GroupBy))
	for _, g := range sel.GroupBy {
		col, ok := g.(*sqlparser.ColName)
		if !ok {
			return nil, fmt.Errorf("GROUP BY supports column names only")
		}
		groupCols = append(groupCols, col.Name.String())
	}

	type group struct {
		cols map[string]any
		rows []map[string]any
	}
	order := []string{}
	groups := map[string]*group{}
	for _, r := range rows {
		var kb strings.Builder
		gc := map[string]any{}
		for _, c := range groupCols {
			fmt.Fprintf(&kb, "%v\x00", r[c])
			gc[c] = r[c]
		}
		key := kb.String()
		g := groups[key]
		if g == nil {
			g = &group{cols: gc}
			groups[key] = g
			order = append(order, key)
		}
		g.rows = append(g.rows, r)
	}
	if len(groupCols) == 0 { // aggregates with no GROUP BY → one group of all rows
		order = []string{""}
		groups = map[string]*group{"": {cols: map[string]any{}, rows: rows}}
	}

	out := make([]map[string]any, 0, len(order))
	for _, key := range order {
		g := groups[key]
		o := map[string]any{}
		for _, se := range sel.SelectExprs {
			ae, ok := se.(*sqlparser.AliasedExpr)
			if !ok {
				return nil, fmt.Errorf("SELECT * is not allowed with GROUP BY/aggregates")
			}
			name, val, err := evalAggOrCol(ae, g.cols, g.rows)
			if err != nil {
				return nil, err
			}
			o[name] = val
		}
		if sel.Having != nil { // filter groups by their aggregate (was parsed and ignored)
			t, err := evalBoolWith(sel.Having.Expr, havingResolver(g.cols, g.rows))
			if err != nil {
				return nil, err
			}
			if t != triTrue { // exclude groups that are false OR unknown
				continue
			}
		}
		out = append(out, o)
	}
	return out, nil
}

func evalAggOrCol(ae *sqlparser.AliasedExpr, groupCols map[string]any, rows []map[string]any) (string, any, error) {
	name := ""
	if !ae.As.IsEmpty() {
		name = ae.As.String()
	}
	switch e := ae.Expr.(type) {
	case *sqlparser.FuncExpr:
		if name == "" {
			name = sqlparser.String(e)
		}
		v, err := computeAgg(e.Name.Lowered(), e.Exprs, e.Distinct, rows)
		return name, v, err
	case *sqlparser.ColName:
		col := e.Name.String()
		if name == "" {
			name = col
		}
		return name, groupCols[col], nil
	}
	return "", nil, fmt.Errorf("SELECT with GROUP BY supports group columns and aggregates")
}

func computeAgg(fn string, exprs sqlparser.SelectExprs, distinct bool, rows []map[string]any) (any, error) {
	star, col := false, ""
	if len(exprs) == 1 {
		switch a := exprs[0].(type) {
		case *sqlparser.StarExpr:
			star = true
		case *sqlparser.AliasedExpr:
			c, ok := a.Expr.(*sqlparser.ColName)
			if !ok {
				return nil, fmt.Errorf("%s(...) supports a column or *", fn)
			}
			col = c.Name.String()
		}
	}
	if star && distinct {
		return nil, fmt.Errorf("%s(DISTINCT *) is not supported", fn)
	}
	// values gathers the non-null column values the aggregate folds over,
	// de-duplicated when DISTINCT is set (count(DISTINCT col) etc. — previously the
	// DISTINCT was parsed and ignored). count(*) is handled separately.
	values := func() []any {
		var vs []any
		var seen map[string]bool
		if distinct {
			seen = map[string]bool{}
		}
		for _, r := range rows {
			v := r[col]
			if v == nil {
				continue
			}
			if distinct {
				k, _ := json.Marshal(v)
				if seen[string(k)] {
					continue
				}
				seen[string(k)] = true
			}
			vs = append(vs, v)
		}
		return vs
	}
	switch fn {
	case "count":
		if star {
			return float64(len(rows)), nil // count(*) counts rows, nulls included
		}
		return float64(len(values())), nil
	case "sum", "avg":
		sum, n := 0.0, 0
		for _, v := range values() {
			if f, ok := toFloat(v); ok {
				sum += f
				n++
			}
		}
		if fn == "avg" {
			if n == 0 {
				return nil, nil
			}
			return sum / float64(n), nil
		}
		return sum, nil
	case "min", "max":
		var best any
		for _, v := range values() {
			if best == nil {
				best = v
				continue
			}
			c := compareVals(best, v)
			if (fn == "min" && c > 0) || (fn == "max" && c < 0) {
				best = v
			}
		}
		return best, nil
	}
	return nil, fmt.Errorf("unsupported aggregate %q", fn)
}

// tri is SQL three-valued logic: TRUE, FALSE, or UNKNOWN (a comparison touching
// NULL). WHERE and HAVING keep only TRUE; NOT UNKNOWN is UNKNOWN, so collapsing
// NULL to false (as the old code did) made `col != 'x'` wrongly keep rows where
// col is absent.
type tri uint8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func (t tri) not() tri {
	switch t {
	case triTrue:
		return triFalse
	case triFalse:
		return triTrue
	default:
		return triUnknown
	}
}

func andTri(a, b tri) tri {
	if a == triFalse || b == triFalse {
		return triFalse
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triTrue
}

func orTri(a, b tri) tri {
	if a == triTrue || b == triTrue {
		return triTrue
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triFalse
}

// resolver evaluates a leaf expression (a column, literal, or — for HAVING — an
// aggregate) to a concrete value. WHERE and HAVING share evalBoolWith and differ
// only in how leaves resolve.
type resolver func(sqlparser.Expr) (any, error)

func rowResolver(r map[string]any) resolver {
	return func(expr sqlparser.Expr) (any, error) {
		if col, ok := expr.(*sqlparser.ColName); ok {
			return r[col.Name.String()], nil
		}
		return literalVal(expr)
	}
}

func havingResolver(groupCols map[string]any, rows []map[string]any) resolver {
	return func(expr sqlparser.Expr) (any, error) {
		switch e := expr.(type) {
		case *sqlparser.FuncExpr:
			return computeAgg(e.Name.Lowered(), e.Exprs, e.Distinct, rows)
		case *sqlparser.ColName:
			return groupCols[e.Name.String()], nil // HAVING may reference group columns
		}
		return literalVal(expr)
	}
}

func evalBoolWith(expr sqlparser.Expr, val resolver) (tri, error) {
	switch e := expr.(type) {
	case *sqlparser.AndExpr:
		l, err := evalBoolWith(e.Left, val)
		if err != nil {
			return triFalse, err
		}
		if l == triFalse {
			return triFalse, nil
		}
		r, err := evalBoolWith(e.Right, val)
		if err != nil {
			return triFalse, err
		}
		return andTri(l, r), nil
	case *sqlparser.OrExpr:
		l, err := evalBoolWith(e.Left, val)
		if err != nil {
			return triFalse, err
		}
		if l == triTrue {
			return triTrue, nil
		}
		r, err := evalBoolWith(e.Right, val)
		if err != nil {
			return triFalse, err
		}
		return orTri(l, r), nil
	case *sqlparser.ParenExpr:
		return evalBoolWith(e.Expr, val)
	case *sqlparser.NotExpr:
		v, err := evalBoolWith(e.Expr, val)
		return v.not(), err
	case *sqlparser.ComparisonExpr:
		return evalComparison(e, val)
	}
	return triFalse, fmt.Errorf("unsupported boolean expression")
}

func evalComparison(e *sqlparser.ComparisonExpr, val resolver) (tri, error) {
	l, err := val(e.Left)
	if err != nil {
		return triFalse, err
	}
	rt, err := val(e.Right)
	if err != nil {
		return triFalse, err
	}
	if l == nil || rt == nil { // any comparison with NULL is UNKNOWN
		return triUnknown, nil
	}
	c := compareVals(l, rt)
	var b bool
	switch e.Operator {
	case sqlparser.EqualStr:
		b = c == 0
	case sqlparser.NotEqualStr:
		b = c != 0
	case sqlparser.LessThanStr:
		b = c < 0
	case sqlparser.GreaterThanStr:
		b = c > 0
	case sqlparser.LessEqualStr:
		b = c <= 0
	case sqlparser.GreaterEqualStr:
		b = c >= 0
	default:
		return triFalse, fmt.Errorf("unsupported operator %q", e.Operator)
	}
	if b {
		return triTrue, nil
	}
	return triFalse, nil
}

// literalVal evaluates a non-column literal: a number, string, NULL, or bool.
func literalVal(expr sqlparser.Expr) (any, error) {
	switch e := expr.(type) {
	case *sqlparser.SQLVal:
		if e.Type == sqlparser.IntVal || e.Type == sqlparser.FloatVal {
			return strconv.ParseFloat(string(e.Val), 64)
		}
		return string(e.Val), nil
	case *sqlparser.NullVal:
		return nil, nil
	case sqlparser.BoolVal:
		return bool(e), nil
	}
	return nil, fmt.Errorf("unsupported value in WHERE/HAVING")
}

func orderBy(rows []map[string]any, ob sqlparser.OrderBy) error {
	type key struct {
		col  string
		desc bool
	}
	keys := make([]key, 0, len(ob))
	for _, o := range ob {
		col, ok := o.Expr.(*sqlparser.ColName)
		if !ok {
			return fmt.Errorf("ORDER BY supports column names only")
		}
		keys = append(keys, key{col.Name.String(), o.Direction == sqlparser.DescScr})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		for _, k := range keys {
			c := compareVals(rows[i][k.col], rows[j][k.col])
			if c == 0 {
				continue
			}
			if k.desc {
				return c > 0
			}
			return c < 0
		}
		return false
	})
	return nil
}

func intVal(expr sqlparser.Expr) (int, error) {
	v, ok := expr.(*sqlparser.SQLVal)
	if !ok || v.Type != sqlparser.IntVal {
		return 0, fmt.Errorf("LIMIT/OFFSET must be an integer")
	}
	return strconv.Atoi(string(v.Val))
}

func selectHasAggregate(exprs sqlparser.SelectExprs) bool {
	for _, se := range exprs {
		if ae, ok := se.(*sqlparser.AliasedExpr); ok {
			if _, ok := ae.Expr.(*sqlparser.FuncExpr); ok {
				return true
			}
		}
	}
	return false
}

// compareVals orders two values: numerically when both are numeric (numbers,
// numeric strings, or bools), otherwise as strings. Numeric affinity is
// intentional — see TestNumericStringCoercion.
func compareVals(a, b any) int {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			switch {
			case af < bf:
				return -1
			case af > bf:
				return 1
			default:
				return 0
			}
		}
	}
	return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}
