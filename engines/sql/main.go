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
// Supported: SELECT (columns, *, and the aggregates count/sum/avg/min/max),
// WHERE (= != < > <= >= combined with AND/OR/NOT/parens), GROUP BY, ORDER BY,
// LIMIT. Input is a JSON array of objects (or a single object).
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
		die(1, "sql: %v", err)
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
			ok, err := evalBool(sel.Where.Expr, r)
			if err != nil {
				return nil, err
			}
			if ok {
				kept = append(kept, r)
			}
		}
		rows = kept
	}

	var out []map[string]any
	var err error
	if selectHasAggregate(sel.SelectExprs) || len(sel.GroupBy) > 0 {
		out, err = aggregate(sel, rows)
	} else {
		out, err = project(sel.SelectExprs, rows)
	}
	if err != nil {
		return nil, err
	}

	if len(sel.OrderBy) > 0 {
		if err := orderBy(out, sel.OrderBy); err != nil {
			return nil, err
		}
	}
	if sel.Limit != nil && sel.Limit.Rowcount != nil {
		n, err := intVal(sel.Limit.Rowcount)
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

func aggregate(sel *sqlparser.Select, rows []map[string]any) ([]map[string]any, error) {
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
		v, err := computeAgg(e.Name.Lowered(), e.Exprs, rows)
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

func computeAgg(fn string, exprs sqlparser.SelectExprs, rows []map[string]any) (any, error) {
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
	switch fn {
	case "count":
		if star {
			return float64(len(rows)), nil
		}
		n := 0
		for _, r := range rows {
			if r[col] != nil {
				n++
			}
		}
		return float64(n), nil
	case "sum", "avg":
		sum, n := 0.0, 0
		for _, r := range rows {
			if f, ok := toFloat(r[col]); ok {
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
		for _, r := range rows {
			v := r[col]
			if v == nil {
				continue
			}
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

func evalBool(expr sqlparser.Expr, r map[string]any) (bool, error) {
	switch e := expr.(type) {
	case *sqlparser.AndExpr:
		l, err := evalBool(e.Left, r)
		if err != nil || !l {
			return false, err
		}
		return evalBool(e.Right, r)
	case *sqlparser.OrExpr:
		l, err := evalBool(e.Left, r)
		if err != nil || l {
			return l, err
		}
		return evalBool(e.Right, r)
	case *sqlparser.ParenExpr:
		return evalBool(e.Expr, r)
	case *sqlparser.NotExpr:
		v, err := evalBool(e.Expr, r)
		return !v, err
	case *sqlparser.ComparisonExpr:
		return evalComparison(e, r)
	}
	return false, fmt.Errorf("unsupported WHERE expression")
}

func evalComparison(e *sqlparser.ComparisonExpr, r map[string]any) (bool, error) {
	l, err := evalVal(e.Left, r)
	if err != nil {
		return false, err
	}
	rt, err := evalVal(e.Right, r)
	if err != nil {
		return false, err
	}
	c := compareVals(l, rt)
	switch e.Operator {
	case sqlparser.EqualStr:
		return c == 0, nil
	case sqlparser.NotEqualStr:
		return c != 0, nil
	case sqlparser.LessThanStr:
		return c < 0, nil
	case sqlparser.GreaterThanStr:
		return c > 0, nil
	case sqlparser.LessEqualStr:
		return c <= 0, nil
	case sqlparser.GreaterEqualStr:
		return c >= 0, nil
	}
	return false, fmt.Errorf("unsupported operator %q", e.Operator)
}

func evalVal(expr sqlparser.Expr, r map[string]any) (any, error) {
	switch e := expr.(type) {
	case *sqlparser.ColName:
		return r[e.Name.String()], nil
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
	return nil, fmt.Errorf("unsupported value in WHERE")
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
		return 0, fmt.Errorf("LIMIT must be an integer")
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
// numeric strings, or bools), otherwise as strings.
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
