package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"microagency/internal/budget"
	"microagency/internal/refstore"
	"microagency/internal/router"
	"microagency/internal/sandbox"
	"microagency/internal/wasmexec"
)

// reduceInputs maps resolved reference payloads to guest input files: a single ref
// lands at /app/input (back-compat), several at /app/input_1..N (so code can
// join/correlate across multiple large results).
func reduceInputs(payloads []string) []sandbox.Input {
	if len(payloads) == 1 {
		return []sandbox.Input{{Data: []byte(payloads[0]), Path: "/app/input"}}
	}
	inputs := make([]sandbox.Input, len(payloads))
	for i, p := range payloads {
		inputs[i] = sandbox.Input{Data: []byte(p), Path: fmt.Sprintf("/app/input_%d", i+1)}
	}
	return inputs
}

// toolDefs is the tools/list payload — the surface a stock MCP client sees.
func toolDefs() []map[string]any {
	strProp := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	return []map[string]any{
		{
			"name":        "reduce",
			"description": "Compute over stored result references OR small inline data, off-context, returning only the result. Inputs (choose one): `ref` (one <ref_> handle from a large tool result), `refs` (several — to JOIN/correlate/diff across multiple large results), or `data` (small inline JSON/text you already have). Then EITHER a `query` (a declarative reduction over a SINGLE input — you need not name the `engine`, it's inferred) OR `code` (Python that reads the input from /app/input, or /app/input_1..N when you passed multiple refs, and prints the result). Use `data` for EXACT DETERMINISTIC work the model is unreliable at even when the data is small and already in context — exact/big-number arithmetic, money-precision decimals, date & timezone math, unit conversions, hashing/encoding, parsing — do it here deterministically, don't compute it in your head. Use `ref`/`refs` to shape or combine large results without pulling them into context (a large reduction is itself returned as a new reference). Pick the engine by shape: sql for tabular/aggregate work, jq for structured JSON; multiple inputs, large data, regex, or non-trivial logic → code.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ref":    strProp("a reference handle like <ref_3> from a prior result"),
					"refs":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "several reference handles to combine with code; read at /app/input_1..N in guest order"},
					"data":   strProp("small inline JSON/text to compute over exactly — for deterministic ops (hash, date/timezone math, unit conversion, exact arithmetic, parsing); large data should be a reference instead"),
					"query":  strProp("a declarative reduction over a single input (sql/jq/text/html)"),
					"engine": strProp("optional query language: sql | jq | text | html — inferred from the query if omitted"),
					"code":   strProp("Python that reads the input from /app/input (or /app/input_1..N for multiple refs) and prints the result; required to combine several refs"),
				},
			},
		},
		{
			"name":        "find_tools",
			"description": "Discover aggregated upstream tools by keyword. These tools are NOT in your tool list (kept out of context on purpose); search here to find the relevant few. Returns each tool's name, description, and inputSchema. To use one, call `call_tool` with its name and arguments.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": strProp("what you want to do, in keywords"),
					"limit": map[string]any{"type": "integer", "description": "max results (default 10)"},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "call_tool",
			"description": "Invoke a tool discovered via find_tools. Pass its `name` and `arguments` (matching the tool's inputSchema). Use this for aggregated upstream tools, which aren't in your tool list.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":      strProp("the tool name from find_tools"),
					"arguments": map[string]any{"type": "object", "description": "arguments matching the tool's inputSchema"},
				},
				"required": []string{"name"},
			},
		},
	}
}

// toolResult builds a successful tools/call result carrying one JSON text block.
func toolResult(payload any) map[string]any {
	b, err := json.Marshal(payload)
	if err != nil {
		return toolError("internal: marshal result: %v", err)
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
		"isError": false,
	}
}

// toolError builds an error tools/call result (isError=true, not a protocol error).
func toolError(format string, args ...any) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": fmt.Sprintf(format, args...)}},
		"isError": true,
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolCall(ctx context.Context, req rpcRequest) rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	var result map[string]any
	switch p.Name {
	case "reduce":
		result = s.reduce(ctx, p.Arguments)
	case "find_tools":
		result = s.findTools(ctx, p.Arguments)
	case "call_tool":
		result = s.callTool(ctx, p.Arguments)
	default:
		if res, ok := s.invokeUpstream(ctx, p.Name, p.Arguments); ok {
			result = res
		} else {
			result = toolError("unknown tool: %s", p.Name)
		}
	}
	return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// firstNonEmpty returns the first non-blank value, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// engineFromQuery infers the query LANGUAGE (engine) from its syntax, so the agent
// can express intent without naming the engine. "" when it can't tell.
func engineFromQuery(query string) string {
	q := strings.TrimSpace(query)
	if q == "" {
		return ""
	}
	if l := strings.ToLower(q); strings.HasPrefix(l, "select ") || strings.HasPrefix(l, "select\n") || strings.HasPrefix(l, "with ") {
		return "sql"
	}
	switch q[0] {
	case '.', '[', '{', '(':
		return "jq"
	}
	return ""
}

// detectEngine returns the engine inferred from the query IF it's configured on
// this server, else "" (caller falls through to the default).
func (s *Server) detectEngine(query string) string {
	if d := engineFromQuery(query); d != "" {
		if _, ok := s.wasm[d]; ok {
			return d
		}
	}
	return ""
}

// largeReduceThreshold is the referenced-payload size at or above which a
// declarative reduce is treated as MB-scale work. At this size jq (small/
// structured shaping) is the wrong substrate — its worst case, a regex scan over
// several MB, can exhaust the wasm engine timeout, and because a declarative
// reduce runs the engine synchronously inside the MCP tool call, the client's
// ~60s call cancellation kills it regardless of the engine's own timeout. The
// columnar sql engine handles MB-scale JSON far better (engine benchmarks: a
// 3.2 MB array aggregates in ~2s vs jq's ~3.7s, and the gap widens with size).
// So on a large reduce we STEER the agent (advisory on success, actionable steer
// on timeout) toward a sql SELECT or code — we do NOT silently reroute the
// engine, which would only turn a jq query into a confusing sql parse error.
// 1 MiB sits well above ordinary shaping — small refs are KiB-scale (the inline
// allowance is 16 KiB) — so only genuinely large reductions are flagged.
const largeReduceThreshold = 1 << 20 // 1 MiB

// reduce runs a reduction over a stored reference OFF-CONTEXT and returns only the
// computed result. The request SHAPE selects the substrate, same rule as run: a
// declarative query → wasm engine; arbitrary code → microVM (reading the bytes
// from /app/input). The referenced data never enters the model's context.
// reduceInlineBytes is the inline allowance for a REDUCE output. It is deliberately
// more generous than the raw-result threshold (budget.MaxBytes): a reduction is the
// agent's explicit answer and is meant to be read. Without this, a reduction that
// lands just over the raw threshold — e.g. an identity reduce of a ~3 KB ref — gets
// re-reffed, leaving the result un-viewable (every whole-result reduce re-parks it).
const reduceInlineBytes = 16 << 10 // 16 KiB

// finalizeReduce inlines a reduce outcome that was reffed but is small enough to
// read directly (<= the reduce allowance). Genuinely large reductions stay reffed
// so the agent can reduce further. The orphaned ref is harmless (small, in-store).
func (s *Server) finalizeReduce(out budget.Outcome) budget.Outcome {
	cap := reduceInlineBytes
	if s.budget.MaxBytes > cap { // never re-ref what would inline as a raw result
		cap = s.budget.MaxBytes
	}
	if out.Reffed && out.Summary.Bytes <= cap && s.budget.Store != nil {
		if data, ok := s.budget.Store.Get(out.Ref); ok {
			return budget.Outcome{Inline: data}
		}
	}
	return out
}

func (s *Server) reduce(ctx context.Context, args json.RawMessage) map[string]any {
	var in struct {
		Ref    string   `json:"ref"`
		Refs   []string `json:"refs"`
		Data   string   `json:"data"`
		Query  string   `json:"query"`
		Engine string   `json:"engine"`
		Code   string   `json:"code"`
	}
	_ = json.Unmarshal(args, &in)
	if s.budget.Store == nil {
		return toolError("references are not enabled on this server")
	}
	// The input is EITHER references (`ref`/`refs`, resolved from the refstore) OR
	// inline `data` (small, in-context data to compute over exactly). Resolve the
	// payloads up front, failing closed on any unknown handle.
	refs := in.Refs
	if len(refs) == 0 && strings.TrimSpace(in.Ref) != "" {
		refs = []string{in.Ref}
	}
	var payloads []string
	var refLabel string
	switch {
	case len(refs) > 0:
		if in.Data != "" {
			return toolError("reduce: give references (ref/refs) OR inline data, not both")
		}
		payloads = make([]string, len(refs))
		for i, rf := range refs {
			p, ok := s.budget.Store.Get(refstore.Ref(rf))
			if !ok {
				return toolError("unknown reference %q", rf)
			}
			payloads[i] = p
		}
		refLabel = strings.Join(refs, ",")
	case in.Data != "":
		// Inline data is the exact-computation path (hash, date math, unit
		// conversion, parsing) on small, in-context data. Bounded to the inline
		// threshold — anything larger should already be a reference, not re-sent.
		limit := s.budget.MaxBytes
		if limit <= 0 {
			limit = reduceInlineBytes
		}
		if len(in.Data) > limit {
			return toolError("reduce: inline data is %d bytes (cap %d) — large enough that it should be a reference; work with the <ref_> instead", len(in.Data), limit)
		}
		payloads = []string{in.Data}
		refLabel = "inline"
	default:
		return toolError("reduce requires a reference (ref=<ref> / refs=[...]) or inline data (data=<...>)")
	}
	totalIn := 0
	for _, p := range payloads {
		totalIn += len(p)
	}
	user := principalOf(ctx).Subject
	runID := s.nextRunID()
	start := time.Now()

	switch {
	case strings.TrimSpace(in.Query) != "":
		if len(s.wasm) == 0 {
			return toolError("declarative reduce is not enabled on this server; use code")
		}
		if len(refs) > 1 {
			return toolError("declarative reduce (query) takes a single reference; to combine %d references use code that reads /app/input_1..%d (Python).", len(refs), len(refs))
		}
		payload := payloads[0]
		// A self-reference for the failure steer: a ref by handle, or inline data.
		selfRef := "data=<your inline data>"
		if len(refs) > 0 {
			selfRef = fmt.Sprintf("ref=%q", refs[0])
		}
		// The agent expresses INTENT; the router picks the engine from the query's
		// language when one isn't named (explicit engine still wins, then an inferred
		// language, then the server default). Selection is size-BLIND — an ambiguous
		// query is almost always jq-shaped, and silently rerouting it to sql (which
		// only accepts SELECT/WITH) would just produce a confusing parse error. We
		// steer the agent on size instead (advisory below / actionable timeout error).
		engineName := firstNonEmpty(in.Engine, s.detectEngine(in.Query), s.wasmDefault)
		eng, ok := s.wasm[engineName]
		if !ok {
			return toolError("unknown engine %q; configured engines: %s", engineName, strings.Join(s.wasmEngineNames(), ", "))
		}
		summary, err := eng.Run(ctx, in.Query, []byte(payload))
		if err != nil {
			// A non-zero engine exit carries the module's stderr, which can echo the
			// referenced data — RELOCATE it to the operator's audit record (bounded)
			// and keep the agent-facing error content-free: exit code + where the
			// operator can read the diagnostic.
			var exitErr *wasmexec.ExitError
			if errors.As(err, &exitErr) {
				s.putRun(runID, runRecord{
					Kind: "reduce", SourceID: refLabel, User: user,
					Substrate: "wasm", Engine: engineName, LatencyMs: time.Since(start).Milliseconds(),
					InputBytes: len(payload),
					ExitCode:   exitErr.ExitCode, Stderr: router.CapStderr(exitErr.Stderr),
				})
				err = fmt.Errorf("engine module exited %d; its stderr was captured for the operator (run %s, /admin/runs), not returned here", exitErr.ExitCode, runID)
			}
			// Turn a dead-end failure into the productive next step. Over a large ref
			// the likely cause is jq exhausting the engine timeout (or the MCP client's
			// ~60s call cancellation, since the engine runs synchronously inside the
			// tool call) on MB-scale data — so make the steer size-aware and concrete.
			if len(payload) >= largeReduceThreshold && engineName == "jq" {
				return toolError("reduce: the jq engine failed over ~%s of data (%v). At MB scale jq is the wrong substrate — reformulate as %s.", mbOf(len(payload)), err, s.largeReduceAlt(selfRef))
			}
			return toolError("reduce: the %q engine failed (%v). For large data, regex, or complex logic, run it as code instead — reduce(%s, code=<python that reads /app/input>).", engineName, err, selfRef)
		}
		out := s.finalizeReduce(s.budget.Apply(string(summary)))
		s.putRun(runID, runRecord{
			Kind: "reduce", SourceID: refLabel, User: user,
			Substrate: "wasm", Engine: engineName, LatencyMs: time.Since(start).Milliseconds(),
			InputBytes: len(payload), OutputBytes: len(summary),
			Reffed: out.Reffed, Ref: string(out.Ref), Bytes: out.Summary.Bytes,
		})
		return s.reduceResult(runID, out, s.largeReduceHint(engineName, len(payload)))

	case strings.TrimSpace(in.Code) != "":
		dec, err := s.runner.Run(ctx, router.Request{
			Name: "reduce-" + runID, Code: in.Code,
			Inputs: reduceInputs(payloads),
		})
		if err != nil {
			// A guest failure carries the VM console log, which tees guest output and
			// can echo the input data — RELOCATE it to the operator's audit record
			// (bounded) and keep the agent-facing error content-free.
			var gf *sandbox.GuestFailureError
			if errors.As(err, &gf) {
				s.putRun(runID, runRecord{
					Kind: "reduce", SourceID: refLabel, User: user,
					Substrate: "microvm", LatencyMs: time.Since(start).Milliseconds(),
					InputBytes: totalIn, ExitCode: -1,
					Stderr: router.CapStderr(gf.SerialLog),
				})
				return toolError("reduce: the sandbox failed before returning a result. Its console log was captured for the operator (run %s, /admin/runs), not returned here. Retry, or ask the operator to check that run.", runID)
			}
			return toolError("reduce: %v", err)
		}
		outputBytes := len(dec.Inline)
		if dec.Reffed {
			outputBytes = dec.Summary.Bytes
		}
		auditErr := ""
		if dec.AuditErr != nil {
			auditErr = dec.AuditErr.Error()
		}
		out := s.finalizeReduce(budget.Outcome{Reffed: dec.Reffed, Inline: dec.Inline, Ref: dec.Ref, Summary: dec.Summary})
		s.putRun(runID, runRecord{
			Kind: "reduce", SourceID: refLabel, User: user,
			Substrate: "microvm", LatencyMs: time.Since(start).Milliseconds(),
			InputBytes: totalIn, OutputBytes: outputBytes,
			Reffed: out.Reffed, Ref: string(out.Ref), Bytes: out.Summary.Bytes,
			ExitCode: dec.ExitCode, Stderr: dec.Stderr, Audit: dec.Audit, AuditErr: auditErr,
		})
		if dec.ExitCode != 0 {
			// Content-free by design: a traceback (or a stray print to stderr) over
			// /app/input can echo the exact bytes the ref model keeps off-context, so
			// stderr never enters the agent's context — it lives in the operator's
			// audit record (recorded above, surfaced via /admin/runs and the console).
			return toolError("reduce code failed (exit %d). The guest's stderr is not returned here (it can echo the referenced data); the operator can read it in the audit log (run %s, /admin/runs). Fix the code and retry — the inputs are unchanged.", dec.ExitCode, runID)
		}
		return s.reduceResult(runID, out, "") // code already handles any size — no advisory

	default:
		return toolError("reduce requires either query+engine (declarative) or code (Python)")
	}
}

// mbOf formats a byte count as a compact MB string for the size-aware steers.
func mbOf(n int) string { return fmt.Sprintf("%.1f MB", float64(n)/(1<<20)) }

// largeReduceAlt names the substrate(s) to reformulate a large jq reduce as, in a
// ready-to-run shape: a sql SELECT when the columnar engine is configured, else
// code. Both keep the referenced data off-context. selfRef is a pre-formatted
// self-reference token (either `ref="<handle>"` or `data=<your inline data>`), so
// this works on both the reffed and the inline-data reduce paths.
func (s *Server) largeReduceAlt(selfRef string) string {
	if _, ok := s.wasm["sql"]; ok {
		return fmt.Sprintf("a sql SELECT — reduce(%s, engine=\"sql\", query=<SELECT ... FROM data ...>) — or code — reduce(%s, code=<python that reads /app/input>)", selfRef, selfRef)
	}
	return fmt.Sprintf("code — reduce(%s, code=<python that reads /app/input>)", selfRef)
}

// largeReduceHint returns a concise, non-breaking advisory for a jq reduce that
// SUCCEEDED over a large ref: jq is for small/structured shaping, and for MB-scale
// data a columnar sql SELECT (~3x faster on MB JSON in the engine benchmarks) or
// code is usually the right substrate. "" unless the reduce ran on jq and the ref
// is genuinely large — so it never fires on ordinary shaping or an already-fast
// engine, and it never changes the computed result.
func (s *Server) largeReduceHint(engineName string, payloadBytes int) string {
	if engineName != "jq" || payloadBytes < largeReduceThreshold {
		return ""
	}
	alt := "code"
	if _, ok := s.wasm["sql"]; ok {
		alt = "a sql SELECT (columnar — ~3x faster on MB-scale JSON here) or code"
	}
	return fmt.Sprintf("this ref is ~%s, MB-scale for jq (which is for small/structured shaping). It ran on jq; if that was slow or nears the ~60s tool-call limit, reformulate as %s.", mbOf(payloadBytes), alt)
}

// reduceResult shapes a reduction outcome for the model: the computed result
// inline, or a new reference + size + structural preview if the reduction itself is
// large (so a chained reduce is often unnecessary). A non-empty advisory is
// attached alongside the result without altering it (a substrate steer, not a
// failure).
func (s *Server) reduceResult(runID string, out budget.Outcome, advisory string) map[string]any {
	r := map[string]any{"run_id": runID, "reffed": out.Reffed}
	if out.Reffed {
		r["ref"] = string(out.Ref)
		summary := map[string]any{"bytes": out.Summary.Bytes}
		if p := s.refPreview(out.Ref); p != nil {
			summary["preview"] = p
		}
		r["summary"] = summary
	} else {
		r["result"] = out.Inline
	}
	if advisory != "" {
		r["advisory"] = advisory
	}
	return toolResult(r)
}
