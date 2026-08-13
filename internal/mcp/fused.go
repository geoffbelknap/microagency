package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"microagency/internal/budget"
	"microagency/internal/wasmexec"
)

const maxFusedQueryBytes = 16 << 10

// declarativeTransform is the bounded call_tool post-processing contract. It
// deliberately has no code field: credentialed arbitrary code remains outside
// this path, while the configured declarative engines are pure and local.
type declarativeTransform struct {
	Query  string `json:"query"`
	Engine string `json:"engine,omitempty"`
}

type transformContextKey struct{}

func (s *Server) parseTransform(raw json.RawMessage) (*declarativeTransform, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var transform declarativeTransform
	if err := dec.Decode(&transform); err != nil {
		return nil, fmt.Errorf("transform must contain only query and optional engine: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("transform must be one JSON object")
	}
	transform.Query = strings.TrimSpace(transform.Query)
	transform.Engine = strings.TrimSpace(transform.Engine)
	if transform.Query == "" {
		return nil, fmt.Errorf("transform.query is required")
	}
	if len(transform.Query) > maxFusedQueryBytes {
		return nil, fmt.Errorf("transform.query is %d bytes (cap %d)", len(transform.Query), maxFusedQueryBytes)
	}
	if s.budget.Store == nil {
		return nil, fmt.Errorf("transform requires references to be enabled so its output threshold can fail closed")
	}
	engineName := firstNonEmpty(transform.Engine, s.detectEngine(transform.Query), s.wasmDefault)
	if engineName == "" {
		return nil, fmt.Errorf("declarative transform is not enabled on this server")
	}
	if _, ok := s.wasm[engineName]; !ok {
		return nil, fmt.Errorf("unknown transform engine %q; configured engines: %s", engineName, strings.Join(s.wasmEngineNames(), ", "))
	}
	transform.Engine = engineName
	return &transform, nil
}

func withTransform(ctx context.Context, transform *declarativeTransform) context.Context {
	if transform == nil {
		return ctx
	}
	return context.WithValue(ctx, transformContextKey{}, transform)
}

func transformOf(ctx context.Context) *declarativeTransform {
	transform, _ := ctx.Value(transformContextKey{}).(*declarativeTransform)
	return transform
}

func transformDigest(query string) string {
	digest := sha256.Sum256([]byte(query))
	return hex.EncodeToString(digest[:])
}

// fusedProxyResult transforms one successful upstream result without another
// client round trip. The upstream call has already happened exactly once. Every
// failure therefore withholds the raw result and explicitly avoids retry advice,
// which is essential for mutating tools.
func (s *Server) fusedProxyResult(ctx context.Context, runID, upstream, tool, sourceTool string, transform *declarativeTransform, passthrough map[string]any, raw json.RawMessage, egressHost string, evaluated *evaluatedGrant) proxyOutcome {
	payload := resultPayload(passthrough)
	rawBytes := max(len(raw), len(payload))
	if link := offloadURL(payload); link != "" {
		data, err := s.fetchOffload(ctx, link, evaluated)
		if err != nil {
			return fusedFailure(runID, rawBytes, 0, 0, "offload_error", egressHost,
				"the upstream result could not be retrieved for transformation; it was withheld", false)
		}
		payload = string(data)
		rawBytes = max(rawBytes, len(data))
	}
	if _, truncated := truncatedNotice(payload); truncated {
		return fusedFailure(runID, rawBytes, len(payload), 0, "truncated_input", egressHost,
			"the upstream returned truncated or malformed data, so the transformation was not run and the raw result was withheld", false)
	}

	engine := s.wasm[transform.Engine] // validated before egress by parseTransform
	started := time.Now()
	summary, err := engine.Run(ctx, transform.Query, []byte(payload))
	latency := time.Since(started).Milliseconds()
	if err != nil {
		status, detail, exitCode := "engine_error", "the declarative transformation failed", 1
		var exitErr *wasmexec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode
			if exitErr.BadQuery() {
				status = "bad_query"
				detail = fmt.Sprintf("the %q engine rejected the transformation query: %s", transform.Engine, capQueryDiagnostic(exitErr.Stderr))
			}
		}
		out := fusedFailure(runID, rawBytes, len(payload), len(summary), status, egressHost, detail, true)
		out.transformLatencyMs = latency
		if exitCode != 0 {
			out.err = fmt.Errorf("fused transform %s (exit %d)", status, exitCode)
		}
		return out
	}

	// Field minimization still runs at the model boundary, over the transformed
	// answer rather than the raw upstream dataset. The declarative engine is local
	// and credential-blind; only this scrubbed answer proceeds to the budget gate.
	preMinimize := map[string]any{"result": string(summary)}
	scrubbed, alerts, protected, err := s.scrubInbound(ctx, upstream, tool, preMinimize)
	if err != nil {
		out := fusedFailure(runID, rawBytes, len(payload), len(summary), "minimize_error", egressHost,
			"field minimization failed after transformation; the answer and raw result were withheld", true)
		out.transformLatencyMs = time.Since(started).Milliseconds()
		return out
	}
	answer, ok := scrubbed["result"].(string)
	if !ok {
		out := fusedFailure(runID, rawBytes, len(payload), len(summary), "minimize_shape_error", egressHost,
			"field minimization returned an invalid transformed-answer shape; the result was withheld", true)
		out.transformLatencyMs = time.Since(started).Milliseconds()
		return out
	}
	minimizedBytes := marshalLen(preMinimize) - marshalLen(scrubbed)
	if minimizedBytes < 0 {
		minimizedBytes = 0
	}
	outcome := s.budget.Apply(answer, principalOf(ctx).Subject)
	return proxyOutcome{
		result:   s.fusedResult(runID, sourceTool, transform, outcome),
		rawBytes: rawBytes, minimizedBytes: minimizedBytes, outcome: outcome,
		egressHost: egressHost, protected: protected, extra: minimizeAlertEvents(alerts),
		transformRan: true, transformInputBytes: len(payload), transformOutputBytes: len(summary),
		transformLatencyMs: time.Since(started).Milliseconds(), transformStatus: "succeeded",
	}
}

func fusedFailure(runID string, rawBytes, inputBytes, outputBytes int, status, egressHost, detail string, ran bool) proxyOutcome {
	return proxyOutcome{
		result:   toolError("call_tool completed the upstream call once, but %s. The raw result did not enter context. Do not automatically retry a mutating tool; inspect run %s or reconcile upstream state first.", detail, runID),
		rawBytes: rawBytes, err: fmt.Errorf("fused transform %s", status), egressHost: egressHost,
		transformRan: ran, transformInputBytes: inputBytes, transformOutputBytes: outputBytes,
		transformStatus: status,
	}
}

func (s *Server) fusedResult(runID, sourceTool string, transform *declarativeTransform, out budget.Outcome) map[string]any {
	result := map[string]any{
		"run_id": runID,
		"reffed": out.Reffed,
		"provenance": map[string]any{
			"source_tool": sourceTool,
			"transformation": map[string]any{
				"engine":       transform.Engine,
				"query_sha256": transformDigest(transform.Query),
			},
		},
	}
	if out.Reffed {
		result["ref"] = string(out.Ref)
		summary := map[string]any{"bytes": out.Summary.Bytes}
		if preview := s.refPreview(out.Ref); preview != nil {
			summary["preview"] = preview
		}
		result["summary"] = summary
	} else {
		result["result"] = out.Inline
	}
	return toolResult(result)
}
