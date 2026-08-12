package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"microagency/internal/auth"
	"microagency/internal/refstore"
	"microagency/internal/sandbox"
)

const (
	defaultProgramMaxCalls   = 16
	defaultProgramMaxBytes   = 16 << 20
	defaultProgramMaxSeconds = 300
	maxProgramCalls          = 100
	maxProgramBytes          = 64 << 20
	maxProgramSeconds        = 360
	maxProgramTools          = 32
	maxProgramSearches       = 16
	maxProgramRequestBytes   = 1 << 20
	maxProgramRequestIDBytes = 64
	programSDKPath           = "/app/microagency.py"
)

// programConfig is the explicit capability grant attached to reduce(code).
// Exact tool names keep a generated program narrower than the authenticated
// caller's complete gateway authority; the broker independently enforces read
// classification, ownership, enabled state, and the declared resource budgets.
type programConfig struct {
	AllowedTools []string `json:"allowed_tools"`
	MaxCalls     int      `json:"max_calls"`
	MaxBytes     int      `json:"max_bytes"`
	MaxSeconds   int      `json:"max_seconds"`
}

type programCtxKey int

const programPolicyKey programCtxKey = 0

type programPolicy struct {
	allowed   map[string]struct{}
	parentRun string
	requestID string
}

func withProgramPolicy(ctx context.Context, policy *programPolicy) context.Context {
	return context.WithValue(ctx, programPolicyKey, policy)
}

func programPolicyOf(ctx context.Context) *programPolicy {
	policy, _ := ctx.Value(programPolicyKey).(*programPolicy)
	return policy
}

func programAuditContext(ctx context.Context) (parentRun, delivery, requestID string) {
	if policy := programPolicyOf(ctx); policy != nil {
		return policy.parentRun, "program", policy.requestID
	}
	return "", "", ""
}

// programBroker is one serialized, run-scoped broker. Serialization makes
// request-id replay deterministic and keeps all budget checks atomic. The
// prototype intentionally favors a small auditable protocol over concurrency.
type programBroker struct {
	mu sync.Mutex

	server    *Server
	ctx       context.Context
	principal *auth.Principal
	taskID    string
	parentRun string
	path      string
	allowed   map[string]struct{}
	tools     []string
	maxCalls  int
	maxBytes  int
	maxOps    int
	// maxRequests also counts malformed requests and exact replays. Without a
	// transport-level cap, hostile guest code could bypass the logical operation
	// budget and consume host HTTP work until the wall-time deadline.
	maxRequests int

	calls               int
	searches            int
	bytes               int
	ops                 int
	requests            int
	requestBudgetLogged bool
	status              string
	seen                map[string]programReplay
}

type programReplay struct {
	digest   string
	response programResponse
}

type programRequest struct {
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Query     string          `json:"query,omitempty"`
	Limit     int             `json:"limit,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type programResponse struct {
	ID     string             `json:"id,omitempty"`
	OK     bool               `json:"ok"`
	Result any                `json:"result,omitempty"`
	Error  *programError      `json:"error,omitempty"`
	Budget programBudgetState `json:"budget"`
}

type programError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type programBudgetState struct {
	CallsRemaining int `json:"calls_remaining"`
	BytesRemaining int `json:"bytes_remaining"`
}

type programStats struct {
	Tools  []string
	Calls  int
	Bytes  int
	Status string
}

func (s *Server) newProgramBroker(parent context.Context, parentRun, taskID string, cfg programConfig) (*programBroker, context.CancelFunc, error) {
	normalized, err := s.validateProgramConfig(parent, cfg)
	if err != nil {
		return nil, nil, err
	}
	capability := make([]byte, 24)
	if _, err := rand.Read(capability); err != nil {
		return nil, nil, fmt.Errorf("create run-scoped broker capability: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(normalized.MaxSeconds)*time.Second)
	allowed := make(map[string]struct{}, len(normalized.AllowedTools))
	for _, name := range normalized.AllowedTools {
		allowed[name] = struct{}{}
	}
	principal := *principalOf(parent)
	b := &programBroker{
		server: s, ctx: ctx, principal: &principal, taskID: taskID, parentRun: parentRun,
		path:    "/v1/program/" + base64.RawURLEncoding.EncodeToString(capability),
		allowed: allowed, tools: normalized.AllowedTools,
		maxCalls: normalized.MaxCalls, maxBytes: normalized.MaxBytes,
		maxOps:      normalized.MaxCalls + maxProgramSearches + 16,
		maxRequests: normalized.MaxCalls + maxProgramSearches + 32,
		status:      "completed", seen: map[string]programReplay{},
	}
	return b, cancel, nil
}

func (s *Server) validateProgramConfig(ctx context.Context, cfg programConfig) (programConfig, error) {
	if len(cfg.AllowedTools) == 0 {
		return cfg, errors.New("program.allowed_tools requires at least one exact tool name from find_tools")
	}
	if len(cfg.AllowedTools) > maxProgramTools {
		return cfg, fmt.Errorf("program.allowed_tools has %d entries (cap %d)", len(cfg.AllowedTools), maxProgramTools)
	}
	if cfg.MaxCalls == 0 {
		cfg.MaxCalls = defaultProgramMaxCalls
	}
	if cfg.MaxCalls < 1 || cfg.MaxCalls > maxProgramCalls {
		return cfg, fmt.Errorf("program.max_calls must be 1..%d", maxProgramCalls)
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = defaultProgramMaxBytes
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > maxProgramBytes {
		return cfg, fmt.Errorf("program.max_bytes must be 1..%d", maxProgramBytes)
	}
	if cfg.MaxSeconds == 0 {
		cfg.MaxSeconds = defaultProgramMaxSeconds
	}
	if cfg.MaxSeconds < 1 || cfg.MaxSeconds > maxProgramSeconds {
		return cfg, fmt.Errorf("program.max_seconds must be 1..%d", maxProgramSeconds)
	}

	seen := make(map[string]struct{}, len(cfg.AllowedTools))
	principal := principalOf(ctx).Subject
	for _, raw := range cfg.AllowedTools {
		name := strings.TrimSpace(raw)
		if name == "" || len(name) > 512 {
			return cfg, errors.New("program.allowed_tools contains an empty or overlong name")
		}
		if _, duplicate := seen[name]; duplicate {
			return cfg, fmt.Errorf("program.allowed_tools repeats %q", name)
		}
		seen[name] = struct{}{}
		upName, toolName, namespaced := strings.Cut(name, nsSep)
		rec, ok := s.snapshotUpstream(upName)
		if !namespaced || !ok || rec.revoked || (rec.owner != "" && rec.owner != principal) {
			return cfg, fmt.Errorf("program tool %q is unknown to this caller", name)
		}
		if !rec.enabled {
			return cfg, fmt.Errorf("program tool %q is not enabled", name)
		}
		tool, ok := findTool(rec.tools, toolName)
		if !ok {
			return cfg, fmt.Errorf("program tool %q is not in the current upstream schema", name)
		}
		if isWriteTool(tool) {
			return cfg, fmt.Errorf("program tool %q is write/destructive or unclassifiable; governed programs are read-only", name)
		}
	}
	sort.Strings(cfg.AllowedTools)
	return cfg, nil
}

func (b *programBroker) SDKInput() sandbox.Input {
	endpoint := sandbox.HostServiceGuestURL + b.path
	code := fmt.Sprintf(`"""Run-scoped, read-only microagency tool broker.

The module contains no upstream credential. The endpoint disappears with this
sandbox run and accepts only the exact tools granted by the outer reduce call.
"""
import itertools
import json
import urllib.error
import urllib.request

_ENDPOINT = %q
_IDS = itertools.count(1)

class BrokerError(RuntimeError):
    def __init__(self, code, message, retryable=False, budget=None):
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.budget = budget or {}

def _request(operation, **fields):
    request_id = "request-%%d" %% next(_IDS)
    payload = {"id": request_id, "operation": operation}
    payload.update(fields)
    request = urllib.request.Request(
        _ENDPOINT,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            body = json.load(response)
    except urllib.error.HTTPError as error:
        try:
            body = json.load(error)
        except Exception:
            raise BrokerError("transport_error", "broker request failed", True) from None
    except Exception as error:
        raise BrokerError("transport_error", str(error), True) from None
    if not body.get("ok"):
        detail = body.get("error") or {}
        raise BrokerError(detail.get("code", "broker_error"), detail.get("message", "broker request failed"), detail.get("retryable", False), body.get("budget"))
    return body.get("result")

def find_tools(query, limit=10):
    """Return typed schemas for read tools granted to this run."""
    return _request("find_tools", query=query, limit=limit)

def call_tool(name, arguments=None):
    """Invoke one granted read tool through the gateway's normal call path."""
    return _request("call_tool", name=name, arguments=arguments or {})
`, endpoint)
	return sandbox.Input{Data: []byte(code), Path: programSDKPath}
}

func (b *programBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.Path != b.path {
		http.NotFound(w, r)
		return
	}
	// Serialize from the first byte, not only during tool execution. This keeps
	// request parsing bounded too and matches the protocol's single-call model.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests >= b.maxRequests {
		b.status = "budget_exhausted"
		if !b.requestBudgetLogged {
			b.recordDecision("budget_exhausted", "", "broker request budget exhausted", 1)
			b.requestBudgetLogged = true
		}
		writeProgramJSON(w, http.StatusTooManyRequests, b.errorResponse("", "budget_exhausted", "broker request budget exhausted", false))
		return
	}
	b.requests++
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProgramRequestBytes))
	if err != nil {
		writeProgramJSON(w, http.StatusRequestEntityTooLarge, b.errorResponse("", "invalid_request", "request exceeds the broker input cap", false))
		return
	}
	var req programRequest
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeProgramJSON(w, http.StatusBadRequest, b.errorResponse("", "invalid_request", "request is not valid broker JSON", false))
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		writeProgramJSON(w, http.StatusBadRequest, b.errorResponse(req.ID, "invalid_request", "request contains trailing JSON", false))
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(b.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	response := b.processLocked(ctx, req, body)
	writeProgramJSON(w, http.StatusOK, response)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("extra JSON value")
		}
		return err
	}
	return nil
}

func (b *programBroker) processLocked(ctx context.Context, req programRequest, body []byte) programResponse {
	if !validProgramRequestID(req.ID) {
		return b.errorResponse(req.ID, "invalid_request", "id must be 1..64 safe ASCII characters", false)
	}
	digestBytes := sha256.Sum256(body)
	digest := hex.EncodeToString(digestBytes[:])
	if replay, ok := b.seen[req.ID]; ok {
		if replay.digest != digest {
			b.recordDecision("replay_mismatch", req.ID, "request id reused with different content", 1)
			return b.errorResponse(req.ID, "replay_mismatch", "request id was already used for different content", false)
		}
		b.recordDecision("replay", req.ID, "identical request replayed without another upstream call", 0)
		response := replay.response
		response.Budget = b.budgetState()
		return response
	}
	// Check the run context directly as well as the request context. AfterFunc
	// propagates cancellation to an in-flight request, but its callback is
	// asynchronous and must not leave a window for a new post-cancel call.
	if err := b.ctx.Err(); err != nil {
		b.status = "canceled"
		if errors.Is(err, context.DeadlineExceeded) {
			b.status = "budget_exhausted"
			response := b.errorResponse(req.ID, "budget_exhausted", "the governed program time budget expired", false)
			b.seen[req.ID] = programReplay{digest: digest, response: response}
			return response
		}
		response := b.errorResponse(req.ID, "canceled", "the governed program was canceled", false)
		b.seen[req.ID] = programReplay{digest: digest, response: response}
		return response
	}
	if err := ctx.Err(); err != nil {
		b.status = "canceled"
		response := b.errorResponse(req.ID, "canceled", "the governed program was canceled", false)
		b.seen[req.ID] = programReplay{digest: digest, response: response}
		return response
	}
	if b.ops >= b.maxOps {
		b.status = "budget_exhausted"
		response := b.errorResponse(req.ID, "budget_exhausted", "broker operation budget exhausted", false)
		b.recordDecision("budget_exhausted", req.ID, "operation budget exhausted", 1)
		b.seen[req.ID] = programReplay{digest: digest, response: response}
		return response
	}
	b.ops++

	var response programResponse
	switch req.Operation {
	case "find_tools":
		response = b.findToolsLocked(ctx, req)
	case "call_tool":
		response = b.callToolLocked(ctx, req)
	default:
		response = b.errorResponse(req.ID, "invalid_request", "operation must be find_tools or call_tool", false)
	}
	response.ID = req.ID
	response.Budget = b.budgetState()
	b.seen[req.ID] = programReplay{digest: digest, response: response}
	return response
}

func (b *programBroker) findToolsLocked(ctx context.Context, req programRequest) programResponse {
	if b.searches >= maxProgramSearches {
		b.status = "budget_exhausted"
		b.recordDecision("budget_exhausted", req.ID, "discovery budget exhausted", 1)
		return b.errorResponse(req.ID, "budget_exhausted", "tool discovery budget exhausted", false)
	}
	b.searches++
	limit := req.Limit
	if limit <= 0 {
		limit = 10
	}
	args, _ := json.Marshal(map[string]any{"query": req.Query, "limit": limit, "task_id": b.taskID})
	callCtx := b.callContext(ctx, req.ID)
	result := b.server.findToolsAllowed(callCtx, args, b.allowed)
	if resultIsError(result) {
		return b.errorResponse(req.ID, "discovery_error", safeToolError(result), false)
	}
	payload := resultPayload(result)
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return b.errorResponse(req.ID, "internal", "gateway returned malformed discovery data", false)
	}
	return b.deliver(req.ID, decoded)
}

func (b *programBroker) callToolLocked(ctx context.Context, req programRequest) programResponse {
	if b.calls >= b.maxCalls {
		b.status = "budget_exhausted"
		b.recordDecision("budget_exhausted", req.ID, "tool-call budget exhausted", 1)
		return b.errorResponse(req.ID, "budget_exhausted", "tool-call budget exhausted", false)
	}
	b.calls++
	if len(req.Arguments) == 0 {
		req.Arguments = json.RawMessage(`{}`)
	}
	if !json.Valid(req.Arguments) {
		return b.errorResponse(req.ID, "invalid_request", "arguments must be valid JSON", false)
	}
	callCtx := b.callContext(ctx, req.ID)
	result, found := b.server.invokeUpstream(callCtx, req.Name, req.Arguments)
	if !found {
		return b.errorResponse(req.ID, "unauthorized_tool", "tool is not available through this governed program", false)
	}
	if resultIsError(result) {
		return b.errorResponse(req.ID, classifyProgramToolError(result), safeToolError(result), false)
	}
	payload, err := b.materializeResult(result)
	if err != nil {
		return b.errorResponse(req.ID, "result_unavailable", "tool result could not be delivered inside the sandbox", false)
	}
	if json.Valid([]byte(payload)) {
		return b.deliver(req.ID, json.RawMessage(payload))
	}
	return b.deliver(req.ID, payload)
}

func (b *programBroker) callContext(ctx context.Context, requestID string) context.Context {
	ctx = context.WithValue(ctx, principalKey, b.principal)
	ctx = withTaskID(ctx, b.taskID)
	return withProgramPolicy(ctx, &programPolicy{allowed: b.allowed, parentRun: b.parentRun, requestID: requestID})
}

func (b *programBroker) materializeResult(result map[string]any) (string, error) {
	payload := resultPayload(result)
	var handle struct {
		Reffed bool   `json:"reffed"`
		Ref    string `json:"ref"`
	}
	if json.Unmarshal([]byte(payload), &handle) == nil && handle.Reffed && handle.Ref != "" {
		if b.server.budget.Store == nil {
			return "", errors.New("ref store unavailable")
		}
		data, owner, ok := b.server.budget.Store.Get(refstore.Ref(handle.Ref))
		if !ok || owner != b.principal.Subject {
			return "", errors.New("ref unavailable")
		}
		return data, nil
	}
	return payload, nil
}

func (b *programBroker) deliver(id string, result any) programResponse {
	encoded, err := json.Marshal(result)
	if err != nil {
		return b.errorResponse(id, "internal", "broker could not encode the result", false)
	}
	if len(encoded) > b.maxBytes-b.bytes {
		b.status = "budget_exhausted"
		b.recordDecision("budget_exhausted", id, "result-byte budget exhausted", 1)
		return b.errorResponse(id, "budget_exhausted", "result-byte budget exhausted; narrow the page size or projection", false)
	}
	b.bytes += len(encoded)
	return programResponse{ID: id, OK: true, Result: result, Budget: b.budgetState()}
}

func (b *programBroker) errorResponse(id, code, message string, retryable bool) programResponse {
	return programResponse{ID: id, OK: false, Error: &programError{Code: code, Message: message, Retryable: retryable}, Budget: b.budgetState()}
}

func (b *programBroker) budgetState() programBudgetState {
	calls := b.maxCalls - b.calls
	bytes := b.maxBytes - b.bytes
	if calls < 0 {
		calls = 0
	}
	if bytes < 0 {
		bytes = 0
	}
	return programBudgetState{CallsRemaining: calls, BytesRemaining: bytes}
}

func (b *programBroker) Stats() programStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	status := b.status
	if b.ctx.Err() != nil && status == "completed" {
		if errors.Is(b.ctx.Err(), context.DeadlineExceeded) {
			status = "budget_exhausted"
		} else {
			status = "canceled"
		}
	}
	return programStats{Tools: append([]string(nil), b.tools...), Calls: b.calls, Bytes: b.bytes, Status: status}
}

func (b *programBroker) recordDecision(event, requestID, detail string, exitCode int) {
	b.server.putRun(b.server.nextRunID(), runRecord{
		Kind: "program", TaskID: b.taskID, User: b.principal.Subject,
		ParentRunID: b.parentRun, Delivery: "program", ProgramRequestID: requestID,
		Tool: event, ExitCode: exitCode, AuditErr: detail,
	})
}

func validProgramRequestID(id string) bool {
	if len(id) == 0 || len(id) > maxProgramRequestIDBytes {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func safeToolError(result map[string]any) string {
	payload := strings.TrimSpace(resultPayload(result))
	if payload == "" {
		return "gateway refused the tool request"
	}
	if len(payload) > 2048 {
		payload = payload[:2048] + "...[truncated]"
	}
	return payload
}

func classifyProgramToolError(result map[string]any) string {
	message := strings.ToLower(safeToolError(result))
	switch {
	case strings.Contains(message, "governed programs are read-only"):
		return "write_forbidden"
	case strings.Contains(message, "not granted to this governed program"), strings.Contains(message, "unknown tool"):
		return "unauthorized_tool"
	default:
		return "tool_error"
	}
}

func writeProgramJSON(w http.ResponseWriter, status int, response programResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}
