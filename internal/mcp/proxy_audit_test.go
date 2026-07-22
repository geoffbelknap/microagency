package mcp

import (
	"strings"
	"testing"
)

// invokeUpstream records EVERY outcome in one place, so distinct outcome paths —
// a pre-dial refusal (no egress) and a successful call — each add exactly one
// audit record, and the refusal carries its reason. This pins the structural
// "every outcome is audited" guarantee after the single-record refactor.
func TestEveryProxyOutcomeIsAudited(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing"}, {name: "create-thing"}}, false)
	if err := s.SetUpstreamReadOnly("u", true); err != nil {
		t.Fatalf("set read-only: %v", err)
	}

	before := len(s.RunLog())

	// Refusal path: a read-only write is refused before any egress — still audited.
	call(t, s, "call_tool", map[string]any{"name": "u__create-thing", "arguments": map[string]any{}})
	if got := len(s.RunLog()); got != before+1 {
		t.Fatalf("read-only refusal not audited: runs %d→%d", before, got)
	}
	// Newest-first; the refusal record carries its reason as a non-success outcome.
	if rec := s.RunLog()[0]; rec.ExitCode == 0 || !strings.Contains(rec.AuditErr, "read-only") {
		t.Fatalf("refusal audit record should record the reason: exit=%d auditErr=%q", rec.ExitCode, rec.AuditErr)
	}

	// Success path: a read reaches the upstream and is audited too.
	call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{}})
	if got := len(s.RunLog()); got != before+2 {
		t.Fatalf("successful read not audited: runs %d, want %d", got, before+2)
	}
	if rec := s.RunLog()[0]; rec.ExitCode != 0 || rec.AuditErr != "" {
		t.Fatalf("success record should be clean: exit=%d auditErr=%q", rec.ExitCode, rec.AuditErr)
	}
}
