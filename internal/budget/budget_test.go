package budget

import (
	"strings"
	"testing"

	"microagency/internal/refstore"
)

func TestApplyUnderBudgetReturnsInline(t *testing.T) {
	g := Gate{MaxBytes: 2048, Store: refstore.NewMemStore()}
	out := g.Apply("small result", "")
	if out.Reffed {
		t.Fatal("under-budget payload was reffed")
	}
	if out.Inline != "small result" {
		t.Fatalf("inline = %q, want %q", out.Inline, "small result")
	}
}

func TestApplyOverBudgetRefsAndStores(t *testing.T) {
	store := refstore.NewMemStore()
	g := Gate{MaxBytes: 16, Store: store}
	big := strings.Repeat("x", 100)

	out := g.Apply(big, "")

	if !out.Reffed {
		t.Fatal("over-budget payload was returned inline (S4 violation)")
	}
	if out.Inline != "" {
		t.Fatalf("over-budget Inline should be empty, got %d bytes", len(out.Inline))
	}
	if out.Ref == "" {
		t.Fatal("over-budget Ref is empty")
	}
	if out.Summary.Bytes != 100 {
		t.Fatalf("summary bytes = %d, want 100", out.Summary.Bytes)
	}
	// The full payload must be retrievable from the store via the ref —
	// nothing was lost, it just didn't go to the model.
	got, _, ok := store.Get(out.Ref)
	if !ok || got != big {
		t.Fatalf("store.Get(%q) round-trip failed (ok=%v)", out.Ref, ok)
	}
}

func TestApplyExactlyAtBudgetIsInline(t *testing.T) {
	g := Gate{MaxBytes: 5, Store: refstore.NewMemStore()}
	out := g.Apply("12345", "") // len == MaxBytes
	if out.Reffed {
		t.Fatal("payload exactly at budget was reffed; boundary should be inclusive")
	}
}
