package refstore

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemStorePutGetRoundTrip(t *testing.T) {
	s := NewMemStore()
	ref, sum := s.Put("hello world")
	if ref != "<ref_1>" {
		t.Fatalf("first ref = %q, want <ref_1>", ref)
	}
	if sum.Bytes != len("hello world") {
		t.Fatalf("summary bytes = %d, want %d", sum.Bytes, len("hello world"))
	}
	got, ok := s.Get(ref)
	if !ok || got != "hello world" {
		t.Fatalf("Get(%q) = (%q,%v), want (hello world,true)", ref, got, ok)
	}
}

func TestMemStoreDeterministicSequentialRefs(t *testing.T) {
	s := NewMemStore()
	r1, _ := s.Put("a")
	r2, _ := s.Put("b")
	if r1 != "<ref_1>" || r2 != "<ref_2>" {
		t.Fatalf("refs = %q,%q, want <ref_1>,<ref_2>", r1, r2)
	}
}

// The summary is size-only by design: any raw-byte head here would hand payload
// content back to the model and defeat minimization. The agent-facing preview is
// the values-free structural one computed at the gateway.
func TestMemStoreSummaryCarriesNoPayloadBytes(t *testing.T) {
	s := NewMemStore()
	_, sum := s.Put("abcdefgh")
	if sum.Bytes != 8 {
		t.Fatalf("bytes = %d, want 8", sum.Bytes)
	}
	if b, _ := json.Marshal(sum); strings.Contains(string(b), "abcd") {
		t.Fatalf("summary must not carry payload content: %s", b)
	}
}

func TestMemStoreGetUnknownRef(t *testing.T) {
	s := NewMemStore()
	if _, ok := s.Get("<ref_99>"); ok {
		t.Fatal("Get on unknown ref returned ok=true")
	}
}
