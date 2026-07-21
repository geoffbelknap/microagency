package refstore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMemStorePutGetRoundTrip(t *testing.T) {
	s := NewMemStore()
	ref, sum := s.Put("hello world", "alice")
	if _, ok := refToken(ref); !ok {
		t.Fatalf("ref %q is not a well-formed handle", ref)
	}
	if sum.Bytes != len("hello world") {
		t.Fatalf("summary bytes = %d, want %d", sum.Bytes, len("hello world"))
	}
	got, owner, ok := s.Get(ref)
	if !ok || got != "hello world" {
		t.Fatalf("Get(%q) = (%q,%v), want (hello world,true)", ref, got, ok)
	}
	if owner != "alice" {
		t.Fatalf("Get owner = %q, want alice (the creating subject)", owner)
	}
}

// Handles must be unguessable and non-enumerable: random (not sequential), so one
// ref can't reveal the existence of others and the space can't be walked.
func TestMemStoreRefsAreUnguessable(t *testing.T) {
	s := NewMemStore()
	r1, _ := s.Put("a", "")
	r2, _ := s.Put("b", "")
	if r1 == r2 {
		t.Fatalf("two Puts returned the same handle %q", r1)
	}
	for _, r := range []Ref{r1, r2} {
		tok, ok := refToken(r)
		if !ok {
			t.Fatalf("handle %q is malformed", r)
		}
		if len(tok) != refTokenLen {
			t.Fatalf("handle %q token len = %d, want %d", r, len(tok), refTokenLen)
		}
	}
	// Sequential handles would be trivially guessable — assert we are NOT that.
	if r1 == "<ref_1>" || r2 == "<ref_2>" {
		t.Fatalf("handles look sequential (%q,%q) — must be random", r1, r2)
	}
}

// The summary is size-only by design: any raw-byte head here would hand payload
// content back to the model and defeat minimization. The agent-facing preview is
// the values-free structural one computed at the gateway.
func TestMemStoreSummaryCarriesNoPayloadBytes(t *testing.T) {
	s := NewMemStore()
	_, sum := s.Put("abcdefgh", "")
	if sum.Bytes != 8 {
		t.Fatalf("bytes = %d, want 8", sum.Bytes)
	}
	if b, _ := json.Marshal(sum); strings.Contains(string(b), "abcd") {
		t.Fatalf("summary must not carry payload content: %s", b)
	}
}

func TestMemStoreGetUnknownRef(t *testing.T) {
	s := NewMemStore()
	if _, _, ok := s.Get("<ref_99>"); ok {
		t.Fatal("Get on unknown ref returned ok=true")
	}
}

// A bounded store keeps at most maxEntries, evicting the oldest — so a long-lived
// gateway can't accumulate parked payloads for the process lifetime.
func TestBoundedMemStoreEvictsOldest(t *testing.T) {
	s := NewBoundedMemStore(0, 3) // no TTL, cap 3
	refs := make([]Ref, 5)
	for i := range refs {
		refs[i], _ = s.Put(string(rune('a'+i)), "")
	}
	// The two oldest are evicted; the three newest remain.
	for i, ref := range refs {
		_, _, ok := s.Get(ref)
		if i < 2 && ok {
			t.Fatalf("ref %d (%q) should have been evicted", i, ref)
		}
		if i >= 2 && !ok {
			t.Fatalf("ref %d (%q) should still be present", i, ref)
		}
	}
}

// TTL expiry: an entry older than the TTL is gone, both on sweep and on Get.
func TestBoundedMemStoreTTLExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewBoundedMemStore(time.Minute, 0)
	s.now = func() time.Time { return now }
	ref, _ := s.Put("data", "")
	if _, _, ok := s.Get(ref); !ok {
		t.Fatal("fresh entry must be present")
	}
	now = now.Add(2 * time.Minute) // advance past the TTL
	if _, _, ok := s.Get(ref); ok {
		t.Fatal("expired entry must not be returned")
	}
}

// The default NewMemStore is unbounded (back-compat): nothing is evicted.
func TestMemStoreUnboundedByDefault(t *testing.T) {
	s := NewMemStore()
	refs := make([]Ref, 50)
	for i := range refs {
		refs[i], _ = s.Put("x", "")
	}
	for _, ref := range refs {
		if _, _, ok := s.Get(ref); !ok {
			t.Fatalf("unbounded store dropped %q", ref)
		}
	}
}
