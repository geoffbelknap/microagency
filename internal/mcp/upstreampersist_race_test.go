package mcp

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// The persistence layer must serialize its read-modify-write of upstreams.json.
// Before the persistMu funnel, concurrent mutators each did load → mutate → write
// with no lock, so two interleaved writes silently dropped one registration. This
// registers N upstreams concurrently and then mutates them concurrently; every one
// must survive. Run under -race, it also proves the file access is data-race free.
func TestConcurrentRegistrationsNoLostUpdates(t *testing.T) {
	s := NewServer(fakeRunner{}, WithStateDir(t.TempDir()))
	const n = 40

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("up%02d", i)
			s.persistRegistration(name, "https://example.test/"+name, false, authStatic, "")
			// Follow-on mutations that each do their own load-modify-write.
			s.persistReadOnly(name, i%2 == 0)
			s.persistOwner(name, fmt.Sprintf("owner%02d", i))
		}(i)
	}
	wg.Wait()

	regs := s.loadRegistrations()
	if len(regs) != n {
		t.Fatalf("lost updates: persisted %d registrations, want %d", len(regs), n)
	}
	seen := make(map[string]upstreamReg, len(regs))
	for _, r := range regs {
		seen[r.Name] = r
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("up%02d", i)
		r, ok := seen[name]
		if !ok {
			t.Fatalf("registration %q was dropped", name)
		}
		if want := fmt.Sprintf("owner%02d", i); r.Owner != want {
			t.Errorf("%q owner = %q, want %q", name, r.Owner, want)
		}
		if want := i%2 == 0; r.ReadOnly != want {
			t.Errorf("%q read-only = %v, want %v", name, r.ReadOnly, want)
		}
	}
}

// removeRegistration racing with concurrent adds must also be consistent: the
// remove takes effect and no unrelated registration is lost.
func TestConcurrentRegisterAndRemove(t *testing.T) {
	s := NewServer(fakeRunner{}, WithStateDir(t.TempDir()))
	ctx := context.Background()
	const n = 30

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("k%02d", i)
			s.persistRegistration(name, "https://example.test/"+name, false, authNone, "")
			if i%3 == 0 { // remove a third of them concurrently
				s.removeRegistration(ctx, name)
			}
		}(i)
	}
	wg.Wait()

	regs := s.loadRegistrations()
	want := 0
	for i := 0; i < n; i++ {
		if i%3 != 0 {
			want++
		}
	}
	if len(regs) != want {
		t.Fatalf("after concurrent add/remove: %d registrations, want %d", len(regs), want)
	}
	for _, r := range regs {
		var i int
		fmt.Sscanf(r.Name, "k%d", &i)
		if i%3 == 0 {
			t.Errorf("%q should have been removed", r.Name)
		}
	}
}
