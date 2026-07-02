package refstore

import "sync"

// MemStore is an in-memory Store with unguessable, random ref handles. Safe for
// concurrent use.
type MemStore struct {
	mu    sync.Mutex
	items map[Ref]string
	// newID mints a handle; defaults to randRef. Injectable so tests can force a
	// known (or colliding) sequence — the mint loop still guarantees uniqueness.
	newID func() Ref
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{items: map[Ref]string{}, newID: randRef}
}

func (s *MemStore) Put(payload string) (Ref, Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := s.mintLocked()
	s.items[ref] = payload
	return ref, Summary{Bytes: len(payload)}
}

// mintLocked returns a fresh handle not already in use, so a repeated id source
// (e.g. a deterministic test generator) can never overwrite an existing entry.
func (s *MemStore) mintLocked() Ref {
	for {
		ref := s.newID()
		if _, exists := s.items[ref]; !exists {
			return ref
		}
	}
}

func (s *MemStore) Get(ref Ref) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[ref]
	return p, ok
}
