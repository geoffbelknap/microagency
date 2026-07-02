package refstore

import (
	"fmt"
	"sync"
)

// MemStore is an in-memory Store with deterministic, sequential ref handles.
// Safe for concurrent use.
type MemStore struct {
	mu    sync.Mutex
	seq   int
	items map[Ref]string
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{items: map[Ref]string{}}
}

func (s *MemStore) Put(payload string) (Ref, Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	ref := Ref(fmt.Sprintf("<ref_%d>", s.seq))
	s.items[ref] = payload
	return ref, Summary{Bytes: len(payload)}
}

func (s *MemStore) Get(ref Ref) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[ref]
	return p, ok
}
