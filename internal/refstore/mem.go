package refstore

import (
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store with unguessable, random ref handles. Retention
// can be BOUNDED (a TTL and a max-entry cap, swept lazily on write) so a
// long-lived gateway that parks many results doesn't grow without limit — the
// in-memory analog of FileStore's bounds. Safe for concurrent use.
type MemStore struct {
	mu         sync.Mutex
	items      map[Ref]memItem
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	// newID mints a handle; defaults to randRef. Injectable so tests can force a
	// known (or colliding) sequence — the mint loop still guarantees uniqueness.
	newID func() Ref
}

type memItem struct {
	payload string
	created time.Time
}

// NewMemStore returns an empty, UNBOUNDED MemStore (no TTL, no cap). Suitable for
// tests and short-lived processes; a long-running server should use
// NewBoundedMemStore so parked results can't accumulate for the process lifetime.
func NewMemStore() *MemStore {
	return &MemStore{items: map[Ref]memItem{}, now: time.Now, newID: randRef}
}

// NewBoundedMemStore returns a MemStore that expires entries older than ttl and
// keeps at most maxEntries (evicting the oldest). ttl<=0 disables expiry;
// maxEntries<=0 disables the cap.
func NewBoundedMemStore(ttl time.Duration, maxEntries int) *MemStore {
	s := NewMemStore()
	s.ttl, s.maxEntries = ttl, maxEntries
	return s
}

func (s *MemStore) Put(payload string) (Ref, Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := s.mintLocked()
	s.items[ref] = memItem{payload: payload, created: s.now()}
	s.sweepLocked() // after the write, so the cap counts the new entry (never evicts it — it's newest)
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
	it, ok := s.items[ref]
	if !ok {
		return "", false
	}
	if s.ttl > 0 && s.now().Sub(it.created) > s.ttl {
		delete(s.items, ref) // expired — drop it
		return "", false
	}
	return it.payload, true
}

// sweepLocked drops expired entries and, if over the cap, the oldest — bounding
// retention (mirrors FileStore.sweepLocked).
func (s *MemStore) sweepLocked() {
	if s.ttl <= 0 && s.maxEntries <= 0 {
		return
	}
	if s.ttl > 0 {
		now := s.now()
		for ref, it := range s.items {
			if now.Sub(it.created) > s.ttl {
				delete(s.items, ref)
			}
		}
	}
	if s.maxEntries > 0 && len(s.items) > s.maxEntries {
		type item struct {
			ref     Ref
			created time.Time
		}
		live := make([]item, 0, len(s.items))
		for ref, it := range s.items {
			live = append(live, item{ref, it.created})
		}
		sort.Slice(live, func(i, j int) bool { return live[i].created.Before(live[j].created) })
		for _, it := range live[:len(live)-s.maxEntries] {
			delete(s.items, it.ref)
		}
	}
}
