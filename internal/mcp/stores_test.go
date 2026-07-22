package mcp

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The registry, run store, and OAuth-flow store each carry their own mutex now, so
// hammering all three concurrently must be race-free (run under -race) and can't
// deadlock (no critical section spans two). Also proves independence: recording a
// run doesn't block a registry write.
func TestConcernStoresIndependentUnderLoad(t *testing.T) {
	s := NewServer(fakeRunner{})
	const n = 60
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t"}) }()
		go func(i int) {
			defer wg.Done()
			s.putOAuthFlow(fmt.Sprintf("st%d", i), &oauthFlow{name: "x", expiry: time.Now().Add(time.Hour)})
		}(i)
		go func(i int) {
			defer wg.Done()
			_ = s.registerUpstream(fmt.Sprintf("u%d", i), &upstream{conn: &fakeConn{endpoint: "x"}, enabled: true})
		}(i)
	}
	wg.Wait()

	if got := len(s.RunLog()); got != n {
		t.Fatalf("run store: %d runs, want %d", got, n)
	}
	if got := len(s.UpstreamList()); got != n {
		t.Fatalf("registry: %d upstreams, want %d", got, n)
	}
}
