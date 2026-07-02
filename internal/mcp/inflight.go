package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// The in-flight cache decouples a slow READ's execution from the caller's request
// context. An MCP client cancels a tool call at its own timeout (~60s); today that
// cancel propagates and ABORTS the upstream call, wasting work that was nearly done.
// Here the upstream call runs under a detached context (microagency's own 5m bound),
// so a caller cancel doesn't kill it — the work finishes and its result is cached
// briefly, so an identical retry collects it instead of re-dialing. It also
// single-flights: concurrent identical calls share one execution.
//
// READS ONLY. A slow write must NOT continue after the caller gave up (it could
// commit after the client stopped waiting → a retry double-writes), so writes run
// under the caller context as before and this cache never sees them.
const (
	inflightTTL = 90 * time.Second // how long a completed detached result stays collectable
	maxInflight = 256              // cap concurrent + cached entries (ASK 8: operations are bounded)
)

type inflightCall struct {
	done chan struct{}
	res  json.RawMessage
	err  error
	at   time.Time // completion time; zero until done
}

type inflight struct {
	mu    sync.Mutex
	calls map[string]*inflightCall
}

func newInflight() *inflight { return &inflight{calls: map[string]*inflightCall{}} }

// inflightKey identifies a call by upstream + tool + exact arguments.
func inflightKey(upstream, tool string, args json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(upstream))
	h.Write([]byte{0})
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

// do runs fn for key at most once concurrently and caches a SUCCESSFUL result for
// inflightTTL (an error is delivered to the waiters that shared the execution, then
// dropped — a retry re-runs rather than replaying a transient failure).
// waitCtx is the CALLER's context; fn runs under a detached 5m context so a caller
// cancel never aborts it. Returns canceled=true when the caller gave up before the
// result was ready — the detached run keeps going and caches the result for a retry.
// When the cache is at capacity it falls back to running fn under waitCtx (no
// caching), so the guarantee degrades to today's behavior rather than blocking.
func (f *inflight) do(waitCtx context.Context, key string, fn func(context.Context) (json.RawMessage, error)) (res json.RawMessage, err error, canceled bool) {
	f.mu.Lock()
	c, ok := f.calls[key]
	if ok && !c.at.IsZero() { // a completed result is cached
		if time.Since(c.at) < inflightTTL {
			f.mu.Unlock()
			return c.res, c.err, false
		}
		delete(f.calls, key) // stale — re-run
		ok = false
	}
	if !ok {
		f.sweepLocked()
		if len(f.calls) >= maxInflight {
			f.mu.Unlock()
			res, err = fn(waitCtx) // capacity reached: no decoupling, run inline
			return res, err, waitCtx.Err() != nil
		}
		c = &inflightCall{done: make(chan struct{})}
		f.calls[key] = c
		go func() {
			runCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			r, e := fn(runCtx)
			f.mu.Lock()
			c.res, c.err, c.at = r, e, time.Now()
			if e != nil && f.calls[key] == c {
				// An error is delivered to everyone already waiting (they shared this
				// execution) but never CACHED: a transient upstream failure — a 503, a
				// timeout — must not be replayed verbatim to fresh retries for the rest
				// of the TTL. The agent's natural "try again" gets a real re-run.
				delete(f.calls, key)
			}
			f.mu.Unlock()
			close(c.done)
		}()
	}
	f.mu.Unlock()

	select {
	case <-c.done:
		return c.res, c.err, false
	case <-waitCtx.Done():
		return nil, waitCtx.Err(), true
	}
}

// sweepLocked drops completed entries older than the TTL. Caller holds f.mu.
func (f *inflight) sweepLocked() {
	for k, c := range f.calls {
		if !c.at.IsZero() && time.Since(c.at) > inflightTTL {
			delete(f.calls, k)
		}
	}
}
