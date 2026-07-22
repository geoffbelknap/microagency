package mcp

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"microagency/internal/gateway"
)

// An upstream's most-recent call outcome is surfaced in UpstreamList, so an
// operator can see a dead or erroring upstream instead of learning it per call.
func TestUpstreamHealthSurfacedInList(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Fresh: no health yet.
	if info := s.UpstreamList()[0]; info.LastOK != "" || info.LastError != "" {
		t.Fatalf("fresh upstream should carry no health: %+v", info)
	}

	// A failed call is recorded with a timestamp.
	s.recordUpstreamHealth("docs", fmt.Errorf("connection refused"))
	if info := s.UpstreamList()[0]; info.LastError != "connection refused" || info.LastErrorAt == "" {
		t.Fatalf("failure not surfaced: %+v", info)
	}

	// A later success is recorded (last error remains as history).
	s.recordUpstreamHealth("docs", nil)
	if info := s.UpstreamList()[0]; info.LastOK == "" {
		t.Fatalf("success not surfaced: %+v", info)
	}

	// Health for an unknown upstream is a no-op (no panic, nothing recorded).
	s.recordUpstreamHealth("nope", fmt.Errorf("x"))
}
