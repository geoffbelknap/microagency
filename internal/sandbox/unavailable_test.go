package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestUnavailableProviderReturnsClearError: in a deployment without nested
// virtualization (e.g. microagency running inside a microVM), the microVM
// reduce path is unavailable. The provider must fail every Run with a clear,
// typed error rather than pretend to run.
func TestUnavailableProviderReturnsClearError(t *testing.T) {
	p := UnavailableProvider{Reason: "no nested virtualization in this deployment"}

	_, err := p.Run(context.Background(), Spec{Name: "x", Command: "python /app/run.py"})
	if err == nil {
		t.Fatal("UnavailableProvider.Run must return an error")
	}
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("error should wrap ErrProviderUnavailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "no nested virtualization") {
		t.Fatalf("error should include the reason, got %q", err.Error())
	}
}
