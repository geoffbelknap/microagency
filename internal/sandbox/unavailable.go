package sandbox

import (
	"context"
	"errors"
	"fmt"
)

// ErrProviderUnavailable marks a reduce that needed the microVM sandbox in a
// deployment where it is not available. Callers can test for it with
// errors.Is to route the failure to a clear "engines-only" message.
var ErrProviderUnavailable = errors.New("microVM reduce unavailable in this deployment")

// UnavailableProvider is a sandbox.Provider that always fails: the microVM
// reduce path is disabled (e.g. microagency running inside a microVM with no
// nested virtualization). Declarative reduce over the wasm engines is
// unaffected — those never reach the provider. Every Run returns
// ErrProviderUnavailable so the failure is explicit, never a silent no-op.
type UnavailableProvider struct {
	Reason string
}

func (p UnavailableProvider) Run(_ context.Context, _ Spec) (Result, error) {
	if p.Reason != "" {
		return Result{}, fmt.Errorf("%w: %s", ErrProviderUnavailable, p.Reason)
	}
	return Result{}, ErrProviderUnavailable
}
