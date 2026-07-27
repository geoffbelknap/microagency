package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/geoffbelknap/microagent/pkg/workspace"
)

// selfCheckName is the workspace the doctor's end-to-end check runs as. On
// success it is deleted; on failure it is kept so the operator can inspect
// it with the microagent CLI.
const selfCheckName = "m2-doctor-selfcheck"

// selfCheckMarker is what the probe code prints; seeing it back proves the
// whole path — rootfs build, boot, file injection, interpreter, result
// channel — not just the pieces.
const selfCheckMarker = "microagency-selfcheck-ok"

// SelfCheckResult is what an end-to-end probe of the reduce(code) substrate
// established. Exactly one of OK / TimedOut / a failure Detail describes the
// outcome.
type SelfCheckResult struct {
	OK       bool
	TimedOut bool
	// Detail is operator-safe text for the failure classes: the guest's own
	// start diagnosis (substrate text, never workload output), or an
	// exit-class summary. Empty when OK.
	Detail string
	// Kept reports that the failed workspace was preserved under
	// selfCheckName for inspection.
	Kept bool
}

// SelfCheck boots a trivial reduce(code) through the same provider, image,
// and code path a real reduce uses, and reports what actually happened.
//
// This exists because doctor's affirmative verdict used to be gated on host
// prerequisites alone. A host can hold every prerequisite and still fail
// every reduce — the poisoned-rootfs incident was exactly that shape, live
// for two days behind a green verdict. A claim that reduce(code) will work
// is only honest when a reduce(code) worked.
func SelfCheck(ctx context.Context, image, codePath string, timeout time.Duration) SelfCheckResult {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	p := MicroagentProvider{}
	res, err := p.Run(ctx, Spec{
		Name:     selfCheckName,
		Image:    image,
		Code:     fmt.Sprintf("print(%q)", selfCheckMarker),
		CodePath: codePath,
		Command:  "python " + codePath,
		Timeout:  timeout,
	})
	if err != nil {
		if ctx.Err() != nil {
			// Ran out of budget, not out of substrate: a cold image cache
			// pulls the workload image on first use, which can dominate the
			// window. Nothing was established either way.
			return SelfCheckResult{TimedOut: true}
		}
		return SelfCheckResult{Detail: fmt.Sprintf("the sandbox failed before returning a result: %v", err), Kept: true}
	}
	switch {
	case res.StartError != "":
		return SelfCheckResult{Detail: "the guest could not start the code runner: " + res.StartError, Kept: true}
	case res.ExitCode != 0:
		return SelfCheckResult{Detail: fmt.Sprintf("the probe exited %d", res.ExitCode), Kept: true}
	case !strings.Contains(res.Stdout, selfCheckMarker):
		return SelfCheckResult{Detail: "the probe ran but its output never came back", Kept: true}
	}
	// Only a clean pass deletes the evidence.
	cleanupWorkspace(context.WithoutCancel(ctx), workspace.DefaultOptions(), selfCheckName)
	return SelfCheckResult{OK: true}
}
