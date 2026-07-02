package mcp

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"runtime"
	"runtime/debug"
	"time"

	"microagency/internal/sandbox"
	"microagency/internal/secretstore"
)

// InfraComponent is one runtime component's real status for the console footer.
// Status is "ok" (healthy), "warn" (unknown/degraded but not down), "bad"
// (down/tampered), or "off" (intentionally not configured). Detail carries the
// same signals `microagency doctor` prints, shown when the operator clicks it.
type InfraComponent struct {
	Key    string         `json:"key"`
	Label  string         `json:"label"`
	Status string         `json:"status"`
	Detail map[string]any `json:"detail,omitempty"`
}

// InfraBuild identifies the running binary from its embedded VCS stamp.
type InfraBuild struct {
	Version  string `json:"version,omitempty"` // release version (main.version via -ldflags)
	Revision string `json:"revision"`
	Time     string `json:"time,omitempty"`
	Go       string `json:"go"`
	Modified bool   `json:"modified"`
}

// InfraHost identifies who and where this operator surface runs: the OS user the
// daemon runs as, and the address the console is bound to. Loopback is true when
// that bind is local-only (the default, most private posture) — false when the
// console is reachable over the network.
type InfraHost struct {
	User     string `json:"user"`           // OS user the daemon runs as
	Addr     string `json:"addr,omitempty"` // console bind address, e.g. 127.0.0.1:8765
	Loopback bool   `json:"loopback"`       // bound to a local-only address
}

// InfraStatus is the console footer's data: what's actually running, probed live.
type InfraStatus struct {
	Build      InfraBuild       `json:"build"`
	Host       InfraHost        `json:"host"`
	Components []InfraComponent `json:"components"`
}

// InfraStatus reports the real health of microagency's runtime components — the
// same picture `microagency doctor` gives, served to the console so the footer
// reflects truth instead of a static list. The sandbox and secret probes are
// time-bounded and best-effort; nothing here fabricates a status.
func (s *Server) InfraStatus(ctx context.Context) InfraStatus {
	st := InfraStatus{Build: buildInfo()}
	st.Build.Version = s.version
	st.Host = hostInfo(s.consoleAddr)

	// gateway — if this handler answered, the gateway + admin plane are up.
	st.Components = append(st.Components, InfraComponent{
		Key: "gateway", Label: "gateway", Status: "ok",
		Detail: map[string]any{"note": "serving the admin API and the MCP endpoint"},
	})

	// secrets — the credential store that keeps upstream tokens off the agent.
	st.Components = append(st.Components, s.secretsComponent(ctx))

	// index — the tool catalog the agent searches instead of tools/list.
	ups := s.UpstreamList()
	enabled := 0
	for _, u := range ups {
		if u.State == "enabled" {
			enabled++
		}
	}
	st.Components = append(st.Components, InfraComponent{
		Key: "index", Label: "index", Status: "ok",
		Detail: map[string]any{"connections": len(ups), "enabled": enabled, "discovered": len(ups) - enabled},
	})

	// engines — the wasm reduce substrate (declarative off-context compute).
	engines := s.wasmEngineNames()
	eng := InfraComponent{Key: "engines", Label: "query engines", Status: "ok",
		Detail: map[string]any{"engines": engines}}
	if len(engines) == 0 {
		eng.Status = "off"
		eng.Detail = map[string]any{"note": "declarative reduce is disabled — no engines loaded"}
	}
	st.Components = append(st.Components, eng)

	// sandbox — the microVM (code) runtime; the exact probe `doctor` runs.
	st.Components = append(st.Components, sandboxComponent(ctx))

	// audit — the tamper-evident hash chain.
	st.Components = append(st.Components, s.auditComponent())

	return st
}

func (s *Server) secretsComponent(ctx context.Context) InfraComponent {
	c := InfraComponent{Key: "secrets", Label: "secrets", Status: "off",
		Detail: map[string]any{"note": "in-memory only — credentials are not persisted across restart"}}
	if s.secrets == nil {
		return c
	}
	kind := s.secrets.Kind() // "vault" | "file"
	c.Label = kind
	// A cheap Load probes reachability; ErrNotFound still means the store answered.
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	reachable := true
	if _, err := s.secrets.Load(probeCtx, "infra-probe/__unused__"); err != nil && !errors.Is(err, secretstore.ErrNotFound) {
		reachable = false
	}
	c.Detail = map[string]any{"backend": kind, "reachable": reachable}
	switch {
	case !reachable:
		c.Status = "bad"
	case kind == "file":
		// OpenBao is the managed default and is always attempted; the file store is
		// only reached when Bao couldn't come up. It works (0600 file) but it's a
		// degraded posture — not the encrypted vault, and it diverges from a Bao that
		// later recovers — so warn rather than report a healthy "ok".
		c.Status = "warn"
		c.Detail["note"] = "OpenBao unavailable — using the local file store (0600). Credentials persist, but not in the encrypted vault; check the openbao logs under ~/.microagency/openbao."
	default:
		c.Status = "ok"
	}
	return c
}

func sandboxComponent(ctx context.Context) InfraComponent {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	h := sandbox.InspectRuntime(probeCtx)
	c := InfraComponent{Key: "microvm", Label: "microVM", Detail: map[string]any{
		"backend": h.Backend, "architecture": h.Architecture,
		"virtualization": h.Virtualization, "supervisor_ready": h.SupervisorReady,
		"guest_init_ready": h.GuestInitReady, "kvm": h.KVM, "vsock": h.Vsock,
		"version": h.Version, "probe_error": h.ProbeError,
	}}
	switch {
	case h.Usable():
		c.Status = "ok"
	case !h.Probed():
		c.Status = "warn" // unknown — reduce(code) may still work; the wasm engines don't need it
	default:
		c.Status = "bad"
	}
	return c
}

func (s *Server) auditComponent() InfraComponent {
	c := InfraComponent{Key: "audit", Label: "audit", Status: "ok"}
	v, err := VerifyAuditLog(s.auditPath())
	if err != nil {
		c.Status = "warn"
		c.Detail = map[string]any{"note": "no audit entries yet"}
		return c
	}
	c.Detail = map[string]any{"intact": v.Intact, "lines": v.Lines}
	if !v.Intact {
		c.Status = "bad"
		c.Detail["break_at"] = v.BreakAt
	}
	return c
}

// hostInfo reports the OS user the daemon runs as and the console bind address,
// with Loopback set when that address is local-only. A missing addr (plain `go
// build` / tests) leaves Addr empty and Loopback false — the browser then falls
// back to its own location.
func hostInfo(consoleAddr string) InfraHost {
	h := InfraHost{User: osUsername(), Addr: consoleAddr}
	if consoleAddr == "" {
		return h
	}
	host := consoleAddr
	if hh, _, err := net.SplitHostPort(consoleAddr); err == nil {
		host = hh
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		h.Loopback = true
	}
	return h
}

// osUsername is the OS user the process runs as, for the console header. Falls
// back to $USER, then "unknown", so it never blocks the status probe.
func osUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("USER"); n != "" {
		return n
	}
	return "unknown"
}

// buildInfo reads the binary's embedded VCS stamp (go build records it
// automatically). No stamp (e.g. `go run`) yields revision "unknown".
func buildInfo() InfraBuild {
	b := InfraBuild{Revision: "unknown", Go: runtime.Version()}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range info.Settings {
			switch kv.Key {
			case "vcs.revision":
				b.Revision = kv.Value
			case "vcs.time":
				b.Time = kv.Value
			case "vcs.modified":
				b.Modified = kv.Value == "true"
			}
		}
	}
	return b
}
