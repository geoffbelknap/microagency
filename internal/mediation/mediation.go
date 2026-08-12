// Package mediation binds a microagency gateway to a microagent workspace whose
// only direct network destination is the gateway itself.
//
// The deliberately narrow policy avoids synchronizing a changing denylist into
// a running VM. microagent's host-owned locked allowlist admits the gateway host
// and denies every other hostname and direct IP. Upstream churn therefore cannot
// make an old workspace policy fail open; the only unsafe topology (an enabled
// upstream sharing the gateway host) is rejected by microagency.
package mediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/geoffbelknap/microagent/pkg/vmkit"
	"github.com/geoffbelknap/microagent/pkg/workspace"
)

const (
	FileName              = "mediation.json"
	ModeEnforcedWorkspace = "enforced-workspace"
	Version               = 1
)

// Binding is non-secret operator intent. GatewayURL is the MCP URL visible to
// the guest; it must never contain credentials or userinfo.
type Binding struct {
	Version           int       `json:"version"`
	Mode              string    `json:"mode"`
	Workspace         string    `json:"workspace"`
	WorkspaceStateDir string    `json:"workspace_state_dir"`
	GatewayURL        string    `json:"gateway_url"`
	GatewayHost       string    `json:"gateway_host"`
	PolicyDigest      string    `json:"policy_digest"`
	AppliedAt         time.Time `json:"applied_at"`
}

type Status struct {
	Mode           string   `json:"mode"`
	State          string   `json:"state"` // advisory | configured | enforced | degraded | unsupported
	Workspace      string   `json:"workspace,omitempty"`
	GatewayURL     string   `json:"gateway_url,omitempty"`
	GatewayHost    string   `json:"gateway_host,omitempty"`
	PolicyDigest   string   `json:"policy_digest,omitempty"`
	WorkspaceState string   `json:"workspace_state,omitempty"`
	Backend        string   `json:"backend,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Uncovered      []string `json:"uncovered,omitempty"`
}

// Denial is the structured correlation of one host-side microagent egress deny
// with the upstream identities protected by that destination.
type Denial struct {
	Timestamp   string         `json:"timestamp,omitempty"`
	Event       string         `json:"event"`
	Destination string         `json:"destination"`
	Upstreams   []string       `json:"upstreams,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
}

func Path(stateDir string) string { return filepath.Join(stateDir, FileName) }

func Load(stateDir string) (Binding, error) {
	if strings.TrimSpace(stateDir) == "" {
		return Binding{}, os.ErrNotExist
	}
	b, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return Binding{}, err
	}
	var binding Binding
	if err := json.Unmarshal(b, &binding); err != nil {
		return Binding{}, fmt.Errorf("decode mediation binding: %w", err)
	}
	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

func (b Binding) Validate() error {
	if b.Version != Version || b.Mode != ModeEnforcedWorkspace {
		return fmt.Errorf("unsupported mediation binding version/mode %d/%q", b.Version, b.Mode)
	}
	if err := workspace.ValidateName(b.Workspace); err != nil {
		return fmt.Errorf("mediation workspace: %w", err)
	}
	if strings.TrimSpace(b.WorkspaceStateDir) == "" {
		return errors.New("mediation workspace state directory is empty")
	}
	host, clean, err := gatewayEndpoint(b.GatewayURL)
	if err != nil {
		return err
	}
	if host != b.GatewayHost || clean != b.GatewayURL {
		return errors.New("mediation gateway URL/host is not canonical")
	}
	if b.PolicyDigest != policyDigest(host) {
		return errors.New("mediation policy digest does not match the gateway host")
	}
	return nil
}

// NewBinding validates and canonicalizes non-secret binding intent without
// touching either repository's state. Callers use it to preflight upstream
// topology before applying the workspace policy.
func NewBinding(workspaceStateDir, name, rawGatewayURL string) (Binding, error) {
	host, gatewayURL, err := gatewayEndpoint(rawGatewayURL)
	if err != nil {
		return Binding{}, err
	}
	if err := workspace.ValidateName(name); err != nil {
		return Binding{}, err
	}
	if strings.TrimSpace(workspaceStateDir) == "" {
		workspaceStateDir = workspace.DefaultOptions().StateDir
	}
	return Binding{
		Version: Version, Mode: ModeEnforcedWorkspace, Workspace: name,
		WorkspaceStateDir: workspaceStateDir, GatewayURL: gatewayURL,
		GatewayHost: host, PolicyDigest: policyDigest(host),
	}, nil
}

// Enforce applies the supported microagent launch-time contract to a stopped
// workspace, verifies the persisted result, then publishes the binding
// atomically. A running workspace is never rewritten under a live mediator.
func Enforce(stateDir, workspaceStateDir, name, rawGatewayURL string) (Binding, error) {
	binding, err := NewBinding(workspaceStateDir, name, rawGatewayURL)
	if err != nil {
		return Binding{}, err
	}
	host := binding.GatewayHost
	workspaceStateDir = binding.WorkspaceStateDir
	if state, _, stateErr := workspace.LatestStartState(workspaceStateDir, name); stateErr == nil && state == vmkit.StateRunning {
		return Binding{}, fmt.Errorf("workspace %q is running; halt it before changing its host-owned egress policy", name)
	}
	opts := workspace.DefaultOptions()
	opts.StateDir = workspaceStateDir
	if _, err := workspace.Apply(context.Background(), opts, workspace.Spec{
		Name: name,
		Agent: workspace.AgentSpec{
			Egress: vmkit.EgressModeBroker, Allow: []string{host}, LockAllowlist: true,
		},
	}); err != nil {
		return Binding{}, fmt.Errorf("apply workspace egress policy: %w", err)
	}

	got, err := workspace.ReadManifest(workspaceStateDir, name)
	if err != nil || !manifestEnforces(got, host) {
		if err == nil {
			err = errors.New("persisted workspace policy did not match the enforced contract")
		}
		return Binding{}, fmt.Errorf("verify workspace egress policy: %w", err)
	}
	binding.AppliedAt = time.Now().UTC()
	if err := writeAtomic(Path(stateDir), binding); err != nil {
		return Binding{}, fmt.Errorf("save mediation binding: %w", err)
	}
	return binding, nil
}

func Inspect(stateDir string) Status {
	b, err := Load(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return Status{
			Mode: "advisory-local", State: "advisory",
			Reason:    "local hook and client-config checks warn but do not enforce network mediation",
			Uncovered: []string{"local-host clients", "remote clients", "workspaces not explicitly bound"},
		}
	}
	if err != nil {
		return Status{Mode: ModeEnforcedWorkspace, State: "degraded", Reason: err.Error()}
	}
	st := Status{
		Mode: b.Mode, State: "configured", Workspace: b.Workspace, GatewayURL: b.GatewayURL,
		GatewayHost: b.GatewayHost, PolicyDigest: b.PolicyDigest,
		Uncovered: []string{"local-host clients", "remote clients", "other workspaces"},
	}
	manifest, err := workspace.ReadManifest(b.WorkspaceStateDir, b.Workspace)
	if err != nil {
		st.State, st.Reason = "degraded", "workspace manifest unavailable: "+err.Error()
		return st
	}
	opts := workspace.OptionsFromManifest(workspace.DefaultOptions(), manifest)
	st.Backend = opts.Backend
	if !manifestEnforces(manifest, b.GatewayHost) {
		st.State, st.Reason = "degraded", "workspace policy differs from the locked gateway-only contract"
		return st
	}
	policy := vmkit.NormalizeEgressPolicy(vmkit.EgressPolicy{Mode: manifest.EgressMode, Allow: manifest.EgressAllow, AllowlistLocked: manifest.EgressAllowlistLocked})
	if err := policy.ValidateForCaptureProvider(opts.Backend, opts.Network.Mode); err != nil {
		st.State, st.Reason = "unsupported", err.Error()
		return st
	}
	state, _, stateErr := workspace.LatestStartState(b.WorkspaceStateDir, b.Workspace)
	if stateErr != nil {
		st.WorkspaceState, st.Reason = "prepared", "policy is configured; start the workspace to enforce it"
		return st
	}
	st.WorkspaceState = string(state)
	if state == vmkit.StateRunning {
		runtimeState, runtimeErr := workspace.ReadRuntimeState(workspace.Options{StateDir: b.WorkspaceStateDir, Name: b.Workspace})
		if runtimeErr != nil || !configEnforces(runtimeState.Config, b.GatewayHost) {
			st.State = "degraded"
			if runtimeErr != nil {
				st.Reason = "running workspace policy cannot be verified: " + runtimeErr.Error()
			} else {
				st.Reason = "running workspace policy differs from the locked gateway-only contract"
			}
			return st
		}
		response, statusErr := workspace.Status(workspace.Options{StateDir: b.WorkspaceStateDir, Name: b.Workspace, Backend: opts.Backend})
		if statusErr != nil || response.EgressCapture == nil || response.EgressCapture.Live == nil || !*response.EgressCapture.Live {
			st.State = "degraded"
			st.Reason = "host egress mediator liveness is not verified"
			if statusErr != nil {
				st.Reason += ": " + statusErr.Error()
			}
			return st
		}
		st.State = "enforced"
		st.Reason = "host-owned locked allowlist admits only the gateway host"
	} else {
		st.Reason = "policy is configured; enforcement is active whenever the workspace runs"
	}
	return st
}

func configEnforces(c vmkit.Config, gatewayHost string) bool {
	return manifestEnforces(workspace.Manifest{
		EgressMode: c.EgressMode, EgressAllow: c.EgressAllow,
		EgressPassthrough: c.EgressPassthrough, EgressAllowlistLocked: c.EgressAllowlistLocked,
	}, gatewayHost)
}

// ValidateUpstream rejects the only endpoint topology that could bypass a
// gateway-only allowlist: an HTTP(S) upstream hosted on the allowed gateway
// hostname. Non-network transports are outside this egress contract.
func ValidateUpstream(b Binding, endpoint string) error {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Hostname() == "" {
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	if normalizeHost(u.Hostname()) == b.GatewayHost {
		return fmt.Errorf("upstream host %q equals enforced workspace gateway host; use a dedicated gateway host identity", b.GatewayHost)
	}
	return nil
}

// Denials reads the host-side mediator audit and correlates denied named
// destinations with the current protected upstream host map.
func Denials(b Binding, contributors map[string][]string) ([]Denial, error) {
	events, err := workspace.ReadEgressAudit(b.WorkspaceStateDir, b.Workspace)
	var integrityErr workspace.AuditIntegrityError
	if err != nil && !errors.As(err, &integrityErr) {
		return nil, err
	}
	var out []Denial
	for _, ev := range events {
		if !strings.HasSuffix(ev.Event, "_deny") && ev.Event != "egress_deny" {
			continue
		}
		dst := firstNonEmpty(ev.Host, rawString(ev.Raw, "qname"), ev.Dst)
		host := destinationHost(dst)
		ups := append([]string(nil), contributors[host]...)
		sort.Strings(ups)
		out = append(out, Denial{Timestamp: ev.TS, Event: ev.Event, Destination: dst, Upstreams: ups, Reason: ev.Reason, Raw: ev.Raw})
	}
	return out, err
}

func manifestEnforces(m workspace.Manifest, gatewayHost string) bool {
	if vmkit.ResolveEgressModeDefault(m.EgressMode) != vmkit.EgressModeBroker || !m.EgressAllowlistLocked || len(m.EgressPassthrough) != 0 {
		return false
	}
	if len(m.EgressAllow) != 1 {
		return false
	}
	return normalizeHost(m.EgressAllow[0]) == gatewayHost
}

func gatewayEndpoint(raw string) (host, clean string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("--gateway must be an http(s) MCP URL without credentials, query, or fragment")
	}
	host = normalizeHost(u.Hostname())
	if host == "" {
		return "", "", errors.New("--gateway URL has no hostname")
	}
	if strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return "", "", errors.New("--gateway must use the host identity reachable from the workspace, not guest loopback")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" || u.Path == "/" {
		u.Path = "/mcp"
	}
	return host, u.String(), nil
}

func normalizeHost(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

func destinationHost(dst string) string {
	dst = strings.TrimSpace(dst)
	if h, _, err := net.SplitHostPort(dst); err == nil {
		return normalizeHost(h)
	}
	return normalizeHost(dst)
}

func policyDigest(host string) string {
	sum := sha256.Sum256([]byte("broker\nlocked\n" + normalizeHost(host) + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".mediation-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func rawString(raw map[string]any, key string) string {
	value, _ := raw[key].(string)
	return value
}
