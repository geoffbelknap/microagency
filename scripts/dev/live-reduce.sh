#!/usr/bin/env bash
# Run the real reduce(code) probe on the current supported microagent host.
# This must run directly on a host with KVM or Apple Virtualization.framework.
set -euo pipefail

case "${MICROAGENT_E2E_BACKEND:-}" in
  linux-kvm | apple-vf)
    backend="$MICROAGENT_E2E_BACKEND"
    ;;
  applevf)
    backend="apple-vf"
    ;;
  "")
    case "$(uname -s)" in
      Linux) backend="linux-kvm" ;;
      Darwin) backend="apple-vf" ;;
      *) echo "live-reduce: unsupported host $(uname -s)/$(uname -m)" >&2; exit 2 ;;
    esac
    ;;
  *)
    echo "live-reduce: unknown MICROAGENT_E2E_BACKEND=$MICROAGENT_E2E_BACKEND" >&2
    exit 2
    ;;
esac

host_microagent="$(command -v microagent 2>/dev/null || true)"

state_parent="${MICROAGENCY_LIVE_STATE_DIR:-/tmp}"
mkdir -p "$state_parent"
task_root="$(mktemp -d "$state_parent/ma-live.XXXXXX")"
state_base="$task_root/state"
mkdir -p "$state_base"

artifact_dir="${MICROAGENCY_LIVE_ARTIFACT_DIR:-$task_root}"
mkdir -p "$artifact_dir"
report="$artifact_dir/live-reduce-${backend}.txt"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
commit="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
microagent_runtime=unavailable

write_report() {
  local result="$1"
  local completed="$2"
  {
    printf 'result=%s\n' "$result"
    printf 'backend=%s\n' "$backend"
    printf 'commit=%s\n' "$commit"
    printf 'microagent=%s\n' "$microagent_runtime"
    printf 'started=%s\n' "$started"
    printf 'completed=%s\n' "$completed"
    printf 'diagnostic_state=%s\n' "$task_root"
  } > "$report"

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### Live reduce(code): %s\n\n' "$backend"
      printf -- "- Result: \`%s\`\n" "$result"
      printf -- "- Commit: \`%s\`\n" "$commit"
      printf -- "- Completed: \`%s\`\n" "$completed"
      if [ "$result" != passed ]; then
        printf -- "- Diagnostic state: \`%s\`\n" "$task_root"
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

record_failure() {
  status="$?"
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    write_report failed "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "live-reduce: $backend failed; preserved diagnostic state at $task_root" >&2
  fi
  exit "$status"
}
trap record_failure EXIT

# A library consumer must run companion binaries from the same microagent
# release as its Go module. Otherwise a host-wide newer guest-init can silently
# impose a different boot protocol. Linux companions are Go binaries, so build
# the pinned set into this task root unless the caller supplied an exact runtime.
if [ "$backend" = linux-kvm ] && [ -z "${MICROAGENT_FIRECRACKER_SUPERVISOR:-}" ]; then
  microagent_version="$(go list -m -f '{{.Version}}' github.com/geoffbelknap/microagent)"
  runtime="$task_root/runtime"
  mkdir -p "$runtime/bin" "$runtime/libexec"
  GOBIN="$runtime/bin" GOCACHE="$task_root/go-cache" go install "github.com/geoffbelknap/microagent/cmd/microagent@${microagent_version}"
  GOBIN="$runtime/bin" GOCACHE="$task_root/go-cache" go install "github.com/geoffbelknap/microagent/cmd/microagent-guestinit@${microagent_version}"
  GOBIN="$runtime/bin" GOCACHE="$task_root/go-cache" go install "github.com/geoffbelknap/microagent/cmd/microagent-firecracker-supervisor@${microagent_version}"
  cp "$runtime/bin/microagent-guestinit" "$runtime/libexec/microagent-guestinit-$(go env GOARCH)"
  PATH="$runtime/bin:$PATH"
  export PATH
  MICROAGENT_FIRECRACKER_SUPERVISOR="$runtime/bin/microagent-firecracker-supervisor"
  export MICROAGENT_FIRECRACKER_SUPERVISOR
fi

if [ "$backend" = linux-kvm ] && [ -z "${MICROAGENT_FIRECRACKER:-}" ]; then
  if firecracker_path="$(command -v firecracker 2>/dev/null)"; then
    MICROAGENT_FIRECRACKER="$firecracker_path"
  elif [ -n "$host_microagent" ]; then
    host_microagent="$(readlink -f "$host_microagent")"
    candidate="$(dirname "$host_microagent")/../libexec/firecracker"
    if [ -x "$candidate" ]; then
      MICROAGENT_FIRECRACKER="$candidate"
    fi
  fi
  if [ -z "${MICROAGENT_FIRECRACKER:-}" ]; then
    echo "live-reduce: Firecracker is not installed; set MICROAGENT_FIRECRACKER to its executable" >&2
    exit 2
  fi
  export MICROAGENT_FIRECRACKER
fi

if [ "$backend" = apple-vf ] && [ -z "${MICROAGENT_APPLEVF_SUPERVISOR:-}" ]; then
  echo "live-reduce: Apple VF requires a supervisor built from the microagent version pinned in go.mod" >&2
  echo "live-reduce: set MICROAGENT_APPLEVF_SUPERVISOR to that signed binary" >&2
  exit 2
fi

# The microagent library falls back to os.Executable when it launches the
# Apple VF host-fd egress datapath. Under go test that is this package's test
# binary, which has no --egress-datapath mode. Pin the datapath to the same
# task-owned microagent CLI selected above so mediated boots use one release.
if [ "$backend" = apple-vf ]; then
  if [ -z "$host_microagent" ] || [ ! -x "$host_microagent" ]; then
    echo "live-reduce: Apple VF requires the pinned microagent CLI on PATH" >&2
    exit 2
  fi
  MICROAGENT_EGRESS_DATAPATH_BIN="$host_microagent"
  export MICROAGENT_EGRESS_DATAPATH_BIN
fi

microagent_runtime="$(microagent version 2>/dev/null || printf unavailable)"

MICROAGENCY_LIVE_REDUCE=1 \
MICROAGENT_E2E_BACKEND="$backend" \
MICROAGENCY_LIVE_STATE_DIR="$state_base" \
MICROAGENCY_LIVE_CACHE_DIR="$task_root/rootfs-cache" \
GOCACHE="$task_root/go-cache" \
go test -count=1 -v ./internal/mcp -run '^TestLiveReduceCode$'

# The test deletes each exact workspace after all assertions pass. Refuse to
# erase the task root if any workspace survived; that turns cleanup drift into
# a visible failure and preserves the evidence.
if find "$state_base" -mindepth 1 -maxdepth 2 -type d -name 'reduce-run_*' -print -quit | grep -q .; then
  echo "live-reduce: a successful probe left a test workspace under $state_base" >&2
  exit 1
fi

write_report passed "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
case "$(basename "$task_root")" in
  ma-live.*) rm -rf -- "$task_root" ;;
  *) echo "live-reduce: refusing to clean unexpected task root $task_root" >&2; exit 1 ;;
esac
trap - EXIT

echo "live-reduce: $backend passed; task-owned state cleaned"
