---
title: Direct-upstream mediation
description: Advisory local checks and enforced gateway-only egress for governed agent workspaces.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

microagency has two deliberately different mediation postures:

- **Advisory local-host mode** is the default. The Claude Code hook warns about
  direct URLs and `doctor` finds duplicate local MCP wiring. These checks do
  not block packets, see remote clients, or become enforcement because they
  return no warning.
- **Enforced workspace mode** binds one stopped microagent workspace to a
  host-owned, locked egress policy. The workspace can reach the gateway host
  and no other network host. Calls through `call_tool` still work because the
  gateway originates the upstream connection outside the workspace. A direct
  connection from the workspace to an upstream is denied.

The enforced mode is intentionally narrower than a host firewall. microagency
does not install machine-wide packet-filter rules or claim control over local
processes, other workspaces, or remote clients.

## Configure an enforced workspace

Create the workspace first, but leave it stopped. Choose a dedicated host
identity that the workspace can reach. Keep the operator listener on loopback.

With Linux `network: user`, pasta maps the outer host's default gateway address
to host loopback. Pass that mapped address as the guest-visible gateway while
microagency stays bound to loopback:

```sh
microagency down
microagency mediation enforce \
  --workspace governed-agent \
  --gateway http://<mapped-host-loopback>:8765/mcp
microagency up \
  --http 127.0.0.1:8765 \
  --admin-addr 127.0.0.1:8766
microagent start governed-agent
microagency doctor
```

`<mapped-host-loopback>` is the outer host's default IPv4 gateway reported by
the host routing table, not the workspace's `10.43.*` guest gateway. pasta maps
that address back to `127.0.0.1` on the host. Verify the mapping on the target
host before enforcing it.

With routed networking instead, use a dedicated address or DNS identity that
the guest reaches directly, and bind the agent listener to that identity. The
`--gateway` URL is always the identity visible from the guest, never
`127.0.0.1`: loopback inside the workspace is the workspace itself. Use
`--state-dir` on `mediation enforce` when the workspace uses a non-default
microagent state directory.

The command refuses to run while microagency or the workspace is running. It
uses microagent's public workspace contract to persist:

```text
egress mode:       broker
allowlist locked:  true
allowed hosts:     <gateway-host> only
passthrough hosts: none
```

It then writes the non-secret binding to
`~/.microagency/mediation.json`. Start the workspace normally after both
writes verify.

## Why upstream changes do not make the policy stale

The workspace policy is gateway-only, not a copied denylist of today's
upstreams. Adding, removing, disabling, or rebinding an upstream therefore
does not require a live firewall reload: every non-gateway hostname and direct
IP remains denied before and after the registry mutation. The gateway updates
the protected-host identity map under the same registry lock it already uses
for invocation gating.

An enabled upstream cannot share the gateway hostname. Adding, enabling,
reauthorizing, or rebinding one to that hostname is rejected before the
registry commit. A missing or corrupt enforced binding also makes these
mutations fail closed. Use a dedicated gateway host identity; microagent's
egress allowlist is host-granular, so the gateway hostname is reachable on
alternate ports too.

This invariant covers the usual bypass variants:

- an upstream hostname is not on the allowlist;
- a redirect to another host crosses the same mediator and is denied;
- an alternate port does not change the protected upstream hostname;
- a literal direct IP is not the allowed gateway host;
- DNS answers are checked by microagent's mediator at connection time, so a
  changed or rebound answer does not bypass the hostname policy;
- if the gateway is unavailable, the only allowed host has no working MCP
  service and direct upstream paths remain denied.

## Status and denial evidence

Run `microagency mediation status` for a short answer, or add `--json` for the
structured record. `microagency doctor` reports the same posture and always
lists uncovered client classes. It uses these states:

| state | meaning |
|---|---|
| `advisory` | no workspace binding; hook and local config checks only |
| `configured` | the locked policy is persisted; the workspace is stopped |
| `enforced` | the bound workspace is running under the locked policy |
| `degraded` | the binding or workspace policy is missing, corrupt, or changed |
| `unsupported` | the selected backend/network cannot provide complete egress capture |

The operator API exposes the same data at `GET /admin/mediation`. Read
`GET /admin/mediation/denials` for structured host-side microagent denial
records. Each record keeps the attempted destination and correlates a hostname
to every current upstream identity that contributed it. A literal IP with no
DNS/SNI association remains explicitly unattributed—the host audit can prove
the destination and denial, but cannot invent which same-IP service the
process intended.

The denial stream is written by microagent's host-side mediator, outside guest
control. The gateway's separate signed audit chain continues to cover every
`call_tool` and `reduce` execution.

## Coverage boundary

Only the named workspace is enforced. Local-host clients, remote clients, and
other workspaces remain uncovered unless their own governing layer applies an
equivalent locked policy. The hook stays useful as a warning on those paths,
but it remains fail-open and is never reported as enforcement.
