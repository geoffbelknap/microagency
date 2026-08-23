---
title: Protecting managed OpenBao
description: Keep managed OpenBao bootstrap material outside the gateway state directory.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

Managed OpenBao encrypts its data, but it still needs bootstrap material to
unseal and authenticate after a restart. The compatibility posture keeps that
record in `~/.microagency/openbao/bootstrap.json` (mode 0600), beside the
encrypted OpenBao data. `doctor` calls this **same-disk degraded custody**: a
copy of `~/.microagency` contains both halves.

Protected custody moves the record to macOS Keychain, Linux Secret Service, or
an operator helper backed by a KMS or secret manager. Only non-secret
`custody.json` metadata remains under `~/.microagency`. The initial OpenBao root
token is used once to mount KV v2 and create a narrow AppRole, then revoked and
removed from the record. The gateway logs in through that AppRole and renews its
periodic token while it runs. Its policy reaches only `secret/microagency/*` and
its own token-renewal endpoints.

Before a fresh OpenBao initializes, microagency makes the protector round-trip
and delete a non-secret probe. It refuses to initialize over an existing record,
so a stale backup cannot be silently replaced.

## Choose a protector

Check the current posture at any time:

```sh
microagency openbao status
microagency doctor
```

For a new installation, select the protector before the first `up`. For an
existing installation, use `migrate`; the command verifies the new copy before
switching the custody metadata or deleting the old copy.

### macOS Keychain

```sh
export MICROAGENCY_OPENBAO_PROTECTOR=keychain
microagency openbao migrate --to keychain  # omit on a fresh installation
microagency up
```

The managed process uses the login Keychain through `/usr/bin/security`, whose
code identity survives Homebrew binary replacement. The Keychain must be
unlocked before an unattended user daemon starts. `security` accepts a new
value as a command argument, so the value is briefly visible to another process
running as the same user during initialization or migration. Use the command
protector when that host-local process-list exposure is outside your threat
model.

### Linux Secret Service

Install `secret-tool` (`libsecret-tools` on Debian/Ubuntu, `libsecret` on
Fedora) and make an unlocked default Secret Service collection available on the
user session D-Bus. Then run:

```sh
export MICROAGENCY_OPENBAO_PROTECTOR=secret-service
microagency openbao migrate --to secret-service  # omit on a fresh installation
microagency up
```

The value travels to `secret-tool` on standard input, not in arguments or the
environment. A headless host must provision and unlock its collection before
starting microagency. A missing session bus or locked collection is an outage;
microagency does not prompt, reset OpenBao, or fall back to a disk credential
store.

### KMS or secret-manager helper

Set an absolute executable path and select `command` custody:

```sh
export MICROAGENCY_OPENBAO_PROTECTOR=command
export MICROAGENCY_OPENBAO_PROTECTOR_COMMAND=/opt/microagency/bin/openbao-protector
microagency openbao migrate --to command  # omit on a fresh installation
microagency up
```

The helper receives one of these requests:

| invocation | input | output | absent record |
|---|---|---|---|
| `HELPER put ID` | complete record on stdin | none | n/a |
| `HELPER get ID` | none | complete record on stdout | exit 3 |
| `HELPER delete ID` | none | none | exit 3 or 0 |

Every other nonzero exit means the protector is unavailable. The helper must
not log its stdin or stdout. It should authenticate through the host's workload
identity and put the record in a KMS-encrypted secret manager; do not embed
cloud credentials in the helper or its arguments. The helper path and opaque
record ID are non-secret and persist in `custody.json`, so restart does not
depend on shell environment after a successful migration. For substitution
resistance, the helper and its parent directory must not be writable by group or
other users, and the helper path cannot be a symbolic link.

## Restart and failure behavior

On restart, microagency starts OpenBao, retrieves the protected record, unseals
the store, logs in through AppRole, and starts periodic token renewal. This works
after a host reboot when the selected keychain/session/helper is ready first.

If the protector is missing, locked, denies access, returns corrupt data, or
cannot round-trip a write, startup fails closed with the provider and recovery
step in the error. It never resets protected OpenBao and never starts a parallel
plaintext store. Keep `custody.json` and the OpenBao data in place while fixing
the provider.

### Something else is on port 8200

If another process already answers on `127.0.0.1:8200` — an OpenBao left over
from an earlier run, or an unrelated one you started yourself — microagency
refuses to adopt it. It has no way to tell that instance is the one holding
your credentials, and handing them to a process it does not manage would be
worse than not starting:

```
WARN managed OpenBao is unavailable: its port is held by another process
  addr=http://127.0.0.1:8200
  remediation="stop whatever holds http://127.0.0.1:8200 (it was not started by
  microagency), then start microagency again"
```

`doctor` reports the same condition, and names the store that would hold
credentials instead. Free the port and start again; nothing needs repairing.

## Rotate custody

Move the record between protectors with a verified copy-then-switch:

```sh
microagency openbao migrate --to secret-service

export MICROAGENCY_OPENBAO_PROTECTOR_COMMAND=/opt/microagency/bin/new-protector
microagency openbao migrate --to command
```

The old record is deleted only after the target returns the exact bytes and the
new `custody.json` is durable. If old-record deletion fails, the command reports
that the migration committed but cleanup is still required. Rotate the KMS
wrapping key inside a command helper according to that provider's procedure;
the opaque record contract does not change.

Rotate the managed AppRole SecretID independently:

```sh
microagency openbao rotate-login
```

The new SecretID is login-tested and durably protected before the old accessor
is revoked. If old-accessor cleanup fails after the switch, the command reports
the committed rotation and the remaining cleanup error.

Returning to same-disk custody is deliberately noisy:

```sh
microagency openbao migrate --to file --allow-degraded
```

`doctor` immediately reports the downgrade.

## Backup and recovery

Stop both processes before copying the file-backed OpenBao data:

```sh
microagency down
cp -a ~/.microagency/openbao /path/to/secure-backup/openbao
```

The directory contains encrypted OpenBao storage and the non-secret protector
locator, but not the protected record. Back up that record through Keychain,
Secret Service, or the helper's provider as a separate recovery asset. A usable
restore needs both pieces:

1. Restore the `openbao/` directory, including `custody.json`.
2. Restore the matching protector record or its KMS/secret-manager access.
3. Make the protector available and unlocked.
4. Run `microagency openbao status`, then `microagency up`.

If the protector is temporarily unavailable, restore access and retry; do not
delete `custody.json`. If the protected record and all of its backups are
permanently lost, the encrypted OpenBao data cannot be recovered. `purge
--full` deletes the external protector record before removing the state
directory and refuses to remove the directory if that deletion fails.
