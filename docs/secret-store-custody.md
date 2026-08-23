---
title: Protecting the credential store key
description: Keep the encrypted credential store's data key out of the gateway state directory.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-23_

The encrypted credential store holds upstream OAuth refresh tokens, static
bearers, and stored client registrations under AES-256-GCM. That cipher needs a
32-byte data key, and where the key lives decides what an attacker gets from a
copy of `~/.microagency`.

A **protector** holds the key: macOS Keychain, the Linux Secret Service, an
operator helper backed by a KMS or secret manager, or a key file you place
yourself. Only a non-secret locator, `credential-key-custody.json`, stays under
`~/.microagency`, and it names the protector rather than the key.

## Choose a protector

Check the current posture at any time:

```sh
microagency secret-store status
microagency doctor
```

On the first start with a protector configured, microagency generates the data
key, stores it, and reads it back before using it. Later starts retrieve it.

### macOS Keychain

```sh
export MICROAGENCY_SECRET_PROTECTOR=keychain
microagency up
```

The gateway uses the login Keychain through `/usr/bin/security`, whose code
identity survives Homebrew binary replacement. The Keychain must be unlocked
before an unattended user daemon starts. `security` accepts a new value as a
command argument, so the key is briefly visible to another process running as
the same user during creation or migration. Use the command protector when that
host-local process-list exposure is outside your threat model.

### Linux Secret Service

Install `secret-tool` (`libsecret-tools` on Debian/Ubuntu, `libsecret` on
Fedora) and make an unlocked default collection available on the user session
D-Bus. Then run:

```sh
export MICROAGENCY_SECRET_PROTECTOR=secret-service
microagency up
```

The key travels to `secret-tool` on standard input, never in arguments or the
environment. A headless host must provision and unlock its collection before
starting microagency. A missing session bus or a locked collection is an
outage; microagency does not prompt and does not fall back to another store.

### KMS or secret-manager helper

This is the path for a hosted deployment, where the data key should be wrapped
by a KMS the customer controls. Set an absolute executable path and select
`command` custody:

```sh
export MICROAGENCY_SECRET_PROTECTOR=command
export MICROAGENCY_SECRET_PROTECTOR_COMMAND=/opt/microagency/bin/key-protector
microagency up
```

The helper receives one of these requests:

| invocation | input | output | absent record |
|---|---|---|---|
| `HELPER put ID` | data key on stdin | none | n/a |
| `HELPER get ID` | none | data key on stdout | exit 3 |
| `HELPER delete ID` | none | none | exit 3 or 0 |

The key crosses as base64 text. Exit 3 means "no key stored yet" and is the
only nonzero exit that lets microagency create one; every other nonzero exit
means the protector is unavailable and startup stops. The helper must not log
its stdin or stdout. It should authenticate through the host's workload
identity and wrap the key with a KMS; do not embed cloud credentials in the
helper or its arguments. The helper path and opaque record ID are non-secret
and persist in `credential-key-custody.json`, so a restart does not depend on
the shell environment. For substitution resistance, the helper and its parent
directory must not be writable by group or other users, and the helper path
cannot be a symbolic link.

### A key file you hold

```sh
install -d -m 700 ~/.config/microagency
openssl rand 32 > ~/.config/microagency/secret-store.key
chmod 600 ~/.config/microagency/secret-store.key
export MICROAGENCY_SECRET_KEY_FILE=~/.config/microagency/secret-store.key
microagency up
```

This is the `file` protector under its original name, and it behaves exactly as
it always has. microagency never creates this file: a missing key file is a
misconfiguration that stops startup, not a reason to generate a new key. The
file must live outside `~/.microagency`, so copying that directory alone never
copies both the ciphertext and its key, and it must not be readable by group or
other users.

## Restart and failure behavior

On restart, microagency retrieves the data key through the protector and opens
the store. This works after a host reboot when the selected keychain, session,
or helper is ready first.

If the protector is missing, locked, denies access, or returns something that
is not a usable key, startup fails closed with the provider and the recovery
step in the error:

```
open credential store: secretstore: the configured data-key protector is
unavailable: external protector helper: protector helper read failed (exit 1);
restore its KMS/secret-manager access and retry
```

It never starts a second credential store, and
`up --allow-plaintext-credentials` does not override it: that flag decides
whether an unencrypted store is acceptable, not whether a missing key can be
skipped. `doctor` reports the same condition and never shows a store it could
not open as healthy:

```
  secret store      ✗ AES-256-GCM file store (data key: macOS Keychain) — UNVERIFIED
                    macOS Keychain read failed (security exit 51); unlock the login keychain and retry
                    startup will fail closed until this is resolved
```

A protector that answers but holds no key, when the store is *already*
encrypted, is also refused. Generating a fresh key there would leave the
existing credentials permanently unreadable, and the failure would look like a
wrong key rather than a lost record. Restore the protector's record from backup
instead.

### Two settings that disagree

Configuring both a protector and `MICROAGENCY_SECRET_KEY_FILE` is fine while
they hold the same key — that is what a migration looks like when the old
setting is still exported. If they hold different keys, or the locator names a
different protector than the environment does, microagency refuses rather than
guessing which one opens the store:

```
secretstore: the configured data-key custody settings disagree: external
protector helper and MICROAGENCY_SECRET_KEY_FILE hold different data keys;
unset whichever is stale rather than letting startup guess which one opens the
store
```

## Move the key between protectors

```sh
microagency down
export MICROAGENCY_SECRET_PROTECTOR_COMMAND=/opt/microagency/bin/key-protector
microagency secret-store migrate --to command
microagency up
```

The migration copies the **same** data key to the target and verifies the
target returns exactly those bytes. It then commits the locator through a
temporary file and an atomic rename, and only then deletes the old copy.
Stored credentials are never re-encrypted, so the store keeps opening
throughout, and an interrupted migration leaves the old protector
authoritative. Rotate the KMS
wrapping key inside a command helper according to that provider's procedure;
the opaque record contract does not change.

Migrating away from a key file leaves that file in place. microagency did not
create it, it is your backup for a store you may have copied elsewhere, and
deleting it would make the migration irreversible at the moment it is least
proven. Remove it yourself once the new protector is proven.

Moving back to a key file writes the key to disk, so it is deliberately noisy:

```sh
export MICROAGENCY_SECRET_KEY_FILE=~/.config/microagency/secret-store.key
microagency secret-store migrate --to file --allow-degraded
```

It refuses if that path already holds a different key, which may be the only
copy of some other store's key.

## Backup and recovery

Back up two things separately, because either alone is useless:

1. `~/.microagency` — the encrypted store and the non-secret locator.
2. The data key, through the Keychain, Secret Service, or your helper's
   provider.

A usable restore needs both, plus a protector that is available and unlocked.
Run `microagency secret-store status`, then `microagency up`. If the protector
is temporarily unavailable, restore access and retry; do not delete
`credential-key-custody.json`, which is what locates the key. If the data key
and all of its backups are permanently lost, the encrypted credentials cannot
be recovered — re-authenticate each connection instead.

`purge --full` deletes the protected data-key record before removing the state
directory. It keeps the directory if that deletion fails, so the record is
never stranded in a keyring or KMS with nothing left to locate it. Your own
key file is not deleted by `purge`.
