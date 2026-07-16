# Reporting a security issue

Report security issues privately through GitHub's "Report a vulnerability" flow on the [microagency repository](https://github.com/geoffbelknap/microagency/security). Don't open public issues for security-sensitive reports.

microagency is an MCP gateway. It holds upstream credentials and OAuth refresh tokens, and it writes a tamper-evident audit log. Vulnerabilities in credential custody, connection ownership, or audit-chain integrity can expose secrets or hide agent activity, so report them privately and give maintainers a reasonable chance to respond before disclosure.

Include in your report:

- the affected version or commit
- how the gateway is deployed (local binary, container image) and which MCP clients and upstream servers are involved
- reproduction steps
- impact and any known mitigations

## Response

Maintainers will acknowledge reports as soon as practical, investigate with the reporter, and coordinate disclosure timing for confirmed vulnerabilities.

## Supported versions

Security fixes target the latest released version and `main`. Older releases may receive fixes when the patch is small and the affected version is still in active use.

## Trust boundary

For what `microagency` does and doesn't enforce - credential custody, connection ownership, engine sandboxing, audit-chain verification - see [`ARCHITECTURE.md`](ARCHITECTURE.md).
