# Security Policy

## Supported versions

Security fixes are applied to the latest minor release line. The currently supported line is `0.3.x`.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or secret exposure. Use GitHub's private vulnerability reporting flow under the repository Security tab. If that flow is unavailable, contact the maintainer through the repository owner's GitHub profile before sharing technical details.

Include the affected version, minimal reproduction, impact, and whether a scanned fixture contains sensitive data. Do not attach live credentials or execute an untrusted MCP server to produce a report.

## Security invariants

- Default scan, discovery, inventory, approval, hash, diff, policy, audit, decide, and review-pack paths do not execute MCP server commands.
- Live stdio inspection requires both explicit execution consent and an exact command allowlist.
- Secret values must be redacted from human- and machine-readable reports.
- New approval registries are pending by default; approved records require a reviewer, reason, expiry, definition hash, and capability bounds.
- A policy denial cannot be overridden by an approval record.
- Definition or capability drift requires re-approval.

Changes that weaken an invariant require focused tests and an explicit security rationale in the pull request.
