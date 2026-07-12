# Changelog

## 0.3.1 - 2026-07-12

Release, onboarding, and supply-chain hardening.

### Security

- Pinned every GitHub Action dependency to a full commit SHA.
- Made SARIF upload failures block push and tag workflows while keeping pull request
  uploads tolerant of restricted tokens.
- Added monthly Dependabot updates for GitHub Actions and Python dependencies.

### Changed

- Pinned GitHub install examples and Action usage to the `v0.3.1` release tag.
- Made the quick demo self-contained with a versioned shallow checkout.
- Added a GitHub Marketplace badge to the README.

## 0.3.0 - 2026-07-11

Approval-aware admission and registry metadata release.

### Breaking changes

- Renamed the project, Python package, distribution, CLI, report identity, and generated
  contracts from `mcp-guard` to `mcp-admit` / `mcp_admit`.
- Renamed the final-decision CLI command from `admission` to `decide`.
- Changed schema identifiers and baseline kinds from the `mcp-guard.*` namespace to
  `mcp-admit.*`; regenerate stored contracts and baselines before using this release.

### Added

- Fail-closed approval templates with explicit `pending` records.
- Explicit `approve` command requiring reviewer, reason, expiry, and a single server target.
- Approval-aware admission decisions for approved, pending, unknown, expired, and drifted servers.
- `--include` and `--exclude` scan boundaries plus default cache/build directory exclusions.
- Toxic-flow composition rules for sensitive read plus outbound access, injection plus high-impact actions, and execution plus credentials.
- Structured risk factors and an explicit `max_finding_with_composition` scoring method.
- Static support for official MCP Registry `server.json` package and remote metadata.
- Registry checks for mutable versions, missing artifact digests, version mismatch, and declared secret environment requirements.
- Registry package fields in definition hashes so package metadata changes require re-approval.
- Benign vocabulary fixtures to calibrate false positives alongside dangerous fixtures.

### Changed

- `init-policy` now emits `waivers: []`; examples no longer create active exceptions by default.
- `init-approvals` now creates pending review records instead of long-lived approvals.
- Empty capability allowlists now mean no capabilities are approved.
- Repository CI scopes its self-scan to relevant files instead of scanning examples and generated contracts.
- Capability text matching uses token boundaries and narrower messaging/browser/file patterns.

### Security

- Explicit approval can satisfy `require_approval`, but cannot override `deny` or `quarantine`.
- Definition or capability drift produces a quarantine decision.
- Expired, pending, and unknown approvals require review.
- Registry metadata scanning remains static and never installs or executes declared packages.

## 0.2.0 - 2026-07-03

Static-first admission gate release for MCP servers and agent tools.

### Added

- Static-first scanner for MCP configs, manifests, schemas, README metadata, and drift baselines.
- Risk scoring, risk levels, gate results, and policy recommendations for agent tool admission.
- Markdown, JSON, and SARIF scan reports with schema version metadata.
- Policy file support for fail thresholds, ignored findings, denied capabilities, approval levels, built-in profiles, expiring waivers, and report-visible policy effects.
- Baseline hashing and diff detection for tool definition drift.
- Optional stdio live inspection with exact command and environment allowlists.
- Runtime policy and audit report generation for downstream enforcement and review.
- Enterprise admission input payloads for internal approval services.
- Fixture benchmark matrix, CI checks, SARIF upload, and release-readiness packaging metadata.
- JSON Schema output contracts and generated integration samples for downstream parsers.
- Container launch risk detection for privileged Docker and Podman, sensitive host mounts, host networking, and unpinned images.
- Recursive JSON/YAML config discovery for nested MCP server definitions and common server aliases.
- Reviewer explainability fields for policy context, rule explanations, audit reports, admission inputs, and SARIF metadata.
- Static `discover` command for Claude Desktop, Cursor, VS Code, Windsurf, project, and generic MCP config inventory.
- Inventory reports with per-server risk summaries and approval status.
- Server approval registries for approved, unknown, expired, and drifted MCP server entries.
- GitHub Actions workflow, GitHub step summary support, and full `review-pack` artifact generation.
- Expanded sensitive capability rules for OAuth, browser sessions, cloud admin, outbound messaging, payment, and destructive file operations.
- Supply-chain hardening for package `@latest`, downloaded shell execution, transient tunnel URLs, and mutable launch inputs.
- Release checks for committed schema contracts and generated integration samples.

### Security

- Default scan, hash, diff, runtime-policy, audit, and admission commands do not execute MCP servers.
- Live inspection never calls tools and only runs after explicit execution and command allowlists.
- Discovery reports environment key names only and never print configured environment values.
- Inventory, approval, review-pack, and release-check workflows remain static and do not execute MCP server commands.
- Reports redact secret-like values and admission payloads omit finding evidence.
