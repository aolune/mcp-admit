# MCP Admit

[![CI](https://github.com/aolune/mcp-admit/actions/workflows/ci.yml/badge.svg)](https://github.com/aolune/mcp-admit/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

> Static-first, no-exec-by-default admission control for MCP servers and agent tools.

**Inspect. Approve. Admit.**

MCP servers can expose powerful capabilities: filesystem access, shell execution, browser automation, databases, cloud APIs, messaging, credentials, and network egress. Those capabilities become part of an agent's permission boundary.

**MCP Admit** helps developers and security teams review MCP servers and agent tools before they are connected or executed. It scans MCP configs, tool manifests, schemas, descriptions, README metadata, and drift baselines, then combines policy and explicit approvals into an admission decision.

## Why MCP Admit?

MCP Admit focuses on the decision before connection: what a server can do, whether policy permits it, who approved it, and whether its definition has changed since approval.

| Principle | Meaning |
| --- | --- |
| Static-first | Analyze config, manifest, schema, description, README, and metadata first. |
| No-exec-by-default | Do not start untrusted `npx`, `uvx`, `python`, `docker`, or stdio commands during a default scan. |
| Capability-first | Classify what the tool can do before deciding whether it looks malicious. |
| Policy-oriented | Convert findings into allow, approval, sandbox, quarantine, or deny recommendations. |
| Approval-bound | Bind reviewer, reason, expiry, capabilities, and the complete server definition hash. |
| Drift-aware | Quarantine changed definitions and require re-approval. |
| CI-friendly | Emit Markdown, JSON, SARIF, and exit codes for admission gates. |

## Where it fits

MCP Admit is the decision layer before a server reaches a client allowlist, internal registry,
or runtime gateway:

```text
untrusted config / server.json / manifest
  -> inventory + static scan
  -> policy + explicit approval
  -> allow | allow with constraints | review | deny | quarantine
  -> MCP client / internal registry / gateway
```

It does not replace source-code scanners or runtime enforcement. It turns static evidence into a
versioned admission decision, binds approval to the reviewed definition and capabilities, and
invalidates that approval when the definition drifts.

## Quick demo

```powershell
python -m mcp_admit scan examples/poisoned_tool_manifest.json
```

Example summary:

```text
Gate: FAIL
Max severity: CRITICAL
Risk level: L4
Risk score: 95 / 100

Recommended policy:
- Action: deny
- Require approval: yes
- Sandbox: yes
- Network: deny
```

## Detects

- risky stdio launch commands and shell wrappers
- unpinned package execution through `npx`, `uvx`, and `pipx`
- privileged containers, Docker socket mounts, host root mounts, host networking, and unpinned container images
- secret-like environment variables and values
- prompt injection and hidden instructions in tool metadata
- arbitrary file path, URL, command, code, and SQL parameters
- shell, file, network, browser, database, cloud, messaging, and payment capabilities
- overbroad schemas such as `additionalProperties: true`
- toxic capability flows such as sensitive reads combined with outbound channels
- tool definition drift and rug-pull style changes
- nested JSON/YAML MCP server definitions across project and client configs
- official MCP Registry `server.json` packages, remotes, versions, digests, and secret declarations

## Install

From a checkout:

```powershell
pip install -e ".[dev]"
mcp-admit --version
```

From GitHub with `pipx`:

```powershell
pipx install git+https://github.com/aolune/mcp-admit.git
mcp-admit --version
```

From GitHub with `uvx`:

```powershell
uvx --from git+https://github.com/aolune/mcp-admit.git mcp-admit --version
```

After a PyPI release:

```powershell
pipx install mcp-admit
uvx mcp-admit --version
```

## Run locally

Every command below is static-only unless `inspect --allow-exec` is explicitly supplied.

```powershell
mcp-admit --version
python -m mcp_admit scan examples/dangerous_stdio_config.json
python -m mcp_admit scan examples/poisoned_tool_manifest.json --format json
python -m mcp_admit scan examples/poisoned_tool_manifest.json --format sarif
python -m mcp_admit scan examples/poisoned_tool_manifest.json --out report.md
python -m mcp_admit scan examples/poisoned_tool_manifest.json --profile ci --policy examples/policy_example.yaml
python -m mcp_admit scan . --exclude examples/ --exclude schemas/ --exclude README.md
python -m mcp_admit discover examples/client_configs --format json
python -m mcp_admit discover examples/client_configs --scan
python -m mcp_admit discover --client-paths --format markdown
python -m mcp_admit inventory examples/client_configs --format json
python -m mcp_admit init-approvals examples/client_configs --out .mcp-admit/approvals.yaml
python -m mcp_admit approve examples/client_configs --server claude-files --approved-by alice --reason "Reviewed in SEC-123." --expires 2026-12-31 --out .mcp-admit/approvals.yaml
python -m mcp_admit hash examples/poisoned_tool_manifest.json --out baseline.json
python -m mcp_admit diff baseline.json examples/rug_pull_changed.json
python -m mcp_admit diff baseline.json examples/rug_pull_changed.json --format json --out drift.json
python -m mcp_admit init-policy --out .mcp-admit/policy.yaml
python -m mcp_admit explain MCPG-SCHEMA-004
python -m mcp_admit benchmark examples/fixture_matrix.yaml
python -m mcp_admit inspect examples/dangerous_stdio_config.json --server evil
python -m mcp_admit inspect examples/fake_stdio_mcp_config.json --server fake-safe --allow-exec --allow-command "python3 examples/fake_stdio_mcp_server.py"
python -m mcp_admit runtime-policy examples/poisoned_tool_manifest.json --format json
python -m mcp_admit audit examples/dangerous_stdio_config.json
python -m mcp_admit decide examples/client_configs/Claude/claude_desktop_config.json --server claude-files --approvals .mcp-admit/approvals.yaml --service agent-platform --owner security --environment prod --request-id REQ-123 --out admission.json
python -m mcp_admit review-pack examples/client_configs --out-dir mcp-admit-review-pack --github-step-summary
python -m mcp_admit release-check
python -m mcp_admit schema admission --out admission.schema.json
```

## Example fixtures

| Fixture | Purpose |
| --- | --- |
| `examples/safe_readonly_docs_manifest.json` | Safe read-only docs query. |
| `examples/benign_metadata_manifest.json` | Benign domain/message/session vocabulary for false-positive calibration. |
| `examples/registry_safe_server.json` | Safe official `server.json` remote metadata. |
| `examples/registry_risky_server.json` | Mutable registry package, stdio execution, and secret declaration. |
| `examples/dangerous_stdio_config.json` | Shell launch, curl pipe, secret env, and localhost URL. |
| `examples/dangerous_container_mcp_config.json` | Privileged Docker launch with host network and sensitive host mounts. |
| `examples/nested_mcp_config.json` | Nested MCP server config discovered recursively. |
| `examples/yaml_mcp_config.yaml` | YAML MCP config using `mcp.servers`. |
| `examples/mixed_project_config.json` | Mixed project config with server aliases and tool manifests. |
| `examples/client_configs/` | Claude Desktop, Cursor, VS Code, and Windsurf-style MCP config discovery fixtures. |
| `examples/credential_env_mcp_config.json` | Secret-like env exposure. |
| `examples/fake_stdio_mcp_config.json` | Safe fake stdio MCP server for live inspection demos. |
| `examples/fake_stdio_mcp_server.py` | Test-only MCP-like stdio server used by the safe demo. |
| `examples/poisoned_tool_manifest.json` | Prompt injection plus file, network, and shell capability. |
| `examples/dangerous_shell_tool_manifest.json` | Free-form command execution parameter. |
| `examples/arbitrary_file_read_manifest.json` | Free-form file path read. |
| `examples/arbitrary_file_write_manifest.json` | Free-form file write. |
| `examples/network_exfil_tool_manifest.json` | Free-form webhook upload. |
| `examples/toxic_flow_manifest.json` | Sensitive file read combined with an outbound webhook. |
| `examples/overbroad_schema_manifest.json` | Overbroad schema shape. |
| `examples/broad_capabilities_manifest.json` | OAuth, browser, cloud, messaging, payment, and destructive file parameters. |
| `examples/supply_chain_stdio_config.json` | Package `@latest`, downloaded shell execution, and transient tunnel URL. |
| `examples/rug_pull_baseline.json` and `examples/rug_pull_changed.json` | Tool definition drift. |

Run the fixture matrix as a lightweight benchmark:

```powershell
python -m mcp_admit benchmark examples/fixture_matrix.yaml
python -m mcp_admit benchmark examples/fixture_matrix.yaml --format json --out benchmark.json
```

The benchmark verifies that each fixture produces the expected gate, risk level, severity, and rule IDs.

Risk scores use the strongest finding after deterministic composition rules are applied. Reports expose `risk_score_method` and structured `risk_factors`; they do not present the number as a probability of compromise.

## Risk levels

| Level | Meaning | Default policy |
| --- | --- | --- |
| L0 | Informational or no meaningful tool capability. | Allow |
| L1 | Bounded read-only capability. | Allow |
| L2 | Sensitive read or constrained network/schema risk. | Allow with constraints |
| L3 | Write, messaging, database, cloud, arbitrary file, or outbound capability. | Require approval |
| L4 | Shell, code execution, credential access, exfiltration, payment, or destructive capability. | Deny by default or sandbox with explicit approval |

## Input discovery

MCP Admit reads `.json`, `.yaml`, `.yml`, and `README.md` files. For JSON and YAML configs, it recursively discovers MCP server definitions under `mcpServers`, `mcp_servers`, and common `servers` aliases such as `mcp.servers` or project-level server maps. It also recognizes official MCP Registry `server.json` documents with `packages` and `remotes`. Findings keep the nested location path so reviewers can see where each server was found.

README files are treated as tool metadata for static prompt-injection and capability review. No input discovery mode executes configured commands.

Directory scans ignore common VCS, virtualenv, dependency, cache, build, and generated review-pack directories. Use repeatable `--include` and `--exclude` options to define the reviewed boundary. A trailing slash means a whole directory and works consistently in PowerShell and Bash:

```powershell
python -m mcp_admit scan . --include .vscode/ --include server.json
python -m mcp_admit scan . --exclude examples/ --exclude schemas/ --exclude README.md
```

Use `discover` to inventory MCP server entries before scanning:

```powershell
python -m mcp_admit discover .
python -m mcp_admit discover examples/client_configs --format json
python -m mcp_admit discover --client-paths --format markdown
```

`discover` recognizes common Claude Desktop, Cursor, VS Code, Windsurf, project, and generic MCP config shapes. `--client-paths` checks known client config paths under the current home directory, or under a test home supplied with `--home`. Discovery output includes client type, source path, server name, transport, location, and environment key names only; it does not print environment values and does not execute server commands.

Use `inventory` when discovery should include per-server risk summaries and approval status:

```powershell
python -m mcp_admit inventory examples/client_configs
python -m mcp_admit discover examples/client_configs --scan --format json
python -m mcp_admit init-approvals examples/client_configs --out .mcp-admit/approvals.yaml
python -m mcp_admit approve examples/client_configs --server claude-files --approved-by alice --reason "Reviewed in SEC-123." --expires 2026-12-31 --out .mcp-admit/approvals.yaml
python -m mcp_admit inventory examples/client_configs --approvals .mcp-admit/approvals.yaml --fail-on-unknown --fail-on-drift
```

`init-approvals` is fail-closed: it creates `pending` records only. `approve` is the only CLI path that creates an approved record, and it requires an explicit server, reviewer, reason, and expiry. Approval registries bind trust to the complete server definition hash and current capability set. Inventory reports mark each server as `approved`, `pending`, `unknown`, `expired`, or `drifted`.

Use the registry in the final admission decision:

```powershell
python -m mcp_admit decide examples/client_configs/Claude/claude_desktop_config.json --server claude-files --approvals .mcp-admit/approvals.yaml
```

An approved, unchanged definition can satisfy `require_approval`. Required sandbox, egress, credential, and runtime controls remain visible as an `allow_with_constraints` decision. Approval cannot override `deny` or `quarantine`; expired and unknown records require review, while definition or capability drift is quarantined. Approvals track server admission, while policy waivers track finding-level exceptions.

`gate_result` remains the raw static-analysis result; `decision` is the final admission outcome after policy and approval state are applied.

## Policy

Use `--profile` for a built-in posture and `--policy` for local exceptions or overrides. Built-in profiles are:

| Profile | Use |
| --- | --- |
| `dev` | Local exploration; fails only on critical findings and denies credential/payment capabilities. |
| `ci` | CI gate; fails on high findings and denies execution, credential, container escape, and payment capabilities. |
| `enterprise-strict` | Review-heavy admission gate; fails on medium findings and requires review for L3/L4 findings. |

Use a small YAML policy for overrides:

```yaml
version: 1
profile: enterprise-strict
fail_on: medium
ignore_finding_ids: []
deny_capabilities:
  - shell_exec
  - credential_access
require_approval_levels:
  - L3
  - L4
waivers:
  - id: reviewed-webhook
    action: downgrade
    finding_id: MCPG-SCHEMA-003
    reason: Destination is owned by the team and reviewed in ticket SEC-123.
    expires: 2026-12-31
    downgrade_to: medium
```

Waivers require a non-empty `reason` and can match by `finding_id`, `capability`, `server`, or `location`. `action: ignore` removes a matching finding until it expires; `action: downgrade` keeps the finding in the report with reduced severity. JSON and Markdown reports include `policy_context`, `policy_effects`, and `rule_explanations` so reviewers can see which profile and waivers were applied and which rules drove the decision.

Invalid profiles, `fail_on` severities, `require_approval_levels`, and waiver shapes are rejected before the scan report is emitted.

## GitHub Actions and SARIF

The included CI workflow runs the packaged CLI, lints the project, runs tests, builds and uploads distribution artifacts, generates JSON/SARIF MCP Admit reports, runs the fixture benchmark matrix, emits an admission service payload, uploads JSON Schema contracts as artifacts, and uploads SARIF to GitHub Code Scanning when repository permissions allow it.

Minimal workflow step:

```yaml
- run: python -m mcp_admit scan examples/poisoned_tool_manifest.json --format sarif --out mcp-admit-report.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: mcp-admit-report.sarif
    category: mcp-admit
```

The repository also ships a composite action:

```yaml
- uses: aolune/mcp-admit@v0.3.0
  with:
    path: .
    profile: ci
    policy: .mcp-admit/policy.yaml
    fail-on: high
```

For CI admission gates:

```powershell
python -m mcp_admit scan . --profile ci --policy .mcp-admit/policy.yaml --exclude examples/ --exclude schemas/
```

For admission service artifacts:

```powershell
python -m mcp_admit decide examples/poisoned_tool_manifest.json --service agent-platform --owner security --environment ci --request-id github-actions --out mcp-admit-admission.json
python -m mcp_admit schema admission --out mcp-admit-admission.schema.json
```

For a full reviewer package:

```powershell
python -m mcp_admit review-pack . --out-dir mcp-admit-review-pack --github-step-summary --service github-actions --owner security --environment ci
```

The review pack writes scan, inventory, runtime policy, audit, admission, and GitHub step summary artifacts. `release-check` validates committed schema contracts and generated samples before release:

```powershell
python -m mcp_admit release-check
```

## Baseline drift detection

Generate a baseline without executing the MCP server:

```powershell
python -m mcp_admit hash examples/rug_pull_baseline.json --out baseline.json
```

Compare a later manifest or config against that baseline:

```powershell
python -m mcp_admit diff baseline.json examples/rug_pull_changed.json
python -m mcp_admit diff baseline.json examples/rug_pull_changed.json --format sarif --out drift.sarif
```

The baseline stores hashes for descriptions, schemas, server launch definitions, env key names, capabilities, and risk levels. It does not store secret environment values.

## Optional live inspection

`inspect` can perform a tightly-scoped stdio MCP handshake to discover live tool metadata. It is off by default and only runs when both conditions are true:

1. `--allow-exec` is present.
2. The exact normalized launch vector is approved with `--allow-command` or policy `allow_exec_commands`.

Default behavior is safe and non-executing:

```powershell
python -m mcp_admit inspect examples/dangerous_stdio_config.json --server evil
```

The dangerous fixtures are intended for static detection and blocked-path demos. For a successful live handshake, use the safe fake stdio server:

```powershell
python -m mcp_admit inspect examples/fake_stdio_mcp_config.json --server fake-safe --allow-exec --allow-command "python3 examples/fake_stdio_mcp_server.py"
```

If your interpreter is not `python3`, update both the config command and the exact `--allow-command` value. Dangerous fixtures such as `examples/dangerous_stdio_config.json` should remain blocked unless you are deliberately testing the guardrails in a sandbox.

Live inspection currently supports stdio only. It sends `initialize`, `notifications/initialized`, and `tools/list`; it does not call tools and does not execute tool actions. Successful inspection reports include a compact live tool inventory with tool names, redacted descriptions, schema property names, required fields, and `additionalProperties` status. Environment values are never printed, and configured env keys are blocked unless explicitly allowed with `--allow-env`.

## Runtime policy and audit workflow

Generate a runtime policy adapter document from a static scan:

```powershell
python -m mcp_admit runtime-policy examples/poisoned_tool_manifest.json --format json --out runtime-policy.json
```

The runtime policy groups findings into deterministic capability rules such as `runtime.capability.shell_exec` or `runtime.capability.network_send`. Each rule includes the action, approval requirement, sandbox requirement, network posture, risk level, and source finding IDs.

Generate an audit package:

```powershell
python -m mcp_admit audit examples/dangerous_stdio_config.json --out audit.md
```

Audit reports include the scan summary, generated runtime policy, policy context, policy effects, rule explanations, checklist items for approval/sandbox/egress/credentials, and next actions for reviewers. These commands are static-only and do not start MCP servers.

## Enterprise admission service inputs

Generate a deterministic admission payload for an internal approval service. For an MCP config, select one server and provide its approval registry:

```powershell
python -m mcp_admit decide examples/client_configs/Claude/claude_desktop_config.json --server claude-files --approvals .mcp-admit/approvals.yaml --service agent-platform --owner security --environment prod --request-id REQ-123 --out admission.json
```

Admission inputs include subject metadata, the admission decision, gate result, risk score, capabilities, finding IDs, policy context, policy effects, rule explanations, generated runtime policy, audit checklist, and scan summary. They are designed for downstream policy engines that need stable JSON without executing MCP servers.

The payload intentionally omits finding evidence and raw secret values. It keeps reviewer and policy context while preserving MCP Admit's static-first, no-exec-by-default posture.

## Output contracts

Machine-readable JSON Schema contracts are committed under `schemas/`:

| Contract | File | CLI |
| --- | --- | --- |
| Scan report | `schemas/report.schema.json` | `python -m mcp_admit schema report` |
| Runtime policy | `schemas/runtime-policy.schema.json` | `python -m mcp_admit schema runtime-policy` |
| Audit report | `schemas/audit.schema.json` | `python -m mcp_admit schema audit` |
| Admission input | `schemas/admission.schema.json` | `python -m mcp_admit schema admission` |
| Inventory report | `schemas/inventory.schema.json` | `python -m mcp_admit schema inventory` |
| Release check | `schemas/release-check.schema.json` | `python -m mcp_admit schema release-check` |

Golden samples for downstream integration live under `examples/generated/`. They are generated from static fixture scans and are safe to use as parser fixtures; they do not contain raw secret values.

## OWASP MCP mapping

MCP Admit findings include an `owasp` field and SARIF `tags` so reports can be grouped by MCP security themes.
JSON and SARIF reports also include `schema_version` / `report_schema_version` and `tool_version` metadata for stable downstream parsing.
SARIF invocation properties include the policy context, policy effects, and rule explanations for CI systems that consume SARIF instead of the native JSON report.

| Rule family | Mapping |
| --- | --- |
| `MCPG-STDIO-*` | Command Injection, Supply Chain |
| `MCPG-SECRET-*` | Token Mismanagement, Context Over-Sharing |
| `MCPG-CAP-*` | Scope Creep |
| `MCPG-FLOW-*` | Intent Flow Subversion, Context Over-Sharing |
| `MCPG-SCHEMA-*` | Scope Creep, Intent Flow Subversion |
| `MCPG-INJ-*` | Tool Poisoning, Context Injection |
| `MCPG-SC-*` | Supply Chain, Tool Poisoning |
| `MCPG-NET-*` | Intent Flow Subversion, Context Over-Sharing |

Use `explain` to inspect rule metadata:

```powershell
python -m mcp_admit explain MCPG-SCHEMA-004
python -m mcp_admit explain --format json
```

## Non-goals

MCP Admit is not:

- an MCP client
- an MCP gateway
- a runtime sandbox
- a malware analysis platform
- a general SAST replacement
- a guarantee that a server is safe

It identifies risky capabilities and suspicious metadata so teams can make an admission decision before connecting a tool.

## Release notes

See `CHANGELOG.md` for the current release line and the security posture of the generated artifacts.

## Roadmap

**Now - v0.3**

- static/no-exec config, manifest, README, and official `server.json` review
- policy profiles, explicit approvals, immutable baselines, and re-approval on drift
- toxic-flow composition, Markdown/JSON/SARIF, review packs, schemas, and CI gates

**Next**

- measured precision/recall corpus from reviewed public MCP metadata
- additional registry provenance and authorization metadata checks
- adapters for selected gateways and internal admission services

**Later**

- optional signed approval records and attestations
- narrowly scoped runtime integrations only where static admission cannot enforce a control
