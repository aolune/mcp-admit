import json

from mcp_admit.runtime_policy import (
    build_audit_report,
    build_runtime_policy,
    render_audit_json,
    render_audit_markdown,
    render_runtime_policy_json,
    render_runtime_policy_markdown,
)
from mcp_admit.scanner import scan_path


def test_runtime_policy_groups_findings_by_capability():
    scan = scan_path("examples/poisoned_tool_manifest.json")
    report = build_runtime_policy(scan)
    rules = {rule.id: rule for rule in report.rules}

    assert report.schema_version == "mcp-admit.runtime-policy.v1"
    assert report.default_action == "deny"
    assert "runtime.default" in rules
    assert "runtime.capability.shell_exec" in rules
    assert rules["runtime.capability.shell_exec"].action == "deny"
    assert rules["runtime.capability.shell_exec"].sandbox is True
    assert rules["runtime.capability.network_send"].network == "restricted"
    assert "MCPG-SCHEMA-004" in rules["runtime.capability.shell_exec"].finding_ids


def test_runtime_policy_allows_safe_manifest_by_default():
    scan = scan_path("examples/safe_readonly_docs_manifest.json")
    report = build_runtime_policy(scan)

    assert report.default_action == "allow"
    assert len(report.rules) == 1
    assert report.rules[0].id == "runtime.default"
    assert report.rules[0].require_approval is False


def test_runtime_policy_renderers_include_schema_and_rules():
    report = build_runtime_policy(scan_path("examples/network_exfil_tool_manifest.json"))

    parsed = json.loads(render_runtime_policy_json(report))
    assert parsed["schema_version"] == "mcp-admit.runtime-policy.v1"
    assert any(rule["match"].get("capability") == "network_send" for rule in parsed["rules"])

    markdown = render_runtime_policy_markdown(report)
    assert "MCP Admit Runtime Policy" in markdown
    assert "runtime.capability.network_send" in markdown


def test_audit_report_includes_checklist_and_next_actions():
    audit = build_audit_report(scan_path("examples/dangerous_stdio_config.json"))
    statuses = {item.id: item.status for item in audit.items}

    assert audit.schema_version == "mcp-admit.audit.v1"
    assert audit.gate_result == "fail"
    assert statuses["audit.scan_gate"] == "fail"
    assert statuses["audit.approval"] == "warn"
    assert statuses["audit.sandbox"] == "warn"
    assert statuses["audit.egress"] == "warn"
    assert statuses["audit.credentials"] == "warn"
    assert any(rule.id == "MCPG-STDIO-003" for rule in audit.rule_explanations)
    assert any("Do not connect" in action for action in audit.next_actions)


def test_audit_renderers_include_runtime_policy():
    audit = build_audit_report(scan_path("examples/safe_readonly_docs_manifest.json"))

    parsed = json.loads(render_audit_json(audit))
    assert parsed["schema_version"] == "mcp-admit.audit.v1"
    assert parsed["runtime_policy"]["schema_version"] == "mcp-admit.runtime-policy.v1"

    markdown = render_audit_markdown(audit)
    assert "MCP Admit Audit" in markdown
    assert "Runtime policy" in markdown
    assert "Rule explanations" not in markdown
    assert "Record the audit decision" in markdown
