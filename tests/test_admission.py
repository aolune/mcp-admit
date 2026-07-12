import json

from mcp_admit.admission import (
    build_admission_input,
    render_admission_json,
    render_admission_markdown,
)
from mcp_admit.models import ApprovalDecision
from mcp_admit.scanner import scan_path


def test_admission_input_denies_poisoned_manifest():
    report = build_admission_input(
        scan_path("examples/poisoned_tool_manifest.json"),
        service="agent-platform",
        owner="security",
        environment="prod",
        request_id="REQ-123",
    )
    controls = {control.id: control for control in report.controls}

    assert report.schema_version == "mcp-admit.admission.v1"
    assert report.subject.service == "agent-platform"
    assert report.subject.owner == "security"
    assert report.subject.environment == "prod"
    assert report.subject.request_id == "REQ-123"
    assert report.decision == "deny"
    assert report.gate_result == "fail"
    assert "shell_exec" in report.capabilities
    assert "network_send" in report.capabilities
    assert "MCPG-SCHEMA-004" in report.finding_ids
    assert any(rule.id == "MCPG-SCHEMA-004" for rule in report.rule_explanations)
    assert controls["admission.runtime_policy"].status == "pass"
    assert report.runtime_policy.schema_version == "mcp-admit.runtime-policy.v1"
    assert report.audit.schema_version == "mcp-admit.audit.v1"
    assert report.scan_summary.risk_score == report.audit.scan_summary.risk_score


def test_admission_input_allows_safe_manifest():
    report = build_admission_input(scan_path("examples/safe_readonly_docs_manifest.json"))
    controls = {control.id: control for control in report.controls}

    assert report.decision == "allow"
    assert report.gate_result == "pass"
    assert report.capabilities == []
    assert report.finding_ids == []
    assert controls["admission.static_scan"].required is True
    assert controls["admission.runtime_policy"].required is True
    assert controls["admission.human_approval"].required is False
    assert controls["admission.sandbox"].required is False
    assert controls["admission.egress"].required is False
    assert controls["admission.credentials"].required is False


def test_admission_renderers_include_schema_controls_and_mask_secrets():
    report = build_admission_input(
        scan_path("examples/credential_env_mcp_config.json"),
        service="platform",
        owner="security",
    )

    json_report = render_admission_json(report)
    parsed = json.loads(json_report)
    assert parsed["schema_version"] == "mcp-admit.admission.v1"
    assert parsed["subject"]["service"] == "platform"
    assert parsed["runtime_policy"]["schema_version"] == "mcp-admit.runtime-policy.v1"
    assert parsed["rule_explanations"]
    assert "ghp_exampletoken123456" not in json_report

    markdown = render_admission_markdown(report)
    assert "MCP Admit Admission Input" in markdown
    assert "Service: platform" in markdown
    assert "Owner: security" in markdown
    assert "Rule explanations" in markdown
    assert "Controls" in markdown
    assert "Next actions" in markdown
    assert "ghp_exampletoken123456" not in markdown


def test_explicit_approval_satisfies_review_but_not_deny():
    approved = ApprovalDecision(
        status="approved",
        approval_id="test.safe",
        reason="Reviewed in SEC-123.",
    )
    stdio = build_admission_input(
        scan_path("examples/fake_stdio_mcp_config.json"),
        approval=approved,
        server="fake-safe",
    )
    poisoned = build_admission_input(
        scan_path("examples/poisoned_tool_manifest.json"),
        approval=approved,
    )

    assert stdio.decision == "allow_with_constraints"
    assert stdio.approval == approved
    assert stdio.subject.server == "fake-safe"
    assert poisoned.decision == "deny"


def test_drifted_approval_quarantines_and_pending_requires_review():
    scan = scan_path("examples/fake_stdio_mcp_config.json")
    drifted = build_admission_input(
        scan,
        approval=ApprovalDecision(
            status="drifted",
            approval_id="test.safe",
            reason="Definition changed.",
        ),
    )
    pending = build_admission_input(
        scan,
        approval=ApprovalDecision(
            status="pending",
            approval_id="test.safe",
            reason="Awaiting review.",
        ),
    )

    assert drifted.decision == "quarantine"
    assert pending.decision == "review"
