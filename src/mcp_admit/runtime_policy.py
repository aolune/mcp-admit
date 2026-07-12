from __future__ import annotations

import json
from collections import defaultdict

from mcp_admit.models import (
    AuditItem,
    AuditReport,
    Finding,
    RuntimePolicyReport,
    RuntimePolicyRule,
    ScanResult,
)
from mcp_admit.risk import ACTION_ORDER, RISK_ORDER

SANDBOX_CAPABILITIES = {"shell_exec", "code_exec", "file_read", "file_write", "credential_access"}
NETWORK_CAPABILITIES = {"network_fetch", "network_send"}


def _strongest_action(findings: list[Finding]) -> str:
    actions = [finding.policy_action for finding in findings]
    if not actions:
        return "allow"
    return max(actions, key=lambda action: ACTION_ORDER[action])


def _max_risk_level(findings: list[Finding]) -> str:
    return max((finding.risk_level for finding in findings), key=lambda level: RISK_ORDER[level])


def _max_risk_score(findings: list[Finding]) -> int:
    return max(finding.risk_score for finding in findings)


def _network_policy(action: str, capabilities: set[str]) -> str:
    if action in {"deny", "quarantine"}:
        return "deny"
    if capabilities & NETWORK_CAPABILITIES:
        return "restricted"
    return "allow"


def _requires_approval(action: str, risk_level: str) -> bool:
    return action in {"require_approval", "deny", "quarantine"} or risk_level in {"L3", "L4"}


def _requires_sandbox(risk_level: str, capabilities: set[str]) -> bool:
    return risk_level == "L4" or bool(capabilities & SANDBOX_CAPABILITIES)


def _default_rule(scan: ScanResult) -> RuntimePolicyRule:
    policy = scan.summary.recommended_policy
    return RuntimePolicyRule(
        id="runtime.default",
        scope="default",
        match={},
        action=policy.action,
        require_approval=policy.require_approval,
        sandbox=policy.sandbox,
        network=policy.network,
        risk_level=scan.summary.tool_risk_level,
        risk_score=scan.summary.risk_score,
        finding_ids=[],
        reason="Default runtime posture derived from the scan summary.",
    )


def build_runtime_policy(scan: ScanResult) -> RuntimePolicyReport:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in scan.findings:
        grouped[finding.capability].append(finding)

    rules = [_default_rule(scan)]
    for capability in sorted(grouped):
        findings = grouped[capability]
        action = _strongest_action(findings)
        risk_level = _max_risk_level(findings)
        capabilities = {capability}
        finding_ids = sorted({finding.id for finding in findings})
        rules.append(
            RuntimePolicyRule(
                id=f"runtime.capability.{capability}",
                scope="capability",
                match={"capability": capability},
                action=action,
                require_approval=_requires_approval(action, risk_level),
                sandbox=_requires_sandbox(risk_level, capabilities),
                network=_network_policy(action, capabilities),
                risk_level=risk_level,
                risk_score=_max_risk_score(findings),
                finding_ids=finding_ids,
                reason=f"Runtime rule derived from findings for capability {capability}.",
            )
        )

    return RuntimePolicyReport(
        target=scan.target,
        source_schema_version=scan.schema_version,
        default_action=scan.summary.recommended_policy.action,
        rules=rules,
        notes=scan.summary.recommended_policy.notes,
    )


def render_runtime_policy_json(report: RuntimePolicyReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_runtime_policy_markdown(report: RuntimePolicyReport) -> str:
    lines = [
        "# MCP Admit Runtime Policy",
        "",
        f"Target: {report.target}",
        f"Default action: {report.default_action}",
        f"Rules: {len(report.rules)}",
        "",
    ]
    if report.notes:
        lines.extend(["## Notes", ""])
        lines.extend(f"- {note}" for note in report.notes)
        lines.append("")
    lines.extend(
        [
            "## Rules",
            "",
            "| Rule | Scope | Match | Action | Approval | Sandbox | Network | Risk | Findings |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for rule in report.rules:
        match = ", ".join(f"{key}={value}" for key, value in sorted(rule.match.items())) or "all"
        finding_ids = ", ".join(rule.finding_ids) if rule.finding_ids else "n/a"
        lines.append(
            "| {id} | {scope} | {match} | {action} | {approval} | {sandbox} | {network} | {risk} | {findings} |".format(
                id=rule.id,
                scope=rule.scope,
                match=match,
                action=rule.action,
                approval="yes" if rule.require_approval else "no",
                sandbox="yes" if rule.sandbox else "no",
                network=rule.network,
                risk=rule.risk_level,
                findings=finding_ids,
            )
        )
    return "\n".join(lines)


def build_audit_report(scan: ScanResult) -> AuditReport:
    runtime_policy = build_runtime_policy(scan)
    summary = scan.summary
    items = [
        AuditItem(
            id="audit.scan_gate",
            title="Admission gate",
            status=summary.gate_result,
            detail=f"Scan gate result is {summary.gate_result}.",
        ),
        AuditItem(
            id="audit.runtime_policy",
            title="Runtime policy generated",
            status="pass",
            detail=f"Generated {len(runtime_policy.rules)} runtime policy rules.",
        ),
        AuditItem(
            id="audit.approval",
            title="Human approval",
            status="warn" if summary.approval_required else "pass",
            detail="Human approval is required." if summary.approval_required else "No approval required.",
        ),
        AuditItem(
            id="audit.sandbox",
            title="Sandbox requirement",
            status="warn" if summary.sandbox_required else "pass",
            detail="Sandbox execution is required." if summary.sandbox_required else "No sandbox required.",
        ),
        AuditItem(
            id="audit.egress",
            title="Egress review",
            status="warn" if summary.egress_review_required else "pass",
            detail="Network egress review is required."
            if summary.egress_review_required
            else "No egress review required.",
        ),
        AuditItem(
            id="audit.credentials",
            title="Credential review",
            status="warn" if summary.credential_review_required else "pass",
            detail="Credential scope review is required."
            if summary.credential_review_required
            else "No credential review required.",
        ),
    ]

    next_actions = []
    if summary.gate_result == "fail":
        next_actions.append("Do not connect this MCP server or tool until findings are reviewed.")
    if summary.approval_required:
        next_actions.append("Route the runtime policy and scan report to a human approver.")
    if summary.sandbox_required:
        next_actions.append("Require sandboxing before any live or runtime execution.")
    if summary.egress_review_required:
        next_actions.append("Restrict network egress to approved domains before runtime use.")
    if summary.credential_review_required:
        next_actions.append("Review credential scope and avoid passing long-lived secrets.")
    if not next_actions:
        next_actions.append("Record the audit decision and keep the generated runtime policy with the deployment.")

    return AuditReport(
        target=scan.target,
        gate_result=summary.gate_result,
        runtime_policy=runtime_policy,
        scan_summary=summary,
        policy_context=scan.policy_context,
        policy_effects=scan.policy_effects,
        rule_explanations=scan.rule_explanations,
        items=items,
        next_actions=next_actions,
    )


def render_audit_json(report: AuditReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_audit_markdown(report: AuditReport) -> str:
    lines = [
        "# MCP Admit Audit",
        "",
        f"Target: {report.target}",
        f"Gate: {report.gate_result.upper()}",
        f"Runtime policy rules: {len(report.runtime_policy.rules)}",
        "",
        "## Checklist",
        "",
        "| Item | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for item in report.items:
        lines.append(f"| {item.title} | {item.status} | {item.detail} |")
    if (
        report.policy_context.profile
        or report.policy_context.fail_on
        or report.policy_context.deny_capabilities
        or report.policy_context.require_approval_levels
        or report.policy_context.allow_exec_command_count
        or report.policy_context.waiver_count
        or report.policy_context.policy_effect_count
    ):
        context = report.policy_context
        lines.extend(
            [
                "",
                "## Policy context",
                "",
                f"- Profile: {context.profile or 'none'}",
                f"- Fail on: {context.fail_on or 'none'}",
                f"- Denied capabilities: {', '.join(context.deny_capabilities) or 'none'}",
                f"- Approval levels: {', '.join(context.require_approval_levels) or 'none'}",
                f"- Allowlisted exec commands: {context.allow_exec_command_count}",
                f"- Waivers: {context.waiver_count}",
                f"- Policy effects: {context.policy_effect_count}",
            ]
        )
    if report.policy_effects:
        lines.extend(["", "## Policy effects", ""])
        for effect in report.policy_effects:
            lines.append(
                f"- {effect.action}: {effect.finding_id} at {effect.location} "
                f"({effect.policy_ref}) - {effect.reason}"
            )
    if report.rule_explanations:
        lines.extend(
            [
                "",
                "## Rule explanations",
                "",
                "| Rule | Severity | Risk | Capability | Policy |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for rule in report.rule_explanations:
            lines.append(
                f"| {rule.id} | {rule.severity} | {rule.risk_level} | "
                f"{rule.capability} | {rule.policy_action} |"
            )
    lines.extend(["", "## Next actions", ""])
    lines.extend(f"- {action}" for action in report.next_actions)
    lines.extend(["", "## Runtime policy", "", render_runtime_policy_markdown(report.runtime_policy)])
    return "\n".join(lines)
