from __future__ import annotations

import json

from mcp_admit.models import (
    AdmissionControl,
    AdmissionInputReport,
    AdmissionSubject,
    ApprovalDecision,
    AuditReport,
    ScanResult,
)
from mcp_admit.runtime_policy import build_audit_report, build_runtime_policy


def _decision(
    scan: ScanResult,
    approval: ApprovalDecision | None,
) -> tuple[str, str]:
    action = scan.summary.recommended_policy.action
    if action == "deny":
        return "deny", "Policy or risk analysis requires denial."
    if action == "quarantine":
        return "quarantine", "Suspicious metadata requires quarantine."
    if approval is not None:
        if approval.status == "drifted":
            return "quarantine", "Approved server definition or capabilities drifted."
        if approval.status == "expired":
            return "review", "Human approval expired and must be renewed."
        if approval.status == "pending":
            return "review", "Human approval is pending."
        if approval.status == "unknown":
            return "review", "No matching approval record exists."
        constrained = (
            scan.summary.sandbox_required
            or scan.summary.egress_review_required
            or scan.summary.credential_review_required
            or action == "allow_with_constraints"
        )
        if constrained:
            return (
                "allow_with_constraints",
                "Current definition is approved; generated runtime controls remain required.",
            )
        return "allow", "Current definition matches an explicit, unexpired approval."
    if scan.summary.gate_result in {"fail", "warn"} or scan.summary.approval_required:
        return "review", "Static analysis requires human review."
    return "allow", "Static analysis found no admission-blocking risk."


def _control(
    id: str,
    title: str,
    required: bool,
    status: str,
    detail: str,
) -> AdmissionControl:
    return AdmissionControl(id=id, title=title, required=required, status=status, detail=detail)


def _controls(
    scan: ScanResult,
    audit: AuditReport,
    approval: ApprovalDecision | None,
) -> list[AdmissionControl]:
    summary = scan.summary
    controls = [
        _control(
            "admission.static_scan",
            "Static scan completed",
            True,
            summary.gate_result,
            f"Static scan completed with gate result {summary.gate_result}.",
        ),
        _control(
            "admission.runtime_policy",
            "Runtime policy generated",
            True,
            "pass",
            f"Runtime policy contains {len(audit.runtime_policy.rules)} rules.",
        ),
        _control(
            "admission.human_approval",
            "Human approval",
            summary.approval_required,
            "pass"
            if approval is not None and approval.status == "approved"
            else "warn"
            if summary.approval_required
            else "pass",
            "Human approval is satisfied."
            if approval is not None and approval.status == "approved"
            else "Human approval is required."
            if summary.approval_required
            else "No approval required.",
        ),
        _control(
            "admission.sandbox",
            "Sandbox",
            summary.sandbox_required,
            "warn" if summary.sandbox_required else "pass",
            "Sandboxing is required." if summary.sandbox_required else "No sandbox required.",
        ),
        _control(
            "admission.egress",
            "Egress review",
            summary.egress_review_required,
            "warn" if summary.egress_review_required else "pass",
            "Network egress review is required."
            if summary.egress_review_required
            else "No egress review required.",
        ),
        _control(
            "admission.credentials",
            "Credential review",
            summary.credential_review_required,
            "warn" if summary.credential_review_required else "pass",
            "Credential review is required."
            if summary.credential_review_required
            else "No credential review required.",
        ),
    ]
    if approval is not None:
        status = "pass" if approval.status == "approved" else "warn"
        if approval.status in {"expired", "drifted"}:
            status = "fail"
        controls.insert(
            1,
            _control(
                "admission.approval_registry",
                "Approval registry",
                True,
                status,
                f"Approval status is {approval.status}: {approval.reason}",
            ),
        )
    return controls


def build_admission_input(
    scan: ScanResult,
    approval: ApprovalDecision | None = None,
    server: str = "",
    service: str = "unknown",
    owner: str = "unknown",
    environment: str = "unknown",
    request_id: str = "",
) -> AdmissionInputReport:
    runtime_policy = build_runtime_policy(scan)
    audit = build_audit_report(scan)
    capabilities = sorted({finding.capability for finding in scan.findings})
    finding_ids = sorted({finding.id for finding in scan.findings})
    decision, decision_reason = _decision(scan, approval)
    return AdmissionInputReport(
        subject=AdmissionSubject(
            target=scan.target,
            server=server,
            service=service or "unknown",
            owner=owner or "unknown",
            environment=environment or "unknown",
            request_id=request_id or "",
        ),
        decision=decision,
        decision_reason=decision_reason,
        approval=approval,
        gate_result=scan.summary.gate_result,
        risk_level=scan.summary.tool_risk_level,
        risk_score=scan.summary.risk_score,
        capabilities=capabilities,
        finding_ids=finding_ids,
        policy_context=scan.policy_context,
        policy_effects=scan.policy_effects,
        rule_explanations=scan.rule_explanations,
        controls=_controls(scan, audit, approval),
        runtime_policy=runtime_policy,
        audit=audit,
        scan_summary=scan.summary,
    )


def render_admission_json(report: AdmissionInputReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_admission_markdown(report: AdmissionInputReport) -> str:
    lines = [
        "# MCP Admit Admission Input",
        "",
        f"Target: {report.subject.target}",
        f"Service: {report.subject.service}",
        f"Owner: {report.subject.owner}",
        f"Environment: {report.subject.environment}",
    ]
    if report.subject.request_id:
        lines.append(f"Request ID: {report.subject.request_id}")
    if report.subject.server:
        lines.append(f"Server: {report.subject.server}")
    lines.extend(
        [
            f"Decision: {report.decision}",
            f"Decision reason: {report.decision_reason}",
            f"Gate: {report.gate_result.upper()}",
            f"Risk level: {report.risk_level}",
            f"Risk score: {report.risk_score} / 100",
            "",
            "## Capabilities",
            "",
        ]
    )
    if report.capabilities:
        lines.extend(f"- {capability}" for capability in report.capabilities)
    else:
        lines.append("- none")
    if report.approval is not None:
        lines.extend(
            [
                "",
                "## Approval",
                "",
                f"- Status: {report.approval.status}",
                f"- Record: {report.approval.approval_id or 'none'}",
                f"- Reason: {report.approval.reason}",
            ]
        )
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
    lines.extend(
        [
            "",
            "## Controls",
            "",
            "| Control | Required | Status | Detail |",
            "| --- | --- | --- | --- |",
        ]
    )
    for control in report.controls:
        required = "yes" if control.required else "no"
        lines.append(
            f"| {control.title} | {required} | {control.status} | {control.detail} |"
        )
    lines.extend(
        [
            "",
            "## Runtime policy",
            "",
            f"- Rules: {len(report.runtime_policy.rules)}",
            f"- Default action: {report.runtime_policy.default_action}",
            "",
            "## Next actions",
            "",
        ]
    )
    lines.extend(f"- {action}" for action in report.audit.next_actions)
    return "\n".join(lines)
