from __future__ import annotations

from mcp_admit.models import ScanResult


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _has_policy_context(result: ScanResult) -> bool:
    context = result.policy_context
    return bool(
        context.profile
        or context.fail_on
        or context.deny_capabilities
        or context.require_approval_levels
        or context.allow_exec_command_count
        or context.waiver_count
        or context.policy_effect_count
    )


def render_markdown(result: ScanResult) -> str:
    summary = result.summary
    policy = summary.recommended_policy
    lines = [
        "# MCP Admit Report",
        "",
        f"Target: {result.target}",
        f"Gate: {summary.gate_result.upper()}",
        f"Max severity: {summary.max_severity.upper()}",
        f"Risk level: {summary.tool_risk_level}",
        f"Risk score: {summary.risk_score} / 100",
        f"Risk score method: {summary.risk_score_method}",
        "",
        "## Recommended policy",
        "",
        f"- Action: {policy.action}",
        f"- Require approval: {_yes_no(policy.require_approval)}",
        f"- Sandbox: {_yes_no(policy.sandbox)}",
        f"- Network: {policy.network}",
        "",
        "## Summary",
        "",
        f"- Findings: {summary.total_findings}",
        f"- Approval required: {_yes_no(summary.approval_required)}",
        f"- Sandbox required: {_yes_no(summary.sandbox_required)}",
        f"- Egress review required: {_yes_no(summary.egress_review_required)}",
        f"- Credential review required: {_yes_no(summary.credential_review_required)}",
        "",
    ]
    if summary.risk_factors:
        lines.extend(
            [
                "## Risk factors",
                "",
                "| Factor | Score | Capabilities | Occurrences |",
                "| --- | --- | --- | --- |",
            ]
        )
        for factor in summary.risk_factors:
            lines.append(
                f"| {factor.id} | {factor.score} | "
                f"{', '.join(factor.capabilities) or 'none'} | {factor.occurrences} |"
            )
        lines.append("")
    if _has_policy_context(result):
        context = result.policy_context
        lines.extend(
            [
                "## Policy context",
                "",
                f"- Profile: {context.profile or 'none'}",
                f"- Fail on: {context.fail_on or 'none'}",
                f"- Denied capabilities: {', '.join(context.deny_capabilities) or 'none'}",
                f"- Approval levels: {', '.join(context.require_approval_levels) or 'none'}",
                f"- Allowlisted exec commands: {context.allow_exec_command_count}",
                f"- Waivers: {context.waiver_count}",
                f"- Policy effects: {context.policy_effect_count}",
                "",
            ]
        )
    if policy.notes:
        lines.append("## Policy notes")
        lines.append("")
        lines.extend(f"- {note}" for note in policy.notes)
        lines.append("")

    if result.policy_effects:
        lines.extend(["## Policy effects", ""])
        for effect in result.policy_effects:
            lines.append(
                f"- {effect.action}: {effect.finding_id} at {effect.location} "
                f"({effect.policy_ref}) - {effect.reason}"
            )
        lines.append("")

    if result.rule_explanations:
        lines.extend(
            [
                "## Rule explanations",
                "",
                "| Rule | Severity | Risk | Capability | Policy |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for rule in result.rule_explanations:
            lines.append(
                f"| {rule.id} | {rule.severity} | {rule.risk_level} | "
                f"{rule.capability} | {rule.policy_action} |"
            )
        lines.append("")

    lines.extend(["## Findings", ""])
    if not result.findings:
        lines.extend(["No findings.", ""])
        return "\n".join(lines)

    for finding in result.findings:
        lines += [
            f"### {finding.id} {finding.title}",
            "",
            f"Severity: {finding.severity.upper()}",
            f"Capability: {finding.capability}",
            f"Risk level: {finding.risk_level}",
            f"Risk score: {finding.risk_score} / 100",
            f"Policy action: {finding.policy_action}",
            f"Confidence: {finding.confidence:.2f}",
            f"OWASP MCP: {', '.join(finding.owasp) if finding.owasp else 'n/a'}",
            f"Location: {finding.location}",
            f"Evidence: {finding.evidence}",
            "",
            f"Reason: {finding.reason}",
            "",
            f"Recommendation: {finding.recommendation}",
            "",
        ]
    return "\n".join(lines)
