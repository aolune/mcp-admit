from __future__ import annotations

from typing import Any

from mcp_admit.models import Finding, PolicyContext, RuleExplanation, ScanResult
from mcp_admit.rules.catalog import get_rule


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(str(item) for item in value if isinstance(item, str))


def build_policy_context(policy: dict[str, Any] | None, effect_count: int = 0) -> PolicyContext:
    data = policy or {}
    return PolicyContext(
        profile=data.get("profile") if isinstance(data.get("profile"), str) else None,
        fail_on=data.get("fail_on") if isinstance(data.get("fail_on"), str) else None,
        deny_capabilities=_string_list(data.get("deny_capabilities")),
        require_approval_levels=_string_list(data.get("require_approval_levels")),
        allow_exec_command_count=len(_string_list(data.get("allow_exec_commands"))),
        waiver_count=len(data.get("waivers", [])) if isinstance(data.get("waivers", []), list) else 0,
        policy_effect_count=effect_count,
    )


def _fallback_rule(finding: Finding) -> RuleExplanation:
    return RuleExplanation(
        id=finding.id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        capability=finding.capability,
        risk_level=finding.risk_level,
        policy_action=finding.policy_action,
        description=finding.reason,
        recommendation=finding.recommendation,
        owasp=finding.owasp,
    )


def build_rule_explanations(findings: list[Finding]) -> list[RuleExplanation]:
    explanations: list[RuleExplanation] = []
    seen = set()
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        rule = get_rule(finding.id)
        if rule is None:
            explanations.append(_fallback_rule(finding))
            continue
        explanations.append(
            RuleExplanation(
                id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                category=rule["category"],
                capability=rule["capability"],
                risk_level=rule["risk_level"],
                policy_action=rule["policy_action"],
                description=rule["description"],
                recommendation=rule["recommendation"],
                owasp=rule["owasp"],
            )
        )
    return explanations


def refresh_scan_explainability(result: ScanResult, policy: dict[str, Any] | None = None) -> ScanResult:
    result.policy_context = build_policy_context(policy, effect_count=len(result.policy_effects))
    result.rule_explanations = build_rule_explanations(result.findings)
    return result
