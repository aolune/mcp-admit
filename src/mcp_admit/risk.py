from mcp_admit.models import Finding, PolicyDecision, PolicyAction, RiskFactor

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4}
ACTION_ORDER = {
    "allow": 0,
    "allow_with_constraints": 1,
    "require_approval": 2,
    "quarantine": 3,
    "deny": 4,
}

SEVERITY_FALLBACK_SCORE = {
    "info": 0,
    "low": 15,
    "medium": 40,
    "high": 65,
    "critical": 85,
}


def max_severity(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=lambda s: SEV_ORDER[s], default="info")


def max_risk(findings: list[Finding]) -> str:
    return max((f.risk_level for f in findings), key=lambda s: RISK_ORDER[s], default="L0")


def max_risk_score(findings: list[Finding]) -> int:
    return max((f.risk_score or SEVERITY_FALLBACK_SCORE[f.severity] for f in findings), default=0)


def risk_factors(findings: list[Finding], limit: int = 8) -> list[RiskFactor]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.id, []).append(finding)

    factors = []
    for rule_id, matches in grouped.items():
        strongest = max(matches, key=lambda finding: finding.risk_score)
        source_ids = strongest.related_finding_ids or [strongest.id]
        factors.append(
            RiskFactor(
                id=rule_id,
                score=strongest.risk_score or SEVERITY_FALLBACK_SCORE[strongest.severity],
                reason=strongest.reason,
                capabilities=sorted({finding.capability for finding in matches}),
                source_finding_ids=source_ids,
                occurrences=len(matches),
            )
        )
    return sorted(factors, key=lambda factor: (-factor.score, factor.id))[:limit]


def gate_from_findings(findings: list[Finding]) -> str:
    sev = max_severity(findings)
    if sev in {"critical", "high"}:
        return "fail"
    if sev == "medium":
        return "warn"
    return "pass"


def default_action_for_level(level: str) -> PolicyAction:
    if level == "L4":
        return "deny"
    if level == "L3":
        return "require_approval"
    if level == "L2":
        return "allow_with_constraints"
    return "allow"


def strongest_policy_action(findings: list[Finding]) -> PolicyAction:
    actions = [f.policy_action for f in findings]
    if not actions:
        return "allow"
    return max(actions, key=lambda action: ACTION_ORDER[action])


def recommended_policy(findings: list[Finding]) -> PolicyDecision:
    level = max_risk(findings)
    action = strongest_policy_action(findings)
    default_action = default_action_for_level(level)
    if ACTION_ORDER[default_action] > ACTION_ORDER[action]:
        action = default_action

    capabilities = {f.capability for f in findings}
    network = "allow"
    if action in {"deny", "quarantine"}:
        network = "deny"
    elif capabilities & {"network_send", "network_fetch"}:
        network = "restricted"

    notes = []
    if level in {"L3", "L4"}:
        notes.append("Require human review before connecting this MCP server or tool.")
    if "shell_exec" in capabilities or "code_exec" in capabilities:
        notes.append("Do not execute by default; use sandbox and an explicit allowlist if approved.")
    if "credential_access" in capabilities:
        notes.append("Review credential scope and avoid passing long-lived secrets to the server.")
    if "network_send" in capabilities:
        notes.append("Restrict egress to approved domains before allowing outbound writes.")
    if "prompt_injection" in capabilities:
        notes.append("Quarantine suspicious metadata until manually reviewed.")
    if "container_escape" in capabilities:
        notes.append("Remove privileged containers, host namespaces, Docker socket mounts, and broad host bind mounts.")

    return PolicyDecision(
        action=action,
        require_approval=action in {"require_approval", "deny", "quarantine"} or level in {"L3", "L4"},
        sandbox=level == "L4" or bool(capabilities & {"shell_exec", "code_exec", "file_read", "file_write"}),
        network=network,
        notes=notes,
    )
