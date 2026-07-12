from __future__ import annotations

from mcp_admit.models import Finding, ScanSummary
from mcp_admit.risk import (
    gate_from_findings,
    max_risk,
    max_risk_score,
    max_severity,
    recommended_policy,
    risk_factors,
)


def build_summary(findings: list[Finding]) -> ScanSummary:
    policy = recommended_policy(findings)
    return ScanSummary(
        total_findings=len(findings),
        max_severity=max_severity(findings),
        risk_score=max_risk_score(findings),
        tool_risk_level=max_risk(findings),
        gate_result=gate_from_findings(findings),
        approval_required=policy.require_approval,
        sandbox_required=policy.sandbox,
        egress_review_required=any(
            f.capability in {"network_fetch", "network_send"} for f in findings
        ),
        credential_review_required=any(f.capability == "credential_access" for f in findings),
        recommended_policy=policy,
        risk_factors=risk_factors(findings),
    )
