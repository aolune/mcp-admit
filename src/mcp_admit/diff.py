from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_admit.hashing import build_baseline, is_baseline_document
from mcp_admit.models import Finding
from mcp_admit.parsers import extract_tools, load_documents
from mcp_admit.risk import RISK_ORDER, max_risk_score
from mcp_admit.rules import scan_tool
from mcp_admit.standards import annotate_findings


def _tools(path: str):
    docs = [d for _, d in load_documents(Path(path))]
    out = {}
    for d in docs:
        for t in extract_tools(d):
            out[t.name] = t
    return out


def _baseline_document(path: str) -> dict[str, Any] | None:
    docs = [data for _, data in load_documents(Path(path))]
    if len(docs) == 1 and is_baseline_document(docs[0]):
        return docs[0]
    return None


def _by_name(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in items if item.get("name")}


def _tool_findings(tool, source: str) -> list[Finding]:
    return annotate_findings(scan_tool(tool, source))


def _max_risk_level(findings: list[Finding]) -> str:
    return max((finding.risk_level for finding in findings), key=lambda level: RISK_ORDER[level], default="L0")


def _capabilities(findings: list[Finding]) -> set[str]:
    return {finding.capability for finding in findings if finding.capability != "unknown"}


def _primary_capability(capabilities: list[str]) -> str:
    priority = [
        "shell_exec",
        "code_exec",
        "credential_access",
        "network_send",
        "file_write",
        "file_read",
        "overbroad_schema",
    ]
    for capability in priority:
        if capability in capabilities:
            return capability
    return capabilities[0] if capabilities else "supply_chain"


def _supply_chain_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    location: str,
    evidence: str,
    reason: str,
    recommendation: str,
    risk_score: int,
    risk_level: str,
    policy_action: str,
    capability: str = "supply_chain",
) -> Finding:
    return Finding(
        id=rule_id,
        title=title,
        severity=severity,
        category="supply_chain",
        capability=capability,
        location=location,
        evidence=evidence,
        reason=reason,
        recommendation=recommendation,
        risk_score=risk_score,
        risk_level=risk_level,
        policy_action=policy_action,
        confidence=0.95,
    )


def _diff_baseline_document(baseline: dict[str, Any], current: str) -> list[Finding]:
    current_baseline = build_baseline(current)
    findings: list[Finding] = []

    baseline_tools = _by_name(baseline.get("tools", []))
    current_tools = _by_name(current_baseline.get("tools", []))
    baseline_servers = _by_name(baseline.get("servers", []))
    current_servers = _by_name(current_baseline.get("servers", []))

    for name in sorted(current_tools.keys() - baseline_tools.keys()):
        findings.append(
            _supply_chain_finding(
                rule_id="MCPG-SC-003",
                title="tool added",
                severity="medium",
                location=name,
                evidence=name,
                reason="New tool was introduced after baseline.",
                recommendation="Re-run approval workflow for newly added tools.",
                risk_score=45,
                risk_level="L3",
                policy_action="require_approval",
            )
        )

    for name in sorted(baseline_tools.keys() - current_tools.keys()):
        findings.append(
            _supply_chain_finding(
                rule_id="MCPG-SC-004",
                title="tool removed",
                severity="low",
                location=name,
                evidence=name,
                reason="Existing tool removed from current manifest.",
                recommendation="Review removal impact and trust chain.",
                risk_score=15,
                risk_level="L1",
                policy_action="allow",
            )
        )

    for name in sorted(baseline_tools.keys() & current_tools.keys()):
        baseline_tool = baseline_tools[name]
        current_tool = current_tools[name]
        if baseline_tool.get("definition_hash") == current_tool.get("definition_hash"):
            continue

        added_capabilities = sorted(
            set(current_tool.get("capabilities", [])) - set(baseline_tool.get("capabilities", []))
        )
        baseline_risk = str(baseline_tool.get("risk_level", "L0"))
        current_risk = str(current_tool.get("risk_level", "L0"))
        if RISK_ORDER[current_risk] > RISK_ORDER[baseline_risk] or added_capabilities:
            findings.append(
                _supply_chain_finding(
                    rule_id="MCPG-SC-001",
                    title="capability escalation after baseline",
                    severity="high" if current_risk != "L4" else "critical",
                    capability=_primary_capability(added_capabilities),
                    location=name,
                    evidence=", ".join(added_capabilities) or f"{baseline_risk} -> {current_risk}",
                    reason="Tool definition changed in a way that introduces new or higher-risk capabilities.",
                    recommendation="Fail admission and require security re-approval before trusting this tool.",
                    risk_score=max(int(current_tool.get("risk_score", 0)), 75),
                    risk_level=current_risk if current_risk != "L0" else "L3",
                    policy_action="deny" if current_risk == "L4" else "require_approval",
                )
            )
        findings.append(
            _supply_chain_finding(
                rule_id="MCPG-SC-002",
                title="tool definition hash changed",
                severity="high",
                location=name,
                evidence=name,
                reason="Tool schema/description changed compared to baseline.",
                recommendation="Treat as potential rug pull and require security re-review.",
                risk_score=60,
                risk_level="L3",
                policy_action="require_approval",
            )
        )

    for name in sorted(current_servers.keys() - baseline_servers.keys()):
        findings.append(
            _supply_chain_finding(
                rule_id="MCPG-SC-006",
                title="server launch definition added",
                severity="medium",
                location=name,
                evidence=name,
                reason="New MCP server launch configuration was introduced after baseline.",
                recommendation="Run admission review for the newly added server.",
                risk_score=45,
                risk_level="L3",
                policy_action="require_approval",
            )
        )

    for name in sorted(baseline_servers.keys() - current_servers.keys()):
        findings.append(
            _supply_chain_finding(
                rule_id="MCPG-SC-007",
                title="server launch definition removed",
                severity="low",
                location=name,
                evidence=name,
                reason="An MCP server launch configuration was removed after baseline.",
                recommendation="Review removal impact and update approval records.",
                risk_score=15,
                risk_level="L1",
                policy_action="allow",
            )
        )

    for name in sorted(baseline_servers.keys() & current_servers.keys()):
        if baseline_servers[name].get("definition_hash") != current_servers[name].get("definition_hash"):
            findings.append(
                _supply_chain_finding(
                    rule_id="MCPG-SC-005",
                    title="server launch definition changed",
                    severity="high",
                    location=name,
                    evidence=name,
                    reason="Server command, args, env keys, transport, or URL changed compared to baseline.",
                    recommendation="Require security re-review before trusting the updated server launch config.",
                    risk_score=65,
                    risk_level="L3",
                    policy_action="require_approval",
                )
            )

    return annotate_findings(findings)


def diff_tools(base: str, current: str) -> list[Finding]:
    baseline_doc = _baseline_document(base)
    if baseline_doc:
        return _diff_baseline_document(baseline_doc, current)

    baseline_tools = _tools(base)
    current_tools = _tools(current)
    findings: list[Finding] = []

    for n in sorted(current_tools.keys() - baseline_tools.keys()):
        findings.append(
            Finding(
                id="MCPG-SC-003",
                title="tool added",
                severity="medium",
                category="supply_chain",
                capability="supply_chain",
                location=n,
                evidence=n,
                reason="New tool was introduced after baseline.",
                recommendation="Re-run approval workflow for newly added tools.",
                risk_score=45,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.9,
            )
        )

    for n in sorted(baseline_tools.keys() - current_tools.keys()):
        findings.append(
            Finding(
                id="MCPG-SC-004",
                title="tool removed",
                severity="low",
                category="supply_chain",
                capability="supply_chain",
                location=n,
                evidence=n,
                reason="Existing tool removed from current manifest.",
                recommendation="Review removal impact and trust chain.",
                risk_score=15,
                risk_level="L1",
                policy_action="allow",
                confidence=0.9,
            )
        )

    for n in sorted(baseline_tools.keys() & current_tools.keys()):
        baseline_tool = baseline_tools[n]
        current_tool = current_tools[n]
        if baseline_tool.model_dump() != current_tool.model_dump():
            baseline_findings = _tool_findings(baseline_tool, f"{base}.{n}")
            current_findings = _tool_findings(current_tool, f"{current}.{n}")
            baseline_risk = _max_risk_level(baseline_findings)
            current_risk = _max_risk_level(current_findings)
            added_capabilities = sorted(_capabilities(current_findings) - _capabilities(baseline_findings))
            if RISK_ORDER[current_risk] > RISK_ORDER[baseline_risk] or added_capabilities:
                findings.append(
                    Finding(
                        id="MCPG-SC-001",
                        title="capability escalation after baseline",
                        severity="high" if current_risk != "L4" else "critical",
                        category="supply_chain",
                        capability=_primary_capability(added_capabilities),
                        location=n,
                        evidence=", ".join(added_capabilities) or f"{baseline_risk} -> {current_risk}",
                        reason="Tool definition changed in a way that introduces new or higher-risk capabilities.",
                        recommendation="Fail admission and require security re-approval before trusting this tool.",
                        risk_score=max(max_risk_score(current_findings), 75),
                        risk_level=current_risk if current_risk != "L0" else "L3",
                        policy_action="deny" if current_risk == "L4" else "require_approval",
                        confidence=0.95,
                    )
                )
            findings.append(
                Finding(
                    id="MCPG-SC-002",
                    title="tool definition hash changed",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=n,
                    evidence=n,
                    reason="Tool schema/description changed compared to baseline.",
                    recommendation="Treat as potential rug pull and require security re-review.",
                    risk_score=60,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.95,
                )
            )
    return annotate_findings(findings)
