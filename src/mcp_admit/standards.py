from __future__ import annotations

from mcp_admit.models import Finding

OWASP_MCP_RULE_MAP = {
    "MCPG-STDIO": ["MCP Top 10: Command Injection", "MCP Top 10: Supply Chain"],
    "MCPG-SECRET": ["MCP Top 10: Token Mismanagement", "MCP Top 10: Context Over-Sharing"],
    "MCPG-CAP": ["MCP Top 10: Scope Creep"],
    "MCPG-SCHEMA": ["MCP Top 10: Scope Creep", "MCP Top 10: Intent Flow Subversion"],
    "MCPG-INJ": ["MCP Top 10: Tool Poisoning", "MCP Top 10: Context Injection"],
    "MCPG-SC": ["MCP Top 10: Supply Chain", "MCP Top 10: Tool Poisoning"],
    "MCPG-NET": ["MCP Top 10: Intent Flow Subversion", "MCP Top 10: Context Over-Sharing"],
    "MCPG-LIVE": ["MCP Top 10: Command Injection", "MCP Top 10: Supply Chain"],
    "MCPG-FLOW": ["MCP Top 10: Intent Flow Subversion", "MCP Top 10: Context Over-Sharing"],
}


def owasp_for_rule(rule_id: str) -> list[str]:
    for prefix, items in OWASP_MCP_RULE_MAP.items():
        if rule_id.startswith(prefix):
            return items.copy()
    return []


def annotate_finding(finding: Finding) -> Finding:
    if finding.owasp:
        return finding
    return finding.model_copy(update={"owasp": owasp_for_rule(finding.id)})


def annotate_findings(findings: list[Finding]) -> list[Finding]:
    return [annotate_finding(finding) for finding in findings]
