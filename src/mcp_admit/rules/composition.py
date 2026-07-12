from __future__ import annotations

from mcp_admit.models import Finding

SENSITIVE_READ_CAPABILITIES = {"credential_access", "file_read"}
OUTBOUND_CAPABILITIES = {"email_messaging", "network_send"}
HIGH_IMPACT_CAPABILITIES = {
    "cloud_api",
    "code_exec",
    "credential_access",
    "email_messaging",
    "file_write",
    "network_send",
    "payment_purchase",
    "shell_exec",
}


def _ids(findings: list[Finding], capabilities: set[str]) -> list[str]:
    return sorted({finding.id for finding in findings if finding.capability in capabilities})


def _capabilities(findings: list[Finding]) -> set[str]:
    return {finding.capability for finding in findings}


def scan_compositions(findings: list[Finding], target: str) -> list[Finding]:
    capabilities = _capabilities(findings)
    composed: list[Finding] = []

    sensitive = capabilities & SENSITIVE_READ_CAPABILITIES
    outbound = capabilities & OUTBOUND_CAPABILITIES
    if sensitive and outbound:
        source_ids = _ids(findings, sensitive | outbound)
        composed.append(
            Finding(
                id="MCPG-FLOW-001",
                title="sensitive data access combined with outbound channel",
                severity="critical",
                category="capability",
                capability="data_exfiltration",
                location=target,
                evidence=f"Combined findings: {', '.join(source_ids)}",
                reason=(
                    "The admitted tool set can access sensitive data and transmit data "
                    "outside the trust boundary."
                ),
                recommendation=(
                    "Deny by default or isolate sensitive reads from outbound tools with "
                    "separate credentials, egress allowlists, and per-call approval."
                ),
                risk_score=95 if "credential_access" in sensitive else 90,
                risk_level="L4",
                policy_action="deny" if "credential_access" in sensitive else "quarantine",
                confidence=0.9,
                related_finding_ids=source_ids,
            )
        )

    impactful = capabilities & HIGH_IMPACT_CAPABILITIES
    if "prompt_injection" in capabilities and impactful:
        source_ids = _ids(findings, {"prompt_injection"} | impactful)
        composed.append(
            Finding(
                id="MCPG-FLOW-002",
                title="prompt injection combined with high-impact capability",
                severity="critical",
                category="injection",
                capability="prompt_injection",
                location=target,
                evidence=f"Combined findings: {', '.join(source_ids)}",
                reason=(
                    "Suspicious instructions are present in a tool set that can perform "
                    "high-impact actions."
                ),
                recommendation=(
                    "Quarantine the tool set until metadata is reviewed and high-impact "
                    "capabilities are isolated behind explicit approval."
                ),
                risk_score=95,
                risk_level="L4",
                policy_action="quarantine",
                confidence=0.9,
                related_finding_ids=source_ids,
            )
        )

    if capabilities & {"code_exec", "shell_exec"} and "credential_access" in capabilities:
        source_ids = _ids(findings, {"code_exec", "shell_exec", "credential_access"})
        composed.append(
            Finding(
                id="MCPG-FLOW-003",
                title="code execution combined with credential access",
                severity="critical",
                category="capability",
                capability="credential_access",
                location=target,
                evidence=f"Combined findings: {', '.join(source_ids)}",
                reason="Executable server code receives credentials in the same trust boundary.",
                recommendation=(
                    "Deny broad credential passthrough; use scoped short-lived credentials "
                    "inside an isolated execution environment."
                ),
                risk_score=95,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
                related_finding_ids=source_ids,
            )
        )

    return composed
