from __future__ import annotations

import re
from typing import Any

from mcp_admit.models import Finding, ToolDefinition
from mcp_admit.redaction import redact_text
from mcp_admit.rules.text_patterns import (
    CAPABILITY_KEYWORDS,
    HIDDEN_INSTRUCTION_PHRASES,
    INJECTION_PHRASES,
)

BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{48,}={0,2}\b")


def _walk(schema: Any, path: str):
    if isinstance(schema, dict):
        yield path, schema
        for key, value in schema.items():
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            yield from _walk(value, f"{path}[{index}]")


def _field_name(location: str) -> str:
    return location.rsplit(".", 1)[-1].lower()


def _node_text(location: str, node: dict[str, Any]) -> str:
    parts = [_field_name(location)]
    for key in ("name", "description", "title"):
        value = node.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


def _add_once(findings: list[Finding], finding: Finding) -> None:
    key = (finding.id, finding.location)
    if all((existing.id, existing.location) != key for existing in findings):
        findings.append(finding)


def _matches_pattern(text: str, pattern: str) -> bool:
    if pattern and pattern[0].isalnum() and pattern[-1].isalnum():
        return re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(pattern)}(?![A-Za-z0-9_])",
            text,
        ) is not None
    return pattern in text


def _text_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    capability: str,
    location: str,
    evidence: str,
    reason: str,
    recommendation: str,
    risk_score: int,
    risk_level: str,
    policy_action: str,
    confidence: float,
) -> Finding:
    return Finding(
        id=rule_id,
        title=title,
        severity=severity,
        category="injection" if capability == "prompt_injection" else "capability",
        capability=capability,
        location=location,
        evidence=redact_text(evidence[:160]),
        reason=reason,
        recommendation=recommendation,
        risk_score=risk_score,
        risk_level=risk_level,
        policy_action=policy_action,
        confidence=confidence,
    )


def _scan_injection_text(findings: list[Finding], text: str, location: str) -> None:
    lowered = text.lower()
    for phrase in INJECTION_PHRASES:
        if phrase in lowered:
            _add_once(
                findings,
                _text_finding(
                    rule_id="MCPG-INJ-001",
                    title="prompt injection phrase in tool metadata",
                    severity="high",
                    capability="prompt_injection",
                    location=location,
                    evidence=phrase,
                    reason="Tool metadata contains instruction-like language that the model may treat as trusted.",
                    recommendation="Quarantine the tool metadata and require manual review before approval.",
                    risk_score=60,
                    risk_level="L3",
                    policy_action="quarantine",
                    confidence=0.9,
                ),
            )
            break

    if any(phrase in lowered for phrase in HIDDEN_INSTRUCTION_PHRASES) or BASE64_RE.search(text):
        _add_once(
            findings,
            _text_finding(
                rule_id="MCPG-INJ-002",
                title="hidden or obfuscated instruction in tool metadata",
                severity="medium",
                capability="prompt_injection",
                location=location,
                evidence=text,
                reason="Tool metadata contains hidden, obfuscated, or secrecy-oriented instruction markers.",
                recommendation="Require manual review and remove hidden instructions from metadata.",
                risk_score=45,
                risk_level="L2",
                policy_action="quarantine",
                confidence=0.8,
            ),
        )


def _scan_capability_text(findings: list[Finding], text: str, location: str) -> None:
    lowered = text.lower()
    for rule_id, rule in CAPABILITY_KEYWORDS.items():
        if not any(_matches_pattern(lowered, pattern) for pattern in rule["patterns"]):
            continue
        _add_once(
            findings,
            Finding(
                id=rule_id,
                title=str(rule["title"]),
                severity=rule["severity"],
                category="capability",
                capability=str(rule["capability"]),
                location=location,
                evidence=redact_text(text[:160]),
                reason="Tool metadata or schema suggests this tool exposes a sensitive capability.",
                recommendation="Map this capability to explicit approval, sandboxing, and least-privilege controls.",
                risk_score=rule["risk_score"],
                risk_level=rule["risk_level"],
                policy_action=rule["policy_action"],
                confidence=0.75,
            ),
        )


def _scan_schema_shape(findings: list[Finding], node: dict[str, Any], location: str) -> None:
    field_text = _node_text(location, node)
    lowered = field_text.lower()
    is_string = node.get("type") == "string"
    has_constraints = any(key in node for key in ("enum", "const", "pattern", "maxLength", "format"))

    if node.get("additionalProperties") is True:
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-001",
                title="free-form object schema",
                severity="medium",
                category="schema",
                capability="overbroad_schema",
                location=location,
                evidence="additionalProperties=true",
                reason="Loose schemas can hide unreviewed parameters and make consent harder to reason about.",
                recommendation="Set additionalProperties=false and enumerate supported parameters.",
                risk_score=40,
                risk_level="L2",
                policy_action="allow_with_constraints",
                confidence=0.85,
            ),
        )

    if not is_string or has_constraints:
        return

    if any(token in lowered for token in ("path", "filepath", "file path")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-002",
                title="unbounded file path parameter",
                severity="high",
                category="schema",
                capability="file_read",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts a free-form file path without an allowlist or pattern constraint.",
                recommendation="Add allowed roots, path patterns, and per-call approval for sensitive reads.",
                risk_score=65,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.85,
            ),
        )

    if any(token in lowered for token in ("write file", "delete file", "remove file", "overwrite", "output path")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-006",
                title="destructive file write parameter",
                severity="high",
                category="schema",
                capability="file_write",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts an unconstrained file write, delete, remove, or overwrite parameter.",
                recommendation="Constrain writable roots and require approval for destructive filesystem operations.",
                risk_score=70,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.85,
            ),
        )

    if any(token in lowered for token in ("url", "uri", "webhook")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-003",
                title="unbounded url parameter",
                severity="high",
                category="schema",
                capability="network_send",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts a free-form URL without allowed domain constraints.",
                recommendation="Enforce allowed domains and deny outbound writes by default.",
                risk_score=65,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.85,
            ),
        )

    if any(token in lowered for token in ("cookie", "session", "browser profile", "dom selector")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-007",
                title="browser session automation parameter",
                severity="high",
                category="schema",
                capability="browser_automation",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts unconstrained browser session, cookie, or DOM automation input.",
                recommendation="Use isolated browser profiles and require approval for session or cookie access.",
                risk_score=65,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.8,
            ),
        )

    if any(token in lowered for token in ("command", "shell", "script", "exec", "code")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-004",
                title="dangerous command or code parameter",
                severity="critical",
                category="schema",
                capability="shell_exec",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts a free-form command, script, exec, or code parameter.",
                recommendation="Remove generic execution parameters or replace them with enumerated safe actions.",
                risk_score=85,
                risk_level="L4",
                policy_action="deny",
                confidence=0.9,
            ),
        )

    if any(token in lowered for token in ("iam", "role", "policy arn", "bucket", "kubernetes", "cluster admin")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-008",
                title="cloud admin parameter",
                severity="high",
                category="schema",
                capability="cloud_api",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts unconstrained cloud, IAM, storage, or cluster administration input.",
                recommendation="Constrain cloud resources and require least-privilege approval before use.",
                risk_score=70,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.8,
            ),
        )

    if any(token in lowered for token in ("recipient", "channel", "email", "slack", "message body")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-009",
                title="messaging send parameter",
                severity="high",
                category="schema",
                capability="email_messaging",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts unconstrained recipient, channel, or message content input.",
                recommendation="Restrict destinations and require approval for outbound messaging.",
                risk_score=60,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.8,
            ),
        )

    if any(token in lowered for token in ("payment", "purchase", "refund", "charge", "checkout")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-010",
                title="payment or purchase parameter",
                severity="critical",
                category="schema",
                capability="payment_purchase",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts unconstrained payment, purchase, charge, or refund input.",
                recommendation="Deny by default and require explicit business approval for payment actions.",
                risk_score=85,
                risk_level="L4",
                policy_action="deny",
                confidence=0.85,
            ),
        )

    if any(token in lowered for token in ("oauth", "access token", "refresh token", "token scope", "api token")):
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-011",
                title="oauth token or scope parameter",
                severity="high",
                category="schema",
                capability="credential_access",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema accepts unconstrained OAuth, token, or scope input.",
                recommendation="Use scoped short-lived credentials and avoid accepting arbitrary token values.",
                risk_score=75,
                risk_level="L4",
                policy_action="deny",
                confidence=0.85,
            ),
        )

    if "sql" in lowered:
        _add_once(
            findings,
            Finding(
                id="MCPG-SCHEMA-005",
                title="free-form sql parameter",
                severity="high",
                category="schema",
                capability="database_query",
                location=location,
                evidence=redact_text(field_text[:160]),
                reason="Schema appears to accept arbitrary SQL text.",
                recommendation="Use parameterized operations or a constrained query builder instead of raw SQL.",
                risk_score=60,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.85,
            ),
        )


def scan_tool(tool: ToolDefinition, base_loc: str) -> list[Finding]:
    findings: list[Finding] = []
    metadata_loc = f"{base_loc}.{tool.name}.description"
    metadata_text = f"{tool.name} {tool.description}".strip()
    _scan_injection_text(findings, metadata_text, metadata_loc)
    _scan_capability_text(findings, metadata_text, metadata_loc)

    for location, node in _walk(tool.inputSchema, f"{base_loc}.{tool.name}.inputSchema"):
        if not isinstance(node, dict):
            continue
        field_text = _node_text(location, node)
        _scan_injection_text(findings, field_text, location)
        _scan_capability_text(findings, field_text, location)
        _scan_schema_shape(findings, node, location)

    return findings
