from __future__ import annotations

from typing import Any

from mcp_admit.models import Finding, ToolDefinition
from mcp_admit.redaction import redact_text
from mcp_admit.rules.config_rules import SECRET_NAMES
from mcp_admit.rules.schema_rules import scan_tool

MUTABLE_VERSION_MARKERS = {"latest", "main", "master", "next", "snapshot"}
DIGEST_RECOMMENDED_REGISTRIES = {"mcpb", "oci"}


def _document(data: dict[str, Any]) -> dict[str, Any] | None:
    candidate = data.get("server") if isinstance(data.get("server"), dict) else data
    if not isinstance(candidate, dict) or not isinstance(candidate.get("name"), str):
        return None
    if "packages" not in candidate and "remotes" not in candidate:
        return None
    return candidate


def _is_mutable_version(version: str, digest: str) -> bool:
    if digest:
        return False
    lowered = version.strip().lower()
    return (
        not lowered
        or lowered in MUTABLE_VERSION_MARKERS
        or "*" in lowered
        or lowered.endswith(".x")
        or lowered.startswith("^")
        or lowered.startswith("~")
    )


def _declared_secret_name(variable: object) -> str:
    if isinstance(variable, str):
        name = variable
        is_secret = False
    elif isinstance(variable, dict):
        name = str(variable.get("name", ""))
        is_secret = bool(variable.get("isSecret", variable.get("is_secret", False)))
    else:
        return ""
    if is_secret or any(marker in name.upper() for marker in SECRET_NAMES):
        return name
    return ""


def scan_registry_document(data: dict[str, Any], path: str) -> list[Finding]:
    document = _document(data)
    if document is None:
        return []

    findings: list[Finding] = []
    name = str(document["name"])
    description = str(document.get("description", ""))
    if description:
        findings.extend(
            scan_tool(
                ToolDefinition(name=name, description=description),
                f"{path}.server.json",
            )
        )

    server_version = str(document.get("version", ""))
    packages = document.get("packages", [])
    packages = packages if isinstance(packages, list) else []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            continue
        base = f"{path}.packages[{index}]"
        identifier = str(package.get("identifier", ""))
        version = str(package.get("version", ""))
        digest = str(package.get("fileSha256", ""))
        registry_type = str(
            package.get("registryType", document.get("registryType", ""))
        ).lower()
        identifier_has_digest = "@sha256:" in identifier
        immutable_digest = digest or ("sha256" if identifier_has_digest else "")

        if _is_mutable_version(version, immutable_digest):
            findings.append(
                Finding(
                    id="MCPG-SC-008",
                    title="mutable registry package version",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=f"{base}.version",
                    evidence=redact_text(f"{identifier}@{version or 'unversioned'}"),
                    reason="Registry package metadata does not identify an immutable release.",
                    recommendation="Pin an exact package version or immutable artifact digest.",
                    risk_score=70,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.9,
                )
            )

        if (
            registry_type in DIGEST_RECOMMENDED_REGISTRIES
            and not digest
            and not identifier_has_digest
        ):
            findings.append(
                Finding(
                    id="MCPG-SC-009",
                    title="registry artifact lacks immutable digest",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=base,
                    evidence=redact_text(identifier),
                    reason="Binary or container registry artifact is not bound to an immutable digest.",
                    recommendation="Publish and verify fileSha256 or an OCI sha256 digest before approval.",
                    risk_score=70,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.9,
                )
            )

        if server_version and version and server_version != version:
            findings.append(
                Finding(
                    id="MCPG-SC-010",
                    title="server and package versions differ",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=f"{base}.version",
                    evidence=redact_text(
                        f"server={server_version}, package={version}"
                    ),
                    reason="server.json version does not match its published package version.",
                    recommendation="Publish matching server and package versions before admission.",
                    risk_score=65,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.95,
                )
            )

        variables = package.get("environmentVariables", [])
        variables = variables if isinstance(variables, list) else []
        for variable_index, variable in enumerate(variables):
            variable_name = _declared_secret_name(variable)
            if not variable_name:
                continue
            findings.append(
                Finding(
                    id="MCPG-SECRET-003",
                    title="registry package declares secret environment access",
                    severity="high",
                    category="secret",
                    capability="credential_access",
                    location=f"{base}.environmentVariables[{variable_index}]",
                    evidence=redact_text(variable_name),
                    reason="The registry package declares a secret-like runtime environment requirement.",
                    recommendation=(
                        "Use a scoped short-lived credential and require explicit review before injection."
                    ),
                    risk_score=65,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.9,
                )
            )
    return findings
