from __future__ import annotations

import os
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp_admit.mcp_stdio import (
    McpStdioError,
    McpStdioTimeout,
    list_tools_from_stdio,
)
from mcp_admit.explainability import refresh_scan_explainability
from mcp_admit.models import (
    InspectionExecution,
    InspectionReport,
    LiveToolSummary,
    ScanResult,
    ToolDefinition,
)
from mcp_admit.parsers import extract_mcp_server_entries, load_documents
from mcp_admit.policy import apply_policy_with_effects, expand_policy, policy_allow_exec_commands
from mcp_admit.redaction import redact_text
from mcp_admit.rules import scan_tool
from mcp_admit.scanner import scan_path
from mcp_admit.standards import annotate_findings
from mcp_admit.summary import build_summary

ToolLister = Callable[[list[str], dict[str, str], float], list[ToolDefinition]]

SAFE_INHERITED_ENV_KEYS = {
    "PATH",
    "HOME",
    "USER",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SystemRoot",
    "COMSPEC",
}


class InspectionError(ValueError):
    pass


def normalize_launch(server: dict[str, Any]) -> list[str]:
    command = str(server.get("command", "")).strip()
    raw_args = server.get("args", [])
    args = raw_args if isinstance(raw_args, list) else []
    if not command:
        return []
    return [command, *(str(arg) for arg in args)]


def render_launch(argv: list[str]) -> str:
    return shlex.join(argv)


def _server_transport(server: dict[str, Any]) -> str:
    transport = str(server.get("transport", "")).strip()
    if transport:
        return transport
    return "stdio" if server.get("command") else ""


def _servers_for_target(target: str) -> list[tuple[str, str, dict[str, Any]]]:
    servers: list[tuple[str, str, dict[str, Any]]] = []
    for file, data in load_documents(Path(target)):
        for entry in extract_mcp_server_entries(data):
            servers.append((f"{file}.{entry.location}", entry.name, entry.server))
    return servers


def _select_server(
    target: str,
    requested: str | None,
) -> tuple[str, str, dict[str, Any]]:
    servers = _servers_for_target(target)
    if requested:
        matches = [item for item in servers if item[1] == requested]
        if not matches:
            raise InspectionError(f"Server not found: {requested}")
        if len(matches) > 1:
            raise InspectionError(f"Server name is ambiguous across scanned files: {requested}")
        return matches[0]
    if len(servers) == 1:
        return servers[0]
    if not servers:
        raise InspectionError("No mcpServers entries found for live inspection.")
    names = ", ".join(name for _, name, _ in servers)
    raise InspectionError(f"Multiple MCP servers found; choose one with --server. Available: {names}")


def _runtime_env(config_env: dict[str, Any], allowed_env_keys: set[str]) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in SAFE_INHERITED_ENV_KEYS}
    for key, value in config_env.items():
        if key in allowed_env_keys:
            env[str(key)] = str(value)
    return env


def _execution(
    status: str,
    server: str,
    transport: str,
    launch: str,
    message: str,
    finding_id: str | None = None,
    allowed_env_keys: list[str] | None = None,
    blocked_env_keys: list[str] | None = None,
) -> InspectionExecution:
    return InspectionExecution(
        status=status,
        server=server,
        transport=transport,
        launch=redact_text(launch),
        finding_id=finding_id,
        allowed_env_keys=sorted(allowed_env_keys or []),
        blocked_env_keys=sorted(blocked_env_keys or []),
        message=message,
    )


def _apply_policy_to_scan(result: ScanResult, policy: dict[str, Any]) -> ScanResult:
    result.findings, result.policy_effects = apply_policy_with_effects(result.findings, policy)
    result.summary = build_summary(result.findings)
    return refresh_scan_explainability(result, policy)


def _scan_live_tools(
    target: str,
    server_name: str,
    tools: list[ToolDefinition],
    policy: dict[str, Any],
) -> ScanResult:
    findings = []
    for tool in tools:
        findings.extend(scan_tool(tool, f"{target}.{server_name}.live"))
    findings = annotate_findings(findings)
    result = ScanResult(
        target=f"{target}#{server_name}:live",
        findings=findings,
        summary=build_summary(findings),
    )
    return _apply_policy_to_scan(result, policy)


def _live_tool_summary(tool: ToolDefinition) -> LiveToolSummary:
    schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
    properties = schema.get("properties", {})
    property_names = sorted(str(key) for key in properties) if isinstance(properties, dict) else []
    required = schema.get("required", [])
    required_names = sorted(str(item) for item in required) if isinstance(required, list) else []
    additional = schema.get("additionalProperties")
    return LiveToolSummary(
        name=redact_text(tool.name),
        description=redact_text(tool.description),
        input_properties=property_names,
        required=required_names,
        allows_additional_properties=additional if isinstance(additional, bool) else None,
    )


def _live_tool_summaries(tools: list[ToolDefinition]) -> list[LiveToolSummary]:
    return [_live_tool_summary(tool) for tool in tools]


def inspect_path(
    target: str,
    server_name: str | None = None,
    allow_exec: bool = False,
    allow_commands: list[str] | None = None,
    allow_env_keys: list[str] | None = None,
    timeout: float = 5.0,
    policy: dict[str, Any] | None = None,
    tool_lister: ToolLister = list_tools_from_stdio,
) -> InspectionReport:
    loaded_policy = expand_policy(policy or {})
    static_result = _apply_policy_to_scan(scan_path(target), loaded_policy)
    _, selected_name, server = _select_server(target, server_name)
    transport = _server_transport(server)
    argv = normalize_launch(server)
    launch = render_launch(argv) if argv else ""

    if transport != "stdio":
        execution = _execution(
            status="unsupported_transport",
            server=selected_name,
            transport=transport or "unknown",
            launch=launch,
            finding_id="MCPG-LIVE-004",
            message="Live inspection currently supports stdio MCP servers only.",
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )

    if not argv:
        execution = _execution(
            status="unsupported_transport",
            server=selected_name,
            transport="stdio",
            launch=launch,
            finding_id="MCPG-LIVE-004",
            message="Stdio live inspection requires an explicit command.",
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )

    if not allow_exec:
        execution = _execution(
            status="blocked_missing_allow_exec",
            server=selected_name,
            transport="stdio",
            launch=launch,
            finding_id="MCPG-LIVE-001",
            message="Live execution is disabled by default; pass --allow-exec to inspect stdio tools.",
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )

    allowed_commands = set(allow_commands or []) | set(policy_allow_exec_commands(loaded_policy))
    if launch not in allowed_commands:
        execution = _execution(
            status="blocked_command_not_allowlisted",
            server=selected_name,
            transport="stdio",
            launch=launch,
            finding_id="MCPG-LIVE-002",
            message="The exact stdio launch vector is not allowlisted.",
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )

    config_env = server.get("env", {})
    config_env = config_env if isinstance(config_env, dict) else {}
    allowed_env = set(allow_env_keys or [])
    blocked_env = sorted(str(key) for key in config_env if str(key) not in allowed_env)
    if blocked_env:
        execution = _execution(
            status="blocked_env_not_allowlisted",
            server=selected_name,
            transport="stdio",
            launch=launch,
            finding_id="MCPG-LIVE-003",
            allowed_env_keys=sorted(allowed_env),
            blocked_env_keys=blocked_env,
            message="Configured environment keys are not allowlisted for live execution.",
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )

    try:
        live_tools = tool_lister(argv, _runtime_env(config_env, allowed_env), timeout)
    except McpStdioTimeout as error:
        execution = _execution(
            status="timeout",
            server=selected_name,
            transport="stdio",
            launch=launch,
            finding_id="MCPG-LIVE-004",
            allowed_env_keys=sorted(allowed_env),
            message=str(error),
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )
    except (McpStdioError, OSError) as error:
        execution = _execution(
            status="protocol_error",
            server=selected_name,
            transport="stdio",
            launch=launch,
            finding_id="MCPG-LIVE-004",
            allowed_env_keys=sorted(allowed_env),
            message=str(error),
        )
        return InspectionReport(
            target=target,
            server=selected_name,
            execution=execution,
            static_result=static_result,
        )

    live_result = _scan_live_tools(target, selected_name, live_tools, loaded_policy)
    execution = _execution(
        status="success",
        server=selected_name,
        transport="stdio",
        launch=launch,
        allowed_env_keys=sorted(allowed_env),
        message=f"Live inspection discovered {len(live_tools)} tools via tools/list.",
    )
    return InspectionReport(
        target=target,
        server=selected_name,
        execution=execution,
        live_tools=_live_tool_summaries(live_tools),
        static_result=static_result,
        live_result=live_result,
    )
