from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_admit.models import DiscoveredServer, DiscoveryReport
from mcp_admit.parsers import extract_mcp_server_entries, load_documents
from mcp_admit.parsers.config import ParseError
from mcp_admit.redaction import redact_text


@dataclass(frozen=True)
class ClientPreset:
    client: str
    relative_paths: tuple[str, ...]


CLIENT_PRESETS: tuple[ClientPreset, ...] = (
    ClientPreset(
        "claude-desktop",
        (
            "Library/Application Support/Claude/claude_desktop_config.json",
            ".config/Claude/claude_desktop_config.json",
            "AppData/Roaming/Claude/claude_desktop_config.json",
        ),
    ),
    ClientPreset(
        "cursor",
        (
            ".cursor/mcp.json",
            ".cursor/settings.json",
            "Library/Application Support/Cursor/User/mcp.json",
            "AppData/Roaming/Cursor/User/mcp.json",
        ),
    ),
    ClientPreset(
        "vscode",
        (
            ".vscode/mcp.json",
            ".vscode/settings.json",
            "Library/Application Support/Code/User/mcp.json",
            "Library/Application Support/Code/User/settings.json",
            ".config/Code/User/mcp.json",
            ".config/Code/User/settings.json",
            "AppData/Roaming/Code/User/mcp.json",
            "AppData/Roaming/Code/User/settings.json",
        ),
    ),
    ClientPreset(
        "windsurf",
        (
            ".codeium/windsurf/mcp_config.json",
            ".windsurf/mcp.json",
            "Library/Application Support/Windsurf/User/mcp.json",
            "AppData/Roaming/Windsurf/User/mcp.json",
            ".config/Windsurf/User/mcp.json",
        ),
    ),
)


def client_preset_paths(home: Path) -> list[Path]:
    paths = []
    for preset in CLIENT_PRESETS:
        paths.extend(home / relative for relative in preset.relative_paths)
    return paths


def _path_parts_lower(path: Path) -> set[str]:
    return {part.lower() for part in path.parts}


def infer_client(path: Path, data: dict[str, Any]) -> str:
    parts = _path_parts_lower(path)
    name = path.name.lower()
    registry_document = data.get("server") if isinstance(data.get("server"), dict) else data
    if isinstance(registry_document, dict) and (
        isinstance(registry_document.get("packages"), list)
        or isinstance(registry_document.get("remotes"), list)
    ):
        return "mcp-registry"
    if name == "claude_desktop_config.json" or "claude" in parts:
        return "claude-desktop"
    if ".cursor" in parts or "cursor" in parts:
        return "cursor"
    if ".vscode" in parts or "code" in parts or "code - insiders" in parts:
        return "vscode"
    if "windsurf" in parts or {"codeium", "windsurf"} <= parts:
        return "windsurf"
    if name in {".mcp.json", "mcp.json", "mcp.config.json"} or ".mcp" in parts:
        return "project"
    if "mcpServers" in data or "mcp_servers" in data:
        return "generic"
    return "generic"


def _transport(server: dict[str, Any]) -> str:
    raw = server.get("transport")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    if server.get("url"):
        return "http"
    if server.get("command"):
        return "stdio"
    return "unknown"


def _env_keys(server: dict[str, Any]) -> list[str]:
    env = server.get("env", {})
    if not isinstance(env, dict):
        return []
    return sorted(str(key) for key in env)


def summarize_server_entry(path: Path, client: str, entry) -> DiscoveredServer:
    server = entry.server
    command = server.get("command", "")
    url = server.get("url", "")
    identifier = str(server.get("identifier", ""))
    version = str(server.get("version", ""))
    package = f"{identifier}@{version}" if identifier and version else identifier
    return DiscoveredServer(
        client=client,
        source=str(path),
        name=entry.name,
        location=entry.location,
        transport=_transport(server),
        command=redact_text(str(command)) if command else "",
        url=redact_text(str(url)) if url else "",
        package=redact_text(package) if package else "",
        env_keys=_env_keys(server),
    )


def _load_unique_documents(targets: Iterable[Path]) -> list[tuple[Path, dict[str, Any]]]:
    docs = []
    seen = set()
    for target in targets:
        if not target.exists():
            continue
        for file, data in load_documents(target):
            resolved = file.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            docs.append((file, data))
    return docs


def discover_servers(
    path: str | None = ".",
    include_client_paths: bool = False,
    home: str | None = None,
) -> DiscoveryReport:
    targets: list[Path] = []
    if path:
        target_path = Path(path)
        if not target_path.exists():
            raise ParseError(f"Discovery path does not exist: {target_path}")
        targets.append(target_path)
    if include_client_paths:
        targets.extend(client_preset_paths(Path(home).expanduser() if home else Path.home()))

    servers: list[DiscoveredServer] = []
    for file, data in _load_unique_documents(targets):
        client = infer_client(file, data)
        for entry in extract_mcp_server_entries(data):
            servers.append(summarize_server_entry(file, client, entry))

    servers.sort(key=lambda item: (item.client, item.source, item.name, item.location))
    clients = sorted({server.client for server in servers})
    target = path or ("client-presets" if include_client_paths else ".")
    return DiscoveryReport(
        target=target,
        total_servers=len(servers),
        clients=clients,
        servers=servers,
    )


def render_discovery_json(report: DiscoveryReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_discovery_markdown(report: DiscoveryReport) -> str:
    lines = [
        "# MCP Admit Discovery",
        "",
        f"Target: {report.target}",
        f"Servers: {report.total_servers}",
        f"Clients: {', '.join(report.clients) if report.clients else 'none'}",
        "",
        "## Servers",
        "",
    ]
    if not report.servers:
        lines.append("No MCP server entries discovered.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Client | Source | Name | Transport | Package | Env keys | Location |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for server in report.servers:
        env_keys = ", ".join(server.env_keys) if server.env_keys else "none"
        lines.append(
            f"| {server.client} | {server.source} | {server.name} | "
            f"{server.transport} | {server.package or 'n/a'} | {env_keys} | "
            f"{server.location} |"
        )
    return "\n".join(lines)
