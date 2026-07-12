from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class McpServerEntry:
    name: str
    server: dict[str, Any]
    location: str


DEFAULT_EXCLUDE_PATTERNS = (
    ".git/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    ".mcp-admit/**",
    "mcp-admit-review-pack/**",
    "__pycache__/**",
    "**/__pycache__/**",
)
DEFAULT_EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".mcp-admit",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "mcp-admit-review-pack",
    "node_modules",
    "venv",
}


def _normalize_pattern(pattern: str) -> str:
    normalized = pattern.replace("\\", "/").removeprefix("./")
    if normalized.endswith("/"):
        return f"{normalized}**"
    return normalized


def _matches_any(relative_path: str, patterns: list[str] | tuple[str, ...]) -> bool:
    return any(fnmatchcase(relative_path, _normalize_pattern(pattern)) for pattern in patterns)


def _uses_default_excluded_directory(relative_path: str) -> bool:
    directory_parts = relative_path.split("/")[:-1]
    return any(part in DEFAULT_EXCLUDED_DIRECTORY_NAMES for part in directory_parts)


def load_documents(
    path: Path,
    *,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[tuple[Path, dict[str, Any]]]:
    if not path.exists():
        raise ParseError(f"Scan path does not exist: {path}")

    if path.is_file():
        files = [path]
        root = path.parent
        default_excludes: tuple[str, ...] = ()
        use_default_excluded_directories = False
    else:
        root = path
        default_excludes = DEFAULT_EXCLUDE_PATTERNS
        use_default_excluded_directories = True
        files = [
            p
            for p in path.rglob("*")
            if p.suffix.lower() in {".json", ".yaml", ".yml"} or p.name.lower() == "readme.md"
        ]
    docs = []
    includes = include_patterns or []
    excludes = [*default_excludes, *(exclude_patterns or [])]
    for file in sorted(files):
        relative_path = file.relative_to(root).as_posix()
        if use_default_excluded_directories and _uses_default_excluded_directory(
            relative_path
        ):
            continue
        if includes and not _matches_any(relative_path, includes):
            continue
        if excludes and _matches_any(relative_path, excludes):
            continue
        text = file.read_text(encoding="utf-8")
        if file.suffix.lower() == ".md":
            data = {
                "tools": [
                    {
                        "name": file.stem,
                        "description": text,
                        "inputSchema": {},
                        "source_type": "markdown",
                    }
                ]
            }
        else:
            try:
                data = json.loads(text) if file.suffix.lower() == ".json" else yaml.safe_load(text)
            except (json.JSONDecodeError, yaml.YAMLError) as exc:
                raise ParseError(f"Failed to parse {file}: {exc}") from exc
        if isinstance(data, dict):
            docs.append((file, data))
    return docs


def _path_join(path: str, key: object) -> str:
    value = str(key)
    return f"{path}.{value}" if path else value


def _looks_like_server(value: object) -> bool:
    return isinstance(value, dict) and bool(
        {"command", "args", "env", "transport", "url"} & set(value.keys())
    )


def _is_mcp_server_collection(key: str, value: object, path: str) -> bool:
    if not isinstance(value, dict):
        return False
    if key in {"mcpServers", "mcp_servers"}:
        return True
    if key != "servers":
        return False
    parent = path.rsplit(".", 1)[0] if "." in path else ""
    return path.startswith("mcp.") or parent.endswith("mcp") or any(
        _looks_like_server(server) for server in value.values()
    )


def _server_entries_from_collection(path: str, value: dict[str, Any]) -> list[McpServerEntry]:
    entries = []
    for name, server in value.items():
        if _looks_like_server(server):
            entries.append(
                McpServerEntry(
                    name=str(name),
                    server=server,
                    location=_path_join(path, name),
                )
            )
    return entries


def _walk_server_entries(value: object, path: str = "") -> list[McpServerEntry]:
    entries: list[McpServerEntry] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = _path_join(path, key)
            if _is_mcp_server_collection(str(key), child, child_path):
                entries.extend(_server_entries_from_collection(child_path, child))
            entries.extend(_walk_server_entries(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            entries.extend(_walk_server_entries(child, f"{path}[{index}]"))
    return entries


def _registry_document(data: dict[str, Any]) -> dict[str, Any] | None:
    candidate = data.get("server") if isinstance(data.get("server"), dict) else data
    if not isinstance(candidate, dict) or not isinstance(candidate.get("name"), str):
        return None
    if not isinstance(candidate.get("packages"), list) and not isinstance(
        candidate.get("remotes"), list
    ):
        return None
    return candidate


def _registry_entry_name(base_name: str, label: str, total: int) -> str:
    return base_name if total == 1 else f"{base_name}:{label}"


def extract_registry_server_entries(data: dict[str, Any]) -> list[McpServerEntry]:
    document = _registry_document(data)
    if document is None:
        return []

    packages = document.get("packages", [])
    packages = packages if isinstance(packages, list) else []
    remotes = document.get("remotes", [])
    remotes = remotes if isinstance(remotes, list) else []
    total = sum(isinstance(item, dict) for item in [*packages, *remotes])
    base_name = str(document["name"])
    entries: list[McpServerEntry] = []

    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            continue
        identifier = str(package.get("identifier", f"package-{index}"))
        transport = package.get("transport", {})
        transport_type = transport.get("type", "") if isinstance(transport, dict) else ""
        normalized = {
            "transport": str(transport_type),
            "registryType": str(
                package.get("registryType", document.get("registryType", ""))
            ),
            "identifier": identifier,
            "version": str(package.get("version", "")),
            "fileSha256": str(package.get("fileSha256", "")),
            "environmentVariables": package.get("environmentVariables", []),
            "packageArguments": package.get("packageArguments", []),
            "runtimeArguments": package.get("runtimeArguments", []),
        }
        entries.append(
            McpServerEntry(
                name=_registry_entry_name(base_name, identifier, total),
                server=normalized,
                location=f"packages[{index}]",
            )
        )

    for index, remote in enumerate(remotes):
        if not isinstance(remote, dict):
            continue
        url = str(remote.get("url", ""))
        entries.append(
            McpServerEntry(
                name=_registry_entry_name(base_name, url or f"remote-{index}", total),
                server={
                    "transport": str(remote.get("type", "")),
                    "url": url,
                },
                location=f"remotes[{index}]",
            )
        )
    return entries


def is_registry_server_document(data: dict[str, Any]) -> bool:
    return _registry_document(data) is not None


def extract_mcp_server_entries(data: dict[str, Any]) -> list[McpServerEntry]:
    return [*_walk_server_entries(data), *extract_registry_server_entries(data)]


def extract_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry.name: entry.server for entry in extract_mcp_server_entries(data)}
