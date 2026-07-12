from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mcp_admit.parsers import extract_mcp_server_entries, extract_tools, load_documents
from mcp_admit.risk import max_risk, max_risk_score
from mcp_admit.rules import scan_tool
from mcp_admit.standards import annotate_findings

BASELINE_KIND = "mcp-admit-baseline"
BASELINE_VERSION = 1


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_value(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode()).hexdigest()


def server_env_keys(server: dict[str, Any]) -> list[str]:
    env = server.get("env", {})
    return sorted(str(key) for key in env) if isinstance(env, dict) else []


def server_definition_hash(server: dict[str, Any]) -> str:
    env_keys = server_env_keys(server)
    return _hash_value(
        {
            "command": server.get("command", ""),
            "args": server.get("args", []),
            "env_keys": env_keys,
            "transport": server.get("transport", ""),
            "url": server.get("url", ""),
            "registry_type": server.get("registryType", ""),
            "identifier": server.get("identifier", ""),
            "version": server.get("version", ""),
            "file_sha256": server.get("fileSha256", ""),
            "environment_variables": server.get("environmentVariables", []),
            "package_arguments": server.get("packageArguments", []),
            "runtime_arguments": server.get("runtimeArguments", []),
        }
    )


def canonical_hash(path: str) -> str:
    docs = [d for _, d in load_documents(Path(path))]
    return _hash_value(docs)


def build_baseline(path: str) -> dict[str, Any]:
    baseline_path = Path(path)
    servers = []
    tools = []
    docs = []
    for file, data in load_documents(baseline_path):
        docs.append(data)
        for entry in extract_mcp_server_entries(data):
            name = entry.name
            server = entry.server
            env_keys = server_env_keys(server)
            servers.append(
                {
                    "name": name,
                    "source": str(file),
                    "location": entry.location,
                    "command_hash": _hash_value(server.get("command", "")),
                    "args_hash": _hash_value(server.get("args", [])),
                    "env_keys": env_keys,
                    "env_keys_hash": _hash_value(env_keys),
                    "url_hash": _hash_value(server.get("url", "")),
                    "definition_hash": server_definition_hash(server),
                }
            )
        for tool in extract_tools(data):
            findings = annotate_findings(scan_tool(tool, str(file)))
            tools.append(
                {
                    "name": tool.name,
                    "source": str(file),
                    "description_hash": _hash_value(tool.description),
                    "schema_hash": _hash_value(tool.inputSchema),
                    "definition_hash": _hash_value(tool.model_dump()),
                    "capabilities": sorted(
                        {finding.capability for finding in findings if finding.capability != "unknown"}
                    ),
                    "risk_level": max_risk(findings),
                    "risk_score": max_risk_score(findings),
                    "finding_ids": sorted({finding.id for finding in findings}),
                }
            )

    return {
        "kind": BASELINE_KIND,
        "version": BASELINE_VERSION,
        "target": path,
        "documents_hash": _hash_value(docs),
        "servers": sorted(servers, key=lambda item: (item["source"], item["name"])),
        "tools": sorted(tools, key=lambda item: (item["source"], item["name"])),
    }


def render_baseline(path: str) -> str:
    return json.dumps(build_baseline(path), indent=2)


def is_baseline_document(data: dict[str, Any]) -> bool:
    return data.get("kind") == BASELINE_KIND and data.get("version") == BASELINE_VERSION
