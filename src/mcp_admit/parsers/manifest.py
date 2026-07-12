from __future__ import annotations

from typing import Any

from mcp_admit.models import ToolDefinition


def extract_tools(data: dict[str, Any]) -> list[ToolDefinition]:
    raw = data.get("tools")
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            schema = item.get("inputSchema", item.get("input_schema", {})) or {}
            source_type = str(item.get("source_type", "manifest"))
            if source_type not in {"manifest", "markdown"}:
                source_type = "manifest"
            out.append(
                ToolDefinition(
                    name=str(item["name"]),
                    description=str(item.get("description", "")),
                    inputSchema=schema,
                    source_type=source_type,
                )
            )
    return out
