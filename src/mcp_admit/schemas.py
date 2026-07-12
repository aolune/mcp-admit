from __future__ import annotations

import json
from typing import TypeAlias

from pydantic import BaseModel

from mcp_admit.models import (
    AdmissionInputReport,
    AuditReport,
    InventoryReport,
    ReleaseCheckReport,
    RuntimePolicyReport,
    ScanResult,
)

SchemaModel: TypeAlias = type[BaseModel]

SCHEMA_MODELS: dict[str, SchemaModel] = {
    "admission": AdmissionInputReport,
    "audit": AuditReport,
    "inventory": InventoryReport,
    "release-check": ReleaseCheckReport,
    "report": ScanResult,
    "runtime-policy": RuntimePolicyReport,
}

SCHEMA_TITLES = {
    "admission": "MCP Admit Admission Input",
    "audit": "MCP Admit Audit Report",
    "inventory": "MCP Admit Inventory Report",
    "release-check": "MCP Admit Release Check",
    "report": "MCP Admit Scan Report",
    "runtime-policy": "MCP Admit Runtime Policy",
}


def schema_names() -> list[str]:
    return sorted(SCHEMA_MODELS)


def build_json_schema(name: str) -> dict:
    model = SCHEMA_MODELS[name]
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://github.com/aolune/mcp-admit/schemas/{name}.schema.json"
    schema["title"] = SCHEMA_TITLES[name]
    return schema


def render_schema_json(name: str) -> str:
    return json.dumps(build_json_schema(name), indent=2, sort_keys=True)
