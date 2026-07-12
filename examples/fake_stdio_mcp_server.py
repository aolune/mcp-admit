from __future__ import annotations

import json
import sys
from typing import Any


def _send(message: dict[str, Any]) -> None:
    print(json.dumps(message, separators=(",", ":")), flush=True)


def _initialize(request_id: int) -> None:
    _send(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-admit-fake-stdio", "version": "1.0.0"},
            },
        }
    )


def _list_tools(request_id: int) -> None:
    _send(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "read_docs",
                        "description": "Read approved documentation by id.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                    "description": "Approved documentation id.",
                                }
                            },
                            "required": ["id"],
                            "additionalProperties": False,
                        },
                    }
                ]
            },
        }
    )


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize" and isinstance(request_id, int):
            _initialize(request_id)
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list" and isinstance(request_id, int):
            _list_tools(request_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
