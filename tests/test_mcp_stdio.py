from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent

from mcp_admit.mcp_stdio import list_tools_from_stdio


def _write_server(tmp_path: Path, source: str) -> Path:
    server = tmp_path / "fake_mcp_server.py"
    server.write_text(dedent(source), encoding="utf-8")
    return server


def test_stdio_client_lists_tools_from_fake_server(tmp_path):
    # This is a local test-only server, not a command read from a scanned MCP config.
    server = _write_server(
        tmp_path,
        r'''
        import json
        import sys

        for line in sys.stdin:
            message = json.loads(line)
            method = message.get("method")
            if method == "initialize":
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake", "version": "1.0"},
                    },
                }), flush=True)
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "tools": [{
                            "name": "read_docs",
                            "description": "Read approved docs.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"id": {"type": "string"}},
                                "additionalProperties": False,
                            },
                        }]
                    },
                }), flush=True)
        ''',
    )

    tools = list_tools_from_stdio([sys.executable, str(server)], {}, timeout=2.0)

    assert len(tools) == 1
    assert tools[0].name == "read_docs"
    assert tools[0].description == "Read approved docs."
    assert tools[0].inputSchema["additionalProperties"] is False


def test_stdio_client_follows_tools_list_pagination(tmp_path):
    server = _write_server(
        tmp_path,
        r'''
        import json
        import sys

        for line in sys.stdin:
            message = json.loads(line)
            method = message.get("method")
            if method == "initialize":
                print(json.dumps({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake", "version": "1.0"},
                    },
                }), flush=True)
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                cursor = message.get("params", {}).get("cursor")
                if cursor:
                    result = {"tools": [{"name": "second", "description": "", "inputSchema": {}}]}
                else:
                    result = {
                        "tools": [{"name": "first", "description": "", "inputSchema": {}}],
                        "nextCursor": "page-2",
                    }
                print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
        ''',
    )

    tools = list_tools_from_stdio([sys.executable, str(server)], {}, timeout=2.0)

    assert [tool.name for tool in tools] == ["first", "second"]
