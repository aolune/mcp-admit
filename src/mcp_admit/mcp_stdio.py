from __future__ import annotations

import json
import os
import queue
import selectors
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any

from mcp_admit import __version__
from mcp_admit.models import ToolDefinition

MCP_PROTOCOL_VERSION = "2025-06-18"


class McpStdioError(RuntimeError):
    pass


class McpStdioTimeout(McpStdioError):
    pass


class McpStdioProtocolError(McpStdioError):
    pass


def _deadline(timeout: float) -> float:
    return time.monotonic() + timeout


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _write_message(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise McpStdioProtocolError("MCP server stdin is unavailable.")
    proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _readline(proc: subprocess.Popen[str], deadline: float) -> str:
    if proc.stdout is None:
        raise McpStdioProtocolError("MCP server stdout is unavailable.")
    if os.name == "nt":
        return _readline_windows(proc, deadline)

    selector = selectors.DefaultSelector()
    try:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            timeout = _remaining(deadline)
            if timeout <= 0:
                raise McpStdioTimeout("Timed out waiting for MCP server response.")
            events = selector.select(timeout)
            if not events:
                raise McpStdioTimeout("Timed out waiting for MCP server response.")
            line = proc.stdout.readline()
            if line == "":
                raise McpStdioProtocolError("MCP server closed stdout before responding.")
            return line
    finally:
        selector.close()


def _readline_windows(proc: subprocess.Popen[str], deadline: float) -> str:
    if proc.stdout is None:
        raise McpStdioProtocolError("MCP server stdout is unavailable.")
    result: queue.Queue[tuple[str, BaseException | None]] = queue.Queue(maxsize=1)

    def read() -> None:
        try:
            result.put((proc.stdout.readline(), None))
        except BaseException as exc:  # pragma: no cover - defensive pipe error path
            result.put(("", exc))

    threading.Thread(target=read, daemon=True).start()
    timeout = _remaining(deadline)
    if timeout <= 0:
        raise McpStdioTimeout("Timed out waiting for MCP server response.")
    try:
        line, error = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise McpStdioTimeout("Timed out waiting for MCP server response.") from exc
    if error is not None:
        raise McpStdioProtocolError(f"Failed reading MCP server stdout: {error}") from error
    if line == "":
        raise McpStdioProtocolError("MCP server closed stdout before responding.")
    return line


def _read_response(proc: subprocess.Popen[str], request_id: int, deadline: float) -> dict[str, Any]:
    while True:
        line = _readline(proc, deadline).strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise McpStdioProtocolError(f"Invalid JSON-RPC response: {exc}") from exc
        if not isinstance(message, dict) or message.get("id") != request_id:
            continue
        if "error" in message:
            error = message["error"]
            if isinstance(error, dict):
                detail = str(error.get("message", error))
            else:
                detail = str(error)
            raise McpStdioProtocolError(f"MCP server returned error: {detail}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise McpStdioProtocolError("MCP server response did not include an object result.")
        return result


def _shutdown(proc: subprocess.Popen[str], timeout: float) -> None:
    if proc.stdin is not None and not proc.stdin.closed:
        proc.stdin.close()
    try:
        proc.wait(timeout=max(0.1, timeout / 2))
        return
    except subprocess.TimeoutExpired:
        proc.terminate()
    try:
        proc.wait(timeout=max(0.1, timeout / 2))
        return
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=max(0.1, timeout / 2))


def _tool_from_payload(payload: dict[str, Any]) -> ToolDefinition | None:
    name = payload.get("name")
    if not name:
        return None
    schema = payload.get("inputSchema", {})
    if not isinstance(schema, dict):
        schema = {}
    return ToolDefinition(
        name=str(name),
        description=str(payload.get("description", "")),
        inputSchema=schema,
    )


def _list_tools(proc: subprocess.Popen[str], timeout: float, next_id: int) -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    cursor: str | None = None
    while True:
        request_id = next_id
        next_id += 1
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        _write_message(
            proc,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": params,
            },
        )
        result = _read_response(proc, request_id, _deadline(timeout))
        raw_tools = result.get("tools", [])
        if not isinstance(raw_tools, list):
            raise McpStdioProtocolError("tools/list result did not include a tools list.")
        for item in raw_tools:
            if isinstance(item, dict):
                tool = _tool_from_payload(item)
                if tool is not None:
                    tools.append(tool)
        next_cursor = result.get("nextCursor")
        if not next_cursor:
            return tools
        cursor = str(next_cursor)


def list_tools_from_stdio(
    argv: list[str],
    env: dict[str, str],
    timeout: float = 5.0,
    popen_factory: Callable[..., subprocess.Popen[str]] | None = None,
) -> list[ToolDefinition]:
    popen = popen_factory or subprocess.Popen
    proc = popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
        shell=False,
        env=env,
    )
    try:
        _write_message(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-admit", "version": __version__},
                },
            },
        )
        init_result = _read_response(proc, 1, _deadline(timeout))
        capabilities = init_result.get("capabilities", {})
        if not isinstance(capabilities, dict) or "tools" not in capabilities:
            raise McpStdioProtocolError("MCP server did not declare tools capability.")
        _write_message(
            proc,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        return _list_tools(proc, timeout, 2)
    finally:
        _shutdown(proc, timeout)
