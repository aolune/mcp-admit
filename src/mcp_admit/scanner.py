from __future__ import annotations

from pathlib import Path

from mcp_admit.explainability import refresh_scan_explainability
from mcp_admit.models import ScanResult
from mcp_admit.parsers import extract_mcp_server_entries, extract_tools, load_documents
from mcp_admit.parsers.config import ParseError
from mcp_admit.rules import (
    scan_compositions,
    scan_registry_document,
    scan_server,
    scan_tool,
)
from mcp_admit.standards import annotate_findings
from mcp_admit.summary import build_summary


def _result(target: str, findings: list) -> ScanResult:
    findings = [*findings, *scan_compositions(findings, target)]
    findings = annotate_findings(findings)
    result = ScanResult(target=target, findings=findings, summary=build_summary(findings))
    return refresh_scan_explainability(result)


def scan_path(
    target: str,
    *,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> ScanResult:
    findings = []
    for file, data in load_documents(
        Path(target),
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    ):
        findings.extend(scan_registry_document(data, str(file)))
        for entry in extract_mcp_server_entries(data):
            findings.extend(
                scan_server(
                    entry.name,
                    entry.server,
                    str(file),
                    server_path=f"{file}.{entry.location}",
                )
            )
        for tool in extract_tools(data):
            findings.extend(scan_tool(tool, str(file)))
    return _result(target, findings)


def scan_server_path(target: str, server_name: str) -> ScanResult:
    matches = []
    for file, data in load_documents(Path(target)):
        for entry in extract_mcp_server_entries(data):
            if entry.name == server_name:
                matches.append((file, entry))

    if not matches:
        raise ParseError(f"MCP server not found: {server_name}.")
    if len(matches) > 1:
        raise ParseError(
            f"MCP server name is ambiguous: {server_name}. Narrow the input path to one config."
        )

    file, entry = matches[0]
    findings = scan_server(
        entry.name,
        entry.server,
        str(file),
        server_path=f"{file}.{entry.location}",
    )
    return _result(target, findings)
