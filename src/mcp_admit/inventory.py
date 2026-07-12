from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from mcp_admit.approvals import (
    ApprovalError,
    decide_approval,
    load_approval_records,
    render_approval_registry,
)
from mcp_admit.discovery import (
    client_preset_paths,
    infer_client,
    summarize_server_entry,
)
from mcp_admit.hashing import server_definition_hash
from mcp_admit.models import ApprovalRecord, InventoryReport, InventoryServerReport
from mcp_admit.parsers import extract_mcp_server_entries, load_documents
from mcp_admit.parsers.config import ParseError
from mcp_admit.rules import scan_compositions, scan_registry_document, scan_server
from mcp_admit.standards import annotate_findings
from mcp_admit.summary import build_summary


def _target_paths(path: str | None, include_client_paths: bool, home: str | None) -> tuple[str, list[Path]]:
    targets: list[Path] = []
    if path:
        target_path = Path(path)
        if not target_path.exists():
            raise ParseError(f"Inventory path does not exist: {target_path}")
        targets.append(target_path)
    if include_client_paths:
        targets.extend(client_preset_paths(Path(home).expanduser() if home else Path.home()))
    target = path or ("client-presets" if include_client_paths else ".")
    return target, targets


def _documents(
    targets: list[Path],
    *,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
):
    seen = set()
    for target in targets:
        if not target.exists():
            continue
        for file, data in load_documents(
            target,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        ):
            resolved = file.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            yield file, data


def build_inventory_report(
    path: str | None = ".",
    *,
    include_client_paths: bool = False,
    home: str | None = None,
    approvals_path: str | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    today: date | None = None,
) -> InventoryReport:
    target, targets = _target_paths(path, include_client_paths, home)
    approval_records = load_approval_records(approvals_path)
    servers: list[InventoryServerReport] = []

    for file, data in _documents(
        targets,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    ):
        client = infer_client(file, data)
        registry_findings = scan_registry_document(data, str(file))
        for entry in extract_mcp_server_entries(data):
            discovered = summarize_server_entry(file, client, entry)
            server_location = f"{file}.{entry.location}"
            entry_registry_findings = [
                finding
                for finding in registry_findings
                if f".{entry.location}" in finding.location
                or ".server.json." in finding.location
            ]
            base_findings = [
                *entry_registry_findings,
                *scan_server(
                    entry.name,
                    entry.server,
                    str(file),
                    server_path=server_location,
                ),
            ]
            findings = annotate_findings(
                [
                    *base_findings,
                    *scan_compositions(base_findings, server_location),
                ]
            )
            capabilities = sorted({finding.capability for finding in findings if finding.capability != "unknown"})
            definition_hash = server_definition_hash(entry.server)
            approval = decide_approval(
                records=approval_records,
                client=discovered.client,
                source=discovered.source,
                name=discovered.name,
                definition_hash=definition_hash,
                capabilities=capabilities,
                today=today,
            )
            servers.append(
                InventoryServerReport(
                    server=discovered,
                    summary=build_summary(findings),
                    finding_ids=sorted({finding.id for finding in findings}),
                    capabilities=capabilities,
                    definition_hash=definition_hash,
                    approval=approval,
                )
            )

    servers.sort(key=lambda item: (item.server.client, item.server.source, item.server.name))
    return InventoryReport(
        target=target,
        total_servers=len(servers),
        clients=sorted({item.server.client for item in servers}),
        servers=servers,
    )


def render_inventory_json(report: InventoryReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_inventory_markdown(report: InventoryReport) -> str:
    lines = [
        "# MCP Admit Inventory",
        "",
        f"Target: {report.target}",
        f"Servers: {report.total_servers}",
        f"Clients: {', '.join(report.clients) if report.clients else 'none'}",
        "",
        "| Client | Source | Server | Transport | Gate | Risk | Findings | Approval |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not report.servers:
        lines.append("| n/a | n/a | n/a | n/a | pass | L0 | none | unknown |")
        return "\n".join(lines)

    for item in report.servers:
        finding_ids = ", ".join(item.finding_ids) if item.finding_ids else "none"
        lines.append(
            f"| {item.server.client} | {item.server.source} | {item.server.name} | "
            f"{item.server.transport} | {item.summary.gate_result} | "
            f"{item.summary.tool_risk_level} | {finding_ids} | {item.approval.status} |"
        )
    return "\n".join(lines)


def approval_records_from_inventory(
    report: InventoryReport,
) -> list[ApprovalRecord]:
    records = []
    for item in report.servers:
        records.append(
            ApprovalRecord(
                id=f"{item.server.client}.{item.server.name}",
                status="pending",
                client=item.server.client,
                source=item.server.source,
                name=item.server.name,
                definition_hash=item.definition_hash,
                approved_by="",
                reason="",
                expires="",
                allowed_capabilities=item.capabilities,
            )
        )
    return records


def render_inventory_approval_registry(report: InventoryReport) -> str:
    return render_approval_registry(approval_records_from_inventory(report))


def approved_record_from_inventory(
    report: InventoryReport,
    *,
    server_name: str,
    approved_by: str,
    reason: str,
    expires: str,
    today: date | None = None,
) -> ApprovalRecord:
    if not approved_by.strip():
        raise ApprovalError("--approved-by must be non-empty.")
    if not reason.strip():
        raise ApprovalError("--reason must be non-empty.")
    try:
        expiry = date.fromisoformat(expires)
    except ValueError as exc:
        raise ApprovalError("--expires must be an ISO date string.") from exc
    if expiry < (today or date.today()):
        raise ApprovalError("--expires cannot be in the past.")

    matches = [item for item in report.servers if item.server.name == server_name]
    if not matches:
        raise ApprovalError(f"Server not found in inventory: {server_name}.")
    if len(matches) > 1:
        raise ApprovalError(
            f"Server name is ambiguous: {server_name}. Narrow the input path to one config."
        )

    item = matches[0]
    return ApprovalRecord(
        id=f"{item.server.client}.{item.server.name}",
        status="approved",
        client=item.server.client,
        source=item.server.source,
        name=item.server.name,
        definition_hash=item.definition_hash,
        approved_by=approved_by.strip(),
        reason=reason.strip(),
        expires=expires,
        allowed_capabilities=item.capabilities,
    )


def select_inventory_server(
    report: InventoryReport,
    server_name: str | None = None,
) -> InventoryServerReport:
    matches = report.servers
    if server_name:
        matches = [item for item in matches if item.server.name == server_name]
    if not matches:
        label = server_name or report.target
        raise ApprovalError(f"Server not found in inventory: {label}.")
    if len(matches) > 1:
        raise ApprovalError("Multiple servers found; select one with --server.")
    return matches[0]
