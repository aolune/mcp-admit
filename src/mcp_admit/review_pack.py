from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_admit.admission import build_admission_input, render_admission_json
from mcp_admit.explainability import refresh_scan_explainability
from mcp_admit.inventory import (
    build_inventory_report,
    render_inventory_json,
    render_inventory_markdown,
)
from mcp_admit.models import ReviewPackReport
from mcp_admit.policy import apply_policy_with_effects
from mcp_admit.reports import render_json as render_scan_json
from mcp_admit.reports import render_markdown as render_scan_markdown
from mcp_admit.runtime_policy import (
    build_audit_report,
    build_runtime_policy,
    render_audit_markdown,
    render_runtime_policy_json,
)
from mcp_admit.scanner import scan_path
from mcp_admit.summary import build_summary


def _scan_with_policy(
    path: str,
    policy: dict[str, Any],
    *,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
):
    scan = scan_path(
        path,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )
    scan.findings, scan.policy_effects = apply_policy_with_effects(scan.findings, policy)
    scan.summary = build_summary(scan.findings)
    return refresh_scan_explainability(scan, policy)


def _write(output_dir: Path, name: str, content: str) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / name
    target.write_text(content, encoding="utf-8", newline="\n")
    return target.as_posix()


def _github_summary(report: ReviewPackReport) -> str:
    summary = report.scan_summary
    lines = [
        "# MCP Admit Review Pack",
        "",
        f"- Target: {report.target}",
        f"- Gate: {summary.gate_result}",
        f"- Risk: {summary.tool_risk_level} ({summary.risk_score}/100)",
        f"- Inventory servers: {report.inventory.total_servers}",
        "",
        "## Generated files",
        "",
    ]
    lines.extend(f"- `{path}`" for path in report.files)
    return "\n".join(lines)


def build_review_pack(
    *,
    path: str,
    output_dir: str,
    policy: dict[str, Any],
    approvals_path: str | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    include_client_paths: bool = False,
    home: str | None = None,
    service: str = "unknown",
    owner: str = "unknown",
    environment: str = "unknown",
    request_id: str = "",
    github_step_summary: bool = False,
) -> ReviewPackReport:
    out = Path(output_dir)
    scan = _scan_with_policy(
        path,
        policy,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )
    inventory = build_inventory_report(
        path,
        include_client_paths=include_client_paths,
        home=home,
        approvals_path=approvals_path,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )
    runtime_policy = build_runtime_policy(scan)
    audit = build_audit_report(scan)
    approval = inventory.servers[0].approval if inventory.total_servers == 1 else None
    server = inventory.servers[0].server.name if inventory.total_servers == 1 else ""
    admission = build_admission_input(
        scan,
        approval=approval,
        server=server,
        service=service,
        owner=owner,
        environment=environment,
        request_id=request_id,
    )

    files = [
        _write(out, "scan.json", render_scan_json(scan)),
        _write(out, "scan.md", render_scan_markdown(scan)),
        _write(out, "inventory.json", render_inventory_json(inventory)),
        _write(out, "inventory.md", render_inventory_markdown(inventory)),
        _write(out, "runtime-policy.json", render_runtime_policy_json(runtime_policy)),
        _write(out, "audit.md", render_audit_markdown(audit)),
        _write(out, "admission.json", render_admission_json(admission)),
    ]
    report = ReviewPackReport(
        target=path,
        output_dir=str(out),
        files=files,
        inventory=inventory,
        scan_summary=scan.summary,
    )
    if github_step_summary:
        report.files.append(_write(out, "github-step-summary.md", _github_summary(report)))
    return report


def render_review_pack_json(report: ReviewPackReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_review_pack_markdown(report: ReviewPackReport) -> str:
    lines = [
        "# MCP Admit Review Pack",
        "",
        f"Target: {report.target}",
        f"Output directory: {report.output_dir}",
        f"Gate: {report.scan_summary.gate_result.upper()}",
        f"Risk: {report.scan_summary.tool_risk_level} ({report.scan_summary.risk_score} / 100)",
        f"Inventory servers: {report.inventory.total_servers}",
        "",
        "## Files",
        "",
    ]
    lines.extend(f"- `{path}`" for path in report.files)
    return "\n".join(lines)
