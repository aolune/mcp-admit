from __future__ import annotations

import json

from mcp_admit.models import InspectionReport
from mcp_admit.reports.markdown_report import render_markdown


def _property_text(properties: list[str]) -> str:
    return ", ".join(properties) if properties else "none"


def _additional_text(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def render_inspection_json(report: InspectionReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_inspection_markdown(report: InspectionReport) -> str:
    execution = report.execution
    lines = [
        "# MCP Admit Inspection",
        "",
        f"Target: {report.target}",
        f"Server: {report.server}",
        f"Execution: {execution.status}",
        f"Transport: {execution.transport}",
    ]
    if execution.launch:
        lines.append(f"Launch: {execution.launch}")
    if execution.finding_id:
        lines.append(f"Rule: {execution.finding_id}")
    if execution.allowed_env_keys:
        lines.append(f"Allowed env keys: {', '.join(execution.allowed_env_keys)}")
    if execution.blocked_env_keys:
        lines.append(f"Blocked env keys: {', '.join(execution.blocked_env_keys)}")
    lines.extend(["", execution.message, ""])
    if report.live_tools:
        lines.extend(
            [
                "## Live tool inventory",
                "",
                "| Tool | Description | Properties | Required | Additional properties |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for tool in report.live_tools:
            lines.append(
                "| {name} | {description} | {properties} | {required} | {additional} |".format(
                    name=tool.name,
                    description=tool.description or "",
                    properties=_property_text(tool.input_properties),
                    required=_property_text(tool.required),
                    additional=_additional_text(tool.allows_additional_properties),
                )
            )
        lines.append("")
    lines.extend(["## Static scan", "", render_markdown(report.static_result)])
    if report.live_result is not None:
        lines.extend(["", "## Live tools scan", "", render_markdown(report.live_result)])
    return "\n".join(lines)
