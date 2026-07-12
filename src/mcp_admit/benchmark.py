from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from mcp_admit.diff import diff_tools
from mcp_admit.models import ScanResult
from mcp_admit.scanner import scan_path
from mcp_admit.summary import build_summary


def _load_matrix(path: str) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("fixtures"), list):
        raise ValueError("fixture matrix must contain a fixtures list")
    return data


def _result_for_fixture(fixture: dict[str, Any]) -> ScanResult:
    target = str(fixture["target"])
    baseline = fixture.get("baseline")
    if baseline:
        findings = diff_tools(str(baseline), target)
        return ScanResult(
            target=f"{baseline} -> {target}",
            findings=findings,
            summary=build_summary(findings),
        )
    return scan_path(target)


def _check_fixture(name: str, result: ScanResult, expect: dict[str, Any]) -> list[str]:
    failures = []
    summary = result.summary
    expected_gate = expect.get("gate")
    if expected_gate and summary.gate_result != expected_gate:
        failures.append(f"expected gate {expected_gate}, got {summary.gate_result}")

    expected_risk = expect.get("risk_level")
    if expected_risk and summary.tool_risk_level != expected_risk:
        failures.append(f"expected risk level {expected_risk}, got {summary.tool_risk_level}")

    expected_severity = expect.get("max_severity")
    if expected_severity and summary.max_severity != expected_severity:
        failures.append(f"expected max severity {expected_severity}, got {summary.max_severity}")

    ids = {finding.id for finding in result.findings}
    for finding_id in expect.get("contains_findings", []):
        if finding_id not in ids:
            failures.append(f"missing finding {finding_id}")

    unexpected = expect.get("not_contains_findings", [])
    for finding_id in unexpected:
        if finding_id in ids:
            failures.append(f"unexpected finding {finding_id}")

    return [f"{name}: {failure}" for failure in failures]


def run_benchmark(matrix_path: str) -> dict[str, Any]:
    matrix = _load_matrix(matrix_path)
    rows = []
    for fixture in matrix["fixtures"]:
        name = str(fixture.get("name", fixture.get("target", "unnamed")))
        result = _result_for_fixture(fixture)
        failures = _check_fixture(name, result, fixture.get("expect", {}))
        rows.append(
            {
                "name": name,
                "target": result.target,
                "passed": not failures,
                "failures": failures,
                "gate": result.summary.gate_result,
                "risk_level": result.summary.tool_risk_level,
                "max_severity": result.summary.max_severity,
                "risk_score": result.summary.risk_score,
                "finding_ids": sorted({finding.id for finding in result.findings}),
            }
        )

    passed = sum(1 for row in rows if row["passed"])
    failed = len(rows) - passed
    return {
        "matrix": matrix_path,
        "total": len(rows),
        "passed": passed,
        "failed": failed,
        "fixtures": rows,
    }


def render_benchmark_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)


def render_benchmark_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# MCP Admit Fixture Benchmark",
        "",
        f"Matrix: {report['matrix']}",
        f"Total: {report['total']}",
        f"Passed: {report['passed']}",
        f"Failed: {report['failed']}",
        "",
        "| Fixture | Result | Gate | Risk | Severity | Findings |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["fixtures"]:
        result = "PASS" if row["passed"] else "FAIL"
        findings = ", ".join(row["finding_ids"]) if row["finding_ids"] else "-"
        lines.append(
            f"| {row['name']} | {result} | {row['gate']} | {row['risk_level']} | "
            f"{row['max_severity']} | {findings} |"
        )
        for failure in row["failures"]:
            lines.append(f"| {row['name']} detail | {failure} | | | | |")
    return "\n".join(lines)
