from __future__ import annotations

from pathlib import Path

import typer

from mcp_admit import __version__
from mcp_admit.admission import (
    build_admission_input,
    render_admission_json,
    render_admission_markdown,
)
from mcp_admit.approvals import (
    ApprovalError,
    load_approval_records,
    render_approval_registry,
    upsert_approval_record,
)
from mcp_admit.benchmark import (
    render_benchmark_json,
    render_benchmark_markdown,
    run_benchmark,
)
from mcp_admit.diff import diff_tools
from mcp_admit.discovery import discover_servers, render_discovery_json, render_discovery_markdown
from mcp_admit.explainability import refresh_scan_explainability
from mcp_admit.hashing import canonical_hash, render_baseline
from mcp_admit.inspection import InspectionError, inspect_path
from mcp_admit.inventory import (
    approved_record_from_inventory,
    build_inventory_report,
    render_inventory_approval_registry,
    render_inventory_json,
    render_inventory_markdown,
    select_inventory_server,
)
from mcp_admit.models import ScanResult
from mcp_admit.policy import (
    PolicyError,
    apply_policy_with_effects,
    load_policy,
    policy_fail_on,
    render_default_policy,
    should_fail,
)
from mcp_admit.reports import (
    render_inspection_json,
    render_inspection_markdown,
    render_json,
    render_markdown,
    render_sarif,
)
from mcp_admit.release_check import (
    build_release_check_report,
    render_release_check_json,
    render_release_check_markdown,
)
from mcp_admit.review_pack import (
    build_review_pack,
    render_review_pack_json,
    render_review_pack_markdown,
)
from mcp_admit.runtime_policy import (
    build_audit_report,
    build_runtime_policy,
    render_audit_json,
    render_audit_markdown,
    render_runtime_policy_json,
    render_runtime_policy_markdown,
)
from mcp_admit.rules.catalog import all_rules, get_rule, render_rules_json, render_rules_markdown
from mcp_admit.scanner import scan_path, scan_server_path
from mcp_admit.schemas import render_schema_json, schema_names
from mcp_admit.summary import build_summary
from mcp_admit.parsers.config import ParseError

app = typer.Typer(
    help=(
        "MCP Admit: static-first, no-exec-by-default admission control "
        "for MCP servers and agent tools."
    )
)

REPORT_FORMATS = {"markdown", "json", "sarif"}
TEXT_FORMATS = {"markdown", "json"}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcp-admit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    pass


def _fail_unsupported_format(format: str, allowed: set[str]) -> None:
    supported = ", ".join(sorted(allowed))
    typer.echo(f"Unsupported format: {format}. Supported formats: {supported}", err=True)
    raise typer.Exit(2)


def _render_scan_result(result: ScanResult, format: str) -> str:
    if format not in REPORT_FORMATS:
        _fail_unsupported_format(format, REPORT_FORMATS)
    if format == "json":
        return render_json(result)
    if format == "sarif":
        return render_sarif(result)
    return render_markdown(result)


def _render_inspection_result(report, format: str) -> str:
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    if format == "json":
        return render_inspection_json(report)
    return render_inspection_markdown(report)


def _write_or_echo(rendered: str, out: str | None) -> None:
    if out:
        Path(out).write_text(rendered, encoding="utf-8", newline="\n")
    else:
        typer.echo(rendered)


def _fail_policy_error(error: PolicyError) -> None:
    typer.echo(f"Policy error: {error}", err=True)
    raise typer.Exit(2)


def _fail_inspection_error(error: InspectionError) -> None:
    typer.echo(f"Inspection error: {error}", err=True)
    raise typer.Exit(2)


def _fail_parse_error(error: ParseError) -> None:
    typer.echo(f"Parse error: {error}", err=True)
    raise typer.Exit(2)


def _fail_approval_error(error: ApprovalError) -> None:
    typer.echo(f"Approval error: {error}", err=True)
    raise typer.Exit(2)


def _fail_unknown_schema(name: str) -> None:
    supported = ", ".join(schema_names())
    typer.echo(f"Unknown schema: {name}. Supported schemas: {supported}", err=True)
    raise typer.Exit(2)


def _inspection_should_fail(report, fail_on: str | None) -> bool:
    if should_fail(report.static_result.summary.max_severity, fail_on):
        return True
    if report.live_result is not None:
        return should_fail(report.live_result.summary.max_severity, fail_on)
    return False


def _scan_with_policy(
    path: str,
    policy: dict,
    *,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    server_name: str | None = None,
) -> ScanResult:
    if server_name:
        result = scan_server_path(path, server_name)
    else:
        result = scan_path(
            path,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        )
    result.findings, result.policy_effects = apply_policy_with_effects(result.findings, policy)
    result.summary = build_summary(result.findings)
    return refresh_scan_explainability(result, policy)


@app.command()
def scan(
    path: str,
    format: str = typer.Option("markdown", "--format"),
    output_path: str | None = typer.Option(None, "--out"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
    profile: str | None = typer.Option(None, "--profile"),
    include: list[str] | None = typer.Option(None, "--include"),
    exclude: list[str] | None = typer.Option(None, "--exclude"),
):
    try:
        loaded_policy = load_policy(policy, profile=profile)
        effective_fail_on = policy_fail_on(fail_on, loaded_policy)
    except PolicyError as error:
        _fail_policy_error(error)

    try:
        result = _scan_with_policy(
            path,
            loaded_policy,
            include_patterns=include,
            exclude_patterns=exclude,
        )
    except PolicyError as error:
        _fail_policy_error(error)
    rendered = _render_scan_result(result, format)
    _write_or_echo(rendered, output_path)
    if should_fail(result.summary.max_severity, effective_fail_on):
        raise typer.Exit(1)


@app.command()
def discover(
    path: str | None = typer.Argument(None),
    format: str = typer.Option("markdown", "--format"),
    output_path: str | None = typer.Option(None, "--out"),
    client_paths: bool = typer.Option(False, "--client-paths"),
    home: str | None = typer.Option(None, "--home"),
    scan: bool = typer.Option(False, "--scan"),
):
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    target = path if path is not None else None if client_paths else "."
    try:
        if scan:
            inventory = build_inventory_report(target, include_client_paths=client_paths, home=home)
            rendered = render_inventory_json(inventory) if format == "json" else render_inventory_markdown(inventory)
            _write_or_echo(rendered, output_path)
            return
        report = discover_servers(target, include_client_paths=client_paths, home=home)
    except ParseError as error:
        _fail_parse_error(error)
    except ApprovalError as error:
        _fail_approval_error(error)
    rendered = render_discovery_json(report) if format == "json" else render_discovery_markdown(report)
    _write_or_echo(rendered, output_path)


def _inventory_should_fail(report, fail_on_unknown: bool, fail_on_drift: bool) -> bool:
    statuses = {item.approval.status for item in report.servers}
    if fail_on_unknown and statuses & {"unknown", "pending"}:
        return True
    return fail_on_drift and bool(statuses & {"drifted", "expired"})


@app.command()
def inventory(
    path: str | None = typer.Argument(None),
    format: str = typer.Option("markdown", "--format"),
    output_path: str | None = typer.Option(None, "--out"),
    client_paths: bool = typer.Option(False, "--client-paths"),
    home: str | None = typer.Option(None, "--home"),
    approvals: str | None = typer.Option(None, "--approvals"),
    fail_on_unknown: bool = typer.Option(False, "--fail-on-unknown"),
    fail_on_drift: bool = typer.Option(False, "--fail-on-drift"),
    include: list[str] | None = typer.Option(None, "--include"),
    exclude: list[str] | None = typer.Option(None, "--exclude"),
):
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    target = path if path is not None else None if client_paths else "."
    try:
        report = build_inventory_report(
            target,
            include_client_paths=client_paths,
            home=home,
            approvals_path=approvals,
            include_patterns=include,
            exclude_patterns=exclude,
        )
    except ParseError as error:
        _fail_parse_error(error)
    except ApprovalError as error:
        _fail_approval_error(error)
    rendered = render_inventory_json(report) if format == "json" else render_inventory_markdown(report)
    _write_or_echo(rendered, output_path)
    if _inventory_should_fail(report, fail_on_unknown, fail_on_drift):
        raise typer.Exit(1)


@app.command("init-approvals")
def init_approvals(
    path: str | None = typer.Argument(None),
    out: str | None = typer.Option(None, "--out"),
    client_paths: bool = typer.Option(False, "--client-paths"),
    home: str | None = typer.Option(None, "--home"),
):
    target = path if path is not None else None if client_paths else "."
    try:
        report = build_inventory_report(target, include_client_paths=client_paths, home=home)
    except ParseError as error:
        _fail_parse_error(error)
    rendered = render_inventory_approval_registry(report)
    _write_or_echo(rendered, out)


@app.command()
def approve(
    path: str,
    server: str = typer.Option(..., "--server"),
    approved_by: str = typer.Option(..., "--approved-by"),
    reason: str = typer.Option(..., "--reason"),
    expires: str = typer.Option(..., "--expires"),
    out: str = typer.Option(..., "--out"),
):
    try:
        report = build_inventory_report(path)
        record = approved_record_from_inventory(
            report,
            server_name=server,
            approved_by=approved_by,
            reason=reason,
            expires=expires,
        )
        existing = load_approval_records(out) if Path(out).exists() else []
    except ParseError as error:
        _fail_parse_error(error)
    except ApprovalError as error:
        _fail_approval_error(error)

    rendered = render_approval_registry(upsert_approval_record(existing, record))
    _write_or_echo(rendered, out)


@app.command()
def inspect(
    path: str,
    server: str | None = typer.Option(None, "--server"),
    allow_exec: bool = typer.Option(False, "--allow-exec"),
    allow_command: list[str] | None = typer.Option(None, "--allow-command"),
    allow_env: list[str] | None = typer.Option(None, "--allow-env"),
    timeout: float = typer.Option(5.0, "--timeout"),
    format: str = typer.Option("markdown", "--format"),
    output_path: str | None = typer.Option(None, "--out"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
    profile: str | None = typer.Option(None, "--profile"),
):
    if timeout <= 0:
        typer.echo("Inspection error: --timeout must be greater than 0.", err=True)
        raise typer.Exit(2)
    try:
        loaded_policy = load_policy(policy, profile=profile)
        effective_fail_on = policy_fail_on(fail_on, loaded_policy)
        report = inspect_path(
            path,
            server_name=server,
            allow_exec=allow_exec,
            allow_commands=allow_command or [],
            allow_env_keys=allow_env or [],
            timeout=timeout,
            policy=loaded_policy,
        )
    except PolicyError as error:
        _fail_policy_error(error)
    except InspectionError as error:
        _fail_inspection_error(error)

    rendered = _render_inspection_result(report, format)
    _write_or_echo(rendered, output_path)
    if _inspection_should_fail(report, effective_fail_on):
        raise typer.Exit(1)


@app.command("hash")
def hash_cmd(
    path: str,
    out: str | None = typer.Option(None, "--out"),
):
    if out:
        Path(out).write_text(render_baseline(path), encoding="utf-8", newline="\n")
    else:
        typer.echo(canonical_hash(path))


@app.command()
def diff(
    baseline: str,
    current: str,
    format: str = typer.Option("markdown", "--format"),
    out: str | None = typer.Option(None, "--out"),
):
    findings = diff_tools(baseline, current)
    result = ScanResult(target=f"{baseline} -> {current}", findings=findings, summary=build_summary(findings))
    result = refresh_scan_explainability(result)
    rendered = _render_scan_result(result, format)
    _write_or_echo(rendered, out)


@app.command("runtime-policy")
def runtime_policy_cmd(
    path: str,
    format: str = typer.Option("markdown", "--format"),
    out: str | None = typer.Option(None, "--out"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
    profile: str | None = typer.Option(None, "--profile"),
):
    try:
        loaded_policy = load_policy(policy, profile=profile)
        effective_fail_on = policy_fail_on(fail_on, loaded_policy)
        scan = _scan_with_policy(path, loaded_policy)
    except PolicyError as error:
        _fail_policy_error(error)

    report = build_runtime_policy(scan)
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    rendered = render_runtime_policy_json(report) if format == "json" else render_runtime_policy_markdown(report)
    _write_or_echo(rendered, out)
    if should_fail(scan.summary.max_severity, effective_fail_on):
        raise typer.Exit(1)


@app.command()
def audit(
    path: str,
    format: str = typer.Option("markdown", "--format"),
    out: str | None = typer.Option(None, "--out"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
    profile: str | None = typer.Option(None, "--profile"),
):
    try:
        loaded_policy = load_policy(policy, profile=profile)
        effective_fail_on = policy_fail_on(fail_on, loaded_policy)
        scan = _scan_with_policy(path, loaded_policy)
    except PolicyError as error:
        _fail_policy_error(error)

    report = build_audit_report(scan)
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    rendered = render_audit_json(report) if format == "json" else render_audit_markdown(report)
    _write_or_echo(rendered, out)
    if should_fail(scan.summary.max_severity, effective_fail_on):
        raise typer.Exit(1)


@app.command("decide")
def decide(
    path: str,
    server: str | None = typer.Option(None, "--server"),
    approvals: str | None = typer.Option(None, "--approvals"),
    service: str = typer.Option("unknown", "--service"),
    owner: str = typer.Option("unknown", "--owner"),
    environment: str = typer.Option("unknown", "--environment"),
    request_id: str = typer.Option("", "--request-id"),
    format: str = typer.Option("json", "--format"),
    out: str | None = typer.Option(None, "--out"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
    profile: str | None = typer.Option(None, "--profile"),
):
    """Produce a final admission decision from scan, policy, and approval state."""
    approval = None
    try:
        loaded_policy = load_policy(policy, profile=profile)
        effective_fail_on = policy_fail_on(fail_on, loaded_policy)
        selected_server = server
        if selected_server or approvals:
            inventory_report = build_inventory_report(path, approvals_path=approvals)
            inventory_item = select_inventory_server(inventory_report, selected_server)
            selected_server = inventory_item.server.name
            approval = inventory_item.approval
        scan = _scan_with_policy(
            path,
            loaded_policy,
            server_name=selected_server,
        )
    except PolicyError as error:
        _fail_policy_error(error)
    except ParseError as error:
        _fail_parse_error(error)
    except ApprovalError as error:
        _fail_approval_error(error)

    report = build_admission_input(
        scan,
        approval=approval,
        server=selected_server or "",
        service=service,
        owner=owner,
        environment=environment,
        request_id=request_id,
    )
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    rendered = render_admission_json(report) if format == "json" else render_admission_markdown(report)
    _write_or_echo(rendered, out)
    if report.decision not in {"allow", "allow_with_constraints"} and should_fail(
        scan.summary.max_severity, effective_fail_on
    ):
        raise typer.Exit(1)


@app.command("review-pack")
def review_pack(
    path: str,
    out_dir: str = typer.Option("mcp-admit-review-pack", "--out-dir"),
    format: str = typer.Option("markdown", "--format"),
    policy: str | None = typer.Option(None, "--policy"),
    profile: str | None = typer.Option(None, "--profile"),
    approvals: str | None = typer.Option(None, "--approvals"),
    client_paths: bool = typer.Option(False, "--client-paths"),
    home: str | None = typer.Option(None, "--home"),
    service: str = typer.Option("unknown", "--service"),
    owner: str = typer.Option("unknown", "--owner"),
    environment: str = typer.Option("unknown", "--environment"),
    request_id: str = typer.Option("", "--request-id"),
    github_step_summary: bool = typer.Option(False, "--github-step-summary"),
    include: list[str] | None = typer.Option(None, "--include"),
    exclude: list[str] | None = typer.Option(None, "--exclude"),
):
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    try:
        loaded_policy = load_policy(policy, profile=profile)
        report = build_review_pack(
            path=path,
            output_dir=out_dir,
            policy=loaded_policy,
            approvals_path=approvals,
            include_patterns=include,
            exclude_patterns=exclude,
            include_client_paths=client_paths,
            home=home,
            service=service,
            owner=owner,
            environment=environment,
            request_id=request_id,
            github_step_summary=github_step_summary,
        )
    except PolicyError as error:
        _fail_policy_error(error)
    except ParseError as error:
        _fail_parse_error(error)
    except ApprovalError as error:
        _fail_approval_error(error)
    rendered = render_review_pack_json(report) if format == "json" else render_review_pack_markdown(report)
    _write_or_echo(rendered, None)


@app.command("release-check")
def release_check(
    format: str = typer.Option("markdown", "--format"),
):
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    report = build_release_check_report()
    rendered = render_release_check_json(report) if format == "json" else render_release_check_markdown(report)
    _write_or_echo(rendered, None)
    if report.status == "fail":
        raise typer.Exit(1)


@app.command()
def schema(
    name: str = typer.Argument(
        ...,
        help="Schema name: report, runtime-policy, audit, admission, inventory, release-check.",
    ),
    out: str | None = typer.Option(None, "--out"),
):
    if name not in schema_names():
        _fail_unknown_schema(name)
    _write_or_echo(render_schema_json(name), out)


@app.command("init-policy")
def init_policy(
    out: str | None = typer.Option(None, "--out"),
):
    policy_text = render_default_policy()
    if out:
        Path(out).write_text(policy_text, encoding="utf-8", newline="\n")
    else:
        typer.echo(policy_text)


@app.command()
def explain(
    rule_id: str | None = typer.Argument(None),
    format: str = typer.Option("markdown", "--format"),
):
    if rule_id:
        rule = get_rule(rule_id)
        if not rule:
            typer.echo(f"Unknown rule id: {rule_id}", err=True)
            raise typer.Exit(1)
        rules = [rule]
    else:
        rules = all_rules()

    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    if format == "json":
        typer.echo(render_rules_json(rules))
    else:
        typer.echo(render_rules_markdown(rules))


@app.command()
def benchmark(
    matrix: str = typer.Argument("examples/fixture_matrix.yaml"),
    format: str = typer.Option("markdown", "--format"),
    out: str | None = typer.Option(None, "--out"),
):
    report = run_benchmark(matrix)
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    rendered = render_benchmark_json(report) if format == "json" else render_benchmark_markdown(report)
    _write_or_echo(rendered, out)
    if report["failed"]:
        raise typer.Exit(1)
