from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml
from pydantic import ValidationError

from mcp_admit import __version__
from mcp_admit.models import (
    AdmissionInputReport,
    InventoryReport,
    ReleaseCheckItem,
    ReleaseCheckReport,
    RuntimePolicyReport,
)
from mcp_admit.schemas import render_schema_json, schema_names


def _item(id: str, ok: bool, detail: str) -> ReleaseCheckItem:
    return ReleaseCheckItem(id=id, status="pass" if ok else "fail", detail=detail)


def _check_schema(name: str) -> ReleaseCheckItem:
    path = Path("schemas") / f"{name}.schema.json"
    if not path.exists():
        return _item(f"schema.{name}", False, f"Missing schema file: {path}")
    expected = render_schema_json(name)
    actual = path.read_text(encoding="utf-8")
    return _item(
        f"schema.{name}",
        actual == expected,
        f"{path} matches generated contract." if actual == expected else f"{path} is stale.",
    )


def _check_model_sample(path: Path, model, id: str) -> ReleaseCheckItem:
    if not path.exists():
        return _item(id, False, f"Missing generated sample: {path}")
    try:
        sample = model.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, ValidationError) as exc:
        return _item(id, False, f"{path} failed validation: {exc}")
    sample_version = getattr(sample, "tool_version", __version__)
    if sample_version != __version__:
        return _item(
            id,
            False,
            f"{path} uses tool version {sample_version}; expected {__version__}.",
        )
    return _item(id, True, f"{path} validates.")


def _check_package_version() -> ReleaseCheckItem:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    package_version = str(data.get("project", {}).get("version", ""))
    return _item(
        "package.version",
        package_version == __version__,
        f"pyproject.toml and package version are both {__version__}."
        if package_version == __version__
        else f"pyproject.toml has {package_version}; package exports {__version__}.",
    )


def _check_action_metadata() -> ReleaseCheckItem:
    path = Path("action.yml")
    if not path.exists():
        return _item("github.action", False, "Missing action.yml.")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return _item("github.action", False, f"action.yml is invalid YAML: {exc}")
    inputs = data.get("inputs", {}) if isinstance(data, dict) else {}
    runs = data.get("runs", {}) if isinstance(data, dict) else {}
    required_inputs = {"path", "profile", "policy", "fail-on", "format", "output"}
    ok = runs.get("using") == "composite" and required_inputs <= set(inputs)
    return _item(
        "github.action",
        ok,
        "action.yml defines the composite admission scan contract."
        if ok
        else "action.yml is missing composite runs metadata or required inputs.",
    )


def _check_community_file(name: str) -> ReleaseCheckItem:
    path = Path(name)
    exists_and_nonempty = path.exists() and bool(
        path.read_text(encoding="utf-8").strip()
    )
    return _item(
        f"community.{path.stem.lower()}",
        exists_and_nonempty,
        f"{name} is present and non-empty."
        if exists_and_nonempty
        else f"Missing or empty {name}.",
    )


def build_release_check_report() -> ReleaseCheckReport:
    items = [
        _check_package_version(),
        _check_action_metadata(),
        _check_community_file("SECURITY.md"),
        _check_community_file("CONTRIBUTING.md"),
        *[_check_schema(name) for name in schema_names()],
    ]
    items.extend(
        [
            _check_model_sample(
                Path("examples/generated/admission.json"),
                AdmissionInputReport,
                "sample.admission",
            ),
            _check_model_sample(
                Path("examples/generated/inventory.json"),
                InventoryReport,
                "sample.inventory",
            ),
            _check_model_sample(
                Path("examples/generated/runtime-policy.json"),
                RuntimePolicyReport,
                "sample.runtime-policy",
            ),
        ]
    )
    status = "pass" if all(item.status == "pass" for item in items) else "fail"
    return ReleaseCheckReport(status=status, items=items)


def render_release_check_json(report: ReleaseCheckReport) -> str:
    return json.dumps(report.model_dump(), indent=2)


def render_release_check_markdown(report: ReleaseCheckReport) -> str:
    lines = [
        "# MCP Admit Release Check",
        "",
        f"Status: {report.status.upper()}",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for item in report.items:
        lines.append(f"| {item.id} | {item.status} | {item.detail} |")
    return "\n".join(lines)
