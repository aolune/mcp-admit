import json
from pathlib import Path

from mcp_admit.models import AdmissionInputReport, InventoryReport, RuntimePolicyReport
from mcp_admit.schemas import render_schema_json, schema_names


SCHEMA_FILES = {
    "admission": Path("schemas/admission.schema.json"),
    "audit": Path("schemas/audit.schema.json"),
    "inventory": Path("schemas/inventory.schema.json"),
    "release-check": Path("schemas/release-check.schema.json"),
    "report": Path("schemas/report.schema.json"),
    "runtime-policy": Path("schemas/runtime-policy.schema.json"),
}


def test_schema_files_match_generated_contracts():
    assert sorted(SCHEMA_FILES) == schema_names()
    for name, path in SCHEMA_FILES.items():
        assert path.read_text(encoding="utf-8") == render_schema_json(name)


def test_golden_admission_sample_matches_current_model():
    sample = Path("examples/generated/admission.json").read_text(encoding="utf-8")
    report = AdmissionInputReport.model_validate(json.loads(sample))

    assert report.schema_version == "mcp-admit.admission.v1"
    assert report.subject.service == "agent-platform"
    assert report.decision == "deny"
    assert "shell_exec" in report.capabilities
    assert "ghp_exampletoken123456" not in sample


def test_golden_runtime_policy_sample_matches_current_model():
    sample = Path("examples/generated/runtime-policy.json").read_text(encoding="utf-8")
    report = RuntimePolicyReport.model_validate(json.loads(sample))

    assert report.schema_version == "mcp-admit.runtime-policy.v1"
    assert report.default_action == "deny"
    assert any(rule.id == "runtime.capability.shell_exec" for rule in report.rules)


def test_golden_inventory_sample_matches_current_model():
    sample = Path("examples/generated/inventory.json").read_text(encoding="utf-8")
    report = InventoryReport.model_validate(json.loads(sample))

    assert report.schema_version == "mcp-admit.inventory.v1"
    assert report.total_servers == 4
    assert any(server.server.client == "claude-desktop" for server in report.servers)
