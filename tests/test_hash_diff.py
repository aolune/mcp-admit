import json
from pathlib import Path

from mcp_admit.hashing import canonical_hash
from mcp_admit.diff import diff_tools
from mcp_admit.hashing import build_baseline, render_baseline
from mcp_admit.summary import build_summary


def test_hash_and_diff():
    assert canonical_hash("examples/rug_pull_baseline.json")
    f=diff_tools("examples/rug_pull_baseline.json","examples/rug_pull_changed.json")
    ids={x.id for x in f}
    assert "MCPG-SC-001" in ids
    assert "MCPG-SC-002" in ids
    assert "MCPG-SC-003" in ids


def test_diff_marks_added_capability():
    findings = diff_tools("examples/rug_pull_baseline.json", "examples/rug_pull_changed.json")
    escalation = next(f for f in findings if f.id == "MCPG-SC-001")
    assert "network_send" in escalation.evidence
    assert escalation.capability == "network_send"
    assert escalation.policy_action == "require_approval"
    assert escalation.owasp
    assert build_summary(findings).egress_review_required is True


def test_baseline_masks_secret_values():
    rendered = render_baseline("examples/credential_env_mcp_config.json")
    assert "ghp_exampletoken123456" not in rendered
    baseline = json.loads(rendered)
    assert baseline["kind"] == "mcp-admit-baseline"
    assert baseline["servers"][0]["env_keys"] == ["GITHUB_TOKEN"]


def test_diff_accepts_baseline_json(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(render_baseline("examples/rug_pull_baseline.json"), encoding="utf-8")
    findings = diff_tools(str(baseline_path), "examples/rug_pull_changed.json")
    ids = {finding.id for finding in findings}
    assert "MCPG-SC-001" in ids
    assert "MCPG-SC-002" in ids
    assert "MCPG-SC-003" in ids


def test_diff_detects_server_launch_drift(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "changed_config.json"
    baseline_path.write_text(render_baseline("examples/safe_mcp_config.json"), encoding="utf-8")
    current_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "safe": {
                        "transport": "http",
                        "url": "http://localhost:8080/mcp",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    ids = {finding.id for finding in diff_tools(str(baseline_path), str(current_path))}
    assert "MCPG-SC-005" in ids


def test_build_baseline_includes_tool_risk_metadata():
    baseline = build_baseline("examples/poisoned_tool_manifest.json")
    tool = baseline["tools"][0]
    assert tool["risk_level"] == "L4"
    assert tool["risk_score"] >= 75
    assert "shell_exec" in tool["capabilities"]


def test_build_baseline_includes_nested_server_location():
    baseline = build_baseline("examples/nested_mcp_config.json")
    server = baseline["servers"][0]

    assert server["name"] == "nested-danger"
    assert server["location"] == "workspace.integrations.mcpServers.nested-danger"


def test_registry_package_version_changes_definition_hash(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "server.json"
    baseline_path.write_text(
        render_baseline("examples/registry_risky_server.json"),
        encoding="utf-8",
    )
    data = json.loads(Path("examples/registry_risky_server.json").read_text(encoding="utf-8"))
    data["packages"][0]["version"] = "1.2.3"
    current_path.write_text(json.dumps(data), encoding="utf-8")

    ids = {finding.id for finding in diff_tools(str(baseline_path), str(current_path))}

    assert "MCPG-SC-005" in ids
