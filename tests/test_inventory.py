import yaml

from mcp_admit.inventory import (
    build_inventory_report,
    render_inventory_approval_registry,
    render_inventory_json,
    render_inventory_markdown,
)


def test_inventory_scans_discovered_servers_without_env_values():
    report = build_inventory_report("examples/client_configs")
    by_name = {item.server.name: item for item in report.servers}
    rendered = render_inventory_json(report)

    assert report.schema_version == "mcp-admit.inventory.v1"
    assert report.total_servers == 4
    assert by_name["claude-files"].summary.gate_result == "fail"
    assert "MCPG-STDIO-001" in by_name["claude-files"].finding_ids
    assert by_name["windsurf-db"].approval.status == "unknown"
    assert "postgres://example.invalid/db" not in rendered


def test_inventory_approval_registry_starts_pending(tmp_path):
    report = build_inventory_report("examples/client_configs")
    registry = tmp_path / "approvals.yaml"
    registry.write_text(render_inventory_approval_registry(report), encoding="utf-8")

    pending = build_inventory_report("examples/client_configs", approvals_path=str(registry))

    assert {item.approval.status for item in pending.servers} == {"pending"}
    registry_data = yaml.safe_load(registry.read_text(encoding="utf-8"))
    assert {record["status"] for record in registry_data["approvals"]} == {"pending"}
    assert {record["approved_by"] for record in registry_data["approvals"]} == {""}


def test_inventory_detects_drifted_and_expired_approvals(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        '{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}',
        encoding="utf-8",
    )
    base = build_inventory_report(str(config))
    registry_data = yaml.safe_load(render_inventory_approval_registry(base))
    registry_data["approvals"][0]["status"] = "approved"
    registry_data["approvals"][0]["approved_by"] = "alice"
    registry_data["approvals"][0]["reason"] = "Reviewed in SEC-123."
    registry_data["approvals"][0]["expires"] = "2020-01-01"
    registry = tmp_path / "approvals.yaml"
    registry.write_text(yaml.safe_dump(registry_data, sort_keys=False), encoding="utf-8")

    expired = build_inventory_report(str(config), approvals_path=str(registry))
    assert expired.servers[0].approval.status == "expired"

    registry_data["approvals"][0]["expires"] = "2099-01-01"
    registry.write_text(yaml.safe_dump(registry_data, sort_keys=False), encoding="utf-8")
    config.write_text(
        '{"mcpServers":{"local":{"command":"node","args":["changed.js"]}}}',
        encoding="utf-8",
    )
    drifted = build_inventory_report(str(config), approvals_path=str(registry))
    assert drifted.servers[0].approval.status == "drifted"


def test_approved_record_with_empty_capability_allowlist_detects_drift(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        '{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}',
        encoding="utf-8",
    )
    base = build_inventory_report(str(config))
    registry_data = yaml.safe_load(render_inventory_approval_registry(base))
    record = registry_data["approvals"][0]
    record.update(
        {
            "status": "approved",
            "approved_by": "alice",
            "reason": "Reviewed in SEC-124.",
            "expires": "2099-01-01",
            "allowed_capabilities": [],
        }
    )
    registry = tmp_path / "approvals.yaml"
    registry.write_text(yaml.safe_dump(registry_data, sort_keys=False), encoding="utf-8")

    report = build_inventory_report(str(config), approvals_path=str(registry))

    assert report.servers[0].approval.status == "drifted"


def test_inventory_markdown_includes_approval_column():
    markdown = render_inventory_markdown(build_inventory_report("examples/client_configs"))

    assert "MCP Admit Inventory" in markdown
    assert "Approval" in markdown
    assert "claude-files" in markdown
