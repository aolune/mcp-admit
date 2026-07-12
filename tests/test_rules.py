import json

from mcp_admit.rules.catalog import all_rules
from mcp_admit.scanner import scan_path

ALLOWED_RULE_CATEGORIES = {
    "stdio",
    "secret",
    "capability",
    "schema",
    "injection",
    "live_inspection",
    "supply_chain",
}


def test_rules_fire():
    r = scan_path("examples/dangerous_stdio_config.json")
    ids = {f.id for f in r.findings}
    assert "MCPG-STDIO-003" in ids
    assert "MCPG-SECRET-001" in ids


def test_schema_text_patterns_fire_in_input_schema():
    r = scan_path("examples/poisoned_tool_manifest.json")
    ids = {f.id for f in r.findings}
    assert "MCPG-INJ-001" in ids
    assert "MCPG-CAP-004" in ids
    assert "MCPG-SCHEMA-004" in ids


def test_core_fixture_capabilities():
    cases = [
        ("examples/dangerous_shell_tool_manifest.json", "MCPG-SCHEMA-004"),
        ("examples/dangerous_container_mcp_config.json", "MCPG-STDIO-004"),
        ("examples/nested_mcp_config.json", "MCPG-STDIO-003"),
        ("examples/yaml_mcp_config.yaml", "MCPG-SECRET-001"),
        ("examples/mixed_project_config.json", "MCPG-NET-002"),
        ("examples/arbitrary_file_read_manifest.json", "MCPG-SCHEMA-002"),
        ("examples/network_exfil_tool_manifest.json", "MCPG-SCHEMA-003"),
        ("examples/overbroad_schema_manifest.json", "MCPG-SCHEMA-001"),
        ("examples/credential_env_mcp_config.json", "MCPG-SECRET-001"),
        ("examples/poisoned_readme.md", "MCPG-INJ-001"),
        ("examples/broad_capabilities_manifest.json", "MCPG-SCHEMA-011"),
        ("examples/supply_chain_stdio_config.json", "MCPG-STDIO-008"),
    ]
    for path, expected_id in cases:
        ids = {finding.id for finding in scan_path(path).findings}
        assert expected_id in ids


def test_safe_readonly_fixture_passes():
    result = scan_path("examples/safe_readonly_docs_manifest.json")
    assert result.summary.gate_result == "pass"
    assert result.summary.recommended_policy.action == "allow"


def test_benign_domain_message_and_session_words_do_not_infer_capabilities():
    result = scan_path("examples/benign_metadata_manifest.json")

    assert result.findings == []
    assert result.summary.gate_result == "pass"


def test_rule_catalog_uses_planned_taxonomy():
    assert {rule["category"] for rule in all_rules()} <= ALLOWED_RULE_CATEGORIES


def test_network_config_findings_use_supply_chain_category():
    result = scan_path("examples/dangerous_stdio_config.json")
    network_categories = {finding.category for finding in result.findings if finding.id.startswith("MCPG-NET-")}
    assert network_categories == {"supply_chain"}


def test_container_launch_findings_detect_host_escape_paths():
    result = scan_path("examples/dangerous_container_mcp_config.json")
    findings = {finding.id: finding for finding in result.findings}

    assert "MCPG-STDIO-004" in findings
    assert "MCPG-STDIO-005" in findings
    assert "MCPG-STDIO-006" in findings
    assert "MCPG-STDIO-007" in findings
    assert findings["MCPG-STDIO-004"].capability == "container_escape"
    assert findings["MCPG-STDIO-005"].capability == "container_escape"
    assert findings["MCPG-STDIO-007"].capability == "supply_chain"
    assert result.summary.gate_result == "fail"
    assert result.summary.recommended_policy.action == "deny"
    assert any("Docker socket" in note for note in result.summary.recommended_policy.notes)


def test_pinned_container_images_do_not_trigger_unpinned_rule(tmp_path):
    config = tmp_path / "pinned_container_config.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tagged": {
                        "transport": "stdio",
                        "command": "docker",
                        "args": ["run", "--rm", "example/mcp-admin:1.2.3"],
                    },
                    "digest": {
                        "transport": "stdio",
                        "command": "docker",
                        "args": [
                            "run",
                            "--rm",
                            "example/mcp-admin@sha256:"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        ],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    ids = {finding.id for finding in scan_path(str(config)).findings}

    assert "MCPG-STDIO-001" in ids
    assert "MCPG-STDIO-007" not in ids


def test_broad_capability_schema_rules_fire():
    result = scan_path("examples/broad_capabilities_manifest.json")
    ids = {finding.id for finding in result.findings}

    assert "MCPG-SCHEMA-006" in ids
    assert "MCPG-SCHEMA-007" in ids
    assert "MCPG-SCHEMA-008" in ids
    assert "MCPG-SCHEMA-009" in ids
    assert "MCPG-SCHEMA-010" in ids
    assert "MCPG-SCHEMA-011" in ids
    assert "MCPG-CAP-010" in ids


def test_supply_chain_rules_detect_latest_download_shell_and_tunnel():
    result = scan_path("examples/supply_chain_stdio_config.json")
    ids = {finding.id for finding in result.findings}

    assert "MCPG-STDIO-002" in ids
    assert "MCPG-STDIO-008" in ids
    assert "MCPG-NET-003" in ids


def test_nested_server_findings_include_explainable_location():
    result = scan_path("examples/nested_mcp_config.json")
    shell = next(finding for finding in result.findings if finding.id == "MCPG-STDIO-003")

    assert shell.location.endswith(
        "workspace.integrations.mcpServers.nested-danger.command"
    )


def test_toxic_flow_composes_sensitive_read_and_outbound_findings():
    result = scan_path("examples/toxic_flow_manifest.json")
    flow = next(finding for finding in result.findings if finding.id == "MCPG-FLOW-001")

    assert result.summary.tool_risk_level == "L4"
    assert result.summary.risk_score == 90
    assert flow.policy_action == "quarantine"
    assert set(flow.related_finding_ids) >= {"MCPG-SCHEMA-002", "MCPG-SCHEMA-003"}
    assert result.summary.risk_factors[0].id == "MCPG-FLOW-001"


def test_prompt_injection_composes_with_high_impact_capabilities():
    result = scan_path("examples/poisoned_tool_manifest.json")
    ids = {finding.id for finding in result.findings}

    assert "MCPG-FLOW-002" in ids
    assert result.summary.risk_score == 95


def test_official_registry_metadata_is_scanned_without_execution():
    safe = scan_path("examples/registry_safe_server.json")
    risky = scan_path("examples/registry_risky_server.json")
    ids = {finding.id for finding in risky.findings}

    assert safe.summary.gate_result == "pass"
    assert ids >= {
        "MCPG-FLOW-003",
        "MCPG-SC-008",
        "MCPG-SC-010",
        "MCPG-SECRET-003",
        "MCPG-STDIO-001",
    }
    assert risky.summary.recommended_policy.action == "deny"
