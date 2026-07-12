import json

from mcp_admit import __version__
from mcp_admit.inspection import inspect_path
from mcp_admit.reports import (
    render_inspection_json,
    render_inspection_markdown,
    render_json,
    render_markdown,
    render_sarif,
)
from mcp_admit.scanner import scan_path


def test_reports():
    r = scan_path("examples/poisoned_tool_manifest.json")
    markdown = render_markdown(r)
    assert "MCP Admit Report" in markdown
    assert "Gate:" in markdown
    assert "Risk score:" in markdown
    assert "Risk score method: max_finding_with_composition" in markdown
    assert "## Risk factors" in markdown
    assert "Recommended policy" in markdown
    assert "OWASP MCP:" in markdown
    json_report = render_json(r)
    parsed = json.loads(json_report)
    assert parsed["schema_version"] == "mcp-admit.report.v1"
    assert parsed["tool_version"] == __version__
    assert set(parsed) == {
        "schema_version",
        "tool_version",
        "target",
        "findings",
        "summary",
        "policy_context",
        "policy_effects",
        "rule_explanations",
    }
    assert parsed["rule_explanations"]
    assert parsed["rule_explanations"][0]["id"].startswith("MCPG-")
    assert '"findings"' in json_report
    assert '"recommended_policy"' in json_report
    assert '"owasp"' in json_report
    sarif = render_sarif(r)
    parsed_sarif = json.loads(sarif)
    driver = parsed_sarif["runs"][0]["tool"]["driver"]
    invocation = parsed_sarif["runs"][0]["invocations"][0]
    assert driver["semanticVersion"] == __version__
    assert driver["properties"]["report_schema_version"] == "mcp-admit.report.v1"
    assert invocation["properties"]["risk_score_method"] == "max_finding_with_composition"
    assert invocation["properties"]["risk_factors"]
    assert "policy_context" in invocation["properties"]
    assert "rule_explanations" in invocation["properties"]
    assert '"version": "2.1.0"' in sarif
    assert '"ruleId": "MCPG-INJ-001"' in sarif
    assert '"tags"' in sarif


def test_secret_values_are_masked():
    r = scan_path("examples/credential_env_mcp_config.json")
    report = render_markdown(r)
    assert "ghp_exampletoken123456" not in report
    assert "gh***56" in report
    assert "ghp_exampletoken123456" not in render_json(r)
    assert "ghp_exampletoken123456" not in render_sarif(r)


def test_inspection_reports_are_rendered_and_masked():
    report = inspect_path("examples/dangerous_stdio_config.json", server_name="evil")
    markdown = render_inspection_markdown(report)
    json_report = render_inspection_json(report)
    assert "MCP Admit Inspection" in markdown
    assert "blocked_missing_allow_exec" in markdown
    assert '"schema_version": "mcp-admit.inspection.v1"' in json_report
    assert "sk-1234567890" not in markdown
    assert "sk-1234567890" not in json_report


def test_inspection_report_renders_live_tool_inventory():
    from mcp_admit.models import ToolDefinition

    def fake_lister(*args, **kwargs):
        return [
            ToolDefinition(
                name="lookup_docs",
                description="Lookup approved docs.",
                inputSchema={
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
            )
        ]

    report = inspect_path(
        "examples/fake_stdio_mcp_config.json",
        server_name="fake-safe",
        allow_exec=True,
        allow_commands=["python3 examples/fake_stdio_mcp_server.py"],
        tool_lister=fake_lister,
    )
    markdown = render_inspection_markdown(report)
    json_report = render_inspection_json(report)
    assert "Live tool inventory" in markdown
    assert "lookup_docs" in markdown
    assert "id" in markdown
    assert '"live_tools"' in json_report
    assert '"allows_additional_properties": false' in json_report
