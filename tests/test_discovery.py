import json

from mcp_admit.discovery import (
    discover_servers,
    render_discovery_json,
    render_discovery_markdown,
)


def test_discover_servers_infers_client_configs_without_env_values():
    report = discover_servers("examples/client_configs")
    by_name = {server.name: server for server in report.servers}
    rendered = render_discovery_json(report)

    assert report.total_servers == 4
    assert report.clients == ["claude-desktop", "cursor", "vscode", "windsurf"]
    assert by_name["claude-files"].client == "claude-desktop"
    assert by_name["cursor-git"].client == "cursor"
    assert by_name["vscode-docs"].client == "vscode"
    assert by_name["vscode-docs"].transport == "http"
    assert by_name["windsurf-db"].client == "windsurf"
    assert by_name["windsurf-db"].env_keys == ["DATABASE_URL"]
    assert "postgres://example.invalid/db" not in rendered


def test_discover_client_preset_paths(tmp_path):
    config = tmp_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        """
{
  "mcpServers": {
    "preset-server": {
      "command": "python",
      "args": ["-m", "server"],
      "env": {"API_TOKEN": "secret-token-value"}
    }
  }
}
""",
        encoding="utf-8",
    )

    report = discover_servers(None, include_client_paths=True, home=str(tmp_path))
    parsed = json.loads(render_discovery_json(report))

    assert report.target == "client-presets"
    assert parsed["servers"][0]["client"] == "claude-desktop"
    assert parsed["servers"][0]["env_keys"] == ["API_TOKEN"]
    assert "secret-token-value" not in json.dumps(parsed)


def test_discovery_markdown_lists_servers():
    markdown = render_discovery_markdown(discover_servers("examples/client_configs"))

    assert "MCP Admit Discovery" in markdown
    assert "claude-files" in markdown
    assert "vscode-docs" in markdown
    assert "DATABASE_URL" in markdown


def test_discovery_recognizes_official_registry_metadata():
    report = discover_servers("examples/registry_risky_server.json")

    assert report.total_servers == 1
    assert report.servers[0].client == "mcp-registry"
    assert report.servers[0].package == "@example/local-admin@latest"
