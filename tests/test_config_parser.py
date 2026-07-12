from pathlib import Path
from mcp_admit.parsers.config import (
    extract_mcp_server_entries,
    extract_mcp_servers,
    load_documents,
)

def test_load_and_extract():
    docs = load_documents(Path("examples/dangerous_stdio_config.json"))
    assert len(docs) == 1
    servers = extract_mcp_servers(docs[0][1])
    assert "evil" in servers


def test_extracts_nested_mcp_servers_with_locations():
    docs = load_documents(Path("examples/nested_mcp_config.json"))
    entries = extract_mcp_server_entries(docs[0][1])

    assert len(entries) == 1
    assert entries[0].name == "nested-danger"
    assert entries[0].location == "workspace.integrations.mcpServers.nested-danger"
    assert entries[0].server["command"] == "bash"


def test_extracts_yaml_mcp_servers_alias():
    docs = load_documents(Path("examples/yaml_mcp_config.yaml"))
    entries = extract_mcp_server_entries(docs[0][1])

    assert len(entries) == 1
    assert entries[0].name == "yaml-danger"
    assert entries[0].location == "profiles.default.mcp.servers.yaml-danger"


def test_extracts_project_servers_alias():
    docs = load_documents(Path("examples/mixed_project_config.json"))
    entries = extract_mcp_server_entries(docs[0][1])

    assert len(entries) == 1
    assert entries[0].name == "project-http"
    assert entries[0].location == "project.servers.project-http"


def test_directory_loading_honors_include_exclude_and_default_ignored_dirs(tmp_path):
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "keep.json").write_text('{"tools": []}', encoding="utf-8")
    (configs / "skip.json").write_text('{"tools": []}', encoding="utf-8")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "ignored.json").write_text('{"tools": []}', encoding="utf-8")
    nested_modules = tmp_path / "packages" / "app" / "node_modules"
    nested_modules.mkdir(parents=True)
    (nested_modules / "ignored.json").write_text('{"tools": []}', encoding="utf-8")

    docs = load_documents(
        tmp_path,
        include_patterns=["configs/"],
        exclude_patterns=["configs/skip.json"],
    )

    assert [path.name for path, _ in docs] == ["keep.json"]


def test_extracts_official_registry_package_and_remote_entries():
    package_doc = load_documents(Path("examples/registry_risky_server.json"))[0][1]
    remote_doc = load_documents(Path("examples/registry_safe_server.json"))[0][1]

    package = extract_mcp_server_entries(package_doc)
    remote = extract_mcp_server_entries(remote_doc)

    assert len(package) == 1
    assert package[0].name == "io.github.example/local-admin"
    assert package[0].server["registryType"] == "npm"
    assert package[0].server["version"] == "latest"
    assert package[0].location == "packages[0]"
    assert len(remote) == 1
    assert remote[0].server["url"] == "https://docs.example.com/mcp"
    assert remote[0].location == "remotes[0]"
