import subprocess

from mcp_admit.scanner import scan_path
from mcp_admit.inspection import inspect_path


def test_scan_does_not_execute_configured_stdio_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("scanner must not execute configured MCP commands")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    result = scan_path("examples/dangerous_stdio_config.json")
    assert result.findings


def test_recursive_scan_does_not_execute_nested_stdio_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("recursive scanner must not execute configured MCP commands")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    result = scan_path("examples/nested_mcp_config.json")
    assert {finding.id for finding in result.findings} >= {"MCPG-STDIO-001", "MCPG-STDIO-003"}


def test_inspect_default_does_not_execute_configured_stdio_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("inspect must not execute configured MCP commands by default")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    report = inspect_path("examples/dangerous_stdio_config.json", server_name="evil")
    assert report.execution.status == "blocked_missing_allow_exec"


def test_inspect_allow_exec_without_allowlist_does_not_execute(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("inspect must not execute commands without exact allowlist")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    report = inspect_path(
        "examples/dangerous_stdio_config.json",
        server_name="evil",
        allow_exec=True,
        allow_commands=["python -m safe_server"],
    )
    assert report.execution.status == "blocked_command_not_allowlisted"


def test_registry_package_scan_never_executes_declared_package(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("registry metadata scans must never execute packages")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    result = scan_path("examples/registry_risky_server.json")

    assert {finding.id for finding in result.findings} >= {
        "MCPG-SC-008",
        "MCPG-STDIO-001",
    }
