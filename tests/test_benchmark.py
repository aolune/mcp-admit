from typer.testing import CliRunner

from mcp_admit.benchmark import run_benchmark
from mcp_admit.cli import app


runner = CliRunner()


def test_fixture_matrix_passes():
    report = run_benchmark("examples/fixture_matrix.yaml")
    assert report["failed"] == 0
    assert report["passed"] == report["total"]


def test_benchmark_cli_json():
    result = runner.invoke(app, ["benchmark", "examples/fixture_matrix.yaml", "--format", "json"])
    assert result.exit_code == 0
    assert '"failed": 0' in result.stdout
    assert "poisoned tool metadata" in result.stdout


def test_benchmark_cli_out_writes_report(tmp_path):
    output = tmp_path / "benchmark.md"
    result = runner.invoke(
        app,
        ["benchmark", "examples/fixture_matrix.yaml", "--out", str(output)],
    )
    assert result.exit_code == 0
    report = output.read_text(encoding="utf-8")
    assert "MCP Admit Fixture Benchmark" in report
    assert "Failed: 0" in report


def test_benchmark_cli_rejects_unknown_format():
    result = runner.invoke(app, ["benchmark", "examples/fixture_matrix.yaml", "--format", "sarif"])
    assert result.exit_code == 2
    assert "Supported formats: json, markdown" in result.stderr


def test_benchmark_cli_fails_on_unmet_expectation(tmp_path):
    matrix = tmp_path / "bad_matrix.yaml"
    matrix.write_text(
        """
version: 1
fixtures:
  - name: bad expectation
    target: examples/safe_readonly_docs_manifest.json
    expect:
      gate: fail
      contains_findings:
        - MCPG-SCHEMA-004
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["benchmark", str(matrix)])
    assert result.exit_code == 1
    assert "bad expectation" in result.stdout
    assert "missing finding MCPG-SCHEMA-004" in result.stdout
