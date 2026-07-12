import json

from typer.testing import CliRunner

from mcp_admit.cli import app
from mcp_admit.release_check import build_release_check_report
from mcp_admit.review_pack import build_review_pack


runner = CliRunner()


def test_build_review_pack_writes_expected_files(tmp_path):
    report = build_review_pack(
        path="examples/client_configs",
        output_dir=str(tmp_path / "pack"),
        policy={},
        github_step_summary=True,
        service="agent-platform",
        owner="security",
        environment="ci",
    )

    names = {path.rsplit("/", 1)[-1] for path in report.files}
    assert "scan.json" in names
    assert "inventory.json" in names
    assert "runtime-policy.json" in names
    assert "audit.md" in names
    assert "admission.json" in names
    assert "github-step-summary.md" in names
    assert report.inventory.total_servers == 4


def test_review_pack_cli_outputs_summary(tmp_path):
    result = runner.invoke(
        app,
        [
            "review-pack",
            "examples/client_configs",
            "--out-dir",
            str(tmp_path / "pack"),
            "--format",
            "json",
            "--github-step-summary",
        ],
    )
    parsed = json.loads(result.stdout)

    assert result.exit_code == 0
    assert parsed["inventory"]["total_servers"] == 4
    assert (tmp_path / "pack" / "github-step-summary.md").exists()


def test_release_check_passes_current_contracts():
    report = build_release_check_report()

    assert report.status == "pass"
    assert all(item.status == "pass" for item in report.items)
    ids = {item.id for item in report.items}
    assert {
        "package.version",
        "github.action",
        "github.actions_pinned",
        "github.sarif_policy",
        "github.dependabot",
        "readme.release_refs",
        "community.security",
    } <= ids


def test_release_check_cli_json():
    result = runner.invoke(app, ["release-check", "--format", "json"])
    parsed = json.loads(result.stdout)

    assert result.exit_code == 0
    assert parsed["schema_version"] == "mcp-admit.release-check.v1"
    assert parsed["status"] == "pass"
