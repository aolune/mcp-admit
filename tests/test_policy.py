from datetime import date

import pytest

from mcp_admit.policy import (
    PolicyError,
    apply_policy,
    apply_policy_with_effects,
    expand_policy,
    load_policy,
    policy_allow_exec_commands,
    policy_fail_on,
    should_fail,
    validate_policy,
)
from mcp_admit.scanner import scan_path
from mcp_admit.summary import build_summary


def test_policy_ignore_and_fail():
    result = scan_path("examples/poisoned_tool_manifest.json")
    policy = {"ignore_finding_ids": ["MCPG-INJ-002"], "fail_on": "medium"}
    filtered = apply_policy(result.findings, policy)
    assert all(f.id != "MCPG-INJ-002" for f in filtered)
    assert policy_fail_on(None, policy) == "medium"
    assert should_fail("high", "medium") is True


def test_policy_waiver_ignore_requires_reason_and_records_effect():
    result = scan_path("examples/network_exfil_tool_manifest.json")
    policy = {
        "waivers": [
            {
                "id": "approved-webhook",
                "action": "ignore",
                "finding_id": "MCPG-SCHEMA-003",
                "reason": "Webhook domain is reviewed for this test fixture.",
                "expires": "2099-01-01",
            }
        ]
    }

    filtered, effects = apply_policy_with_effects(result.findings, policy, today=date(2026, 6, 25))

    assert all(finding.id != "MCPG-SCHEMA-003" for finding in filtered)
    assert effects[0].action == "ignored"
    assert effects[0].policy_ref == "approved-webhook"
    assert "Webhook domain" in effects[0].reason


def test_policy_waiver_downgrade_overrides_profile_deny():
    result = scan_path("examples/dangerous_container_mcp_config.json")
    policy = {
        "profile": "enterprise-strict",
        "waivers": [
            {
                "id": "container-lab",
                "action": "downgrade",
                "capability": "container_escape",
                "server": "host-control",
                "reason": "Temporary lab-only container review.",
                "expires": "2099-01-01",
                "downgrade_to": "medium",
            }
        ],
    }

    filtered, effects = apply_policy_with_effects(result.findings, policy, today=date(2026, 6, 25))
    container_findings = [finding for finding in filtered if finding.capability == "container_escape"]

    assert container_findings
    assert all(finding.policy_action == "allow_with_constraints" for finding in container_findings)
    assert any(effect.action == "downgraded" for effect in effects)


def test_expired_policy_waiver_records_effect_and_does_not_filter():
    result = scan_path("examples/network_exfil_tool_manifest.json")
    policy = {
        "waivers": [
            {
                "id": "old-webhook",
                "action": "ignore",
                "finding_id": "MCPG-SCHEMA-003",
                "reason": "Expired exception.",
                "expires": "2020-01-01",
            }
        ]
    }

    filtered, effects = apply_policy_with_effects(result.findings, policy, today=date(2026, 6, 25))

    assert any(finding.id == "MCPG-SCHEMA-003" for finding in filtered)
    assert effects[0].action == "expired"


def test_summary_recomputed_after_filtering():
    result = scan_path("examples/dangerous_stdio_config.json")
    filtered = [f for f in result.findings if f.capability != "credential_access"]
    summary = build_summary(filtered)
    assert summary.credential_review_required is False


def test_policy_denies_capability():
    result = scan_path("examples/arbitrary_file_read_manifest.json")
    policy = {"deny_capabilities": ["file_read"]}
    filtered = apply_policy(result.findings, policy)
    assert any(f.capability == "file_read" and f.policy_action == "deny" for f in filtered)


def test_invalid_policy_values_raise_clear_errors():
    with pytest.raises(PolicyError, match="Unsupported fail_on"):
        validate_policy({"fail_on": "severe"})

    with pytest.raises(PolicyError, match="must be a list of strings"):
        validate_policy({"deny_capabilities": "shell_exec"})

    with pytest.raises(PolicyError, match="must be a list of strings"):
        validate_policy({"allow_exec_commands": "python -m server"})

    with pytest.raises(PolicyError, match="Unsupported require_approval_levels"):
        validate_policy({"require_approval_levels": ["L9"]})

    with pytest.raises(PolicyError, match="Unsupported fail_on"):
        should_fail("high", "severe")

    with pytest.raises(PolicyError, match="must include a non-empty reason"):
        validate_policy({"waivers": [{"finding_id": "MCPG-SCHEMA-003"}]})

    with pytest.raises(PolicyError, match="Unknown profile"):
        load_policy(None, profile="prod")


def test_policy_allow_exec_commands():
    policy = {"allow_exec_commands": ["python -m approved_server"]}
    assert policy_allow_exec_commands(policy) == ["python -m approved_server"]


def test_expand_policy_profile_merges_defaults():
    policy = expand_policy({"profile": "ci", "deny_capabilities": ["file_read"]})

    assert policy["profile"] == "ci"
    assert "shell_exec" in policy["deny_capabilities"]
    assert "file_read" in policy["deny_capabilities"]
    assert policy["fail_on"] == "high"


def test_load_policy_profile_merges_file_waivers(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
profile: ci
waivers:
  - id: reviewed-url
    action: downgrade
    finding_id: MCPG-SCHEMA-003
    reason: Reviewed destination allowlist.
    expires: 2099-01-01
""",
        encoding="utf-8",
    )

    policy = load_policy(str(policy_path))

    assert policy["profile"] == "ci"
    assert "shell_exec" in policy["deny_capabilities"]
    assert policy["waivers"][0]["id"] == "reviewed-url"
