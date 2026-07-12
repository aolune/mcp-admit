from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml

from mcp_admit.models import Finding, PolicyEffect

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_LEVELS = {"L0", "L1", "L2", "L3", "L4"}
ACTION_RANK = {
    "allow": 0,
    "allow_with_constraints": 1,
    "require_approval": 2,
    "quarantine": 3,
    "deny": 4,
}
DOWNGRADE_TARGETS = {
    "low": {"risk_level": "L1", "risk_score": 15, "policy_action": "allow"},
    "medium": {"risk_level": "L2", "risk_score": 40, "policy_action": "allow_with_constraints"},
}

BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "dev": {
        "profile": "dev",
        "fail_on": "critical",
        "ignore_finding_ids": [],
        "deny_capabilities": ["credential_access", "payment_purchase"],
        "require_approval_levels": ["L4"],
        "allow_exec_commands": [],
        "waivers": [],
    },
    "ci": {
        "profile": "ci",
        "fail_on": "high",
        "ignore_finding_ids": [],
        "deny_capabilities": [
            "shell_exec",
            "code_exec",
            "credential_access",
            "container_escape",
            "payment_purchase",
        ],
        "require_approval_levels": ["L3", "L4"],
        "allow_exec_commands": [],
        "waivers": [],
    },
    "enterprise-strict": {
        "profile": "enterprise-strict",
        "fail_on": "medium",
        "ignore_finding_ids": [],
        "deny_capabilities": [
            "shell_exec",
            "code_exec",
            "credential_access",
            "container_escape",
            "payment_purchase",
        ],
        "require_approval_levels": ["L3", "L4"],
        "allow_exec_commands": [],
        "waivers": [],
    },
}

DEFAULT_POLICY = """version: 1
profile: enterprise-strict
fail_on: medium
ignore_finding_ids: []
deny_capabilities:
  - shell_exec
  - code_exec
  - credential_access
  - payment_purchase
require_approval_levels:
  - L3
  - L4
allow_exec_commands: []
waivers: []
"""


class PolicyError(ValueError):
    pass


def _format_allowed(values: set[str]) -> str:
    return ", ".join(sorted(values))


def _require_string_list(policy: dict[str, Any], key: str) -> list[str]:
    value = policy.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"Policy field {key} must be a list of strings.")
    return value


def _require_waivers(policy: dict[str, Any]) -> list[dict[str, Any]]:
    value = policy.get("waivers", [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise PolicyError("Policy field waivers must be a list of objects.")
    return value


def _validate_waiver(waiver: dict[str, Any], index: int) -> None:
    action = waiver.get("action", "ignore")
    if action not in {"ignore", "downgrade"}:
        raise PolicyError(f"Policy waiver {index} has unsupported action: {action}.")
    reason = waiver.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise PolicyError(f"Policy waiver {index} must include a non-empty reason.")
    match_keys = {"finding_id", "rule_id", "capability", "server", "location"}
    if not any(isinstance(waiver.get(key), str) and waiver.get(key) for key in match_keys):
        raise PolicyError(
            f"Policy waiver {index} must match at least one of: "
            "finding_id, rule_id, capability, server, location."
        )
    expires = waiver.get("expires")
    if expires is not None:
        if isinstance(expires, date):
            waiver["expires"] = expires.isoformat()
        elif not isinstance(expires, str):
            raise PolicyError(f"Policy waiver {index} expires must be an ISO date string.")
        try:
            date.fromisoformat(str(waiver["expires"]))
        except ValueError as exc:
            raise PolicyError(f"Policy waiver {index} expires must be an ISO date string.") from exc
    downgrade_to = waiver.get("downgrade_to", "medium")
    if action == "downgrade" and downgrade_to not in DOWNGRADE_TARGETS:
        raise PolicyError(
            f"Policy waiver {index} downgrade_to must be one of: "
            f"{_format_allowed(set(DOWNGRADE_TARGETS))}."
        )


def _copy_policy(policy: dict[str, Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key, value in policy.items():
        if isinstance(value, list):
            copied[key] = [item.copy() if isinstance(item, dict) else item for item in value]
        else:
            copied[key] = value
    return copied


def _merge_policy(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = _copy_policy(base)
    list_keys = {
        "ignore_finding_ids",
        "deny_capabilities",
        "require_approval_levels",
        "allow_exec_commands",
        "waivers",
    }
    for key, value in override.items():
        if key in list_keys:
            merged[key] = [*(merged.get(key, []) or []), *(value or [])]
        else:
            merged[key] = value
    return merged


def _profile_policy(profile: str | None) -> dict[str, Any]:
    if not profile:
        return {}
    if profile not in BUILTIN_PROFILES:
        raise PolicyError(
            f"Unknown profile: {profile}. Supported profiles: {_format_allowed(set(BUILTIN_PROFILES))}."
        )
    return _copy_policy(BUILTIN_PROFILES[profile])


def _validate_profile_field(policy: dict[str, Any]) -> None:
    profile = policy.get("profile")
    if profile is None:
        return
    if not isinstance(profile, str):
        raise PolicyError("Policy field profile must be a string.")
    _profile_policy(profile)


def _policy_with_profile(policy: dict[str, Any]) -> dict[str, Any]:
    _validate_profile_field(policy)
    profile = policy.get("profile")
    if not profile:
        return policy
    data = {key: value for key, value in policy.items() if key != "profile"}
    return _merge_policy(_profile_policy(profile), data)


def validate_fail_on(fail_on: str | None) -> str | None:
    if fail_on is None:
        return None
    if fail_on not in SEV_RANK:
        raise PolicyError(
            f"Unsupported fail_on: {fail_on}. Supported severities: {_format_allowed(set(SEV_RANK))}."
        )
    return fail_on


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    _validate_profile_field(policy)
    validate_fail_on(policy.get("fail_on"))
    _require_string_list(policy, "ignore_finding_ids")
    _require_string_list(policy, "deny_capabilities")
    _require_string_list(policy, "allow_exec_commands")
    require_approval_levels = _require_string_list(policy, "require_approval_levels")
    invalid_levels = sorted(set(require_approval_levels) - RISK_LEVELS)
    if invalid_levels:
        raise PolicyError(
            "Unsupported require_approval_levels: "
            f"{', '.join(invalid_levels)}. Supported levels: {_format_allowed(RISK_LEVELS)}."
        )
    for index, waiver in enumerate(_require_waivers(policy)):
        _validate_waiver(waiver, index)
    return policy


def load_policy(policy_path: str | None, profile: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if policy_path:
        path = Path(policy_path)
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        data = loaded if isinstance(loaded, dict) else {}

    selected_profile = profile or data.get("profile")
    base = _profile_policy(selected_profile)
    if selected_profile in BUILTIN_PROFILES:
        data = {key: value for key, value in data.items() if key != "profile"}
    return validate_policy(_merge_policy(base, data))


def expand_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return validate_policy(_policy_with_profile(policy))


def _waiver_expired(waiver: dict[str, Any], today: date) -> bool:
    expires = waiver.get("expires")
    return bool(expires and date.fromisoformat(str(expires)) < today)


def _waiver_ref(waiver: dict[str, Any]) -> str:
    return str(waiver.get("id") or waiver.get("name") or waiver.get("finding_id") or waiver.get("rule_id"))


def _waiver_matches(finding: Finding, waiver: dict[str, Any]) -> bool:
    finding_id = waiver.get("finding_id") or waiver.get("rule_id")
    if finding_id and finding.id != finding_id:
        return False
    capability = waiver.get("capability")
    if capability and finding.capability != capability:
        return False
    server = waiver.get("server")
    if server and f".{server}." not in f".{finding.location}.":
        return False
    location = waiver.get("location")
    if location and str(location) not in finding.location:
        return False
    return True


def _policy_effect(finding: Finding, action: str, waiver: dict[str, Any]) -> PolicyEffect:
    return PolicyEffect(
        action=action,
        finding_id=finding.id,
        location=finding.location,
        reason=str(waiver.get("reason", "")),
        policy_ref=_waiver_ref(waiver),
    )


def _downgrade_finding(finding: Finding, waiver: dict[str, Any]) -> Finding:
    target = str(waiver.get("downgrade_to", "medium"))
    policy = DOWNGRADE_TARGETS[target]
    return finding.model_copy(
        update={
            "severity": target,
            "risk_level": policy["risk_level"],
            "risk_score": min(finding.risk_score, policy["risk_score"]),
            "policy_action": policy["policy_action"],
            "recommendation": f"{finding.recommendation} Downgraded by policy waiver.",
        }
    )


def apply_policy_with_effects(
    findings: list[Finding],
    policy: dict[str, Any],
    today: date | None = None,
) -> tuple[list[Finding], list[PolicyEffect]]:
    policy = expand_policy(policy)
    ignored = set(policy.get("ignore_finding_ids", []))
    deny_capabilities = set(policy.get("deny_capabilities", []))
    require_approval_levels = set(policy.get("require_approval_levels", []))
    waivers = _require_waivers(policy)
    current_date = today or date.today()
    out = []
    effects: list[PolicyEffect] = []

    for finding in findings:
        if finding.id in ignored:
            effects.append(
                PolicyEffect(
                    action="ignored",
                    finding_id=finding.id,
                    location=finding.location,
                    reason="Matched legacy ignore_finding_ids policy.",
                    policy_ref=finding.id,
                )
            )
            continue

        updated = finding
        ignored_by_waiver = False
        downgraded_by_waiver = False
        for waiver in waivers:
            if not _waiver_matches(updated, waiver):
                continue
            if _waiver_expired(waiver, current_date):
                effects.append(_policy_effect(updated, "expired", waiver))
                continue
            action = waiver.get("action", "ignore")
            if action == "ignore":
                effects.append(_policy_effect(updated, "ignored", waiver))
                ignored_by_waiver = True
                break
            updated = _downgrade_finding(updated, waiver)
            effects.append(_policy_effect(finding, "downgraded", waiver))
            downgraded_by_waiver = True
            break
        if ignored_by_waiver:
            continue
        if downgraded_by_waiver:
            out.append(updated)
            continue

        if updated.capability in deny_capabilities:
            updated = updated.model_copy(
                update={
                    "severity": "critical" if updated.risk_level == "L4" else "high",
                    "risk_score": max(updated.risk_score, 75),
                    "risk_level": "L4",
                    "policy_action": "deny",
                    "recommendation": (
                        f"{updated.recommendation} Policy denies capability "
                        f"{updated.capability}."
                    ),
                }
            )
        elif updated.risk_level in require_approval_levels and ACTION_RANK[updated.policy_action] < ACTION_RANK[
            "require_approval"
        ]:
            updated = updated.model_copy(update={"policy_action": "require_approval"})
        out.append(updated)
    return out, effects


def apply_policy(findings: list[Finding], policy: dict[str, Any]) -> list[Finding]:
    filtered, _ = apply_policy_with_effects(findings, policy)
    return filtered


def policy_fail_on(default_fail_on: str | None, policy: dict[str, Any]) -> str | None:
    policy = _policy_with_profile(policy)
    return validate_fail_on(policy.get("fail_on", default_fail_on))


def policy_allow_exec_commands(policy: dict[str, Any]) -> list[str]:
    policy = _policy_with_profile(policy)
    validate_policy(policy)
    return _require_string_list(policy, "allow_exec_commands")


def should_fail(max_severity: str, fail_on: str | None) -> bool:
    if not fail_on:
        return False
    validate_fail_on(fail_on)
    return SEV_RANK[max_severity] >= SEV_RANK[fail_on]


def render_default_policy() -> str:
    return DEFAULT_POLICY
