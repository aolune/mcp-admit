from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml

from mcp_admit.models import ApprovalDecision, ApprovalRecord


class ApprovalError(ValueError):
    pass


def _records_from_data(data: dict[str, Any]) -> list[ApprovalRecord]:
    raw_records = data.get("approvals", [])
    if not isinstance(raw_records, list):
        raise ApprovalError("Approval registry field approvals must be a list.")
    records = [
        ApprovalRecord.model_validate(record)
        for record in raw_records
        if isinstance(record, dict)
    ]
    for record in records:
        if record.status != "approved":
            continue
        if not record.approved_by.strip():
            raise ApprovalError(f"Approval {record.id} must include approved_by.")
        if not record.reason.strip():
            raise ApprovalError(f"Approval {record.id} must include a non-empty reason.")
        if not record.expires:
            raise ApprovalError(f"Approval {record.id} must include an expiry date.")
        try:
            date.fromisoformat(record.expires)
        except ValueError as exc:
            raise ApprovalError(
                f"Approval {record.id} expires must be an ISO date string."
            ) from exc
    return records


def load_approval_records(path: str | None) -> list[ApprovalRecord]:
    if not path:
        return []
    registry = Path(path)
    if not registry.exists():
        raise ApprovalError(f"Approval registry does not exist: {registry}")
    loaded = yaml.safe_load(registry.read_text(encoding="utf-8"))
    if loaded is None:
        return []
    if not isinstance(loaded, dict):
        raise ApprovalError("Approval registry must be a YAML object.")
    return _records_from_data(loaded)


def _matches(record: ApprovalRecord, *, client: str, source: str, name: str) -> bool:
    if record.name != name:
        return False
    if record.client and record.client != client:
        return False
    if record.source and record.source != source:
        return False
    return True


def _specificity(record: ApprovalRecord) -> int:
    return int(bool(record.source)) + int(bool(record.client))


def decide_approval(
    *,
    records: list[ApprovalRecord],
    client: str,
    source: str,
    name: str,
    definition_hash: str,
    capabilities: list[str],
    today: date | None = None,
) -> ApprovalDecision:
    if not records:
        return ApprovalDecision(status="unknown", reason="No approval registry provided.")
    matches = [
        record
        for record in records
        if _matches(record, client=client, source=source, name=name)
    ]
    if not matches:
        return ApprovalDecision(status="unknown", reason="No matching approval record.")

    record = sorted(matches, key=_specificity, reverse=True)[0]
    if record.status == "pending":
        return ApprovalDecision(
            status="pending",
            approval_id=record.id,
            reason="Approval record is pending explicit human review.",
        )
    current_date = today or date.today()
    if record.expires:
        try:
            expires = date.fromisoformat(record.expires)
        except ValueError as exc:
            raise ApprovalError(f"Approval {record.id} expires must be an ISO date string.") from exc
        if expires < current_date:
            return ApprovalDecision(
                status="expired",
                approval_id=record.id,
                reason=f"Approval expired on {record.expires}.",
            )
    if record.definition_hash != definition_hash:
        return ApprovalDecision(
            status="drifted",
            approval_id=record.id,
            reason="Server definition hash changed since approval.",
        )
    allowed = set(record.allowed_capabilities)
    current = set(capabilities)
    if not current <= allowed:
        extra = ", ".join(sorted(current - allowed))
        return ApprovalDecision(
            status="drifted",
            approval_id=record.id,
            reason=f"Server capabilities exceed approval: {extra}.",
        )
    return ApprovalDecision(
        status="approved",
        approval_id=record.id,
        reason=record.reason,
    )


def render_approval_registry(records: list[ApprovalRecord]) -> str:
    data = {
        "version": 1,
        "approvals": [record.model_dump() for record in records],
    }
    return yaml.safe_dump(data, sort_keys=False)


def upsert_approval_record(
    records: list[ApprovalRecord],
    record: ApprovalRecord,
) -> list[ApprovalRecord]:
    updated = [existing for existing in records if existing.id != record.id]
    updated.append(record)
    return sorted(updated, key=lambda item: item.id)
