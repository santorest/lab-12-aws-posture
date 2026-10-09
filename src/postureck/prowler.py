"""Read Prowler's OCSF JSON output: one Finding per record, with the CIS ids of the chosen framework."""

from __future__ import annotations

import json
from typing import Any

from postureck.findings import STATUSES, AuditError, Finding


def _labels(raw: Any) -> tuple[str, ...]:
    """Tags as "Key:Value": EC2 records carry that form, KMS records a "TagKey:<k>", "TagValue:<v>" pair instead."""
    out: list[str] = []
    key = None
    for label in (str(x) for x in raw or ()):
        if label.startswith("TagKey:"):
            key = label.removeprefix("TagKey:")
        elif label.startswith("TagValue:") and key is not None:
            out.append(f"{key}:{label.removeprefix('TagValue:')}")
            key = None
        else:
            out.append(label)
    return tuple(out)


def _record(r: Any, framework_key: str) -> Finding:
    if not isinstance(r, dict):
        raise AuditError("Prowler output: a record is not an object")
    try:
        check_id = r["metadata"]["event_code"]
        resource = r["resources"][0]
        uid = resource["uid"]
        status = r["status_code"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AuditError(f"Prowler output: record without {exc}") from exc
    if not isinstance(check_id, str) or not check_id or not isinstance(uid, str) or not uid:
        raise AuditError("Prowler output: record without a check id or resource")
    if status not in STATUSES:
        raise AuditError(f"Prowler output: {check_id}: unknown status {status!r}")
    region = resource.get("region") or (r.get("cloud") or {}).get("region") or ""
    compliance = (r.get("unmapped") or {}).get("compliance") or {}
    return Finding(
        check_id=check_id,
        resource=uid,
        status=status,
        severity=str(r.get("severity") or "").lower(),
        title=str((r.get("finding_info") or {}).get("title") or ""),
        service=str((resource.get("group") or {}).get("name") or ""),
        region=str(region),
        tool="prowler",
        cis=tuple(str(c) for c in compliance.get(framework_key) or ()),
        labels=_labels(resource.get("labels")),
    )


def parse_prowler(data: bytes, framework_key: str) -> list[Finding]:
    """framework_key is the compliance key in the OCSF records, e.g. "CIS-7.0"."""
    try:
        records = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuditError(f"Prowler output is not JSON: {exc}") from exc
    if not isinstance(records, list) or not records:
        raise AuditError("Prowler output has no findings")
    return [_record(r, framework_key) for r in records]
