"""One finding from either tool, keyed by (check id, resource)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass

STATUSES = ("PASS", "FAIL", "MANUAL")
SEVERITIES = ("critical", "high", "medium", "low", "informational")


class AuditError(Exception):
    """The audit did not really happen: no output, unreadable output, or a deployed service with no finding."""


@dataclass(frozen=True)
class Finding:
    check_id: str
    resource: str
    status: str
    severity: str
    title: str
    service: str
    region: str
    tool: str
    cis: tuple[str, ...]
    labels: tuple[str, ...] = ()  # resource tags as "Key:Value" (Prowler OCSF labels)

    @property
    def key(self) -> tuple[str, str]:
        return (self.check_id, self.resource)


def dump_findings(findings: Sequence[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=1, sort_keys=True) + "\n"


def load_findings(data: bytes) -> list[Finding]:
    """Findings written by dump_findings (the fallback checks' output)."""
    try:
        raw = json.loads(data)
        if not isinstance(raw, list):
            raise TypeError("not a list")
        out = [Finding(**{**r, "cis": tuple(r.get("cis", ())), "labels": tuple(r.get("labels", ()))}) for r in raw]
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise AuditError(f"findings file is not valid: {exc}") from exc
    for f in out:
        if f.status not in STATUSES:
            raise AuditError(f"findings file: {f.check_id}: unknown status {f.status!r}")
    return out
