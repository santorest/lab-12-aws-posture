"""One finding from either tool, keyed by (check id, resource)."""

from __future__ import annotations

from dataclasses import dataclass

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
