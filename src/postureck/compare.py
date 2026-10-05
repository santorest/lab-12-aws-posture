"""Compare the audits before and after the remediation: planted flaws, regressions, open findings, counts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from postureck.findings import AuditError, Finding
from postureck.policy import Exception_, Planted


@dataclass(frozen=True)
class ItemResult:
    id: str
    detected: bool
    after: str  # fixed | failing | excepted | unverified


@dataclass(frozen=True)
class Comparison:
    items: tuple[ItemResult, ...]
    regressions: tuple[Finding, ...]
    open_failing: tuple[Finding, ...]
    counts_before: dict[str, int]
    counts_after: dict[str, int]
    cis_before: dict[str, int]
    cis_after: dict[str, int]


def validate(findings: Sequence[Finding], services: Sequence[str], phase: str) -> None:
    """An audit that produced nothing for a deployed service did not really audit it."""
    seen = {f.service for f in findings}
    missing = [s for s in services if s not in seen]
    if missing:
        raise AuditError(f"{phase} audit: no finding from any tool for deployed service(s) {', '.join(missing)}")


def _matches(f: Finding, item: Planted) -> bool:
    return any(d.tool == f.tool and d.check_id == f.check_id for d in item.detectors) and (
        item.resource_match in f.resource
    )


def _covered(f: Finding, exceptions: Sequence[Exception_]) -> bool:
    return any(e.check_id == f.check_id and e.resource_match in f.resource for e in exceptions)


def _item(item: Planted, before: Sequence[Finding], after: Sequence[Finding], exc: Sequence[Exception_]) -> ItemResult:
    detected = any(f.status == "FAIL" and _matches(f, item) for f in before)
    checks = {d.check_id for d in item.detectors}
    if any(e.check_id in checks and e.resource_match in item.resource_match for e in exc):
        state = "excepted"
    elif any(f.status == "FAIL" and _matches(f, item) for f in after):
        state = "failing"
    elif not any(f.check_id in checks and f.status in ("PASS", "FAIL") for f in after):
        state = "unverified"
    else:
        state = "fixed"
    return ItemResult(item.id, detected, state)


def _counts(findings: Sequence[Finding]) -> tuple[dict[str, int], dict[str, int]]:
    failing = [f for f in findings if f.status == "FAIL"]
    severity = Counter(f.severity for f in failing)
    cis = Counter(f.cis[0].split(".")[0] for f in failing if f.cis)
    return dict(severity), dict(cis)


def compare(
    before: Sequence[Finding],
    after: Sequence[Finding],
    planted: Sequence[Planted],
    exceptions: Sequence[Exception_],
) -> Comparison:
    failed_before = {f.key for f in before if f.status == "FAIL"}
    failing_after = [f for f in after if f.status == "FAIL"]
    regressions = tuple(
        sorted(
            (f for f in failing_after if f.key not in failed_before and not _covered(f, exceptions)),
            key=lambda f: f.key,
        )
    )
    open_failing = tuple(
        sorted(
            (
                f
                for f in failing_after
                if f.key in failed_before and not _covered(f, exceptions) and not any(_matches(f, p) for p in planted)
            ),
            key=lambda f: f.key,
        )
    )
    counts_before, cis_before = _counts(before)
    counts_after, cis_after = _counts(after)
    return Comparison(
        items=tuple(_item(p, before, after, exceptions) for p in planted),
        regressions=regressions,
        open_failing=open_failing,
        counts_before=counts_before,
        counts_after=counts_after,
        cis_before=cis_before,
        cis_after=cis_after,
    )
