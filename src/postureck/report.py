"""results.json (for the gate), a Markdown summary and an HTML report. Escaped and deterministic."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from postureck.compare import Comparison, ItemResult
from postureck.findings import Finding
from postureck.policy import Exception_, Planted, Settings

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def md(text: str) -> str:
    """One Markdown table cell: no raw HTML, no pipe or newline that breaks the row."""
    out = text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return out.replace("<", "&lt;").replace(">", "&gt;")


def _number(item_id: str) -> str:
    m = re.match(r"P(\d+)", item_id)
    return m.group(1) if m else item_id


def _rates(items: Sequence[ItemResult]) -> dict[str, str]:
    groups: dict[str, list[ItemResult]] = {}
    for i in items:
        groups.setdefault(_number(i.id), []).append(i)
    detected = sum(all(p.detected for p in parts) for parts in groups.values())
    # the spec's fix rate counts items that pass after the fix; an excepted part does not pass
    fixed = sum(all(p.after == "fixed" for p in parts) for parts in groups.values())
    return {"detected": f"{detected}/{len(groups)}", "fixed": f"{fixed}/{len(groups)}"}


def _finding(f: Finding) -> dict[str, str]:
    return {"check_id": f.check_id, "resource": f.resource, "severity": f.severity, "title": f.title, "tool": f.tool}


def _tools(p: Planted) -> str:
    return ", ".join(sorted({d.tool for d in p.detectors}))


def results_json(
    c: Comparison,
    planted: Sequence[Planted],
    exceptions: Sequence[Exception_],
    s: Settings,
    inventory: Sequence[str],
    meta: Mapping[str, str],
) -> str:
    by_id = {p.id: p for p in planted}
    data: dict[str, Any] = {
        "items": [
            {
                "id": i.id,
                "title": by_id[i.id].title,
                "cis": by_id[i.id].cis,
                "tools": _tools(by_id[i.id]),
                "detected": i.detected,
                "after": i.after,
            }
            for i in c.items
        ],
        "rates": _rates(c.items),
        "regressions": [_finding(f) for f in c.regressions],
        "open_failing": [_finding(f) for f in c.open_failing],
        "counts": {"before": c.counts_before, "after": c.counts_after},
        "cis": {"before": c.cis_before, "after": c.cis_after},
        "exceptions": [
            {"check_id": e.check_id, "resource_match": e.resource_match, "reason": e.reason, "owner_role": e.owner_role}
            for e in exceptions
        ],
        "inventory_left": list(inventory),
        "settings": {
            "framework": s.framework,
            "services": list(s.services),
            "prowler_version": s.prowler_version,
            "localstack_image": s.localstack_image,
        },
        "meta": dict(meta),
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _severity_rows(c: Comparison) -> list[tuple[str, int, int]]:
    keys = [k for k in SEVERITY_ORDER if k in c.counts_before or k in c.counts_after]
    return [(k, c.counts_before.get(k, 0), c.counts_after.get(k, 0)) for k in keys]


def _cis_rows(c: Comparison) -> list[tuple[str, int, int]]:
    keys = sorted(set(c.cis_before) | set(c.cis_after), key=lambda k: (len(k), k))
    return [(k, c.cis_before.get(k, 0), c.cis_after.get(k, 0)) for k in keys]


def render_markdown(
    c: Comparison,
    planted: Sequence[Planted],
    exceptions: Sequence[Exception_],
    s: Settings,
    inventory: Sequence[str],
    meta: Mapping[str, str],
) -> str:
    by_id = {p.id: p for p in planted}
    rates = _rates(c.items)
    lines = [
        "## AWS posture audit (emulated: LocalStack)",
        "",
        " · ".join(f"{md(k)} {md(v)}" for k, v in sorted(meta.items()))
        + f" · {md(s.framework)} · Prowler {md(s.prowler_version)} · {md(s.localstack_image)}",
        "",
        f"Planted misconfigurations detected before the fix: **{rates['detected']}** · "
        f"fixed after: **{rates['fixed']}** · regressions: **{len(c.regressions)}** · "
        f"resources left after teardown: **{len(inventory)}**",
        "",
        "| Item | Misconfiguration | CIS | Detected | After the fix | Tool |",
        "|---|---|---|---|---|---|",
    ]
    for i in c.items:
        p = by_id[i.id]
        lines.append(
            f"| {md(i.id)} | {md(p.title)} | {md(p.cis)} | {'yes' if i.detected else 'NO'} | {md(i.after)} "
            f"| {md(_tools(p))} |"
        )
    lines += ["", "| Severity (failing) | Before | After |", "|---|---|---|"]
    lines += [f"| {k} | {b} | {a} |" for k, b, a in _severity_rows(c)]
    lines += ["", "| CIS section (failing) | Before | After |", "|---|---|---|"]
    lines += [f"| {md(k)} | {b} | {a} |" for k, b, a in _cis_rows(c)]
    for heading, findings in (("Regressions", c.regressions), ("Open (failing before and after)", c.open_failing)):
        lines += ["", f"### {heading}", ""]
        if findings:
            lines += ["| Check | Resource | Severity | Title | Tool |", "|---|---|---|---|---|"]
            lines += [
                f"| {md(f.check_id)} | {md(f.resource)} | {md(f.severity)} | {md(f.title)} | {md(f.tool)} |"
                for f in findings
            ]
        else:
            lines.append("None.")
    lines += ["", "### Documented exceptions", ""]
    if exceptions:
        lines += ["| Check | Resource | Reason | Owner |", "|---|---|---|---|"]
        lines += [
            f"| {md(e.check_id)} | {md(e.resource_match)} | {md(e.reason)} | {md(e.owner_role)} |" for e in exceptions
        ]
    else:
        lines.append("None.")
    lines += ["", "### Teardown", "", "Nothing left." if not inventory else ", ".join(md(r) for r in inventory)]
    return "\n".join(lines) + "\n"


def render_html(
    c: Comparison,
    planted: Sequence[Planted],
    exceptions: Sequence[Exception_],
    s: Settings,
    inventory: Sequence[str],
    meta: Mapping[str, str],
) -> str:
    e = html.escape
    by_id = {p.id: p for p in planted}
    rates = _rates(c.items)

    def table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
        head = "".join(f"<th>{e(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{e(str(v))}</td>" for v in row) + "</tr>" for row in rows)
        return f"<table><tr>{head}</tr>{body}</table>" if rows else "<p>None.</p>"

    def findings(fs: Sequence[Finding]) -> str:
        return table(
            ("Check", "Resource", "Severity", "Title", "Tool"),
            [(f.check_id, f.resource, f.severity, f.title, f.tool) for f in fs],
        )

    items = [
        (i.id, by_id[i.id].title, by_id[i.id].cis, "yes" if i.detected else "NO", i.after, _tools(by_id[i.id]))
        for i in c.items
    ]
    meta_line = " · ".join(f"{e(k)} {e(v)}" for k, v in sorted(meta.items()))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AWS posture audit</title>'
        "<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;margin:1rem 0}"
        "td,th{border:1px solid #999;padding:.3rem .6rem;text-align:left}</style></head><body>"
        "<h1>AWS posture audit (emulated: LocalStack)</h1>"
        f"<p>{meta_line} · {e(s.framework)} · Prowler {e(s.prowler_version)} · {e(s.localstack_image)}</p>"
        f"<p>Planted misconfigurations detected before the fix: <b>{e(rates['detected'])}</b> · fixed after: "
        f"<b>{e(rates['fixed'])}</b> · regressions: <b>{len(c.regressions)}</b> · resources left after teardown: "
        f"<b>{len(inventory)}</b></p>"
        "<h2>Planted misconfigurations</h2>"
        + table(("Item", "Misconfiguration", "CIS", "Detected", "After the fix", "Tool"), items)
        + "<h2>Failing findings by severity</h2>"
        + table(("Severity", "Before", "After"), _severity_rows(c))
        + "<h2>Failing findings by CIS section</h2>"
        + table(("CIS section", "Before", "After"), _cis_rows(c))
        + "<h2>Regressions</h2>"
        + findings(c.regressions)
        + "<h2>Open (failing before and after)</h2>"
        + findings(c.open_failing)
        + "<h2>Documented exceptions</h2>"
        + table(
            ("Check", "Resource", "Reason", "Owner"),
            [(x.check_id, x.resource_match, x.reason, x.owner_role) for x in exceptions],
        )
        + "<h2>Teardown</h2>"
        + ("<p>Nothing left.</p>" if not inventory else table(("Resource left",), [(r,) for r in inventory]))
        + "</body></html>\n"
    )
