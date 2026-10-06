"""postureck command line. Exit codes: 0 ok, 1 gate failed, 2 the audit did not really happen or bad input."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from postureck.checks import run_checks, session_for
from postureck.compare import compare, validate
from postureck.findings import AuditError, Finding, dump_findings, load_findings
from postureck.gate import failures
from postureck.inventory import inventory
from postureck.policy import ConfigError, load_exceptions, load_planted, load_settings
from postureck.prowler import parse_prowler
from postureck.report import render_html, render_markdown, results_json


def _resources(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(r, str) for r in data):
        raise AuditError(f"{path}: expected a list of resource ids")
    return data


def _check(args: argparse.Namespace) -> None:
    planted = load_planted(args.policy_dir / "misconfigs.yml")
    names = sorted({d.check_id for p in planted for d in p.detectors if d.tool == "postureck"})
    args.out.write_text(dump_findings(run_checks(session_for(args.endpoint), names)), encoding="utf-8")


def _inventory(args: argparse.Namespace) -> None:
    args.out.write_text(json.dumps(inventory(session_for(args.endpoint)), indent=1) + "\n", encoding="utf-8")


def _phase(prowler: Path, own: Path, framework: str, services: Sequence[str], phase: str) -> list[Finding]:
    findings = parse_prowler(prowler.read_bytes(), framework) + load_findings(own.read_bytes())
    validate(findings, services, phase)
    return findings


def _report(args: argparse.Namespace) -> None:
    d = args.policy_dir
    planted, exceptions, settings = (
        load_planted(d / "misconfigs.yml"),
        load_exceptions(d / "exceptions.yml"),
        load_settings(d / "policy.yml"),
    )
    before = _phase(args.before_prowler, args.before_own, settings.framework, settings.services, "before")
    after = _phase(args.after_prowler, args.after_own, settings.framework, settings.services, "after")
    left = sorted(set(_resources(args.inventory)) - set(_resources(args.baseline)))
    meta = dict(pair.split("=", 1) for pair in args.meta)
    call = (compare(before, after, planted, exceptions), planted, exceptions, settings, left, meta)
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(results_json(*call), encoding="utf-8")
    (out / "summary.md").write_text(render_markdown(*call), encoding="utf-8")
    (out / "report.html").write_text(render_html(*call), encoding="utf-8")


def _gate(args: argparse.Namespace) -> int:
    msgs = failures(json.loads(args.results.read_text(encoding="utf-8")))
    for m in msgs:
        print(m)
    if not msgs:
        print("gate passed")
    return 1 if msgs else 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="postureck")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("check", help="run the fallback checks named in misconfigs.yml")
    s.add_argument("--endpoint", required=True)
    s.add_argument("--policy-dir", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("inventory", help="list the resources that exist (teardown check)")
    s.add_argument("--endpoint", required=True)
    s.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("report", help="compare the audits and write results.json, summary.md, report.html")
    for name in ("--policy-dir", "--before-prowler", "--before-own", "--after-prowler", "--after-own", "--baseline",
                 "--inventory", "--out-dir"):  # fmt: skip
        s.add_argument(name, type=Path, required=True)
    s.add_argument("--meta", nargs="*", default=[])
    s = sub.add_parser("gate", help="fail on the gate conditions in results.json")
    s.add_argument("--results", type=Path, required=True)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "gate":
            return _gate(args)
        {"check": _check, "inventory": _inventory, "report": _report}[args.command](args)
    except (AuditError, ConfigError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
