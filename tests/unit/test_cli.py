from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from postureck import cli
from postureck.findings import AuditError, Finding, dump_findings, load_findings

F = Path(__file__).parent / "fixtures"
POLICY = F / "policy-dir"


def report_args(
    out: Path,
    after_own: str = "own-after.json",
    inventory: str = "inventory-empty.json",
    before_prowler: str = "prowler-before.ocsf.json",
) -> list[str]:
    return [
        "report", "--policy-dir", str(POLICY),
        "--before-prowler", str(F / before_prowler), "--before-own", str(F / "own-before.json"),
        "--after-prowler", str(F / "prowler-after.ocsf.json"), "--after-own", str(F / after_own),
        "--baseline", str(F / "inventory-empty.json"), "--inventory", str(F / inventory),
        "--out-dir", str(out), "--meta", "run=7",
    ]  # fmt: skip


def test_report_then_gate_passes_on_a_clean_run(tmp_path: Path):
    assert cli.main(report_args(tmp_path)) == 0
    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert data["rates"] == {"detected": "3/3", "fixed": "3/3"} and data["meta"] == {"run": "7"}
    assert (tmp_path / "summary.md").exists() and (tmp_path / "report.html").exists()
    assert cli.main(["gate", "--results", str(tmp_path / "results.json")]) == 0


def test_gate_fails_when_a_planted_flaw_survives(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert cli.main(report_args(tmp_path, after_own="own-before.json")) == 0
    assert cli.main(["gate", "--results", str(tmp_path / "results.json")]) == 1
    assert "planted flaw still failing after fix: P4a" in capsys.readouterr().out


def test_resources_left_after_teardown_fail_the_gate(tmp_path: Path):
    left = tmp_path / "left.json"
    left.write_text('["arn:aws:s3:::acme-customer-data"]', encoding="utf-8")
    assert cli.main(report_args(tmp_path, inventory=str(left))) == 0
    assert cli.main(["gate", "--results", str(tmp_path / "results.json")]) == 1


def test_missing_file_exits_2(tmp_path: Path):
    assert cli.main(report_args(tmp_path, after_own="nope.json")) == 2


def test_empty_prowler_output_exits_2(tmp_path: Path):
    empty = tmp_path / "empty.ocsf.json"
    empty.write_text("[]", encoding="utf-8")
    assert cli.main(report_args(tmp_path, before_prowler=str(empty))) == 2


def test_deployed_service_missing_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    only_s3 = [r for r in json.loads((F / "prowler-before.ocsf.json").read_text(encoding="utf-8"))
               if r["resources"][0]["group"]["name"] == "s3"]  # fmt: skip
    path = tmp_path / "s3-only.ocsf.json"
    path.write_text(json.dumps(only_s3), encoding="utf-8")
    assert cli.main(report_args(tmp_path, before_prowler=str(path))) == 2
    assert "before audit" in capsys.readouterr().err


def test_findings_round_trip_and_bad_files():
    f = Finding("c", "r", "FAIL", "high", "t", "iam", "us-east-1", "postureck", ("2.10",), ("Name:x",))
    assert load_findings(dump_findings([f]).encode()) == [f]
    for bad in (b"", b"{}", b'[{"check_id": "c"}]', b'[{"check_id": "c", "status": "NOPE"}]'):
        with pytest.raises(AuditError):
            load_findings(bad)


@pytest.fixture
def emulated() -> Iterator[None]:
    with mock_aws():
        yield


def test_check_and_inventory_commands(tmp_path: Path, emulated: None, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cli, "session_for", lambda endpoint: boto3.Session(region_name="us-east-1"))
    boto3.client("iam", region_name="us-east-1").create_user(UserName="svc-deploy")
    boto3.client("iam", region_name="us-east-1").create_access_key(UserName="svc-deploy")
    out = tmp_path / "own.json"
    assert cli.main(["check", "--endpoint", "http://x", "--policy-dir", str(POLICY), "--out", str(out)]) == 0
    (finding,) = load_findings(out.read_bytes())
    assert finding.status == "FAIL" and finding.tool == "postureck"
    inv = tmp_path / "inv.json"
    assert cli.main(["inventory", "--endpoint", "http://x", "--out", str(inv)]) == 0
    assert any(r.endswith(":user/svc-deploy") for r in json.loads(inv.read_text(encoding="utf-8")))
