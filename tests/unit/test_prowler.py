from __future__ import annotations

import json
from pathlib import Path

import pytest

from postureck.findings import AuditError, Finding
from postureck.prowler import parse_prowler

F = Path(__file__).parent / "fixtures"
KEY = "CIS-7.0"


def load(name: str = "prowler-before.ocsf.json") -> bytes:
    return (F / name).read_bytes()


def test_parses_fixture():
    findings = parse_prowler(load(), KEY)
    assert len(findings) == 7
    bucket = next(f for f in findings if f.check_id == "s3_bucket_level_public_access_block")
    assert bucket == Finding(
        check_id="s3_bucket_level_public_access_block",
        resource="arn:aws:s3:::acme-public-assets",
        status="FAIL",
        severity="high",
        title=bucket.title,
        service="s3",
        region="us-east-1",
        tool="prowler",
        cis=("3.1.4",),
        labels=(),
    )
    sg = next(f for f in findings if f.check_id.startswith("ec2_securitygroup"))
    assert sg.labels == ("Name:acme-legacy-admin",) and sg.cis == ("6.3", "6.4")
    assert {f.service for f in findings} == {"s3", "iam", "ec2", "vpc", "kms"}


def test_missing_framework_gives_empty_cis():
    assert all(f.cis == () for f in parse_prowler(load(), "CIS-9.9"))


def _broken(mutate) -> bytes:
    records = json.loads(load())
    mutate(records)
    return json.dumps(records).encode()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b"{}",
        b"[]",
        b'[{"truncated": ',
        _broken(lambda r: r[0]["metadata"].pop("event_code")),
        _broken(lambda r: r[0].pop("resources")),
        _broken(lambda r: r[0]["resources"].clear()),
    ],
)
def test_empty_or_invalid_output_is_an_error(data: bytes):
    with pytest.raises(AuditError):
        parse_prowler(data, KEY)


def test_unknown_status_is_an_error():
    def weird(records):
        records[0]["status_code"] = "WEIRD"

    with pytest.raises(AuditError, match="WEIRD"):
        parse_prowler(_broken(weird), KEY)


def test_manual_status_is_kept():
    def manual(records):
        records[0]["status_code"] = "MANUAL"

    assert parse_prowler(_broken(manual), KEY)[0].status == "MANUAL"
