from __future__ import annotations

import pytest

from postureck.compare import compare, validate
from postureck.findings import AuditError, Finding
from postureck.policy import Detector, Exception_, Planted

SG = Planted(
    "P6a",
    "open admin ports",
    "5.2",
    "acme-legacy-admin",
    (Detector("prowler", "sg_ssh_open"), Detector("postureck", "pc_sg_admin_ports")),
)
BUCKET = Planted("P1", "public bucket", "2.1.4", "acme-public-assets", (Detector("prowler", "s3_public"),))
SG_ARN = "arn:aws:ec2:us-east-1:000000000000:security-group/sg-1 acme-legacy-admin"
BUCKET_ARN = "arn:aws:s3:::acme-public-assets"


def f(
    check: str,
    resource: str,
    status: str = "FAIL",
    tool: str = "prowler",
    severity: str = "high",
    service: str = "ec2",
    cis: tuple[str, ...] = ("5.2",),
) -> Finding:
    return Finding(check, resource, status, severity, f"title {check}", service, "us-east-1", tool, cis)


def test_planted_item_detected_and_fixed():
    c = compare([f("sg_ssh_open", SG_ARN)], [f("sg_ssh_open", SG_ARN, "PASS")], [SG], [])
    (item,) = c.items
    assert (item.id, item.detected, item.after) == ("P6a", True, "fixed")


def test_undetected_planted_flaw_gates():
    c = compare([f("sg_ssh_open", SG_ARN, "PASS")], [f("sg_ssh_open", SG_ARN, "PASS")], [SG], [])
    assert c.items[0].detected is False


def test_detector_silent_after_fix_is_unverified():
    c = compare([f("sg_ssh_open", SG_ARN)], [f("other_check", SG_ARN, "PASS")], [SG], [])
    assert c.items[0].after == "unverified"


def test_failing_after_fix():
    c = compare([f("sg_ssh_open", SG_ARN)], [f("sg_ssh_open", SG_ARN)], [SG], [])
    assert c.items[0].after == "failing"


def test_fail_from_fallback_counts_for_planted_item():
    before = [f("pc_sg_admin_ports", SG_ARN, tool="postureck"), f("sg_ssh_open", SG_ARN, "PASS")]
    after = [f("pc_sg_admin_ports", SG_ARN, tool="postureck"), f("sg_ssh_open", SG_ARN, "PASS")]
    (item,) = compare(before, after, [SG], []).items
    assert item.detected is True and item.after == "failing"


def test_detector_must_match_tool_too():
    # a prowler finding with the fallback's check id is not that detector
    c = compare([f("pc_sg_admin_ports", SG_ARN, tool="prowler")], [], [SG], [])
    assert c.items[0].detected is False


def test_exception_marks_item_excepted():
    exc = Exception_("s3_public", "acme-public-assets", "website bucket", "web team")
    c = compare([f("s3_public", BUCKET_ARN, service="s3")], [f("s3_public", BUCKET_ARN, service="s3")], [BUCKET], [exc])
    assert c.items[0].after == "excepted" and c.regressions == ()


def test_new_failure_is_a_regression_even_when_totals_fall():
    before = [f("a", "r1"), f("b", "r2"), f("c", "r3")]
    after = [f("a", "r1", "PASS"), f("b", "r2", "PASS"), f("c", "r3", "PASS"), f("d", "r4")]
    c = compare(before, after, [], [])
    assert [(x.check_id, x.resource) for x in c.regressions] == [("d", "r4")]


def test_pass_to_fail_is_a_regression():
    c = compare([f("a", "r1", "PASS")], [f("a", "r1")], [], [])
    assert len(c.regressions) == 1


def test_excepted_new_failure_is_not_a_regression():
    exc = Exception_("logging", "trail-bucket", "log bucket", "platform")
    c = compare([], [f("logging", "arn:aws:s3:::trail-bucket")], [], [exc])
    assert c.regressions == ()


def test_open_failing_excludes_planted():
    before = [f("sg_ssh_open", SG_ARN), f("x", "r9")]
    after = [f("sg_ssh_open", SG_ARN), f("x", "r9")]
    c = compare(before, after, [SG], [])
    assert [x.check_id for x in c.open_failing] == ["x"]


def test_manual_counts_nowhere():
    c = compare([f("a", "r1", "MANUAL")], [f("a", "r1", "MANUAL"), f("b", "r2", "MANUAL")], [], [])
    assert c.regressions == () and c.counts_after == {}


def test_counts_by_severity_and_cis():
    before = [
        f("a", "r1", severity="high", cis=("5.2",)),
        f("b", "r2", severity="low", cis=("2.1.4", "2.1.1")),
        f("c", "r3", "PASS"),
    ]
    c = compare(before, [], [], [])
    assert c.counts_before == {"high": 1, "low": 1}
    assert c.cis_before == {"5": 1, "2": 1}


def test_deployed_service_without_findings_is_an_error():
    with pytest.raises(AuditError, match=r"before.*iam|iam.*before"):
        validate([f("s3_public", BUCKET_ARN, service="s3")], ["s3", "iam"], "before")


def test_empty_audit_is_an_error():
    with pytest.raises(AuditError):
        validate([], ["s3"], "after")


def test_validate_passes_with_every_service():
    validate([f("s3_public", BUCKET_ARN, service="s3"), f("x", "u", service="iam")], ["s3", "iam"], "after")


def test_planted_item_matches_by_name_label():
    # security groups, VPCs and keys have random ids; Prowler shows their Name tag as a label
    sg_arn = "arn:aws:ec2:us-east-1:000000000000:security-group/sg-0d1d"
    tagged = Finding(
        "sg_ssh_open", sg_arn, "FAIL", "high", "t", "ec2", "us-east-1", "prowler", (), ("Name:acme-legacy-admin",)
    )
    other = Finding(
        "sg_ssh_open", sg_arn + "x", "FAIL", "high", "t", "ec2", "us-east-1", "prowler", (), ("Name:other",)
    )
    assert compare([tagged], [], [SG], []).items[0].detected is True
    assert compare([other], [], [SG], []).items[0].detected is False


def test_exception_matches_by_name_label():
    exc = Exception_("vpc_endpoint", "acme-vpc", "no private endpoints in a lab VPC", "platform")
    vpc = Finding(
        "vpc_endpoint",
        "arn:aws:ec2:us-east-1:0:vpc/vpc-1",
        "FAIL",
        "low",
        "t",
        "vpc",
        "us-east-1",
        "prowler",
        (),
        ("Name:acme-vpc",),
    )
    assert compare([], [vpc], [], [exc]).regressions == ()
