from __future__ import annotations

import json
from typing import Any

from postureck.compare import compare
from postureck.findings import Finding
from postureck.gate import failures
from postureck.policy import Detector, Exception_, Planted, Settings
from postureck.report import render_html, render_markdown, results_json

S = Settings("cis_7.0_aws", ("s3", "ec2"), "5.44.0", "localstack/localstack@sha256:abc")
P1 = Planted("P1", "public bucket", "2.1.4", "acme-public-assets", (Detector("prowler", "s3_public"),))
P6A = Planted("P6a", "open SSH", "5.2", "acme-legacy-admin", (Detector("prowler", "sg_open"),))
P6B = Planted("P6b", "default SG", "5.4", "default-sg", (Detector("postureck", "pc_sg_default"),))
PLANTED = (P1, P6A, P6B)
EXC = (Exception_("s3_logging", "acme-cloudtrail-logs", "log bucket would need its own log bucket", "platform"),)
B = "arn:aws:s3:::acme-public-assets"
G = "sg-1 acme-legacy-admin"
D = "sg-2 default-sg"


def f(check: str, resource: str, status: str = "FAIL", tool: str = "prowler", title: str = "t") -> Finding:
    return Finding(check, resource, status, "high", title, "s3", "us-east-1", tool, ("2.1.4",))


BEFORE = [f("s3_public", B), f("sg_open", G), f("pc_sg_default", D, tool="postureck")]
CLEAN_AFTER = [f("s3_public", B, "PASS"), f("sg_open", G, "PASS"), f("pc_sg_default", D, "PASS", "postureck")]


def build(after: list[Finding], before: list[Finding] = BEFORE, inventory: tuple[str, ...] = ()) -> dict[str, Any]:
    c = compare(before, after, PLANTED, EXC)
    data: dict[str, Any] = json.loads(results_json(c, PLANTED, EXC, S, inventory, {"run": "1"}))
    return data


def test_clean_run_passes():
    data = build(CLEAN_AFTER)
    assert failures(data) == []
    assert data["rates"] == {"detected": "2/2", "fixed": "2/2"}


def test_rates_group_parts_by_item_number():
    data = build([f("s3_public", B, "PASS"), f("sg_open", G), f("pc_sg_default", D, "PASS", "postureck")])
    # items 1 and 6; item 6 is fixed only when both 6a and 6b are
    assert data["rates"] == {"detected": "2/2", "fixed": "1/2"}


def test_undetected_message():
    data = build(
        CLEAN_AFTER, before=[f("s3_public", B, "PASS"), f("sg_open", G), f("pc_sg_default", D, tool="postureck")]
    )
    assert "planted flaw not detected: P1" in failures(data)


def test_still_failing_message():
    after = [f("s3_public", B, "PASS"), f("sg_open", G), f("pc_sg_default", D, "PASS", "postureck")]
    assert "planted flaw still failing after fix: P6a" in failures(build(after))


def test_unverified_message():
    after = [f("s3_public", B, "PASS"), f("sg_open", G, "PASS")]
    assert "planted flaw unverified after fix (detector silent): P6b" in failures(build(after))


def test_regression_message():
    after = [*CLEAN_AFTER, f("s3_public", "arn:aws:s3:::acme-cloudtrail-logs")]
    assert "regression: s3_public on arn:aws:s3:::acme-cloudtrail-logs" in failures(build(after))


def test_teardown_message():
    assert "teardown left: arn:aws:s3:::acme-customer-data" in failures(
        build(CLEAN_AFTER, inventory=("arn:aws:s3:::acme-customer-data",))
    )


def test_reports_escape_untrusted_text():
    after = [*CLEAN_AFTER, f("x", "arn:aws:s3:::evil<b>", title="<script>x</script> | pipe")]
    c = compare(BEFORE, after, PLANTED, EXC)
    args = (c, PLANTED, EXC, S, (), {"run": "1"})
    html, md = render_html(*args), render_markdown(*args)
    assert "<script>" not in html and "&lt;script&gt;" in html and "evil&lt;b&gt;" in html
    assert "\\| pipe" in md and "<script>" not in md and "&lt;script&gt;" in md


def test_report_names_versions_tools_and_exceptions():
    c = compare(BEFORE, CLEAN_AFTER, PLANTED, EXC)
    html = render_html(c, PLANTED, EXC, S, (), {"run": "42"})
    for text in ("cis_7.0_aws", "5.44.0", "localstack/localstack@sha256:abc", "postureck", "log bucket would need"):
        assert text in html


def test_results_json_is_deterministic():
    c = compare(BEFORE, CLEAN_AFTER, PLANTED, EXC)
    assert results_json(c, PLANTED, EXC, S, (), {"run": "1"}) == results_json(c, PLANTED, EXC, S, (), {"run": "1"})


def test_excepted_part_is_not_counted_as_fixed():
    exc = (*EXC, Exception_("s3_public", "acme-public-assets", "public website by design", "web team"))
    c = compare(BEFORE, CLEAN_AFTER, PLANTED, exc)
    data = json.loads(results_json(c, PLANTED, exc, S, (), {"run": "1"}))
    assert data["rates"] == {"detected": "2/2", "fixed": "1/2"}
