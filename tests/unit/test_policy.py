from __future__ import annotations

from pathlib import Path

import pytest

from postureck.policy import ConfigError, Detector, load_exceptions, load_planted, load_settings

F = Path(__file__).parent / "fixtures"


def test_loads_fixture_files():
    planted = load_planted(F / "misconfigs.yml")
    assert [p.id for p in planted] == ["P1", "P6a"]
    sg = planted[1]
    assert sg.resource_match == "acme-legacy-admin" and sg.cis == "5.2"
    assert sg.detectors[1] == Detector("postureck", "pc_sg_admin_ports")
    (exc,) = load_exceptions(F / "exceptions.yml")
    assert exc.check_id == "s3_bucket_server_access_logging_enabled" and exc.owner_role == "cloud platform team"
    s = load_settings(F / "policy.yml")
    assert s.framework == "cis_7.0_aws" and s.services == ("s3", "iam", "cloudtrail", "ec2", "kms")
    assert s.prowler_version == "5.44.0"


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "f.yml"
    p.write_text(text, encoding="utf-8")
    return p


PLANTED = "planted:\n  - {id: P1, title: t, cis: '1', resource_match: r, detectors: [{tool: prowler, check_id: c}]}\n"


@pytest.mark.parametrize(
    ("loader", "text"),
    [
        (load_exceptions, "exceptions:\n  - {check_id: c, resource_match: r, owner_role: o}\n"),
        (load_exceptions, "exceptions:\n  - {check_id: c, resource_match: r, reason: x}\n"),
        (load_exceptions, "exceptions:\n  - {check_id: c, resource_match: r, reason: '', owner_role: o}\n"),
        (load_planted, "planted:\n  - {id: P1, title: t, cis: '1', resource_match: r, detectors: []}\n"),
        (load_planted, PLANTED.replace("prowler", "scoutsuite")),
        (load_planted, PLANTED + PLANTED.replace("planted:\n", "")),
        (load_planted, "planted:\n  - {id: P1, title: t, cis: '1', detectors: [{tool: prowler, check_id: c}]}\n"),
        (load_planted, "planted: []\n"),
        (load_settings, "framework: x\n"),
        (load_planted, "not: [valid"),
    ],
)
def test_config_errors(tmp_path: Path, loader, text: str):
    with pytest.raises(ConfigError):
        loader(_write(tmp_path, text))
