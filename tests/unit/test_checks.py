from __future__ import annotations

from collections.abc import Iterator

import boto3
import pytest
from moto import mock_aws

from postureck.checks import CHECKS, run_checks
from postureck.inventory import inventory
from postureck.policy import ConfigError


@pytest.fixture
def session() -> Iterator[boto3.Session]:
    with mock_aws():
        yield boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")


def test_pc_iam_user_mfa_keys_fails_then_passes(session: boto3.Session):
    iam = session.client("iam")
    iam.create_user(UserName="svc-deploy")
    key = iam.create_access_key(UserName="svc-deploy")["AccessKey"]["AccessKeyId"]
    (finding,) = run_checks(session, ["pc_iam_user_mfa_keys"])
    assert (finding.status, finding.tool, finding.service) == ("FAIL", "postureck", "iam")
    assert finding.resource.endswith(":user/svc-deploy") and finding.cis == ("2.10",)
    iam.delete_access_key(UserName="svc-deploy", AccessKeyId=key)
    (finding,) = run_checks(session, ["pc_iam_user_mfa_keys"])
    assert finding.status == "PASS"


def test_inactive_key_or_mfa_device_passes(session: boto3.Session):
    iam = session.client("iam")
    iam.create_user(UserName="a")
    key = iam.create_access_key(UserName="a")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="a", AccessKeyId=key, Status="Inactive")
    iam.create_user(UserName="b")
    iam.create_access_key(UserName="b")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="b")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(UserName="b", SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321")
    assert {f.status for f in run_checks(session, ["pc_iam_user_mfa_keys"])} == {"PASS"}


def test_unknown_check_is_config_error(session: boto3.Session):
    with pytest.raises(ConfigError, match="pc_nope"):
        run_checks(session, ["pc_nope"])


def test_catalog_holds_only_what_prowler_cannot_see():
    assert set(CHECKS) == {"pc_iam_user_mfa_keys"}


def test_inventory_lists_created_resources_and_ignores_defaults(session: boto3.Session):
    baseline = set(inventory(session))  # the emulator's own resources (default VPC, its default security group)
    s3 = session.client("s3")
    s3.create_bucket(Bucket="acme-customer-data")
    session.client("iam").create_user(UserName="svc-deploy")
    kms = session.client("kms")
    kept = kms.create_key(Description="kept")["KeyMetadata"]["KeyId"]
    gone = kms.create_key(Description="gone")["KeyMetadata"]["KeyId"]
    kms.schedule_key_deletion(KeyId=gone, PendingWindowInDays=7)
    vpc = session.client("ec2").create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    left = set(inventory(session)) - baseline
    assert "arn:aws:s3:::acme-customer-data" in left
    assert any(r.endswith(":user/svc-deploy") for r in left)
    assert any(kept in r for r in left) and not any(gone in r for r in left)
    assert any(vpc in r for r in left)
    assert not any("vpc-" in r and vpc not in r for r in left)  # the default VPC was in the baseline


def test_session_for_points_every_client_at_the_endpoint(monkeypatch: pytest.MonkeyPatch):
    from postureck.checks import session_for

    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://unused")  # so the teardown restores the variable session_for sets
    client = session_for("http://emulator.test:4566").client("s3")
    assert client.meta.endpoint_url == "http://emulator.test:4566"
