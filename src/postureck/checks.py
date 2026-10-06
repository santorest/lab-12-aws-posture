"""Fallback checks (boto3) for planted flaws Prowler cannot evaluate on the emulator; each finding names postureck."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence

import boto3

from postureck.findings import Finding
from postureck.policy import ConfigError

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"


def session_for(endpoint: str = ENDPOINT) -> boto3.Session:
    """A session for the emulator: fixed test credentials; every client boto3 builds goes to `endpoint`."""
    os.environ["AWS_ENDPOINT_URL"] = endpoint  # read by boto3 when it creates each client
    return boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)  # noqa: S106


def pc_iam_user_mfa_keys(session: boto3.Session) -> list[Finding]:
    """A user with an active access key must have an MFA device (Prowler only checks MFA for console users)."""
    iam = session.client("iam")
    out = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
            active = any(k["Status"] == "Active" for k in keys)
            mfa = bool(iam.list_mfa_devices(UserName=name)["MFADevices"])
            out.append(
                Finding(
                    check_id="pc_iam_user_mfa_keys",
                    resource=user["Arn"],
                    status="FAIL" if active and not mfa else "PASS",
                    severity="high",
                    title="User with an active access key has an MFA device",
                    service="iam",
                    region=REGION,
                    tool="postureck",
                    cis=("2.10",),
                )
            )
    return out


CHECKS: dict[str, Callable[[boto3.Session], list[Finding]]] = {"pc_iam_user_mfa_keys": pc_iam_user_mfa_keys}


def run_checks(session: boto3.Session, names: Sequence[str]) -> list[Finding]:
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise ConfigError(f"unknown postureck check(s): {', '.join(unknown)}")
    return [f for name in names for f in CHECKS[name](session)]
