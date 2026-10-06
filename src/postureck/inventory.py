"""What exists in the emulated account, to prove the teardown left nothing (compared with a baseline before apply)."""

from __future__ import annotations

import boto3


def inventory(session: boto3.Session) -> list[str]:
    """ARNs or ids of the resources the lab could create; defaults and deleted keys are left out."""
    out: list[str] = []
    s3 = session.client("s3")
    out += [f"arn:aws:s3:::{b['Name']}" for b in s3.list_buckets().get("Buckets", [])]

    iam = session.client("iam")
    for users in iam.get_paginator("list_users").paginate():
        out += [u["Arn"] for u in users["Users"]]
    for roles in iam.get_paginator("list_roles").paginate():
        out += [r["Arn"] for r in roles["Roles"] if not r["Path"].startswith("/aws-service-role/")]
    for policies in iam.get_paginator("list_policies").paginate(Scope="Local"):
        out += [p["Arn"] for p in policies["Policies"]]

    ec2 = session.client("ec2")
    vpcs = [v for v in ec2.describe_vpcs()["Vpcs"] if not v.get("IsDefault")]
    out += [f"vpc/{v['VpcId']}" for v in vpcs]
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        if sg.get("VpcId") in {v["VpcId"] for v in vpcs}:
            out.append(f"security-group/{sg['GroupId']}")

    out += [f"flow-log/{fl['FlowLogId']}" for fl in ec2.describe_flow_logs().get("FlowLogs", [])]

    try:
        iam.get_account_password_policy()
        out.append("iam-account-password-policy")
    except iam.exceptions.NoSuchEntityException:
        pass

    kms = session.client("kms")
    for aliases in kms.get_paginator("list_aliases").paginate():
        out += [a["AliasArn"] for a in aliases["Aliases"] if not a["AliasName"].startswith("alias/aws/")]
    for keys in kms.get_paginator("list_keys").paginate():
        for key in keys["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") not in ("PendingDeletion", "Disabled"):
                out.append(meta["Arn"])

    logs = session.client("logs")
    for groups in logs.get_paginator("describe_log_groups").paginate():
        out += [g["arn"] for g in groups["logGroups"]]
    return sorted(out)
