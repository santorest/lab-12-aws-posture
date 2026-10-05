"""Spike summary: per service checks and PASS/FAIL counts; per planted resource, the failing check ids."""

import collections
import glob
import json
import sys

files = glob.glob(f"{sys.argv[1]}/*.ocsf.json")
print("output files:", files)
records = [r for f in files for r in json.load(open(f, encoding="utf-8"))]
print("records:", len(records))
per_service: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
checks: dict[str, set[str]] = collections.defaultdict(set)
for r in records:
    res = (r.get("resources") or [{}])[0]
    service = res.get("group", {}).get("name", "?")
    per_service[service][r.get("status_code", "?")] += 1
    checks[service].add(r["metadata"]["event_code"])
for service in sorted(per_service):
    print(f"{service}: {dict(per_service[service])} checks={len(checks[service])}")

planted = ["acme-public-assets", "acme-customer-data", "svc-deploy", "acme-admin-policy", "acme-trail",
           "acme-cloudtrail-logs", "acme-legacy-admin", "vpc-", "sg-", "key/", "passwordpolicy", "password-policy"]
for name in planted:
    fails = sorted({r["metadata"]["event_code"] for r in records
                    if r.get("status_code") == "FAIL" and name in json.dumps(r.get("resources", []))})
    print(f"FAIL on {name}: {fails}")
account = sorted({r["metadata"]["event_code"] for r in records
                  if r.get("status_code") == "FAIL" and r["metadata"]["event_code"].startswith(("cloudtrail", "iam_password", "vpc_flow", "kms", "ec2_securitygroup_default"))})
print("FAIL account-level/related:", account)
sample = next((r for r in records if r.get("status_code") == "FAIL"), None)
print("sample record:", json.dumps(sample, indent=1)[:3000] if sample else None)
