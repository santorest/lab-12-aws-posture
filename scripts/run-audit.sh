#!/usr/bin/env bash
# The whole cycle against LocalStack (emulated AWS, no real account):
# start LocalStack -> apply vulnerable -> audit -> apply remediated -> audit -> destroy -> inventory -> report -> gate.
# Exit codes: 0 pass, 1 gate failed, 2 the audit did not really happen (emulator, Terraform, Prowler or config error).
set -euo pipefail
cd "$(dirname "$0")/.."
endpoint=http://localhost:4566
setting() { python3 -c "import sys,yaml; print(yaml.safe_load(open('policy/policy.yml'))[sys.argv[1]])" "$1"; }
image=$(setting localstack_image)
services=$(python3 -c "import yaml; print(' '.join(yaml.safe_load(open('policy/policy.yml'))['services']))")
prowler_version=$(setting prowler_version)
fail() { echo "error: $*" >&2; exit 2; }
mkdir -p out

if ! curl -sf "$endpoint/_localstack/health" > /dev/null; then
  docker run -d --name localstack -p 4566:4566 "$image" > /dev/null \
    || fail "cannot start $image"
fi
healthy=""
for _ in $(seq 1 45); do
  if health=$(curl -sf "$endpoint/_localstack/health") && python3 -c "
import json, sys
s = json.loads(sys.argv[1])['services']
sys.exit(0 if all(s.get(k) in ('available', 'running') for k in ('s3', 'iam', 'sts', 'ec2', 'kms', 'logs')) else 1)
" "$health"; then
    healthy=1
    break
  fi
  sleep 2
done
[ -n "$healthy" ] || fail "LocalStack is not healthy"

if [ ! -x .venv-prowler/bin/prowler ]; then
  python3 -m venv .venv-prowler
  .venv-prowler/bin/pip install -q "prowler==$prowler_version"
fi
export AWS_ENDPOINT_URL=$endpoint AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1

audit() {  # $1 = before | after. Prowler exits 3 when checks fail: expected; anything else is an error.
  local rc=0
  rm -rf "out/$1"
  # by service, unused resources included: the emulated account has no workloads, so nothing is "in use"
  # shellcheck disable=SC2086  # $services is a list of service names on purpose
  .venv-prowler/bin/prowler aws --region us-east-1 --services $services --scan-unused-services \
    --output-formats json-ocsf --output-directory "out/$1" > "out/prowler-$1.log" 2>&1 || rc=$?
  [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || { tail -40 "out/prowler-$1.log" >&2; fail "Prowler ($1) exited $rc"; }
  compgen -G "out/$1/*.ocsf.json" > /dev/null || fail "Prowler ($1) wrote no OCSF output"
  postureck check --endpoint "$endpoint" --policy-dir policy --out "out/$1-own.json" || fail "fallback checks ($1)"
}

tf() { terraform -chdir=terraform "$@"; }
# what the emulator holds before the lab creates anything (LocalStack ships its own sample resources)
postureck inventory --endpoint "$endpoint" --out out/baseline.json || fail "baseline inventory"
tf init -input=false > out/terraform-init.log || fail "terraform init"
tf apply -auto-approve -input=false -var-file=envs/vulnerable.tfvars > out/apply-vulnerable.log || fail "apply vulnerable"
audit before
tf apply -auto-approve -input=false -var-file=envs/remediated.tfvars > out/apply-remediated.log || fail "apply remediated"
audit after
tf destroy -auto-approve -input=false -var-file=envs/remediated.tfvars > out/destroy.log || fail "terraform destroy"
postureck inventory --endpoint "$endpoint" --out out/inventory.json || fail "inventory"

before=$(compgen -G "out/before/*.ocsf.json" | head -1)
after=$(compgen -G "out/after/*.ocsf.json" | head -1)
postureck report --policy-dir policy --before-prowler "$before" --before-own out/before-own.json \
  --after-prowler "$after" --after-own out/after-own.json --baseline out/baseline.json --inventory out/inventory.json --out-dir out \
  --meta "run=${GITHUB_RUN_ID:-local}"
postureck gate --results out/results.json
