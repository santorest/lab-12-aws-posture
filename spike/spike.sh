#!/usr/bin/env bash
# Feasibility spike: LocalStack in CI, Terraform applies every planted flaw, Prowler audits the emulator.
set -euo pipefail
cd "$(dirname "$0")"
image="localstack/localstack:4.14.0"

echo "::group::LocalStack"
docker run -d --name localstack -p 4566:4566 -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN:-}" "$image"
docker inspect --format '{{index .RepoDigests 0}}' "$image" || true
ok=""
for _ in $(seq 1 45); do
  if health=$(curl -sf localhost:4566/_localstack/health); then
    echo "$health"
    if python3 -c "import json,sys; s=json.loads(sys.argv[1])['services']; sys.exit(0 if all(s.get(k) in ('available','running') for k in ('s3','iam','sts','cloudtrail','ec2','kms')) else 1)" "$health"; then
      ok=1; break
    fi
  fi
  sleep 2
done
docker logs localstack 2>&1 | tail -40
[ -n "$ok" ] || { echo "LocalStack not healthy" >&2; exit 2; }
echo "::endgroup::"

echo "::group::Terraform"
terraform init -input=false
terraform apply -auto-approve -input=false
echo "::endgroup::"

echo "::group::Prowler"
python3 -m venv ../.venv-prowler
../.venv-prowler/bin/pip install -q prowler==5.44.0
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
start=$(date +%s)
rc=0
../.venv-prowler/bin/prowler aws --region us-east-1 --output-formats json-ocsf --output-directory ../out \
  --compliance cis_7.0_aws --ignore-exit-code-3 > ../out-prowler.log 2>&1 || rc=$?
echo "prowler exit $rc after $(( $(date +%s) - start )) s"
tail -60 ../out-prowler.log
echo "::endgroup::"

python3 summarize.py ../out
