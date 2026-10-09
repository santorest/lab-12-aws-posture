---
title: "AWS Cloud Security Posture Audit (Emulated)"
id: "lab-12-aws-posture"
category: "Cloud Security"
type: "Lab"
status: "completed"
date: "2026-10-06"
time_to_reproduce: "About 10 minutes: one CI run (fork, enable Actions, run CI); the audit job takes 3–5 minutes"
skills: [AWS, LocalStack, Terraform, Prowler, Checkov, Python, boto3, GitHub Actions]
frameworks: [CIS AWS Foundations Benchmark v7.0, CIS Controls v8 (3.3, 3.11, 4.4, 4.5, 5.4, 6.5, 13.6), MITRE ATT&CK (T1530, T1078.004, T1562.007)]
repo: "https://github.com/santorest/lab-12-aws-posture"
bundle: "Published on the portfolio site with its SHA-256 checksum"
---

# AWS Cloud Security Posture Audit (Emulated)

> **TL;DR:** A small company's hand-built AWS account is rebuilt with Terraform on LocalStack, with documented
> misconfigurations planted on purpose: a public bucket, customer data not encrypted with the company's key and unversioned, an
> everything-on-everything policy, a long-lived key without MFA, a weak password policy, SSH and RDP open to the
> internet, an open default security group, a key without rotation and a VPC without flow logs. Prowler audits the
> account before and after a Terraform fix; CI fails unless every planted flaw was detected and then cleared, nothing
> new appeared and the teardown left nothing behind. **The CI runs are real; the AWS account is emulated
> (LocalStack); no real AWS account is used.**

| | |
|---|---|
| **Role played** | Cloud security engineer reviewing a small company's AWS account |
| **Environment** | Public GitHub repository, GitHub-hosted Ubuntu runners, LocalStack 4.14.0 (community edition) |
| **Tools** | Terraform 1.16 + AWS provider 6.67, Prowler 5.44.0, Checkov, Python 3.12, boto3, moto, pytest, ruff, mypy, tflint, shellcheck, gitleaks |
| **Deliverable** | Terraform for a vulnerable and a remediated posture, planted flaws as data, audit-compare-gate tool (`postureck`), CI, branch ruleset, demo PRs |

---

## 1. Problem

Small companies often set up their cloud account by hand, under time pressure, and never review it: a bucket opened
"for a minute", a deploy user with full rights, a key that never expires, the database port open for a contractor.
An audit tool lists hundreds of findings; what is missing is a way to prove that the flaws that matter were found,
that the fix removed them, and that the fix did not open something else.

## 2. Design

- **The account as code.** Terraform builds the account in two postures from the same resources: one variable per
  planted flaw switches it on (`envs/vulnerable.tfvars`) or off (`envs/remediated.tfvars`). Both apply to the same
  state, so the remediation is an in-place change — the way a real fix lands.
- **Planted flaws as data.** `policy/misconfigs.yml` lists each planted part, its CIS AWS Foundations id and the
  checks that must catch it. The roles of the tools are fixed in advance: a flaw that nobody detects is a finding
  about the audit, not a pass.
- **An independent auditor.** Prowler does the auditing. Where Prowler has no check for a planted flaw on the
  emulator, a small fallback check in `postureck` covers it, and every finding names the tool that produced it.
- **Matching that does not drift.** Findings are keyed by (check, resource). Security groups, VPCs and keys have
  random ids, so they are matched by their exact Name tag, which Prowler reports as a label. After the fix, each
  planted item is judged on the exact (check, resource) pairs that failed before: a renamed tag, a PASS on some
  other resource or one detector going silent cannot make a flaw look fixed.
- **A teardown that is checked.** The emulator ships its own sample resources, so the teardown is compared with an
  inventory taken before anything was created.

## 3. The cycle

1. Start LocalStack (pinned by digest) and take the baseline inventory.
2. `terraform apply` the vulnerable posture.
3. Audit: Prowler on S3, IAM, EC2, VPC and KMS with unused resources included (the emulated account has no
   workloads), plus the fallback check.
4. `terraform apply` the remediated posture on the same state.
5. Audit again.
6. `terraform destroy`; the inventory must match the baseline.
7. `postureck report` compares and writes HTML, Markdown and JSON; `postureck gate` decides.

## 4. Measurement and gate

- **Detection rate**: planted items whose detectors failed before the fix (an item with two parts counts when both
  were detected). **Fix rate**: planted items that pass after the fix (an excepted part does not count as fixed).
- **Regressions**: a (check, resource) failing after the fix that was not failing before.
- **Open**: failing before and after, not planted — reported, not gated.
- **Gate** (exit 1): a planted flaw not detected; a planted flaw still failing, or its detector silent, after the
  fix; any regression, even when the totals fell; resources left after teardown.
- **Errors, not results** (exit 2): LocalStack not healthy, a Terraform step failed, Prowler wrote no output, a
  findings file is unreadable, or a deployed service has no finding from any tool.

## 5. Planted misconfigurations

| Item | Misconfiguration | CIS v7.0 | Detected by |
|---|---|---|---|
| 1 | Assets bucket publicly readable, Block Public Access off | 3.1.4 | Prowler |
| 2a | Customer data not encrypted with the company's KMS key | outside CIS 7.0 | Prowler |
| 2b | Customer data bucket unversioned and reachable over HTTP | 3.1.1 | Prowler |
| 3 | Policy allowing every action on every resource, attached to a user | 2.14 | Prowler |
| 4a | Long-lived access key on a user without MFA | 2.10 | postureck |
| 4b | Weak account password policy | 2.8, 2.9 | Prowler |
| 6a | SSH and RDP open to the internet | 6.3 | Prowler |
| 6b | Default security group allows traffic | 6.5 | Prowler |
| 7a | KMS key without rotation | 4.6 | Prowler |
| 7b | VPC without flow logs | 4.7 | Prowler |

Item 5 of the plan, a missing CloudTrail, is not planted: the LocalStack edition that runs without a token has no
CloudTrail service.

## 6. Pipeline

| Job | What it proves |
|---|---|
| `lint` | terraform fmt/validate, tflint (AWS ruleset), ruff, mypy (strict), shellcheck, yamllint |
| `unit` | `postureck` on fixtures cut from real Prowler output and on moto; `terraform test` with a mocked provider; coverage gate 90 % |
| `iac-scan` | Checkov on both postures, for comparison (not gating) |
| `audit` | the whole cycle on LocalStack; artifacts: Prowler output, fallback findings, Terraform logs, inventories, report |
| `secrets` | gitleaks over the full history |

It runs on every pull request, on pushes to `main`, weekly and on demand.

## 7. Results

From [run 37812253346](https://github.com/santorest/lab-12-aws-posture/actions/runs/37812253346) (2026-10-08), the final code after the review fixes; the first green run, [37414269426](https://github.com/santorest/lab-12-aws-posture/actions/runs/37414269426) on `main` (2026-10-06), gave the same numbers. `docs/example-report.html`
is its report. LocalStack 4.14.0 (community edition, pinned by digest), Prowler 5.44.0, Terraform 1.16.5 with the AWS
provider 6.67.0, CIS AWS Foundations v7.0 as Prowler maps it.

| | Before the fix | After the fix |
|---|---|---|
| Planted items detected | **6 / 6** (all 10 parts) | — |
| Planted items passing | 0 / 6 | **6 / 6** (all 10 parts) |
| Regressions | — | **0** |
| Resources left after teardown | — | **0** |

- **Every planted part was caught by the tool assigned to it**: nine by Prowler, one (the access key without MFA) by
  the fallback check, because Prowler only checks MFA for users with console access.
- **Failing findings by CIS section** (the planted parts and everything else Prowler reports on the five services):
  section 2 (identity) 7 → 3, section 3 (storage) 6 → 4, section 4 (logging and keys) 3 → 1, section 6 (networking)
  11 → 8.
- **Open findings: read the totals with care.** 1,201 findings fail both before and after the fix. Only 20 of them
  are on the lab's own resources — controls outside the planted set, such as replication, lifecycle rules, object
  lock, access logging and MFA delete on the two buckets, hardware MFA on the deploy user — and they are reported,
  not hidden. The other 1,181 belong to the emulator itself: 1,159 are "EBS snapshot not encrypted" on LocalStack's
  built-in sample snapshots, which exist before the lab creates anything. That is also why the severity totals barely
  move (high 1,181 → 1,171): the gate judges the planted items, regressions and teardown, not the totals.
- **Time**: the audit step takes about 3 minutes (two Terraform applies, two Prowler scans of about 30 seconds each,
  a destroy); the whole pipeline 4–6 minutes.

**How it got there.** The first complete cycle
([run 37413720116](https://github.com/santorest/lab-12-aws-posture/actions/runs/37413720116)) detected 6/6 but fixed 5/6, and found one regression. The default security
group kept its rules after the "fix": Terraform treats empty rule blocks as "not specified", so nothing was removed —
the rules are now written as an explicit empty list. And the regression was real: the IAM role the fix created for
VPC flow logs could be assumed on behalf of any account (no `aws:SourceAccount` condition). The fix had introduced a
new weakness, and the regression check is what found it.

**Static scan, for comparison.** Checkov, run on both postures, did not report the SSH/RDP rule open to the internet
in either of them: the address range comes from a conditional value it does not resolve. The live audit did.

**Demo pull requests** (closed unmerged; the ruleset blocks the merge):

| PR | Change | What happened |
|---|---|---|
| [#1](https://github.com/santorest/lab-12-aws-posture/pull/1) | SSH and RDP open to the internet again in the remediated posture | detected 6/6 but fixed 5/6: the gate failed with "planted flaw still failing after fix: P6a" |
| [#2](https://github.com/santorest/lab-12-aws-posture/pull/2) | the "fix" also creates a new public bucket, `acme-exports` | every planted item was still fixed (6/6), but the gate failed on 12 regressions on the new bucket, among them public access (critical) and Block Public Access off (high) |

## 8. Lessons

- **The free emulator moved.** Current LocalStack releases refuse to start without an account token; the last
  tokenless release (4.14.0, community edition) works, but it has no CloudTrail — so one of the planted flaws had to
  go, and the write-up says so rather than faking it.
- **"Scan only what is used" hides an emulated account.** By default Prowler skips resources nothing uses; in an
  account without workloads that means the security groups and the VPC were never checked. The audit scans unused
  resources on purpose.
- **A compliance filter is not the audit.** Running Prowler with `--compliance` limits it to that framework's
  checks; scanning by service keeps every check and still records the CIS mapping on each finding.
- **Defaults change what can be planted.** S3 now encrypts every bucket with SSE-S3 by default, on AWS and on the
  emulator, so "no encryption at all" cannot be planted; the item became "not encrypted with the company's own key".
- **A fix can open something new.** The flow-logs role the remediation added could be assumed on behalf of any
  account; the totals still went down, and only the regression check (a finding absent before, failing after)
  caught it.
- **Empty is not the same as "remove".** Terraform treats empty rule blocks on the default security group as "not
  specified" and leaves the old rules in place; an explicit empty list removes them. A plan with mocked providers
  cannot show this — the real apply and the second audit did.
- **Random ids need names.** Security groups, VPCs and keys come back with random ids; tagging them with a Name and
  matching on Prowler's labels is what lets a planted flaw be followed from before to after.

## 9. Limits

- The target is emulated AWS (LocalStack 4.14.0 community), not a real account; results show that the method works,
  not the posture of any real account.
- Prowler's coverage on the emulator is partial; the report names the tool behind each finding.
- Not testable here: CloudTrail, root-account controls, GuardDuty, Security Hub, Organizations.
- The emulator ships sample resources (for example EC2 snapshots); their findings fail before and after and inflate
  the totals. The planted items, regressions and teardown are what the gate judges.

## 10. Reproduce it

Fork the repository and enable Actions: every push runs the cycle. Locally (Linux, macOS or WSL with Docker,
Terraform and Python 3.12), follow the README's quick start: `bash scripts/run-audit.sh` writes `out/report.html` and
`out/results.json`.

## 11. Mapping

| Framework | Items |
|---|---|
| CIS AWS Foundations v7.0 | 2.8, 2.9, 2.10, 2.14, 3.1.1, 3.1.4, 4.6, 4.7, 6.3, 6.5 |
| CIS Controls v8 | 3.3 configure data access control lists, 3.11 encrypt sensitive data at rest, 4.4 and 4.5 firewalls on servers and end-user devices, 5.4 restrict administrator privileges, 6.5 require MFA for administrative access, 13.6 collect network traffic flow logs |
| MITRE ATT&CK | T1530 Data from Cloud Storage, T1078.004 Valid Accounts: Cloud Accounts, T1562.007 Impair Defenses: Disable or Modify Cloud Firewall — what the fixed settings make harder |
