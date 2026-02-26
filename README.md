# Athena Usage Analyser

CloudFormation-deployed Lambda that captures Athena usage via CloudTrail and generates usage and migration readiness reports.

## Prerequisites

- **Python 3.6+** installed
- **AWS CLI** installed ([install guide](https://aws.amazon.com/cli/))
- **AWS credentials configured** — the deploy script will verify credentials before proceeding and prompt you if they're missing. Set up via one of:
  - `aws configure` (access key + secret key)
  - `aws sso login` (AWS SSO / IAM Identity Center)
  - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
  - IAM instance profile (if running on EC2)
- **IAM permissions** — the deploying user/role needs permissions to create CloudFormation stacks, S3 buckets, Lambda functions, IAM roles, EventBridge rules, and read CloudTrail. An admin or `PowerUserAccess` + `IAMFullAccess` policy is recommended for deployment.
- **For Organizations mode**: credentials must be for the management account (or a delegated administrator) with `organizations:ListAccounts` and `cloudformation:CreateStackSet` permissions.
- **CloudTrail** — Athena API calls are management events, which AWS logs by default in all accounts. No extra setup is needed for basic Athena query capture. The deploy script verifies CloudTrail status and, if you want S3 bucket access patterns, offers to enable S3 data events on an existing trail (this incurs additional CloudTrail charges).

## Quick Start

```bash
git clone https://github.com/garnathan/Athena-Usage-Analyser.git
cd Athena-Usage-Analyser
python3 deploy.py           # 1. Deploy
python3 verify_setup.py     # 2. Verify (especially for org/multi-account)
python3 analyse_exports.py  # 3. Analyse
python3 cleanup.py          # 4. Cleanup (when done)
```

All scripts are interactive and guide you through each step.

**Maintenance:** After editing `lambda/index.py`, push the update without a full CloudFormation redeploy:

```bash
python3 update_lambda.py
```

## Deployment Modes

### 1. Single Account (default)

Analyses Athena usage in the account where the stack is deployed. No cross-account setup needed.

### 2. AWS Organizations

The simplest multi-account setup for customers using AWS Organizations:

- **Auto-discovers accounts** via `organizations:ListAccounts`
- **Reads from Organization Trail** — all CloudTrail data from one S3 bucket
- **Deploys cross-account roles via StackSets** — one command for all accounts
- **Cross-account roles are optional** — query strings come from CloudTrail; roles only add execution stats (data scanned, timing)

Requires the collector stack to be in the management account (or delegated admin). An Organization Trail is recommended but optional.

> **AWS Control Tower compatibility:** Control Tower's `BaselineCloudTrail` does **not** set `IsOrganizationTrail=true`. The deploy and verify scripts detect Control Tower trails automatically by matching multi-region trails with "controltower" in the S3 bucket name. No manual configuration needed.

**Additional permissions for Org mode** (beyond the collector account permissions above):

| Permission | Why |
|-----------|-----|
| `organizations:ListAccounts`, `organizations:DescribeOrganization` | Discover member accounts |
| `organizations:ListRoots` | Auto-detect root OU for StackSets |
| `cloudformation:CreateStackSet`, `cloudformation:CreateStackInstances` | Deploy cross-account roles via StackSets |

### 3. Multi-Account (manual)

Analyses multiple AWS accounts via explicit account IDs and cross-account AssumeRole.

**How it works:**
1. You deploy the collector stack in one "collector" account
2. You provide the account IDs of the accounts you want to monitor
3. The deploy script generates an ExternalId (shared secret) and gives you a CloudFormation command to run in each monitored account
4. That command creates a read-only IAM role (`AthenaUsageAnalyserReadRole`) that the collector Lambda assumes

**IAM permissions required in the collector account (where you run `deploy.py`):**

| Permission | Why |
|-----------|-----|
| `sts:GetCallerIdentity` | Verify credentials |
| `cloudformation:*` | Create/update the collector stack |
| `s3:CreateBucket`, `s3:PutObject`, `s3:ListAllMyBuckets` | Create Lambda code bucket and upload code |
| `iam:CreateRole`, `iam:PutRolePolicy`, `iam:PassRole` | Create Lambda execution role (via CloudFormation) |
| `lambda:CreateFunction`, `lambda:UpdateFunctionCode` | Create/update the analyser Lambda |
| `logs:CreateLogGroup`, `logs:PutRetentionPolicy` | Create CloudWatch Log Groups |
| `events:PutRule`, `events:PutTargets` | Create EventBridge schedule |
| `cloudtrail:DescribeTrails`, `cloudtrail:LookupEvents` | Verify CloudTrail and optionally enable S3 data events |
| `cloudtrail:PutEventSelectors` | Only if enabling S3 data events (optional) |

> **Tip:** `AdministratorAccess` or `PowerUserAccess` + `IAMFullAccess` covers all of the above. For least-privilege, use the table above.

**IAM permissions required in each monitored account:**

Deploy the cross-account role template (`cloudformation/cross-account-role.json`) in each monitored account. This creates `AthenaUsageAnalyserReadRole` with only:

| Permission | Why |
|-----------|-----|
| `cloudtrail:LookupEvents` | Read CloudTrail management events (Athena API calls) |
| `athena:GetQueryExecution`, `athena:BatchGetQueryExecution` | Fetch query execution details (data scanned, timing) |

The role's trust policy only allows the collector Lambda to assume it, secured with an ExternalId.

**To deploy the cross-account role**, run this in each monitored account (the deploy script prints this exact command with your values filled in):

```bash
aws cloudformation create-stack \
  --stack-name AthenaUsageAnalyserRole \
  --template-body file://cloudformation/cross-account-role.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=CollectorAccountId,ParameterValue=<collector-account-id> \
    ParameterKey=CollectorStackName,ParameterValue=<stack-name> \
    ParameterKey=ExternalId,ParameterValue=<external-id>
```

**Important notes:**
- The cross-account role is read-only — it cannot modify anything in the monitored accounts
- If the role doesn't exist in an account, the Lambda logs a warning and skips that account (doesn't fail)
- The collector account is always analysed locally (no cross-account role needed for itself)
- You can deploy the cross-account roles before or after the collector stack

## Verification

After deploying in org or multi-account mode, run the verification script:

```bash
python3 verify_setup.py
```

This runs 9 automated checks with auto-fix capabilities:

| Check | What it verifies | Auto-fixes |
|-------|-----------------|------------|
| 1. CloudFormation Stack | Stack exists and is healthy | — |
| 2. Lambda Configuration | Env vars, ExternalId consistency | ExternalId mismatch between stack and StackSet |
| 3. EventBridge Schedule | Schedule rule exists and is enabled | Re-enables disabled schedules |
| 4. S3 Analysis Bucket | Bucket is accessible, recent exports exist | — |
| 5. CloudTrail | Management events are being logged | — |
| 6. Org Trail Visibility | Cross-account events via Organization Trail S3 | Auto-detects and configures org trail bucket |
| 7. CloudWatch Logs | Recent Lambda errors or warnings | — |
| 8. Cross-Account Roles | Roles exist and are assumable | Identifies ExternalId/role trust issues |
| 9. Test Invocation | End-to-end Lambda invocation with short lookback | — |

For Organization deployments, **always run this after `deploy.py`** — it catches configuration issues that are invisible until runtime (ExternalId mismatches, missing org trail config, disabled schedules).

## Parameters

The deploy script asks for these interactively. All have sensible defaults.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `AnalysisMode` | `single` | `single` or `multi` |
| `MonitoredAccountIds` | *(empty)* | Comma-separated AWS account IDs (manual multi-account) |
| `CrossAccountExternalId` | *(auto-generated)* | Shared secret for AssumeRole trust |
| `MultiAccountMethod` | `manual` | `manual` or `org` (AWS Organizations) |
| `OrganizationId` | *(auto-detected)* | AWS Organization ID (org mode) |
| `OrgTrailBucket` | *(auto-detected)* | Organization Trail S3 bucket (org mode) |
| `AthenaWorkgroups` | `*` | Workgroups to monitor |
| `S3BucketsToMonitor` | `*` | S3 buckets to track. `*` = auto-detect, `bucket1,bucket2` = explicit list, or JSON for per-account config (see below) |
| `CloudTrailBucket` | *(auto-detected)* | CloudTrail S3 bucket |
| `AnalysisIntervalMinutes` | `60` | How often to run (default: hourly) |
| `RetentionDays` | `90` | Data retention period (7-365 days) |
| `KMSKeyArn` | *(empty)* | KMS key for encryption (AES-256 if not set) |

### Per-Account S3 Bucket Configuration

In multi-account mode, each account may have different S3 bucket names. The `S3BucketsToMonitor` parameter supports three formats:

| Format | Example | Behaviour |
|--------|---------|-----------|
| Auto-detect | `*` | Pattern-matches bucket names at runtime (e.g. `athena-results`, `datalake-*`) |
| CSV | `bucket1,bucket2` | Monitor these specific buckets in all accounts |
| JSON | `{"*":["*"],"111111111111":["bucketA"]}` | Per-account overrides with `*` as the default |

The deploy script handles this interactively — you choose "auto-detect for all" or "configure each account individually".

## Output

Each analysis run exports a zip to S3: `summary.json`, `athena_events.json`, `s3_events.json`, `workgroup_report.txt`, `workgroup_stats.csv`, and `per_account_summary.json` (multi-account only).

The analysis script downloads these and generates an HTML report that opens in your browser. In multi-account mode, the report includes a per-account breakdown.

## What Gets Captured

- Query patterns, types (SELECT, CTAS, DDL, etc.), and data scanned
- Workgroup, user, database, and table usage
- S3 bucket access patterns
- Migration readiness: query complexity, DDL tracking, long-running queries, concurrency, partition usage, SQL compatibility flags, and a 0-100 readiness score

## Troubleshooting

### AccessDenied on all accounts (ExternalId mismatch)

**Symptom:** Every cross-account AssumeRole fails with `AccessDenied`, even though roles exist in all accounts.

**Cause:** On re-deployment, a new `CrossAccountExternalId` UUID was generated for the CloudFormation stack, but the existing StackSet kept the old UUID. The cross-account roles trust the old ExternalId.

**Fix:** Run `python3 verify_setup.py` — check 2 detects the mismatch and auto-fixes it. The deploy script now also reuses the existing ExternalId on re-deploys and updates the StackSet when it already exists.

### No cross-account CloudTrail events found

**Symptom:** The Lambda only returns events from the management account, not member accounts.

**Cause:** The `cloudtrail:LookupEvents` API only returns events from the **calling account**, regardless of whether an Organization Trail exists. It does not return cross-account events.

**Fix:** Configure an Organization Trail S3 bucket so the Lambda reads cross-account events from S3 instead. Run `python3 verify_setup.py` — check 6 auto-detects the org trail bucket and configures it.

### Control Tower trail not detected

**Symptom:** Deploy or verify says "no Organization Trail found" even though Control Tower is configured.

**Cause:** AWS Control Tower's `BaselineCloudTrail` sets `IsMultiRegionTrail=true` but does **not** set `IsOrganizationTrail=true`, so a naive check misses it.

**Fix:** Already handled — the scripts use a 3-priority detection: (1) explicit `IsOrganizationTrail`, (2) Control Tower pattern (multi-region + "controltower" in bucket name), (3) any multi-region trail.

### Lambda timeout with partial or missing results

**Symptom:** Lambda returns partial data or the invocation times out for large organizations (50+ accounts).

**Behaviour:** The Lambda checks remaining execution time before each account and stops early with a 45-second buffer to export whatever data was collected. The response includes `"partial": true` and skipped accounts are marked in the per-account summary.

**Mitigation:** The default Lambda timeout is 15 minutes (900s). For very large organizations, consider splitting monitored accounts across multiple collector stacks, or running the analysis in LOOKBACK mode with a longer time range to capture data over multiple invocations.

## Security

- S3 bucket: all public access blocked, TLS 1.2 enforced, server-side encryption (AES-256 default, optional KMS), versioning with noncurrent expiry
- Lambda: input validation, file size limits, sanitized error responses, query string masking, reserved concurrency
- IAM: least-privilege policies scoped to specific resources; cross-account roles are read-only with ExternalId validation
- No secrets or credentials stored — uses IAM roles and STS AssumeRole throughout
