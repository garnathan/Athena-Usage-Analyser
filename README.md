# Athena Usage Analyser

CloudFormation-deployed Lambda that captures Athena usage via CloudTrail and generates usage and migration readiness reports.

## Quick Start

```bash
python3 deploy.py           # 1. Deploy
python3 analyse_exports.py  # 2. Analyse
python3 cleanup.py          # 3. Cleanup (when done)
```

All three scripts are interactive and guide you through each step. Requires the AWS CLI to be installed and configured.

## What Gets Captured

- Query patterns, types (SELECT, CTAS, DDL, etc.), and data scanned
- Workgroup, user, database, and table usage
- S3 bucket access patterns
- Migration readiness: query complexity, DDL tracking, long-running queries, concurrency, partition usage, SQL compatibility flags, and a 0-100 readiness score

## Deployment Modes

### 1. Single Account (default)

Analyses Athena usage in the account where the stack is deployed.

### 2. Multi-Account (manual)

Analyses multiple AWS accounts via explicit account IDs and cross-account AssumeRole. The deploy script collects account IDs, generates an ExternalId, and shows commands to deploy a read-only IAM role in each monitored account.

The cross-account role grants read-only access to `cloudtrail:LookupEvents` and `athena:BatchGetQueryExecution`.

### 3. AWS Organizations

The simplest multi-account setup for customers using AWS Organizations:

- **Auto-discovers accounts** via `organizations:ListAccounts`
- **Reads from Organization Trail** — all CloudTrail data from one S3 bucket
- **Deploys cross-account roles via StackSets** — one command for all accounts
- **Cross-account roles are optional** — query strings come from CloudTrail; roles only add execution stats (data scanned, timing)

Requires the collector stack to be in the management account (or delegated admin). An Organization Trail is recommended but optional.

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
| `S3BucketsToMonitor` | `*` | S3 buckets to track |
| `CloudTrailBucket` | *(auto-detected)* | CloudTrail S3 bucket |
| `AnalysisIntervalMinutes` | `60` | How often to run (default: hourly) |
| `RetentionDays` | `90` | Data retention period (7-365 days) |
| `KMSKeyArn` | *(empty)* | KMS key for encryption (AES-256 if not set) |

## Output

Each analysis run exports a zip to S3: `summary.json`, `athena_events.json`, `s3_events.json`, `workgroup_report.txt`, `workgroup_stats.csv`, and `per_account_summary.json` (multi-account only).

The analysis script downloads these and generates an HTML report that opens in your browser. In multi-account mode, the report includes a per-account breakdown.

## Security

- All public access blocked on S3, SSL/TLS enforced, server-side encryption (AES-256 or KMS)
- IAM policies follow least-privilege
- Cross-account roles are read-only with ExternalId trust validation
