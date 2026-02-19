# Athena Usage Analyser

A CloudFormation-deployed Lambda that captures Amazon Athena usage via CloudTrail events and generates comprehensive usage and migration readiness reports.

## What Gets Captured

### Basic Usage Metrics
- Query patterns (SQL structures with values sanitized)
- Query types (SELECT, CTAS, INSERT, DDL, etc.)
- Workgroup usage and data scanned
- User activity and timing
- Database and table access frequency
- S3 bucket access patterns

### Migration Readiness Analysis
- **Query Complexity**: JOIN counts, CTE usage, subquery depth, potential full table scans
- **DDL Operations**: CREATE, DROP, ALTER, TRUNCATE tracking by user and time
- **Long-Running Queries**: Queries exceeding 10, 30, or 60 minute thresholds
- **Concurrency Patterns**: Peak concurrent queries per minute
- **Partition Usage**: Queries using vs missing partition filters
- **SQL Compatibility Flags**: Features requiring attention during migration
- **Migration Readiness Score**: 0-100 score based on complexity, DDL patterns, and compatibility

---

## Step 1: Deploy

The interactive deploy script handles everything — CloudTrail verification, optional S3 data event setup, and CloudFormation stack deployment:

```bash
python3 deploy.py
```

The script will walk you through:

1. **Pre-flight checks** — verifies AWS CLI, credentials, and the CloudFormation template
2. **Region & CloudTrail** — asks for your AWS region and verifies CloudTrail is active
3. **S3 Data Events (optional)** — offers to enable S3 data events for bucket-level access monitoring. If enabled, you select a CloudTrail trail and pick S3 buckets from your account
4. **Configure & Deploy** — collects stack parameters (with sensible defaults), shows a summary, and deploys the CloudFormation stack

> **Note:** The script requires the AWS CLI to be installed and configured. If credentials are missing or expired, it will prompt you to authenticate and retry.

### Available Parameters

The deploy script asks for these interactively. All have sensible defaults.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `AthenaWorkgroups` | `*` | Workgroups to monitor (comma-separated, or `*` for all) |
| `S3BucketsToMonitor` | `*` | S3 buckets to track (`*` auto-detects Athena-related buckets) |
| `CloudTrailBucket` | *(auto-detected)* | **Required for S3 monitoring.** CloudTrail S3 bucket where logs are stored |
| `AnalysisIntervalMinutes` | `10` | How often to run (5-60 minutes) |
| `RetentionDays` | `90` | Data retention period (7-365 days) |
| `KMSKeyArn` | *(empty)* | KMS key for encryption (uses AES-256 if not specified) |

The last three are available under "Customize advanced settings" during deployment.

---

## Step 2: Analyse

The analysis script handles Lambda invocation, export download, and report generation:

```bash
python3 analyse_exports.py
```

Running with no arguments starts **interactive mode**, which walks you through:

1. **Find deployed stack** — auto-discovers the CloudFormation stack and reads its outputs (Lambda function name, S3 bucket)
2. **Run analysis (optional)** — invoke the Lambda for historical data with a selectable time range (7/30/60/90 days or custom)
3. **Download & generate report** — syncs exports from S3 and generates an HTML report that opens in your browser

You can also run in **direct mode** by passing a local exports path:

```bash
python3 analyse_exports.py ./exports/                        # HTML report, auto-opens
python3 analyse_exports.py ./exports/ --output report.txt    # Text report instead
python3 analyse_exports.py ./exports/ --no-open              # HTML report, no auto-open
```

> **Note:** The Lambda also runs automatically every `AnalysisIntervalMinutes` (default: 10 minutes). You can skip the Lambda invocation step if you only want to download and report on existing data.

---

## Step 3: Cleanup

The interactive cleanup script removes all deployed resources:

```bash
python3 cleanup.py
```

The script will walk you through:

1. **Find deployed stack** — auto-discovers the CloudFormation stack
2. **Cleanup** — with a confirmation prompt, then:
   - Empties the S3 analysis bucket
   - Deletes the CloudFormation stack and waits for completion
   - Optionally deletes the retained S3 bucket (has a Retain policy)
   - Optionally deletes local exports and generated reports

---

## Output Files

Each analysis run exports a zip to S3 containing:

| File | Contents |
|------|----------|
| `summary.json` | Complete analysis summary |
| `athena_events.json` | Raw Athena CloudTrail events |
| `s3_events.json` | Raw S3 CloudTrail events |
| `workgroup_report.txt` | Human-readable workgroup summary |
| `workgroup_stats.csv` | Workgroup statistics |

## Security

- All public access blocked on S3 bucket
- SSL/TLS enforced for all S3 operations
- Server-side encryption (AES-256 or customer KMS key)
- IAM policies follow least-privilege principle
