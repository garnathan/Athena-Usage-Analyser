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

## Step 2: Run Analysis

### Automatic Collection (Future Data)

Once deployed, the Lambda runs automatically every `AnalysisIntervalMinutes` (default: 10 minutes) to continuously collect Athena usage data. No manual action is required for ongoing monitoring.

### Manual Invocation (Historical Data)

You can also invoke the Lambda manually to collect historical data. This is useful for:
- Initial deployment to capture past activity
- One-time analysis of a specific time period

> **Important:** Historical analysis only works for time periods when CloudTrail was already configured. If you just enabled S3 data events, you can only retrieve historical data from that point forward.

**2.1** Run analysis for the last 60 days (example):
```bash
# Calculate dates for the last 60 days
END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TIME=$(date -u -v-60d +"%Y-%m-%dT%H:%M:%SZ")  # macOS
# START_TIME=$(date -u -d "60 days ago" +"%Y-%m-%dT%H:%M:%SZ")  # Linux

aws lambda invoke \
  --function-name athena-usage-analyser-analyser \
  --payload "{\"start_time\": \"$START_TIME\", \"end_time\": \"$END_TIME\"}" \
  --cli-binary-format raw-in-base64-out \
  --region <REGION> \
  output.json && cat output.json
```

> **Note:** The maximum lookback is 90 days (CloudTrail API limit). S3 data events are only available if CloudTrail S3 logging was enabled during that period.

**2.2** Run analysis for a specific time range:
```bash
aws lambda invoke \
  --function-name athena-usage-analyser-analyser \
  --payload '{"start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-31T23:59:59Z"}' \
  --cli-binary-format raw-in-base64-out \
  --region <REGION> \
  output.json && cat output.json
```

---

## Step 3: Retrieve Results

**3.1** List available exports:
```bash
aws s3 ls s3://athena-usage-analyser-analysis-<ACCOUNT_ID>/exports/ --recursive
```

**3.2** Download all exports:
```bash
aws s3 sync s3://athena-usage-analyser-analysis-<ACCOUNT_ID>/exports/ ./exports/
```

**3.3** Generate analysis report (see [ANALYSIS.md](ANALYSIS.md) for details):
```bash
python3 analyse_exports.py ./exports/
```

---

## Step 4: Cleanup

**4.1** Empty the S3 bucket:
```bash
aws s3 rm s3://athena-usage-analyser-analysis-<ACCOUNT_ID> --recursive
```

**4.2** Delete the CloudFormation stack:
```bash
aws cloudformation delete-stack \
  --stack-name athena-usage-analyser \
  --region <REGION>
```

**4.3** (Optional) Delete the retained S3 bucket manually if needed:
```bash
aws s3 rb s3://athena-usage-analyser-analysis-<ACCOUNT_ID>
```

> **Note:** The S3 bucket has a `Retain` policy and must be deleted manually after stack removal.

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
