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

## Step 1: Verify CloudTrail is Enabled

Athena API calls are logged as **management events** in CloudTrail, which are enabled by default.

**1.1** Verify CloudTrail is enabled in your region:
```bash
aws cloudtrail describe-trails --region <REGION>
```

You should see at least one trail. Note the `Name` field for use in Step 2.

---

## Step 2: Enable S3 Data Events (Required for S3 Monitoring)

To capture S3 bucket access patterns (GetObject, PutObject, etc.), you must:
1. Enable **S3 data events** in CloudTrail (these are NOT enabled by default)
2. Set the **CloudTrailBucket** parameter when deploying (required because S3 data events are only available via CloudTrail log files, not the CloudTrail API)

**2.1** Enable S3 data events for your data lake buckets:
```bash
aws cloudtrail put-event-selectors \
  --trail-name <TRAIL_NAME> \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": [
        "arn:aws:s3:::<BUCKET_1>/",
        "arn:aws:s3:::<BUCKET_2>/",
        "arn:aws:s3:::<BUCKET_3>/"
      ]
    }]
  }]' \
  --region <REGION>
```

**2.2** Verify S3 data events are enabled:
```bash
aws cloudtrail get-event-selectors --trail-name <TRAIL_NAME> --region <REGION>
```

**2.3** Find your CloudTrail S3 bucket name (needed for Step 3):
```bash
aws cloudtrail describe-trails --region <REGION> --query 'trailList[].S3BucketName'
```

> **Note:** S3 data events have a ~15-20 minute delay when first enabled. After that, CloudTrail delivers logs to S3 every 5-15 minutes. S3 data events incur additional CloudTrail charges.

---

## Step 3: Deploy the CloudFormation Stack

**3.1** Deploy with default settings:
```bash
aws cloudformation create-stack \
  --stack-name athena-usage-analyser \
  --template-body file://cloudformation/athena-usage-analyser.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <REGION>
```

**3.2** (Optional) Deploy with custom parameters:
```bash
aws cloudformation create-stack \
  --stack-name athena-usage-analyser \
  --template-body file://cloudformation/athena-usage-analyser.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=AthenaWorkgroups,ParameterValue="primary,analytics" \
    ParameterKey=S3BucketsToMonitor,ParameterValue="my-datalake-raw,my-datalake-processed" \
    ParameterKey=CloudTrailBucket,ParameterValue="my-cloudtrail-bucket" \
    ParameterKey=RetentionDays,ParameterValue=180 \
  --region <REGION>
```

**3.3** Wait for stack creation to complete:
```bash
aws cloudformation wait stack-create-complete \
  --stack-name athena-usage-analyser \
  --region <REGION>
```

### Available Parameters

All parameters are optional. Defaults work for most use cases.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `AthenaWorkgroups` | `*` | Workgroups to monitor (comma-separated, or `*` for all) |
| `S3BucketsToMonitor` | `*` | S3 buckets to track (`*` auto-detects Athena-related buckets) |
| `CloudTrailBucket` | *(empty)* | **Required for S3 monitoring.** CloudTrail S3 bucket where logs are stored |
| `AnalysisIntervalMinutes` | `10` | How often to run (5-60 minutes) |
| `RetentionDays` | `90` | Data retention period (7-365 days) |
| `KMSKeyArn` | *(empty)* | KMS key for encryption (uses AES-256 if not specified) |

---

## Step 4: Run Analysis

### Automatic Collection (Future Data)

Once deployed, the Lambda runs automatically every `AnalysisIntervalMinutes` (default: 10 minutes) to continuously collect Athena usage data. No manual action is required for ongoing monitoring.

### Manual Invocation (Historical Data)

You can also invoke the Lambda manually to collect historical data. This is useful for:
- Initial deployment to capture past activity
- One-time analysis of a specific time period

> **Important:** Historical analysis only works for time periods when CloudTrail was already configured. If you just enabled S3 data events, you can only retrieve historical data from that point forward.

**4.1** Run analysis for the last 60 days (example):
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

**4.2** Run analysis for a specific time range:
```bash
aws lambda invoke \
  --function-name athena-usage-analyser-analyser \
  --payload '{"start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-31T23:59:59Z"}' \
  --cli-binary-format raw-in-base64-out \
  --region <REGION> \
  output.json && cat output.json
```

---

## Step 5: Retrieve Results

**5.1** List available exports:
```bash
aws s3 ls s3://athena-usage-analyser-analysis-<ACCOUNT_ID>/exports/ --recursive
```

**5.2** Download all exports:
```bash
aws s3 sync s3://athena-usage-analyser-analysis-<ACCOUNT_ID>/exports/ ./exports/
```

**5.3** Generate analysis report (see [ANALYSIS.md](ANALYSIS.md) for details):
```bash
python3 analyse_exports.py ./exports/
```

---

## Step 6: Cleanup

**6.1** Empty the S3 bucket:
```bash
aws s3 rm s3://athena-usage-analyser-analysis-<ACCOUNT_ID> --recursive
```

**6.2** Delete the CloudFormation stack:
```bash
aws cloudformation delete-stack \
  --stack-name athena-usage-analyser \
  --region <REGION>
```

**6.3** (Optional) Delete the retained S3 bucket manually if needed:
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
