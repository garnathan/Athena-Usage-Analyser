#!/usr/bin/env python3
"""
Tests for AWS Organizations code paths in the Lambda function.

Uses unittest.mock to simulate AWS API responses without needing
a real AWS Organization. Covers:
  - Account discovery (success, empty, error)
  - Org trail S3 reading (success, missing config, error)
  - Lambda handler org mode branching
  - Merge analyser correctness
  - Graceful fallback when cross-account roles unavailable
  - Single-account and manual multi-account paths still work
"""

import gzip
import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root so we can import the lambda module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lambda"))

# Set required environment variables BEFORE importing index
os.environ.setdefault("OUTPUT_BUCKET", "test-output-bucket")
os.environ.setdefault("CLOUDTRAIL_BUCKET", "")
os.environ.setdefault("LOG_GROUP_NAME", "/test/events")

# Mock boto3 BEFORE importing index — the module creates clients at import time
# and will fail without AWS credentials
import boto3  # noqa: E402

_real_boto3_client = boto3.client
_mock_clients = {}


def _mock_boto3_client(service_name, **kwargs):
    """Return a MagicMock for each AWS service client created at module level."""
    if service_name not in _mock_clients:
        _mock_clients[service_name] = MagicMock(name=f"mock_{service_name}_client")
    return _mock_clients[service_name]


boto3.client = _mock_boto3_client

import index  # noqa: E402

# Restore real boto3.client (individual tests will patch as needed)
boto3.client = _real_boto3_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_cloudtrail_gzip(records):
    """Create a gzip-compressed CloudTrail JSON blob."""
    data = json.dumps({"Records": records}).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(data)
    buf.seek(0)
    return buf


def make_athena_event(event_name, query_id="q-123", workgroup="primary",
                      query_string="SELECT 1", user_arn="arn:aws:iam::123:user/testuser"):
    """Create a synthetic CloudTrail Athena event record."""
    record = {
        "eventSource": "athena.amazonaws.com",
        "eventName": event_name,
        "eventTime": "2026-02-20T10:00:00Z",
        "eventID": f"evt-{event_name}-{query_id}",
        "userIdentity": {"arn": user_arn, "principalId": "AIDA123:testuser"},
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "1.2.3.4",
        "requestParameters": {
            "workGroup": workgroup,
            "queryString": query_string,
        },
        "responseElements": {},
    }
    if event_name == "StartQueryExecution":
        record["responseElements"]["queryExecutionId"] = query_id
        record["requestParameters"]["queryExecutionContext"] = {"database": "testdb"}
    return record


# ---------------------------------------------------------------------------
# Account Discovery Tests
# ---------------------------------------------------------------------------


def test_discover_org_accounts_success():
    """Test successful account discovery."""
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"},
            {"Id": "333333333333", "Status": "SUSPENDED"},
            {"Id": "005078755324", "Status": "ACTIVE"},  # local account
        ]}
    ]
    mock_org = MagicMock()
    mock_org.get_paginator.return_value = mock_paginator

    with patch("index.boto3.client", return_value=mock_org), \
         patch("index._get_account_id", return_value="005078755324"):
        accounts = index.discover_org_accounts()

    assert accounts == ["111111111111", "222222222222"]


def test_discover_org_accounts_empty():
    """Test discovery when no member accounts exist."""
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Accounts": [
            {"Id": "005078755324", "Status": "ACTIVE"},  # only local
        ]}
    ]
    mock_org = MagicMock()
    mock_org.get_paginator.return_value = mock_paginator

    with patch("index.boto3.client", return_value=mock_org), \
         patch("index._get_account_id", return_value="005078755324"):
        accounts = index.discover_org_accounts()

    assert accounts == []


def test_discover_org_accounts_error():
    """Test discovery when Organizations API fails."""
    mock_org = MagicMock()
    mock_org.get_paginator.side_effect = Exception("AccessDeniedException")

    with patch("index.boto3.client", return_value=mock_org), \
         patch("index._get_account_id", return_value="005078755324"):
        accounts = index.discover_org_accounts()

    assert accounts == []


# ---------------------------------------------------------------------------
# Org Trail S3 Reading Tests
# ---------------------------------------------------------------------------


def test_fetch_events_from_org_trail_success():
    """Test reading CloudTrail events from org trail S3 bucket."""
    analyser = index.AthenaUsageAnalyser(account_id="111111111111")

    records = [
        make_athena_event("StartQueryExecution", "q-org-1",
                          user_arn="arn:aws:iam::111111111111:user/bob"),
        make_athena_event("StartQueryExecution", "q-org-2",
                          query_string="SELECT COUNT(*) FROM users",
                          user_arn="arn:aws:iam::111111111111:user/alice"),
    ]
    ct_gzip = make_cloudtrail_gzip(records)

    mock_s3 = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Contents": [{"Key": "AWSLogs/o-abc123/111111111111/CloudTrail/eu-west-1/2026/02/20/file.json.gz"}]}
    ]
    mock_s3.get_paginator.return_value = mock_paginator
    mock_s3.get_object.return_value = {
        "ContentLength": 500,
        "Body": ct_gzip,
    }

    start = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 2, 20, 23, 59, 59, tzinfo=timezone.utc)

    with patch("index.s3_client", mock_s3), \
         patch("index.ORG_TRAIL_BUCKET", "org-trail-bucket"), \
         patch("index.ORGANIZATION_ID", "o-abc123"), \
         patch("index._get_region", return_value="eu-west-1"):
        analyser._fetch_events_from_org_trail("111111111111", start, end)

    assert len(analyser.athena_events) == 2
    assert len(analyser.query_execution_ids) == 2


def test_fetch_events_from_org_trail_missing_config():
    """Test org trail fetch when bucket/org ID not configured."""
    analyser = index.AthenaUsageAnalyser(account_id="111111111111")
    start = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 2, 20, 23, 59, 59, tzinfo=timezone.utc)

    with patch("index.ORG_TRAIL_BUCKET", ""), \
         patch("index.ORGANIZATION_ID", ""):
        analyser._fetch_events_from_org_trail("111111111111", start, end)

    assert len(analyser.athena_events) == 0


def test_fetch_events_from_org_trail_s3_error():
    """Test org trail fetch when S3 access fails."""
    analyser = index.AthenaUsageAnalyser(account_id="111111111111")
    start = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 2, 20, 23, 59, 59, tzinfo=timezone.utc)

    mock_s3 = MagicMock()
    mock_s3.get_paginator.side_effect = Exception("AccessDenied")

    with patch("index.s3_client", mock_s3), \
         patch("index.ORG_TRAIL_BUCKET", "org-trail-bucket"), \
         patch("index.ORGANIZATION_ID", "o-abc123"), \
         patch("index._get_region", return_value="eu-west-1"):
        analyser._fetch_events_from_org_trail("111111111111", start, end)

    assert len(analyser.errors) == 1
    assert analyser.errors[0]["source"] == "org_trail_s3"


# ---------------------------------------------------------------------------
# Org Trail Analysis Tests
# ---------------------------------------------------------------------------


def test_analyse_account_from_org_trail_no_role():
    """Test org trail analysis when cross-account role is unavailable."""
    records = [
        make_athena_event("StartQueryExecution", "q-norole-1",
                          query_string="SELECT * FROM orders",
                          user_arn="arn:aws:iam::111111111111:user/carol"),
    ]
    ct_gzip = make_cloudtrail_gzip(records)

    mock_s3 = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Contents": [{"Key": "AWSLogs/o-abc123/111111111111/CloudTrail/eu-west-1/2026/02/20/file.json.gz"}]}
    ]
    mock_s3.get_paginator.return_value = mock_paginator
    mock_s3.get_object.return_value = {
        "ContentLength": 300,
        "Body": ct_gzip,
    }

    mock_sts = MagicMock()
    mock_sts.assume_role.side_effect = Exception("AccessDenied")

    with patch("index.s3_client", mock_s3), \
         patch("index.sts_client", mock_sts), \
         patch("index.ORG_TRAIL_BUCKET", "org-trail-bucket"), \
         patch("index.ORGANIZATION_ID", "o-abc123"), \
         patch("index._get_region", return_value="eu-west-1"):
        acct = index.analyse_account_from_org_trail(
            "111111111111",
            datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 2, 20, 23, 59, 59, tzinfo=timezone.utc),
        )

    assert acct is not None
    assert len(acct.athena_events) == 1
    assert "q-norole-1" in acct.fetched_queries
    assert acct.fetched_queries["q-norole-1"]["query"] == "SELECT * FROM orders"
    assert acct.fetched_queries["q-norole-1"]["data_scanned"] == 0


def test_analyse_account_from_org_trail_with_enrichment():
    """Test org trail analysis WITH cross-account role (enrichment)."""
    records = [
        make_athena_event("StartQueryExecution", "q-enrich-1",
                          query_string="SELECT * FROM products",
                          user_arn="arn:aws:iam::222222222222:user/dave"),
    ]
    ct_gzip = make_cloudtrail_gzip(records)

    mock_s3 = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Contents": [{"Key": "AWSLogs/o-abc123/222222222222/CloudTrail/eu-west-1/2026/02/20/file.json.gz"}]}
    ]
    mock_s3.get_paginator.return_value = mock_paginator
    mock_s3.get_object.return_value = {
        "ContentLength": 300,
        "Body": ct_gzip,
    }

    mock_sts = MagicMock()
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA_FAKE",
            "SecretAccessKey": "fake_secret",
            "SessionToken": "fake_token",
        }
    }

    mock_athena = MagicMock()
    mock_athena.batch_get_query_execution.return_value = {
        "QueryExecutions": [{
            "QueryExecutionId": "q-enrich-1",
            "Query": "SELECT * FROM products",
            "WorkGroup": "primary",
            "QueryExecutionContext": {"Database": "testdb"},
            "Status": {"State": "SUCCEEDED"},
            "Statistics": {
                "DataScannedInBytes": 1048576,
                "EngineExecutionTimeInMillis": 3500,
            },
        }],
        "UnprocessedQueryExecutionIds": [],
    }

    mock_session = MagicMock()
    mock_session.client.side_effect = lambda svc: {
        "cloudtrail": MagicMock(),
        "athena": mock_athena,
        "s3": MagicMock(),
    }[svc]

    with patch("index.s3_client", mock_s3), \
         patch("index.sts_client", mock_sts), \
         patch("index.boto3.Session", return_value=mock_session), \
         patch("index.ORG_TRAIL_BUCKET", "org-trail-bucket"), \
         patch("index.ORGANIZATION_ID", "o-abc123"), \
         patch("index.CROSS_ACCOUNT_EXTERNAL_ID", ""), \
         patch("index._get_region", return_value="eu-west-1"):
        acct = index.analyse_account_from_org_trail(
            "222222222222",
            datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 2, 20, 23, 59, 59, tzinfo=timezone.utc),
        )

    assert acct is not None
    assert "q-enrich-1" in acct.fetched_queries
    assert acct.fetched_queries["q-enrich-1"]["data_scanned"] == 1048576
    assert acct.fetched_queries["q-enrich-1"]["execution_time_ms"] == 3500
    assert acct.fetched_queries["q-enrich-1"]["status"] == "SUCCEEDED"


# ---------------------------------------------------------------------------
# Merge Analyser Tests
# ---------------------------------------------------------------------------


def test_merge_analyser():
    """Test merging per-account analysers into aggregate."""
    target = index.AthenaUsageAnalyser()
    source1 = index.AthenaUsageAnalyser(account_id="111111111111")
    source2 = index.AthenaUsageAnalyser(account_id="222222222222")

    source1.athena_events = [{"event_name": "StartQueryExecution", "user_id": "alice"}]
    source1.user_stats["alice"]["query_count"] = 5
    source1.user_stats["alice"]["last_activity"] = "2026-02-20T10:00:00Z"
    source1.workgroup_stats["primary"]["query_count"] = 5
    source1.workgroup_stats["primary"]["users"].add("alice")
    source1.hourly_query_counts["2026-02-20T10"] = 5

    source2.athena_events = [{"event_name": "StartQueryExecution", "user_id": "bob"}]
    source2.user_stats["bob"]["query_count"] = 3
    source2.user_stats["bob"]["last_activity"] = "2026-02-20T11:00:00Z"
    source2.workgroup_stats["primary"]["query_count"] = 3
    source2.workgroup_stats["primary"]["users"].add("bob")
    source2.hourly_query_counts["2026-02-20T11"] = 3

    index.merge_analyser(target, source1)
    index.merge_analyser(target, source2)

    assert len(target.athena_events) == 2
    assert target.user_stats["alice"]["query_count"] == 5
    assert target.user_stats["bob"]["query_count"] == 3
    assert target.workgroup_stats["primary"]["query_count"] == 8
    assert target.workgroup_stats["primary"]["users"] == {"alice", "bob"}
    assert target.hourly_query_counts["2026-02-20T10"] == 5
    assert target.hourly_query_counts["2026-02-20T11"] == 3


# ---------------------------------------------------------------------------
# Core Functionality Tests
# ---------------------------------------------------------------------------


def test_event_deduplication():
    """Test that duplicate eventIDs are filtered out."""
    analyser = index.AthenaUsageAnalyser()
    event = make_athena_event("StartQueryExecution", "q-dedup-1")

    analyser._process_event(event)
    analyser._process_event(event)  # duplicate
    analyser._process_event(event)  # duplicate

    assert len(analyser.athena_events) == 1


def test_cloudtrail_query_string_extraction():
    """Test that query strings are extracted from CloudTrail requestParameters."""
    analyser = index.AthenaUsageAnalyser()
    event = make_athena_event(
        "StartQueryExecution", "q-ct-1",
        query_string="SELECT name FROM customers WHERE id = 42",
    )
    analyser._process_event(event)

    assert "q-ct-1" in analyser.fetched_queries
    assert analyser.fetched_queries["q-ct-1"]["query"] == \
        "SELECT name FROM customers WHERE id = 42"
    assert analyser.fetched_queries["q-ct-1"]["database"] == "testdb"
    assert analyser.fetched_queries["q-ct-1"]["data_scanned"] == 0


def test_sanitize_query():
    """Test query sanitization strips sensitive values."""
    analyser = index.AthenaUsageAnalyser()

    q1 = analyser._sanitize_query("SELECT * FROM users WHERE name = 'John' AND age > 30")
    assert "'John'" not in q1
    assert "30" not in q1 or "<NUM>" in q1

    q2 = analyser._sanitize_query("SELECT * FROM t -- this is a comment")
    assert "--" not in q2

    q3 = analyser._sanitize_query("SELECT * FROM t /* block comment */ WHERE 1=1")
    assert "/*" not in q3

    q4 = analyser._sanitize_query("SELECT * FROM t WHERE name = 'O\\'Brien'")
    assert "O\\" not in q4


def test_file_size_limit():
    """Test that oversized CloudTrail files are skipped."""
    analyser = index.AthenaUsageAnalyser()
    mock_s3 = MagicMock()
    mock_s3.get_object.return_value = {
        "ContentLength": 60 * 1024 * 1024,  # 60 MB > 50 MB limit
        "Body": io.BytesIO(b""),
    }

    analyser._process_cloudtrail_file_from_bucket("bucket", "key.gz", mock_s3)

    assert len(analyser.athena_events) == 0


def test_workgroup_filtering():
    """Test workgroup allow-list filtering."""
    analyser = index.AthenaUsageAnalyser()

    with patch("index.MONITORED_WORKGROUPS", {"analytics", "primary"}):
        event1 = make_athena_event("StartQueryExecution", "q-wg-1", workgroup="primary")
        event2 = make_athena_event("StartQueryExecution", "q-wg-2", workgroup="secret")
        analyser._process_event(event1)
        analyser._process_event(event2)

    assert len(analyser.athena_events) == 1
    assert "secret" in analyser.skipped_workgroups


def test_csv_injection_prevention():
    """Test that workgroup names are quoted to prevent CSV injection."""
    analyser = index.AthenaUsageAnalyser()
    analyser.start_time = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)
    analyser.end_time = datetime(2026, 2, 20, 1, 0, 0, tzinfo=timezone.utc)

    analyser.workgroup_stats['=CMD("calc")']['query_count'] = 1
    analyser.workgroup_stats['=CMD("calc")']['users'] = {"hacker"}
    analyser.workgroup_stats['=CMD("calc")']['total_data_scanned'] = 0
    analyser.workgroup_stats['=CMD("calc")']['query_types'] = {"SELECT": 1}

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    with patch("index.s3_client", mock_s3), \
         patch("index.OUTPUT_BUCKET", "test-bucket"):
        analyser.export_to_s3()

    call_args = mock_s3.put_object.call_args
    zip_bytes = call_args[1]["Body"] if "Body" in call_args[1] else call_args[0][0]
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        csv_content = zf.read("workgroup_stats.csv").decode("utf-8")

    assert '"=CMD(""calc"")"' in csv_content


def test_generate_summary_structure():
    """Test that generate_summary produces expected structure."""
    analyser = index.AthenaUsageAnalyser()
    analyser.start_time = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)
    analyser.end_time = datetime(2026, 2, 20, 1, 0, 0, tzinfo=timezone.utc)

    event = make_athena_event("StartQueryExecution", "q-summary-1")
    analyser._process_event(event)
    analyser._process_fetched_queries()

    summary = analyser.generate_summary()

    required_keys = [
        "analysis_period", "configuration", "overview",
        "workgroup_stats", "user_stats", "database_stats",
        "query_patterns", "s3_bucket_stats", "hourly_query_counts", "errors",
    ]
    for key in required_keys:
        assert key in summary, f"Missing key: {key}"

    assert summary["configuration"]["analysis_mode"] == index.ANALYSIS_MODE
    assert summary["configuration"]["multi_account_method"] == index.MULTI_ACCOUNT_METHOD

    # Verify JSON serializable
    summary_json = json.dumps(summary, default=str)
    assert isinstance(summary_json, str)


# ---------------------------------------------------------------------------
# Lambda Handler Tests
# ---------------------------------------------------------------------------


def test_lambda_handler_input_validation():
    """Test lambda_handler input validation."""
    # Bad time format
    result = index.lambda_handler(
        {"start_time": "not-a-date", "end_time": "2026-02-20T00:00:00Z"}, None
    )
    assert result["statusCode"] == 400

    # start >= end
    result = index.lambda_handler(
        {"start_time": "2026-02-20T12:00:00Z", "end_time": "2026-02-20T10:00:00Z"}, None
    )
    assert result["statusCode"] == 400

    # Range > 90 days
    result = index.lambda_handler(
        {"start_time": "2025-01-01T00:00:00Z", "end_time": "2026-02-20T00:00:00Z"}, None
    )
    assert result["statusCode"] == 400


def test_lambda_handler_org_mode_empty_discovery():
    """Test lambda_handler in org mode when no accounts are discovered."""
    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    with patch("index.ANALYSIS_MODE", "multi"), \
         patch("index.MULTI_ACCOUNT_METHOD", "org"), \
         patch("index.discover_org_accounts", return_value=[]), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", MagicMock()), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        result = index.lambda_handler(
            {"start_time": "2026-02-20T00:00:00Z",
             "end_time": "2026-02-20T01:00:00Z"},
            None,
        )

    assert result["statusCode"] == 200
    assert result["body"]["analysis_mode"] == "multi"


def test_lambda_handler_org_mode_with_accounts():
    """Test lambda_handler in org mode with discovered accounts."""
    records = [
        make_athena_event("StartQueryExecution", "q-handler-1",
                          user_arn="arn:aws:iam::111111111111:user/eve"),
    ]
    ct_gzip = make_cloudtrail_gzip(records)

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}
    mock_s3_paginator = MagicMock()
    mock_s3_paginator.paginate.return_value = [
        {"Contents": [{"Key": "AWSLogs/o-abc123/111111111111/CloudTrail/eu-west-1/2026/02/20/file.json.gz"}]}
    ]
    mock_s3.get_paginator.return_value = mock_s3_paginator
    mock_s3.get_object.return_value = {
        "ContentLength": 300,
        "Body": ct_gzip,
    }

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    mock_sts = MagicMock()
    mock_sts.assume_role.side_effect = Exception("AccessDenied")
    mock_sts.get_caller_identity.return_value = {"Account": "005078755324"}

    with patch("index.ANALYSIS_MODE", "multi"), \
         patch("index.MULTI_ACCOUNT_METHOD", "org"), \
         patch("index.ORG_TRAIL_BUCKET", "org-trail-bucket"), \
         patch("index.ORGANIZATION_ID", "o-abc123"), \
         patch("index.CROSS_ACCOUNT_EXTERNAL_ID", ""), \
         patch("index.discover_org_accounts", return_value=["111111111111"]), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", MagicMock()), \
         patch("index.sts_client", mock_sts), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        result = index.lambda_handler(
            {"start_time": "2026-02-20T00:00:00Z",
             "end_time": "2026-02-20T01:00:00Z"},
            None,
        )

    assert result["statusCode"] == 200
    assert result["body"]["accounts_analysed"] == 1


# ---------------------------------------------------------------------------
# Single-Account & Manual Multi-Account Handler Tests
# ---------------------------------------------------------------------------


def test_lambda_handler_single_account():
    """Test lambda_handler in single-account mode (the default path)."""
    records = [
        make_athena_event("StartQueryExecution", "q-single-1",
                          query_string="SELECT * FROM customers"),
        make_athena_event("StartQueryExecution", "q-single-2",
                          query_string="SELECT COUNT(*) FROM orders"),
    ]

    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{
        "Events": [
            {
                "EventId": "ct-evt-1",
                "EventTime": datetime(2026, 2, 20, 10, 0, 0, tzinfo=timezone.utc),
                "EventName": "StartQueryExecution",
                "EventSource": "athena.amazonaws.com",
                "CloudTrailEvent": json.dumps(records[0]),
            },
            {
                "EventId": "ct-evt-2",
                "EventTime": datetime(2026, 2, 20, 10, 5, 0, tzinfo=timezone.utc),
                "EventName": "StartQueryExecution",
                "EventSource": "athena.amazonaws.com",
                "CloudTrailEvent": json.dumps(records[1]),
            },
        ]
    }]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    mock_athena = MagicMock()
    mock_athena.batch_get_query_execution.return_value = {
        "QueryExecutions": [
            {
                "QueryExecutionId": "q-single-1",
                "Query": "SELECT * FROM customers",
                "WorkGroup": "primary",
                "QueryExecutionContext": {"Database": "raw"},
                "Status": {"State": "SUCCEEDED"},
                "Statistics": {
                    "DataScannedInBytes": 524288,
                    "EngineExecutionTimeInMillis": 1200,
                },
            },
            {
                "QueryExecutionId": "q-single-2",
                "Query": "SELECT COUNT(*) FROM orders",
                "WorkGroup": "primary",
                "QueryExecutionContext": {"Database": "raw"},
                "Status": {"State": "SUCCEEDED"},
                "Statistics": {
                    "DataScannedInBytes": 262144,
                    "EngineExecutionTimeInMillis": 800,
                },
            },
        ],
        "UnprocessedQueryExecutionIds": [],
    }

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    with patch("index.ANALYSIS_MODE", "single"), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", mock_athena), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        result = index.lambda_handler(
            {"start_time": "2026-02-20T00:00:00Z",
             "end_time": "2026-02-20T23:59:59Z"},
            None,
        )

    assert result["statusCode"] == 200
    assert result["body"]["analysis_mode"] == "single"
    assert result["body"]["overview"]["total_athena_events"] == 2
    assert result["body"]["overview"]["queries_fetched_from_athena"] == 2
    # Should have exported to S3
    assert mock_s3.put_object.called
    # Should have written to CloudWatch Logs
    assert mock_logs.put_log_events.called


def test_lambda_handler_single_account_no_events():
    """Test single-account mode when CloudTrail returns no events."""
    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    with patch("index.ANALYSIS_MODE", "single"), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", MagicMock()), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        result = index.lambda_handler(
            {"start_time": "2026-02-20T00:00:00Z",
             "end_time": "2026-02-20T01:00:00Z"},
            None,
        )

    assert result["statusCode"] == 200
    assert result["body"]["overview"]["total_athena_events"] == 0


def test_lambda_handler_scheduled_mode():
    """Test lambda_handler with SCHEDULED mode (no explicit time range)."""
    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    with patch("index.ANALYSIS_MODE", "single"), \
         patch("index.MODE", "SCHEDULED"), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", MagicMock()), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        result = index.lambda_handler({}, None)

    assert result["statusCode"] == 200
    assert result["body"]["mode"] == "SCHEDULED"


def test_lambda_handler_lookback_mode():
    """Test lambda_handler with LOOKBACK mode."""
    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    with patch("index.ANALYSIS_MODE", "single"), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", MagicMock()), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        result = index.lambda_handler({"mode": "LOOKBACK"}, None)

    assert result["statusCode"] == 200
    assert result["body"]["mode"] == "LOOKBACK"


def test_lambda_handler_export_contains_expected_files():
    """Test that the S3 export contains expected zip entries."""
    mock_ct = MagicMock()
    mock_ct_paginator = MagicMock()
    mock_ct_paginator.paginate.return_value = [{"Events": []}]
    mock_ct.get_paginator.return_value = mock_ct_paginator

    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {}

    mock_logs = MagicMock()
    mock_logs.create_log_stream.return_value = {}
    mock_logs.put_log_events.return_value = {}

    with patch("index.ANALYSIS_MODE", "single"), \
         patch("index.s3_client", mock_s3), \
         patch("index.logs_client", mock_logs), \
         patch("index.cloudtrail_client", mock_ct), \
         patch("index.athena_client", MagicMock()), \
         patch("index._get_account_id", return_value="005078755324"), \
         patch("index._get_region", return_value="eu-west-1"):
        index.lambda_handler(
            {"start_time": "2026-02-20T00:00:00Z",
             "end_time": "2026-02-20T01:00:00Z"},
            None,
        )

    # Verify the zip content
    call_args = mock_s3.put_object.call_args
    zip_bytes = call_args[1].get("Body") or call_args[0][0]

    import zipfile as zf_mod
    with zf_mod.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        assert "summary.json" in names
        assert "athena_events.json" in names
        assert "s3_events.json" in names
        assert "workgroup_report.txt" in names
        assert "workgroup_stats.csv" in names

        # Verify summary.json is valid JSON
        summary = json.loads(zf.read("summary.json"))
        assert "overview" in summary
        assert "configuration" in summary
