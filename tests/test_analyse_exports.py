#!/usr/bin/env python3
"""
Tests for the analysis/report generation pipeline.

Creates synthetic Lambda export data (mimicking what the Lambda produces)
and runs analyse_exports.py against it to validate the full report chain
for both single-account and multi-account (org) modes.
"""

import io
import json
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Mock install_dependencies to avoid installing packages during tests
with patch("_helpers.install_dependencies"):
    import analyse_exports


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TMPDIR = Path(__file__).resolve().parent / "tmp_exports"


def make_summary(
    mode="single",
    method="manual",
    account_id=None,
    workgroups=None,
    users=None,
    databases=None,
    athena_event_count=10,
    query_count=10,
    per_account=None,
):
    """Create a realistic summary.json structure."""
    if workgroups is None:
        workgroups = {
            "primary": {
                "query_count": 8,
                "users": ["alice", "bob"],
                "total_data_scanned": 1073741824,  # 1 GB
                "query_types": {"SELECT": 5, "CTAS": 2, "DDL": 1},
            },
            "analytics": {
                "query_count": 2,
                "users": ["carol"],
                "total_data_scanned": 536870912,  # 0.5 GB
                "query_types": {"SELECT": 2},
            },
        }
    if users is None:
        users = {
            "alice": {
                "query_count": 5,
                "workgroups": ["primary"],
                "last_activity": "2026-02-20T10:30:00Z",
                "data_scanned": 700000000,
            },
            "bob": {
                "query_count": 3,
                "workgroups": ["primary"],
                "last_activity": "2026-02-20T11:00:00Z",
                "data_scanned": 373741824,
            },
            "carol": {
                "query_count": 2,
                "workgroups": ["analytics"],
                "last_activity": "2026-02-20T09:00:00Z",
                "data_scanned": 536870912,
            },
        }
    if databases is None:
        databases = {
            "raw": {"query_count": 6, "users": ["alice", "bob"]},
            "processed": {"query_count": 3, "users": ["alice", "carol"]},
            "default": {"query_count": 1, "users": ["bob"]},
        }

    summary = {
        "analysis_period": {
            "start": "2026-02-20T00:00:00+00:00",
            "end": "2026-02-20T23:59:59+00:00",
        },
        "configuration": {
            "monitored_workgroups": ["*"],
            "monitored_s3_buckets": ["*"],
            "analysis_mode": mode,
            "multi_account_method": method,
        },
        "overview": {
            "total_athena_events": athena_event_count,
            "total_s3_events": 5,
            "query_execution_ids_found": query_count,
            "queries_fetched_from_athena": query_count,
            "unique_users": len(users),
            "unique_workgroups": len(workgroups),
            "unique_databases": len(databases),
            "unique_query_patterns": 4,
            "skipped_workgroups": [],
            "skipped_buckets_count": 0,
        },
        "workgroup_stats": workgroups,
        "user_stats": users,
        "database_stats": databases,
        "query_patterns": {
            "SELECT * FROM <table>": {
                "count": 5,
                "examples": ["SELECT * FROM raw.customers"],
                "users": ["alice"],
                "workgroups": ["primary"],
                "databases": ["raw"],
            },
            "SELECT COUNT(*) FROM <table>": {
                "count": 3,
                "examples": ["SELECT COUNT(*) FROM raw.sales"],
                "users": ["bob"],
                "workgroups": ["primary"],
                "databases": ["raw"],
            },
        },
        "s3_bucket_stats": {
            "my-data-bucket": {
                "event_count": 3,
                "operations": {"GetObject": 2, "PutObject": 1},
            },
        },
        "hourly_query_counts": {
            "2026-02-20T09": 2,
            "2026-02-20T10": 5,
            "2026-02-20T11": 3,
        },
        "errors": [],
    }
    if account_id:
        summary["account_id"] = account_id
    if per_account:
        summary["per_account"] = per_account
    return summary


def make_athena_events(count=10):
    """Create synthetic athena events."""
    events = []
    for i in range(count):
        events.append({
            "event_name": "StartQueryExecution",
            "event_time": f"2026-02-20T{10 + i % 4:02d}:{i * 5 % 60:02d}:00Z",
            "event_id": f"evt-{i:04d}",
            "user_id": ["alice", "bob", "carol"][i % 3],
            "user_arn": f"arn:aws:iam::111111111111:user/{['alice', 'bob', 'carol'][i % 3]}",
            "workgroup": ["primary", "analytics"][i % 2],
            "query_execution_id": f"q-{i:04d}",
            "query_string": f"SELECT * FROM table_{i}",
            "source_ip": "10.0.0.1",
            "database": ["raw", "processed"][i % 2],
        })
    return events


def make_s3_events(count=5):
    """Create synthetic S3 events."""
    events = []
    for i in range(count):
        events.append({
            "event_name": ["GetObject", "PutObject"][i % 2],
            "event_time": f"2026-02-20T{10 + i:02d}:00:00Z",
            "event_id": f"s3-evt-{i:04d}",
            "user_id": "alice",
            "bucket_name": "my-data-bucket",
            "object_key": f"data/file_{i}.csv",
            "bytes_transferred": (i + 1) * 1024,
        })
    return events


def create_export_zip(summary, athena_events=None, s3_events=None,
                      per_account_summaries=None):
    """Create an in-memory zip file matching Lambda's export format."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.json", json.dumps(summary, indent=2, default=str))
        zf.writestr(
            "athena_events.json",
            json.dumps(athena_events or [], indent=2, default=str),
        )
        zf.writestr(
            "s3_events.json",
            json.dumps(s3_events or [], indent=2, default=str),
        )
        if per_account_summaries:
            zf.writestr(
                "per_account_summary.json",
                json.dumps(per_account_summaries, indent=2, default=str),
            )

        # CSV
        csv_lines = ["workgroup,query_count,unique_users,data_scanned_gb"]
        for wg, stats in summary.get("workgroup_stats", {}).items():
            safe_wg = '"' + wg.replace('"', '""') + '"'
            users_count = len(stats.get("users", []))
            scanned_gb = stats.get("total_data_scanned", 0) / (1024**3)
            csv_lines.append(f"{safe_wg},{stats['query_count']},{users_count},{scanned_gb:.4f}")
        zf.writestr("workgroup_stats.csv", "\n".join(csv_lines))

    buf.seek(0)
    return buf


def save_export_zip(buf, path):
    """Save a zip buffer to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(buf.getvalue())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_single_account_analysis(tmp_path):
    """Test full analysis pipeline for single-account mode."""
    summary = make_summary(mode="single")
    events = make_athena_events(10)
    s3_events = make_s3_events(5)

    zip_buf = create_export_zip(summary, events, s3_events)
    zip_path = tmp_path / "exports" / "2026" / "02" / "20" / "export.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    count = analyser.load_exports()

    assert count == 1
    assert len(analyser.all_summaries) == 1
    assert len(analyser.all_athena_events) == 10
    assert len(analyser.all_s3_events) == 5
    assert analyser.analysis_mode == "single"

    # Verify workgroup stats were merged
    assert "primary" in analyser.workgroup_stats
    assert "analytics" in analyser.workgroup_stats
    assert analyser.workgroup_stats["primary"]["query_count"] == 8

    # Verify user stats
    assert "alice" in analyser.user_stats
    assert analyser.user_stats["alice"]["query_count"] == 5


def test_multi_account_org_analysis(tmp_path):
    """Test full analysis pipeline for multi-account org mode."""
    per_account = [
        {
            "account_id": "222222222222",
            "overview": {
                "total_athena_events": 5,
                "query_execution_ids_found": 5,
            },
            "workgroup_stats": {
                "primary": {
                    "query_count": 5,
                    "users": ["dave"],
                    "total_data_scanned": 500000000,
                    "query_types": {"SELECT": 5},
                },
            },
        },
        {
            "account_id": "333333333333",
            "overview": {
                "total_athena_events": 3,
                "query_execution_ids_found": 3,
            },
            "workgroup_stats": {
                "analytics": {
                    "query_count": 3,
                    "users": ["eve"],
                    "total_data_scanned": 300000000,
                    "query_types": {"SELECT": 2, "DDL": 1},
                },
            },
        },
    ]

    summary = make_summary(mode="multi", method="org", per_account=per_account)
    events = make_athena_events(10)

    zip_buf = create_export_zip(summary, events, per_account_summaries=per_account)
    zip_path = tmp_path / "exports" / "export_org.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    count = analyser.load_exports()

    assert count == 1
    assert analyser.analysis_mode == "multi"
    assert analyser.multi_account_method == "org"
    assert len(analyser.per_account_summaries) == 2


def test_multiple_export_files(tmp_path):
    """Test loading and merging multiple export files."""
    for day in range(18, 21):
        summary = make_summary(
            workgroups={
                "primary": {
                    "query_count": day - 17,
                    "users": [f"user_{day}"],
                    "total_data_scanned": day * 100000000,
                    "query_types": {"SELECT": day - 17},
                },
            }
        )
        events = make_athena_events(day - 17)
        zip_buf = create_export_zip(summary, events)
        zip_path = tmp_path / "exports" / f"2026/02/{day}/export.zip"
        save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    count = analyser.load_exports()

    assert count == 3
    assert len(analyser.all_summaries) == 3
    # Primary workgroup should have merged counts: 1 + 2 + 3 = 6
    assert analyser.workgroup_stats["primary"]["query_count"] == 6


def test_report_generation_single_account(tmp_path):
    """Test that HTML report is generated successfully for single-account."""
    summary = make_summary(mode="single")
    events = make_athena_events(10)
    s3_events = make_s3_events(5)

    zip_buf = create_export_zip(summary, events, s3_events)
    zip_path = tmp_path / "exports" / "export.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    analyser.load_exports()

    report_path = str(tmp_path / "test-report.html")
    analyser.generate_html_report(report_path)

    html = Path(report_path).read_text()
    assert len(html) > 1000  # Should be a substantial HTML document
    assert "Athena Usage" in html
    assert "primary" in html
    assert "analytics" in html
    assert "alice" in html


def test_report_generation_multi_account(tmp_path):
    """Test that HTML report includes multi-account info."""
    per_account = [
        {
            "account_id": "222222222222",
            "overview": {"total_athena_events": 5},
            "workgroup_stats": {
                "primary": {
                    "query_count": 5,
                    "users": ["dave"],
                    "total_data_scanned": 500000000,
                    "query_types": {"SELECT": 5},
                },
            },
        },
    ]

    summary = make_summary(mode="multi", method="org", per_account=per_account)
    events = make_athena_events(10)

    zip_buf = create_export_zip(summary, events, per_account_summaries=per_account)
    zip_path = tmp_path / "exports" / "export.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    analyser.load_exports()

    report_path = str(tmp_path / "test-report-multi.html")
    analyser.generate_html_report(report_path)

    html = Path(report_path).read_text()
    assert "222222222222" in html


def test_empty_export(tmp_path):
    """Test handling of empty export data."""
    summary = make_summary(
        workgroups={},
        users={},
        databases={},
        athena_event_count=0,
        query_count=0,
    )
    zip_buf = create_export_zip(summary, [], [])
    zip_path = tmp_path / "exports" / "empty.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    count = analyser.load_exports()

    assert count == 1
    assert len(analyser.all_athena_events) == 0

    # Report generation should still succeed
    report_path = str(tmp_path / "test-report-empty.html")
    analyser.generate_html_report(report_path)
    html = Path(report_path).read_text()
    assert len(html) > 100


def test_no_exports_found(tmp_path):
    """Test handling when no zip files exist."""
    empty_dir = tmp_path / "exports"
    empty_dir.mkdir()

    analyser = analyse_exports.AthenaExportAnalyser(empty_dir)
    count = analyser.load_exports()

    assert count == 0


def test_event_processing_concurrency(tmp_path):
    """Test that event processing correctly tracks concurrent queries."""
    events = []
    # Create overlapping queries
    for i in range(5):
        events.append({
            "event_name": "StartQueryExecution",
            "event_time": f"2026-02-20T10:{i * 2:02d}:00Z",
            "event_id": f"evt-conc-{i:04d}",
            "user_id": "alice",
            "user_arn": "arn:aws:iam::111111111111:user/alice",
            "workgroup": "primary",
            "query_execution_id": f"q-conc-{i:04d}",
            "query_string": f"SELECT * FROM table_{i}",
            "source_ip": "10.0.0.1",
            "database": "raw",
        })

    summary = make_summary()
    zip_buf = create_export_zip(summary, events)
    zip_path = tmp_path / "exports" / "concurrent.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    analyser.load_exports()

    # Should have processed events into timeline
    assert len(analyser.all_athena_events) == 5


def test_summary_json_structure(tmp_path):
    """Test that the summary structure matches what the analyser expects."""
    summary = make_summary()

    # Verify all required keys exist
    required_keys = [
        "analysis_period", "configuration", "overview",
        "workgroup_stats", "user_stats", "database_stats",
        "query_patterns", "s3_bucket_stats", "hourly_query_counts", "errors",
    ]
    for key in required_keys:
        assert key in summary, f"Missing key in summary: {key}"

    # Create export and verify it loads cleanly
    zip_buf = create_export_zip(summary, make_athena_events())
    zip_path = tmp_path / "exports" / "structure.zip"
    save_export_zip(zip_buf, zip_path)

    analyser = analyse_exports.AthenaExportAnalyser(tmp_path / "exports")
    count = analyser.load_exports()
    assert count == 1
    assert len(analyser.processing_errors) == 0
