#!/usr/bin/env python3
"""
Tests for per-account S3 bucket configuration.

Covers:
  - Lambda: parse_bucket_config(), get_account_buckets(), should_monitor_bucket()
  - Deploy: encode_bucket_config(), format_bucket_config_display()
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Lambda tests — import the index module with mocked boto3
# ---------------------------------------------------------------------------

# Add project root so we can import modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lambda"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Set required environment variables BEFORE importing index
os.environ.setdefault("OUTPUT_BUCKET", "test-output-bucket")
os.environ.setdefault("CLOUDTRAIL_BUCKET", "")
os.environ.setdefault("LOG_GROUP_NAME", "/test/events")

# Mock boto3 BEFORE importing index
import boto3  # noqa: E402

_real_boto3_client = boto3.client
_mock_clients = {}


def _mock_boto3_client(service_name, **kwargs):
    if service_name not in _mock_clients:
        _mock_clients[service_name] = MagicMock(name=f"mock_{service_name}_client")
    return _mock_clients[service_name]


boto3.client = _mock_boto3_client

import index  # noqa: E402

boto3.client = _real_boto3_client


# ---------------------------------------------------------------------------
# parse_bucket_config tests
# ---------------------------------------------------------------------------


def test_parse_star():
    assert index.parse_bucket_config("*") == {"*": {"*"}}


def test_parse_empty():
    assert index.parse_bucket_config("") == {"*": {"*"}}


def test_parse_whitespace():
    assert index.parse_bucket_config("  ") == {"*": {"*"}}


def test_parse_legacy_csv():
    result = index.parse_bucket_config("bucket1,bucket2")
    assert result == {"*": {"bucket1", "bucket2"}}


def test_parse_legacy_csv_with_spaces():
    result = index.parse_bucket_config(" bucket1 , bucket2 ")
    assert result == {"*": {"bucket1", "bucket2"}}


def test_parse_single_bucket():
    result = index.parse_bucket_config("my-datalake")
    assert result == {"*": {"my-datalake"}}


def test_parse_json_global_only():
    raw = json.dumps({"*": ["*"]})
    result = index.parse_bucket_config(raw)
    assert result == {"*": {"*"}}


def test_parse_json_per_account():
    raw = json.dumps({
        "*": ["*"],
        "111111111111": ["bucketA", "bucketB"],
        "222222222222": ["*"],
    })
    result = index.parse_bucket_config(raw)
    assert result["*"] == {"*"}
    assert result["111111111111"] == {"bucketA", "bucketB"}
    assert result["222222222222"] == {"*"}


def test_parse_json_no_default():
    raw = json.dumps({"111111111111": ["bucketA"]})
    result = index.parse_bucket_config(raw)
    assert "111111111111" in result
    assert result["111111111111"] == {"bucketA"}
    assert "*" not in result


def test_parse_json_explicit_buckets_for_default():
    raw = json.dumps({"*": ["lake", "results"]})
    result = index.parse_bucket_config(raw)
    assert result["*"] == {"lake", "results"}


# ---------------------------------------------------------------------------
# get_account_buckets tests
# ---------------------------------------------------------------------------


def test_get_account_buckets_with_explicit_config():
    config = {
        "*": {"*"},
        "111111111111": {"bucketA", "bucketB"},
    }
    assert index.get_account_buckets("111111111111", config) == {"bucketA", "bucketB"}


def test_get_account_buckets_falls_back_to_default():
    config = {"*": {"*"}, "111111111111": {"bucketA"}}
    assert index.get_account_buckets("999999999999", config) == {"*"}


def test_get_account_buckets_no_account_id():
    config = {"*": {"lake-bucket"}}
    assert index.get_account_buckets(None, config) == {"lake-bucket"}


def test_get_account_buckets_empty_account_id():
    config = {"*": {"lake-bucket"}}
    assert index.get_account_buckets("", config) == {"lake-bucket"}


def test_get_account_buckets_no_default_key():
    config = {"111111111111": {"bucketA"}}
    # Unknown account with no default key -> fallback returns {"*"}
    assert index.get_account_buckets("999999999999", config) == {"*"}


# ---------------------------------------------------------------------------
# should_monitor_bucket tests (integration with AthenaUsageAnalyser)
# ---------------------------------------------------------------------------


def test_should_monitor_bucket_global_star():
    config = {"*": {"*"}}
    with patch.object(index, "BUCKET_CONFIG", config):
        analyser = index.AthenaUsageAnalyser(account_id="111111111111")
        # "athena" matches auto-detect patterns
        assert analyser.should_monitor_bucket("athena-results") is True
        # random bucket should not match auto-detect
        assert analyser.should_monitor_bucket("unrelated-logs") is False


def test_should_monitor_bucket_per_account_explicit():
    config = {
        "*": {"*"},
        "111111111111": {"my-specific-bucket"},
    }
    with patch.object(index, "BUCKET_CONFIG", config):
        # Account with explicit config
        analyser = index.AthenaUsageAnalyser(account_id="111111111111")
        assert analyser.should_monitor_bucket("my-specific-bucket") is True
        assert analyser.should_monitor_bucket("other-bucket") is False

        # Different account falls back to default (auto-detect)
        other = index.AthenaUsageAnalyser(account_id="222222222222")
        assert other.should_monitor_bucket("athena-results") is True
        assert other.should_monitor_bucket("unrelated-logs") is False


def test_should_monitor_bucket_per_account_star():
    config = {
        "*": {"specific-bucket"},
        "111111111111": {"*"},
    }
    with patch.object(index, "BUCKET_CONFIG", config):
        # Account with auto-detect override
        analyser = index.AthenaUsageAnalyser(account_id="111111111111")
        assert analyser.should_monitor_bucket("datalake-prod") is True

        # Default uses explicit list
        other = index.AthenaUsageAnalyser(account_id="222222222222")
        assert other.should_monitor_bucket("specific-bucket") is True
        assert other.should_monitor_bucket("datalake-prod") is False


def test_should_monitor_bucket_no_account_id():
    """Local/single-account mode — no account_id set."""
    config = {"*": {"my-lake", "my-results"}}
    with patch.object(index, "BUCKET_CONFIG", config):
        analyser = index.AthenaUsageAnalyser()
        assert analyser.should_monitor_bucket("my-lake") is True
        assert analyser.should_monitor_bucket("other") is False


# ---------------------------------------------------------------------------
# Deploy script tests — encode_bucket_config, format_bucket_config_display
# ---------------------------------------------------------------------------

# Import deploy with mocked dependencies
with patch("_helpers.install_dependencies"):
    import deploy


def test_encode_all_star():
    assert deploy.encode_bucket_config({"*": ["*"]}) == "*"


def test_encode_all_accounts_star():
    result = deploy.encode_bucket_config({
        "111111111111": ["*"],
        "222222222222": ["*"],
    })
    assert result == "*"


def test_encode_single_default_csv():
    result = deploy.encode_bucket_config({"*": ["bucket1", "bucket2"]})
    assert result == "bucket1,bucket2"


def test_encode_per_account_json():
    bucket_map = {
        "111111111111": ["bucketA"],
        "222222222222": ["*"],
    }
    result = deploy.encode_bucket_config(bucket_map)
    parsed = json.loads(result)
    assert parsed["111111111111"] == ["bucketA"]
    assert parsed["222222222222"] == ["*"]


def test_encode_mixed_star_and_explicit():
    bucket_map = {
        "*": ["*"],
        "111111111111": ["specific-bucket"],
    }
    result = deploy.encode_bucket_config(bucket_map)
    parsed = json.loads(result)
    assert parsed["*"] == ["*"]
    assert parsed["111111111111"] == ["specific-bucket"]


def test_format_display_star():
    assert deploy.format_bucket_config_display("*") == "auto-detect (*)"


def test_format_display_csv():
    assert deploy.format_bucket_config_display("bucket1,bucket2") == "bucket1,bucket2"


def test_format_display_json():
    encoded = json.dumps({"*": ["*"], "111111111111": ["bucketA"]})
    result = deploy.format_bucket_config_display(encoded)
    assert "default: *" in result
    assert "111111111111: bucketA" in result


# ---------------------------------------------------------------------------
# Round-trip: encode -> parse
# ---------------------------------------------------------------------------


def test_roundtrip_star():
    bucket_map = {"*": ["*"]}
    encoded = deploy.encode_bucket_config(bucket_map)
    parsed = index.parse_bucket_config(encoded)
    assert parsed == {"*": {"*"}}


def test_roundtrip_csv():
    bucket_map = {"*": ["bucket1", "bucket2"]}
    encoded = deploy.encode_bucket_config(bucket_map)
    parsed = index.parse_bucket_config(encoded)
    assert parsed == {"*": {"bucket1", "bucket2"}}


def test_roundtrip_per_account():
    bucket_map = {
        "*": ["*"],
        "111111111111": ["bucketA", "bucketB"],
        "222222222222": ["*"],
    }
    encoded = deploy.encode_bucket_config(bucket_map)
    parsed = index.parse_bucket_config(encoded)
    assert parsed["*"] == {"*"}
    assert parsed["111111111111"] == {"bucketA", "bucketB"}
    assert parsed["222222222222"] == {"*"}
