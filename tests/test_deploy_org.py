#!/usr/bin/env python3
"""
Tests for the deploy script's AWS Organizations flow.

Mocks AWS CLI calls and interactive prompts to validate the org setup
logic without needing a real AWS environment.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root so we can import deploy
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Mock install_dependencies so it doesn't install packages during tests
with patch("_helpers.install_dependencies"):
    import deploy


# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

ORG_DESCRIBE_RESPONSE = json.dumps({
    "Organization": {
        "Id": "o-abc123def4",
        "Arn": "arn:aws:organizations::111111111111:organization/o-abc123def4",
        "MasterAccountId": "111111111111",
        "MasterAccountEmail": "admin@example.com",
        "AvailableOracleCount": 0,
    }
})

ORG_LIST_ACCOUNTS_RESPONSE = json.dumps({
    "Accounts": [
        {"Id": "111111111111", "Name": "Management", "Email": "admin@example.com", "Status": "ACTIVE"},
        {"Id": "222222222222", "Name": "Production", "Email": "prod@example.com", "Status": "ACTIVE"},
        {"Id": "333333333333", "Name": "Staging", "Email": "staging@example.com", "Status": "ACTIVE"},
        {"Id": "444444444444", "Name": "Old Account", "Email": "old@example.com", "Status": "SUSPENDED"},
    ]
})

ORG_TRAILS_RESPONSE = json.dumps({
    "trailList": [
        {
            "Name": "MyOrgTrail",
            "S3BucketName": "my-org-trail-bucket",
            "IsMultiRegionTrail": True,
            "IsOrganizationTrail": True,
            "HomeRegion": "eu-west-1",
        },
        {
            "Name": "LocalTrail",
            "S3BucketName": "local-trail-bucket",
            "IsMultiRegionTrail": False,
            "IsOrganizationTrail": False,
        },
    ]
})

ORG_TRAILS_NO_ORG_TRAIL = json.dumps({
    "trailList": [
        {
            "Name": "LocalTrail",
            "S3BucketName": "local-trail-bucket",
            "IsMultiRegionTrail": False,
            "IsOrganizationTrail": False,
        },
    ]
})


def mock_run_aws_success(args, region=None):
    """Mock run_aws that returns appropriate responses based on the command."""
    cmd = args[0] if args else ""
    subcmd = args[1] if len(args) > 1 else ""

    if cmd == "organizations" and subcmd == "describe-organization":
        return True, ORG_DESCRIBE_RESPONSE
    if cmd == "organizations" and subcmd == "list-accounts":
        return True, ORG_LIST_ACCOUNTS_RESPONSE
    if cmd == "cloudtrail" and subcmd == "describe-trails":
        return True, ORG_TRAILS_RESPONSE
    return False, "Unknown command"


def mock_run_aws_no_org_trail(args, region=None):
    """Mock run_aws where there's no org trail."""
    cmd = args[0] if args else ""
    subcmd = args[1] if len(args) > 1 else ""

    if cmd == "organizations" and subcmd == "describe-organization":
        return True, ORG_DESCRIBE_RESPONSE
    if cmd == "organizations" and subcmd == "list-accounts":
        return True, ORG_LIST_ACCOUNTS_RESPONSE
    if cmd == "cloudtrail" and subcmd == "describe-trails":
        return True, ORG_TRAILS_NO_ORG_TRAIL
    return False, "Unknown command"


def mock_run_aws_org_failure(args, region=None):
    """Mock run_aws where Organizations API fails."""
    cmd = args[0] if args else ""
    subcmd = args[1] if len(args) > 1 else ""

    if cmd == "organizations" and subcmd == "describe-organization":
        return False, "An error occurred (AWSOrganizationsNotInUseException)"
    return False, "Unknown command"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_step_org_setup_success_with_trail():
    """Test org setup with all APIs succeeding and org trail found."""
    with patch("deploy.run_aws", side_effect=mock_run_aws_success), \
         patch("deploy.Confirm.ask", return_value=True), \
         patch("deploy.Prompt.ask", return_value="test-external-id"):
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    assert result["mode"] == "multi"
    assert result["method"] == "org"
    assert result["org_id"] == "o-abc123def4"
    assert result["org_trail_bucket"] == "my-org-trail-bucket"
    # Should have 2 member accounts (excluding management and suspended)
    assert result["account_ids"] == ["222222222222", "333333333333"]
    assert result["want_enrichment"] is True
    assert result["external_id"] == "test-external-id"


def test_step_org_setup_no_org_trail_manual_bucket():
    """Test org setup when no org trail is found — user provides bucket manually."""
    prompt_responses = iter(["custom-trail-bucket", "ext-id-manual"])

    with patch("deploy.run_aws", side_effect=mock_run_aws_no_org_trail), \
         patch("deploy.Confirm.ask", return_value=True), \
         patch("deploy.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_responses)):
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    assert result["org_trail_bucket"] == "custom-trail-bucket"
    assert result["account_ids"] == ["222222222222", "333333333333"]


def test_step_org_setup_no_org_trail_skip_bucket():
    """Test org setup when no org trail — user skips bucket."""
    prompt_responses = iter(["", "ext-id-skip"])

    with patch("deploy.run_aws", side_effect=mock_run_aws_no_org_trail), \
         patch("deploy.Confirm.ask", return_value=True), \
         patch("deploy.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_responses)):
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    assert result["org_trail_bucket"] == ""


def test_step_org_setup_no_enrichment():
    """Test org setup when user declines cross-account enrichment."""
    with patch("deploy.run_aws", side_effect=mock_run_aws_success), \
         patch("deploy.Confirm.ask", return_value=False):
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    assert result["want_enrichment"] is False
    assert result["external_id"] == ""


def test_step_org_setup_not_management_account():
    """Test org setup when running from a non-management account."""
    with patch("deploy.run_aws", side_effect=mock_run_aws_success), \
         patch("deploy.Confirm.ask", return_value=True), \
         patch("deploy.Prompt.ask", return_value="ext-id-non-mgmt"):
        # Running from account 222222222222 (not the management account)
        result = deploy.step_org_setup("222222222222", "eu-west-1")

    assert result["mode"] == "multi"
    # Only member accounts excluding the collector (222222222222)
    assert "222222222222" not in result["account_ids"]
    assert "111111111111" in result["account_ids"]
    assert "333333333333" in result["account_ids"]


def test_step_org_setup_org_api_failure_fallback():
    """Test org setup when Organizations API fails — user falls back."""
    # When org fails, Confirm.ask offers fallback, then step_analysis_mode is called
    with patch("deploy.run_aws", side_effect=mock_run_aws_org_failure), \
         patch("deploy.Confirm.ask", return_value=True), \
         patch("deploy.step_analysis_mode", return_value={"mode": "single"}) as mock_mode:
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    # Should have fallen back to step_analysis_mode
    mock_mode.assert_called_once_with("111111111111", "eu-west-1")
    assert result["mode"] == "single"


def test_step_org_setup_org_api_failure_exit():
    """Test org setup when Organizations API fails — user declines fallback."""
    with patch("deploy.run_aws", side_effect=mock_run_aws_org_failure), \
         patch("deploy.Confirm.ask", return_value=False):
        try:
            deploy.step_org_setup("111111111111", "eu-west-1")
            assert False, "Should have called sys.exit"
        except SystemExit as e:
            assert e.code == 0


def test_step_analysis_mode_selects_org():
    """Test that selecting option 3 in analysis mode calls step_org_setup."""
    org_config = {
        "mode": "multi",
        "method": "org",
        "org_id": "o-test",
        "org_trail_bucket": "trail-bucket",
        "account_ids": ["222222222222"],
        "external_id": "ext-id",
        "want_enrichment": True,
    }
    with patch("deploy.Prompt.ask", return_value="3"), \
         patch("deploy.step_org_setup", return_value=org_config) as mock_org:
        result = deploy.step_analysis_mode("111111111111", "eu-west-1")

    mock_org.assert_called_once_with("111111111111", "eu-west-1")
    assert result["method"] == "org"


def test_step_analysis_mode_selects_single():
    """Test that selecting option 1 returns single-account config."""
    with patch("deploy.Prompt.ask", return_value="1"):
        result = deploy.step_analysis_mode("111111111111", "eu-west-1")

    assert result["mode"] == "single"


def test_suspended_accounts_excluded():
    """Test that suspended accounts are excluded from the member list."""
    with patch("deploy.run_aws", side_effect=mock_run_aws_success), \
         patch("deploy.Confirm.ask", return_value=False):
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    # Account 444444444444 is SUSPENDED, should not appear
    assert "444444444444" not in result["account_ids"]
    assert len(result["account_ids"]) == 2


def test_config_dict_structure():
    """Validate the full structure of the returned config dict."""
    with patch("deploy.run_aws", side_effect=mock_run_aws_success), \
         patch("deploy.Confirm.ask", return_value=True), \
         patch("deploy.Prompt.ask", return_value="ext-validation"):
        result = deploy.step_org_setup("111111111111", "eu-west-1")

    required_keys = {"mode", "method", "org_id", "org_trail_bucket",
                     "account_ids", "external_id", "want_enrichment"}
    assert set(result.keys()) == required_keys
    assert isinstance(result["account_ids"], list)
    assert all(len(a) == 12 and a.isdigit() for a in result["account_ids"])
