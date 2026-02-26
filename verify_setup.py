#!/usr/bin/env python3
"""Verify that the Athena Usage Analyser deployment is configured correctly.

Reads the deploy config (.deploy_config.json) and checks:
  1. CloudFormation stack exists and is healthy
  2. Lambda function is configured correctly
  3. EventBridge schedule rule exists
  4. S3 analysis bucket is accessible
  5. CloudTrail is logging events
  6. Cross-account roles exist and are assumable (multi-account/org mode)
  7. Test invocation of the Lambda with a short lookback
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Bootstrap: install Rich if needed, then import
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from _helpers import install_dependencies, run_aws, get_default_region

install_dependencies(["rich"])

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CROSS_ACCOUNT_ROLE_NAME = "AthenaUsageAnalyserReadRole"


def _load_deploy_config() -> Optional[Dict[str, str]]:
    """Load stack name and region from .deploy_config.json."""
    config_path = SCRIPT_DIR / ".deploy_config.json"
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _get_stack_outputs(stack_name: str, region: str) -> Optional[Dict[str, str]]:
    """Get CloudFormation stack outputs as a dict."""
    ok, output = run_aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack_name],
        region=region,
    )
    if not ok:
        return None
    try:
        stack = json.loads(output).get("Stacks", [{}])[0]
        return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    except (json.JSONDecodeError, IndexError, KeyError):
        return None


def _get_stack_parameters(stack_name: str, region: str) -> Dict[str, str]:
    """Get CloudFormation stack parameters as a dict."""
    ok, output = run_aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack_name],
        region=region,
    )
    if not ok:
        return {}
    try:
        stack = json.loads(output).get("Stacks", [{}])[0]
        return {
            p["ParameterKey"]: p["ParameterValue"]
            for p in stack.get("Parameters", [])
        }
    except (json.JSONDecodeError, IndexError, KeyError):
        return {}


def _get_lambda_env(function_name: str, region: str) -> Dict[str, str]:
    """Get Lambda environment variables."""
    ok, output = run_aws(
        ["lambda", "get-function-configuration", "--function-name", function_name],
        region=region,
    )
    if not ok:
        return {}
    try:
        return json.loads(output).get("Environment", {}).get("Variables", {})
    except (json.JSONDecodeError, KeyError):
        return {}


def _get_caller_identity(region: str) -> Optional[Dict[str, str]]:
    """Get current AWS caller identity."""
    ok, output = run_aws(["sts", "get-caller-identity"], region=region)
    if not ok:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def _check_role_exists(account_id: str, role_name: str, external_id: str,
                       region: str) -> Tuple[bool, str]:
    """Try to assume a cross-account role. Returns (success, message)."""
    assume_args = [
        "sts", "assume-role",
        "--role-arn", f"arn:aws:iam::{account_id}:role/{role_name}",
        "--role-session-name", "VerifySetup",
        "--duration-seconds", "900",
    ]
    if external_id:
        assume_args += ["--external-id", external_id]

    ok, output = run_aws(assume_args, region=region)
    if ok:
        return True, "Role assumed successfully"
    # Parse common errors
    if "AccessDenied" in output:
        return False, "AccessDenied — role may not exist or trust policy is misconfigured"
    if "not authorized" in output.lower():
        return False, f"Not authorised — Lambda role may lack sts:AssumeRole permission"
    return False, output.split("\n")[0] if output else "Unknown error"


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_stack(stack_name: str, region: str) -> Tuple[bool, Dict[str, str]]:
    """Check 1: CloudFormation stack exists and is healthy."""
    console.print("\n[bold]1. CloudFormation Stack[/bold]")

    ok, output = run_aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack_name],
        region=region,
    )
    if not ok:
        console.print(f"  [red]✗[/red] Stack '{stack_name}' not found in {region}")
        console.print(f"    {output}")
        return False, {}

    try:
        stack = json.loads(output).get("Stacks", [{}])[0]
    except (json.JSONDecodeError, IndexError):
        console.print("  [red]✗[/red] Could not parse stack response")
        return False, {}

    status = stack.get("StackStatus", "UNKNOWN")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    if "COMPLETE" in status and "ROLLBACK" not in status:
        console.print(f"  [green]✓[/green] Stack status: {status}")
    else:
        console.print(f"  [red]✗[/red] Stack status: {status}")
        if "ROLLBACK" in status:
            console.print("    Stack is in a failed state. Delete and redeploy.")
        return False, outputs

    # Show key outputs
    for key in ["LambdaFunctionName", "AnalysisBucketName", "ExportsLocation",
                "AnalysisMode", "MonitoredAccountIds", "MultiAccountMethod", "OrganizationId"]:
        if key in outputs:
            console.print(f"  [green]✓[/green] {key}: {outputs[key]}")

    return True, outputs


def check_lambda(outputs: Dict[str, str], region: str) -> bool:
    """Check 2: Lambda function configuration."""
    console.print("\n[bold]2. Lambda Function[/bold]")

    fn_name = outputs.get("LambdaFunctionName", "")
    if not fn_name:
        console.print("  [red]✗[/red] LambdaFunctionName not in stack outputs")
        return False

    env = _get_lambda_env(fn_name, region)
    if not env:
        console.print(f"  [red]✗[/red] Could not get Lambda config for '{fn_name}'")
        return False

    console.print(f"  [green]✓[/green] Lambda function: {fn_name}")

    # Check critical env vars
    all_ok = True
    critical_vars = ["OUTPUT_BUCKET", "ANALYSIS_MODE"]
    for var in critical_vars:
        val = env.get(var, "")
        if val:
            console.print(f"  [green]✓[/green] {var} = {val}")
        else:
            console.print(f"  [red]✗[/red] {var} is not set")
            all_ok = False

    # Show informational env vars
    info_vars = [
        "LOOKBACK_MINUTES", "ATHENA_WORKGROUPS", "S3_BUCKETS_TO_MONITOR",
        "MONITORED_ACCOUNT_IDS", "CROSS_ACCOUNT_EXTERNAL_ID",
        "MULTI_ACCOUNT_METHOD", "ORGANIZATION_ID", "ORG_TRAIL_BUCKET",
    ]
    for var in info_vars:
        val = env.get(var, "")
        if val:
            # Mask the external ID
            display_val = val
            if var == "CROSS_ACCOUNT_EXTERNAL_ID":
                display_val = val[:4] + "****" if len(val) > 4 else "****"
            console.print(f"  [dim]  {var} = {display_val}[/dim]")

    return all_ok


def check_schedule(stack_name: str, region: str) -> bool:
    """Check 3: EventBridge schedule rule."""
    console.print("\n[bold]3. EventBridge Schedule[/bold]")

    rule_name = f"{stack_name}-schedule"
    ok, output = run_aws(
        ["events", "describe-rule", "--name", rule_name],
        region=region,
    )
    if not ok:
        console.print(f"  [red]✗[/red] Schedule rule '{rule_name}' not found")
        return False

    try:
        rule = json.loads(output)
    except json.JSONDecodeError:
        console.print("  [red]✗[/red] Could not parse rule response")
        return False

    state = rule.get("State", "UNKNOWN")
    schedule = rule.get("ScheduleExpression", "UNKNOWN")

    if state == "ENABLED":
        console.print(f"  [green]✓[/green] Schedule: {schedule} (ENABLED)")
    else:
        console.print(f"  [yellow]![/yellow] Schedule: {schedule} ({state})")
        console.print("    The schedule is disabled. The Lambda won't run automatically.")

        # Auto-enable
        console.print("    Enabling schedule...")
        enable_ok, enable_output = run_aws(
            ["events", "enable-rule", "--name", rule_name],
            region=region,
        )
        if enable_ok:
            console.print(f"  [green]✓[/green] Schedule enabled successfully")
        else:
            console.print(f"  [red]✗[/red] Could not enable schedule: {enable_output}")
            console.print(
                f"    Run manually: aws events enable-rule --name {rule_name} --region {region}"
            )

    return True


def check_s3_bucket(outputs: Dict[str, str], region: str) -> bool:
    """Check 4: S3 analysis bucket is accessible."""
    console.print("\n[bold]4. S3 Analysis Bucket[/bold]")

    bucket = outputs.get("AnalysisBucketName", "")
    if not bucket:
        console.print("  [red]✗[/red] AnalysisBucketName not in stack outputs")
        return False

    ok, output = run_aws(
        ["s3api", "head-bucket", "--bucket", bucket],
        region=region,
    )
    if ok:
        console.print(f"  [green]✓[/green] Bucket accessible: {bucket}")
    else:
        console.print(f"  [red]✗[/red] Bucket not accessible: {bucket}")
        console.print(f"    {output}")
        return False

    # Check for existing exports
    ok, output = run_aws(
        ["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", "exports/",
         "--max-keys", "5"],
        region=region,
    )
    if ok:
        try:
            objects = json.loads(output).get("Contents", [])
            if objects:
                console.print(f"  [green]✓[/green] Found {len(objects)}+ export file(s)")
                latest = objects[-1]
                console.print(f"    Latest: {latest.get('Key', '')} ({latest.get('LastModified', '')})")
            else:
                console.print(
                    "  [yellow]![/yellow] No exports yet — Lambda may not have run, or no data was found"
                )
        except json.JSONDecodeError:
            console.print("  [yellow]![/yellow] No exports yet")

    # Check for reports
    ok, output = run_aws(
        ["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", "reports/",
         "--max-keys", "5"],
        region=region,
    )
    if ok:
        try:
            objects = json.loads(output).get("Contents", [])
            if objects:
                console.print(f"  [green]✓[/green] Found {len(objects)}+ report file(s)")
        except json.JSONDecodeError:
            pass

    return True


def check_cloudtrail(region: str) -> bool:
    """Check 5: CloudTrail is logging management events."""
    console.print("\n[bold]5. CloudTrail[/bold]")

    ok, output = run_aws(["cloudtrail", "describe-trails"], region=region)
    if not ok:
        console.print(f"  [red]✗[/red] Could not describe trails: {output}")
        return False

    try:
        trails = json.loads(output).get("trailList", [])
    except json.JSONDecodeError:
        console.print("  [red]✗[/red] Could not parse trail response")
        return False

    if not trails:
        console.print("  [red]✗[/red] No CloudTrail trails found in this account")
        console.print("    CloudTrail is required to capture Athena API events.")
        return False

    all_ok = False
    for trail in trails:
        name = trail.get("Name", "unknown")
        is_multi = trail.get("IsMultiRegionTrail", False)
        is_org = trail.get("IsOrganizationTrail", False)
        home_region = trail.get("HomeRegion", "")

        # Check if trail is logging
        trail_ok, status_output = run_aws(
            ["cloudtrail", "get-trail-status", "--name", name],
            region=home_region or region,
        )
        is_logging = False
        if trail_ok:
            try:
                is_logging = json.loads(status_output).get("IsLogging", False)
            except json.JSONDecodeError:
                pass

        status_icon = "[green]✓[/green]" if is_logging else "[red]✗[/red]"
        labels = []
        if is_multi:
            labels.append("multi-region")
        if is_org:
            labels.append("org trail")
        label_str = f" ({', '.join(labels)})" if labels else ""

        console.print(
            f"  {status_icon} {name}{label_str} — "
            f"{'logging' if is_logging else 'NOT logging'}"
        )

        # Check event selectors to verify management events are captured
        if is_logging:
            sel_ok, sel_output = run_aws(
                ["cloudtrail", "get-event-selectors", "--trail-name", name],
                region=home_region or region,
            )
            if sel_ok:
                try:
                    sel_data = json.loads(sel_output)
                    # Check basic event selectors
                    selectors = sel_data.get("EventSelectors", [])
                    for sel in selectors:
                        mgmt = sel.get("IncludeManagementEvents", True)
                        read_write = sel.get("ReadWriteType", "All")
                        data_resources = sel.get("DataResources", [])
                        console.print(
                            f"    Events: management={'yes' if mgmt else 'NO'} "
                            f"read/write={read_write} "
                            f"data_resources={len(data_resources)}"
                        )
                        if not mgmt:
                            console.print(
                                "    [red]✗ Management events NOT included — "
                                "Athena API calls will not be logged![/red]"
                            )
                    # Check advanced event selectors
                    advanced = sel_data.get("AdvancedEventSelectors", [])
                    if advanced:
                        has_mgmt = any(
                            any(
                                f.get("Field") == "eventCategory"
                                and "Management" in f.get("Equals", [])
                                for f in sel_item.get("FieldSelectors", [])
                            )
                            for sel_item in advanced
                        )
                        console.print(
                            f"    Advanced selectors: {len(advanced)} rule(s), "
                            f"management={'yes' if has_mgmt else 'NO'}"
                        )
                        if not has_mgmt:
                            console.print(
                                "    [red]✗ No management event selector — "
                                "Athena API calls will not be logged![/red]"
                            )
                except json.JSONDecodeError:
                    pass

        # Show trail S3 bucket
        s3_bucket = trail.get("S3BucketName", "")
        if s3_bucket:
            console.print(f"    S3 bucket: {s3_bucket}")

        if is_logging:
            all_ok = True

    if not all_ok:
        console.print("  [red]✗[/red] No active CloudTrail trail found")
        console.print("    At least one trail must be logging for the analyser to work.")

    # Quick check: can we look up recent Athena events?
    ok, output = run_aws(
        [
            "cloudtrail", "lookup-events",
            "--lookup-attributes", "AttributeKey=EventSource,AttributeValue=athena.amazonaws.com",
            "--max-results", "1",
        ],
        region=region,
    )
    if ok:
        try:
            events = json.loads(output).get("Events", [])
            if events:
                event_time = events[0].get("EventTime", "")
                event_name = events[0].get("EventName", "")
                console.print(
                    f"  [green]✓[/green] Recent Athena event found: {event_name} ({event_time})"
                )
            else:
                console.print(
                    "  [yellow]![/yellow] No Athena events found in CloudTrail yet"
                )
                console.print(
                    "    Run some Athena queries and wait a few minutes for events to appear."
                )
        except json.JSONDecodeError:
            pass

    return all_ok


def check_cross_account_roles(
    outputs: Dict[str, str], env: Dict[str, str], region: str,
    stack_name: str,
) -> bool:
    """Check 6: Cross-account roles in remote accounts.

    The cross-account role trusts the *Lambda execution role*, not the user
    running this script.  So instead of trying to assume the role directly
    (which will always fail from EC2), we:
      a) Check StackSet instance deployment status (did the role get deployed?)
      b) Attempt assume-role via the Lambda role (chain through it)
      c) Show clear guidance when direct assume fails
    """
    console.print("\n[bold]6. Cross-Account Roles[/bold]")

    analysis_mode = env.get("ANALYSIS_MODE", outputs.get("AnalysisMode", "single"))
    if analysis_mode == "single":
        console.print("  [dim]Skipped — single-account mode[/dim]")
        return True

    method = env.get("MULTI_ACCOUNT_METHOD", outputs.get("MultiAccountMethod", "manual"))
    external_id = env.get("CROSS_ACCOUNT_EXTERNAL_ID", "")

    # Determine account list
    account_ids: List[str] = []
    if method == "org":
        org_id = env.get("ORGANIZATION_ID", "")
        console.print(f"  Mode: Organization ({org_id})")

        # Try to list accounts from Organizations
        ok, output = run_aws(
            ["organizations", "list-accounts"],
            region=region,
        )
        if ok:
            try:
                accounts = json.loads(output).get("Accounts", [])
                identity = _get_caller_identity(region)
                local_account = identity.get("Account", "") if identity else ""

                for acct in accounts:
                    if acct.get("Status") == "ACTIVE" and acct.get("Id") != local_account:
                        account_ids.append(acct["Id"])
                console.print(
                    f"  [green]✓[/green] Organizations API accessible — "
                    f"found {len(account_ids)} remote account(s)"
                )
            except json.JSONDecodeError:
                console.print("  [red]✗[/red] Could not parse Organizations response")
                return False
        else:
            console.print(f"  [red]✗[/red] Cannot list accounts: {output}")
            console.print(
                "    The Lambda role needs organizations:ListAccounts permission."
            )
            monitored = env.get("MONITORED_ACCOUNT_IDS", "")
            if monitored:
                account_ids = [a.strip() for a in monitored.split(",") if a.strip()]
                console.print(
                    f"  [yellow]![/yellow] Falling back to MONITORED_ACCOUNT_IDS: "
                    f"{len(account_ids)} account(s)"
                )
    else:
        monitored = env.get("MONITORED_ACCOUNT_IDS", "")
        if not monitored:
            console.print("  [red]✗[/red] MONITORED_ACCOUNT_IDS is empty")
            console.print("    Multi-account mode requires account IDs to be configured.")
            return False
        account_ids = [a.strip() for a in monitored.split(",") if a.strip()]
        console.print(f"  Mode: Manual — {len(account_ids)} remote account(s)")

    if not account_ids:
        console.print("  [yellow]![/yellow] No remote accounts to check")
        return True

    # Check org trail bucket if org mode
    if method == "org":
        org_trail_bucket = env.get("ORG_TRAIL_BUCKET", "")
        if org_trail_bucket:
            ok, output = run_aws(
                ["s3api", "head-bucket", "--bucket", org_trail_bucket],
                region=region,
            )
            if ok:
                console.print(f"  [green]✓[/green] Org trail bucket accessible: {org_trail_bucket}")
            else:
                console.print(f"  [red]✗[/red] Org trail bucket NOT accessible: {org_trail_bucket}")
                console.print(f"    {output}")
        else:
            console.print(
                "  [yellow]![/yellow] ORG_TRAIL_BUCKET not set — "
                "Lambda will use per-account CloudTrail API (slower)"
            )

    # --- Check StackSet deployment status ---
    console.print()
    stackset_name = "AthenaUsageAnalyserRole"
    stackset_ok, stackset_output = run_aws(
        [
            "cloudformation", "list-stack-instances",
            "--stack-set-name", stackset_name,
        ],
        region=region,
    )

    stackset_instances: Dict[str, Dict] = {}
    if stackset_ok:
        try:
            summaries = json.loads(stackset_output).get("Summaries", [])
            for s in summaries:
                stackset_instances[s.get("Account", "")] = s
            console.print(
                f"  [green]✓[/green] StackSet '{stackset_name}' has "
                f"{len(summaries)} instance(s)"
            )
        except json.JSONDecodeError:
            pass
    else:
        console.print(
            f"  [yellow]![/yellow] StackSet '{stackset_name}' not found — "
            "roles may have been deployed manually"
        )

    # --- Attempt to assume the Lambda execution role for chained role testing ---
    lambda_role_name = f"{stack_name}-lambda-role"
    identity = _get_caller_identity(region)
    local_account = identity.get("Account", "") if identity else ""
    lambda_role_arn = f"arn:aws:iam::{local_account}:role/{lambda_role_name}"

    console.print()
    console.print(f"  Assuming Lambda role to test cross-account access...")
    console.print(f"  [dim]{lambda_role_arn}[/dim]")

    lambda_assume_ok, lambda_assume_output = run_aws(
        [
            "sts", "assume-role",
            "--role-arn", lambda_role_arn,
            "--role-session-name", "VerifySetupChained",
            "--duration-seconds", "900",
        ],
        region=region,
    )

    lambda_creds: Optional[Dict[str, str]] = None
    if lambda_assume_ok:
        try:
            creds_raw = json.loads(lambda_assume_output).get("Credentials", {})
            lambda_creds = {
                "AWS_ACCESS_KEY_ID": creds_raw.get("AccessKeyId", ""),
                "AWS_SECRET_ACCESS_KEY": creds_raw.get("SecretAccessKey", ""),
                "AWS_SESSION_TOKEN": creds_raw.get("SessionToken", ""),
            }
            console.print(f"  [green]✓[/green] Assumed Lambda role successfully")
        except json.JSONDecodeError:
            lambda_creds = None

    if not lambda_creds:
        console.print(
            f"  [yellow]![/yellow] Cannot assume Lambda role from this session"
        )
        console.print(
            "    The cross-account role trusts only the Lambda execution role, not your\n"
            "    current credentials. This is expected if you are running as an EC2 user.\n"
            "    [bold]Step 7 (Test Lambda Invocation) will verify cross-account access instead.[/bold]"
        )

    # --- Build results table ---
    console.print()
    all_ok = True
    accounts_with_no_events: List[str] = []
    results_table = Table(box=box.SIMPLE, pad_edge=True)
    results_table.add_column("Account", style="cyan", min_width=14)
    results_table.add_column("StackSet", style="white")

    if lambda_creds:
        results_table.add_column("AssumeRole", style="white")
        results_table.add_column("CloudTrail", style="white")
        results_table.add_column("Athena API", style="white")
        results_table.add_column("Athena Events", style="white")

    for acct_id in account_ids:
        # Check StackSet deployment status for this account
        instance = stackset_instances.get(acct_id)
        if instance:
            ss_status = instance.get("Status", "UNKNOWN")
            if ss_status == "CURRENT":
                ss_display = "[green]✓ deployed[/green]"
            elif "FAILED" in ss_status or "OUTDATED" in ss_status:
                reason = instance.get("StatusReason", "")
                ss_display = f"[red]✗ {ss_status}[/red]"
                if reason:
                    ss_display += f" ({reason[:50]})"
                all_ok = False
            else:
                ss_display = f"[yellow]{ss_status}[/yellow]"
        else:
            ss_display = "[red]✗ not deployed[/red]"
            all_ok = False

        if not lambda_creds:
            results_table.add_row(acct_id, ss_display)
            continue

        # We have Lambda creds — try to chain-assume the cross-account role
        assume_args = [
            "sts", "assume-role",
            "--role-arn", f"arn:aws:iam::{acct_id}:role/{CROSS_ACCOUNT_ROLE_NAME}",
            "--role-session-name", "VerifySetupChained",
            "--duration-seconds", "900",
        ]
        if external_id:
            assume_args += ["--external-id", external_id]

        ok, assume_output = _run_remote_aws(assume_args, region, lambda_creds)
        if not ok:
            results_table.add_row(
                acct_id, ss_display,
                f"[red]✗[/red]", "[dim]-[/dim]", "[dim]-[/dim]", "[dim]-[/dim]",
            )
            all_ok = False
            continue

        try:
            remote_creds_raw = json.loads(assume_output).get("Credentials", {})
            remote_creds = {
                "AWS_ACCESS_KEY_ID": remote_creds_raw.get("AccessKeyId", ""),
                "AWS_SECRET_ACCESS_KEY": remote_creds_raw.get("SecretAccessKey", ""),
                "AWS_SESSION_TOKEN": remote_creds_raw.get("SessionToken", ""),
            }
        except (json.JSONDecodeError, AttributeError):
            results_table.add_row(
                acct_id, ss_display,
                "[red]✗[/red]", "[dim]-[/dim]", "[dim]-[/dim]", "[dim]-[/dim]",
            )
            all_ok = False
            continue

        # Test CloudTrail access
        ct_ok = _test_remote_api(
            ["cloudtrail", "lookup-events", "--max-results", "1"],
            region, remote_creds,
        )

        # Test Athena access
        athena_ok = _test_remote_api(
            ["athena", "list-work-groups", "--max-results", "1"],
            region, remote_creds,
        )

        # Check for actual Athena events
        athena_events = _count_remote_athena_events(region, remote_creds)

        ct_status = "[green]✓[/green]" if ct_ok else "[red]✗[/red]"
        athena_status = "[green]✓[/green]" if athena_ok else "[red]✗[/red]"
        events_status = (
            f"[green]✓ {athena_events} events[/green]"
            if athena_events > 0
            else "[yellow]0 events[/yellow]"
        )

        results_table.add_row(
            acct_id, ss_display,
            "[green]✓[/green]", ct_status, athena_status, events_status,
        )
        if not ct_ok or not athena_ok:
            all_ok = False
        if athena_events == 0:
            accounts_with_no_events.append(acct_id)

    console.print(results_table)

    # Fix OUTDATED StackSet instances
    outdated_accounts = [
        acct_id for acct_id in account_ids
        if stackset_instances.get(acct_id, {}).get("Status") == "OUTDATED"
    ]
    not_deployed_accounts = [
        acct_id for acct_id in account_ids
        if acct_id not in stackset_instances
    ]

    op_in_progress = False
    if (outdated_accounts or not_deployed_accounts) and stackset_ok:
        # Check if a StackSet operation is already in progress
        list_ops_ok, list_ops_output = run_aws(
            [
                "cloudformation", "list-stack-set-operations",
                "--stack-set-name", stackset_name,
                "--max-results", "1",
            ],
            region=region,
        )
        if list_ops_ok:
            try:
                ops = json.loads(list_ops_output).get("Summaries", [])
                if ops and ops[0].get("Status") == "RUNNING":
                    op_in_progress = True
                    op_id = ops[0].get("OperationId", "")
                    console.print()
                    console.print(
                        f"  [yellow]![/yellow] A StackSet operation is already in progress"
                    )
                    console.print(
                        f"    Operation: {op_id[:40]}..."
                    )
                    console.print(
                        "    Waiting for it to complete before updating..."
                    )
            except json.JSONDecodeError:
                pass

        if op_in_progress:
            # Wait for the in-progress operation to finish (up to 5 minutes)
            import time
            waited = 0
            max_wait = 300
            while waited < max_wait:
                time.sleep(15)
                waited += 15
                console.print(f"    [dim]Waiting... ({waited}s)[/dim]")
                check_ok, check_output = run_aws(
                    [
                        "cloudformation", "list-stack-set-operations",
                        "--stack-set-name", stackset_name,
                        "--max-results", "1",
                    ],
                    region=region,
                )
                if check_ok:
                    try:
                        ops = json.loads(check_output).get("Summaries", [])
                        if not ops or ops[0].get("Status") != "RUNNING":
                            console.print(
                                f"  [green]✓[/green] Previous operation completed"
                            )
                            op_in_progress = False
                            break
                    except json.JSONDecodeError:
                        break

            if op_in_progress:
                console.print(
                    "  [yellow]![/yellow] Previous operation still running after 5 minutes"
                )
                console.print(
                    "    Re-run this script later to update OUTDATED instances."
                )

    if outdated_accounts and stackset_ok and not op_in_progress:
        console.print()
        console.print(
            f"  [yellow]![/yellow] {len(outdated_accounts)} account(s) have OUTDATED StackSet instances"
        )
        console.print("    Updating now...")

        update_ok, update_output = run_aws(
            [
                "cloudformation", "update-stack-instances",
                "--stack-set-name", stackset_name,
                "--accounts", *outdated_accounts,
                "--regions", region,
            ],
            region=region,
        )
        if update_ok:
            console.print(
                f"  [green]✓[/green] StackSet update initiated for {len(outdated_accounts)} account(s)"
            )
            console.print(
                "    This may take a few minutes. Re-run this script to check progress."
            )
        else:
            console.print(
                f"  [red]✗[/red] Could not update: {update_output}"
            )

    if not_deployed_accounts and stackset_ok and not op_in_progress:
        console.print()
        console.print(
            f"  [yellow]![/yellow] {len(not_deployed_accounts)} account(s) have no StackSet instance"
        )
        console.print("    Creating now...")

        create_ok, create_output = run_aws(
            [
                "cloudformation", "create-stack-instances",
                "--stack-set-name", stackset_name,
                "--accounts", *not_deployed_accounts,
                "--regions", region,
            ],
            region=region,
        )
        if create_ok:
            console.print(
                f"  [green]✓[/green] StackSet deployment initiated for {len(not_deployed_accounts)} account(s)"
            )
        else:
            console.print(
                f"  [red]✗[/red] Could not create: {create_output}"
            )

    # Diagnosis for accounts with no Athena events
    if accounts_with_no_events and lambda_creds:
        console.print()
        console.print(
            Panel(
                f"  {len(accounts_with_no_events)} account(s) have no recent Athena events:\n"
                f"  {', '.join(accounts_with_no_events[:10])}"
                + (f"\n  ...and {len(accounts_with_no_events) - 10} more"
                   if len(accounts_with_no_events) > 10 else "")
                + "\n"
                "\n"
                "  Possible reasons:\n"
                "  1. No one has run Athena queries in these accounts recently\n"
                "  2. CloudTrail management events are not enabled in these accounts\n"
                "  3. The org trail is not capturing events from these accounts\n"
                "     → Check the org trail event selectors include management events\n"
                "  4. Events exist but not for athena.amazonaws.com yet\n"
                "     → Run a test query in the remote account and wait ~5 minutes\n"
                "\n"
                "  [bold]To check manually from a remote account:[/bold]\n"
                "  aws cloudtrail lookup-events \\\n"
                "    --lookup-attributes AttributeKey=EventSource,"
                "AttributeValue=athena.amazonaws.com \\\n"
                "    --max-results 5",
                title="[yellow]No Athena Events in Remote Accounts[/yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

    if not all_ok:
        console.print()
        identity = _get_caller_identity(region)
        local_acct = identity.get("Account", "<YOUR_COLLECTOR_ACCOUNT>") if identity else "<YOUR_COLLECTOR_ACCOUNT>"
        console.print(
            Panel(
                "  Some remote accounts failed verification.\n"
                "\n"
                "  Common causes:\n"
                "  1. Cross-account role not deployed in remote account\n"
                "     → Check StackSet status or deploy manually (see below)\n"
                "  2. Trust policy references wrong collector account or external ID\n"
                f"     → Collector account: {local_acct}\n"
                f"     → Stack name: {stack_name}\n"
                f"     → Lambda role: {stack_name}-lambda-role\n"
                "  3. External ID mismatch between collector and remote roles\n"
                "\n"
                "  [bold]To manually deploy the role in a remote account:[/bold]\n"
                "  aws cloudformation create-stack \\\n"
                "    --stack-name AthenaUsageAnalyserRole \\\n"
                "    --template-body file://cloudformation/cross-account-role.json \\\n"
                "    --capabilities CAPABILITY_NAMED_IAM \\\n"
                "    --parameters \\\n"
                f"      ParameterKey=CollectorAccountId,ParameterValue={local_acct} \\\n"
                f"      ParameterKey=CollectorStackName,ParameterValue={stack_name} \\\n"
                "      ParameterKey=ExternalId,ParameterValue=<YOUR_EXTERNAL_ID>",
                title="[yellow]Troubleshooting[/yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

    return all_ok


def _test_remote_api(args: List[str], region: str,
                     cred_env: Dict[str, str]) -> bool:
    """Run an AWS CLI command with assumed-role credentials."""
    import os
    cmd = ["aws"] + args + ["--region", region, "--output", "json", "--no-cli-pager"]
    env = {**os.environ, **cred_env}
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _run_remote_aws(args: List[str], region: str,
                    cred_env: Dict[str, str]) -> Tuple[bool, str]:
    """Run an AWS CLI command with assumed-role credentials, return output."""
    import os
    cmd = ["aws"] + args + ["--region", region, "--output", "json", "--no-cli-pager"]
    env = {**os.environ, **cred_env}
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env,
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)


def _count_remote_athena_events(region: str, cred_env: Dict[str, str]) -> int:
    """Count recent Athena CloudTrail events in a remote account."""
    ok, output = _run_remote_aws(
        [
            "cloudtrail", "lookup-events",
            "--lookup-attributes",
            "AttributeKey=EventSource,AttributeValue=athena.amazonaws.com",
            "--max-results", "10",
        ],
        region, cred_env,
    )
    if not ok:
        return 0
    try:
        return len(json.loads(output).get("Events", []))
    except json.JSONDecodeError:
        return 0


def check_test_invocation(outputs: Dict[str, str], region: str) -> bool:
    """Check 7: Test invoke the Lambda with a short lookback."""
    console.print("\n[bold]7. Test Lambda Invocation[/bold]")

    fn_name = outputs.get("LambdaFunctionName", "")
    if not fn_name:
        console.print("  [red]✗[/red] No Lambda function name available")
        return False

    console.print(
        f"  Invoking {fn_name} with 5-minute lookback..."
    )
    console.print("  [dim]This may take up to 60 seconds.[/dim]")

    # Create a temp output file path
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        output_file = f.name

    payload = json.dumps({"lookback_minutes": 5})

    ok, output = run_aws(
        [
            "lambda", "invoke",
            "--function-name", fn_name,
            "--payload", payload,
            "--cli-read-timeout", "120",
            output_file,
        ],
        region=region,
        timeout=180,
    )

    if not ok:
        console.print(f"  [red]✗[/red] Invocation failed: {output}")
        return False

    # Check invocation result
    try:
        invoke_meta = json.loads(output)
    except json.JSONDecodeError:
        invoke_meta = {}

    status_code = invoke_meta.get("StatusCode", 0)
    fn_error = invoke_meta.get("FunctionError", "")

    if fn_error:
        console.print(f"  [red]✗[/red] Lambda returned error: {fn_error}")
        # Read the output file for details
        try:
            error_detail = Path(output_file).read_text()
            try:
                error_json = json.loads(error_detail)
                error_msg = error_json.get("errorMessage", error_detail[:500])
            except json.JSONDecodeError:
                error_msg = error_detail[:500]
            console.print(f"    {error_msg}")
        except OSError:
            pass
        return False

    if status_code == 200:
        console.print(f"  [green]✓[/green] Lambda invoked successfully (HTTP {status_code})")
    else:
        console.print(f"  [yellow]![/yellow] Lambda returned HTTP {status_code}")

    # Parse the Lambda response
    try:
        response = json.loads(Path(output_file).read_text())
    except (json.JSONDecodeError, OSError):
        response = {}

    # Show summary from response
    if isinstance(response, dict):
        body = response
        # Lambda may return a nested body
        if "body" in response:
            try:
                body = json.loads(response["body"]) if isinstance(response["body"], str) else response["body"]
            except (json.JSONDecodeError, TypeError):
                body = response

        # Show accounts processed
        accounts = body.get("accounts_processed", body.get("accounts", []))
        if isinstance(accounts, list):
            console.print(f"  [green]✓[/green] Accounts processed: {len(accounts)}")
            for acct in accounts:
                if isinstance(acct, dict):
                    acct_id = acct.get("account_id", "unknown")
                    events = acct.get("total_events", acct.get("events", 0))
                    error = acct.get("error", "")
                    if error:
                        console.print(f"    [red]✗[/red] {acct_id}: {error}")
                    else:
                        console.print(f"    [green]✓[/green] {acct_id}: {events} events")
                elif isinstance(acct, str):
                    console.print(f"    [green]✓[/green] {acct}")

        # Show total events
        total = body.get("total_events", body.get("total", ""))
        if total:
            console.print(f"  [green]✓[/green] Total events: {total}")

        # Show export location
        export = body.get("export_path", body.get("s3_path", ""))
        if export:
            console.print(f"  [green]✓[/green] Export: {export}")

    # Clean up
    try:
        Path(output_file).unlink()
    except OSError:
        pass

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    console.print(
        Panel(
            "  Verifying Athena Usage Analyser deployment",
            title="[bold]Setup Verification[/bold]",
            border_style="blue",
            padding=(0, 2),
        )
    )

    # Load deploy config
    config = _load_deploy_config()
    if config:
        stack_name = config.get("stack_name", "athena-usage-analyser")
        region = config.get("region", "")
        console.print(f"\n  Using deploy config: stack=[cyan]{stack_name}[/cyan] region=[cyan]{region}[/cyan]")
    else:
        console.print("\n  [yellow]![/yellow] No .deploy_config.json found")
        region = get_default_region() or "us-east-1"
        stack_name = "athena-usage-analyser"
        console.print(f"  Using defaults: stack=[cyan]{stack_name}[/cyan] region=[cyan]{region}[/cyan]")

    # Verify AWS credentials
    identity = _get_caller_identity(region)
    if not identity:
        console.print("\n  [red]✗[/red] AWS credentials not configured or expired")
        console.print("  Run: aws configure  or  aws sso login")
        sys.exit(1)

    console.print(
        f"  Account: [cyan]{identity.get('Account', '')}[/cyan]  "
        f"User: [cyan]{identity.get('Arn', '').split('/')[-1]}[/cyan]"
    )

    # Run checks
    passed = 0
    failed = 0
    warnings = 0
    total = 7

    # 1. Stack
    stack_ok, outputs = check_stack(stack_name, region)
    if stack_ok:
        passed += 1
    else:
        failed += 1
        console.print(
            "\n[red]Stack check failed — cannot continue without a valid stack.[/red]"
        )
        _print_summary(passed, failed, warnings, total)
        sys.exit(1)

    # 2. Lambda
    lambda_ok = check_lambda(outputs, region)
    if lambda_ok:
        passed += 1
    else:
        failed += 1

    # Get Lambda env for cross-account checks
    fn_name = outputs.get("LambdaFunctionName", "")
    env = _get_lambda_env(fn_name, region) if fn_name else {}

    # 3. Schedule
    schedule_ok = check_schedule(stack_name, region)
    if schedule_ok:
        passed += 1
    else:
        warnings += 1

    # 4. S3 Bucket
    s3_ok = check_s3_bucket(outputs, region)
    if s3_ok:
        passed += 1
    else:
        failed += 1

    # 5. CloudTrail
    ct_ok = check_cloudtrail(region)
    if ct_ok:
        passed += 1
    else:
        failed += 1

    # 6. Cross-Account Roles
    xaccount_ok = check_cross_account_roles(outputs, env, region, stack_name)
    if xaccount_ok:
        passed += 1
    else:
        failed += 1

    # 7. Test Invocation
    invoke_ok = check_test_invocation(outputs, region)
    if invoke_ok:
        passed += 1
    else:
        failed += 1

    _print_summary(passed, failed, warnings, total)


def _print_summary(passed: int, failed: int, warnings: int, total: int):
    console.print()
    if failed == 0:
        style = "green"
        title = "All Checks Passed"
        icon = "✓"
    else:
        style = "red"
        title = "Issues Found"
        icon = "✗"

    lines = [f"  {icon} {passed}/{total} checks passed"]
    if warnings:
        lines.append(f"  ! {warnings} warning(s)")
    if failed:
        lines.append(f"  ✗ {failed} check(s) failed")
        lines.append("")
        lines.append("  Fix the issues above and re-run this script.")

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[{style}]{title}[/{style}]",
            border_style=style,
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
