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
        console.print(f"    Enable it: aws events enable-rule --name {rule_name} --region {region}")

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
    outputs: Dict[str, str], env: Dict[str, str], region: str
) -> bool:
    """Check 6: Cross-account roles in remote accounts."""
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
                # Get local account
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
            # Fall back to MONITORED_ACCOUNT_IDS if set
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

    # Test each remote account
    console.print()
    all_ok = True
    accounts_with_no_events: List[str] = []
    results_table = Table(box=box.SIMPLE, pad_edge=True)
    results_table.add_column("Account", style="cyan", min_width=14)
    results_table.add_column("Role", style="white")
    results_table.add_column("AssumeRole", style="white")
    results_table.add_column("CloudTrail", style="white")
    results_table.add_column("Athena API", style="white")
    results_table.add_column("Athena Events", style="white")

    for acct_id in account_ids:
        role_ok, role_msg = _check_role_exists(
            acct_id, CROSS_ACCOUNT_ROLE_NAME, external_id, region
        )

        if not role_ok:
            results_table.add_row(
                acct_id,
                CROSS_ACCOUNT_ROLE_NAME,
                f"[red]✗[/red] {role_msg}",
                "[dim]-[/dim]",
                "[dim]-[/dim]",
                "[dim]-[/dim]",
            )
            all_ok = False
            continue

        # Role assumed — now test CloudTrail and Athena access
        # We need to use the temp credentials from AssumeRole
        assume_args = [
            "sts", "assume-role",
            "--role-arn", f"arn:aws:iam::{acct_id}:role/{CROSS_ACCOUNT_ROLE_NAME}",
            "--role-session-name", "VerifySetup",
            "--duration-seconds", "900",
        ]
        if external_id:
            assume_args += ["--external-id", external_id]
        ok, assume_output = run_aws(assume_args, region=region)
        if not ok:
            results_table.add_row(
                acct_id, CROSS_ACCOUNT_ROLE_NAME,
                "[red]✗[/red]", "[dim]-[/dim]", "[dim]-[/dim]", "[dim]-[/dim]",
            )
            all_ok = False
            continue

        try:
            creds = json.loads(assume_output).get("Credentials", {})
        except json.JSONDecodeError:
            results_table.add_row(
                acct_id, CROSS_ACCOUNT_ROLE_NAME,
                "[red]✗[/red]", "[dim]-[/dim]", "[dim]-[/dim]", "[dim]-[/dim]",
            )
            all_ok = False
            continue

        # Set temp creds as env vars for subprocess calls
        cred_env = {
            "AWS_ACCESS_KEY_ID": creds.get("AccessKeyId", ""),
            "AWS_SECRET_ACCESS_KEY": creds.get("SecretAccessKey", ""),
            "AWS_SESSION_TOKEN": creds.get("SessionToken", ""),
        }

        # Test CloudTrail access (permission check)
        ct_ok = _test_remote_api(
            [
                "cloudtrail", "lookup-events",
                "--max-results", "1",
            ],
            region, cred_env,
        )

        # Test Athena access (permission check)
        athena_ok = _test_remote_api(
            ["athena", "list-work-groups", "--max-results", "1"],
            region, cred_env,
        )

        # Check for actual Athena events in this account's CloudTrail
        athena_events = _count_remote_athena_events(region, cred_env)

        ct_status = "[green]✓[/green]" if ct_ok else "[red]✗[/red]"
        athena_status = "[green]✓[/green]" if athena_ok else "[red]✗[/red]"
        events_status = (
            f"[green]✓ {athena_events} events[/green]"
            if athena_events > 0
            else "[yellow]0 events[/yellow]"
        )

        results_table.add_row(
            acct_id, CROSS_ACCOUNT_ROLE_NAME,
            "[green]✓[/green]", ct_status, athena_status, events_status,
        )
        if not ct_ok or not athena_ok:
            all_ok = False
        if athena_events == 0:
            accounts_with_no_events.append(acct_id)

    console.print(results_table)

    # Diagnosis for accounts with no Athena events
    if accounts_with_no_events:
        console.print()
        console.print(
            Panel(
                f"  {len(accounts_with_no_events)} account(s) have no recent Athena events:\n"
                f"  {', '.join(accounts_with_no_events)}\n"
                "\n"
                "  Possible reasons:\n"
                "  1. No one has run Athena queries in these accounts recently\n"
                "  2. CloudTrail management events are not enabled in these accounts\n"
                "  3. The org trail is not capturing events from these accounts\n"
                "     → Check the org trail's event selectors include management events\n"
                "  4. Events are present but the Athena event source filter found nothing\n"
                "     → Run a test query in the remote account and wait a few minutes\n"
                "\n"
                "  [bold]To check manually from a remote account:[/bold]\n"
                "  aws cloudtrail lookup-events \\\n"
                "    --lookup-attributes AttributeKey=EventSource,AttributeValue=athena.amazonaws.com \\\n"
                "    --max-results 5",
                title="[yellow]No Athena Events in Remote Accounts[/yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )

    if not all_ok:
        console.print()
        console.print(
            Panel(
                "  Some remote accounts failed verification.\n"
                "\n"
                "  Common causes:\n"
                "  1. Cross-account role does not exist in the remote account\n"
                "     → Deploy the StackSet or manually create the role\n"
                "  2. Trust policy mismatch (wrong collector account or external ID)\n"
                "     → Check the role's trust policy in IAM\n"
                "  3. The Lambda role lacks sts:AssumeRole permission\n"
                "     → Redeploy with multi-account mode enabled\n"
                "\n"
                "  [bold]To manually create the role in a remote account:[/bold]\n"
                "  aws cloudformation create-stack \\\n"
                "    --stack-name AthenaUsageAnalyserRole \\\n"
                "    --template-body file://cloudformation/cross-account-role.json \\\n"
                "    --capabilities CAPABILITY_NAMED_IAM \\\n"
                "    --parameters \\\n"
                "      ParameterKey=CollectorAccountId,ParameterValue=<YOUR_COLLECTOR_ACCOUNT> \\\n"
                "      ParameterKey=CollectorStackName,ParameterValue=<YOUR_STACK_NAME> \\\n"
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
    xaccount_ok = check_cross_account_roles(outputs, env, region)
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
