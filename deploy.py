#!/usr/bin/env python3
"""
Athena Usage Analyser — Interactive Deploy Script

Automates CloudTrail verification, optional S3 data event setup, and
CloudFormation stack deployment through an interactive terminal UI.

Usage:
    python3 deploy.py
"""

import json
import re
import subprocess
import sys
import tempfile
import uuid
import zipfile
import io
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure sibling modules are importable regardless of working directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _helpers import install_dependencies, run_aws, get_default_region

install_dependencies(["rich"])

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

console = Console()

TEMPLATE_REL_PATH = Path("cloudformation") / "athena-usage-analyser.json"
CROSS_ACCOUNT_TEMPLATE_REL_PATH = Path("cloudformation") / "cross-account-role.json"
LAMBDA_DIR = Path("lambda")
SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def validate_stack_name(name: str) -> bool:
    """Validate CloudFormation stack name."""
    return bool(re.match(r"^[a-zA-Z][-a-zA-Z0-9]*$", name)) and len(name) <= 128


def validate_account_id(account_id: str) -> bool:
    """Validate a 12-digit AWS account ID."""
    return bool(re.match(r"^\d{12}$", account_id))


def package_lambda() -> bytes:
    """Package the lambda/index.py into a zip file in memory. Returns zip bytes."""
    lambda_path = SCRIPT_DIR / LAMBDA_DIR / "index.py"
    if not lambda_path.exists():
        console.print(
            Panel(
                f"[red]Lambda code not found.[/red]\n\nExpected: {lambda_path}",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(lambda_path, "index.py")
    buf.seek(0)
    return buf.getvalue()


def upload_lambda_code(bucket: str, stack_name: str, region: str) -> Tuple[str, str]:
    """Package and upload Lambda code to S3. Returns (bucket, key)."""
    s3_key = f"lambda-code/{stack_name}/index.zip"
    zip_bytes = package_lambda()

    # Write to temp file for upload
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(zip_bytes)
        tmp_path = tmp.name

    ok, output = run_aws(
        [
            "s3",
            "cp",
            tmp_path,
            f"s3://{bucket}/{s3_key}",
        ],
        region=region,
    )
    # Clean up temp file
    Path(tmp_path).unlink(missing_ok=True)

    if not ok:
        console.print(f"  [red]✗[/red] Failed to upload Lambda code: {output}")
        sys.exit(1)

    return bucket, s3_key


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def preflight_checks() -> Dict:
    """Verify AWS CLI, credentials, and template. Returns context dict."""
    console.print()
    console.print("[bold]Pre-flight Checks[/bold]")
    console.print()

    # 1. AWS CLI
    with console.status("Checking AWS CLI..."):
        result = subprocess.run(["aws", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        console.print(
            Panel(
                "[red]AWS CLI is not installed.[/red]\n\n"
                "Install it from: https://aws.amazon.com/cli/",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)
    version = result.stdout.strip().split()[0] if result.stdout else "unknown"
    console.print(f"  [green]✓[/green] AWS CLI: {version}")

    # 2. AWS credentials (with retry loop)
    account_id = None
    while True:
        with console.status("Checking AWS credentials..."):
            ok, output = run_aws(["sts", "get-caller-identity"])
        if ok:
            identity = json.loads(output)
            account_id = identity.get("Account", "unknown")
            arn = identity.get("Arn", "")
            console.print(f"  [green]✓[/green] Authenticated: {arn}")
            console.print(f"  [green]✓[/green] Account: {account_id}")
            break
        else:
            console.print()
            console.print(
                Panel(
                    "[yellow]AWS credentials are not configured or have expired.[/yellow]\n\n"
                    "Options:\n"
                    "  • Run [bold]aws configure[/bold] to set up access keys\n"
                    "  • Run [bold]aws sso login[/bold] if using SSO\n"
                    "  • Set [bold]AWS_ACCESS_KEY_ID[/bold] and [bold]AWS_SECRET_ACCESS_KEY[/bold] environment variables",
                    title="Authentication Required",
                    border_style="yellow",
                )
            )
            if not Confirm.ask("  Retry after authenticating?", default=True):
                console.print("\n[dim]Cancelled.[/dim]")
                sys.exit(0)

    # 3. Template file
    template_path = SCRIPT_DIR / TEMPLATE_REL_PATH
    if not template_path.exists():
        console.print(
            Panel(
                f"[red]CloudFormation template not found.[/red]\n\n"
                f"Expected: {template_path}\n"
                "Make sure you're running from the project root.",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)
    console.print(f"  [green]✓[/green] Template: {TEMPLATE_REL_PATH}")

    default_region = get_default_region()

    return {
        "account_id": account_id,
        "default_region": default_region,
        "template_path": template_path,
    }


# ---------------------------------------------------------------------------
# Step 1: Region & CloudTrail
# ---------------------------------------------------------------------------


def step_cloudtrail(default_region: Optional[str]) -> Tuple[str, List[Dict]]:
    """Verify CloudTrail. Returns (region, trail_list)."""
    console.print()
    console.print("[bold]Step 1 · Region & CloudTrail[/bold]")
    console.print()

    # Ask for region
    region = Prompt.ask(
        "  AWS Region",
        default=default_region or "us-east-1",
    )

    # Describe trails
    with console.status(f"  Checking CloudTrail in {region}..."):
        ok, output = run_aws(["cloudtrail", "describe-trails"], region=region)

    if not ok:
        console.print(f"  [red]✗[/red] Failed to query CloudTrail: {output}")
        console.print(
            "  [dim]Continuing — management events are logged by default.[/dim]"
        )
        return region, []

    trails_data = json.loads(output).get("trailList", [])

    if not trails_data:
        console.print()
        console.print(
            "  [yellow]![/yellow] No explicit CloudTrail trails found in this region."
        )
        console.print(
            "  [dim]Management events (including Athena API calls) are still logged by default.[/dim]"
        )
        return region, []

    # Show trails table
    table = Table(box=box.ROUNDED, show_edge=True, pad_edge=True)
    table.add_column("Trail Name", style="cyan")
    table.add_column("S3 Bucket", style="green")
    table.add_column("Multi-Region", justify="center")

    for t in trails_data:
        table.add_row(
            t.get("Name", "—"),
            t.get("S3BucketName", "—"),
            "Yes" if t.get("IsMultiRegionTrail") else "No",
        )

    console.print()
    console.print(table)
    console.print(
        f"\n  [green]✓[/green] CloudTrail is active ({len(trails_data)} trail{'s' if len(trails_data) != 1 else ''})"
    )

    return region, trails_data


# ---------------------------------------------------------------------------
# Step 2: S3 Data Events
# ---------------------------------------------------------------------------


def step_s3_events(region: str, trails: List[Dict]) -> Tuple[Optional[str], Optional[str]]:
    """Optionally enable S3 data events. Returns (CloudTrail bucket, monitored S3 buckets CSV) or (None, None)."""
    console.print()
    console.print("[bold]Step 2 · S3 Data Events (Optional)[/bold]")
    console.print()
    console.print(
        "  S3 data events capture bucket-level access patterns (GetObject, PutObject, etc.).\n"
        "  These are [bold]not[/bold] enabled by default and incur additional CloudTrail charges."
    )
    console.print()

    if not Confirm.ask("  Enable S3 data events?", default=True):
        console.print(
            "\n  [dim]Skipped — S3 bucket monitoring will not be available.[/dim]"
        )
        return None, None

    # Pick trail from discovered trails
    trail_names = [t.get("Name", "") for t in trails if t.get("Name")]

    if not trail_names:
        console.print("  [red]✗[/red] No trails available to configure.")
        console.print("  [dim]Skipping S3 data events.[/dim]")
        return None, None

    if len(trail_names) == 1:
        trail_name = trail_names[0]
        console.print(f"  Using trail: [cyan]{trail_name}[/cyan]")
    else:
        console.print()
        for i, name in enumerate(trail_names, 1):
            console.print(f"  [bold]{i}[/bold]. {name}")
        console.print()
        while True:
            choice_str = Prompt.ask(
                f"  Select trail (1-{len(trail_names)})", default="1"
            )
            try:
                choice_idx = int(choice_str)
                if 1 <= choice_idx <= len(trail_names):
                    trail_name = trail_names[choice_idx - 1]
                    break
            except ValueError:
                pass
            console.print(
                f"  [red]✗[/red] Enter a number between 1 and {len(trail_names)}."
            )
        console.print(f"  Using trail: [cyan]{trail_name}[/cyan]")

    # Buckets to monitor — list account buckets and let user select
    console.print()
    with console.status("  Listing S3 buckets..."):
        buckets_ok, buckets_output = run_aws(["s3api", "list-buckets"], region=region)

    if not buckets_ok:
        console.print(
            f"  [yellow]![/yellow] Could not list S3 buckets: {buckets_output}"
        )
        console.print("  [dim]Enter bucket names manually instead.[/dim]")
        buckets_input = Prompt.ask("  S3 buckets to monitor (comma-separated)")
        bucket_names = [b.strip() for b in buckets_input.split(",") if b.strip()]
    else:
        all_buckets = [b["Name"] for b in json.loads(buckets_output).get("Buckets", [])]
        if not all_buckets:
            console.print("  [yellow]![/yellow] No S3 buckets found in this account.")
            buckets_input = Prompt.ask("  S3 buckets to monitor (comma-separated)")
            bucket_names = [b.strip() for b in buckets_input.split(",") if b.strip()]
        else:
            console.print()
            for i, name in enumerate(all_buckets, 1):
                console.print(f"  [bold]{i:>3}[/bold]. {name}")
            console.print()
            while True:
                selection = Prompt.ask(
                    "  Select buckets (comma-separated numbers, e.g. 1,3,5)"
                )
                try:
                    indices = [
                        int(s.strip()) for s in selection.split(",") if s.strip()
                    ]
                    if indices and all(1 <= idx <= len(all_buckets) for idx in indices):
                        bucket_names = [all_buckets[idx - 1] for idx in indices]
                        break
                except ValueError:
                    pass
                console.print(
                    f"  [red]✗[/red] Enter numbers between 1 and {len(all_buckets)}, separated by commas."
                )

            for b in bucket_names:
                console.print(f"  [green]✓[/green] {b}")

    if not bucket_names:
        console.print("  [red]✗[/red] No buckets provided. Skipping S3 data events.")
        return None, None

    # Build data resource ARNs
    data_resources = [f"arn:aws:s3:::{b}/" for b in bucket_names]
    event_selector = json.dumps(
        [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [
                    {"Type": "AWS::S3::Object", "Values": data_resources}
                ],
            }
        ]
    )

    # Enable
    console.print()
    with console.status("  Enabling S3 data events..."):
        ok, output = run_aws(
            [
                "cloudtrail",
                "put-event-selectors",
                "--trail-name",
                trail_name,
                "--event-selectors",
                event_selector,
            ],
            region=region,
        )

    if not ok:
        console.print(f"  [red]✗[/red] Failed to enable S3 data events: {output}")
        if Confirm.ask("  Continue without S3 monitoring?", default=True):
            return None, None
        console.print("\n[dim]Cancelled.[/dim]")
        sys.exit(0)

    console.print("  [green]✓[/green] S3 data events enabled")

    # Verify
    with console.status("  Verifying configuration..."):
        ok, output = run_aws(
            [
                "cloudtrail",
                "get-event-selectors",
                "--trail-name",
                trail_name,
            ],
            region=region,
        )

    if ok:
        console.print("  [green]✓[/green] Configuration verified")
    else:
        console.print("  [yellow]![/yellow] Could not verify — continuing anyway")

    # Find CloudTrail S3 bucket for this trail
    cloudtrail_bucket = None
    for t in trails:
        if t.get("Name") == trail_name:
            cloudtrail_bucket = t.get("S3BucketName")
            break

    if cloudtrail_bucket:
        console.print(f"  [green]✓[/green] CloudTrail logs bucket: {cloudtrail_bucket}")

    return cloudtrail_bucket, ",".join(bucket_names)


# ---------------------------------------------------------------------------
# Step 3: Analysis Mode
# ---------------------------------------------------------------------------


def step_analysis_mode(account_id: str, region: str) -> Dict:
    """Ask whether to use single, multi-account, or AWS Organizations mode."""
    console.print()
    console.print("[bold]Step 3 · Analysis Mode[/bold]")
    console.print()
    console.print(
        "  [bold]1[/bold]. Single AWS account    [dim](analyse this account only)[/dim]"
    )
    console.print(
        "  [bold]2[/bold]. Multiple AWS accounts [dim](analyse multiple accounts via explicit IDs)[/dim]"
    )
    console.print(
        "  [bold]3[/bold]. AWS Organizations   [dim](auto-discover accounts, use org trail)[/dim]"
    )
    console.print()

    while True:
        choice = Prompt.ask("  Select mode", choices=["1", "2", "3"], default="1")
        if choice in ("1", "2", "3"):
            break

    if choice == "1":
        console.print("  [green]✓[/green] Single-account mode")
        return {"mode": "single"}

    if choice == "3":
        return step_org_setup(account_id, region)

    # Multi-account mode (manual)
    console.print()
    console.print(
        "  Multi-account mode analyses Athena usage across multiple AWS accounts.\n"
        "  You will need to deploy a read-only IAM role in each monitored account."
    )
    console.print()

    # Collect account IDs
    while True:
        accounts_input = Prompt.ask(
            "  AWS account IDs to analyse [dim](comma-separated, 12-digit IDs)[/dim]"
        )
        account_ids = [a.strip() for a in accounts_input.split(",") if a.strip()]
        if not account_ids:
            console.print("  [red]✗[/red] At least one account ID is required.")
            continue
        invalid = [a for a in account_ids if not validate_account_id(a)]
        if invalid:
            console.print(
                f"  [red]✗[/red] Invalid account IDs: {', '.join(invalid)}. "
                "Must be 12 digits."
            )
            continue
        if account_id in account_ids:
            console.print(
                f"  [yellow]![/yellow] Removed collector account {account_id} "
                "(it will be analysed locally)."
            )
            account_ids = [a for a in account_ids if a != account_id]
            if not account_ids:
                console.print("  [red]✗[/red] No remote accounts remaining.")
                continue
        break

    for aid in account_ids:
        console.print(f"  [green]✓[/green] {aid}")

    # ExternalId
    console.print()
    default_external_id = str(uuid.uuid4())
    external_id = Prompt.ask(
        "  ExternalId for cross-account trust [dim](auto-generated, or enter your own)[/dim]",
        default=default_external_id,
    )
    console.print(f"  [green]✓[/green] ExternalId: {external_id}")

    return {
        "mode": "multi",
        "method": "manual",
        "account_ids": account_ids,
        "external_id": external_id,
    }


def step_org_setup(account_id: str, region: str) -> Dict:
    """Set up AWS Organizations mode. Auto-discovers org ID, accounts, and org trail."""
    console.print()
    console.print(
        "  AWS Organizations mode auto-discovers member accounts and reads\n"
        "  CloudTrail data from a centralized Organization Trail bucket."
    )
    console.print()

    # 1. Discover organization
    with console.status("  Checking AWS Organizations..."):
        ok, output = run_aws(["organizations", "describe-organization"], region=region)

    if not ok:
        console.print(
            Panel(
                "[red]Failed to query AWS Organizations.[/red]\n\n"
                "This account may not be the management account, or Organizations\n"
                "is not enabled. Org mode requires the collector to run in the\n"
                "management account (or a delegated administrator account).\n\n"
                f"Error: {output}",
                title="Organizations Not Available",
                border_style="red",
            )
        )
        console.print()
        if Confirm.ask("  Fall back to manual multi-account mode?", default=True):
            return step_analysis_mode(account_id, region)
        sys.exit(0)

    org_data = json.loads(output).get("Organization", {})
    org_id = org_data.get("Id", "")
    master_account_id = org_data.get("MasterAccountId", "")

    console.print(f"  [green]✓[/green] Organization ID: {org_id}")
    console.print(f"  [green]✓[/green] Management Account: {master_account_id}")

    if master_account_id != account_id:
        console.print(
            f"\n  [yellow]![/yellow] This account ({account_id}) is not the management account.\n"
            "  Org API calls may require delegated administrator permissions."
        )

    # 2. List accounts
    console.print()
    with console.status("  Discovering member accounts..."):
        ok, output = run_aws(["organizations", "list-accounts"], region=region)

    if not ok:
        console.print(f"  [red]✗[/red] Failed to list accounts: {output}")
        sys.exit(1)

    all_accounts = json.loads(output).get("Accounts", [])
    active_accounts = [a for a in all_accounts if a["Status"] == "ACTIVE"]
    member_accounts = [a for a in active_accounts if a["Id"] != account_id]

    acct_table = Table(box=box.ROUNDED, show_edge=True, pad_edge=True)
    acct_table.add_column("Account ID", style="cyan")
    acct_table.add_column("Name", style="white")
    acct_table.add_column("Email", style="dim")

    for a in active_accounts:
        suffix = " (collector)" if a["Id"] == account_id else ""
        acct_table.add_row(
            a["Id"],
            a.get("Name", "—") + suffix,
            a.get("Email", "—"),
        )

    console.print(acct_table)
    console.print(
        f"\n  [green]✓[/green] {len(member_accounts)} member accounts to analyse"
    )

    # 3. Detect Organization Trail
    console.print()
    with console.status("  Looking for Organization CloudTrail trail..."):
        ok, output = run_aws(["cloudtrail", "describe-trails"], region=region)

    org_trail_bucket = ""
    if ok:
        trails = json.loads(output).get("trailList", [])
        org_trails = [t for t in trails if t.get("IsOrganizationTrail")]
        if org_trails:
            org_trail = org_trails[0]
            org_trail_bucket = org_trail.get("S3BucketName", "")
            console.print(
                f"  [green]✓[/green] Organization Trail found: {org_trail.get('Name')}"
            )
            console.print(f"  [green]✓[/green] Org Trail Bucket: {org_trail_bucket}")
        else:
            console.print("  [yellow]![/yellow] No Organization Trail found.")
            console.print(
                "  [dim]Without an org trail, the Lambda will read CloudTrail per-account\n"
                "  via cross-account roles (same as manual multi-account mode).[/dim]"
            )

    if not org_trail_bucket:
        org_trail_bucket = Prompt.ask(
            "  Organization Trail S3 bucket [dim](leave empty to skip)[/dim]",
            default="",
        )

    # 4. Cross-account roles (optional for query enrichment)
    console.print()
    console.print(
        "  [bold]Cross-account roles (optional)[/bold]\n"
        "  Org mode reads CloudTrail from the org trail bucket, so cross-account\n"
        "  roles are only needed for Athena query enrichment (execution stats\n"
        "  like data scanned and timing). Query strings are already in CloudTrail."
    )
    console.print()

    want_enrichment = Confirm.ask(
        "  Deploy cross-account roles for query enrichment?", default=True
    )

    external_id = ""
    if want_enrichment:
        default_external_id = str(uuid.uuid4())
        external_id = Prompt.ask(
            "  ExternalId for cross-account trust",
            default=default_external_id,
        )
        console.print(f"  [green]✓[/green] ExternalId: {external_id}")

    return {
        "mode": "multi",
        "method": "org",
        "org_id": org_id,
        "org_trail_bucket": org_trail_bucket,
        "account_ids": [a["Id"] for a in member_accounts],
        "external_id": external_id,
        "want_enrichment": want_enrichment,
    }


def show_org_stacksets_instructions(
    account_id: str,
    stack_name: str,
    external_id: str,
    region: str,
) -> None:
    """Display StackSets deployment instructions for org mode."""
    console.print()
    console.print("[bold]Cross-Account Role Setup via StackSets[/bold]")
    console.print()
    console.print(
        "  With AWS Organizations, you can deploy the cross-account role to\n"
        "  all member accounts at once using CloudFormation StackSets."
    )
    console.print()

    cmd = (
        f"aws cloudformation create-stack-set \\\n"
        f"  --stack-set-name AthenaUsageAnalyserRole \\\n"
        f"  --template-body file://cloudformation/cross-account-role.json \\\n"
        f"  --capabilities CAPABILITY_NAMED_IAM \\\n"
        f"  --permission-model SERVICE_MANAGED \\\n"
        f"  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \\\n"
        f"  --parameters \\\n"
        f"    ParameterKey=CollectorAccountId,ParameterValue={account_id} \\\n"
        f"    ParameterKey=CollectorStackName,ParameterValue={stack_name} \\\n"
        f"    ParameterKey=ExternalId,ParameterValue={external_id}\n\n"
        f"# Then create instances in all accounts:\n"
        f"aws cloudformation create-stack-instances \\\n"
        f"  --stack-set-name AthenaUsageAnalyserRole \\\n"
        f"  --deployment-targets OrganizationalUnitIds=<root-ou-id> \\\n"
        f"  --regions {region}"
    )

    console.print(
        Panel(
            cmd,
            title="Run in the management account",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    console.print()
    console.print(
        "  [dim]To find your root OU ID:[/dim]\n"
        "  [dim]  aws organizations list-roots --query 'Roots[0].Id'[/dim]\n"
        "\n"
        "  [dim]Auto-deployment is enabled, so new accounts joining the org\n"
        "  will automatically get the role deployed.[/dim]"
    )
    console.print()
    Prompt.ask("  Press Enter to continue")


def show_cross_account_instructions(
    account_id: str,
    stack_name: str,
    external_id: str,
    monitored_accounts: List[str],
) -> None:
    """Display cross-account role deployment instructions."""
    console.print()
    console.print("[bold]Cross-Account Role Setup[/bold]")
    console.print()
    console.print(
        "  Deploy the following CloudFormation stack in [bold]each monitored account[/bold].\n"
        "  This creates a read-only IAM role that allows the collector Lambda to\n"
        "  access CloudTrail and Athena data."
    )
    console.print()

    cmd = (
        f"aws cloudformation create-stack \\\n"
        f"  --stack-name AthenaUsageAnalyserRole \\\n"
        f"  --template-body file://cloudformation/cross-account-role.json \\\n"
        f"  --capabilities CAPABILITY_NAMED_IAM \\\n"
        f"  --parameters \\\n"
        f"    ParameterKey=CollectorAccountId,ParameterValue={account_id} \\\n"
        f"    ParameterKey=CollectorStackName,ParameterValue={stack_name} \\\n"
        f"    ParameterKey=ExternalId,ParameterValue={external_id}"
    )

    console.print(
        Panel(
            cmd,
            title="Run in each monitored account",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    console.print(
        f"  Accounts requiring this role: [bold]{', '.join(monitored_accounts)}[/bold]"
    )
    console.print()
    console.print(
        "  [dim]Note: You can deploy the role now or after the collector stack is created.\n"
        "  The Lambda will log warnings for any accounts where the role is not yet available.[/dim]"
    )
    console.print()
    Prompt.ask("  Press Enter to continue")


# ---------------------------------------------------------------------------
# Step 4: Configure & Deploy
# ---------------------------------------------------------------------------


def step_deploy(
    region: str,
    cloudtrail_bucket: Optional[str],
    template_path: Path,
    account_id: str,
    analysis_config: Optional[Dict] = None,
    monitored_s3_buckets: Optional[str] = None,
) -> None:
    """Collect parameters, deploy stack, wait, show results."""
    if analysis_config is None:
        analysis_config = {"mode": "single"}

    console.print()
    console.print("[bold]Step 4 · Configure & Deploy[/bold]")
    console.print()

    # Stack name
    while True:
        stack_name = Prompt.ask("  Stack name", default="athena-usage-analyser")
        if validate_stack_name(stack_name):
            break
        console.print(
            "  [red]✗[/red] Invalid name. Must start with a letter and contain only letters, numbers, and hyphens."
        )

    # CloudTrail bucket (only if S3 events were enabled)
    ct_bucket = ""
    if cloudtrail_bucket is not None:
        ct_bucket = Prompt.ask("  CloudTrail S3 bucket", default=cloudtrail_bucket)

    # Workgroups
    workgroups = Prompt.ask(
        "  Athena Workgroups to monitor [dim](comma-separated or \\* for all)[/dim]",
        default="*",
    )

    # S3 buckets to monitor (use selection from Step 2 if available)
    s3_default = monitored_s3_buckets if monitored_s3_buckets else "*"
    s3_buckets = Prompt.ask(
        "  S3 Buckets to monitor [dim](comma-separated or \\* for auto-detect)[/dim]",
        default=s3_default,
    )

    # Defaults for advanced settings
    interval = 60
    retention = 90
    kms_key = ""

    # Multi-account settings
    analysis_mode = analysis_config.get("mode", "single")
    multi_account_method = analysis_config.get("method", "manual")
    monitored_account_ids = ",".join(analysis_config.get("account_ids", []))
    external_id = analysis_config.get("external_id", "")
    org_id = analysis_config.get("org_id", "")
    org_trail_bucket = analysis_config.get("org_trail_bucket", "")

    # Summary table
    console.print()
    summary = Table(
        title="Deployment Configuration",
        box=box.ROUNDED,
        show_edge=True,
        pad_edge=True,
        title_style="bold",
    )
    summary.add_column("Parameter", style="cyan")
    summary.add_column("Value", style="white")

    summary.add_row("Stack Name", stack_name)
    summary.add_row("Region", region)
    summary.add_row("Analysis Mode", analysis_mode)
    if analysis_mode == "multi":
        if multi_account_method == "org":
            summary.add_row("Multi-Account Method", "AWS Organizations")
            summary.add_row("Organization ID", org_id)
            summary.add_row(
                "Org Trail Bucket",
                org_trail_bucket or "[dim]— (not set)[/dim]",
            )
            summary.add_row(
                "Discovered Accounts",
                str(len(analysis_config.get("account_ids", []))),
            )
        else:
            summary.add_row(
                "Monitored Accounts",
                ", ".join(analysis_config.get("account_ids", [])),
            )
    summary.add_row("Athena Workgroups", workgroups)
    summary.add_row("S3 Buckets to Monitor", s3_buckets)
    summary.add_row("CloudTrail Bucket", ct_bucket or "[dim]— (not set)[/dim]")
    summary.add_row(
        "Analysis Interval",
        f"{interval // 60} hours"
        if interval >= 60 and interval % 60 == 0
        else f"{interval} minutes",
    )
    summary.add_row("Retention", f"{retention} days")
    summary.add_row("KMS Key", kms_key or "[dim]None (AES-256)[/dim]")

    console.print(summary)

    # Advanced settings
    console.print()
    if Confirm.ask("  Customize advanced settings?", default=False):
        console.print()
        while True:
            interval = IntPrompt.ask(
                "  Analysis interval (minutes, 5-1440)", default=60
            )
            if 5 <= interval <= 1440:
                break
            console.print("  [red]✗[/red] Must be between 5 and 1440.")

        while True:
            retention = IntPrompt.ask("  Retention period (days, 7-365)", default=90)
            if 7 <= retention <= 365:
                break
            console.print("  [red]✗[/red] Must be between 7 and 365.")

        kms_key = Prompt.ask(
            "  KMS Key ARN [dim](leave empty for AES-256)[/dim]",
            default="",
        )
        if kms_key and not kms_key.startswith("arn:aws:kms:"):
            console.print(
                "  [yellow]![/yellow] That doesn't look like a KMS ARN — using it anyway."
            )

        # Redisplay summary
        console.print()
        summary = Table(
            title="Deployment Configuration (Updated)",
            box=box.ROUNDED,
            show_edge=True,
            pad_edge=True,
            title_style="bold",
        )
        summary.add_column("Parameter", style="cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Stack Name", stack_name)
        summary.add_row("Region", region)
        summary.add_row("Analysis Mode", analysis_mode)
        if analysis_mode == "multi":
            summary.add_row(
                "Monitored Accounts",
                ", ".join(analysis_config.get("account_ids", [])),
            )
        summary.add_row("Athena Workgroups", workgroups)
        summary.add_row("S3 Buckets to Monitor", s3_buckets)
        summary.add_row("CloudTrail Bucket", ct_bucket or "[dim]— (not set)[/dim]")
        summary.add_row(
            "Analysis Interval",
            f"{interval // 60} hours"
            if interval >= 60 and interval % 60 == 0
            else f"{interval} minutes",
        )
        summary.add_row("Retention", f"{retention} days")
        summary.add_row("KMS Key", kms_key or "[dim]None (AES-256)[/dim]")
        console.print(summary)

    # Check if stack already exists
    is_update = False
    console.print()
    with console.status("  Checking for existing stack..."):
        exists_ok, exists_output = run_aws(
            ["cloudformation", "describe-stacks", "--stack-name", stack_name],
            region=region,
        )

    if exists_ok:
        stacks = json.loads(exists_output).get("Stacks", [])
        if stacks:
            status = stacks[0].get("StackStatus", "UNKNOWN")
            console.print(
                f"  [yellow]![/yellow] Stack [bold]{stack_name}[/bold] already exists (status: {status})"
            )
            console.print()
            choice = Prompt.ask(
                "  What would you like to do?",
                choices=["update", "rename", "abort"],
                default="abort",
            )
            if choice == "abort":
                console.print("\n[dim]Cancelled.[/dim]")
                sys.exit(0)
            elif choice == "rename":
                while True:
                    stack_name = Prompt.ask("  New stack name")
                    if validate_stack_name(stack_name):
                        break
                    console.print("  [red]✗[/red] Invalid name.")
            elif choice == "update":
                is_update = True

    # Final confirmation
    console.print()
    if not Confirm.ask("  Deploy this stack?", default=True):
        console.print("\n[dim]Cancelled.[/dim]")
        sys.exit(0)

    # ---- Package and upload Lambda code ----
    console.print()

    # We need an S3 bucket for the Lambda code. For new stacks, we create a
    # temporary bucket. For updates, we reuse the analysis bucket.
    if is_update:
        # Get the existing analysis bucket from stack outputs
        _, desc_output = run_aws(
            ["cloudformation", "describe-stacks", "--stack-name", stack_name],
            region=region,
        )
        try:
            stack_info = json.loads(desc_output).get("Stacks", [{}])[0]
            code_bucket = None
            for o in stack_info.get("Outputs", []):
                if o["OutputKey"] == "AnalysisBucketName":
                    code_bucket = o["OutputValue"]
                    break
            if not code_bucket:
                console.print(
                    "  [red]✗[/red] Could not find analysis bucket in stack outputs."
                )
                sys.exit(1)
        except (json.JSONDecodeError, IndexError, KeyError):
            console.print("  [red]✗[/red] Could not read stack outputs.")
            sys.exit(1)
    else:
        # Create a temporary S3 bucket for the Lambda code
        code_bucket = f"{account_id}-{stack_name}-lambda-code-{region}"
        # Truncate if too long (S3 bucket names max 63 chars)
        if len(code_bucket) > 63:
            code_bucket = code_bucket[:63].rstrip("-")

        with console.status(f"  Creating Lambda code bucket: {code_bucket}..."):
            if region == "us-east-1":
                create_ok, create_output = run_aws(
                    ["s3api", "create-bucket", "--bucket", code_bucket],
                    region=region,
                )
            else:
                create_ok, create_output = run_aws(
                    [
                        "s3api",
                        "create-bucket",
                        "--bucket",
                        code_bucket,
                        "--create-bucket-configuration",
                        f"LocationConstraint={region}",
                    ],
                    region=region,
                )

        if not create_ok:
            if "BucketAlreadyOwnedByYou" in create_output:
                console.print(
                    f"  [green]✓[/green] Lambda code bucket exists: {code_bucket}"
                )
            else:
                console.print(
                    f"  [red]✗[/red] Failed to create bucket: {create_output}"
                )
                sys.exit(1)
        else:
            console.print(f"  [green]✓[/green] Lambda code bucket: {code_bucket}")

    with console.status("  Packaging and uploading Lambda code..."):
        lambda_bucket, lambda_key = upload_lambda_code(code_bucket, stack_name, region)
    console.print(
        f"  [green]✓[/green] Lambda code uploaded: s3://{lambda_bucket}/{lambda_key}"
    )

    # Build parameters
    params = [
        f"ParameterKey=AthenaWorkgroups,ParameterValue={workgroups}",
        f"ParameterKey=S3BucketsToMonitor,ParameterValue={s3_buckets}",
        f"ParameterKey=AnalysisIntervalMinutes,ParameterValue={interval}",
        f"ParameterKey=RetentionDays,ParameterValue={retention}",
        f"ParameterKey=LambdaCodeBucket,ParameterValue={lambda_bucket}",
        f"ParameterKey=LambdaCodeKey,ParameterValue={lambda_key}",
        f"ParameterKey=AnalysisMode,ParameterValue={analysis_mode}",
    ]
    if ct_bucket:
        params.append(f"ParameterKey=CloudTrailBucket,ParameterValue={ct_bucket}")
    if kms_key:
        params.append(f"ParameterKey=KMSKeyArn,ParameterValue={kms_key}")
    if monitored_account_ids:
        params.append(
            f"ParameterKey=MonitoredAccountIds,ParameterValue={monitored_account_ids}"
        )
    if external_id:
        params.append(
            f"ParameterKey=CrossAccountExternalId,ParameterValue={external_id}"
        )
    if multi_account_method and multi_account_method != "manual":
        params.append(
            f"ParameterKey=MultiAccountMethod,ParameterValue={multi_account_method}"
        )
    if org_id:
        params.append(f"ParameterKey=OrganizationId,ParameterValue={org_id}")
    if org_trail_bucket:
        params.append(f"ParameterKey=OrgTrailBucket,ParameterValue={org_trail_bucket}")

    # Determine create vs update
    action = "update-stack" if is_update else "create-stack"
    action_label = "Updating" if is_update else "Creating"
    wait_action = "stack-update-complete" if is_update else "stack-create-complete"

    # Deploy
    console.print()
    with console.status(f"  {action_label} CloudFormation stack..."):
        deploy_ok, deploy_output = run_aws(
            [
                "cloudformation",
                action,
                "--stack-name",
                stack_name,
                "--template-body",
                f"file://{template_path}",
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "--parameters",
            ]
            + params,
            region=region,
        )

    if not deploy_ok:
        console.print(
            Panel(
                f"[red]Stack {action_label.lower()} failed.[/red]\n\n{deploy_output}",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)

    console.print(f"  [green]✓[/green] Stack {action_label.lower()} initiated")

    # Wait for completion
    with console.status(
        "  Waiting for stack to complete (this may take 2-3 minutes)..."
    ):
        wait_ok, wait_output = run_aws(
            [
                "cloudformation",
                "wait",
                wait_action,
                "--stack-name",
                stack_name,
            ],
            region=region,
        )

    if not wait_ok:
        # Get failure reason
        _, desc_output = run_aws(
            ["cloudformation", "describe-stacks", "--stack-name", stack_name],
            region=region,
        )
        reason = ""
        try:
            stack_info = json.loads(desc_output).get("Stacks", [{}])[0]
            reason = stack_info.get("StackStatusReason", "Unknown reason")
            status = stack_info.get("StackStatus", "UNKNOWN")
        except (json.JSONDecodeError, IndexError):
            status = "UNKNOWN"
            reason = wait_output

        console.print(
            Panel(
                f"[red]Stack {action_label.lower()} failed.[/red]\n\n"
                f"  Status: {status}\n"
                f"  Reason: {reason}\n\n"
                f"To investigate:\n"
                f"  aws cloudformation describe-stack-events --stack-name {stack_name} --region {region}",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)

    # Get stack outputs
    _, desc_output = run_aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack_name],
        region=region,
    )
    outputs = {}
    try:
        stack_info = json.loads(desc_output).get("Stacks", [{}])[0]
        for o in stack_info.get("Outputs", []):
            outputs[o["OutputKey"]] = o["OutputValue"]
    except (json.JSONDecodeError, IndexError, KeyError):
        pass

    # Success panel
    console.print()
    output_lines = [
        f"  [green]✓[/green] Stack:   [bold]{stack_name}[/bold]",
        f"  [green]✓[/green] Region:  {region}",
        f"  [green]✓[/green] Status:  {'UPDATE' if is_update else 'CREATE'}_COMPLETE",
    ]

    if outputs:
        output_lines.append("")
        for key, val in outputs.items():
            output_lines.append(f"  {key}: {val}")

    if analysis_mode == "multi":
        output_lines.append("")
        output_lines.append(
            f"  [green]✓[/green] Mode: Multi-account "
            f"({len(analysis_config.get('account_ids', []))} accounts)"
        )

    output_lines.append("")
    output_lines.append(f"  The analyser runs every {interval} minutes automatically.")
    output_lines.append("  To run a historical analysis, see README Step 2.")

    console.print(
        Panel(
            "\n".join(output_lines),
            title="[green]Deployment Complete[/green]",
            border_style="green",
            padding=(1, 2),
        )
    )

    # Show cross-account role instructions after deployment
    if analysis_mode == "multi":
        if multi_account_method == "org" and analysis_config.get("want_enrichment"):
            show_org_stacksets_instructions(account_id, stack_name, external_id, region)
        elif multi_account_method != "org":
            show_cross_account_instructions(
                account_id,
                stack_name,
                external_id,
                analysis_config.get("account_ids", []),
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    console.print()
    console.print(
        Panel(
            "[bold]Athena Usage Analyser[/bold] — Deploy\n"
            "[dim]Interactive deployment for AWS CloudFormation[/dim]",
            box=box.ROUNDED,
            padding=(1, 4),
        )
    )

    ctx = preflight_checks()
    region, trails = step_cloudtrail(ctx["default_region"])
    cloudtrail_bucket, monitored_s3_buckets = step_s3_events(region, trails)
    analysis_config = step_analysis_mode(ctx["account_id"], region)
    step_deploy(
        region,
        cloudtrail_bucket,
        ctx["template_path"],
        ctx["account_id"],
        analysis_config,
        monitored_s3_buckets,
    )

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[dim]Cancelled.[/dim]\n")
        sys.exit(0)
