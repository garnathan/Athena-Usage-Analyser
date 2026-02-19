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
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Auto-install rich if needed (same pattern as analyse_exports.py)
REQUIRED_PACKAGES = ["rich"]


def install_dependencies():
    """Install required packages if not already installed."""
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing required package: {package}...")
            try:
                subprocess.check_call(
                    ["pip3", "install", "--user", package],
                    stdout=subprocess.DEVNULL,
                )
                print(f"  {package} installed successfully.")
            except subprocess.CalledProcessError:
                try:
                    subprocess.check_call(
                        ["pip3", "install", "--break-system-packages", package],
                        stdout=subprocess.DEVNULL,
                    )
                    print(f"  {package} installed successfully.")
                except subprocess.CalledProcessError as e:
                    print(f"  Failed to install {package}: {e}")
                    print(f"  Please run: pip3 install {package}")
                    sys.exit(1)


install_dependencies()

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

console = Console()

TEMPLATE_REL_PATH = Path("cloudformation") / "athena-usage-analyser.json"
SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_aws(args: List[str], region: Optional[str] = None) -> Tuple[bool, str]:
    """Run an AWS CLI command. Returns (success, stdout_or_stderr)."""
    cmd = ["aws"] + args
    if region:
        cmd += ["--region", region]
    cmd += ["--output", "json", "--no-cli-pager"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, result.stdout.strip()
    return False, result.stderr.strip()


def get_default_region() -> Optional[str]:
    """Get the default region from AWS CLI config."""
    result = subprocess.run(
        ["aws", "configure", "get", "region"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def validate_stack_name(name: str) -> bool:
    """Validate CloudFormation stack name."""
    return bool(re.match(r"^[a-zA-Z][-a-zA-Z0-9]*$", name)) and len(name) <= 128


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
        result = subprocess.run(
            ["aws", "--version"], capture_output=True, text=True
        )
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
        console.print("  [dim]Continuing — management events are logged by default.[/dim]")
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
    console.print(f"\n  [green]✓[/green] CloudTrail is active ({len(trails_data)} trail{'s' if len(trails_data) != 1 else ''})")

    return region, trails_data


# ---------------------------------------------------------------------------
# Step 2: S3 Data Events
# ---------------------------------------------------------------------------


def step_s3_events(region: str, trails: List[Dict]) -> Optional[str]:
    """Optionally enable S3 data events. Returns CloudTrail bucket name or None."""
    console.print()
    console.print("[bold]Step 2 · S3 Data Events (Optional)[/bold]")
    console.print()
    console.print(
        "  S3 data events capture bucket-level access patterns (GetObject, PutObject, etc.).\n"
        "  These are [bold]not[/bold] enabled by default and incur additional CloudTrail charges."
    )
    console.print()

    if not Confirm.ask("  Enable S3 data events?", default=False):
        console.print(
            "\n  [dim]Skipped — S3 bucket monitoring will not be available.[/dim]"
        )
        return None

    # Pick trail from discovered trails
    trail_names = [t.get("Name", "") for t in trails if t.get("Name")]

    if not trail_names:
        console.print("  [red]✗[/red] No trails available to configure.")
        console.print("  [dim]Skipping S3 data events.[/dim]")
        return None

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
            console.print(f"  [red]✗[/red] Enter a number between 1 and {len(trail_names)}.")
        console.print(f"  Using trail: [cyan]{trail_name}[/cyan]")

    # Buckets to monitor — list account buckets and let user select
    console.print()
    with console.status("  Listing S3 buckets..."):
        buckets_ok, buckets_output = run_aws(["s3api", "list-buckets"], region=region)

    if not buckets_ok:
        console.print(f"  [yellow]![/yellow] Could not list S3 buckets: {buckets_output}")
        console.print("  [dim]Enter bucket names manually instead.[/dim]")
        buckets_input = Prompt.ask(
            "  S3 buckets to monitor (comma-separated)"
        )
        bucket_names = [b.strip() for b in buckets_input.split(",") if b.strip()]
    else:
        all_buckets = [
            b["Name"] for b in json.loads(buckets_output).get("Buckets", [])
        ]
        if not all_buckets:
            console.print("  [yellow]![/yellow] No S3 buckets found in this account.")
            buckets_input = Prompt.ask(
                "  S3 buckets to monitor (comma-separated)"
            )
            bucket_names = [b.strip() for b in buckets_input.split(",") if b.strip()]
        else:
            console.print()
            for i, name in enumerate(all_buckets, 1):
                console.print(f"  [bold]{i:>3}[/bold]. {name}")
            console.print()
            while True:
                selection = Prompt.ask(
                    f"  Select buckets (comma-separated numbers, e.g. 1,3,5)"
                )
                try:
                    indices = [int(s.strip()) for s in selection.split(",") if s.strip()]
                    if indices and all(1 <= idx <= len(all_buckets) for idx in indices):
                        bucket_names = [all_buckets[idx - 1] for idx in indices]
                        break
                except ValueError:
                    pass
                console.print(f"  [red]✗[/red] Enter numbers between 1 and {len(all_buckets)}, separated by commas.")

            for b in bucket_names:
                console.print(f"  [green]✓[/green] {b}")

    if not bucket_names:
        console.print("  [red]✗[/red] No buckets provided. Skipping S3 data events.")
        return None

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
            return None
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

    return cloudtrail_bucket


# ---------------------------------------------------------------------------
# Step 3: Configure & Deploy
# ---------------------------------------------------------------------------


def step_deploy(
    region: str,
    cloudtrail_bucket: Optional[str],
    template_path: Path,
    account_id: str,
) -> None:
    """Collect parameters, deploy stack, wait, show results."""
    console.print()
    console.print("[bold]Step 3 · Configure & Deploy[/bold]")
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
        ct_bucket = Prompt.ask(
            "  CloudTrail S3 bucket", default=cloudtrail_bucket
        )

    # Workgroups
    workgroups = Prompt.ask(
        "  Athena Workgroups to monitor [dim](comma-separated or \\* for all)[/dim]",
        default="*",
    )

    # S3 buckets to monitor
    s3_buckets = Prompt.ask(
        "  S3 Buckets to monitor [dim](comma-separated or \\* for auto-detect)[/dim]",
        default="*",
    )

    # Defaults for advanced settings
    interval = 10
    retention = 90
    kms_key = ""

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
    summary.add_row("Athena Workgroups", workgroups)
    summary.add_row("S3 Buckets to Monitor", s3_buckets)
    summary.add_row("CloudTrail Bucket", ct_bucket or "[dim]— (not set)[/dim]")
    summary.add_row("Analysis Interval", f"{interval} minutes")
    summary.add_row("Retention", f"{retention} days")
    summary.add_row("KMS Key", kms_key or "[dim]None (AES-256)[/dim]")

    console.print(summary)

    # Advanced settings
    console.print()
    if Confirm.ask("  Customize advanced settings?", default=False):
        console.print()
        while True:
            interval = IntPrompt.ask(
                "  Analysis interval (minutes, 5-60)", default=10
            )
            if 5 <= interval <= 60:
                break
            console.print("  [red]✗[/red] Must be between 5 and 60.")

        while True:
            retention = IntPrompt.ask(
                "  Retention period (days, 7-365)", default=90
            )
            if 7 <= retention <= 365:
                break
            console.print("  [red]✗[/red] Must be between 7 and 365.")

        kms_key = Prompt.ask(
            "  KMS Key ARN [dim](leave empty for AES-256)[/dim]",
            default="",
        )
        if kms_key and not kms_key.startswith("arn:aws:kms:"):
            console.print("  [yellow]![/yellow] That doesn't look like a KMS ARN — using it anyway.")

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
        summary.add_row("Athena Workgroups", workgroups)
        summary.add_row("S3 Buckets to Monitor", s3_buckets)
        summary.add_row("CloudTrail Bucket", ct_bucket or "[dim]— (not set)[/dim]")
        summary.add_row("Analysis Interval", f"{interval} minutes")
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
                    console.print(
                        "  [red]✗[/red] Invalid name."
                    )
            elif choice == "update":
                is_update = True

    # Final confirmation
    console.print()
    if not Confirm.ask("  Deploy this stack?", default=True):
        console.print("\n[dim]Cancelled.[/dim]")
        sys.exit(0)

    # Build parameters
    params = [
        f"ParameterKey=AthenaWorkgroups,ParameterValue={workgroups}",
        f"ParameterKey=S3BucketsToMonitor,ParameterValue={s3_buckets}",
        f"ParameterKey=AnalysisIntervalMinutes,ParameterValue={interval}",
        f"ParameterKey=RetentionDays,ParameterValue={retention}",
    ]
    if ct_bucket:
        params.append(f"ParameterKey=CloudTrailBucket,ParameterValue={ct_bucket}")
    if kms_key:
        params.append(f"ParameterKey=KMSKeyArn,ParameterValue={kms_key}")

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
        f"  Waiting for stack to complete (this may take 2-3 minutes)..."
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

    output_lines.append("")
    output_lines.append(f"  The analyser runs every {interval} minutes automatically.")
    output_lines.append("  To run a historical analysis, see README Step 4.")

    console.print(
        Panel(
            "\n".join(output_lines),
            title="[green]Deployment Complete[/green]",
            border_style="green",
            padding=(1, 2),
        )
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
    cloudtrail_bucket = step_s3_events(region, trails)
    step_deploy(region, cloudtrail_bucket, ctx["template_path"], ctx["account_id"])

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[dim]Cancelled.[/dim]\n")
        sys.exit(0)
