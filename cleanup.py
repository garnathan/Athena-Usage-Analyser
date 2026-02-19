#!/usr/bin/env python3
"""
Athena Usage Analyser — Interactive Cleanup Script

Removes the deployed CloudFormation stack, empties and deletes the S3 bucket,
and optionally cleans up local exports — all through an interactive terminal UI.

Usage:
    python3 cleanup.py
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from _helpers import install_dependencies, run_aws, get_default_region

install_dependencies(["rich"])

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()

SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_stack_outputs(stack_name: str, region: str) -> Optional[Dict[str, str]]:
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


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def preflight_checks() -> Dict:
    """Verify AWS CLI and credentials. Returns context dict."""
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
    while True:
        with console.status("Checking AWS credentials..."):
            ok, output = run_aws(["sts", "get-caller-identity"])
        if ok:
            identity = json.loads(output)
            arn = identity.get("Arn", "")
            console.print(f"  [green]✓[/green] Authenticated: {arn}")
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

    default_region = get_default_region()

    return {"default_region": default_region}


# ---------------------------------------------------------------------------
# Step 1: Find the stack
# ---------------------------------------------------------------------------


def step_find_stack(default_region: Optional[str]) -> Tuple[str, str, Dict[str, str]]:
    """Find the deployed stack. Returns (region, stack_name, outputs)."""
    console.print()
    console.print("[bold]Step 1 · Find Deployed Stack[/bold]")
    console.print()

    region = Prompt.ask("  AWS Region", default=default_region or "us-east-1")

    # Try default stack name first
    default_stack = "athena-usage-analyser"

    with console.status(f"  Looking for stack [cyan]{default_stack}[/cyan]..."):
        outputs = get_stack_outputs(default_stack, region)

    if outputs:
        console.print(f"  [green]✓[/green] Found stack: [bold]{default_stack}[/bold]")
        _show_stack_info(outputs)
        return region, default_stack, outputs

    # Not found — list stacks and let user pick
    console.print(f"  [dim]Stack '{default_stack}' not found. Searching...[/dim]")
    console.print()

    with console.status("  Listing CloudFormation stacks..."):
        ok, output = run_aws(
            [
                "cloudformation",
                "list-stacks",
                "--stack-status-filter",
                "CREATE_COMPLETE",
                "UPDATE_COMPLETE",
            ],
            region=region,
        )

    if not ok:
        console.print(f"  [red]✗[/red] Failed to list stacks: {output}")
        stack_name = Prompt.ask("  Enter stack name")
        outputs = get_stack_outputs(stack_name, region)
        if not outputs:
            console.print(
                Panel(
                    f"[red]Could not find stack '{stack_name}' in {region}.[/red]",
                    title="Error",
                    border_style="red",
                )
            )
            sys.exit(1)
        return region, stack_name, outputs

    stacks = json.loads(output).get("StackSummaries", [])
    analyser_stacks = [s for s in stacks if "athena" in s.get("StackName", "").lower()]

    if not analyser_stacks:
        console.print("  [yellow]![/yellow] No Athena-related stacks found.")
        stack_name = Prompt.ask("  Enter stack name")
        outputs = get_stack_outputs(stack_name, region)
        if not outputs:
            console.print(
                Panel(
                    f"[red]Could not find stack '{stack_name}' in {region}.[/red]",
                    title="Error",
                    border_style="red",
                )
            )
            sys.exit(1)
        return region, stack_name, outputs

    if len(analyser_stacks) == 1:
        stack_name = analyser_stacks[0]["StackName"]
        console.print(f"  [green]✓[/green] Found stack: [bold]{stack_name}[/bold]")
    else:
        for i, s in enumerate(analyser_stacks, 1):
            console.print(f"  [bold]{i}[/bold]. {s['StackName']}")
        console.print()
        while True:
            choice_str = Prompt.ask(
                f"  Select stack (1-{len(analyser_stacks)})", default="1"
            )
            try:
                idx = int(choice_str)
                if 1 <= idx <= len(analyser_stacks):
                    stack_name = analyser_stacks[idx - 1]["StackName"]
                    break
            except ValueError:
                pass
            console.print(
                f"  [red]✗[/red] Enter a number between 1 and {len(analyser_stacks)}."
            )

    outputs = get_stack_outputs(stack_name, region)
    if not outputs:
        console.print(
            Panel(
                f"[red]Could not read outputs for stack '{stack_name}'.[/red]",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)

    _show_stack_info(outputs)
    return region, stack_name, outputs


def _show_stack_info(outputs: Dict[str, str]) -> None:
    """Display key stack outputs."""
    table = Table(box=box.ROUNDED, show_edge=True, pad_edge=True)
    table.add_column("Resource", style="cyan")
    table.add_column("Value", style="white")

    if "LambdaFunctionName" in outputs:
        table.add_row("Lambda Function", outputs["LambdaFunctionName"])
    if "AnalysisBucketName" in outputs:
        table.add_row("S3 Bucket", outputs["AnalysisBucketName"])

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# Step 2: Cleanup
# ---------------------------------------------------------------------------


def get_stack_parameters(stack_name: str, region: str) -> Dict[str, str]:
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
            p["ParameterKey"]: p["ParameterValue"] for p in stack.get("Parameters", [])
        }
    except (json.JSONDecodeError, IndexError, KeyError):
        return {}


def step_cleanup(region: str, stack_name: str, outputs: Dict[str, str]) -> None:
    """Empty bucket, delete stack, optionally remove retained bucket and local exports."""
    console.print()
    console.print("[bold]Step 2 · Cleanup[/bold]")
    console.print()

    bucket_name = outputs.get("AnalysisBucketName", "")

    # Check if this was a multi-account deployment
    params = get_stack_parameters(stack_name, region)
    is_multi_account = params.get("AnalysisMode") == "multi"
    multi_account_method = params.get("MultiAccountMethod", "manual")
    monitored_accounts = [
        a.strip() for a in params.get("MonitoredAccountIds", "").split(",") if a.strip()
    ]

    # Summary of what will be deleted
    console.print("  This will:")
    console.print(
        f"    • Empty S3 bucket [cyan]{bucket_name}[/cyan]"
    ) if bucket_name else None
    console.print(f"    • Delete CloudFormation stack [cyan]{stack_name}[/cyan]")
    console.print("    • Optionally remove the retained S3 bucket")
    console.print()

    console.print(
        Panel(
            "[yellow]This action is destructive and cannot be undone.[/yellow]\n"
            "All collected analysis data will be permanently deleted.",
            title="Warning",
            border_style="yellow",
        )
    )
    console.print()

    if not Confirm.ask("  Proceed with cleanup?", default=False):
        console.print("\n[dim]Cancelled.[/dim]")
        sys.exit(0)

    # 1. Empty S3 bucket
    if bucket_name:
        console.print()
        with console.status(f"  Emptying S3 bucket {bucket_name}..."):
            ok, output = run_aws(
                ["s3", "rm", f"s3://{bucket_name}", "--recursive"],
                region=region,
            )

        if ok:
            console.print("  [green]✓[/green] S3 bucket emptied")
        else:
            console.print(f"  [yellow]![/yellow] Could not empty bucket: {output}")

    # 2. Delete CloudFormation stack
    console.print()
    with console.status(f"  Deleting CloudFormation stack {stack_name}..."):
        ok, output = run_aws(
            ["cloudformation", "delete-stack", "--stack-name", stack_name],
            region=region,
        )

    if not ok:
        console.print(
            Panel(
                f"[red]Failed to delete stack.[/red]\n\n{output}",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)

    console.print("  [green]✓[/green] Stack deletion initiated")

    # Wait for deletion
    with console.status("  Waiting for stack deletion to complete..."):
        wait_ok, wait_output = run_aws(
            [
                "cloudformation",
                "wait",
                "stack-delete-complete",
                "--stack-name",
                stack_name,
            ],
            region=region,
        )

    if wait_ok:
        console.print("  [green]✓[/green] Stack deleted")
    else:
        console.print(
            f"  [yellow]![/yellow] Stack deletion may still be in progress: {wait_output}"
        )

    # 3. Optionally delete retained S3 bucket
    if bucket_name:
        console.print()
        console.print(
            f"  The S3 bucket [cyan]{bucket_name}[/cyan] has a Retain policy and still exists."
        )
        if Confirm.ask("  Delete the retained S3 bucket?", default=False):
            with console.status(f"  Deleting bucket {bucket_name}..."):
                ok, output = run_aws(
                    ["s3", "rb", f"s3://{bucket_name}"],
                    region=region,
                )
            if ok:
                console.print("  [green]✓[/green] S3 bucket deleted")
            else:
                console.print(f"  [yellow]![/yellow] Could not delete bucket: {output}")
                console.print(
                    f"  [dim]You can delete it manually: aws s3 rb s3://{bucket_name}[/dim]"
                )

    # 4. Optionally clean up local exports
    exports_dir = SCRIPT_DIR / "exports"
    report_file = SCRIPT_DIR / "athena-usage-report.html"
    local_files_exist = exports_dir.exists() or report_file.exists()

    if local_files_exist:
        console.print()
        console.print("  Local files found:")
        if exports_dir.exists():
            zip_count = len(list(exports_dir.glob("*.zip")))
            console.print(
                f"    • {exports_dir} ({zip_count} export{'s' if zip_count != 1 else ''})"
            )
        if report_file.exists():
            console.print(f"    • {report_file}")

        if Confirm.ask("  Delete local exports and reports?", default=False):
            if exports_dir.exists():
                shutil.rmtree(exports_dir)
                console.print(f"  [green]✓[/green] Deleted {exports_dir}")
            if report_file.exists():
                report_file.unlink()
                console.print(f"  [green]✓[/green] Deleted {report_file}")

    # Cross-account role cleanup guidance
    if is_multi_account:
        console.print()
        if multi_account_method == "org":
            console.print(
                Panel(
                    "[yellow]Cross-account roles may have been deployed via StackSets.[/yellow]\n\n"
                    "To clean up the StackSet and all instances:\n\n"
                    "  aws cloudformation delete-stack-instances \\\n"
                    "    --stack-set-name AthenaUsageAnalyserRole \\\n"
                    "    --deployment-targets OrganizationalUnitIds=<root-ou-id> \\\n"
                    "    --regions <region> --no-retain-stacks\n\n"
                    "  # Wait for instances to be deleted, then:\n"
                    "  aws cloudformation delete-stack-set \\\n"
                    "    --stack-set-name AthenaUsageAnalyserRole\n\n"
                    "To find your root OU ID:\n"
                    "  aws organizations list-roots --query 'Roots[0].Id'",
                    title="StackSets Cleanup",
                    border_style="yellow",
                    padding=(1, 2),
                )
            )
        elif monitored_accounts:
            console.print(
                Panel(
                    "[yellow]Cross-account roles were deployed in monitored accounts.[/yellow]\n\n"
                    "These must be deleted separately in each monitored account:\n\n"
                    + "\n".join(
                        f"  aws cloudformation delete-stack "
                        f"--stack-name AthenaUsageAnalyserRole "
                        f"  # Account: {acct}"
                        for acct in monitored_accounts
                    )
                    + "\n\nRun the above command while authenticated to each account.",
                    title="Cross-Account Cleanup",
                    border_style="yellow",
                    padding=(1, 2),
                )
            )

    # Lambda code bucket cleanup
    lambda_code_bucket = params.get("LambdaCodeBucket", "")
    if lambda_code_bucket and lambda_code_bucket != bucket_name:
        console.print()
        console.print(
            f"  [dim]Lambda code bucket [cyan]{lambda_code_bucket}[/cyan] may also need cleanup.[/dim]"
        )
        if Confirm.ask("  Delete the Lambda code bucket?", default=False):
            with console.status(f"  Emptying and deleting {lambda_code_bucket}..."):
                run_aws(
                    ["s3", "rm", f"s3://{lambda_code_bucket}", "--recursive"],
                    region=region,
                )
                ok, output = run_aws(
                    ["s3", "rb", f"s3://{lambda_code_bucket}"],
                    region=region,
                )
            if ok:
                console.print("  [green]✓[/green] Lambda code bucket deleted")
            else:
                console.print(f"  [yellow]![/yellow] Could not delete bucket: {output}")

    # Success panel
    console.print()
    console.print(
        Panel(
            f"  [green]✓[/green] Stack [bold]{stack_name}[/bold] deleted\n"
            f"  [green]✓[/green] Region: {region}\n"
            f"\n"
            f"  All resources have been cleaned up.",
            title="[green]Cleanup Complete[/green]",
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
            "[bold]Athena Usage Analyser[/bold] — Cleanup\n"
            "[dim]Remove stack, S3 bucket, and local exports[/dim]",
            box=box.ROUNDED,
            padding=(1, 4),
        )
    )

    ctx = preflight_checks()
    region, stack_name, outputs = step_find_stack(ctx["default_region"])
    step_cleanup(region, stack_name, outputs)

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[dim]Cancelled.[/dim]\n")
        sys.exit(0)
