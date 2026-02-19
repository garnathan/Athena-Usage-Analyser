#!/usr/bin/env python3
"""
Athena Usage Analyser — Interactive Analysis Script

Invokes the Lambda for historical data collection, downloads exports from S3,
and generates an HTML report — all through an interactive terminal UI.

Usage:
    python3 analyse.py
"""

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
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

    # 3. analyse_exports.py exists
    analyser_path = SCRIPT_DIR / "analyse_exports.py"
    if not analyser_path.exists():
        console.print(
            Panel(
                "[red]analyse_exports.py not found.[/red]\n\n"
                f"Expected: {analyser_path}\n"
                "Make sure you're running from the project root.",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)
    console.print(f"  [green]✓[/green] analyse_exports.py found")

    default_region = get_default_region()

    return {
        "account_id": account_id,
        "default_region": default_region,
        "analyser_path": analyser_path,
    }


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
        # Fall back to manual entry
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
    # Filter to likely analyser stacks
    analyser_stacks = [
        s for s in stacks if "athena" in s.get("StackName", "").lower()
    ]

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
            console.print(f"  [red]✗[/red] Enter a number between 1 and {len(analyser_stacks)}.")

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
    if "ExportsLocation" in outputs:
        table.add_row("Exports Path", outputs["ExportsLocation"])

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# Step 2: Invoke Lambda
# ---------------------------------------------------------------------------


def step_invoke_lambda(region: str, outputs: Dict[str, str]) -> None:
    """Optionally invoke Lambda for historical analysis."""
    console.print()
    console.print("[bold]Step 2 · Run Analysis (Optional)[/bold]")
    console.print()
    console.print(
        "  The Lambda collects data automatically on a schedule.\n"
        "  You can also invoke it now to capture historical data (up to 90 days)."
    )
    console.print()

    if not Confirm.ask("  Invoke Lambda for historical analysis?", default=True):
        console.print("\n  [dim]Skipped — will use existing exports.[/dim]")
        return

    # Time range
    console.print()
    console.print("  How far back should the analysis go?")
    console.print()
    console.print("  [bold]1[/bold]. Last 7 days")
    console.print("  [bold]2[/bold]. Last 30 days")
    console.print("  [bold]3[/bold]. Last 60 days")
    console.print("  [bold]4[/bold]. Last 90 days (maximum)")
    console.print("  [bold]5[/bold]. Custom date range")
    console.print()

    while True:
        choice = Prompt.ask("  Select time range (1-5)", default="3")
        if choice in ("1", "2", "3", "4", "5"):
            break
        console.print("  [red]✗[/red] Enter a number between 1 and 5.")

    now = datetime.now(timezone.utc)

    if choice == "5":
        # Custom range
        while True:
            start_str = Prompt.ask("  Start date (YYYY-MM-DD)")
            try:
                start_date = datetime.strptime(start_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                break
            except ValueError:
                console.print("  [red]✗[/red] Use format YYYY-MM-DD.")

        while True:
            end_str = Prompt.ask(
                "  End date (YYYY-MM-DD)", default=now.strftime("%Y-%m-%d")
            )
            try:
                end_date = datetime.strptime(end_str, "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc
                )
                if end_date >= start_date:
                    break
                console.print("  [red]✗[/red] End date must be after start date.")
            except ValueError:
                console.print("  [red]✗[/red] Use format YYYY-MM-DD.")

        start_time = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        days_map = {"1": 7, "2": 30, "3": 60, "4": 90}
        days = days_map[choice]
        start_time = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    function_name = outputs.get("LambdaFunctionName", "athena-usage-analyser-analyser")
    payload = json.dumps({"start_time": start_time, "end_time": end_time})

    console.print()
    console.print(f"  Time range: {start_time} → {end_time}")
    console.print(f"  Function:   {function_name}")

    # Invoke
    console.print()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_file = tmp.name

    with console.status("  Invoking Lambda (this may take a few minutes)..."):
        ok, output = run_aws(
            [
                "lambda",
                "invoke",
                "--function-name",
                function_name,
                "--payload",
                payload,
                "--cli-binary-format",
                "raw-in-base64-out",
                output_file,
            ],
            region=region,
        )

    if not ok:
        console.print(
            Panel(
                f"[red]Lambda invocation failed.[/red]\n\n{output}",
                title="Error",
                border_style="red",
            )
        )
        if not Confirm.ask("  Continue to download existing exports?", default=True):
            console.print("\n[dim]Cancelled.[/dim]")
            sys.exit(0)
        return

    # Check response
    try:
        invoke_result = json.loads(output)
        status_code = invoke_result.get("StatusCode", 0)
        function_error = invoke_result.get("FunctionError", "")
    except json.JSONDecodeError:
        status_code = 0
        function_error = ""

    if function_error:
        # Read the error payload
        try:
            error_payload = Path(output_file).read_text()
            console.print(f"  [red]✗[/red] Lambda returned an error: {error_payload[:500]}")
        except Exception:
            console.print(f"  [red]✗[/red] Lambda returned error: {function_error}")
        if not Confirm.ask("  Continue to download existing exports?", default=True):
            console.print("\n[dim]Cancelled.[/dim]")
            sys.exit(0)
    elif status_code == 200:
        console.print("  [green]✓[/green] Lambda invocation successful")
        try:
            result_data = json.loads(Path(output_file).read_text())
            if isinstance(result_data, dict) and result_data.get("statusCode") == 200:
                body = result_data.get("body", "")
                if isinstance(body, str):
                    try:
                        body = json.loads(body)
                    except json.JSONDecodeError:
                        pass
                if isinstance(body, dict):
                    export_path = body.get("export_path", "")
                    if export_path:
                        console.print(f"  [green]✓[/green] Export: {export_path}")
        except Exception:
            pass
    else:
        console.print(f"  [green]✓[/green] Lambda invocation completed (status: {status_code})")

    # Clean up temp file
    try:
        Path(output_file).unlink()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Step 3: Download & Report
# ---------------------------------------------------------------------------


def step_download_and_report(
    region: str, outputs: Dict[str, str], analyser_path: Path
) -> None:
    """Download exports from S3 and generate HTML report."""
    console.print()
    console.print("[bold]Step 3 · Download & Generate Report[/bold]")
    console.print()

    bucket_name = outputs.get("AnalysisBucketName", "")
    exports_s3_path = outputs.get("ExportsLocation", f"s3://{bucket_name}/exports/")

    if not bucket_name and not exports_s3_path:
        console.print("  [red]✗[/red] Could not determine S3 bucket from stack outputs.")
        exports_s3_path = Prompt.ask("  Enter S3 exports path (e.g. s3://bucket/exports/)")

    # Local download directory
    default_dir = str(SCRIPT_DIR / "exports")
    exports_dir = Prompt.ask("  Local exports directory", default=default_dir)
    exports_path = Path(exports_dir)

    # Download
    console.print()
    with console.status(f"  Downloading exports from {exports_s3_path}..."):
        ok, output = run_aws(
            ["s3", "sync", exports_s3_path, str(exports_path)],
            region=region,
        )

    if not ok:
        console.print(
            Panel(
                f"[red]Failed to download exports.[/red]\n\n{output}",
                title="Error",
                border_style="red",
            )
        )
        sys.exit(1)

    # Count downloaded files
    zip_files = list(exports_path.glob("*.zip"))
    if not zip_files:
        console.print(
            Panel(
                "[yellow]No export files found.[/yellow]\n\n"
                "The Lambda may not have run yet, or exports may be in a different location.\n"
                f"Checked: {exports_path}",
                title="No Data",
                border_style="yellow",
            )
        )
        sys.exit(0)

    console.print(f"  [green]✓[/green] Downloaded {len(zip_files)} export{'s' if len(zip_files) != 1 else ''}")

    # Generate report
    console.print()
    report_name = "athena-usage-report.html"
    report_path = SCRIPT_DIR / report_name

    console.print(f"  Generating HTML report...")
    console.print()

    result = subprocess.run(
        [
            sys.executable,
            str(analyser_path),
            str(exports_path),
            "--html",
            str(report_path),
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        console.print(f"  [red]✗[/red] Report generation failed")
        if result.stderr:
            console.print(f"  [dim]{result.stderr[:500]}[/dim]")
        sys.exit(1)

    console.print(f"  [green]✓[/green] Report generated: {report_path}")

    # Success panel
    console.print()
    console.print(
        Panel(
            f"  [green]✓[/green] Exports:  {exports_path} ({len(zip_files)} files)\n"
            f"  [green]✓[/green] Report:   {report_path}\n"
            f"\n"
            f"  The report should open in your browser automatically.\n"
            f"  If not, open [bold]{report_name}[/bold] manually.",
            title="[green]Analysis Complete[/green]",
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
            "[bold]Athena Usage Analyser[/bold] — Analyse\n"
            "[dim]Invoke Lambda, download exports, and generate report[/dim]",
            box=box.ROUNDED,
            padding=(1, 4),
        )
    )

    ctx = preflight_checks()
    region, stack_name, outputs = step_find_stack(ctx["default_region"])
    step_invoke_lambda(region, outputs)
    step_download_and_report(region, outputs, ctx["analyser_path"])

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[dim]Cancelled.[/dim]\n")
        sys.exit(0)
