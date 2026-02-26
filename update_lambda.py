#!/usr/bin/env python3
"""Update the deployed Lambda function with the latest local code.

Reads .deploy_config.json for stack name and region, packages lambda/index.py
into a zip, and pushes it directly via `aws lambda update-function-code`.
"""

import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LAMBDA_FILE = SCRIPT_DIR / "lambda" / "index.py"
CONFIG_FILE = SCRIPT_DIR / ".deploy_config.json"


def run_aws(args, region=None, timeout=60):
    cmd = ["aws"] + args
    if region:
        cmd += ["--region", region]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip() or result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "AWS CLI not found"


def main():
    # Load config
    if CONFIG_FILE.exists():
        config = json.loads(CONFIG_FILE.read_text())
        stack_name = config.get("stack_name", "athena-usage-analyser")
        region = config.get("region", "")
    else:
        print(f"No {CONFIG_FILE.name} found — using defaults")
        stack_name = "athena-usage-analyser"
        region = ""

    if not region:
        ok, out = run_aws(["configure", "get", "region"])
        region = out.strip() if ok and out.strip() else "us-east-1"

    print(f"Stack:  {stack_name}")
    print(f"Region: {region}")

    # Get Lambda function name from CFN outputs
    ok, output = run_aws(
        [
            "cloudformation", "describe-stacks",
            "--stack-name", stack_name,
            "--query", "Stacks[0].Outputs",
        ],
        region=region,
    )
    if not ok:
        print(f"ERROR: Could not describe stack: {output}")
        sys.exit(1)

    fn_name = None
    for out in json.loads(output):
        if out.get("OutputKey") == "LambdaFunctionName":
            fn_name = out["OutputValue"]
            break

    if not fn_name:
        print("ERROR: LambdaFunctionName not found in stack outputs")
        sys.exit(1)

    print(f"Lambda: {fn_name}")

    # Check lambda source exists
    if not LAMBDA_FILE.exists():
        print(f"ERROR: {LAMBDA_FILE} not found")
        sys.exit(1)

    # Package
    print("\nPackaging lambda/index.py ...")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        zip_path = tmp.name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(LAMBDA_FILE, "index.py")

    zip_size = Path(zip_path).stat().st_size
    print(f"  Zip size: {zip_size:,} bytes")

    # Update
    print(f"Updating {fn_name} ...")
    ok, output = run_aws(
        [
            "lambda", "update-function-code",
            "--function-name", fn_name,
            "--zip-file", f"fileb://{zip_path}",
        ],
        region=region,
        timeout=120,
    )

    # Clean up
    Path(zip_path).unlink(missing_ok=True)

    if not ok:
        print(f"ERROR: {output}")
        sys.exit(1)

    # Parse response
    try:
        resp = json.loads(output)
        last_modified = resp.get("LastModified", "")
        code_size = resp.get("CodeSize", 0)
        print(f"\n  ✓ Lambda updated successfully")
        print(f"    Last modified: {last_modified}")
        print(f"    Code size:     {code_size:,} bytes")
    except json.JSONDecodeError:
        print(f"\n  ✓ Lambda updated successfully")

    print(f"\nDone. The next Lambda invocation will use the updated code.")


if __name__ == "__main__":
    main()
