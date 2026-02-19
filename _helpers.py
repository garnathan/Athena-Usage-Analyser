"""Shared helpers for Athena Usage Analyser scripts."""

import subprocess
import sys
from typing import List, Optional, Tuple


def install_dependencies(packages: List[str]):
    """Install required packages if not already installed."""
    for package in packages:
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
