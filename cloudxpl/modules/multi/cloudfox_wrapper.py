"""Wrapper for CloudFox cloud enumeration tool.

Source: https://github.com/BishopFox/cloudfox
License: MIT
SRC-ID: SRC-1031
Category: Cloud enumeration, offensive, AWS, Azure, GCP, Bishop Fox
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.multi.cloudfox_wrapper.v1",
    "safety_class": "RECON",
    "requires_authorization": True,
    "side_effects": ["cloud_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526", "T1087.004", "T1580"],
}

COMMANDS = {
    "aws": [
        "access-keys", "buckets", "ecr", "eks", "endpoints", "env-vars",
        "iam-simulator", "instances", "inventory", "lambda", "permissions",
        "principals", "role-trusts", "route53", "secrets",
    ],
    "azure": ["instances-map", "rbac-map", "storage-map"],
    "gcp": ["instances-map", "iam-map"],
}


def _find_cloudfox() -> str | None:
    binary = shutil.which("cloudfox")
    if binary:
        return binary
    for candidate in [
        os.path.expanduser("~/go/bin/cloudfox"),
        "/opt/cloudfox/cloudfox",
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def run(args: Any) -> int:
    """Execute cloudfox_wrapper module.

    Actions (via args.action):
        check  - Verify CloudFox installation
        list   - List available commands per provider
        enum   - Run enumeration command (--provider, --command)
        all    - Run all commands for a provider
    """
    action = getattr(args, "action", "check")
    provider = getattr(args, "provider", "aws")
    print(f"[*] {MANIFEST['capability_id']} : CloudFox cloud enumeration")
    print(f"[*] Action: {action} | Provider: {provider}")

    results: dict[str, Any] = {"module": "cloudfox_wrapper", "action": action, "findings": []}

    cf = _find_cloudfox()

    if action == "check":
        results["installed"] = cf is not None
        results["path"] = cf
        if cf:
            proc = subprocess.run([cf, "--version"], capture_output=True, text=True, timeout=10)
            results["version"] = proc.stdout.strip()
            print(f"[+] CloudFox: {results['version']}")
        else:
            print("[-] CloudFox not found")
        results["status"] = "completed"
        _save(args, "multi_cloudfox_check", results)
        return 0

    if action == "list":
        results["commands"] = COMMANDS
        for prov, cmds in COMMANDS.items():
            print(f"  [{prov}] {', '.join(cmds)}")
        results["status"] = "completed"
        _save(args, "multi_cloudfox_list", results)
        return 0

    if not cf:
        print("[-] CloudFox not installed", file=sys.stderr)
        return 1

    if action == "enum":
        command = getattr(args, "command", None)
        if not command:
            print("[-] --command required", file=sys.stderr)
            return 1
        cmd = [cf, provider, command]
        profile = getattr(args, "profile", None)
        if profile:
            cmd.extend(["--profile", profile])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results["findings"].append({
                "command": command,
                "stdout": proc.stdout[:8192],
                "returncode": proc.returncode,
            })
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        _save(args, f"multi_cloudfox_{command}", results)
        return 0

    if action == "all":
        cmds = COMMANDS.get(provider, [])
        for command in cmds:
            print(f"[*] Running: cloudfox {provider} {command}")
            cmd = [cf, provider, command]
            profile = getattr(args, "profile", None)
            if profile:
                cmd.extend(["--profile", profile])
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                results["findings"].append({
                    "command": command,
                    "stdout": proc.stdout[:4096],
                    "returncode": proc.returncode,
                })
            except subprocess.TimeoutExpired:
                results["findings"].append({"command": command, "error": "timeout"})
        results["status"] = "completed"
        _save(args, "multi_cloudfox_all", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
