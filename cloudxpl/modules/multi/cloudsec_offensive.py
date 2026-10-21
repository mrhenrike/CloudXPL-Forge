"""Wrapper for CloudSec offensive cloud security toolkit.

Source: https://github.com/eshlomo1/CloudSec
License: verify
SRC-ID: SRC-676
Category: Offensive cloud security, Azure, Entra ID, AWS, M365, red team
"""

import json
import os
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.multi.cloudsec_offensive.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["cloud_api_calls", "credential_enumeration"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004", "T1078.004", "T1069.003"],
}

MODULES = {
    "azure_enum": "Enumerate Azure resources (tenants, subscriptions, groups)",
    "entra_spray": "Password spray against Entra ID endpoints",
    "m365_enum": "Enumerate M365 mailbox, SharePoint, Teams exposure",
    "aws_enum": "Enumerate AWS IAM, S3, EC2 via CloudSec scripts",
    "token_abuse": "Token request and abuse flows (device code, refresh token)",
}


def _find_cloudsec() -> str | None:
    for candidate in [
        "/opt/CloudSec",
        os.path.expanduser("~/CloudSec"),
        os.path.expanduser("~/tools/CloudSec"),
    ]:
        if os.path.isdir(candidate):
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
    """Execute cloudsec_offensive module.

    Actions (via args.action):
        check   - Verify CloudSec installation
        list    - List available modules
        exec    - Run a specific module (--module)
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} : CloudSec offensive toolkit")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {"module": "cloudsec_offensive", "action": action, "findings": []}

    cs_dir = _find_cloudsec()

    if action == "check":
        results["installed"] = cs_dir is not None
        results["path"] = cs_dir
        if cs_dir:
            scripts = list(Path(cs_dir).rglob("*.py"))
            results["script_count"] = len(scripts)
            print(f"[+] CloudSec at: {cs_dir} ({len(scripts)} scripts)")
        else:
            print("[-] CloudSec not found")
        results["status"] = "completed"
        _save(args, "multi_cloudsec_check", results)
        return 0

    if action == "list":
        results["modules"] = MODULES
        for name, desc in MODULES.items():
            print(f"  [{name}] {desc}")
        results["status"] = "completed"
        _save(args, "multi_cloudsec_list", results)
        return 0

    if not cs_dir:
        print("[-] CloudSec not installed", file=sys.stderr)
        return 1

    if action == "exec":
        module = getattr(args, "module", None)
        if not module or module not in MODULES:
            print(f"[-] --module required (one of: {', '.join(MODULES)})", file=sys.stderr)
            return 1

        script_map = {
            "azure_enum": "Azure/azure_enum.py",
            "entra_spray": "Azure/entra_spray.py",
            "m365_enum": "M365/m365_enum.py",
            "aws_enum": "AWS/aws_enum.py",
            "token_abuse": "Azure/token_abuse.py",
        }
        script = os.path.join(cs_dir, script_map.get(module, ""))
        if not os.path.isfile(script):
            print(f"[-] Script not found: {script}", file=sys.stderr)
            results["status"] = "script_missing"
            _save(args, f"multi_cloudsec_{module}", results)
            return 1

        cmd = [sys.executable, script]
        target = getattr(args, "target_tenant", None)
        if target:
            cmd.extend(["--tenant", target])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results["findings"].append({
                "module": module,
                "stdout": proc.stdout[:8192],
                "returncode": proc.returncode,
            })
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        _save(args, f"multi_cloudsec_{module}", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
