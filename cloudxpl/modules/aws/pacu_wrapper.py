"""Wrapper for Pacu AWS exploitation framework.

Source: https://github.com/RhinoSecurityLabs/pacu
License: BSD-3-Clause
SRC-ID: SRC-1032
Category: AWS exploitation, Rhino Security Labs, IAM, EC2, S3, Lambda
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.pacu_wrapper.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": [
        "aws_api_calls",
        "credential_enumeration",
        "privilege_escalation_attempts",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004", "T1078.004", "T1580"],
}

PACU_MODULES = {
    "iam__enum_permissions": "Enumerate IAM permissions for current user/role",
    "iam__enum_users_roles_policies_groups": "Enumerate IAM users, roles, policies, groups",
    "iam__privesc_scan": "Scan for IAM privilege escalation paths",
    "ec2__enum": "Enumerate EC2 instances, security groups, VPCs",
    "s3__enum": "Enumerate S3 buckets and their ACLs",
    "lambda__enum": "Enumerate Lambda functions and their configurations",
    "sts__assume_role": "Attempt to assume discoverable roles",
    "ecs__enum": "Enumerate ECS clusters and task definitions",
    "ecr__enum": "Enumerate ECR repositories",
    "secretsmanager__enum": "Enumerate Secrets Manager secrets",
}


def _find_pacu() -> str | None:
    binary = shutil.which("pacu")
    if binary:
        return binary
    for candidate in [
        os.path.expanduser("~/.local/bin/pacu"),
        "/opt/pacu/cli.py",
        os.path.expanduser("~/pacu/cli.py"),
    ]:
        if os.path.isfile(candidate):
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


def _run_pacu_module(pacu_bin: str, module: str, session: str, args: Any) -> dict[str, Any]:
    cmd = [pacu_bin, "--session", session, "--module-name", module, "--exec"]

    profile = getattr(args, "profile", None)
    if profile:
        cmd.extend(["--set-keys", profile])

    region = getattr(args, "region", None)
    if region:
        cmd.extend(["--regions", region])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return {
            "module": module,
            "success": proc.returncode == 0,
            "stdout": proc.stdout[:4096],
            "stderr": proc.stderr[:2048] if proc.returncode != 0 else "",
        }
    except subprocess.TimeoutExpired:
        return {"module": module, "success": False, "error": "timeout (300s)"}
    except OSError as exc:
        return {"module": module, "success": False, "error": str(exc)}


def run(args: Any) -> int:
    """Execute pacu_wrapper module.

    Supported actions (via args.action):
        check   - Verify Pacu installation
        list    - List available Pacu modules
        enum    - Run enumeration modules (--modules or all)
        privesc - Run privilege escalation scan
    """
    action = getattr(args, "action", "check")
    session_name = getattr(args, "session_name", "xpl_pacu")

    print(f"[*] {MANIFEST['capability_id']} : Pacu AWS exploitation framework")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {
        "module": "pacu_wrapper",
        "action": action,
        "findings": [],
    }

    pacu_bin = _find_pacu()

    if action == "check":
        results["pacu_found"] = pacu_bin is not None
        results["pacu_path"] = pacu_bin
        if pacu_bin:
            print(f"[+] Pacu found at: {pacu_bin}")
        else:
            print("[-] Pacu not found; install via: pip install pacu")
        results["status"] = "completed"
        _save(args, "aws_pacu_check", results)
        return 0

    if action == "list":
        results["modules"] = PACU_MODULES
        for name, desc in PACU_MODULES.items():
            print(f"  [{name}] {desc}")
        results["status"] = "completed"
        _save(args, "aws_pacu_list", results)
        return 0

    if not pacu_bin:
        print("[-] Pacu not installed", file=sys.stderr)
        return 1

    if action == "enum":
        targets = getattr(args, "modules", None)
        if targets:
            module_list = [m.strip() for m in targets.split(",")]
        else:
            module_list = [m for m in PACU_MODULES if "__enum" in m]

        for mod in module_list:
            print(f"[*] Running: {mod}")
            result = _run_pacu_module(pacu_bin, mod, session_name, args)
            results["findings"].append(result)

        results["status"] = "completed"
        _save(args, "aws_pacu_enum", results)
        return 0

    if action == "privesc":
        print("[*] Running: iam__privesc_scan")
        result = _run_pacu_module(pacu_bin, "iam__privesc_scan", session_name, args)
        results["findings"].append(result)
        results["status"] = "completed"
        _save(args, "aws_pacu_privesc", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
