"""Wrapper for CloudToolKit multi-cloud assessment framework.

Source: https://github.com/404tk/cloudtoolkit
License: verify
SRC-ID: SRC-1024
Category: Multi-cloud, OCI, AWS, Alibaba, ECS, OSS, RAM, RDS, DNS
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.multi.cloudtoolkit_wrapper.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["cloud_api_calls", "credential_enumeration", "resource_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526", "T1087.004", "T1136.003"],
}

PROVIDER_MODULES = {
    "aws": ["ecs_enum", "s3_enum", "iam_enum", "rds_enum", "ec2_exec"],
    "alibaba": ["ecs_enum", "oss_enum", "ram_enum", "rds_enum", "dns_enum"],
    "oci": ["compute_enum", "bucket_enum", "iam_enum"],
}


def _find_cloudtoolkit() -> str | None:
    binary = shutil.which("cloudtoolkit")
    if binary:
        return binary
    for candidate in [
        os.path.expanduser("~/go/bin/cloudtoolkit"),
        "/opt/cloudtoolkit/cloudtoolkit",
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
    """Execute cloudtoolkit_wrapper module.

    Actions (via args.action):
        check  - Verify CloudToolKit installation
        list   - List provider modules
        exec   - Run module (--provider, --module)
    """
    action = getattr(args, "action", "check")
    provider = getattr(args, "provider", "aws")
    print(f"[*] {MANIFEST['capability_id']} : CloudToolKit multi-cloud assessment")
    print(f"[*] Action: {action} | Provider: {provider}")

    results: dict[str, Any] = {"module": "cloudtoolkit_wrapper", "action": action, "findings": []}

    ctk = _find_cloudtoolkit()

    if action == "check":
        results["installed"] = ctk is not None
        results["path"] = ctk
        print(f"[+] CloudToolKit: {ctk or 'not found'}")
        results["status"] = "completed"
        _save(args, "multi_ctk_check", results)
        return 0

    if action == "list":
        results["providers"] = PROVIDER_MODULES
        for prov, mods in PROVIDER_MODULES.items():
            print(f"  [{prov}] {', '.join(mods)}")
        results["status"] = "completed"
        _save(args, "multi_ctk_list", results)
        return 0

    if not ctk:
        print("[-] CloudToolKit not installed", file=sys.stderr)
        return 1

    if action == "exec":
        module = getattr(args, "module", None)
        if not module:
            print("[-] --module required", file=sys.stderr)
            return 1

        cmd = [ctk, provider, module]
        ak = getattr(args, "access_key", None)
        sk = getattr(args, "secret_key", None)
        if ak:
            cmd.extend(["--access-key", ak])
        if sk:
            cmd.extend(["--secret-key", sk])
        region = getattr(args, "region", None)
        if region:
            cmd.extend(["--region", region])

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
        _save(args, f"multi_ctk_{module}", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
