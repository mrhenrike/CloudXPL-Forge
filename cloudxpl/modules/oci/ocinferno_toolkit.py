"""Wrapper for OCInferno OCI pentesting toolkit.

Source: CloudSec 2026 (Scott Weston)
License: verify
SRC-ID: SRC-1026
Category: OCI pentest, IAM ANTLR parser, Burp extension, recon, privesc
"""

import json
import os
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.oci.ocinferno_toolkit.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["oci_api_calls", "iam_enumeration"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004", "T1078.004", "T1069.003"],
}

TOOLS = {
    "recon": "OCI tenant and compartment reconnaissance",
    "iam_parse": "Parse IAM policies with ANTLR grammar",
    "privesc_graph": "OpenGraph privilege escalation visualizer",
    "api_sign": "OCI API request signing (Burp extension helper)",
}


def _find_ocinferno() -> str | None:
    for candidate in [
        "/opt/ocinferno",
        os.path.expanduser("~/ocinferno"),
        os.path.expanduser("~/tools/ocinferno"),
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
    """Execute ocinferno_toolkit module.

    Actions (via args.action):
        check   - Verify OCInferno installation
        list    - List available tools
        recon   - Run OCI reconnaissance
        privesc - Run privilege escalation graph analysis
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} : OCInferno OCI pentest toolkit")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {"module": "ocinferno_toolkit", "action": action, "findings": []}

    oci_dir = _find_ocinferno()

    if action == "check":
        results["installed"] = oci_dir is not None
        results["path"] = oci_dir
        if oci_dir:
            scripts = list(Path(oci_dir).rglob("*.py"))
            results["script_count"] = len(scripts)
            print(f"[+] OCInferno at: {oci_dir} ({len(scripts)} scripts)")
        else:
            print("[-] OCInferno not found")
        results["status"] = "completed"
        _save(args, "oci_ocinferno_check", results)
        return 0

    if action == "list":
        results["tools"] = TOOLS
        for name, desc in TOOLS.items():
            print(f"  [{name}] {desc}")
        results["status"] = "completed"
        _save(args, "oci_ocinferno_list", results)
        return 0

    if not oci_dir:
        print("[-] OCInferno not installed", file=sys.stderr)
        return 1

    if action in ("recon", "privesc"):
        tenancy = getattr(args, "tenancy_ocid", None)
        if not tenancy:
            print("[-] --tenancy_ocid required", file=sys.stderr)
            return 1

        script_name = "recon.py" if action == "recon" else "privesc_graph.py"
        script = os.path.join(oci_dir, script_name)

        if not os.path.isfile(script):
            print(f"[-] Script not found: {script}", file=sys.stderr)
            return 1

        cmd = [sys.executable, script, "--tenancy", tenancy]
        region = getattr(args, "region", None)
        if region:
            cmd.extend(["--region", region])
        key_file = getattr(args, "key_file", None)
        if key_file:
            cmd.extend(["--key-file", key_file])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results["findings"].append({
                "tool": action,
                "stdout": proc.stdout[:8192],
                "returncode": proc.returncode,
            })
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        _save(args, f"oci_ocinferno_{action}", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
