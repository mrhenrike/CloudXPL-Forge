"""Wrapper for pOliCI OCI IAM policy parser.

Source: XM Cyber / DEF CON 34
License: open-source; verify
SRC-ID: SRC-1027
Category: OCI IAM, policy parser, privilege escalation, audit
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.oci.polici_iam_parser.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["oci_api_reads"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004", "T1069.003"],
}


def _find_polici() -> str | None:
    binary = shutil.which("polici")
    if binary:
        return binary
    for candidate in [
        os.path.expanduser("~/tools/polici/polici"),
        "/opt/polici/polici",
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
    """Execute polici_iam_parser module.

    Actions (via args.action):
        check    - Verify pOliCI installation
        parse    - Parse IAM policies for a tenancy (--tenancy_ocid)
        privesc  - Check for privilege escalation paths
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} : pOliCI OCI IAM parser")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {"module": "polici_iam_parser", "action": action, "findings": []}

    polici = _find_polici()

    if action == "check":
        results["installed"] = polici is not None
        results["path"] = polici
        print(f"[+] pOliCI: {polici or 'not found'}")
        results["status"] = "completed"
        _save(args, "oci_polici_check", results)
        return 0

    if not polici:
        print("[-] pOliCI not installed", file=sys.stderr)
        return 1

    tenancy = getattr(args, "tenancy_ocid", None)
    if not tenancy:
        print("[-] --tenancy_ocid required", file=sys.stderr)
        return 1

    if action == "parse":
        cmd = [polici, "parse", "--tenancy", tenancy]
        compartment = getattr(args, "compartment_ocid", None)
        if compartment:
            cmd.extend(["--compartment", compartment])
        fmt = getattr(args, "output_format", "json")
        cmd.extend(["--format", fmt])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results["findings"].append({
                "action": "parse",
                "stdout": proc.stdout[:8192],
                "returncode": proc.returncode,
            })
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        _save(args, "oci_polici_parse", results)
        return 0

    if action == "privesc":
        cmd = [polici, "privesc", "--tenancy", tenancy]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results["findings"].append({
                "action": "privesc",
                "stdout": proc.stdout[:8192],
                "returncode": proc.returncode,
            })
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        _save(args, "oci_polici_privesc", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
