"""Wrapper for CloudBrute multi-cloud infrastructure discovery.

Source: https://github.com/0xsha/CloudBrute
License: verify
SRC-ID: SRC-1025
Category: Multi-cloud discovery, recon, bug bounty, red team, Alibaba
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.multi.cloudbrute_discovery.v1",
    "safety_class": "RECON",
    "requires_authorization": True,
    "side_effects": ["dns_queries", "http_requests"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526", "T1580"],
}

PROVIDERS = ["aws", "azure", "gcp", "alibaba", "digitalocean"]


def _find_cloudbrute() -> str | None:
    binary = shutil.which("CloudBrute") or shutil.which("cloudbrute")
    if binary:
        return binary
    for candidate in [
        "/opt/CloudBrute/CloudBrute",
        os.path.expanduser("~/go/bin/CloudBrute"),
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
    """Execute cloudbrute_discovery module.

    Actions (via args.action):
        check  - Verify CloudBrute installation
        scan   - Run infrastructure discovery (--target required)
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} : CloudBrute multi-cloud discovery")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {"module": "cloudbrute_discovery", "action": action, "findings": []}

    cb = _find_cloudbrute()

    if action == "check":
        results["installed"] = cb is not None
        results["path"] = cb
        results["providers"] = PROVIDERS
        print(f"[+] CloudBrute: {cb or 'not found'}")
        results["status"] = "completed"
        _save(args, "multi_cloudbrute_check", results)
        return 0

    if not cb:
        print("[-] CloudBrute not installed", file=sys.stderr)
        return 1

    if action == "scan":
        target = getattr(args, "target", None)
        if not target:
            print("[-] --target required for scan", file=sys.stderr)
            return 1

        cmd = [cb, "-d", target]
        wordlist = getattr(args, "wordlist", None)
        if wordlist:
            cmd.extend(["-w", wordlist])
        threads = getattr(args, "threads", 10)
        cmd.extend(["-t", str(threads)])

        providers = getattr(args, "providers", None)
        if providers:
            for p in providers if isinstance(providers, list) else providers.split(","):
                cmd.extend(["-p", p.strip()])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            results["stdout"] = proc.stdout[:8192]
            results["returncode"] = proc.returncode
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        except OSError as exc:
            results["status"] = "error"
            results["error"] = str(exc)

        _save(args, "multi_cloudbrute_scan", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
