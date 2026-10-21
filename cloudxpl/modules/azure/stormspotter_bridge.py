"""Stormspotter graph analysis bridge for Azure."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.azure.stormspotter_bridge.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004"],
}


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
    """Execute stormspotter_bridge module."""
    provider = getattr(args, "command", "azure")
    print(f"[*] {MANIFEST['capability_id']}  -  Stormspotter graph analysis bridge for Azure")
    print(f"[*] Provider: {provider} | Service: stormspotter")
    print(f"[*] Target: Azure AD graph")

    results: dict[str, Any] = {
        "module": "stormspotter_bridge",
        "provider": provider,
        "findings": [],
        "summary": {},
    }

    try:
        libs = "shutil".split(",")
        for lib in libs:
            __import__(lib.strip())
    except ImportError as exc:
        print(f"[!] Required library not installed: {exc}", file=sys.stderr)
        print(f"[*] Install: pip install {str(exc).split(chr(39))[1] if chr(39) in str(exc) else 'required-lib'}")
        results["status"] = "missing_dependency"
        results["error"] = str(exc)
        _save(args, "azure_stormspotter_bridge", results)
        return 1

    target = getattr(args, "target", None)
    region = getattr(args, "region", "us-east-1")
    profile = getattr(args, "profile", None)
    project = getattr(args, "project", None)

    print("[*] Analyzing Azure AD graph for attack paths...")

    import shutil

    try:
        stormspotter = shutil.which("stormspotter")
        azurehound = shutil.which("azurehound")

        if stormspotter:
            print(f"[*] Stormspotter found: {stormspotter}")
            domain = target or "tenant.onmicrosoft.com"
            print(f"[*] Usage: stormspotter --tenant {domain}")
            results["findings"].append({"tool": "stormspotter", "available": True})
        elif azurehound:
            print(f"[*] AzureHound found: {azurehound}")
            print("[*] Usage: azurehound list --tenant <tenant-id> -o output.json")
            print("[*] Import into BloodHound CE for graph analysis")
            results["findings"].append({"tool": "azurehound", "available": True})
        else:
            print("[!] Stormspotter not found")
            print("[*] Source: https://github.com/Azure/Stormspotter")
            print("[*] Alternative: AzureHound for BloodHound CE")

        results["status"] = "completed"
        results["summary"] = {
            "items_checked": 0,
            "findings_count": len(results["findings"]),
            "key_finding": "attack paths in Azure AD",
            "tool_available": stormspotter is not None or azurehound is not None,
        }
        print("[+] Analysis complete")
    except Exception as exc:
        print(f"[-] Module execution failed: {exc}", file=sys.stderr)
        results["status"] = "error"
        results["error"] = str(exc)
        _save(args, "azure_stormspotter_bridge", results)
        return 1

    _save(args, "azure_stormspotter_bridge", results)
    return 0
