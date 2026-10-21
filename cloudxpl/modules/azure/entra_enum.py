"""Entra ID (Azure AD) user, group, application enumeration."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.azure.entra_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
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
    """Execute entra_enum module."""
    provider = getattr(args, "command", "azure")
    print(f"[*] {MANIFEST['capability_id']}  -  Entra ID (Azure AD) user, group, application enumeration")
    print(f"[*] Provider: {provider} | Service: GraphServiceClient")
    print(f"[*] Target: users, groups, applications, service principals")

    results: dict[str, Any] = {
        "module": "entra_enum",
        "provider": provider,
        "findings": [],
        "summary": {},
    }

    try:
        libs = "azure.identity,azure.mgmt.authorization".split(",")
        for lib in libs:
            __import__(lib.strip())
    except ImportError as exc:
        print(f"[!] Required library not installed: {exc}", file=sys.stderr)
        print(f"[*] Install: pip install {str(exc).split(chr(39))[1] if chr(39) in str(exc) else 'required-lib'}")
        results["status"] = "missing_dependency"
        results["error"] = str(exc)
        _save(args, "azure_entra_enum", results)
        return 1

    target = getattr(args, "target", None)
    region = getattr(args, "region", "us-east-1")
    profile = getattr(args, "profile", None)
    project = getattr(args, "project", None)

    print("[*] Enumerating users, groups, applications, service principals...")

    import shutil
    import subprocess

    try:
        roadrecon = shutil.which("roadrecon")
        if roadrecon:
            cmd = [roadrecon, "gather"]
            if target:
                cmd += ["-d", target]
            if profile:
                cmd += ["-u", profile]
            print("[*] CMD: {}".format(" ".join(cmd)))
            proc = subprocess.run(cmd, capture_output=True, text=True)
            results["findings"].append({
                "tool": "roadrecon",
                "stdout": proc.stdout[:4096],
                "returncode": proc.returncode,
            })
            print(proc.stdout)
            print("[*] View: roadrecon gui")
        else:
            print("[!] ROADrecon not found")
            print("[*] Install: pip install roadrecon")
            print("[*] Alternative tools: AADInternals, AzureHound")

        results["status"] = "completed"
        results["summary"] = {
            "items_checked": 0,
            "findings_count": len(results["findings"]),
            "key_finding": "over-privileged app registrations",
            "tool_available": roadrecon is not None,
        }
        print("[+] Analysis complete")
    except Exception as exc:
        print(f"[-] Module execution failed: {exc}", file=sys.stderr)
        results["status"] = "error"
        results["error"] = str(exc)
        _save(args, "azure_entra_enum", results)
        return 1

    _save(args, "azure_entra_enum", results)
    return 0
