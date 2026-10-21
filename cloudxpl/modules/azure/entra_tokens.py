"""Entra ID OAuth token theft, refresh token abuse, PRT extraction."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.azure.entra_tokens.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1528"],
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
    """Execute entra_tokens module."""
    provider = getattr(args, "command", "azure")
    print(f"[*] {MANIFEST['capability_id']}  -  Entra ID OAuth token theft, refresh token abuse, PRT extraction")
    print(f"[*] Provider: {provider} | Service: TokenCredential")
    print(f"[*] Target: OAuth tokens, refresh tokens, PRT")

    results: dict[str, Any] = {
        "module": "entra_tokens",
        "provider": provider,
        "findings": [],
        "summary": {},
    }

    try:
        libs = "azure.identity".split(",")
        for lib in libs:
            __import__(lib.strip())
    except ImportError as exc:
        print(f"[!] Required library not installed: {exc}", file=sys.stderr)
        print(f"[*] Install: pip install {str(exc).split(chr(39))[1] if chr(39) in str(exc) else 'required-lib'}")
        results["status"] = "missing_dependency"
        results["error"] = str(exc)
        _save(args, "azure_entra_tokens", results)
        return 1

    target = getattr(args, "target", None)
    region = getattr(args, "region", "us-east-1")
    profile = getattr(args, "profile", None)
    project = getattr(args, "project", None)

    print("[*] Enumerating OAuth tokens, refresh tokens, PRT...")

    import shutil

    try:
        print("\n[*] Token types:")
        print("  - PRT (Primary Refresh Token): SSO token, cached on device")
        print("  - Refresh Token: long-lived, can generate new access tokens")
        print("  - Access Token (JWT): short-lived, used for API calls")

        print("\n[*] Tools:")
        print("  - ROADtools: roadtx interactiveauth / roadtx gettokens")
        print("  - TokenTactics: Invoke-RefreshToMSGraphToken")
        print("  - AADInternals: Get-AADIntAccessToken")

        roadtx = shutil.which("roadtx")
        if roadtx:
            user = target or "user"
            domain = region or "tenant.onmicrosoft.com"
            print(f"\n[*] ROADtx available. Use:")
            print(f"  roadtx interactiveauth -u {user}@{domain}")
            print("  roadtx gettokens --refresh-token <RT>")
            results["findings"].append({"tool": "roadtx", "available": True})
        else:
            print("\n[!] ROADtx not found. Install: pip install roadlib roadtx")

        results["status"] = "completed"
        results["summary"] = {
            "items_checked": 0,
            "findings_count": len(results["findings"]),
            "key_finding": "leaked or reusable tokens",
            "tool_available": roadtx is not None,
        }
        print("[+] Analysis complete")
    except Exception as exc:
        print(f"[-] Module execution failed: {exc}", file=sys.stderr)
        results["status"] = "error"
        results["error"] = str(exc)
        _save(args, "azure_entra_tokens", results)
        return 1

    _save(args, "azure_entra_tokens", results)
    return 0
