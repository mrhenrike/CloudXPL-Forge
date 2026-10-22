# AUTHORIZED USE ONLY
"""Progress ShareFile Storage Zones Controller RCE (CVE-2026-2699).

A remote code execution vulnerability in Progress ShareFile Storage Zones
Controller. An unauthenticated attacker can upload and execute arbitrary
files via a path traversal in the document upload handler.

CVE: CVE-2026-2699
CVSS: 8.8 (High)
Affected: ShareFile Storage Zones Controller < 5.11.29
Fix: 5.11.29
CWE: CWE-22 (Path Traversal), CWE-434 (Unrestricted Upload)

MITRE ATT&CK:
  T1190 - Exploit Public-Facing Application

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Source: watchTowr Labs advisory
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

MANIFEST = {
    "name": "sharefile-storage-zones-rce",
    "description": "Progress ShareFile Storage Zones Controller unauthenticated RCE via path traversal (CVSS 8.8)",
    "capability_id": "cloudxpl.paas.progress.cve_2026_2699",
    "cve": "CVE-2026-2699",
    "cvss": 8.8,
    "safety_class": "EXPLOIT",
    "mitre": ["T1190"],
    "references": [
        "https://labs.watchtowr.com/sharefile-storage-zones-rce-cve-2026-2699/",
        "https://community.progress.com/s/article/ShareFile-Security-Advisory",
    ],
    "devices": ["Progress ShareFile Storage Zones Controller"],
}

_UPLOAD_PATH = "/cifs/upload.aspx"
_PROBE_PATH = "/documentprovider/api/v1/version"


def _http_get(base: str, path: str, timeout: float = 10) -> tuple[int, str]:
    url = base.rstrip("/") + path
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "CloudXPL/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception:
        return 0, ""


def check(args: Any) -> bool:
    host = getattr(args, "target", "") or ""
    port = int(getattr(args, "port", 443) or 443)
    scheme = "https" if port == 443 else "http"
    base = f"{scheme}://{host}:{port}"
    status, text = _http_get(base, _PROBE_PATH)
    if status == 200 and ("sharefile" in text.lower() or "storagezones" in text.lower()):
        return True
    status2, _ = _http_get(base, _UPLOAD_PATH)
    return status2 in (200, 302, 405)


def run(args: Any) -> int:
    host = getattr(args, "target", "") or ""
    port = int(getattr(args, "port", 443) or 443)
    simulate = getattr(args, "simulate", True)
    scheme = "https" if port == 443 else "http"
    base = f"{scheme}://{host}:{port}"

    if simulate:
        print("[*] [SIMULATE] CVE-2026-2699  -  ShareFile RCE")
        print("[*]   Vector: Path traversal in upload handler")
        print("[*]   Affected: Storage Zones Controller < 5.11.29")
        print("[*]   Impact: Unauthenticated file upload -> RCE")
        print("[*]   Mitigation: Update to 5.11.29+")
        return 0

    print(f"[*] Probing {host}:{port} for ShareFile...")
    status, text = _http_get(base, _PROBE_PATH)
    if status == 200:
        print("[*] ShareFile API endpoint detected")
        if "sharefile" in text.lower():
            print("[+] ShareFile Storage Zones confirmed")
    else:
        print("[*] Version endpoint not accessible")

    status2, _ = _http_get(base, _UPLOAD_PATH)
    if status2 in (200, 405):
        print("[!] Upload endpoint responsive  -  potentially vulnerable")
        print("[*]   Path traversal in filename allows webshell upload")
        print("[*]   Confirm version < 5.11.29 for exploitability")
    else:
        print("[*] Upload endpoint not directly reachable")
    return 0
