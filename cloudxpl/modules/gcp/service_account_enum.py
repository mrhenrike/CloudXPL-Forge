"""GCP Service Account enumeration  -  list SAs, keys, permissions."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any

import requests


MANIFEST = {
    "capability_id": "cloudxpl.gcp.service_account_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["gcp_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004"],
}

IAM_API = "https://iam.googleapis.com/v1"


def _get_token() -> str | None:
    try:
        from google.auth.transport.requests import Request
        from google.auth import default
        creds, _ = default()
        creds.refresh(Request())
        return creds.token
    except Exception:
        return None


def run(args: Any) -> int:
    project = args.project_id
    print(f"[*] GCP Service Account Enumeration (project: {project})")

    token = _get_token()
    if not token:
        print("[!] Could not obtain GCP credentials", file=sys.stderr)
        return 1

    headers = {"Authorization": f"Bearer {token}"}

    try:
        resp = requests.get(
            f"{IAM_API}/projects/{project}/serviceAccounts",
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        accounts = resp.json().get("accounts", [])
    except Exception as exc:
        print(f"[-] list service accounts failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] {len(accounts)} service accounts")
    results = []

    for sa in accounts:
        entry = {
            "email": sa.get("email"),
            "name": sa.get("displayName"),
            "unique_id": sa.get("uniqueId"),
            "disabled": sa.get("disabled", False),
            "keys": [],
        }

        try:
            keys_resp = requests.get(
                f"{IAM_API}/{sa['name']}/keys",
                headers=headers,
                timeout=10,
            )
            if keys_resp.status_code == 200:
                for key in keys_resp.json().get("keys", []):
                    key_entry = {
                        "key_id": key.get("name", "").split("/")[-1],
                        "key_type": key.get("keyType"),
                        "key_origin": key.get("keyOrigin"),
                        "valid_after": key.get("validAfterTime"),
                        "valid_before": key.get("validBeforeTime"),
                    }
                    if key.get("keyType") == "USER_MANAGED":
                        print(f"  [!] {sa['email']}: user-managed key {key_entry['key_id'][:8]}...")
                    entry["keys"].append(key_entry)
        except Exception:
            entry["keys_error"] = "AccessDenied"

        results.append(entry)

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"gcp_service_accounts_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    user_managed = sum(
        1 for r in results
        for k in r.get("keys", [])
        if k.get("key_type") == "USER_MANAGED"
    )
    print(f"[+] {user_managed} user-managed keys across {len(results)} SAs → {out_path}")
    return 0
