"""Azure Storage enumeration  -  storage accounts, containers, public access."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.azure.storage_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["azure_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1530"],
}


def run(args: Any) -> int:
    print("[*] Azure Storage Account Enumeration")

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        print("[!] azure-identity / azure-mgmt-storage not installed", file=sys.stderr)
        return 1

    credential = DefaultAzureCredential()
    results = []

    if not args.subscription_id:
        print("[!] --subscription-id required for Azure modules", file=sys.stderr)
        return 1

    storage_client = StorageManagementClient(credential, args.subscription_id)

    try:
        accounts = list(storage_client.storage_accounts.list())
    except Exception as exc:
        print(f"[-] list storage accounts failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] {len(accounts)} storage accounts")

    for acct in accounts:
        rg_name = acct.id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in acct.id else None
        entry: dict[str, Any] = {
            "name": acct.name,
            "location": acct.location,
            "resource_group": rg_name,
            "kind": acct.kind.value if acct.kind else None,
            "sku": acct.sku.name.value if acct.sku else None,
            "https_only": acct.enable_https_traffic_only,
            "min_tls": getattr(acct, "minimum_tls_version", None),
            "allow_blob_public": acct.allow_blob_public_access,
            "network_default_action": None,
            "containers": [],
        }

        if acct.network_rule_set:
            entry["network_default_action"] = acct.network_rule_set.default_action.value

        if acct.allow_blob_public_access:
            print(f"  [!] {acct.name}: blob public access ALLOWED")

        if rg_name:
            try:
                containers = storage_client.blob_containers.list(rg_name, acct.name)
                for c in containers:
                    c_entry = {
                        "name": c.name,
                        "public_access": c.public_access.value if c.public_access else "None",
                    }
                    if c.public_access and c.public_access.value != "None":
                        print(f"    [!] container {acct.name}/{c.name}: public={c.public_access.value}")
                    entry["containers"].append(c_entry)
            except Exception:
                entry["containers_error"] = "AccessDenied"

        results.append(entry)

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"azure_storage_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    public_count = sum(1 for r in results if r.get("allow_blob_public"))
    print(f"[+] {public_count} with public blob access, {len(results)} total → {out_path}")
    return 0
