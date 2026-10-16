"""Azure subscription enumeration — list subscriptions, resource groups, RBAC."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.azure.subscription_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["azure_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526"],
}


def run(args: Any) -> int:
    print("[*] Azure Subscription Enumeration")

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    except ImportError:
        print("[!] azure-identity / azure-mgmt-resource not installed", file=sys.stderr)
        return 1

    credential = DefaultAzureCredential()
    sub_client = SubscriptionClient(credential)

    results: dict[str, Any] = {"subscriptions": []}

    try:
        for sub in sub_client.subscriptions.list():
            entry = {
                "subscription_id": sub.subscription_id,
                "display_name": sub.display_name,
                "state": sub.state.value if sub.state else None,
                "tenant_id": sub.tenant_id,
                "resource_groups": [],
            }

            try:
                rg_client = ResourceManagementClient(credential, sub.subscription_id)
                for rg in rg_client.resource_groups.list():
                    entry["resource_groups"].append({
                        "name": rg.name,
                        "location": rg.location,
                        "tags": dict(rg.tags) if rg.tags else {},
                    })
            except Exception as exc:
                entry["rg_error"] = str(exc)

            results["subscriptions"].append(entry)
            print(f"  [+] {sub.display_name} ({sub.subscription_id}): "
                  f"{len(entry['resource_groups'])} resource groups")
    except Exception as exc:
        print(f"[-] Subscription listing failed: {exc}", file=sys.stderr)
        return 1

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"azure_subscriptions_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"[+] {len(results['subscriptions'])} subscriptions → {out_path}")
    return 0
