"""GCP Project enumeration — list projects, APIs, compute instances."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import requests


MANIFEST = {
    "capability_id": "cloudxpl.gcp.project_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["gcp_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526"],
}

CRM_API = "https://cloudresourcemanager.googleapis.com/v1"
COMPUTE_API = "https://compute.googleapis.com/compute/v1"


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
    print("[*] GCP Project Enumeration")

    token = _get_token()
    if not token:
        print("[!] Could not obtain GCP credentials", file=sys.stderr)
        return 1

    headers = {"Authorization": f"Bearer {token}"}
    results: dict[str, Any] = {"projects": []}

    try:
        resp = requests.get(f"{CRM_API}/projects", headers=headers, timeout=15)
        resp.raise_for_status()
        projects = resp.json().get("projects", [])
    except Exception as exc:
        print(f"[-] list projects failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] {len(projects)} projects accessible")

    for proj in projects:
        project_id = proj.get("projectId")
        entry = {
            "project_id": project_id,
            "name": proj.get("name"),
            "number": proj.get("projectNumber"),
            "state": proj.get("lifecycleState"),
            "labels": proj.get("labels", {}),
            "enabled_apis": [],
            "compute_instances": [],
        }

        try:
            api_resp = requests.get(
                f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services",
                params={"filter": "state:ENABLED"},
                headers=headers,
                timeout=15,
            )
            if api_resp.status_code == 200:
                services = api_resp.json().get("services", [])
                entry["enabled_apis"] = [
                    s.get("config", {}).get("name", s.get("name"))
                    for s in services
                ]
        except Exception:
            entry["apis_error"] = "AccessDenied"

        try:
            instances_resp = requests.get(
                f"{COMPUTE_API}/projects/{project_id}/aggregated/instances",
                headers=headers,
                timeout=15,
            )
            if instances_resp.status_code == 200:
                for zone_data in instances_resp.json().get("items", {}).values():
                    for inst in zone_data.get("instances", []):
                        entry["compute_instances"].append({
                            "name": inst.get("name"),
                            "zone": inst.get("zone", "").split("/")[-1],
                            "status": inst.get("status"),
                            "machine_type": inst.get("machineType", "").split("/")[-1],
                            "external_ip": next(
                                (ac.get("natIP")
                                 for ni in inst.get("networkInterfaces", [])
                                 for ac in ni.get("accessConfigs", [])
                                 if ac.get("natIP")),
                                None
                            ),
                        })
        except Exception:
            entry["compute_error"] = "AccessDenied"

        results["projects"].append(entry)
        print(f"  [*] {project_id}: {len(entry['enabled_apis'])} APIs, "
              f"{len(entry['compute_instances'])} instances")

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"gcp_projects_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"[+] {len(results['projects'])} projects → {out_path}")
    return 0
