"""GCP Cloud Storage bucket enumeration — list buckets, IAM, public access."""


import json
import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.gcp.bucket_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["gcp_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1530"],
}


def run(args: Any) -> int:
    project = args.project_id
    print(f"[*] GCP Bucket Enumeration (project: {project})")

    try:
        from google.cloud import storage
    except ImportError:
        print("[!] google-cloud-storage not installed", file=sys.stderr)
        return 1

    client = storage.Client(project=project)

    try:
        buckets = list(client.list_buckets())
    except Exception as exc:
        print(f"[-] list_buckets failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] {len(buckets)} buckets")
    results = []

    for bucket in buckets:
        entry: dict[str, Any] = {
            "name": bucket.name,
            "location": bucket.location,
            "storage_class": bucket.storage_class,
            "versioning": bucket.versioning_enabled,
            "uniform_access": bucket.iam_configuration.uniform_bucket_level_access_enabled,
            "public_access_prevention": getattr(
                bucket.iam_configuration, "public_access_prevention", "inherited"
            ),
        }

        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            public_bindings = []
            for binding in policy.bindings:
                public_members = [
                    m for m in binding["members"]
                    if m in ("allUsers", "allAuthenticatedUsers")
                ]
                if public_members:
                    public_bindings.append({
                        "role": binding["role"],
                        "members": public_members,
                    })
            entry["public_iam"] = public_bindings
            if public_bindings:
                print(f"  [!] {bucket.name}: PUBLIC IAM bindings found")
        except Exception:
            entry["iam_error"] = "AccessDenied"

        results.append(entry)

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"gcp_buckets_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    public_count = sum(1 for r in results if r.get("public_iam"))
    print(f"[+] {public_count} public buckets, {len(results)} total → {out_path}")
    return 0
