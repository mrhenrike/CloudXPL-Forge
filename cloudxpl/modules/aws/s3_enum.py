"""AWS S3 bucket enumeration — list buckets, check ACLs, detect public access."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.s3_enum.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": ["aws_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1530"],
}


def run(args: Any) -> int:
    print(f"[*] AWS S3 Bucket Enumeration (region: {args.region})")

    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr)
        return 1

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as exc:
        print(f"[-] list_buckets failed: {exc}", file=sys.stderr)
        return 1

    print(f"[+] {len(buckets)} buckets found")
    results = []

    for bucket in buckets:
        name = bucket["BucketName"]
        entry: dict[str, Any] = {"name": name, "created": bucket["CreationDate"].isoformat()}

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public_grants = [
                g for g in acl.get("Grants", [])
                if g.get("Grantee", {}).get("URI", "").endswith("AllUsers")
                or g.get("Grantee", {}).get("URI", "").endswith("AuthenticatedUsers")
            ]
            entry["public_acl"] = bool(public_grants)
            if public_grants:
                entry["public_grants"] = [g["Permission"] for g in public_grants]
                print(f"  [!] {name}: PUBLIC ACL — {', '.join(entry['public_grants'])}")
        except Exception:
            entry["acl_error"] = "AccessDenied"

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            entry["public_access_block"] = pab
            all_blocked = all(pab.values())
            if not all_blocked:
                print(f"  [!] {name}: Public access block INCOMPLETE")
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            entry["public_access_block"] = None
            print(f"  [!] {name}: NO public access block configured")
        except Exception:
            pass

        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            entry["encryption"] = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except Exception:
            entry["encryption"] = None

        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            entry["versioning"] = versioning.get("Status", "Disabled")
        except Exception:
            pass

        results.append(entry)

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"aws_s3_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    public_count = sum(1 for r in results if r.get("public_acl"))
    print(f"[+] {public_count} public buckets, {len(results)} total → {out_path}")
    return 0
