"""AWS GuardDuty evasion analysis — detector status, suppression rules, finding types."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.guardduty_bypass.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.001"],
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

    print(f"[*] AWS GuardDuty Evasion Analysis (region: {args.region})")
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed", file=sys.stderr); return 1
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    gd = session.client("guardduty")
    results = {"detectors": [], "findings_summary": [], "evasion_notes": []}
    try:
        detector_ids = gd.list_detectors()["DetectorIds"]
        for did in detector_ids:
            det = gd.get_detector(DetectorId=did)
            info = {"detector_id": did, "status": det["Status"], "data_sources": {}}
            for src in ["S3Logs", "CloudTrail", "DNSLogs", "FlowLogs", "Kubernetes"]:
                ds = det.get("DataSources", {}).get(src, {})
                if ds:
                    info["data_sources"][src] = ds.get("Status", "UNKNOWN")
            results["detectors"].append(info)
            if det["Status"] != "ENABLED":
                print(f"  [!] Detector {did}: NOT ENABLED")
                results["evasion_notes"].append(f"Detector {did} is {det['Status']}")
            else:
                print(f"  [+] Detector {did}: enabled")
                for src, status in info["data_sources"].items():
                    if status != "ENABLED":
                        print(f"    [!] {src}: {status}")
                        results["evasion_notes"].append(f"{src} not enabled on {did}")
            try:
                filters = gd.list_filters(DetectorId=did)
                if filters.get("FilterNames"):
                    results["evasion_notes"].append(f"{len(filters['FilterNames'])} suppression filters on {did}")
            except Exception: pass
    except Exception as exc:
        print(f"[-] GuardDuty enum failed: {exc}"); return 1
    _save(args, "aws_guardduty_bypass", results)
    print(f"[+] {len(results['detectors'])} detectors, {len(results['evasion_notes'])} evasion notes")
    return 0
