"""Wrapper stub for pOliCI OCI IAM policy parser.

Source: XM Cyber / DEF CON 34
License: open-source; verify
SRC-ID: SRC-1027
Category: OCI IAM, policy parser, privilege escalation, audit

pOliCI is an OCI IAM policy parser that calculates effective
permissions per principal. Identifies over-privileged identities
and potential privilege escalation paths. Presented at DEF CON 34.
"""

from dataclasses import dataclass


@dataclass
class POliCIConfig:
    tenancy_ocid: str = ""
    compartment_ocid: str | None = None
    output_format: str = "json"
    check_privesc: bool = True
