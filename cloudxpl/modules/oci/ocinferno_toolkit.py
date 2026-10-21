"""Wrapper stub for OCInferno OCI pentesting toolkit.

Source: CloudSec 2026 (Scott Weston)
License: verify
SRC-ID: SRC-1026
Category: OCI pentest, IAM ANTLR parser, Burp extension, recon, privesc

OCInferno is a comprehensive OCI pentesting toolkit presented at
CloudSec 2026. Includes an IAM ANTLR parser, Burp extension for
OCI API signing, recon framework, and OpenGraph privesc visualizer.
"""

from dataclasses import dataclass


@dataclass
class OCInfernoConfig:
    tenancy_ocid: str = ""
    user_ocid: str = ""
    region: str = "us-ashburn-1"
    key_file: str | None = None
    modules: list[str] | None = None
