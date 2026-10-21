"""Wrapper stub for Pacu AWS exploitation framework.

Source: https://github.com/RhinoSecurityLabs/pacu
License: BSD-3-Clause
SRC-ID: SRC-1032
Category: AWS exploitation, Rhino Security Labs, IAM, EC2, S3, Lambda

Pacu is an AWS exploitation framework by Rhino Security Labs.
Provides comprehensive modules for AWS security assessment
including IAM, EC2, S3, Lambda, and privilege escalation.
"""

from dataclasses import dataclass


@dataclass
class PacuConfig:
    profile: str = ""
    region: str | None = None
    modules: list[str] | None = None
    session_name: str = "xpl_pacu"
