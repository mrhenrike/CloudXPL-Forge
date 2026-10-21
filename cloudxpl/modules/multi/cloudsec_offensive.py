"""Wrapper stub for CloudSec offensive cloud security toolkit.

Source: https://github.com/eshlomo1/CloudSec
License: verify
SRC-ID: SRC-676
Category: Offensive cloud security, Azure, Entra ID, AWS, M365, red team

CloudSec provides offensive cloud security tools focused on
Azure, Entra ID, AWS, and M365. Designed for red team engagements
and cloud security assessments.
"""

from dataclasses import dataclass


@dataclass
class CloudSecConfig:
    provider: str = "azure"
    target_tenant: str = ""
    modules: list[str] | None = None
    output_dir: str = "cloudsec_output"
