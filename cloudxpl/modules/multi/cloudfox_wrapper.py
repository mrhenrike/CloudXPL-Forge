"""Wrapper stub for CloudFox cloud enumeration tool.

Source: https://github.com/BishopFox/cloudfox
License: MIT
SRC-ID: SRC-1031
Category: Cloud enumeration, offensive, AWS, Azure, GCP, Bishop Fox

CloudFox is an offensive cloud enumeration tool by Bishop Fox.
Automates situational awareness for penetration testers and
red teamers in AWS, Azure, and GCP environments.
"""

from dataclasses import dataclass


@dataclass
class CloudFoxConfig:
    provider: str = "aws"
    profile: str = ""
    region: str | None = None
    output_format: str = "table"
    commands: list[str] | None = None
