"""Wrapper stub for CloudBrute multi-cloud infrastructure discovery.

Source: https://github.com/0xsha/CloudBrute
License: verify
SRC-ID: SRC-1025
Category: Multi-cloud discovery, recon, bug bounty, red team, Alibaba

CloudBrute discovers cloud infrastructure across multiple providers
including AWS, Azure, GCP, and Alibaba Cloud. Designed for bug
bounty and red team recon engagements.
"""

from dataclasses import dataclass


@dataclass
class CloudBruteConfig:
    target: str = ""
    providers: list[str] | None = None
    wordlist: str | None = None
    threads: int = 10
    timeout: int = 10
