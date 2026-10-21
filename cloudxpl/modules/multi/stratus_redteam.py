"""Wrapper stub for Stratus Red Team cloud adversary emulation.

Source: https://github.com/DataDog/stratus-red-team
License: Apache-2.0
SRC-ID: SRC-1033
Category: Adversary emulation, cloud, AWS, Azure, GCP, K8s, DataDog

Stratus Red Team is a granular adversary emulation tool for cloud
environments by DataDog. Provides atomic attack techniques mapped
to MITRE ATT&CK for AWS, Azure, GCP, and Kubernetes.
"""

from dataclasses import dataclass


@dataclass
class StratusRedTeamConfig:
    provider: str = "aws"
    technique: str = ""
    warm_up: bool = True
    cleanup: bool = True
