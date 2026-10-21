"""Wrapper stub for CloudToolKit multi-cloud assessment framework.

Source: https://github.com/404tk/cloudtoolkit
License: verify
SRC-ID: SRC-1024
Category: Multi-cloud, OCI, AWS, Alibaba, ECS, OSS, RAM, RDS, DNS

CloudToolKit is a multi-cloud assessment framework supporting
OCI, AWS, and Alibaba Cloud. Provides ECS/OSS/RAM/RDS/DNS
enumeration, backdoor user creation, bucket dump, and command
execution capabilities.
"""

from dataclasses import dataclass


@dataclass
class CloudToolKitConfig:
    provider: str = "aws"
    access_key: str = ""
    secret_key: str = ""
    region: str = ""
    modules: list[str] | None = None
