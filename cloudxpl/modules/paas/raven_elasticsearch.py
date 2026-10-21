"""Wrapper stub for RAVEN Elasticsearch offensive tool.

Source: SpiderLabs/LevelBlue
License: verify
SRC-ID: SRC-1028
Category: Elasticsearch, offensive, CVE, SpiderLabs

RAVEN is an offensive tool for Elasticsearch by SpiderLabs/LevelBlue.
Provides 19 modules covering 8 tracked CVEs for Elasticsearch
security assessment and exploitation.
"""

from dataclasses import dataclass


@dataclass
class RavenElasticsearchConfig:
    target: str = ""
    port: int = 9200
    use_ssl: bool = False
    modules: list[str] | None = None
    timeout: int = 10
