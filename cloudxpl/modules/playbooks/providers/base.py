"""
Provider — Abstract base classes
==================================
Define contratos para integração com firewalls e EDR/XDR.
Cada vendor implementa sua própria classe concreta.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallProvider(ABC):
    """Abstract base for any firewall vendor."""

    @abstractmethod
    def status(self) -> dict:
        ...

    @abstractmethod
    def block_ip(self, ip: str, comment: str = "") -> str:
        ...

    @abstractmethod
    def unblock_ip(self, ip: str) -> str:
        ...

    @abstractmethod
    def block_domain(self, domain: str) -> str:
        ...

    @abstractmethod
    def block_url(self, url: str) -> str:
        ...

    @abstractmethod
    def isolate_host(self, ip: str, reason: str = "") -> str:
        ...

    @abstractmethod
    def deisolate_host(self, ip: str) -> str:
        ...

    @abstractmethod
    def list_iocs(self) -> dict:
        ...

    @abstractmethod
    def close(self) -> None:
        ...


class EDRProvider(ABC):
    """Abstract base for any EDR/XDR vendor."""

    @abstractmethod
    def status(self) -> dict:
        ...

    @abstractmethod
    def list_agents(self, infected_only: bool = False) -> list:
        ...

    @abstractmethod
    def isolate_agent(self, agent_id: str, reason: str = "") -> dict:
        ...

    @abstractmethod
    def deisolate_agent(self, agent_id: str) -> dict:
        ...

    @abstractmethod
    def scan_agent(self, agent_id: str) -> dict:
        ...

    @abstractmethod
    def list_threats(self, unresolved_only: bool = True) -> list:
        ...

    @abstractmethod
    def blacklist_hash(self, sha1: str, description: str = "") -> dict:
        ...

    @abstractmethod
    def collect_iocs(self) -> dict:
        ...
