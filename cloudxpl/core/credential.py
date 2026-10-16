"""Cloud credential management — provider-agnostic credential handling."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CloudCredential:
    provider: str
    identity: str
    credential_type: str = "unknown"
    access_key: str | None = None
    secret_key: str | None = None
    token: str | None = None
    profile: str | None = None
    region: str | None = None
    project_id: str | None = None
    subscription_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def masked_secret(self) -> str:
        if self.secret_key:
            return self.secret_key[:4] + "****" + self.secret_key[-4:]
        return "(none)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "identity": self.identity,
            "credential_type": self.credential_type,
            "region": self.region,
            "project_id": self.project_id,
            "subscription_id": self.subscription_id,
        }
