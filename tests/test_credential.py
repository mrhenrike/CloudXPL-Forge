"""Tests for cloudxpl.core.credential module."""


import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cloudxpl.core.credential import CloudCredential


def test_credential_create():
    cred = CloudCredential(provider="aws", identity="arn:aws:iam::123:user/test")
    assert cred.provider == "aws"
    assert cred.identity == "arn:aws:iam::123:user/test"


def test_masked_secret_none():
    cred = CloudCredential(provider="gcp", identity="sa@project.iam")
    assert cred.masked_secret == "(none)"


def test_masked_secret_present():
    cred = CloudCredential(provider="aws", identity="test")
    cred.secret_key = "ABCDEFGHIJKLMNOP"
    masked = cred.masked_secret
    assert "****" in masked
    assert masked.startswith("ABCD")
    assert masked.endswith("MNOP")


def test_to_dict_excludes_secret():
    cred = CloudCredential(provider="azure", identity="sp@tenant")
    cred.secret_key = "supersecret12345"
    d = cred.to_dict()
    assert "secret_key" not in d
    assert "provider" in d
    assert d["provider"] == "azure"


def test_to_dict_fields():
    cred = CloudCredential(
        provider="oci",
        identity="ocid1.user",
        region="us-ashburn-1",
        subscription_id="sub-123",
    )
    d = cred.to_dict()
    assert d["region"] == "us-ashburn-1"
    assert d["subscription_id"] == "sub-123"


def test_credential_type_default():
    cred = CloudCredential(provider="aws", identity="test")
    assert cred.credential_type == "unknown"


def test_extra_field():
    cred = CloudCredential(provider="aws", identity="test", extra={"role": "admin"})
    assert cred.extra["role"] == "admin"


def test_token_field():
    cred = CloudCredential(provider="azure", identity="test", token="eyJ...")
    assert cred.token == "eyJ..."


def test_profile_field():
    cred = CloudCredential(provider="aws", identity="test", profile="production")
    assert cred.profile == "production"
