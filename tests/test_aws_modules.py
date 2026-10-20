"""Tests for AWS provider modules: MANIFEST validation, run() with mocked boto3."""

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _aws_module_paths():
    """Yield (module_name, dotted_path) for every AWS module."""
    from cloudxpl.core.dispatcher import MODULE_MAP
    for key, path in MODULE_MAP["aws"].items():
        yield key, path


class TestAWSManifests:
    @pytest.mark.parametrize("key,path", list(_aws_module_paths()))
    def test_manifest_present(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", None))
        assert manifest is not None, f"AWS/{key}: missing MANIFEST/INFO"

    @pytest.mark.parametrize("key,path", list(_aws_module_paths()))
    def test_has_run_function(self, key, path) -> None:
        mod = importlib.import_module(path)
        assert callable(getattr(mod, "run", None)), f"AWS/{key}: missing run()"

    @pytest.mark.parametrize("key,path", list(_aws_module_paths()))
    def test_manifest_has_capability_id(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        has_id = "capability_id" in manifest or "name" in manifest
        assert has_id, f"AWS/{key}: missing identity key"

    @pytest.mark.parametrize("key,path", list(_aws_module_paths()))
    def test_manifest_has_mitre(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        mitre = manifest.get("mitre", manifest.get("mitre_attack", []))
        assert isinstance(mitre, list), f"AWS/{key}: mitre must be a list"


class TestAWSRunNoBoto3:
    """Test that modules return 1 when boto3 is unavailable."""

    def _args(self, module: str = "s3-enum") -> SimpleNamespace:
        return SimpleNamespace(
            command="aws", module=module,
            region="us-east-1", profile=None,
            role_arn=None, target=None, output=".",
            json=False, verbose=False,
        )

    def test_s3_enum_no_boto3(self) -> None:
        mod = importlib.import_module("cloudxpl.modules.aws.s3_enum")
        with patch.dict(sys.modules, {"boto3": None}):
            with patch("builtins.__import__", side_effect=_selective_import_error("boto3")):
                ret = mod.run(self._args("s3-enum"))
        assert ret == 1

    def test_iam_enum_no_boto3(self) -> None:
        mod = importlib.import_module("cloudxpl.modules.aws.iam_enum")
        with patch.dict(sys.modules, {"boto3": None}):
            with patch("builtins.__import__", side_effect=_selective_import_error("boto3")):
                ret = mod.run(self._args("iam-enum"))
        assert ret == 1

    def test_ec2_enum_no_boto3(self) -> None:
        mod = importlib.import_module("cloudxpl.modules.aws.ec2_enum")
        with patch.dict(sys.modules, {"boto3": None}):
            with patch("builtins.__import__", side_effect=_selective_import_error("boto3")):
                ret = mod.run(self._args("ec2-enum"))
        assert ret == 1


def _selective_import_error(blocked: str):
    """Return a side_effect that blocks a specific import."""
    _real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def _import(name, *args, **kwargs):
        if name == blocked:
            raise ImportError(f"No module named '{blocked}'")
        return _real_import(name, *args, **kwargs)
    return _import
