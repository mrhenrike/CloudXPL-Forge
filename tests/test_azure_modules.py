"""Tests for Azure provider modules: MANIFEST validation and structure."""

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _azure_module_paths():
    from cloudxpl.core.dispatcher import MODULE_MAP
    for key, path in MODULE_MAP["azure"].items():
        yield key, path


class TestAzureManifests:
    @pytest.mark.parametrize("key,path", list(_azure_module_paths()))
    def test_manifest_present(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", None))
        assert manifest is not None, f"Azure/{key}: missing MANIFEST/INFO"

    @pytest.mark.parametrize("key,path", list(_azure_module_paths()))
    def test_has_run_function(self, key, path) -> None:
        mod = importlib.import_module(path)
        assert callable(getattr(mod, "run", None)), f"Azure/{key}: missing run()"

    @pytest.mark.parametrize("key,path", list(_azure_module_paths()))
    def test_manifest_has_identity(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        has_id = "capability_id" in manifest or "name" in manifest
        assert has_id, f"Azure/{key}: missing identity key"

    @pytest.mark.parametrize("key,path", list(_azure_module_paths()))
    def test_safety_class_valid(self, key, path) -> None:
        allowed = {"READ_ONLY", "ACTIVE", "DESTRUCTIVE", "EXPLOIT", "BRIDGE", "RECON"}
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        sc = manifest.get("safety_class")
        if sc is not None:
            assert sc in allowed, f"Azure/{key}: invalid safety_class '{sc}'"


class TestAzureModuleCounts:
    def test_entra_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        entra_keys = [k for k in MODULE_MAP["azure"] if "entra" in k]
        assert len(entra_keys) >= 3

    def test_blob_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        blob_keys = [k for k in MODULE_MAP["azure"] if "blob" in k]
        assert len(blob_keys) >= 2

    def test_cve_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        cve_keys = [k for k in MODULE_MAP["azure"] if "cve" in k.lower()]
        assert len(cve_keys) >= 3
