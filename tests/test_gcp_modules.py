"""Tests for GCP provider modules: MANIFEST validation and structure."""

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _gcp_module_paths():
    from cloudxpl.core.dispatcher import MODULE_MAP
    for key, path in MODULE_MAP["gcp"].items():
        yield key, path


class TestGCPManifests:
    @pytest.mark.parametrize("key,path", list(_gcp_module_paths()))
    def test_manifest_present(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", None))
        assert manifest is not None, f"GCP/{key}: missing MANIFEST/INFO"

    @pytest.mark.parametrize("key,path", list(_gcp_module_paths()))
    def test_has_run_function(self, key, path) -> None:
        mod = importlib.import_module(path)
        assert callable(getattr(mod, "run", None)), f"GCP/{key}: missing run()"

    @pytest.mark.parametrize("key,path", list(_gcp_module_paths()))
    def test_manifest_has_identity(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        has_id = "capability_id" in manifest or "name" in manifest
        assert has_id, f"GCP/{key}: missing identity key"


class TestGCPModuleCounts:
    def test_bucket_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        bucket_keys = [k for k in MODULE_MAP["gcp"] if "bucket" in k]
        assert len(bucket_keys) >= 3

    def test_gke_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        gke_keys = [k for k in MODULE_MAP["gcp"] if "gke" in k]
        assert len(gke_keys) >= 2

    def test_iam_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        iam_keys = [k for k in MODULE_MAP["gcp"] if "iam" in k]
        assert len(iam_keys) >= 1

    def test_cve_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        cve_keys = [k for k in MODULE_MAP["gcp"] if "cve" in k.lower()]
        assert len(cve_keys) >= 3
