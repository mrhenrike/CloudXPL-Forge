"""Tests for Kubernetes modules: MANIFEST validation and structure."""

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _k8s_module_paths():
    from cloudxpl.core.dispatcher import MODULE_MAP
    for key, path in MODULE_MAP["k8s"].items():
        yield key, path


class TestK8SManifests:
    @pytest.mark.parametrize("key,path", list(_k8s_module_paths()))
    def test_manifest_present(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", None))
        assert manifest is not None, f"K8S/{key}: missing MANIFEST/INFO"

    @pytest.mark.parametrize("key,path", list(_k8s_module_paths()))
    def test_has_run_function(self, key, path) -> None:
        mod = importlib.import_module(path)
        assert callable(getattr(mod, "run", None)), f"K8S/{key}: missing run()"

    @pytest.mark.parametrize("key,path", list(_k8s_module_paths()))
    def test_manifest_has_identity(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        has_id = "capability_id" in manifest or "name" in manifest
        assert has_id, f"K8S/{key}: missing identity key"


class TestK8SModuleCounts:
    def test_rbac_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        rbac_keys = [k for k in MODULE_MAP["k8s"] if "rbac" in k]
        assert len(rbac_keys) >= 2

    def test_container_escape_exists(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        assert "container-escape" in MODULE_MAP["k8s"]

    def test_cve_modules_exist(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        cve_keys = [k for k in MODULE_MAP["k8s"] if "cve" in k.lower()]
        assert len(cve_keys) >= 5

    def test_secret_dump_exists(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        assert "secret-dump" in MODULE_MAP["k8s"]

    def test_pod_enum_exists(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        assert "pod-enum" in MODULE_MAP["k8s"]

    def test_sa_token_theft_exists(self) -> None:
        from cloudxpl.core.dispatcher import MODULE_MAP
        assert "sa-token-theft" in MODULE_MAP["k8s"]
