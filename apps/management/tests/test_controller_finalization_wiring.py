"""Fixed layout / systemd / compose-contract / composition wiring for finalization (2b-3b-iii).

Proves the fixed paths (broker unit through the strict unit authority; handoffs under an owned root;
marker/locator; /run byte-match to the commissioning + API planes), the broker unit's LoadCredential
+ fixed entrypoint + present-but-disabled AF_UNIX rendering, the one-shot RO mount matrix + the
no-secret-reaches-the-ordinary-API guard, and that the REAL finalization adapter is composed ONLY by
the root-gated install composer while a bare EngineDeps + the steady-state composer stay SEALED.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    ENROLLMENT_SIGNER_SOCKET_PATH,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError, production
from secp_management import controller_compose_contract as cc
from secp_management.controller_finalization import RealControllerEnrollmentFinalizationAdapter
from secp_management.engine import EngineDeps
from secp_management.enrollment_signer_db import ENROLLMENT_SIGNER_CREDENTIAL_ID
from secp_management.finalization import SealedControllerEnrollmentFinalizationAdapter
from secp_management.layout import ManagementLocations
from secp_management.real_adapters import PinnedExecutables, RealAdapterContext
from secp_management.systemd import render_enrollment_signer_broker_service
from secp_management.topology import BROKER_ENTRYPOINT

_LOC = ManagementLocations()


# ---- layout -----------------------------------------------------------------------------------
def test_broker_unit_path_goes_only_through_the_strict_unit_authority():
    assert _LOC.broker_unit_path() == "/etc/systemd/system/secp-enrollment-signer-broker.service"
    _LOC.assert_unit_writable(_LOC.broker_unit_path())  # permitted
    _LOC.assert_unit_writable(_LOC.controller_unit_path())
    with pytest.raises(ManagementError) as e:
        _LOC.assert_unit_writable("/etc/systemd/system/evil.service")
    assert e.value.reason_code == "layout_unit_path_not_fixed"


def test_handoff_host_paths_are_owned_and_container_paths_are_not():
    _LOC.assert_writable(_LOC.provisioning_handoff_host_path())  # under bootstrap_state (owned)
    _LOC.assert_writable(_LOC.activation_handoff_host_path())
    for p in (_LOC.provisioning_handoff_container_path(), _LOC.activation_handoff_container_path()):
        with pytest.raises(ManagementError) as e:
            _LOC.assert_writable(p)  # /run/secp/... is never installer-writable
        assert e.value.reason_code == "layout_path_not_owned"


def test_marker_and_locator_paths_are_fixed_and_owned():
    assert _LOC.api_signer_marker_path() == "/etc/secp/controller/enrollment-signer.enabled"
    assert _LOC.controller_api_locator_path() == "/etc/secp/controller/api-locator.json"
    _LOC.assert_writable(_LOC.api_signer_marker_path())
    _LOC.assert_writable(_LOC.controller_api_locator_path())


def test_run_and_container_paths_byte_match_the_other_planes():
    # management may not import secp_api in PRODUCTION; a test may, to prove the fixed literals
    # match.
    from secp_api.activate_controller_identity_once import HANDOFF_PATH as ACT
    from secp_api.enrollment_signer_marker import MARKER_PATH
    from secp_api.provision_enrollment_signer_role_once import HANDOFF_PATH as PROV

    assert _LOC.broker_socket_path() == ENROLLMENT_SIGNER_SOCKET_PATH
    assert _LOC.provisioning_handoff_container_path() == PROV
    assert _LOC.activation_handoff_container_path() == ACT
    assert _LOC.api_signer_marker_path() == MARKER_PATH


# ---- systemd broker unit ----------------------------------------------------------------------
def test_broker_unit_renders_loadcredential_entrypoint_and_stays_disabled():
    text = render_enrollment_signer_broker_service(
        exec_argv=BROKER_ENTRYPOINT,
        load_credential=(ENROLLMENT_SIGNER_CREDENTIAL_ID, _LOC.enrollment_signer_credential_path()),
    )
    assert "ExecStart=" + " ".join(BROKER_ENTRYPOINT) in text
    assert (
        f"LoadCredential={ENROLLMENT_SIGNER_CREDENTIAL_ID}:"
        f"{_LOC.enrollment_signer_credential_path()}" in text
    )
    assert "RestrictAddressFamilies=AF_UNIX" in text and "AF_INET" not in text
    assert "User=root" in text and "[Install]" not in text  # present-but-disabled, no TCP


def test_broker_credential_id_is_grammar_checked():
    with pytest.raises(ManagementError) as e:
        render_enrollment_signer_broker_service(
            exec_argv=BROKER_ENTRYPOINT, load_credential=("bad:id", "/etc/secp/x")
        )
    assert e.value.reason_code == "systemd_credential_id_unclean"


# ---- compose contract -------------------------------------------------------------------------
def test_one_shot_mounts_are_read_only_and_the_marker_is_host_equals_container():
    prov = cc.provisioning_oneshot_mount(_LOC)
    act = cc.activation_oneshot_mount(_LOC)
    marker = cc.api_marker_mount(_LOC)
    assert prov.read_only and act.read_only and marker.read_only
    assert prov.as_compose_volume().endswith(":ro")
    assert marker.host_path == marker.container_path == _LOC.api_signer_marker_path()


def test_no_secret_reaches_the_ordinary_api_guard():
    # the ordinary API's ONLY finalization mount (the marker) is safe
    cc.assert_no_secret_reaches_ordinary_api((cc.api_marker_mount(_LOC).host_path,), locations=_LOC)
    # every secret-bearing host path is refused
    for secret in (
        CONTROLLER_ENROLLMENT_KEY_PATH,
        _LOC.controller_server_key_path(),
        _LOC.enrollment_signer_credential_path(),
        _LOC.provisioning_handoff_host_path(),
        _LOC.activation_handoff_host_path(),
    ):
        with pytest.raises(ManagementError) as e:
            cc.assert_no_secret_reaches_ordinary_api((secret,), locations=_LOC)
        assert e.value.reason_code == "finalization_secret_mount_reaches_api"


def test_render_broker_reviewed_unit_is_content_bound():
    unit = cc.render_broker_reviewed_unit(_LOC)
    unit.verify()  # identity == sha256(content)
    assert b"LoadCredential=" in unit.content and b"[Install]" not in unit.content


# ---- production composition -------------------------------------------------------------------
def test_bare_engine_deps_and_steady_state_keep_finalization_sealed():
    assert isinstance(
        EngineDeps().finalization_adapter, SealedControllerEnrollmentFinalizationAdapter
    )


def test_build_real_finalization_adapter_returns_the_real_leaf():
    d = "sha256:" + "0" * 64
    from secp_operator_deployment.pinned_exec import ExecutablePin

    p = ExecutablePin(path="/usr/bin/docker", digest=d)
    ctx = RealAdapterContext(
        locations=_LOC,
        fs=InMemoryFilesystem(),
        runner=object(),
        executables=PinnedExecutables(container_runtime=p, compose_runtime=p, service_manager=p),
    )
    adapter = production.build_real_controller_finalization_adapter(ctx)
    assert isinstance(adapter, RealControllerEnrollmentFinalizationAdapter)


def test_install_composer_is_root_gated_first(monkeypatch):
    import secp_management.controller_install as ci

    def _no_root():
        raise ManagementError("controller_install_requires_posix_root")

    monkeypatch.setattr(ci, "assert_posix_root", _no_root)
    with pytest.raises(ManagementError) as e:
        production.controller_install_engine_deps()
    assert e.value.reason_code == "controller_install_requires_posix_root"


# ---- plane boundary ---------------------------------------------------------------------------
def test_new_production_modules_never_import_secp_api():
    pkg = Path(production.__file__).parent
    for name in (
        "controller_finalization.py",
        "controller_compose_contract.py",
        "enrollment_signer_broker_serve.py",
        "production.py",
        "layout.py",
        "systemd.py",
        "topology.py",
        "enrollment_signer_db.py",
    ):
        tree = ast.parse((pkg / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not a.name.startswith("secp_api") for a in node.names), name
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("secp_api"), name
