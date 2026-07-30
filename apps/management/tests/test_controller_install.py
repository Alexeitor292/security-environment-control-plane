"""Validated, root-gated controller-install options (SECP-PR5H-B2, commit 2b-2)."""

from __future__ import annotations

import os

import pytest
from secp_management import ManagementError
from secp_management.controller_install import (
    ControllerInstallError,
    ControllerInstallOptions,
    assert_posix_root,
    build_controller_install_options,
)


def test_valid_options_round_trip():
    opts = build_controller_install_options(
        public_origin="https://controller.secp.example:8443", tls_mode="generated_local_ca"
    )
    assert opts.tls_mode == "generated_local_ca"
    assert opts.safe_summary() == {
        "canonical_origin": "https://controller.secp.example:8443",
        "tls_mode": "generated_local_ca",
    }
    assert "redacted-origin" in repr(opts) and "controller.secp.example" not in repr(opts)


@pytest.mark.parametrize(
    "origin,reason",
    [
        ("http://controller.secp.example", "controller_install_origin_invalid"),  # not https
        ("https://user@controller.example", "controller_install_origin_invalid"),  # userinfo
        ("https://controller.example/path", "controller_install_origin_invalid"),  # path
        ("https://controller.example?q=1", "controller_install_origin_invalid"),  # query
        ("https://CONTROLLER.example", "controller_install_origin_invalid"),  # uppercase host
        ("https://controller.example\n", "controller_install_origin_invalid"),  # control char
    ],
)
def test_bad_origin_is_refused(origin, reason):
    with pytest.raises(ManagementError) as e:
        build_controller_install_options(public_origin=origin, tls_mode="generated_local_ca")
    assert e.value.reason_code == reason


def test_unknown_tls_mode_is_refused():
    with pytest.raises(ControllerInstallError) as e:
        build_controller_install_options(
            public_origin="https://controller.example", tls_mode="acme_http_01"
        )
    assert e.value.reason_code == "controller_install_tls_mode_invalid"


def test_missing_inputs_are_refused():
    with pytest.raises(ManagementError) as e:
        build_controller_install_options(public_origin=None, tls_mode="generated_local_ca")
    assert e.value.reason_code == "controller_install_origin_required"
    with pytest.raises(ManagementError) as e2:
        build_controller_install_options(public_origin="https://c.example", tls_mode=None)
    assert e2.value.reason_code == "controller_install_tls_mode_required"


def test_imported_mode_is_accepted():
    opts = ControllerInstallOptions(
        canonical_origin="https://c.example", tls_mode="imported_enterprise_tls"
    )
    assert opts.tls_mode == "imported_enterprise_tls"


def test_root_gate_is_enforced():
    if os.name != "posix":
        with pytest.raises(ManagementError) as e:
            assert_posix_root()
        assert e.value.reason_code == "controller_install_unsupported_platform"
    else:
        # on POSIX CI the test process is non-root; the gate must refuse (never a silent pass)
        euid = os.geteuid()  # type: ignore[attr-defined]
        if euid != 0:
            with pytest.raises(ManagementError) as e:
                assert_posix_root()
            assert e.value.reason_code == "controller_install_requires_root"
        else:
            assert_posix_root()  # root: passes
