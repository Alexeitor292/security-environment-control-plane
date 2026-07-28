"""Fixed broker entrypoint (SECP-PR5H-B2, 2b-3b-iii): no-arg composition + fail-closed startup.

Hermetic: the real ``build_production_broker`` refuses off-POSIX, so composition + fail-closed paths
are exercised through the reviewed seams (never a live socket / DB / root). Proves the entrypoint
selects nothing, composes the existing broker behind the fixed non-root peer allowlist on the fixed
socket-group gid, and fails closed with a bounded reason on any startup fault.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from secp_commissioning.enrollment_signer_role import EnrollmentSignerRoleError
from secp_management import ManagementError
from secp_management import enrollment_signer_broker_serve as serve
from secp_management.topology import API_RUNTIME_GID, API_RUNTIME_UID


class _Listener:
    def getsockname(self):
        return None

    def close(self):
        pass


def _ok_seams(captured):
    def broker_builder(*, engine, allowed_peers):
        captured["engine"] = engine
        captured["allowed_peers"] = allowed_peers
        return "broker"

    def socket_binder(*, socket_group_gid):
        captured["gid"] = socket_group_gid
        return _Listener()

    def serve_fn(broker, listener):
        captured["served"] = (broker, listener)

    return dict(
        require_posix_root=lambda: None,
        load_password=lambda: "a" * 64,
        engine_builder=lambda pw: ("engine", pw),
        broker_builder=broker_builder,
        socket_binder=socket_binder,
        serve=serve_fn,
    )


def test_happy_path_composes_the_fixed_broker_and_serves():
    captured: dict = {}
    code = serve.run_broker(**_ok_seams(captured))
    assert code == serve.EXIT_OK
    assert captured["allowed_peers"] == ((API_RUNTIME_UID, API_RUNTIME_GID),)
    assert captured["gid"] == API_RUNTIME_GID
    assert captured["engine"] == ("engine", "a" * 64)  # dedicated-role engine from the credential
    assert captured["served"][0] == "broker"


def test_fails_closed_off_posix_or_non_root(capsys):
    def gate():
        raise ManagementError("enrollment_signer_broker_requires_root")

    code = serve.run_broker(**{**_ok_seams({}), "require_posix_root": gate})
    assert code == serve.EXIT_FAIL_CLOSED
    assert capsys.readouterr().err.strip() == "enrollment_signer_broker_requires_root"


def test_fails_closed_when_the_credential_is_unavailable(capsys):
    def load():
        raise EnrollmentSignerRoleError("enrollment_signer_credential_unavailable")

    code = serve.run_broker(**{**_ok_seams({}), "load_password": load})
    assert code == serve.EXIT_FAIL_CLOSED
    assert capsys.readouterr().err.strip() == "enrollment_signer_credential_unavailable"


def test_unexpected_startup_fault_is_a_bounded_fail_closed(capsys):
    def binder(*, socket_group_gid):
        raise RuntimeError("boom with secret /path/xyz")

    code = serve.run_broker(**{**_ok_seams({}), "socket_binder": binder})
    assert code == serve.EXIT_FAIL_CLOSED
    err = capsys.readouterr().err.strip()
    assert err == "enrollment_signer_broker_startup_failed" and "secret" not in err


def test_main_accepts_no_argument():
    with pytest.raises(SystemExit):
        serve.main(["--socket", "/tmp/x"])  # any argument is refused by argparse


def test_entrypoint_module_never_imports_secp_api():
    src = Path(serve.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("secp_api") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secp_api")
