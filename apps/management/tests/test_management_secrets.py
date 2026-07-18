"""No secret leakage + strict evidence + systemd hardening + CLI surface (SECP-PR5E §13/§14)."""

from __future__ import annotations

import json

import pytest
from _mgmt_support import (
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.cli import build_parser, run

_SECRETS = ("password", "vault:", "openbao:", "BEGIN PRIVATE KEY", "x-vault-token", "secret_key")


def _worker_deps():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    return deps_for(fs, fresh_worker_world(), trust), bd, fs


def _assert_no_secret(payload: dict) -> None:
    text = json.dumps(payload).lower()
    for token in _SECRETS:
        assert token.lower() not in text


def test_no_secret_in_any_json_report():
    deps, bd, _fs = _worker_deps()
    for argv in (
        ["release", "verify", "--bundle", bd],
        ["host", "inspect"],
        ["bootstrap", "worker", "--bundle", bd],
        ["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"],
        ["status", "worker"],
        ["evidence", "worker"],
        ["rollback", "worker"],
    ):
        _code, rep = run(argv, deps)
        _assert_no_secret(rep)


def test_evidence_is_strict_and_nonsecret():
    deps, bd, fs = _worker_deps()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    raw = fs.safe_read(
        "/var/lib/secp/bootstrap/worker-evidence.json", max_bytes=1 << 18, expected_uid=0
    )
    text = raw.decode().lower()
    for token in _SECRETS:
        assert token.lower() not in text
    from secp_management.evidence import evidence_from_dict

    doc = json.loads(raw)
    with pytest.raises(ManagementError):
        evidence_from_dict({**doc, "api_key": "x"})


def test_evidence_effect_flags_must_be_false():
    from secp_management.evidence import evidence_from_dict

    deps, bd, fs = _worker_deps()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    raw = fs.safe_read(
        "/var/lib/secp/bootstrap/worker-evidence.json", max_bytes=1 << 18, expected_uid=0
    )
    doc = json.loads(raw)
    with pytest.raises(ManagementError) as exc:
        evidence_from_dict({**doc, "proxmox_contacted": True})
    assert exc.value.reason_code == "evidence_effect_flag_invalid"


def test_evidence_seal_states_enforced():
    from secp_management.evidence import evidence_from_dict

    deps, bd, fs = _worker_deps()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    raw = fs.safe_read(
        "/var/lib/secp/bootstrap/worker-evidence.json", max_bytes=1 << 18, expected_uid=0
    )
    doc = json.loads(raw)
    with pytest.raises(ManagementError) as exc:
        evidence_from_dict({**doc, "operator_activation_sealed": False})
    assert exc.value.reason_code == "evidence_operator_activation_seal_invalid"


def test_status_independently_revalidates_evidence():
    # status re-observes host state; it never trusts stored booleans alone. A good install whose
    # LATER observation shows the operator running must fail closed.
    deps, bd, fs = _worker_deps()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    bad = deps_for(fs, prepared_worker_world(operator_running=True), deps.trust_root)
    _code, st = run(["status", "worker"], bad)
    assert st["ok"] is False


# --- systemd hardening ---


def test_operator_unit_has_no_install_section():
    from secp_management.systemd import render_operator_unit_disabled

    unit = render_operator_unit_disabled(
        exec_argv=("/opt/secp/operator/bin/entrypoint",),
        user="secp-operator",
        group="secp-operator",
    )
    assert "[Install]" not in unit and "WantedBy" not in unit
    assert "NoNewPrivileges=yes" in unit and "ProtectSystem=strict" in unit
    assert "CapabilityBoundingSet=" in unit


def test_service_unit_rejects_shell_and_env_entrypoints():
    from secp_management.systemd import render_service_unit

    for bad in (("/bin/sh", "-c", "x"), ("/usr/bin/env", "python")):
        with pytest.raises(ManagementError):
            render_service_unit(
                description="x",
                exec_argv=bad,
                user="u",
                group="g",
                read_write_paths=(),
                wanted_by="multi-user.target",
            )


def test_service_unit_requires_absolute_exec():
    from secp_management.systemd import render_service_unit

    with pytest.raises(ManagementError):
        render_service_unit(
            description="x",
            exec_argv=("python", "-m", "x"),
            user="u",
            group="g",
            read_write_paths=(),
            wanted_by=None,
        )


# --- CLI surface ---


def test_no_forbidden_subcommands():
    import argparse
    import contextlib
    import io

    parser = build_parser()
    for forbidden in ("activate", "apply", "destroy", "proxmox", "ssh", "exec", "shell"):
        with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
            parser.parse_args([forbidden])
    assert isinstance(parser, argparse.ArgumentParser)


def test_json_and_human_execute_same_engine():
    deps, bd, _fs = _worker_deps()
    code_a, payload_a = run(["status", "worker"], deps)
    code_b, payload_b = run(["--json", "status", "worker"], deps)
    assert code_a == code_b and payload_a == payload_b
