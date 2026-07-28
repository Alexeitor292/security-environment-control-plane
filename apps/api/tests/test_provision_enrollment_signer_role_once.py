"""Fixed API-plane enrollment-signer role provisioning one-shot — validation + posture (2b-3b).

Covers the handoff validation + the non-PostgreSQL refusal offline. The REAL create/rotate + the
least-privilege posture proof against a live database is the PostgreSQL zero-skip fence (2b-3d).
"""

from __future__ import annotations

import json

import pytest
from secp_api import provision_enrollment_signer_role_once as mod
from secp_commissioning.canonical import canonical_json
from secp_commissioning.enrollment_signer_role import (
    generate_signer_db_password,
    scram_sha256_verifier,
)
from sqlalchemy import create_engine


def _sqlite():
    return create_engine("sqlite+pysqlite:///:memory:", future=True)


def _handoff_bytes(*, operation_id="op-1", verifier=None, **over) -> bytes:
    env = {
        "schema": mod._HANDOFF_SCHEMA,
        "operation_id": operation_id,
        "scram_verifier": verifier or scram_sha256_verifier(generate_signer_db_password()),
        "created_at": "2026-07-28T00:00:00Z",
    }
    env.update(over)
    return canonical_json(env).encode()


def _write(tmp_path, raw: bytes) -> str:
    p = tmp_path / "enrollment-signer-role-provision.json"
    p.write_bytes(raw)
    return str(p)


def test_valid_handoff_refuses_on_non_postgres(tmp_path):
    code, payload = mod.run_provision(
        handoff_path=_write(tmp_path, _handoff_bytes()), engine=_sqlite()
    )
    assert code == mod.EXIT_UNSUPPORTED
    assert payload["reason_code"] == "provision_role_requires_postgresql"


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda raw: json.dumps(json.loads(raw), indent=2).encode(),
            "provision_handoff_noncanonical",
        ),
        (
            lambda raw: canonical_json({**json.loads(raw), "schema": "other/v9"}).encode(),
            "provision_handoff_schema_unknown",
        ),
        (
            lambda raw: canonical_json(
                {**json.loads(raw), "scram_verifier": "not-a-verifier"}
            ).encode(),
            "provision_handoff_verifier_invalid",
        ),
        (
            lambda raw: canonical_json({**json.loads(raw), "extra": 1}).encode(),
            "provision_handoff_malformed",
        ),
        (lambda raw: b"not json", "provision_handoff_not_json"),
    ],
)
def test_malformed_handoff_is_refused(tmp_path, mutate, reason):
    code, payload = mod.run_provision(
        handoff_path=_write(tmp_path, mutate(_handoff_bytes())), engine=_sqlite()
    )
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == reason


def test_missing_handoff_is_refused(tmp_path):
    code, payload = mod.run_provision(handoff_path=str(tmp_path / "absent.json"), engine=_sqlite())
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == "provision_handoff_unreadable"


def test_injection_shaped_verifier_is_refused(tmp_path):
    bad = "SCRAM-SHA-256$4096:AAAA$BBBB:CCCC'; DROP ROLE postgres; --"
    code, payload = mod.run_provision(
        handoff_path=_write(tmp_path, _handoff_bytes(verifier=bad)), engine=_sqlite()
    )
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == "provision_handoff_verifier_invalid"
