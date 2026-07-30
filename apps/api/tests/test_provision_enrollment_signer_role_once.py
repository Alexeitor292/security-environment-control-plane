"""Enrollment-signer role provisioning one-shot — validation + non-PG refusal (2b-3b C2/C4).

Covers the handoff validation (via an injected reader seam — production uses the POSIX-hardened
reader) + the non-PostgreSQL refusal offline. The REAL create/rotate, hostile-role repair, and the
live least-privilege posture proof against a database are the PostgreSQL zero-skip fence.
"""

from __future__ import annotations

import pytest
from secp_api import provision_enrollment_signer_role_once as mod
from secp_commissioning.canonical import canonical_json
from secp_commissioning.enrollment_signer_role import (
    generate_signer_db_password,
    scram_sha256_verifier,
)
from secp_commissioning.hardened_handoff import HardenedHandoffError
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


def _run(raw: bytes, *, engine=None):
    return mod.run_provision(read_handoff=lambda: raw, engine=engine or _sqlite())


def test_valid_handoff_refuses_on_non_postgres():
    code, payload = _run(_handoff_bytes())
    assert code == mod.EXIT_UNSUPPORTED
    assert payload["reason_code"] == "provision_role_requires_postgresql"


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda raw: __import__("json").dumps(__import__("json").loads(raw), indent=2).encode(),
            "provision_handoff_noncanonical",
        ),
        (
            lambda raw: canonical_json(
                {**__import__("json").loads(raw), "schema": "other/v9"}
            ).encode(),
            "provision_handoff_schema_unknown",
        ),
        (
            lambda raw: canonical_json(
                {**__import__("json").loads(raw), "scram_verifier": "not-a-verifier"}
            ).encode(),
            "provision_handoff_verifier_invalid",
        ),
        (
            lambda raw: canonical_json({**__import__("json").loads(raw), "extra": 1}).encode(),
            "provision_handoff_malformed",
        ),
        (lambda raw: b"not json", "provision_handoff_not_json"),
    ],
)
def test_malformed_handoff_is_refused(mutate, reason):
    code, payload = _run(mutate(_handoff_bytes()))
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == reason


def test_hardened_reader_failure_is_refused():
    def _bad():
        raise HardenedHandoffError("handoff_object_unsafe")

    code, payload = mod.run_provision(read_handoff=_bad, engine=_sqlite())
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == "handoff_object_unsafe"


def test_injection_shaped_verifier_is_refused():
    bad = "SCRAM-SHA-256$4096:AAAA$BBBB:CCCC'; DROP ROLE postgres; --"
    code, payload = _run(_handoff_bytes(verifier=bad))
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == "provision_handoff_verifier_invalid"
