"""Controller-identity activation one-shot — exact-operation durable idempotency (SECP-PR5H-B2 C3).

Drives the one-shot through a per-test in-memory DB (the ``engine`` fixture rebinds the API
sessionmaker) with an injected reader seam (the production reader is POSIX-hardened) and an injected
``now`` (freshness). Proves first-execution + receipt commit atomically, exact byte-equivalent
replay (after restart / rotation / rotation-back / freshness expiry), the operation-binding
conflicts, the
already-active refusal, activation-failure leaving no receipt, and corrupt-receipt refusal.
"""

from __future__ import annotations

import json

import pytest
from secp_api import activate_controller_identity_once as mod
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.controller_identity_models import ControllerIdentityActivationReceipt
from secp_api.db import get_sessionmaker
from secp_commissioning.canonical import canonical_json, sha256_bytes
from sqlalchemy import select

_SCHEMA = mod.CONTROLLER_IDENTITY_ACTIVATION_SCHEMA
_T0 = "2026-07-28T00:00:00Z"
from datetime import UTC, datetime  # noqa: E402

_FRESH = datetime(2026, 7, 28, 0, 1, 0, tzinfo=UTC)  # 60s after _T0
_STALE = datetime(2026, 7, 28, 2, 0, 0, tzinfo=UTC)  # 2h after _T0


def _fields(proof) -> dict[str, str]:
    return {f: getattr(proof, f) for f in mod._IDENTITY_FIELDS}


def _handoff(
    proof,
    *,
    operation_id="op-1",
    expected_row=None,
    expected_token=None,
    generation=0,
    created_at=_T0,
    **over,
) -> bytes:
    fields = _fields(proof)
    env = {
        "schema": _SCHEMA,
        "operation_id": operation_id,
        "candidate_digest": sha256_bytes(
            canonical_json({f: fields[f] for f in mod._IDENTITY_FIELDS}).encode()
        ),
        "expected_predecessor_row_id": expected_row,
        "expected_predecessor_activation_token": expected_token,
        "generation": generation,
        "handoff_created_at": created_at,
        **fields,
    }
    env.update(over)
    return canonical_json(env).encode()


def _reader(raw: bytes):
    return lambda: raw


def _run(raw: bytes, *, now=_FRESH):
    return mod.run_activation(
        read_handoff=_reader(raw), session_factory=get_sessionmaker(), now=now
    )


_A = build_test_verified_controller_identity()
_B = build_test_verified_controller_identity(
    controller_installation_id="controller-b0000001", controller_trust_anchor_hex="22" * 32
)


def _receipt_count(prefix="") -> int:
    with get_sessionmaker()() as s:
        return len(s.execute(select(ControllerIdentityActivationReceipt)).scalars().all())


def test_first_execution_commits_activation_and_receipt_atomically(engine):
    code, receipt = _run(_handoff(_A))
    assert code == mod.EXIT_OK and receipt["created"] is True
    assert receipt["previous_active_row_id"] is None and receipt["resulting_status"] == "active"
    assert _receipt_count() == 1  # the durable receipt exists
    blob = json.dumps(receipt)
    for forbidden in ("password", "verifier", "PRIVATE KEY", "postgresql", "dsn"):
        assert forbidden not in blob


def test_exact_replay_returns_byte_equivalent_receipt(engine):
    raw = _handoff(_A)
    _, r1 = _run(raw)
    code, r2 = _run(raw)  # exact replay (same handoff), even a second time
    assert code == mod.EXIT_OK
    assert canonical_json(r1) == canonical_json(r2) and r2["created"] is True
    assert _receipt_count() == 1  # replay inserted nothing


def test_exact_replay_after_rotation_and_rotation_back(engine):
    _, r1 = _run(_handoff(_A, operation_id="op-A"))  # fresh install: generation 0
    row_a = r1["resulting_row_id"]
    # rotate A -> B (upgrade: generation must be predecessor + 1)
    _, r2 = _run(
        _handoff(
            _B,
            operation_id="op-B",
            expected_row=row_a,
            expected_token=r1["activation_token"],
            generation=1,
        )
    )
    row_b = r2["resulting_row_id"]
    # rotate back B -> A' (fresh candidate _A again, new op): next generation
    _run(
        _handoff(
            _A,
            operation_id="op-A2",
            expected_row=row_b,
            expected_token=r2["activation_token"],
            generation=2,
        )
    )
    # op-A replay still returns its ORIGINAL receipt (proves committed, not current)
    code, replay = _run(
        _handoff(_A, operation_id="op-A"), now=_STALE
    )  # even after freshness expiry
    assert code == mod.EXIT_OK
    assert canonical_json(replay) == canonical_json(r1)
    assert replay["resulting_row_id"] == row_a


def test_fresh_install_with_nonzero_generation_refuses(engine):
    # F6: a fresh install (no active predecessor) MUST be generation 0.
    code, payload = _run(_handoff(_A, operation_id="op-fresh", generation=1))
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == "activation_generation_not_fresh"
    assert _receipt_count() == 0


@pytest.mark.parametrize(
    "generation,reason",
    [
        (0, "activation_generation_out_of_order"),  # stale (== predecessor's number)
        (1, "activation_generation_out_of_order"),  # replay of predecessor's own number
        (3, "activation_generation_out_of_order"),  # skipped a generation
        (5, "activation_generation_out_of_order"),  # far ahead
    ],
)
def test_upgrade_generation_must_be_exactly_predecessor_plus_one(engine, generation, reason):
    # F6: fresh install is generation 0; the ONLY valid rotation number is predecessor + 1 (== 2
    # here, after one prior rotation raises A's predecessor number to 1). Every other value refuses.
    _, r1 = _run(_handoff(_A, operation_id="op-A"))  # generation 0
    _, r2 = _run(
        _handoff(
            _B,
            operation_id="op-B",
            expected_row=r1["resulting_row_id"],
            expected_token=r1["activation_token"],
            generation=1,
        )
    )  # B now active, its predecessor number is 1 → next valid is 2
    code, payload = _run(
        _handoff(
            _A,
            operation_id="op-C",
            expected_row=r2["resulting_row_id"],
            expected_token=r2["activation_token"],
            generation=generation,
        )
    )
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == reason


def test_stale_first_execution_refuses_but_stale_replay_succeeds(engine):
    stale_first = _run(_handoff(_A, operation_id="op-stale"), now=_STALE)
    assert stale_first[0] == mod.EXIT_STALE
    assert _receipt_count() == 0
    # a fresh first execution, then a STALE replay of it, succeeds (lookup precedes freshness)
    _run(_handoff(_A, operation_id="op-ok"))
    code, _ = _run(_handoff(_A, operation_id="op-ok"), now=_STALE)
    assert code == mod.EXIT_OK


@pytest.mark.parametrize(
    "mutate",
    [
        {"candidate_field": True},  # different candidate (different identity)
        {"generation": 3},  # different generation
        {"created_at": "2026-07-28T00:00:01Z"},  # different timestamp
    ],
)
def test_same_operation_with_a_changed_binding_conflicts(engine, mutate):
    _run(_handoff(_A, operation_id="op-x"))
    if mutate.pop("candidate_field", False):
        raw = _handoff(_B, operation_id="op-x")  # same op id, different candidate
    else:
        raw = _handoff(_A, operation_id="op-x", **mutate)
    code, payload = _run(raw, now=_FRESH)
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == "activation_operation_conflict"


def test_new_operation_with_an_already_active_candidate_conflicts(engine):
    _run(_handoff(_A, operation_id="op-first"))
    # a DIFFERENT operation id presenting the SAME (already active) candidate cannot claim it
    code, payload = _run(_handoff(_A, operation_id="op-second"))
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == "activation_candidate_already_active"


def test_stale_predecessor_conflicts(engine):
    _run(_handoff(_A, operation_id="op-a"))
    # a fresh-install handoff (predecessor None) when an identity is already active
    code, payload = _run(_handoff(_B, operation_id="op-b"))
    assert code == mod.EXIT_OPERATION_CONFLICT
    assert payload["reason_code"] == "activation_predecessor_conflict"


def test_wrong_predecessor_token_conflicts(engine):
    _, r1 = _run(_handoff(_A, operation_id="op-a"))
    code, payload = _run(
        _handoff(
            _B, operation_id="op-b", expected_row=r1["resulting_row_id"], expected_token="wrong|t"
        )
    )
    assert code == mod.EXIT_OPERATION_CONFLICT


def test_activation_failure_leaves_no_receipt(engine):
    bad = build_test_verified_controller_identity()
    fields = _fields(bad)
    fields["release_digest"] = fields[
        "controller_key_id"
    ]  # key == release digest → separation break
    env = {
        "schema": _SCHEMA,
        "operation_id": "op-bad",
        "candidate_digest": sha256_bytes(
            canonical_json({f: fields[f] for f in mod._IDENTITY_FIELDS}).encode()
        ),
        "expected_predecessor_row_id": None,
        "expected_predecessor_activation_token": None,
        "generation": 0,
        "handoff_created_at": _T0,
        **fields,
    }
    code, _ = _run(canonical_json(env).encode())
    assert code == mod.EXIT_ACTIVATION_REFUSED
    assert _receipt_count() == 0  # no receipt without a committed activation


def test_corrupt_stored_receipt_refuses(engine):
    _, r1 = _run(_handoff(_A, operation_id="op-c"))
    with get_sessionmaker()() as s:
        row = s.execute(select(ControllerIdentityActivationReceipt)).scalars().one()
        row.receipt_json = row.receipt_json.replace(
            "active", "revoked"
        )  # tamper (digest now stale)
        s.commit()
    code, payload = _run(_handoff(_A, operation_id="op-c"))
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload["reason_code"] == "controller_activation_state_corrupt"


@pytest.mark.parametrize(
    "raw,reason",
    [
        (
            lambda: json.dumps(json.loads(_handoff(_A)), indent=2).encode(),
            "activation_handoff_noncanonical",
        ),
        (
            lambda: canonical_json({**json.loads(_handoff(_A)), "schema": "x/v9"}).encode(),
            "activation_handoff_schema_unknown",
        ),
        (
            lambda: canonical_json(
                {**json.loads(_handoff(_A)), "handoff_created_at": "not-a-time"}
            ).encode(),
            "activation_handoff_timestamp_noncanonical",
        ),
        (
            lambda: canonical_json(
                {**json.loads(_handoff(_A)), "expected_predecessor_activation_token": "x|y"}
            ).encode(),
            "activation_handoff_predecessor_pairing",
        ),
        (lambda: b"not json", "activation_handoff_not_json"),
    ],
)
def test_malformed_handoff_is_refused(engine, raw, reason):
    code, payload = _run(raw())
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == reason
