"""Fixed API-plane controller-identity activation one-shot (SECP-PR5H-B2, commit 2b-3b).

Proves the one-shot activates the verified identity from the fixed handoff, is idempotent on exact
replay, rotates under the expected-predecessor CAS, conflicts on a stale predecessor, refuses a
malformed/non-canonical/digest-mismatched handoff, refuses an activation that breaks the identity-
proof invariants (key separation), and returns only a bounded non-secret receipt. The ``engine``
fixture rebinds the API sessionmaker to a per-test in-memory DB, so ``run_activation`` drives it.
"""

from __future__ import annotations

import json

import pytest
from secp_api import activate_controller_identity_once as mod
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_commissioning.canonical import canonical_json, sha256_bytes


def _fields(proof) -> dict[str, str]:
    return {f: getattr(proof, f) for f in mod._IDENTITY_FIELDS}


def _digest(fields: dict[str, str]) -> str:
    return sha256_bytes(canonical_json({f: fields[f] for f in mod._IDENTITY_FIELDS}).encode())


def _handoff_bytes(proof, *, operation_id="op-1", expected_predecessor=None, **over) -> bytes:
    fields = _fields(proof)
    env = {
        "schema": mod._HANDOFF_SCHEMA,
        "operation_id": operation_id,
        "expected_predecessor_row_id": expected_predecessor,
        **fields,
        "candidate_digest": _digest(fields),
        "created_at": "2026-07-28T00:00:00Z",
    }
    env.update(over)
    return canonical_json(env).encode()


def _write(tmp_path, raw: bytes) -> str:
    p = tmp_path / "controller-identity-activation.json"
    p.write_bytes(raw)
    return str(p)


_A = build_test_verified_controller_identity()
_B = build_test_verified_controller_identity(
    controller_installation_id="controller-b0000001", controller_trust_anchor_hex="22" * 32
)


def test_fresh_activation_succeeds_with_a_bounded_receipt(engine, tmp_path):
    code, receipt = mod.run_activation(handoff_path=_write(tmp_path, _handoff_bytes(_A)))
    assert code == mod.EXIT_OK
    assert receipt["created"] is True
    assert receipt["previous_active_row_id"] is None
    assert receipt["resulting_status"] == "active"
    assert receipt["candidate_digest"] == _digest(_fields(_A))
    assert receipt["resulting_public_state_digest"].startswith("sha256:")
    # no secret-shaped field in the receipt
    blob = json.dumps(receipt)
    for forbidden in ("password", "verifier", "PRIVATE KEY", "database", "postgresql", "dsn"):
        assert forbidden not in blob


def test_exact_replay_is_idempotent(engine, tmp_path):
    path = _write(tmp_path, _handoff_bytes(_A))
    code1, r1 = mod.run_activation(handoff_path=path)
    code2, r2 = mod.run_activation(handoff_path=path)
    assert code1 == code2 == mod.EXIT_OK
    assert r1["created"] is True and r2["created"] is False  # second is an idempotent no-op
    assert r1["resulting_row_id"] == r2["resulting_row_id"]


def test_rotation_under_the_expected_predecessor_succeeds(engine, tmp_path):
    _, r1 = mod.run_activation(handoff_path=_write(tmp_path, _handoff_bytes(_A)))
    code, r2 = mod.run_activation(
        handoff_path=_write(
            tmp_path,
            _handoff_bytes(_B, operation_id="op-2", expected_predecessor=r1["resulting_row_id"]),
        )
    )
    assert code == mod.EXIT_OK and r2["created"] is True
    assert r2["previous_active_row_id"] == r1["resulting_row_id"]
    assert r2["resulting_row_id"] != r1["resulting_row_id"]


def test_stale_predecessor_conflicts(engine, tmp_path):
    mod.run_activation(handoff_path=_write(tmp_path, _handoff_bytes(_A)))
    # a fresh-install handoff (expected predecessor None) submitted when an identity is already
    # active
    code, payload = mod.run_activation(
        handoff_path=_write(tmp_path, _handoff_bytes(_B, operation_id="op-3"))
    )
    assert code == mod.EXIT_PREDECESSOR_CONFLICT
    assert payload["reason_code"] == "controller_identity_predecessor_conflict"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: json.dumps(json.loads(raw), indent=2).encode(),  # non-canonical
        lambda raw: json.dumps(
            {**json.loads(raw), "schema": "other/v9"}, sort_keys=True, separators=(",", ":")
        ).encode(),
        lambda raw: json.dumps(
            {**json.loads(raw), "candidate_digest": "sha256:" + "0" * 64},
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        lambda raw: json.dumps(
            {**json.loads(raw), "extra": 1}, sort_keys=True, separators=(",", ":")
        ).encode(),
        lambda raw: b"not json",
    ],
)
def test_malformed_handoff_is_refused(engine, tmp_path, mutate):
    code, payload = mod.run_activation(handoff_path=_write(tmp_path, mutate(_handoff_bytes(_A))))
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"].startswith("activation_handoff_")


def test_missing_handoff_is_refused(engine, tmp_path):
    code, payload = mod.run_activation(handoff_path=str(tmp_path / "absent.json"))
    assert code == mod.EXIT_HANDOFF_INVALID
    assert payload["reason_code"] == "activation_handoff_unreadable"


def test_activation_that_breaks_key_separation_is_refused(engine, tmp_path):
    # a handoff whose controller_key_id equals the release_digest violates key separation; the
    # candidate digest is self-consistent, so it passes handoff validation but the identity service
    # refuses it.
    bad = build_test_verified_controller_identity()
    fields = _fields(bad)
    fields["release_digest"] = fields[
        "controller_key_id"
    ]  # key == release digest → separation break
    env = {
        "schema": mod._HANDOFF_SCHEMA,
        "operation_id": "op-bad",
        "expected_predecessor_row_id": None,
        **fields,
        "candidate_digest": _digest(fields),
        "created_at": "2026-07-28T00:00:00Z",
    }
    code, payload = mod.run_activation(handoff_path=_write(tmp_path, canonical_json(env).encode()))
    assert code == mod.EXIT_ACTIVATION_REFUSED
    assert "reason_code" in payload
