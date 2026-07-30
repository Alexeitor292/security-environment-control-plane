"""Fixed API-plane controller-identity activation one-shot (SECP-PR5H-B2, 2b-3b C2/C3).

``python -m secp_api.activate_controller_identity_once`` — the narrow local transaction participant
the root installer invokes (via a fixed ``compose run api`` one-shot) as the PENULTIMATE
finalization step, because the API plane owns the controller-identity persistence invariants + the
ORM transaction.

It reads ONLY the single fixed handoff through the plane-neutral HARDENED reader (root-owned, exact
API-group, 0640, regular, single-link, no-follow, fstat, before/after identity sample), validates a
strict CLOSED operation envelope, and applies EXACT-OPERATION idempotency backed by the durable
``controller_identity_activation_receipt`` table:

* the ``operation_id`` is bound (via a domain-separated ``operation_digest``) to the candidate, the
  expected predecessor row + activation token (or explicit fresh-install absence), the installation,
  release, generation, and the canonical-UTC handoff timestamp — the SAME ``operation_id`` with ANY
  changed field conflicts, and a NEW ``operation_id`` cannot claim replay;
* FIRST execution (no receipt): enforce a bounded freshness window, take the shared controller-
  identity advisory lock, validate the exact predecessor CAS, refuse a new operation whose candidate
  is merely already active, invoke the EXISTING ``activate_controller_identity`` (all proof +
  key-separation invariants), read back, build the bounded receipt, INSERT it, and commit activation
  + receipt in ONE transaction — no activation without receipt, no receipt without activation;
* a UNIQUE(operation_id) race rolls the loser back and reloads + validates the winning receipt;
* EXACT replay returns the byte-equivalent stored receipt (after restart / rotation / freshness
  expiry) and performs NO mutation — a replay proves the operation committed, NOT that the identity
  is currently active (the management adapter reobserves the active identity before writing the
  marker);
* corruption (bad digest, noncanonical, parse/history mismatch, impossible pairing) refuses state-
  corrupt; the trusted path only INSERTs and SELECTs this write-once table.

It NEVER receives the enrollment private key and returns ONLY a bounded non-secret receipt. Exit
codes: 0 ok/replay; 1 handoff invalid; 2 operation conflict; 3 activation refused; 4 ambiguous
state; 5 state corrupt; 6 stale first execution.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_bytes
from secp_commissioning.controller_enrollment_signer import ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY
from secp_commissioning.hardened_handoff import HardenedHandoffError, read_hardened_fixed_handoff
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secp_api.controller_identity_models import (
    CONTROLLER_IDENTITY_ACTIVATION_SCHEMA,
    ControllerEnrollmentIdentity,
    ControllerIdentityActivationReceipt,
)
from secp_api.db import get_sessionmaker
from secp_api.errors import WorkerEnrollmentError
from secp_api.services.controller_identity import (
    VerifiedControllerIdentity,
    activate_controller_identity,
)

#: The single fixed path the handoff is mounted read-only at inside the one-shot container.
HANDOFF_PATH = "/run/secp/handoff/controller-identity-activation.json"
_MAX_HANDOFF_BYTES = 8 * 1024
_OPERATION_DOMAIN = "secp.controller-identity-activation-operation/v1"
_FRESHNESS_SECONDS = 900  # first-execution handoff must be within +/- 15 minutes of now
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

EXIT_OK = 0
EXIT_HANDOFF_INVALID = 1
EXIT_OPERATION_CONFLICT = 2
EXIT_ACTIVATION_REFUSED = 3
EXIT_AMBIGUOUS_STATE = 4
EXIT_STATE_CORRUPT = 5
EXIT_STALE = 6

#: The eight identity fields, in the fixed order the candidate/public-state digests canonicalize.
_IDENTITY_FIELDS = (
    "controller_installation_id",
    "controller_key_id",
    "controller_trust_anchor_hex",
    "controller_origin",
    "release_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
    "enrollment_key_proof_id",
)
_RECEIPT_FIELDS = (
    "operation_id",
    "candidate_digest",
    "resulting_row_id",
    "activation_token",
    "previous_active_row_id",
    "created",
    "resulting_status",
    "resulting_public_state_digest",
)


class _HandoffInvalid(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _ActivationHandoff(BaseModel):
    """The strict, closed activation-operation envelope. Extra/missing fields + wrong types refuse;
    every value is bounded; the predecessor row + token are BOTH present (rotation) or BOTH null."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_id: str = Field(alias="schema", min_length=1, max_length=64)
    operation_id: str = Field(min_length=1, max_length=128)
    candidate_digest: str = Field(min_length=71, max_length=71)
    expected_predecessor_row_id: str | None = Field(default=None, max_length=64)
    expected_predecessor_activation_token: str | None = Field(default=None, max_length=128)
    generation: int = Field(ge=0, le=2**31 - 1)
    handoff_created_at: str = Field(min_length=1, max_length=40)
    controller_installation_id: str = Field(min_length=8, max_length=64)
    controller_key_id: str = Field(min_length=71, max_length=71)
    controller_trust_anchor_hex: str = Field(min_length=64, max_length=64)
    controller_origin: str = Field(min_length=1, max_length=269)
    release_digest: str = Field(min_length=71, max_length=71)
    management_identity_digest: str = Field(min_length=71, max_length=71)
    bootstrap_evidence_digest: str = Field(min_length=71, max_length=71)
    enrollment_key_proof_id: str = Field(min_length=8, max_length=120)


def _identity_digest(values: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json({f: values[f] for f in _IDENTITY_FIELDS}).encode("utf-8"))


def _operation_digest(h: _ActivationHandoff) -> str:
    envelope = {
        "domain": _OPERATION_DOMAIN,
        "schema": h.schema_id,
        "operation_id": h.operation_id,
        "candidate_digest": h.candidate_digest,
        "expected_predecessor_row_id": h.expected_predecessor_row_id,
        "expected_predecessor_activation_token": h.expected_predecessor_activation_token,
        "controller_installation_id": h.controller_installation_id,
        "release_digest": h.release_digest,
        "generation": h.generation,
        "handoff_created_at": h.handoff_created_at,
    }
    return sha256_bytes(canonical_json(envelope).encode("utf-8"))


def _parse_utc(value: str) -> datetime | None:
    if not _UTC.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _parse_handoff(raw: bytes) -> _ActivationHandoff:
    if not raw or len(raw) > _MAX_HANDOFF_BYTES:
        raise _HandoffInvalid("activation_handoff_size_invalid")
    body = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise _HandoffInvalid("activation_handoff_not_json") from None
    if not isinstance(obj, dict) or canonical_json(obj).encode("utf-8") != body:
        raise _HandoffInvalid("activation_handoff_noncanonical")
    try:
        handoff = _ActivationHandoff.model_validate(obj)
    except ValidationError:
        raise _HandoffInvalid("activation_handoff_malformed") from None
    if handoff.schema_id != CONTROLLER_IDENTITY_ACTIVATION_SCHEMA:
        raise _HandoffInvalid("activation_handoff_schema_unknown")
    if not is_sha256_digest(handoff.candidate_digest):
        raise _HandoffInvalid("activation_handoff_candidate_digest_invalid")
    if _identity_digest(handoff.model_dump()) != handoff.candidate_digest:
        raise _HandoffInvalid("activation_handoff_candidate_digest_mismatch")
    # predecessor row id + token are BOTH present (rotation) or BOTH null (fresh install)
    if (handoff.expected_predecessor_row_id is None) != (
        handoff.expected_predecessor_activation_token is None
    ):
        raise _HandoffInvalid("activation_handoff_predecessor_pairing")
    if _parse_utc(handoff.handoff_created_at) is None:
        raise _HandoffInvalid("activation_handoff_timestamp_noncanonical")
    return handoff


def _production_reader() -> bytes:
    gid = int(getattr(os, "getegid", lambda: -1)())
    return read_hardened_fixed_handoff(HANDOFF_PATH, expected_gid=gid, max_bytes=_MAX_HANDOFF_BYTES)


# --------------------------------------------------------------------- receipt build + parse


def _row_values(row: ControllerEnrollmentIdentity) -> dict[str, str]:
    return {f: str(getattr(row, f)) for f in _IDENTITY_FIELDS}


def _token(row: ControllerEnrollmentIdentity) -> str:
    return f"{row.id}|{row.activated_at}"


def _build_receipt(
    h: _ActivationHandoff,
    *,
    row: ControllerEnrollmentIdentity,
    created: bool,
    previous_active_row_id: str | None,
) -> dict[str, Any]:
    public_state = {"resulting_row_id": str(row.id), **_row_values(row)}
    return {
        "operation_id": h.operation_id,
        "candidate_digest": h.candidate_digest,
        "resulting_row_id": str(row.id),
        "activation_token": _token(row),
        "previous_active_row_id": previous_active_row_id,
        "created": created,
        "resulting_status": str(row.status),
        "resulting_public_state_digest": sha256_bytes(canonical_json(public_state).encode("utf-8")),
    }


class _StrictReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str
    candidate_digest: str
    resulting_row_id: str
    activation_token: str
    previous_active_row_id: str | None
    created: bool
    resulting_status: str
    resulting_public_state_digest: str


# --------------------------------------------------------------------- durable flow


def _advisory_lock(session: Session) -> None:
    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(:k)"), {"k": ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY}
        )


def _load_receipt(
    session: Session, operation_id: str
) -> ControllerIdentityActivationReceipt | None:
    return (
        session.execute(
            select(ControllerIdentityActivationReceipt).where(
                ControllerIdentityActivationReceipt.operation_id == operation_id
            )
        )
        .scalars()
        .one_or_none()
    )


def _exact_replay(
    session: Session, existing: ControllerIdentityActivationReceipt, op_digest: str
) -> tuple[int, dict[str, Any]]:
    """Return the exact stored receipt for a matching operation, conflict on any binding change, or
    state-corrupt on a tampered/incoherent stored receipt. Performs NO mutation."""
    if existing.operation_digest != op_digest:
        return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_operation_conflict"}
    raw = existing.receipt_json.encode("utf-8")
    if sha256_bytes(raw) != existing.receipt_digest:
        return EXIT_STATE_CORRUPT, {"reason_code": "controller_activation_state_corrupt"}
    try:
        obj = json.loads(raw)
    except ValueError:
        return EXIT_STATE_CORRUPT, {"reason_code": "controller_activation_state_corrupt"}
    if not isinstance(obj, dict) or canonical_json(obj).encode("utf-8") != raw:
        return EXIT_STATE_CORRUPT, {"reason_code": "controller_activation_state_corrupt"}
    try:
        parsed = _StrictReceipt.model_validate(obj)
    except ValidationError:
        return EXIT_STATE_CORRUPT, {"reason_code": "controller_activation_state_corrupt"}
    if (
        parsed.operation_id != existing.operation_id
        or parsed.resulting_row_id != str(existing.resulting_row_id)
        or parsed.activation_token != existing.resulting_activation_token
        or parsed.resulting_public_state_digest != existing.resulting_public_state_digest
    ):
        return EXIT_STATE_CORRUPT, {"reason_code": "controller_activation_state_corrupt"}
    # the historical resulting identity row must still exist (not necessarily active)
    hist = session.get(ControllerEnrollmentIdentity, existing.resulting_row_id)
    if hist is None:
        return EXIT_STATE_CORRUPT, {"reason_code": "controller_activation_state_corrupt"}
    return EXIT_OK, obj  # the EXACT stored receipt bytes (as the parsed object)


def _latest_receipt_for_row(
    session: Session, row_id: Any
) -> ControllerIdentityActivationReceipt | None:
    """The most recent durable receipt whose activation RESULTED IN ``row_id`` — the authoritative
    source of that identity generation's number (F6). Ordered by ``recorded_at`` so the newest wins
    even if a row was reactivated across a rollback."""
    return (
        session.execute(
            select(ControllerIdentityActivationReceipt)
            .where(ControllerIdentityActivationReceipt.resulting_row_id == row_id)
            .order_by(ControllerIdentityActivationReceipt.recorded_at.desc())
        )
        .scalars()
        .first()
    )


def _validate_generation(
    session: Session, h: _ActivationHandoff, current: ControllerEnrollmentIdentity | None
) -> tuple[int, dict[str, Any]] | None:
    """Independently validate the handoff generation against the DURABLE predecessor receipt (under
    the advisory lock the caller holds): a fresh install (no active predecessor) MUST be generation
    0; a rotation MUST be exactly the predecessor receipt's generation + 1 (a stale, skipped, or
    downgrade generation refuses). Returns a conflict tuple, or ``None`` when the order is valid."""
    if current is None:
        if h.generation != 0:
            return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_generation_not_fresh"}
        return None
    prev = _latest_receipt_for_row(session, current.id)
    if prev is None:
        return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_predecessor_receipt_missing"}
    if h.generation != int(prev.generation) + 1:
        return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_generation_out_of_order"}
    return None


def _first_execution(
    session: Session, h: _ActivationHandoff, op_digest: str, now: datetime
) -> tuple[int, dict[str, Any]]:
    delta = abs((now - _parse_utc(h.handoff_created_at)).total_seconds())  # type: ignore[operator]
    if delta > _FRESHNESS_SECONDS:
        return EXIT_STALE, {"reason_code": "activation_handoff_stale"}
    rows = (
        session.execute(
            select(ControllerEnrollmentIdentity).where(
                ControllerEnrollmentIdentity.status == "active"
            )
        )
        .scalars()
        .all()
    )
    if len(rows) > 1:
        return EXIT_AMBIGUOUS_STATE, {"reason_code": "controller_identity_ambiguous"}
    current = rows[0] if rows else None
    if current is not None and _identity_digest(_row_values(current)) == h.candidate_digest:
        # The candidate is ALREADY active. Before refusing, do ONE authoritative re-read of the
        # receipt for THIS exact operation_id under the advisory lock we already hold: the initial
        # lookup in run_activation can miss (a lost/stale read) while THIS operation in fact already
        # committed — in which case this is a legitimate exact replay, not a new-operation attempt.
        # _exact_replay revalidates the operation_digest + every stored binding and mutates nothing;
        # a genuinely NEW operation_id (no receipt) still cannot claim replay merely because its
        # candidate happens to be active.
        committed = _load_receipt(session, h.operation_id)
        if committed is not None:
            return _exact_replay(session, committed, op_digest)
        return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_candidate_already_active"}
    actual_row = str(current.id) if current is not None else None
    actual_token = _token(current) if current is not None else None
    if (
        h.expected_predecessor_row_id != actual_row
        or h.expected_predecessor_activation_token != actual_token
    ):
        return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_predecessor_conflict"}
    gen_conflict = _validate_generation(session, h, current)
    if gen_conflict is not None:
        return gen_conflict
    proof = VerifiedControllerIdentity(**{f: getattr(h, f) for f in _IDENTITY_FIELDS})
    try:
        row = activate_controller_identity(session, proof)
    except WorkerEnrollmentError as exc:
        session.rollback()
        return EXIT_ACTIVATION_REFUSED, {"reason_code": str(exc.code)}
    session.flush()
    session.refresh(row)  # use the DB-persisted activated_at so the token matches later re-reads
    receipt = _build_receipt(h, row=row, created=True, previous_active_row_id=actual_row)
    receipt_json = canonical_json(receipt)
    session.add(
        ControllerIdentityActivationReceipt(
            operation_id=h.operation_id,
            operation_schema=h.schema_id,
            operation_digest=op_digest,
            candidate_digest=h.candidate_digest,
            expected_predecessor_row_id=(
                current.id if current is not None else None  # UUID FK, never a string
            ),
            expected_predecessor_activation_token=h.expected_predecessor_activation_token,
            controller_installation_id=h.controller_installation_id,
            release_digest=h.release_digest,
            generation=h.generation,
            handoff_created_at=h.handoff_created_at,
            resulting_row_id=row.id,
            resulting_activation_token=receipt["activation_token"],
            resulting_public_state_digest=receipt["resulting_public_state_digest"],
            receipt_json=receipt_json,
            receipt_digest=sha256_bytes(receipt_json.encode("utf-8")),
        )
    )
    try:
        session.commit()  # activation + receipt commit atomically
    except IntegrityError:
        session.rollback()  # a concurrent winner took UNIQUE(operation_id)
        winner = _load_receipt(session, h.operation_id)
        if winner is None:
            return EXIT_OPERATION_CONFLICT, {"reason_code": "activation_operation_conflict"}
        return _exact_replay(session, winner, op_digest)
    return EXIT_OK, receipt


def run_activation(
    *,
    read_handoff: Any = None,
    session_factory: sessionmaker[Session] | None = None,
    now: datetime | None = None,
) -> tuple[int, dict[str, Any]]:
    """Read + validate the fixed handoff and apply exact-operation idempotent activation. Returns
    ``(exit_code, bounded_receipt_or_reason)``. ``read_handoff`` defaults to the production hardened
    fixed-path reader; tests inject a verified-reader seam (never a production path override)."""
    reader = read_handoff if read_handoff is not None else _production_reader
    try:
        handoff = _parse_handoff(reader())
    except HardenedHandoffError as exc:
        return EXIT_HANDOFF_INVALID, {"reason_code": exc.reason_code}
    except _HandoffInvalid as exc:
        return EXIT_HANDOFF_INVALID, {"reason_code": exc.reason_code}
    op_digest = _operation_digest(handoff)
    resolved_now = (datetime.now(UTC) if now is None else now).astimezone(UTC)
    factory = session_factory if session_factory is not None else get_sessionmaker()
    session = factory()
    try:
        _advisory_lock(session)
        existing = _load_receipt(session, handoff.operation_id)
        if existing is not None:
            code, payload = _exact_replay(session, existing, op_digest)
        else:
            code, payload = _first_execution(session, handoff, op_digest, resolved_now)
        if code != EXIT_OK:
            session.rollback()  # a refusal/replay commits nothing new
        return code, payload
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(
        prog="python -m secp_api.activate_controller_identity_once",
        description=(
            "Activate the verified controller identity from the fixed root-owned handoff (no "
            "argument selects the handoff, the database, or the identity)."
        ),
    ).parse_args(argv)
    code, payload = run_activation()
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))  # noqa: T201
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
