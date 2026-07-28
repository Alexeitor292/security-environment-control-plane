"""Fixed API-plane controller-identity activation one-shot (SECP-PR5H-B2, commit 2b-3b).

``python -m secp_api.activate_controller_identity_once`` — a NARROW local transaction participant
the
root management installer invokes (via a fixed code-owned ``compose run api`` one-shot) as the
PENULTIMATE finalization step. It exists only because the API plane owns the controller-identity
persistence invariants + the ORM transaction: the management plane never imports the API, so it
hands
off the verified identity through this one-shot instead of reimplementing activation as raw SQL.

It has NO HTTP route, NO browser access, NO generic module/command/SQL/DSN/file-path selection, and
it
NEVER receives the controller enrollment PRIVATE key — only the public anchor + derived key id +
derived proof id, whose relationship the existing identity-proof logic re-validates. It reads ONLY
the single fixed handoff (mounted read-only at a fixed path), verifies its canonical form / type /
metadata / bounds and the self-consistent candidate digest, reconstructs the exact
:class:`VerifiedControllerIdentity`, and activates it through the EXISTING
:func:`activate_controller_identity` service (shared advisory lock; single-active ``UNIQUE`` marker;
full proof + key-separation invariants preserved) under an expected-predecessor CAS binding. An
exact
re-run is idempotent; a different candidate under a stale predecessor conflicts. It returns ONLY a
bounded, non-secret public receipt (never a private key, DSN, raw row, SQL, or exception).

Exit codes: 0 activated (or idempotent replay); 1 handoff invalid; 2 predecessor conflict; 3
activation refused by the identity-proof invariants; 4 ambiguous existing state.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_bytes
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from secp_api.controller_identity_models import ControllerEnrollmentIdentity
from secp_api.db import get_sessionmaker
from secp_api.errors import WorkerEnrollmentError
from secp_api.services.controller_identity import (
    VerifiedControllerIdentity,
    activate_controller_identity,
)

#: The single fixed path the handoff is mounted read-only at inside the one-shot container. NEVER a
#: caller-supplied path — the ``handoff_path`` parameter exists only for the hermetic tests.
HANDOFF_PATH = "/run/secp/handoff/controller-identity-activation.json"
_HANDOFF_SCHEMA = "secp.controller-identity-activation/v1"
_MAX_HANDOFF_BYTES = 8 * 1024

EXIT_OK = 0
EXIT_HANDOFF_INVALID = 1
EXIT_PREDECESSOR_CONFLICT = 2
EXIT_ACTIVATION_REFUSED = 3
EXIT_AMBIGUOUS_STATE = 4

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


class _HandoffInvalid(Exception):
    """A bounded, one-shot-authored refusal — only a closed reason code, never handoff bytes."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _ActivationHandoff(BaseModel):
    """The strict, closed activation envelope the management installer writes. Extra fields, missing
    fields, and wrong types are refused; every value is bounded."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_id: str = Field(alias="schema", min_length=1, max_length=64)
    operation_id: str = Field(min_length=1, max_length=128)
    expected_predecessor_row_id: str | None = Field(default=None, max_length=64)
    controller_installation_id: str = Field(min_length=1, max_length=64)
    controller_key_id: str = Field(min_length=71, max_length=71)
    controller_trust_anchor_hex: str = Field(min_length=64, max_length=64)
    controller_origin: str = Field(min_length=1, max_length=269)
    release_digest: str = Field(min_length=71, max_length=71)
    management_identity_digest: str = Field(min_length=71, max_length=71)
    bootstrap_evidence_digest: str = Field(min_length=71, max_length=71)
    enrollment_key_proof_id: str = Field(min_length=8, max_length=120)
    candidate_digest: str = Field(min_length=71, max_length=71)
    created_at: str = Field(min_length=1, max_length=40)


def _identity_digest(values: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json({f: values[f] for f in _IDENTITY_FIELDS}).encode("utf-8"))


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
    if handoff.schema_id != _HANDOFF_SCHEMA:
        raise _HandoffInvalid("activation_handoff_schema_unknown")
    if not is_sha256_digest(handoff.candidate_digest):
        raise _HandoffInvalid("activation_handoff_candidate_digest_invalid")
    values = handoff.model_dump()
    if _identity_digest(values) != handoff.candidate_digest:
        raise _HandoffInvalid("activation_handoff_candidate_digest_mismatch")
    return handoff


def _read_handoff(handoff_path: str) -> bytes:
    try:
        with open(handoff_path, "rb") as fh:
            return fh.read(_MAX_HANDOFF_BYTES + 1)
    except OSError:
        raise _HandoffInvalid("activation_handoff_unreadable") from None


def _row_values(row: ControllerEnrollmentIdentity) -> dict[str, str]:
    return {f: str(getattr(row, f)) for f in _IDENTITY_FIELDS}


def _token(row: ControllerEnrollmentIdentity) -> str:
    return f"{row.id}|{row.activated_at}"


def _receipt(
    handoff: _ActivationHandoff,
    *,
    row: ControllerEnrollmentIdentity,
    created: bool,
    previous_active_row_id: str | None,
) -> dict[str, Any]:
    public_state = {"resulting_row_id": str(row.id), **_row_values(row)}
    return {
        "operation_id": handoff.operation_id,
        "candidate_digest": handoff.candidate_digest,
        "resulting_row_id": str(row.id),
        "activation_token": _token(row),
        "previous_active_row_id": previous_active_row_id,
        "created": created,
        "resulting_status": str(row.status),
        "resulting_public_state_digest": sha256_bytes(canonical_json(public_state).encode("utf-8")),
    }


def _activate(session: Session, handoff: _ActivationHandoff) -> tuple[int, dict[str, Any]]:
    rows = (
        session.execute(
            select(ControllerEnrollmentIdentity).where(
                ControllerEnrollmentIdentity.status == "active"
            )
        )
        .scalars()
        .all()
    )
    if len(rows) > 1:  # the UNIQUE(active_marker) makes this impossible; refuse if the DB disagrees
        return EXIT_AMBIGUOUS_STATE, {"reason_code": "controller_identity_ambiguous"}
    current = rows[0] if rows else None

    # idempotent replay: the current active identity IS exactly this candidate → no-op,
    # created=False.
    if current is not None and _identity_digest(_row_values(current)) == handoff.candidate_digest:
        return EXIT_OK, _receipt(
            handoff,
            row=current,
            created=False,
            previous_active_row_id=handoff.expected_predecessor_row_id,
        )

    # CAS: the handoff's expected predecessor must equal the CURRENT active row (None for fresh).
    actual_predecessor = str(current.id) if current is not None else None
    if handoff.expected_predecessor_row_id != actual_predecessor:
        return EXIT_PREDECESSOR_CONFLICT, {
            "reason_code": "controller_identity_predecessor_conflict"
        }

    proof = VerifiedControllerIdentity(
        controller_installation_id=handoff.controller_installation_id,
        controller_key_id=handoff.controller_key_id,
        controller_trust_anchor_hex=handoff.controller_trust_anchor_hex,
        controller_origin=handoff.controller_origin,
        release_digest=handoff.release_digest,
        management_identity_digest=handoff.management_identity_digest,
        bootstrap_evidence_digest=handoff.bootstrap_evidence_digest,
        enrollment_key_proof_id=handoff.enrollment_key_proof_id,
    )
    try:
        row = activate_controller_identity(
            session, proof
        )  # preserves proof + key-separation + lock
    except WorkerEnrollmentError as exc:
        return EXIT_ACTIVATION_REFUSED, {"reason_code": str(exc.code)}
    session.flush()
    return EXIT_OK, _receipt(
        handoff, row=row, created=True, previous_active_row_id=actual_predecessor
    )


def run_activation(
    *, handoff_path: str = HANDOFF_PATH, session_factory: sessionmaker[Session] | None = None
) -> tuple[int, dict[str, Any]]:
    """Read + validate the fixed handoff and activate the verified identity under the expected-
    predecessor CAS. Returns ``(exit_code, bounded_receipt_or_reason)``; commits only on success."""
    try:
        handoff = _parse_handoff(_read_handoff(handoff_path))
    except _HandoffInvalid as exc:
        return EXIT_HANDOFF_INVALID, {"reason_code": exc.reason_code}
    factory = session_factory if session_factory is not None else get_sessionmaker()
    session = factory()
    try:
        code, payload = _activate(session, handoff)
        if code == EXIT_OK:
            session.commit()
        else:
            session.rollback()
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
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))  # noqa: T201 - one-shot receipt
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
