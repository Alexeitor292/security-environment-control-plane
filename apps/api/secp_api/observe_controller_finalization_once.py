"""Fixed API-plane controller-finalization DB-state OBSERVATION one-shot (SECP-PR5H-B2, 2b-3c-c).

``python -m secp_api.observe_controller_finalization_once`` — the fixed, READ-ONLY counterpart to
the reviewed provisioning/activation one-shots, required by clean-room review 4803080223 (findings
R1/R3). The management installer's pre-mutation finalization inventory classifies every host-side
finalization object itself, but the two DATABASE-plane objects — the dedicated
``secp_enrollment_signer`` role and the authoritative ACTIVE controller enrollment identity — live
behind the API plane's connection. The management plane may not import ``secp_api`` (and has no
admin DSN), so it drives THIS one-shot across the existing reviewed root -> API boundary::

    compose run --rm --no-deps api python -m secp_api.observe_controller_finalization_once

and parses the bounded canonical receipt it prints.

The one-shot is deliberately as narrow as the siblings:

* it is **fixed** — ``argparse`` accepts NO option beyond ``--help``; nothing selects the database,
  the role, a table, a schema, an operation, a module, a path, a credential, or the output format;
* it is **read-only** — it opens plain (never ``begin()``) connections, issues only the code-owned
  catalog + two-table SELECTs held in the ``_SQL_*`` constants and the two ORM-typed selects, and
  never executes a driver-level statement, a DDL/DML verb, a commit, or a flush. It takes NO handoff
  and NO input of any kind (it observes; it never mutates);
* it is **nonsecret** — it never SELECTs ``rolpassword``/a verifier/a DSN/a key. Credential POSTURE
  is derived from two BOOLEANS computed inside the database (``rolpassword IS NOT NULL`` and a
  ``LIKE 'SCRAM-SHA-256%'`` shape test); the verifier bytes never leave PostgreSQL. The receipt
  carries no exception text, no path, and no connection string;
* it is **canonical + bounded** — one strict, versioned, self-validated flat receipt (closed field
  set, closed value vocabularies, bounded counters) under :data:`_MAX_RECEIPT_BYTES`;
* it **fails closed** — any DB fault, any unparseable/incoherent durable state, and any receipt that
  fails its own strict self-validation yield a bounded ``reason_code`` payload and a NON-ZERO exit
  code, never a rubber-stamped "absent".

What it observes (review R1/R3): whether the dedicated role exists; its exact closed attribute set;
its exact direct memberships in BOTH directions; its owned-object count; its exact
schema/table/sequence/routine privileges; whether its stored credential posture is compatible with
the reviewed LOGIN-role contract; whether an ACTIVE controller identity exists; that identity's
exact PUBLIC binding fields; the durable activation generation; activation-receipt coherence; and
whether CONFLICTING (>1) active rows exist.

Receipt states (``observed_state``): ``absent`` (both database objects proven absent) / ``exact``
(every present object matches the reviewed contract) / ``drifted`` (present but deviating —
reported, never normalized, and never fatal, because a drifted role is still unambiguously PRESENT
and refusing would strand the installer with less information than the receipt already carries) /
``conflicting`` (>1 active identity — ambiguous, fatal) / ``corrupt`` (incoherent durable state —
fatal).

Compatibility: the reviewed management parser
(``secp_management.controller_finalization_inventory._parse_db_receipt``) reads the LAST stdout line
and requires EXACTLY the five fields ``schema``, ``role_name``, ``role_present``,
``active_identity_present``, ``activation_generation``. Those five are first-class receipt fields;
:func:`compat_projection` is their pure projection, printed as the final line ONLY on a successful
(exit-0) observation. A conflicting/corrupt/faulted run therefore ends with a NON-five-field line,
so even a caller that ignores the exit code fails closed instead of adopting an ambiguous state.

Exit codes: 0 observed (absent/exact/drifted); 1 conflicting active identities; 2 state corrupt;
3 unsupported (non-PostgreSQL); 4 database fault.
"""

from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE
from sqlalchemy import Connection, Engine, func, select, text

from secp_api.controller_identity_models import (
    CONTROLLER_IDENTITY_ACTIVATION_SCHEMA,
    CONTROLLER_IDENTITY_ACTIVE,
    ControllerEnrollmentIdentity,
    ControllerIdentityActivationReceipt,
)
from secp_api.db import get_engine

#: The one closed, versioned observation-receipt schema (the management parser pins this string).
OBSERVATION_SCHEMA = "secp.controller-finalization-db-state/v1"
#: The EXACT five fields the reviewed management probe parses, in no significant order (the printed
#: projection is canonical JSON, so key order is the canonical one regardless).
COMPAT_FIELDS: tuple[str, ...] = (
    "schema",
    "role_name",
    "role_present",
    "active_identity_present",
    "activation_generation",
)

EXIT_OK = 0
EXIT_CONFLICTING = 1
EXIT_STATE_CORRUPT = 2
EXIT_UNSUPPORTED = 3
EXIT_DB_ERROR = 4

#: The closed observation vocabulary (also the receipt's rollup ``observed_state``).
STATE_ABSENT = "absent"
STATE_EXACT = "exact"
STATE_DRIFTED = "drifted"
STATE_CONFLICTING = "conflicting"
STATE_CORRUPT = "corrupt"

#: The closed credential-POSTURE vocabulary. No value here is derived from verifier BYTES: the
#: database computes two booleans and only the classification crosses the boundary.
POSTURE_ABSENT = "absent"  # the role does not exist
POSTURE_NOLOGIN = "nologin"  # exists but cannot log in
POSTURE_NO_PASSWORD = "no_password"  # LOGIN with no stored password at all
#: the reviewed contract: LOGIN + a stored SCRAM-SHA-256 verifier
POSTURE_SCRAM_LOGIN = "scram_login"
POSTURE_NONSCRAM_LOGIN = "nonscram_login"  # LOGIN + a stored NON-SCRAM (e.g. md5) secret
POSTURE_UNOBSERVABLE = "unobservable"  # the shadow catalog is not readable by this connection

_IDENTITY_TABLE = "controller_enrollment_identity"
_RECEIPT_TABLE = "controller_identity_activation_receipt"
#: Bounded receipt size + bounded counters — the receipt can never grow with database size.
_MAX_RECEIPT_BYTES = 8192
_MAX_COUNT = 1_000_000
_MAX_GENERATION = 1_000_000

#: The eight PUBLIC identity binding fields, in the fixed order the activation receipt's
#: ``resulting_public_state_digest`` canonicalizes (so the two digests are directly comparable).
_IDENTITY_PUBLIC_FIELDS: tuple[str, ...] = (
    "controller_installation_id",
    "controller_key_id",
    "controller_trust_anchor_hex",
    "controller_origin",
    "release_digest",
    "management_identity_digest",
    "bootstrap_evidence_digest",
    "enrollment_key_proof_id",
)

#: The reviewed least-privilege role contract (mirrors ``render_signer_role_sql`` + the provisioning
#: one-shot's ``_verify_role_posture``): a plain LOGIN role, owning nothing, member of nothing, with
#: schema USAGE + SELECT on the ONE identity table and nothing else anywhere.
_REVIEWED_ATTRIBUTES: dict[str, bool] = {
    "login": True,
    "superuser": False,
    "createrole": False,
    "createdb": False,
    "bypassrls": False,
    "inherit": False,
    "replication": False,
}
_REVIEWED_PRIVILEGES: dict[str, Any] = {
    "schema_usage": True,
    "schema_create": False,
    "identity_select": True,
    "identity_insert": False,
    "identity_update": False,
    "identity_delete": False,
    "receipt_any": False,
    "other_tables_readable": 0,
    "sequences_privileged": 0,
    "routines_granted": 0,
}

# --------------------------------------------------------------------- the code-owned read-only SQL
#
# Every statement below is a MODULE CONSTANT (never built, formatted, or interpolated at runtime);
# the only runtime values are bound parameters, and every one of them is itself a code constant.

_SQL_ROLE_ATTRIBUTES = (
    "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolinherit, "
    "rolreplication FROM pg_roles WHERE rolname = :r"
)
_SQL_ROLE_MEMBERSHIPS = (
    "SELECT (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON m.member = r.oid "
    "WHERE r.rolname = :r), (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r "
    "ON m.roleid = r.oid WHERE r.rolname = :r)"
)
_SQL_ROLE_OWNED_OBJECTS = (
    "SELECT (SELECT count(*) FROM pg_class c JOIN pg_roles o ON c.relowner = o.oid"
    " WHERE o.rolname = :r)"
    " + (SELECT count(*) FROM pg_namespace ns JOIN pg_roles o ON ns.nspowner = o.oid"
    " WHERE o.rolname = :r)"
    " + (SELECT count(*) FROM pg_proc p JOIN pg_roles o ON p.proowner = o.oid"
    " WHERE o.rolname = :r)"
)
_SQL_SCHEMA_PRIVILEGES = (
    "SELECT has_schema_privilege(:r, 'public', 'USAGE'), "
    "has_schema_privilege(:r, 'public', 'CREATE')"
)
_SQL_TABLE_PRIVILEGES = (
    "SELECT"
    " CASE WHEN to_regclass(:i) IS NULL THEN NULL"
    " ELSE has_table_privilege(:r, :i, 'SELECT') END,"
    " CASE WHEN to_regclass(:i) IS NULL THEN NULL"
    " ELSE has_table_privilege(:r, :i, 'INSERT') END,"
    " CASE WHEN to_regclass(:i) IS NULL THEN NULL"
    " ELSE has_table_privilege(:r, :i, 'UPDATE') END,"
    " CASE WHEN to_regclass(:i) IS NULL THEN NULL"
    " ELSE has_table_privilege(:r, :i, 'DELETE') END,"
    " CASE WHEN to_regclass(:c) IS NULL THEN NULL ELSE ("
    "has_table_privilege(:r, :c, 'SELECT') OR has_table_privilege(:r, :c, 'INSERT')"
    " OR has_table_privilege(:r, :c, 'UPDATE') OR has_table_privilege(:r, :c, 'DELETE')) END"
)
_SQL_OTHER_TABLE_READS = (
    "SELECT count(*) FROM pg_tables t WHERE t.schemaname = 'public' AND t.tablename <> :i "
    "AND has_table_privilege(:r, quote_ident(t.schemaname) || '.' || quote_ident(t.tablename), "
    "'SELECT')"
)
_SQL_SEQUENCE_PRIVILEGES = (
    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid "
    "WHERE c.relkind = 'S' AND n.nspname = 'public' AND ("
    "has_sequence_privilege(:r, c.oid, 'USAGE') OR has_sequence_privilege(:r, c.oid, 'SELECT') "
    "OR has_sequence_privilege(:r, c.oid, 'UPDATE'))"
)
#: Routine EXECUTE is counted from DIRECT ACL entries only: PostgreSQL grants EXECUTE to PUBLIC by
#: default, so ``has_function_privilege`` would report a privilege the role was never granted.
_SQL_ROUTINE_GRANTS = (
    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "
    "JOIN pg_roles g ON g.rolname = :r "
    "JOIN LATERAL aclexplode(p.proacl) a ON a.grantee = g.oid WHERE n.nspname = 'public'"
)
#: Credential POSTURE only: two booleans computed INSIDE the database. ``rolpassword`` itself is
#: never selected, never returned, and never reachable from the receipt.
_SQL_CREDENTIAL_POSTURE = (
    "SELECT (rolpassword IS NOT NULL), (rolpassword LIKE 'SCRAM-SHA-256%') "
    "FROM pg_authid WHERE rolname = :r"
)


# --------------------------------------------------------------------- internal observation facts


@dataclass(frozen=True)
class _RoleFacts:
    """The dedicated signer role as observed from the catalogs (never any credential material)."""

    state: str
    present: bool
    attributes: dict[str, bool] | None
    posture: str
    compatible: bool
    member_of: int | None
    members: int | None
    owned: int | None
    privileges: dict[str, Any] | None


@dataclass(frozen=True)
class _IdentityFacts:
    """The authoritative ACTIVE controller enrollment identity (public binding fields only)."""

    state: str
    rows: int
    pk: uuid.UUID | None
    public: dict[str, str] | None
    token: str | None
    status: str | None
    verified: bool | None
    public_state_digest: str | None


@dataclass(frozen=True)
class _ReceiptFacts:
    """The durable activation receipt bound to the ACTIVE identity (generation + coherence)."""

    state: str
    rows: int
    generation: int | None
    operation_id: str | None
    operation_schema: str | None


_ABSENT_ROLE = _RoleFacts(
    state=STATE_ABSENT,
    present=False,
    attributes=None,
    posture=POSTURE_ABSENT,
    compatible=False,
    member_of=None,
    members=None,
    owned=None,
    privileges=None,
)


def _bounded(value: Any) -> int:
    """A bounded, nonnegative counter — the receipt never grows with database size."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return min(max(number, 0), _MAX_COUNT)


def _flag(value: Any) -> bool | None:
    """A three-valued catalog flag: ``None`` stays unobserved, everything else is a strict bool."""
    return None if value is None else bool(value)


# --------------------------------------------------------------------- role observation


def _credential_posture(engine: Engine, *, can_login: bool) -> str:
    """Classify the role's STORED credential posture without exposing one byte of it.

    The shadow catalog (``pg_authid``) is superuser-readable only. When this connection cannot
    read it the posture is ``unobservable`` — which is NOT compatible, so the role can never be
    classified ``exact`` on an unprovable credential. It runs on its OWN short-lived connection so
    a permission error can never poison the observation transaction."""
    if not can_login:
        return POSTURE_NOLOGIN
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(_SQL_CREDENTIAL_POSTURE), {"r": ENROLLMENT_SIGNER_DB_ROLE}
            ).one_or_none()
    except Exception:  # any fault here is unprovable, never a proven posture
        return POSTURE_UNOBSERVABLE
    if row is None:
        return POSTURE_UNOBSERVABLE
    if not bool(row[0]):
        return POSTURE_NO_PASSWORD
    return POSTURE_SCRAM_LOGIN if bool(row[1]) else POSTURE_NONSCRAM_LOGIN


def classify_role(
    *,
    attributes: dict[str, bool],
    privileges: dict[str, Any],
    member_of: int,
    members: int,
    owned: int,
    posture: str,
) -> str:
    """``exact`` ONLY when the observed role matches the reviewed least-privilege contract in EVERY
    dimension: the closed attribute set, the exact privilege posture, no membership in either
    direction, no owned object, and a provably compatible SCRAM LOGIN credential. Anything else —
    including an UNOBSERVABLE credential — is ``drifted``: exactness is never assumed."""
    return (
        STATE_EXACT
        if (
            attributes == _REVIEWED_ATTRIBUTES
            and privileges == _REVIEWED_PRIVILEGES
            and member_of == 0
            and members == 0
            and owned == 0
            and posture == POSTURE_SCRAM_LOGIN
        )
        else STATE_DRIFTED
    )


def _observe_role(engine: Engine) -> _RoleFacts:
    """Observe the dedicated ``secp_enrollment_signer`` role EXACTLY: existence, the closed
    attribute set, direct memberships in BOTH directions, owned objects, and the complete
    schema/table/sequence/routine privilege posture. Read-only catalog SELECTs only."""
    role = ENROLLMENT_SIGNER_DB_ROLE
    with engine.connect() as conn:
        attributes_row = conn.execute(text(_SQL_ROLE_ATTRIBUTES), {"r": role}).one_or_none()
        if attributes_row is None:
            return _ABSENT_ROLE
        attributes = {
            "login": bool(attributes_row[0]),
            "superuser": bool(attributes_row[1]),
            "createrole": bool(attributes_row[2]),
            "createdb": bool(attributes_row[3]),
            "bypassrls": bool(attributes_row[4]),
            "inherit": bool(attributes_row[5]),
            "replication": bool(attributes_row[6]),
        }
        memberships = conn.execute(text(_SQL_ROLE_MEMBERSHIPS), {"r": role}).one()
        owned = _bounded(conn.execute(text(_SQL_ROLE_OWNED_OBJECTS), {"r": role}).scalar())
        schema_row = conn.execute(text(_SQL_SCHEMA_PRIVILEGES), {"r": role}).one()
        table_row = conn.execute(
            text(_SQL_TABLE_PRIVILEGES),
            {"r": role, "i": _IDENTITY_TABLE, "c": _RECEIPT_TABLE},
        ).one()
        others = _bounded(
            conn.execute(text(_SQL_OTHER_TABLE_READS), {"r": role, "i": _IDENTITY_TABLE}).scalar()
        )
        sequences = _bounded(conn.execute(text(_SQL_SEQUENCE_PRIVILEGES), {"r": role}).scalar())
        routines = _bounded(conn.execute(text(_SQL_ROUTINE_GRANTS), {"r": role}).scalar())
    privileges: dict[str, Any] = {
        "schema_usage": bool(schema_row[0]),
        "schema_create": bool(schema_row[1]),
        "identity_select": _flag(table_row[0]),
        "identity_insert": _flag(table_row[1]),
        "identity_update": _flag(table_row[2]),
        "identity_delete": _flag(table_row[3]),
        "receipt_any": _flag(table_row[4]),
        "other_tables_readable": others,
        "sequences_privileged": sequences,
        "routines_granted": routines,
    }
    posture = _credential_posture(engine, can_login=attributes["login"])
    member_of = _bounded(memberships[0])
    members = _bounded(memberships[1])
    compatible = posture == POSTURE_SCRAM_LOGIN
    return _RoleFacts(
        state=classify_role(
            attributes=attributes,
            privileges=privileges,
            member_of=member_of,
            members=members,
            owned=owned,
            posture=posture,
        ),
        present=True,
        attributes=attributes,
        posture=posture,
        compatible=compatible,
        member_of=member_of,
        members=members,
        owned=owned,
        privileges=privileges,
    )


# --------------------------------------------------------------------- identity observation

_IDENTITY_COLUMNS = (
    ControllerEnrollmentIdentity.id,
    ControllerEnrollmentIdentity.status,
    ControllerEnrollmentIdentity.verified,
    ControllerEnrollmentIdentity.activated_at,
    ControllerEnrollmentIdentity.controller_installation_id,
    ControllerEnrollmentIdentity.controller_key_id,
    ControllerEnrollmentIdentity.controller_trust_anchor_hex,
    ControllerEnrollmentIdentity.controller_origin,
    ControllerEnrollmentIdentity.release_digest,
    ControllerEnrollmentIdentity.management_identity_digest,
    ControllerEnrollmentIdentity.bootstrap_evidence_digest,
    ControllerEnrollmentIdentity.enrollment_key_proof_id,
)
_RECEIPT_COLUMNS = (
    ControllerIdentityActivationReceipt.operation_id,
    ControllerIdentityActivationReceipt.operation_schema,
    ControllerIdentityActivationReceipt.generation,
    ControllerIdentityActivationReceipt.resulting_activation_token,
    ControllerIdentityActivationReceipt.resulting_public_state_digest,
    ControllerIdentityActivationReceipt.receipt_json,
    ControllerIdentityActivationReceipt.receipt_digest,
    ControllerIdentityActivationReceipt.controller_installation_id,
    ControllerIdentityActivationReceipt.release_digest,
)

_ABSENT_IDENTITY = _IdentityFacts(
    state=STATE_ABSENT,
    rows=0,
    pk=None,
    public=None,
    token=None,
    status=None,
    verified=None,
    public_state_digest=None,
)


class _StoredReceipt(BaseModel):
    """The strict, closed shape of the stored canonical activation-receipt bytes (the exact contract
    ``activate_controller_identity_once`` writes). Any deviation is CORRUPT, never adopted."""

    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str
    candidate_digest: str
    resulting_row_id: str
    activation_token: str
    previous_active_row_id: str | None
    created: bool
    resulting_status: str
    resulting_public_state_digest: str


def _observe_identity(conn: Connection) -> _IdentityFacts:
    """Observe the authoritative ACTIVE controller enrollment identity. Zero rows is a proven
    absence; more than one is CONFLICTING (ambiguous, fatal); an active-but-unverified or
    wrong-status row is CORRUPT (the DB check constraints forbid it, so its presence means the
    invariant was bypassed)."""
    total = _bounded(
        conn.execute(
            select(func.count())
            .select_from(ControllerEnrollmentIdentity)
            .where(ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE)
        ).scalar()
    )
    if total == 0:
        return _ABSENT_IDENTITY
    if total > 1:
        return _IdentityFacts(
            state=STATE_CONFLICTING,
            rows=total,
            pk=None,
            public=None,
            token=None,
            status=None,
            verified=None,
            public_state_digest=None,
        )
    row = (
        conn.execute(
            select(*_IDENTITY_COLUMNS)
            .where(ControllerEnrollmentIdentity.status == CONTROLLER_IDENTITY_ACTIVE)
            .order_by(ControllerEnrollmentIdentity.id)
            .limit(1)
        )
        .mappings()
        .one()
    )
    public = {field: str(row[field]) for field in _IDENTITY_PUBLIC_FIELDS}
    digest = sha256_bytes(
        canonical_json({"resulting_row_id": str(row["id"]), **public}).encode("utf-8")
    )
    corrupt = (
        row["verified"] is not True
        or row["activated_at"] is None
        or str(row["status"]) != CONTROLLER_IDENTITY_ACTIVE
    )
    return _IdentityFacts(
        state=STATE_CORRUPT if corrupt else STATE_EXACT,
        rows=total,
        pk=row["id"],
        public=public,
        # the SAME activation-token rule the durable receipt records, so the two are comparable
        token=f"{row['id']}|{row['activated_at']}",
        status=str(row["status"]),
        verified=bool(row["verified"]),
        public_state_digest=digest,
    )


def _observe_activation_receipt(conn: Connection, identity: _IdentityFacts) -> _ReceiptFacts:
    """Observe the durable activation receipt bound to the ACTIVE identity — the authoritative
    source of the activation GENERATION — and prove it is coherent with the live row.

    ``absent`` means no durable receipt resulted in the current active row (an identity activated
    outside the reviewed one-shot); ``corrupt`` means a receipt exists but its digest, canonical
    bytes, closed shape, schema, generation, or its recorded binding to the live row do not hold."""
    rows = _bounded(
        conn.execute(select(func.count()).select_from(ControllerIdentityActivationReceipt)).scalar()
    )
    if identity.pk is None or identity.state != STATE_EXACT:
        return _ReceiptFacts(
            state=STATE_ABSENT, rows=rows, generation=None, operation_id=None, operation_schema=None
        )
    stored = (
        conn.execute(
            select(*_RECEIPT_COLUMNS)
            .where(ControllerIdentityActivationReceipt.resulting_row_id == identity.pk)
            .order_by(ControllerIdentityActivationReceipt.recorded_at.desc())
            .limit(1)
        )
        .mappings()
        .first()
    )
    if stored is None:
        return _ReceiptFacts(
            state=STATE_ABSENT, rows=rows, generation=None, operation_id=None, operation_schema=None
        )
    corrupt = _ReceiptFacts(
        state=STATE_CORRUPT, rows=rows, generation=None, operation_id=None, operation_schema=None
    )
    raw = str(stored["receipt_json"]).encode("utf-8")
    if sha256_bytes(raw) != str(stored["receipt_digest"]):
        return corrupt
    try:
        parsed = json.loads(raw)
    except ValueError:
        return corrupt
    if not isinstance(parsed, dict) or canonical_json(parsed).encode("utf-8") != raw:
        return corrupt
    try:
        receipt = _StoredReceipt.model_validate(parsed)
    except ValidationError:
        return corrupt
    generation = stored["generation"]
    if not isinstance(generation, int) or isinstance(generation, bool):
        return corrupt
    if generation < 0 or generation > _MAX_GENERATION:
        return corrupt
    if str(stored["operation_schema"]) != CONTROLLER_IDENTITY_ACTIVATION_SCHEMA:
        return corrupt
    if (
        receipt.resulting_row_id != str(identity.pk)
        or receipt.activation_token != str(stored["resulting_activation_token"])
        or receipt.resulting_public_state_digest != str(stored["resulting_public_state_digest"])
    ):
        return corrupt
    # the receipt must still bind the LIVE row: same activation token, same public-state digest, and
    # the same installation/release the identity carries.
    if identity.public is None:
        return corrupt
    if (
        receipt.activation_token != identity.token
        or receipt.resulting_public_state_digest != identity.public_state_digest
        or str(stored["controller_installation_id"])
        != identity.public["controller_installation_id"]
        or str(stored["release_digest"]) != identity.public["release_digest"]
    ):
        return corrupt
    return _ReceiptFacts(
        state=STATE_EXACT,
        rows=rows,
        generation=generation,
        operation_id=receipt.operation_id,
        operation_schema=str(stored["operation_schema"]),
    )


# --------------------------------------------------------------------- the canonical receipt


class _ObservationReceipt(BaseModel):
    """The strict, closed, flat observation receipt. Extra/missing fields, wrong types, and any
    value outside a closed vocabulary refuse — the one-shot never prints a receipt it cannot
    re-validate."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_id: Literal["secp.controller-finalization-db-state/v1"] = Field(alias="schema")
    role_name: Literal["secp_enrollment_signer"]
    role_present: bool
    active_identity_present: bool
    activation_generation: int | None = Field(default=None, ge=0, le=_MAX_GENERATION)
    observed_state: Literal["absent", "exact", "drifted", "conflicting", "corrupt"]
    role_state: Literal["absent", "exact", "drifted"]
    role_attr_login: bool | None
    role_attr_superuser: bool | None
    role_attr_createrole: bool | None
    role_attr_createdb: bool | None
    role_attr_bypassrls: bool | None
    role_attr_inherit: bool | None
    role_attr_replication: bool | None
    role_credential_posture: Literal[
        "absent", "nologin", "no_password", "scram_login", "nonscram_login", "unobservable"
    ]
    role_credential_compatible: bool
    role_member_of_count: int | None = Field(default=None, ge=0, le=_MAX_COUNT)
    role_members_count: int | None = Field(default=None, ge=0, le=_MAX_COUNT)
    role_owned_objects: int | None = Field(default=None, ge=0, le=_MAX_COUNT)
    role_priv_schema_usage: bool | None
    role_priv_schema_create: bool | None
    role_priv_identity_select: bool | None
    role_priv_identity_insert: bool | None
    role_priv_identity_update: bool | None
    role_priv_identity_delete: bool | None
    role_priv_receipt_any: bool | None
    role_priv_other_tables_readable: int | None = Field(default=None, ge=0, le=_MAX_COUNT)
    role_priv_sequences_privileged: int | None = Field(default=None, ge=0, le=_MAX_COUNT)
    role_priv_routines_granted: int | None = Field(default=None, ge=0, le=_MAX_COUNT)
    identity_state: Literal["absent", "exact", "conflicting", "corrupt"]
    identity_active_rows: int = Field(ge=0, le=_MAX_COUNT)
    identity_row_id: str | None = Field(default=None, max_length=64)
    identity_activation_token: str | None = Field(default=None, max_length=128)
    identity_status: str | None = Field(default=None, max_length=16)
    identity_verified: bool | None
    identity_controller_installation_id: str | None = Field(default=None, max_length=64)
    identity_controller_key_id: str | None = Field(default=None, max_length=80)
    identity_controller_trust_anchor_hex: str | None = Field(default=None, max_length=64)
    identity_controller_origin: str | None = Field(default=None, max_length=269)
    identity_release_digest: str | None = Field(default=None, max_length=80)
    identity_management_identity_digest: str | None = Field(default=None, max_length=80)
    identity_bootstrap_evidence_digest: str | None = Field(default=None, max_length=80)
    identity_enrollment_key_proof_id: str | None = Field(default=None, max_length=120)
    identity_public_state_digest: str | None = Field(default=None, max_length=80)
    activation_receipt_state: Literal["absent", "exact", "corrupt"]
    activation_receipt_rows: int = Field(ge=0, le=_MAX_COUNT)
    activation_receipt_operation_id: str | None = Field(default=None, max_length=128)
    activation_receipt_schema: str | None = Field(default=None, max_length=64)


def _rollup(role: _RoleFacts, identity: _IdentityFacts, receipt: _ReceiptFacts) -> str:
    """The closed rollup: incoherence beats ambiguity beats drift beats a proven absence."""
    if identity.state == STATE_CORRUPT or receipt.state == STATE_CORRUPT:
        return STATE_CORRUPT
    if identity.state == STATE_CONFLICTING:
        return STATE_CONFLICTING
    if role.state == STATE_DRIFTED:
        return STATE_DRIFTED
    if identity.state == STATE_EXACT and receipt.state == STATE_ABSENT:
        return STATE_DRIFTED  # an active identity with no durable receipt is a coherence gap
    if role.state == STATE_ABSENT and identity.state == STATE_ABSENT:
        return STATE_ABSENT
    return STATE_EXACT


def _build_receipt(
    role: _RoleFacts, identity: _IdentityFacts, receipt: _ReceiptFacts
) -> dict[str, Any]:
    """Flatten the three observations into the single closed canonical receipt."""
    attributes = role.attributes or {}
    privileges = role.privileges or {}
    public = identity.public or {}
    return {
        "schema": OBSERVATION_SCHEMA,
        "role_name": ENROLLMENT_SIGNER_DB_ROLE,
        "role_present": role.present,
        "active_identity_present": identity.state != STATE_ABSENT,
        "activation_generation": receipt.generation,
        "observed_state": _rollup(role, identity, receipt),
        "role_state": role.state,
        "role_attr_login": attributes.get("login"),
        "role_attr_superuser": attributes.get("superuser"),
        "role_attr_createrole": attributes.get("createrole"),
        "role_attr_createdb": attributes.get("createdb"),
        "role_attr_bypassrls": attributes.get("bypassrls"),
        "role_attr_inherit": attributes.get("inherit"),
        "role_attr_replication": attributes.get("replication"),
        "role_credential_posture": role.posture,
        "role_credential_compatible": role.compatible,
        "role_member_of_count": role.member_of,
        "role_members_count": role.members,
        "role_owned_objects": role.owned,
        "role_priv_schema_usage": privileges.get("schema_usage"),
        "role_priv_schema_create": privileges.get("schema_create"),
        "role_priv_identity_select": privileges.get("identity_select"),
        "role_priv_identity_insert": privileges.get("identity_insert"),
        "role_priv_identity_update": privileges.get("identity_update"),
        "role_priv_identity_delete": privileges.get("identity_delete"),
        "role_priv_receipt_any": privileges.get("receipt_any"),
        "role_priv_other_tables_readable": privileges.get("other_tables_readable"),
        "role_priv_sequences_privileged": privileges.get("sequences_privileged"),
        "role_priv_routines_granted": privileges.get("routines_granted"),
        "identity_state": identity.state,
        "identity_active_rows": identity.rows,
        "identity_row_id": None if identity.pk is None else str(identity.pk),
        "identity_activation_token": identity.token,
        "identity_status": identity.status,
        "identity_verified": identity.verified,
        "identity_controller_installation_id": public.get("controller_installation_id"),
        "identity_controller_key_id": public.get("controller_key_id"),
        "identity_controller_trust_anchor_hex": public.get("controller_trust_anchor_hex"),
        "identity_controller_origin": public.get("controller_origin"),
        "identity_release_digest": public.get("release_digest"),
        "identity_management_identity_digest": public.get("management_identity_digest"),
        "identity_bootstrap_evidence_digest": public.get("bootstrap_evidence_digest"),
        "identity_enrollment_key_proof_id": public.get("enrollment_key_proof_id"),
        "identity_public_state_digest": identity.public_state_digest,
        "activation_receipt_state": receipt.state,
        "activation_receipt_rows": receipt.rows,
        "activation_receipt_operation_id": receipt.operation_id,
        "activation_receipt_schema": receipt.operation_schema,
    }


def compat_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    """The PURE projection of the five reviewed compatibility fields — values are copied verbatim
    from the receipt, never recomputed, so the projection can never disagree with it."""
    return {key: receipt[key] for key in COMPAT_FIELDS}


# --------------------------------------------------------------------- the one-shot


def run_observation(
    *, engine: Engine | None = None, observe_role: Any = None
) -> tuple[int, dict[str, Any]]:
    """Perform the complete READ-ONLY observation and return ``(exit_code, receipt_or_reason)``.

    Takes no input: there is no handoff, no argument, and no caller-selected object anywhere on the
    path. ``engine``/``observe_role`` are the same kind of verified test seams the sibling one-shots
    expose (``engine``/``read_handoff``/``session_factory``); production always uses the API's own
    engine and the code-owned catalog observation. Role observation is PostgreSQL-only, so a
    non-PostgreSQL engine refuses rather than guessing."""
    eng = engine if engine is not None else get_engine()
    if eng.dialect.name != "postgresql":
        return EXIT_UNSUPPORTED, {"reason_code": "finalization_observation_requires_postgresql"}
    reader = observe_role if observe_role is not None else _observe_role
    try:
        role = reader(eng)
        with eng.connect() as conn:  # a plain read-only connection: never begin()/commit()
            identity = _observe_identity(conn)
            receipt = _observe_activation_receipt(conn, identity)
    except Exception:  # bounded: never a raw exception, a DSN, or a partial state
        return EXIT_DB_ERROR, {"reason_code": "finalization_observation_db_error"}
    try:
        payload = _build_receipt(role, identity, receipt)
        _ObservationReceipt.model_validate(payload)
    except Exception:  # a receipt that fails its OWN strict schema is refused, never printed
        return EXIT_STATE_CORRUPT, {"reason_code": "finalization_observation_receipt_invalid"}
    if len(canonical_json(payload).encode("utf-8")) > _MAX_RECEIPT_BYTES:
        return EXIT_STATE_CORRUPT, {"reason_code": "finalization_observation_receipt_oversize"}
    observed = payload["observed_state"]
    if observed == STATE_CORRUPT:
        return EXIT_STATE_CORRUPT, payload
    if observed == STATE_CONFLICTING:
        return EXIT_CONFLICTING, payload
    return EXIT_OK, payload


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(
        prog="python -m secp_api.observe_controller_finalization_once",
        description=(
            "Observe the controller-enrollment finalization database state READ-ONLY (no argument "
            "selects the database, the role, the SQL, the tables, or the output format)."
        ),
    ).parse_args(argv)
    code, payload = run_observation()
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))  # noqa: T201
    if code == EXIT_OK and all(key in payload for key in COMPAT_FIELDS):
        # LAST line on success only: the reviewed management parser reads the final line and pins
        # exactly these five fields. On any refusal the final line is NOT a five-field document, so
        # a caller that ignores the exit code still fails closed.
        print(  # noqa: T201
            json.dumps(compat_projection(payload), sort_keys=True, separators=(",", ":"))
        )
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
