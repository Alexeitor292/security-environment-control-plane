"""Controller-finalization DB-state observation one-shot — offline behaviour (SECP-PR5H-B2 2b-3c-c).

Drives the fixed READ-ONLY one-shot (clean-room review 4803080223, R1/R3) through the per-test
in-memory database the ``engine`` fixture rebinds. The identity/receipt half of the observation is
portable, so it runs for real here; the ROLE half is PostgreSQL catalog SQL and is injected through
the same kind of verified seam the sibling suites use for their readers (the live catalog proof is
the zero-skip PostgreSQL fence).

Covers: the non-PostgreSQL refusal, a proven absence, an exact role + activated identity, the exact
public binding fields, privilege / attribute / membership / ownership / credential DRIFT, an active
identity with no durable receipt, CONFLICTING (>1) active rows, a CORRUPT stored receipt, the
canonical + bounded + closed receipt, the leakage assertions, the five-field management projection,
and the fixed-surface / plane-boundary / read-only guards.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from secp_api import activate_controller_identity_once as activation
from secp_api import observe_controller_finalization_once as mod
from secp_api.controller_identity_dev import build_test_verified_controller_identity
from secp_api.controller_identity_models import ControllerIdentityActivationReceipt
from secp_api.db import get_sessionmaker
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.enrollment_signer_role import ENROLLMENT_SIGNER_DB_ROLE
from sqlalchemy import create_engine, select, text

_T0 = "2026-07-28T00:00:00Z"
_NOW = datetime(2026, 7, 28, 0, 1, 0, tzinfo=UTC)

_A = build_test_verified_controller_identity()
_B = build_test_verified_controller_identity(
    controller_installation_id="controller-b0000001", controller_trust_anchor_hex="22" * 32
)


class _AsPostgres:
    """Present the hermetic test engine as a PostgreSQL one so the PORTABLE identity/receipt half
    of the one-shot runs for real offline. It is a dialect facade only: it forwards ``connect()``
    to the real engine and adds no behaviour of its own."""

    def __init__(self, engine: object) -> None:
        self._engine = engine
        self.dialect = SimpleNamespace(name="postgresql")

    def connect(self):  # type: ignore[no-untyped-def]
        return self._engine.connect()  # type: ignore[attr-defined]


def _role(**over: object) -> mod._RoleFacts:
    """Reviewed-exact role facts, optionally perturbed. The STATE is always recomputed by the
    module's own :func:`classify_role`, so a drift case can never be hand-labelled by the test."""
    attributes = {**mod._REVIEWED_ATTRIBUTES, **over.pop("attributes", {})}  # type: ignore[dict-item]
    privileges = {**mod._REVIEWED_PRIVILEGES, **over.pop("privileges", {})}  # type: ignore[dict-item]
    posture = str(over.pop("posture", mod.POSTURE_SCRAM_LOGIN))
    member_of = int(over.pop("member_of", 0))  # type: ignore[arg-type]
    members = int(over.pop("members", 0))  # type: ignore[arg-type]
    owned = int(over.pop("owned", 0))  # type: ignore[arg-type]
    assert not over, over
    return mod._RoleFacts(
        state=mod.classify_role(
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
        compatible=posture == mod.POSTURE_SCRAM_LOGIN,
        member_of=member_of,
        members=members,
        owned=owned,
        privileges=privileges,
    )


def _observe(engine, role: mod._RoleFacts | None = None):  # type: ignore[no-untyped-def]
    return mod.run_observation(
        engine=_AsPostgres(engine), observe_role=lambda _engine: role or _role()
    )


def _handoff(proof, *, operation_id: str = "op-1", **over: object) -> bytes:
    fields = {f: getattr(proof, f) for f in activation._IDENTITY_FIELDS}
    env: dict[str, object] = {
        "schema": activation.CONTROLLER_IDENTITY_ACTIVATION_SCHEMA,
        "operation_id": operation_id,
        "candidate_digest": sha256_bytes(canonical_json(dict(fields)).encode()),
        "expected_predecessor_row_id": None,
        "expected_predecessor_activation_token": None,
        "generation": 0,
        "handoff_created_at": _T0,
        **fields,
    }
    env.update(over)
    return canonical_json(env).encode()


def _activate(proof, **over: object) -> dict:
    """Seed a REAL controller identity + its durable activation receipt through the reviewed
    activation one-shot (never a hand-built row), so the observation sees genuine durable state."""
    code, receipt = activation.run_activation(
        read_handoff=lambda: _handoff(proof, **over),  # type: ignore[arg-type]
        session_factory=get_sessionmaker(),
        now=_NOW,
    )
    assert code == activation.EXIT_OK, receipt
    return receipt


# --------------------------------------------------------------------------- refusals + absence


def test_a_non_postgresql_engine_refuses_rather_than_guessing(engine):
    code, payload = mod.run_observation(engine=create_engine("sqlite+pysqlite:///:memory:"))
    assert code == mod.EXIT_UNSUPPORTED
    assert payload == {"reason_code": "finalization_observation_requires_postgresql"}


def test_absent_role_and_absent_identity_is_a_proven_absence(engine):
    code, payload = _observe(engine, mod._ABSENT_ROLE)
    assert code == mod.EXIT_OK
    assert payload["observed_state"] == "absent"
    assert payload["role_state"] == "absent" and payload["identity_state"] == "absent"
    assert payload["role_present"] is False
    assert payload["active_identity_present"] is False
    assert payload["activation_generation"] is None
    assert payload["role_credential_posture"] == "absent"
    # every role/identity detail is UNOBSERVED (None), never a fabricated False/0
    for key in ("role_attr_login", "role_owned_objects", "role_priv_identity_select"):
        assert payload[key] is None
    assert payload["identity_row_id"] is None and payload["identity_active_rows"] == 0


def test_an_absent_role_with_an_active_identity_is_reported_as_a_partial_install(engine):
    _activate(_A)
    code, payload = _observe(engine, mod._ABSENT_ROLE)
    assert code == mod.EXIT_OK
    assert payload["role_present"] is False and payload["active_identity_present"] is True
    assert payload["observed_state"] == "exact"  # each PRESENT object is exact; nothing is drifted
    assert payload["activation_generation"] == 0


def test_a_database_fault_fails_closed_with_a_bounded_reason(engine):
    def _explode(_engine):
        raise RuntimeError("connection refused for postgresql://secret@host/db")

    code, payload = mod.run_observation(engine=_AsPostgres(engine), observe_role=_explode)
    assert code == mod.EXIT_DB_ERROR
    assert payload == {"reason_code": "finalization_observation_db_error"}
    assert "postgresql" not in canonical_json(payload)  # no raw exception, no DSN


# --------------------------------------------------------------------------- the exact observation


def test_an_exact_role_and_activated_identity_observe_exact(engine):
    receipt = _activate(_A)
    code, payload = _observe(engine)
    assert code == mod.EXIT_OK
    assert payload["observed_state"] == "exact"
    assert payload["role_state"] == "exact" and payload["identity_state"] == "exact"
    assert payload["activation_receipt_state"] == "exact"
    assert payload["role_present"] is True and payload["active_identity_present"] is True
    assert payload["activation_generation"] == 0
    assert payload["activation_receipt_operation_id"] == "op-1"
    assert payload["activation_receipt_schema"] == activation.CONTROLLER_IDENTITY_ACTIVATION_SCHEMA
    assert payload["activation_receipt_rows"] == 1
    # the observed public-state digest + activation token are the receipt's own, byte-for-byte
    assert payload["identity_public_state_digest"] == receipt["resulting_public_state_digest"]
    assert payload["identity_activation_token"] == receipt["activation_token"]
    assert payload["identity_row_id"] == receipt["resulting_row_id"]


def test_the_exact_active_row_public_binding_fields_are_reported(engine):
    _activate(_A)
    _, payload = _observe(engine)
    for field in mod._IDENTITY_PUBLIC_FIELDS:
        assert payload[f"identity_{field}"] == getattr(_A, field)
    assert payload["identity_status"] == "active" and payload["identity_verified"] is True
    assert payload["identity_active_rows"] == 1


def test_the_generation_follows_the_durable_receipt_across_a_rotation(engine):
    first = _activate(_A)
    _activate(
        _B,
        operation_id="op-2",
        expected_predecessor_row_id=first["resulting_row_id"],
        expected_predecessor_activation_token=first["activation_token"],
        generation=1,
    )
    _, payload = _observe(engine)
    assert payload["activation_generation"] == 1  # the ACTIVE row's own durable generation
    assert payload["identity_controller_installation_id"] == _B.controller_installation_id
    assert payload["activation_receipt_rows"] == 2  # history is preserved, not counted as current


# --------------------------------------------------------------------------- drift


@pytest.mark.parametrize(
    "perturbation",
    [
        {"privileges": {"identity_insert": True}},  # a WRITE grant on the identity table
        {"privileges": {"identity_select": False}},  # the reviewed read was revoked
        {"privileges": {"receipt_any": True}},  # reach into the write-once receipt table
        {"privileges": {"schema_create": True}},  # CREATE on the public schema
        {"privileges": {"other_tables_readable": 3}},  # unrelated reads
        {"privileges": {"sequences_privileged": 1}},
        {"privileges": {"routines_granted": 1}},
        {"privileges": {"identity_select": None}},  # the identity table is not even present
        {"attributes": {"superuser": True}},
        {"attributes": {"createrole": True}},
        {"attributes": {"createdb": True}},
        {"attributes": {"bypassrls": True}},
        {"attributes": {"inherit": True}},
        {"attributes": {"replication": True}},
        {"attributes": {"login": False}},
        {"member_of": 1},  # a SET ROLE escalation path upward
        {"members": 1},  # ... and downward
        {"owned": 1},  # an owned object is a persistence foothold
        {"posture": "no_password"},
        {"posture": "nonscram_login"},
        {"posture": "unobservable"},  # an UNPROVABLE credential is never "exact"
    ],
)
def test_any_role_drift_is_detected_and_reported(engine, perturbation):
    code, payload = _observe(engine, _role(**perturbation))
    assert code == mod.EXIT_OK  # drift is REPORTED, not fatal: the role is unambiguously there
    assert payload["role_state"] == "drifted"
    assert payload["observed_state"] == "drifted"
    assert payload["role_present"] is True  # the management freshness gate still sees it


def test_the_privilege_drift_detail_is_carried_verbatim(engine):
    drifted = _role(privileges={"identity_insert": True, "sequences_privileged": 2})
    _, payload = _observe(engine, drifted)
    assert payload["role_priv_identity_insert"] is True
    assert payload["role_priv_sequences_privileged"] == 2
    assert payload["role_priv_identity_select"] is True  # the untouched dimensions stay exact


def test_an_active_identity_with_no_durable_receipt_is_drift_not_absence(engine):
    _activate(_A)
    with get_sessionmaker()() as session:
        session.execute(text("DELETE FROM controller_identity_activation_receipt"))
        session.commit()
    code, payload = _observe(engine)
    assert code == mod.EXIT_OK
    assert payload["observed_state"] == "drifted"
    assert payload["activation_receipt_state"] == "absent"
    assert payload["active_identity_present"] is True
    assert payload["activation_generation"] is None  # never guessed


# --------------------------------------------------------------------------- ambiguity + corruption


def _force_conflicting_active_rows(engine) -> None:
    """Manufacture the corrupted state the single-active UNIQUE + CHECK constraints exist to
    prevent, by suspending SQLite's check enforcement for one statement."""
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
        conn.exec_driver_sql(
            "UPDATE controller_enrollment_identity SET status = 'active' "
            "WHERE status = 'superseded'"
        )
        conn.commit()


def test_conflicting_active_identities_fail_closed(engine):
    first = _activate(_A)
    _activate(
        _B,
        operation_id="op-2",
        expected_predecessor_row_id=first["resulting_row_id"],
        expected_predecessor_activation_token=first["activation_token"],
        generation=1,
    )
    _force_conflicting_active_rows(engine)
    code, payload = _observe(engine)
    assert code == mod.EXIT_CONFLICTING
    assert payload["observed_state"] == "conflicting"
    assert payload["identity_state"] == "conflicting"
    assert payload["identity_active_rows"] == 2
    # an ambiguous identity publishes NO binding and NO generation
    assert payload["identity_row_id"] is None and payload["activation_generation"] is None


@pytest.mark.parametrize(
    "tamper",
    [
        lambda row: row.receipt_json.replace("active", "revoked"),  # digest no longer matches
        lambda row: json.dumps(json.loads(row.receipt_json), indent=2),  # noncanonical bytes
        lambda row: "{not json",
        lambda row: canonical_json({**json.loads(row.receipt_json), "extra": 1}),  # not the shape
    ],
)
def test_a_corrupt_stored_receipt_fails_closed(engine, tamper):
    _activate(_A)
    with get_sessionmaker()() as session:
        row = session.execute(select(ControllerIdentityActivationReceipt)).scalars().one()
        row.receipt_json = tamper(row)
        session.commit()
    code, payload = _observe(engine)
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload["observed_state"] == "corrupt"
    assert payload["activation_receipt_state"] == "corrupt"
    assert payload["activation_generation"] is None


def test_a_receipt_bound_to_a_different_public_state_is_corrupt(engine):
    """The stored receipt must still bind the LIVE row: a mutated identity binding (which the
    write-once receipt cannot follow) is incoherence, never a silently adopted new state."""
    _activate(_A)
    with get_sessionmaker()() as session:
        session.execute(
            text(
                "UPDATE controller_enrollment_identity "
                "SET controller_origin = 'https://moved.example.test'"
            )
        )
        session.commit()
    code, payload = _observe(engine)
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload["activation_receipt_state"] == "corrupt"


def test_an_active_but_unverified_row_is_corrupt(engine):
    _activate(_A)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
        conn.exec_driver_sql(
            "UPDATE controller_enrollment_identity SET verified = 0 WHERE status = 'active'"
        )
        conn.commit()
    code, payload = _observe(engine)
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload["identity_state"] == "corrupt"


# --------------------------------------------------------------------------- the receipt contract


def test_the_receipt_is_canonical_closed_and_bounded(engine):
    _activate(_A)
    _, payload = _observe(engine)
    encoded = canonical_json(payload)
    assert json.loads(encoded) == payload  # round-trips exactly
    assert canonical_json(json.loads(encoded)) == encoded  # canonical fixed point
    assert len(encoded.encode("utf-8")) <= mod._MAX_RECEIPT_BYTES
    assert set(payload) == set(mod._ObservationReceipt.model_fields) - {"schema_id"} | {"schema"}
    assert len(payload) == len(set(payload))  # no duplicate field by construction
    assert payload["schema"] == "secp.controller-finalization-db-state/v1"
    for value in payload.values():
        assert value is None or isinstance(value, bool | int | str)


def test_every_receipt_value_is_from_a_closed_vocabulary(engine):
    _activate(_A)
    _, payload = _observe(engine)
    assert payload["observed_state"] in {"absent", "exact", "drifted", "conflicting", "corrupt"}
    assert payload["role_state"] in {"absent", "exact", "drifted"}
    assert payload["identity_state"] in {"absent", "exact", "conflicting", "corrupt"}
    assert payload["activation_receipt_state"] in {"absent", "exact", "corrupt"}
    assert payload["role_credential_posture"] in {
        "absent",
        "nologin",
        "no_password",
        "scram_login",
        "nonscram_login",
        "unobservable",
    }


def test_a_receipt_that_fails_its_own_strict_schema_is_never_printed(engine, monkeypatch):
    monkeypatch.setattr(mod, "_build_receipt", lambda *_a, **_k: {"schema": "wrong", "extra": 1})
    code, payload = _observe(engine)
    assert code == mod.EXIT_STATE_CORRUPT
    assert payload == {"reason_code": "finalization_observation_receipt_invalid"}


def test_the_receipt_never_carries_credential_dsn_or_key_material(engine):
    _activate(_A)
    _, payload = _observe(engine)
    blob = canonical_json(payload).lower()
    for forbidden in (
        "password",
        "verifier",
        "scram-sha-256$",
        "rolpassword",
        "secret",
        "private key",
        "begin ",
        "postgresql",
        "postgres:",
        "psycopg",
        "sqlite",
        "dsn",
        "@",  # no credential-bearing URL authority anywhere
        "traceback",
        "error",
    ):
        assert forbidden not in blob, forbidden
    # the ONLY URL in the receipt is the identity's own PUBLIC https origin — never a DSN
    assert blob.count("://") == 1
    assert payload["identity_controller_origin"].startswith("https://")
    # the posture is a CLASSIFICATION word, never derived credential bytes
    assert payload["role_credential_posture"] == "scram_login"
    assert payload["role_credential_compatible"] is True


# --------------------------------------------------------------------------- management projection


def test_the_projection_is_exactly_the_five_reviewed_management_fields(engine):
    _activate(_A)
    _, payload = _observe(engine)
    projection = mod.compat_projection(payload)
    assert set(projection) == {
        "schema",
        "role_name",
        "role_present",
        "active_identity_present",
        "activation_generation",
    }
    assert projection["schema"] == "secp.controller-finalization-db-state/v1"
    assert projection["role_name"] == ENROLLMENT_SIGNER_DB_ROLE
    assert isinstance(projection["role_present"], bool)
    assert isinstance(projection["active_identity_present"], bool)
    assert projection["activation_generation"] is None or (
        type(projection["activation_generation"]) is int
        and 0 <= projection["activation_generation"] <= 1_000_000
    )
    # a PURE projection: every value is the receipt's own, never recomputed
    assert projection == {key: payload[key] for key in projection}


def test_an_absent_identity_never_reports_a_generation(engine):
    """The reviewed management parser treats a generation with no active identity as INCOHERENT and
    seals; the receipt must therefore never emit that pairing."""
    _, payload = _observe(engine, mod._ABSENT_ROLE)
    projection = mod.compat_projection(payload)
    assert projection["active_identity_present"] is False
    assert projection["activation_generation"] is None


def test_main_prints_the_receipt_then_the_projection_as_the_last_line(engine, monkeypatch, capsys):
    _activate(_A)
    _, payload = _observe(engine)
    monkeypatch.setattr(mod, "run_observation", lambda: (mod.EXIT_OK, payload))
    assert mod.main([]) == mod.EXIT_OK
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == payload and lines[0] == canonical_json(payload)
    last = json.loads(lines[-1])
    assert set(last) == set(mod.COMPAT_FIELDS)
    assert lines[-1] == canonical_json(last)  # byte-canonical, exactly as the parser requires


@pytest.mark.parametrize(
    "code", [mod.EXIT_CONFLICTING, mod.EXIT_STATE_CORRUPT, mod.EXIT_UNSUPPORTED, mod.EXIT_DB_ERROR]
)
def test_a_refusal_never_ends_with_a_five_field_line(engine, monkeypatch, capsys, code):
    """Defence in depth: a caller that ignored the exit code would still fail closed, because the
    LAST line of a refusal is never a parseable five-field state document."""
    monkeypatch.setattr(mod, "run_observation", lambda: (code, {"reason_code": "x"}))
    assert mod.main([]) == code
    last = capsys.readouterr().out.strip().splitlines()[-1]
    assert set(json.loads(last)) != set(mod.COMPAT_FIELDS)


def test_main_against_the_real_engine_refuses_the_non_postgresql_test_database(engine, capsys):
    assert mod.main([]) == mod.EXIT_UNSUPPORTED
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1  # no projection on a refusal
    assert json.loads(lines[0]) == {"reason_code": "finalization_observation_requires_postgresql"}


# --------------------------------------------------------------------------- fixed-surface guards


@pytest.mark.parametrize(
    "argv",
    [
        ["--role", "postgres"],
        ["--table", "users"],
        ["--sql", "SELECT 1"],
        ["--database-url", "postgresql://x"],
        ["--format", "yaml"],
        ["--handoff", "/tmp/x.json"],
        ["positional"],
    ],
)
def test_the_one_shot_accepts_no_caller_selected_argument(argv):
    with pytest.raises(SystemExit) as exc:
        mod.main(argv)
    assert exc.value.code == 2


def _tree() -> ast.Module:
    return ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))


def test_the_module_is_api_plane_and_never_imports_the_management_plane():
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("secp_management") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secp_management")
        elif isinstance(node, ast.Name):
            assert not node.id.startswith("secp_management")
        elif isinstance(node, ast.Attribute):
            assert not node.attr.startswith("secp_management")


def test_every_sql_statement_is_a_module_constant_never_built_at_runtime():
    calls = 0
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__", "getattr"}
            if node.func.id == "text":
                calls += 1
                assert len(node.args) == 1
                assert isinstance(node.args[0], ast.Name), ast.dump(node)
                assert node.args[0].id.startswith("_SQL_")
    assert calls >= 8  # every catalog statement goes through the constants
    constants = {n: v for n, v in vars(mod).items() if n.startswith("_SQL_")}
    assert len(constants) >= 8
    for name, statement in constants.items():
        assert isinstance(statement, str), name
        assert statement.startswith("SELECT "), name
        for verb in (
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "DROP ",
            "ALTER ",
            "CREATE ",
            "GRANT ",
            "REVOKE ",
            "TRUNCATE",
            ";",
        ):
            assert verb not in statement, (name, verb)


def test_the_module_has_no_mutation_capability_at_all():
    attributes = {n.attr for n in ast.walk(_tree()) if isinstance(n, ast.Attribute)}
    assert not (
        attributes
        & {
            "exec_driver_sql",
            "begin",
            "begin_nested",
            "commit",
            "rollback",
            "flush",
            "add",
            "add_all",
            "merge",
            "bulk_save_objects",
            "session_scope",
            "get_sessionmaker",
        }
    )
    imported: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert not (imported & {"subprocess", "os", "shutil", "socket", "ctypes", "pathlib"})


def test_the_observation_takes_no_handoff_and_no_input():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "read_hardened_fixed_handoff" not in source
    assert "/run/secp/handoff" not in source
    assert "HANDOFF_PATH" not in source
