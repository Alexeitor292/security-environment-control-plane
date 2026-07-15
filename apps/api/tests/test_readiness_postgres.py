"""B1B-PR4 — PostgreSQL constraint + immutability proofs (ADR-021 §Q).

SQLite never proves a PostgreSQL trigger or a partial unique index. These run against a real
PostgreSQL 16 (CI) and are skipped locally unless ``SECP_TEST_POSTGRES_URL`` is set.

They prove, on the real engine:

* the migration applies and downgrades truthfully (single head);
* readiness EVIDENCE is append-only (the trigger refuses every UPDATE and DELETE) — a prior
  successful record can never be mutated into failure or erased;
* the plan-secret authorization's binding facts are immutable, its approval/revocation facts are
  set-once, its terminal states are final, and only the closed transitions are allowed;
* the evidence rows are managed only while the authorization is draft;
* the partial unique idempotency indexes hold;
* no readiness table has a secret / reference / endpoint / state-path column.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL readiness tests"
)

_READINESS_TABLES = (
    "toolchain_attestation_record",
    "credential_binding",
    "remote_state_readiness_record",
    "plan_secret_readiness_authorization",
    "plan_secret_readiness_evidence",
    "plan_secret_resolution_lease",
    "plan_secret_readiness_record",
)

# Explicit revision pins for the migration-specific downgrade proof. The seven PR4 readiness tables
# are CREATED by ``_PR4_REVISION`` and REMOVED by downgrading below it to ``_PR3_REVISION``. These
# are pinned — never head-relative "-1" — so the proof stays correct as later migrations (PR5A and
# beyond) stack on top of PR4 and move the head. (Same migration-pinning principle as
# ``test_eligibility_preflight_postgres.py``.)
_PR3_REVISION = "c7e1a9b3d5f2"
_PR4_REVISION = "d6a1f3c8b902"

_FORBIDDEN_COLUMN_FRAGMENTS = (
    "secret_ref",
    "credential_reference_hash",
    "backend_binding_hash",  # B1B-PR4 §5: the confirmation oracle is GONE
    "backend_reference",
    "token",
    "password",
    "endpoint",
    "base_url",
    "bucket",
    "container",
    "object_key",
    "state_key",
    "state_path",
    "namespace_name",
    "access_key",
    "account_id",
    "response_body",
    "exception",
)


# Every PR4 guard trigger, and the table it protects. Each must be installed **ENABLE ALWAYS**
# (``tgenabled = 'A'``), never the default ENABLE ORIGIN (``'O'``): an ORIGIN trigger does not fire
# under ``session_replication_role = replica``, so a session able to set replica mode could erase
# immutable readiness evidence, rewrite an approved authorization, or swap a credential reference
# without rotating its binding. (Same class of bypass as the SECP-B6 admission guard.)
_GUARD_TRIGGERS = (
    ("toolchain_attestation_record", "secp_toolchain_attestation_record_immutable"),
    ("remote_state_readiness_record", "secp_remote_state_readiness_record_immutable"),
    ("plan_secret_readiness_record", "secp_plan_secret_readiness_record_immutable"),
    (
        "plan_secret_readiness_authorization",
        "secp_plan_secret_readiness_authorization_immutable",
    ),
    ("plan_secret_readiness_evidence", "secp_plan_secret_readiness_evidence_draft_only"),
    ("credential_binding", "secp_credential_binding_immutable"),
    ("execution_target", "secp_execution_target_credential_rotation"),
)


def _triggers(conn, table: str) -> dict[str, str]:
    """``{trigger_name: tgenabled}`` for one table's non-internal triggers.

    NOTE: ``to_regclass(:t)`` — never ``:t::regclass``. SQLAlchemy's ``text()`` bind-parameter regex
    refuses to bind a name that is immediately followed by ``:``, so ``:t::regclass`` reaches the
    driver as literal SQL and raises ``syntax error at or near ":"``.
    """
    return {
        r[0]: r[1]
        for r in conn.execute(
            text(
                "SELECT tgname, tgenabled FROM pg_trigger "
                "WHERE tgrelid = to_regclass(:t) AND NOT tgisinternal"
            ),
            {"t": table},
        ).fetchall()
    }


def _seed(conn, sql: str, params: dict) -> None:
    """Insert a probe row WITHOUT its full FK parent chain.

    ``SET LOCAL`` — never a bare ``SET``: ``session_replication_role`` is a SESSION-level GUC that
    SURVIVES the commit, so a bare ``SET`` stays in force when SQLAlchemy hands the same pooled
    connection to the next ``engine.begin()`` block — silently disabling every ORIGIN trigger for
    the rest of the test. ``SET LOCAL`` is confined to this transaction.

    Replica mode disables the FK (RI) triggers, which is the whole point here; it does NOT disable
    the PR4 guards, which are ENABLE ALWAYS.
    """
    conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
    conn.execute(text(sql), params)


def _real_target(conn, secret_ref: str | None = "vault:fixture/a") -> tuple[uuid.UUID, uuid.UUID]:
    """A REAL organization + execution_target (no FK bypass).

    The rotation trigger INSERTs into ``credential_binding``, whose FKs point at both — so those two
    parents must genuinely exist for the trigger's own write to be a realistic proof.
    """
    org, target = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(UTC)
    conn.execute(
        text(
            "INSERT INTO organization (id, name, slug, created_at) VALUES (:id, 'Org', :slug, :now)"
        ),
        {"id": org, "slug": f"org-{org.hex[:10]}", "now": now},
    )
    conn.execute(
        text(
            "INSERT INTO execution_target ("
            " id, organization_id, display_name, plugin_name, config, config_hash,"
            " secret_ref, status, scope_policy, created_at"
            ") VALUES ("
            " :t, :org, 'lab', 'proxmox', '{}'::json, 'h',"
            " :ref, 'active', '{}'::json, :now)"
        ),
        {"t": target, "org": org, "ref": secret_ref, "now": now},
    )
    return org, target


def _bindings(conn, target: uuid.UUID) -> list[tuple[int, str]]:
    return [
        (r[0], r[1])
        for r in conn.execute(
            text(
                "SELECT binding_version, status FROM credential_binding "
                "WHERE execution_target_id = :t ORDER BY binding_version"
            ),
            {"t": target},
        ).fetchall()
    ]


def _alembic_config() -> Config:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    cfg = Config(os.path.join(root, "apps", "api", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(root, "apps", "api", "migrations"))
    cfg.set_main_option("sqlalchemy.url", PG_URL or "")
    return cfg


@pytest.fixture
def pg_engine():
    from secp_api.config import get_settings

    engine = create_engine(PG_URL, future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = PG_URL or ""
    get_settings.cache_clear()
    command.upgrade(_alembic_config(), "head")
    try:
        yield engine
    finally:
        if previous is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous
        get_settings.cache_clear()
        engine.dispose()


def test_the_migration_creates_every_readiness_table_with_a_single_head(pg_engine):
    tables = set(inspect(pg_engine).get_table_names())
    for table in _READINESS_TABLES:
        assert table in tables, table

    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(_alembic_config()).get_heads()
    assert len(heads) == 1, heads


def test_no_readiness_table_has_a_secret_or_backend_locator_column(pg_engine):
    inspector = inspect(pg_engine)
    for table in _READINESS_TABLES:
        for column in inspector.get_columns(table):
            name = column["name"]
            if name in ("secret_purpose", "credential_reference_scheme"):
                continue  # a bounded PURPOSE class / a bounded SCHEME token — never a value
            for fragment in _FORBIDDEN_COLUMN_FRAGMENTS:
                assert fragment not in name, f"{table}.{name}"


def test_the_downgrade_is_truthful(pg_engine):
    # The fixture upgraded to the branch's CURRENT head (PR5A sits above PR4). Downgrade EXPLICITLY
    # to the pre-PR4 (PR3) revision — this removes PR5A first, then PR4 — so every PR4 readiness
    # table is genuinely gone. A head-relative "-1" would only remove PR5A now and truthfully leave
    # the PR4 tables in place, which is exactly the stale assumption this pinning replaces.
    command.downgrade(_alembic_config(), _PR3_REVISION)
    tables = set(inspect(pg_engine).get_table_names())
    for table in _READINESS_TABLES:
        assert table not in tables, table
    # Upgrading exactly to PR4 recreates every PR4 readiness table (its downgrade is truthful) ...
    command.upgrade(_alembic_config(), _PR4_REVISION)
    tables = set(inspect(pg_engine).get_table_names())
    for table in _READINESS_TABLES:
        assert table in tables, table
    # ... then restore the branch's current head schema so the fixture teardown is consistent.
    command.upgrade(_alembic_config(), "head")


# --- trigger behaviour ---------------------------------------------------------------------------


def test_readiness_evidence_is_append_only_on_postgresql(pg_engine):
    """The trigger refuses every UPDATE and DELETE on both readiness-evidence tables.

    A prior successful record can never be mutated into failure and can never be erased — even by
    raw SQL that bypasses the ORM guard entirely.
    """
    for table in ("remote_state_readiness_record", "plan_secret_readiness_record"):
        with pg_engine.begin() as conn:
            names = _triggers(conn, table)
        assert f"secp_{table}_immutable" in names, (table, names)

    # Prove the trigger FIRES, not merely that it exists: a raw UPDATE/DELETE must raise.
    org = uuid.uuid4()
    rec = uuid.uuid4()
    now = datetime.now(UTC)
    with pg_engine.begin() as conn:
        _seed(
            conn,
            (
                "INSERT INTO remote_state_readiness_record ("
                " id, organization_id, execution_target_id, target_onboarding_id,"
                " deployment_plan_id, provisioning_manifest_id, toolchain_profile_id,"
                " eligibility_preflight_id, toolchain_attestation_id,"
                " worker_identity_registration_id,"
                " worker_identity_version, provisioning_manifest_content_hash,"
                " target_config_hash, onboarding_boundary_hash, eligibility_evidence_hash,"
                " eligibility_policy_version, toolchain_profile_hash,"
                " toolchain_attestation_policy_version, toolchain_attestation_hash,"
                " activation_dossier_hash,"
                " state_backend_class, state_namespace_hash,"
                " capability_class, adapter_registration_id,"
                " operation_fingerprint, readiness_policy_version, adapter_contract_version,"
                " outcome, facets, reason_codes, collected_at, expires_at, evidence_hash,"
                " created_at"
                ") VALUES ("
                " :id, :org, :u, :u, :u, :u, :u, :u, :u, :u, 1, 'h', 'h', 'h', 'h', 'p', 'h', 'p',"
                " 'ah', 'd', 'remote', 'h', 'controlled_live', :u, 'fp', 'p', 'a', 'ready',"
                " '[]'::json, '[]'::json, :now, :later, 'eh', :now)"
            ),
            {
                "id": rec,
                "org": org,
                "u": uuid.uuid4(),
                "now": now,
                "later": now + timedelta(hours=6),
            },
        )

    with pytest.raises(Exception, match="immutable|append-only"):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE remote_state_readiness_record SET outcome = 'not_ready' WHERE id = :i"
                ),
                {"i": rec},
            )
    with pytest.raises(Exception, match="immutable|append-only"):
        with pg_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM remote_state_readiness_record WHERE id = :i"), {"i": rec}
            )

    # The row survives untouched.
    with pg_engine.begin() as conn:
        outcome = conn.execute(
            text("SELECT outcome FROM remote_state_readiness_record WHERE id = :i"), {"i": rec}
        ).scalar_one()
    assert outcome == "ready"


def test_every_readiness_guard_trigger_is_enable_always(pg_engine):
    """``tgenabled = 'A'`` — the guards fire even under ``session_replication_role = replica``.

    An ENABLE ORIGIN trigger (``'O'``, the PostgreSQL default) is SILENTLY SKIPPED in replica mode.
    Leaving the readiness guards at ORIGIN would mean any session able to set replica mode could
    erase immutable evidence, rewrite an approved authorization, or substitute a credential
    reference without rotating its binding — defeating the guarantees this PR exists to make.
    """
    with pg_engine.begin() as conn:
        for table, trigger in _GUARD_TRIGGERS:
            names = _triggers(conn, table)
            assert trigger in names, (table, names)
            assert names[trigger] == "A", (trigger, names[trigger])


def test_replica_mode_cannot_erase_immutable_readiness_evidence(pg_engine):
    """The append-only guard survives the replica-mode bypass (the SECP-B6 attack class)."""
    rec = uuid.uuid4()
    now = datetime.now(UTC)
    with pg_engine.begin() as conn:
        _seed(
            conn,
            (
                "INSERT INTO toolchain_attestation_record ("
                " id, organization_id, execution_target_id, toolchain_profile_id,"
                " toolchain_profile_hash, worker_identity_registration_id,"
                " worker_identity_version, verifier_policy_version, outcome,"
                " verified_facets, reason_codes, operation_fingerprint, collected_at,"
                " expires_at, evidence_hash, created_at"
                ") VALUES ("
                " :id, :u, :u, :u, 'h', :u, 1, 'p', 'attested',"
                " '[]'::json, '[]'::json, 'fp', :now, :later, 'eh', :now)"
            ),
            {"id": rec, "u": uuid.uuid4(), "now": now, "later": now + timedelta(hours=6)},
        )

    # An attacker who can set replica mode STILL cannot erase or rewrite the evidence.
    for statement in (
        "UPDATE toolchain_attestation_record SET outcome = 'failed' WHERE id = :i",
        "DELETE FROM toolchain_attestation_record WHERE id = :i",
    ):
        with pytest.raises(Exception, match="immutable|append-only"):
            with pg_engine.begin() as conn:
                conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
                conn.execute(text(statement), {"i": rec})

    with pg_engine.begin() as conn:
        outcome = conn.execute(
            text("SELECT outcome FROM toolchain_attestation_record WHERE id = :i"), {"i": rec}
        ).scalar_one()
    assert outcome == "attested"


def test_the_toolchain_attestation_record_is_append_only(pg_engine):
    """A DURABLE attestation is evidence: it can never be mutated into a pass, or erased."""
    with pg_engine.begin() as conn:
        names = _triggers(conn, "toolchain_attestation_record")
    assert "secp_toolchain_attestation_record_immutable" in names, names

    rec = uuid.uuid4()
    now = datetime.now(UTC)
    with pg_engine.begin() as conn:
        _seed(
            conn,
            (
                "INSERT INTO toolchain_attestation_record ("
                " id, organization_id, execution_target_id, toolchain_profile_id,"
                " toolchain_profile_hash, worker_identity_registration_id,"
                " worker_identity_version, verifier_policy_version, outcome,"
                " verified_facets, reason_codes, operation_fingerprint, collected_at,"
                " expires_at, evidence_hash, created_at"
                ") VALUES ("
                " :id, :u, :u, :u, 'h', :u, 1, 'p', 'failed',"
                " '[]'::json, '[\"executable_missing\"]'::json, 'fp', :now, :later, 'eh', :now)"
            ),
            {"id": rec, "u": uuid.uuid4(), "now": now, "later": now + timedelta(hours=6)},
        )

    # A FAILED attestation can never be flipped to ``attested``, and it can never be erased.
    with pytest.raises(Exception, match="immutable|append-only"):
        with pg_engine.begin() as conn:
            conn.execute(
                text("UPDATE toolchain_attestation_record SET outcome = 'attested' WHERE id = :i"),
                {"i": rec},
            )
    with pytest.raises(Exception, match="immutable|append-only"):
        with pg_engine.begin() as conn:
            conn.execute(text("DELETE FROM toolchain_attestation_record WHERE id = :i"), {"i": rec})

    with pg_engine.begin() as conn:
        outcome = conn.execute(
            text("SELECT outcome FROM toolchain_attestation_record WHERE id = :i"), {"i": rec}
        ).scalar_one()
    assert outcome == "failed"


def test_a_raw_secret_ref_update_still_rotates_the_credential_binding(pg_engine):
    """B1B-PR4 §2: a credential replacement can never be UNNOTICED — even bypassing the ORM.

    The ORM ``before_flush`` hook is the portable layer. This proves the PostgreSQL trigger closes
    the raw/Core path: a plain ``UPDATE execution_target SET secret_ref = ...`` executed with no ORM
    in sight still retires the active binding and issues the next version.
    """
    now = datetime.now(UTC)
    with pg_engine.begin() as conn:
        # REAL parent rows: the trigger's own INSERT into credential_binding must satisfy its FKs,
        # so bypassing them here would make the proof vacuous.
        org, target = _real_target(conn)
        conn.execute(
            text(
                "INSERT INTO credential_binding ("
                " id, organization_id, execution_target_id, purpose_class, binding_version,"
                " status, created_at"
                ") VALUES (:id, :org, :t, 'provider_plan_read', 1, 'active', :now)"
            ),
            {"id": uuid.uuid4(), "org": org, "t": target, "now": now},
        )

    # The raw swap. No ORM, no service, no announcement — and no replica-mode escape hatch either
    # (the trigger is ENABLE ALWAYS, so replica mode would not have helped an attacker anyway).
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE execution_target SET secret_ref = 'vault:fixture/b' WHERE id = :t"),
            {"t": target},
        )

    # The binding ROTATED: v1 retired, v2 active. Every prior authorization + readiness record that
    # folded v1 into its operation fingerprint is now invalid.
    with pg_engine.begin() as conn:
        assert _bindings(conn, target) == [(1, "rotated"), (2, "active")]

    # Even under replica mode the swap still rotates (ENABLE ALWAYS).
    with pg_engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
        conn.execute(
            text("UPDATE execution_target SET secret_ref = 'vault:fixture/c' WHERE id = :t"),
            {"t": target},
        )
    with pg_engine.begin() as conn:
        assert _bindings(conn, target) == [(1, "rotated"), (2, "rotated"), (3, "active")]

    # Clearing the reference entirely retires the binding and leaves NO active one.
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE execution_target SET secret_ref = NULL WHERE id = :t"), {"t": target}
        )
    with pg_engine.begin() as conn:
        assert _bindings(conn, target) == [
            (1, "rotated"),
            (2, "rotated"),
            (3, "rotated"),
        ]

    # An UPDATE that does NOT touch secret_ref must not rotate anything.
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE execution_target SET display_name = 'renamed' WHERE id = :t"),
            {"t": target},
        )
    with pg_engine.begin() as conn:
        assert len(_bindings(conn, target)) == 3

    # And no reference (or hash of one) is anywhere in the binding table.
    with pg_engine.begin() as conn:
        columns = {
            r[0]
            for r in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'credential_binding'"
                )
            ).fetchall()
        }
    assert not any("ref" in c or "hash" in c or "locator" in c for c in columns), columns


def test_a_credential_binding_identity_is_immutable_and_undeletable(pg_engine):
    binding = uuid.uuid4()
    now = datetime.now(UTC)
    with pg_engine.begin() as conn:
        org, target = _real_target(conn)
        conn.execute(
            text(
                "INSERT INTO credential_binding ("
                " id, organization_id, execution_target_id, purpose_class, binding_version,"
                " status, created_at"
                ") VALUES (:id, :org, :t, 'provider_plan_read', 1, 'active', :now)"
            ),
            {"id": binding, "org": org, "t": target, "now": now},
        )

    with pytest.raises(Exception, match="immutable"):
        with pg_engine.begin() as conn:
            conn.execute(
                text("UPDATE credential_binding SET binding_version = 99 WHERE id = :i"),
                {"i": binding},
            )
    with pytest.raises(Exception, match="cannot be deleted"):
        with pg_engine.begin() as conn:
            conn.execute(text("DELETE FROM credential_binding WHERE id = :i"), {"i": binding})

    # The closed lifecycle transition IS allowed (active -> rotated), and is then final.
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE credential_binding SET status = 'rotated' WHERE id = :i"), {"i": binding}
        )
    with pytest.raises(Exception, match="terminal status is final"):
        with pg_engine.begin() as conn:
            conn.execute(
                text("UPDATE credential_binding SET status = 'active' WHERE id = :i"),
                {"i": binding},
            )


def test_the_plan_secret_authorization_triggers_exist(pg_engine):
    for table, trigger in (
        (
            "plan_secret_readiness_authorization",
            "secp_plan_secret_readiness_authorization_immutable",
        ),
        ("plan_secret_readiness_evidence", "secp_plan_secret_readiness_evidence_draft_only"),
    ):
        with pg_engine.begin() as conn:
            names = _triggers(conn, table)
        assert trigger in names, (table, names)


def test_the_partial_unique_idempotency_indexes_exist(pg_engine):
    expected = {
        "toolchain_attestation_record": "uq_toolchain_attestation_operation",
        "credential_binding": "uq_credential_binding_active",
        "remote_state_readiness_record": "uq_remote_state_readiness_operation",
        "plan_secret_readiness_record": "uq_plan_secret_readiness_operation",
        "plan_secret_readiness_authorization": "uq_plan_secret_authorization_active",
    }
    inspector = inspect(pg_engine)
    for table, index in expected.items():
        names = {i["name"] for i in inspector.get_indexes(table)}
        assert index in names, (table, names)

    # The active-authorization slot is PARTIAL (draft/approved only).
    with pg_engine.begin() as conn:
        definition = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = :n"),
            {"n": "uq_plan_secret_authorization_active"},
        ).scalar_one()
    assert "WHERE" in definition.upper()
    assert "draft" in definition and "approved" in definition

    # Exactly ONE active credential binding per (target, purpose class) — a partial index too.
    with pg_engine.begin() as conn:
        binding_def = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = :n"),
            {"n": "uq_credential_binding_active"},
        ).scalar_one()
    assert "WHERE" in binding_def.upper()
    assert "active" in binding_def


def test_the_lease_uniqueness_key_is_enforced(pg_engine):
    inspector = inspect(pg_engine)
    constraints = inspector.get_unique_constraints("plan_secret_resolution_lease")
    names = {c["name"] for c in constraints}
    assert "uq_plan_secret_lease_operation" in names
    key = next(c for c in constraints if c["name"] == "uq_plan_secret_lease_operation")
    assert set(key["column_names"]) == {
        "authorization_id",
        "authorization_version",
        "operation_fingerprint",
    }
    # Worker identity is deliberately NOT part of the key.
    assert "worker_identity_id" not in key["column_names"]


# --- the SUPPORTED ORM rotation path, on the REAL engine ------------------------------------------


def test_the_orm_rotation_path_rotates_exactly_once_on_postgresql(pg_engine):
    """The ORM hook and the trigger must not BOTH rotate (B1B-PR4 §2).

    Both layers deliberately overlap — the ORM hook is the portable SQLite+PostgreSQL enforcement,
    the trigger closes the raw/Core path that bypasses the ORM entirely. On PostgreSQL they would
    otherwise BOTH fire on the same ``secret_ref`` change and issue two versions, colliding on
    ``uq_credential_binding_target_purpose_version``. The ORM path announces itself with a
    transaction-scoped ``SET LOCAL secp.credential_rotation = 'on'`` so the trigger stands down, and
    this proves it end to end on a real engine — nothing else exercises that GUC.
    """
    from secp_api.credential_binding import ensure_credential_binding
    from secp_api.models import ExecutionTarget, Organization
    from sqlalchemy.orm import Session as OrmSession

    with OrmSession(bind=pg_engine) as session:
        org = Organization(name="Org", slug=f"org-{uuid.uuid4().hex[:10]}")
        session.add(org)
        session.flush()
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="lab",
            plugin_name="proxmox",
            config={},
            config_hash="h",
            secret_ref="vault:fixture/a",
            scope_policy={},
        )
        session.add(target)
        session.flush()
        ensure_credential_binding(session, target)
        session.commit()
        target_id = target.id

        with pg_engine.begin() as conn:
            assert _bindings(conn, target_id) == [(1, "active")]

        # THE SUPPORTED PATH: replace the reference through the ORM.
        target.secret_ref = "vault:fixture/b"
        session.commit()

    # EXACTLY ONE rotation — not two. (A double rotation would have raised IntegrityError on the
    # unique key, or produced version 3.)
    with pg_engine.begin() as conn:
        assert _bindings(conn, target_id) == [(1, "rotated"), (2, "active")]

    # The announcement is transaction-scoped: a LATER raw UPDATE on the same pooled connection is
    # still caught and auto-rotated by the trigger.
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE execution_target SET secret_ref = 'vault:fixture/c' WHERE id = :t"),
            {"t": target_id},
        )
    with pg_engine.begin() as conn:
        assert _bindings(conn, target_id) == [(1, "rotated"), (2, "rotated"), (3, "active")]


def test_the_orm_registers_a_target_with_one_binding_and_no_reference_anywhere(pg_engine):
    """Registering a target creates exactly ONE opaque binding — and stores no reference/hash."""
    from secp_api.credential_binding import ensure_credential_binding
    from secp_api.models import ExecutionTarget, Organization
    from sqlalchemy.orm import Session as OrmSession

    with OrmSession(bind=pg_engine) as session:
        org = Organization(name="Org", slug=f"org-{uuid.uuid4().hex[:10]}")
        session.add(org)
        session.flush()
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="lab",
            plugin_name="proxmox",
            config={},
            config_hash="h",
            secret_ref="vault:secp-fake-lab/plan-read",
            scope_policy={},
        )
        session.add(target)
        session.flush()
        ensure_credential_binding(session, target)
        session.commit()
        target_id = target.id

    with pg_engine.begin() as conn:
        assert _bindings(conn, target_id) == [(1, "active")]
        row = (
            conn.execute(
                text("SELECT * FROM credential_binding WHERE execution_target_id = :t"),
                {"t": target_id},
            )
            .mappings()
            .one()
        )
    rendered = " ".join(f"{k}={v!r}" for k, v in row.items())
    reference = "vault:secp-fake-lab/plan-read"
    assert reference not in rendered
    assert hashlib.sha256(reference.encode()).hexdigest() not in rendered


def test_a_concurrent_session_never_disables_another_sessions_rotation_trigger(pg_engine):
    """Finding 11 regression: the ORM rotation announcement is PER-SESSION, never a module global.

    Two sessions run concurrently. Session A rotates a credential through the ORM (announcing
    ``secp.credential_rotation = 'on'`` for its OWN transaction). While A's flush is in flight,
    session B — doing unrelated work — must NOT be able to clear A's announcement. If the flag were
    a module global (the original defect), B's ``after_flush`` would wipe it, A would never issue
    the matching ``off``, and a LATER raw UPDATE in A's transaction would find the trigger stood
    down and swap a credential UNNOTICED. With per-session ``Session.info`` state, A's later raw
    UPDATE still rotates.
    """
    from secp_api.credential_binding import ensure_credential_binding
    from secp_api.models import ExecutionTarget, Organization
    from sqlalchemy.orm import Session as OrmSession

    def _new_target(session) -> uuid.UUID:
        org = Organization(name="Org", slug=f"org-{uuid.uuid4().hex[:10]}")
        session.add(org)
        session.flush()
        target = ExecutionTarget(
            organization_id=org.id,
            display_name="lab",
            plugin_name="proxmox",
            config={},
            config_hash="h",
            secret_ref="vault:fixture/a",
            scope_policy={},
        )
        session.add(target)
        session.flush()
        ensure_credential_binding(session, target)
        return target.id

    with OrmSession(bind=pg_engine) as a, OrmSession(bind=pg_engine) as b:
        a_target = _new_target(a)
        b_target = _new_target(b)
        a.commit()
        b.commit()

        # A rotates through the ORM and flushes (announcing 'on' for A's transaction only) ...
        a_row = a.get(ExecutionTarget, a_target)
        a_row.secret_ref = "vault:fixture/a2"
        a.flush()
        # ... and interleaved, B flushes unrelated work. A module-global flag would be cleared HERE.
        b_row = b.get(ExecutionTarget, b_target)
        b_row.display_name = "unrelated-change"
        b.flush()

        # A now issues a raw Core UPDATE on ITS secret_ref within the SAME transaction. The trigger
        # must still fire (B did not disable it), so this rotates too.
        a.execute(
            text("UPDATE execution_target SET secret_ref = 'vault:fixture/a3' WHERE id = :t"),
            {"t": a_target},
        )
        a.commit()
        b.commit()

    # A's target rotated THREE times (v1 initial, v2 ORM swap, v3 raw swap) — the raw swap was never
    # invisibly suppressed by B.
    with pg_engine.begin() as conn:
        assert _bindings(conn, a_target) == [(1, "rotated"), (2, "rotated"), (3, "active")]
