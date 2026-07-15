"""B1B-PR5A — PostgreSQL trigger + schema proofs for the plan-activation prerequisites (ADR-022).

SQLite never proves a PostgreSQL trigger. These run against a real PostgreSQL (CI) and are skipped
locally unless ``SECP_TEST_POSTGRES_URL`` is set. They prove, on the real engine (migration
``b3d9f1a7c2e5``):

* the reviewed activation dossier's bound facts are immutable and the row is undeletable — even by
  raw SQL that bypasses the ORM guard entirely;
* a raw ``UPDATE`` of ``execution_target.state_backend_secret_ref`` rotates ONLY the
  ``state_backend_plan`` binding, leaving the ``provider_plan_read`` binding untouched (the two
  credentials rotate independently);
* (amendment §1) a raw provider/state reference change stamps the new binding's ``binding_source``
  (``dedicated_operation`` vs ``legacy_generic``), a legacy ``secret_ref`` change cannot refresh a
  dedicated binding, and ``binding_source`` cannot be relabeled (immutable identity);
* (amendment §4) ``revocation_reason_code`` is set-once, settable only on the transition to
  ``revoked``, and constrained to the closed code set by a CHECK constraint (which fires even under
  replica mode — a CHECK is not a trigger);
* the enqueue-only plan-generation ATTEMPT record is append-only (every UPDATE and DELETE raises);
* each guard trigger is installed ``ENABLE ALWAYS`` so it fires even under
  ``session_replication_role = replica``.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")
# The current single Alembic head. A DELIBERATE DRIFT GUARD: every new migration must bump it, so a
# migration can never be added without a conscious decision.
_CURRENT_HEAD = "c4e2f9a1b7d3"
# This suite tests the PR5A plan-activation migration SPECIFICALLY (its dossier/authorization/
# attempt tables + triggers, including the append-only attempt trigger that B1B-PR5B later REPLACED
# with a transition guard). Its schema-under-test is therefore pinned to the exact PR5A revision,
# not the moving current head — so it keeps asserting PR5A behavior truthfully as migrations land.
_PR5A_REVISION = "b3d9f1a7c2e5"

pytestmark = pytest.mark.skipif(
    not PG_URL, reason="set SECP_TEST_POSTGRES_URL to run PostgreSQL plan-activation tests"
)

_PLAN_ACTIVATION_TABLES = (
    "real_lab_activation_dossier",
    "real_lab_activation_dossier_evidence",
    "real_plan_generation_authorization",
    "real_plan_generation_attempt",
)

# Each PR5A guard trigger and the table it protects. Each must be ``ENABLE ALWAYS`` (``tgenabled =
# 'A'``), never the default ENABLE ORIGIN (``'O'``): an ORIGIN trigger is silently skipped under
# ``session_replication_role = replica``, so a session able to set replica mode could rewrite an
# immutable dossier, erase an append-only attempt, or swap a credential reference without rotating
# its binding.
_GUARD_TRIGGERS = (
    ("real_lab_activation_dossier", "secp_real_lab_activation_dossier_immutable"),
    (
        "real_lab_activation_dossier_evidence",
        "secp_real_lab_activation_dossier_evidence_draft_only",
    ),
    (
        "real_plan_generation_authorization",
        "secp_real_plan_generation_authorization_immutable",
    ),
    ("real_plan_generation_attempt", "secp_real_plan_generation_attempt_immutable"),
    ("execution_target", "secp_execution_target_credential_rotation"),
)


def _now() -> datetime:
    return datetime.now(UTC)


def _cfg() -> Config:
    api_dir = Path(__file__).resolve().parents[1]
    cfg = Config(str(api_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_dir / "migrations"))
    cfg.set_main_option("sqlalchemy.url", str(PG_URL))
    return cfg


@pytest.fixture
def pg_engine():
    from secp_api.config import get_settings

    engine = create_engine(str(PG_URL), future=True)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    previous = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = str(PG_URL)
    get_settings.cache_clear()
    command.upgrade(_cfg(), _PR5A_REVISION)
    try:
        yield engine
    finally:
        if previous is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = previous
        get_settings.cache_clear()
        engine.dispose()


def _triggers(conn, table: str) -> dict[str, str]:
    """``{trigger_name: tgenabled}`` for one table's non-internal triggers.

    NOTE: ``to_regclass(:t)`` — never ``:t::regclass``. SQLAlchemy's ``text()`` bind-parameter regex
    refuses to bind a name immediately followed by ``:``, so ``:t::regclass`` reaches the driver as
    literal SQL and raises ``syntax error at or near ":"``.
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
    survives the commit, so a bare ``SET`` would stay in force when SQLAlchemy hands the same pooled
    connection to the next ``engine.begin()`` block. Replica mode disables the FK (RI) triggers,
    which is the whole point here; it does NOT disable the PR5A guards, which are ENABLE ALWAYS.
    """
    conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
    conn.execute(text(sql), params)


def _real_target(conn) -> tuple[uuid.UUID, uuid.UUID]:
    """A REAL organization + execution_target (no FK bypass).

    The rotation trigger INSERTs into ``credential_binding``, whose FKs point at both — so those two
    parents must genuinely exist for the trigger's own write to be a realistic proof.
    """
    org, target = uuid.uuid4(), uuid.uuid4()
    now = _now()
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
            " 'vault:fixture/a', 'active', '{}'::json, :now)"
        ),
        {"t": target, "org": org, "now": now},
    )
    return org, target


def _insert_binding(
    conn, org, target, purpose: str, version: int, status: str, *, source: str = "legacy_generic"
) -> None:
    conn.execute(
        text(
            "INSERT INTO credential_binding ("
            " id, organization_id, execution_target_id, purpose_class, binding_version,"
            " status, binding_source, created_at"
            ") VALUES (:id, :org, :t, :p, :v, :s, :src, :now)"
        ),
        {
            "id": uuid.uuid4(),
            "org": org,
            "t": target,
            "p": purpose,
            "v": version,
            "s": status,
            "src": source,
            "now": _now(),
        },
    )


def _bindings(conn, target: uuid.UUID, purpose: str) -> list[tuple[int, str]]:
    return [
        (r[0], r[1])
        for r in conn.execute(
            text(
                "SELECT binding_version, status FROM credential_binding "
                "WHERE execution_target_id = :t AND purpose_class = :p ORDER BY binding_version"
            ),
            {"t": target, "p": purpose},
        ).fetchall()
    ]


def _active_binding_source(conn, target: uuid.UUID, purpose: str) -> str | None:
    return conn.execute(
        text(
            "SELECT binding_source FROM credential_binding "
            "WHERE execution_target_id = :t AND purpose_class = :p AND status = 'active'"
        ),
        {"t": target, "p": purpose},
    ).scalar_one_or_none()


def _seed_dossier(conn, dossier_id: uuid.UUID) -> None:
    now = _now()
    _seed(
        conn,
        (
            "INSERT INTO real_lab_activation_dossier ("
            " id, organization_id, execution_target_id, target_onboarding_id, deployment_plan_id,"
            " environment_version_id, provisioning_manifest_id, toolchain_profile_id,"
            " toolchain_attestation_id, worker_identity_registration_id, worker_identity_version,"
            " provider_credential_binding_id, provider_credential_binding_version,"
            " state_credential_binding_id, state_credential_binding_version,"
            " environment_version_content_hash, deployment_plan_content_hash,"
            " provisioning_manifest_content_hash, target_config_hash, onboarding_boundary_hash,"
            " toolchain_profile_hash, toolchain_attestation_hash, toolchain_attestation_expires_at,"
            " state_namespace_hash, recovery_owner_proof, emergency_stop_owner_proof,"
            " operation_kind, dossier_revision, dossier_hash, evidence_fingerprint,"
            " authorization_expiry, status, revision, revocation_reason_code, created_at"
            ") VALUES ("
            " :id, :u, :u, :u, :u, :u, :u, :u, :u, :u, 1, :u, 1, :u, 1,"
            " 'h', 'h', 'h', 'h', 'h', 'h', 'ah', :later, 'ns', 'proof-r', 'proof-e',"
            " 'plan_secret_readiness', 1, 'sha256:real-dossier-hash', '', :later, 'draft', 0, '',"
            " :now)"
        ),
        {"id": dossier_id, "u": uuid.uuid4(), "now": now, "later": now + timedelta(hours=6)},
    )


def _seed_attempt(conn, attempt_id: uuid.UUID) -> None:
    now = _now()
    _seed(
        conn,
        (
            "INSERT INTO real_plan_generation_attempt ("
            " id, organization_id, execution_target_id, deployment_plan_id,"
            " provisioning_manifest_id, operation_fingerprint, status, refusal_reason_code,"
            " collected_at, created_at"
            ") VALUES (:id, :u, :u, :u, :u, 'fp', 'refused', 'not_ready', :now, :now)"
        ),
        {"id": attempt_id, "u": uuid.uuid4(), "now": now},
    )


def test_single_head():
    script = ScriptDirectory.from_config(_cfg())
    assert list(script.get_heads()) == [_CURRENT_HEAD]


def test_the_migration_creates_every_plan_activation_table(pg_engine):
    tables = set(inspect(pg_engine).get_table_names())
    for table in _PLAN_ACTIVATION_TABLES:
        assert table in tables, table


def test_the_activation_dossier_bound_facts_are_immutable_and_undeletable(pg_engine):
    """A raw UPDATE of a bound column, and a raw DELETE, must both raise — the reviewed dossier is a
    durable record whose upstream facts can never be rewritten and whose row can never be erased."""
    with pg_engine.begin() as conn:
        names = _triggers(conn, "real_lab_activation_dossier")
    assert "secp_real_lab_activation_dossier_immutable" in names, names

    dossier = uuid.uuid4()
    with pg_engine.begin() as conn:
        _seed_dossier(conn, dossier)

    # Mutating a BOUND fact (the opaque dossier hash) is refused.
    with pytest.raises(Exception, match="immutable|binding facts"):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE real_lab_activation_dossier SET dossier_hash = 'sha256:tampered' "
                    "WHERE id = :i"
                ),
                {"i": dossier},
            )
    # The row cannot be deleted.
    with pytest.raises(Exception, match="cannot be deleted"):
        with pg_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM real_lab_activation_dossier WHERE id = :i"), {"i": dossier}
            )

    # The row survives untouched.
    with pg_engine.begin() as conn:
        stored = conn.execute(
            text("SELECT dossier_hash, status FROM real_lab_activation_dossier WHERE id = :i"),
            {"i": dossier},
        ).one()
    assert stored == ("sha256:real-dossier-hash", "draft")


def test_a_raw_state_ref_update_rotates_only_the_state_binding(pg_engine):
    """B1B-PR5A §4: the two operation credentials rotate INDEPENDENTLY, even bypassing the ORM.

    A plain ``UPDATE execution_target SET state_backend_secret_ref = ...`` retires the active
    state-backend binding and issues its next version, while the provider binding is untouched.
    """
    with pg_engine.begin() as conn:
        org, target = _real_target(conn)
        _insert_binding(conn, org, target, "provider_plan_read", 1, "active")
        _insert_binding(conn, org, target, "state_backend_plan", 1, "active")

    # The raw swap of ONLY the state reference. No ORM, no service, no announcement.
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execution_target "
                "SET state_backend_secret_ref = 'env:SECP_PROVIDER_SECRET__STATE' WHERE id = :t"
            ),
            {"t": target},
        )

    with pg_engine.begin() as conn:
        # The state binding rotated (v1 retired, v2 active) ...
        assert _bindings(conn, target, "state_backend_plan") == [(1, "rotated"), (2, "active")]
        # ... and the provider binding is COMPLETELY untouched.
        assert _bindings(conn, target, "provider_plan_read") == [(1, "active")]


def test_the_plan_generation_attempt_is_append_only(pg_engine):
    """The enqueue-only attempt record is append-only workflow state: no UPDATE, no DELETE."""
    with pg_engine.begin() as conn:
        names = _triggers(conn, "real_plan_generation_attempt")
    assert "secp_real_plan_generation_attempt_immutable" in names, names

    attempt = uuid.uuid4()
    with pg_engine.begin() as conn:
        _seed_attempt(conn, attempt)

    for statement in (
        "UPDATE real_plan_generation_attempt SET status = 'requested' WHERE id = :i",
        "DELETE FROM real_plan_generation_attempt WHERE id = :i",
    ):
        with pytest.raises(Exception, match="immutable|append-only"):
            with pg_engine.begin() as conn:
                conn.execute(text(statement), {"i": attempt})

    with pg_engine.begin() as conn:
        status = conn.execute(
            text("SELECT status FROM real_plan_generation_attempt WHERE id = :i"), {"i": attempt}
        ).scalar_one()
    assert status == "refused"


def test_every_pr5a_guard_trigger_is_enable_always(pg_engine):
    """``tgenabled = 'A'`` — the guards fire even under ``session_replication_role = replica``."""
    with pg_engine.begin() as conn:
        for table, trigger in _GUARD_TRIGGERS:
            names = _triggers(conn, table)
            assert trigger in names, (table, names)
            assert names[trigger] == "A", (trigger, names[trigger])


def test_a_raw_provider_ref_update_creates_a_dedicated_binding(pg_engine):
    """Amendment §1: a raw ``UPDATE`` of the dedicated ``provider_plan_secret_ref`` rotates the
    provider binding and stamps the new binding ``dedicated_operation`` (a real-plan-eligible
    source), while the state binding is untouched."""
    with pg_engine.begin() as conn:
        org, target = _real_target(conn)
        _insert_binding(conn, org, target, "provider_plan_read", 1, "active")
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execution_target "
                "SET provider_plan_secret_ref = 'env:SECP_PROVIDER_SECRET__PROV' WHERE id = :t"
            ),
            {"t": target},
        )
    with pg_engine.begin() as conn:
        assert _bindings(conn, target, "provider_plan_read") == [(1, "rotated"), (2, "active")]
        assert _active_binding_source(conn, target, "provider_plan_read") == "dedicated_operation"


def test_a_raw_secret_ref_change_with_a_dedicated_provider_ref_does_not_rotate(pg_engine):
    """Amendment §1: a legacy ``secret_ref`` change can NEVER refresh a dedicated (real-plan)
    provider binding. With a dedicated provider reference set, changing ``secret_ref`` leaves the
    provider binding exactly as it was."""
    with pg_engine.begin() as conn:
        org, target = _real_target(conn)
        # Setting the dedicated provider reference creates the v1 dedicated binding via the trigger.
        conn.execute(
            text(
                "UPDATE execution_target "
                "SET provider_plan_secret_ref = 'env:SECP_PROVIDER_SECRET__PROV' WHERE id = :t"
            ),
            {"t": target},
        )
    with pg_engine.begin() as conn:
        assert _bindings(conn, target, "provider_plan_read") == [(1, "active")]
        assert _active_binding_source(conn, target, "provider_plan_read") == "dedicated_operation"
    # Now change ONLY the generic secret_ref while the dedicated provider ref remains set.
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE execution_target SET secret_ref = 'vault:fixture/rotated' WHERE id = :t"),
            {"t": target},
        )
    with pg_engine.begin() as conn:
        # UNCHANGED: still v1 active, still dedicated — a legacy ref cannot refresh it.
        assert _bindings(conn, target, "provider_plan_read") == [(1, "active")]
        assert _active_binding_source(conn, target, "provider_plan_read") == "dedicated_operation"


def test_a_raw_secret_ref_change_without_a_dedicated_ref_rotates_a_legacy_binding(pg_engine):
    """Amendment §1: with NO dedicated provider reference, a ``secret_ref`` change rotates the
    provider binding — and the new binding stays ``legacy_generic`` (never a real-plan source)."""
    with pg_engine.begin() as conn:
        org, target = _real_target(conn)
        _insert_binding(
            conn, org, target, "provider_plan_read", 1, "active", source="legacy_generic"
        )
    with pg_engine.begin() as conn:
        conn.execute(
            text("UPDATE execution_target SET secret_ref = 'vault:fixture/rotated' WHERE id = :t"),
            {"t": target},
        )
    with pg_engine.begin() as conn:
        assert _bindings(conn, target, "provider_plan_read") == [(1, "rotated"), (2, "active")]
        assert _active_binding_source(conn, target, "provider_plan_read") == "legacy_generic"


def test_a_credential_binding_source_cannot_be_relabeled(pg_engine):
    """Amendment §1: ``binding_source`` is part of the immutable identity — a raw ``UPDATE``
    relabeling a legacy binding as dedicated (which would let it satisfy a real-plan gate) raises,
    even under replica mode."""
    with pg_engine.begin() as conn:
        org, target = _real_target(conn)
        _insert_binding(
            conn, org, target, "provider_plan_read", 1, "active", source="legacy_generic"
        )
        binding_id = conn.execute(
            text(
                "SELECT id FROM credential_binding WHERE execution_target_id = :t "
                "AND purpose_class = 'provider_plan_read'"
            ),
            {"t": target},
        ).scalar_one()
    for replica in (False, True):
        with pytest.raises(Exception, match="identity is immutable"):
            with pg_engine.begin() as conn:
                if replica:
                    conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
                conn.execute(
                    text(
                        "UPDATE credential_binding SET binding_source = 'dedicated_operation' "
                        "WHERE id = :i"
                    ),
                    {"i": binding_id},
                )
    with pg_engine.begin() as conn:
        assert _active_binding_source(conn, target, "provider_plan_read") == "legacy_generic"


def test_dossier_revocation_reason_code_is_set_once(pg_engine):
    """Amendment §4: ``revocation_reason_code`` may be set only on the transition to revoked, and
    can never be altered or cleared afterward — even by raw SQL under replica mode."""
    dossier = uuid.uuid4()
    with pg_engine.begin() as conn:
        _seed_dossier(conn, dossier)

    # It cannot be set while the record is NOT revoked (still draft).
    with pytest.raises(Exception, match="only when revoking|set-once"):
        with pg_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE real_lab_activation_dossier SET revocation_reason_code = 'operator' "
                    "WHERE id = :i"
                ),
                {"i": dossier},
            )

    # A valid revocation sets it (status -> revoked + reason together).
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE real_lab_activation_dossier "
                "SET status = 'revoked', revocation_reason_code = 'operator' WHERE id = :i"
            ),
            {"i": dossier},
        )

    # Afterward it can never be altered or cleared (revision bump avoids the CAS-unrelated path).
    for new_reason in ("security_review", ""):
        with pytest.raises(Exception, match="set-once|terminal"):
            with pg_engine.begin() as conn:
                conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
                conn.execute(
                    text(
                        "UPDATE real_lab_activation_dossier "
                        "SET revocation_reason_code = :r WHERE id = :i"
                    ),
                    {"r": new_reason, "i": dossier},
                )
    with pg_engine.begin() as conn:
        reason = conn.execute(
            text("SELECT revocation_reason_code FROM real_lab_activation_dossier WHERE id = :i"),
            {"i": dossier},
        ).scalar_one()
    assert reason == "operator"


def test_a_free_text_revocation_reason_is_rejected_by_the_check_constraint(pg_engine):
    """Amendment §4: only a closed code (or the empty default) may be stored. A raw UPDATE flipping
    a draft dossier to revoked with arbitrary free text is rejected by the DB CHECK constraint —
    which fires even under replica mode (a CHECK is not a trigger)."""
    dossier = uuid.uuid4()
    with pg_engine.begin() as conn:
        _seed_dossier(conn, dossier)
    for replica in (False, True):
        with pytest.raises(Exception, match="revocation_reason_code|check constraint"):
            with pg_engine.begin() as conn:
                if replica:
                    conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
                conn.execute(
                    text(
                        "UPDATE real_lab_activation_dossier "
                        "SET status = 'revoked', revocation_reason_code = 'arbitrary free text' "
                        "WHERE id = :i"
                    ),
                    {"i": dossier},
                )
    # A closed code is accepted.
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE real_lab_activation_dossier "
                "SET status = 'revoked', revocation_reason_code = 'security_review' WHERE id = :i"
            ),
            {"i": dossier},
        )
    with pg_engine.begin() as conn:
        reason = conn.execute(
            text("SELECT revocation_reason_code FROM real_lab_activation_dossier WHERE id = :i"),
            {"i": dossier},
        ).scalar_one()
    assert reason == "security_review"


def test_a_raw_insert_cannot_preset_a_revocation_reason_on_a_non_revoked_row(pg_engine):
    """Amendment §4 (INSERT-path close-out): a CHECK forbids a non-empty revocation_reason_code on a
    non-revoked row, so even a hand-built raw INSERT of a draft dossier with a pre-set reason is
    rejected — even under replica mode (a CHECK is not a trigger)."""

    def _seed_draft_with_reason(conn, dossier_id: uuid.UUID, reason: str, status: str) -> None:
        now = _now()
        conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
        conn.execute(
            text(
                "INSERT INTO real_lab_activation_dossier ("
                " id, organization_id, execution_target_id, target_onboarding_id,"
                " deployment_plan_id, environment_version_id, provisioning_manifest_id,"
                " toolchain_profile_id, toolchain_attestation_id, worker_identity_registration_id,"
                " worker_identity_version, provider_credential_binding_id,"
                " provider_credential_binding_version, state_credential_binding_id,"
                " state_credential_binding_version, environment_version_content_hash,"
                " deployment_plan_content_hash, provisioning_manifest_content_hash,"
                " target_config_hash, onboarding_boundary_hash, toolchain_profile_hash,"
                " toolchain_attestation_hash, toolchain_attestation_expires_at,"
                " state_namespace_hash, recovery_owner_proof, emergency_stop_owner_proof,"
                " operation_kind, dossier_revision, dossier_hash, evidence_fingerprint,"
                " authorization_expiry, status, revision, revocation_reason_code, created_at"
                ") VALUES ("
                " :id, :u, :u, :u, :u, :u, :u, :u, :u, :u, 1, :u, 1, :u, 1, 'h', 'h', 'h', 'h',"
                " 'h', 'h', 'ah', :later, 'ns', 'proof-r', 'proof-e', 'plan_secret_readiness', 1,"
                " 'sha256:h', '', :later, :st, 0, :r, :now)"
            ),
            {
                "id": dossier_id,
                "u": uuid.uuid4(),
                "now": now,
                "later": now + timedelta(hours=6),
                "st": status,
                "r": reason,
            },
        )

    # A draft row with a pre-set reason is rejected by the requires-revoked CHECK.
    with pytest.raises(Exception, match="revocation_requires_revoked|check constraint"):
        with pg_engine.begin() as conn:
            _seed_draft_with_reason(conn, uuid.uuid4(), "operator", "draft")


def test_replica_mode_cannot_erase_an_append_only_attempt(pg_engine):
    """The append-only guard survives the replica-mode bypass (the SECP-B6 attack class)."""
    attempt = uuid.uuid4()
    with pg_engine.begin() as conn:
        _seed_attempt(conn, attempt)

    for statement in (
        "UPDATE real_plan_generation_attempt SET status = 'requested' WHERE id = :i",
        "DELETE FROM real_plan_generation_attempt WHERE id = :i",
    ):
        with pytest.raises(Exception, match="immutable|append-only"):
            with pg_engine.begin() as conn:
                conn.execute(text("SET LOCAL session_replication_role = 'replica'"))
                conn.execute(text(statement), {"i": attempt})

    with pg_engine.begin() as conn:
        status = conn.execute(
            text("SELECT status FROM real_plan_generation_attempt WHERE id = :i"), {"i": attempt}
        ).scalar_one()
    assert status == "refused"
