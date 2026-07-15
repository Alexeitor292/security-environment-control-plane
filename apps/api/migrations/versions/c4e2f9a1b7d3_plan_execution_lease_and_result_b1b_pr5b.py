"""plan-only execution lease + durable result + attempt lifecycle (B1B-PR5B, ADR-022 §6/§8)

Adds the two durable execution tables and expands the attempt lifecycle, all WITHOUT ever storing a
real deployment value:

* ``plan_generation_execution_lease`` — the CAS concurrency + attempt-budget control. A partial
  unique index (``operation_fingerprint WHERE status='active'``) is the CAS guard; a CHECK bounds
  ``attempts_used`` by the fixed ``attempt_budget``; an ``ENABLE ALWAYS`` trigger makes the binding
  facts immutable, guards status transitions (active → consumed/expired/recovery_required, terminal
  final), makes ``attempts_used`` monotonic, and makes ``result_id``/``consumed_at``/the closed
  ``recovery_reason_code`` set-once.
* ``real_plan_generation_result`` — the durable, IMMUTABLE, append-only redacted canonical change
  set. Exactly one successful result per ``(authorization_id, authorization_version,
  operation_fingerprint)``. An ``ENABLE ALWAYS`` trigger refuses every UPDATE and DELETE.
* the ``real_plan_generation_attempt`` append-only trigger is REPLACED with a tight transition guard
  so the attempt can carry the execution lifecycle (requested → running → completed/failed/
  recovery_required, plus the PR5A requested → refused edge) with immutable binding facts.

There is NO secret / secret-reference / secret-reference-hash / endpoint / backend-address / URL /
bucket / object-key / state-path / namespace-name / argv / cwd / executable-path / workspace-path /
mirror-path / environment-value / stdout / stderr / raw-diagnostic / binary-plan / raw-show-JSON
column. Every guard is installed ``ENABLE ALWAYS`` (it fires under ``session_replication_role``
``= replica``).

Revision ID: c4e2f9a1b7d3
Revises: b3d9f1a7c2e5
Create Date: 2026-07-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4e2f9a1b7d3"
down_revision: str | None = "b3d9f1a7c2e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIVE_LEASE = sa.text("status = 'active'")
_RUNNING_OR_COMPLETED = sa.text("status in ('running','completed')")
_REFUSED_ONLY = sa.text("status = 'refused'")

_LEASE_STATUSES = "'active', 'consumed', 'expired', 'recovery_required'"
_RESULT_STATUSES = "'pending_approval', 'no_changes', 'superseded'"
_ATTEMPT_STATUSES = "'requested', 'refused', 'running', 'completed', 'failed', 'recovery_required'"
_RECOVERY_CODES = (
    "'', 'cleanup_residue', 'uncertain_process_termination', 'commit_uncertain', 'internal'"
)


def upgrade() -> None:
    # --- the plan-only execution lease (CAS + attempt budget) ------------------------------------
    op.create_table(
        "plan_generation_execution_lease",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_expiry", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("environment_version_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("activation_dossier_id", sa.Uuid(), nullable=False),
        sa.Column("activation_dossier_hash", sa.String(length=120), nullable=False),
        sa.Column("activation_dossier_revision", sa.Integer(), nullable=False),
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=False),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("provider_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("provider_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("state_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("state_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("remote_state_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("remote_state_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_secret_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("plan_secret_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("lease_epoch", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=80), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_budget", sa.Integer(), nullable=False),
        sa.Column("attempts_used", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("recovery_reason_code", sa.String(length=80), nullable=False),
        sa.Column("result_id", sa.Uuid(), nullable=True),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["authorization_id"], ["real_plan_generation_authorization.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["activation_dossier_id"], ["real_lab_activation_dossier.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "authorization_id",
            "authorization_version",
            "operation_fingerprint",
            "lease_epoch",
            name="uq_plan_execution_lease_epoch",
        ),
        sa.CheckConstraint("attempt_budget > 0", name="ck_plan_execution_lease_budget_positive"),
        sa.CheckConstraint("attempts_used >= 0", name="ck_plan_execution_lease_attempts_nonneg"),
        sa.CheckConstraint(
            "attempts_used <= attempt_budget", name="ck_plan_execution_lease_attempts_bounded"
        ),
        sa.CheckConstraint(f"status IN ({_LEASE_STATUSES})", name="ck_plan_execution_lease_status"),
        sa.CheckConstraint(
            f"recovery_reason_code IN ({_RECOVERY_CODES})",
            name="ck_plan_execution_lease_recovery_reason_code",
        ),
    )
    with op.batch_alter_table("plan_generation_execution_lease", schema=None) as b:
        for col in (
            "organization_id",
            "authorization_id",
            "provisioning_manifest_id",
            "deployment_plan_id",
            "execution_target_id",
            "activation_dossier_id",
            "operation_fingerprint",
        ):
            b.create_index(b.f(f"ix_plan_generation_execution_lease_{col}"), [col])
        b.create_index(
            "uq_plan_execution_lease_active",
            ["operation_fingerprint"],
            unique=True,
            sqlite_where=_ACTIVE_LEASE,
            postgresql_where=_ACTIVE_LEASE,
        )

    # --- the durable, immutable, append-only canonical change-set result -------------------------
    op.create_table(
        "real_plan_generation_result",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("execution_lease_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_content_hash", sa.String(length=80), nullable=False),
        sa.Column("environment_version_id", sa.Uuid(), nullable=False),
        sa.Column("environment_version_content_hash", sa.String(length=80), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("activation_dossier_id", sa.Uuid(), nullable=False),
        sa.Column("activation_dossier_hash", sa.String(length=120), nullable=False),
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=False),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("fresh_attestation_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("provider_source", sa.String(length=120), nullable=False),
        sa.Column("provider_version", sa.String(length=60), nullable=False),
        sa.Column("provider_lockfile_hash", sa.String(length=80), nullable=False),
        sa.Column("provider_mirror_identity", sa.String(length=80), nullable=False),
        sa.Column("module_bundle_hash", sa.String(length=80), nullable=False),
        sa.Column("renderer_version", sa.String(length=120), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("provider_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("provider_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("state_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("state_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("remote_state_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("remote_state_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_secret_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("plan_secret_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("change_set", sa.JSON(), nullable=False),
        sa.Column("change_set_hash", sa.String(length=80), nullable=False),
        sa.Column("workspace_hash", sa.String(length=80), nullable=False),
        sa.Column("change_summary", sa.JSON(), nullable=False),
        sa.Column("change_policy_version", sa.String(length=120), nullable=False),
        sa.Column("change_policy_outcome", sa.String(length=40), nullable=False),
        sa.Column("plan_only_capability_contract_version", sa.String(length=120), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("change_set_approval_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["attempt_id"], ["real_plan_generation_attempt.id"]),
        sa.ForeignKeyConstraint(["execution_lease_id"], ["plan_generation_execution_lease.id"]),
        sa.ForeignKeyConstraint(["authorization_id"], ["real_plan_generation_authorization.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(
            ["change_set_approval_id"], ["provisioning_change_set_approval.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "authorization_id",
            "authorization_version",
            "operation_fingerprint",
            name="uq_plan_generation_result_operation",
        ),
        sa.CheckConstraint(
            f"status IN ({_RESULT_STATUSES})", name="ck_plan_generation_result_status"
        ),
    )
    with op.batch_alter_table("real_plan_generation_result", schema=None) as b:
        for col in (
            "organization_id",
            "attempt_id",
            "execution_lease_id",
            "authorization_id",
            "provisioning_manifest_id",
            "change_set_hash",
            "operation_fingerprint",
            "change_set_approval_id",
        ):
            b.create_index(b.f(f"ix_real_plan_generation_result_{col}"), [col])

    # --- expand the attempt lifecycle (closed-status CHECK + running/completed exactly-once) ------
    # The closed-status CHECK is added via ALTER on PostgreSQL (the only place raw INSERTs of a bogus
    # status must be refused at the DB level); SQLite cannot ALTER-ADD a constraint and relies on the
    # ORM ``EnumType`` for its (test-only) fixtures.
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE real_plan_generation_attempt ADD CONSTRAINT "
            f"ck_plan_generation_attempt_status CHECK (status IN ({_ATTEMPT_STATUSES}))"
        )
    with op.batch_alter_table("real_plan_generation_attempt", schema=None) as b:
        b.create_index(
            "uq_plan_generation_attempt_inflight",
            ["provisioning_manifest_id", "operation_fingerprint"],
            unique=True,
            sqlite_where=_RUNNING_OR_COMPLETED,
            postgresql_where=_RUNNING_OR_COMPLETED,
        )

    _install_pr5b_triggers()


def downgrade() -> None:
    _drop_pr5b_triggers()

    with op.batch_alter_table("real_plan_generation_attempt", schema=None) as b:
        b.drop_index("uq_plan_generation_attempt_inflight")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE real_plan_generation_attempt "
            "DROP CONSTRAINT IF EXISTS ck_plan_generation_attempt_status"
        )

    with op.batch_alter_table("real_plan_generation_result", schema=None) as b:
        for col in (
            "change_set_approval_id",
            "operation_fingerprint",
            "change_set_hash",
            "provisioning_manifest_id",
            "authorization_id",
            "execution_lease_id",
            "attempt_id",
            "organization_id",
        ):
            b.drop_index(b.f(f"ix_real_plan_generation_result_{col}"))
    op.drop_table("real_plan_generation_result")

    with op.batch_alter_table("plan_generation_execution_lease", schema=None) as b:
        b.drop_index("uq_plan_execution_lease_active")
        for col in (
            "operation_fingerprint",
            "activation_dossier_id",
            "execution_target_id",
            "deployment_plan_id",
            "provisioning_manifest_id",
            "authorization_id",
            "organization_id",
        ):
            b.drop_index(b.f(f"ix_plan_generation_execution_lease_{col}"))
    op.drop_table("plan_generation_execution_lease")

    # Restore the PR5A append-only attempt trigger EXACTLY as PR5A installed it.
    _restore_pr5a_attempt_trigger()


def _install_pr5b_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    # --- the result is fully immutable (append-only): no UPDATE, no DELETE -----------------------
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_real_plan_generation_result_immutable()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'real_plan_generation_result rows are immutable (append-only durable result)';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_real_plan_generation_result_immutable
        BEFORE UPDATE OR DELETE ON real_plan_generation_result
        FOR EACH ROW EXECUTE FUNCTION secp_real_plan_generation_result_immutable();
        """
    )
    op.execute(
        "ALTER TABLE real_plan_generation_result "
        "ENABLE ALWAYS TRIGGER secp_real_plan_generation_result_immutable"
    )

    # --- the lease: immutable bindings; guarded transitions; monotonic attempts; set-once ---------
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_plan_generation_execution_lease_guard()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'plan_generation_execution_lease rows cannot be deleted';
            END IF;
            -- Immutable binding facts + budget + epoch + acquisition.
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
               OR NEW.authorization_version IS DISTINCT FROM OLD.authorization_version
               OR NEW.authorization_expiry IS DISTINCT FROM OLD.authorization_expiry
               OR NEW.provisioning_manifest_id IS DISTINCT FROM OLD.provisioning_manifest_id
               OR NEW.provisioning_manifest_content_hash
                    IS DISTINCT FROM OLD.provisioning_manifest_content_hash
               OR NEW.deployment_plan_id IS DISTINCT FROM OLD.deployment_plan_id
               OR NEW.environment_version_id IS DISTINCT FROM OLD.environment_version_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.target_config_hash IS DISTINCT FROM OLD.target_config_hash
               OR NEW.target_onboarding_id IS DISTINCT FROM OLD.target_onboarding_id
               OR NEW.onboarding_boundary_hash IS DISTINCT FROM OLD.onboarding_boundary_hash
               OR NEW.activation_dossier_id IS DISTINCT FROM OLD.activation_dossier_id
               OR NEW.activation_dossier_hash IS DISTINCT FROM OLD.activation_dossier_hash
               OR NEW.activation_dossier_revision IS DISTINCT FROM OLD.activation_dossier_revision
               OR NEW.eligibility_preflight_id IS DISTINCT FROM OLD.eligibility_preflight_id
               OR NEW.eligibility_evidence_hash IS DISTINCT FROM OLD.eligibility_evidence_hash
               OR NEW.toolchain_profile_id IS DISTINCT FROM OLD.toolchain_profile_id
               OR NEW.toolchain_profile_hash IS DISTINCT FROM OLD.toolchain_profile_hash
               OR NEW.toolchain_attestation_id IS DISTINCT FROM OLD.toolchain_attestation_id
               OR NEW.toolchain_attestation_hash IS DISTINCT FROM OLD.toolchain_attestation_hash
               OR NEW.worker_identity_registration_id
                    IS DISTINCT FROM OLD.worker_identity_registration_id
               OR NEW.worker_identity_version IS DISTINCT FROM OLD.worker_identity_version
               OR NEW.provider_credential_binding_id
                    IS DISTINCT FROM OLD.provider_credential_binding_id
               OR NEW.provider_credential_binding_version
                    IS DISTINCT FROM OLD.provider_credential_binding_version
               OR NEW.state_credential_binding_id IS DISTINCT FROM OLD.state_credential_binding_id
               OR NEW.state_credential_binding_version
                    IS DISTINCT FROM OLD.state_credential_binding_version
               OR NEW.remote_state_readiness_id IS DISTINCT FROM OLD.remote_state_readiness_id
               OR NEW.remote_state_evidence_hash IS DISTINCT FROM OLD.remote_state_evidence_hash
               OR NEW.plan_secret_readiness_id IS DISTINCT FROM OLD.plan_secret_readiness_id
               OR NEW.plan_secret_evidence_hash IS DISTINCT FROM OLD.plan_secret_evidence_hash
               OR NEW.operation_fingerprint IS DISTINCT FROM OLD.operation_fingerprint
               OR NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch
               OR NEW.attempt_budget IS DISTINCT FROM OLD.attempt_budget
               OR NEW.acquired_at IS DISTINCT FROM OLD.acquired_at
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'plan_generation_execution_lease binding facts are immutable';
            END IF;

            -- attempts_used is monotonic non-decreasing (the CHECK bounds it by attempt_budget).
            IF NEW.attempts_used < OLD.attempts_used THEN
                RAISE EXCEPTION 'plan_generation_execution_lease attempts_used cannot decrease';
            END IF;

            -- A terminal lease is final.
            IF OLD.status IN ('consumed', 'expired', 'recovery_required')
               AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION 'plan_generation_execution_lease terminal status is final';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (OLD.status = 'active'
                        AND NEW.status IN ('consumed', 'expired', 'recovery_required')) THEN
                RAISE EXCEPTION
                    'plan_generation_execution_lease status transition is not allowed';
            END IF;

            -- result_id / consumed_at are set-once, and result_id only on consumption.
            IF OLD.result_id IS NOT NULL AND NEW.result_id IS DISTINCT FROM OLD.result_id THEN
                RAISE EXCEPTION 'plan_generation_execution_lease result_id is set-once';
            END IF;
            IF NEW.result_id IS NOT NULL AND OLD.result_id IS NULL
               AND NEW.status IS DISTINCT FROM 'consumed' THEN
                RAISE EXCEPTION
                    'plan_generation_execution_lease result_id may be set only on consumption';
            END IF;
            IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
                RAISE EXCEPTION 'plan_generation_execution_lease consumed_at is set-once';
            END IF;

            -- recovery_reason_code is set-once and only on the recovery_required transition.
            IF OLD.recovery_reason_code <> ''
               AND NEW.recovery_reason_code IS DISTINCT FROM OLD.recovery_reason_code THEN
                RAISE EXCEPTION
                    'plan_generation_execution_lease recovery_reason_code is set-once';
            END IF;
            IF OLD.recovery_reason_code = '' AND NEW.recovery_reason_code <> ''
               AND NEW.status IS DISTINCT FROM 'recovery_required' THEN
                RAISE EXCEPTION
                    'plan_generation_execution_lease recovery_reason_code needs recovery_required';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_plan_generation_execution_lease_guard
        BEFORE UPDATE OR DELETE ON plan_generation_execution_lease
        FOR EACH ROW EXECUTE FUNCTION secp_plan_generation_execution_lease_guard();
        """
    )
    op.execute(
        "ALTER TABLE plan_generation_execution_lease "
        "ENABLE ALWAYS TRIGGER secp_plan_generation_execution_lease_guard"
    )

    # --- REPLACE the PR5A append-only attempt trigger with a tight transition guard ---------------
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_plan_generation_attempt_immutable "
        "ON real_plan_generation_attempt"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_real_plan_generation_attempt_transition()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'real_plan_generation_attempt rows cannot be deleted';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.authorization_id IS DISTINCT FROM OLD.authorization_id
               OR NEW.authorization_version IS DISTINCT FROM OLD.authorization_version
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.deployment_plan_id IS DISTINCT FROM OLD.deployment_plan_id
               OR NEW.provisioning_manifest_id IS DISTINCT FROM OLD.provisioning_manifest_id
               OR NEW.target_onboarding_id IS DISTINCT FROM OLD.target_onboarding_id
               OR NEW.activation_dossier_id IS DISTINCT FROM OLD.activation_dossier_id
               OR NEW.operation_fingerprint IS DISTINCT FROM OLD.operation_fingerprint
               OR NEW.collected_at IS DISTINCT FROM OLD.collected_at
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'real_plan_generation_attempt binding facts are immutable';
            END IF;

            IF OLD.status IN ('completed', 'refused', 'failed', 'recovery_required')
               AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION 'real_plan_generation_attempt terminal status is final';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                    (OLD.status = 'requested'
                        AND NEW.status IN ('running','refused','failed','recovery_required'))
                 OR (OLD.status = 'running'
                        AND NEW.status IN ('completed','failed','recovery_required'))
               )
            THEN
                RAISE EXCEPTION 'real_plan_generation_attempt status transition is not allowed';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_real_plan_generation_attempt_transition
        BEFORE UPDATE OR DELETE ON real_plan_generation_attempt
        FOR EACH ROW EXECUTE FUNCTION secp_real_plan_generation_attempt_transition();
        """
    )
    op.execute(
        "ALTER TABLE real_plan_generation_attempt "
        "ENABLE ALWAYS TRIGGER secp_real_plan_generation_attempt_transition"
    )


def _drop_pr5b_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_plan_generation_attempt_transition "
        "ON real_plan_generation_attempt"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_real_plan_generation_attempt_transition")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_plan_generation_execution_lease_guard "
        "ON plan_generation_execution_lease"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_plan_generation_execution_lease_guard")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_plan_generation_result_immutable "
        "ON real_plan_generation_result"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_real_plan_generation_result_immutable")


def _restore_pr5a_attempt_trigger() -> None:
    """Downgrade: restore the PR5A append-only attempt trigger EXACTLY (no weaker guard)."""
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_real_plan_generation_attempt_immutable()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION
                'real_plan_generation_attempt rows are immutable (append-only workflow state)';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_real_plan_generation_attempt_immutable
        BEFORE UPDATE OR DELETE ON real_plan_generation_attempt
        FOR EACH ROW EXECUTE FUNCTION secp_real_plan_generation_attempt_immutable();
        """
    )
    op.execute(
        "ALTER TABLE real_plan_generation_attempt "
        "ENABLE ALWAYS TRIGGER secp_real_plan_generation_attempt_immutable"
    )
