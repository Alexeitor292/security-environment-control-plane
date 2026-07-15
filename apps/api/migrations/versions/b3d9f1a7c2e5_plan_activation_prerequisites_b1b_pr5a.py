"""plan activation prerequisites: dossier, plan-gen auth, attempt + op-specific creds (B1B-PR5A)

Adds the four durable tables of ADR-022 and closes operation-specific credential separation, all
WITHOUT ever storing a real deployment value:

* ``real_lab_activation_dossier`` / ``real_lab_activation_dossier_evidence`` — the human-reviewed
  activation-dossier lifecycle (draft → evidence → approved → revoked/expired/superseded). The
  detailed dossier stays deployment-local; only safe ids, opaque hashes, bounded categories, and
  opaque UUID proof ids + bounded issuer labels are persisted.
* ``real_plan_generation_authorization`` — the SEPARATE, dedicated-permission authorization to
  GENERATE a real plan (``plan_generation`` only). It authorizes no apply/destroy.
* ``real_plan_generation_attempt`` — the enqueue-only workflow attempt record. It never reaches
  ``completed`` in PR5A (the worker refuses at the sealed plan-only boundary).

It also adds the operation-specific credential-reference columns to ``execution_target``
(``provider_plan_secret_ref`` + ``state_backend_secret_ref``) and the credential-binding pin columns
to ``provisioning_manifest``, and GENERALISES the credential-rotation trigger so a raw ``UPDATE`` of
EITHER the provider reference OR the state reference rotates ONLY its matching opaque binding.

There is NO secret column, NO secret-reference-hash column, NO endpoint / URL / bucket / object-key
/ state-path / namespace-name column, and NO raw-JSON-only security binding. Credential identity
stays an OPAQUE binding id + version; dimensional review evidence is an opaque UUID proof id +
bounded issuer. Every guard is installed **ENABLE ALWAYS**, not ENABLE ORIGIN, so it fires even
under ``session_replication_role = replica`` (the same reasoning as the B1B-PR4 readiness guards).

Revision ID: b3d9f1a7c2e5
Revises: d6a1f3c8b902
Create Date: 2026-07-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3d9f1a7c2e5"
down_revision: str | None = "d6a1f3c8b902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIVE_DOSSIER = sa.text("status in ('draft','approved')")
_ACTIVE_PLAN_AUTHORIZATION = sa.text("status in ('draft','approved')")
_REFUSED_ONLY = sa.text("status = 'refused'")

# Amendment §4: the closed revocation-reason-code set (empty string = unset). Must stay in sync with
# ``secp_api.plan_activation_models.REVOCATION_REASON_CODES``. A DB-level CHECK — not a trigger —
# fires for every write including raw/Core UPDATEs and under ``session_replication_role=replica``.
_REVOCATION_REASON_CHECK = (
    "revocation_reason_code IN ('', 'operator', 'superseded', 'credential_rotated', "
    "'preflight_invalidated', 'readiness_drift', 'policy_change', 'security_review', 'expired')"
)
# The reason may be non-empty ONLY on a revoked row. A CHECK fires on INSERT + UPDATE, every path,
# and under replica — closing the INSERT-path caveat the UPDATE-only trigger/ORM guard left open.
_REVOCATION_REQUIRES_REVOKED = "revocation_reason_code = '' OR status = 'revoked'"


def upgrade() -> None:
    # --- operation-specific credential references on the target (B1B-PR5A §4) ---------------------
    # Opaque pointers, exactly like ``secret_ref``: never a secret, never hashed. The provider
    # binding prefers ``provider_plan_secret_ref`` (falling back to ``secret_ref`` for dev); the
    # state binding is sourced ONLY from ``state_backend_secret_ref``.
    with op.batch_alter_table("execution_target", schema=None) as b:
        b.add_column(sa.Column("provider_plan_secret_ref", sa.String(length=500), nullable=True))
        b.add_column(sa.Column("state_backend_secret_ref", sa.String(length=500), nullable=True))

    # --- credential-binding pins on the immutable manifest (B1B-PR5A §5) --------------------------
    # The three-way binding pins the OPAQUE credential id + version (never a reference) in the
    # immutable manifest for BOTH purposes; the worker requires exact agreement.
    with op.batch_alter_table("provisioning_manifest", schema=None) as b:
        b.add_column(sa.Column("provider_credential_binding_id", sa.Uuid(), nullable=True))
        b.add_column(
            sa.Column("provider_credential_binding_version", sa.Integer(), nullable=True)
        )
        b.add_column(sa.Column("state_credential_binding_id", sa.Uuid(), nullable=True))
        b.add_column(sa.Column("state_credential_binding_version", sa.Integer(), nullable=True))

    # --- the opaque credential-binding SOURCE class + backfill (B1B-PR5A amendment §1) ------------
    # ``binding_source`` records which authoritative reference sourced a binding. Existing PR4 rows
    # backfill to ``legacy_generic`` (the only source that existed then), so a pre-amendment binding
    # can NEVER be mistaken for a dedicated real-plan binding. It is part of the immutable identity.
    op.add_column(
        "credential_binding",
        sa.Column(
            "binding_source",
            sa.String(length=40),
            nullable=False,
            server_default="legacy_generic",
        ),
    )

    # --- the human-reviewed activation dossier (B1B-PR5A §3) --------------------------------------
    op.create_table(
        "real_lab_activation_dossier",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("environment_version_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("provider_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("provider_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("state_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("state_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("environment_version_content_hash", sa.String(length=80), nullable=False),
        sa.Column("deployment_plan_content_hash", sa.String(length=80), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state_namespace_hash", sa.String(length=80), nullable=False),
        # Downstream snapshots — bound if current at approval; combined readiness re-verifies.
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=True),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=True),
        sa.Column("remote_state_readiness_id", sa.Uuid(), nullable=True),
        sa.Column("remote_state_evidence_hash", sa.String(length=80), nullable=True),
        sa.Column("plan_secret_readiness_id", sa.Uuid(), nullable=True),
        sa.Column("plan_secret_evidence_hash", sa.String(length=80), nullable=True),
        # Reviewed operator responsibilities — OPAQUE proof ids only.
        sa.Column("recovery_owner_proof", sa.String(length=120), nullable=False),
        sa.Column("emergency_stop_owner_proof", sa.String(length=120), nullable=False),
        sa.Column("operation_kind", sa.String(length=40), nullable=False),
        sa.Column("dossier_revision", sa.Integer(), nullable=False),
        sa.Column("dossier_hash", sa.String(length=120), nullable=False),
        sa.Column("evidence_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("authorization_expiry", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_by", sa.Uuid(), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason_code", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["target_onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["environment_version_id"], ["environment_version.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.ForeignKeyConstraint(
            ["toolchain_attestation_id"], ["toolchain_attestation_record.id"]
        ),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.ForeignKeyConstraint(["provider_credential_binding_id"], ["credential_binding.id"]),
        sa.ForeignKeyConstraint(["state_credential_binding_id"], ["credential_binding.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provisioning_manifest_id",
            "dossier_revision",
            name="uq_activation_dossier_manifest_revision",
        ),
        # Amendment §4: a DB-level CHECK enforces the closed revocation-reason-code set for EVERY
        # write (raw/Core/replica — a CHECK is not a trigger). No free text can be stored.
        sa.CheckConstraint(
            _REVOCATION_REASON_CHECK, name="ck_activation_dossier_revocation_reason_code"
        ),
        sa.CheckConstraint(
            _REVOCATION_REQUIRES_REVOKED,
            name="ck_activation_dossier_revocation_requires_revoked",
        ),
    )
    with op.batch_alter_table("real_lab_activation_dossier", schema=None) as b:
        for col in (
            "organization_id",
            "execution_target_id",
            "target_onboarding_id",
            "deployment_plan_id",
            "environment_version_id",
            "provisioning_manifest_id",
            "toolchain_profile_id",
            "toolchain_attestation_id",
            "worker_identity_registration_id",
            "provider_credential_binding_id",
            "state_credential_binding_id",
            "state_namespace_hash",
            "dossier_hash",
        ):
            b.create_index(b.f(f"ix_real_lab_activation_dossier_{col}"), [col])
        b.create_index(
            "uq_activation_dossier_active",
            ["provisioning_manifest_id"],
            unique=True,
            sqlite_where=_ACTIVE_DOSSIER,
            postgresql_where=_ACTIVE_DOSSIER,
        )

    op.create_table(
        "real_lab_activation_dossier_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("dossier_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("proof_id", sa.String(length=120), nullable=False),
        sa.Column("issuer", sa.String(length=120), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["dossier_id"], ["real_lab_activation_dossier.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dossier_id", "kind", name="uq_activation_dossier_evidence_kind"),
    )
    with op.batch_alter_table("real_lab_activation_dossier_evidence", schema=None) as b:
        b.create_index(b.f("ix_real_lab_activation_dossier_evidence_dossier_id"), ["dossier_id"])

    # --- the SEPARATE plan-generation authorization (B1B-PR5A §7) ---------------------------------
    op.create_table(
        "real_plan_generation_authorization",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("activation_dossier_id", sa.Uuid(), nullable=False),
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        sa.Column("remote_state_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("plan_secret_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("provider_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("provider_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("state_credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("state_credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("remote_state_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("plan_secret_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("activation_dossier_hash", sa.String(length=120), nullable=False),
        sa.Column("dossier_evidence_fingerprint", sa.String(length=80), nullable=False),
        # ``purpose`` is server-forced to 'plan_generation'. Apply/destroy purposes are absent.
        sa.Column("purpose", sa.String(length=40), nullable=False),
        sa.Column("plan_only_capability_contract_version", sa.String(length=120), nullable=False),
        sa.Column("readiness_policy_version", sa.String(length=120), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("authorization_expiry", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by", sa.Uuid(), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason_code", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["target_onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.ForeignKeyConstraint(
            ["activation_dossier_id"], ["real_lab_activation_dossier.id"]
        ),
        sa.ForeignKeyConstraint(["eligibility_preflight_id"], ["target_preflight.id"]),
        sa.ForeignKeyConstraint(
            ["toolchain_attestation_id"], ["toolchain_attestation_record.id"]
        ),
        sa.ForeignKeyConstraint(
            ["remote_state_readiness_id"], ["remote_state_readiness_record.id"]
        ),
        sa.ForeignKeyConstraint(
            ["plan_secret_readiness_id"], ["plan_secret_readiness_record.id"]
        ),
        sa.ForeignKeyConstraint(["provider_credential_binding_id"], ["credential_binding.id"]),
        sa.ForeignKeyConstraint(["state_credential_binding_id"], ["credential_binding.id"]),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provisioning_manifest_id",
            "authorization_version",
            name="uq_plan_generation_authorization_manifest_version",
        ),
        sa.CheckConstraint(
            _REVOCATION_REASON_CHECK,
            name="ck_plan_generation_authorization_revocation_reason_code",
        ),
        sa.CheckConstraint(
            _REVOCATION_REQUIRES_REVOKED,
            name="ck_plan_generation_authorization_revocation_requires_revoked",
        ),
    )
    with op.batch_alter_table("real_plan_generation_authorization", schema=None) as b:
        for col in (
            "organization_id",
            "execution_target_id",
            "target_onboarding_id",
            "deployment_plan_id",
            "provisioning_manifest_id",
            "toolchain_profile_id",
            "activation_dossier_id",
            "eligibility_preflight_id",
            "toolchain_attestation_id",
            "remote_state_readiness_id",
            "plan_secret_readiness_id",
            "provider_credential_binding_id",
            "state_credential_binding_id",
            "worker_identity_registration_id",
            "operation_fingerprint",
        ):
            b.create_index(b.f(f"ix_real_plan_generation_authorization_{col}"), [col])
        b.create_index(
            "uq_plan_generation_authorization_active",
            ["provisioning_manifest_id"],
            unique=True,
            sqlite_where=_ACTIVE_PLAN_AUTHORIZATION,
            postgresql_where=_ACTIVE_PLAN_AUTHORIZATION,
        )

    # --- the enqueue-only workflow attempt record (B1B-PR5A §12) ----------------------------------
    op.create_table(
        "real_plan_generation_attempt",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=True),
        sa.Column("authorization_version", sa.Integer(), nullable=True),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=True),
        sa.Column("activation_dossier_id", sa.Uuid(), nullable=True),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("refusal_reason_code", sa.String(length=80), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(
            ["authorization_id"], ["real_plan_generation_authorization.id"]
        ),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(["target_onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(
            ["activation_dossier_id"], ["real_lab_activation_dossier.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("real_plan_generation_attempt", schema=None) as b:
        for col in (
            "organization_id",
            "authorization_id",
            "execution_target_id",
            "deployment_plan_id",
            "provisioning_manifest_id",
            "operation_fingerprint",
        ):
            b.create_index(b.f(f"ix_real_plan_generation_attempt_{col}"), [col])
        b.create_index(
            "uq_plan_generation_attempt_operation",
            ["provisioning_manifest_id", "operation_fingerprint"],
            unique=True,
            sqlite_where=_REFUSED_ONLY,
            postgresql_where=_REFUSED_ONLY,
        )

    _install_pr5a_triggers()


def downgrade() -> None:
    _drop_pr5a_triggers()

    with op.batch_alter_table("real_plan_generation_attempt", schema=None) as b:
        b.drop_index("uq_plan_generation_attempt_operation")
        for col in (
            "operation_fingerprint",
            "provisioning_manifest_id",
            "deployment_plan_id",
            "execution_target_id",
            "authorization_id",
            "organization_id",
        ):
            b.drop_index(b.f(f"ix_real_plan_generation_attempt_{col}"))
    op.drop_table("real_plan_generation_attempt")

    with op.batch_alter_table("real_plan_generation_authorization", schema=None) as b:
        b.drop_index("uq_plan_generation_authorization_active")
        for col in (
            "operation_fingerprint",
            "worker_identity_registration_id",
            "state_credential_binding_id",
            "provider_credential_binding_id",
            "plan_secret_readiness_id",
            "remote_state_readiness_id",
            "toolchain_attestation_id",
            "eligibility_preflight_id",
            "activation_dossier_id",
            "toolchain_profile_id",
            "provisioning_manifest_id",
            "deployment_plan_id",
            "target_onboarding_id",
            "execution_target_id",
            "organization_id",
        ):
            b.drop_index(b.f(f"ix_real_plan_generation_authorization_{col}"))
    op.drop_table("real_plan_generation_authorization")

    with op.batch_alter_table("real_lab_activation_dossier_evidence", schema=None) as b:
        b.drop_index(b.f("ix_real_lab_activation_dossier_evidence_dossier_id"))
    op.drop_table("real_lab_activation_dossier_evidence")

    with op.batch_alter_table("real_lab_activation_dossier", schema=None) as b:
        b.drop_index("uq_activation_dossier_active")
        for col in (
            "dossier_hash",
            "state_namespace_hash",
            "state_credential_binding_id",
            "provider_credential_binding_id",
            "worker_identity_registration_id",
            "toolchain_attestation_id",
            "toolchain_profile_id",
            "provisioning_manifest_id",
            "environment_version_id",
            "deployment_plan_id",
            "target_onboarding_id",
            "execution_target_id",
            "organization_id",
        ):
            b.drop_index(b.f(f"ix_real_lab_activation_dossier_{col}"))
    op.drop_table("real_lab_activation_dossier")

    with op.batch_alter_table("provisioning_manifest", schema=None) as b:
        b.drop_column("state_credential_binding_version")
        b.drop_column("state_credential_binding_id")
        b.drop_column("provider_credential_binding_version")
        b.drop_column("provider_credential_binding_id")

    with op.batch_alter_table("execution_target", schema=None) as b:
        b.drop_column("state_backend_secret_ref")
        b.drop_column("provider_plan_secret_ref")

    # Restore the B1B-PR4 single-purpose (provider-only) rotation + immutability functions, so a
    # downgrade leaves EXACTLY the shape PR4 installed — not a silently weaker guard.
    _restore_pr4_credential_rotation_trigger()
    op.drop_column("credential_binding", "binding_source")


def _install_pr5a_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    # --- the dossier: binding facts immutable; metadata set-once; closed transitions; no delete ---
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_real_lab_activation_dossier_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'real_lab_activation_dossier rows cannot be deleted';
            END IF;
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.target_onboarding_id IS DISTINCT FROM OLD.target_onboarding_id
               OR NEW.deployment_plan_id IS DISTINCT FROM OLD.deployment_plan_id
               OR NEW.environment_version_id IS DISTINCT FROM OLD.environment_version_id
               OR NEW.provisioning_manifest_id IS DISTINCT FROM OLD.provisioning_manifest_id
               OR NEW.toolchain_profile_id IS DISTINCT FROM OLD.toolchain_profile_id
               OR NEW.toolchain_attestation_id IS DISTINCT FROM OLD.toolchain_attestation_id
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
               OR NEW.environment_version_content_hash
                    IS DISTINCT FROM OLD.environment_version_content_hash
               OR NEW.deployment_plan_content_hash
                    IS DISTINCT FROM OLD.deployment_plan_content_hash
               OR NEW.provisioning_manifest_content_hash
                    IS DISTINCT FROM OLD.provisioning_manifest_content_hash
               OR NEW.target_config_hash IS DISTINCT FROM OLD.target_config_hash
               OR NEW.onboarding_boundary_hash IS DISTINCT FROM OLD.onboarding_boundary_hash
               OR NEW.toolchain_profile_hash IS DISTINCT FROM OLD.toolchain_profile_hash
               OR NEW.toolchain_attestation_hash IS DISTINCT FROM OLD.toolchain_attestation_hash
               OR NEW.state_namespace_hash IS DISTINCT FROM OLD.state_namespace_hash
               OR NEW.recovery_owner_proof IS DISTINCT FROM OLD.recovery_owner_proof
               OR NEW.emergency_stop_owner_proof IS DISTINCT FROM OLD.emergency_stop_owner_proof
               OR NEW.operation_kind IS DISTINCT FROM OLD.operation_kind
               OR NEW.dossier_revision IS DISTINCT FROM OLD.dossier_revision
               OR NEW.dossier_hash IS DISTINCT FROM OLD.dossier_hash
               OR NEW.authorization_expiry IS DISTINCT FROM OLD.authorization_expiry
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'real_lab_activation_dossier binding facts are immutable';
            END IF;

            IF OLD.status IN ('revoked', 'expired', 'superseded')
               AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION 'real_lab_activation_dossier terminal status is final';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                    (OLD.status = 'draft'
                        AND NEW.status IN ('approved','revoked','expired','superseded'))
                 OR (OLD.status = 'approved'
                        AND NEW.status IN ('revoked','expired','superseded'))
               )
            THEN
                RAISE EXCEPTION 'real_lab_activation_dossier status transition is not allowed';
            END IF;

            IF OLD.evidence_fingerprint <> ''
               AND NEW.evidence_fingerprint IS DISTINCT FROM OLD.evidence_fingerprint THEN
                RAISE EXCEPTION 'dossier evidence_fingerprint is set-once';
            END IF;
            IF OLD.approved_by IS NOT NULL
               AND NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
                RAISE EXCEPTION 'dossier approved_by is set-once';
            END IF;
            IF OLD.approved_at IS NOT NULL
               AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
                RAISE EXCEPTION 'dossier approved_at is set-once';
            END IF;
            IF OLD.revoked_by IS NOT NULL
               AND NEW.revoked_by IS DISTINCT FROM OLD.revoked_by THEN
                RAISE EXCEPTION 'dossier revoked_by is set-once';
            END IF;
            IF OLD.revoked_at IS NOT NULL
               AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                RAISE EXCEPTION 'dossier revoked_at is set-once';
            END IF;
            IF OLD.superseded_by IS NOT NULL
               AND NEW.superseded_by IS DISTINCT FROM OLD.superseded_by THEN
                RAISE EXCEPTION 'dossier superseded_by is set-once';
            END IF;
            IF OLD.superseded_at IS NOT NULL
               AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at THEN
                RAISE EXCEPTION 'dossier superseded_at is set-once';
            END IF;
            -- The revocation reason code is set-once: it may become non-empty ONLY on the
            -- transition to 'revoked', and can never be altered or cleared afterward.
            IF OLD.revocation_reason_code <> ''
               AND NEW.revocation_reason_code IS DISTINCT FROM OLD.revocation_reason_code THEN
                RAISE EXCEPTION 'dossier revocation_reason_code is set-once';
            END IF;
            IF OLD.revocation_reason_code = ''
               AND NEW.revocation_reason_code <> ''
               AND NEW.status IS DISTINCT FROM 'revoked' THEN
                RAISE EXCEPTION
                    'dossier revocation_reason_code may be set only when revoking';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_real_lab_activation_dossier_immutable
        BEFORE UPDATE OR DELETE ON real_lab_activation_dossier
        FOR EACH ROW EXECUTE FUNCTION secp_real_lab_activation_dossier_immutable();
        """
    )
    op.execute(
        "ALTER TABLE real_lab_activation_dossier "
        "ENABLE ALWAYS TRIGGER secp_real_lab_activation_dossier_immutable"
    )

    # --- dossier evidence is managed ONLY while the dossier is draft ------------------------------
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_real_lab_activation_dossier_evidence_draft_only()
        RETURNS trigger AS $$
        DECLARE
            parent_status text;
            parent_id uuid;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                parent_id := OLD.dossier_id;
            ELSE
                parent_id := NEW.dossier_id;
            END IF;
            SELECT status INTO parent_status
            FROM real_lab_activation_dossier WHERE id = parent_id;
            IF parent_status IS NOT NULL AND parent_status <> 'draft' THEN
                RAISE EXCEPTION
                    'real_lab_activation_dossier_evidence is managed only while draft';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_real_lab_activation_dossier_evidence_draft_only
        BEFORE INSERT OR UPDATE OR DELETE ON real_lab_activation_dossier_evidence
        FOR EACH ROW EXECUTE FUNCTION secp_real_lab_activation_dossier_evidence_draft_only();
        """
    )
    op.execute(
        "ALTER TABLE real_lab_activation_dossier_evidence "
        "ENABLE ALWAYS TRIGGER secp_real_lab_activation_dossier_evidence_draft_only"
    )

    # --- the plan-generation authorization: binding facts immutable; metadata set-once -----------
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_real_plan_generation_authorization_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'real_plan_generation_authorization rows cannot be deleted';
            END IF;
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.target_onboarding_id IS DISTINCT FROM OLD.target_onboarding_id
               OR NEW.deployment_plan_id IS DISTINCT FROM OLD.deployment_plan_id
               OR NEW.provisioning_manifest_id IS DISTINCT FROM OLD.provisioning_manifest_id
               OR NEW.toolchain_profile_id IS DISTINCT FROM OLD.toolchain_profile_id
               OR NEW.activation_dossier_id IS DISTINCT FROM OLD.activation_dossier_id
               OR NEW.eligibility_preflight_id IS DISTINCT FROM OLD.eligibility_preflight_id
               OR NEW.toolchain_attestation_id IS DISTINCT FROM OLD.toolchain_attestation_id
               OR NEW.remote_state_readiness_id IS DISTINCT FROM OLD.remote_state_readiness_id
               OR NEW.plan_secret_readiness_id IS DISTINCT FROM OLD.plan_secret_readiness_id
               OR NEW.provider_credential_binding_id
                    IS DISTINCT FROM OLD.provider_credential_binding_id
               OR NEW.provider_credential_binding_version
                    IS DISTINCT FROM OLD.provider_credential_binding_version
               OR NEW.state_credential_binding_id IS DISTINCT FROM OLD.state_credential_binding_id
               OR NEW.state_credential_binding_version
                    IS DISTINCT FROM OLD.state_credential_binding_version
               OR NEW.worker_identity_registration_id
                    IS DISTINCT FROM OLD.worker_identity_registration_id
               OR NEW.worker_identity_version IS DISTINCT FROM OLD.worker_identity_version
               OR NEW.provisioning_manifest_content_hash
                    IS DISTINCT FROM OLD.provisioning_manifest_content_hash
               OR NEW.target_config_hash IS DISTINCT FROM OLD.target_config_hash
               OR NEW.onboarding_boundary_hash IS DISTINCT FROM OLD.onboarding_boundary_hash
               OR NEW.eligibility_evidence_hash IS DISTINCT FROM OLD.eligibility_evidence_hash
               OR NEW.toolchain_profile_hash IS DISTINCT FROM OLD.toolchain_profile_hash
               OR NEW.toolchain_attestation_hash IS DISTINCT FROM OLD.toolchain_attestation_hash
               OR NEW.remote_state_evidence_hash IS DISTINCT FROM OLD.remote_state_evidence_hash
               OR NEW.plan_secret_evidence_hash IS DISTINCT FROM OLD.plan_secret_evidence_hash
               OR NEW.activation_dossier_hash IS DISTINCT FROM OLD.activation_dossier_hash
               OR NEW.dossier_evidence_fingerprint
                    IS DISTINCT FROM OLD.dossier_evidence_fingerprint
               OR NEW.purpose IS DISTINCT FROM OLD.purpose
               OR NEW.plan_only_capability_contract_version
                    IS DISTINCT FROM OLD.plan_only_capability_contract_version
               OR NEW.readiness_policy_version IS DISTINCT FROM OLD.readiness_policy_version
               OR NEW.operation_fingerprint IS DISTINCT FROM OLD.operation_fingerprint
               OR NEW.authorization_expiry IS DISTINCT FROM OLD.authorization_expiry
               OR NEW.authorization_version IS DISTINCT FROM OLD.authorization_version
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'real_plan_generation_authorization binding facts are immutable';
            END IF;

            IF OLD.status IN ('revoked', 'expired', 'consumed')
               AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION 'real_plan_generation_authorization terminal status is final';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                    (OLD.status = 'draft'    AND NEW.status IN ('approved','revoked','expired'))
                 OR (OLD.status = 'approved' AND NEW.status IN ('consumed','revoked','expired'))
               )
            THEN
                RAISE EXCEPTION
                    'real_plan_generation_authorization status transition is not allowed';
            END IF;

            IF OLD.evidence_fingerprint <> ''
               AND NEW.evidence_fingerprint IS DISTINCT FROM OLD.evidence_fingerprint THEN
                RAISE EXCEPTION 'plan-gen authorization evidence_fingerprint is set-once';
            END IF;
            IF OLD.approved_by IS NOT NULL
               AND NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
                RAISE EXCEPTION 'plan-gen authorization approved_by is set-once';
            END IF;
            IF OLD.approved_at IS NOT NULL
               AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
                RAISE EXCEPTION 'plan-gen authorization approved_at is set-once';
            END IF;
            IF OLD.revoked_by IS NOT NULL
               AND NEW.revoked_by IS DISTINCT FROM OLD.revoked_by THEN
                RAISE EXCEPTION 'plan-gen authorization revoked_by is set-once';
            END IF;
            IF OLD.revoked_at IS NOT NULL
               AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                RAISE EXCEPTION 'plan-gen authorization revoked_at is set-once';
            END IF;
            IF OLD.consumed_by IS NOT NULL
               AND NEW.consumed_by IS DISTINCT FROM OLD.consumed_by THEN
                RAISE EXCEPTION 'plan-gen authorization consumed_by is set-once';
            END IF;
            IF OLD.consumed_at IS NOT NULL
               AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
                RAISE EXCEPTION 'plan-gen authorization consumed_at is set-once';
            END IF;
            -- The revocation reason code is set-once: it may become non-empty ONLY on the
            -- transition to 'revoked', and can never be altered or cleared afterward.
            IF OLD.revocation_reason_code <> ''
               AND NEW.revocation_reason_code IS DISTINCT FROM OLD.revocation_reason_code THEN
                RAISE EXCEPTION 'plan-gen authorization revocation_reason_code is set-once';
            END IF;
            IF OLD.revocation_reason_code = ''
               AND NEW.revocation_reason_code <> ''
               AND NEW.status IS DISTINCT FROM 'revoked' THEN
                RAISE EXCEPTION
                    'plan-gen authorization revocation_reason_code may be set only when revoking';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_real_plan_generation_authorization_immutable
        BEFORE UPDATE OR DELETE ON real_plan_generation_authorization
        FOR EACH ROW EXECUTE FUNCTION secp_real_plan_generation_authorization_immutable();
        """
    )
    op.execute(
        "ALTER TABLE real_plan_generation_authorization "
        "ENABLE ALWAYS TRIGGER secp_real_plan_generation_authorization_immutable"
    )

    # --- the attempt record is append-only (no UPDATE, no DELETE) --------------------------------
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

    # --- GENERALISE the credential-rotation trigger to BOTH operation purposes (B1B-PR5A §1) ------
    # It rotates ONLY the matching binding, ONLY when that purpose's OWN source reference changes,
    # and records the new binding's SOURCE class:
    #   * provider_plan_read rotates when the DEDICATED ``provider_plan_secret_ref`` changes (which
    #     may flip the source class), OR when the generic ``secret_ref`` changes WHILE no dedicated
    #     reference is set. A ``secret_ref`` change while a dedicated reference is present does NOT
    #     rotate the (dedicated, real-plan) binding — a legacy reference can never refresh it.
    #   * state_backend_plan rotates ONLY when ``state_backend_secret_ref`` changes; it is always
    #     ``dedicated_operation``.
    # The supported ORM path announces itself with ``SET LOCAL secp.credential_rotation = 'on'`` so
    # the rotation is applied exactly once; a raw ``UPDATE`` bypassing the ORM is rotated here.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_execution_target_credential_rotation()
        RETURNS trigger AS $$
        DECLARE
            next_version integer;
            orm_handled boolean;
            provider_source text;
            provider_ref text;
        BEGIN
            orm_handled := coalesce(current_setting('secp.credential_rotation', true), '') = 'on';

            -- PROVIDER purpose: rotate on a dedicated-ref change, or a generic-ref change while no
            -- dedicated ref is set. A legacy ``secret_ref`` change never refreshes a dedicated
            -- (real-plan) binding.
            IF NOT orm_handled AND (
                    NEW.provider_plan_secret_ref IS DISTINCT FROM OLD.provider_plan_secret_ref
                 OR (NEW.secret_ref IS DISTINCT FROM OLD.secret_ref
                        AND NEW.provider_plan_secret_ref IS NULL)
               ) THEN
                UPDATE credential_binding
                   SET status = 'rotated', rotated_at = now()
                 WHERE execution_target_id = NEW.id
                   AND purpose_class = 'provider_plan_read'
                   AND status = 'active';
                provider_ref := coalesce(NEW.provider_plan_secret_ref, NEW.secret_ref);
                IF provider_ref IS NOT NULL THEN
                    IF NEW.provider_plan_secret_ref IS NOT NULL THEN
                        provider_source := 'dedicated_operation';
                    ELSE
                        provider_source := 'legacy_generic';
                    END IF;
                    SELECT coalesce(max(binding_version), 0) + 1 INTO next_version
                      FROM credential_binding
                     WHERE execution_target_id = NEW.id
                       AND purpose_class = 'provider_plan_read';
                    INSERT INTO credential_binding (
                        id, organization_id, execution_target_id, purpose_class, binding_version,
                        status, binding_source, created_at
                    ) VALUES (
                        gen_random_uuid(), NEW.organization_id, NEW.id, 'provider_plan_read',
                        next_version, 'active', provider_source, now()
                    );
                END IF;
            END IF;

            -- STATE purpose: rotate only on a state-reference change; always dedicated_operation.
            IF NOT orm_handled
               AND NEW.state_backend_secret_ref IS DISTINCT FROM OLD.state_backend_secret_ref THEN
                UPDATE credential_binding
                   SET status = 'rotated', rotated_at = now()
                 WHERE execution_target_id = NEW.id
                   AND purpose_class = 'state_backend_plan'
                   AND status = 'active';
                IF NEW.state_backend_secret_ref IS NOT NULL THEN
                    SELECT coalesce(max(binding_version), 0) + 1 INTO next_version
                      FROM credential_binding
                     WHERE execution_target_id = NEW.id
                       AND purpose_class = 'state_backend_plan';
                    INSERT INTO credential_binding (
                        id, organization_id, execution_target_id, purpose_class, binding_version,
                        status, binding_source, created_at
                    ) VALUES (
                        gen_random_uuid(), NEW.organization_id, NEW.id, 'state_backend_plan',
                        next_version, 'active', 'dedicated_operation', now()
                    );
                END IF;
            END IF;

            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    # The trigger itself (installed by B1B-PR4) is unchanged; only the function body is replaced.
    # It remains ENABLE ALWAYS from PR4 — CREATE OR REPLACE FUNCTION does not reset that.

    # --- extend the credential-binding immutability guard to protect the new SOURCE class ---------
    # ``binding_source`` is part of the binding's immutable identity: a raw UPDATE cannot relabel a
    # legacy binding as dedicated (which would let it satisfy a real-plan gate). CREATE OR REPLACE
    # keeps the PR4 trigger + its ENABLE ALWAYS state.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_credential_binding_immutable() RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'credential_binding rows cannot be deleted';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.purpose_class IS DISTINCT FROM OLD.purpose_class
               OR NEW.binding_version IS DISTINCT FROM OLD.binding_version
               OR NEW.binding_source IS DISTINCT FROM OLD.binding_source
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'credential_binding identity is immutable';
            END IF;
            IF OLD.status <> 'active' AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION 'credential_binding terminal status is final';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )


def _restore_pr4_credential_rotation_trigger() -> None:
    """Downgrade: restore the B1B-PR4 provider-only rotation + immutability functions."""
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_execution_target_credential_rotation()
        RETURNS trigger AS $$
        DECLARE
            next_version integer;
        BEGIN
            IF NEW.secret_ref IS NOT DISTINCT FROM OLD.secret_ref THEN
                RETURN NEW;
            END IF;
            IF coalesce(current_setting('secp.credential_rotation', true), '') = 'on' THEN
                RETURN NEW;
            END IF;

            UPDATE credential_binding
               SET status = 'rotated', rotated_at = now()
             WHERE execution_target_id = NEW.id
               AND purpose_class = 'provider_plan_read'
               AND status = 'active';

            IF NEW.secret_ref IS NULL THEN
                RETURN NEW;
            END IF;

            SELECT coalesce(max(binding_version), 0) + 1 INTO next_version
              FROM credential_binding
             WHERE execution_target_id = NEW.id
               AND purpose_class = 'provider_plan_read';

            INSERT INTO credential_binding (
                id, organization_id, execution_target_id, purpose_class, binding_version,
                status, created_at
            ) VALUES (
                gen_random_uuid(), NEW.organization_id, NEW.id, 'provider_plan_read', next_version,
                'active', now()
            );
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    # Restore the PR4 credential-binding immutability guard (without the ``binding_source`` column,
    # which the downgrade drops).
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_credential_binding_immutable() RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'credential_binding rows cannot be deleted';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.purpose_class IS DISTINCT FROM OLD.purpose_class
               OR NEW.binding_version IS DISTINCT FROM OLD.binding_version
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'credential_binding identity is immutable';
            END IF;
            IF OLD.status <> 'active' AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION 'credential_binding terminal status is final';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )


def _drop_pr5a_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_plan_generation_attempt_immutable "
        "ON real_plan_generation_attempt"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_real_plan_generation_attempt_immutable")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_plan_generation_authorization_immutable "
        "ON real_plan_generation_authorization"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_real_plan_generation_authorization_immutable")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_lab_activation_dossier_evidence_draft_only "
        "ON real_lab_activation_dossier_evidence"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_real_lab_activation_dossier_evidence_draft_only")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_real_lab_activation_dossier_immutable "
        "ON real_lab_activation_dossier"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_real_lab_activation_dossier_immutable")
