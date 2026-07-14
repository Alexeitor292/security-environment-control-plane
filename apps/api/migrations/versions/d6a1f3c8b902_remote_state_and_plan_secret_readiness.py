"""readiness: toolchain attestation, credential binding, remote state + plan secret (B1B-PR4)

Adds the seven durable tables of ADR-021:

* ``toolchain_attestation_record`` — the DURABLE, worker-produced PR2 toolchain attestation. A
  matching toolchain-profile hash is a DECLARATION, not evidence; both readiness operations bind the
  exact attestation record id + evidence hash.
* ``credential_binding`` — an OPAQUE, versioned identity for a target's credential SELECTION. It
  closes the post-approval ``secret_ref`` substitution gap WITHOUT storing the reference or any hash
  of it: the table is a bare id + monotonic version.
* ``remote_state_readiness_record`` / ``plan_secret_readiness_authorization`` /
  ``plan_secret_readiness_evidence`` / ``plan_secret_resolution_lease`` /
  ``plan_secret_readiness_record``.

Every security-critical binding is a TYPED column with a typed foreign key; the only JSON columns
hold bounded typed facet names / reason codes. There is NO secret column, NO secret-reference
column, NO secret-reference-hash column, NO endpoint / URL / bucket / object-key / state-path /
namespace-name column, and NO raw-JSON-only security binding.

There is deliberately **no digest taken directly over the backend reference** either: an unsalted
hash of an enumerable locator is an offline CONFIRMATION ORACLE. The backend is anchored instead by
the immutable ``ToolchainProfile`` content hash, an opaque adapter registration UUID, and a
server-derived namespace hash computed over non-sensitive UUIDs. External proof ids are UUID columns
— a UUID can never BE a bucket name, a hostname, or a state-file path.

PostgreSQL triggers make the evidence tables append-only (a prior successful record can never be
mutated into failure); make the plan-secret authorization's binding facts immutable, its
approval/revocation facts set-once and its lifecycle transitions closed; keep a credential binding's
opaque identity immutable; and AUTO-ROTATE the credential binding whenever ``secret_ref`` changes —
so even a raw ``UPDATE`` that bypasses the ORM entirely cannot replace a credential unnoticed.

Every one of those guards is installed **ENABLE ALWAYS**, not the default ENABLE ORIGIN. A trigger
left at ENABLE ORIGIN does not fire under ``session_replication_role = replica`` — so any session
able to set replica mode could erase immutable readiness evidence, rewrite an approved authorization,
or swap a credential reference without rotating its binding. ENABLE ALWAYS closes that bypass (the
same reasoning as the SECP-B6 worker-admission guard).

Revision ID: d6a1f3c8b902
Revises: c7e1a9b3d5f2
Create Date: 2026-07-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d6a1f3c8b902"
down_revision: str | None = "c7e1a9b3d5f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIVE_AUTHORIZATION = sa.text("status in ('draft','approved')")
# Exact-once applies to the TERMINAL (``ready``) outcome only: NON-ready attempts append as
# immutable attempt history so a retry is possible and the bounded lease budget is reachable.
_READY_ONLY = sa.text("outcome = 'ready'")
_ATTESTED_ONLY = sa.text("outcome = 'attested'")
_ACTIVE_BINDING = sa.text("status = 'active'")


def upgrade() -> None:
    # --- the DURABLE PR2 toolchain attestation (B1B-PR4 §1) --------------------------------------
    # It stores NO path, NO filename, NO executable content, NO provider content, NO CLI content and
    # NO raw expected/observed digest — only ids, bounded facet NAMES, bounded reason codes, versions
    # and content hashes.
    op.create_table(
        "toolchain_attestation_record",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("verifier_policy_version", sa.String(length=120), nullable=False),
        sa.Column("outcome", sa.String(length=40), nullable=False),
        sa.Column("verified_facets", sa.JSON(), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("toolchain_attestation_record", schema=None) as b:
        b.create_index(b.f("ix_toolchain_attestation_record_organization_id"), ["organization_id"])
        b.create_index(
            b.f("ix_toolchain_attestation_record_execution_target_id"), ["execution_target_id"]
        )
        b.create_index(
            b.f("ix_toolchain_attestation_record_toolchain_profile_id"), ["toolchain_profile_id"]
        )
        b.create_index(
            b.f("ix_toolchain_attestation_record_worker_identity_registration_id"),
            ["worker_identity_registration_id"],
        )
        b.create_index(
            b.f("ix_toolchain_attestation_record_operation_fingerprint"), ["operation_fingerprint"]
        )
        b.create_index(b.f("ix_toolchain_attestation_record_evidence_hash"), ["evidence_hash"])
        b.create_index(
            "uq_toolchain_attestation_operation",
            ["toolchain_profile_id", "operation_fingerprint"],
            unique=True,
            sqlite_where=_ATTESTED_ONLY,
            postgresql_where=_ATTESTED_ONLY,
        )

    # --- the OPAQUE, versioned credential binding (B1B-PR4 §2) ------------------------------------
    # There is deliberately NO column here that could hold a secret, a secret reference, a hash of a
    # reference, a locator, a backend path, or a credential value.
    op.create_table(
        "credential_binding",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("purpose_class", sa.String(length=40), nullable=False),
        sa.Column("binding_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "execution_target_id",
            "purpose_class",
            "binding_version",
            name="uq_credential_binding_target_purpose_version",
        ),
    )
    with op.batch_alter_table("credential_binding", schema=None) as b:
        b.create_index(b.f("ix_credential_binding_organization_id"), ["organization_id"])
        b.create_index(b.f("ix_credential_binding_execution_target_id"), ["execution_target_id"])
        b.create_index(
            "uq_credential_binding_active",
            ["execution_target_id", "purpose_class"],
            unique=True,
            sqlite_where=_ACTIVE_BINDING,
            postgresql_where=_ACTIVE_BINDING,
        )

    op.create_table(
        "remote_state_readiness_record",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("eligibility_policy_version", sa.String(length=120), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_policy_version", sa.String(length=120), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("activation_dossier_hash", sa.String(length=120), nullable=False),
        # A bounded backend CLASS + a server-derived namespace hash over non-sensitive UUIDs. There
        # is deliberately NO digest of the backend reference / URL / bucket / object key here: an
        # unsalted hash of an enumerable locator is an offline confirmation oracle (ADR-021 §E).
        sa.Column("state_backend_class", sa.String(length=20), nullable=False),
        sa.Column("state_namespace_hash", sa.String(length=80), nullable=False),
        # External proof ids are UUIDs — a UUID can never BE a bucket / hostname / state-file name.
        sa.Column("encryption_proof_id", sa.Uuid(), nullable=True),
        sa.Column("lock_proof_id", sa.Uuid(), nullable=True),
        sa.Column("backup_proof_id", sa.Uuid(), nullable=True),
        sa.Column("restore_proof_id", sa.Uuid(), nullable=True),
        # Controlled-live adapter provenance (B1B-PR4 §3): a self-declared contract version is not
        # provenance. TEST-ONLY evidence can never be mistaken for deployment evidence.
        sa.Column("capability_class", sa.String(length=20), nullable=False),
        sa.Column("adapter_registration_id", sa.Uuid(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("readiness_policy_version", sa.String(length=120), nullable=False),
        sa.Column("adapter_contract_version", sa.String(length=120), nullable=False),
        sa.Column("outcome", sa.String(length=40), nullable=False),
        sa.Column("facets", sa.JSON(), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["eligibility_preflight_id"], ["target_preflight.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(["target_onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.ForeignKeyConstraint(
            ["toolchain_attestation_id"], ["toolchain_attestation_record.id"]
        ),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("remote_state_readiness_record", schema=None) as b:
        b.create_index(b.f("ix_remote_state_readiness_record_organization_id"), ["organization_id"])
        b.create_index(
            b.f("ix_remote_state_readiness_record_execution_target_id"), ["execution_target_id"]
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_target_onboarding_id"), ["target_onboarding_id"]
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_deployment_plan_id"), ["deployment_plan_id"]
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_provisioning_manifest_id"),
            ["provisioning_manifest_id"],
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_toolchain_profile_id"), ["toolchain_profile_id"]
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_eligibility_preflight_id"),
            ["eligibility_preflight_id"],
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_toolchain_attestation_id"),
            ["toolchain_attestation_id"],
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_worker_identity_registration_id"),
            ["worker_identity_registration_id"],
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_state_namespace_hash"), ["state_namespace_hash"]
        )
        b.create_index(
            b.f("ix_remote_state_readiness_record_operation_fingerprint"), ["operation_fingerprint"]
        )
        b.create_index(b.f("ix_remote_state_readiness_record_evidence_hash"), ["evidence_hash"])
        b.create_index(
            "uq_remote_state_readiness_operation",
            ["provisioning_manifest_id", "operation_fingerprint"],
            unique=True,
            sqlite_where=_READY_ONLY,
            postgresql_where=_READY_ONLY,
        )

    op.create_table(
        "plan_secret_readiness_authorization",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=False),
        sa.Column("remote_state_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        # The OPAQUE credential binding this authorization approves. Rotating the target's
        # secret_ref rotates the binding, which invalidates the authorization through the operation
        # fingerprint — WITHOUT storing the reference or any hash of it.
        sa.Column("credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("remote_state_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("activation_dossier_hash", sa.String(length=120), nullable=False),
        # The purpose is server-forced to 'plan_read'. Apply/destroy purposes are unrepresentable.
        sa.Column("purpose", sa.String(length=40), nullable=False),
        # The reviewed credential-reference SCHEME ('vault'/'env') — NEVER the reference, never a
        # hash of it.
        sa.Column("credential_reference_scheme", sa.String(length=20), nullable=False),
        sa.Column("resolver_contract_version", sa.String(length=120), nullable=False),
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
        sa.Column("revocation_reason_code", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["eligibility_preflight_id"], ["target_preflight.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(
            ["remote_state_readiness_id"], ["remote_state_readiness_record.id"]
        ),
        sa.ForeignKeyConstraint(
            ["toolchain_attestation_id"], ["toolchain_attestation_record.id"]
        ),
        sa.ForeignKeyConstraint(["credential_binding_id"], ["credential_binding.id"]),
        sa.ForeignKeyConstraint(["target_onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provisioning_manifest_id",
            "authorization_version",
            name="uq_plan_secret_authorization_manifest_version",
        ),
    )
    with op.batch_alter_table("plan_secret_readiness_authorization", schema=None) as b:
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_organization_id"), ["organization_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_execution_target_id"),
            ["execution_target_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_target_onboarding_id"),
            ["target_onboarding_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_deployment_plan_id"), ["deployment_plan_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_provisioning_manifest_id"),
            ["provisioning_manifest_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_toolchain_profile_id"),
            ["toolchain_profile_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_eligibility_preflight_id"),
            ["eligibility_preflight_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_remote_state_readiness_id"),
            ["remote_state_readiness_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_toolchain_attestation_id"),
            ["toolchain_attestation_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_credential_binding_id"),
            ["credential_binding_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_worker_identity_registration_id"),
            ["worker_identity_registration_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_authorization_operation_fingerprint"),
            ["operation_fingerprint"],
        )
        b.create_index(
            "uq_plan_secret_authorization_active",
            ["provisioning_manifest_id"],
            unique=True,
            sqlite_where=_ACTIVE_AUTHORIZATION,
            postgresql_where=_ACTIVE_AUTHORIZATION,
        )

    op.create_table(
        "plan_secret_readiness_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("proof_id", sa.String(length=120), nullable=False),
        sa.Column("issuer", sa.String(length=120), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["authorization_id"], ["plan_secret_readiness_authorization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("authorization_id", "kind", name="uq_plan_secret_evidence_kind"),
    )
    with op.batch_alter_table("plan_secret_readiness_evidence", schema=None) as b:
        b.create_index(
            b.f("ix_plan_secret_readiness_evidence_authorization_id"), ["authorization_id"]
        )

    op.create_table(
        "plan_secret_resolution_lease",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("worker_identity_id", sa.String(length=120), nullable=False),
        sa.Column("reason_code", sa.String(length=60), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["authorization_id"], ["plan_secret_readiness_authorization.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "authorization_id",
            "authorization_version",
            "operation_fingerprint",
            name="uq_plan_secret_lease_operation",
        ),
    )
    with op.batch_alter_table("plan_secret_resolution_lease", schema=None) as b:
        b.create_index(b.f("ix_plan_secret_resolution_lease_organization_id"), ["organization_id"])
        b.create_index(
            b.f("ix_plan_secret_resolution_lease_authorization_id"), ["authorization_id"]
        )

    op.create_table(
        "plan_secret_readiness_record",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("execution_target_id", sa.Uuid(), nullable=False),
        sa.Column("target_onboarding_id", sa.Uuid(), nullable=False),
        sa.Column("deployment_plan_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_profile_id", sa.Uuid(), nullable=False),
        sa.Column("eligibility_preflight_id", sa.Uuid(), nullable=False),
        sa.Column("remote_state_readiness_id", sa.Uuid(), nullable=False),
        sa.Column("toolchain_attestation_id", sa.Uuid(), nullable=False),
        sa.Column("credential_binding_id", sa.Uuid(), nullable=False),
        sa.Column("credential_binding_version", sa.Integer(), nullable=False),
        sa.Column("worker_identity_registration_id", sa.Uuid(), nullable=False),
        sa.Column("worker_identity_version", sa.Integer(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=True),
        sa.Column("capability_class", sa.String(length=20), nullable=False),
        sa.Column("adapter_registration_id", sa.Uuid(), nullable=False),
        sa.Column("provisioning_manifest_content_hash", sa.String(length=80), nullable=False),
        sa.Column("target_config_hash", sa.String(length=80), nullable=False),
        sa.Column("onboarding_boundary_hash", sa.String(length=80), nullable=False),
        sa.Column("eligibility_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_profile_hash", sa.String(length=80), nullable=False),
        sa.Column("toolchain_attestation_hash", sa.String(length=80), nullable=False),
        sa.Column("remote_state_evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("activation_dossier_hash", sa.String(length=120), nullable=False),
        sa.Column("authorization_evidence_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("secret_purpose", sa.String(length=40), nullable=False),
        sa.Column("resolver_contract_version", sa.String(length=120), nullable=False),
        sa.Column("self_test_policy_version", sa.String(length=120), nullable=False),
        sa.Column("env_contract_version", sa.String(length=120), nullable=False),
        sa.Column("readiness_policy_version", sa.String(length=120), nullable=False),
        sa.Column("self_test_proof_id", sa.Uuid(), nullable=True),
        sa.Column("operation_fingerprint", sa.String(length=80), nullable=False),
        sa.Column("outcome", sa.String(length=40), nullable=False),
        sa.Column("facets", sa.JSON(), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_hash", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["authorization_id"], ["plan_secret_readiness_authorization.id"]),
        sa.ForeignKeyConstraint(["deployment_plan_id"], ["deployment_plan.id"]),
        sa.ForeignKeyConstraint(["eligibility_preflight_id"], ["target_preflight.id"]),
        sa.ForeignKeyConstraint(["execution_target_id"], ["execution_target.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organization.id"]),
        sa.ForeignKeyConstraint(["provisioning_manifest_id"], ["provisioning_manifest.id"]),
        sa.ForeignKeyConstraint(
            ["remote_state_readiness_id"], ["remote_state_readiness_record.id"]
        ),
        sa.ForeignKeyConstraint(
            ["toolchain_attestation_id"], ["toolchain_attestation_record.id"]
        ),
        sa.ForeignKeyConstraint(["credential_binding_id"], ["credential_binding.id"]),
        sa.ForeignKeyConstraint(["target_onboarding_id"], ["target_onboarding.id"]),
        sa.ForeignKeyConstraint(["toolchain_profile_id"], ["toolchain_profile.id"]),
        sa.ForeignKeyConstraint(
            ["worker_identity_registration_id"], ["worker_identity_registration.id"]
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("plan_secret_readiness_record", schema=None) as b:
        b.create_index(b.f("ix_plan_secret_readiness_record_organization_id"), ["organization_id"])
        b.create_index(
            b.f("ix_plan_secret_readiness_record_authorization_id"), ["authorization_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_execution_target_id"), ["execution_target_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_target_onboarding_id"), ["target_onboarding_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_deployment_plan_id"), ["deployment_plan_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_provisioning_manifest_id"),
            ["provisioning_manifest_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_toolchain_profile_id"), ["toolchain_profile_id"]
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_eligibility_preflight_id"),
            ["eligibility_preflight_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_remote_state_readiness_id"),
            ["remote_state_readiness_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_toolchain_attestation_id"),
            ["toolchain_attestation_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_credential_binding_id"),
            ["credential_binding_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_worker_identity_registration_id"),
            ["worker_identity_registration_id"],
        )
        b.create_index(
            b.f("ix_plan_secret_readiness_record_operation_fingerprint"), ["operation_fingerprint"]
        )
        b.create_index(b.f("ix_plan_secret_readiness_record_evidence_hash"), ["evidence_hash"])
        b.create_index(
            "uq_plan_secret_readiness_operation",
            ["provisioning_manifest_id", "operation_fingerprint"],
            unique=True,
            sqlite_where=_READY_ONLY,
            postgresql_where=_READY_ONLY,
        )

    _install_immutability_triggers()


def downgrade() -> None:
    _drop_immutability_triggers()
    with op.batch_alter_table("plan_secret_readiness_record", schema=None) as b:
        b.drop_index("uq_plan_secret_readiness_operation")
        b.drop_index(b.f("ix_plan_secret_readiness_record_evidence_hash"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_operation_fingerprint"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_worker_identity_registration_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_credential_binding_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_toolchain_attestation_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_remote_state_readiness_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_eligibility_preflight_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_toolchain_profile_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_provisioning_manifest_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_deployment_plan_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_target_onboarding_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_execution_target_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_authorization_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_record_organization_id"))
    op.drop_table("plan_secret_readiness_record")

    with op.batch_alter_table("plan_secret_resolution_lease", schema=None) as b:
        b.drop_index(b.f("ix_plan_secret_resolution_lease_authorization_id"))
        b.drop_index(b.f("ix_plan_secret_resolution_lease_organization_id"))
    op.drop_table("plan_secret_resolution_lease")

    with op.batch_alter_table("plan_secret_readiness_evidence", schema=None) as b:
        b.drop_index(b.f("ix_plan_secret_readiness_evidence_authorization_id"))
    op.drop_table("plan_secret_readiness_evidence")

    with op.batch_alter_table("plan_secret_readiness_authorization", schema=None) as b:
        b.drop_index("uq_plan_secret_authorization_active")
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_operation_fingerprint"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_worker_identity_registration_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_credential_binding_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_toolchain_attestation_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_remote_state_readiness_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_eligibility_preflight_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_toolchain_profile_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_provisioning_manifest_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_deployment_plan_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_target_onboarding_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_execution_target_id"))
        b.drop_index(b.f("ix_plan_secret_readiness_authorization_organization_id"))
    op.drop_table("plan_secret_readiness_authorization")

    with op.batch_alter_table("remote_state_readiness_record", schema=None) as b:
        b.drop_index("uq_remote_state_readiness_operation")
        b.drop_index(b.f("ix_remote_state_readiness_record_evidence_hash"))
        b.drop_index(b.f("ix_remote_state_readiness_record_operation_fingerprint"))
        b.drop_index(b.f("ix_remote_state_readiness_record_state_namespace_hash"))
        b.drop_index(b.f("ix_remote_state_readiness_record_worker_identity_registration_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_toolchain_attestation_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_eligibility_preflight_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_toolchain_profile_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_provisioning_manifest_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_deployment_plan_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_target_onboarding_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_execution_target_id"))
        b.drop_index(b.f("ix_remote_state_readiness_record_organization_id"))
    op.drop_table("remote_state_readiness_record")

    with op.batch_alter_table("credential_binding", schema=None) as b:
        b.drop_index("uq_credential_binding_active")
        b.drop_index(b.f("ix_credential_binding_execution_target_id"))
        b.drop_index(b.f("ix_credential_binding_organization_id"))
    op.drop_table("credential_binding")

    with op.batch_alter_table("toolchain_attestation_record", schema=None) as b:
        b.drop_index("uq_toolchain_attestation_operation")
        b.drop_index(b.f("ix_toolchain_attestation_record_evidence_hash"))
        b.drop_index(b.f("ix_toolchain_attestation_record_operation_fingerprint"))
        b.drop_index(b.f("ix_toolchain_attestation_record_worker_identity_registration_id"))
        b.drop_index(b.f("ix_toolchain_attestation_record_toolchain_profile_id"))
        b.drop_index(b.f("ix_toolchain_attestation_record_execution_target_id"))
        b.drop_index(b.f("ix_toolchain_attestation_record_organization_id"))
    op.drop_table("toolchain_attestation_record")


def _install_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return

    # Readiness EVIDENCE is append-only: a prior successful record can never be mutated into
    # failure, and history can never be erased. Drift/expiry invalidation is DERIVED; a new attempt
    # creates a NEW immutable row under a new operation fingerprint (ADR-021 §N).
    for table in (
        "toolchain_attestation_record",
        "remote_state_readiness_record",
        "plan_secret_readiness_record",
    ):
        op.execute(
            f"""
            CREATE OR REPLACE FUNCTION secp_{table}_immutable() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION '{table} rows are immutable (append-only readiness evidence)';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER secp_{table}_immutable
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION secp_{table}_immutable();
            """
        )
        # ENABLE ALWAYS (not the default ENABLE ORIGIN) so the guard fires even under
        # ``session_replication_role = replica`` — otherwise any session that can set replica mode
        # could UPDATE or DELETE immutable readiness EVIDENCE, which would defeat the entire
        # append-only guarantee. Same rationale as the SECP-B6 admission guard.
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER secp_{table}_immutable")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_plan_secret_readiness_authorization_immutable()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'plan_secret_readiness_authorization rows cannot be deleted';
            END IF;

            -- Binding facts are immutable after creation.
            IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
               OR NEW.execution_target_id IS DISTINCT FROM OLD.execution_target_id
               OR NEW.target_onboarding_id IS DISTINCT FROM OLD.target_onboarding_id
               OR NEW.deployment_plan_id IS DISTINCT FROM OLD.deployment_plan_id
               OR NEW.provisioning_manifest_id IS DISTINCT FROM OLD.provisioning_manifest_id
               OR NEW.toolchain_profile_id IS DISTINCT FROM OLD.toolchain_profile_id
               OR NEW.eligibility_preflight_id IS DISTINCT FROM OLD.eligibility_preflight_id
               OR NEW.remote_state_readiness_id IS DISTINCT FROM OLD.remote_state_readiness_id
               OR NEW.toolchain_attestation_id IS DISTINCT FROM OLD.toolchain_attestation_id
               OR NEW.credential_binding_id IS DISTINCT FROM OLD.credential_binding_id
               OR NEW.credential_binding_version IS DISTINCT FROM OLD.credential_binding_version
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
               OR NEW.activation_dossier_hash IS DISTINCT FROM OLD.activation_dossier_hash
               OR NEW.purpose IS DISTINCT FROM OLD.purpose
               OR NEW.credential_reference_scheme IS DISTINCT FROM OLD.credential_reference_scheme
               OR NEW.resolver_contract_version IS DISTINCT FROM OLD.resolver_contract_version
               OR NEW.readiness_policy_version IS DISTINCT FROM OLD.readiness_policy_version
               OR NEW.operation_fingerprint IS DISTINCT FROM OLD.operation_fingerprint
               OR NEW.authorization_expiry IS DISTINCT FROM OLD.authorization_expiry
               OR NEW.authorization_version IS DISTINCT FROM OLD.authorization_version
               OR NEW.created_by IS DISTINCT FROM OLD.created_by
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION
                    'plan_secret_readiness_authorization binding facts are immutable';
            END IF;

            -- Terminal states are final; only the closed transitions are allowed.
            IF OLD.status IN ('revoked', 'expired')
               AND NEW.status IS DISTINCT FROM OLD.status THEN
                RAISE EXCEPTION
                    'plan_secret_readiness_authorization terminal status is final';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status
               AND NOT (
                    (OLD.status = 'draft'    AND NEW.status IN ('approved','revoked','expired'))
                 OR (OLD.status = 'approved' AND NEW.status IN ('revoked','expired'))
               )
            THEN
                RAISE EXCEPTION
                    'plan_secret_readiness_authorization status transition is not allowed';
            END IF;

            -- Approval / revocation facts + the evidence fingerprint are set-once.
            IF OLD.evidence_fingerprint <> ''
               AND NEW.evidence_fingerprint IS DISTINCT FROM OLD.evidence_fingerprint THEN
                RAISE EXCEPTION 'evidence_fingerprint is set-once';
            END IF;
            IF OLD.approved_by IS NOT NULL
               AND NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
                RAISE EXCEPTION 'approved_by is set-once';
            END IF;
            IF OLD.approved_at IS NOT NULL
               AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
                RAISE EXCEPTION 'approved_at is set-once';
            END IF;
            IF OLD.revoked_by IS NOT NULL
               AND NEW.revoked_by IS DISTINCT FROM OLD.revoked_by THEN
                RAISE EXCEPTION 'revoked_by is set-once';
            END IF;
            IF OLD.revoked_at IS NOT NULL
               AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                RAISE EXCEPTION 'revoked_at is set-once';
            END IF;

            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER secp_plan_secret_readiness_authorization_immutable
        BEFORE UPDATE OR DELETE ON plan_secret_readiness_authorization
        FOR EACH ROW EXECUTE FUNCTION secp_plan_secret_readiness_authorization_immutable();
        """
    )
    op.execute(
        "ALTER TABLE plan_secret_readiness_authorization "
        "ENABLE ALWAYS TRIGGER secp_plan_secret_readiness_authorization_immutable"
    )

    # Evidence rows are managed ONLY while the authorization is draft.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secp_plan_secret_readiness_evidence_draft_only()
        RETURNS trigger AS $$
        DECLARE
            parent_status text;
            parent_id uuid;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                parent_id := OLD.authorization_id;
            ELSE
                parent_id := NEW.authorization_id;
            END IF;
            SELECT status INTO parent_status
            FROM plan_secret_readiness_authorization WHERE id = parent_id;
            IF parent_status IS NOT NULL AND parent_status <> 'draft' THEN
                RAISE EXCEPTION
                    'plan_secret_readiness_evidence is managed only while draft';
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
        CREATE TRIGGER secp_plan_secret_readiness_evidence_draft_only
        BEFORE INSERT OR UPDATE OR DELETE ON plan_secret_readiness_evidence
        FOR EACH ROW EXECUTE FUNCTION secp_plan_secret_readiness_evidence_draft_only();
        """
    )
    op.execute(
        "ALTER TABLE plan_secret_readiness_evidence "
        "ENABLE ALWAYS TRIGGER secp_plan_secret_readiness_evidence_draft_only"
    )

    # A credential binding's OPAQUE identity is immutable; only the closed lifecycle transition
    # active -> rotated/revoked (+ rotated_at) may change, and a binding can never be deleted —
    # deleting one would erase the fact that a credential was replaced.
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
    op.execute(
        """
        CREATE TRIGGER secp_credential_binding_immutable
        BEFORE UPDATE OR DELETE ON credential_binding
        FOR EACH ROW EXECUTE FUNCTION secp_credential_binding_immutable();
        """
    )
    op.execute(
        "ALTER TABLE credential_binding "
        "ENABLE ALWAYS TRIGGER secp_credential_binding_immutable"
    )

    # B1B-PR4 §2 — a credential replacement can never be UNNOTICED.
    #
    # ``ExecutionTarget.secret_ref`` is an opaque pointer, not an immutable column, and PR4 may not
    # persist a hash of it (a hash of an enumerable locator is itself a confirmation oracle). So the
    # database ROTATES the opaque binding whenever the reference changes. Because the binding id +
    # version are folded into every readiness operation fingerprint, the rotation invalidates every
    # prior authorization and readiness record WITHOUT modifying any historical evidence.
    #
    # The supported ORM path announces itself with a transaction-scoped ``SET LOCAL`` (it has already
    # rotated in the same flush), so the rotation is applied exactly once. A raw / Core / psql
    # ``UPDATE`` that bypasses the ORM entirely makes NO such announcement — and is rotated here.
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
                RETURN NEW;  -- the supported ORM path already rotated in this flush
            END IF;

            UPDATE credential_binding
               SET status = 'rotated', rotated_at = now()
             WHERE execution_target_id = NEW.id
               AND purpose_class = 'provider_plan_read'
               AND status = 'active';

            IF NEW.secret_ref IS NULL THEN
                RETURN NEW;  -- the credential selection was removed: no active binding remains
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
    op.execute(
        """
        CREATE TRIGGER secp_execution_target_credential_rotation
        BEFORE UPDATE ON execution_target
        FOR EACH ROW EXECUTE FUNCTION secp_execution_target_credential_rotation();
        """
    )
    # ENABLE ALWAYS: a session that can set ``session_replication_role = replica`` must not be able
    # to substitute a credential reference WITHOUT rotating its opaque binding. Replica mode would
    # otherwise silently restore exactly the invisible-swap gap this trigger exists to close.
    op.execute(
        "ALTER TABLE execution_target "
        "ENABLE ALWAYS TRIGGER secp_execution_target_credential_rotation"
    )


def _drop_immutability_triggers() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        "DROP TRIGGER IF EXISTS secp_execution_target_credential_rotation ON execution_target"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_execution_target_credential_rotation")
    op.execute("DROP TRIGGER IF EXISTS secp_credential_binding_immutable ON credential_binding")
    op.execute("DROP FUNCTION IF EXISTS secp_credential_binding_immutable")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_plan_secret_readiness_evidence_draft_only "
        "ON plan_secret_readiness_evidence"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_plan_secret_readiness_evidence_draft_only")
    op.execute(
        "DROP TRIGGER IF EXISTS secp_plan_secret_readiness_authorization_immutable "
        "ON plan_secret_readiness_authorization"
    )
    op.execute("DROP FUNCTION IF EXISTS secp_plan_secret_readiness_authorization_immutable")
    for table in (
        "toolchain_attestation_record",
        "remote_state_readiness_record",
        "plan_secret_readiness_record",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS secp_{table}_immutable ON {table}")
        op.execute(f"DROP FUNCTION IF EXISTS secp_{table}_immutable")
