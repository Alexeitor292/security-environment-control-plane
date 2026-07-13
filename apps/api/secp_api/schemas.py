"""Pydantic request/response schemas for the control-plane API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from secp_api.models import DeploymentPlan, EnvironmentVersion


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- requests -----------------------------------------------------------------


class TemplateCreate(BaseModel):
    name: str
    slug: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    display_name: str = ""
    description: str = ""


class VersionCreate(BaseModel):
    definition: dict


class ExerciseCreate(BaseModel):
    template_id: uuid.UUID
    version_id: uuid.UUID
    name: str
    execution_target_id: uuid.UUID | None = None


class DecisionBody(BaseModel):
    reason: str = ""


# --- responses ----------------------------------------------------------------


class TemplateOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    display_name: str
    description: str
    created_at: datetime


class VersionPublicationProvenanceOut(BaseModel):
    """Typed, server-owned publication provenance for a published v1alpha2 EnvironmentVersion
    (ADR-016 PR C). Populated ONLY from the immutable mirrored database columns; every value
    equals the embedded ``spec.publicationProvenance`` (the DB enforces that coherence), and
    ``publication_fingerprint`` is the server-derived column — never client-supplied."""

    topology_document_id: uuid.UUID
    topology_revision_id: uuid.UUID
    topology_content_hash: str
    topology_validation_result_id: uuid.UUID
    topology_validation_result_hash: str
    base_environment_version_id: uuid.UUID | None
    publication_contract_version: str
    publication_fingerprint: str

    @classmethod
    def from_version(cls, version: EnvironmentVersion) -> VersionPublicationProvenanceOut | None:
        """The single provenance serializer: typed provenance from the immutable mirrored columns
        for a published v1alpha2 row (``publication_fingerprint`` set), else ``None`` for legacy
        v1alpha1. Never derived from spec, plan summary, or topology-authoring rows. A v1alpha2 row
        missing any mirrored column is impossible (the DB rejects incoherent rows) and fails closed
        here via the required-field validation."""
        if version.publication_fingerprint is None:
            return None
        return cls(
            topology_document_id=version.source_topology_document_id,
            topology_revision_id=version.source_topology_revision_id,
            topology_content_hash=version.topology_content_hash,
            topology_validation_result_id=version.topology_validation_result_id,
            topology_validation_result_hash=version.topology_validation_result_hash,
            base_environment_version_id=version.base_environment_version_id,
            publication_contract_version=version.publication_contract_version,
            publication_fingerprint=version.publication_fingerprint,
        )


class VersionOut(ORMModel):
    id: uuid.UUID
    template_id: uuid.UUID
    version_number: int
    api_version: str
    content_hash: str
    spec: dict
    created_at: datetime
    # None for legacy/manual v1alpha1 rows; typed provenance for published v1alpha2 rows.
    publication_provenance: VersionPublicationProvenanceOut | None = None

    @classmethod
    def from_version(cls, version: EnvironmentVersion) -> VersionOut:
        """Centralized EnvironmentVersion -> VersionOut serializer."""
        return cls(
            id=version.id,
            template_id=version.template_id,
            version_number=version.version_number,
            api_version=version.api_version,
            content_hash=version.content_hash,
            spec=version.spec,
            created_at=version.created_at,
            publication_provenance=VersionPublicationProvenanceOut.from_version(version),
        )


class ExerciseOut(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    template_id: uuid.UUID
    environment_version_id: uuid.UUID
    name: str
    lifecycle_state: str
    team_count: int
    execution_target_id: uuid.UUID | None = None
    created_at: datetime


class InstanceOut(ORMModel):
    id: uuid.UUID
    exercise_id: uuid.UUID
    team_index: int
    team_ref: str
    instance_ref: str
    lifecycle_state: str
    provider: str


class PlanEnvironmentVersionBindingOut(BaseModel):
    """Typed read model for the ONE EnvironmentVersion a DeploymentPlan binds (ADR-016 PR E).

    Derived from the exact immutable EnvironmentVersion the plan pins via
    ``environment_version_id`` + ``version_content_hash`` — NOT from plan.summary, the version
    spec, or any topology-authoring row. It carries no full spec and adds no second canonical
    binding: the plan's only canonical version binding stays ``environment_version_id`` +
    ``version_content_hash``. ``publication_provenance`` is the same server-owned provenance
    surfaced by ``VersionOut`` (null for legacy/manual v1alpha1)."""

    environment_version_id: uuid.UUID
    template_id: uuid.UUID
    version_number: int
    api_version: str
    content_hash: str
    publication_provenance: VersionPublicationProvenanceOut | None


class PlanOut(ORMModel):
    id: uuid.UUID
    exercise_id: uuid.UUID
    environment_version_id: uuid.UUID
    version_content_hash: str
    # Target-pinning fields (null for Simulator path).
    execution_target_id: uuid.UUID | None = None
    target_config_hash: str | None = None
    status: str
    summary: dict
    approved_content_hash: str | None
    decided_at: datetime | None
    created_at: datetime
    # ADR-016 PR E: typed view of the exact bound immutable EnvironmentVersion + its provenance.
    # Optional-with-default only so ``model_validate`` stays usable in narrow internal paths; every
    # API response is built through ``from_plan`` with the verified version.
    environment_version_binding: PlanEnvironmentVersionBindingOut | None = None

    @classmethod
    def from_plan(cls, plan: DeploymentPlan, version: EnvironmentVersion) -> PlanOut:
        """Centralized DeploymentPlan -> PlanOut serializer with the verified bound version.

        Fails closed (``PlanVersionBindingError``, redacted 409) unless the plan and the supplied
        version agree on organization, id, and the pinned content hash. The exercise-side invariants
        (exercise.environment_version_id == plan.environment_version_id and exercise.template_id ==
        version.template_id) are enforced by ``planning.require_plan_version_binding``, which
        produces the ``version`` passed here. No topology-authoring row is consulted.
        """
        from secp_api.errors import PlanVersionBindingError

        if (
            plan.organization_id != version.organization_id
            or plan.environment_version_id != version.id
            or plan.version_content_hash != version.content_hash
        ):
            raise PlanVersionBindingError()
        binding = PlanEnvironmentVersionBindingOut(
            environment_version_id=version.id,
            template_id=version.template_id,
            version_number=version.version_number,
            api_version=version.api_version,
            content_hash=version.content_hash,
            publication_provenance=VersionPublicationProvenanceOut.from_version(version),
        )
        return cls(
            id=plan.id,
            exercise_id=plan.exercise_id,
            environment_version_id=plan.environment_version_id,
            version_content_hash=plan.version_content_hash,
            execution_target_id=plan.execution_target_id,
            target_config_hash=plan.target_config_hash,
            status=plan.status.value,
            summary=plan.summary,
            approved_content_hash=plan.approved_content_hash,
            decided_at=plan.decided_at,
            created_at=plan.created_at,
            environment_version_binding=binding,
        )


class WorkflowRunOut(ORMModel):
    id: uuid.UUID
    exercise_id: uuid.UUID
    kind: str
    status: str
    dispatch_mode: str
    correlation_id: str
    target_instance_id: uuid.UUID | None
    detail: dict
    created_at: datetime
    finished_at: datetime | None


class AuditEventOut(ORMModel):
    id: uuid.UUID
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    data: dict
    created_at: datetime


class PluginOut(BaseModel):
    name: str
    version: str
    contract_version: str
    healthy: bool
    simulated: bool
    capabilities: list[str]


class PrincipalOut(BaseModel):
    user_id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    permissions: list[str]
    is_dev_fallback: bool


class AuthConfigOut(BaseModel):
    """Public, SECRET-FREE browser authentication configuration (ADR-018 / OIDC-B).

    Everything here is non-secret and server-owned. ``mode`` is derived from the dev-fallback gate;
    ``scope`` is a fixed value that excludes ``offline_access``; ``redirect_path`` /
    ``post_logout_redirect_path`` are fixed relative application paths. There is NO client secret,
    token, or endpoint credential — a public browser client has none, and the backend remains the
    authoritative token verifier (OIDC-A / ADR-017)."""

    mode: Literal["dev_fallback", "oidc"]
    issuer: str
    client_id: str
    audience: str
    scope: str
    redirect_path: str
    post_logout_redirect_path: str


class ValidationOut(BaseModel):
    ok: bool
    errors: list[str] = []
    warnings: list[str] = []
