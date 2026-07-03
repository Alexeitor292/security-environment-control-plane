"""Worker-owned live-read authorization loader/verifier contract (SECP-002B-1B-6).

This module is dormant contract code for a future activation workflow. It does not dispatch
work, resolve secrets, construct transports, instantiate collectors, persist evidence, or call
``run_live_readonly_collection``. Tests use fake repositories and hash providers only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from secp_api.enums import (
    LiveReadAuthorizationStatus,
    OnboardingStatus,
    TargetStatus,
)
from secp_api.models import ExecutionTarget, LiveReadAuthorization, TargetOnboarding

from secp_worker.onboarding.live_readonly import LiveReadCollectionBinding


@dataclass(frozen=True, repr=False)
class LiveReadAuthorizationContract:
    """Expected live-read contract versions for one future activation attempt."""

    evidence_source: str
    verification_level: str
    collector_contract_version: str
    endpoint_allowlist_version: str

    def __repr__(self) -> str:
        return (
            "LiveReadAuthorizationContract("
            f"evidence_source={self.evidence_source!r}, "
            f"verification_level={self.verification_level!r}, "
            f"collector_contract_version={self.collector_contract_version!r}, "
            f"endpoint_allowlist_version={self.endpoint_allowlist_version!r})"
        )


@dataclass(frozen=True, repr=False)
class LiveReadAuthorizationLoadRequest:
    """IDs pinned into a future activation job.

    The request contains only IDs/version. It does not carry target config, declared boundary,
    credential references, secret references, endpoints, or observed evidence.
    """

    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    onboarding_id: uuid.UUID
    authorization_id: uuid.UUID
    authorization_version: int

    def __repr__(self) -> str:
        return (
            "LiveReadAuthorizationLoadRequest("
            f"organization_id={self.organization_id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"authorization_id={self.authorization_id!s}, "
            f"authorization_version={self.authorization_version!r})"
        )


@dataclass(frozen=True, repr=False)
class LiveReadAuthorizationValidationRefusal:
    """Secret-free refusal event emitted by the verifier contract."""

    reason_code: str
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID | None = None
    onboarding_id: uuid.UUID | None = None
    authorization_id: uuid.UUID | None = None
    authorization_version: int | None = None

    def __repr__(self) -> str:
        return (
            "LiveReadAuthorizationValidationRefusal("
            f"reason_code={self.reason_code!r}, "
            f"organization_id={self.organization_id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"authorization_id={self.authorization_id!s}, "
            f"authorization_version={self.authorization_version!r})"
        )

    def audit_payload(self) -> dict:
        payload: dict[str, object] = {
            "reason_code": self.reason_code,
            "status": "refused",
        }
        if self.execution_target_id is not None:
            payload["execution_target_id"] = str(self.execution_target_id)
        if self.onboarding_id is not None:
            payload["onboarding_id"] = str(self.onboarding_id)
        if self.authorization_id is not None:
            payload["authorization_id"] = str(self.authorization_id)
        if self.authorization_version is not None:
            payload["authorization_version"] = self.authorization_version
        return payload


@dataclass(frozen=True, repr=False)
class VerifiedLiveReadAuthorization:
    """Verified records plus the binding for ``run_live_readonly_collection``.

    ``execution_target`` may carry an opaque ``secret_ref``. The custom repr therefore exposes
    only IDs and the already-redacted binding repr.
    """

    execution_target: ExecutionTarget
    onboarding: TargetOnboarding
    authorization: LiveReadAuthorization
    binding: LiveReadCollectionBinding

    def __repr__(self) -> str:
        return (
            "VerifiedLiveReadAuthorization("
            f"execution_target_id={self.execution_target.id!s}, "
            f"onboarding_id={self.onboarding.id!s}, "
            f"authorization_id={self.authorization.id!s}, "
            f"binding={self.binding!r})"
        )


class LiveReadAuthorizationRefused(Exception):
    """Fail-closed verifier refusal with a generic, secret-free reason code."""

    def __init__(self, reason_code: str, refusal: LiveReadAuthorizationValidationRefusal) -> None:
        super().__init__(f"live-read authorization refused: {reason_code}")
        self.reason_code = reason_code
        self.refusal = refusal


@runtime_checkable
class LiveReadAuthorizationRepository(Protocol):
    """Authoritative record-loader seam for a future activation workflow."""

    def get_execution_target(self, target_id: uuid.UUID) -> ExecutionTarget | None: ...

    def get_target_onboarding(self, onboarding_id: uuid.UUID) -> TargetOnboarding | None: ...

    def get_live_read_authorization(
        self, authorization_id: uuid.UUID
    ) -> LiveReadAuthorization | None: ...


@runtime_checkable
class LiveReadConnectionHashProvider(Protocol):
    """Provider-neutral current connection-hash seam.

    The hash provider must return the same secret-free connection hash expected by
    ``LiveReadCollectionBinding.target_config_hash``. It must not hash credential refs.
    """

    def current_connection_hash(self, execution_target: ExecutionTarget) -> str: ...


@runtime_checkable
class LiveReadAuthorizationAuditSink(Protocol):
    """Secret-free refusal audit seam used by the loader/verifier contract."""

    def record_validation_refused(
        self, refusal: LiveReadAuthorizationValidationRefusal
    ) -> None: ...


class NullLiveReadAuthorizationAuditSink:
    def record_validation_refused(self, refusal: LiveReadAuthorizationValidationRefusal) -> None:
        return None


def load_and_verify_live_read_authorization(
    *,
    request: LiveReadAuthorizationLoadRequest,
    repository: LiveReadAuthorizationRepository,
    connection_hash_provider: LiveReadConnectionHashProvider,
    expected_contract: LiveReadAuthorizationContract,
    audit_sink: LiveReadAuthorizationAuditSink | None = None,
    now: datetime | None = None,
) -> VerifiedLiveReadAuthorization:
    """Load authoritative records and build a binding only after every check passes."""
    audit_sink = audit_sink or NullLiveReadAuthorizationAuditSink()
    now = now or datetime.now(UTC)

    def refuse(
        reason_code: str,
        *,
        execution_target_id: uuid.UUID | None = request.execution_target_id,
        onboarding_id: uuid.UUID | None = request.onboarding_id,
        authorization_id: uuid.UUID | None = request.authorization_id,
        authorization_version: int | None = request.authorization_version,
    ) -> None:
        refusal = LiveReadAuthorizationValidationRefusal(
            reason_code=reason_code,
            organization_id=request.organization_id,
            execution_target_id=execution_target_id,
            onboarding_id=onboarding_id,
            authorization_id=authorization_id,
            authorization_version=authorization_version,
        )
        audit_sink.record_validation_refused(refusal)
        raise LiveReadAuthorizationRefused(reason_code, refusal)

    authorization = repository.get_live_read_authorization(request.authorization_id)
    if authorization is None:
        refuse("authorization_missing", authorization_id=None)

    target = repository.get_execution_target(request.execution_target_id)
    if target is None:
        refuse("execution_target_missing")
    onboarding = repository.get_target_onboarding(request.onboarding_id)
    if onboarding is None:
        refuse("onboarding_missing")

    assert authorization is not None
    assert target is not None
    assert onboarding is not None

    if authorization.organization_id != request.organization_id:
        refuse("wrong_organization")
    if target.organization_id != request.organization_id:
        refuse("wrong_organization")
    if onboarding.organization_id != request.organization_id:
        refuse("wrong_organization")
    if target.organization_id != onboarding.organization_id:
        refuse("wrong_organization")
    if authorization.execution_target_id != request.execution_target_id:
        refuse("wrong_execution_target")
    if authorization.execution_target_id != target.id:
        refuse("wrong_execution_target")
    if authorization.onboarding_id != request.onboarding_id:
        refuse("wrong_onboarding")
    if authorization.onboarding_id != onboarding.id:
        refuse("wrong_onboarding")
    if onboarding.execution_target_id != target.id:
        refuse("wrong_onboarding")
    if target.status != TargetStatus.active:
        refuse("target_not_active")
    if onboarding.status != OnboardingStatus.active:
        refuse("onboarding_not_active")
    credential_ref = target.secret_ref
    if not (isinstance(credential_ref, str) and credential_ref.strip()):
        refuse("target_credential_reference_missing")
    assert isinstance(credential_ref, str)

    status = authorization.status
    if status == LiveReadAuthorizationStatus.draft:
        refuse("authorization_draft")
    if status == LiveReadAuthorizationStatus.revoked:
        refuse("authorization_revoked")
    if status == LiveReadAuthorizationStatus.expired:
        refuse("authorization_expired")
    if status != LiveReadAuthorizationStatus.approved:
        refuse("authorization_not_approved")

    expiry = authorization.authorization_expiry
    if expiry.tzinfo is None:
        refuse("authorization_expiry_malformed")
    if expiry <= now:
        refuse("authorization_expired")

    if authorization.authorization_version != request.authorization_version:
        refuse("authorization_version_drift")
    if authorization.connection_hash != connection_hash_provider.current_connection_hash(target):
        refuse("connection_hash_drift")
    if authorization.boundary_hash != onboarding.boundary_hash:
        refuse("boundary_hash_drift")
    if authorization.evidence_source != expected_contract.evidence_source:
        refuse("evidence_source_drift")
    if authorization.verification_level != expected_contract.verification_level:
        refuse("verification_level_drift")
    if authorization.collector_contract_version != expected_contract.collector_contract_version:
        refuse("collector_contract_version_drift")
    if authorization.endpoint_allowlist_version != expected_contract.endpoint_allowlist_version:
        refuse("endpoint_allowlist_version_drift")

    binding = LiveReadCollectionBinding(
        execution_target_id=str(target.id),
        target_config_hash=authorization.connection_hash,
        onboarding_id=str(onboarding.id),
        boundary_hash=authorization.boundary_hash,
        authorization_id=str(authorization.id),
        authorization_version=authorization.authorization_version,
        authorization_expiry=_canonical_utc(expiry),
        credential_ref=credential_ref,
        evidence_source=authorization.evidence_source,
        verification_level=authorization.verification_level,
        collector_contract_version=authorization.collector_contract_version,
        endpoint_allowlist_version=authorization.endpoint_allowlist_version,
    )
    return VerifiedLiveReadAuthorization(
        execution_target=target,
        onboarding=onboarding,
        authorization=authorization,
        binding=binding,
    )


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(UTC).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"
