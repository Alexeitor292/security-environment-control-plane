"""Domain errors. These map to HTTP responses in the API layer."""

from __future__ import annotations


class DomainError(Exception):
    """Base class for control-plane domain errors."""

    http_status = 400
    code = "domain_error"
    # When True, the HTTP handler serializes ONLY the closed ``code`` (no free-form message,
    # details, or rejected input). Existing errors keep their message (redacted=False).
    redacted = False

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ReadonlyPreflightError(DomainError):
    """Closed-code, message-redacted error for the read-only preflight feature (SECP-B2-0).

    The HTTP layer serializes only the closed code (``{"error": {"code": ...}}``); no free-form
    backend message reaches the API/UI. Constructed from the closed
    :class:`~secp_api.enums.ReadonlyPreflightErrorCode` catalog.
    """

    redacted = True

    _STATUS = {
        "readonly_preflight_not_found": 404,
        "readonly_preflight_forbidden": 403,
        "readonly_preflight_substrate_ineligible": 409,
        "readonly_preflight_authorization_invalid": 409,
        "readonly_preflight_lifecycle_conflict": 409,
        "readonly_preflight_queue_conflict": 409,
        "readonly_preflight_internal_failure": 500,
    }

    def __init__(self, code: object) -> None:
        # ``code`` is a ReadonlyPreflightErrorCode (imported lazily to avoid an enums import cycle).
        code_value = getattr(code, "value", str(code))
        # The internal message is never serialized (redacted); it aids server-side debugging only.
        super().__init__(code_value)
        self.code = code_value
        self.http_status = self._STATUS.get(code_value, 400)


class ResolverActivationError(DomainError):
    """Closed-code, message-redacted error for resolver-activation authorization (SECP-B2-4.1).

    The HTTP layer serializes only the closed code (``{"error": {"code": ...}}``); no free-form
    backend message, evidence value, or reference reaches the API/UI.
    """

    redacted = True
    # True when this fail-closed refusal ALSO materialized a durable, revision-safe state transition
    # (e.g. expiring a stale authorization + its single expiration audit) that MUST be committed
    # even though the request errors. The router commits before re-raising so the transition
    # survives the request while the caller still receives the closed refusal.
    durable_transition: bool = False

    _STATUS = {
        "resolver_activation_not_found": 404,
        "resolver_activation_forbidden": 403,
        "resolver_activation_invalid_state": 409,
        "resolver_activation_substrate_ineligible": 409,
        "resolver_activation_evidence_incomplete": 409,
        "resolver_activation_evidence_invalid": 422,
        "resolver_activation_lifecycle_conflict": 409,
        "resolver_activation_internal_failure": 500,
    }

    def __init__(self, code: object) -> None:
        code_value = getattr(code, "value", str(code))
        super().__init__(code_value)
        self.code = code_value
        self.http_status = self._STATUS.get(code_value, 400)


class TopologyAuthoringError(DomainError):
    """Closed-code, message-redacted error for topology draft authoring (SECP-B9).

    The HTTP layer serializes only the closed code (``{"error": {"code": ...}}``);
    no free-form backend message, rejected input, or topology content reaches the
    API/UI. Codes are :class:`~secp_api.enums.TopologyAuthoringErrorCode` values.
    """

    redacted = True
    # True when a fail-closed refusal ALSO recorded a durable refusal audit event
    # that must survive the request. The router commits before re-raising.
    durable_transition: bool = False

    _STATUS = {
        "topology_not_found": 404,
        "topology_revision_not_found": 404,
        "topology_source_not_found": 404,
        "topology_permission_denied": 403,
        "topology_cross_org_forbidden": 403,
        "topology_revision_stale": 409,
        "topology_hash_mismatch": 409,
        "topology_revision_not_current": 409,
        "topology_validation_required": 409,
        "topology_validation_not_current": 409,
        "topology_already_submitted": 409,
        "topology_revision_immutable": 409,
        "topology_approval_required": 409,
        "topology_not_submitted": 409,
        "topology_schema_invalid": 422,
        "topology_document_too_large": 413,
        "topology_secret_field_forbidden": 422,
        "topology_unknown_object_kind": 422,
        "topology_invalid_relationship": 422,
    }

    def __init__(self, code: object) -> None:
        code_value = getattr(code, "value", str(code))
        super().__init__(code_value)
        self.code = code_value
        self.http_status = self._STATUS.get(code_value, 400)


class WorkerIdentityError(DomainError):
    """Closed-code, message-redacted error for worker-identity registration (SECP-B2-4.3).

    The HTTP layer serializes only the closed code (``{"error": {"code": ...}}``); no free-form
    message, identity value, anchor, deployment binding, or evidence value reaches the API/UI.
    """

    redacted = True
    # True when a fail-closed refusal ALSO materialized a durable, revision-safe transition (e.g.
    # expiring a stale registration + its single expiration audit) that MUST be committed even when
    # the request errors. The router commits before re-raising so the transition survives the call.
    durable_transition: bool = False

    _STATUS = {
        "worker_identity_not_found": 404,
        "worker_identity_forbidden": 403,
        "worker_identity_invalid_state": 409,
        "worker_identity_invalid_metadata": 422,
        "worker_identity_evidence_incomplete": 409,
        "worker_identity_lifecycle_conflict": 409,
        "worker_identity_internal_failure": 500,
    }

    def __init__(self, code: object) -> None:
        code_value = getattr(code, "value", str(code))
        super().__init__(code_value)
        self.code = code_value
        self.http_status = self._STATUS.get(code_value, 400)


class NotFoundError(DomainError):
    http_status = 404
    code = "not_found"


class AuthorizationError(DomainError):
    http_status = 403
    code = "forbidden"


class AuthenticationError(DomainError):
    http_status = 401
    code = "unauthenticated"


class ImmutableResourceError(DomainError):
    http_status = 409
    code = "immutable_resource"


class InvalidTransitionError(DomainError):
    http_status = 409
    code = "invalid_transition"


class ApprovalRequiredError(DomainError):
    http_status = 409
    code = "approval_required"


class ProvisioningRefusedError(DomainError):
    """Raised when a (fake) provisioning operation is refused by the safety gate."""

    http_status = 403
    code = "provisioning_refused"


class ValidationFailedError(DomainError):
    http_status = 422
    code = "validation_failed"

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = errors or []


class LiveEvidenceSealedError(ValidationFailedError):
    """Raised when code attempts to create live_verified / provider_worker onboarding
    evidence while the SECP-002B-1B-0 live-evidence seal is in force (correction pass).

    Live evidence collection is a future B1-B capability; in this release the seal is an
    unconditional code-level constant, not a configuration toggle. Subclasses
    ``ValidationFailedError`` so existing validation handlers still surface it.
    """

    http_status = 403
    code = "live_evidence_sealed"
