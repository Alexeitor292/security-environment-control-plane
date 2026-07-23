"""Domain errors. These map to HTTP responses in the API layer."""

from __future__ import annotations


class DomainError(Exception):
    """Base class for control-plane domain errors."""

    http_status = 400
    code = "domain_error"
    # When True, the HTTP handler serializes ONLY the closed ``code`` (no free-form message,
    # details, or rejected input). Existing errors keep their message (redacted=False).
    redacted = False
    # When set (e.g. "Bearer"), the HTTP handler adds a ``WWW-Authenticate`` response header.
    # Only the authentication errors set this; every other error leaves it None.
    www_authenticate: str | None = None

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


class ReadinessError(DomainError):
    """Closed-code, message-redacted error for the B1B-PR4 readiness surface (ADR-021 §P).

    The HTTP layer serializes only the closed code (``{"error": {"code": ...}}``). No backend
    message, endpoint, backend URL, state key, secret reference, evidence value, adapter detail,
    rejected caller value, or exception body ever reaches the API/UI.
    """

    redacted = True
    # True when a fail-closed refusal ALSO materialized a durable, revision-safe transition (e.g.
    # expiring a stale authorization + its single expiry audit) that must be committed even though
    # the request errors. The router commits before re-raising.
    durable_transition: bool = False

    _STATUS = {
        "not_found": 404,
        "forbidden": 403,
        "invalid_state": 409,
        "binding_invalid": 409,
        "evidence_incomplete": 409,
        "evidence_invalid": 422,
        "lifecycle_conflict": 409,
        "internal_failure": 500,
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


class EnvironmentPublicationError(DomainError):
    """Closed-code, message-redacted error for EnvironmentVersion publication (SECP-B10 / ADR-016).

    The publication service maps every failure (including pure ``PublicationContractError`` codes)
    onto a closed :class:`~secp_api.enums.EnvironmentPublicationErrorCode`; no backend exception
    text, IntegrityError, ValidationError, or SchemaValidationError escapes. PR C adds the complete
    closed per-code HTTP status map below — every enum member is mapped deliberately; an unknown
    code fails closed to 500 rather than leaking through a generic default.
    """

    redacted = True

    # Complete, explicit EnvironmentPublicationErrorCode -> HTTP status map (ADR-016 PR C). Keep in
    # sync with the enum; a boundary test asserts every member is present.
    _STATUS = {
        # 403 Forbidden — authorization / cross-org
        "version_publish_permission_denied": 403,
        "version_publish_cross_org_forbidden": 403,
        "version_publish_base_version_cross_org_forbidden": 403,
        # 404 Not Found — a referenced object does not exist for this actor
        "version_publish_template_not_found": 404,
        "version_publish_topology_not_found": 404,
        "version_publish_validation_missing": 404,
        "version_publish_base_version_not_found": 404,
        # 409 Conflict — state/precondition/idempotency conflicts
        "version_publish_topology_not_approved": 409,
        "version_publish_topology_hash_mismatch": 409,
        "version_publish_validation_not_passing": 409,
        "version_publish_validation_stale": 409,
        "version_publish_base_version_required": 409,
        "version_publish_base_version_mismatch": 409,
        "version_publish_template_mismatch": 409,
        "version_publish_conflict": 409,
        # 422 Unprocessable Entity — malformed/forbidden caller content in the definition
        "version_publish_definition_invalid": 422,
        "version_publish_topology_in_payload_forbidden": 422,
        "version_publish_provenance_in_payload_forbidden": 422,
        "version_publish_topology_invalid": 422,
        "version_publish_provenance_invalid": 422,
        "version_publish_role_topology_mismatch": 422,
        "version_publish_network_topology_mismatch": 422,
        "version_publish_unsupported_role_kind": 422,
        # 500 Internal — durable refusal auditing itself failed (no version persisted)
        "version_publish_audit_failure": 500,
    }

    def __init__(self, code: object) -> None:
        code_value = getattr(code, "value", str(code))
        # The internal message equals the code; it is never serialized (redacted).
        super().__init__(code_value)
        self.code = code_value
        # Fail closed: an unmapped code becomes 500 rather than leaking through a generic default.
        self.http_status = self._STATUS.get(code_value, 500)


class PlanVersionBindingError(DomainError):
    """Closed-code, message-redacted error for an impossible/corrupted DeploymentPlan <-> one
    EnvironmentVersion binding (ADR-016 PR E). The HTTP layer serializes ONLY the closed code —
    no expected/actual hash, version/template/exercise id, spec, or raw database text — so an
    external caller cannot probe which field disagreed. Server logs may name the invariant
    category without logging definition/topology content."""

    redacted = True
    http_status = 409
    code = "plan_version_binding_invalid"

    def __init__(self, message: str = "plan/version binding invalid") -> None:
        super().__init__(message)


class NotFoundError(DomainError):
    http_status = 404
    code = "not_found"


class AuthorizationError(DomainError):
    http_status = 403
    code = "forbidden"


class AuthenticationError(DomainError):
    """Closed, redacted authentication refusal (ADR-017). The HTTP layer serializes ONLY the closed
    code ``{"error": {"code": "unauthenticated"}}`` with a ``WWW-Authenticate: Bearer`` header — it
    NEVER reveals whether the cause was a bad signature, expiration, issuer, audience, kid, missing
    subject, unknown internal user, malformed token, provider response, or network failure. The
    internal message aids server-side debugging only and is never sent to the caller."""

    http_status = 401
    code = "unauthenticated"
    redacted = True
    www_authenticate = "Bearer"


class AuthenticationUnavailableError(DomainError):
    """Closed, redacted 503 for a TEMPORARY verifier-infrastructure failure — the token could not be
    checked because discovery/JWKS is unavailable or malformed (ADR-017). Distinct from a definitive
    401 refusal: the caller may retry. The body is ONLY ``{"error": {"code":
    "authentication_unavailable"}}`` with a ``WWW-Authenticate: Bearer`` header; no provider URL,
    response body, or exception text is ever exposed."""

    http_status = 503
    code = "authentication_unavailable"
    redacted = True
    www_authenticate = "Bearer"

    def __init__(self, message: str = "authentication temporarily unavailable") -> None:
        super().__init__(message)


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


class WorkerEnrollmentError(DomainError):
    """Closed-code, message-redacted error for durable worker enrollment (SECP-PR5H-A, ADR-027).

    The HTTP layer serializes ONLY the closed ``code`` — never a free-form message, a rejected
    input, key material, a host path, an endpoint, an identity or a raw internal exception. The code
    is a bounded ``enrollment_*`` value; it may be a persistence/service code OR a surfaced pure
    transition-contract code (ADR-027 "delegate, never pre-screen").

    ``durable_transition`` marks a fail-closed refusal that ALSO materialized a durable,
    revision-safe transition (e.g. driving a corrupted row to ``recovery_required``) which must be
    committed even though the request errors; the router commits before re-raising.
    """

    redacted = True
    durable_transition: bool = False

    _STATUS = {
        "enrollment_schema_unavailable": 503,
        "enrollment_not_found": 404,
        "enrollment_forbidden": 403,
        "enrollment_scope_mismatch": 409,
        "enrollment_revision_conflict": 409,
        "enrollment_state_corrupt": 409,
        "enrollment_history_inconsistent": 409,
        "enrollment_receipt_conflict": 409,
        "enrollment_invitation_not_found": 404,
        "enrollment_invitation_consumed": 409,
        "enrollment_invitation_revoked": 409,
        "enrollment_invitation_expired": 409,
        "enrollment_invitation_conflict": 409,
        "enrollment_creation_conflict": 409,
        "enrollment_internal_failure": 500,
        # surfaced pure transition-contract codes: an invalid input is 422, a state/lifecycle
        # conflict is 409 (the default for anything not explicitly listed)
        "enrollment_invitation_invalid": 422,
        "enrollment_trust_anchor_invalid": 422,
        "enrollment_origin_not_https": 422,
        "enrollment_time_invalid": 422,
        "enrollment_handoff_invalid": 422,
        "enrollment_reason_code_invalid": 422,
    }

    def __init__(self, code: object, *, durable_transition: bool = False) -> None:
        code_value = getattr(code, "value", str(code))
        super().__init__(code_value)
        self.code = code_value
        self.http_status = self._STATUS.get(code_value, 409)
        self.durable_transition = durable_transition
