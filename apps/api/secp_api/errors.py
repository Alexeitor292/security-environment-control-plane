"""Domain errors. These map to HTTP responses in the API layer."""

from __future__ import annotations


class DomainError(Exception):
    """Base class for control-plane domain errors."""

    http_status = 400
    code = "domain_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


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
