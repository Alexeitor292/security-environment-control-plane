"""Versioned declarative environment-definition schema.

Validation dispatches on ``apiVersion``. The current version is
``controlplane.security/v1alpha1``. Breaking changes require a new version
directory (ADR-002).
"""

from secp_scenario_schema.validator import (
    SchemaValidationError,
    canonicalize,
    content_hash,
    validate_definition,
)

__all__ = [
    "SchemaValidationError",
    "canonicalize",
    "content_hash",
    "validate_definition",
]
