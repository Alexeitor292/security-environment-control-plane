"""Worker-only secret resolution (ADR-007).

Secret references are resolved ONLY here, in the worker, and ONLY immediately
before a provider operation. Resolved secrets are never persisted, logged, or
serialized into snapshots/audit/responses. Errors are redacted.

SECP-002A ships:
- ``EnvSecretResolver`` — a local-dev resolver for the ``env:`` scheme (reads a
  namespaced environment variable). Placeholder for a production secret manager.
- ``FakeSecretResolver`` — an in-memory resolver for tests (never reads real env).
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from secp_api.secret_refs import parse_secret_ref
from secp_plugin_api.v1 import ProviderCredential


class SecretResolutionError(Exception):
    """Raised when a secret reference cannot be resolved.

    The message is REDACTED: it identifies the reference shape but never includes
    the secret value (there is none on failure) nor the raw locator value beyond
    what is needed to debug.
    """


@runtime_checkable
class SecretResolver(Protocol):
    def resolve(self, secret_ref: str) -> ProviderCredential: ...


class EnvSecretResolver:
    """Resolve ``env:SECP_PROVIDER_SECRET__<NAME>`` from the environment.

    Local-development placeholder for a real secret manager. The interface accepts
    additional schemes without changing callers (ADR-007).
    """

    def resolve(self, secret_ref: str) -> ProviderCredential:
        scheme, locator = parse_secret_ref(secret_ref)  # raises on bad syntax
        if scheme != "env":
            raise SecretResolutionError(f"EnvSecretResolver cannot resolve scheme '{scheme}'")
        value = os.environ.get(locator)
        if not value:
            # Redacted: name the missing variable, never a value.
            raise SecretResolutionError(f"secret for reference scheme '{scheme}' is not available")
        return ProviderCredential(secret=value)


class FakeSecretResolver:
    """In-memory resolver for tests. Never reads real environment secrets."""

    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._mapping = dict(mapping or {})

    def set(self, secret_ref: str, value: str) -> None:
        self._mapping[secret_ref] = value

    def resolve(self, secret_ref: str) -> ProviderCredential:
        parse_secret_ref(secret_ref)  # enforce valid syntax even in tests
        if secret_ref not in self._mapping:
            raise SecretResolutionError("secret for reference is not available")
        return ProviderCredential(secret=self._mapping[secret_ref])
