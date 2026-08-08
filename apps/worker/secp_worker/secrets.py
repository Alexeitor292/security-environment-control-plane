"""Worker-only secret resolution (ADR-007).

Secret references are resolved ONLY here, in the worker, and ONLY immediately
before a provider operation. Resolved secrets are never persisted, logged, or
serialized into snapshots/audit/responses. Errors are redacted.

Three implementations, and exactly one of them is what production composes:

- ``SealedProviderSecretResolver`` — the SHIPPED default. Resolves nothing, reads no
  environment, contacts no backend. A deployment that has not composed a trusted
  secret backend refuses before target contact rather than falling back.
- ``EnvSecretResolver`` — **DEVELOPMENT AND TEST ONLY**. It reads ``os.environ``.
  It was wired into the shipped Temporal discovery activity, which meant a
  production Proxmox credential could come from an environment variable; that is
  the reachability this module's guard now forbids.
- ``FakeSecretResolver`` — an in-memory resolver for tests (never reads real env).

WHY THE ENV RESOLVER STILL EXISTS
----------------------------------
Deleting it outright would push local development onto some other ad-hoc path, and
an undocumented one is worse than a named one. What matters is that no production
composition can REACH it — asserted structurally by
``test_production_worker_composition_cannot_reach_the_env_resolver`` rather than by
this docstring. A stale ``SECP_PROVIDER_SECRET__*`` variable in a deployment
environment is therefore inert.
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


class SealedProviderSecretResolver:
    """The SHIPPED resolver. Always fails closed; reads nothing.

    It implements :class:`SecretResolver` so the discovery seam is satisfied structurally, and then
    refuses — which is the honest state of a deployment with no trusted secret backend composed.
    The alternative it replaces was reading ``os.environ``, and the difference matters more than it
    looks: a missing environment variable and a missing BACKEND are different facts, and the env
    resolver reported the first while the operator needed to know the second.

    A future reviewed composition injects a real worker-only backend-backed resolver here. Until
    then a live discovery terminates as unavailable rather than resolving a credential from a place
    nothing authorized.
    """

    def resolve(self, secret_ref: str) -> ProviderCredential:
        parse_secret_ref(secret_ref)  # still enforce the reference grammar before refusing
        raise SecretResolutionError(
            "no trusted secret backend is composed for this worker; provider credentials are "
            "never read from the environment or the filesystem"
        )


class EnvSecretResolver:
    """DEV AND TEST ONLY — resolves ``env:SECP_PROVIDER_SECRET__<NAME>`` from ``os.environ``.

    **Not reachable from any production composition**, and a structural test enforces that. It was
    previously constructed by the shipped Temporal discovery activity, which made a production
    Proxmox credential sourceable from an environment variable.
    """

    def resolve(self, secret_ref: str) -> ProviderCredential:
        scheme, locator = parse_secret_ref(secret_ref)  # raises on bad syntax
        if scheme != "env":
            raise SecretResolutionError(f"EnvSecretResolver cannot resolve scheme '{scheme}'")
        value = os.environ.get(locator)
        if not value:
            # Redacted: name the missing variable, never a value.
            raise SecretResolutionError(f"secret for reference scheme '{scheme}' is not available")
        return ProviderCredential.from_secret(value)


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
        return ProviderCredential.from_secret(self._mapping[secret_ref])
