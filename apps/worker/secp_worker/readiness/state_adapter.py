"""Provider-neutral, worker-only remote-state readiness adapter seam (B1B-PR4 / ADR-021 §D, §E).

The adapter is the ONLY thing in SECP that may touch a remote-state backend, and it is EXPLICITLY
INJECTED by the deployment-local worker composition. It is never inferred or discovered from an
environment variable, the backend kind, ``PATH``, an installed SDK, a URL string, or caller data.
The shipped default (:class:`SealedRemoteStateReadinessAdapter`) refuses.

**No state-body surface exists.** The :class:`RemoteStateReadinessAdapter` protocol declares exactly
two members — ``contract_version`` and ``evaluate`` — and
:data:`~secp_api.readiness_contract.FORBIDDEN_STATE_ADAPTER_METHODS` names the methods an adapter
may
never expose (``get_state``, ``read_state``, ``download_state``, ``upload_state``, ``write_state``,
``put_state``, ``restore_state``, ``delete_state``, ``force_unlock``).
:func:`assert_no_state_body_surface` refuses any adapter that exposes one, so a state payload cannot
be read, written, returned, or persisted through this seam — there is no interface for it.

The adapter receives a TYPED authoritative binding (never a raw dict) and may return only a TYPED,
secret-free report. It performs backend CONTROL-METADATA validation only.

**Ephemeral lock probe (backend control metadata, NOT an infrastructure mutation).** An adapter MAY
prove lock capability with a bounded, idempotent lock-metadata probe in a DEDICATED readiness
namespace when its backend supports one. Such a probe must be: idempotent; bounded; released in a
``finally``; safe under cancellation; target/namespace-bound; incapable of force-unlocking another
owner; and it must NEVER read or write an OpenTofu state body. When lock capability cannot be proven
without touching a real state payload, the adapter MUST report it as unprovable — the evaluation
then returns ``unverifiable``, never a fabricated pass. The report declares the probe's outcome
(``probe_released``, ``force_unlock_available``, ``caller_supplied_owner``) and the evaluation
refuses on any unsafe posture.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from secp_api.readiness_contract import (
    ReadinessBinding,
)


class RemoteStateReadinessUnavailable(Exception):
    """The shipped, sealed adapter refuses. Carries a closed, secret-free message."""


@dataclass(frozen=True, repr=False)
class RemoteStateReadinessBinding:
    """The typed authoritative binding handed to a remote-state adapter.

    It embeds the secret-free :class:`~secp_api.readiness_contract.ReadinessBinding` plus the two
    values an adapter needs to prove it is bound to the SAME backend the toolchain profile pins: the
    backend ``kind`` and its OPAQUE ``reference``. Those two values are worker-local: they are never
    persisted, audited, logged, returned by the API, or placed in a Temporal argument — and no
    digest of them is either. The durable evidence carries only the bounded ``state_backend_class``,
    the immutable ``toolchain_profile_hash``, and a namespace identity derived from server-owned
    UUIDs (B1B-PR4 §5).

    ``__repr__`` is redacted so the reference can never leak into a log, exception, or test
    artefact.
    """

    binding: ReadinessBinding
    state_backend_kind: str = field(repr=False)
    state_backend_reference: str = field(repr=False)

    def __repr__(self) -> str:
        return "RemoteStateReadinessBinding(<redacted>)"


@dataclass(frozen=True)
class StateProof:
    """An immutable EXTERNAL proof (encryption-at-rest / backup / restore).

    PR4 VALIDATES a proof; it never invents one and never performs a backup or a restore against
    real state. The proof carries no backup content, no restore content, no path, and no object
    name — only an opaque id, an issuer, a performed-at time, the namespace/backend binding it
    covers, and an expiry.
    """

    # A UUID, never a free label. A label such as ``acme-tfstate.s3.amazonaws.com`` is syntactically
    # valid — and persisting it, OR AN UNSALTED DIGEST OF IT, would put an enumerable backend
    # locator
    # (or a confirmation oracle for one) into durable evidence.
    proof_id: uuid.UUID
    issuer: uuid.UUID
    performed_at: datetime
    # The BACKEND BINDING ANCHOR is the exact immutable ToolchainProfile content hash — never a
    # digest of the backend reference.
    toolchain_profile_hash: str
    namespace_hash: str
    expires_at: datetime | None = None
    # Restore proofs only: a proof that a restore was actually TESTED (not merely offered).
    restore_tested: bool = False


@dataclass(frozen=True)
class LockCapabilityProof:
    """An immutable lock-capability proof for the exact readiness namespace.

    ``lock_capability`` and ``contention_detected`` must BOTH be proven explicitly: a documentation
    flag, a successful metadata read, or a backend type is never sufficient. ``probe_released`` says
    the bounded ephemeral probe was released in a ``finally``. ``force_unlock_available`` and
    ``caller_supplied_owner`` are both REFUSAL conditions.
    """

    proof_id: uuid.UUID
    issuer: uuid.UUID
    performed_at: datetime
    # BOTH bindings are required, exactly like the encryption/backup/restore proofs: a lock proof
    # issued against a DIFFERENT toolchain profile (hence a different backend) must not satisfy this
    # backend's locking facet.
    toolchain_profile_hash: str
    namespace_hash: str
    lock_capability: bool
    contention_detected: bool
    force_unlock_available: bool
    caller_supplied_owner: bool
    probe_released: bool
    expires_at: datetime | None = None


@dataclass(frozen=True, repr=False)
class RemoteStateAdapterReport:
    """The TYPED, secret-free result an adapter may return. Nothing else may cross the seam.

    There is no field for a state body, state JSON, resource identity, object key, backend URL,
    bucket / container name, account id, access key, token, provider body, or lock payload — and the
    evaluation additionally refuses any report whose bounded fields are over-sized (defence against
    an adapter smuggling data into a reason code or a proof id).
    """

    # backend_class ∈ {"remote", "local", "unknown"}; anything not provably remote fails closed.
    backend_class: str
    # The backend kind the adapter is bound to. Compared IN MEMORY against the pinned
    # ToolchainProfile; it is NEVER persisted, audited, or returned.
    backend_kind: str
    # The exact immutable ToolchainProfile content hash the adapter was activated against. This is
    # the BACKEND BINDING ANCHOR: there is deliberately no digest of the backend reference anywhere.
    toolchain_profile_hash: str
    # The namespace identity the adapter WOULD use. It must equal the server-derived identity.
    namespace_identity: str
    # Transport security (§D.2).
    tls_mode: str
    trusted_identity_policy: str
    certificate_validation_enabled: bool
    proxy_inheritance_enabled: bool
    redirect_observed: bool
    destination_stable: bool
    # Namespace occupancy (§D.9). ``None`` = could not be determined WITHOUT reading a state body →
    # unverifiable. It is decided from METADATA/version identity only; the body is never read.
    namespace_state_present: bool | None
    expected_namespace_marker: str = ""
    # Least privilege (§D.8): the EXACT allowed backend actions, or an empty tuple when the scope
    # evidence is unavailable (→ unverifiable; a successful metadata read is never proof).
    allowed_actions: tuple[str, ...] = ()
    scope_evidence_available: bool = False
    # Local fallback (§D.10).
    local_fallback_available: bool = False
    # Proofs (§D.4, §D.5, §D.6, §D.7). ``None`` = absent → the facet fails closed.
    encryption: StateProof | None = None
    locking: LockCapabilityProof | None = None
    backup: StateProof | None = None
    restore: StateProof | None = None
    # Bounded, closed reason codes the adapter itself wants to surface. Free text is refused.
    reason_codes: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return f"RemoteStateAdapterReport(backend_class={self.backend_class!r}, <redacted>)"


@runtime_checkable
class RemoteStateReadinessAdapter(Protocol):
    """The complete adapter surface. There is deliberately NO state-body method.

    An implementation is supplied ONLY by the reviewed deployment-local worker composition.
    """

    @property
    def contract_version(self) -> str:
        """The adapter contract this implementation satisfies. A mismatch fails closed."""
        ...

    def evaluate(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> RemoteStateAdapterReport:
        """Perform bounded backend CONTROL-METADATA validation and return a typed report.

        It must never read or write an OpenTofu state body, never force-unlock, and never return
        state content. Any ephemeral lock probe must be idempotent, bounded, released in a
        ``finally``, cancellation-safe, and namespace-bound.
        """
        ...


class SealedRemoteStateReadinessAdapter:
    """The SHIPPED DEFAULT. It contacts nothing and refuses unconditionally.

    Unsealing is not a configuration flag: a reviewed deployment-local composition must inject a
    real adapter. No environment variable, backend kind, URL, or caller input can produce one.
    """

    @property
    def contract_version(self) -> str:
        from secp_api.readiness_contract import REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        return REMOTE_STATE_ADAPTER_CONTRACT_VERSION

    def evaluate(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> RemoteStateAdapterReport:
        raise RemoteStateReadinessUnavailable(
            "no remote-state readiness adapter is configured; the shipped composition is sealed "
            "and contacts no state backend. Injecting a real adapter is a reviewed "
            "deployment-local change, never a configuration setting."
        )


# The COMPLETE public INVOCABLE surface an adapter may expose. This is an ALLOWLIST, not a denylist:
# a state-body member under ANY name (``fetch_tfstate``, ``pull``, ``blob``…) is refused, not just
# the nine names in :data:`FORBIDDEN_STATE_ADAPTER_METHODS`. Inert public DATA attributes (a test
# fake's call log, a counter) are harmless — they cannot perform I/O on access — and are permitted.
_ALLOWED_ADAPTER_SURFACE = frozenset({"contract_version", "evaluate"})


def _is_invocable(value: object) -> bool:
    """True for a member whose mere ACCESS or CALL could perform I/O.

    Functions, ``property``/descriptor objects, ``classmethod``/``staticmethod``, and any callable.
    Determined from the raw ``__dict__`` value — the descriptor is NEVER invoked.
    """
    return callable(value) or hasattr(type(value), "__get__")


def assert_no_state_body_surface(adapter: object) -> None:
    """Refuse any adapter whose public INVOCABLE surface exceeds ``{contract_version, evaluate}``.

    Structural defence in depth: even a well-behaved ``evaluate`` cannot make an adapter safe if the
    object also carries a state-body member that some future caller could reach.

    **The check never calls ``getattr`` on the instance.** ``getattr`` would EXECUTE a descriptor —
    so an adapter defining ``@property def get_state(self)`` that downloads the state body would
    have that body downloaded *by the guard itself* — performing the very read it exists to prevent.
    Instead this reads the CLASS MRO ``__dict__``s and the instance ``__dict__`` raw values, which
    detects a descriptor without ever invoking it.
    """
    invocable: set[str] = set()
    for klass in type(adapter).__mro__:
        if klass is object:
            continue
        invocable.update(
            name
            for name, value in vars(klass).items()
            if not name.startswith("_") and _is_invocable(value)
        )
    invocable.update(
        name
        for name, value in vars(adapter).items()
        if not name.startswith("_") and _is_invocable(value)
    )

    if invocable - _ALLOWED_ADAPTER_SURFACE:
        # The offending name is NOT echoed: it is attacker-influenced input.
        raise RemoteStateReadinessUnavailable(
            "remote-state readiness adapter exposes an invocable surface beyond "
            "{contract_version, evaluate}; the readiness contract has no member through which an "
            "OpenTofu state payload may be read, written, restored, deleted, or force-unlocked"
        )
