"""Toolchain provenance verification seam (SECP-002B-1A, ADR-013) — worker-only.

Before init/plan/apply/destroy, the ``OpenTofuRunner`` requires *proof* that the pinned
toolchain provenance holds: executable identity, exact version, binary-integrity digest,
module-bundle identity/hash, provider lockfile hash, offline provider-mirror identity, and
renderer version.

In B1-A the only verifier is ``FakeToolchainVerifier`` — it attests the pinned values
**without inspecting any real binary, file, provider, or mirror**. ``RealToolchainVerifier``
is an inert scaffold that raises if constructed/used; it is **not constructed anywhere in
B1-A**. No real verification (filesystem, digest, network) occurs in this PR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# The provenance facets the runner requires proof of before executing.
_REQUIRED_FACETS = (
    "executable",
    "version",
    "binary_digest",
    "module_bundle",
    "lockfile",
    "mirror",
    "renderer",
)


@dataclass(frozen=True)
class ToolchainVerification:
    """Attestation that each pinned provenance facet has been verified."""

    verified: frozenset[str] = field(default_factory=frozenset)
    reasons: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return set(_REQUIRED_FACETS).issubset(self.verified)

    def missing(self) -> list[str]:
        return sorted(set(_REQUIRED_FACETS) - set(self.verified))


@runtime_checkable
class ToolchainVerifier(Protocol):
    """Attest pinned toolchain provenance without leaking secrets."""

    def verify(self, profile: dict) -> ToolchainVerification: ...


class FakeToolchainVerifier:
    """B1-A verifier. Attests provenance facets without touching real binaries/files.

    ``attest`` selects which facets are attested (default: all), so tests can simulate a
    verifier that fails a specific facet.
    """

    def __init__(self, attest: frozenset[str] | set[str] | None = None) -> None:
        self._attest = frozenset(attest if attest is not None else _REQUIRED_FACETS)

    def verify(self, profile: dict) -> ToolchainVerification:
        # No I/O: this is a fake attestation of the pinned values already present in the
        # (validated) profile. A real verifier (B1-B) would check the binary digest, the
        # provider lockfile, and the offline mirror.
        missing = set(_REQUIRED_FACETS) - set(self._attest)
        reasons = tuple(f"facet not attested: {m}" for m in sorted(missing))
        return ToolchainVerification(verified=frozenset(self._attest), reasons=reasons)


class RealToolchainVerifier:
    """Inert scaffold for the future real verifier (B1-B). Never constructed in B1-A."""

    def __init__(self, *_args, **_kwargs) -> None:  # pragma: no cover - B1-B only
        raise NotImplementedError(
            "RealToolchainVerifier is not available in SECP-002B-1A; real binary/provider/"
            "mirror verification is a reviewed disposable-lab (B1-B) concern"
        )

    def verify(self, profile: dict) -> ToolchainVerification:  # pragma: no cover - B1-B only
        raise NotImplementedError
