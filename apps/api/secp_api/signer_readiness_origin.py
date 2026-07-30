"""Fixed application-level origin gate for the private signer-READINESS surface (2b-3c-c, Defect-3).

Defect-3 B: the readiness surface was reachable by ANY peer that could reach the controller API's
origin. It is a private, root-installer-only observation surface — the management plane's ONE way to
learn the API's ACTUAL effective signer — so it must prove the final in-controller hop exactly the
way the worker-admission surface does, with its OWN material.

The MECHANISM is the shared :mod:`secp_api.fixed_origin_gate` primitive (opaque non-disclosing
secret, ``[0-9a-f]{64}\\n`` parser, ``O_NOFOLLOW``/``O_CLOEXEC`` open with ``fstat``-on-descriptor
posture proof, exactly-one constant-time header comparison). What is defined HERE is only this
DOMAIN, and every part of it is DISTINCT from worker admission:

* a distinct header — :data:`ENROLLMENT_SIGNER_READINESS_GATE_HEADER`;
* a distinct fixed code-owned container path —
  :data:`ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH` — fed by a distinct root-owned host file
  (:data:`ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH`, named in the plane-neutral commissioning
  contract because the management writer may never import ``secp_api``);
* a distinct opaque secret TYPE and a distinct closed reason-code prefix.

Because a domain authenticates only its OWN exact secret type, the worker-admission gate value can
never open the readiness surface and the readiness gate value can never admit a worker — even if an
operator installed byte-identical secrets in both files.

There is NO feature flag on this surface, unlike admission's controlled-integration profile. The
gate FILE is the configuration: absence of the file on an unconfigured controller means the surface
simply does not exist (404), while a PRESENT gate that cannot be proven safe is a bounded 503 — a
configured control that fails to load never silently opens the surface.
"""

from __future__ import annotations

from typing import ClassVar

from fastapi import Depends, HTTPException, Request
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
    ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES,
    ENROLLMENT_SIGNER_READINESS_GATE_HEADER,
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
)

from secp_api.fixed_origin_gate import (
    FixedOriginGate,
    FixedOriginGateError,
    FixedOriginGateSecret,
)

#: The bounded code returned when a PRESENT gate could not be proven safe/readable.
READINESS_GATE_UNAVAILABLE_CODE = "enrollment_signer_readiness_gate_unavailable"


class EnrollmentSignerReadinessGateError(FixedOriginGateError):
    """The fixed readiness origin-gate secret was absent or failed strict validation."""


class EnrollmentSignerReadinessGateSecret(FixedOriginGateSecret):
    """Opaque validated readiness-gate material whose repr/str never disclose its value.

    A DISTINCT type from the worker-admission secret, which is what makes cross-domain acceptance
    structurally impossible rather than merely improbable."""

    __slots__ = ()

    reason_prefix: ClassVar[str] = "readiness_gate_secret"
    error_class: ClassVar[type[FixedOriginGateError]] = EnrollmentSignerReadinessGateError


#: The ONE readiness origin-gate domain. Not caller-selectable in any way.
ENROLLMENT_SIGNER_READINESS_GATE = FixedOriginGate(
    header=ENROLLMENT_SIGNER_READINESS_GATE_HEADER,
    container_path=ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
    secret_class=EnrollmentSignerReadinessGateSecret,
    file_bytes=ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES,
)


def parse_enrollment_signer_readiness_gate(raw: bytes) -> FixedOriginGateSecret:
    """Parse the one closed on-disk representation: 256-bit lowercase hex plus one LF."""

    return ENROLLMENT_SIGNER_READINESS_GATE.parse(raw)


def load_fixed_enrollment_signer_readiness_gate() -> FixedOriginGateSecret:
    """Read and validate the sole code-owned root-controlled gate path without following links."""

    return ENROLLMENT_SIGNER_READINESS_GATE.load()


def enrollment_signer_readiness_gate_secret() -> FixedOriginGateSecret | None:
    """Load the fixed readiness-gate material.

    ``None`` means the gate file is ABSENT — this controller was never configured with a readiness
    gate, so the surface is not available at all and the caller renders a plain 404. A PRESENT gate
    that is unsafe, unreadable or malformed is a bounded 503: a configured control that cannot be
    proven never degrades into an open surface.
    """

    try:
        return load_fixed_enrollment_signer_readiness_gate()
    except FixedOriginGateError as exc:
        if exc.absent:
            return None
        raise HTTPException(
            status_code=503,
            detail={"code": READINESS_GATE_UNAVAILABLE_CODE},
        ) from None


def require_enrollment_signer_readiness_origin(
    request: Request,
    gate: FixedOriginGateSecret | None = Depends(enrollment_signer_readiness_gate_secret),
) -> None:
    """Refuse the readiness surface unless exactly one injected gate value authenticates.

    Attached as a ROUTER-level dependency, so it runs BEFORE any route body: an unauthorized request
    never reaches the observation, never opens or connects the broker socket, and never performs the
    no-sign exchange. An unconfigured gate, a missing/duplicate/malformed/wrong header value and a
    value from another gate domain are ALL the same bare 404 — the surface discloses no distinction
    between "not deployed here" and "you did not authenticate".
    """

    if gate is None or not ENROLLMENT_SIGNER_READINESS_GATE.authenticates(gate, request):
        raise HTTPException(status_code=404, detail={"code": "not_found"})


__all__ = [
    "ENROLLMENT_SIGNER_READINESS_GATE",
    "ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH",
    "ENROLLMENT_SIGNER_READINESS_GATE_FILE_BYTES",
    "ENROLLMENT_SIGNER_READINESS_GATE_HEADER",
    "ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH",
    "READINESS_GATE_UNAVAILABLE_CODE",
    "EnrollmentSignerReadinessGateError",
    "EnrollmentSignerReadinessGateSecret",
    "enrollment_signer_readiness_gate_secret",
    "load_fixed_enrollment_signer_readiness_gate",
    "parse_enrollment_signer_readiness_gate",
    "require_enrollment_signer_readiness_origin",
]
