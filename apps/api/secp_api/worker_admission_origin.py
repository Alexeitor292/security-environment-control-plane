"""Fixed application-level origin gate for the private worker-admission surface.

The worker reaches admission through the dedicated TLS proxy.  TLS terminates at that proxy, so
the proxy proves the final in-controller hop with a high-entropy value read from a fixed,
root-controlled file.  The value is deliberately not a setting: callers cannot select a path or
put the secret in an environment variable, compose contract, log record, or evidence document.

The MECHANISM — the opaque non-disclosing secret, the ``[0-9a-f]{64}\\n`` parser, the
``O_NOFOLLOW``/``O_CLOEXEC`` open with ``fstat``-on-descriptor posture proof, and the exactly-one
constant-time header comparison — lives in :mod:`secp_api.fixed_origin_gate` and is shared with the
sibling readiness gate (2b-3c-c Defect-3 A).  What stays here is only this DOMAIN: its own header
name, its own fixed container path, its own opaque secret type and reason codes, and its own
controlled-integration profile rule.  Because the domain authenticates only its own exact secret
type, the readiness gate's material can never admit a worker and vice versa.

This gate is additional transport provenance only.  Worker identity remains the Ed25519
signed-nonce protocol implemented by :mod:`secp_api.services.worker_admission`.
"""

from __future__ import annotations

from typing import ClassVar

from fastapi import Depends, HTTPException, Request

from secp_api.config import Settings
from secp_api.deps import settings_dep
from secp_api.fixed_origin_gate import (
    FIXED_ORIGIN_GATE_FILE_BYTES,
    FixedOriginGate,
    FixedOriginGateError,
    FixedOriginGateSecret,
)

WORKER_ADMISSION_PROXY_GATE_HEADER = "X-SECP-Admission-Proxy-Gate"
WORKER_ADMISSION_PROXY_GATE_CONTAINER_PATH = "/run/secp/admission-proxy-gate.secret"
WORKER_ADMISSION_PROXY_GATE_FILE_BYTES = FIXED_ORIGIN_GATE_FILE_BYTES


class WorkerAdmissionProxyGateError(FixedOriginGateError):
    """The fixed origin-gate secret was absent or failed strict validation."""


class WorkerAdmissionProxyGateSecret(FixedOriginGateSecret):
    """Opaque validated gate material whose repr/str never disclose its value."""

    __slots__ = ()

    reason_prefix: ClassVar[str] = "proxy_gate_secret"
    error_class: ClassVar[type[FixedOriginGateError]] = WorkerAdmissionProxyGateError


#: The ONE worker-admission origin-gate domain. Not caller-selectable in any way.
WORKER_ADMISSION_PROXY_GATE = FixedOriginGate(
    header=WORKER_ADMISSION_PROXY_GATE_HEADER,
    container_path=WORKER_ADMISSION_PROXY_GATE_CONTAINER_PATH,
    secret_class=WorkerAdmissionProxyGateSecret,
)


def parse_worker_admission_proxy_gate(raw: bytes) -> FixedOriginGateSecret:
    """Parse the one closed on-disk representation: 256-bit lowercase hex plus one LF."""

    return WORKER_ADMISSION_PROXY_GATE.parse(raw)


def load_fixed_worker_admission_proxy_gate() -> FixedOriginGateSecret:
    """Read and validate the sole code-owned root-controlled gate path without following links."""

    return WORKER_ADMISSION_PROXY_GATE.load()


def worker_admission_proxy_gate_secret(
    settings: Settings = Depends(settings_dep),
) -> FixedOriginGateSecret | None:
    """Load gate material only for an explicitly enabled controlled-integration profile."""

    if not settings.discovery_controlled_integration_enabled:
        return None
    try:
        return load_fixed_worker_admission_proxy_gate()
    except WorkerAdmissionProxyGateError:
        raise HTTPException(
            status_code=503,
            detail={"code": "worker_admission_proxy_gate_unavailable"},
        ) from None


def require_worker_admission_proxy_origin(
    request: Request,
    settings: Settings = Depends(settings_dep),
    gate: FixedOriginGateSecret | None = Depends(worker_admission_proxy_gate_secret),
) -> None:
    """Refuse enabled admission unless exactly one proxy-injected gate value authenticates."""

    if not settings.discovery_controlled_integration_enabled:
        return
    if gate is None:  # defense in depth against an inconsistent dependency override
        raise HTTPException(
            status_code=503,
            detail={"code": "worker_admission_proxy_gate_unavailable"},
        )
    if not WORKER_ADMISSION_PROXY_GATE.authenticates(gate, request):
        # Hide the private surface and disclose no distinction between absent/malformed/bad values.
        raise HTTPException(status_code=404, detail={"code": "not_found"})


__all__ = [
    "WORKER_ADMISSION_PROXY_GATE",
    "WORKER_ADMISSION_PROXY_GATE_CONTAINER_PATH",
    "WORKER_ADMISSION_PROXY_GATE_FILE_BYTES",
    "WORKER_ADMISSION_PROXY_GATE_HEADER",
    "WorkerAdmissionProxyGateError",
    "WorkerAdmissionProxyGateSecret",
    "load_fixed_worker_admission_proxy_gate",
    "parse_worker_admission_proxy_gate",
    "require_worker_admission_proxy_origin",
    "worker_admission_proxy_gate_secret",
]
