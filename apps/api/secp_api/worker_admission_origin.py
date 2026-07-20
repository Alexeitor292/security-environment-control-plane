"""Fixed application-level origin gate for the private worker-admission surface.

The worker reaches admission through the dedicated TLS proxy.  TLS terminates at that proxy, so
the proxy proves the final in-controller hop with a high-entropy value read from a fixed,
root-controlled file.  The value is deliberately not a setting: callers cannot select a path or
put the secret in an environment variable, compose contract, log record, or evidence document.

This gate is additional transport provenance only.  Worker identity remains the Ed25519
signed-nonce protocol implemented by :mod:`secp_api.services.worker_admission`.
"""

from __future__ import annotations

import hmac
import os
import re
import stat

from fastapi import Depends, HTTPException, Request

from secp_api.config import Settings
from secp_api.deps import settings_dep

WORKER_ADMISSION_PROXY_GATE_HEADER = "X-SECP-Admission-Proxy-Gate"
WORKER_ADMISSION_PROXY_GATE_CONTAINER_PATH = "/run/secp/admission-proxy-gate.secret"
WORKER_ADMISSION_PROXY_GATE_FILE_BYTES = 65

_HEADER_NAME_BYTES = WORKER_ADMISSION_PROXY_GATE_HEADER.lower().encode("ascii")
_SECRET_PATTERN = re.compile(rb"[0-9a-f]{64}\n")
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class WorkerAdmissionProxyGateError(RuntimeError):
    """The fixed origin-gate secret was absent or failed strict validation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class WorkerAdmissionProxyGateSecret:
    """Opaque validated gate material whose repr/str never disclose its value."""

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if not isinstance(value, bytes) or not re.fullmatch(rb"[0-9a-f]{64}", value):
            raise WorkerAdmissionProxyGateError("proxy_gate_secret_invalid")
        self.__value = value

    def __repr__(self) -> str:
        return "WorkerAdmissionProxyGateSecret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def header_value(self) -> str:
        """Return the value only for construction of the proxy's single upstream request."""

        return self.__value.decode("ascii")

    def matches_raw_header_values(self, values: tuple[bytes, ...]) -> bool:
        """Verify exactly one raw header value with a fixed-size constant-time comparison."""

        exactly_one = len(values) == 1
        candidate = values[0] if exactly_one and len(values[0]) == len(self.__value) else b"\0" * 64
        matches = hmac.compare_digest(self.__value, candidate)
        return exactly_one and len(values[0]) == len(self.__value) and matches


def parse_worker_admission_proxy_gate(raw: bytes) -> WorkerAdmissionProxyGateSecret:
    """Parse the one closed on-disk representation: 256-bit lowercase hex plus one LF."""

    if not isinstance(raw, bytes) or len(raw) != WORKER_ADMISSION_PROXY_GATE_FILE_BYTES:
        raise WorkerAdmissionProxyGateError("proxy_gate_secret_size_invalid")
    if _SECRET_PATTERN.fullmatch(raw) is None:
        raise WorkerAdmissionProxyGateError("proxy_gate_secret_format_invalid")
    return WorkerAdmissionProxyGateSecret(raw[:-1])


def load_fixed_worker_admission_proxy_gate() -> WorkerAdmissionProxyGateSecret:
    """Read and validate the sole code-owned root-controlled gate path without following links."""

    path = WORKER_ADMISSION_PROXY_GATE_CONTAINER_PATH
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError:
        raise WorkerAdmissionProxyGateError("proxy_gate_secret_open_failed") from None
    try:
        metadata = os.fstat(fd)
        mode = metadata.st_mode & 0o7777
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != 0
            or metadata.st_gid <= 0
            or mode != 0o640
            or metadata.st_size != WORKER_ADMISSION_PROXY_GATE_FILE_BYTES
        ):
            raise WorkerAdmissionProxyGateError("proxy_gate_secret_metadata_invalid")
        raw = os.read(fd, WORKER_ADMISSION_PROXY_GATE_FILE_BYTES + 1)
        if len(raw) != metadata.st_size:
            raise WorkerAdmissionProxyGateError("proxy_gate_secret_read_invalid")
        return parse_worker_admission_proxy_gate(raw)
    finally:
        os.close(fd)


def worker_admission_proxy_gate_secret(
    settings: Settings = Depends(settings_dep),
) -> WorkerAdmissionProxyGateSecret | None:
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
    gate: WorkerAdmissionProxyGateSecret | None = Depends(worker_admission_proxy_gate_secret),
) -> None:
    """Refuse enabled admission unless exactly one proxy-injected gate value authenticates."""

    if not settings.discovery_controlled_integration_enabled:
        return
    if gate is None:  # defense in depth against an inconsistent dependency override
        raise HTTPException(
            status_code=503,
            detail={"code": "worker_admission_proxy_gate_unavailable"},
        )
    raw_values = tuple(
        value
        for name, value in request.scope.get("headers", ())
        if name.lower() == _HEADER_NAME_BYTES
    )
    if not gate.matches_raw_header_values(raw_values):
        # Hide the private surface and disclose no distinction between absent/malformed/bad values.
        raise HTTPException(status_code=404, detail={"code": "not_found"})


__all__ = [
    "WORKER_ADMISSION_PROXY_GATE_HEADER",
    "WORKER_ADMISSION_PROXY_GATE_CONTAINER_PATH",
    "WORKER_ADMISSION_PROXY_GATE_FILE_BYTES",
    "WorkerAdmissionProxyGateError",
    "WorkerAdmissionProxyGateSecret",
    "parse_worker_admission_proxy_gate",
    "load_fixed_worker_admission_proxy_gate",
    "worker_admission_proxy_gate_secret",
    "require_worker_admission_proxy_origin",
]
