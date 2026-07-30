"""Validated, root-gated controller-install options (SECP-PR5H-B2, commit 2b-2).

The root controller installation takes exactly two operator-supplied deployment facts — the
controller's canonical PUBLIC HTTPS origin and which policy-permitted TLS mode to use — and NOTHING
else (no CA path, key, certificate, DB DSN, credential, image tag, or arbitrary path/command). This
module is the closed, validated carrier for those two facts plus the root gate every real
installation write must pass. It is the typed input the 2b-3 install/upgrade lifecycle consumes to
drive the :mod:`~secp_management.controller_tls` producer, the fixed-CA-path locator record, and the
dedicated signer-role provisioning.

Validation is total and bounded: the origin is a clean ``https://host[:port]`` with no userinfo /
path / query / fragment and a DNS (or, only if later permitted, IP) host; the mode is one of the two
closed release modes. The root gate is POSIX-only and fails closed elsewhere. This module opens no
path, runs no subprocess, and reaches no network.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import NoReturn

from secp_management import ManagementError
from secp_management.release_bundle import (
    TLS_MODE_GENERATED_LOCAL_CA,
    TLS_MODE_IMPORTED_ENTERPRISE,
)

_TLS_MODES = (TLS_MODE_GENERATED_LOCAL_CA, TLS_MODE_IMPORTED_ENTERPRISE)
_MAX_ORIGIN_LEN = 269
# a clean canonical https origin: host + optional port, NO userinfo/path/query/fragment. This is the
# SAME grammar the controller-API locator records, so the validated origin round-trips into the
# locator unchanged.
_HTTPS_ORIGIN = re.compile(r"https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ControllerInstallError(ManagementError):
    """A bounded, closed controller-install refusal — only a reason code, never the origin value."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerInstallError(reason_code)


def assert_posix_root() -> None:
    """The install write gate: real production writes require a POSIX root process. Off POSIX (a dev
    host) or as a non-root user this fails closed with a bounded reason, never a silent no-op."""
    if os.name != "posix":
        _reject("controller_install_unsupported_platform")
    if getattr(os, "geteuid")() != 0:  # noqa: B009 - POSIX-only; guarded above
        _reject("controller_install_requires_root")


@dataclass(frozen=True)
class ControllerInstallOptions:
    """The two validated operator-supplied controller-install facts. Its repr is redacted so neither
    the origin nor the mode leaks into an unexpected log context."""

    canonical_origin: str
    tls_mode: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.canonical_origin, str)
            or not (1 <= len(self.canonical_origin) <= _MAX_ORIGIN_LEN)
            or _CONTROL.search(self.canonical_origin)
            or not _HTTPS_ORIGIN.fullmatch(self.canonical_origin)
        ):
            _reject("controller_install_origin_invalid")
        if self.tls_mode not in _TLS_MODES:
            _reject("controller_install_tls_mode_invalid")

    def __repr__(self) -> str:  # never the origin
        return f"ControllerInstallOptions(tls_mode={self.tls_mode!r}, <redacted-origin>)"

    def safe_summary(self) -> dict[str, str]:
        """Public install facts safe for a dry-run plan (the origin IS public deployment info)."""
        return {"canonical_origin": self.canonical_origin, "tls_mode": self.tls_mode}


def build_controller_install_options(
    *, public_origin: str | None, tls_mode: str | None
) -> ControllerInstallOptions:
    """Build the validated options from the ``--public-origin`` / ``--tls-mode`` CLI inputs. Both
    are REQUIRED for a controller install (a missing value is a bounded refusal, never a default
    origin or an implicit mode)."""
    if not public_origin:
        _reject("controller_install_origin_required")
    if not tls_mode:
        _reject("controller_install_tls_mode_required")
    return ControllerInstallOptions(canonical_origin=public_origin, tls_mode=tls_mode)


__all__ = [
    "ControllerInstallError",
    "ControllerInstallOptions",
    "assert_posix_root",
    "build_controller_install_options",
]
