"""Immutable, secret-free Proxmox target-configuration model + parser (SECP-002B-1B-4).

Plugin-owned. Accepts **exactly** three fields — ``base_url``, ``verify_tls``, ``credential_ref``
— and nothing else. It rejects unknown keys (including any secret-like field such as
token/password/secret/cookie/headers/credential), nested values, and non-string/non-boolean
types. ``base_url`` must be a valid exact Proxmox HTTPS API root, ``verify_tls`` must be exactly
``True``, and ``credential_ref`` must be a non-empty **opaque** string (a reference, never a
secret value).

Rejected raw configuration values are never logged, serialized, returned, or hashed — parse
errors report only field/key names and value *types*, never values. The validated model exposes
a deterministic **connection representation** containing ONLY ``base_url`` + ``verify_tls`` — the
only thing that is ever canonical-hashed. The opaque ``credential_ref`` is deliberately excluded
from the hash: an opaque credential reference is never hashed and is bound only through exact
in-memory equality.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_plugin_proxmox.transport import _validate_base_url

_ALLOWED_KEYS = ("base_url", "verify_tls", "credential_ref")


class ProxmoxTargetConfigError(Exception):
    """Raised when a raw target configuration is not a valid, secret-free Proxmox config.

    Messages contain only field/key names and value *types* — never rejected raw values.
    """


@dataclass(frozen=True)
class ValidatedProxmoxTargetConfig:
    """A validated, immutable, secret-free Proxmox target configuration."""

    base_url: str
    verify_tls: bool
    credential_ref: str

    def connection_representation(self) -> dict:
        """Deterministic connection identity for hashing — ONLY ``base_url`` + ``verify_tls``.

        The opaque ``credential_ref`` is deliberately EXCLUDED: an opaque credential reference is
        never hashed; it is bound only through exact in-memory equality.
        """
        return {"base_url": self.base_url, "verify_tls": self.verify_tls}


def parse_proxmox_target_config(raw: object) -> ValidatedProxmoxTargetConfig:
    """Validate ``raw`` into a :class:`ValidatedProxmoxTargetConfig` or raise
    :class:`ProxmoxTargetConfigError`. Never echoes rejected raw values."""
    if not isinstance(raw, dict):
        raise ProxmoxTargetConfigError(f"target config must be an object, not {type(raw).__name__}")

    unknown = sorted(str(k) for k in raw if k not in _ALLOWED_KEYS)
    if unknown:
        # Report only key NAMES (never values); secret-like fields land here and are refused.
        raise ProxmoxTargetConfigError(f"unknown target config keys: {unknown}")

    missing = [k for k in _ALLOWED_KEYS if k not in raw]
    if missing:
        raise ProxmoxTargetConfigError(f"missing required target config fields: {missing}")

    base_url = raw["base_url"]
    verify_tls = raw["verify_tls"]
    credential_ref = raw["credential_ref"]

    # Strict types: base_url/credential_ref are plain strings; verify_tls is a plain bool. This
    # rejects nested values (dict/list), credential objects, and any non-string/non-boolean type.
    if not isinstance(base_url, str):
        raise ProxmoxTargetConfigError(f"base_url must be a string, not {type(base_url).__name__}")
    if not isinstance(verify_tls, bool):
        raise ProxmoxTargetConfigError(
            f"verify_tls must be a boolean, not {type(verify_tls).__name__}"
        )
    if not isinstance(credential_ref, str):
        raise ProxmoxTargetConfigError(
            f"credential_ref must be a string, not {type(credential_ref).__name__}"
        )

    # base_url must be a valid exact Proxmox HTTPS API root (reuses the transport contract).
    try:
        _validate_base_url(base_url)
    except ValueError as exc:
        raise ProxmoxTargetConfigError(f"invalid base_url: {exc}") from exc
    if verify_tls is not True:
        raise ProxmoxTargetConfigError("verify_tls must be exactly True")
    if not credential_ref.strip():
        raise ProxmoxTargetConfigError("credential_ref must be a non-empty opaque string")

    return ValidatedProxmoxTargetConfig(
        base_url=base_url, verify_tls=verify_tls, credential_ref=credential_ref
    )
