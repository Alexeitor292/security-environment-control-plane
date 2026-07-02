"""Read-only Proxmox plugin (SECP-002A).

Worker/plugin code ONLY — never imported by ``apps/api``. Advertises only
``validate``, ``health``, ``discover``, ``status``; ``apply``/``reset``/``destroy``
hard-fail with ``UnsupportedCapabilityError`` before any provider request. The HTTP
transport allows GET only. No real endpoint is contacted during SECP-002A
development, tests, CI, or runtime verification. See ADR-006/007/010 and
``docs/proxmox/``.
"""

from secp_plugin_proxmox.live_collector import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LiveReadOnlyProxmoxCollector,
)
from secp_plugin_proxmox.plugin import ProxmoxPlugin
from secp_plugin_proxmox.readonly_normalize import normalize_proxmox_observations
from secp_plugin_proxmox.readonly_policy import (
    ALLOWED_PATH_TEMPLATES,
    PROXMOX_READONLY_POLICY_VERSION,
    CrossHostRequestRefused,
    NonCanonicalPathRefused,
    QueryParametersRefused,
    RedirectRefused,
    UnknownPathRefused,
    assert_no_params,
    assert_request_allowed,
    canonical_path_violation,
    path_is_allowed,
)
from secp_plugin_proxmox.readonly_transport import (
    FakeProxmoxReadOnlyTransport,
    RedirectResponse,
    fake_transport_factory,
)
from secp_plugin_proxmox.target_config import (
    ProxmoxTargetConfigError,
    ValidatedProxmoxTargetConfig,
    parse_proxmox_target_config,
)
from secp_plugin_proxmox.transport import (
    HttpxReadOnlyTransport,
    MutatingRequestRefused,
    ReadOnlyHttpTransport,
)

__all__ = [
    "ProxmoxPlugin",
    "HttpxReadOnlyTransport",
    "MutatingRequestRefused",
    "ReadOnlyHttpTransport",
    # SECP-002B-1B-3 — offline fake read-only transport, closed policy, normalizer.
    "FakeProxmoxReadOnlyTransport",
    "RedirectResponse",
    "fake_transport_factory",
    "ALLOWED_PATH_TEMPLATES",
    "PROXMOX_READONLY_POLICY_VERSION",
    "CrossHostRequestRefused",
    "NonCanonicalPathRefused",
    "QueryParametersRefused",
    "RedirectRefused",
    "UnknownPathRefused",
    "assert_no_params",
    "assert_request_allowed",
    "canonical_path_violation",
    "path_is_allowed",
    "normalize_proxmox_observations",
    # SECP-002B-1B-4 — dormant live read-only collector (default-disabled; DI-only).
    "LiveReadOnlyProxmoxCollector",
    "LIVE_READ_EVIDENCE_SOURCE",
    "LIVE_READ_COLLECTOR_CONTRACT_VERSION",
    "ProxmoxTargetConfigError",
    "ValidatedProxmoxTargetConfig",
    "parse_proxmox_target_config",
]
