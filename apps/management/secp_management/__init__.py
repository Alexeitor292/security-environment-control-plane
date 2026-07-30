"""SECP-PR5E — management-plane bootstrap foundation (local-first, human-supervised).

This package owns the repository's management-plane installer (``secpctl``): the signed offline
release-bundle contract, the closed controller/worker role model, the local controller/worker
bootstrap plans, safe adoption of already-existing installations, the strict nonsecret evidence, and
the revalidating status. It is LOCAL-FIRST: it never becomes a remote root-SSH deployment service,
it
never contacts external infrastructure, and it never activates the sealed controlled-live operator.

The three SECP planes are strictly ordered (see :mod:`secp_management.planes`): a LOWER plane may
never
create, mutate, reset, adopt, or destroy an object in a HIGHER plane. The controller and site
workers
are MANAGEMENT-plane objects — never scenario workloads — even when a customer physically hosts them
on the same Proxmox cluster.

Every failure is a :class:`ManagementError` carrying ONLY a bounded, closed ``reason_code`` — never
a
path, value, endpoint, credential, secret, host address, or third-party exception text.
"""

from __future__ import annotations

# The management-bootstrap CONTRACT version (distinct from the tool/package version). Evidence and
# identity documents whose contract version is not EXACTLY this are refused (unchanged legacy
# semantics). ``BOOTSTRAP_CONTRACT_VERSION`` remains v1alpha1 so existing authenticated records read
# unchanged; the release MANIFEST accepts a bounded, closed compatibility window (SECP-PR5H-B2):
# legacy ``v1alpha1`` (accepted for upgrade/rollback) and newly-issued ``v1alpha2`` (which carries
# the B2 installation profile — platform, host-runtime executable pins, controller TLS policy).
# New release-building tooling emits only v1alpha2; clean-host B2 installs require v1alpha2.
BOOTSTRAP_CONTRACT_VERSION = "secp.management-bootstrap/v1alpha1"
BOOTSTRAP_CONTRACT_VERSION_V1ALPHA1 = "secp.management-bootstrap/v1alpha1"
BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2 = "secp.management-bootstrap/v1alpha2"
#: The closed compatibility window of accepted release-manifest contract versions.
SUPPORTED_BOOTSTRAP_CONTRACT_VERSIONS = (
    BOOTSTRAP_CONTRACT_VERSION_V1ALPHA1,
    BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2,
)

# The package's own version, recorded in evidence.
PACKAGE_VERSION = "0.1.0"

# The reviewed package IMPLEMENTATION identity (bound into evidence + identity provenance).
PACKAGE_IMPLEMENTATION_ID = "secp-pr5e/management-bootstrap/v1"

# The closed management plane classification. Management-plane objects are NEVER scenario
# resources.
PLANE_MANAGEMENT = "management"

_MAX_REASON_CODE = 120

__all__ = [
    "BOOTSTRAP_CONTRACT_VERSION",
    "BOOTSTRAP_CONTRACT_VERSION_V1ALPHA1",
    "BOOTSTRAP_CONTRACT_VERSION_V1ALPHA2",
    "SUPPORTED_BOOTSTRAP_CONTRACT_VERSIONS",
    "PACKAGE_VERSION",
    "PACKAGE_IMPLEMENTATION_ID",
    "PLANE_MANAGEMENT",
    "ManagementError",
    "reject",
]


class ManagementError(Exception):
    """A management-bootstrap operation failed closed. Carries a BOUNDED, closed, snake_case
    ``reason_code`` and nothing else — never a value, path, endpoint, credential, secret, host
    address, or raw upstream message. ``__str__``/``repr`` expose only the reason code, so a failure
    can never leak a secret or a host identity into a log, traceback, CLI payload, or evidence."""

    def __init__(self, reason_code: str) -> None:
        code = reason_code if isinstance(reason_code, str) else "internal"
        self.reason_code = code[:_MAX_REASON_CODE]
        super().__init__(self.reason_code)

    def __repr__(self) -> str:  # never echo anything but the bounded code
        return f"ManagementError({self.reason_code!r})"


def reject(reason_code: str) -> None:
    """Raise a :class:`ManagementError` with a closed reason code (never a value)."""
    raise ManagementError(reason_code)
