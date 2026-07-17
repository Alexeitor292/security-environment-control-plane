"""Shared, redaction-safe error type for the commissioning engine (SECP-PR5C, ADR-023).

Every failure in this package is a :class:`CommissioningError` carrying ONLY a bounded, closed,
snake_case ``reason_code`` — never a descriptor value, path, endpoint, credential, secret, digest of
a low-entropy locator, or third-party exception text. The reason code is the sole detail exposed to
a caller, a log line, the CLI JSON output, or an evidence record. This mirrors the
closed-reason-code
discipline of ``secp_worker.mounted_bundle`` and the readiness/plan-gen recorders.
"""

from __future__ import annotations

from typing import NoReturn

# A reason code is a short, fixed, lower_snake token (optionally ``prefix:subject`` where
# ``subject``
# is a NON-secret field PATH, never a value). Bound its length so a smuggled value can never ride
# out inside a reason code.
_MAX_REASON_CODE = 120


class CommissioningError(Exception):
    """A commissioning operation failed. Carries a bounded closed ``reason_code`` and nothing else.

    ``__str__`` / ``repr`` expose only the reason code, so an exception can never leak a descriptor
    value, filesystem path, or host fact into a log, traceback, CLI payload, or test snapshot.
    """

    def __init__(self, reason_code: str) -> None:
        code = reason_code if isinstance(reason_code, str) else "internal"
        # Defensive truncation: a bounded reason code can never smuggle a value out.
        self.reason_code = code[:_MAX_REASON_CODE]
        super().__init__(self.reason_code)

    def __repr__(self) -> str:
        return f"CommissioningError({self.reason_code!r})"


def reject(reason_code: str) -> NoReturn:
    """Raise a :class:`CommissioningError` with a closed reason code (never a value)."""
    raise CommissioningError(reason_code)
