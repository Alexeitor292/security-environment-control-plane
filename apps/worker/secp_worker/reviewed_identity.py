"""Reviewed implementation-identity + digest helpers for the concrete worker backend seams (PR5B).

The controlled-live composition must be bound to the EXACT reviewed concrete implementation of each
external-contact seam — not merely "something that satisfies the Protocol". These helpers provide
the
identity anchor used for that binding:

* :func:`object_identity` returns the object's actual ``module.qualname`` — the ground truth that a
  duck-typed object, a foreign subclass, or a fake CANNOT forge without editing the reviewed module
  itself (its ``__module__`` is fixed to the defining module). It matches the existing readiness
  ``implementation_identity`` convention.
* :func:`declaration_digest` is the stable digest of a reviewed registration label, matching the
  existing ``plan_only_executor_implementation_digest`` convention.

Binding against BOTH the actual identity and a pinned registration/digest refuses: a duck-typed
object, a foreign subclass where the exact type is required, a forged registration, a forged digest,
and a correct-Protocol-wrong-implementation object. This module performs no I/O and imports nothing
capable of it.
"""

from __future__ import annotations

import hashlib


class ReviewedIdentityError(Exception):
    """A reviewed concrete implementation was expected but a different object was supplied."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def object_identity(obj: object) -> str:
    """The actual ``module.qualname`` of ``obj``'s class — the un-forgeable identity."""
    klass = type(obj)
    return f"{klass.__module__}.{klass.__qualname__}"


def declaration_digest(identifier: str) -> str:
    """The stable ``sha256:`` digest of a reviewed registration label."""
    return "sha256:" + hashlib.sha256(identifier.encode()).hexdigest()


def assert_reviewed_object(
    obj: object,
    *,
    expected_identity: str,
    expected_registration: str,
    reason_code: str,
) -> None:
    """Refuse ``obj`` unless it is the EXACT reviewed concrete implementation.

    Two checks, both must hold: (1) the actual ``module.qualname`` equals ``expected_identity`` —
    the
    un-forgeable anchor, so a duck-typed object, a foreign subclass, or a fake claiming the right
    registration is refused (its defining module fixes its ``__module__``); (2) the class's declared
    ``IMPLEMENTATION_ID`` equals ``expected_registration`` — so a real class whose reviewed
    registration
    was tampered with is also refused. The reviewed digest is then ``declaration_digest`` of the
    registration. A single ``reason_code`` is raised — the offending object is never echoed.
    """
    if object_identity(obj) != expected_identity:
        raise ReviewedIdentityError(reason_code)
    if getattr(type(obj), "IMPLEMENTATION_ID", None) != expected_registration:
        raise ReviewedIdentityError(reason_code)
