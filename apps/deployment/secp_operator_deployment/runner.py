"""The operator worker run hook — HARD-SEALED in SECP-PR5D.

:func:`run_operator_worker` is the exact hook the PR5C entrypoint calls. In this milestone operator
activation is sealed by a REVIEWED CODE CONSTANT (``_OPERATOR_ACTIVATION_SEALED`` = ``True``), never
a config flag. It validates the registration is EXACTLY the authoritative
``OperatorWorkerRegistration``
type (an un-forgeable ``type(...) is`` identity check — a forged ``__module__``/``__qualname__`` +
shaped attributes is refused), then — with the seal ``True`` — refuses with the bounded reason
``operator_activation_sealed`` BEFORE constructing or starting a Temporal ``Worker``. It writes no
``import temporalio`` (the authoritative type is imported lazily, only when the hook is actually
called — never at module import), starts no event loop, registers no workflows/activities,
inspects no
secret, contacts no Temporal, and mutates no service state.

No configuration field, environment variable, CLI option, database row, endpoint, installed package,
or caller boolean can bypass the seal — flipping it is a deliberate, separately-reviewed code
change.
"""

from __future__ import annotations

from secp_operator_deployment import DeploymentPackageError

# The dedicated deployment-package operator-activation seal. Reviewed CODE CONSTANT, never config.
# PR5D ships with this ``True``: the operator worker is prepared and installed DISABLED and can
# never
# be started from here. Apply/destroy remain impossible; the plan-only seal remains False; both B1-A
# subprocess seals remain True.
_OPERATOR_ACTIVATION_SEALED = True


def _is_operator_registration(registration: object) -> bool:
    # Import the AUTHORITATIVE type lazily (no module-level import, so importing this module drags
    # in
    # no worker/Temporal machinery) and require an EXACT type identity — not forgeable
    # module/qualname
    # strings or duck-typed attributes.
    try:
        from secp_worker.operator_bootstrap import OperatorWorkerRegistration
    except Exception:
        return False
    return type(registration) is OperatorWorkerRegistration


def run_operator_worker(registration: object) -> int:
    """Refuse to start the operator worker while activation is sealed (this milestone).

    Validates the registration is EXACTLY the authoritative ``OperatorWorkerRegistration`` type,
    then
    — with the seal ``True`` — raises :class:`DeploymentPackageError`
    (``operator_activation_sealed``)
    before any ``Worker`` construction. No secret inspection, no Temporal contact, no event loop, no
    service mutation.
    """
    if not _is_operator_registration(registration):
        raise DeploymentPackageError("operator_registration_invalid")
    if _OPERATOR_ACTIVATION_SEALED:
        # HARD SEAL — refuse before constructing or starting a Temporal Worker.
        raise DeploymentPackageError("operator_activation_sealed")
    # Unreachable while sealed. Even if the seal were flipped, starting the worker is a separately
    # reviewed change that must add the Temporal Worker construction here; this milestone adds none.
    raise DeploymentPackageError("operator_activation_sealed")  # pragma: no cover
