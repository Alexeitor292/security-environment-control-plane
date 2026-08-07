"""Reviewed management-plane topology facts + the safety seals (SECP-PR5E).

Code-owned constants that pin the canonical controller stack + worker topology, plus a fail-closed
read of the four safety seals. These are NEVER host-selected and NEVER carry a secret or a host
address. The queue / service / container / health identities mirror the reviewed PR5C commissioning
+
PR5D deployment values so the management bootstrap reconciles both prepared-state definitions.
"""

from __future__ import annotations

from dataclasses import dataclass

# Queues (reviewed, distinct). The ordinary worker never polls the operator queue.
ORDINARY_TASK_QUEUE = "secp-orchestration"
OPERATOR_TASK_QUEUE = "secp-controlled-live-v1"

#: The interpreter INSIDE THE ORDINARY WORKER CONTAINER, which ``real_adapters`` reaches with
#: ``docker exec <container> <argv>``. The image is built by ``infra/dev/Dockerfile.python`` from
#: ``python:3.11-slim``, whose interpreter lives under ``/usr/local`` (the official image builds
#: CPython with the default ``configure`` prefix and symlinks only within ``/usr/local/bin``).
#: Bound to that base image by ``tests/test_health_command_interpreter.py``, so changing the
#: ``FROM`` line fails loudly here instead of silently breaking the probe on a real host.
#:
#: This is the CONTAINER's interpreter only. The management HOST has its own at
#: ``/usr/bin/python3`` (see ``BROKER_ENTRYPOINT`` below) and the two must not be unified: the host
#: is not the container. They once held the same literal for unrelated reasons, which is the shape
#: a well-meant "fix one, fix them all" edit turns into a defect.
#:
#: ABSOLUTE, never resolved from PATH — a reviewed property, not an oversight: an argv whose
#: executable is looked up at run time is hijackable by whatever PATH the unit or container
#: inherits. ``profile.py::_v_health`` enforces the same independently ("health command executable
#: must be an absolute POSIX path").
WORKER_CONTAINER_INTERPRETER = "/usr/local/bin/python3"

# Worker topology identities (mirror the PR5D reviewed documentation values).
OPERATOR_SERVICE_NAME = "secp-operator-worker.service"
ORDINARY_CONTAINER_NAME = "secp-ordinary-worker"
ORDINARY_HEALTH_COMMAND: tuple[str, ...] = (
    WORKER_CONTAINER_INTERPRETER,
    "-m",
    "secp_worker.health",
    "check",
)


# The reviewed controller stack service identities (from infra/dev/docker-compose.yml). The
# bootstrap reuses these reviewed definitions; it never invents a divergent stack. Image *content
# digests* are release-bundle-pinned (never a floating tag); these are the logical component +
# reviewed image reference only, used for topology/inventory identity.
@dataclass(frozen=True)
class ControllerService:
    component: str
    image_ref: str
    privileged: bool = False


CONTROLLER_STACK: tuple[ControllerService, ...] = (
    ControllerService("postgres", "postgres:16-alpine"),
    ControllerService("minio", "minio/minio"),
    ControllerService("keycloak", "quay.io/keycloak/keycloak:25.0"),
    ControllerService("temporal", "temporalio/auto-setup:1.24"),
    ControllerService("temporal-ui", "temporalio/ui:2.31.0"),
    ControllerService("api", "secp/api"),
    ControllerService("worker", "secp/worker"),
    ControllerService("web", "secp/web"),
)
# The exact reviewed controller component set adoption + status require to be present, running,
# healthy, and digest-bound (never host-selected; derived from the reviewed stack above).
EXPECTED_CONTROLLER_COMPONENTS: tuple[str, ...] = tuple(s.component for s in CONTROLLER_STACK)
# The exact reviewed database migration command (never a shell string; argv only).
CONTROLLER_MIGRATION_ARGV: tuple[str, ...] = ("alembic", "upgrade", "head")

# Fixed, reviewed absolute entrypoints the code-owned systemd units wrap (never host-selected).
OPERATOR_ENTRYPOINT: tuple[str, ...] = ("/opt/secp/operator/bin/entrypoint",)
CONTROLLER_STACK_ENTRYPOINT: tuple[str, ...] = ("/opt/secp/controller/bin/stack-supervisor",)
# The fixed root-gated enrollment-signer broker entrypoint (SECP-PR5H-B2, 2b-3b-iii): an absolute
# ``python -m`` invocation of the code-owned serve module (mirrors ORDINARY_HEALTH_COMMAND's
# absolute
# python convention). It takes NO argument — the socket, key, credential, DB role and peer policy
# are
# all code constants — so a rendered unit can never point the broker at another socket/key/role/DSN.
# NOTE: this runs on the management HOST, where /usr/bin/python3 is correct. It is deliberately NOT
# the worker container's interpreter (see WORKER_CONTAINER_INTERPRETER above) and must not be
# "unified" with it — the convention is shared, the path is not.
BROKER_ENTRYPOINT: tuple[str, ...] = (
    "/usr/bin/python3",
    "-m",
    "secp_management.enrollment_signer_broker_serve",
)
_RUNTIME_UID = 10001
_RUNTIME_GID = 10001
# The reviewed non-root controller-API runtime identity (uid/gid 10001) — the EXACT peer pair the
# broker allowlists (SO_PEERCRED), the (api_uid, api_gid) bound into the signer-enablement marker,
# and the group the root installer chowns the broker socket + handoff files to. Both planes agree on
# this one code-owned value (the API re-derives its own via os.geteuid/os.getegid at runtime).
API_RUNTIME_UID = _RUNTIME_UID
API_RUNTIME_GID = _RUNTIME_GID


@dataclass(frozen=True)
class SealState:
    """The four reviewed safety seals, observed fail-closed.

    THE FIELD NAMES ARE A COMPATIBILITY SURFACE, NOT A DESCRIPTION. All four are required members
    of the signed :class:`~secp_management.evidence.BootstrapEvidence` document, whose
    ``canonical()`` is a full ``model_dump()`` — so each name sits inside ``digest()``, which
    carries an independently verified Ed25519 attestation. Renaming one, removing one, or making
    one optional would change the canonical field set and invalidate the digest of every evidence
    document already issued. They are therefore fixed. A future evidence-schema version may rename
    the concepts cleanly; that is not an M1 change.

    WHAT THE TWO ``b1a_`` FIELDS MEAN NOW. ADR-030 retired the `_B1A_SUBPROCESS_SEALED` constants
    they used to read. Their meaning moved with the architecture:

    ``old True``  the capability is globally sealed, therefore unauthorized execution is impossible
    ``new True``  the production capability may exist, but the unauthorized path was BEHAVIOURALLY
                  exercised and stayed closed

    The transition is monotonic: every historical ``True`` remains truthful under the new reading,
    because a capability that could not exist could not be reached without authority either. That
    is what lets the field set stay fixed while the constants underneath it go.

    These booleans are **not execution authority** and must never be used as such. They exist for
    bootstrap-evidence compatibility, status re-observation, and the historical safety record. Real
    execution authority comes only from the ADR-030 durable operation derivation.
    """

    operator_activation_sealed: bool
    plan_only_process_sealed: bool
    b1a_subprocess_sealed_activation: bool
    b1a_subprocess_sealed_executor: bool

    @property
    def safe(self) -> bool:
        return (
            self.operator_activation_sealed is True
            and self.plan_only_process_sealed is False
            and self.b1a_subprocess_sealed_activation is True
            and self.b1a_subprocess_sealed_executor is True
        )


def read_seals() -> SealState:
    """Observe the four seals fail-closed. Never a config, never an environment variable.

    The two ``b1a_`` values are DERIVED BY EXERCISE, from ``secp_worker.safety_seal_probe``, because
    ADR-030 retired the constants they used to read. That is not merely a substitution: a constant
    was always a claim ABOUT code elsewhere, and deleting the guard it described left every seal
    still reporting ``True``. The probe attempts the unauthorized routes to the real executor —
    including a forged authority object — and reports what actually happened.

    Fail-closed is explicit: the probe distinguishes ``sealed`` from ``undetermined``, and only
    ``sealed`` becomes ``True`` here. A derivation that could not be performed is unknown, and
    unknown is not permission. An import failure is likewise ``False`` rather than an exception,
    because a bootstrap that cannot observe a seal must record that it could not — not refuse to
    produce evidence, and not claim the seal held.

    The remaining two values still come from constants, and deliberately: ``_OPERATOR_ACTIVATION_
    SEALED`` and ``_PLAN_ONLY_PROCESS_SEALED`` have not been retired. When the operator one is,
    the same rule applies to it — preserve the evidence field, retire the constant, derive the
    closure behaviourally — and it should be changed here rather than rediscovered as a conflict.
    """
    from secp_operator_deployment.runner import _OPERATOR_ACTIVATION_SEALED
    from secp_worker.plan_gen import process_boundary as pb

    # NOTE the name collision: the probe's ``SealState`` is a three-valued ENUM
    # (sealed/unsealed/undetermined) while this module's is the four-boolean RECORD. Same word, two
    # concepts. Rather than import the enum and risk the two being confused at a glance, the probe's
    # state is compared by VALUE — ``"sealed"`` is a member of a ``str`` enum, so the comparison is
    # exact and carries the meaning at the point of use.
    closed: set[str] = set()
    try:
        from secp_worker.safety_seal_probe import derive_seals

        closed = {item.name for item in derive_seals() if item.state.value == "sealed"}
    except Exception:  # noqa: BLE001 - an unobservable seal is False, never True
        closed = set()

    return SealState(
        operator_activation_sealed=bool(_OPERATOR_ACTIVATION_SEALED),
        plan_only_process_sealed=bool(pb._PLAN_ONLY_PROCESS_SEALED),
        b1a_subprocess_sealed_activation="generic_activation_subprocess_sealed" in closed,
        b1a_subprocess_sealed_executor="generic_executor_subprocess_sealed" in closed,
    )
