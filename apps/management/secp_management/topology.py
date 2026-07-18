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

# Worker topology identities (mirror the PR5D reviewed documentation values).
OPERATOR_SERVICE_NAME = "secp-operator-worker.service"
ORDINARY_CONTAINER_NAME = "secp-ordinary-worker"
ORDINARY_HEALTH_COMMAND: tuple[str, ...] = (
    "/usr/bin/python3",
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
_RUNTIME_UID = 10001
_RUNTIME_GID = 10001


@dataclass(frozen=True)
class SealState:
    """The four reviewed safety seals, observed fail-closed from the actual code constants."""

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
    """Read the four seals directly from the reviewed code constants (never a config/env)."""
    from secp_operator_deployment.runner import _OPERATOR_ACTIVATION_SEALED
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    return SealState(
        operator_activation_sealed=bool(_OPERATOR_ACTIVATION_SEALED),
        plan_only_process_sealed=bool(pb._PLAN_ONLY_PROCESS_SEALED),
        b1a_subprocess_sealed_activation=bool(act._B1A_SUBPROCESS_SEALED),
        b1a_subprocess_sealed_executor=bool(pe._B1A_SUBPROCESS_SEALED),
    )
