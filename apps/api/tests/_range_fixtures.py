"""Shared scriptable range provider for the range-lifecycle tests.

The provider is faked on purpose: these tests are about what the SERVICE writes given what a
provider reports. The real Docker provider is exercised in ``test_range_docker_provider.py``.

``FakeProvider`` mirrors the one in ``test_range_lifecycle.py``; it lives here so the
stranded-operation tests can script teardown outcomes — in particular an UNREACHABLE probe, which
is the only way to prove that ``clean`` is unreachable without a real observation.
"""

from __future__ import annotations

from secp_api.range_enums import (
    RangeOperationKind,
    RangeResourceKind,
    RangeStepStatus,
)
from secp_api.range_models import RangeInstance
from secp_api.range_providers.base import (
    DeployResult,
    ProviderHealth,
    RecordedStep,
    ResourceObservation,
    TeardownObservation,
    TeardownResourceOutcome,
    TeardownResult,
)
from secp_api.services import ranges
from secp_worker.range import reset_providers, set_provider
from secp_worker.range.execution import execute_range_operation


class FakeProvider:
    """A scriptable stand-in for a real provider.

    ``deploy_ok`` / ``teardown`` decide what the provider REPORTS; the assertions are about what the
    service then persists. Nothing here talks to Docker.
    """

    name = "local_docker"

    def __init__(self) -> None:
        self.deploy_ok = True
        self.verify_components = True
        self.healthy = True
        self.teardown: TeardownResult | None = None
        self.destroy_calls: list[tuple[str, tuple[ResourceObservation, ...]]] = []

    def health(self) -> ProviderHealth:
        return ProviderHealth(reachable=self.healthy, endpoint_id="fake-daemon", version="0.0-fake")

    def plan_steps(self, spec, kind):
        return [
            RecordedStep(key="preflight", label="preflight"),
            *[RecordedStep(key=f"start:{c.key}", label=f"start {c.key}") for c in spec.components],
        ]

    def _resources(self, spec) -> tuple[ResourceObservation, ...]:
        network = ResourceObservation(
            kind=RangeResourceKind.network,
            name=f"secp-range-{spec.resource_prefix}",
            external_id="net-1234",
            owner_label=f"secp.range.id={spec.range_id}",
            verified=True,
        )
        containers = [
            ResourceObservation(
                kind=RangeResourceKind.container,
                name=f"secp-range-{spec.resource_prefix}-{component.key}",
                component_key=component.key,
                external_id=f"cid-{component.key}",
                image=component.image,
                image_digest=f"sha256:{component.key}",
                owner_label=f"secp.range.id={spec.range_id}",
                host_port=30000 + index,
                verified=self.verify_components,
            )
            for index, component in enumerate(spec.components)
        ]
        return (network, *containers)

    def deploy(self, spec, ctx) -> DeployResult:
        ctx.begin("preflight")
        ctx.finish("preflight", RangeStepStatus.succeeded)
        if not self.deploy_ok:
            return DeployResult(
                ok=False,
                resources=self._resources(spec),
                failure_code="readiness_not_observed",
                failure_message="the target never responded",
            )
        return DeployResult(ok=True, resources=self._resources(spec))

    def reset(self, spec, existing, ctx) -> DeployResult:
        return self.deploy(spec, ctx)

    def destroy(self, spec, existing, ctx) -> TeardownResult:
        self.destroy_calls.append((spec.range_id, existing))
        if self.teardown is not None:
            return self.teardown
        return TeardownResult(
            probe_reachable=True,
            observations=tuple(
                TeardownObservation(
                    kind=resource.kind,
                    name=resource.name,
                    external_id=resource.external_id,
                    outcome=TeardownResourceOutcome.removed,
                    detail="confirmed absent",
                )
                for resource in existing
            ),
        )


def provider_fixture():
    """Body of the ``provider`` fixture, for a test module to wrap with ``@pytest.fixture``.

    Deliberately NOT decorated here. A decorated fixture imported into a test module and then named
    as a test parameter reads to linters as a redefinition, and silencing that per test is worse
    than letting each module own the one-line registration.
    """
    fake = FakeProvider()
    set_provider("local_docker", fake)
    yield fake
    reset_providers()


def deploy_ready_range(session, principal, provider) -> RangeInstance:
    """Deploy ``web-breach-lab`` all the way to ``ready`` with its resources recorded."""
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.deploy
    )
    session.commit()
    execute_range_operation(session, operation.id)
    session.refresh(instance)
    return instance
