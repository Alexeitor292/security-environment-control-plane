"""Range lifecycle: state machine, resource records, and — the part that matters — the difference
between a proved teardown and one that could not be observed.

The provider is faked here on purpose: these tests are about what the SERVICE writes given what a
provider reports. The real Docker provider is exercised in ``test_range_docker_provider.py``.
"""

from __future__ import annotations

import uuid

import pytest
import secp_api.range_models  # noqa: F401  (registers the range tables on Base before create_all)
from secp_api.range_enums import (
    RangeOperationKind,
    RangeOperationStatus,
    RangeResourceKind,
    RangeResourceState,
    RangeState,
    RangeStepStatus,
    ResidueVerdict,
)
from secp_api.range_models import RangeInstance
from secp_api.range_providers import reset_providers, set_provider
from secp_api.range_providers.base import (
    DeployResult,
    ProviderHealth,
    RecordedStep,
    ResourceObservation,
    TeardownObservation,
    TeardownResourceOutcome,
    TeardownResult,
)
from secp_api.services import competitions, ranges


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


@pytest.fixture
def provider():
    fake = FakeProvider()
    set_provider("local_docker", fake)
    yield fake
    reset_providers()


@pytest.fixture(autouse=True)
def _inline_runner():
    from secp_api.services import range_runner

    range_runner.set_mode("inline")
    yield
    range_runner.set_mode("thread")


def _deploy(session, principal, provider) -> RangeInstance:
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.deploy
    )
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)
    return instance


def test_catalog_ships_one_complete_range(session, principal):
    templates = ranges.list_templates(session)
    assert [template.slug for template in templates] == ["web-breach-lab"]
    spec = templates[0].spec
    assert {component["key"] for component in spec["components"]} == {"dvwa", "juice-shop"}
    assert len(spec["challenges"]) == 6
    # The persisted spec must never carry a flag value — only how many there are.
    assert all("flag_count" in challenge for challenge in spec["challenges"])
    assert "flags" not in str(spec)


def test_deploy_reaches_ready_only_with_verified_resources(session, principal, provider):
    instance = _deploy(session, principal, provider)

    assert instance.state is RangeState.ready
    assert instance.deployed_at is not None
    resources = ranges.list_resources(session, principal, instance.id)
    assert len(resources) == 3  # one network + two containers
    assert all(r.state is RangeResourceState.verified for r in resources)

    from secp_api.range_projection import range_out

    projected = range_out(session, instance)
    assert {target.component_key for target in projected.access} == {"dvwa", "juice-shop"}
    assert all(target.host == "127.0.0.1" for target in projected.access)


def test_a_container_that_never_responds_does_not_reach_ready(session, principal, provider):
    provider.deploy_ok = False
    provider.verify_components = False
    instance = _deploy(session, principal, provider)

    assert instance.state is RangeState.failed
    assert instance.state_reason == "the target never responded"
    resources = ranges.list_resources(session, principal, instance.id)
    containers = [r for r in resources if r.kind is RangeResourceKind.container]
    # Started but never observed responding: recorded as created, NEVER verified.
    assert all(r.state is RangeResourceState.created for r in containers)

    from secp_api.range_projection import range_out

    # No access link is offered for something we never saw respond.
    assert range_out(session, instance).access == []


def test_destroy_confirmed_absent_is_clean_and_destroyed(session, principal, provider):
    instance = _deploy(session, principal, provider)
    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)

    assert instance.state is RangeState.destroyed
    assert instance.residue_verdict is ResidueVerdict.clean
    evidence = ranges.list_teardown_evidence(session, principal, instance.id)
    assert len(evidence) == 1
    assert evidence[0].verdict is ResidueVerdict.clean
    assert evidence[0].probe_reachable is True
    assert evidence[0].still_present == 0
    assert evidence[0].unproven_count == 0


def test_unreachable_daemon_makes_teardown_unproven_never_clean(session, principal, provider):
    """THE CENTRAL PROPERTY.

    When the daemon is unreachable, the removal and the existence check fail for the same reason.
    The check's silence is therefore not evidence of absence. The range must land in
    ``recovery_required`` with an ``unproven`` verdict — never ``destroyed``, never ``clean``.
    """
    instance = _deploy(session, principal, provider)
    live = ranges.list_resources(session, principal, instance.id)
    provider.teardown = TeardownResult(
        probe_reachable=False,
        observations=tuple(
            TeardownObservation(
                kind=row.kind,
                name=row.name,
                external_id=row.external_id,
                outcome=TeardownResourceOutcome.unproven,
                detail="the Docker daemon was unreachable",
            )
            for row in live
        ),
        reason="the Docker daemon was unreachable; removal and the existence check share that "
        "failure mode, so absence was not proved",
    )

    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)
    session.refresh(operation)

    assert instance.state is RangeState.recovery_required
    assert instance.state is not RangeState.destroyed
    assert instance.residue_verdict is ResidueVerdict.unproven
    assert instance.residue_verdict is not ResidueVerdict.clean
    assert instance.destroyed_at is None

    # The operation is neither a success nor a failure — it is unproven.
    assert operation.status is RangeOperationStatus.unproven
    assert operation.status is not RangeOperationStatus.succeeded

    evidence = ranges.list_teardown_evidence(session, principal, instance.id)[0]
    assert evidence.verdict is ResidueVerdict.unproven
    assert evidence.probe_reachable is False
    assert evidence.removed_confirmed == 0
    assert evidence.unproven_count == len(live)
    assert "share" in (evidence.reason or "")

    # Every resource row records the same honesty: unknown, not removed.
    assert all(
        row.state is RangeResourceState.unproven
        for row in ranges.list_resources(session, principal, instance.id)
    )

    events = ranges.list_events(session, principal, instance.id)
    assert any(event.kind == "range_teardown_unproven" for event in events)


def test_a_single_unproven_resource_taints_the_whole_verdict(session, principal, provider):
    """One unobservable resource is enough. A mostly-confirmed teardown is still not a clean one."""
    instance = _deploy(session, principal, provider)
    live = ranges.list_resources(session, principal, instance.id)
    observations = [
        TeardownObservation(
            kind=row.kind,
            name=row.name,
            external_id=row.external_id,
            outcome=TeardownResourceOutcome.removed,
            detail="confirmed absent",
        )
        for row in live[:-1]
    ]
    observations.append(
        TeardownObservation(
            kind=live[-1].kind,
            name=live[-1].name,
            external_id=live[-1].external_id,
            outcome=TeardownResourceOutcome.unproven,
            detail="could not observe",
        )
    )
    provider.teardown = TeardownResult(probe_reachable=True, observations=tuple(observations))

    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)

    assert instance.residue_verdict is ResidueVerdict.unproven
    assert instance.state is RangeState.recovery_required


def test_resource_still_present_is_residue_not_unproven(session, principal, provider):
    instance = _deploy(session, principal, provider)
    live = ranges.list_resources(session, principal, instance.id)
    provider.teardown = TeardownResult(
        probe_reachable=True,
        observations=(
            TeardownObservation(
                kind=live[0].kind,
                name=live[0].name,
                external_id=live[0].external_id,
                outcome=TeardownResourceOutcome.present,
                detail="still present after removal",
            ),
        ),
    )

    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)
    session.refresh(operation)

    assert instance.residue_verdict is ResidueVerdict.residue
    assert instance.state is RangeState.recovery_required
    assert operation.status is RangeOperationStatus.failed


def test_reset_returns_to_ready_and_clears_scores(session, principal, provider):
    instance = _deploy(session, principal, provider)
    competition = competitions.create_competition(session, principal, instance.id)
    team = competitions.create_team(session, principal, competition.id, name="Red")
    competitions.start_competition(session, principal, competition.id)
    session.commit()
    challenge = competitions.list_challenges(session, principal, competition.id)[0]
    competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value="password",
    )
    session.commit()
    _, entries, _ = competitions.scoreboard(session, principal, competition.id)
    assert entries[0].score == challenge.points

    _, operation = ranges.start_operation(session, principal, instance.id, RangeOperationKind.reset)
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)

    assert instance.state is RangeState.ready
    _, entries, _ = competitions.scoreboard(session, principal, competition.id)
    assert entries[0].score == 0
    assert entries[0].solved_count == 0


def test_a_failed_operation_never_narrows_the_set_of_resources_we_own(session, principal, provider):
    """REGRESSION — the false-clean chain observed against real Docker.

    A reset failed partway: the provider could not remove one container, so it never restarted it
    and its result mentioned only the resources it had touched. The service reconciled the live set
    against that result and retired the unmentioned rows as ``removed``. The later destroy then
    proved absence of the rows that were LEFT and reported ``clean`` — while a container and a
    network were still running on the daemon.

    Every probe was honest; the set they were asked about had been silently narrowed. So a failed
    operation must leave the owned set intact, and the destroy must still sweep everything.
    """
    instance = _deploy(session, principal, provider)
    before = {row.name for row in ranges.list_resources(session, principal, instance.id)}
    assert len(before) == 3

    # A reset that fails after touching nothing — the shape the real failure took.
    provider.deploy_ok = False
    _, operation = ranges.start_operation(session, principal, instance.id, RangeOperationKind.reset)
    session.commit()
    ranges.execute_operation(session, operation.id)
    session.refresh(instance)
    assert instance.state is RangeState.failed

    live = [
        row
        for row in ranges.list_resources(session, principal, instance.id)
        if row.removed_at is None
    ]
    assert {row.name for row in live} == before, (
        "a failed operation must not retire resources it simply did not mention"
    )
    assert all(row.state is not RangeResourceState.removed for row in live)

    # The destroy therefore still sees — and sweeps — everything.
    provider.deploy_ok = True
    _, destroy_op = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    ranges.execute_operation(session, destroy_op.id)
    session.refresh(instance)

    evidence = ranges.list_teardown_evidence(session, principal, instance.id)[0]
    assert evidence.expected_count == 3
    assert {item["name"] for item in evidence.resources} == before
    assert instance.state is RangeState.destroyed


def test_teardown_evidence_never_counts_a_resource_that_was_never_created(
    session, principal, provider
):
    """A component with nothing recorded contributes NO observation.

    Counting "we never created it" as "we confirmed it is gone" would inflate the evidence with a
    resource that was never at risk, making the teardown look better attested than it is.
    """
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    instance.state = RangeState.ready
    session.commit()

    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.destroy
    )
    session.commit()
    ranges.execute_operation(session, operation.id)

    evidence = ranges.list_teardown_evidence(session, principal, instance.id)[0]
    assert evidence.expected_count == 0
    assert evidence.removed_confirmed == 0
    assert evidence.resources == []


@pytest.mark.parametrize(
    ("state", "kind"),
    [
        (RangeState.draft, "reset"),
        (RangeState.destroyed, "deploy"),
        (RangeState.destroyed, "destroy"),
        (RangeState.deploying, "deploy"),
    ],
)
def test_invalid_transitions_are_refused(session, principal, provider, state, kind):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    instance.state = state
    session.commit()
    with pytest.raises(ranges.RangeInvalidTransitionError):
        ranges.start_operation(session, principal, instance.id, RangeOperationKind(kind))


def test_a_second_operation_cannot_start_while_one_is_in_flight(session, principal, provider):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    ranges.start_operation(session, principal, instance.id, RangeOperationKind.deploy)
    session.commit()
    instance.state = (
        RangeState.failed
    )  # even if the state were re-opened, the operation guard holds
    session.commit()
    with pytest.raises(ranges.RangeInvalidTransitionError):
        ranges.start_operation(session, principal, instance.id, RangeOperationKind.deploy)


def test_ranges_are_organization_scoped(session, principal, other_org_principal, provider):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    from secp_api.errors import AuthorizationError

    with pytest.raises(AuthorizationError):
        ranges.get_range(session, other_org_principal, instance.id)


def test_unknown_range_is_a_range_specific_404(session, principal, provider):
    with pytest.raises(ranges.RangeNotFoundError) as excinfo:
        ranges.get_range(session, principal, uuid.uuid4())
    assert excinfo.value.code == "range_not_found"
    assert excinfo.value.http_status == 404
