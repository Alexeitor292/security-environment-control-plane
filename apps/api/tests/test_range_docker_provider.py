"""The local Docker provider's two safety properties, tested without needing a Docker daemon.

1. **A negative from a probe that could not run is ``unproven``, never "absent".** The hazard is
   specific: ``docker inspect`` exits 1 both for "no such object" and for "cannot reach the
   daemon", and a teardown reaches the second case *precisely when* its own removal just failed for
   the same reason. So the probe must never promote a non-zero exit to proof of absence on the
   strength of the error text alone.

2. **Only resources this range created are ever removed.** Ownership is re-read from the live
   object's labels before any removal, so a recorded id that now points at something else is
   refused rather than deleted.

Both are driven by substituting the CLI seam, so they run in CI with no daemon.
"""

from __future__ import annotations

import pytest
import secp_api.range_models  # noqa: F401
from secp_api.range_enums import RangeResourceKind
from secp_api.range_providers import docker_cli
from secp_api.range_providers.base import (
    ComponentSpec,
    OperationContext,
    ProviderHealth,
    RangeSpec,
    RecordedStep,
    ResourceObservation,
    TeardownObservation,
    TeardownResourceOutcome,
)
from secp_api.range_providers.docker_cli import (
    CommandResult,
    DaemonHealth,
    DockerUnavailableError,
)
from secp_api.range_providers.local_docker import (
    OWNER_LABEL_KEY,
    OWNER_LABEL_VALUE,
    RANGE_ID_LABEL_KEY,
    LocalDockerProvider,
)

RANGE_ID = "11111111-2222-3333-4444-555555555555"

DAEMON_DOWN_STDERR = (
    "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; "
    "check if the path is correct and if the daemon is running: open "
    "//./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified."
)
NOT_FOUND_STDERR = "Error response from daemon: No such container: cid-dvwa"


def _spec() -> RangeSpec:
    return RangeSpec(
        range_id=RANGE_ID,
        resource_prefix="abc123",
        components=(
            ComponentSpec(
                key="dvwa",
                name="DVWA",
                role="target",
                image="vulnerables/web-dvwa:1.9",
                container_port=80,
            ),
        ),
    )


def _ctx(steps: list[RecordedStep]) -> OperationContext:
    return OperationContext(steps, lambda *_: None, lambda *_: None)


# --- property 1: a probe that cannot run answers "unknown" --------------------


def test_object_exists_is_unknown_when_the_daemon_is_unreachable(monkeypatch):
    def fake_run(args, **kwargs):
        raise DockerUnavailableError(DAEMON_DOWN_STDERR)

    monkeypatch.setattr(docker_cli, "run", fake_run)
    assert docker_cli.object_exists("container", "cid-dvwa") is None


def test_a_not_found_error_is_not_believed_unless_the_daemon_answers(monkeypatch):
    """THE CENTRAL CASE.

    ``inspect`` returns a textbook "No such container" — but the daemon is not answering. The error
    text alone must not be enough: absence stays unknown.
    """
    monkeypatch.setattr(
        docker_cli,
        "run",
        lambda args, **kwargs: CommandResult(returncode=1, stdout="", stderr=NOT_FOUND_STDERR),
    )
    monkeypatch.setattr(
        docker_cli, "daemon_health", lambda: DaemonHealth(reachable=False, detail="down")
    )
    assert docker_cli.object_exists("container", "cid-dvwa") is None


def test_absence_is_proved_only_when_the_probe_proves_itself(monkeypatch):
    monkeypatch.setattr(
        docker_cli,
        "run",
        lambda args, **kwargs: CommandResult(returncode=1, stdout="", stderr=NOT_FOUND_STDERR),
    )
    monkeypatch.setattr(
        docker_cli,
        "daemon_health",
        lambda: DaemonHealth(reachable=True, daemon_id="D1", version="29.4.0"),
    )
    assert docker_cli.object_exists("container", "cid-dvwa") is False


#: Captured from a live daemon (29.4.0), not recalled. Docker uses TWO different phrasings and the
#: network one was missed at first, which made every ordinary teardown report its network as
#: ``unproven``. A warning that fires on every clean run is one operators stop reading.
NOT_FOUND_STDERR_BY_KIND = {
    "container": "Error response from daemon: No such container: {ref}",
    "network": "Error response from daemon: network {ref} not found",
    "image": "Error response from daemon: No such image: {ref}",
}


@pytest.mark.parametrize("kind", sorted(NOT_FOUND_STDERR_BY_KIND))
def test_every_real_not_found_phrasing_proves_absence(monkeypatch, kind):
    """REGRESSION — a clean teardown must not report ``unproven`` just because Docker reworded."""
    reference = "be26d57caf64a55e17a5d00bc3627f5f1b57305284494476835b714924252b25"
    stderr = NOT_FOUND_STDERR_BY_KIND[kind].format(ref=reference)
    monkeypatch.setattr(
        docker_cli,
        "run",
        lambda args, **kwargs: CommandResult(returncode=1, stdout="", stderr=stderr),
    )
    monkeypatch.setattr(
        docker_cli, "daemon_health", lambda: DaemonHealth(reachable=True, daemon_id="D1")
    )
    probe_kind = "container" if kind == "container" else "network"
    assert docker_cli.object_exists(probe_kind, reference) is False


def test_a_not_found_about_some_other_object_is_not_evidence_about_ours(monkeypatch):
    """The message must name the object we asked about, or it proves nothing about it."""
    monkeypatch.setattr(
        docker_cli,
        "run",
        lambda args, **kwargs: CommandResult(
            returncode=1, stdout="", stderr="Error response from daemon: manifest not found"
        ),
    )
    monkeypatch.setattr(
        docker_cli, "daemon_health", lambda: DaemonHealth(reachable=True, daemon_id="D1")
    )
    assert docker_cli.object_exists("network", "secp-range-abc123") is None


def test_an_unrecognised_failure_is_unknown_not_absent(monkeypatch):
    """No guessing. A non-zero exit that is not a recognisable "not found" proves nothing."""
    monkeypatch.setattr(
        docker_cli,
        "run",
        lambda args, **kwargs: CommandResult(
            returncode=1, stdout="", stderr="Error response from daemon: something else entirely"
        ),
    )
    monkeypatch.setattr(
        docker_cli, "daemon_health", lambda: DaemonHealth(reachable=True, daemon_id="D1")
    )
    assert docker_cli.object_exists("container", "cid-dvwa") is None


def test_destroy_with_an_unreachable_daemon_reports_unproven_for_everything(monkeypatch):
    provider = LocalDockerProvider()
    monkeypatch.setattr(
        provider, "health", lambda: ProviderHealth(reachable=False, detail=DAEMON_DOWN_STDERR)
    )
    spec = _spec()
    existing = (
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="secp-range-abc123-dvwa",
            component_key="dvwa",
            external_id="cid-dvwa",
            owner_label=f"{RANGE_ID_LABEL_KEY}={RANGE_ID}",
        ),
        ResourceObservation(
            kind=RangeResourceKind.network,
            name="secp-range-abc123",
            external_id="net-1",
            owner_label=f"{RANGE_ID_LABEL_KEY}={RANGE_ID}",
        ),
    )
    result = provider.destroy(spec, existing, _ctx(provider.plan_steps(spec, "destroy")))

    assert result.probe_reachable is False
    assert {o.outcome for o in result.observations} == {TeardownResourceOutcome.unproven}
    assert TeardownResourceOutcome.removed not in {o.outcome for o in result.observations}
    assert "share" in (result.reason or "")


def test_a_daemon_that_dies_mid_teardown_invalidates_the_removals(monkeypatch):
    """Removals appear to succeed, then the observer goes away. Nothing may be claimed as proved."""
    provider = LocalDockerProvider()
    monkeypatch.setattr(
        provider, "health", lambda: ProviderHealth(reachable=True, endpoint_id="D1", version="29.4")
    )
    monkeypatch.setattr(
        provider,
        "_remove_one",
        lambda spec, resource, kind: TeardownObservation(
            kind=kind,
            name=resource.name if resource else "x",
            external_id=resource.external_id if resource else None,
            outcome=TeardownResourceOutcome.removed,
            detail="removal requested",
        ),
    )
    # The post-removal health check is the one that matters — and it fails.
    import secp_api.range_providers.local_docker as local_docker

    monkeypatch.setattr(
        local_docker, "daemon_health", lambda: DaemonHealth(reachable=False, detail="gone")
    )

    spec = _spec()
    existing = (
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="secp-range-abc123-dvwa",
            component_key="dvwa",
            external_id="cid-dvwa",
            owner_label=f"{RANGE_ID_LABEL_KEY}={RANGE_ID}",
        ),
    )
    result = provider.destroy(spec, existing, _ctx(provider.plan_steps(spec, "destroy")))

    assert result.probe_reachable is False
    assert {o.outcome for o in result.observations} == {TeardownResourceOutcome.unproven}
    assert "could not run" in (result.reason or "") or "not proved" in (result.reason or "")


def test_a_different_daemon_answering_does_not_prove_our_resources_are_gone(monkeypatch):
    """Endpoint identity is pinned. Another daemon's "no such object" is about ITS world."""
    provider = LocalDockerProvider()
    monkeypatch.setattr(
        provider, "health", lambda: ProviderHealth(reachable=True, endpoint_id="D1", version="29.4")
    )
    monkeypatch.setattr(
        provider,
        "_remove_one",
        lambda spec, resource, kind: TeardownObservation(
            kind=kind,
            name=resource.name if resource else "x",
            external_id=resource.external_id if resource else None,
            outcome=TeardownResourceOutcome.removed,
            detail="removal requested",
        ),
    )
    import secp_api.range_providers.local_docker as local_docker

    # Reachable — but it is a DIFFERENT daemon than the one that created the resources.
    monkeypatch.setattr(
        local_docker,
        "daemon_health",
        lambda: DaemonHealth(reachable=True, daemon_id="D2-somewhere-else", version="29.4"),
    )

    spec = _spec()
    existing = (
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="secp-range-abc123-dvwa",
            component_key="dvwa",
            external_id="cid-dvwa",
            owner_label=f"{RANGE_ID_LABEL_KEY}={RANGE_ID}",
        ),
    )
    result = provider.destroy(spec, existing, _ctx(provider.plan_steps(spec, "destroy")))

    assert result.probe_reachable is False
    assert {o.outcome for o in result.observations} == {TeardownResourceOutcome.unproven}
    assert "different daemon" in (result.reason or "")


# --- property 2: never remove what we do not own ------------------------------


def test_a_resource_without_our_ownership_labels_is_refused_not_removed(monkeypatch):
    """A recorded id that now points at something else must NOT be deleted."""
    provider = LocalDockerProvider()
    import secp_api.range_providers.local_docker as local_docker

    removals: list[list[str]] = []

    monkeypatch.setattr(local_docker, "object_exists", lambda kind, ref: True)
    monkeypatch.setattr(
        local_docker,
        "inspect_json",
        lambda kind, ref: {"Config": {"Labels": {"com.example.someone-else": "yes"}}},
    )
    monkeypatch.setattr(
        local_docker,
        "run",
        lambda args, **kwargs: removals.append(args) or CommandResult(0, "", ""),
    )

    outcome = provider._remove_one(
        _spec(),
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="postgres-prod",
            external_id="cid-not-ours",
            owner_label="whatever",
        ),
        RangeResourceKind.container,
    )

    assert outcome.outcome is TeardownResourceOutcome.present
    assert "refused to remove" in (outcome.detail or "")
    assert removals == [], "nothing may be removed when the ownership labels do not match"


def test_a_resource_labelled_for_a_different_range_is_refused(monkeypatch):
    provider = LocalDockerProvider()
    import secp_api.range_providers.local_docker as local_docker

    removals: list[list[str]] = []
    monkeypatch.setattr(local_docker, "object_exists", lambda kind, ref: True)
    monkeypatch.setattr(
        local_docker,
        "inspect_json",
        lambda kind, ref: {
            "Config": {
                "Labels": {
                    OWNER_LABEL_KEY: OWNER_LABEL_VALUE,
                    RANGE_ID_LABEL_KEY: "99999999-9999-4999-8999-999999999999",
                }
            }
        },
    )
    monkeypatch.setattr(
        local_docker,
        "run",
        lambda args, **kwargs: removals.append(args) or CommandResult(0, "", ""),
    )

    outcome = provider._remove_one(
        _spec(),
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="secp-range-other-dvwa",
            external_id="cid-other-range",
            owner_label="x",
        ),
        RangeResourceKind.container,
    )
    assert outcome.outcome is TeardownResourceOutcome.present
    assert removals == []


def test_our_own_resource_is_removed(monkeypatch):
    provider = LocalDockerProvider()
    import secp_api.range_providers.local_docker as local_docker

    removals: list[list[str]] = []
    monkeypatch.setattr(local_docker, "object_exists", lambda kind, ref: True)
    monkeypatch.setattr(
        local_docker,
        "inspect_json",
        lambda kind, ref: {
            "Config": {"Labels": {OWNER_LABEL_KEY: OWNER_LABEL_VALUE, RANGE_ID_LABEL_KEY: RANGE_ID}}
        },
    )
    monkeypatch.setattr(
        local_docker,
        "run",
        lambda args, **kwargs: removals.append(args) or CommandResult(0, "", ""),
    )

    outcome = provider._remove_one(
        _spec(),
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="secp-range-abc123-dvwa",
            external_id="cid-dvwa",
            owner_label="x",
        ),
        RangeResourceKind.container,
    )
    assert outcome.outcome is TeardownResourceOutcome.removed
    assert removals and removals[0][0] == "rm"
    assert "cid-dvwa" in removals[0]


def _capture_run(monkeypatch, module, responses=None):
    """Record every argv the provider hands to the docker CLI."""
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if responses is not None and args and args[0] in responses:
            return responses[args[0]]
        return CommandResult(returncode=0, stdout="stub-id", stderr="")

    monkeypatch.setattr(module, "run", fake_run)
    return calls


def test_a_destroy_only_ever_names_specific_recorded_ids(monkeypatch):
    """Behavioural, not textual: inspect the argv the provider actually issues.

    Removal must always name ONE specific recorded id. ``prune`` or a label ``--filter`` would
    select by pattern, and a pattern can match a bystander that merely looks like ours.
    """
    provider = LocalDockerProvider()
    import secp_api.range_providers.local_docker as local_docker
    monkeypatch.setattr(
        provider, "health", lambda: ProviderHealth(reachable=True, endpoint_id="D1", version="29.4")
    )
    monkeypatch.setattr(local_docker, "object_exists", lambda kind, ref: True)
    monkeypatch.setattr(
        local_docker,
        "inspect_json",
        lambda kind, ref: {
            "Config": {
                "Labels": {OWNER_LABEL_KEY: OWNER_LABEL_VALUE, RANGE_ID_LABEL_KEY: RANGE_ID}
            },
            "Labels": {OWNER_LABEL_KEY: OWNER_LABEL_VALUE, RANGE_ID_LABEL_KEY: RANGE_ID},
        },
    )
    monkeypatch.setattr(
        local_docker, "daemon_health", lambda: DaemonHealth(reachable=True, daemon_id="D1")
    )
    calls = _capture_run(monkeypatch, local_docker)

    spec = _spec()
    recorded = {"cid-dvwa", "net-1"}
    existing = (
        ResourceObservation(
            kind=RangeResourceKind.container,
            name="secp-range-abc123-dvwa",
            component_key="dvwa",
            external_id="cid-dvwa",
            owner_label="x",
        ),
        ResourceObservation(
            kind=RangeResourceKind.network,
            name="secp-range-abc123",
            external_id="net-1",
            owner_label="x",
        ),
    )
    provider.destroy(spec, existing, _ctx(provider.plan_steps(spec, "destroy")))

    removals = [c for c in calls if c[0] == "rm" or c[:2] == ["network", "rm"]]
    assert removals, "the destroy issued no removal at all"
    for argv in removals:
        assert not any(arg == "prune" for arg in argv)
        assert not any(arg.startswith("--filter") for arg in argv)
        assert recorded & set(argv), f"removal did not name a recorded id: {argv}"
    assert all("prune" not in c for c in calls)


def test_published_ports_bind_loopback_only(monkeypatch):
    """Intentionally vulnerable software is never offered to the LAN."""
    provider = LocalDockerProvider()
    import secp_api.range_providers.local_docker as local_docker
    assert local_docker.BIND_HOST == "127.0.0.1"
    monkeypatch.setattr(
        provider, "health", lambda: ProviderHealth(reachable=True, endpoint_id="D1", version="29.4")
    )
    monkeypatch.setattr(local_docker, "image_digest", lambda image: "sha256:stub")
    monkeypatch.setattr(provider, "_published_port", lambda name, port: 40000)
    monkeypatch.setattr(provider, "_verify_component", lambda component, obs: (True, "HTTP 200"))
    calls = _capture_run(monkeypatch, local_docker)

    spec = _spec()
    provider.deploy(spec, _ctx(provider.plan_steps(spec, "deploy")))

    run_calls = [c for c in calls if c and c[0] == "run"]
    assert run_calls, "no container was started"
    for argv in run_calls:
        publish = argv[argv.index("--publish") + 1]
        assert publish.startswith("127.0.0.1:"), f"port not bound to loopback: {publish}"
        assert not publish.startswith("0.0.0.0")
        # Ownership is stamped at creation — teardown's safety check depends on it being there.
        assert f"{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}" in argv
        assert f"{RANGE_ID_LABEL_KEY}={RANGE_ID}" in argv


# --- the seal -----------------------------------------------------------------


def test_the_local_docker_provider_is_sealed_by_default(monkeypatch):
    """A Docker socket is root-equivalent on the host, so this capability is opt-in.

    See the standing architecture exception at the top of
    ``secp_api/range_providers/local_docker.py``: until range execution moves to the worker
    boundary or a reviewed charter exception is recorded, the seal is what stops a deployment
    acquiring privileged local execution by accident.
    """
    from secp_api.config import get_settings
    from secp_api.range_providers import (
        RangeProviderSealedError,
        get_provider,
        reset_providers,
    )

    reset_providers()
    get_settings.cache_clear()
    monkeypatch.delenv("SECP_RANGE_LOCAL_DOCKER", raising=False)
    try:
        with pytest.raises(RangeProviderSealedError):
            get_provider("local_docker")
    finally:
        reset_providers()
        get_settings.cache_clear()


def test_the_seal_can_never_be_opened_in_production(monkeypatch):
    from secp_api.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("SECP_RANGE_LOCAL_DOCKER", "true")
    monkeypatch.setenv("SECP_APP_ENV", "production")
    monkeypatch.setenv("SECP_AUTH_DEV_MODE", "false")
    monkeypatch.setenv("SECP_WORKFLOW_DISPATCH_MODE", "temporal")
    # A production Settings refuses to construct at all unless the rest of the production
    # configuration is valid, so supply it — the point of the test is the seal, not the validator.
    monkeypatch.setenv("SECP_OIDC_ISSUER", "https://idp.example.com/realms/secp")
    monkeypatch.setenv("SECP_PUBLIC_ORIGIN", "https://secp.example.com")
    monkeypatch.setenv("SECP_CORS_ALLOW_ORIGINS", "[]")
    try:
        settings = get_settings()
        assert settings.range_local_docker is True
        assert settings.range_local_docker_enabled is False
    finally:
        get_settings.cache_clear()
