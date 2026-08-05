"""The real-Docker milestone: one container actually deployed, actually answered, actually gone.

WHY THIS FILE EXISTS SEPARATELY FROM ``test_range_docker_provider.py``
---------------------------------------------------------------------
That module substitutes the CLI seam and drives the provider against a scripted fake. It proves the
provider's LOGIC — that an unreachable probe yields ``unproven``, that an unowned label is refused.
It proves exactly nothing about the provider's CONTACT with a daemon, because in that module no
daemon exists. Both halves are necessary and neither substitutes for the other.

This module is the other half. It drives the ordinary HTTP API against a real Docker daemon and
then checks the outcome with ``docker`` commands that this code did not issue, through a subprocess
helper that deliberately does NOT import :mod:`secp_api.range_providers.docker_cli`. A verifier that
shares its implementation with the thing it verifies can only confirm that the code agrees with
itself.

WHAT IS PROVED HERE, IN ORDER
-----------------------------
1. A range is created through ``POST /api/v1/ranges``.
2. ``POST /ranges/{id}/deploy`` really pulls, really creates a network, really starts a container.
3. Readiness is DERIVED FROM OBSERVATION — the recorded step detail is the HTTP status the app
   itself returned, and the test independently fetches the published URL and finds Juice Shop's own
   markup in the body. Nothing here sleeps and then assumes.
4. The published port is bound to 127.0.0.1 and to nothing else, checked against the daemon's own
   port map rather than against our intent.
5. A teardown attempted while the daemon is unreachable reports ``unproven`` and drives the range to
   ``recovery_required`` — while the container is demonstrably still running. This is the case the
   whole three-state vocabulary exists for: the existence check fails for the same reason the
   removal did, so its silence is not evidence of absence.
6. A teardown against a live daemon then reports ``clean``, and NOTHING owned by the range remains.
7. The host's full container/network/volume inventory is byte-identical before and after. Unrelated
   resources are not merely "probably fine" — they are enumerated and compared.

WHY THE SKIP IS LOUD
--------------------
A tier that silently vanishes reads exactly like a tier that passed. This program has been bitten by
that twice (an ``importorskip`` on an optional extra, and a JUnit report that could not express
deselection), so the skip here is not allowed to be quiet:

* :func:`test_the_real_docker_tier_is_accounted_for` is NOT skippable. It always runs and always
  reports which way this module went.
* Setting ``SECP_REQUIRE_REAL_DOCKER_PROOF=1`` turns an absent daemon from a skip into a FAILURE.
  A CI job that is supposed to have Docker sets it, and then losing the daemon breaks the build
  instead of quietly shrinking it.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
import warnings
from contextlib import contextmanager

import pytest
import secp_api.range_models  # noqa: F401  (registers the range tables on Base before create_all)
from fastapi.testclient import TestClient
from secp_api.deps import current_principal
from secp_api.range_enums import (
    RangeOperationStatus,
    RangeResourceState,
    RangeState,
    ResidueVerdict,
)

TEMPLATE_SLUG = "juice-shop-solo"
COMPONENT_KEY = "juice-shop"
EXPECTED_IMAGE = "bkimminich/juice-shop:v17.1.0"
RANGE_ID_LABEL = "secp.range.id"

#: Turns "no daemon" from a skip into a failure. For CI jobs that are supposed to have Docker.
REQUIRE_ENV = "SECP_REQUIRE_REAL_DOCKER_PROOF"

#: A port nothing listens on. Used to make the daemon unreachable for one operation WITHOUT
#: stopping the real daemon, which would disrupt containers this test does not own.
DEAD_DOCKER_ENDPOINT = "tcp://127.0.0.1:1"


# --- an independent view of Docker, sharing no code with the module under test ------------------


def _docker(*args: str) -> subprocess.CompletedProcess:
    """Run ``docker`` directly.

    Intentionally a separate implementation from ``range_providers.docker_cli``. ``encoding`` is
    explicit for the same reason it is there: ``text=True`` alone decodes with the locale codec,
    which is cp1252 on a default Windows host, and the Juice Shop image carries a label containing
    a character that codec cannot represent.
    """
    return subprocess.run(  # noqa: S603 - fixed binary, argument vector, never a shell
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def _daemon_reachable() -> bool:
    try:
        return _docker("version", "--format", "{{.Server.Version}}").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


DOCKER_REACHABLE = _daemon_reachable()

requires_docker = pytest.mark.skipif(
    not DOCKER_REACHABLE,
    reason=(
        "SKIPPED TIER: no reachable Docker daemon, so the real-container proof did NOT run. "
        f"Everything the local Docker provider claims here is unverified in this run. Set "
        f"{REQUIRE_ENV}=1 to make this a failure instead of a skip."
    ),
)


def _lines(result: subprocess.CompletedProcess) -> list[str]:
    return [line for line in (result.stdout or "").splitlines() if line.strip()]


def _inventory() -> dict[str, list[str]]:
    """Every container, network and volume on the host, by name.

    Compared before and after the whole flow. This is what makes "we touched nothing else" a
    measurement rather than an assurance.
    """
    return {
        "containers": sorted(_lines(_docker("ps", "-a", "--format", "{{.Names}}"))),
        "networks": sorted(_lines(_docker("network", "ls", "--format", "{{.Name}}"))),
        "volumes": sorted(_lines(_docker("volume", "ls", "--format", "{{.Name}}"))),
    }


def _owned_by(range_id: str) -> dict[str, list[str]]:
    """Everything still carrying this range's ownership label. The residue enumeration."""
    label = f"label={RANGE_ID_LABEL}={range_id}"
    return {
        "containers": _lines(_docker("ps", "-a", "--filter", label, "--format", "{{.Names}}")),
        "networks": _lines(_docker("network", "ls", "--filter", label, "--format", "{{.Name}}")),
        "volumes": _lines(_docker("volume", "ls", "--filter", label, "--format", "{{.Name}}")),
    }


def _http_get_text(url: str, timeout: float = 15.0) -> tuple[int, str]:
    request = urllib.request.Request(url, method="GET")  # noqa: S310 - fixed loopback scheme
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read(200_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(200_000).decode("utf-8", errors="replace")


@contextmanager
def _unreachable_daemon():
    """Point the docker client at a dead endpoint for the duration of the block.

    Deliberately NOT ``docker stop``/``systemctl stop docker``: stopping the daemon would take down
    every unrelated container on this host. Redirecting the client reproduces the property under
    test — the provider cannot reach its control API — without touching anything we do not own.
    """
    previous = os.environ.get("DOCKER_HOST")
    os.environ["DOCKER_HOST"] = DEAD_DOCKER_ENDPOINT
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("DOCKER_HOST", None)
        else:
            os.environ["DOCKER_HOST"] = previous


# --- fixtures -----------------------------------------------------------------------------------


@pytest.fixture
def docker_range_env(monkeypatch):
    """Unseal the local Docker provider and run range operations synchronously.

    The provider is sealed by default because a Docker socket is root-equivalent. Enabling it is an
    explicit, dev-only opt-in, and this fixture is the only place in the suite that does it.
    """
    from secp_api.config import get_settings
    from secp_api.services import range_runner

    monkeypatch.setenv("SECP_RANGE_LOCAL_DOCKER", "true")
    get_settings.cache_clear()

    from secp_api.range_providers import reset_providers

    reset_providers()

    assert get_settings().range_local_docker_enabled, (
        "the local Docker provider is still sealed; this environment refuses to enable it "
        "(is SECP_ENVIRONMENT set to a production value?)"
    )

    previous_mode = range_runner.get_mode()
    range_runner.set_mode("inline")
    try:
        yield
    finally:
        range_runner.set_mode(previous_mode)
        reset_providers()
        get_settings.cache_clear()


@pytest.fixture
def client(engine, principal) -> TestClient:
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    app.dependency_overrides[current_principal] = lambda: principal
    return TestClient(app)


def _operation(client: TestClient, response) -> dict:
    """Re-read an operation after the 202.

    The route projects the operation row BEFORE scheduling the work, so the 202 body always says
    ``pending``. In inline mode the work is already finished by the time the response arrives, so
    the outcome is one GET away.
    """
    assert response.status_code == 202, response.text
    operation_id = response.json()["id"]
    fetched = client.get(f"/api/v1/range-operations/{operation_id}")
    assert fetched.status_code == 200, fetched.text
    return fetched.json()


def _pretty(payload) -> str:
    return json.dumps(payload, indent=2, default=str)


def _evidence(label: str, value: object) -> None:
    """Emit one line of evidence.

    A green assertion says a claim held; it does not say WHAT held. Run with ``-s`` and these lines
    are the operator-readable record of the container, the endpoint and the teardown that this run
    actually observed — the thing worth keeping when the run is over.
    """
    print(f"[range-proof] {label}: {value}", flush=True)


# --- the accounting test: never skipped ---------------------------------------------------------


def test_the_real_docker_tier_is_accounted_for():
    """ALWAYS RUNS, so this module can never disappear from a report without saying so.

    A skipped test and a test that was never collected look identical in a JUnit XML once the tier
    is gone. This one is not skippable, so the report always carries a statement about whether the
    real-container proof ran.
    """
    required = os.environ.get(REQUIRE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}
    if DOCKER_REACHABLE:
        return
    if required:
        pytest.fail(
            f"{REQUIRE_ENV} is set, but no Docker daemon is reachable. The real-container proof "
            "did not run. This is a failure rather than a skip on purpose: this job is configured "
            "to have Docker, so a missing daemon is a broken environment, not a smaller test run."
        )
    warnings.warn(
        "REAL-DOCKER TIER SKIPPED: no reachable Docker daemon. The local Docker provider's contact "
        "with a daemon is UNVERIFIED in this run — only its logic (against a substituted CLI) was "
        f"tested. Set {REQUIRE_ENV}=1 to make this a hard failure.",
        stacklevel=1,
    )


# --- the milestone ------------------------------------------------------------------------------


@requires_docker
def test_one_real_container_deploys_answers_and_is_removed_without_residue(
    client, docker_range_env
):
    """Create through the API, deploy for real, talk to the target, tear down, prove it is gone."""
    baseline = _inventory()

    # 1. CREATE ------------------------------------------------------------------------------
    created = client.post(
        "/api/v1/ranges",
        json={"template_slug": TEMPLATE_SLUG, "name": "real-docker-proof"},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    range_id = body["id"]
    assert body["state"] == RangeState.draft.value
    assert body["provider"] == "local_docker"
    assert body["access"] == [], "a range that has never deployed cannot have an access endpoint"

    # 2. DEPLOY ------------------------------------------------------------------------------
    operation = _operation(client, client.post(f"/api/v1/ranges/{range_id}/deploy"))
    assert operation["status"] == RangeOperationStatus.succeeded.value, _pretty(operation)

    steps = {step["key"]: step for step in operation["steps"]}
    assert steps[f"pull:{COMPONENT_KEY}"]["status"] == "succeeded"
    assert steps["network"]["status"] == "succeeded"
    assert steps[f"start:{COMPONENT_KEY}"]["status"] == "succeeded"

    # 3. READINESS BY OBSERVATION -------------------------------------------------------------
    # The verify step's recorded detail is the status line the application itself returned. A
    # deploy that merely started a container cannot produce this.
    verify = steps[f"verify:{COMPONENT_KEY}"]
    assert verify["status"] == "succeeded", _pretty(verify)
    assert verify["detail"].startswith("HTTP "), (
        "readiness must be the target's own response, not an assumption: " f"{verify['detail']!r}"
    )

    resources = client.get(f"/api/v1/ranges/{range_id}/resources").json()
    containers = [r for r in resources if r["kind"] == "container"]
    networks = [r for r in resources if r["kind"] == "network"]
    assert len(containers) == 1, _pretty(resources)
    assert len(networks) == 1, _pretty(resources)
    container, network = containers[0], networks[0]

    assert container["state"] == RangeResourceState.verified.value
    assert container["image"] == EXPECTED_IMAGE
    assert container["image_digest"].startswith("sha256:"), (
        "the digest that actually ran must be recorded, not just the tag we asked for"
    )
    assert container["host_port"]

    # 4. THE DAEMON'S OWN ACCOUNT OF THAT CONTAINER -------------------------------------------
    inspected = _docker("container", "inspect", container["external_id"])
    assert inspected.returncode == 0, inspected.stderr
    live = json.loads(inspected.stdout)[0]
    assert live["State"]["Running"] is True
    assert live["Config"]["Labels"][RANGE_ID_LABEL] == range_id
    assert network["name"] in live["NetworkSettings"]["Networks"], (
        "the container must be on the range's own network, not the default bridge"
    )

    # Loopback only. Checked against the daemon's port map, not against our intent.
    bindings = live["NetworkSettings"]["Ports"]["3000/tcp"]
    assert [b["HostIp"] for b in bindings] == ["127.0.0.1"], (
        f"intentionally vulnerable software must never leave loopback: {bindings}"
    )

    _evidence("range id", range_id)
    _evidence("container", f"{container['name']}  id={live['Id'][:12]}  image={container['image']}")
    _evidence("image digest", container["image_digest"])
    _evidence("network", f"{network['name']}  id={(network['external_id'] or '')[:12]}")
    _evidence("started at", live["State"]["StartedAt"])
    _evidence("port binding", bindings)
    _evidence("readiness (observed)", verify["detail"])

    # 5. THE ACCESS ENDPOINT ACTUALLY ANSWERS -------------------------------------------------
    ranged = client.get(f"/api/v1/ranges/{range_id}").json()
    assert ranged["state"] in {RangeState.ready.value, RangeState.active.value}
    assert len(ranged["access"]) == 1, _pretty(ranged["access"])
    access = ranged["access"][0]
    assert access["host"] == "127.0.0.1"
    assert access["port"] == container["host_port"]

    status, page = _http_get_text(access["url"])
    assert status == 200, f"{access['url']} answered {status}"
    assert "juice" in page.lower(), (
        "the endpoint answered, but not with Juice Shop's own page; the port may be someone "
        f"else's. First 300 bytes: {page[:300]!r}"
    )

    title = page[page.lower().find("<title") : page.lower().find("</title>") + 8]
    _evidence("access endpoint", access["url"])
    _evidence("endpoint answered", f"HTTP {status}, {len(page)} bytes")
    _evidence("served page title", title.strip() or page[:120])

    # 6. TEARDOWN WITH AN UNREACHABLE DAEMON IS `unproven`, NEVER CLEAN -----------------------
    # The container is up right now. If an unreachable probe were allowed to report "clean", it
    # would do so here, while the thing it claims is gone is still serving traffic.
    with _unreachable_daemon():
        blind = _operation(client, client.post(f"/api/v1/ranges/{range_id}/destroy"))

    assert blind["status"] == RangeOperationStatus.unproven.value, _pretty(blind)
    assert blind["failure_code"] == "residue_unproven"

    after_blind = client.get(f"/api/v1/ranges/{range_id}").json()
    assert after_blind["state"] == RangeState.recovery_required.value
    assert after_blind["residue_verdict"] == ResidueVerdict.unproven.value
    assert after_blind["state_reason"]

    unproven_evidence = [
        e
        for e in client.get(f"/api/v1/ranges/{range_id}/teardown-evidence").json()
        if e["verdict"] == ResidueVerdict.unproven.value
    ]
    assert len(unproven_evidence) == 1, "the blind teardown must leave a record of its own blindness"
    assert unproven_evidence[0]["probe_reachable"] is False
    assert unproven_evidence[0]["removed_confirmed"] == 0
    assert unproven_evidence[0]["unproven_count"] == 2, _pretty(unproven_evidence[0])

    # And the resources really are still there — the refusal to claim "clean" was correct.
    _evidence("blind teardown status", blind["status"])
    _evidence("blind teardown state", f"{after_blind['state']} / {after_blind['residue_verdict']}")
    _evidence("blind teardown reason", after_blind["state_reason"])

    still_owned = _owned_by(range_id)
    _evidence("owned resources after blind teardown", still_owned)
    assert container["name"] in still_owned["containers"]
    assert network["name"] in still_owned["networks"]
    assert json.loads(_docker("container", "inspect", container["external_id"]).stdout)[0]["State"][
        "Running"
    ] is True

    # 7. TEARDOWN WITH A LIVE DAEMON IS CLEAN --------------------------------------------------
    destroyed = _operation(client, client.post(f"/api/v1/ranges/{range_id}/destroy"))
    assert destroyed["status"] == RangeOperationStatus.succeeded.value, _pretty(destroyed)

    final = client.get(f"/api/v1/ranges/{range_id}").json()
    assert final["state"] == RangeState.destroyed.value
    assert final["residue_verdict"] == ResidueVerdict.clean.value

    clean_evidence = [
        e
        for e in client.get(f"/api/v1/ranges/{range_id}/teardown-evidence").json()
        if e["verdict"] == ResidueVerdict.clean.value
    ]
    assert len(clean_evidence) == 1, "the successful teardown must leave its own evidence row"
    assert clean_evidence[0]["probe_reachable"] is True
    assert clean_evidence[0]["still_present"] == 0
    assert clean_evidence[0]["unproven_count"] == 0
    assert clean_evidence[0]["removed_confirmed"] == 2

    # 8. ZERO OWNED RESIDUE, ENUMERATED ------------------------------------------------------
    residue = _owned_by(range_id)
    _evidence("clean teardown status", destroyed["status"])
    _evidence("teardown evidence", _pretty(clean_evidence[0]["resources"]))
    _evidence("owned resources after clean teardown", residue)
    assert residue == {"containers": [], "networks": [], "volumes": []}

    # 9. AND NOTHING ELSE ON THIS HOST MOVED --------------------------------------------------
    _evidence(
        "host inventory unchanged",
        f"{len(baseline['containers'])} containers, {len(baseline['networks'])} networks, "
        f"{len(baseline['volumes'])} volumes",
    )
    assert _inventory() == baseline, (
        "the host inventory differs from the pre-test baseline; a range teardown must remove "
        "exactly what the range created and nothing else"
    )
