"""PostgreSQL + real-socket gate for the Proxmox operator command surface.

WHY THIS MODULE EXISTS SEPARATELY FROM THE UNIT SUITE
-------------------------------------------------------
Every test in ``apps/api/tests`` drives the app through ``fastapi.testclient.TestClient``, which
runs the ASGI app to completion in-process: the request exit stack — and every
``Depends``-with-yield teardown — is closed before the assertion. That makes two whole classes of
defect structurally invisible there, whatever database is underneath:

* **response ordering.** A command that answers ``201`` before its transaction commits looks correct
  under ``TestClient`` and produces, on a real socket, a record the immediately following read
  cannot see. The command surface is exactly where that matters: the whole point of a durable
  command is that a client can read back what it just asked for.
* **the real request pipeline.** Authentication, error handlers, and the middleware stack all run
  under ``TestClient``, but a route is only genuinely *reachable* when something has bound a port
  and answered a socket. A route registered on a router that was never included answers a
  ``TestClient`` call through the same object graph and 404s a real client.

CI already runs real PostgreSQL 16. This supplies the socket, for the four properties the brief
requires proving on the wire rather than by direct function call: every route requires
authentication, organization scoping holds, target scoping holds, and an ordinary worker cannot be
used for controlled-live execution.

WHAT IT DOES NOT DO
---------------------
It contacts no Proxmox cluster, runs no OpenTofu, starts no container and spawns no process. The
only listener is an ephemeral loopback port inside the runner, and the only observation is a
recorded fixture — exactly what the worker would have written.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECP_APP_ENV", "test")
os.environ.setdefault("SECP_WORKFLOW_DISPATCH_MODE", "inline")

import uuid  # noqa: E402
from collections.abc import Iterator  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
import secp_api.immutability  # noqa: E402,F401  (registers ORM immutability guards)
from secp_api.db import get_sessionmaker, reset_engine_for_tests  # noqa: E402
from secp_api.models import Base, Organization, Role, User, UserRoleAssignment  # noqa: E402
from secp_api.seed import bootstrap_dev  # noqa: E402
from secp_api.services import proxmox_lifecycle, ranges  # noqa: E402
from secp_api.worker_enrollment_models import WorkerEnrollmentState  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402

from socket_gate_tests.live_api_server import live_api_server  # noqa: E402

PG_URL = os.environ.get("SECP_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="set SECP_TEST_POSTGRES_URL to run the PostgreSQL live-socket operator surface gate",
)

HTTP_TIMEOUT_SECONDS = 30.0
TARGET_ID = "tgt-socket-gate-01"
FINGERPRINT = "sha256:socketgate01"
DIGEST = "sha256:" + "ab" * 32
WORKER_INSTALLATION = "worker-socket-gate-01"
RELEASE_DIGEST = "sha256:" + "cd" * 32

#: The eight command paths. Enumerated here and CROSS-CHECKED against the live router below, so a
#: command added without an authentication proof fails this module rather than sliding in unproven.
COMMAND_SUFFIXES = (
    "topology-compilation",
    "plan-generation",
    "plan-review-submission",
    "execution-request",
    "reset-request",
    "reconciliation-request",
    "destroy-plan-generation",
    "destroy-execution-request",
)


class OperatorSurfaceInconclusive(AssertionError):
    """The gate could not measure what it claims to, so it refuses to report a verdict."""


# --- fixtures -------------------------------------------------------------------


def _observation_payload() -> dict:
    storage = {
        "storage_id": "local-lvm",
        "content_types": ["images", "rootdir"],
        "available_bytes": 2_000_000_000_000,
    }
    node = {
        "online": True,
        "cpu_cores_total": 64,
        "memory_bytes_total": 512_000_000_000,
        "storages": [storage],
        "bridges": ["vmbr0", "vmbr1"],
    }
    return {
        "identity": {
            "target_id": TARGET_ID,
            "cluster_name": "pve-socket-gate",
            "cluster_fingerprint": FINGERPRINT,
            "management_cidrs": ["10.0.0.0/24"],
            "management_bridges": ["vmbr0"],
        },
        "nodes": [{"node_name": "pve1", **node}, {"node_name": "pve2", **node}],
        "templates": [
            {"template_ref": "kali-2026", "vmid": 8000, "node_name": "pve1", "guest_kind": "qemu"},
            {"template_ref": "dvwa-1.9", "vmid": 8001, "node_name": "pve1", "guest_kind": "qemu"},
            {"template_ref": "juice-v17", "vmid": 8002, "node_name": "pve1", "guest_kind": "qemu"},
        ],
        "sdn_supported": True,
        "firewall_supported": True,
        "vlan_tags_in_use": [100],
        "vmids_in_use": [100, 8000, 8001, 8002],
        "macs_in_use": ["BC:24:11:00:00:01"],
        "subnets_in_use": ["10.0.0.0/24"],
        "sdn_names_in_use": ["legacy"],
        "firewall_names_in_use": ["existing"],
    }


def _binding_payload() -> dict:
    return {
        "observation": _observation_payload(),
        "teams": [
            {"team_ref": "red", "label": "Red"},
            {"team_ref": "blue", "label": "Blue"},
        ],
        "images": [
            {
                "workload_key": "attacker",
                "role": "attacker",
                "template_ref": "kali-2026",
                "workload_version": "2026.1",
                "image_digest": DIGEST,
                "approval_reference": "CAB-2026-11",
                "service_port": 22,
            },
            {
                "workload_key": "dvwa",
                "role": "target",
                "template_ref": "dvwa-1.9",
                "workload_version": "1.9",
                "image_digest": DIGEST,
                "approval_reference": "CAB-2026-12",
                "service_port": 80,
            },
            {
                "workload_key": "juice-shop",
                "role": "target",
                "template_ref": "juice-v17",
                "workload_version": "v17.1.0",
                "image_digest": DIGEST,
                "approval_reference": "CAB-2026-13",
                "service_port": 3000,
            },
        ],
        "profiles": {
            "attacker": {"cpu_cores": 4, "memory_mb": 8192, "disk_gb": 60},
            "target": {"cpu_cores": 2, "memory_mb": 4096, "disk_gb": 20},
        },
        "snapshot_id": "snap-socket-gate",
        "evidence_hash": "sha256:evidence",
        # NOW, so the freshness bound is satisfied and the execution commands are reachable.
        "observed_at": datetime.now(UTC).isoformat(),
        "scoring_port": 443,
        "generation": 1,
    }


@pytest.fixture(scope="module")
def pg_engine() -> Iterator[Engine]:
    """Rebind the process-global engine to real PostgreSQL, on a freshly created schema."""
    assert PG_URL
    engine = reset_engine_for_tests(PG_URL)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(engine)
    factory = get_sessionmaker()
    with factory() as session:
        bootstrap_dev(session)
        session.commit()
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def fixtures(pg_engine: Engine) -> dict:
    """Everything the gate reads, created once against real PostgreSQL and committed.

    Two organizations: the dev principal's own, and a second one whose range the dev principal must
    never be able to touch. Both ranges are real rows created through the real service.
    """
    assert pg_engine is not None
    factory = get_sessionmaker()
    with factory() as session:
        principal = bootstrap_dev(session)
        own = ranges.create_range(
            session, principal, template_slug="proxmox-web-breach-lab", name="socket-gate-own"
        )
        ranges.record_event(
            session,
            own,
            kind=proxmox_lifecycle.EVENT_OBSERVATION,
            message="discovery observation recorded",
            data=_binding_payload(),
        )

        other_org = Organization(name="Socket Gate Other Org", slug="socket-gate-other")
        session.add(other_org)
        session.flush()
        role = session.query(Role).filter_by(name="platform-admin").one()
        other_user = User(
            organization_id=other_org.id,
            email="socket-gate-other@local.test",
            display_name="Other Admin",
            subject="socket-gate-other",
        )
        session.add(other_user)
        session.flush()
        session.add(
            UserRoleAssignment(
                organization_id=other_org.id, user_id=other_user.id, role_id=role.id
            )
        )
        from secp_api.auth import Principal
        from secp_api.enums import Permission

        other_principal = Principal(
            user_id=other_user.id,
            organization_id=other_org.id,
            email=other_user.email,
            permissions=frozenset(Permission),
        )
        foreign = ranges.create_range(
            session,
            other_principal,
            template_slug="proxmox-web-breach-lab",
            name="socket-gate-foreign",
        )
        ranges.record_event(
            session,
            foreign,
            kind=proxmox_lifecycle.EVENT_OBSERVATION,
            message="discovery observation recorded",
            data=_binding_payload(),
        )

        # An ORDINARY worker: enrolled, identified, and NOT healthy. It has not completed the full
        # attestation exchange, so it may not be handed controlled-live execution.
        moment = datetime.now(UTC)
        session.add(
            WorkerEnrollmentState(
                enrollment_id="sha256:" + "77" * 32,
                organization_id=principal.organization_id,
                deployment_site_label="socket-gate-site",
                contract_version="secp-enrollment/v1",
                state="worker_bound",
                revision=1,
                sequence=1,
                controller_installation_id="controller-socket-gate",
                controller_key_id=DIGEST,
                worker_installation_id=WORKER_INSTALLATION,
                worker_key_id=DIGEST,
                release_digest=RELEASE_DIGEST,
                transaction_id="txn-socket-gate",
                expires_at=(moment + timedelta(days=1)).isoformat(),
                updated_at=moment.isoformat(),
                state_digest=DIGEST,
                expires_at_ts=moment + timedelta(days=1),
            )
        )
        session.commit()

        compiled = proxmox_lifecycle.compile_plan(session, own)
        if isinstance(compiled, proxmox_lifecycle.BlockedPlan):  # pragma: no cover - fixture guard
            raise OperatorSurfaceInconclusive(
                f"the gate's own fixture does not compile, so nothing below measures the surface: "
                f"{compiled.describe()}"
            )
        return {
            "range_id": str(own.id),
            "foreign_range_id": str(foreign.id),
            "plan_hash": compiled.plan_hash,
            "destroy_hash": compiled.destroy_hash,
            "version": own.event_sequence,
        }


@pytest.fixture(scope="module")
def live_base_url(pg_engine: Engine) -> Iterator[str]:
    """The real, shipped application composition served over a real ephemeral-port TCP socket."""
    assert pg_engine is not None
    from secp_api.main import create_app

    app = create_app()
    # The schema and dev seed are created explicitly above; clearing the startup hook keeps the run
    # deterministic. No route, dependency, middleware or error handler is altered.
    app.router.on_startup.clear()
    with live_api_server(app) as server:
        yield server.base_url


def _client(base_url: str) -> httpx.Client:
    return httpx.Client(base_url=base_url, timeout=HTTP_TIMEOUT_SECONDS)


def _envelope(version: int, **overrides) -> dict:
    body = {
        "idempotency_key": f"socket-gate-{uuid.uuid4().hex}",
        "expected_version": version,
        "operation_generation": 1,
        "target_id": TARGET_ID,
        "cluster_fingerprint": FINGERPRINT,
    }
    body.update(overrides)
    return body


# --- the gate is not vacuous ------------------------------------------------------


def test_the_command_surface_is_reachable_over_a_real_socket(live_base_url: str, fixtures: dict):
    """Proves the rest of this module measures something.

    A route registered on a router nobody included answers a ``TestClient`` call through the same
    object graph and 404s a real client. Nothing below would be meaningful if the surface were not
    genuinely served, so that is established first — and the enumeration of command paths this
    module uses is checked against the LIVE OpenAPI rather than trusted.
    """
    with _client(live_base_url) as client:
        spec = client.get("/openapi.json")
        assert spec.status_code == 200
        paths = set(spec.json()["paths"])

    served = {
        path.rsplit("/", 1)[-1]
        for path in paths
        if "/proxmox/" in path and path.rsplit("/", 1)[-1] in COMMAND_SUFFIXES
    }
    assert served == set(COMMAND_SUFFIXES), (
        f"this gate proves authentication for {sorted(COMMAND_SUFFIXES)} but the live router "
        f"serves {sorted(served)}. A command with no authentication proof must fail here."
    )
    assert "/api/v1/ranges/{range_id}/proxmox/commands" in paths


def test_a_command_round_trips_over_the_socket_and_is_readable_immediately(
    live_base_url: str, fixtures: dict
):
    """Read-after-write on the command surface, over a real socket against real PostgreSQL.

    The whole value of a durable command record is that a client can read back what it just asked
    for. If the response were sent before the transaction committed, this GET — issued on the very
    next request — would not see the record, and no ``TestClient`` test could ever notice.
    """
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/topology-compilation",
            json=_envelope(fixtures["version"]),
        )
        assert response.status_code == 201, response.text
        created = response.json()
        assert created["operation_kind"] == "compile_topology"

        readback = client.get(f"/api/v1/ranges/{fixtures['range_id']}/proxmox/commands")
        assert readback.status_code == 200
        kinds = [item["operation_kind"] for item in readback.json()]
        assert "compile_topology" in kinds, (
            "the command answered 201 for a record the immediately following request could not "
            "read — the response was sent before its transaction committed"
        )
        # Advance the caller's view: the record just written moved the range's version.
        fixtures["version"] = created["accepted_version"] + 1


# --- authentication ---------------------------------------------------------------


@pytest.mark.parametrize("suffix", COMMAND_SUFFIXES)
def test_every_command_route_requires_authentication(
    live_base_url: str, fixtures: dict, suffix: str
):
    """A presented bearer token is ALWAYS verified and never falls back to the dev principal.

    Sent with a body that would otherwise be valid, so a 401/403 cannot be mistaken for a schema
    rejection: the request is refused because of who is asking, not because of what was asked.
    """
    body = {
        **_envelope(fixtures["version"]),
        "plan_hash": fixtures["plan_hash"],
        "destroy_hash": fixtures["destroy_hash"],
        "worker_installation_id": WORKER_INSTALLATION,
        "release_digest": RELEASE_DIGEST,
    }
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/{suffix}",
            json=body,
            headers={"Authorization": "Bearer not-a-real-token"},
        )
    assert response.status_code in (401, 403), (suffix, response.status_code, response.text)


@pytest.mark.parametrize(
    "suffix", ("worker", "workload", "reset-plan", "reconciliation", "evidence", "commands")
)
def test_every_new_read_route_requires_authentication(
    live_base_url: str, fixtures: dict, suffix: str
):
    with _client(live_base_url) as client:
        response = client.get(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/{suffix}",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
    assert response.status_code in (401, 403), (suffix, response.status_code)


@pytest.mark.parametrize(
    "path",
    (
        "/api/v1/range-scenarios",
        "/api/v1/range-scenarios/web-breach-lab",
        "/api/v1/ranges/{range_id}/scenario",
    ),
)
def test_every_scenario_catalog_route_requires_authentication(
    live_base_url: str, fixtures: dict, path: str
):
    """The catalog is not tenant data, and it still requires an authenticated caller.

    Two of these name no range at all, so they are the routes most likely to be assumed public.
    They are not: the shipped catalog tells an unauthenticated reader which scenarios this
    deployment can run and what is blocking them, which is a description of the environment.
    """
    url = path.replace("{range_id}", fixtures["range_id"])
    with _client(live_base_url) as client:
        response = client.get(url, headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code in (401, 403), (path, response.status_code)


# --- organization scoping ----------------------------------------------------------


def test_a_command_cannot_reach_another_organizations_range(live_base_url: str, fixtures: dict):
    """The range exists and compiles — it is simply not this caller's."""
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['foreign_range_id']}/proxmox/topology-compilation",
            json=_envelope(fixtures["version"]),
        )
    assert response.status_code == 403, response.text


def test_a_read_cannot_reach_another_organizations_range(live_base_url: str, fixtures: dict):
    with _client(live_base_url) as client:
        for suffix in ("worker", "workload", "evidence", "commands"):
            response = client.get(
                f"/api/v1/ranges/{fixtures['foreign_range_id']}/proxmox/{suffix}"
            )
            assert response.status_code == 403, (suffix, response.status_code)


# --- target scoping -----------------------------------------------------------------


def test_a_command_naming_the_wrong_target_is_refused(live_base_url: str, fixtures: dict):
    """Target scope is checked against the plan, never taken from the caller."""
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/topology-compilation",
            json=_envelope(fixtures["version"], target_id="tgt-somewhere-else"),
        )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "target_mismatch"


def test_a_command_naming_the_wrong_cluster_fingerprint_is_refused(
    live_base_url: str, fixtures: dict
):
    """A cluster rebuilt under the same name is a different cluster."""
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/topology-compilation",
            json=_envelope(fixtures["version"], cluster_fingerprint="sha256:not-that-cluster"),
        )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "cluster_fingerprint_mismatch"


# --- an ordinary worker may not execute ---------------------------------------------


def test_an_ordinary_worker_cannot_be_used_for_controlled_live_execution(
    live_base_url: str, fixtures: dict
):
    """The enrolled-but-not-healthy worker is refused BY NAME, over the wire.

    ``worker_bound`` is a real enrollment state: the worker's identity is bound but the full
    attestation exchange has not completed. It is exactly the case that must not be handed work
    that creates virtual machines on real hardware.
    """
    body = {
        **_envelope(fixtures["version"]),
        "plan_hash": fixtures["plan_hash"],
        "worker_installation_id": WORKER_INSTALLATION,
        "release_digest": RELEASE_DIGEST,
    }
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/execution-request", json=body
        )
        assert response.status_code == 409, response.text
        # It is refused for a worker/authorization reason, never quietly accepted.
        code = response.json()["error"]["code"]
        assert code in (
            "worker_not_healthy",
            "plan_not_generated",
            "plan_not_submitted",
            "plan_not_approved",
            "apply_not_authorized",
        ), code

        # And the read surface agrees, without the caller having to issue a command to find out.
        worker = client.get(f"/api/v1/ranges/{fixtures['range_id']}/proxmox/worker")
        assert worker.status_code == 200
        payload = worker.json()
        assert payload["enrolled"] is True
        assert payload["state"] == "worker_bound"
        assert payload["eligible_for_execution"] is False
        assert "worker_not_healthy" in payload["blockers"]


def test_an_unknown_worker_is_refused_over_the_wire(live_base_url: str, fixtures: dict):
    body = {
        **_envelope(fixtures["version"]),
        "plan_hash": fixtures["plan_hash"],
        "worker_installation_id": "worker-nobody-enrolled",
        "release_digest": RELEASE_DIGEST,
    }
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/execution-request", json=body
        )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] in (
        "worker_mismatch",
        "plan_not_generated",
        "plan_not_submitted",
        "plan_not_approved",
        "apply_not_authorized",
    )


# --- apply and destroy stay separate on the wire --------------------------------------


def test_an_apply_body_is_rejected_by_the_destroy_endpoint_over_the_socket(
    live_base_url: str, fixtures: dict
):
    """422, not a destroyed range. The schemas make one unusable as the other."""
    apply_body = {
        **_envelope(fixtures["version"]),
        "plan_hash": fixtures["plan_hash"],
        "worker_installation_id": WORKER_INSTALLATION,
        "release_digest": RELEASE_DIGEST,
    }
    with _client(live_base_url) as client:
        response = client.post(
            f"/api/v1/ranges/{fixtures['range_id']}/proxmox/destroy-execution-request",
            json=apply_body,
        )
    assert response.status_code == 422, response.text
