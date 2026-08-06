"""The observation has a real producer, driven through the real exchange.

A gate with no producer is the defect this repository keeps finding in its own work: a module that
is correct, tested, green, and reached by nothing. So this file does not test ``_observe`` in
isolation. It drives the actual authenticated worker exchange through the ASGI app and then asks
the registry whether anything was recorded.

It reuses the exchange harness from ``test_enrollment_exchange`` rather than rebuilding one. That
harness already solves the hard part — an injected signer, a real proof-of-possession, a real
signed worker result — and a second copy of it would drift from the first.
"""

from __future__ import annotations

from datetime import UTC, datetime

from secp_api.worker_observation import (
    OBSERVATION_FRESH,
    OBSERVATION_UNOBSERVED,
    SOURCE_ENROLLMENT_EXCHANGE,
    registry,
)
from secp_commissioning import enrollment_attestation as ea
from secp_management.signing import generate_keypair
from test_enrollment_exchange import (
    _create_invitation,
    _drive_bind,
    _pop_body,
    _post_bind,
    _wire_signer,
)
from test_enrollment_exchange import client as client  # noqa: F401 - re-exported fixture


def _fresh_registry():
    """Start from a controller that has heard from nobody.

    The registry is a module-level singleton because it models a property of the process. Clearing
    it is exactly what a restart does, so tests share the real object rather than a stand-in.
    """
    registry().clear()
    return registry()


def _worker_id_of(client, inv) -> str:
    """Read the worker identity from the PUBLIC status projection.

    Recomputing it from the key with the harness's own formula would make this test agree with the
    harness rather than with the control plane — and it is the control plane's idea of the worker's
    identity that the observation must be keyed by.
    """
    response = client.get(f"/api/v1/enrollment/{inv['enrollment_id']}")
    assert response.status_code == 200, response.text
    return response.json()["worker_installation_id"]


def test_a_successful_bind_exchange_records_an_observation(client, session):
    reg = _fresh_registry()
    before = datetime.now(UTC)

    inv, _wpriv, _wpub, _offer = _drive_bind(client, session)
    worker_installation_id = _worker_id_of(client, inv)
    assert worker_installation_id, "the exchange bound no worker identity"

    observation = reg.get(worker_installation_id)
    assert observation is not None, "the bind exchange recorded no observation"
    assert observation.observation_source == SOURCE_ENROLLMENT_EXCHANGE
    assert observation.observed_at >= before

    projection = reg.project(worker_installation_id, now=datetime.now(UTC))
    assert projection.state == OBSERVATION_FRESH
    assert projection.is_observed is True

    # The exchange conveys no queue and no role, and the projection says so by name rather than
    # rendering a blank that reads as "serves no queue".
    assert "observed_task_queue" in projection.unreported_fields
    assert "worker_role" in projection.unreported_fields


def test_a_refused_exchange_records_nothing(client, session):
    """A refused request proves nothing about the worker.

    This is the security-relevant half. If a refusal recorded an observation, anyone who could reach
    the endpoint could keep a dead worker looking alive — without ever holding its key.
    """
    reg = _fresh_registry()
    _wire_signer(client, session)
    inv = _create_invitation(client)

    # A real, well-formed proof of possession — signed by a DIFFERENT key than the one presented.
    wpriv, wpub = generate_keypair()
    _other_priv, other_pub = generate_keypair()
    wid = "worker-" + ea.key_id_for(other_pub).split(":")[-1][:16]
    body = _pop_body(inv, wpriv, wpub, worker_installation_id=wid)
    body["worker_public_key_hex"] = other_pub

    response = _post_bind(client, inv, body)
    assert response.status_code >= 400, f"expected refusal, got {response.status_code}"
    assert reg.get(wid) is None
    assert reg.project(wid, now=datetime.now(UTC)).state == OBSERVATION_UNOBSERVED


def test_liveness_does_not_survive_a_restart_even_though_enrollment_does(client, session):
    """The two facts are independent, shown side by side.

    A real exchange is driven, so the durable enrollment row genuinely advanced. Then the registry
    is cleared — which is what a controller restart does to a process-local dict. The reading must
    fall back to ``unobserved``: not to the enrollment state, and not to ``stale``, which would
    imply the control plane still knows when it last heard from this worker.
    """
    reg = _fresh_registry()
    inv, _wpriv, _wpub, _offer = _drive_bind(client, session)
    worker_installation_id = _worker_id_of(client, inv)
    assert reg.project(worker_installation_id, now=datetime.now(UTC)).state == OBSERVATION_FRESH

    reg.clear()  # the restart

    after = reg.project(worker_installation_id, now=datetime.now(UTC))
    assert after.state == OBSERVATION_UNOBSERVED
    assert after.observed_at is None

    # The durable enrollment row is untouched and still readable — it did not restart.
    status = client.get(f"/api/v1/enrollment/{inv['enrollment_id']}")
    assert status.status_code == 200
    assert status.json()["worker_installation_id"] == worker_installation_id
