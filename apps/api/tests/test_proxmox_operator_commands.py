"""The Proxmox operator COMMAND surface.

Eight acts an operator can issue over HTTP, the preflight every one of them passes, and the closed
set of refusal codes a client branches on.

Four properties are what this file exists to hold:

* **a command persists intent and stops.** Nothing here applies, destroys, resets, runs OpenTofu,
  spawns a process or contacts a cluster. The three commands that need a worker create a durable
  operation and hand it to the outbox, and the API's involvement ends there.
* **apply and destroy are structurally separate.** No body validates as both, no record can be read
  as either, and no apply artifact — hash, approval, authorization or permission — reaches a
  destroy check.
* **a retry reuses the durable operation.** One accepted command is one infrastructure job, however
  many times the request is repeated.
* **every refusal code has a test that provokes it.** The last test in this module enumerates
  ``RefusalCode`` FROM THE LIVE MODULE and fails on any member nothing provoked — see
  :func:`test_every_refusal_code_has_a_test_that_provokes_it` for why it is built that way and how
  it refuses to report green on a partial run.

Nothing here contacts Proxmox. The observation is the recorded fixture the worker would write.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from secp_api.enums import Permission
from secp_api.errors import AuthorizationError
from secp_api.range_enums import RangeOperationStatus, RangeState
from secp_api.services import proxmox_commands, proxmox_lifecycle, ranges
from secp_api.services.proxmox_commands import (
    CommandEnvelope,
    CommandKind,
    ProxmoxCommandRefused,
    RefusalCode,
    WorkerAssertion,
)
from secp_api.worker_enrollment_models import WorkerEnrollmentState
from test_proxmox_http_surface import binding_payload, make_range, observation_payload

TARGET_ID = "tgt-lab-01"
FINGERPRINT = "sha256:aa11bb22"
WORKER_INSTALLATION = "worker-installation-0001"
RELEASE_DIGEST = "sha256:" + "cd" * 32


# --- the coverage recorder -----------------------------------------------------
#
# Populated by the two helpers below and read by the exhaustiveness test. It records codes that were
# actually OBSERVED — raised, or reported on a response — rather than codes a marker claims are
# covered. A marker is written by the same author as the code and can be wrong in exactly the way
# the exhaustiveness proof is supposed to catch.

_PROVOKED: set[RefusalCode] = set()


def refuses(code: RefusalCode, call, *args, **kwargs) -> ProxmoxCommandRefused:
    """Assert ``call`` refuses with exactly ``code``, and record that the code was provoked."""
    with pytest.raises(ProxmoxCommandRefused) as excinfo:
        call(*args, **kwargs)
    actual = excinfo.value.refusal_code
    assert actual is code, f"expected refusal {code.value}, got {actual.value}"
    # The wire form must carry the code, not just the exception object.
    assert excinfo.value.code == code.value
    _PROVOKED.add(code)
    return excinfo.value


def reports(code: RefusalCode, observed: RefusalCode | None) -> None:
    """Assert a RESPONSE reported ``code``, and record it.

    Some codes are never raised: ``reconciliation_consumer_unavailable`` is a field on an ACCEPTED
    command's record, because the command succeeded and nothing picked it up. It still has to be
    covered, so the recorder accepts both shapes.
    """
    assert observed is code, f"expected reported {code.value}, got {observed}"
    _PROVOKED.add(code)


# --- fixtures ------------------------------------------------------------------


@pytest.fixture
def client(engine, principal):
    from secp_api.db import get_sessionmaker
    from secp_api.deps import current_principal
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    _ = get_sessionmaker()
    app.dependency_overrides[current_principal] = lambda: principal
    return TestClient(app)


def fresh_binding(**overrides) -> dict:
    """The recorded binding, stamped NOW so the freshness bound is satisfied.

    The shared fixture pins ``observed_at`` to a fixed moment, which is right for hash determinism
    and wrong for the three commands that refuse a stale observation. Tests that want staleness ask
    for it explicitly.
    """
    payload = binding_payload(**overrides)
    payload["observed_at"] = datetime.now(UTC).isoformat()
    return payload


def proxmox_range(session, principal, **overrides):
    instance = make_range(session, principal, record_observation=False)
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_OBSERVATION,
        message="discovery observation recorded",
        data=fresh_binding(**overrides),
    )
    session.flush()
    return instance


def envelope(session, instance, **overrides) -> CommandEnvelope:
    """An envelope whose every claim is currently TRUE. Tests break one field at a time."""
    fields = {
        "idempotency_key": f"idem-{uuid.uuid4().hex}",
        "expected_version": instance.event_sequence,
        "operation_generation": 1,
        "target_id": TARGET_ID,
        "cluster_fingerprint": FINGERPRINT,
    }
    fields.update(overrides)
    return CommandEnvelope(**fields)


def worker_assertion(**overrides) -> WorkerAssertion:
    fields = {
        "worker_installation_id": WORKER_INSTALLATION,
        "release_digest": RELEASE_DIGEST,
    }
    fields.update(overrides)
    return WorkerAssertion(**fields)


def enroll_worker(session, principal, *, state: str = "healthy", release: str = RELEASE_DIGEST):
    """A durable worker enrollment row satisfying every portable CHECK constraint."""
    digest = "sha256:" + "11" * 32
    moment = datetime.now(UTC)
    row = WorkerEnrollmentState(
        enrollment_id="sha256:" + uuid.uuid4().hex + uuid.uuid4().hex[:32],
        organization_id=principal.organization_id,
        deployment_site_label="lab-site-01",
        contract_version="secp-enrollment/v1",
        state=state,
        revision=1,
        sequence=1,
        predecessor_digest="",
        controller_installation_id="controller-installation-01",
        controller_key_id=digest,
        worker_installation_id=WORKER_INSTALLATION,
        worker_key_id=digest,
        release_digest=release,
        transaction_id="txn-0001",
        offer_digest="",
        result_digest="",
        expires_at=(moment + timedelta(days=1)).isoformat(),
        updated_at=moment.isoformat(),
        refusal_reason="",
        state_digest=digest,
        expires_at_ts=moment + timedelta(days=1),
    )
    session.add(row)
    session.flush()
    return row


def drive_to_authorized_apply(session, principal, instance):
    """Walk the full apply chain: compile -> generate -> submit -> approve -> authorize."""
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    proxmox_commands.submit_plan_for_review(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)
    return compiled


def drive_to_authorized_destroy(session, principal, instance):
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.generate_destroy_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
    )
    proxmox_lifecycle.approve_destroy_plan(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    proxmox_lifecycle.authorize_destroy(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    return compiled


# --- the happy path ------------------------------------------------------------


def test_the_eight_commands_are_distinct_acts_with_distinct_permissions():
    """No generic command. Every kind has its own event, its own permission, its own path."""
    assert len(CommandKind) == 8
    assert set(proxmox_commands.COMMAND_EVENT_KINDS) == set(CommandKind)
    assert set(proxmox_commands.COMMAND_PERMISSIONS) == set(CommandKind)
    # One event kind per command; two acts sharing a kind would make a fold ambiguous.
    assert len(set(proxmox_commands.COMMAND_EVENT_KINDS.values())) == len(CommandKind)
    # The destroy family needs exercise:destroy, which exercise:apply never implies.
    for kind in proxmox_commands.DESTROY_FAMILY:
        assert proxmox_commands.COMMAND_PERMISSIONS[kind] is Permission.exercise_destroy
    assert proxmox_commands.COMMAND_PERMISSIONS[CommandKind.request_execution] is (
        Permission.exercise_apply
    )


def test_compile_generate_submit_records_the_chain(session, principal):
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)

    compilation = proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    assert compilation.operation_kind is CommandKind.compile_topology
    assert compilation.subject_hash == compiled.plan_hash
    assert compilation.enqueued is False

    generated = proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    assert generated.operation_kind is CommandKind.generate_plan
    assert generated.subject_hash == compiled.plan_hash

    submitted = proxmox_commands.submit_plan_for_review(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    assert submitted.operation_kind is CommandKind.submit_plan_for_review
    # Submission approves NOTHING.
    assert proxmox_lifecycle.plan_approval(session, instance) is None


def test_a_command_records_the_version_it_matched_not_the_one_it_created(session, principal):
    """``accepted_version`` is the CAS token that matched, read before the record bumps it."""
    instance = proxmox_range(session, principal)
    version = instance.event_sequence
    record = proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    assert record.accepted_version == version
    assert instance.event_sequence == version + 1


def test_requesting_execution_enqueues_exactly_one_operation(session, principal, monkeypatch):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    dispatched: list[uuid.UUID] = []
    _stub_dispatcher(monkeypatch, dispatched)

    record = proxmox_commands.request_execution(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )
    assert record.operation_kind is CommandKind.request_execution
    assert record.enqueued is True
    assert record.operation_id is not None
    assert dispatched == [record.operation_id]
    operation = ranges.get_operation(session, principal, record.operation_id)
    assert operation.status is RangeOperationStatus.pending
    assert instance.state is RangeState.deploying


def _stub_dispatcher(monkeypatch, sink: list):
    """Capture dispatches without a Temporal server. The API's own call is what is under test."""

    class _Recorder:
        mode = "temporal"

        def dispatch_range_operation(self, session, operation_id):
            sink.append(operation_id)
            return None

    monkeypatch.setattr(proxmox_commands, "get_dispatcher", lambda: _Recorder(), raising=False)
    import secp_api.dispatch as dispatch_module

    monkeypatch.setattr(dispatch_module, "get_dispatcher", lambda *a, **k: _Recorder())


# --- retries reuse the durable operation ---------------------------------------


def test_an_exact_retry_returns_the_same_operation_and_enqueues_nothing_new(
    session, principal, monkeypatch
):
    """The property that keeps a lost response from becoming two applies."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    dispatched: list[uuid.UUID] = []
    _stub_dispatcher(monkeypatch, dispatched)

    env = envelope(session, instance)
    first = proxmox_commands.request_execution(
        session,
        principal,
        instance.id,
        envelope=env,
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )
    # A retry carries the SAME key. The version has moved on, and that must not matter — a retry is
    # not a new decision and must not be refused for a CAS token the first attempt consumed.
    retry = proxmox_commands.request_execution(
        session,
        principal,
        instance.id,
        envelope=CommandEnvelope(
            idempotency_key=env.idempotency_key,
            expected_version=instance.event_sequence,
            operation_generation=env.operation_generation,
            target_id=env.target_id,
            cluster_fingerprint=env.cluster_fingerprint,
        ),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )
    assert retry.deduplicated is True
    assert retry.operation_id == first.operation_id
    assert len(dispatched) == 1, "a retry must not enqueue a second infrastructure job"
    operations = ranges.list_operations(session, principal, instance.id)
    assert len(operations) == 1


def test_a_retry_of_a_non_enqueueing_command_is_also_deduplicated(session, principal):
    instance = proxmox_range(session, principal)
    env = envelope(session, instance)
    first = proxmox_commands.compile_topology(session, principal, instance.id, envelope=env)
    again = proxmox_commands.compile_topology(
        session,
        principal,
        instance.id,
        envelope=CommandEnvelope(
            idempotency_key=env.idempotency_key,
            expected_version=instance.event_sequence,
            operation_generation=env.operation_generation,
            target_id=env.target_id,
            cluster_fingerprint=env.cluster_fingerprint,
        ),
    )
    assert again.deduplicated is True
    assert again.sequence == first.sequence
    assert first.deduplicated is False


# --- apply and destroy are structurally separate --------------------------------


def test_no_request_body_validates_as_both_an_apply_and_a_destroy(client, session, principal):
    """The schemas make one unusable as the other — a 422, not a destroyed range."""
    instance = proxmox_range(session, principal)
    session.commit()
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    base = {
        "idempotency_key": "idem-cross-family-0001",
        "expected_version": instance.event_sequence,
        "operation_generation": 1,
        "target_id": TARGET_ID,
        "cluster_fingerprint": FINGERPRINT,
        "worker_installation_id": WORKER_INSTALLATION,
        "release_digest": RELEASE_DIGEST,
    }
    apply_body = {**base, "plan_hash": compiled.plan_hash}
    destroy_body = {**base, "destroy_hash": compiled.destroy_hash}

    # An apply body posted to the destroy endpoint: unknown `plan_hash`, missing `destroy_hash`.
    response = client.post(
        f"/api/v1/ranges/{instance.id}/proxmox/destroy-execution-request", json=apply_body
    )
    assert response.status_code == 422
    # And the reverse.
    response = client.post(
        f"/api/v1/ranges/{instance.id}/proxmox/execution-request", json=destroy_body
    )
    assert response.status_code == 422


def test_a_plan_hash_is_not_a_valid_destroy_hash_for_the_same_range(session, principal):
    """Different hash DOMAINS: one digest cannot satisfy both families even by accident."""
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert compiled.plan_hash != compiled.destroy_hash
    refuses(
        RefusalCode.destroy_plan_identity_mismatch,
        proxmox_commands.generate_destroy_plan,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.plan_hash,
    )


def test_an_authorized_apply_never_authorizes_a_destroy(session, principal):
    """Every destroy check is reached only by destroy artifacts. The whole chain is separate."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    # Fully authorized to APPLY, and destroy is still refused at its first missing link.
    assert proxmox_lifecycle.apply_authorization(session, instance) is not None
    refuses(
        RefusalCode.destroy_plan_not_generated,
        proxmox_commands.request_destroy_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
        worker=worker_assertion(),
    )


def test_operation_kind_travels_on_the_record_and_into_the_openapi(client, session, principal):
    instance = proxmox_range(session, principal)
    session.commit()
    body = {
        "idempotency_key": "idem-kind-on-the-wire-01",
        "expected_version": instance.event_sequence,
        "operation_generation": 1,
        "target_id": TARGET_ID,
        "cluster_fingerprint": FINGERPRINT,
    }
    response = client.post(f"/api/v1/ranges/{instance.id}/proxmox/topology-compilation", json=body)
    assert response.status_code == 201
    assert response.json()["operation_kind"] == "compile_topology"

    spec = client.get("/openapi.json").json()
    schema = spec["components"]["schemas"]["ProxmoxCommandOut"]
    assert "operation_kind" in schema["required"], (
        "operation_kind must be REQUIRED, or a generated client may treat it as optional and "
        "fall back to inferring the act from the path"
    )
    kinds = spec["components"]["schemas"]["CommandKind"]["enum"]
    assert set(kinds) == {kind.value for kind in CommandKind}


# --- the API executes nothing ---------------------------------------------------


def test_no_command_module_imports_a_privileged_adapter():
    """Checked on the parsed IMPORTS, not on the source text.

    A substring scan over the file was the obvious version and it is wrong in both directions: it
    fires on the word "OpenTofu" in a docstring explaining that the module never runs OpenTofu, and
    it would miss ``__import__("subprocess")`` entirely. Only the import graph decides what a module
    can actually reach, so that is what is read.
    """
    import ast

    import secp_api.services.proxmox_commands as module

    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    forbidden_roots = {
        "subprocess",
        "os",
        "socket",
        "shutil",
        "paramiko",
        "proxmoxer",
        "requests",
        "httpx",
        "docker",
    }
    reached = {name.split(".")[0] for name in imported}
    assert not (reached & forbidden_roots), (
        f"the command service imports {sorted(reached & forbidden_roots)} — it may not reach a "
        "process, a socket, a host filesystem or a provider client"
    )
    # The only worker-adjacent import is the DISPATCH SEAM, and it is function-local so it exists
    # at the single enqueue point rather than at module scope.
    worker_imports = {name for name in imported if name.startswith("secp_worker")}
    assert not worker_imports, worker_imports
    assert "secp_api.dispatch" in imported
    seam = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "secp_api.dispatch"
    ]
    assert len(seam) == 1, "exactly one dispatch import, at the one place work is enqueued"
    module_level = {
        node.module for node in tree.body if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "secp_api.dispatch" not in module_level


def test_the_approval_endpoints_still_execute_nothing(session, principal):
    """Approving and authorizing remain pure records — the commands did not change that."""
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)
    assert ranges.list_operations(session, principal, instance.id) == []
    assert instance.state is RangeState.draft


# --- reconciliation: recorded, and honest about not being in flight -------------


def test_reconciliation_is_recorded_durably_and_says_nothing_took_it(session, principal):
    """Enqueueing it as a range operation would run a DEPLOY. See the service docstring."""
    instance = proxmox_range(session, principal)
    instance.state = RangeState.ready
    session.flush()
    record = proxmox_commands.request_reconciliation(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    assert record.operation_kind is CommandKind.request_reconciliation
    assert record.enqueued is False
    assert record.operation_id is None
    reports(RefusalCode.reconciliation_consumer_unavailable, record.not_enqueued_reason)
    # Durable: it is on the log and readable back.
    assert (
        proxmox_commands.latest_command(
            session, instance, CommandKind.request_reconciliation
        ).sequence
        == record.sequence
    )
    # And it created no operation that would look in-flight to an operator.
    assert ranges.list_operations(session, principal, instance.id) == []


def test_reconciliation_is_not_in_the_enqueueing_map():
    """A regression fence: adding it here without fixing the worker would run a deploy."""
    assert CommandKind.request_reconciliation not in proxmox_commands.COMMAND_OPERATION_KINDS
    assert set(proxmox_commands.COMMAND_OPERATION_KINDS) == {
        CommandKind.request_execution,
        CommandKind.request_reset,
        CommandKind.request_destroy_execution,
    }


# --- authentication, permission, and organization scope -------------------------


def test_every_command_route_requires_authentication(engine, principal):
    """No override: the real dependency must refuse an unauthenticated caller."""
    from secp_api.config import get_settings
    from secp_api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    app.router.on_startup.clear()
    unauthenticated = TestClient(app)
    spec = app.openapi()["paths"]
    command_paths = [
        path
        for path in spec
        if "/proxmox/" in path
        and any(
            suffix in path
            for suffix in (
                "topology-compilation",
                "plan-generation",
                "plan-review-submission",
                "execution-request",
                "reset-request",
                "reconciliation-request",
                "destroy-plan-generation",
                "destroy-execution-request",
            )
        )
    ]
    assert len(command_paths) == 8, command_paths
    for path in command_paths:
        url = path.replace("{range_id}", str(uuid.uuid4()))
        response = unauthenticated.post(url, json={}, headers={"Authorization": "Bearer nope"})
        assert response.status_code in (401, 403), (path, response.status_code)


def test_a_principal_without_the_exact_permission_is_refused(session, principal):
    """`exercise:operate` gets you the read. It is never enough for a command."""
    import dataclasses

    instance = proxmox_range(session, principal)
    reader = dataclasses.replace(principal, permissions=frozenset({Permission.exercise_operate}))
    with pytest.raises(AuthorizationError):
        proxmox_commands.compile_topology(
            session, reader, instance.id, envelope=envelope(session, instance)
        )


def test_holding_apply_never_permits_a_destroy_command(session, principal):
    import dataclasses

    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    applier = dataclasses.replace(
        principal,
        permissions=frozenset(
            {Permission.exercise_operate, Permission.exercise_apply, Permission.plan_generate}
        ),
    )
    with pytest.raises(AuthorizationError):
        proxmox_commands.generate_destroy_plan(
            session,
            applier,
            instance.id,
            envelope=envelope(session, instance),
            destroy_hash=compiled.destroy_hash,
        )


def test_a_command_is_scoped_to_the_callers_organization(session, principal, other_org_principal):
    instance = proxmox_range(session, principal)
    with pytest.raises(AuthorizationError):
        proxmox_commands.compile_topology(
            session, other_org_principal, instance.id, envelope=envelope(session, instance)
        )


# --- the refusals, one test per code -------------------------------------------


def test_refusal_range_not_proxmox(session, principal):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.flush()
    refuses(
        RefusalCode.range_not_proxmox,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
    )


def test_refusal_target_mismatch(session, principal):
    instance = proxmox_range(session, principal)
    refuses(
        RefusalCode.target_mismatch,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance, target_id="tgt-somewhere-else"),
    )


def test_refusal_cluster_fingerprint_mismatch(session, principal):
    """A cluster rebuilt under the same name is a DIFFERENT cluster."""
    instance = proxmox_range(session, principal)
    refuses(
        RefusalCode.cluster_fingerprint_mismatch,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance, cluster_fingerprint="sha256:deadbeef"),
    )


def test_refusal_ownership_scope_mismatch(session, principal, monkeypatch):
    """A compiled plan stamped for another range must never be acted on.

    Provoked by substituting a plan whose ownership names a different organization. That cannot
    happen through the ordinary compiler — which is the point: this is the check that notices if it
    ever does, and a check nobody has ever seen fire is a check nobody knows works.
    """
    import dataclasses

    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    foreign = dataclasses.replace(
        compiled.workload.topology.ownership, organization_id=str(uuid.uuid4())
    )
    topology = dataclasses.replace(compiled.workload.topology, ownership=foreign)
    workload = dataclasses.replace(compiled.workload, topology=topology)
    monkeypatch.setattr(
        proxmox_commands.proxmox_lifecycle,
        "compile_plan",
        lambda *a, **k: dataclasses.replace(compiled, workload=workload),
    )
    refuses(
        RefusalCode.ownership_scope_mismatch,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
    )


def test_refusal_plan_blocked(session, principal):
    """An unobserved fact is not guessed — the plan does not compile and no command may act."""
    payload = observation_payload()
    payload["sdn_supported"] = None
    instance = proxmox_range(session, principal, observation=payload)
    refuses(
        RefusalCode.plan_blocked,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
    )


def test_refusal_observation_absent(session, principal):
    """An UNCHECKED prerequisite, and it is not the same refusal as a blocked plan."""
    instance = make_range(session, principal, record_observation=False)
    refuses(
        RefusalCode.observation_absent,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
    )


def test_refusal_observation_stale(session, principal):
    """Stale blocks EXECUTION and not planning: the plan is still worth reading."""
    instance = make_range(session, principal)  # the shared fixture's fixed, old observed_at
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    refuses(
        RefusalCode.observation_stale,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )
    # ...and the same stale observation did NOT stop the planning commands above.
    assert proxmox_commands.latest_command(session, instance, CommandKind.generate_plan) is not None


def test_refusal_plan_not_generated(session, principal):
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    refuses(
        RefusalCode.plan_not_generated,
        proxmox_commands.submit_plan_for_review,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )


def test_refusal_plan_not_submitted(session, principal):
    """Generating a plan does not imply putting it in front of a reviewer."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    refuses(
        RefusalCode.plan_not_submitted,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_refusal_plan_not_approved(session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    proxmox_commands.submit_plan_for_review(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    refuses(
        RefusalCode.plan_not_approved,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_refusal_apply_not_authorized(session, principal):
    """Approving a plan and authorizing its apply are two decisions."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    proxmox_commands.submit_plan_for_review(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    refuses(
        RefusalCode.apply_not_authorized,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_refusal_destroy_plan_not_generated(session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    refuses(
        RefusalCode.destroy_plan_not_generated,
        proxmox_commands.request_destroy_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
        worker=worker_assertion(),
    )


def test_refusal_destroy_plan_not_approved(session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.generate_destroy_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
    )
    refuses(
        RefusalCode.destroy_plan_not_approved,
        proxmox_commands.request_destroy_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
        worker=worker_assertion(),
    )


def test_refusal_destroy_not_authorized(session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.generate_destroy_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
    )
    proxmox_lifecycle.approve_destroy_plan(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    refuses(
        RefusalCode.destroy_not_authorized,
        proxmox_commands.request_destroy_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
        worker=worker_assertion(),
    )


def test_refusal_plan_identity_mismatch(session, principal):
    instance = proxmox_range(session, principal)
    refuses(
        RefusalCode.plan_identity_mismatch,
        proxmox_commands.generate_plan,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash="sha256:" + "00" * 32,
    )


def test_refusal_destroy_plan_identity_mismatch(session, principal):
    instance = proxmox_range(session, principal)
    refuses(
        RefusalCode.destroy_plan_identity_mismatch,
        proxmox_commands.generate_destroy_plan,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash="sha256:" + "00" * 32,
    )


def test_refusal_desired_state_changed(session, principal):
    """Generate, then let the desired state move, then act on the NEW hash.

    Naming the OLD hash would be caught earlier as a plan identity mismatch. This is the subtler
    case: a caller who re-read the plan and is acting on a document that was never generated.
    """
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    # A new observation lands: another team is now in the request, so the plan moves.
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_OBSERVATION,
        message="discovery observation re-recorded",
        data=fresh_binding(
            teams=[
                {"team_ref": "red", "label": "Red"},
                {"team_ref": "blue", "label": "Blue"},
                {"team_ref": "green", "label": "Green"},
            ]
        ),
    )
    session.flush()
    moved = proxmox_lifecycle.compile_plan(session, instance)
    assert moved.plan_hash != compiled.plan_hash
    refuses(
        RefusalCode.desired_state_changed,
        proxmox_commands.submit_plan_for_review,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=moved.plan_hash,
    )


def test_refusal_allocation_changed(session, principal):
    """The same document reserving DIFFERENT identifiers — the shape nobody notices.

    Provoked by rewriting the recorded ledger hash on the generation event, which is exactly the
    observable a real drift would produce: the plan hash still matches and the reservations do not.
    """
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    generated = proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    event = _event_at(session, instance, generated.sequence)
    event.data = {**event.data, "ledger_hash": "sha256:" + "ff" * 32}
    session.flush()
    refuses(
        RefusalCode.allocation_changed,
        proxmox_commands.submit_plan_for_review,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )


def _event_at(session, instance, sequence):
    from secp_api.range_models import RangeLifecycleEvent
    from sqlalchemy import select

    return session.execute(
        select(RangeLifecycleEvent).where(
            RangeLifecycleEvent.range_instance_id == instance.id,
            RangeLifecycleEvent.sequence == sequence,
        )
    ).scalar_one()


def test_refusal_version_conflict(session, principal):
    """Compare-and-swap: anything recorded since the caller read invalidates their decision."""
    instance = proxmox_range(session, principal)
    refuses(
        RefusalCode.version_conflict,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance, expected_version=instance.event_sequence - 1),
    )


def test_refusal_operation_generation_mismatch(session, principal):
    instance = proxmox_range(session, principal)
    refuses(
        RefusalCode.operation_generation_mismatch,
        proxmox_commands.compile_topology,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance, operation_generation=99),
    )


def test_refusal_idempotency_key_reused(session, principal):
    """A DIFFERENT request under a used key is refused, never served from the first record."""
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    key = "idem-reused-key-0001"
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance, idempotency_key=key)
    )
    refuses(
        RefusalCode.idempotency_key_reused,
        proxmox_commands.generate_plan,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance, idempotency_key=key),
        plan_hash=compiled.plan_hash,
    )


def test_refusal_operation_in_flight(session, principal, monkeypatch):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    _stub_dispatcher(monkeypatch, [])
    proxmox_commands.request_execution(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )
    instance.state = RangeState.failed  # a lifecycle state a second request could start from
    session.flush()
    refuses(
        RefusalCode.operation_in_flight,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_refusal_lifecycle_state_invalid(session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    instance.state = RangeState.ready
    session.flush()
    refuses(
        RefusalCode.lifecycle_state_invalid,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_refusal_worker_mismatch(session, principal):
    """Execution is handed to a NAMED, enrolled worker."""
    instance = proxmox_range(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    refuses(
        RefusalCode.worker_mismatch,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(worker_installation_id="worker-nobody-knows"),
    )


def test_refusal_worker_not_healthy(session, principal):
    """An ORDINARY or partially-enrolled worker may not be given controlled-live execution."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal, state="worker_bound")
    compiled = drive_to_authorized_apply(session, principal, instance)
    refuses(
        RefusalCode.worker_not_healthy,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_refusal_release_mismatch(session, principal):
    """The release decides which gates the executing process runs."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal, release="sha256:" + "ab" * 32)
    compiled = drive_to_authorized_apply(session, principal, instance)
    refuses(
        RefusalCode.release_mismatch,
        proxmox_commands.request_execution,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


# --- reset and destroy execution over the full chain ---------------------------


def drive_to_authorized_reset(session, principal, instance):
    """Approve and authorize the RESET scope — the guests that will be destroyed."""
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_reset_plan(
        session, principal, instance.id, reset_hash=compiled.reset_hash
    )
    proxmox_lifecycle.authorize_reset(
        session, principal, instance.id, reset_hash=compiled.reset_hash
    )
    return compiled


def test_a_reset_requires_its_own_authorization_not_the_applys(session, principal, monkeypatch):
    """A reset DESTROYS every guest, so it carries its own approval over its own hash domain."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_reset(session, principal, instance)
    instance.state = RangeState.ready
    session.flush()
    dispatched: list[uuid.UUID] = []
    _stub_dispatcher(monkeypatch, dispatched)
    record = proxmox_commands.request_reset(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        reset_hash=compiled.reset_hash,
        worker=worker_assertion(),
    )
    assert record.operation_kind is CommandKind.request_reset
    assert record.subject_hash == compiled.reset_hash
    assert record.subject_hash != compiled.plan_hash
    assert record.enqueued is True
    assert len(dispatched) == 1


def test_refusal_reset_plan_not_approved(session, principal):
    """An authorized APPLY does not approve the reset scope."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_apply(session, principal, instance)
    instance.state = RangeState.ready
    session.flush()
    refuses(
        RefusalCode.reset_plan_not_approved,
        proxmox_commands.request_reset,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        reset_hash=compiled.reset_hash,
        worker=worker_assertion(),
    )


def test_refusal_reset_not_authorized(session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_reset_plan(
        session, principal, instance.id, reset_hash=compiled.reset_hash
    )
    instance.state = RangeState.ready
    session.flush()
    refuses(
        RefusalCode.reset_not_authorized,
        proxmox_commands.request_reset,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        reset_hash=compiled.reset_hash,
        worker=worker_assertion(),
    )


def test_refusal_reset_plan_identity_mismatch(session, principal):
    """A plan hash is not a valid reset hash — a third domain, not a variant of the first."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    instance.state = RangeState.ready
    session.flush()
    refuses(
        RefusalCode.reset_plan_identity_mismatch,
        proxmox_commands.request_reset,
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        reset_hash=compiled.plan_hash,
        worker=worker_assertion(),
    )


def test_destroy_execution_runs_the_whole_destroy_chain(session, principal, monkeypatch):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    compiled = drive_to_authorized_destroy(session, principal, instance)
    dispatched: list[uuid.UUID] = []
    _stub_dispatcher(monkeypatch, dispatched)
    record = proxmox_commands.request_destroy_execution(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        destroy_hash=compiled.destroy_hash,
        worker=worker_assertion(),
    )
    assert record.operation_kind is CommandKind.request_destroy_execution
    assert record.subject_hash == compiled.destroy_hash
    assert record.enqueued is True
    assert len(dispatched) == 1
    assert instance.state is RangeState.destroying


# --- the audit read -------------------------------------------------------------


def test_the_commands_read_returns_the_latest_of_each_kind(client, session, principal):
    instance = proxmox_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    proxmox_commands.generate_plan(
        session,
        principal,
        instance.id,
        envelope=envelope(session, instance),
        plan_hash=compiled.plan_hash,
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/commands").json()
    kinds = [item["operation_kind"] for item in body]
    assert kinds == ["compile_topology", "generate_plan"]
    assert all(item["subject_hash"] == compiled.plan_hash for item in body)


# --- the exhaustiveness proof ---------------------------------------------------


def test_every_refusal_code_has_a_test_that_provokes_it(request):
    """Enumerated FROM THE LIVE ENUM, and satisfied only by codes actually observed.

    Two decisions make this proof mean something.

    **The code list comes from the module, not from this file.** A list maintained here would be
    written by whoever wrote the codes, and cannot notice a code they forgot — it would simply not
    mention it and pass.

    **Coverage is recorded from observation, not from a marker.** ``refuses()`` records a code only
    after asserting that exact code was raised, and ``reports()`` only after asserting it appeared
    on a response. A ``@covers(...)`` marker would let a test claim a code it never triggers.

    **It refuses an unmeasurable run.** ``_PROVOKED`` is filled by the other tests in this module,
    so running this test alone would find it nearly empty and — without the guard below — would
    report a swathe of false failures, or, if written the other way round, a false pass. The guard
    checks that every test defined here is in the collected session and fails loudly if not, so a
    partial run says "this proof was not made" rather than producing a verdict.
    """
    defined = {
        name for name, value in globals().items() if name.startswith("test_") and callable(value)
    }
    collected = {item.name.partition("[")[0] for item in request.session.items}
    not_run = defined - collected
    assert not not_run, (
        f"{len(not_run)} test(s) in this module were not collected in this run, so the coverage "
        f"recorder is incomplete and this proof cannot be made: {sorted(not_run)}. Run the whole "
        "module."
    )

    declared = set(RefusalCode)
    missing = declared - _PROVOKED
    assert not missing, (
        f"{len(missing)} refusal code(s) exist with no test that provokes them: "
        f"{sorted(code.value for code in missing)}. A code a client can receive and no test has "
        "ever produced is a code nobody has checked the meaning of."
    )
    # And the reverse: nothing was recorded that is not a real member (a stale code left behind
    # after a rename would otherwise sit in the recorder unnoticed).
    assert _PROVOKED <= declared


def test_every_refusal_code_has_an_explicit_http_status():
    """No default. A code added later must be given a status deliberately, not inherit one."""
    from secp_api.services.proxmox_commands import _REFUSAL_STATUS

    assert set(_REFUSAL_STATUS) == set(RefusalCode)
    assert all(status in (409, 501) for status in _REFUSAL_STATUS.values())
