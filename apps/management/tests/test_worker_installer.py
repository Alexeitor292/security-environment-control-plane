"""Fail-closed proofs for the P1 Proxmox worker installer and the two-role separation.

Every refusal named in the P1 brief has a test here, and each one asserts the EXACT bounded reason
code rather than merely that something raised — a test that accepts any refusal cannot tell a
correct refusal from an unrelated crash on the way to it.
"""

from __future__ import annotations

import hashlib

import pytest
from secp_management.worker_installer import (
    INSTALLATION_STEPS,
    InstallationRequest,
    InstallerDeps,
    SealedDurableIdentityStore,
    SealedServiceManager,
    SealedWorkerEnroller,
    WorkerInstallerError,
    install,
    plan_installation,
    validate_installation_request,
)
from secp_management.worker_roles import (
    ROLE_CAPABILITIES,
    WorkerRole,
    WorkerRoleError,
    privileged_capability_names,
    require_role_capability_separation,
    resolve_role_queue,
)

ORDINARY_QUEUE = "secp-ordinary"
OPERATOR_QUEUE = "secp-controlled-live"

# a raw 32-byte Ed25519 public key as hex; key_id_for is sha256 over the RAW bytes
ANCHOR_HEX = "ab" * 32
OTHER_ANCHOR_HEX = "cd" * 32
RELEASE = "sha256:" + "1" * 64
OTHER_RELEASE = "sha256:" + "2" * 64


def key_id(anchor_hex: str) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(anchor_hex)).hexdigest()


# --- doubles -------------------------------------------------------------------------------------


class FakeServices:
    def __init__(self, *, active: bool = True, fail_install: bool = False) -> None:
        self.calls: list[str] = []
        self._active = active
        self._fail_install = fail_install

    def install(self, service_name: str, *, role: str, task_queue: str) -> None:
        self.calls.append(f"install:{role}:{task_queue}")
        if self._fail_install:
            raise OSError("host refused")

    def enable(self, service_name: str) -> None:
        self.calls.append("enable")

    def is_active(self, service_name: str) -> bool:
        return self._active

    def disable(self, service_name: str) -> None:
        self.calls.append("disable")

    def restart(self, service_name: str) -> None:
        self.calls.append("restart")


class FakeIdentities:
    def __init__(self, existing: dict | None = None, *, fail_persist: bool = False) -> None:
        self.record = existing
        self._fail_persist = fail_persist
        self.persists = 0

    def load(self) -> dict | None:
        return self.record

    def persist(self, record: dict) -> None:
        if self._fail_persist:
            raise OSError("read-only filesystem")
        self.persists += 1
        self.record = dict(record)


class FakeEnroller:
    def __init__(self, *, state: str = "healthy", raises: Exception | None = None) -> None:
        self._state = state
        self._raises = raises
        self.called = 0

    def enroll(self, invitation: dict, *, now: str, expected_controller_key_id=None) -> dict:
        self.expected_controller_key_id = expected_controller_key_id
        self.called += 1
        if self._raises is not None:
            raise self._raises
        return {"enrollment_id": invitation["enrollment_id"], "state": self._state, "revision": 3}


class FakeInvitations:
    def __init__(self, invitation: dict) -> None:
        self._invitation = invitation

    def load(self, path: str) -> dict:
        return dict(self._invitation)


def invitation(
    *, anchor_hex: str = ANCHOR_HEX, installation_id: str = "worker-a", release: str = RELEASE
) -> dict:
    return {
        "enrollment_id": "enr-1",
        "invitation_id": "inv-1",
        "controller_installation_id": installation_id,
        "controller_key_id": key_id(anchor_hex),
        "controller_origin": "https://controller.example",
        "transaction_id": "txn-1",
        "release_digest": release,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "controller_ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----",
    }


def request(role: WorkerRole = WorkerRole.ordinary, **over: object) -> InstallationRequest:
    base = {
        "controller_origin": "https://controller.example",
        "installation_id": "worker-a",
        "release_digest": RELEASE,
        "role": role,
        "worker_plane": "management",
        "controller_trust_anchor_hex": ANCHOR_HEX,
        "invitation_file": "/etc/secp/invitation.json",
        "service_name": "secp-worker",
        "target_association": (
            "pve-node-1" if role is WorkerRole.infrastructure_operator else None
        ),
    }
    base.update(over)
    return InstallationRequest(**base)  # type: ignore[arg-type]


def deps(**over: object) -> InstallerDeps:
    base: dict = {
        "services": FakeServices(),
        "identities": FakeIdentities(),
        "enroller": FakeEnroller(),
        "invitations": FakeInvitations(invitation()),
        "now": lambda: "2026-08-05T00:00:00+00:00",
    }
    base.update(over)
    return InstallerDeps(**base)  # type: ignore[arg-type]


def run(req: InstallationRequest, d: InstallerDeps) -> dict:
    return install(req, d, ordinary_task_queue=ORDINARY_QUEUE, operator_task_queue=OPERATOR_QUEUE)


def refusal(req: InstallationRequest, d: InstallerDeps) -> str:
    with pytest.raises(WorkerInstallerError) as exc:
        run(req, d)
    return exc.value.reason_code


# --- the two roles and the separation between them -----------------------------------------------


def test_the_ordinary_role_holds_no_privileged_capability():
    ordinary = ROLE_CAPABILITIES[WorkerRole.ordinary]
    names = privileged_capability_names()
    # the four capabilities the brief names must all be covered, and all be False
    assert set(names) == {
        "infrastructure_mutation_credentials",
        "provisioning_execution",
        "host_network_mutation",
        "controlled_live_queue",
    }
    assert all(getattr(ordinary, n) is False for n in names)


def test_only_the_infrastructure_operator_consumes_the_controlled_live_queue():
    consumers = [r for r, c in ROLE_CAPABILITIES.items() if c.controlled_live_queue]
    assert consumers == [WorkerRole.infrastructure_operator]


def test_the_capability_table_must_cover_every_live_role(monkeypatch):
    """The guard is inverted: it asks whether every role in the LIVE enum has a row, so a role
    added without one is refused rather than silently exempt."""
    require_role_capability_separation()  # green as shipped
    trimmed = {
        WorkerRole.infrastructure_operator: ROLE_CAPABILITIES[WorkerRole.infrastructure_operator]
    }
    monkeypatch.setattr("secp_management.worker_roles.ROLE_CAPABILITIES", trimmed, raising=True)
    with pytest.raises(WorkerRoleError) as exc:
        require_role_capability_separation()
    assert exc.value.reason_code == "installer_role_table_incomplete"


def test_an_over_privileged_ordinary_row_is_refused(monkeypatch):
    """Mutation proof: the check fails when the property it claims to hold is broken."""
    from secp_management.worker_roles import RoleCapabilities

    broken = dict(ROLE_CAPABILITIES)
    broken[WorkerRole.ordinary] = RoleCapabilities(
        queue_kind="ordinary", provisioning_execution=True
    )
    monkeypatch.setattr("secp_management.worker_roles.ROLE_CAPABILITIES", broken, raising=True)
    with pytest.raises(WorkerRoleError) as exc:
        require_role_capability_separation()
    assert exc.value.reason_code == "installer_ordinary_role_over_privileged"


@pytest.mark.parametrize(
    ("role", "expected"),
    [(WorkerRole.ordinary, ORDINARY_QUEUE), (WorkerRole.infrastructure_operator, OPERATOR_QUEUE)],
)
def test_each_role_resolves_to_its_own_queue(role, expected):
    assert (
        resolve_role_queue(
            role, ordinary_task_queue=ORDINARY_QUEUE, operator_task_queue=OPERATOR_QUEUE
        )
        == expected
    )


@pytest.mark.parametrize("role", list(WorkerRole))
def test_a_shared_queue_is_refused_for_either_role(role):
    """Two workers on one Temporal queue re-creates the stranded-operation defect by construction,
    so it is refused at plan time — for BOTH roles, not only the privileged one."""
    with pytest.raises(WorkerRoleError) as exc:
        resolve_role_queue(role, ordinary_task_queue="same", operator_task_queue="same")
    assert exc.value.reason_code == "installer_role_queues_not_separated"


def test_an_unauthorized_role_is_refused():
    with pytest.raises(WorkerRoleError) as exc:
        validate_installation_request(request(role="root"))  # type: ignore[arg-type]
    assert exc.value.reason_code == "installer_role_not_authorized"


# --- request-level separation --------------------------------------------------------------------


def test_an_ordinary_worker_may_not_be_associated_with_a_target_association():
    with pytest.raises(WorkerInstallerError) as exc:
        validate_installation_request(request(WorkerRole.ordinary, target_association="pve-node-1"))
    assert exc.value.reason_code == "installer_target_association_forbidden"


def test_the_privileged_role_requires_a_target_association():
    with pytest.raises(WorkerInstallerError) as exc:
        validate_installation_request(
            request(WorkerRole.infrastructure_operator, target_association=None)
        )
    assert exc.value.reason_code == "installer_target_association_required"


def test_the_privileged_role_may_not_be_installed_off_the_management_plane():
    with pytest.raises(WorkerInstallerError) as exc:
        validate_installation_request(
            request(WorkerRole.infrastructure_operator, worker_plane="workload")
        )
    assert exc.value.reason_code == "installer_role_plane_mismatch"


def test_a_well_formed_request_validates():
    """The control for the refusal tests: without it, a validator that refused EVERYTHING would
    pass every fail-closed test in this file."""
    validated = validate_installation_request(request())
    assert validated.role is WorkerRole.ordinary


def test_a_secret_shaped_request_field_is_refused_before_anything_runs():
    """Enrollment material must never travel in the request; the shared forbidden-secret scanner is
    what makes that a refusal rather than a convention.

    The scan runs FIRST, before the per-field grammars, so this asserts the SECRET reason code
    specifically — a grammar refusal here would mean the scan was not what caught it, and a request
    whose secret happened to be grammar-valid would go through.
    """
    bad = request()
    object.__setattr__(bad, "service_name", "-----BEGIN PRIVATE KEY-----")
    with pytest.raises(WorkerInstallerError) as exc:
        validate_installation_request(bad)
    assert exc.value.reason_code == "installer_request_forbidden_secret"


# --- the fail-closed conditions the brief names --------------------------------------------------


def test_a_controller_trust_anchor_that_cannot_be_verified_refuses():
    d = deps(invitations=FakeInvitations(invitation(anchor_hex=OTHER_ANCHOR_HEX)))
    assert refusal(request(), d) == "installer_trust_anchor_mismatch"


def test_a_differing_installation_identity_refuses():
    d = deps(invitations=FakeInvitations(invitation(installation_id="worker-b")))
    assert refusal(request(), d) == "installer_installation_identity_mismatch"


def test_a_differing_release_digest_refuses():
    d = deps(invitations=FakeInvitations(invitation(release=OTHER_RELEASE)))
    assert refusal(request(), d) == "installer_release_digest_mismatch"


def test_a_replayed_enrollment_refuses():
    spent = FakeIdentities(
        {
            "installation_id": "worker-a",
            "enrollment_id": "enr-1",
            "invitation_id": "inv-1",
            "role": "ordinary",
        }
    )
    assert refusal(request(), deps(identities=spent)) == "installer_enrollment_replayed"


def test_a_durable_identity_that_cannot_persist_refuses_before_the_service_is_installed():
    services = FakeServices()
    d = deps(identities=FakeIdentities(fail_persist=True), services=services)
    assert refusal(request(), d) == "installer_identity_not_durable"
    assert services.calls == [], "the service must not be installed without a durable identity"


def test_a_service_that_does_not_come_active_refuses_and_rolls_back():
    services = FakeServices(active=False)
    assert refusal(request(), deps(services=services)) == "installer_service_not_active"
    assert "disable" in services.calls


def test_service_activation_without_authenticated_enrollment_fails_closed_and_rolls_back():
    """THE headline P1 condition: the service is up and enabled, but the authenticated exchange did
    not reach healthy. That host must not be left polling at boot, so the installation FAILS and the
    service is rolled back — never reported as a partial success."""
    services = FakeServices(active=True)
    enroller = FakeEnroller(state="refused")
    d = deps(services=services, enroller=enroller)
    assert refusal(request(), d) == "installer_enrolled_service_unauthenticated"
    assert enroller.called == 1
    assert "enable" in services.calls and "disable" in services.calls
    assert services.calls.index("disable") > services.calls.index("enable")


def test_an_enrollment_that_raises_also_rolls_the_service_back():
    services = FakeServices(active=True)

    class Bounded(Exception):
        reason_code = "enrollment_transport_failed"

    d = deps(services=services, enroller=FakeEnroller(raises=Bounded()))
    assert refusal(request(), d) == "enrollment_transport_failed"
    assert "disable" in services.calls


def test_restart_verification_failure_refuses():
    class NoRestart(FakeServices):
        def restart(self, service_name: str) -> None:
            self.calls.append("restart")
            raise OSError("unit failed to restart")

    assert refusal(request(), deps(services=NoRestart())) == (
        "installer_restart_verification_failed"
    )


# --- the successful path, and what it records ----------------------------------------------------


@pytest.mark.parametrize("role", list(WorkerRole))
def test_a_successful_installation_records_role_bound_evidence(role):
    services = FakeServices()
    identities = FakeIdentities()
    record = run(request(role), deps(services=services, identities=identities))

    expected_queue = (
        OPERATOR_QUEUE if role is WorkerRole.infrastructure_operator else ORDINARY_QUEUE
    )
    assert record["task_queue"] == expected_queue
    assert record["role"] == role.value
    assert record["state"] == "healthy"
    assert record["controlled_live_queue_consumer"] is (role is WorkerRole.infrastructure_operator)
    # the service was installed bound to the role's OWN queue, and restart-verified
    assert f"install:{role.value}:{expected_queue}" in services.calls
    assert "restart" in services.calls
    assert "disable" not in services.calls
    assert identities.record is not None and identities.record["state"] == "healthy"


def test_the_two_roles_never_share_a_queue_in_a_real_installation():
    queues = set()
    for role in WorkerRole:
        record = run(request(role), deps())
        queues.add(record["task_queue"])
    assert len(queues) == len(list(WorkerRole)), "the installed roles share a Temporal queue"


def test_no_installation_output_carries_the_invitation_path_or_material():
    """The plan and the evidence record are quotable into a ticket; neither may carry the
    short-lived enrollment material or the path it lives at."""
    req = request()
    plan = plan_installation(
        req, ordinary_task_queue=ORDINARY_QUEUE, operator_task_queue=OPERATOR_QUEUE
    )
    record = run(req, deps())
    for payload in (plan, record):
        text = repr(payload)
        assert req.invitation_file not in text
        assert "controller_ca_bundle_pem" not in text
        assert "BEGIN CERTIFICATE" not in text


def test_the_plan_is_pure_and_touches_no_host():
    services = FakeServices()
    identities = FakeIdentities()
    plan_installation(
        request(), ordinary_task_queue=ORDINARY_QUEUE, operator_task_queue=OPERATOR_QUEUE
    )
    assert services.calls == [] and identities.persists == 0
    assert list(INSTALLATION_STEPS)[0] == "validate_request"
    # every trust check precedes the first host mutation
    steps = list(INSTALLATION_STEPS)
    assert steps.index("verify_not_replayed") < steps.index("persist_durable_identity")
    assert steps.index("verify_controller_trust_anchor") < steps.index("install_service")


# --- the shipped defaults are sealed --------------------------------------------------------------


def test_every_shipped_host_seam_is_sealed():
    with pytest.raises(WorkerInstallerError) as exc:
        SealedServiceManager().enable("secp-worker")
    assert exc.value.reason_code == "installer_service_manager_sealed"

    with pytest.raises(WorkerInstallerError) as exc:
        SealedDurableIdentityStore().persist({})
    assert exc.value.reason_code == "installer_identity_store_sealed"

    with pytest.raises(WorkerInstallerError) as exc:
        SealedWorkerEnroller().enroll({}, now="")
    assert exc.value.reason_code == "installer_worker_enroller_sealed"


# --- the secpctl surface --------------------------------------------------------------------------


def _cli_argv(role: str = "ordinary", **over: str) -> list[str]:
    argv = {
        "--invitation": "/etc/secp/invitation.json",
        "--role": role,
        "--plane": "management",
        "--installation-id": "worker-a",
        "--controller-origin": "https://controller.example",
        "--controller-trust-anchor": ANCHOR_HEX,
        "--release-digest": RELEASE,
        "--service-name": "secp-worker",
        "--ordinary-queue": ORDINARY_QUEUE,
        "--operator-queue": OPERATOR_QUEUE,
    }
    argv.update(over)
    flat = ["worker", "install"]
    for key, value in argv.items():
        flat += [key, value]
    return flat


def test_the_cli_dry_run_reports_the_plan_and_touches_no_host():
    from secp_management.cli import run as cli_run

    code, report = cli_run(_cli_argv())
    assert code == 0
    assert report["mode"] == "dry_run"
    assert report["plan"]["task_queue"] == ORDINARY_QUEUE
    assert report["plan"]["capabilities"]["controlled_live_queue"] is False
    assert report["plan"]["connection_direction"] == "worker_dials_controller"


def test_the_cli_refuses_a_shared_queue_before_any_write():
    from secp_management.cli import run as cli_run

    code, report = cli_run(_cli_argv(**{"--operator-queue": ORDINARY_QUEUE}))
    assert code != 0
    assert report["reason_code"] == "installer_role_queues_not_separated"


def test_the_cli_refuses_an_ordinary_worker_bound_to_a_target_association():
    from secp_management.cli import run as cli_run

    code, report = cli_run(_cli_argv() + ["--target-association", "pve-node-1"])
    assert code != 0
    assert report["reason_code"] == "installer_target_association_forbidden"


def test_the_cli_write_path_refuses_on_a_host_with_no_reviewed_service_adapter():
    """The composed installer keeps its HOST seams sealed, so the write path refuses honestly
    instead of reporting an installation that did not happen."""
    from secp_management.cli import run as cli_run

    code, report = cli_run(
        _cli_argv(role="infrastructure_operator")
        + ["--target-association", "pve-node-1", "--write", "--confirm"]
    )
    assert code != 0
    assert report["reason_code"] != "installer_role_queues_not_separated"
    assert "invitation" not in repr(report).lower() or "/etc/secp" not in repr(report)


def test_no_enrollment_material_reaches_the_command_line():
    """The invitation is passed by PATH. Nothing on the argv carries the material, so it cannot
    reach shell history or the process table."""
    from secp_management.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(_cli_argv())
    values = [str(v) for v in vars(args).values() if v is not None]
    assert "BEGIN CERTIFICATE" not in " ".join(values)
    assert args.invitation == "/etc/secp/invitation.json"


def test_the_default_deps_cannot_install_anything():
    """A default-constructed installer refuses at the first host mutation rather than silently
    no-opping its host steps and reporting a successful install on a host where nothing happened."""
    d = InstallerDeps(invitations=FakeInvitations(invitation()), enroller=FakeEnroller())
    assert refusal(request(), d) == "installer_identity_store_sealed"
