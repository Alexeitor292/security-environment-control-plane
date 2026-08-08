"""Host-local worker-enrollment health probes (SECP WS-B, W3).

Hermetic. The probes DERIVE from the management-plane bootstrap's durable worker records rather
than standing up a second host observer, so these tests seed those exact documents on the in-memory
hardened filesystem and prove:

* the two document paths and the four reviewed seal positions byte-match the management plane
  (the boundary is preserved by pinned literals + this guard, not by an import);
* all eleven checks are TRUE only on a correctly prepared host, and each specific defect fails the
  specific check it belongs to — no probe fabricates a ``True``;
* a context describing another exchange satisfies nothing, however healthy the host is;
* the three new leaves (key seam, durable state store, probes) compose into a driver that actually
  reaches ``healthy`` against a faithful in-process controller.
"""

from __future__ import annotations

import json

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import BOOTSTRAP_CONTRACT_VERSION
from secp_management.evidence import BootstrapEvidence, ManagementPlaneIdentity
from secp_management.layout import ManagementLocations
from secp_management.planes import Plane, Role
from secp_management.signing import generate_keypair
from secp_management.topology import (
    OPERATOR_SERVICE_NAME,
    OPERATOR_TASK_QUEUE,
    ORDINARY_CONTAINER_NAME,
    ORDINARY_TASK_QUEUE,
    SealState,
)
from secp_worker.enrollment_driver import (
    HealthObservationContext,
    LocalWorkerHealthObserver,
    WorkerEnrollmentDriver,
    WorkerEnrollmentDriverError,
    WorkerHealthProbes,
)
from secp_worker.enrollment_health_probes import (
    _EVIDENCE_BOOLS,
    _REVIEWED_SEALS,
    MANAGEMENT_WORKER_EVIDENCE_PATH,
    MANAGEMENT_WORKER_IDENTITY_PATH,
    LocalWorkerHealthProbes,
    read_installed_worker_record,
)
from secp_worker.enrollment_http_transport import (
    EnrollmentInvitationInputs,
    WorkerEnrollmentSigner,
)
from secp_worker.enrollment_key import LocalWorkerEnrollmentKeySeam
from secp_worker.enrollment_state_store import DurableWorkerEnrollmentStateStore

RELEASE = "sha256:" + "a" * 64
ENROLLMENT = "sha256:" + "1" * 64
TRANSACTION = "txn-0001"
OFFER_DIGEST = "sha256:" + "c" * 64
NOW = "2026-07-30T00:00:00+00:00"
FUTURE = "2999-01-01T00:00:00+00:00"
BOOTSTRAP_DIR = "/var/lib/secp/bootstrap"
# a grammar-valid controller CA chain; these tests never open a socket, so no real key is needed
CA_PEM = (
    "-----BEGIN CERTIFICATE-----\nMIIBfakeCAforTESTS0000000000000==\n-----END CERTIFICATE-----\n"
)

# The two seeded documents are built from the management plane's OWN strict models and serialized
# through their own ``canonical()`` — never hand-rolled here. ``read_installed_worker_record``
# projects fifteen field NAMES owned by those models; a hand-written dict would keep passing after a
# rename while the production projection silently returned ``None``, turning every derived check
# False and making a healthy worker unable to enroll. Building the real documents means a rename
# breaks construction here (loudly) instead, and
# ``test_every_projected_field_name_exists_in_the_management_documents`` pins the projection itself.
_IDENTITY = ManagementPlaneIdentity(
    bootstrap_contract_version=BOOTSTRAP_CONTRACT_VERSION,
    plane=Plane.MANAGEMENT.value,
    role=Role.WORKER.value,
    installation_id="worker-aaaaaaaa",
    release_digest=RELEASE,
    source_sha="s" * 40,
    source_tree_sha="t" * 40,
    installed_artifact_digests=(),
    created_at=NOW,
).canonical()
_EVIDENCE = BootstrapEvidence(
    bootstrap_contract_version=BOOTSTRAP_CONTRACT_VERSION,
    mode="installed",
    role=Role.WORKER.value,
    plane=Plane.MANAGEMENT.value,
    installation_id="worker-aaaaaaaa",
    release_aggregate_digest=RELEASE,
    signing_anchor_id="sha256:" + "9" * 64,
    source_sha="s" * 40,
    source_tree_sha="t" * 40,
    image_digests=(),
    wheel_digests=(),
    implementation_aggregate="sha256:" + "b" * 64,
    path_bindings=(),
    container_identities=(ORDINARY_CONTAINER_NAME,),
    service_identities=(OPERATOR_SERVICE_NAME,),
    config_identity="sha256:" + "d" * 64,
    unit_identity="sha256:" + "e" * 64,
    deployment_package_aggregate="sha256:" + "f" * 64,
    runtime_uid=1000,
    runtime_gid=1000,
    ordinary_task_queue=ORDINARY_TASK_QUEUE,
    operator_task_queue=OPERATOR_TASK_QUEUE,
    health_command_identity="sha256:" + "7" * 64,
    object_records=(),
    transaction_timestamp=NOW,
    **_REVIEWED_SEALS,
    external_contacts_performed=False,
    workflows_submitted=False,
    run_plan_generation_called=False,
    opentofu_executed=False,
    proxmox_contacted=False,
).canonical()


def _invitation(**over) -> EnrollmentInvitationInputs:
    fields = dict(
        enrollment_id=ENROLLMENT,
        invitation_id="sha256:" + "2" * 64,
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id="sha256:" + "9" * 64,
        controller_origin="https://ctrl.example.test",
        controller_transaction_id=TRANSACTION,
        release_digest=RELEASE,
        expires_at=FUTURE,
        controller_ca_bundle_pem=CA_PEM,
    )
    fields.update(over)
    return EnrollmentInvitationInputs(**fields)


def _seed_host(
    fs: InMemoryFilesystem, *, identity: dict | None = None, evidence: dict | None = None
) -> None:
    """Seed the two root-owned 0640 management documents a bootstrapped worker host carries."""
    fs.seed_dir(BOOTSTRAP_DIR, mode=0o755)
    for path, doc in (
        (MANAGEMENT_WORKER_IDENTITY_PATH, {**_IDENTITY, **(identity or {})}),
        (MANAGEMENT_WORKER_EVIDENCE_PATH, {**_EVIDENCE, **(evidence or {})}),
    ):
        fs.seed_file(path, json.dumps(doc, sort_keys=True).encode("utf-8"), mode=0o640)


def _ctx(**over) -> HealthObservationContext:
    fields = dict(
        enrollment_id=ENROLLMENT,
        release_digest=RELEASE,
        controller_transaction_id=TRANSACTION,
        worker_key_id="",
        offer_claim_digest=OFFER_DIGEST,
    )
    fields.update(over)
    return HealthObservationContext(**fields)


def _prepared_host(**seed) -> tuple[InMemoryFilesystem, LocalWorkerHealthProbes, str]:
    """A host in the correct end state: management records seeded, the enrollment key provisioned,
    and the offer-stage marker recorded (exactly what the driver has done by observation time)."""
    fs = InMemoryFilesystem()
    _seed_host(fs, **seed)
    signer = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create()
    store = DurableWorkerEnrollmentStateStore(fs)
    store.record(ENROLLMENT, "offer_verified")
    probes = LocalWorkerHealthProbes(invitation=_invitation(), fs=fs, state_store=store)
    return fs, probes, signer.worker_key_id


def _observe(probes: LocalWorkerHealthProbes, ctx: HealthObservationContext) -> dict[str, bool]:
    return LocalWorkerHealthObserver(probes).observe(ctx).as_evidence()


# --- boundary + parity guards --------------------------------------------------------------------


def test_the_fixed_document_paths_byte_match_the_management_layout():
    """The worker plane must not import secp_management, so the two paths are pinned literals.
    This guard (the test layer may import both planes) proves they cannot drift apart."""
    locations = ManagementLocations()
    assert MANAGEMENT_WORKER_IDENTITY_PATH == locations.identity_path("worker")
    assert MANAGEMENT_WORKER_EVIDENCE_PATH == locations.evidence_path("worker")


def test_the_new_worker_seams_never_import_the_management_plane():
    """The derivation must stay a read of pinned paths — never an import across the boundary."""
    import ast
    from pathlib import Path

    from secp_worker import enrollment_health_probes, enrollment_key, enrollment_state_store

    for module in (enrollment_health_probes, enrollment_key, enrollment_state_store):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not [m for m in imported if m.split(".")[0] == "secp_management"], module.__name__


def test_the_reviewed_seal_positions_match_the_management_seal_predicate():
    """The probes accept exactly the seal configuration the management plane calls safe."""
    assert SealState(**_REVIEWED_SEALS).safe is True
    for name in _REVIEWED_SEALS:
        flipped = {**_REVIEWED_SEALS, name: not _REVIEWED_SEALS[name]}
        assert SealState(**flipped).safe is False


#: Every field name ``read_installed_worker_record`` projects out of each management document. These
#: are the THIRD drift axis (after the two document paths and the four seal positions): the
#: projection reads them by string key, so a rename in ``BootstrapEvidence`` /
#: ``ManagementPlaneIdentity`` would make the read return ``None`` — every derived check False, the
#: worker permanently unable to reach healthy — with no other test failing.
_PROJECTED_IDENTITY_FIELDS = frozenset({"role", "plane", "release_digest", "installation_id"})
_PROJECTED_EVIDENCE_FIELDS = frozenset(
    {
        "role",
        "plane",
        "mode",
        "release_aggregate_digest",
        "unit_identity",
        "config_identity",
        "deployment_package_aggregate",
        "ordinary_task_queue",
        "operator_task_queue",
        *_EVIDENCE_BOOLS,
    }
)


def test_every_projected_field_name_exists_in_the_management_documents():
    """The projection's field names must all be REAL fields of the management-plane models.

    Guards the rename axis the two existing parity guards do not cover: renaming e.g.
    ``BootstrapEvidence.deployment_package_aggregate`` makes ``read_installed_worker_record`` return
    ``None`` in production — a silent, total false-red — while every behavioural test below keeps
    passing, because they seed their documents from the same hand-written source they assert on."""
    assert _PROJECTED_IDENTITY_FIELDS <= set(ManagementPlaneIdentity.model_fields)
    assert _PROJECTED_EVIDENCE_FIELDS <= set(BootstrapEvidence.model_fields)
    # and they survive canonicalization (the exact bytes the bootstrap writes to disk)
    assert _PROJECTED_IDENTITY_FIELDS <= set(_IDENTITY)
    assert _PROJECTED_EVIDENCE_FIELDS <= set(_EVIDENCE)


def test_the_seeded_documents_actually_satisfy_the_production_projection():
    """The real documents a bootstrapped worker carries must project successfully — so the fixtures
    above prove the production reader works, not merely that some dict shape does."""
    fs = InMemoryFilesystem()
    _seed_host(fs)

    record = read_installed_worker_record(fs)

    assert record is not None
    assert record.release_digest == RELEASE
    assert record.mode == "installed"
    assert record.ordinary_task_queue == ORDINARY_TASK_QUEUE
    assert record.operator_task_queue == OPERATOR_TASK_QUEUE
    assert record.ordinary_task_queue != record.operator_task_queue
    assert all(record.flag(name) is _REVIEWED_SEALS[name] for name in _REVIEWED_SEALS)


def test_the_probes_satisfy_the_declared_protocol():
    probes: WorkerHealthProbes = _prepared_host()[1]
    for check in ea.REQUIRED_HEALTH_CHECKS:
        assert callable(getattr(probes, check))


# --- the happy path ------------------------------------------------------------------------------


def test_all_eleven_checks_are_true_on_a_correctly_prepared_host():
    _fs, probes, key_id = _prepared_host()

    evidence = _observe(probes, _ctx(worker_key_id=key_id))

    assert evidence == dict.fromkeys(ea.REQUIRED_HEALTH_CHECKS, True)


def test_an_adopted_worker_install_is_equally_acceptable():
    _fs, probes, key_id = _prepared_host(evidence={"mode": "adopted"})

    assert _observe(probes, _ctx(worker_key_id=key_id)) == dict.fromkeys(
        ea.REQUIRED_HEALTH_CHECKS, True
    )


# --- the derived record --------------------------------------------------------------------------


def test_an_unbootstrapped_host_fails_every_derived_check():
    fs = InMemoryFilesystem()
    signer = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create()
    store = DurableWorkerEnrollmentStateStore(fs)
    store.record(ENROLLMENT, "offer_verified")
    probes = LocalWorkerHealthProbes(invitation=_invitation(), fs=fs, state_store=store)

    evidence = _observe(probes, _ctx(worker_key_id=signer.worker_key_id))

    assert read_installed_worker_record(fs) is None
    assert evidence["exact_release"] is False
    assert evidence["operator_worker_disabled"] is False
    assert evidence["no_provider_contact"] is False
    assert evidence["no_opentofu_execution"] is False
    assert evidence["no_controlled_live_submission"] is False
    # the checks that do NOT depend on the host records still observe honestly
    assert evidence["worker_enrollment_key_protected"] is True
    assert evidence["local_enrollment_state_present"] is True


@pytest.mark.parametrize(
    ("identity", "evidence"),
    [
        ({"role": "controller"}, None),  # a controller document is never read as a worker one
        (None, {"role": "controller"}),
        ({"plane": "scenario"}, None),
        (None, {"plane": "scenario"}),
        ({"release_digest": "sha256:" + "b" * 64}, None),  # the two documents must agree
        (None, {"release_aggregate_digest": "sha256:" + "b" * 64}),
        ({"release_digest": "not-a-digest"}, None),
        (None, {"mode": "planned"}),
        (None, {"opentofu_executed": "false"}),  # a non-boolean proof is never read as a proof
        (None, {"proxmox_contacted": None}),
    ],
)
def test_an_incoherent_record_pair_is_refused_outright(identity, evidence):
    fs = InMemoryFilesystem()
    _seed_host(fs, identity=identity, evidence=evidence)

    assert read_installed_worker_record(fs) is None


@pytest.mark.parametrize(
    "seed",
    [
        lambda fs, path: fs.seed_file(path, b"{}", mode=0o644),  # loosened mode
        lambda fs, path: fs.seed_file(path, b"{}", uid=1000, mode=0o640),  # foreign owner
        lambda fs, path: fs.seed_file(path, b"{}", mode=0o640, nlink=2),  # hardlinked
        lambda fs, path: fs.seed_symlink(path),
        lambda fs, path: fs.seed_file(path, b"not json", mode=0o640),
        lambda fs, path: fs.seed_file(path, b"[1,2]", mode=0o640),  # not an object
        lambda fs, path: fs.seed_file(path, b'{"role":"worker","role":"x"}', mode=0o640),
    ],
)
def test_an_untrusted_or_malformed_document_reads_as_absent(seed):
    fs = InMemoryFilesystem()
    _seed_host(fs)
    seed(fs, MANAGEMENT_WORKER_EVIDENCE_PATH)

    assert read_installed_worker_record(fs) is None


def test_a_missing_document_reads_as_absent():
    fs = InMemoryFilesystem()
    _seed_host(fs)
    fs.remove_file(MANAGEMENT_WORKER_IDENTITY_PATH)

    assert read_installed_worker_record(fs) is None


# --- per-check refusals --------------------------------------------------------------------------


def test_a_release_the_host_did_not_install_fails_exact_release():
    other = "sha256:" + "b" * 64
    fs = InMemoryFilesystem()
    _seed_host(fs)
    signer = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create()
    store = DurableWorkerEnrollmentStateStore(fs)
    store.record(ENROLLMENT, "offer_verified")
    # the invitation and the exchange agree with each other, but NOT with the installed release
    probes = LocalWorkerHealthProbes(
        invitation=_invitation(release_digest=other), fs=fs, state_store=store
    )

    evidence = _observe(probes, _ctx(release_digest=other, worker_key_id=signer.worker_key_id))

    assert evidence["exact_release"] is False
    assert evidence["operator_worker_disabled"] is True  # only the release check is affected


@pytest.mark.parametrize(
    ("flag", "failing"),
    [
        ("proxmox_contacted", "no_provider_contact"),
        ("external_contacts_performed", "no_provider_contact"),
        ("opentofu_executed", "no_opentofu_execution"),
        ("workflows_submitted", "no_controlled_live_submission"),
        ("run_plan_generation_called", "no_controlled_live_submission"),
    ],
)
def test_a_recorded_activity_fails_its_inertness_check(flag, failing):
    _fs, probes, key_id = _prepared_host(evidence={flag: True})

    evidence = _observe(probes, _ctx(worker_key_id=key_id))

    assert evidence[failing] is False
    assert evidence["exact_release"] is True  # the record itself is still coherent


@pytest.mark.parametrize("seal", sorted(_REVIEWED_SEALS))
def test_a_seal_out_of_its_reviewed_position_fails_every_inertness_check(seal):
    _fs, probes, key_id = _prepared_host(evidence={seal: not _REVIEWED_SEALS[seal]})

    evidence = _observe(probes, _ctx(worker_key_id=key_id))

    assert evidence["operator_worker_disabled"] is False
    assert evidence["no_provider_contact"] is False
    assert evidence["no_opentofu_execution"] is False
    assert evidence["no_controlled_live_submission"] is False


@pytest.mark.parametrize(
    "evidence_override",
    [
        {"unit_identity": ""},
        {"config_identity": ""},
        {"deployment_package_aggregate": ""},
        # the ordinary worker polling the OPERATOR queue (the two must stay distinct)
        {"ordinary_task_queue": OPERATOR_TASK_QUEUE},
    ],
)
def test_a_worker_host_without_the_prepared_operator_end_state_fails(evidence_override):
    _fs, probes, key_id = _prepared_host(evidence=evidence_override)

    assert _observe(probes, _ctx(worker_key_id=key_id))["operator_worker_disabled"] is False


def test_a_foreign_or_absent_enrollment_key_fails_the_key_check():
    _fs, probes, key_id = _prepared_host()

    for wrong in ("", "sha256:" + "0" * 64, key_id.upper()):
        evidence = _observe(probes, _ctx(worker_key_id=wrong))
        assert evidence["worker_enrollment_key_protected"] is False


def test_an_unprovisioned_key_fails_the_key_check():
    fs = InMemoryFilesystem()
    _seed_host(fs)
    store = DurableWorkerEnrollmentStateStore(fs)
    store.record(ENROLLMENT, "offer_verified")
    probes = LocalWorkerHealthProbes(invitation=_invitation(), fs=fs, state_store=store)

    evidence = _observe(probes, _ctx(worker_key_id="sha256:" + "0" * 64))

    assert evidence["worker_enrollment_key_protected"] is False


def test_a_missing_step_marker_fails_the_state_and_predecessor_checks():
    fs = InMemoryFilesystem()
    _seed_host(fs)
    signer = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create()
    probes = LocalWorkerHealthProbes(
        invitation=_invitation(), fs=fs, state_store=DurableWorkerEnrollmentStateStore(fs)
    )

    evidence = _observe(probes, _ctx(worker_key_id=signer.worker_key_id))

    assert evidence["local_enrollment_state_present"] is False
    assert evidence["expected_predecessor"] is False
    assert evidence["exact_release"] is True


def test_a_malformed_offer_content_address_fails_the_offer_checks():
    _fs, probes, key_id = _prepared_host()

    evidence = _observe(probes, _ctx(worker_key_id=key_id, offer_claim_digest="not-a-digest"))

    assert evidence["invitation_and_offer_verified"] is False
    assert evidence["expected_predecessor"] is False


@pytest.mark.parametrize(
    "override",
    [
        {"controller_key_id": "not-a-key-id"},
        {"controller_origin": "http://ctrl.example.test"},
        {"controller_installation_id": ""},
    ],
)
def test_an_unpinned_controller_identity_fails_the_pin_check(override):
    fs = InMemoryFilesystem()
    _seed_host(fs)
    signer = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create()
    store = DurableWorkerEnrollmentStateStore(fs)
    store.record(ENROLLMENT, "offer_verified")
    probes = LocalWorkerHealthProbes(invitation=_invitation(**override), fs=fs, state_store=store)

    evidence = _observe(probes, _ctx(worker_key_id=signer.worker_key_id))

    assert evidence["controller_key_pinned"] is False


def test_a_context_from_another_exchange_satisfies_nothing_pinned():
    _fs, probes, key_id = _prepared_host()

    other = _ctx(
        enrollment_id="sha256:" + "7" * 64,
        controller_transaction_id="txn-9999",
        worker_key_id=key_id,
    )
    evidence = _observe(probes, other)

    assert evidence["invitation_and_offer_verified"] is False
    assert evidence["controller_key_pinned"] is False
    assert evidence["expected_transaction"] is False
    assert evidence["expected_predecessor"] is False
    assert evidence["local_enrollment_state_present"] is False


def test_a_transaction_the_invitation_does_not_name_fails_the_transaction_check():
    _fs, probes, key_id = _prepared_host()

    evidence = _observe(
        probes, _ctx(worker_key_id=key_id, controller_transaction_id="txn-tampered")
    )

    assert evidence["expected_transaction"] is False
    assert evidence["invitation_and_offer_verified"] is True  # scoped: only its own check fails


def test_the_host_record_is_read_once_per_observation_run():
    fs, probes, key_id = _prepared_host()
    reads: list[str] = []
    original = fs.safe_read

    def counting(path, *, max_bytes, expected_uid):  # noqa: ANN001, ANN202
        reads.append(path)
        return original(path, max_bytes=max_bytes, expected_uid=expected_uid)

    fs.safe_read = counting  # type: ignore[method-assign]
    _observe(probes, _ctx(worker_key_id=key_id))

    # the eleven checks can never disagree about the host: one snapshot, not eleven re-reads
    assert reads.count(MANAGEMENT_WORKER_IDENTITY_PATH) == 1
    assert reads.count(MANAGEMENT_WORKER_EVIDENCE_PATH) == 1


def test_a_probe_that_raises_is_a_false_observation_never_a_fabricated_true():
    class ExplodingStore:
        def load(self, enrollment_id: str) -> str | None:
            raise RuntimeError("marker backend unavailable")

        def record(self, enrollment_id: str, step: str) -> None:
            return None

    fs = InMemoryFilesystem()
    _seed_host(fs)
    signer = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create()
    probes = LocalWorkerHealthProbes(invitation=_invitation(), fs=fs, state_store=ExplodingStore())

    evidence = _observe(probes, _ctx(worker_key_id=signer.worker_key_id))

    assert evidence["local_enrollment_state_present"] is False
    assert evidence["expected_predecessor"] is False


# --- composition: the three leaves drive a real exchange to healthy -------------------------------


class _FakeController:
    """A faithful in-process controller: it verifies the worker PoP, mints a REAL controller-signed
    offer, then verifies the signed worker result. No network, no fabricated signature."""

    def __init__(self, signer: WorkerEnrollmentSigner, *, priv: str) -> None:
        self._signer = signer
        self._priv = priv
        self.health_evidence: dict | None = None

    def _worker_installation(self) -> str:
        return "worker-" + self._signer.worker_key_id.split(":", 1)[-1][:16]

    def submit_binding(self, invitation: EnrollmentInvitationInputs) -> tuple[int, dict]:
        binding = ea.worker_binding_claim(
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_installation_id=self._worker_installation(),
            worker_key_id=self._signer.worker_key_id,
            release_digest=invitation.release_digest,
            expires_at=invitation.expires_at,
        )
        pop = self._signer.sign_binding(ea.claim_digest(binding))
        ea.verify_detached(
            pop,
            expected_key_id=self._signer.worker_key_id,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.POP_KIND,
            digest=ea.claim_digest(binding),
        )
        claim = ea.controller_offer_claim(
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_origin=invitation.controller_origin,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_installation_id=self._worker_installation(),
            worker_key_id=self._signer.worker_key_id,
            release_digest=invitation.release_digest,
            expires_at=invitation.expires_at,
            predecessor_digest="sha256:" + "b" * 64,
        )
        att = ea.sign_detached(
            self._priv,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.OFFER_KIND,
            digest=ea.claim_digest(claim),
        )
        return 200, {
            "signed_offer": {
                "claim": claim,
                "attestation": {
                    "algorithm": att.algorithm,
                    "key_id": att.key_id,
                    "public_key_hex": att.public_key_hex,
                    "signature": att.signature,
                },
            },
            "enrollment": {"state": "offer_transported", "revision": 2},
        }

    def submit_result(
        self,
        invitation: EnrollmentInvitationInputs,
        *,
        predecessor_digest: str,
        outcome: str,
        health_evidence: dict,
        generation: str,
        challenge: str,
    ) -> tuple[int, dict]:
        self.health_evidence = health_evidence
        assert ea.health_evidence_complete(health_evidence)
        return 200, {"enrollment": {"state": "healthy", "revision": 5}}


def _drive(fs: InMemoryFilesystem, *, controller_keypair=None) -> tuple[dict, dict]:
    """Drive one enrollment over the composed leaves.

    ``controller_keypair`` is threaded so a caller can drive TWICE AS THE SAME CONTROLLER. It used
    to generate a fresh pair per call, which made "a restarted worker" silently a DIFFERENT
    controller — invisible before the ownership binding existed, and now correctly refused by it.
    """
    priv, pub = controller_keypair if controller_keypair is not None else generate_keypair()
    invitation = _invitation(controller_key_id=ea.key_id_for(pub))
    key_seam = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True)
    store = DurableWorkerEnrollmentStateStore(fs)
    controllers: list[_FakeController] = []

    def transport_factory(
        signer: WorkerEnrollmentSigner, built_for: EnrollmentInvitationInputs
    ) -> _FakeController:
        # the factory is per-invitation: the origin and CA chain are the invitation's own
        assert built_for is invitation
        controller = _FakeController(signer, priv=priv)
        controllers.append(controller)
        return controller

    driver = WorkerEnrollmentDriver(
        key_seam=key_seam,
        transport_factory=transport_factory,
        state_store=store,
        # the SAME hardened filesystem the leaves already compose over — which is exactly how
        # production wires it, so this composition test exercises the real shape
        ownership_store=fs,
        health_observer=LocalWorkerHealthObserver(
            LocalWorkerHealthProbes(invitation=invitation, fs=fs, state_store=store)
        ),
    )
    # the independent first-contact fact, from the operator channel rather than the invitation
    outcome = driver.enroll(invitation, now=NOW, expected_controller_key_id=ea.key_id_for(pub))
    return (
        {"state": outcome.state, "revision": outcome.revision, "resumed": outcome.already_healthy},
        controllers[0].health_evidence or {},
    )


def test_the_three_leaves_compose_into_a_driver_that_reaches_healthy():
    fs = InMemoryFilesystem()
    _seed_host(fs)

    outcome, evidence = _drive(fs)

    assert outcome == {"state": "healthy", "revision": 5, "resumed": False}
    assert evidence == dict.fromkeys(ea.REQUIRED_HEALTH_CHECKS, True)
    # the durable marker survives the run, so a restart resumes instead of re-driving blind
    assert DurableWorkerEnrollmentStateStore(fs).load(ENROLLMENT) == "healthy"


def test_a_second_run_resumes_from_the_durable_marker_with_the_same_key():
    fs = InMemoryFilesystem()
    _seed_host(fs)

    # THE SAME controller across both runs — a restart, not a different control plane.
    controller = generate_keypair()

    first, _ = _drive(fs, controller_keypair=controller)
    first_key = LocalWorkerEnrollmentKeySeam(fs).load_or_create().worker_key_id
    second, _ = _drive(fs, controller_keypair=controller)  # a RESTARTED worker, same host state

    assert first["resumed"] is False
    assert second["resumed"] is True  # the durable marker is what makes the resume observable
    assert LocalWorkerEnrollmentKeySeam(fs).load_or_create().worker_key_id == first_key
    # and the exact-same-owner re-drive is idempotent rather than a second binding
    from secp_worker.worker_ownership import load_worker_ownership

    owner = load_worker_ownership(fs)
    assert owner is not None
    assert owner.binding_generation == 1


def test_a_second_run_by_a_DIFFERENT_controller_is_refused_before_network():
    """The write-once property, discovered by this suite rather than asserted into it.

    Before the ownership binding existed, `_drive` generated a fresh controller keypair per call and
    nothing noticed that "a restarted worker" was actually a different control plane. It is refused
    now, and refused at the gate — so the second controller receives no proof of possession.
    """
    fs = InMemoryFilesystem()
    _seed_host(fs)
    _drive(fs, controller_keypair=generate_keypair())

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        _drive(fs, controller_keypair=generate_keypair())
    assert ei.value.reason_code == "enrollment_ownership_controller_key_mismatch"


def test_an_unprepared_host_refuses_locally_and_submits_no_result():
    fs = InMemoryFilesystem()  # no management records: the host was never bootstrapped

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        _drive(fs)

    assert ei.value.reason_code == "enrollment_worker_health_incomplete"
