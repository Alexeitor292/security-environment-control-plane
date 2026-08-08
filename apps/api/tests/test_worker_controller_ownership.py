"""The worker's anti-hijack ownership binding — the adversarial matrix (M1 pre-live).

Hermetic: an in-memory hardened filesystem and an in-process controller double. No socket, no real
host, no Proxmox.

Every test here asserts a REFUSAL for a specific attacker capability, not that a function returns
something. The property under test throughout is that a worker already claimed by one control plane
cannot be taken by another, and that a worker not yet claimed will not be claimed by whoever speaks
first.
"""

from __future__ import annotations

import json

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.runtime import InMemoryFilesystem
from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
from secp_worker.enrollment_key import (
    WORKER_ENROLLMENT_KEY_PATH,
    WORKER_ENROLLMENT_PUBLIC_PATH,
    WORKER_ENROLLMENT_ROOT,
)
from secp_worker.worker_ownership import (
    WORKER_OWNERSHIP_PATH,
    WORKER_OWNERSHIP_SCHEMA,
    WorkerControllerOwnership,
    clear_worker_ownership,
    install_worker_ownership,
    load_worker_ownership,
    reset_worker_ownership,
)

CTRL_KEY = "sha256:" + "a" * 64
WORKER_KEY = "sha256:" + "b" * 64


def _fs() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    fs.makedir(WORKER_ENROLLMENT_ROOT, uid=0, gid=0, mode=0o700)
    return fs


def _owner(**over) -> WorkerControllerOwnership:
    base = dict(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_origin="https://ctrl.example.test",
        worker_key_id=WORKER_KEY,
    )
    base.update(over)
    return WorkerControllerOwnership(**base)


def _write_raw(fs: InMemoryFilesystem, payload: bytes, *, mode: int = 0o600, uid: int = 0) -> None:
    fs.exclusive_install(WORKER_OWNERSHIP_PATH, payload, uid=uid, gid=0, mode=mode)


# === absent vs corrupt — the distinction the whole module exists for =============================


def test_an_absent_document_reads_as_genuinely_unowned():
    assert load_worker_ownership(_fs()) is None


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not json at all",
        b"[]",
        b'"a string"',
        b"null",
        b"{}",
        json.dumps({"schema": WORKER_OWNERSHIP_SCHEMA}).encode(),  # missing every identity
        json.dumps({**_owner().canonical(), "extra": "x"}).encode(),  # unknown key
        json.dumps(
            {k: v for k, v in _owner().canonical().items() if k != "worker_key_id"}
        ).encode(),
        json.dumps({**_owner().canonical(), "controller_key_id": ""}).encode(),
        json.dumps({**_owner().canonical(), "controller_key_id": "   "}).encode(),
        json.dumps({**_owner().canonical(), "controller_key_id": 7}).encode(),
        json.dumps({**_owner().canonical(), "binding_generation": 0}).encode(),
        json.dumps({**_owner().canonical(), "binding_generation": True}).encode(),
        json.dumps({**_owner().canonical(), "binding_generation": "1"}).encode(),
    ],
)
def test_a_corrupt_document_refuses_and_is_never_read_as_unowned(payload):
    """THE test this module exists for.

    If any of these returned ``None`` the caller would proceed to bind a NEW owner, which turns
    "damage a file on the worker" into a remote worker-claim primitive. Every malformation must
    raise instead.
    """
    fs = _fs()
    _write_raw(fs, payload)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        load_worker_ownership(fs)
    assert ei.value.reason_code.startswith("enrollment_ownership_")


def test_a_future_schema_refuses_rather_than_being_partially_understood():
    fs = _fs()
    _write_raw(fs, json.dumps({**_owner().canonical(), "schema": "something/v2"}).encode())
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        load_worker_ownership(fs)
    assert ei.value.reason_code == "enrollment_ownership_schema_unknown"


# === the protected-file contract ================================================================


@pytest.mark.parametrize("mode", [0o644, 0o666, 0o600 | 0o070, 0o700])
def test_a_wrong_mode_refuses(mode):
    fs = _fs()
    _write_raw(fs, json.dumps(_owner().canonical()).encode(), mode=mode)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        load_worker_ownership(fs)
    assert ei.value.reason_code == "enrollment_ownership_metadata_invalid"


def test_a_foreign_owner_refuses():
    fs = _fs()
    _write_raw(fs, json.dumps(_owner().canonical()).encode(), uid=1000)
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        load_worker_ownership(fs)
    assert ei.value.reason_code == "enrollment_ownership_metadata_invalid"


def test_the_document_is_held_to_the_same_contract_as_the_protected_key():
    """Asserted structurally: one checker, two callers.

    A second copy of the symlink / nlink / uid / mode rules is how the two drift and one of them
    ends up trusting a hardlink.
    """
    import inspect

    from secp_worker import worker_ownership
    from secp_worker.enrollment_key import require_protected_file_stat

    source = inspect.getsource(worker_ownership)
    assert "require_protected_file_stat" in source
    assert require_protected_file_stat is worker_ownership.require_protected_file_stat


# === write-once ==================================================================================


def test_a_first_binding_is_installed_and_reads_back():
    fs = _fs()
    install_worker_ownership(fs, _owner())
    loaded = load_worker_ownership(fs)
    assert loaded is not None
    assert loaded.matches(_owner())


def test_rebinding_the_identical_owner_is_idempotent():
    fs = _fs()
    install_worker_ownership(fs, _owner())
    again = install_worker_ownership(fs, _owner())
    assert again.matches(_owner())


@pytest.mark.parametrize(
    "field,value",
    [
        ("controller_installation_id", "controller-bbbbbbbb"),
        ("controller_key_id", "sha256:" + "c" * 64),
        ("controller_origin", "https://attacker.example.test"),
        ("worker_key_id", "sha256:" + "d" * 64),
    ],
)
def test_no_field_may_change_through_ordinary_enrollment(field, value):
    """Every field, not a chosen subset.

    Deciding which identity is allowed to differ is how a re-claim becomes possible: an attacker
    needs only one field to be the excluded one.
    """
    fs = _fs()
    install_worker_ownership(fs, _owner())
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        install_worker_ownership(fs, _owner(**{field: value}))
    assert ei.value.reason_code == "enrollment_ownership_already_bound"


# === the local reset =============================================================================


@pytest.mark.parametrize("write,confirm", [(False, False), (False, True), (True, False)])
def test_reset_requires_both_explicit_local_gates(write, confirm):
    fs = _fs()
    install_worker_ownership(fs, _owner())
    with pytest.raises(WorkerEnrollmentDriverError):
        reset_worker_ownership(fs, write=write, confirm=confirm)
    assert load_worker_ownership(fs) is not None  # still owned


def test_reset_releases_the_worker_and_rotates_its_enrollment_identity():
    fs = _fs()
    fs.exclusive_install(WORKER_ENROLLMENT_KEY_PATH, b"f" * 64, uid=0, gid=0, mode=0o600)
    fs.exclusive_install(WORKER_ENROLLMENT_PUBLIC_PATH, b"e" * 64, uid=0, gid=0, mode=0o644)
    install_worker_ownership(fs, _owner())

    outcome = reset_worker_ownership(fs, write=True, confirm=True)

    assert outcome.ownership_removed is True
    assert outcome.enrollment_key_rotated is True
    assert load_worker_ownership(fs) is None  # genuinely unowned
    # rotating is what stops the OLD controller continuing to recognise this worker as the same
    # principal — a release that kept the key would hand over a claimed identity
    assert fs.lstat(WORKER_ENROLLMENT_KEY_PATH) is None
    assert fs.lstat(WORKER_ENROLLMENT_PUBLIC_PATH) is None


def test_after_reset_a_different_controller_may_claim_the_worker():
    fs = _fs()
    install_worker_ownership(fs, _owner())
    reset_worker_ownership(fs, write=True, confirm=True)
    other = _owner(controller_installation_id="controller-bbbbbbbb")
    assert install_worker_ownership(fs, other).matches(other)


def test_reset_touches_no_infrastructure():
    """Worker ownership and Proxmox resource ownership are different authority domains.

    A local administrative release must not be able to destroy a running range, so nothing here may
    reach a provider, a transport or a subprocess.

    Asserted over the module's IMPORTS via the AST, not over its text. A substring scan matches the
    docstring that explains the rule — which is exactly how this test failed on its first writing.
    Asking what the code imports is the property meant.
    """
    import ast
    import inspect

    from secp_worker import worker_ownership

    tree = ast.parse(inspect.getsource(worker_ownership))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    for name in imported:
        head = name.split(".")[0]
        assert head not in {"httpx", "subprocess", "socket", "requests", "ssl"}, name
        assert "proxmox" not in name.lower(), name
        assert "opentofu" not in name.lower(), name


def test_no_remote_surface_can_reach_the_reset():
    """The only transfer mechanism is a person with root on the worker.

    A controller able to release a worker it does not own is the hijack the binding exists to
    prevent, so the reset must not be reachable from the API or from a Temporal activity.
    """
    import pathlib

    import secp_api
    import secp_worker

    api_root = pathlib.Path(secp_api.__file__).parent
    worker_root = pathlib.Path(secp_worker.__file__).parent

    for path in api_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "reset_worker_ownership" not in text, path
        assert "clear_worker_ownership" not in text, path

    # and no Temporal activity in the worker reaches it either
    for name in ("temporal_app.py", "temporal_workflows.py", "orchestration.py"):
        candidate = worker_root / name
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8")
            assert "reset_worker_ownership" not in text, name
            assert "clear_worker_ownership" not in text, name


# === the first-contact trust fact ================================================================


def test_the_first_contact_trust_fact_cannot_come_from_the_invitation():
    """Structural, and the single most important property of the design.

    Adding one more value to the invitation would be self-authentication: the invitation already
    carries the controller origin, the controller key id AND the CA, so an attacker who supplies
    all three supplies a coherent identity that TLS and signature checks then correctly
    authenticate. The expected key must therefore be a SEPARATE parameter that the driver never
    reads off the invitation.
    """
    import inspect

    from secp_worker.enrollment_driver import WorkerEnrollmentDriver
    from secp_worker.enrollment_http_transport import EnrollmentInvitationInputs

    params = inspect.signature(WorkerEnrollmentDriver.enroll).parameters
    assert "expected_controller_key_id" in params

    # it is not a field of the invitation type, so it cannot travel with a substituted one
    invitation_fields = set(EnrollmentInvitationInputs.__dataclass_fields__)
    assert "expected_controller_key_id" not in invitation_fields

    # and the gate never derives it from the invitation
    gate = inspect.getsource(WorkerEnrollmentDriver._ownership_gate)
    assert "invitation.controller_key_id" in gate  # it is COMPARED against
    assert "expected_controller_key_id = invitation" not in gate  # never ASSIGNED from


def test_the_operator_anchor_is_the_controller_signing_key_not_a_tls_ca():
    """A named guard against the conflation that would silently create a vulnerability.

    ``controller_trust_anchor_hex`` is a raw Ed25519 PUBLIC SIGNING key — it is the public half of
    the key that signs the controller offer. Treating it as a TLS CA fingerprint (or vice versa)
    would authenticate the wrong thing entirely, and both are lowercase hex so nothing else would
    catch it.
    """
    from secp_management.worker_installer import _TRUST_ANCHOR_HEX, _expected_controller_key_id

    # a raw 32-byte Ed25519 public key, NOT a `sha256:`-prefixed digest
    assert _TRUST_ANCHOR_HEX.pattern == r"^[0-9a-f]{64}$"

    class _Req:
        controller_trust_anchor_hex = "ab" * 32

    # derived with the SAME primitive the controller and the driver use, so the three cannot
    # disagree about what a key id is
    assert _expected_controller_key_id(_Req()) == ea.key_id_for("ab" * 32)


def test_the_production_enroller_always_supplies_an_ownership_store():
    """Reachability: the gate is only real if production actually wires the store.

    A security helper reached solely from tests is the shape this repository has shipped before.
    """
    import inspect

    from secp_management.worker_enroller import DriverWorkerEnroller

    build = inspect.getsource(DriverWorkerEnroller._build_driver)
    assert "ownership_store=self._fs" in build

    enroll = inspect.getsource(DriverWorkerEnroller.enroll)
    assert "expected_controller_key_id=expected_controller_key_id" in enroll


def test_both_production_cli_chains_pass_the_operator_anchor():
    """`worker install` AND `worker enroll` — not just the one that already had an anchor."""
    import inspect

    from secp_management import enrollment_cli, worker_installer

    installer = inspect.getsource(worker_installer)
    assert "expected_controller_key_id=_expected_controller_key_id(validated)" in installer

    cli = inspect.getsource(enrollment_cli)
    assert cli.count("_expected_controller_key_id(") >= 3  # definition + enroll + retry


def test_the_gate_has_no_bypass_switch():
    """No `allow_unowned`, no `ownership_enabled`, no boolean that widens what may enroll."""
    import inspect

    from secp_worker.enrollment_driver import WorkerEnrollmentDriver

    source = inspect.getsource(WorkerEnrollmentDriver)
    for banned in (
        "allow_unowned",
        "ownership_enabled",
        "skip_ownership",
        "ownership_optional",
        "require_ownership",
    ):
        assert banned not in source, banned


def test_clear_is_not_reachable_without_the_gates():
    fs = _fs()
    install_worker_ownership(fs, _owner())
    for write, confirm in ((False, False), (False, True), (True, False)):
        with pytest.raises(WorkerEnrollmentDriverError):
            clear_worker_ownership(fs, write=write, confirm=confirm)
    assert load_worker_ownership(fs) is not None
