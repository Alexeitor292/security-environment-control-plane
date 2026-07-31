"""Host-local worker-enrollment health probes (SECP WS-B, W3).

The concrete :class:`~secp_worker.enrollment_driver.WorkerHealthProbes` a deployment wires into
:class:`~secp_worker.enrollment_driver.LocalWorkerHealthObserver` — one real observation per
required check, so the driver can attest ``healthy`` from CHECKED FACTS instead of the sealed
observer's outright refusal.

DERIVED, NOT RE-OBSERVED
------------------------
The worker host state is ALREADY observed, by the management-plane bootstrap: it runs
``RealManagementHostObserver.observe_worker`` and then gates on the complete canonical prepared end
state (``_worker_end_state_reason``) BEFORE it writes its two durable root-owned documents. A fifth
independent observer family — a second container-runtime / systemd probe from the worker plane —
would be a defect: two observers of the same host will eventually disagree, and the one attesting
enrollment health would be the unreviewed one.

So these probes DERIVE from that existing observation. They read the management plane's own durable
records at their fixed paths through the hardened filesystem and project the bounded, non-secret
facts they need. The strongest property comes for free: the worker evidence document EXISTS ONLY IF
the management end-state gate passed, so a present, coherent, role-matched evidence document is
itself the proof that the canonical prepared end state (ordinary running + healthy on the exact
signed image, operator present but NOT enabled and NOT running, ordinary not polling the operator
queue, package trusted) was actually observed.

The plane boundary is preserved: ``apps/worker`` never imports ``secp_management``. The two
document paths and the four seal positions are FIXED literals here that byte-match the
management-plane constants, exactly as the management layout already does for the commissioning
socket and API handoff paths; a guard test in the test layer (which may import both planes) proves
the byte-match so the two planes cannot drift.

Everything else each probe needs is either the operator's independently-held invitation (pinned at
construction, never taken from the context being validated), the protected on-disk enrollment key,
or the durable restart marker. A probe that cannot make its observation returns ``False``; none
fabricates a ``True``, and none raises (the observer treats a raise as ``False`` anyway).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from secp_commissioning.canonical import is_sha256_digest
from secp_commissioning.runtime import FileStat, FilesystemBackend

from secp_worker.enrollment_driver import (
    HealthObservationContext,
    WorkerEnrollmentStateStore,
)
from secp_worker.enrollment_http_transport import EnrollmentInvitationInputs
from secp_worker.enrollment_key import observe_local_worker_enrollment_key
from secp_worker.enrollment_state_store import WORKER_ENROLLMENT_STEPS

#: The management-plane bootstrap's durable worker records, at their EXACT fixed paths. These byte-
#: match ``ManagementLocations.identity_path("worker")`` / ``.evidence_path("worker")``; a guard
#: test proves it. They are read-only here — the worker plane never writes a management document.
MANAGEMENT_WORKER_IDENTITY_PATH = "/var/lib/secp/bootstrap/worker-identity.json"
MANAGEMENT_WORKER_EVIDENCE_PATH = "/var/lib/secp/bootstrap/worker-evidence.json"

#: The mode/ownership the management plane installs its managed documents with (root:root 0640).
_MANAGED_DOC_MODE = 0o640
_MAX_DOC_BYTES = 256 * 1024
_MANAGEMENT_PLANE = "management"
_WORKER_ROLE = "worker"
#: The two install modes a legitimately bootstrapped worker host can carry.
_INSTALLED_MODES = ("installed", "adopted")
#: The step marker that proves the offer stage of THIS enrollment completed locally.
_STEP_OFFER_VERIFIED = WORKER_ENROLLMENT_STEPS[0]

#: The four reviewed safety seals in their REVIEWED positions — the exact predicate the management
#: plane's ``SealState.safe`` applies to the same four values. ``plan_only_process_sealed`` is
#: deliberately ``False`` (the plan-only process boundary is not sealed); the other three are
#: ``True``. Read here from the values the bootstrap RECORDED, never re-read from code constants:
#: re-reading them from the worker plane would be a second seal observer.
_REVIEWED_SEALS: dict[str, bool] = {
    "operator_activation_sealed": True,
    "plan_only_process_sealed": False,
    "b1a_subprocess_sealed_activation": True,
    "b1a_subprocess_sealed_executor": True,
}

_EVIDENCE_BOOLS: tuple[str, ...] = (
    "external_contacts_performed",
    "workflows_submitted",
    "run_plan_generation_called",
    "opentofu_executed",
    "proxmox_contacted",
    *_REVIEWED_SEALS,
)


@dataclass(frozen=True)
class InstalledWorkerRecord:
    """The bounded, NON-SECRET projection of the management bootstrap's durable worker records.

    Only the fields an enrollment health check needs are projected; no path, credential, or private
    material is carried. Its mere existence already means the management end-state gate passed."""

    release_digest: str  # the installed release, from the identity document
    installation_id: str
    mode: str
    evidence_release_aggregate: str
    unit_identity: str
    config_identity: str
    deployment_package_aggregate: str
    ordinary_task_queue: str
    operator_task_queue: str
    flags: dict[str, bool]

    def flag(self, name: str) -> bool | None:
        value = self.flags.get(name)
        return value if isinstance(value, bool) else None


def _doc_trusted(st: FileStat | None) -> bool:
    """A managed document is trusted only as a plain, unlinked, root-owned 0640 regular file."""
    return bool(
        st is not None
        and not st.is_symlink
        and st.is_regular
        and not st.is_dir
        and not st.is_special
        and st.nlink == 1
        and st.uid == 0
        and st.gid == 0
        and st.mode == _MANAGED_DOC_MODE
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ValueError("duplicate_key")
        seen.add(key)
    return dict(pairs)


def _read_document(fs: FilesystemBackend, path: str) -> dict[str, Any] | None:
    """Read ONE management document through the hardened filesystem and parse it strictly. Any
    failure — drifted metadata, unreadable, oversized, non-JSON, duplicate keys, not an object —
    is ``None``; this never raises and never partially trusts a document."""
    try:
        if not _doc_trusted(fs.lstat(path)):
            return None
        raw = fs.safe_read(path, max_bytes=_MAX_DOC_BYTES, expected_uid=0)
    except Exception:  # noqa: BLE001 - an unreadable document is an absent observation
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    return value if isinstance(value, str) else ""


def read_installed_worker_record(fs: FilesystemBackend) -> InstalledWorkerRecord | None:
    """Project the management plane's durable worker identity + evidence into one bounded record,
    or ``None`` when the pair is absent, drifted, mismatched, or not a WORKER management install.

    Both documents must agree on the role, the plane and the release aggregate — a controller
    document, a document for another release, or a mismatched pair is refused rather than
    partially believed."""
    identity = _read_document(fs, MANAGEMENT_WORKER_IDENTITY_PATH)
    evidence = _read_document(fs, MANAGEMENT_WORKER_EVIDENCE_PATH)
    if identity is None or evidence is None:
        return None
    if _string(identity, "role") != _WORKER_ROLE or _string(evidence, "role") != _WORKER_ROLE:
        return None
    if _string(identity, "plane") != _MANAGEMENT_PLANE or _string(evidence, "plane") != (
        _MANAGEMENT_PLANE
    ):
        return None
    release_digest = _string(identity, "release_digest")
    aggregate = _string(evidence, "release_aggregate_digest")
    if not is_sha256_digest(release_digest) or release_digest != aggregate:
        return None
    mode = _string(evidence, "mode")
    if mode not in _INSTALLED_MODES:
        return None
    flags: dict[str, bool] = {}
    for name in _EVIDENCE_BOOLS:
        value = evidence.get(name)
        if not isinstance(value, bool):
            return None  # a missing or non-boolean proof is never read as a proof
        flags[name] = value
    return InstalledWorkerRecord(
        release_digest=release_digest,
        installation_id=_string(identity, "installation_id"),
        mode=mode,
        evidence_release_aggregate=aggregate,
        unit_identity=_string(evidence, "unit_identity"),
        config_identity=_string(evidence, "config_identity"),
        deployment_package_aggregate=_string(evidence, "deployment_package_aggregate"),
        ordinary_task_queue=_string(evidence, "ordinary_task_queue"),
        operator_task_queue=_string(evidence, "operator_task_queue"),
        flags=flags,
    )


class LocalWorkerHealthProbes:
    """The production probes: eleven real observations derived from four host-local sources.

    ============================  ==============================================================
    source                        what it proves
    ============================  ==============================================================
    the PINNED invitation         the exchange being reported is the one this host was handed
    the management records        the installed release + the observed prepared end state
    the protected key pair        the enrollment key exists at the hardened path and is THIS key
    the durable step marker       the offer stage of THIS enrollment actually completed locally
    ============================  ==============================================================

    The invitation is held at construction and is NEVER taken from the context under validation, so
    a context describing a different enrollment, release, or transaction cannot satisfy the checks.

    The management records are read ONCE per instance (a deployment builds one instance per
    enrollment run) and cached, so the eleven checks can never disagree with each other about the
    host — the same reason image presence is taken as a single snapshot rather than re-queried.
    """

    __slots__ = ("_invitation", "_fs", "_state_store", "_record", "_record_read")

    def __init__(
        self,
        *,
        invitation: EnrollmentInvitationInputs,
        fs: FilesystemBackend,
        state_store: WorkerEnrollmentStateStore,
    ) -> None:
        self._invitation = invitation
        self._fs = fs
        self._state_store = state_store
        self._record: InstalledWorkerRecord | None = None
        self._record_read = False

    def __repr__(self) -> str:  # never a path, a key, or an invitation field
        return "LocalWorkerHealthProbes(<redacted>)"

    # --- the single derived observation ----------------------------------------------------------

    def _installed(self) -> InstalledWorkerRecord | None:
        if not self._record_read:
            self._record_read = True
            try:
                self._record = read_installed_worker_record(self._fs)
            except Exception:  # noqa: BLE001 - an unavailable read is an absent observation
                self._record = None
        return self._record

    def _seals_reviewed(self) -> bool:
        """Every one of the four seals is in its REVIEWED position in the bootstrap's own record."""
        record = self._installed()
        if record is None:
            return False
        return all(record.flag(name) is expected for name, expected in _REVIEWED_SEALS.items())

    def _inert(self, *names: str) -> bool:
        """Each named bootstrap activity proof is recorded as ``False`` (it did NOT happen)."""
        record = self._installed()
        if record is None:
            return False
        return all(record.flag(name) is False for name in names)

    def _same_enrollment(self, ctx: HealthObservationContext) -> bool:
        return bool(ctx.enrollment_id) and ctx.enrollment_id == self._invitation.enrollment_id

    def _marker(self, ctx: HealthObservationContext) -> str | None:
        try:
            return self._state_store.load(ctx.enrollment_id)
        except Exception:  # noqa: BLE001 - an unreadable marker is simply no marker
            return None

    # --- the eleven required checks ---------------------------------------------------------------

    def invitation_and_offer_verified(self, ctx: HealthObservationContext) -> bool:
        """The driver reaches this observation only AFTER it independently rebuilt and verified the
        controller offer against the invitation's pinned key; the verified offer's content address
        is in the context. This probe confirms the observation it is being asked to attest belongs
        to the EXACT invitation this host holds and carries a real offer content address — it does
        not re-verify the signature (the driver owns that duty and cannot reach here without it),
        but a context from any other exchange can never satisfy it."""
        return self._same_enrollment(ctx) and is_sha256_digest(ctx.offer_claim_digest)

    def controller_key_pinned(self, ctx: HealthObservationContext) -> bool:
        """The controller identity the offer was verified against is PINNED by the held invitation:
        a well-formed key id (the form ``verify_detached`` requires to accept a signer at all) and
        an https origin — neither discovered nor negotiated during the exchange."""
        return (
            self._same_enrollment(ctx)
            and is_sha256_digest(self._invitation.controller_key_id)
            and self._invitation.controller_origin.startswith("https://")
            and bool(self._invitation.controller_installation_id)
        )

    def expected_transaction(self, ctx: HealthObservationContext) -> bool:
        """The controller transaction in the observation is the EXACT transaction the held
        invitation names."""
        return (
            self._same_enrollment(ctx)
            and bool(ctx.controller_transaction_id)
            and ctx.controller_transaction_id == self._invitation.controller_transaction_id
        )

    def expected_predecessor(self, ctx: HealthObservationContext) -> bool:
        """The result the worker is about to sign chains to the exact verified offer: its content
        address is well formed AND the durable marker records that the offer stage of THIS
        enrollment completed locally, so the predecessor is not a value invented this run."""
        return (
            self._same_enrollment(ctx)
            and is_sha256_digest(ctx.offer_claim_digest)
            and self._marker(ctx) == _STEP_OFFER_VERIFIED
        )

    def exact_release(self, ctx: HealthObservationContext) -> bool:
        """The release the enrollment is bound to is the release actually INSTALLED on this host —
        the management bootstrap's own identity document and its evidence both report it, and both
        must equal the invitation and the observation. This is the check that makes a worker
        enrolled under one release but running another impossible."""
        record = self._installed()
        return bool(
            record is not None
            and is_sha256_digest(ctx.release_digest)
            and ctx.release_digest == self._invitation.release_digest
            and ctx.release_digest == record.release_digest
            and ctx.release_digest == record.evidence_release_aggregate
        )

    def worker_enrollment_key_protected(self, ctx: HealthObservationContext) -> bool:
        """A coherent enrollment key pair exists at the reviewed fixed path with the reviewed
        ownership and 0600 mode, AND it is the key that signed this exchange. A drifted, foreign-
        owned, symlinked, hardlinked, or incoherent pair observes as absent and fails here."""
        observed = observe_local_worker_enrollment_key(self._fs)
        return bool(observed) and observed == ctx.worker_key_id

    def local_enrollment_state_present(self, ctx: HealthObservationContext) -> bool:
        """The durable restart marker for THIS enrollment is present and carries a known step, so a
        restarted worker resumes against the controller instead of re-driving blind."""
        return self._same_enrollment(ctx) and self._marker(ctx) in WORKER_ENROLLMENT_STEPS

    def operator_worker_disabled(self, ctx: HealthObservationContext) -> bool:
        """The operator worker is present but DISABLED and STOPPED.

        Derived, not re-observed: the management bootstrap gates on the complete canonical prepared
        end state — which refuses ``worker_operator_not_disabled_stopped``, and equally refuses an
        ordinary worker that polls the operator queue — BEFORE it writes the evidence document read
        here. So a coherent worker evidence record, with the operator unit identity it installed,
        two distinct task queues, and the operator-activation seal in its reviewed position, is
        that observation. A second container/systemd observer from this plane would be a fifth
        observer family of the same host, not a stronger proof."""
        record = self._installed()
        return bool(
            record is not None
            and self._same_enrollment(ctx)
            and self._seals_reviewed()
            and record.unit_identity
            and record.config_identity
            and record.deployment_package_aggregate
            and record.ordinary_task_queue
            and record.operator_task_queue
            and record.ordinary_task_queue != record.operator_task_queue
        )

    # The three inertness probes below take ``ctx`` to satisfy the uniform ``WorkerHealthProbes``
    # signature and deliberately do NOT read it: they attest facts about the BOOTSTRAP TRANSACTION
    # that built this host, which is a property of the host alone and cannot vary per exchange.
    # Binding them to ``ctx`` would not strengthen them — it would only make a host-wide fact look
    # exchange-scoped. Do not "fix" this by adding a ``_same_enrollment(ctx)`` conjunct.

    def no_provider_contact(self, ctx: HealthObservationContext) -> bool:
        """No provider was contacted while this host was built: the bootstrap transaction RECORDED
        both its provider-contact and its external-contact proofs as ``False``, and it recorded the
        seals that make provider contact unreachable in their reviewed positions.

        This is a statement about what was OBSERVED AT BOOTSTRAP TIME, not a live assertion about
        the current process — see the module docstring. A probe here re-reading today's seal state
        would be a second, unreviewed observer of the same host."""
        return self._inert("proxmox_contacted", "external_contacts_performed") and (
            self._seals_reviewed()
        )

    def no_opentofu_execution(self, ctx: HealthObservationContext) -> bool:
        """No OpenTofu ran while this host was built: the recorded execution proof was ``False`` and
        both B1-A subprocess seals were recorded in their reviewed ``True`` position — the position
        in which the real process executor could not be constructed."""
        return self._inert("opentofu_executed") and self._seals_reviewed()

    def no_controlled_live_submission(self, ctx: HealthObservationContext) -> bool:
        """Nothing was submitted to the controlled-live path while this host was built: neither a
        workflow submission nor a plan-generation run was recorded, and the operator-activation seal
        was recorded in its reviewed position."""
        return self._inert("workflows_submitted", "run_plan_generation_called") and (
            self._seals_reviewed()
        )


__all__ = [
    "MANAGEMENT_WORKER_EVIDENCE_PATH",
    "MANAGEMENT_WORKER_IDENTITY_PATH",
    "InstalledWorkerRecord",
    "LocalWorkerHealthProbes",
    "read_installed_worker_record",
]
