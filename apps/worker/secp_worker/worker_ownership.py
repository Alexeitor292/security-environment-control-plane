"""The worker's durable answer to "which control plane owns me?" (ADR-026/027, M1 pre-live).

Before this existed, a worker persisted no controller identity at all. ``enrollment_state_store``
says so in its own docstring — it writes the last completed enrollment STEP and explicitly no key,
offer, claim, attestation or controller origin. With nothing pinned, a second enrollment had nothing
to disagree with: an attacker who could substitute the invitation supplied the controller origin,
the controller signing key AND the TLS trust anchor together, and TLS and signature checks then
correctly authenticated the identity that attacker had chosen.

WHY THIS IS NOT STORED IN THE ENROLLMENT STATE STORE
-----------------------------------------------------
That store is a retry hint, and its semantics are deliberately forgiving: a missing or unreadable
marker means "re-drive the exchange", so a local fault can never fail an enrollment the controller
already advanced. Those are the right semantics for a hint and catastrophic ones for ownership.

    a corrupt retry hint  -> re-drive enrollment          (safe)
    a corrupt owner record -> "this worker is unowned"    (a remote worker-claim primitive)

So ownership is a separate document with inverted failure semantics, and the distinction is the
whole point of the module:

    absent                                   -> genuinely unowned
    present, structurally trusted, valid     -> owned
    present but malformed / wrong mode /
    wrong owner / symlink / hardlinked /
    truncated / unparseable                  -> OWNERSHIP CORRUPT -> REFUSE

Never "corrupt, therefore unowned". An attacker who can damage a file must not thereby be able to
hand the worker to a different control plane.

WHAT IT HOLDS, AND WHAT IT DELIBERATELY DOES NOT
--------------------------------------------------
PUBLIC identities only — no private key, no pairing secret, no credential, no token.

It pins EXACTLY the four controller/worker identities the controller's offer signature actually
covers, verified by reading ``controller_offer_claim``'s field list rather than assumed:
``controller_installation_id``, ``controller_key_id``, ``controller_origin`` and ``worker_key_id``.

It does NOT yet pin the organization, the deployment site, or the controller's TLS trust anchor.
Those three are absent from every signed claim in the current exchange, and pinning a value merely
because it arrived beside a valid signature is the defect this module exists to prevent — an
attacker who substitutes the CA while transparently proxying the real controller would otherwise
get their anchor permanently pinned on the strength of the real controller's signature over fields
that say nothing about it. Adding them requires a controller-signed ownership claim under its own
attestation ``kind``; until that exists, pinning them would be a binding this worker cannot
actually verify.

What v1 does protect against is controller SUBSTITUTION, which is the hijack: an attacker
supplying their own invitation supplies their own ``controller_key_id``, and an owned worker
refuses before any packet leaves the host.

The storage contract is the one :mod:`secp_worker.enrollment_key` already established for the
protected key pair, reusing its checker rather than restating it: root-owned 0700 parent, 0600
regular file, ``nlink == 1``, no symlink, exclusive atomic install with compensation, and a
read-back that proves what is ON DISK is what was meant.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import ExclusiveFileReceipt, FilesystemBackend

from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
from secp_worker.enrollment_key import (
    WORKER_ENROLLMENT_ROOT,
    require_protected_file_stat,
)

#: The EXACT ownership document. A reviewed code constant beside the protected key pair — never a
#: CLI argument, an environment variable or a caller-selected path, so no caller can point the
#: loader at a document an attacker controls.
WORKER_OWNERSHIP_PATH = f"{WORKER_ENROLLMENT_ROOT}/controller-ownership.json"

_OWNERSHIP_MODE = 0o600
#: A generous ceiling for a document of ~10 short identity strings. Bounded so a planted multi-
#: gigabyte file is refused rather than read.
_MAX_OWNERSHIP_BYTES = 16 * 1024

#: The document's own schema tag. A record written by a future, differently-shaped version is
#: refused as corrupt rather than partially understood.
WORKER_OWNERSHIP_SCHEMA = "secp.worker-enrollment.local-ownership/v1"

#: Every field of the binding, in the order a reviewer reads them. Used to validate an on-disk
#: document exactly: a missing key and an unexpected key are both refusals, so a document cannot
#: acquire meaning nothing here understands.
_OWNERSHIP_FIELDS = (
    "schema",
    "controller_installation_id",
    "controller_key_id",
    "controller_origin",
    "worker_key_id",
    "binding_generation",
)


def _reject(reason_code: str) -> None:
    raise WorkerEnrollmentDriverError(reason_code)


@dataclass(frozen=True)
class WorkerControllerOwnership:
    """Who owns this worker. PUBLIC identities only; frozen so a loaded record cannot be edited."""

    controller_installation_id: str
    controller_key_id: str
    controller_origin: str
    worker_key_id: str
    #: Increments only through an explicit LOCAL reset followed by a new enrollment. It exists so an
    #: operator can tell a re-claimed worker from one that was never reset, and it is deliberately
    #: NOT something a controller can set.
    binding_generation: int = 1

    def __repr__(self) -> str:
        # Identities are public, but a repr that dumps them into a log invites them into evidence
        # and error text where the redaction rules assume no identity is present.
        return f"WorkerControllerOwnership(controller={self.controller_installation_id!r})"

    def canonical(self) -> dict[str, object]:
        return {"schema": WORKER_OWNERSHIP_SCHEMA, **asdict(self)}

    def matches(self, other: WorkerControllerOwnership) -> bool:
        """Exact equality across EVERY field. No field is 'informational'.

        Written as a whole-record comparison rather than a list of the fields that "matter",
        because deciding which identity may differ is how a re-claim becomes possible: an attacker
        needs only one field to be the excluded one.
        """
        return self.canonical() == other.canonical()


def _decode(raw: bytes) -> WorkerControllerOwnership:
    """Parse and fully validate a document. Every failure is CORRUPT, never absent."""
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise WorkerEnrollmentDriverError("enrollment_ownership_corrupt") from None
    if not isinstance(parsed, dict) or set(parsed) != set(_OWNERSHIP_FIELDS):
        _reject("enrollment_ownership_corrupt")
    if parsed.get("schema") != WORKER_OWNERSHIP_SCHEMA:
        _reject("enrollment_ownership_schema_unknown")
    generation = parsed.get("binding_generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        _reject("enrollment_ownership_corrupt")
    values = {k: v for k, v in parsed.items() if k not in ("schema", "binding_generation")}
    for value in values.values():
        if not isinstance(value, str) or not value.strip():
            _reject("enrollment_ownership_corrupt")
    return WorkerControllerOwnership(binding_generation=generation, **values)


def load_worker_ownership(fs: FilesystemBackend) -> WorkerControllerOwnership | None:
    """The owner of this worker, or ``None`` if there genuinely is none.

    ``None`` means the document is ABSENT. Every other failure raises, because a caller that
    receives ``None`` proceeds to bind a new owner, and reaching that state through corruption is
    exactly the attack this module exists to stop.
    """
    st = fs.lstat(WORKER_OWNERSHIP_PATH)
    if st is None:
        return None
    require_protected_file_stat(st, mode=_OWNERSHIP_MODE, reason="enrollment_ownership")
    try:
        raw = fs.safe_read(WORKER_OWNERSHIP_PATH, max_bytes=_MAX_OWNERSHIP_BYTES, expected_uid=0)
    except Exception:
        # An unreadable document is NOT an absent one. Refusing here is what keeps a filesystem
        # fault from presenting as an unowned worker.
        raise WorkerEnrollmentDriverError("enrollment_ownership_unreadable") from None
    return _decode(raw)


def install_worker_ownership(
    fs: FilesystemBackend, ownership: WorkerControllerOwnership
) -> WorkerControllerOwnership:
    """Bind an owner to an UNOWNED worker, atomically. Idempotent for the identical owner.

    Exclusive install, so an existing document is never adopted or overwritten by this path — a
    change of owner is only ever the explicit local reset. If a document already exists it is
    loaded and compared: identical is a no-op (the exact controller retrying an interrupted
    enrollment), and anything else refuses.
    """
    existing = load_worker_ownership(fs)
    if existing is not None:
        if not existing.matches(ownership):
            _reject("enrollment_ownership_already_bound")
        return existing

    payload = canonical_json(ownership.canonical()).encode("ascii")
    receipt: ExclusiveFileReceipt | None = None
    try:
        receipt = fs.exclusive_install(
            WORKER_OWNERSHIP_PATH, payload, uid=0, gid=0, mode=_OWNERSHIP_MODE
        )
        # Prove what is ON DISK decodes to the intended record, rather than trusting what was held
        # in memory — the same read-back the protected key pair performs.
        written = load_worker_ownership(fs)
        if written is None or not written.matches(ownership):
            _reject("enrollment_ownership_install_changed")
        if not fs.created_file_matches(receipt):
            _reject("enrollment_ownership_install_changed")
    except Exception as exc:
        if receipt is not None:
            try:
                if not fs.remove_created_file(receipt):
                    raise WorkerEnrollmentDriverError(
                        "enrollment_ownership_compensation_failed"
                    ) from None
            except WorkerEnrollmentDriverError:
                raise
            except Exception:
                raise WorkerEnrollmentDriverError(
                    "enrollment_ownership_compensation_failed"
                ) from None
        if isinstance(exc, WorkerEnrollmentDriverError):
            raise
        raise WorkerEnrollmentDriverError("enrollment_ownership_install_failed") from None
    return ownership


def clear_worker_ownership(fs: FilesystemBackend, *, write: bool, confirm: bool) -> bool:
    """The LOCAL, privileged, destructive release of ownership. Returns whether a record was removed.

    Gated by the same explicit ``write`` + ``confirm`` pair the key provisioning uses, so it cannot
    happen as a side effect of anything. There is deliberately no controller-supplied argument and
    no network in this function's reach: the only mechanism by which a worker changes hands is a
    person with root on the worker deciding so.

    It removes the binding only. Rotating the enrollment key and clearing the stale retry hints are
    the caller's remaining steps, kept separate because a partial reset must be visible as such
    rather than hidden inside one function that half-succeeded.
    """
    if not write:
        _reject("enrollment_ownership_write_authority_required")
    if not confirm:
        _reject("enrollment_ownership_confirmation_required")
    st = fs.lstat(WORKER_OWNERSHIP_PATH)
    if st is None:
        return False
    # Held to the same contract even on the way out: refusing to unlink an object that is not the
    # expected protected regular file means a planted symlink is never followed during a reset.
    require_protected_file_stat(st, mode=_OWNERSHIP_MODE, reason="enrollment_ownership")
    try:
        fs.remove_file(WORKER_OWNERSHIP_PATH)
    except Exception:
        raise WorkerEnrollmentDriverError("enrollment_ownership_reset_failed") from None
    if fs.lstat(WORKER_OWNERSHIP_PATH) is not None:
        _reject("enrollment_ownership_reset_failed")
    return True


__all__ = [
    "WORKER_OWNERSHIP_PATH",
    "WORKER_OWNERSHIP_SCHEMA",
    "WorkerControllerOwnership",
    "clear_worker_ownership",
    "install_worker_ownership",
    "load_worker_ownership",
]
