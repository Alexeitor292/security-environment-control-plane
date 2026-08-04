"""The enrollment + identity stages: one invitation, two hosts, the real supported interfaces.

WHAT THIS MODULE DRIVES
-----------------------
Nothing here simulates the product. Every effect is a real ``secpctl`` invocation inside a real
host, and the two hosts are genuinely two machines (the fleet stage proves that before this module
runs). The supported surfaces, verified against the CLI parser rather than against documentation:

``secpctl enrollment invite create|status|revoke``  controller side, ``_add_enrollment_parser``
``secpctl worker enroll|enrollment status|retry``   worker side, ``_add_worker_parser``

Note the group name: it is ``enrollment invite create``. ``invitation create`` does not exist, and a
harness written against the wrong name would refuse at the parser and be indistinguishable from a
product that could not create an invitation.

THE SUPPORTED ARTIFACT PATH
---------------------------
The invitation travels as a FILE, and this module transports it the way an operator does: capture
the ``--json`` report of ``enrollment invite create`` on the controller, write those exact bytes to
a file on the worker, and point ``secpctl worker enroll --invitation`` at it. The bytes are never
reshaped, so what the worker validates through
:func:`~secp_management.enrollment_cli.load_invitation_file` is what the operator was handed.

The two hosts share no filesystem. The invitation crosses as bytes held briefly in this process,
which is the only thing that ever crosses, and it is public material by construction.

ONE-SHOT SEMANTICS ARE RESPECTED, NOT WORKED AROUND
---------------------------------------------------
The invitation is captured ONCE, from the one response that ever carries it. This module has no
re-fetch path and must not grow one: ``enrollment status`` deliberately returns a status projection
with no invitation material in it, and that deliberate absence is what
:func:`observe_invitation_is_not_refetchable` measures.

IDENTITY SEPARATION
-------------------
Every cross-host identity comparison is between two values the two sides derived INDEPENDENTLY. The
worker's key id is computed ON THE WORKER, by the worker host's own installed
:func:`~secp_commissioning.enrollment_attestation.key_id_for`, from the public anchor at the
reviewed path; the controller's view comes from ``secpctl enrollment status``. A match then means
the controller learned the worker's identity through the exchange. If instead the harness computed
one value and compared it with itself, the check would pass on a fleet where enrollment never
happened — which is the exact failure this program exists to prevent.

The worker's PRIVATE key is never read, never digested in this process, and never transported. The
only thing that leaves the worker is a SHA-256 of the key file, computed on the worker; a digest of
32 random bytes discloses nothing, and it is what lets :func:`observe_private_key_containment` make
a real negative claim without moving the thing under test.

REVIEWED LITERALS, NOT IMPORTS
------------------------------
The product paths and the three identity derivations below are FIXED literals that byte-match the
product's own constants, following the idiom
:mod:`secp_worker.enrollment_health_probes` already uses for the two management document paths. The
harness therefore does not import the management or API planes at run time, and
``apps/acceptance/tests/test_acceptance_enrollment_derivations.py`` — which may import both — proves
the byte-match, so the two cannot drift silently.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from secp_commissioning.descriptor import scan_forbidden

from secp_acceptance import AcceptanceError
from secp_acceptance.hosts import Host, HostFleet
from secp_acceptance.shell import Result, run

# --------------------------------------------------------------------------- reviewed literals

#: The customer-facing management entrypoint (``[project.scripts] secpctl``).
SECPCTL = "secpctl"

#: The host interpreter. ``infra/acceptance/Dockerfile.host`` installs Ubuntu's python3 here, and
#: the reviewed broker entrypoint already depends on that exact path, so this is not a new
#: assumption the harness introduces. It is deliberately NOT the worker CONTAINER's interpreter —
#: see the long warning in ``infra/acceptance/Dockerfile.host``.
HOST_PYTHON = "/usr/bin/python3"

#: The worker's host-local enrollment state, byte-matching ``secp_worker.enrollment_key`` and
#: ``secp_worker.enrollment_state_store``.
WORKER_ENROLLMENT_ROOT = "/var/lib/secp/worker-enrollment"
WORKER_ENROLLMENT_PRIVATE_PATH = f"{WORKER_ENROLLMENT_ROOT}/enrollment-signing-key"
WORKER_ENROLLMENT_PUBLIC_PATH = f"{WORKER_ENROLLMENT_ROOT}/enrollment-key.pub"
WORKER_ENROLLMENT_STATE_DIR = f"{WORKER_ENROLLMENT_ROOT}/state"

#: The management bootstrap's durable worker records, byte-matching
#: ``secp_worker.enrollment_health_probes``. Read only to project the installed release.
MANAGEMENT_WORKER_IDENTITY_PATH = "/var/lib/secp/bootstrap/worker-identity.json"

#: The protected controller-API locator, byte-matching ``secp_management.controller_api_locator``.
CONTROLLER_API_LOCATOR_PATH = "/etc/secp/controller/api-locator.json"

#: The controller-side roots the product writes its own durable state under. The containment search
#: is bounded to these on purpose: an unbounded walk of the whole host would spend minutes in the
#: nested Docker image store and still not settle the question it is asked (see the residual named
#: in :func:`observe_private_key_containment`).
CONTROLLER_STATE_ROOTS: tuple[str, ...] = (
    "/etc/secp",
    "/var/lib/secp",
    "/opt/secp",
    "/run/secp",
)

#: Where the harness lands the invitation on the WORKER host. Run-scoped and under ``/run``, so it
#: does not survive the host and cannot be mistaken for managed state.
INVITATION_HOST_DIR = "/run/secp-acceptance"
INVITATION_HOST_PATH = f"{INVITATION_HOST_DIR}/invitation.json"

#: The documented opt-in operator-token seam (``secp_management.operator_auth``). The acceptance run
#: uses it because ``secpctl auth login`` is a device-authorization grant needing an OS keystore and
#: a human approval at the IdP; see the gap this module's callers must declare.
OPERATOR_TOKEN_FILE_ENV = "SECP_OPERATOR_TOKEN_FILE"

#: The enrollment API prefix, byte-matching ``secp_management.enrollment_controller_client``.
ENROLLMENT_API_PREFIX = "/api/v1/enrollment"

#: The exact grammar ``HttpsEnrollmentControllerClient._valid_enrollment_id`` enforces. Applied here
#: too, so a malformed id from a report is a bounded harness refusal instead of an argv the CLI has
#: to reject.
_ENROLLMENT_ID = re.compile(r"sha256:[0-9a-f]{64}")

#: The fields the worker's loader requires (``enrollment_cli._REQUIRED_INVITATION_KEYS``).
REQUIRED_INVITATION_KEYS: tuple[str, ...] = (
    "enrollment_id",
    "invitation_id",
    "controller_installation_id",
    "controller_key_id",
    "controller_origin",
    "transaction_id",
    "release_digest",
    "expires_at",
    "controller_ca_bundle_pem",
)

#: Invitation fields that are REDEEMABLE — the ones that make a re-fetch equivalent to a second
#: invitation. ``invitation_is_one_shot`` asserts a status read carries none of them.
REDEEMABLE_INVITATION_KEYS: frozenset[str] = frozenset(
    {
        "invitation_id",
        "controller_ca_bundle_pem",
        "controller_trust_anchor_hex",
        "controller_key_id",
        "transaction_id",
    }
)

#: The controller-authoritative state a completed enrollment must reach
#: (``enrollment_cli._STATE_HEALTHY``).
STATE_HEALTHY = "healthy"

#: The bounded walk cap. A search that hit its cap has NOT proven absence, so
#: :func:`observe_private_key_containment` reports it incomplete rather than clean.
_MAX_SCANNED_FILES = 20000
_MAX_SCANNED_FILE_BYTES = 16 * 1024 * 1024


# --------------------------------------------------------------------------- reviewed derivations
#
# Three one-line derivations, held here as reviewed literals rather than imported across a plane
# boundary. Each is guard-tested byte-for-byte against the product function named in its docstring.

_HEX64 = re.compile(r"[0-9a-f]{64}")


def status_fingerprint(value: str) -> str:
    """The controller status projection's display fingerprint.

    Byte-matches ``secp_api.worker_enrollment_contract._fingerprint``. The conditional is part of
    the contract and is reproduced exactly: a short non-hex tail renders EMPTY, and an empty
    rendering must never be compared equal to an empty observation, or two absent identities would
    read as a match.
    """
    if not value:
        return ""
    tail = value.split(":", 1)[-1]
    return tail[:12] if _HEX64.fullmatch(tail) or len(tail) >= 12 else ""


def worker_installation_label(worker_key_id: str) -> str:
    """The worker installation label the worker REPORTS to the controller.

    Byte-matches ``secp_worker.enrollment_http_transport._installation_from_key``. Read this twice
    before changing it: the label is derived from the worker's ENROLLMENT KEY, not from the
    management bootstrap's ``installation_id`` in ``worker-identity.json``. Comparing the controller
    against the bootstrap id would compare two unrelated values and could only ever fail — the
    quiet, permanent kind of failure that gets explained away rather than fixed.
    """
    return "worker-" + worker_key_id.split(":", 1)[-1][:16]


def controller_key_fingerprint(controller_key_id: str) -> str:
    """The human-comparable controller fingerprint ``secpctl worker enroll`` shows on a dry run.

    Byte-matches ``secp_management.enrollment_cli.controller_key_fingerprint``.
    """
    body = controller_key_id.split(":", 1)[-1]
    return " ".join(body[i : i + 8] for i in range(0, min(len(body), 32), 8))


# --------------------------------------------------------------------------- the host seam
#
# `Host.exec` cannot carry an environment, and the operator-token seam is an environment variable,
# so these compose the docker argv directly through the same bounded `shell.run` every other host
# effect goes through: an argv LIST, shell=False, bounded output, no shell string anywhere. Every
# interpolated value is a module constant or a value this module has already validated against a
# closed grammar.


def host_exec(
    host: Host,
    argv: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    timeout: int = 300,
) -> Result:
    """Run one command inside a host, optionally with environment variables."""
    prefix: list[str] = ["docker", "exec"]
    for name, value in (env or {}).items():
        prefix += ["--env", f"{name}={value}"]
    return run((*prefix, host.container, *argv), timeout=timeout)


def host_python(
    host: Host,
    script: str,
    args: Sequence[str] = (),
    *,
    timeout: int = 300,
) -> Result:
    """Run a HARNESS-AUTHORED python program inside a host, with its inputs as argv.

    The program arrives on stdin and its inputs arrive as argv, so nothing is ever interpolated into
    a source string — the same property :meth:`Host.exec_as_script` preserves for shell, kept for
    the cases where a shell cannot express the observation (a stat projection, a digest walk).
    """
    return run(
        ("docker", "exec", "-i", host.container, HOST_PYTHON, "-", *args),
        timeout=timeout,
        stdin_bytes=script.encode("utf-8"),
    )


def _parse_json(result: Result, *, reason: str) -> Any:
    """Parse a bounded JSON payload from a completed process. The raw output never enters the error:
    it routinely carries host paths and origins."""
    if not result.ok:
        raise AcceptanceError(reason)
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise AcceptanceError("acceptance_observation_malformed") from None


def secpctl_json(
    host: Host,
    argv: Sequence[str],
    *,
    token_path: str | None = None,
    timeout: int = 900,
) -> tuple[int, dict]:
    """Run ``secpctl --json <argv>`` inside a host and return its ``(exit_code, report)``.

    A refusal is a RESULT here, not an exception: every enrollment command returns a bounded report
    with a ``reason_code`` on the refusal paths, and the caller needs that code to record the check
    honestly. Only an unparseable report is an error.
    """
    env = {OPERATOR_TOKEN_FILE_ENV: token_path} if token_path else None
    result = host_exec(host, (SECPCTL, "--json", *argv), env=env, timeout=timeout)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise AcceptanceError("acceptance_observation_malformed") from None
    if not isinstance(report, dict):
        raise AcceptanceError("acceptance_observation_malformed")
    return result.exit_code, report


# --------------------------------------------------------------------------- outcome classification
#
# THE DISTINCTION THIS SECTION EXISTS FOR
# ---------------------------------------
# "The harness could not look" and "the harness looked and found the bad thing" are different
# results, and collapsing them is how a positively-observed defect gets filed as an absence of
# evidence. Every classifier below is a pure function of an observation dict, so which of the three
# it returns is testable without a fleet.
#
# The rule, applied uniformly: if the producer can distinguish observed-false from could-not-look,
# then observed-false is VIOLATED. Severity lives in the reason code, never in the outcome.
#
# WHY THE OUTCOME STRING IS A LOCAL CONSTANT
# ------------------------------------------
# ``violated`` is not yet in this tree's ``secp_acceptance.reasons`` vocabulary — it arrives
# with the evidence stream's contract. Rather than guess at an import that does not resolve, the
# value is held here, and a guard test pins it against the real vocabulary the moment that
# vocabulary carries it while still asserting something true about the vocabulary as it stands.

OUTCOME_OBSERVED = "observed"
OUTCOME_UNPROVEN = "unproven"
OUTCOME_VIOLATED = "violated"

#: Reason codes for the two non-positive outcomes. A ``violated`` reason MUST be a HARNESS reason:
#: the harness is reporting what it saw, and attributing that observation to a PRODUCT refusal code
#: would say the product refused when it did not.
#:
#: This tree has no harness code meaning "the harness observed the condition this check rules out" —
#: the closest, ``acceptance_observation_malformed``, describes a broken observation rather than a
#: sound observation of a broken thing. So the intended codes are named here and listed as PENDING;
#: a guard test asserts exactly which are still missing, and will fail when they land under other
#: names rather than letting a wrong code ship quietly.
REASON_COULD_NOT_LOOK = "acceptance_observation_unavailable"
REASON_OBSERVATION_MALFORMED = "acceptance_observation_malformed"
REASON_IDENTITY_DISAGREES = "acceptance_cross_host_identity_disagrees"
REASON_PRIVATE_KEY_ESCAPED = "acceptance_worker_private_key_escaped"
REASON_INVITATION_REFETCHABLE = "acceptance_invitation_refetchable"
REASON_RELEASE_DISAGREES = "acceptance_enrolled_release_disagrees"

#: The codes above that this tree's ``HARNESS_REASONS`` does not yet carry. Not a wish list — the
#: guard test recomputes it, so it shrinks on its own as the vocabulary grows and cannot drift.
PENDING_HARNESS_REASONS: frozenset[str] = frozenset(
    {
        REASON_IDENTITY_DISAGREES,
        REASON_PRIVATE_KEY_ESCAPED,
        REASON_INVITATION_REFETCHABLE,
        REASON_RELEASE_DISAGREES,
    }
)


@dataclass(frozen=True)
class CheckVerdict:
    """One check's three-valued outcome plus its bounded reason.

    ``reason_code`` is REQUIRED for everything except ``observed`` and FORBIDDEN for ``observed`` —
    the same rule :class:`~secp_acceptance.evidence.CheckRecord` enforces, applied at the point the
    verdict is decided so a malformed pair cannot reach the recorder at all.
    """

    outcome: str
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.outcome == OUTCOME_OBSERVED and self.reason_code is not None:
            raise AcceptanceError("acceptance_evidence_invalid")
        if self.outcome != OUTCOME_OBSERVED and not self.reason_code:
            raise AcceptanceError("acceptance_evidence_invalid")

    @property
    def is_pass(self) -> bool:
        """Only a positive observation passes. ``violated`` and ``unproven`` are both failures, for
        different reasons, and neither is ever a pass."""
        return self.outcome == OUTCOME_OBSERVED


def classify_private_key_containment(observed: Mapping[str, object]) -> CheckVerdict:
    """Three-valued verdict for ``worker_private_key_never_left_worker``.

    Finding the key material on the controller is an OBSERVATION, not a failure to observe — the
    scan ran, completed, and found it. Filing that as ``unproven`` would report the strongest
    possible negative result as an absence of evidence.
    """
    if not observed.get("key_digest_observed"):
        return CheckVerdict(OUTCOME_UNPROVEN, REASON_COULD_NOT_LOOK)
    if not observed.get("controller_scan_complete"):
        # A truncated walk did not look everywhere it claimed to, so it can neither clear nor
        # convict. This is the one branch that must NOT become `violated`.
        return CheckVerdict(OUTCOME_UNPROVEN, REASON_COULD_NOT_LOOK)
    if observed.get("contained"):
        return CheckVerdict(OUTCOME_OBSERVED)
    return CheckVerdict(OUTCOME_VIOLATED, REASON_PRIVATE_KEY_ESCAPED)


def classify_invitation_one_shot(
    observed: Mapping[str, object], *, status_readable: bool
) -> CheckVerdict:
    """Three-valued verdict for ``invitation_is_one_shot``.

    A status read that SUCCEEDED and carried redeemable invitation material is a positive
    observation that the invitation is re-fetchable — the property the check exists to rule out.
    """
    if not status_readable:
        return CheckVerdict(OUTCOME_UNPROVEN, REASON_COULD_NOT_LOOK)
    if observed.get("not_refetchable"):
        return CheckVerdict(OUTCOME_OBSERVED)
    return CheckVerdict(OUTCOME_VIOLATED, REASON_INVITATION_REFETCHABLE)


def classify_identity_agreement(observed: Mapping[str, object]) -> CheckVerdict:
    """Three-valued verdict for the two cross-host identity checks.

    A DISAGREEMENT is not an absence of evidence: both sides produced an identity and they are not
    the same one, which means the controller recorded an identity that is not this worker's. That is
    the condition the check exists to rule out, so it is ``violated``.

    Either side being absent IS an absence of evidence — the exchange may simply never have reached
    the controller — so that is ``unproven``.
    """
    if not observed.get("derived_present") or not observed.get("recorded_present"):
        return CheckVerdict(OUTCOME_UNPROVEN, REASON_COULD_NOT_LOOK)
    if observed.get("agree"):
        return CheckVerdict(OUTCOME_OBSERVED)
    return CheckVerdict(OUTCOME_VIOLATED, REASON_IDENTITY_DISAGREES)


def classify_release_agreement(observed: Mapping[str, object]) -> CheckVerdict:
    """Three-valued verdict for ``enrolled_release_equals_installed_release``.

    READ THIS BEFORE CHANGING IT TO ``unproven``. Both digests are read from their own authority,
    and when both are present and differ the harness has SETTLED the question — it has not failed to
    look. Under the program's own eligibility rule (can the producer distinguish observed-false from
    could-not-look?) that is ``violated``.

    This matters because the divergence is the program's most consequential product finding.
    ``unproven`` would report a measured, reproducible disagreement as "we could not tell", which
    understates it in precisely the direction that gets a finding deprioritised.

    ``unproven`` remains correct when a digest could not be READ at all — an unbootstrapped worker,
    or an invitation that was never created.
    """
    if not observed.get("installed_present") or not observed.get("enrolled_present"):
        return CheckVerdict(OUTCOME_UNPROVEN, REASON_COULD_NOT_LOOK)
    if observed.get("agree"):
        return CheckVerdict(OUTCOME_OBSERVED)
    return CheckVerdict(OUTCOME_VIOLATED, REASON_RELEASE_DISAGREES)


# --------------------------------------------------------------------------- the invitation


@dataclass(frozen=True)
class InvitationArtifact:
    """The invitation exactly as the operator received it, plus its parsed report.

    ``raw`` is the byte-for-byte stdout of ``enrollment invite create --json``. Those are the bytes
    written to the worker: the harness reshapes nothing, so the file the worker validates is the
    file the operator was handed.
    """

    raw: bytes
    report: dict

    @property
    def enrollment_id(self) -> str:
        return str(self.report["enrollment_id"])

    def projection(self) -> dict[str, object]:
        """The bounded, secret-free projection of the invitation.

        Deliberately narrow. The CA chain is public but large, the origin is a host address, and
        neither belongs in an observation; their PRESENCE and shape are what the check asserts.
        """
        return {
            "mode": self.report.get("mode"),
            "state": self.report.get("state"),
            "revision": self.report.get("revision"),
            "required_fields_present": sorted(
                key for key in REQUIRED_INVITATION_KEYS if self.report.get(key)
            ),
            "enrollment_id_wellformed": bool(_ENROLLMENT_ID.fullmatch(self.enrollment_id)),
            "ca_chain_present": bool(str(self.report.get("controller_ca_bundle_pem", "")).strip()),
            "carries_no_secret_material": self.carries_no_secret_material(),
        }

    def carries_no_secret_material(self) -> bool:
        """The invitation is the ONE artifact that crosses hosts, so it gets the product's own
        forbidden-material scan. A private key pasted into it would refuse here rather than being
        transported."""
        try:
            scan_forbidden(self.report)
        except Exception:  # noqa: BLE001 - any refusal is a failed observation, bounded
            return False
        return True


def create_invitation(
    controller: Host,
    *,
    site_label: str,
    ttl_seconds: int,
    token_path: str,
) -> tuple[int, InvitationArtifact | dict]:
    """``secpctl enrollment invite create --write --confirm`` on the controller host.

    Returns ``(exit_code, artifact)`` on success and ``(exit_code, report)`` on a refusal, so the
    caller records the product's own reason code rather than a harness paraphrase of it.

    The idempotency key is NOT supplied: ``invite_create`` generates its own and reuses it only
    across its own bounded lost-response retry. Supplying one here would be the harness taking over
    a retry-safety property that belongs to the product.
    """
    env = {OPERATOR_TOKEN_FILE_ENV: token_path}
    result = host_exec(
        controller,
        (
            SECPCTL,
            "--json",
            "enrollment",
            "invite",
            "create",
            "--site",
            site_label,
            "--ttl-seconds",
            str(int(ttl_seconds)),
            "--write",
            "--confirm",
        ),
        env=env,
        timeout=900,
    )
    report = _parse_report(result)
    if result.exit_code != 0 or report.get("mode") != "written":
        return result.exit_code, report
    missing = [key for key in REQUIRED_INVITATION_KEYS if not report.get(key)]
    if missing or not _ENROLLMENT_ID.fullmatch(str(report.get("enrollment_id", ""))):
        # A "successful" create whose report cannot be redeemed is not a success. Surfacing it as a
        # malformed observation keeps it out of the transfer step, where it would fail much later
        # with nothing pointing back here.
        raise AcceptanceError("acceptance_observation_malformed")
    return result.exit_code, InvitationArtifact(raw=result.stdout.encode("utf-8"), report=report)


def _parse_report(result: Result) -> dict:
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise AcceptanceError("acceptance_observation_malformed") from None
    if not isinstance(report, dict):
        raise AcceptanceError("acceptance_observation_malformed")
    return report


def deliver_invitation(worker: Host, artifact: InvitationArtifact) -> str:
    """Write the invitation onto the WORKER host and return its path there.

    This is the whole hand-off. The two hosts share no mount, so the bytes cross only through this
    process, and they cross unchanged. Delivering a reshaped invitation would prove that the harness
    can construct a file the worker accepts — not that the operator's artifact is usable.
    """
    worker.exec(("mkdir", "-p", INVITATION_HOST_DIR), check=True)
    worker.write_file(INVITATION_HOST_PATH, artifact.raw, mode="0644")
    return INVITATION_HOST_PATH


def observe_invitation_delivery(worker: Host, artifact: InvitationArtifact) -> dict[str, object]:
    """Prove the delivered file is byte-identical to what the controller emitted.

    Read back from the worker rather than trusted from the write call: a transfer that silently
    truncated would otherwise surface as an opaque validation failure inside ``worker enroll``.
    """
    landed = worker.read_file(INVITATION_HOST_PATH)
    return {
        "delivered": landed == artifact.raw,
        "bytes": len(artifact.raw),
        "path_is_run_scoped": INVITATION_HOST_PATH.startswith("/run/"),
    }


# --------------------------------------------------------------------------- enrollment stage


def worker_enroll_dry_run(worker: Host, invitation_path: str) -> tuple[int, dict]:
    """``secpctl worker enroll --invitation <path>`` with NO write gates.

    This is where an operator verifies the controller identity out of band before committing the
    worker to it, so the report must carry the fingerprint. It also mutates nothing, which is the
    property that makes running it first safe.
    """
    return secpctl_json(worker, ("worker", "enroll", "--invitation", invitation_path))


def observe_enroll_dry_run(report: dict, artifact: InvitationArtifact) -> dict[str, object]:
    """The dry run showed the fingerprint, and it is the fingerprint of the INVITATION's pinned
    controller key — recomputed here from the artifact rather than read back from the same report,
    so the check cannot pass by comparing the report with itself."""
    expected = controller_key_fingerprint(str(artifact.report["controller_key_id"]))
    shown = str(report.get("controller_key_fingerprint", ""))
    return {
        "mode": report.get("mode"),
        "fingerprint_shown": bool(shown),
        "fingerprint_matches_invitation": bool(shown) and shown == expected,
        "no_mutation_claimed": report.get("mode") == "dry_run",
    }


def worker_enroll(worker: Host, invitation_path: str) -> tuple[int, dict]:
    """``secpctl worker enroll --invitation <path> --write --confirm`` — the real drive.

    Reaching here is what authorizes the key seam to CREATE the worker's enrollment key if it does
    not exist; with a key already provisioned the seam is a pure read.
    """
    return secpctl_json(
        worker,
        ("worker", "enroll", "--invitation", invitation_path, "--write", "--confirm"),
        timeout=900,
    )


def worker_enrollment_status(worker: Host, invitation_path: str) -> tuple[int, dict]:
    """``secpctl worker enrollment status`` — read-only local reconciliation.

    Its ``state`` is the LOCAL restart marker (``unknown``/``offer_verified``/``healthy``), not the
    controller's authoritative state. Treating it as the latter would let a stale local marker read
    as a healthy enrollment.
    """
    return secpctl_json(worker, ("worker", "enrollment", "status", "--invitation", invitation_path))


def controller_enrollment_status(
    controller: Host, *, enrollment_id: str, token_path: str
) -> tuple[int, dict]:
    """``secpctl enrollment status --enrollment-id <id>`` — the controller's authoritative view."""
    if not _ENROLLMENT_ID.fullmatch(enrollment_id):
        raise AcceptanceError("acceptance_observation_malformed")
    return secpctl_json(
        controller,
        ("enrollment", "status", "--enrollment-id", enrollment_id),
        token_path=token_path,
    )


def observe_controller_state(report: dict) -> dict[str, object]:
    """The bounded projection of the controller's authoritative enrollment state."""
    return {
        "state": report.get("state"),
        "revision": report.get("revision"),
        "healthy": report.get("state") == STATE_HEALTHY,
        "refusal_reason": report.get("refusal_reason") or "",
        "worker_identity_recorded": bool(report.get("worker_key_fingerprint")),
    }


def observe_invitation_is_not_refetchable(status_report: dict) -> dict[str, object]:
    """The one-shot property, measured as the property it actually is.

    ``enrollment status`` is the only supported read of an enrollment after creation, and it carries
    NONE of the redeemable invitation fields. That absence is the whole mechanism: an operator who
    loses the invitation cannot ask for it again, so a leaked status read is not a leaked
    invitation.

    This deliberately does NOT claim "a second, different worker cannot redeem it". Proving that
    needs a third identity the two-host fleet does not have, and manufacturing a second worker key
    in the harness would be a mock standing in for the adversary — the shape of proof this program
    refuses. Callers declare that limit as a gap.
    """
    present = sorted(key for key in REDEEMABLE_INVITATION_KEYS if status_report.get(key))
    return {
        "redeemable_fields_in_status": present,
        "not_refetchable": not present,
        "status_fields": sorted(k for k in status_report if k not in ("command", "mode")),
    }


# --------------------------------------------------------------------------- identity stage

_STAT_SCRIPT = """
import json, os, stat, sys
out = []
for path in sys.argv[1:]:
    try:
        st = os.lstat(path)
    except OSError:
        out.append({"present": False})
        continue
    out.append({
        "present": True,
        "regular": bool(stat.S_ISREG(st.st_mode)),
        "symlink": bool(stat.S_ISLNK(st.st_mode)),
        "directory": bool(stat.S_ISDIR(st.st_mode)),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.S_IMODE(st.st_mode),
        "nlink": st.st_nlink,
    })
sys.stdout.write(json.dumps(out))
"""


def _stat_paths(host: Host, paths: Sequence[str]) -> list[dict]:
    observed = _parse_json(
        host_python(host, _STAT_SCRIPT, paths), reason="acceptance_observation_unavailable"
    )
    if not isinstance(observed, list) or len(observed) != len(paths):
        raise AcceptanceError("acceptance_observation_malformed")
    return observed


def observe_worker_enrollment_key(worker: Host) -> dict[str, object]:
    """The protected key pair exists at the reviewed paths with the reviewed protection.

    A bounded metadata projection only: type, ownership, mode, link count. The key bytes are never
    read by the harness — the point of the check is that they are protected, and reading them to
    prove it would be the harness doing the thing it is checking nobody does.
    """
    private, public, root, state = _stat_paths(
        worker,
        (
            WORKER_ENROLLMENT_PRIVATE_PATH,
            WORKER_ENROLLMENT_PUBLIC_PATH,
            WORKER_ENROLLMENT_ROOT,
            WORKER_ENROLLMENT_STATE_DIR,
        ),
    )
    return {
        "private_protected": _is_protected_file(private, mode=0o600),
        "public_present": _is_protected_file(public, mode=0o644),
        "root_is_private_dir": bool(
            root.get("present")
            and root.get("directory")
            and not root.get("symlink")
            and root.get("uid") == 0
            and root.get("gid") == 0
            and root.get("mode") == 0o700
        ),
        "state_dir_present": bool(state.get("present") and state.get("directory")),
        "private_mode": private.get("mode"),
        "private_uid": private.get("uid"),
        "private_nlink": private.get("nlink"),
    }


def _is_protected_file(observed: Mapping[str, object], *, mode: int) -> bool:
    """A plain, unlinked, root-owned file at the EXACT reviewed mode — the same predicate
    ``secp_worker.enrollment_key._require_stat`` applies before it will trust the pair."""
    return bool(
        observed.get("present")
        and observed.get("regular")
        and not observed.get("symlink")
        and not observed.get("directory")
        and observed.get("nlink") == 1
        and observed.get("uid") == 0
        and observed.get("gid") == 0
        and observed.get("mode") == mode
    )


_KEY_ID_SCRIPT = """
import json, sys
from secp_commissioning.enrollment_attestation import key_id_for
with open(sys.argv[1], "rb") as handle:
    raw = handle.read(65)
sys.stdout.write(json.dumps({"key_id": key_id_for(raw.decode("ascii").strip())}))
"""


def observe_worker_key_identity(worker: Host) -> dict[str, str]:
    """The worker's enrollment key id, derived ON THE WORKER from its own public anchor.

    Run through the worker host's OWN installed ``key_id_for`` rather than recomputed here. That is
    what makes the later comparison against the controller a comparison between two independent
    derivations instead of a value compared with itself.

    Only the PUBLIC anchor is read (0644 by design, and the authoritative worker identity is the id
    derived from it).
    """
    observed = _parse_json(
        host_python(worker, _KEY_ID_SCRIPT, (WORKER_ENROLLMENT_PUBLIC_PATH,)),
        reason="acceptance_observation_unavailable",
    )
    key_id = observed.get("key_id") if isinstance(observed, dict) else None
    if not isinstance(key_id, str) or not _ENROLLMENT_ID.fullmatch(key_id):
        raise AcceptanceError("acceptance_observation_malformed")
    return {"key_id": key_id}


def observe_key_fingerprint_agreement(
    *, worker_key_id: str, status_report: dict
) -> dict[str, object]:
    """The controller's recorded worker fingerprint equals the one derived from the worker's key.

    An EMPTY controller fingerprint never counts as agreement: two absent identities would otherwise
    compare equal, and a run in which the exchange never reached the controller would report a
    match. The worker side must additionally be a WELL-FORMED key id, so a missing observation
    cannot be projected into a value that happens to match something.
    """
    derived = status_fingerprint(worker_key_id) if _well_formed_key_id(worker_key_id) else ""
    recorded = str(status_report.get("worker_key_fingerprint", ""))
    return {
        "derived_present": bool(derived),
        "recorded_present": bool(recorded),
        "agree": bool(derived) and bool(recorded) and derived == recorded,
    }


def _well_formed_key_id(worker_key_id: str) -> bool:
    """A key id the worker could actually have derived from a real anchor.

    This exists because the two derivations degrade differently on an absent observation:
    :func:`status_fingerprint` returns ``""`` (self-evidently absent) but
    :func:`worker_installation_label` returns ``"worker-"`` — a NON-EMPTY value manufactured from
    nothing, which a bare presence check would happily compare. Gating both on the key id closes
    that asymmetry at the source instead of patching each predicate.
    """
    return bool(_ENROLLMENT_ID.fullmatch(worker_key_id))


def observe_installation_id_agreement(
    *, worker_key_id: str, status_report: dict
) -> dict[str, object]:
    """The controller's recorded worker installation id equals the key-derived label.

    The comparison is against the ENROLLMENT-KEY-derived label, which is what the worker actually
    submits — not the management bootstrap's ``installation_id``. See
    :func:`worker_installation_label`.

    Gated on a well-formed key id: without that gate an ABSENT worker observation still yields the
    non-empty label ``"worker-"``, and a presence check on the derived side would pass on nothing.
    """
    derived = worker_installation_label(worker_key_id) if _well_formed_key_id(worker_key_id) else ""
    recorded = str(status_report.get("worker_installation_id", ""))
    return {
        "derived_present": bool(derived),
        "recorded_present": bool(recorded),
        "agree": bool(derived) and bool(recorded) and derived == recorded,
    }


_FILE_DIGEST_SCRIPT = """
import hashlib, json, sys
out = []
for path in sys.argv[1:]:
    try:
        with open(path, "rb") as handle:
            out.append(hashlib.sha256(handle.read(1 << 20)).hexdigest())
    except OSError:
        out.append("")
sys.stdout.write(json.dumps(out))
"""

#: The caps arrive as argv rather than as literals so the hermetic tests can drive the
#: incompleteness paths with a tiny budget. A test that could only exercise the caps by writing 16
#: MiB would not be written, and the branch that turns a truncated walk into ``complete: false`` is
#: the one this whole check depends on.
_TREE_DIGEST_SCRIPT = """
import hashlib, json, os, sys
MAX_FILES = int(sys.argv[1])
MAX_BYTES = int(sys.argv[2])
digests = set()
files = 0
complete = True
for root in sys.argv[3:]:
    if not os.path.isdir(root):
        continue
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.islink(path):
                    continue
                if os.path.getsize(path) > MAX_BYTES:
                    complete = False
                    continue
                with open(path, "rb") as handle:
                    digests.add(hashlib.sha256(handle.read()).hexdigest())
            except OSError:
                complete = False
                continue
            files += 1
            if files > MAX_FILES:
                complete = False
                break
        if not complete and files > MAX_FILES:
            break
sys.stdout.write(json.dumps({"complete": complete, "files": files,
                             "digests": sorted(digests)}))
"""


def observe_private_key_containment(worker: Host, controller: Host) -> dict[str, object]:
    """The worker's private enrollment key never left the worker.

    Three independent parts, none of which moves the key:

    1. the reviewed enrollment root does not exist on the CONTROLLER host at all, so the exact
       protected path never appeared there;
    2. the SHA-256 of the key file — computed ON THE WORKER, and a digest of 32 random bytes
       discloses nothing — matches no whole file anywhere under the controller's own state roots;
    3. the digest is a real one (an unreadable key yields an empty digest, which must never be
       compared against a set and read as absence).

    THE RESIDUAL, STATED PLAINLY: this catches a whole-file copy. It does NOT catch the key embedded
    inside a larger controller-side blob — a database page, an archive, a log line — because
    searching for embedded bytes requires transporting the private key off the worker, which is the
    very thing under test. Callers declare that limit as a gap rather than let a reader infer a
    stronger claim from a passing check.
    """
    digests = _parse_json(
        host_python(worker, _FILE_DIGEST_SCRIPT, (WORKER_ENROLLMENT_PRIVATE_PATH,)),
        reason="acceptance_observation_unavailable",
    )
    if not isinstance(digests, list) or len(digests) != 1 or not isinstance(digests[0], str):
        raise AcceptanceError("acceptance_observation_malformed")

    (controller_root,) = _stat_paths(controller, (WORKER_ENROLLMENT_ROOT,))
    walk = _parse_json(
        host_python(
            controller,
            _TREE_DIGEST_SCRIPT,
            (str(_MAX_SCANNED_FILES), str(_MAX_SCANNED_FILE_BYTES), *CONTROLLER_STATE_ROOTS),
            timeout=900,
        ),
        reason="acceptance_observation_unavailable",
    )
    if not isinstance(walk, dict) or not isinstance(walk.get("digests"), list):
        raise AcceptanceError("acceptance_observation_malformed")

    return containment_verdict(
        key_digest=digests[0],
        controller_root_present=bool(controller_root.get("present")),
        scan_complete=bool(walk.get("complete")),
        scanned_files=int(walk.get("files", 0)),
        scanned_digests=frozenset(str(d) for d in walk["digests"]),
    )


def containment_verdict(
    *,
    key_digest: str,
    controller_root_present: bool,
    scan_complete: bool,
    scanned_files: int,
    scanned_digests: frozenset[str],
) -> dict[str, object]:
    """The containment conjunction, kept pure so it can be tested without a fleet.

    Two ways this could quietly become a false pass, both closed here:

    * an EMPTY key digest (an unreadable key) is not "a digest that appears nowhere" — it is no
      observation at all, so it can never satisfy ``contained``;
    * an INCOMPLETE scan is not absence. A walk that hit its file cap, or skipped an oversized or
      unreadable file, has not looked everywhere it claimed to, and a verdict built on it would be
      the strongest-sounding check in the stage resting on the weakest evidence.
    """
    absent = bool(key_digest) and key_digest not in scanned_digests
    return {
        "key_digest_observed": bool(key_digest),
        "enrollment_root_absent_on_controller": not controller_root_present,
        "controller_scan_complete": scan_complete,
        "controller_files_scanned": scanned_files,
        "no_whole_file_copy_on_controller": absent,
        "contained": absent and scan_complete and not controller_root_present,
    }


_INSTALLED_RELEASE_SCRIPT = """
import json, sys
try:
    with open(sys.argv[1], "rb") as handle:
        document = json.loads(handle.read(262144).decode("utf-8"))
except (OSError, ValueError):
    document = {}
sys.stdout.write(json.dumps({
    "release_digest": document.get("release_digest", ""),
    "role": document.get("role", ""),
}))
"""


def observe_release_agreement(worker: Host, *, artifact: InvitationArtifact) -> dict[str, object]:
    """The release the enrollment is bound to versus the release actually installed on the worker.

    Both sides are read from their own authority: the invitation's ``release_digest`` (which the
    controller sourced from its ACTIVE enrollment identity) and the management bootstrap's own
    ``worker-identity.json`` on the worker host.

    A reader of a failing result should look at the release contract, not at this harness: the two
    digests are the aggregate content addresses of two DIFFERENT signed manifests — a controller
    manifest and a worker manifest, whose ``role`` field is part of the canonical bytes — so they
    cannot be equal for any pair of bundles that a role-checked install would accept.
    """
    observed = _parse_json(
        host_python(worker, _INSTALLED_RELEASE_SCRIPT, (MANAGEMENT_WORKER_IDENTITY_PATH,)),
        reason="acceptance_observation_unavailable",
    )
    installed = str(observed.get("release_digest", "")) if isinstance(observed, dict) else ""
    enrolled = str(artifact.report.get("release_digest", ""))
    return {
        "installed_present": bool(installed),
        "enrolled_present": bool(enrolled),
        "agree": bool(installed) and installed == enrolled,
        "installed_fingerprint": status_fingerprint(installed),
        "enrolled_fingerprint": status_fingerprint(enrolled),
    }


# --------------------------------------------------------------------------- inventory (API)

_INVENTORY_SCRIPT = """
import json, ssl, sys, urllib.error, urllib.request
locator_path, token_path, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
with open(locator_path, "rb") as handle:
    locator = json.loads(handle.read(4096).decode("utf-8"))
with open(token_path, "rb") as handle:
    bearer = handle.read(8192).decode("ascii").strip()

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

context = ssl.create_default_context(cafile=locator["ca_bundle_path"])
opener = urllib.request.build_opener(
    _NoRedirect(), urllib.request.HTTPSHandler(context=context)
)
request = urllib.request.Request(
    locator["canonical_origin"] + prefix,
    headers={"Accept": "application/json", "Accept-Encoding": "identity",
             "Authorization": "Bearer " + bearer},
)
try:
    with opener.open(request, timeout=15) as response:
        status, raw = response.status, response.read(65536)
except urllib.error.HTTPError as exc:
    status, raw = exc.code, exc.read(65536)
except Exception:
    sys.stdout.write(json.dumps({"status": 0, "items": [], "reachable": False}))
    raise SystemExit(0)
try:
    body = json.loads(raw.decode("utf-8"))
except ValueError:
    body = {}
items = body.get("items") if isinstance(body, dict) else None
sys.stdout.write(json.dumps({
    "status": status,
    "reachable": True,
    "items": [
        {"enrollment_id": item.get("enrollment_id", ""), "state": item.get("state", "")}
        for item in (items if isinstance(items, list) else [])
    ],
}))
"""


def observe_enrollment_inventory(
    controller: Host, *, token_path: str, enrollment_id: str
) -> dict[str, object]:
    """The org-scoped enrollment inventory lists this enrollment.

    THE PROVENANCE OF THIS ONE OBSERVATION IS WEAKER THAN THE OTHERS, AND CALLERS MUST DECLARE IT.
    ``GET /api/v1/enrollment`` is a supported customer interface — it is exactly what the web UI
    calls — but there is no ``secpctl enrollment list`` and
    :class:`~secp_management.enrollment_controller_client.EnrollmentControllerClient` has no list
    method, so this request is harness-authored rather than issued through product client code.

    Everything about the request that CAN be taken from the product is: the origin and CA come from
    the bootstrap-recorded locator, and the bearer comes from the same protected token file the
    product's own client reads. Redirects are refused and only ids and states are projected — never
    a header, an origin, or the bearer.
    """
    observed = _parse_json(
        host_python(
            controller,
            _INVENTORY_SCRIPT,
            (CONTROLLER_API_LOCATOR_PATH, token_path, ENROLLMENT_API_PREFIX),
            timeout=300,
        ),
        reason="acceptance_observation_unavailable",
    )
    if not isinstance(observed, dict):
        raise AcceptanceError("acceptance_observation_malformed")
    raw_items = observed.get("items")
    items: list[dict] = (
        [entry for entry in raw_items if isinstance(entry, dict)]
        if isinstance(raw_items, list)
        else []
    )
    listed = [entry for entry in items if entry.get("enrollment_id") == enrollment_id]
    return {
        "reachable": bool(observed.get("reachable")),
        "status": observed.get("status"),
        "listed": bool(listed),
        "listed_state": str(listed[0].get("state", "")) if listed else "",
        "items_returned": len(items),
    }


# --------------------------------------------------------------------------- restart persistence


def restart_worker_host(fleet: HostFleet, *, timeout_seconds: int = 240) -> dict[str, object]:
    """Restart the WORKER host and wait until it is genuinely usable again.

    A real reboot of that machine: the container is restarted, systemd comes back up as PID 1 and
    the host's own Docker daemon comes back with it. The volume-backed state under
    ``/var/lib/secp`` survives, which is precisely what makes the re-observation afterwards a
    statement about durability rather than about a process that never stopped.

    Readiness is polled through the fleet's OWN :meth:`HostFleet.observe_readiness`, so this waits
    on the same two facts the fleet stage proved in the first place instead of inventing a second,
    weaker definition of "up".

    Handed to the lifecycle stream as the restart driver; this module only needs it to re-observe
    identity, and deliberately records no lifecycle check of its own.
    """
    worker = fleet.worker()
    from secp_acceptance.shell import docker

    restarted = docker("restart", worker.container, timeout=300)
    if not restarted.ok:
        raise AcceptanceError("acceptance_host_command_failed")
    deadline = time.monotonic() + timeout_seconds
    ready: dict[str, object] = {}
    while time.monotonic() < deadline:
        try:
            ready = fleet.observe_readiness(worker)
        except AcceptanceError:
            ready = {}
        if ready.get("systemd_state") in ("running", "degraded") and ready.get("dockerd_answers"):
            return {
                "restarted": True,
                "systemd_state": ready.get("systemd_state"),
                "dockerd_answers": ready.get("dockerd_answers"),
            }
        time.sleep(2.0)
    raise AcceptanceError("acceptance_host_systemd_not_running")


def observe_identity_survived_restart(
    *, before: Mapping[str, object], after: Mapping[str, object]
) -> dict[str, object]:
    """The worker's identity and its durable marker are unchanged across a restart.

    ``before``/``after`` are two :func:`observe_worker_key_identity` results and two
    :func:`observe_restart_marker` results taken either side of :func:`restart_worker_host`. An
    ABSENT identity on both sides is not persistence — it is two absences — so the predicate
    requires the value to be present as well as equal.
    """
    key_before = str(before.get("key_id", ""))
    key_after = str(after.get("key_id", ""))
    step_before = str(before.get("step", ""))
    step_after = str(after.get("step", ""))
    return {
        "key_id_present": bool(key_before) and bool(key_after),
        "key_id_unchanged": bool(key_before) and key_before == key_after,
        "marker_present": bool(step_before) and bool(step_after),
        "marker_unchanged": bool(step_before) and step_before == step_after,
        "survived": bool(key_before)
        and key_before == key_after
        and bool(step_before)
        and step_before == step_after,
    }


def observe_restart_marker(worker: Host, invitation_path: str) -> dict[str, str]:
    """The worker's own local restart marker for this enrollment, read through the supported
    ``secpctl worker enrollment status`` rather than off the disk.

    Read through the product on purpose: the marker file is named by the SHA-256 of the enrollment
    id, and a harness that recomputed that name would be re-implementing the store's addressing
    scheme — a second implementation that can agree with the first while both are wrong.
    """
    _exit_code, report = worker_enrollment_status(worker, invitation_path)
    return {"step": str(report.get("state", ""))}


__all__ = [
    "CONTROLLER_API_LOCATOR_PATH",
    "CONTROLLER_STATE_ROOTS",
    "ENROLLMENT_API_PREFIX",
    "INVITATION_HOST_PATH",
    "MANAGEMENT_WORKER_IDENTITY_PATH",
    "OPERATOR_TOKEN_FILE_ENV",
    "OUTCOME_OBSERVED",
    "OUTCOME_UNPROVEN",
    "OUTCOME_VIOLATED",
    "PENDING_HARNESS_REASONS",
    "REASON_COULD_NOT_LOOK",
    "REASON_IDENTITY_DISAGREES",
    "REASON_INVITATION_REFETCHABLE",
    "REASON_OBSERVATION_MALFORMED",
    "REASON_PRIVATE_KEY_ESCAPED",
    "REASON_RELEASE_DISAGREES",
    "REDEEMABLE_INVITATION_KEYS",
    "REQUIRED_INVITATION_KEYS",
    "SECPCTL",
    "STATE_HEALTHY",
    "CheckVerdict",
    "classify_identity_agreement",
    "classify_invitation_one_shot",
    "classify_private_key_containment",
    "classify_release_agreement",
    "WORKER_ENROLLMENT_PRIVATE_PATH",
    "WORKER_ENROLLMENT_PUBLIC_PATH",
    "WORKER_ENROLLMENT_ROOT",
    "WORKER_ENROLLMENT_STATE_DIR",
    "InvitationArtifact",
    "containment_verdict",
    "controller_enrollment_status",
    "controller_key_fingerprint",
    "create_invitation",
    "deliver_invitation",
    "host_exec",
    "host_python",
    "observe_controller_state",
    "observe_enroll_dry_run",
    "observe_enrollment_inventory",
    "observe_identity_survived_restart",
    "observe_installation_id_agreement",
    "observe_invitation_delivery",
    "observe_invitation_is_not_refetchable",
    "observe_key_fingerprint_agreement",
    "observe_private_key_containment",
    "observe_release_agreement",
    "observe_restart_marker",
    "observe_worker_enrollment_key",
    "observe_worker_key_identity",
    "restart_worker_host",
    "secpctl_json",
    "status_fingerprint",
    "worker_enroll",
    "worker_enroll_dry_run",
    "worker_enrollment_status",
    "worker_installation_label",
]
