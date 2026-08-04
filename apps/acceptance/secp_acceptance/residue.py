"""Did the run leak a privileged host — or could we simply not tell?

A leaked privileged container with a nested Docker daemon inside is the most expensive thing this
harness can leave behind, so the question "is the machine clean?" is asked at the end of every run.
This module exists because that question has THREE answers and the obvious implementation only has
two.

THE DISTINCTION THIS MODULE IS FOR
----------------------------------
``clean`` and ``could not observe`` are not the same answer, and the second one must never be
rendered as the first. A caller reads a teardown verdict for exactly one reason: to find out whether
it needs to go and remove something. "No" is only useful when it was actually established; "no,
because nothing could be reached" is the answer that stops the caller looking at the precise moment
it should start.

That is not hypothetical here. ``HostFleet.destroy`` shipped with this defect once: it removed each
object and then asked ``docker inspect`` whether it was still there, and with the daemon down every
removal failed AND every inspect answered "not found" — for the same reason, which is that nothing
could be reached at all. It reported a clean teardown having done nothing.
``test_acceptance_teardown_honesty.py`` pins the fix. This module generalises the lesson so that
every later teardown check is built on a primitive that CANNOT express that confusion.

THREE RULES, AND EVERY PROPERTY BELOW FOLLOWS FROM THEM
-------------------------------------------------------
1. **Probe the runtime FIRST, and stop when it does not answer.** Without this, every enumeration
   below fails and the sweep concludes "found nothing" from a machine it never reached. Stopping
   also keeps a dead daemon fast: each further call would otherwise wait out its own timeout.

1b. **Reachable is not the same as RIGHT.** A daemon that answers but is not the one the fleet was
   built on enumerates a machine our objects were never created on, finds nothing, and says
   "clean" — an answer about the wrong computer. This is not a hypothetical: this program's own
   negative control makes the runtime wrong precisely by pointing ``DOCKER_HOST`` somewhere else.
   When the caller supplies the expected daemon identity, a mismatch is ``unobservable``; when it
   does not, the report says so in ``daemon_bound`` rather than letting a reader assume otherwise.

2. **ENUMERATE; never ask "does this object exist?".** This is the load-bearing rule and it is worth
   reading twice. ``docker inspect NAME`` fails identically for "the object is gone" and "the daemon
   is not there", so a sweep built on it cannot tell absence from ignorance — it is the original
   defect wearing a different name. A LIST call separates them cleanly:

   * the listing FAILED                      -> unobservable  (we do not know)
   * the listing SUCCEEDED and was empty     -> clean         (we looked, nothing is there)
   * the listing SUCCEEDED and named objects -> residual      (we looked, and here they are)

   An empty answer and a failed answer are different values here, where under ``inspect`` they were
   the same one.

A PARTIAL SWEEP IS NEVER CLEAN — BUT IT MAY STILL BE RESIDUAL
--------------------------------------------------------------
Three object kinds are swept (containers, volumes, networks). If ANY of the three cannot be
enumerated, the sweep did not finish looking and can never conclude ``clean``: a run that leaked a
volume but could only read containers has not been shown to be clean of anything that matters.

What the partial sweep DID establish still decides the verdict, though. If it already saw an object
of ours, the property "this run leaked nothing" is settled FALSE, and the incompleteness only bounds
how much more there might be — so the verdict is ``residual`` and ``kinds_observed`` carries the
incompleteness. Only a partial sweep that found nothing is ``unobservable``.

Both halves of that are the same rule: report what was established. Calling a seen leak
``unobservable`` would understate known information, which is the exact mirror of the defect this
module exists for — that one reported clean when it did not know; this would report ignorance when
it did.

WHAT A CALLER MAY DO WITH THE VERDICT
-------------------------------------
:func:`outcome_for` is the ONLY mapping from a verdict to an acceptance outcome:
``clean`` -> ``observed``, ``residual`` -> ``violated``, ``unobservable`` -> ``unproven``.

``unproven`` and ``violated`` are opposites — could-not-look versus looked-and-saw-the-bad-thing —
and neither is in ``PASSING_OUTCOMES``. There is no path from ``unobservable`` to ``observed``.

``refused`` is never produced here. That outcome means THE PRODUCT refused and the refusal was the
point of the check; nothing about a teardown sweep is a product refusal, so keeping it unreachable
is what stops ``refused`` and ``unproven`` blurring in the stages that consume this.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import observation_digest
from secp_acceptance.reasons import OUTCOME_OBSERVED, OUTCOME_UNPROVEN, OUTCOME_VIOLATED
from secp_acceptance.shell import Result, docker

#: We looked at every kind, and this run owns nothing that is still there.
VERDICT_CLEAN = "clean"
#: We looked at every kind, and named objects from this run survived. The leak the caller is for.
VERDICT_RESIDUAL = "residual"
#: We could not look. NOT a synonym for clean, and never rendered as one.
VERDICT_UNOBSERVABLE = "unobservable"

VERDICTS: frozenset[str] = frozenset({VERDICT_CLEAN, VERDICT_RESIDUAL, VERDICT_UNOBSERVABLE})

#: The object kinds swept, each with the LIST argv that enumerates it.
#:
#: These are the same three enumerations the acceptance workflow's outer "Refuse to finish having
#: leaked a privileged host" step greps, and ``test_acceptance_residue.py`` pins that agreement. The
#: outer step is a shell backstop that runs even when the harness process died; this is the inner
#: reading that can be recorded as evidence. Two readings of one fact are only worth having while
#: they are readings of the SAME fact, so a kind added to one and not the other is a defect.
KIND_CONTAINER = "container"
KIND_VOLUME = "volume"
KIND_NETWORK = "network"

SWEEP_ARGV: tuple[tuple[str, tuple[str, ...]], ...] = (
    (KIND_CONTAINER, ("ps", "-a", "--format", "{{.Names}}")),
    (KIND_VOLUME, ("volume", "ls", "--format", "{{.Name}}")),
    (KIND_NETWORK, ("network", "ls", "--format", "{{.Name}}")),
)

KINDS: tuple[str, ...] = tuple(kind for kind, _argv in SWEEP_ARGV)

#: Bounded per-call timeouts. A listing is cheap; a listing that is not cheap is a symptom, and
#: waiting on it is how a fast honest failure became an eight-minute one last time.
PROBE_TIMEOUT_SECONDS = 60
LIST_TIMEOUT_SECONDS = 60

#: The reason code a ``violated`` outcome carries. It is a HARNESS code, and that is the whole
#: point: ``violated`` is the harness reporting what IT saw, so attributing it to a product code
#: would credit the product with a refusal it never made. The vocabulary deliberately has ONE code
#: for every violation rather than one per check, because the check id already names the property
#: that broke — so a leaked container and an activated operator unit share it.
VIOLATION_REASON = "acceptance_prohibited_state_observed"


@dataclass(frozen=True)
class ResidueReport:
    """The three-valued answer, plus enough context to know what was actually read.

    ``kinds_observed`` is not decoration: it is how a caller distinguishes a clean verdict that
    swept all three kinds from one produced by a sweep that has quietly lost a kind. A clean verdict
    is only as good as the set of things it looked at, so that set travels with it.
    """

    verdict: str
    #: ``kind:name`` for every surviving object FOUND, sorted. For an operator to READ — never for
    #: the evidence document, which takes :meth:`observation` instead.
    #:
    #: This is what was found; ``verdict`` is what may be concluded, and the two are deliberately
    #: separate. A sweep that read containers, found a leak, and then could not read volumes is
    #: ``unobservable`` — it has not enumerated the residue completely — but it still carries the
    #: container it saw, because throwing that away would hide a known leak behind "we do not know".
    residual: tuple[str, ...]
    #: The kinds successfully enumerated. Equal to :data:`KINDS` on any conclusive verdict.
    kinds_observed: tuple[str, ...]
    #: The bounded reason a non-clean verdict carries. ``None`` only when clean.
    reason_code: str | None
    #: Whether the swept daemon was PROVEN to be the one the fleet was built on. A clean verdict
    #: from an unbound sweep is a statement about some machine, not necessarily about ours.
    daemon_bound: bool = False

    @property
    def clean(self) -> bool:
        """True ONLY for an established clean sweep.

        Written as an equality against one verdict rather than as ``!= residual``, so a verdict
        added later is non-clean by default. A caller that gets this wrong stops looking for a
        privileged container it just leaked.
        """
        return self.verdict == VERDICT_CLEAN

    @property
    def observed(self) -> bool:
        """Whether the machine was actually READ. False for unobservable, regardless of residue."""
        return self.verdict in (VERDICT_CLEAN, VERDICT_RESIDUAL)

    def observation(self) -> dict[str, object]:
        """The bounded, secret-free projection an evidence check records.

        The surviving object NAMES are reduced to a count and a content address. They are harness-
        generated and carry no secret, but they are per-run values that say nothing to a later
        reader of the evidence, and the document's rule is digests and counts rather than ids.
        """
        return {
            "verdict": self.verdict,
            "kinds_observed": list(self.kinds_observed),
            "residual_count": len(self.residual),
            "residual_identity": observation_digest({"residual": list(self.residual)}),
            "reason_code": self.reason_code,
            "daemon_bound": self.daemon_bound,
        }


def _listing(argv: tuple[str, ...]) -> Result | None:
    """One enumeration. ``None`` when it could not be made — including on a bounded timeout.

    A timeout is emphatically not an empty listing, and letting :class:`AcceptanceError` escape
    would surface it as a harness crash rather than as the unobservable verdict it is.
    """
    try:
        result = docker(*argv, timeout=LIST_TIMEOUT_SECONDS)
    except AcceptanceError:
        return None
    return result if result.ok else None


def sweep(prefix: str, *, expected_daemon: str = "") -> ResidueReport:
    """Sweep the OUTER container runtime for objects named under ``prefix``.

    Every object this harness creates on the outer daemon is named under a single run-scoped prefix,
    which is what makes a sweep possible without touching anything that is not ours: a developer's
    own containers and CI's own networks are named nothing like it and are never reported.

    An empty prefix REFUSES rather than sweeping. It would match every object on the machine — and,
    read the other way, a prefix nobody used makes the sweep vacuously clean forever. Neither is an
    answer, so neither is returned as one.

    ``expected_daemon`` is the identity of the daemon the fleet was BUILT on (``HostFleet``
    records it as ``outer_daemon``). Supplying it closes the third way to report a false clean, and
    it is not hypothetical: this program's own negative control makes the runtime wrong by pointing
    ``DOCKER_HOST`` somewhere else. A daemon that is LIVE but is not the one our objects were
    created on enumerates a machine they were never on, finds nothing, and answers "clean" — an
    answer about the wrong computer. Bound, that becomes ``unobservable``.

    It defaults to unbound because a caller with no fleet (an early-failure teardown) genuinely has
    no identity to bind to. That is why the verdict carries ``daemon_bound``: an unbound clean sweep
    is a weaker sentence than a bound one, and the report says which it is rather than letting a
    reader assume the stronger.
    """
    if not prefix:
        raise AcceptanceError("acceptance_proof_would_be_vacuous")

    # RULE 1. Nothing below is meaningful without this, so it happens first and it stops here.
    try:
        probe = docker("version", "--format", "{{.Server.Os}}", timeout=PROBE_TIMEOUT_SECONDS)
    except AcceptanceError as exc:
        return ResidueReport(VERDICT_UNOBSERVABLE, (), (), exc.reason_code)
    if not probe.ok:
        return ResidueReport(
            VERDICT_UNOBSERVABLE, (), (), "acceptance_container_runtime_unavailable"
        )

    # RULE 1b. Reachable is not the same as RIGHT. Prove it is our machine before believing it.
    bound = False
    if expected_daemon:
        try:
            identity = docker("info", "--format", "{{.ID}}", timeout=PROBE_TIMEOUT_SECONDS)
        except AcceptanceError as exc:
            return ResidueReport(VERDICT_UNOBSERVABLE, (), (), exc.reason_code)
        if not identity.ok or not identity.stdout.strip():
            return ResidueReport(VERDICT_UNOBSERVABLE, (), (), "acceptance_observation_unavailable")
        if identity.stdout.strip() != expected_daemon:
            return ResidueReport(VERDICT_UNOBSERVABLE, (), (), "acceptance_residue_daemon_mismatch")
        bound = True

    # RULE 2. Enumerate. A failed listing is a different value from an empty one.
    observed: list[str] = []
    residual: list[str] = []
    for kind, argv in SWEEP_ARGV:
        listing = _listing(argv)
        if listing is None:
            # A partial sweep can never establish CLEAN — it did not finish looking. But if it
            # already SAW something of ours, the property "this run leaked nothing" is settled
            # false, and the incompleteness only bounds how much more there might be. So what was
            # established decides the verdict, and ``kinds_observed`` carries the incompleteness.
            #
            # Calling this ``unobservable`` would understate known information — the exact mirror
            # of the defect this module exists for. That one reported clean when it did not know;
            # this would report ignorance when it did.
            if residual:
                return ResidueReport(
                    VERDICT_RESIDUAL,
                    tuple(sorted(residual)),
                    tuple(observed),
                    VIOLATION_REASON,
                    daemon_bound=bound,
                )
            return ResidueReport(
                VERDICT_UNOBSERVABLE,
                (),
                tuple(observed),
                "acceptance_observation_unavailable",
                daemon_bound=bound,
            )
        observed.append(kind)
        for line in listing.stdout.splitlines():
            name = line.strip()
            if name.startswith(prefix):
                residual.append(f"{kind}:{name}")

    if residual:
        return ResidueReport(
            VERDICT_RESIDUAL,
            tuple(sorted(residual)),
            tuple(observed),
            VIOLATION_REASON,
            daemon_bound=bound,
        )
    return ResidueReport(VERDICT_CLEAN, (), tuple(observed), None, daemon_bound=bound)


def outcome_for(report: ResidueReport) -> tuple[str, str | None]:
    """The ONLY mapping from a residue verdict to an acceptance outcome + reason code.

    One function, so the "unobservable is not a pass" rule is enforced in one place rather than
    re-derived at each call site — the shape of mistake that put a false clean into this harness
    once already. Kept separate from the recorder so the stage that records it supplies the shared
    run, and this stays a pure function that the hermetic tests can pin exhaustively.

    * ``clean``        -> ``observed``  (we looked, and there is nothing of ours here)
    * ``residual``     -> ``violated``  (we looked, and here is the leaked privileged container)
    * ``unobservable`` -> ``unproven``  (we could not look, and that is never a pass)

    ``residual`` is ``violated`` rather than ``unproven`` under the eligibility rule this program
    settled on: can the producer tell observed-false from could-not-look? This one can — telling
    them apart is the whole reason the module exists — so an enumerated, named leak is maximal
    knowledge of a prohibited state, not ignorance. Recording it as ``unproven`` would file the
    single most expensive thing this harness can leave behind under "we are not sure".

    Neither ``violated`` nor ``unproven`` is in ``PASSING_OUTCOMES``, so this changes how a leak
    READS, never whether it passes. ``refused`` stays unreachable BY CONSTRUCTION — nothing here is
    a product refusal — and an unrecognised verdict raises rather than falling through to a default,
    which would be a silent extra path to a pass.
    """
    if report.verdict == VERDICT_CLEAN:
        return OUTCOME_OBSERVED, None
    if report.verdict == VERDICT_RESIDUAL:
        return OUTCOME_VIOLATED, report.reason_code or VIOLATION_REASON
    if report.verdict == VERDICT_UNOBSERVABLE:
        return OUTCOME_UNPROVEN, report.reason_code or "acceptance_observation_unavailable"
    raise AcceptanceError("acceptance_observation_malformed")


__all__ = [
    "KINDS",
    "KIND_CONTAINER",
    "KIND_NETWORK",
    "KIND_VOLUME",
    "LIST_TIMEOUT_SECONDS",
    "PROBE_TIMEOUT_SECONDS",
    "SWEEP_ARGV",
    "VERDICTS",
    "VERDICT_CLEAN",
    "VERDICT_RESIDUAL",
    "VERDICT_UNOBSERVABLE",
    "ResidueReport",
    "outcome_for",
    "sweep",
]
