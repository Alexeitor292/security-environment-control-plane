"""Freshness as a property of the discovery snapshot itself, and what a plan must refuse over.

Discovery had no freshness bound. The 12-hour TTL that exists (``target_discovery/engine.py``)
grades the *derived candidate plan*, not the observation it was compiled from — so a plan minted one
minute ago from a snapshot taken last week reads as fresh, and the two facts it would need to be
challenged on are not in the same place.

**A fresh plan compiled from stale discovery is still invalid.** The plan's own TTL stays separate
and neither substitutes for the other, so this module grades the snapshot and says nothing about the
plan's age.

Pure: no clock is read here and no I/O happens. ``now`` is always a parameter, which is what lets
the clock-skew check be a check rather than an assumption.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from secp_api.enums import DiscoveryFailureCode

#: How long a discovery snapshot may be relied on. Shorter than the candidate-plan TTL on purpose:
#: the observation is the thing the physical world can invalidate underneath you, and a cluster can
#: gain a VM, a VLAN or an SDN zone in minutes.
DEFAULT_SNAPSHOT_FRESHNESS = timedelta(minutes=30)

#: How far ahead of the evaluating clock a producer timestamp may sit before it is a fault. Two
#: machines with NTP disagree by milliseconds; a minute of disagreement is a broken clock, and a
#: broken clock must never read as freshness.
DEFAULT_ALLOWED_SKEW = timedelta(seconds=60)

FRESHNESS_FRESH = "fresh"
FRESHNESS_EXPIRED = "expired"
FRESHNESS_CLOCK_SKEWED = "clock_skewed"
FRESHNESS_UNBOUNDED = "unbounded"


@dataclass(frozen=True)
class SnapshotBinding:
    """What a discovery snapshot must state about itself before anything may compile from it.

    Every field is part of the answer to one question: *is this observation the right one, of the
    right thing, by the right producer, recently enough?* A snapshot that cannot answer all four is
    not a weaker snapshot — it is one the compiler must refuse, because each missing part
    corresponds to a different way of being wrong about a real cluster.
    """

    # --- when -------------------------------------------------------------------------------
    observation_started_at: datetime | None = None
    observation_completed_at: datetime | None = None
    #: The PRODUCER's own clock at completion. Kept separately from
    #: ``observation_completed_at`` because they are the same instant measured by different
    #: machines, and their disagreement is exactly the skew finding.
    producer_timestamp: datetime | None = None
    #: When the control plane received it. Absent for a snapshot read straight from storage.
    controller_received_at: datetime | None = None
    freshness_bound: timedelta = DEFAULT_SNAPSHOT_FRESHNESS

    # --- of what, by whom -------------------------------------------------------------------
    target_identity: str = ""
    worker_installation_id: str = ""
    worker_release_fingerprint: str = ""
    discovery_contract_version: str = ""

    # --- authenticity -----------------------------------------------------------------------
    #: True only when a signature over the canonical binding verified against a TRUSTED key.
    #: A content hash is not a signature: it proves nobody corrupted the bytes in transit, not
    #: that the party who produced them was the worker they claim to be.
    signature_verified: bool = False
    signing_key_fingerprint: str = ""

    # --- completeness -----------------------------------------------------------------------
    #: Required facts that are not usable, mapped to their observation state. Populated from
    #: ``discovery_observation.unusable_facts`` so the reason survives into the refusal.
    missing_required_facts: tuple[tuple[str, str], ...] = ()
    #: Set when the snapshot contradicts itself — e.g. completion before start.
    internal_inconsistency: str = ""

    def expires_at(self) -> datetime | None:
        """Deterministically derived rather than stored, so it cannot drift from the bound."""
        if self.observation_completed_at is None:
            return None
        return self.observation_completed_at + self.freshness_bound


def freshness_state(
    binding: SnapshotBinding,
    *,
    now: datetime,
    allowed_skew: timedelta = DEFAULT_ALLOWED_SKEW,
) -> str:
    """Grade the snapshot's age. Says nothing about authenticity or completeness."""
    completed = binding.observation_completed_at
    if completed is None:
        # No completion time is not "fresh until proven otherwise". It is a snapshot that cannot
        # be aged at all, and the compiler must treat it as unusable rather than current.
        return FRESHNESS_UNBOUNDED
    if completed - now > allowed_skew:
        return FRESHNESS_CLOCK_SKEWED
    if now - completed > binding.freshness_bound:
        return FRESHNESS_EXPIRED
    return FRESHNESS_FRESH


def plan_refusal_reasons(
    binding: SnapshotBinding,
    *,
    now: datetime,
    expected_target_identity: str,
    expected_worker_installation_id: str,
    expected_worker_release_fingerprint: str,
    expected_contract_version: str,
    trusted_key_fingerprints: frozenset[str],
    allowed_skew: timedelta = DEFAULT_ALLOWED_SKEW,
) -> tuple[str, ...]:
    """Every reason a plan must refuse to compile from this snapshot. Empty means it may.

    All nine conditions are checked and ALL failing ones are returned, not the first. An operator
    who fixes an expired snapshot only to meet an unrelated binding mismatch on the next attempt has
    been told half the truth twice; the whole set is cheaper for everyone.

    Returns ``DiscoveryFailureCode`` values so the refusal joins the existing closed, secret-free
    reason vocabulary rather than inventing a parallel one.
    """
    reasons: list[str] = []

    state = freshness_state(binding, now=now, allowed_skew=allowed_skew)
    if state == FRESHNESS_CLOCK_SKEWED:
        reasons.append(DiscoveryFailureCode.discovery_clock_skew.value)
    elif state in (FRESHNESS_EXPIRED, FRESHNESS_UNBOUNDED):
        reasons.append(DiscoveryFailureCode.discovery_snapshot_expired.value)

    # Unsigned, and signed-by-an-untrusted-key, are the same refusal with different causes: in both
    # cases nothing establishes who produced this. They share a code and are separated by the
    # snapshot's own fields rather than by two near-identical vocabulary members.
    if not binding.signature_verified:
        reasons.append(DiscoveryFailureCode.discovery_evidence_unauthenticated.value)
    elif (
        not binding.signing_key_fingerprint
        or binding.signing_key_fingerprint not in trusted_key_fingerprints
    ):
        reasons.append(DiscoveryFailureCode.discovery_evidence_unauthenticated.value)

    # Wrong target, wrong worker, wrong release, wrong contract. One code, because the compiler's
    # response to all four is identical — re-run discovery — while the snapshot's own fields say
    # which it was.
    if (
        binding.target_identity != expected_target_identity
        or binding.worker_installation_id != expected_worker_installation_id
        or binding.worker_release_fingerprint != expected_worker_release_fingerprint
        or binding.discovery_contract_version != expected_contract_version
    ):
        reasons.append(DiscoveryFailureCode.discovery_binding_mismatch.value)

    if binding.missing_required_facts:
        # Named individually: "a required fact is missing" is not actionable, and the STATE matters
        # because permission_denied is an operator action while not_implemented is a release
        # blocker.
        for fact, fact_state in binding.missing_required_facts:
            reasons.append(f"required_fact_unusable:{fact}:{fact_state}")

    if binding.internal_inconsistency:
        reasons.append(DiscoveryFailureCode.discovery_binding_mismatch.value)

    # Stable order, de-duplicated: two independent causes can map to one code, and a refusal list
    # that repeats itself reads as more findings than there are.
    seen: set[str] = set()
    ordered: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            ordered.append(reason)
    return tuple(ordered)


def detect_internal_inconsistency(binding: SnapshotBinding) -> str:
    """Contradictions a snapshot can carry about itself, as a bounded reason string.

    Separate from :func:`plan_refusal_reasons` so it can run at PRODUCTION time — the cheapest place
    to catch a malformed snapshot is before it is ever stored, not when something tries to compile
    from it.
    """
    started = binding.observation_started_at
    completed = binding.observation_completed_at
    if started is not None and completed is not None and completed < started:
        return "observation_completed_before_it_started"
    if binding.freshness_bound <= timedelta(0):
        return "non_positive_freshness_bound"
    if binding.signature_verified and not binding.signing_key_fingerprint:
        return "signature_verified_without_a_key_fingerprint"
    return ""
