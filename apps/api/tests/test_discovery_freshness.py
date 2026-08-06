"""A fresh plan compiled from stale discovery is still invalid.

The nine refusal conditions, each tested as the scenario it prevents rather than as a branch. The
one that motivates the module: discovery's only existing time bound is a 12-hour TTL on the DERIVED
candidate plan, so a plan minted a minute ago from a week-old observation currently reads as fresh.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from secp_api.discovery_freshness import (
    DEFAULT_SNAPSHOT_FRESHNESS,
    FRESHNESS_CLOCK_SKEWED,
    FRESHNESS_FRESH,
    FRESHNESS_UNBOUNDED,
    SnapshotBinding,
    detect_internal_inconsistency,
    freshness_state,
    plan_refusal_reasons,
)

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
TARGET = "target-abc"
WORKER = "wk-0001"
RELEASE = "sha256:" + "b" * 64
CONTRACT = "secp-discovery/contract/v1"
KEY = "sha256:" + "k" * 64
TRUSTED = frozenset({KEY})


def _binding(**overrides) -> SnapshotBinding:
    base = dict(
        observation_started_at=NOW - timedelta(seconds=40),
        observation_completed_at=NOW - timedelta(seconds=10),
        producer_timestamp=NOW - timedelta(seconds=10),
        controller_received_at=NOW - timedelta(seconds=9),
        target_identity=TARGET,
        worker_installation_id=WORKER,
        worker_release_fingerprint=RELEASE,
        discovery_contract_version=CONTRACT,
        signature_verified=True,
        signing_key_fingerprint=KEY,
    )
    base.update(overrides)
    return SnapshotBinding(**base)


def _reasons(binding, **overrides) -> tuple[str, ...]:
    kwargs = dict(
        now=NOW,
        expected_target_identity=TARGET,
        expected_worker_installation_id=WORKER,
        expected_worker_release_fingerprint=RELEASE,
        expected_contract_version=CONTRACT,
        trusted_key_fingerprints=TRUSTED,
    )
    kwargs.update(overrides)
    return plan_refusal_reasons(binding, **kwargs)


def test_a_good_snapshot_is_accepted():
    """A gate that never opens is not a gate."""
    assert _reasons(_binding()) == ()


# --- the nine refusals ----------------------------------------------------------------------------


def test_expired_snapshot_refuses():
    old = _binding(observation_completed_at=NOW - DEFAULT_SNAPSHOT_FRESHNESS - timedelta(seconds=1))
    assert "discovery_snapshot_expired" in _reasons(old)


def test_a_snapshot_with_no_completion_time_is_refused_not_assumed_fresh():
    """Unbounded is not "current until proven otherwise" — it cannot be aged at all."""
    assert freshness_state(_binding(observation_completed_at=None), now=NOW) == FRESHNESS_UNBOUNDED
    assert "discovery_snapshot_expired" in _reasons(_binding(observation_completed_at=None))


def test_an_unsigned_snapshot_refuses():
    """A content hash proves the bytes were not corrupted. It does not prove who made them."""
    assert "discovery_evidence_unauthenticated" in _reasons(_binding(signature_verified=False))


def test_a_snapshot_signed_by_an_untrusted_key_refuses():
    other = "sha256:" + "9" * 64
    assert "discovery_evidence_unauthenticated" in _reasons(_binding(signing_key_fingerprint=other))


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_identity", "target-other"),
        ("worker_installation_id", "wk-9999"),
        ("worker_release_fingerprint", "sha256:" + "0" * 64),
        ("discovery_contract_version", "secp-discovery/contract/v0"),
    ],
)
def test_a_snapshot_bound_to_something_else_refuses(field, value):
    """Wrong target, wrong worker, wrong release, wrong contract — four ways, one response."""
    assert "discovery_binding_mismatch" in _reasons(_binding(**{field: value}))


def test_a_missing_required_fact_refuses_and_names_it_with_its_state():
    """ "A required fact is missing" is not actionable. Which fact, and in what state, is.

    permission_denied is an operator action; not_implemented is a release blocker. The refusal
    carries the difference so it reaches the right person.
    """
    binding = _binding(
        missing_required_facts=(
            ("sdn_zones", "permission_denied"),
            ("pending_sdn", "not_implemented"),
        )
    )
    reasons = _reasons(binding)
    assert "required_fact_unusable:sdn_zones:permission_denied" in reasons
    assert "required_fact_unusable:pending_sdn:not_implemented" in reasons


def test_an_internally_inconsistent_snapshot_refuses():
    assert "discovery_binding_mismatch" in _reasons(
        _binding(internal_inconsistency="observation_completed_before_it_started")
    )


def test_a_snapshot_from_the_future_is_skew_not_freshness():
    """A clock ahead of ours is a fault, not freshness.

    Reporting it as fresh would turn a broken clock into a guarantee, and the error would run in
    the direction where a stale cluster looks current.
    """
    ahead = _binding(observation_completed_at=NOW + timedelta(minutes=5))
    assert freshness_state(ahead, now=NOW) == FRESHNESS_CLOCK_SKEWED
    assert "discovery_clock_skew" in _reasons(ahead)
    # And it is NOT reported as expired — that would send an operator to re-run discovery when the
    # actual fix is NTP.
    assert "discovery_snapshot_expired" not in _reasons(ahead)


def test_small_skew_within_the_allowance_is_still_fresh():
    """Two NTP-synced machines disagree by milliseconds. A second is not a fault."""
    assert freshness_state(
        _binding(observation_completed_at=NOW + timedelta(seconds=5)), now=NOW
    ) == (FRESHNESS_FRESH)


# --- all reasons at once, and stably -------------------------------------------------------------


def test_every_failing_condition_is_reported_not_just_the_first():
    """An operator who fixes an expired snapshot only to hit a binding mismatch next attempt has
    been told half the truth twice."""
    bad = _binding(
        observation_completed_at=NOW - timedelta(days=7),
        signature_verified=False,
        target_identity="target-other",
        missing_required_facts=(("sdn_zones", "permission_denied"),),
    )
    reasons = _reasons(bad)
    assert "discovery_snapshot_expired" in reasons
    assert "discovery_evidence_unauthenticated" in reasons
    assert "discovery_binding_mismatch" in reasons
    assert "required_fact_unusable:sdn_zones:permission_denied" in reasons


def test_reasons_are_deduplicated_and_stably_ordered():
    """Two independent causes can map to one code; a list that repeats itself reads as more
    findings than there are."""
    bad = _binding(
        target_identity="other",
        worker_installation_id="other",
        internal_inconsistency="observation_completed_before_it_started",
    )
    reasons = _reasons(bad)
    assert reasons.count("discovery_binding_mismatch") == 1
    assert reasons == _reasons(bad)


# --- expiry is derived, not stored ----------------------------------------------------------------


def test_expiry_is_derived_so_it_cannot_drift_from_the_bound():
    binding = _binding()
    assert binding.expires_at() == binding.observation_completed_at + binding.freshness_bound
    tighter = _binding(freshness_bound=timedelta(minutes=5))
    assert tighter.expires_at() == tighter.observation_completed_at + timedelta(minutes=5)


def test_a_snapshot_with_no_completion_time_has_no_expiry():
    assert _binding(observation_completed_at=None).expires_at() is None


# --- catch it at production time, not at compile time --------------------------------------------


@pytest.mark.parametrize(
    "overrides,expected",
    [
        (
            {"observation_completed_at": NOW - timedelta(minutes=5), "observation_started_at": NOW},
            "observation_completed_before_it_started",
        ),
        ({"freshness_bound": timedelta(0)}, "non_positive_freshness_bound"),
        ({"signing_key_fingerprint": ""}, "signature_verified_without_a_key_fingerprint"),
    ],
)
def test_internal_inconsistency_is_detectable_before_storage(overrides, expected):
    """The cheapest place to catch a malformed snapshot is before it is ever stored."""
    assert detect_internal_inconsistency(_binding(**overrides)) == expected


def test_a_sound_binding_has_no_inconsistency():
    assert detect_internal_inconsistency(_binding()) == ""
