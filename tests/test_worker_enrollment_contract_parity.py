"""Exhaustive cross-plane byte-parity corpus for the worker-enrollment contract (SECP-PR5H-A).

The reviewed plane boundary forbids ``apps/api`` from importing ``secp_management``, so the API
keeps a narrow mirror of the pure transition contract.  Only the TEST layer may import both; this
module is the guard that makes the duplication safe.

For every corpus case it requires EITHER:

* byte-identical canonical serialized output **and** identical digest; or
* refusal with the **same** bounded reason code.

It deliberately does NOT compare source text — only observable contract behavior, canonical bytes,
digests and bounded refusal codes.  It fails closed if a state or transition is added to one side
only, if canonical field ORDER changes, if a schema/version drifts, if a reason code drifts, or if
one side accepts a case the other refuses.
"""

from __future__ import annotations

import json

import pytest
import secp_management.enrollment as mgmt
from secp_api import worker_enrollment_contract as api

# --- deterministic fixtures (identical inputs on both sides) ----------------------------------

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = mgmt.sha256_digest_of_hex(CTRL_HEX)
WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = mgmt.sha256_digest_of_hex(WORKER_HEX)
OTHER_KEY = mgmt.sha256_digest_of_hex((b"\x44" * 32).hex())
RELEASE = "sha256:" + "a" * 64
TXN = "txn-0001"
NONCE = "sha256:" + "b" * 64
CREATED = "2026-07-21T00:00:00Z"
EXPIRES = "2026-07-21T01:00:00Z"
NOW = "2026-07-21T00:10:00Z"
LATER = "2026-07-21T00:20:00Z"
AFTER = "2026-07-21T02:00:00Z"
CTRL_INSTALL = "controller-aaaaaaaa"
WORKER_INSTALL = "worker-bbbbbbbb"
OFFER_D = "sha256:" + "c" * 64
RESULT_D = "sha256:" + "d" * 64
ORIGIN = "https://ctrl.example.com"


def _invitation_kwargs(**over: object) -> dict:
    kw: dict = dict(
        controller_installation_id=CTRL_INSTALL,
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id=TXN,
        nonce=NONCE,
        created_at=CREATED,
        expires_at=EXPIRES,
    )
    kw.update(over)
    return kw


def _reason_of(exc: BaseException) -> str:
    code = getattr(exc, "reason_code", None)
    return code if isinstance(code, str) else f"{type(exc).__name__}"


def _run(fn) -> tuple[str, object]:
    """('ok', value) or ('refused', bounded_reason_code)."""
    try:
        return "ok", fn()
    except Exception as exc:  # noqa: BLE001 - parity compares refusal CODES across planes
        return "refused", _reason_of(exc)


def _canonical_bytes(obj) -> bytes:
    return json.dumps(
        obj.canonical(), sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True
    ).encode("utf-8")


def assert_parity(label: str, mgmt_fn, api_fn) -> None:
    """The single parity assertion: same outcome, and on success byte-identical canonical bytes
    and digest."""
    m_status, m_value = _run(mgmt_fn)
    a_status, a_value = _run(api_fn)
    assert m_status == a_status, (
        f"{label}: management={m_status}({m_value!r}) but api={a_status}({a_value!r}) — "
        "one side accepted a case the other refused"
    )
    if m_status == "refused":
        assert m_value == a_value, f"{label}: refusal code drift {m_value!r} vs {a_value!r}"
        return
    assert _canonical_bytes(m_value) == _canonical_bytes(a_value), (
        f"{label}: canonical bytes differ"
    )
    assert m_value.digest() == a_value.digest(), f"{label}: digest differs"


# --- inventory parity (fails closed if either side gains/loses a state or edge) ----------------


def test_state_constants_are_identical() -> None:
    assert api.ALL_STATES == (
        mgmt.INVITED,
        mgmt.WORKER_BOUND,
        mgmt.OFFER_TRANSPORTED,
        mgmt.RESULT_TRANSPORTED,
        mgmt.VERIFIED,
        mgmt.HEALTHY,
        mgmt.REFUSED,
        mgmt.RECOVERY_REQUIRED,
    )
    for name in (
        "INVITED",
        "WORKER_BOUND",
        "OFFER_TRANSPORTED",
        "RESULT_TRANSPORTED",
        "VERIFIED",
        "HEALTHY",
        "REFUSED",
        "RECOVERY_REQUIRED",
    ):
        assert getattr(api, name) == getattr(mgmt, name), name


def test_transition_and_active_sets_are_identical() -> None:
    assert api.ADVANCE == mgmt._ADVANCE
    assert api.ACTIVE == mgmt._ACTIVE


def test_schema_and_contract_versions_are_identical() -> None:
    assert api.ENROLLMENT_CONTRACT_VERSION == mgmt.ENROLLMENT_CONTRACT_VERSION
    assert api.INVITATION_SCHEMA == mgmt._INVITATION_SCHEMA
    assert api.STATE_SCHEMA == mgmt._STATE_SCHEMA


def test_bounded_limits_are_identical() -> None:
    assert api.MAX_TTL_SECONDS == mgmt._MAX_TTL_SECONDS
    assert api.MIN_TTL_SECONDS == mgmt._MIN_TTL_SECONDS
    assert api.MAX_FIELD_LEN == mgmt._MAX_FIELD_LEN
    assert api.MAX_ORIGIN_LEN == mgmt._MAX_ORIGIN_LEN


def test_canonical_field_order_is_identical() -> None:
    m_inv = mgmt.create_invitation(**_invitation_kwargs())
    a_inv = api.create_invitation(**_invitation_kwargs())
    assert list(m_inv.canonical()) == list(a_inv.canonical())
    m_state = mgmt.open_enrollment(m_inv, now=NOW)
    a_state = api.open_enrollment(a_inv, now=NOW)
    assert list(m_state.canonical()) == list(a_state.canonical())
    # the state carries EXACTLY the 17 contract fields plus the schema marker
    assert len(m_state.canonical()) == 18


def test_deployment_site_label_is_not_part_of_the_canonical_contract() -> None:
    # the opaque grouping label must never affect a digest; it is API-side only
    a_inv = api.create_invitation(**_invitation_kwargs())
    a_state = api.open_enrollment(a_inv, now=NOW)
    assert not any("site" in key for key in a_state.canonical())
    assert not any("site" in key for key in a_inv.canonical())
    assert api.is_deployment_site_label("site-01.rack_2") is True
    for bad in ["", "a" * 121, "site/01", "site:01", "a@b", "has space", "https://x", "10.0.0.5/x"]:
        assert api.is_deployment_site_label(bad) is False, bad


# --- invitation canonicalization + digest ------------------------------------------------------


def test_invitation_canonical_and_digest_parity() -> None:
    assert_parity(
        "invitation",
        lambda: mgmt.create_invitation(**_invitation_kwargs()),
        lambda: api.create_invitation(**_invitation_kwargs()),
    )


@pytest.mark.parametrize(
    ("label", "over"),
    [
        ("bad_contract_nonce", {"nonce": "not-a-digest"}),
        ("bad_installation", {"controller_installation_id": "X"}),
        ("bad_key_id", {"controller_key_id": "sha256:zz"}),
        ("anchor_not_hex", {"controller_trust_anchor_hex": "zz"}),
        ("anchor_key_mismatch", {"controller_trust_anchor_hex": (b"\x99" * 32).hex()}),
        ("origin_not_https", {"controller_origin": "http://ctrl.example.com"}),
        ("origin_too_long", {"controller_origin": "https://" + "a" * 300}),
        ("release_not_digest", {"release_digest": "nope"}),
        ("txn_empty", {"transaction_id": ""}),
        ("txn_too_long", {"transaction_id": "t" * 513}),
        ("txn_max_len", {"transaction_id": "t" * 512}),
        ("created_not_utc", {"created_at": "2026-07-21T00:00:00"}),
        ("expiry_before_created", {"expires_at": "2026-07-20T00:00:00Z"}),
        ("ttl_zero", {"expires_at": CREATED}),
        ("ttl_over_cap", {"expires_at": "2026-07-22T02:00:00Z"}),
        ("ttl_at_cap", {"expires_at": "2026-07-22T00:00:00Z"}),
        ("ttl_min", {"expires_at": "2026-07-21T00:00:01Z"}),
        ("offset_form_timestamp", {"created_at": "2026-07-21T00:00:00+00:00"}),
    ],
)
def test_invitation_boundary_and_malformed_parity(label: str, over: dict) -> None:
    assert_parity(
        f"invitation:{label}",
        lambda: mgmt.create_invitation(**_invitation_kwargs(**over)),
        lambda: api.create_invitation(**_invitation_kwargs(**over)),
    )


# --- single-plane builders (one source of truth for the fixture path) ----------------------------


def _invitation(mod):
    return mod.create_invitation(**_invitation_kwargs())


def _open(mod):
    return mod.open_enrollment(_invitation(mod), now=NOW)


def _bind(mod):
    return mod.bind_worker_identity(
        _open(mod),
        worker_installation_id=WORKER_INSTALL,
        worker_key_id=WORKER_KEY,
        transaction_id=TXN,
        now=NOW,
    )


def _offer(mod):
    facts = mod.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY)
    return mod.record_controller_offer(_bind(mod), facts, now=NOW)


def _result(mod):
    facts = mod.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY)
    return mod.record_worker_result(_offer(mod), facts, now=NOW)


def _verify(mod):
    return mod.mark_verified(_result(mod), release_digest=RELEASE, now=NOW)


def _healthy_of(mod):
    return mod.mark_healthy(_verify(mod), now=NOW)


# --- golden digests: the security correction must not have moved any valid serialization ---------
#
# Captured from the authoritative implementation BEFORE the participant-separation guard was added.
# The guard only ADDS a refusal for an invalid identity configuration, so every valid state must
# still serialize to exactly these bytes.  If a future change alters canonical output or field
# order, this fails loudly rather than silently re-keying every persisted enrollment.

GOLDEN_DIGESTS = {
    "invitation": "sha256:a5585ec31af82382bd9d699bda924bd3771d0c64f82a8dd07a293bb49dcd6adf",
    "invited": "sha256:60249c0bdc5ed26a3ffcb7fc7bc681a2545e32afb481e9ab0e1736a3fab26529",
    "worker_bound": "sha256:d9b1cc278bb2ea45664f05aeca8627733ea67760acb9d0d54916c5491261b8e0",
    "offer_transported": "sha256:58b3e5dc5864e9e90cc193c877a295a8f091efadfc153bb603553623d3f298b5",
    "result_transported": "sha256:6e2b4346fd976904e860f5925a22d6d982592af63d3eca668b460158c5713dab",
    "verified": "sha256:08a478db1137103bb3f24e21502af508a5713fa2c4c639a919a44440a533f6f6",
    "healthy": "sha256:fb3bd1d3f93ea1769daffe177b85e79a5d63130ce7ff2db53c9a05ba388eda00",
    "refused": "sha256:d9ed06bc332db9ebdddc4a05e5b929d30016162e07d83ed9deb271b668e7e196",
    "recovery_required": "sha256:b7c844effcf10b0db44119975333c692d44269e3ca09ef67b26457454deac4f7",
}


@pytest.mark.parametrize("plane", ["mgmt", "api"])
def test_valid_state_digests_match_the_pre_correction_goldens(plane: str) -> None:
    mod = mgmt if plane == "mgmt" else api
    produced = {"invitation": _invitation(mod).digest()}
    for label, build in (
        ("invited", _open),
        ("worker_bound", _bind),
        ("offer_transported", _offer),
        ("result_transported", _result),
        ("verified", _verify),
        ("healthy", _healthy_of),
    ):
        produced[label] = build(mod).digest()
    healthy = _healthy_of(mod)
    produced["refused"] = mod.refuse(healthy, "post_health_fault").digest()
    produced["recovery_required"] = mod.require_recovery(healthy, "operator_recovery").digest()
    assert produced == GOLDEN_DIGESTS, {
        k: (produced[k], GOLDEN_DIGESTS[k]) for k in produced if produced[k] != GOLDEN_DIGESTS[k]
    }


# --- participant separation (controller and worker must be DISTINCT signers) ----------------------
#
# Regression coverage for a confirmed defect found while mirroring: the self-enrolment guard checked
# only ``worker_installation_id`` against ``controller_installation_id``, never the KEY IDs.  A
# worker declaring a different installation id but reusing the controller's key id bound cleanly and
# drove the enrollment all the way to ``healthy`` — collapsing both signature bindings onto one key
# while every check reported success.  Both planes now refuse with ``enrollment_worker_mismatch``.


def _same_key_state(mod, state: str):
    """A directly constructed / rehydrated state whose participants are NOT separated."""
    from dataclasses import replace as _replace

    return _replace(_healthy_of(mod), worker_key_id=CTRL_KEY, state=state)


def test_same_key_binding_refuses_even_with_distinct_installation_ids() -> None:
    m, a = _states()
    assert_parity(
        "separation:initial_bind",
        lambda: mgmt.bind_worker_identity(
            m,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=CTRL_KEY,
            transaction_id=TXN,
            now=NOW,
        ),
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=CTRL_KEY,
            transaction_id=TXN,
            now=NOW,
        ),
    )
    # the refusal is the EXISTING bounded code, not a new one that would fingerprint the check
    _, code = _run(
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=CTRL_KEY,
            transaction_id=TXN,
            now=NOW,
        )
    )
    assert code == "enrollment_worker_mismatch"


def test_same_key_pre_bound_state_refuses_a_rebind_with_a_clean_key() -> None:
    """Pins the SECOND binding guard — the state's OWN (rehydrated) pair.

    The discriminating input: the stored row is already same-key, and the retry proposes a *clean*,
    distinct key.  The proposed-identity guard passes, so only the state's-own-pair guard can
    decide.
    Without it the call reaches the exact-retry branch and returns ``enrollment_already_bound``,
    which would wrongly report an ordinary rebind conflict for a corrupted row.  Asserted
    absolutely, not merely by parity: if BOTH planes regressed together, parity alone would pass.
    """
    for mod in (mgmt, api):
        state = _same_key_state(mod, mod.WORKER_BOUND)
        _, code = _run(
            lambda mod=mod, state=state: mod.bind_worker_identity(
                state,
                worker_installation_id="worker-cccccccc",
                worker_key_id=OTHER_KEY,
                transaction_id=TXN,
                now=NOW,
            )
        )
        assert code == "enrollment_worker_mismatch", (mod.__name__, code)


def test_same_key_exact_retry_at_worker_bound_refuses() -> None:
    """The guard runs BEFORE the exact-retry branch, so a malformed pre-bound state cannot be waved
    through as an idempotent retry."""
    m = _same_key_state(mgmt, mgmt.WORKER_BOUND)
    a = _same_key_state(api, api.WORKER_BOUND)

    def call(mod, state):
        return lambda: mod.bind_worker_identity(
            state,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=CTRL_KEY,
            transaction_id=TXN,
            now=NOW,
        )

    assert_parity("separation:exact_retry", call(mgmt, m), call(api, a))
    # absolute, per plane — parity alone cannot detect both planes regressing together
    for mod, state in ((mgmt, m), (api, a)):
        _, code = _run(call(mod, state))
        assert code == "enrollment_worker_mismatch", (mod.__name__, code)


def _separation_call(mod, state, op: str):
    """The four later transitions, invoked against ``state``."""
    if op == "offer":
        facts = mod.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY)
        return lambda: mod.record_controller_offer(state, facts, now=NOW)
    if op == "result":
        facts = mod.HandoffFacts("worker-result", RESULT_D, TXN, CTRL_KEY)
        return lambda: mod.record_worker_result(state, facts, now=NOW)
    if op == "verify":
        return lambda: mod.mark_verified(state, release_digest=RELEASE, now=NOW)
    return lambda: mod.mark_healthy(state, now=NOW)


@pytest.mark.parametrize(
    ("label", "from_state", "op"),
    [
        ("offer_transported", "WORKER_BOUND", "offer"),
        ("result_transported", "OFFER_TRANSPORTED", "result"),
        ("verified", "RESULT_TRANSPORTED", "verify"),
        ("healthy", "VERIFIED", "healthy"),
    ],
)
def test_same_key_state_cannot_advance(label: str, from_state: str, op: str) -> None:
    """The FORWARD-edge path.  Note this alone does not pin the per-transition guards — a forward
    edge falls through to ``_advance``, whose own guard would fire even if the per-transition one
    were removed.  ``test_same_key_state_cannot_be_reaffirmed_at_its_own_state`` covers that."""
    assert_parity(
        f"separation:advance_to_{label}",
        _separation_call(mgmt, _same_key_state(mgmt, getattr(mgmt, from_state)), op),
        _separation_call(api, _same_key_state(api, getattr(api, from_state)), op),
    )
    for mod in (mgmt, api):
        _, code = _run(_separation_call(mod, _same_key_state(mod, getattr(mod, from_state)), op))
        assert code == "enrollment_worker_mismatch", (label, mod.__name__, code)


@pytest.mark.parametrize(
    ("label", "at_state", "op"),
    [
        ("offer_transported", "OFFER_TRANSPORTED", "offer"),
        ("result_transported", "RESULT_TRANSPORTED", "result"),
        ("verified", "VERIFIED", "verify"),
        ("healthy", "HEALTHY", "healthy"),
    ],
)
def test_same_key_state_cannot_be_reaffirmed_at_its_own_state(
    label: str, at_state: str, op: str
) -> None:
    """The IDEMPOTENT-RETRY path — the only place the per-transition guards are the deciding check.

    A transition called against a state ALREADY AT its target returns early, before ``_advance`` is
    reached, so ``_advance``'s backstop cannot help.  Without the per-transition guard a corrupted
    same-key row would keep being re-affirmed as ``healthy``/``verified`` and keep reporting success
    to a retrying caller.  This is exactly the placement requirement "guard before the exact-retry
    branch", extended to every later transition.
    """
    assert_parity(
        f"separation:reaffirm_{label}",
        _separation_call(mgmt, _same_key_state(mgmt, getattr(mgmt, at_state)), op),
        _separation_call(api, _same_key_state(api, getattr(api, at_state)), op),
    )
    for mod in (mgmt, api):
        _, code = _run(_separation_call(mod, _same_key_state(mod, getattr(mod, at_state)), op))
        assert code == "enrollment_worker_mismatch", (label, mod.__name__, code)


def test_clean_state_is_still_reaffirmed_idempotently_at_its_own_state() -> None:
    """Control for the test above: with DISTINCT keys the same at-target calls are still no-ops that
    return the very same object, so the new coverage pins the guard rather than breaking
    idempotency."""
    for mod in (mgmt, api):
        offered = _offer(mod)
        assert (
            mod.record_controller_offer(
                offered, mod.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=LATER
            )
            is offered
        )
        resulted = _result(mod)
        assert (
            mod.record_worker_result(
                resulted, mod.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY), now=LATER
            )
            is resulted
        )
        verified = _verify(mod)
        assert mod.mark_verified(verified, release_digest=RELEASE, now=LATER) is verified
        healthy = _healthy_of(mod)
        assert mod.mark_healthy(healthy, now=LATER) is healthy


def test_same_key_state_can_still_be_refused_and_recovered() -> None:
    """Remediation must remain possible: a corrupted enrollment has to be movable to a terminal, so
    the separation guard is deliberately NOT applied to refuse()/require_recovery()."""
    m = _same_key_state(mgmt, mgmt.WORKER_BOUND)
    a = _same_key_state(api, api.WORKER_BOUND)
    assert_parity(
        "separation:refuse",
        lambda: mgmt.refuse(m, "key_collision"),
        lambda: api.refuse(a, "key_collision"),
    )
    assert_parity(
        "separation:require_recovery",
        lambda: mgmt.require_recovery(m, "key_collision"),
        lambda: api.require_recovery(a, "key_collision"),
    )
    assert mgmt.refuse(m, "key_collision").state == mgmt.REFUSED
    assert api.require_recovery(a, "key_collision").state == api.RECOVERY_REQUIRED


def test_distinct_keys_still_complete_the_entire_valid_path() -> None:
    """The correction must not have narrowed the legitimate path."""
    for mod in (mgmt, api):
        healthy = _healthy_of(mod)
        assert healthy.state == mod.HEALTHY
        assert healthy.controller_key_id != healthy.worker_key_id
    m, a = _healthy()
    assert _canonical_bytes(m) == _canonical_bytes(a)
    assert m.digest() == a.digest() == GOLDEN_DIGESTS["healthy"]


# --- secret-leakage refusal parity --------------------------------------------------------------
#
# ``transaction_id`` is the ONLY canonical field bounded by length alone (no grammar), so it is the
# one field through which secret-shaped material can actually reach the secret scan.  Both planes
# must refuse it identically, and the scan must run LAST — a longer-than-bound secret is refused for
# being over-length, not for being a secret, so the refusal never confirms "that looked like a key".


@pytest.mark.parametrize(
    ("label", "transaction_id"),
    [
        ("vault_uri", "vault:kv/data/db"),
        ("openbao_uri", "openbao:kv/data/db"),
        ("bearer_token", "Bearer abcdefgh12345678"),
        ("authorization_header", "authorization: x"),
        ("aws_access_key", "AKIA1234567890ABCDEF"),
        ("jwt", "eyJhbGciOiJI.eyJzdWIiOiI.sig"),
        ("private_key_pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("ssh_public_key", "ssh-ed25519 AAAAC3Nz"),
        ("x_vault_token", "x-vault-token"),
        ("benign_lookalike", "txn-vaulted-0001"),
    ],
)
def test_secret_shaped_transaction_id_refusal_parity(label: str, transaction_id: str) -> None:
    assert_parity(
        f"secret_scan:{label}",
        lambda: mgmt.create_invitation(**_invitation_kwargs(transaction_id=transaction_id)),
        lambda: api.create_invitation(**_invitation_kwargs(transaction_id=transaction_id)),
    )


def test_over_length_wins_over_the_secret_scan_on_both_planes() -> None:
    """Ordering parity: the bounded-length refusal fires BEFORE the secret scan, so an over-long
    secret-shaped value never returns the more specific 'this was secret-shaped' code."""
    over = {"transaction_id": "vault:" + "a" * 600}
    assert_parity(
        "secret_scan:over_length_first",
        lambda: mgmt.create_invitation(**_invitation_kwargs(**over)),
        lambda: api.create_invitation(**_invitation_kwargs(**over)),
    )
    _, code = _run(lambda: api.create_invitation(**_invitation_kwargs(**over)))
    assert code == "enrollment_invitation_invalid"


def test_public_view_never_carries_the_transaction_id() -> None:
    """The one length-only field is deliberately absent from the public projection, so even a value
    that passed the scan cannot reach a status/browser surface."""
    m, a = _bound()
    assert "transaction_id" not in m.public_view()
    assert "transaction_id" not in a.public_view()
    assert m.transaction_id == a.transaction_id == TXN


# --- helpers to build matched states on both sides ---------------------------------------------


# Each returns the (management, api) pair for one state, built through the SINGLE-plane builders
# above so both planes always walk an identical fixture path.


def _states():
    return _open(mgmt), _open(api)


def _bound():
    return _bind(mgmt), _bind(api)


def _offered():
    return _offer(mgmt), _offer(api)


def _resulted():
    return _result(mgmt), _result(api)


def _verified():
    return _verify(mgmt), _verify(api)


def _healthy():
    return _healthy_of(mgmt), _healthy_of(api)


# --- every state + every valid transition ------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "build"),
    [
        ("invited", _states),
        ("worker_bound", _bound),
        ("offer_transported", _offered),
        ("result_transported", _resulted),
        ("verified", _verified),
        ("healthy", _healthy),
    ],
)
def test_every_state_has_identical_canonical_bytes_and_digest(label: str, build) -> None:
    m, a = build()
    assert m.state == a.state == (label if label != "invited" else mgmt.INVITED)
    assert _canonical_bytes(m) == _canonical_bytes(a), label
    assert m.digest() == a.digest(), label
    assert m.public_view() == a.public_view(), label


def test_full_forward_path_digest_chain_is_identical() -> None:
    # each revision's predecessor_digest chains the prior digest identically on both sides
    for build in (_states, _bound, _offered, _resulted, _verified, _healthy):
        m, a = build()
        assert m.predecessor_digest == a.predecessor_digest
        assert (m.revision, m.sequence) == (a.revision, a.sequence)


# --- refusal / recovery ------------------------------------------------------------------------


def test_refuse_and_require_recovery_parity() -> None:
    m, a = _bound()
    assert_parity(
        "refuse", lambda: mgmt.refuse(m, "handoff_failed"), lambda: api.refuse(a, "handoff_failed")
    )
    assert_parity(
        "require_recovery",
        lambda: mgmt.require_recovery(m, "enrollment_expired"),
        lambda: api.require_recovery(a, "enrollment_expired"),
    )
    # refused -> recovery_required is a LIVE edge (recovery_required is the only absorbing terminal)
    mr, ar = mgmt.refuse(m, "handoff_failed"), api.refuse(a, "handoff_failed")
    assert_parity(
        "refused_to_recovery",
        lambda: mgmt.require_recovery(mr, "operator_recovery"),
        lambda: api.require_recovery(ar, "operator_recovery"),
    )
    # healthy can legally be flipped to refused (refuse never consults the active set)
    mh, ah = _healthy()
    assert_parity(
        "healthy_to_refused",
        lambda: mgmt.refuse(mh, "post_health_fault"),
        lambda: api.refuse(ah, "post_health_fault"),
    )


def test_recovery_required_is_the_only_absorbing_terminal() -> None:
    """The persistence layer relies on this: ``recovery_required`` absorbs everything, ``refused``
    does not, and neither terminal can advance."""
    from dataclasses import replace as _replace

    mb, ab = _bound()
    mr = mgmt.require_recovery(mb, "operator_recovery")
    ar = api.require_recovery(ab, "operator_recovery")
    assert mr.state == ar.state == mgmt.RECOVERY_REQUIRED

    # absorbing: refuse() and require_recovery() are no-ops returning the SAME object
    assert_parity(
        "recovery_absorbs_refuse", lambda: mgmt.refuse(mr, "later"), lambda: api.refuse(ar, "later")
    )
    assert mgmt.refuse(mr, "later") is mr
    assert api.refuse(ar, "later") is ar
    assert_parity(
        "recovery_absorbs_recovery",
        lambda: mgmt.require_recovery(mr, "later"),
        lambda: api.require_recovery(ar, "later"),
    )
    assert mgmt.require_recovery(mr, "later") is mr
    assert api.require_recovery(ar, "later") is ar

    # ...and the NEGATIVE half this test is named for: `refused` must NOT absorb require_recovery.
    # Asserted absolutely on each plane — parity alone would still pass if both planes made
    # `refused` absorbing, silently stranding a refused enrollment outside the recovery path.
    for mod, refused in (
        (mgmt, mgmt.refuse(mb, "handoff_failed")),
        (api, api.refuse(ab, "handoff_failed")),
    ):
        recovered = mod.require_recovery(refused, "operator_recovery")
        assert recovered.state == mod.RECOVERY_REQUIRED, mod.__name__
        assert recovered is not refused, mod.__name__
        assert recovered.revision == refused.revision + 1, mod.__name__
        assert recovered.predecessor_digest == refused.digest(), mod.__name__

    # ...and neither terminal can advance
    terminals = (
        ("from_recovery", mr, ar),
        ("from_refused", mgmt.refuse(mb, "handoff_failed"), api.refuse(ab, "handoff_failed")),
    )
    for label, m_state, a_state in terminals:
        assert_parity(
            f"advance_{label}",
            lambda s=m_state: mgmt.record_controller_offer(
                s, mgmt.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=NOW
            ),
            lambda s=a_state: api.record_controller_offer(
                s, api.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=NOW
            ),
        )

    # an unknown/unsupported state value is refused, never treated as active
    mu, au = _replace(mb, state="not_a_state"), _replace(ab, state="not_a_state")
    assert_parity(
        "advance_from_unknown_state",
        lambda: mgmt.mark_healthy(mu, now=NOW),
        lambda: api.mark_healthy(au, now=NOW),
    )


@pytest.mark.parametrize(
    "reason",
    [
        "ok_code",
        "a",
        "a" * 64,
        "a" * 65,
        "Has_Upper",
        "has space",
        "has/slash",
        "has:colon",
        "has.dot",
        "1leading_digit",
        "",
        "trailing_",
    ],
)
def test_reason_code_normalization_parity(reason: str) -> None:
    m, a = _bound()
    assert_parity(
        f"reason:{reason!r}", lambda: mgmt.refuse(m, reason), lambda: api.refuse(a, reason)
    )


# --- exact retry / conflicting retry / replay --------------------------------------------------


def test_exact_retry_at_target_state_parity() -> None:
    m, a = _bound()
    assert_parity(
        "bind_exact_retry",
        lambda: mgmt.bind_worker_identity(
            m,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=LATER,
        ),
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=LATER,
        ),
    )
    mo, ao = _offered()
    assert_parity(
        "offer_exact_retry",
        lambda: mgmt.record_controller_offer(
            mo, mgmt.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=LATER
        ),
        lambda: api.record_controller_offer(
            ao, api.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=LATER
        ),
    )
    mr, ar = _resulted()
    assert_parity(
        "result_exact_retry",
        lambda: mgmt.record_worker_result(
            mr, mgmt.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY), now=LATER
        ),
        lambda: api.record_worker_result(
            ar, api.HandoffFacts("worker-result", RESULT_D, TXN, WORKER_KEY), now=LATER
        ),
    )
    mv, av = _verified()
    assert_parity(
        "verify_exact_retry",
        lambda: mgmt.mark_verified(mv, release_digest=RELEASE, now=LATER),
        lambda: api.mark_verified(av, release_digest=RELEASE, now=LATER),
    )
    mh, ah = _healthy()
    assert_parity(
        "healthy_exact_retry",
        lambda: mgmt.mark_healthy(mh, now=LATER),
        lambda: api.mark_healthy(ah, now=LATER),
    )
    # every exact retry is an identity no-op, on BOTH planes — asserted absolutely, because parity
    # alone would still pass if both planes started returning a fresh equal object (which would
    # inflate the revision and break the predecessor chain in the persistence layer)
    for mod in (mgmt, api):
        bound = _bind(mod)
        assert (
            mod.bind_worker_identity(
                bound,
                worker_installation_id=WORKER_INSTALL,
                worker_key_id=WORKER_KEY,
                transaction_id=TXN,
                now=LATER,
            )
            is bound
        )


def test_wrong_release_is_refused_even_on_an_already_verified_state() -> None:
    """Pins mark_verified's CHECK ORDER: the release comparison runs BEFORE the ``VERIFIED``
    idempotent branch.  If they were swapped, an already-verified enrollment would silently accept
    re-verification against a DIFFERENT release digest and report success."""
    other_release = "sha256:" + "f" * 64
    assert_parity(
        "verify_retry_wrong_release",
        lambda: mgmt.mark_verified(_verify(mgmt), release_digest=other_release, now=LATER),
        lambda: api.mark_verified(_verify(api), release_digest=other_release, now=LATER),
    )
    for mod in (mgmt, api):
        _, code = _run(
            lambda mod=mod: mod.mark_verified(_verify(mod), release_digest=other_release, now=LATER)
        )
        assert code == "enrollment_release_mismatch", (mod.__name__, code)


def test_conflicting_retry_and_replay_parity() -> None:
    m, a = _bound()
    assert_parity(
        "bind_different_worker",
        lambda: mgmt.bind_worker_identity(
            m,
            worker_installation_id="worker-cccccccc",
            worker_key_id=OTHER_KEY,
            transaction_id=TXN,
            now=LATER,
        ),
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id="worker-cccccccc",
            worker_key_id=OTHER_KEY,
            transaction_id=TXN,
            now=LATER,
        ),
    )
    mo, ao = _offered()
    other = "sha256:" + "9" * 64
    assert_parity(
        "offer_replay_different_digest",
        lambda: mgmt.record_controller_offer(
            mo, mgmt.HandoffFacts("controller-offer", other, TXN, CTRL_KEY), now=NOW
        ),
        lambda: api.record_controller_offer(
            ao, api.HandoffFacts("controller-offer", other, TXN, CTRL_KEY), now=NOW
        ),
    )
    mr, ar = _resulted()
    assert_parity(
        "result_replay_different_digest",
        lambda: mgmt.record_worker_result(
            mr, mgmt.HandoffFacts("worker-result", other, TXN, WORKER_KEY), now=NOW
        ),
        lambda: api.record_worker_result(
            ar, api.HandoffFacts("worker-result", other, TXN, WORKER_KEY), now=NOW
        ),
    )
    # a stale offer AFTER the state advanced is a wrong-state refusal, not a no-op
    assert_parity(
        "stale_offer_after_result",
        lambda: mgmt.record_controller_offer(
            mr, mgmt.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=NOW
        ),
        lambda: api.record_controller_offer(
            ar, api.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=NOW
        ),
    )


def test_out_of_order_transition_parity() -> None:
    m, a = _states()
    assert_parity(
        "offer_before_bind",
        lambda: mgmt.record_controller_offer(
            m, mgmt.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=NOW
        ),
        lambda: api.record_controller_offer(
            a, api.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=NOW
        ),
    )
    assert_parity(
        "verify_before_result",
        lambda: mgmt.mark_verified(m, release_digest=RELEASE, now=NOW),
        lambda: api.mark_verified(a, release_digest=RELEASE, now=NOW),
    )
    assert_parity(
        "healthy_before_verify",
        lambda: mgmt.mark_healthy(m, now=NOW),
        lambda: api.mark_healthy(a, now=NOW),
    )


# --- substitution: wrong controller / worker / transaction / release ---------------------------


def test_wrong_identity_transaction_and_release_parity() -> None:
    m, a = _states()
    assert_parity(
        "wrong_transaction_on_bind",
        lambda: mgmt.bind_worker_identity(
            m,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=WORKER_KEY,
            transaction_id="other-txn",
            now=NOW,
        ),
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id=WORKER_KEY,
            transaction_id="other-txn",
            now=NOW,
        ),
    )
    assert_parity(
        "worker_is_the_controller",
        lambda: mgmt.bind_worker_identity(
            m,
            worker_installation_id=CTRL_INSTALL,
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
        ),
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id=CTRL_INSTALL,
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
        ),
    )
    assert_parity(
        "bad_worker_installation",
        lambda: mgmt.bind_worker_identity(
            m, worker_installation_id="X", worker_key_id=WORKER_KEY, transaction_id=TXN, now=NOW
        ),
        lambda: api.bind_worker_identity(
            a, worker_installation_id="X", worker_key_id=WORKER_KEY, transaction_id=TXN, now=NOW
        ),
    )
    assert_parity(
        "bad_worker_key",
        lambda: mgmt.bind_worker_identity(
            m,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id="nope",
            transaction_id=TXN,
            now=NOW,
        ),
        lambda: api.bind_worker_identity(
            a,
            worker_installation_id=WORKER_INSTALL,
            worker_key_id="nope",
            transaction_id=TXN,
            now=NOW,
        ),
    )
    mb, ab = _bound()
    assert_parity(
        "offer_wrong_signer",
        lambda: mgmt.record_controller_offer(
            mb, mgmt.HandoffFacts("controller-offer", OFFER_D, TXN, OTHER_KEY), now=NOW
        ),
        lambda: api.record_controller_offer(
            ab, api.HandoffFacts("controller-offer", OFFER_D, TXN, OTHER_KEY), now=NOW
        ),
    )
    assert_parity(
        "offer_wrong_kind",
        lambda: mgmt.record_controller_offer(
            mb, mgmt.HandoffFacts("worker-result", OFFER_D, TXN, CTRL_KEY), now=NOW
        ),
        lambda: api.record_controller_offer(
            ab, api.HandoffFacts("worker-result", OFFER_D, TXN, CTRL_KEY), now=NOW
        ),
    )
    assert_parity(
        "offer_wrong_transaction",
        lambda: mgmt.record_controller_offer(
            mb, mgmt.HandoffFacts("controller-offer", OFFER_D, "other", CTRL_KEY), now=NOW
        ),
        lambda: api.record_controller_offer(
            ab, api.HandoffFacts("controller-offer", OFFER_D, "other", CTRL_KEY), now=NOW
        ),
    )
    mo, ao = _offered()
    assert_parity(
        "result_wrong_signer",
        lambda: mgmt.record_worker_result(
            mo, mgmt.HandoffFacts("worker-result", RESULT_D, TXN, OTHER_KEY), now=NOW
        ),
        lambda: api.record_worker_result(
            ao, api.HandoffFacts("worker-result", RESULT_D, TXN, OTHER_KEY), now=NOW
        ),
    )
    mr, ar = _resulted()
    assert_parity(
        "wrong_release_on_verify",
        lambda: mgmt.mark_verified(mr, release_digest="sha256:" + "f" * 64, now=NOW),
        lambda: api.mark_verified(ar, release_digest="sha256:" + "f" * 64, now=NOW),
    )


# --- expiry + stale revision / sequence / predecessor ------------------------------------------


def test_expiry_parity() -> None:
    m, a = _bound()
    assert_parity(
        "transition_after_expiry",
        lambda: mgmt.record_controller_offer(
            m, mgmt.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=AFTER
        ),
        lambda: api.record_controller_offer(
            a, api.HandoffFacts("controller-offer", OFFER_D, TXN, CTRL_KEY), now=AFTER
        ),
    )
    assert_parity(
        "open_after_expiry",
        lambda: mgmt.open_enrollment(mgmt.create_invitation(**_invitation_kwargs()), now=AFTER),
        lambda: api.open_enrollment(api.create_invitation(**_invitation_kwargs()), now=AFTER),
    )
    assert_parity(
        "malformed_now",
        lambda: mgmt.open_enrollment(
            mgmt.create_invitation(**_invitation_kwargs()), now="not-a-time"
        ),
        lambda: api.open_enrollment(
            api.create_invitation(**_invitation_kwargs()), now="not-a-time"
        ),
    )


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("stale_revision", {"revision": 0}),
        ("future_revision", {"revision": 99}),
        ("wrong_sequence", {"sequence": 99}),
        ("wrong_predecessor", {"predecessor_digest": "sha256:" + "e" * 64}),
        ("empty_predecessor", {"predecessor_digest": ""}),
    ],
)
def test_mutated_state_fields_digest_identically(label: str, mutate: dict) -> None:
    """A tampered/stale field must change the digest the SAME way on both sides — that is what makes
    the CAS predicate (revision + state_digest) enforceable rather than decorative."""
    from dataclasses import replace as _replace

    m, a = _bound()
    m2, a2 = _replace(m, **mutate), _replace(a, **mutate)
    assert _canonical_bytes(m2) == _canonical_bytes(a2), label
    assert m2.digest() == a2.digest(), label
    assert m2.digest() != m.digest(), f"{label}: mutation did not change the digest"


# --- public projection --------------------------------------------------------------------------


@pytest.mark.parametrize("build", [_states, _bound, _offered, _resulted, _verified, _healthy])
def test_public_projection_parity_and_redaction(build) -> None:
    m, a = build()
    assert m.public_view() == a.public_view()
    blob = json.dumps(m.public_view(), sort_keys=True)
    # the projection exposes fingerprints only — never a full key id, anchor, or raw digest
    assert CTRL_HEX not in blob and WORKER_HEX not in blob
    assert CTRL_KEY not in blob and WORKER_KEY not in blob
    assert RELEASE not in blob
