"""Hermetic proofs for the durable worker-enrollment state machine + signed-handoff contracts
(SECP-PR5G).

Everything here is pure: no socket, subprocess, Temporal worker, workflow, OpenTofu, provider, or
secret is ever contacted, and timestamps are supplied explicitly (the module never reads a clock).
"""

from __future__ import annotations

import ast
import inspect
import json

import pytest
import secp_management.enrollment as en
from secp_management import ManagementError

_CTRL_HEX = (b"\x11" * 32).hex()
_CTRL_KEY = en.sha256_digest_of_hex(_CTRL_HEX)
_WORKER_HEX = (b"\x22" * 32).hex()
_WORKER_KEY = en.sha256_digest_of_hex(_WORKER_HEX)
_OTHER_KEY = en.sha256_digest_of_hex((b"\x44" * 32).hex())
_RELEASE = "sha256:" + "a" * 64
_TXN = "txn-0001"
_NONCE = "sha256:" + "b" * 64
_CREATED = "2026-07-21T00:00:00Z"
_EXPIRES = "2026-07-21T01:00:00Z"
_NOW = "2026-07-21T00:10:00Z"
_LATER = "2026-07-21T00:20:00Z"
_AFTER = "2026-07-21T02:00:00Z"
_CTRL_INSTALL = "controller-aaaaaaaa"
_WORKER_INSTALL = "worker-bbbbbbbb"
_OFFER_D = "sha256:" + "c" * 64
_RESULT_D = "sha256:" + "d" * 64


def _invitation(**over: object) -> en.WorkerEnrollmentInvitation:
    kw: dict[str, object] = dict(
        controller_installation_id=_CTRL_INSTALL,
        controller_key_id=_CTRL_KEY,
        controller_trust_anchor_hex=_CTRL_HEX,
        controller_origin="https://ctrl.example.com",
        release_digest=_RELEASE,
        transaction_id=_TXN,
        nonce=_NONCE,
        created_at=_CREATED,
        expires_at=_EXPIRES,
    )
    kw.update(over)
    return en.create_invitation(**kw)  # type: ignore[arg-type]


def _reason(exc: pytest.ExceptionInfo[ManagementError]) -> str:
    return exc.value.reason_code


def _offer(digest: str = _OFFER_D, txn: str = _TXN, key: str = _CTRL_KEY) -> en.HandoffFacts:
    return en.HandoffFacts("controller-offer", digest, txn, key)


def _result(digest: str = _RESULT_D, txn: str = _TXN, key: str = _WORKER_KEY) -> en.HandoffFacts:
    return en.HandoffFacts("worker-result", digest, txn, key)


def _bound(state: en.EnrollmentState, *, now: str = _NOW) -> en.EnrollmentState:
    return en.bind_worker_identity(
        state,
        worker_installation_id=_WORKER_INSTALL,
        worker_key_id=_WORKER_KEY,
        transaction_id=_TXN,
        now=now,
    )


# --- lifecycle -------------------------------------------------------------------------------


def test_refusal_reason_must_be_a_bounded_code_never_a_path_or_endpoint() -> None:
    s = _bound(en.open_enrollment(_invitation(), now=_NOW))
    # a free-form reason carrying a host path / endpoint / IP is refused at the boundary, so it can
    # never ride into refusal_reason and out through public_view
    for leaky in (
        "cannot reach https://10.0.0.5:8443/x",
        "/etc/secp/worker/key",
        "Failed: 192.168.1.9",
    ):
        with pytest.raises(ManagementError) as e:
            en.refuse(s, leaky)
        assert _reason(e) == "enrollment_reason_code_invalid"
    with pytest.raises(ManagementError):
        en.require_recovery(s, "/opt/secp/leak")
    refused = en.refuse(s, "handoff_verification_failed")  # a bounded snake_case code is accepted
    assert refused.state == en.REFUSED
    view = refused.public_view()
    assert view["refusal_reason"] == "handoff_verification_failed"
    assert ":" not in view["refusal_reason"] and "/" not in view["refusal_reason"]


def test_full_lifecycle_invited_to_healthy() -> None:
    s = en.open_enrollment(_invitation(), now=_NOW)
    assert s.state == en.INVITED and s.revision == 0 and s.sequence == 0
    s = _bound(s)
    assert s.state == en.WORKER_BOUND and s.worker_installation_id == _WORKER_INSTALL
    s = en.record_controller_offer(s, _offer(), now=_NOW)
    assert s.state == en.OFFER_TRANSPORTED and s.offer_digest == _OFFER_D
    s = en.record_worker_result(s, _result(), now=_NOW)
    assert s.state == en.RESULT_TRANSPORTED and s.result_digest == _RESULT_D
    s = en.mark_verified(s, release_digest=_RELEASE, now=_NOW)
    assert s.state == en.VERIFIED
    s = en.mark_healthy(s, now=_NOW)
    assert s.state == en.HEALTHY and s.revision == 5 and s.sequence == 5


def test_predecessor_and_sequence_chain_is_monotonic() -> None:
    s0 = en.open_enrollment(_invitation(), now=_NOW)
    s1 = _bound(s0)
    assert s1.predecessor_digest == s0.digest() and s1.revision == 1 and s1.sequence == 1
    s2 = en.record_controller_offer(s1, _offer(), now=_NOW)
    assert s2.predecessor_digest == s1.digest() and s2.revision == 2 and s2.sequence == 2


# --- expiry ----------------------------------------------------------------------------------


def test_expired_invitation_refuses_open() -> None:
    with pytest.raises(ManagementError) as e:
        en.open_enrollment(_invitation(), now=_AFTER)
    assert _reason(e) == "enrollment_invitation_expired"


def test_transition_after_expiry_refuses() -> None:
    s = _bound(en.open_enrollment(_invitation(), now=_NOW))
    with pytest.raises(ManagementError) as e:
        en.record_controller_offer(s, _offer(), now=_AFTER)
    assert _reason(e) == "enrollment_expired"


def test_invitation_ttl_upper_bound_refuses() -> None:
    with pytest.raises(ManagementError) as e:
        _invitation(expires_at="2026-07-22T02:00:00Z")  # 26h > 24h cap
    assert _reason(e) == "enrollment_invitation_invalid"


# --- single-use / replay / duplicate / stale -------------------------------------------------


def test_single_use_a_different_worker_cannot_rebind() -> None:
    s = _bound(en.open_enrollment(_invitation(), now=_NOW))
    with pytest.raises(ManagementError) as e:
        en.bind_worker_identity(
            s,
            worker_installation_id="worker-cccccccc",
            worker_key_id=en.sha256_digest_of_hex((b"\x33" * 32).hex()),
            transaction_id=_TXN,
            now=_LATER,
        )
    assert _reason(e) == "enrollment_already_bound"


def test_replay_a_different_offer_for_the_same_step_refuses() -> None:
    s = en.record_controller_offer(
        _bound(en.open_enrollment(_invitation(), now=_NOW)), _offer(), now=_NOW
    )
    with pytest.raises(ManagementError) as e:
        en.record_controller_offer(s, _offer(digest="sha256:" + "9" * 64), now=_NOW)
    assert _reason(e) == "enrollment_replay"


def test_duplicate_exact_offer_is_idempotent() -> None:
    s = en.record_controller_offer(
        _bound(en.open_enrollment(_invitation(), now=_NOW)), _offer(), now=_NOW
    )
    assert en.record_controller_offer(s, _offer(), now=_LATER) is s


def test_stale_offer_after_result_refuses_wrong_state() -> None:
    s = en.record_worker_result(
        en.record_controller_offer(
            _bound(en.open_enrollment(_invitation(), now=_NOW)), _offer(), now=_NOW
        ),
        _result(),
        now=_NOW,
    )
    with pytest.raises(ManagementError) as e:
        en.record_controller_offer(s, _offer(), now=_NOW)
    assert _reason(e) == "enrollment_wrong_state"


def test_out_of_order_offer_before_bind_refuses() -> None:
    s = en.open_enrollment(_invitation(), now=_NOW)
    with pytest.raises(ManagementError) as e:
        en.record_controller_offer(s, _offer(), now=_NOW)
    assert _reason(e) == "enrollment_wrong_state"


# --- idempotent exact retry ------------------------------------------------------------------


def test_idempotent_exact_retries_return_same_state() -> None:
    s = _bound(en.open_enrollment(_invitation(), now=_NOW))
    assert _bound(s, now=_LATER) is s  # bind
    s = en.record_controller_offer(s, _offer(), now=_NOW)
    s = en.record_worker_result(s, _result(), now=_NOW)
    assert en.record_worker_result(s, _result(), now=_LATER) is s  # result
    s = en.mark_verified(s, release_digest=_RELEASE, now=_NOW)
    assert en.mark_verified(s, release_digest=_RELEASE, now=_LATER) is s  # verified
    s = en.mark_healthy(s, now=_NOW)
    assert en.mark_healthy(s, now=_LATER) is s  # healthy


# --- wrong controller / worker / release / transaction / installation ------------------------


def test_wrong_controller_offer_key_refuses() -> None:
    s = _bound(en.open_enrollment(_invitation(), now=_NOW))
    with pytest.raises(ManagementError) as e:
        en.record_controller_offer(s, _offer(key=_OTHER_KEY), now=_NOW)
    assert _reason(e) == "enrollment_controller_mismatch"


def test_wrong_worker_result_key_refuses() -> None:
    s = en.record_controller_offer(
        _bound(en.open_enrollment(_invitation(), now=_NOW)), _offer(), now=_NOW
    )
    with pytest.raises(ManagementError) as e:
        en.record_worker_result(s, _result(key=_OTHER_KEY), now=_NOW)
    assert _reason(e) == "enrollment_worker_mismatch"


def test_wrong_release_refuses_verify() -> None:
    s = en.record_worker_result(
        en.record_controller_offer(
            _bound(en.open_enrollment(_invitation(), now=_NOW)), _offer(), now=_NOW
        ),
        _result(),
        now=_NOW,
    )
    with pytest.raises(ManagementError) as e:
        en.mark_verified(s, release_digest="sha256:" + "0" * 64, now=_NOW)
    assert _reason(e) == "enrollment_release_mismatch"


def test_wrong_transaction_at_bind_refuses() -> None:
    s = en.open_enrollment(_invitation(), now=_NOW)
    with pytest.raises(ManagementError) as e:
        en.bind_worker_identity(
            s,
            worker_installation_id=_WORKER_INSTALL,
            worker_key_id=_WORKER_KEY,
            transaction_id="txn-9999",
            now=_NOW,
        )
    assert _reason(e) == "enrollment_transaction_mismatch"


def test_wrong_transaction_on_offer_refuses() -> None:
    s = _bound(en.open_enrollment(_invitation(), now=_NOW))
    with pytest.raises(ManagementError) as e:
        en.record_controller_offer(s, _offer(txn="txn-9999"), now=_NOW)
    assert _reason(e) == "enrollment_transaction_mismatch"


def test_cross_installation_controller_as_its_own_worker_refuses() -> None:
    s = en.open_enrollment(_invitation(), now=_NOW)
    with pytest.raises(ManagementError) as e:
        en.bind_worker_identity(
            s,
            worker_installation_id=_CTRL_INSTALL,
            worker_key_id=_WORKER_KEY,
            transaction_id=_TXN,
            now=_NOW,
        )
    assert _reason(e) == "enrollment_installation_mismatch"


# --- invitation contract validation ----------------------------------------------------------


def test_invitation_non_https_origin_refuses() -> None:
    with pytest.raises(ManagementError) as e:
        _invitation(controller_origin="http://ctrl.example.com")
    assert _reason(e) == "enrollment_origin_not_https"


def test_invitation_trust_anchor_must_derive_the_pinned_key_id() -> None:
    with pytest.raises(ManagementError) as e:
        _invitation(controller_trust_anchor_hex=(b"\x99" * 32).hex())
    assert _reason(e) == "enrollment_trust_anchor_invalid"


# --- signed-handoff binding boundary ---------------------------------------------------------


class _FakeVerifier:
    def __init__(self, txn: str = _TXN, raise_reason: str | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._txn = txn
        self._raise = raise_reason

    def verify_controller_offer(self, record: object, attestation: object, *, key_id: str) -> str:
        self.calls.append(("offer", key_id))
        if self._raise:
            raise ManagementError(self._raise)
        return self._txn

    def verify_worker_result(self, record: object, attestation: object, *, key_id: str) -> str:
        self.calls.append(("result", key_id))
        if self._raise:
            raise ManagementError(self._raise)
        return self._txn


class _Rec:
    def __init__(self, digest: str) -> None:
        self._d = digest

    def digest(self) -> str:
        return self._d


def test_bind_controller_offer_verifies_then_binds_facts() -> None:
    v = _FakeVerifier()
    facts = en.bind_controller_offer(
        _Rec(_OFFER_D), object(), expected_key_id=_CTRL_KEY, verifier=v
    )
    assert facts == en.HandoffFacts("controller-offer", _OFFER_D, _TXN, _CTRL_KEY)
    assert v.calls == [("offer", _CTRL_KEY)]


def test_bind_offer_propagates_verifier_refusal() -> None:
    v = _FakeVerifier(raise_reason="handoff_signature_invalid")
    with pytest.raises(ManagementError) as e:
        en.bind_controller_offer(_Rec(_OFFER_D), object(), expected_key_id=_CTRL_KEY, verifier=v)
    assert _reason(e) == "handoff_signature_invalid"


def _discovery_handoff_verifier() -> en.HandoffVerifier:
    """The concrete PR5F-backed HandoffVerifier.  It lives HERE, not in secp_management, because the
    management plane must never import the PR5F root deployment authority (a plane boundary,
    tests/test_pr5f_discovery_activation_boundary.py); the real consumer is the PR5H wiring layer,
    for which this test stands in."""
    from secp_discovery_activation.handoff import ControllerOffer, WorkerResult, verify_handoff

    def _verify(record: object, attestation: object, *, key_id: str, expected: type) -> str:
        if type(record) is not expected:
            raise ManagementError("enrollment_handoff_invalid")
        verify_handoff(record, attestation, expected_key_id=key_id)  # type: ignore[arg-type]
        return str(getattr(record, "transaction_id"))  # noqa: B009

    class _V:
        def verify_controller_offer(self, record: object, att: object, *, key_id: str) -> str:
            return _verify(record, att, key_id=key_id, expected=ControllerOffer)

        def verify_worker_result(self, record: object, att: object, *, key_id: str) -> str:
            return _verify(record, att, key_id=key_id, expected=WorkerResult)

    return _V()


def test_discovery_handoff_verifier_rejects_a_non_offer_record() -> None:
    v = _discovery_handoff_verifier()
    with pytest.raises(ManagementError) as e:
        v.verify_controller_offer(object(), object(), key_id=_CTRL_KEY)
    assert _reason(e) == "enrollment_handoff_invalid"


# --- sealed transport ------------------------------------------------------------------------


def test_sealed_transport_refuses_every_exchange() -> None:
    t = en.SealedEnrollmentTransport()
    with pytest.raises(ManagementError) as e:
        t.deliver_controller_offer(enrollment_id="x", payload=b"y")
    assert _reason(e) == "enrollment_transport_not_activated"
    with pytest.raises(ManagementError) as e:
        t.retrieve_worker_result(enrollment_id="x")
    assert _reason(e) == "enrollment_transport_not_activated"


# --- bounded / redacted evidence -------------------------------------------------------------


def test_public_view_is_bounded_and_redacted() -> None:
    s = en.mark_healthy(
        en.mark_verified(
            en.record_worker_result(
                en.record_controller_offer(
                    _bound(en.open_enrollment(_invitation(), now=_NOW)), _offer(), now=_NOW
                ),
                _result(),
                now=_NOW,
            ),
            release_digest=_RELEASE,
            now=_NOW,
        ),
        now=_NOW,
    )
    view = s.public_view()
    assert view["controller_key_fingerprint"] == _CTRL_KEY.split(":")[1][:12]
    assert view["worker_key_fingerprint"] == _WORKER_KEY.split(":")[1][:12]
    blob = json.dumps(view)
    # never the raw public keys, full digests, key material, or a host path
    assert _CTRL_HEX not in blob and _WORKER_HEX not in blob
    assert _OFFER_D not in blob and _RESULT_D not in blob
    assert "/" not in blob and "BEGIN" not in blob


# --- no provider / host / network / Temporal / OpenTofu / secret contact ----------------------


def test_module_performs_no_forbidden_contact() -> None:
    # Parse the AST (never raw text, so prose in the docstring cannot trip it): the module must
    # import no network/subprocess/provider/Temporal/OpenTofu package and call no shell primitive.
    tree = ast.parse(inspect.getsource(en))
    forbidden_roots = {
        "socket",
        "subprocess",
        "temporalio",
        "requests",
        "httpx",
        "boto3",
        "kubernetes",
        "paramiko",
        "urllib",
        "http",
        "ssl",
        "opentofu",
        "proxmox",
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint(forbidden_roots), imported & forbidden_roots
    # no shell primitive call (os.system / Popen / eval / exec)
    called = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    } | {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert called.isdisjoint({"system", "Popen", "eval", "exec", "popen", "spawn"}), called


def test_contracts_carry_no_provider_field() -> None:
    inv = _invitation().canonical()
    state = en.open_enrollment(_invitation(), now=_NOW).canonical()
    blob = json.dumps([inv, state]).lower()
    for provider in (
        "proxmox",
        "kubernetes",
        "aws",
        "azure",
        "gcp",
        "vmware",
        "opentofu",
        "terraform",
        "openstack",
    ):
        assert provider not in blob, provider
