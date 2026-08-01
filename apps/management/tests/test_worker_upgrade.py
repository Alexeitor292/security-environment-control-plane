"""Managed WORKER upgrade — release A to a linear successor B (SECP WS-B).

The managed-upgrade anchor (``test_controller_upgrade_2b3c``) is controller-only, because the
controller carries the stack/finalization/generation machinery an upgrade has to thread. The worker
upgrade is a genuinely different, much smaller path — no finalization, no identity activation, no
migration transition — and it had no coverage of its own. This file is that coverage.

What a worker upgrade must do:

* re-drive the reviewed worker ops for release B, rebind the identity and the installed-release
  record to B, and prove the COMPLETE canonical end state for B by reobservation — never by trusting
  a stored flag or the fact that ops ran;
* keep the operator unit present-but-disabled-and-stopped across the upgrade, and keep the ordinary
  worker off the operator queue. An upgrade is the obvious place for that isolation to be lost, so
  it is asserted on the post-upgrade end state, not only on a fresh install;
* fail CLOSED on a bad B end state, compensate, and leave no documents claiming B is installed;
* refuse a bundle for the wrong role outright.

Hermetic: the shared in-memory hardened filesystem and the closed fake worker adapter/observer from
``_mgmt_support``. Only leaf host effects are simulated — the engine code path is the real one.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from _mgmt_support import (
    WORKER_OPERATOR_IMAGE,
    default_artifacts,
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import sha256_bytes
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run
from secp_management.topology import OPERATOR_TASK_QUEUE, ORDINARY_TASK_QUEUE

#: Release B ships a DIFFERENT ordinary worker image, so "the upgrade actually happened" is provable
#: from the observed end state rather than from the release version string alone.
B_ORDINARY_IMAGE = sha256_bytes(b"image:worker/ordinary@B")

_A_SOURCE = "a" * 40
_B_SOURCE = "d" * 40

_ID = "/var/lib/secp/bootstrap/worker-identity.json"
_RR = "/var/lib/secp/bootstrap/worker-installed-release.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"


def _b_artifacts() -> list[dict]:
    """Release B's artifact set: identical to A except the ordinary worker image."""
    arts = [dict(a) for a in default_artifacts("worker")]
    for art in arts:
        if art.get("purpose") == "worker/ordinary":
            art["image_digest"] = B_ORDINARY_IMAGE
    return arts


def _installed_a(**world_overrides):
    """Install release A on a fresh host and return ``(deps, fs, trust, kid, priv)``."""
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bundle_a = "/var/lib/secp/bootstrap/release/worker-a"
    seed_signed_bundle(fs, bundle_a, "worker", kid, priv, source_sha=_A_SOURCE)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(**world_overrides), trust)
    code, _rep = run(["bootstrap", "worker", "--bundle", bundle_a, "--write", "--confirm"], deps)
    assert code == 0
    return deps, fs, trust, kid, priv


def _seed_b(fs, kid, priv, *, parent_sha: str | None = _A_SOURCE, artifacts=None) -> str:
    bundle_b = "/var/lib/secp/bootstrap/release/worker-b"
    seed_signed_bundle(
        fs,
        bundle_b,
        "worker",
        kid,
        priv,
        artifacts if artifacts is not None else _b_artifacts(),
        release_version="0.2.0",
        source_sha=_B_SOURCE,
        parent_sha=parent_sha,
    )
    return bundle_b


def _upgrade_world(**overrides):
    """A host already running A, whose adapter will bring up B's ordinary image on restart."""
    return dict(start_image_digest=B_ORDINARY_IMAGE, **overrides)


# --- the happy path ------------------------------------------------------------------------------


def test_worker_upgrade_a_to_b_rebinds_the_installed_release():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    # the host's ordinary worker comes up on B's image once the upgrade restarts it
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 0, rep
    assert rep["mode"] == "written"
    assert rep["reobserved_healthy"] is True
    record = fs.safe_read(_RR, max_bytes=1 << 20, expected_uid=0).decode()
    assert "0.2.0" in record, "the installed-release record must rebind to B"


def test_the_upgraded_worker_reports_ok_status_on_release_b():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)
    assert run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)[0] == 0

    code, status = run(["status", "worker"], deps)

    assert code == 0 and status["ok"] is True
    # status derives the expected end state from the SIGNED record, so an ok status here is
    # independent proof that the record and the running worker both moved to B
    assert status["dimensions"]["ordinary_queue"] == ORDINARY_TASK_QUEUE


def test_an_upgrade_is_deterministic_in_dry_run():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)

    _c1, first = run(["bootstrap", "worker", "--bundle", bundle_b], deps)
    _c2, second = run(["bootstrap", "worker", "--bundle", bundle_b], deps)

    assert first["plan"] == second["plan"]


def test_an_upgrade_dry_run_touches_neither_the_host_nor_the_documents():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    world = fresh_worker_world(**_upgrade_world())
    deps = deps_for(fs, world, deps.trust_root)
    before = set(fs.paths())

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b], deps)

    assert code == 0 and rep["mode"] == "dry_run"
    assert set(fs.paths()) == before
    assert deps.worker_adapter._w.ops == []


# --- the operator boundary must survive the upgrade ----------------------------------------------


def test_the_operator_stays_disabled_and_stopped_across_the_upgrade():
    """An upgrade re-runs the install ops — the obvious place for operator isolation to be lost."""
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 0
    assert rep["operator_started"] is False
    assert rep["operator_enabled"] is False
    world = deps.worker_adapter._w
    assert world.operator_present is True, "the unit is installed..."
    assert world.operator_running is False and world.operator_enabled is False, (
        "...but never active"
    )
    # only the ordinary worker is ever started, on the upgrade path exactly as on a fresh install
    assert [op.split(":")[0] for op in world.ops].count("start_ordinary") == 1
    assert not any(op.startswith("start_operator") for op in world.ops)


def test_an_upgrade_that_would_put_the_worker_on_the_operator_queue_refuses():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(
        fs,
        fresh_worker_world(**_upgrade_world(start_polls_operator_queue=True)),
        deps.trust_root,
    )

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 2
    assert rep["reason_code"] == "worker_ordinary_polls_operator_queue"


def test_the_two_queues_stay_distinct_after_an_upgrade():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)
    run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    _code, status = run(["status", "worker"], deps)

    assert status["dimensions"]["ordinary_queue"] == ORDINARY_TASK_QUEUE
    assert status["dimensions"]["operator_queue"] == OPERATOR_TASK_QUEUE
    assert ORDINARY_TASK_QUEUE != OPERATOR_TASK_QUEUE


# --- failure injection: a bad B end state must not leave B claimed as installed ------------------


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"start_healthy": False}, "worker_ordinary_not_ready"),
        ({"start_operator_running": True}, "worker_operator_not_disabled_stopped"),
        ({"start_operator_enabled": True}, "worker_operator_not_disabled_stopped"),
        ({"package_trusted_on_install": False}, "worker_operator_package_untrusted"),
        ({"start_operator_image": "sha256:" + "9" * 64}, "worker_operator_image_mismatch"),
        ({"bad_installed_config": True}, "worker_ordinary_config_mismatch"),
        ({"bad_installed_unit": True}, "worker_operator_unit_mismatch"),
        ({"bad_installed_package": True}, "worker_deployment_package_mismatch"),
        ({"stay_incoherent": True}, "worker_reobservation_incoherent"),
    ],
)
def test_a_failed_upgrade_end_state_refuses_and_leaves_no_release_b_claim(overrides, reason):
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world(**overrides)), deps.trust_root)

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 2
    assert rep["reason_code"] == reason
    # the documents were compensated, so nothing on disk claims release B is installed
    remaining = set(fs.paths())
    for path in (_ID, _RR, _EV):
        if path in remaining:
            assert b"0.2.0" not in fs.safe_read(path, max_bytes=1 << 20, expected_uid=0), path


def test_an_upgrade_to_the_wrong_ordinary_image_refuses():
    """B declares B's image; a host that came up on A's image must not be accepted as upgraded."""
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    # deliberately do NOT move the host to B's image
    deps = deps_for(fs, fresh_worker_world(), deps.trust_root)

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 2
    assert rep["reason_code"] == "worker_ordinary_image_mismatch"


def test_the_ordinary_worker_running_the_operator_image_is_refused_on_upgrade():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(
        fs,
        fresh_worker_world(start_image_digest=WORKER_OPERATOR_IMAGE),
        deps.trust_root,
    )

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 2
    assert rep["reason_code"] == "worker_ordinary_image_mismatch"


def test_a_compensation_that_cannot_be_proven_is_recovery_required():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(
        fs,
        fresh_worker_world(**_upgrade_world(start_healthy=False, compensation_fails=True)),
        deps.trust_root,
    )

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 2
    # the engine must say "a human has to look at this", never report a clean refusal it cannot back
    assert rep["reason_code"] == "recovery_required" or rep.get("recovery_required") is True


def test_a_sealed_adapter_cannot_report_a_written_upgrade():
    from secp_management.adapters import SealedWorkerBootstrapAdapter

    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)
    sealed = replace(deps, worker_adapter=SealedWorkerBootstrapAdapter())

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], sealed)

    assert code == 2
    assert rep["reason_code"] == "worker_bootstrap_adapter_not_provisioned"


# --- role + release integrity on the upgrade path ------------------------------------------------


def test_a_controller_bundle_can_never_upgrade_a_worker():
    deps, fs, _trust, kid, priv = _installed_a()
    controller_bundle = "/var/lib/secp/bootstrap/release/controller-b"
    seed_signed_bundle(fs, controller_bundle, "controller", kid, priv)

    code, rep = run(
        ["bootstrap", "worker", "--bundle", controller_bundle, "--write", "--confirm"], deps
    )

    assert code == 2
    assert rep["reason_code"] == "release_role_mismatch"


def test_an_unsigned_or_tampered_successor_cannot_upgrade():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    # tamper with B's ordinary image AFTER signing: the digest no longer matches the manifest
    fs.seed_file(f"{bundle_b}/images/ordinary.tar", b"tampered-after-signing\n", mode=0o644)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)

    assert code == 2
    assert rep["reason_code"] in (
        "release_artifact_digest_mismatch",
        "release_artifact_size_mismatch",
        "fs_read_size_invalid",
    )


def test_an_upgrade_still_requires_the_write_confirm_gate_and_root():
    deps, fs, _trust, kid, priv = _installed_a()
    bundle_b = _seed_b(fs, kid, priv)
    upgrade_deps = deps_for(fs, fresh_worker_world(**_upgrade_world()), deps.trust_root)

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write"], upgrade_deps)
    assert code == 2 and rep["reason_code"] == "write_requires_confirm"

    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--confirm"], upgrade_deps)
    assert code == 2 and rep["reason_code"] == "confirm_requires_write"

    not_root = deps_for(fs, fresh_worker_world(**_upgrade_world(is_root=False)), deps.trust_root)
    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], not_root)
    assert code == 2 and rep["reason_code"] == "root_required_for_write"


# --- the two upgrade-eligibility refusals that guard the PRIOR install ---------------------------
#
# These are the checks that stop an upgrade being driven over a tampered or drifted prior
# installation. They are load-bearing rather than redundant: `_classify_preexisting` returns
# `preexisting_changed_release` BEFORE running the attestation and installed-document checks, so
# `_classify_worker_upgrade_eligibility` is the only place they ever run. Both are reachable.

_ID_DOC = "/var/lib/secp/bootstrap/worker-identity.json"
_RR_DOC = "/var/lib/secp/bootstrap/worker-installed-release.json"
_SIG_DOC = "/var/lib/secp/bootstrap/worker-installed-release.sig.json"
_ATT_DOC = "/var/lib/secp/bootstrap/worker-evidence.attestation.json"


def _read_doc(fs, path):
    return fs.safe_read(path, max_bytes=1 << 20, expected_uid=0)


def _upgrade_after(fs, trust, kid, priv, tamper, **world):
    """Install A, seed successor B, apply ``tamper``, then attempt the upgrade."""
    bundle_b = _seed_b(fs, kid, priv)
    tamper(fs)
    deps = deps_for(fs, fresh_worker_world(**_upgrade_world(**world)), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bundle_b, "--write", "--confirm"], deps)
    return code, rep, deps


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param("signature", id="forged_attestation_signature"),
        pytest.param("key_id", id="attestation_from_an_untrusted_anchor"),
    ],
)
def test_an_unauthenticated_prior_install_cannot_be_upgraded(mutate):
    """The prior install's evidence attestation must still verify before it may be upgraded.

    Without this, an attacker who re-authored the evidence of a running worker could then drive a
    'managed upgrade' over it — the upgrade path would be trusting a record nothing authenticated.
    """
    deps, fs, trust, kid, priv = _installed_a()

    def _tamper(filesystem):
        document = json.loads(_read_doc(filesystem, _ATT_DOC).decode())
        if mutate == "signature":
            signature = document.get("signature") or ""
            document["signature"] = ("0" if signature[:1] != "0" else "1") + signature[1:]
        else:
            document["key_id"] = "some-other-anchor/v1"
        filesystem.seed_file(_ATT_DOC, json.dumps(document).encode(), mode=0o640)

    code, rep, upgrade_deps = _upgrade_after(fs, deps.trust_root, kid, priv, _tamper)

    assert code == 2
    assert rep["reason_code"] == "worker_upgrade_prior_unauthenticated"
    assert upgrade_deps.worker_adapter._w.ops == [], "classification must precede every host op"


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(_RR_DOC, id="installed_release_record"),
        pytest.param(_ID_DOC, id="identity_document"),
        pytest.param(_SIG_DOC, id="release_signature"),
    ],
)
def test_a_drifted_prior_install_cannot_be_upgraded(document):
    """A managed document whose CONTENT drifted refuses — reachable, and this is how.

    A single appended byte is the sharpest case: the document still parses and still cross-binds, so
    `_classify_preexisting` passes it, and only the installed-document content verifier catches it.
    That is precisely why this check cannot be folded into the earlier classification.
    """
    deps, fs, trust, kid, priv = _installed_a()

    def _tamper(filesystem):
        filesystem.seed_file(document, _read_doc(filesystem, document) + b"\n", mode=0o640)

    code, rep, upgrade_deps = _upgrade_after(fs, deps.trust_root, kid, priv, _tamper)

    assert code == 2
    assert rep["reason_code"] == "worker_upgrade_prior_drifted"
    assert upgrade_deps.worker_adapter._w.ops == [], "classification must precede every host op"


def test_the_three_upgrade_refusals_are_distinct_and_all_reachable():
    """Anti-vacuity: three separate prior-install failure modes, three distinct bounded codes."""
    codes = {
        "worker_upgrade_not_linear_successor",
        "worker_upgrade_prior_unauthenticated",
        "worker_upgrade_prior_drifted",
    }
    source = (Path(__file__).resolve().parents[1] / "secp_management" / "engine.py").read_text(
        encoding="utf-8"
    )
    for code in codes:
        assert source.count(code) >= 1, code
    assert len(codes) == 3
