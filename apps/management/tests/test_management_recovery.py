"""Proven, fail-closed DOCUMENT compensation (SECP-PR5E round 5 blocker 2).

``_DocWriter.compensate`` proves every journal entry was reversed: an overwritten document is
restored to its exact original bytes/metadata (re-read + re-lstat), a newly-created document is
proven
absent. If ANY restoration, removal, or post-reversal reverification fails, the transaction reports
``recovery_required`` — it never swallows a compensation failure and never reports an ordinary
refusal
after leaving a document mutated. A ``FlakyFilesystem`` injects each failure mode.
"""

from __future__ import annotations

from dataclasses import replace

from _mgmt_support import (
    FlakyFilesystem,
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run

_ID = "/var/lib/secp/bootstrap/worker-identity.json"
_RR = "/var/lib/secp/bootstrap/worker-installed-release.json"
_SIG = "/var/lib/secp/bootstrap/worker-installed-release.sig.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"
_LATER = "2026-08-01T00:00:00+00:00"


def _seed(fs):
    bd = "/var/lib/secp/bootstrap/release/w"
    trust, kid, priv, _pub = ephemeral_trust_root()
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    return trust, bd


def _install(fs, trust, bd):
    assert (
        run(
            ["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs, fresh_worker_world(), trust),
        )[0]
        == 0
    )


def test_newly_created_document_removal_failure_reports_recovery_required():
    # a FRESH bootstrap whose final reobservation fails must REMOVE the newly-written documents;
    # if the removal itself cannot be performed, the transaction fails closed (recovery_required).
    inner = InMemoryFilesystem()
    trust, bd = _seed(inner)
    flaky = FlakyFilesystem(inner, fail_remove=True)
    deps = deps_for(flaky, fresh_worker_world(start_healthy=False), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"


def test_overwritten_document_restore_failure_reports_recovery_required():
    # a valid install re-bootstrapped at a later time overwrites the documents; if the final
    # reobservation fails AND restoring the originals raises, the transaction fails closed.
    inner = InMemoryFilesystem()
    trust, bd = _seed(inner)
    _install(inner, trust, bd)
    # transaction writes identity/record/signature (3 installs); the first restore is install #4.
    flaky = FlakyFilesystem(inner, fail_install_after=3)
    deps = replace(
        deps_for(flaky, fresh_worker_world(start_healthy=False), trust), clock=lambda: _LATER
    )
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"


def test_restore_that_silently_no_ops_fails_final_reverification():
    # if a restoration APPEARS to run but writes nothing, the mandatory post-restore proof (re-read
    # of the exact original bytes) fails, so compensation is unprovable → recovery_required (never a
    # false success that would leave the document holding the reinstalled bytes).
    inner = InMemoryFilesystem()
    trust, bd = _seed(inner)
    _install(inner, trust, bd)
    flaky = FlakyFilesystem(inner, silent_install_after=3)
    deps = replace(
        deps_for(flaky, fresh_worker_world(start_healthy=False), trust), clock=lambda: _LATER
    )
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"


def test_provable_document_compensation_restores_and_refuses_ordinarily():
    # the control case: when restoration IS provable, a failed re-install restores the originals and
    # returns an ORDINARY refusal (not recovery_required) — the install is not bricked.
    inner = InMemoryFilesystem()
    trust, bd = _seed(inner)
    _install(inner, trust, bd)
    original = inner.safe_read(_ID, max_bytes=1 << 18, expected_uid=0)
    deps = replace(
        deps_for(inner, fresh_worker_world(start_healthy=False), trust), clock=lambda: _LATER
    )
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "worker_ordinary_not_ready"
    assert inner.safe_read(_ID, max_bytes=1 << 18, expected_uid=0) == original  # restored exactly
    code, st = run(["status", "worker"], deps_for(inner, prepared_worker_world(), trust))
    assert code == 0 and st["ok"] is True  # not bricked
