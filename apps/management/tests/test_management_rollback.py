"""Content-bound, independently-authenticated rollback (SECP-PR5E round 4 blockers 2 + 3).

Rollback runs the ONE shared installed-document integrity verifier, which authenticates every
document
against digests derived INDEPENDENTLY from the signature-verified release record + the release-bound
identity — never from the (re-authorable) evidence — and checks
type/symlink/link-count/UID/GID/mode.
So a re-authored evidence that rewrote the recorded digests, a drifted/substituted document, or a
metadata drift is refused BEFORE any object is removed; a no-op or sealed adapter can never return
``written``.
"""

from __future__ import annotations

import json
from dataclasses import replace

from _mgmt_support import (
    FailingRollbackAdapter,
    FlakyFilesystem,
    NoOpRollbackAdapter,
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.adapters import SealedRollbackAdapter
from secp_management.cli import run
from secp_management.layout import ManagementLocations

_ID = "/var/lib/secp/bootstrap/worker-identity.json"
_RR = "/var/lib/secp/bootstrap/worker-installed-release.json"
_SIG = "/var/lib/secp/bootstrap/worker-installed-release.sig.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"
_DOCS = (_ID, _RR, _SIG, _EV)


def _installed_worker():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, _rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0
    return deps, fs


def _read(fs, path):
    return fs.safe_read(path, max_bytes=1 << 20, expected_uid=0)


# --- happy path ---


def test_rollback_dry_run_lists_only_created_objects():
    deps, _fs = _installed_worker()
    code, rep = run(["rollback", "worker"], deps)
    assert code == 0 and rep["mode"] == "dry_run"
    # identity, manifest, signature, evidence + the detached attestation
    assert len(rep["removable_bindings"]) == 5
    assert rep["ordinary_worker_restarted"] is False
    assert rep["controller_persistent_data_removed"] is False


def test_rollback_removes_exact_created_documents():
    deps, fs = _installed_worker()
    assert all(d in set(fs.paths()) for d in _DOCS)
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    assert sorted(rep["removed_bindings"]) == sorted(rep["removable_bindings"])
    assert not any(d in set(fs.paths()) for d in _DOCS)


def test_rollback_refuses_without_evidence():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, rep = run(["rollback", "worker"], deps)
    assert code == 2 and rep["reason_code"] in ("evidence_absent", "fs_read_not_regular")


# --- false-success prohibitions ---


def test_no_op_rollback_cannot_return_written():
    deps, fs = _installed_worker()
    noop = replace(deps, rollback_adapter=NoOpRollbackAdapter())
    code, rep = run(["rollback", "worker", "--write", "--confirm"], noop)
    assert code == 2 and rep["reason_code"] == "rollback_removal_incomplete"
    assert _ID in set(fs.paths())


def test_sealed_rollback_adapter_refuses_not_implemented():
    deps, fs = _installed_worker()
    sealed = replace(deps, rollback_adapter=SealedRollbackAdapter())
    code, rep = run(["rollback", "worker", "--write", "--confirm"], sealed)
    assert code == 2 and rep["reason_code"] == "rollback_not_implemented"
    assert all(d in set(fs.paths()) for d in _DOCS)


# --- integrity / authentication drift refuses BEFORE any removal ---


def _assert_refused_no_removal(deps, fs, reason):
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == reason
    assert all(d in set(fs.paths()) for d in _DOCS)


def test_altered_mode_refuses():
    deps, fs = _installed_worker()
    fs.seed_file(_ID, _read(fs, _ID), mode=0o600, uid=0)  # same content, wrong mode
    _assert_refused_no_removal(deps, fs, "rollback_document_mode_drift")


def test_forged_evidence_object_record_refuses():
    # re-author the (canonical) evidence to record a DIFFERENT manifest content digest — the
    # detached attestation binds the whole evidence, so it fails before any removal is attempted.
    deps, fs = _installed_worker()
    doc = json.loads(_read(fs, _EV))
    for rec in doc["object_records"]:
        if rec["kind"] == "release_manifest":
            rec["content_sha256"] = "sha256:" + "0" * 64  # forged
    fs.seed_file(_EV, canonical_json(doc).encode(), mode=0o640, uid=0)
    _assert_refused_no_removal(deps, fs, "evidence_attestation_untrusted")


def test_non_canonical_evidence_refuses():
    deps, fs = _installed_worker()
    fs.seed_file(_EV, b"  " + _read(fs, _EV), mode=0o640, uid=0)  # valid JSON, non-canonical bytes
    _assert_refused_no_removal(deps, fs, "rollback_evidence_content_drift")


def test_modified_release_record_refuses():
    # tampering the installed manifest breaks its Ed25519 signature → refused at record load
    deps, fs = _installed_worker()
    fs.seed_file(_RR, b"tampered manifest bytes\n", mode=0o640, uid=0)
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"].startswith("release_")
    assert all(d in set(fs.paths()) for d in _DOCS)


def test_hardlinked_object_refuses():
    deps, fs = _installed_worker()
    fs.seed_file(_ID, _read(fs, _ID), mode=0o640, uid=0, nlink=2)
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] in (
        "rollback_document_hardlinked",
        "fs_read_hardlinked",
    )
    assert all(d in set(fs.paths()) for d in _DOCS)


def test_symlinked_object_refuses():
    deps, fs = _installed_worker()
    fs.seed_symlink(_ID)
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] in (
        "rollback_document_symlink",
        "fs_read_not_regular",
        "identity_unreadable",
    )
    assert _RR in set(fs.paths()) and _EV in set(fs.paths())


def test_wrong_owner_refuses():
    deps, fs = _installed_worker()
    fs.seed_file(_ID, _read(fs, _ID), mode=0o640, uid=1000)
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] in (
        "rollback_document_untrusted_owner",
        "fs_read_untrusted_owner_or_mode",
    )
    assert all(d in set(fs.paths()) for d in _DOCS)


# --- round 5 blocker 4: transactional removal — a failed removal RESTORES every already-removed
#     document (proving each) and returns an ordinary refusal, OR reports recovery_required if a
#     restoration cannot be proven. Evidence is preserved until every other removal succeeds. ---


def _installed_flaky(rollback_at, *, flaky_kwargs=None, adapter_kwargs=None):
    """Install a worker over an InMemoryFilesystem, then wrap it in a FlakyFilesystem shared by both
    the engine and a FailingRollbackAdapter that raises on its ``rollback_at``-th removal."""
    trust, kid, priv, _pub = ephemeral_trust_root()
    inner = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(inner, bd, "worker", kid, priv)
    seed_write_ancestors(inner)
    assert (
        run(
            ["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(inner, fresh_worker_world(), trust),
        )[0]
        == 0
    )
    loc = ManagementLocations()
    fs = FlakyFilesystem(inner, **(flaky_kwargs or {}))
    adapter = FailingRollbackAdapter(fs, loc, fail_at=rollback_at, **(adapter_kwargs or {}))
    deps = deps_for(fs, fresh_worker_world(), trust, rollback_adapter=adapter, locations=loc)
    return deps, fs


def _rollback_restores_all(fail_at):
    deps, fs = _installed_flaky(fail_at)
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "fake_removal_failed"  # ordinary refusal
    assert all(d in set(fs.paths()) for d in _DOCS)  # fully restored — never left partial


def test_rollback_second_removal_failure_restores_everything():
    _rollback_restores_all(2)  # identity removed, manifest removal fails → identity restored


def test_rollback_third_removal_failure_restores_everything():
    # identity + manifest removed, signature removal fails → both restored
    _rollback_restores_all(3)


def test_rollback_final_evidence_removal_failure_restores_everything():
    # the plan removes evidence LAST (5th): identity, manifest, signature, attestation already gone.
    _rollback_restores_all(5)


def test_rollback_removal_failure_with_unprovable_restore_reports_recovery_required():
    # the 2nd removal fails AND restoring the already-removed identity silently writes nothing, so
    # the restoration cannot be proven → recovery_required (never an ordinary refusal after a
    # partial removal that could not be undone).
    deps, fs = _installed_flaky(2, flaky_kwargs={"silent_install_after": 0})
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"


def test_rollback_non_management_removal_error_still_restores_everything():
    # a real adapter can surface the hardened filesystem's OWN fault (a non-ManagementError); the
    # transactional guarantee must not depend on the exception type — every already-removed document
    # is restored and the failure is reported as a bounded rollback_transaction_error, never an
    # uncaught crash that leaves a half-removed install.
    deps, fs = _installed_flaky(3, adapter_kwargs={"filesystem_error": True})
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "rollback_transaction_error"
    assert all(d in set(fs.paths()) for d in _DOCS)  # fully restored


def test_rollback_non_management_error_with_unprovable_restore_reports_recovery_required():
    deps, fs = _installed_flaky(
        3, flaky_kwargs={"silent_install_after": 0}, adapter_kwargs={"filesystem_error": True}
    )
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "recovery_required"
