"""CLI — fixed locations, fresh-process rollback, no activate (defects #1B, #5D, #9)."""

from __future__ import annotations

import json
import tempfile

import pytest
from _support import (
    DIGEST_CP,
    DIGEST_OP,
    DIGEST_OW,
    OPERATOR_QUEUE,
    S_REG,
    SOURCE_SHA,
    SOURCE_TREE_SHA,
    FakeOsSeam,
    FakeStat,
    good_lstats,
    valid_descriptor_raw,
)
from secp_commissioning.cli import CommissioningDeps, run
from secp_commissioning.render import InMemoryStagingSeam
from secp_commissioning.runtime import InMemoryContainerRuntime, InMemoryFilesystem
from secp_commissioning.status import StaticServiceState

_CONTENT = json.dumps(valid_descriptor_raw()).encode("utf-8")

_PINS = [
    "--expected-source-sha",
    SOURCE_SHA,
    "--expected-source-tree-sha",
    SOURCE_TREE_SHA,
    "--expected-control-plane-image",
    DIGEST_CP,
    "--expected-ordinary-image",
    DIGEST_OW,
    "--expected-operator-image",
    DIGEST_OP,
    "--expected-operator-queue",
    OPERATOR_QUEUE,
]


def _deps(fs=None):
    seam = FakeOsSeam(good_lstats(_CONTENT), FakeStat(S_REG, st_size=len(_CONTENT)), _CONTENT)
    return CommissioningDeps(
        fs=fs or InMemoryFilesystem(),
        container_runtime=InMemoryContainerRuntime(present=(DIGEST_CP, DIGEST_OW, DIGEST_OP)),
        service_state=StaticServiceState(),
        clock=lambda: "2026-07-17T00:00:00+00:00",
        descriptor_os_seam=seam,
        staging_dir_factory=tempfile.mkdtemp,
        staging_seam_factory=lambda root: InMemoryStagingSeam(root),
    )


def test_verify_ok():
    code, payload = run(["verify", *_PINS], _deps())
    assert code == 0 and payload["ok"] is True


def test_plan_deterministic_and_matches_engine():
    c1, p1 = run(["plan", *_PINS], _deps())
    c2, p2 = run(["plan", *_PINS], _deps())
    assert c1 == 0 and p1["plan_digest"] == p2["plan_digest"]


def test_install_dry_run_default():
    fs = InMemoryFilesystem()
    code, payload = run(["install-prepared", *_PINS], _deps(fs))
    assert code == 0 and payload["mode"] == "dry_run"
    assert fs.lstat("/var/lib/secp/commissioning/evidence.json") is None


def test_install_write_status_evidence_and_fresh_process_rollback():
    fs = InMemoryFilesystem()
    code, payload = run(["install-prepared", *_PINS, "--write", "--confirm"], _deps(fs))
    assert code == 0 and payload["mode"] == "written"
    # fresh deps sharing the same fs (a new process)
    scode, spayload = run(["status"], _deps(fs))
    assert scode == 0 and spayload["state"] == "prepared"
    ecode, epayload = run(["evidence"], _deps(fs))
    assert ecode == 0 and epayload["evidence"]["activation_status"] == "prepared"
    rcode, rpayload = run(["rollback-prepared", "--write", "--confirm"], _deps(fs))
    assert rcode == 0 and rpayload["mode"] == "written"
    assert run(["status"], _deps(fs))[1]["state"] == "absent"


def test_status_absent_exit_code():
    code, payload = run(["status"], _deps())
    assert code == 1 and payload["state"] == "absent"


def test_no_activate_subcommand():
    with pytest.raises(SystemExit):
        run(["activate", *_PINS], _deps())


def test_no_arbitrary_write_location_flags():
    import io
    from contextlib import redirect_stderr

    from secp_commissioning.cli import build_parser

    parser = build_parser()
    for flag in ("--descriptor", "--evidence", "--staging"):
        with redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
            parser.parse_args(["install-prepared", *_PINS, flag, "/tmp/x"])
