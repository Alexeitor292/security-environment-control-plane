"""Regressions for the SECP-PR5H-B2A trusted-ancestor CI reliability defect.

The root/systemd/Docker fences intermittently failed with ``bootstrap_file_install_failed`` while
installing under ``/etc/systemd/system/...``, and PR5F's inline preflight once reported
``/etc: not root:root`` -- on unchanged code, before any product test had run, and passing
again on a later attempt. Three things were wrong, and none of them was the security rule itself:

1. **Unattributable.** ``_install_file`` maps every ``FilesystemError`` to one opaque
   ``bootstrap_file_install_failed``, so nothing recorded WHICH ancestor was untrusted or what it
   observed. The only available response was a blind re-run.
2. **Misclassified.** An invalid machine surfaced as 30 errored product tests, which reads as "the
   feature is broken".
3. **Unproven isolation.** Nothing asserted that the root suites leave the fixed system parents'
   metadata exactly as they found it, so contamination could not be ruled out.

This suite closes 2 and 3 and proves the rule still fails closed. It runs everywhere: the isolation
and fail-closed proofs use the hardened in-memory filesystem and the attestation gate's pure
functions, so they are not gated on POSIX or root.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import os
import posixpath
import re
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from secp_commissioning.runtime import FilesystemError, InMemoryFilesystem

_GATE_DIR = str(Path(__file__).resolve().parents[1] / "infra" / "ci")
if _GATE_DIR not in sys.path:  # the gate is a standalone CI script, not an installed package
    sys.path.insert(0, _GATE_DIR)

import attest_trusted_ancestry as gate  # noqa: E402

#: POSIX-only proofs: mode/ownership semantics and absolute-POSIX paths do not exist on Windows.
_POSIX_ONLY = pytest.mark.skipif(
    not hasattr(os, "getuid"), reason="POSIX path and ownership semantics are POSIX-only"
)

#: the fixed system parents a root fence traverses and must never mutate
FIXED_SYSTEM_PARENTS = ("/", "/etc", "/etc/systemd", "/etc/systemd/system")


# --------------------------------------------------------------------------- the gate's contract


def test_the_three_outcomes_are_distinct_exit_codes() -> None:
    """An invalid machine must never be confusable with a product-test failure, and pytest's own
    failure code (1) must not collide with either."""
    assert gate.EXIT_OK == 0
    assert gate.EXIT_INFRASTRUCTURE_INVALID == 78
    assert gate.EXIT_GATE_UNUSABLE == 2
    codes = {gate.EXIT_OK, gate.EXIT_INFRASTRUCTURE_INVALID, gate.EXIT_GATE_UNUSABLE}
    assert len(codes) == 3
    assert 1 not in codes  # pytest's generic failure code stays unambiguous


def test_the_gate_walks_the_complete_ancestry_in_traversal_order() -> None:
    assert gate.ancestors_of("/etc/systemd/system") == list(FIXED_SYSTEM_PARENTS)
    assert gate.ancestors_of("/") == ["/"]
    assert gate.ancestors_of("/a/b/c") == ["/", "/a", "/a/b", "/a/b/c"]


def test_the_gate_refuses_a_relative_path_rather_than_guessing() -> None:
    with pytest.raises(ValueError):
        gate.ancestors_of("etc/systemd")


def test_the_write_mask_is_group_and_other_write() -> None:
    """The rule the gate mirrors: an ancestor writable by any identity other than the single trusted
    owner makes everything beneath it attacker-influenceable."""
    assert gate.WRITE_MASK == 0o022
    assert 0o755 & gate.WRITE_MASK == 0
    for unsafe in (0o775, 0o757, 0o777):
        assert unsafe & gate.WRITE_MASK != 0


def test_the_gate_classifies_each_untrusted_posture_by_name(tmp_path: Path) -> None:
    """Bounded, specific reasons -- the diagnosability that was missing."""
    target = tmp_path / "child"
    target.mkdir()
    observation = gate.observe(str(target))
    assert observation["statable"] is True
    assert observation["kind"] == "directory"
    assert set(observation) >= {"uid", "gid", "mode", "dev", "inode", "nlink", "path"}

    missing = gate.observe(str(tmp_path / "absent"))
    assert missing["statable"] is False
    assert missing["absent"] is True
    assert missing["problems"] == []  # ABSENT is not UNTRUSTED -- see below

    regular = tmp_path / "file"
    regular.write_bytes(b"x")
    assert "not_a_directory" in gate.observe(str(regular))["problems"]  # type: ignore[operator]


def test_the_gate_never_emits_a_file_content_or_a_secret_bearing_leaf(tmp_path: Path) -> None:
    """Evidence is metadata about DIRECTORIES only. The gate must not become a disclosure channel:
    the readiness gate, credentials and keys are files, and none of them is ever stat'd or read."""
    secret = tmp_path / "gate.secret"
    secret.write_bytes(b"7c" * 32)
    record = gate.observe(str(tmp_path))
    rendered = repr(record)
    assert "7c7c" not in rendered
    assert "gate.secret" not in rendered


# ------------------------------------- the rule still fails closed, and writes nothing


def _seed_chain(fs: InMemoryFilesystem) -> None:
    for directory in FIXED_SYSTEM_PARENTS[1:]:
        fs.seed_dir(directory, uid=0, gid=0, mode=0o755)


@pytest.mark.parametrize(
    "uid,gid,mode",
    [
        (1000, 0, 0o755),  # not root-owned
        (0, 1000, 0o755),  # not root-GROUP-owned
        (0, 0, 0o775),  # group-writable
        (0, 0, 0o777),  # world-writable
    ],
)
def test_a_drifted_ancestor_still_fails_closed(uid: int, gid: int, mode: int) -> None:
    """The correction must not have relaxed anything: a genuinely drifted ancestor is still refused,
    exactly as the intermittent CI failures were RIGHT to refuse."""
    fs = InMemoryFilesystem()
    _seed_chain(fs)
    fs.seed_dir("/etc/systemd/system", uid=uid, gid=gid, mode=mode)
    with pytest.raises(FilesystemError):
        fs.atomic_install(
            "/etc/systemd/system/secp-controller.service", b"[Unit]\n", uid=0, gid=0, mode=0o644
        )


def test_no_write_occurs_after_an_ancestry_refusal() -> None:
    """A refusal must be total: nothing is created, and no temporary artifact is left behind."""
    fs = InMemoryFilesystem()
    _seed_chain(fs)
    fs.seed_dir("/etc/systemd", uid=0, gid=1000, mode=0o755)  # a drifted INTERMEDIATE ancestor
    before = set(fs.paths())
    with pytest.raises(FilesystemError):
        fs.atomic_install(
            "/etc/systemd/system/secp-controller.service", b"[Unit]\n", uid=0, gid=0, mode=0o644
        )
    assert set(fs.paths()) == before  # not even a .tmp
    assert fs.lstat("/etc/systemd/system/secp-controller.service") is None


def test_a_trusted_chain_still_installs() -> None:
    """The positive control: with every ancestor trusted the same write succeeds, so the refusals
    above are attributable to ancestry and not to a broken harness."""
    fs = InMemoryFilesystem()
    _seed_chain(fs)
    fs.atomic_install(
        "/etc/systemd/system/secp-controller.service", b"[Unit]\n", uid=0, gid=0, mode=0o644
    )
    assert fs.lstat("/etc/systemd/system/secp-controller.service") is not None


# ------------------------------------------------- no suite may mutate a fixed system parent


def _fixed_parent_tuples() -> dict[str, tuple[int, int, int] | None]:
    """The exact (uid, gid, mode) of each fixed system parent, or None where it does not exist."""
    snapshot: dict[str, tuple[int, int, int] | None] = {}
    for path in FIXED_SYSTEM_PARENTS:
        try:
            st = os.lstat(path)
        except OSError:
            snapshot[path] = None
            continue
        snapshot[path] = (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
    return snapshot


def test_no_source_or_test_chowns_or_chmods_a_fixed_system_parent() -> None:
    """A static proof of the isolation property, so it holds for tests that never run on this host.

    The intermittent failures were consistent with an earlier test mutating a shared parent, and
    that hypothesis could not be ruled out by inspection alone. This asserts it structurally: no
    source or test file may ``chown``/``chmod`` a fixed system parent, whatever the ordering.

    Matched on CANONICAL paths, not on quoted literals. The literal form this used to use
    shared the review finding that hit the workflow scan: a mode change whose argument is written
    with a trailing slash, a doubled leading slash, or a trailing dot names the same target and
    every one of those spellings evaded it. See `_canonical_path`.

    (Spelled without a quoted fixed-parent literal beside a mode-change call, because this scan
    reads its own file and treats comment text as an act -- it caught these very lines twice.)"""
    root = Path(__file__).resolve().parents[1]
    fixed = set(FIXED_SYSTEM_PARENTS)
    offenders: list[str] = []
    for path in list(root.glob("apps/**/*.py")) + list(root.glob("tests/**/*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if ("os.chown(" not in line) and ("os.chmod(" not in line):
                continue
            if _quoted_path_literals(line) & fixed:
                offenders.append(f"{path.relative_to(root)}: {line.strip()[:80]}")
    assert offenders == [], offenders


def test_the_fixed_system_parents_are_unchanged_by_this_session() -> None:
    """A runtime guard: whatever else this session did, the shared parents look as they do now.

    Paired with the static proof above, this is the "an earlier test cannot alter trusted parent
    metadata for a later test" regression: it fails loudly if a test mutated one."""
    first = _fixed_parent_tuples()
    second = _fixed_parent_tuples()
    assert first == second
    for path, observed in first.items():
        if observed is None or path == "/":
            continue
        uid, gid, mode = observed
        # If this ever fires on CI it means the MACHINE is invalid, which the attestation gate now
        # reports as infrastructure_invalid before any product test runs.
        assert (uid, gid) == (0, 0), f"{path} is not root:root ({uid}:{gid})"
        assert mode & gate.WRITE_MASK == 0, f"{path} is group/other-writable ({oct(mode)})"


@_POSIX_ONLY
def test_an_absent_code_owned_directory_is_not_a_failure(tmp_path: Path) -> None:
    """The distinction the first CI run of this gate exposed -- in my own wiring, not the runner.

    `/etc/secp/controller` is created by the fence (or its prepare step), so at gate time it may not
    exist. My first wiring reported that as `infrastructure_invalid`, which asserts a creation ORDER
    this gate has no business asserting and refuses a perfectly valid machine. Every ancestor that
    EXISTS must be trusted; an absent code-owned component is recorded and allowed."""
    # A chain whose ENTIRE tail is absent, rooted directly at "/" -- deliberately NOT under
    # tmp_path: on Linux that lives beneath /tmp, which is legitimately world-writable (1777), so
    # walking it would report a real and correct untrusted-ancestor finding and prove nothing about
    # absence. The first CI run of this test failed exactly that way.
    code, report, untrusted = gate.attest(["/secp-attest-absent-probe/not/created/yet"])
    assert code == gate.EXIT_OK
    assert report["verdict"] == "trusted"
    assert untrusted == []
    absent = report["absent"]
    assert isinstance(absent, list)
    assert [Path(entry).name for entry in absent] == [
        "secp-attest-absent-probe",
        "not",
        "created",
        "yet",
    ]


@_POSIX_ONLY
def test_an_untrusted_existing_prefix_still_fails_even_with_an_absent_tail(tmp_path: Path) -> None:
    """Allowing an absent tail must not become a way to skip checking the existing prefix."""
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    os.chmod(prefix, 0o775)  # group-writable: a real, existing, untrusted ancestor
    code, report, untrusted = gate.attest([str(prefix / "absent" / "tail")])
    assert code == gate.EXIT_INFRASTRUCTURE_INVALID
    assert report["verdict"] == "infrastructure_invalid"
    offending = {str(o["path"]) for o in untrusted}
    assert str(prefix) in offending  # the prefix itself is named, not merely the tail
    entry = next(o for o in untrusted if str(o["path"]) == str(prefix))
    problems = entry["problems"]
    assert isinstance(problems, list) and "group_or_other_writable" in problems


# --------------------------------- teardown restores what a test temporarily changed


@pytest.mark.skipif(
    not hasattr(os, "getuid"), reason="POSIX mode/ownership semantics are POSIX-only"
)
def test_teardown_restores_the_exact_original_stat_tuple(tmp_path: Path) -> None:
    """When a test must temporarily change a test-OWNED object, teardown restores the exact tuple.

    Demonstrated on a test-owned directory rather than a shared parent, because the contract is that
    a shared parent is never changed at all (proven above)."""
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o755)
    original = os.lstat(owned)
    before = (original.st_uid, original.st_gid, stat.S_IMODE(original.st_mode))

    os.chmod(owned, 0o700)
    assert stat.S_IMODE(os.lstat(owned).st_mode) == 0o700
    os.chmod(owned, before[2])  # the teardown contract

    restored = os.lstat(owned)
    assert (restored.st_uid, restored.st_gid, stat.S_IMODE(restored.st_mode)) == before
    assert restored.st_ino == original.st_ino  # the same object, not a replacement


# ------------------------------------------------- CI-R1: filesystem classification is TOTAL
#
# The gate caught every OSError from `os.lstat` and called it `absent=True, problems=[]`. Only
# ENOENT
# proves absence. Every other error means the posture could not be OBSERVED, which is not the same
# thing: EACCES/EPERM say something is denying the root gate a stat it should always get, ENOTDIR/
# ELOOP say a component is not the kind of object the contract assumes, EIO/ESTALE say the storage
# answer is unreliable, and an unknown errno is by definition uncharacterised. Any of those
# passing as "absent" would let an UNOBSERVABLE ancestor through the gate and then be traversed
# by the installer.

_ESTALE = getattr(errno, "ESTALE", None)

#: (errno, expected verdict). ENOENT is the SOLE accepted absence case.
CLASSIFICATION_MATRIX: list[tuple[int, bool]] = [
    (errno.ENOENT, True),
    (errno.EACCES, False),
    (errno.EPERM, False),
    (errno.EIO, False),
    (errno.ENOTDIR, False),
    (errno.ELOOP, False),
    (errno.ENAMETOOLONG, False),
    (4242, False),  # an errno this gate has never heard of
] + ([(_ESTALE, False)] if _ESTALE is not None else [])


def _with_lstat_errno(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    """Make every ``os.lstat`` the gate performs raise exactly ``code``, deterministically."""

    def _raise(path: str, *args: object, **kwargs: object) -> None:
        raise OSError(code, "injected")

    monkeypatch.setattr(gate.os, "lstat", _raise)


@pytest.mark.parametrize("code,expect_absent", CLASSIFICATION_MATRIX)
def test_only_enoent_is_classified_as_absence(
    monkeypatch: pytest.MonkeyPatch, code: int, expect_absent: bool
) -> None:
    _with_lstat_errno(monkeypatch, code)
    record = gate.observe("/probe")
    assert record["statable"] is False
    assert record["errno"] == code  # the bounded numeric errno is retained
    if expect_absent:
        assert record["absent"] is True
        assert record["problems"] == []
    else:
        assert record["absent"] is False
        assert record["problems"] == ["not_statable"]


@pytest.mark.parametrize("code,expect_absent", CLASSIFICATION_MATRIX)
def test_an_unobservable_ancestor_is_infrastructure_invalid(
    monkeypatch: pytest.MonkeyPatch, code: int, expect_absent: bool
) -> None:
    """The verdict, not just the record: an unobservable ancestor must stop the job at exit 78."""
    _with_lstat_errno(monkeypatch, code)
    exit_code, report, untrusted = gate.attest(["/etc/systemd/system"])
    if expect_absent:
        assert exit_code == gate.EXIT_OK
        assert report["verdict"] == "trusted"
        assert untrusted == []
    else:
        assert exit_code == gate.EXIT_INFRASTRUCTURE_INVALID
        assert report["verdict"] == "infrastructure_invalid"
        assert untrusted, "an unobservable ancestor must be reported"
        for entry in untrusted:
            assert entry["problems"] == ["not_statable"]


@pytest.mark.parametrize("code,_expect", [c for c in CLASSIFICATION_MATRIX if not c[1]])
def test_no_refusal_exposes_exception_text_or_a_host_value(
    monkeypatch: pytest.MonkeyPatch, code: int, _expect: bool
) -> None:
    """Bounded evidence only: the numeric errno, never the OS message."""
    _with_lstat_errno(monkeypatch, code)
    _exit_code, report, _untrusted = gate.attest(["/etc/systemd/system"])
    rendered = repr(report)
    assert "injected" not in rendered  # the exception's own text
    assert "strerror" not in rendered


def test_a_refused_observation_is_never_repaired_or_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One observation per ancestor. The gate never re-stats a refused component, never repairs it,
    and performs no write of any kind -- it only classifies."""
    calls: list[str] = []

    def _raise(path: str, *args: object, **kwargs: object) -> None:
        calls.append(path)
        raise OSError(errno.EACCES, "injected")

    monkeypatch.setattr(gate.os, "lstat", _raise)
    for forbidden in ("chown", "chmod", "mkdir", "makedirs", "rename", "replace", "remove"):
        monkeypatch.setattr(
            gate.os,
            forbidden,
            lambda *a, **k: pytest.fail("the gate must never mutate the filesystem"),
            raising=False,
        )
    code, _report, untrusted = gate.attest(["/etc/systemd/system"])
    assert code == gate.EXIT_INFRASTRUCTURE_INVALID
    assert untrusted
    assert calls == ["/", "/etc", "/etc/systemd", "/etc/systemd/system"]  # once each, in order


@_POSIX_ONLY
def test_the_cli_exits_78_so_the_product_test_step_never_starts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate is a job GATE: a non-zero exit fails the step, so the product-test step that follows
    it in the same job never runs."""

    def _raise(path: str, *args: object, **kwargs: object) -> None:
        raise OSError(errno.EACCES, "injected")

    monkeypatch.setattr(gate.os, "lstat", _raise)
    assert gate.main(["/etc/systemd/system"]) == gate.EXIT_INFRASTRUCTURE_INVALID
    out = capsys.readouterr().out
    assert "infrastructure_invalid" in out
    assert "not_statable" in out
    assert "the product tests were not run" in out


def test_a_trusted_observation_still_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive control for the whole CI-R1 matrix."""

    class _Fake:
        st_mode = stat.S_IFDIR | 0o755
        st_uid = 0
        st_gid = 0
        st_dev = 1
        st_ino = 2
        st_nlink = 3

    monkeypatch.setattr(gate.os, "lstat", lambda path, *a, **k: _Fake())
    code, report, untrusted = gate.attest(["/etc/systemd/system"])
    assert code == gate.EXIT_OK
    assert report["verdict"] == "trusted"
    assert untrusted == []


# ------------------------------------------------- CI-R2: workflow order proofs are JOB-LOCAL
#
# The previous proof searched the whole workflow PREFIX, so an attestation in an EARLIER job
# satisfied it for every later job -- a job could have shipped with no gate at all and the test
# would still have passed. These proofs parse the workflow and inspect `jobs.<job>.steps`
# positionally, inside one job.

_GATE_SCRIPT = "infra/ci/attest_trusted_ancestry.py"

#: job key -> the product-test step that must be preceded, IN THAT JOB, by an attestation step.
REQUIRED_GATED_JOBS: dict[str, str] = {
    # SECP-WSA. This fence was root-elevated with NO attestation gate at all: its sandbox is built
    # directly beneath `/` (apps/commissioning/tests/test_commissioning_realfs.py:26), so an
    # untrusted `/` would have surfaced as errored product tests -- "the feature is broken" --
    # instead of a classified invalid machine, which is the exact confusion this suite exists to
    # prevent. `/` is its complete ancestry, so `/` is what it attests.
    "backend-realfs-root": "Run production RealFilesystem tests as root",
    "backend-discovery-activation-root": (
        "Run PR5F fixed-layout root transaction tests (no skips)"
    ),
    "backend-deployment-root": "Run deployment root-security tests as root (no skips)",
    "backend-management-root": "Run management-plane root-security tests as root (no skips)",
    "backend-management-real-adapters-root": (
        "Run the real management adapter E2E as root (no skips)"
    ),
    "backend-management-controller-real-adapters-root": (
        "Drive the real controller bootstrap + migration + observer as root (no skips)"
    ),
}

#: PR5F additionally sequences two preparation steps, each of which must be preceded by the
#: attestation covering the tree it is about to create in.
PR5F_PREPARATION_ORDER: list[tuple[str, str]] = [
    ("/var/lib", "Prepare the fixed trusted production parent"),
    ("/etc", "Prepare the fixed trusted controller-config parent (PR5F.1 env file)"),
]


def _workflow() -> dict:
    text = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    return yaml.safe_load(text)


def _steps(workflow: dict, job: str) -> list[dict]:
    assert job in workflow["jobs"], f"job {job} is absent from the workflow"
    return list(workflow["jobs"][job]["steps"])


def _is_gate(step: dict) -> bool:
    return _GATE_SCRIPT in str(step.get("run", ""))


def _index_of_step(steps: list[dict], name: str) -> int:
    for index, step in enumerate(steps):
        if step.get("name") == name:
            return index
    raise AssertionError(f"step {name!r} not found in this job")


def _gate_indices(steps: list[dict]) -> list[int]:
    return [index for index, step in enumerate(steps) if _is_gate(step)]


def assert_job_local_gate_order(workflow: dict) -> None:
    """The CI-R2 contract, factored so the mutation regressions can drive it directly."""
    for job, product_step in REQUIRED_GATED_JOBS.items():
        steps = _steps(workflow, job)
        product_index = _index_of_step(steps, product_step)
        gates = _gate_indices(steps)
        assert gates, f"{job}: no attestation step in THIS job"
        assert min(gates) < product_index, (
            f"{job}: every attestation runs at or after the product-test step"
        )
        for index in gates:
            step = steps[index]
            assert step.get("continue-on-error") in (None, False), f"{job}: gate continue-on-error"
            assert "if" not in step, f"{job}: gate is conditional"
            run = str(step["run"])
            assert "|| true" not in run, f"{job}: gate exit code is swallowed"
            assert "||" not in run and "; true" not in run, f"{job}: gate exit code is swallowed"
            assert "set +e" not in run, f"{job}: gate exit code is swallowed"

    # PR5F sequences its preparation steps too: each must follow the attestation for its tree.
    steps = _steps(workflow, "backend-discovery-activation-root")
    for tree, preparation in PR5F_PREPARATION_ORDER:
        prep_index = _index_of_step(steps, preparation)
        covering = [
            index
            for index in _gate_indices(steps)
            if tree in str(steps[index]["run"]) and index < prep_index
        ]
        assert covering, f"no {tree} attestation precedes {preparation!r}"
    # and the full-path attestation still precedes the product tests
    product_index = _index_of_step(steps, REQUIRED_GATED_JOBS["backend-discovery-activation-root"])
    full = [
        index
        for index in _gate_indices(steps)
        if "/etc/secp/controller" in str(steps[index]["run"]) and index < product_index
    ]
    assert full, "no full-path attestation precedes the PR5F product tests"


def test_every_root_fence_attests_ancestry_in_its_own_job_before_its_product_tests() -> None:
    assert_job_local_gate_order(_workflow())


def test_every_required_job_exists_and_is_pinned_to_a_deterministic_image() -> None:
    workflow = _workflow()
    for job in REQUIRED_GATED_JOBS:
        runs_on = workflow["jobs"][job]["runs-on"]
        assert runs_on != "ubuntu-latest", f"{job} is on a rolling image"


# ---- mutation regressions: the proof must FAIL when the property is broken -------------------


def _mutated() -> dict:
    """A deep-enough copy that a mutation cannot leak into another test."""
    return copy.deepcopy(_workflow())


@contextlib.contextmanager
def refuses(mutated: object, pristine: object) -> Iterator[None]:
    """Assert the mutation ACTUALLY LANDED, then that the contract refuses it.

    A mutation that silently fails to apply is indistinguishable from one the guard caught: both
    are a green test. Every regression below would still pass if its edit quietly became a no-op --
    a `.replace()` whose needle moved, a step name that was renamed, a key that is now spelled
    differently -- and the suite would report that the property is defended when nothing checked it.

    So the edit is proven to have changed the subject BEFORE the guard is asked about it. This is a
    guard on the guards, and it is the reason these regressions can be cited as evidence at all."""
    assert mutated != pristine, (
        "the mutation did not change anything, so this test would pass even if the guard did "
        "nothing at all -- fix the mutation, not the guard"
    )
    with pytest.raises(AssertionError):
        yield


def test_the_mutation_harness_itself_fails_on_a_no_op_edit() -> None:
    """The control for `refuses`: a mutation that changes nothing must be reported, not tolerated.

    Without this, `refuses` is itself an unproven claim -- exactly the shape this suite refuses."""
    workflow = _mutated()  # deep copy, but nothing changed
    with pytest.raises(AssertionError, match="did not change anything"):
        with refuses(workflow, _workflow()):
            pass  # never reached


def test_the_mutation_harness_requires_the_guard_to_actually_refuse() -> None:
    """The other half: a landed mutation that the guard does NOT refuse must fail the test."""
    workflow = _mutated()
    workflow["jobs"]["backend-realfs-root"]["name"] = "renamed, but no guard cares"
    with pytest.raises(pytest.fail.Exception):
        with refuses(workflow, _workflow()):
            pass  # the guard raised nothing, so `pytest.raises` must fail


def test_the_proof_fails_when_the_last_root_job_loses_its_gate() -> None:
    workflow = _mutated()
    job = "backend-management-controller-real-adapters-root"
    steps = workflow["jobs"][job]["steps"]
    workflow["jobs"][job]["steps"] = [s for s in steps if not _is_gate(s)]
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_moves_after_its_product_test_step() -> None:
    workflow = _mutated()
    job = "backend-deployment-root"
    steps = workflow["jobs"][job]["steps"]
    gate_index = _gate_indices(steps)[0]
    moved = steps.pop(gate_index)
    steps.append(moved)  # now strictly after the product-test step
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_only_an_earlier_job_has_a_gate() -> None:
    """The exact hole in the old prefix-search proof."""
    workflow = _mutated()
    job = "backend-management-real-adapters-root"
    workflow["jobs"][job]["steps"] = [s for s in workflow["jobs"][job]["steps"] if not _is_gate(s)]
    # an EARLIER job keeps its gate, which used to be enough to satisfy the old test
    assert _gate_indices(_steps(workflow, "backend-deployment-root"))
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_is_allowed_to_continue_on_error() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    steps[_gate_indices(steps)[0]]["continue-on-error"] = True
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_becomes_conditional() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    steps[_gate_indices(steps)[0]]["if"] = "always()"
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_swallows_the_exit_code() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    index = _gate_indices(steps)[0]
    steps[index]["run"] = str(steps[index]["run"]).rstrip() + " || true\n"
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_the_pr5f_etc_attestation_moves_after_its_preparation() -> None:
    workflow = _mutated()
    steps = workflow["jobs"]["backend-discovery-activation-root"]["steps"]
    prep = _index_of_step(
        steps, "Prepare the fixed trusted controller-config parent (PR5F.1 env file)"
    )
    covering = [i for i in _gate_indices(steps) if "/etc" in str(steps[i]["run"]) and i < prep]
    assert covering
    moved = steps.pop(covering[-1])
    steps.insert(prep, moved)  # now at/after the preparation step
    with refuses(workflow, _workflow()):
        assert_job_local_gate_order(workflow)


def test_the_unmutated_workflow_passes() -> None:
    """The control: every mutation above is a real break, not a broken assertion."""
    assert_job_local_gate_order(_workflow())


# --------------------------- SECP-WSA: the fence runs inside a CONTROLLED environment
#
# Pinning `runs-on` was never enough, and the evidence now says so directly. In run 30522895412 job
# 90807107915 observed `/etc` uid=1001 gid=1001 (dev 2049, inode 42, mount `/`) and exited 78,
# while two SIBLING jobs of that same run -- same commit, same `ImageVersion 20260726.254.1` --
# observed uid=0. That is per-VM variance, so no image pin can remove it, and a green root fence on
# a hosted VM is a coin flip rather than evidence.
#
# The tier-1 fences therefore execute inside a digest-pinned container whose `/etc` comes from a
# content-addressed layer and is root-owned by construction. The RULE is untouched:
# `attest_trusted_ancestry.py` is byte-for-byte unchanged and still decides the job. It is sound to
# move it because the gate is namespace-relative by construction -- it observes the filesystem only
# through `os.lstat` on plain absolute paths, `ancestors_of` is pure string splitting, and its one
# `/proc` read is `/proc/self/mountinfo` (evidence only, feeding no verdict). Run inside the
# container, it attests the container's ancestry.
#
# These proofs assert the environment is genuinely controlled, that the pin cannot drift between
# its copies, and -- the property most worth defending -- that the gate is never REDIRECTED out of
# the environment the product tests then run in.

_CONTROLLED_ENV_MANIFEST = (
    Path(__file__).resolve().parents[1] / "infra" / "ci" / "controlled-root-env.json"
)

#: Root fences that still execute directly on the nondeterministic hosted VM. Both drive real
#: systemd units (`systemctl daemon-reload` / `is-enabled` / `is-active`) and a real container
#: runtime, which a GitHub `container:` job provides neither of, so they are HELD pending the
#: operator decision on a job-constructed privileged environment (tier 2). This set may only ever
#: SHRINK; `test_the_uncontrolled_set_is_exactly_the_two_systemd_fences` refuses an addition.
NOT_YET_CONTROLLED: frozenset[str] = frozenset(
    {
        "backend-management-real-adapters-root",
        "backend-management-controller-real-adapters-root",
    }
)

#: Ways a gate could be made to observe some OTHER namespace than the one the product tests use.
#: A gate that attests a machine the tests never run on proves nothing at all. Scanned against
#: whitespace-NORMALISED text (see `_assert_runs_in_this_environment`), so a tab- or newline-
#: separated spelling matches exactly as a space-separated one does.
_NAMESPACE_ESCAPES = ("docker ", "podman ", "ssh ", "chroot ", "nsenter ", "unshare ")

#: An absolute path as it appears either in shell (`chown root:root /etc`) or in the inline Python
#: the fences heredoc (a mode change whose first argument is a quoted absolute path). Used to
#: compare what a line TARGETS against the exact fixed-system-parent literals.
#: NB deliberately spelled without a quoted `/etc` literal beside a mode-change call, because
#: `test_no_source_or_test_chowns_or_chmods_a_fixed_system_parent` scans this file too and reads
#: comment text as an act -- it caught this very comment on the first run.
_PATH_LITERAL = re.compile(r"/[A-Za-z0-9_./-]*")

#: An absolute path written as a Python string literal -- the form a mode-change call takes when
#: its target really is a path, as opposed to pathlib's `/` join operator.
_QUOTED_PATH_LITERAL = re.compile(r"""["'](/[^"']*)["']""")

#: Container keys/flags that would import host state into the environment the gate attests. A bind
#: mount of the host's `/etc` reinstates precisely the nondeterministic directory this work exists
#: to remove -- and it would do so while every other proof here stayed green, because the job would
#: still declare a digest-pinned `container:`.
_HOST_IMPORTING_OPTIONS = ("--privileged", "-v ", "--volume", "--mount", "--userns")


def _normalised(run: str) -> str:
    """Collapse every run of whitespace to one space, so token scans cannot be evaded by spelling.

    Without this, `sudo\tdocker\texec` passes a scan for `"docker "` while doing exactly what the
    scan exists to refuse."""
    return " ".join(run.split())


def _executable_lines(run: str) -> list[str]:
    """The lines of a `run:` block that actually EXECUTE -- comments stripped.

    These fences carry long explanatory comments inside their `run:` blocks, and a scan that reads
    them cannot distinguish "this step chowns /etc" from "this step explains that it never chowns
    /etc". Only executed text may be evidence."""
    return [line for line in run.splitlines() if not line.lstrip().startswith("#")]


def _canonical_path(raw: str) -> str:
    """Collapse a written path to the single spelling the fixed-parent comparison uses.

    REVIEW FINDING, and a real one: `_PATH_LITERAL` matches the trailing slash, so
    `chown -R root:root /etc/` yielded the literal `/etc/`, which is not `==` to the `/etc` in
    `FIXED_SYSTEM_PARENTS`. The intersection was empty and the repair scan silently passed -- a
    fence could have repaired the very posture the gate exists to observe, which is the case the
    comment on `assert_no_root_fence_repairs_a_fixed_system_parent` calls worse than a missing
    gate. `/etc/`, `//etc`, `/etc/.` and `/etc/..` all evaded it.

    `posixpath.normpath` alone is not enough: it deliberately preserves exactly two leading slashes
    (`//etc` stays `//etc`), so runs of slashes are collapsed first."""
    return posixpath.normpath(re.sub(r"/{2,}", "/", raw))


def _path_literals(text: str) -> set[str]:
    """Every absolute path a SHELL line names, in canonical form.

    Bare tokens are intended here: `chown root:root /` has no quotes and must still be seen."""
    return {_canonical_path(found) for found in _PATH_LITERAL.findall(text)}


def _quoted_path_literals(text: str) -> set[str]:
    """Every absolute path a PYTHON line names as a string literal, in canonical form.

    The bare-token form above cannot be used on Python source: `os.chmod(mount / f, 0o600)` uses
    `/` as pathlib's join operator, which reads as the literal path `/` -- a fixed system parent --
    and produced 14 false offenders across `apps/api/tests` on the first run of this. Python spells
    a real path as a string, so requiring quotes separates the operator from the target while still
    catching every evading spelling the review finding identified."""
    return {_canonical_path(found) for found in _QUOTED_PATH_LITERAL.findall(text)}


def _is_digest_pinned(image: str) -> bool:
    """True only for `name:tag@sha256:<64 lowercase hex>` -- a tag alone is not a pin."""
    base, separator, digest = image.partition("@")
    if not base or not separator or not digest.startswith("sha256:"):
        return False
    body = digest[len("sha256:") :]
    return len(body) == 64 and all(character in "0123456789abcdef" for character in body)


def _manifest() -> dict:
    return json.loads(_CONTROLLED_ENV_MANIFEST.read_text(encoding="utf-8"))


def controlled_jobs() -> list[str]:
    """Every gated root fence that must run inside the controlled environment today."""
    return sorted(set(REQUIRED_GATED_JOBS) - NOT_YET_CONTROLLED)


def _assert_runs_in_this_environment(job: str, role: str, run: str) -> None:
    """Refuse anything that would move ``run`` into a different mount namespace.

    The gate and the product tests must observe ONE filesystem. A gate attesting a machine the
    tests never touch, and tests running on a machine the gate never attested, are the SAME defect
    seen from opposite ends -- so the scan has to cover both, not just the gate.

    LIMITATION, recorded rather than fixed: ``_NAMESPACE_ESCAPES`` is a DENYLIST and is therefore
    inherently incomplete. A wrapper script, a differently-named tool, or a redirect assembled at
    runtime from a variable would all still pass it. It raises the cost of an ACCIDENTAL redirect;
    it is not a defence against a determined one.

    Two spellings that USED to pass and no longer do: ``unshare`` is now named, and the scan runs
    against whitespace-normalised text, so a tab-separated or line-broken ``sudo docker exec`` is
    caught. Both were verified by mutation, not by reading -- see the regressions below.
    """
    run = _normalised(run)
    for escape in _NAMESPACE_ESCAPES:
        assert escape not in run, (
            f"{job}: the {role} is redirected out of the controlled environment "
            f"({escape.strip()}), so the gate and the product tests would not observe the same "
            "filesystem"
        )


def _assert_no_host_state_is_imported(job: str, container: dict | str, manifest: dict) -> None:
    """The environment must be the pinned image plus exactly the reviewed options, and NOTHING ELSE.

    A digest pin only fixes what the image layer contains; it says nothing about what is mounted
    over it afterwards. ``container.volumes: ["/etc:/etc"]`` -- or the same thing spelled
    ``options: -v /:/host`` -- would put the hosted VM's nondeterministic `/etc` back inside the
    very namespace the gate attests, while `container:`, the digest pin, the manifest cross-check
    and every redirect scan all stayed green. That is the exact "green while proving less" shape
    this suite exists to refuse, so it is checked rather than assumed.

    `options` is additionally required to EQUAL the manifest's, for the same reason the image is:
    one reviewed environment, not four that drift apart. It is not enough to denylist the harmful
    spellings, because the denylist cannot anticipate every flag that changes what the fences
    observe -- equality means any change to the environment is a change to the reviewed manifest."""
    if not isinstance(container, dict):
        return  # the bare-string form has no volumes and no options to import anything through
    assert "volumes" not in container, (
        f"{job}: `container.volumes` mounts host paths into the attested tree, so the ancestry "
        "the gate walks would no longer come from the pinned layer"
    )
    options = _normalised(str(container.get("options", "")))
    for flag in _HOST_IMPORTING_OPTIONS:
        assert flag not in f"{options} ", (
            f"{job}: `container.options` contains {flag.strip()}, which imports host state into "
            "the environment the gate attests"
        )
    declared = _normalised(str(manifest.get("options", "")))
    assert options == declared, (
        f"{job}: `container.options` is {options!r}, the manifest declares {declared!r}; the four "
        "controlled fences must be ONE reviewed environment"
    )


def _assert_the_prelude_matches_the_manifest(job: str, steps: list[dict], manifest: dict) -> None:
    """The manifest's package list must be the list the fence actually installs.

    A documented set that drifts from the executed set is a claim that reads as a disclosure and
    is not one. Deriving the assertion from the workflow makes the manifest executable."""
    preludes = [
        step for step in steps if "apt-get install" in _normalised(str(step.get("run", "")))
    ]
    assert len(preludes) == 1, (
        f"{job}: expected exactly one prerequisite prelude, found {len(preludes)}"
    )
    line = next(
        candidate
        for candidate in _executable_lines(str(preludes[0]["run"]))
        if "apt-get install" in candidate
    )
    tokens = _normalised(line).split()
    marker = "--no-install-recommends"
    assert marker in tokens, f"{job}: the prelude must pin its install to {marker}"
    installed = sorted(tokens[tokens.index(marker) + 1 :])
    assert installed == sorted(manifest["packages"]), (
        f"{job}: the prelude installs {installed}, the manifest declares "
        f"{sorted(manifest['packages'])}"
    )


def assert_controlled_environment(workflow: dict, manifest: dict) -> None:
    """The SECP-WSA contract, factored so the mutation regressions can drive it directly."""
    pinned = str(manifest["image"])
    assert _is_digest_pinned(pinned), f"the manifest pin is not digest-pinned: {pinned}"
    # the manifest must not contradict ITSELF: `base` and `digest` are what a human reads and
    # `image` is what the workflow is checked against, so a split between them is a silent lie.
    assert pinned == f"{manifest['base']}@{manifest['digest']}", (
        f"the manifest's own fields disagree: {pinned} != {manifest['base']}@{manifest['digest']}"
    )

    for job in controlled_jobs():
        container = workflow["jobs"][job].get("container")
        assert container, f"{job}: no controlled environment (no `container:`)"
        image = str(container["image"] if isinstance(container, dict) else container)
        assert _is_digest_pinned(image), f"{job}: environment is not digest-pinned: {image}"
        # one reviewed environment, not four independently drifting ones
        assert image == pinned, f"{job}: pin drifted from the manifest ({image} != {pinned})"
        _assert_no_host_state_is_imported(job, container, manifest)

        # A STEP-level scan cannot see either of these. A job-level `continue-on-error: true` makes
        # the whole fence non-blocking and a job-level `if` can switch it off entirely -- in both
        # cases the gate still exits 78 and the fence still stops nothing, which is the
        # "green while proving less" shape this suite exists to refuse.
        # Coverage note, so the next reader knows what is load-bearing here:
        # `test_ci_workflow.py::test_no_continue_on_error_anywhere` ALREADY forbids
        # `continue-on-error` at job and step level for every job, so that half is defence in depth
        # and locality (the property stays inside this contract if that test ever narrows). The
        # job-level `if` is NOT covered anywhere else -- that half closes a real gap.
        specification = workflow["jobs"][job]
        assert specification.get("continue-on-error") in (None, False), (
            f"{job}: job-level continue-on-error makes the fence non-blocking"
        )
        assert "if" not in specification, (
            f"{job}: a job-level `if` can switch the fence off entirely"
        )

        steps = _steps(workflow, job)
        gates = _gate_indices(steps)
        assert gates, f"{job}: no attestation step in THIS job"
        # The property is "the gate attests the environment the PRODUCT TESTS run in", and it breaks
        # SYMMETRICALLY. Scanning only the gate caught a redirected gate and missed a redirected
        # product step -- the identical hole from the other side.
        for index in gates:
            _assert_runs_in_this_environment(job, "gate", str(steps[index]["run"]))
        product_index = _index_of_step(steps, REQUIRED_GATED_JOBS[job])
        _assert_runs_in_this_environment(job, "product-test step", str(steps[product_index]["run"]))

        # The pristine posture is recorded FIRST, so a posture change is attributable to the pinned
        # image rather than to something that ran after it -- the question the old ordering (first
        # observation only after checkout and setup-uv) could not answer.
        #
        # "Before the first third-party action" was the original assertion and it is too weak for
        # the claim being made: `infra/ci/FOLLOWUP-controlled-runner.md` and the job comments say
        # the canary is the FIRST step, and a repo-owned `run:` step inserted above it would leave
        # that prose false while the proof stayed green. So the position is pinned exactly.
        canary = [i for i, step in enumerate(steps) if "stat -c" in str(step.get("run", ""))]
        assert canary, f"{job}: no pristine-posture canary"
        assert canary[0] == 0, (
            f"{job}: the canary is step {canary[0]}, not the first step, so it no longer records "
            "the environment's PRISTINE posture"
        )
        first_action = next((i for i, step in enumerate(steps) if "uses" in step), len(steps))
        assert canary[0] < first_action, f"{job}: the canary runs after a third-party action"
        # and it must observe the two components every root fence's ancestry depends on -- a canary
        # that stopped naming them would still be a `stat -c` step and would still prove nothing.
        observed = _path_literals(_normalised(str(steps[canary[0]]["run"])))
        assert {"/", "/etc"} <= observed, (
            f"{job}: the canary observes {sorted(observed)}, which does not cover / and /etc"
        )

        _assert_the_prelude_matches_the_manifest(job, steps, manifest)

    # the manifest is the single source of truth for the pin; neither side may drift from the other
    assert sorted(manifest["controlled_jobs"]) == controlled_jobs()
    assert sorted(manifest["not_yet_controlled"]) == sorted(NOT_YET_CONTROLLED)


def test_every_controlled_root_fence_runs_in_the_pinned_environment() -> None:
    assert_controlled_environment(_workflow(), _manifest())


def test_the_uncontrolled_set_is_exactly_the_two_systemd_fences() -> None:
    """Tier 2 is HELD, not forgotten. Naming the remainder exactly keeps the gap visible.

    The may-only-shrink property is carried by the EXACT-EQUALITY assertion below, plus the manifest
    cross-check in `assert_controlled_environment`. The subset assertion that follows it does NOT
    carry it -- a strict subset still evaluates True with a third job added -- and is only a
    well-formedness check that every held job is a job this suite actually gates.

    CORRECTION, proven by mutation: none of that reaches ci.yml, so on its own it did NOT stop "a
    third fence being quietly parked on the hosted runner", which is what this pairing was
    previously described as achieving. Both constants could stay untouched while a brand-new
    `backend-<x>-root` job appeared in the workflow with no gate and no controlled environment.
    What closes that is `assert_every_root_fence_is_accounted_for`, which DERIVES the fence set from
    the workflow and refuses any fence these constants do not govern."""
    assert NOT_YET_CONTROLLED == frozenset(
        {
            "backend-management-real-adapters-root",
            "backend-management-controller-real-adapters-root",
        }
    )
    # well-formedness only: see the docstring -- this permits growth and must not be relied on
    assert NOT_YET_CONTROLLED < set(REQUIRED_GATED_JOBS)


def test_the_realfs_fence_attests_its_complete_ancestry() -> None:
    """It builds its sandbox directly beneath `/`, so `/` is the whole ancestry -- and until
    SECP-WSA it was the one root-elevated fence with no gate at all."""
    steps = _steps(_workflow(), "backend-realfs-root")
    gates = _gate_indices(steps)
    assert gates, "the RealFilesystem fence must attest its ancestry"
    assert any(
        str(steps[index]["run"]).rstrip().endswith(f"{_GATE_SCRIPT} /") for index in gates
    ), "the RealFilesystem fence must attest exactly `/`"


# ------------------- every root fence in the workflow is ACCOUNTED FOR, not just the known ones
#
# `REQUIRED_GATED_JOBS` and `NOT_YET_CONTROLLED` are hand-maintained constants, and until now
# NOTHING tied either of them to the workflow. `test_the_uncontrolled_set_is_exactly_the_two_
# systemd_fences` compares the constant to a literal copy of ITSELF, which stops the constant being
# edited silently but says nothing about ci.yml. So the property claimed for the pair -- "a third
# fence cannot be quietly parked on the nondeterministic hosted runner" -- did not hold: a new
# `backend-<x>-root` job could be added with no gate and no `container:`, and every proof in this
# file stayed green. Verified by mutation, not by inspection.
#
# Deriving the set from the workflow closes it, and closes it in a way that cannot be satisfied
# quietly: a new root fence must be added to `REQUIRED_GATED_JOBS` (which forces a job-local gate
# before its product step), and from there it is either controlled -- `container:` pinned to the
# manifest, and named in the manifest's `controlled_jobs` -- or it must be added to
# `NOT_YET_CONTROLLED`, which fails the exact-equality assertion AND the manifest cross-check.
# Every route ends at a visible, reviewed edit.


def root_fences(workflow: dict) -> set[str]:
    """Every job in the workflow that executes with root authority.

    Two independent discriminators, unioned, because either alone is evadable in an obvious way:

    * a step that elevates via ``sudo`` -- catches a root fence named without the suffix;
    * a job key ending in ``-root`` -- catches a fence that stops using ``sudo``, which is a real
      possibility now that the controlled fences are already uid 0 inside their container.

    They agree exactly on today's workflow (all six fences, no other job)."""
    fences = set()
    for job, specification in workflow["jobs"].items():
        elevates = any(
            "sudo " in _normalised(str(step.get("run", "")))
            for step in specification.get("steps", [])
        )
        if elevates or job.endswith("-root"):
            fences.add(job)
    return fences


def assert_every_root_fence_is_accounted_for(workflow: dict) -> None:
    """No root fence may exist that this suite does not gate and classify."""
    declared = set(REQUIRED_GATED_JOBS)
    discovered = root_fences(workflow)
    assert discovered == declared, (
        "the workflow's root fences and this suite's declared set disagree; "
        f"ungoverned in ci.yml: {sorted(discovered - declared)}; "
        f"declared but absent from ci.yml: {sorted(declared - discovered)}"
    )
    # every declared fence is in exactly one of the two buckets, and the buckets do not overlap
    assert NOT_YET_CONTROLLED <= declared, sorted(NOT_YET_CONTROLLED - declared)
    assert set(controlled_jobs()) | NOT_YET_CONTROLLED == declared
    assert set(controlled_jobs()) & NOT_YET_CONTROLLED == set()


def test_every_root_fence_in_the_workflow_is_governed_by_this_suite() -> None:
    assert_every_root_fence_is_accounted_for(_workflow())


def test_the_two_discriminators_independently_find_the_same_fences() -> None:
    """If they ever diverge, one of them has stopped describing what a root fence looks like and
    the union is quietly carrying the other. Worth knowing at that moment, not later."""
    workflow = _workflow()
    by_elevation = {
        job
        for job, specification in workflow["jobs"].items()
        if any(
            "sudo " in _normalised(str(step.get("run", "")))
            for step in specification.get("steps", [])
        )
    }
    by_name = {job for job in workflow["jobs"] if job.endswith("-root")}
    assert by_elevation == by_name == set(REQUIRED_GATED_JOBS)


# ------------------------- no root fence REPAIRS the posture it is about to attest
#
# `test_no_source_or_test_chowns_or_chmods_a_fixed_system_parent` proves this for `apps/**` and
# `tests/**`. The workflow was the remaining surface, and it is the one that runs as root: a
# `sudo chown root:root /etc` in a prelude would turn every fence green by REPAIRING the exact
# posture the gate exists to refuse, which is worse than a missing gate because it looks like a
# pass. The job comments assert "no package repairs, chowns or chmods a system directory"; this
# makes that sentence executable.


def assert_no_root_fence_repairs_a_fixed_system_parent(workflow: dict) -> None:
    offenders: list[str] = []
    for job in sorted(root_fences(workflow)):
        for step in workflow["jobs"][job].get("steps", []):
            for line in _executable_lines(str(step.get("run", ""))):
                normalised = _normalised(line)
                if not any(
                    call in normalised
                    for call in ("chown ", "chmod ", "chown(", "chmod(", "chown -", "chmod -")
                ):
                    continue
                targeted = _path_literals(normalised) & set(FIXED_SYSTEM_PARENTS)
                if targeted:
                    offenders.append(f"{job}: {sorted(targeted)} in {normalised[:70]!r}")
    assert offenders == [], (
        "a root fence repairs a fixed system parent, which would make the trusted-ancestor gate "
        f"pass by construction rather than by observation: {offenders}"
    )


def test_no_root_fence_repairs_a_fixed_system_parent() -> None:
    assert_no_root_fence_repairs_a_fixed_system_parent(_workflow())


# ---- mutation regressions: each property must FAIL when broken -------------------------------


def test_the_controlled_proof_fails_when_a_fence_loses_its_environment() -> None:
    workflow = _mutated()
    del workflow["jobs"]["backend-deployment-root"]["container"]
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_a_pin_drifts_from_the_manifest() -> None:
    workflow = _mutated()
    workflow["jobs"]["backend-management-root"]["container"]["image"] = (
        "ubuntu:24.04@sha256:" + "0" * 64
    )
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_an_environment_is_only_tag_pinned() -> None:
    """A tag reintroduces exactly the silent-rollover variable this work removes."""
    workflow = _mutated()
    workflow["jobs"]["backend-realfs-root"]["container"]["image"] = "ubuntu:24.04"
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_gate_is_redirected_out_of_the_environment() -> None:
    """The subtlest break: the fence still HAS a gate, and the gate still exits 78 -- but it is
    attesting a different namespace from the one the product tests run in."""
    workflow = _mutated()
    steps = workflow["jobs"]["backend-management-root"]["steps"]
    index = _gate_indices(steps)[0]
    steps[index]["run"] = "sudo docker exec other-host " + str(steps[index]["run"]).lstrip()
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_canary_moves_after_a_third_party_action() -> None:
    workflow = _mutated()
    steps = workflow["jobs"]["backend-realfs-root"]["steps"]
    canary = next(i for i, step in enumerate(steps) if "stat -c" in str(step.get("run", "")))
    moved = steps.pop(canary)
    first_action = next(i for i, step in enumerate(steps) if "uses" in step)
    steps.insert(first_action + 1, moved)
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_product_tests_are_redirected_out() -> None:
    """The symmetric half of the redirect property, and the one the first version MISSED.

    The fence still has a gate, the gate still runs in the controlled environment and still exits
    78 on a bad posture -- but the product tests execute somewhere the gate never attested. That is
    a vacuous pass, and before this it went undetected while every other proof stayed green."""
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    index = _index_of_step(steps, REQUIRED_GATED_JOBS[job])
    steps[index]["run"] = "sudo docker exec other-host " + str(steps[index]["run"]).lstrip()
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_a_fence_is_made_non_blocking_at_job_level() -> None:
    """`continue-on-error` at JOB level is invisible to a step-level scan: the gate still exits 78
    and the fence still stops nothing."""
    workflow = _mutated()
    workflow["jobs"]["backend-deployment-root"]["continue-on-error"] = True
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_a_fence_is_switched_off_at_job_level() -> None:
    """A job-level `if` can disable the whole fence without touching a single step."""
    workflow = _mutated()
    workflow["jobs"]["backend-deployment-root"]["if"] = "false"
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_host_etc_is_mounted_over_the_pinned_layer() -> None:
    """The break that would defeat the ENTIRE change while looking perfect.

    The job still declares a digest-pinned `container:`, the pin still equals the manifest, the
    gate still runs inside it and still exits 78 on a bad posture -- but the `/etc` it walks is the
    hosted VM's nondeterministic one, mounted straight back in. Every other proof here stayed green
    for this mutation before the volumes check existed."""
    workflow = _mutated()
    workflow["jobs"]["backend-management-root"]["container"]["volumes"] = ["/etc:/etc"]
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


@pytest.mark.parametrize(
    "options",
    ["--privileged", "-v /:/host", "--volume /etc:/etc", "--mount type=bind,src=/etc,dst=/etc"],
)
def test_the_controlled_proof_fails_when_options_import_host_state(options: str) -> None:
    """The same defect spelled through raw docker `options:` instead of the `volumes:` key.

    Driven with a manifest that DECLARES the harmful options, so the options-equality check cannot
    be what fires. The denylist has to catch this on its own, which is the property under test."""
    manifest = dict(_manifest())
    manifest["options"] = options
    container = {"image": manifest["image"], "options": options}
    with pytest.raises(AssertionError, match="imports host state"):
        _assert_no_host_state_is_imported("backend-deployment-root", container, manifest)


def test_the_controlled_proof_fails_when_a_fence_option_drifts_from_the_manifest() -> None:
    """Four fences declaring four different option strings is four environments, which is what the
    manifest exists to prevent -- the image alone is not the whole environment."""
    workflow = _mutated()
    workflow["jobs"]["backend-realfs-root"]["container"]["options"] = "--init --cpus 2"
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_environment_provides_an_orphan_reaper() -> None:
    """Discovered by running it, not by reasoning about it.

    The first CI run of this environment (30609943702) failed `backend-deployment-root`'s
    `test_timeout_proves_full_group_disappearance_no_orphan` with reason_code
    `command_group_not_terminated`. A GitHub `container:` job's PID 1 does not reap, so after the
    deployment runner's bounded SIGTERM -> grace -> SIGKILL sequence the killed grandchild stayed a
    ZOMBIE; `killpg(pgid, 0)` kept succeeding instead of returning ESRCH, and the runner could not
    prove the group had disappeared. It refused rather than reporting a termination it had not
    proven -- the fence working -- so the defect was in the environment, which lacked a property
    every real machine has. Pinned here so the requirement cannot be dropped as an unexplained flag.
    """
    assert "--init" in _normalised(str(_manifest()["options"]))


def test_the_controlled_proof_fails_when_a_step_is_inserted_above_the_canary() -> None:
    """`before the first third-party action` was too weak: a repo-owned `run:` step above the
    canary left the documented "first step" claim false with every proof still green."""
    workflow = _mutated()
    steps = workflow["jobs"]["backend-realfs-root"]["steps"]
    steps.insert(0, {"name": "Something that runs first", "run": "echo anything\n"})
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_canary_stops_observing_the_ancestry() -> None:
    """A `stat -c` step that names neither `/` nor `/etc` satisfies a substring scan and records
    nothing about the posture every root fence depends on."""
    workflow = _mutated()
    steps = workflow["jobs"]["backend-realfs-root"]["steps"]
    index = next(i for i, step in enumerate(steps) if "stat -c" in str(step.get("run", "")))
    steps[index]["run"] = "stat -c '%u %g %n' /tmp\n"
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_prelude_drifts_from_the_manifest() -> None:
    workflow = _mutated()
    steps = workflow["jobs"]["backend-management-root"]["steps"]
    index = next(i for i, step in enumerate(steps) if "apt-get install" in str(step.get("run", "")))
    steps[index]["run"] = str(steps[index]["run"]).replace(" git ", " git openssh-client ")
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_prelude_is_removed_entirely() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    workflow["jobs"][job]["steps"] = [
        step
        for step in workflow["jobs"][job]["steps"]
        if "apt-get install" not in str(step.get("run", ""))
    ]
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_controlled_proof_fails_when_the_manifest_contradicts_itself() -> None:
    """`base` + `digest` are what a human reads; `image` is what the workflow is checked against."""
    manifest = dict(_manifest())
    manifest["digest"] = "sha256:" + "b" * 64
    with refuses(manifest, _manifest()):
        assert_controlled_environment(_workflow(), manifest)


@pytest.mark.parametrize("escape", ["sudo\tdocker\texec other-host ", "unshare --mount "])
def test_the_redirect_scan_catches_the_spellings_that_used_to_evade_it(escape: str) -> None:
    """Both were holes: the tab spelling passed a scan for `"docker "`, and `unshare` was named in
    the recorded limitation but not in the denylist. Proven by mutation, not by reading."""
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    index = _index_of_step(steps, REQUIRED_GATED_JOBS[job])
    steps[index]["run"] = escape + str(steps[index]["run"]).lstrip()
    with refuses(workflow, _workflow()):
        assert_controlled_environment(workflow, _manifest())


def test_the_accounting_proof_fails_when_a_new_root_fence_is_added_to_the_workflow() -> None:
    """The hole behind the claim "a third fence cannot be quietly parked on the hosted runner":
    before this, a whole new root job with no gate and no controlled environment was invisible."""
    workflow = _mutated()
    workflow["jobs"]["backend-newfence-root"] = {
        "name": "A new root fence nobody added to the constants",
        "runs-on": "ubuntu-24.04",
        "steps": [{"name": "Run new root tests", "run": "sudo .venv/bin/python -m pytest x\n"}],
    }
    with refuses(workflow, _workflow()):
        assert_every_root_fence_is_accounted_for(workflow)


def test_the_accounting_proof_fails_for_a_root_fence_that_avoids_the_naming_convention() -> None:
    """The `-root` suffix alone would miss this one; the elevation discriminator catches it."""
    workflow = _mutated()
    workflow["jobs"]["backend-privileged-checks"] = {
        "name": "Root work under a name the convention does not cover",
        "runs-on": "ubuntu-24.04",
        "steps": [{"name": "Elevate", "run": "sudo install -d -m 0755 /var/lib/secp\n"}],
    }
    with refuses(workflow, _workflow()):
        assert_every_root_fence_is_accounted_for(workflow)


def test_the_accounting_proof_fails_when_a_fence_is_parked_in_the_held_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other escape route, and the one the accounting check alone does NOT close.

    Declare the new fence in `REQUIRED_GATED_JOBS` (satisfying the accounting check), then hide it
    among the tier-2 holdouts so it never needs a `container:`. That is refused one layer further
    in: the manifest cross-check in `assert_controlled_environment` compares the held set against
    `infra/ci/controlled-root-env.json`, so parking a fence there cannot be done without editing
    the reviewed manifest too. Driven for real by patching the module constant."""
    original = NOT_YET_CONTROLLED
    monkeypatch.setattr(
        sys.modules[__name__],
        "NOT_YET_CONTROLLED",
        original | {"backend-newfence-root"},
    )
    # the same guard `refuses` applies: prove the patch LANDED before trusting the refusal, or a
    # monkeypatch that silently targeted the wrong module would read as the property being defended
    with refuses(NOT_YET_CONTROLLED, original):
        assert_controlled_environment(_workflow(), _manifest())


@pytest.mark.parametrize(
    "repair",
    [
        "chown root:root /etc",
        # every spelling below EVADED this scan until the review finding was fixed: the regression
        # only ever exercised the no-slash form, so it passed and gave false confidence
        "chown -R root:root /etc/",
        "chmod 0755 //etc",
        "chmod 0755 /etc/.",
        "chown root:root /etc/systemd/",
        "chmod 0755 /etc/..",  # spelled as a parent traversal, but the target is `/`
    ],
)
def test_the_repair_proof_fails_when_a_fence_chowns_a_fixed_system_parent(repair: str) -> None:
    """The worst possible break: the gate passes because the posture was REPAIRED, not observed."""
    workflow = _mutated()
    steps = workflow["jobs"]["backend-deployment-root"]["steps"]
    index = next(i for i, step in enumerate(steps) if "apt-get" in str(step.get("run", "")))
    steps[index]["run"] = str(steps[index]["run"]) + repair + "\n"
    with refuses(workflow, _workflow()):
        assert_no_root_fence_repairs_a_fixed_system_parent(workflow)


@pytest.mark.parametrize(
    "target,expected",
    [
        ("/etc/", "/etc"),
        ("//etc", "/etc"),
        ("/etc/.", "/etc"),
        ("/etc/..", "/"),
        ("/etc//systemd//", "/etc/systemd"),
        ("/root/secp-roottest", "/root/secp-roottest"),  # a legitimate target stays untouched
        ("/usr/local/bin/docker-compose", "/usr/local/bin/docker-compose"),
    ],
)
def test_a_path_is_compared_by_what_it_targets_not_how_it_is_spelled(
    target: str, expected: str
) -> None:
    """The unit behind the fix, so canonicalisation cannot silently regress to string equality."""
    assert _canonical_path(target) == expected


def test_the_source_scan_also_matches_the_evading_spellings() -> None:
    """The sibling static scan carried the identical defect and is fixed by the same canonicalising
    helper -- but on QUOTED literals, because Python spells a path as a string."""
    fixed = set(FIXED_SYSTEM_PARENTS)
    for spelling in ('"/etc/"', '"//etc"', '"/etc/."', '"/etc"', "'/etc/systemd/'"):
        line = f"os.chmod({spelling}, 0o777)"
        assert _quoted_path_literals(line) & fixed, f"{spelling} evades the scan"
    # a genuinely different target still does not match
    assert not _quoted_path_literals('os.chmod("/root/owned", 0o700)') & fixed


def test_the_source_scan_does_not_read_pathlib_division_as_the_root_directory() -> None:
    """The regression for the false-positive half, which is how this fix could break the build.

    `os.chmod(mount / f, 0o600)` uses `/` as pathlib's join operator. A bare-token scan reads that
    as the path `/` -- a fixed system parent -- and flagged 14 real, correct lines across
    `apps/api/tests`. Requiring quotes is what separates the operator from a target."""
    fixed = set(FIXED_SYSTEM_PARENTS)
    for innocent in (
        "os.chmod(mount / f, 0o600)",
        'os.chmod(mount / "manifest.json", 0o600)',
        "os.chown(base / child, 0, 0)",
    ):
        assert not _quoted_path_literals(innocent) & fixed, innocent
        # and the bare-token extractor is exactly why it cannot be used here
        assert _path_literals("os.chmod(mount / f, 0o600)") & fixed


def test_the_repair_proof_reads_only_executed_lines_not_comments() -> None:
    """The fences explain at length that they never repair a system parent. A scan that could not
    tell the explanation from the act would fire on the existing workflow, so this pins the
    distinction: the same text as a comment is not evidence, and as a command it is."""
    workflow = _mutated()
    steps = workflow["jobs"]["backend-deployment-root"]["steps"]
    steps[0]["run"] = "# this step does not chown /etc, and never chmod /etc either\n" + str(
        steps[0]["run"]
    )
    assert_no_root_fence_repairs_a_fixed_system_parent(workflow)  # a comment is not an act

    steps[0]["run"] = "chmod 0755 /etc\n" + str(steps[0]["run"])
    with refuses(workflow, _workflow()):
        assert_no_root_fence_repairs_a_fixed_system_parent(workflow)


def test_the_unmutated_controlled_environment_passes() -> None:
    """The control: every mutation above is a real break, not a broken assertion."""
    assert_controlled_environment(_workflow(), _manifest())
    assert_every_root_fence_is_accounted_for(_workflow())
    assert_no_root_fence_repairs_a_fixed_system_parent(_workflow())
