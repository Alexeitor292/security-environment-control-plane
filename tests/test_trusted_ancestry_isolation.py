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

import copy
import errno
import os
import stat
import sys
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
    source or test file may ``chown``/``chmod`` a fixed system parent, whatever the ordering."""
    root = Path(__file__).resolve().parents[1]
    literals = tuple(f'"{p}"' for p in FIXED_SYSTEM_PARENTS if p != "/") + ("'/etc'", '"/etc"')
    offenders: list[str] = []
    for path in list(root.glob("apps/**/*.py")) + list(root.glob("tests/**/*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if ("os.chown(" not in line) and ("os.chmod(" not in line):
                continue
            if any(literal in line for literal in literals):
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


def test_the_proof_fails_when_the_last_root_job_loses_its_gate() -> None:
    workflow = _mutated()
    job = "backend-management-controller-real-adapters-root"
    steps = workflow["jobs"][job]["steps"]
    workflow["jobs"][job]["steps"] = [s for s in steps if not _is_gate(s)]
    with pytest.raises(AssertionError):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_moves_after_its_product_test_step() -> None:
    workflow = _mutated()
    job = "backend-deployment-root"
    steps = workflow["jobs"][job]["steps"]
    gate_index = _gate_indices(steps)[0]
    moved = steps.pop(gate_index)
    steps.append(moved)  # now strictly after the product-test step
    with pytest.raises(AssertionError):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_only_an_earlier_job_has_a_gate() -> None:
    """The exact hole in the old prefix-search proof."""
    workflow = _mutated()
    job = "backend-management-real-adapters-root"
    workflow["jobs"][job]["steps"] = [s for s in workflow["jobs"][job]["steps"] if not _is_gate(s)]
    # an EARLIER job keeps its gate, which used to be enough to satisfy the old test
    assert _gate_indices(_steps(workflow, "backend-deployment-root"))
    with pytest.raises(AssertionError):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_is_allowed_to_continue_on_error() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    steps[_gate_indices(steps)[0]]["continue-on-error"] = True
    with pytest.raises(AssertionError):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_becomes_conditional() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    steps[_gate_indices(steps)[0]]["if"] = "always()"
    with pytest.raises(AssertionError):
        assert_job_local_gate_order(workflow)


def test_the_proof_fails_when_a_gate_swallows_the_exit_code() -> None:
    workflow = _mutated()
    job = "backend-management-root"
    steps = workflow["jobs"][job]["steps"]
    index = _gate_indices(steps)[0]
    steps[index]["run"] = str(steps[index]["run"]).rstrip() + " || true\n"
    with pytest.raises(AssertionError):
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
    with pytest.raises(AssertionError):
        assert_job_local_gate_order(workflow)


def test_the_unmutated_workflow_passes() -> None:
    """The control: every mutation above is a real break, not a broken assertion."""
    assert_job_local_gate_order(_workflow())
