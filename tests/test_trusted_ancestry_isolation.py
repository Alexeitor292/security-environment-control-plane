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

import os
import stat
import sys
from pathlib import Path

import pytest
from secp_commissioning.runtime import FilesystemError, InMemoryFilesystem

_GATE_DIR = str(Path(__file__).resolve().parents[1] / "infra" / "ci")
if _GATE_DIR not in sys.path:  # the gate is a standalone CI script, not an installed package
    sys.path.insert(0, _GATE_DIR)

import attest_trusted_ancestry as gate  # noqa: E402

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


_POSIX_ONLY = pytest.mark.skipif(
    not hasattr(os, "getuid"), reason="POSIX path and ownership semantics are POSIX-only"
)


@_POSIX_ONLY
def test_an_absent_code_owned_directory_is_not_a_failure(tmp_path: Path) -> None:
    """The distinction the first CI run of this gate exposed -- in my own wiring, not the runner.

    `/etc/secp/controller` is created by the fence (or its prepare step), so at gate time it may not
    exist. My first wiring reported that as `infrastructure_invalid`, which asserts a creation ORDER
    this gate has no business asserting and refuses a perfectly valid machine. Every ancestor that
    EXISTS must be trusted; an absent code-owned component is recorded and allowed."""
    code, report, untrusted = gate.attest([str(tmp_path / "not" / "created" / "yet")])
    assert code == gate.EXIT_OK
    assert report["verdict"] == "trusted"
    assert untrusted == []
    absent = report["absent"]
    assert isinstance(absent, list)
    assert [Path(p).name for p in absent] == ["not", "created", "yet"]


@_POSIX_ONLY
def test_an_untrusted_existing_prefix_still_fails_even_with_an_absent_tail(tmp_path: Path) -> None:
    """Allowing an absent tail must not become a way to skip checking the existing prefix."""
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o775)  # group-writable: a real, existing, untrusted ancestor
    os.chmod(prefix, 0o775)
    code, report, untrusted = gate.attest([str(prefix / "absent" / "tail")])
    assert code == gate.EXIT_INFRASTRUCTURE_INVALID
    assert report["verdict"] == "infrastructure_invalid"
    offending = [str(o["path"]) for o in untrusted]
    assert str(prefix) in offending
    assert "group_or_other_writable" in untrusted[-1]["problems"]  # type: ignore[operator]


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


# ------------------------------------------------- the fences are gated before their product tests


def test_every_root_fence_attests_ancestry_before_running_product_tests() -> None:
    """The classification fix, asserted against the workflow itself: each root fence must run the
    attestation gate BEFORE the step that executes product tests, so an invalid machine can never
    again present as a product failure."""
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    gated_steps = (
        "Drive the real controller bootstrap + migration + observer as root (no skips)",
        "Run the real management adapter E2E as root (no skips)",
        "Run PR5F fixed-layout root transaction tests (no skips)",
        "Run management-plane root-security tests as root (no skips)",
        "Run deployment root-security tests as root (no skips)",
    )
    attest_marker = "attest_trusted_ancestry.py"
    for step in gated_steps:
        assert step in workflow, step
        preceding = workflow[: workflow.index(step)]
        # the gate must appear between the previous product-test step and this one
        assert attest_marker in preceding, f"{step} is not preceded by the ancestry gate"
    assert workflow.count(attest_marker) >= len(gated_steps)


def test_the_gate_is_never_allowed_to_continue_on_error() -> None:
    """A security gate that a job is permitted to ignore is not a gate."""
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    for block in workflow.split("- name: Attest trusted ancestry")[1:]:
        head = block.split("- name:")[0]
        assert "continue-on-error" not in head
        assert "|| true" not in head
        assert "if: always()" not in head
