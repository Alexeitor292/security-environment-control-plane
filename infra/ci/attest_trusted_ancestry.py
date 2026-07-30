"""Attest the trusted-ancestor posture a root fence depends on, BEFORE any product test runs.

SECP-PR5H-B2A reliability defect. The root/systemd/Docker fences intermittently failed with
``bootstrap_file_install_failed`` while installing under ``/etc/systemd/system/...``, and PR5F's
inline preflight once reported ``/etc: not root:root`` -- on unchanged code, before any product test
had executed, and passing again on a later attempt with no code change.

`RealFilesystem._open_parent` walks every path component with ``O_NOFOLLOW`` and ``fstat``-verifies
each ancestor to be a real directory, root-owned, and not group/other-writable. That rule is correct
and is NOT relaxed anywhere: an installer must never write through an ancestor it cannot vouch for.
The problem was never the rule -- it was that a violation was indistinguishable from a product bug:

* ``_install_file`` maps every ``FilesystemError`` to one opaque ``bootstrap_file_install_failed``,
  so the log never named WHICH ancestor was untrusted or what it observed;
* the failure surfaced as 30 errored product tests, which reads as "the feature is broken" when the
  actual meaning is "this machine is not a valid place to run the proof";
* so the only available response was to re-run and hope for a better runner, which is exactly the
  "retry until green" anti-pattern that hides a security signal.

This script closes that. It runs as a job GATE: it captures bounded evidence for every ancestor the
fence will traverse, and if any is untrusted it exits ``EXIT_INFRASTRUCTURE_INVALID`` so the job
fails as INFRASTRUCTURE, before a single product test executes. A product-test failure and an
invalid machine are then never confused for one another.

What it deliberately does NOT do:

* it does not repair, ``chown`` or ``chmod`` anything -- an unexpected ancestor posture is reported,
  never silently fixed and proceeded through;
* it does not special-case ``/etc`` or any other component as trusted;
* it does not downgrade a violation to a warning or a skip;
* it does not accept the runner user as an acceptable owner.

Evidence is bounded and non-secret by construction: only ``lstat`` metadata (type, uid, gid,
mode, device, inode, link count) for code-owned DIRECTORY paths, the process identity, the mount
line governing each path, and runner image metadata from the environment. It never reads file
contents and never emits a secret-bearing leaf path -- the readiness gate, credentials and keys
are files, and this script stats directories only.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import stat
import sys

EXIT_OK = 0
#: The machine is not a valid place to run the proof. Distinct from any product-test exit code.
EXIT_INFRASTRUCTURE_INVALID = 78
#: The gate itself could not run (bad arguments, unusable platform).
EXIT_GATE_UNUSABLE = 2

#: Group-write | other-write. An ancestor carrying either is writable by an identity that is not the
#: single trusted owner, so anything beneath it is attacker-influenceable.
WRITE_MASK = 0o022

#: Environment keys worth recording to correlate a bad posture with a runner image rollout. All are
#: non-secret CI metadata; anything unset is simply omitted.
_RUNNER_ENV_KEYS = (
    "RUNNER_OS",
    "RUNNER_ARCH",
    "RUNNER_NAME",
    "RUNNER_ENVIRONMENT",
    "ImageOS",
    "ImageVersion",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_JOB",
    "GITHUB_WORKFLOW",
)


def ancestors_of(path: str) -> list[str]:
    """``/`` plus every intermediate directory of ``path``, in traversal order.

    The leaf is included only when it is itself a directory the fence traverses; a caller passes
    directories, never secret-bearing files."""
    if not posixpath.isabs(path):
        raise ValueError("ancestry attestation requires absolute paths")
    parts = [p for p in path.split("/") if p]
    chain = ["/"]
    for index in range(len(parts)):
        chain.append("/" + "/".join(parts[: index + 1]))
    return chain


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    return "special"


def _mount_line(path: str) -> str:
    """The longest mount point governing ``path``, so a namespace/bind difference is visible."""
    best = ""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            for raw in handle:
                fields = raw.split()
                if len(fields) < 5:
                    continue
                point = fields[4]
                governs = path == point or path.startswith(point.rstrip("/") + "/")
                if governs and len(point) > len(best):
                    best = point
    except OSError:
        return ""
    return best


def observe(path: str) -> dict[str, object]:
    """One ancestor's bounded evidence, plus the exact reasons it is not trusted (if any)."""
    record: dict[str, object] = {"path": path}
    try:
        st = os.lstat(path)
    except OSError as exc:
        record.update(statable=False, errno=exc.errno, problems=["not_statable"])
        return record
    mode = st.st_mode
    problems: list[str] = []
    if _kind(mode) != "directory":
        problems.append("not_a_directory")
    if st.st_uid != 0 or st.st_gid != 0:
        problems.append("not_root_owned")
    if stat.S_IMODE(mode) & WRITE_MASK:
        problems.append("group_or_other_writable")
    record.update(
        statable=True,
        kind=_kind(mode),
        uid=st.st_uid,
        gid=st.st_gid,
        mode=oct(stat.S_IMODE(mode)),
        dev=st.st_dev,
        inode=st.st_ino,
        nlink=st.st_nlink,
        mount=_mount_line(path),
        problems=problems,
    )
    return record


def process_identity() -> dict[str, object]:
    # POSIX-only identity: this gate runs only under the root fences (mypy checks on Windows too).
    return {
        "uid": os.getuid(),  # type: ignore[attr-defined]
        "euid": os.geteuid(),  # type: ignore[attr-defined]
        "gid": os.getgid(),  # type: ignore[attr-defined]
        "egid": os.getegid(),  # type: ignore[attr-defined]
        "groups": sorted(os.getgroups()),  # type: ignore[attr-defined]
        "umask": oct(_current_umask()),
    }


def _current_umask() -> int:
    """Read the umask without leaving it changed."""
    value = os.umask(0o022)
    os.umask(value)
    return value


def runner_metadata() -> dict[str, str]:
    return {key: os.environ[key] for key in _RUNNER_ENV_KEYS if os.environ.get(key)}


def attest(paths: list[str]) -> tuple[int, dict[str, object], list[dict[str, object]]]:
    """Observe every ancestor of every requested path exactly once, in traversal order."""
    seen: list[str] = []
    for path in paths:
        for ancestor in ancestors_of(path):
            if ancestor not in seen:
                seen.append(ancestor)
    observations = [observe(ancestor) for ancestor in seen]
    untrusted = [o for o in observations if o.get("problems")]
    report: dict[str, object] = {
        "verdict": "infrastructure_invalid" if untrusted else "trusted",
        "requested": paths,
        "process": process_identity(),
        "runner": runner_metadata(),
        "ancestors": observations,
    }
    return (EXIT_INFRASTRUCTURE_INVALID if untrusted else EXIT_OK), report, untrusted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attest-trusted-ancestry",
        description=(
            "Attest that every ancestor a root fence will traverse is a real, root-owned, "
            "non-group/other-writable directory. Exits 78 (infrastructure_invalid) otherwise."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="absolute directory paths whose full ancestry must be trusted",
    )
    args = parser.parse_args(argv)
    if not hasattr(os, "getuid"):  # pragma: no cover - POSIX-only gate
        print("::error::ancestry attestation requires POSIX")
        return EXIT_GATE_UNUSABLE
    try:
        code, report, untrusted = attest(list(args.paths))
    except ValueError as exc:
        print(f"::error::{exc}")
        return EXIT_GATE_UNUSABLE
    # the full bounded evidence, always -- a passing attestation is the baseline a later failure is
    # compared against, so it is just as worth recording as a failing one.
    print(json.dumps(report, indent=2, sort_keys=True))
    if code == EXIT_INFRASTRUCTURE_INVALID:
        for observation in untrusted:
            raw = observation.get("problems")
            problems = raw if isinstance(raw, list) else []
            joined = ",".join(str(item) for item in problems)
            print(
                f"::error::infrastructure_invalid: {observation['path']} {joined} "
                f"(uid={observation.get('uid')} gid={observation.get('gid')} "
                f"mode={observation.get('mode')} kind={observation.get('kind')})"
            )
        print(
            "::error::This machine is not a valid place to run the root proof. The "
            "trusted-ancestor rule is NOT relaxed and the posture is NOT repaired; the "
            "product tests were not run."
        )
    return code


if __name__ == "__main__":  # pragma: no cover - CLI
    sys.exit(main())
