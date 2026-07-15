"""The plan-only process boundary + command grammar (B1B-PR5B, ADR-022 §2/§4).

This is a SEPARATE, narrow seam from the generic ``SubprocessProcessExecutor`` (which stays sealed
in both PR5A and PR5B). ``PlanOnlyProcessExecutor`` has its OWN code seal constant,
``_PLAN_ONLY_PROCESS_SEALED``. It was ``True`` through PR5A and the whole PR5B build-out; the final
reviewed PR5B activation flips it to ``False`` so the plan-only executor can be constructed on the
production path — but ONLY through :func:`issue_plan_only_executor`, with an exact controlled-live
capability, and ONLY after the shipped-disabled composition has been replaced by a separately
reviewed deployment-local composition (the shipped default still refuses before any I/O). The
generic subprocess seal (``_B1A_SUBPROCESS_SEALED``) and the apply/destroy seals stay ``True`` code
constants, so a plan-only build can never apply or destroy.

The plan-only command grammar (:func:`validate_plan_only_command`) is a pure validator: it admits
only ``init`` (offline), a non-destroy ``plan``, and ``show -json`` against an exact transient plan
file, bound to a pinned executable and an approved ephemeral workspace. It rejects apply, destroy,
``plan -destroy``, and every other subcommand/flag/token — fail-closed, before any process would be
constructed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import posixpath
import subprocess
import sys
from dataclasses import dataclass
from typing import NoReturn, SupportsIndex

# The reviewed plan-only executor implementation identity. A capability is accepted only by the
# EXACT reviewed executor: its declared ``process_implementation_digest`` must equal this digest, so
# a self-declared contract version alone never suffices (ADR-022 §4). Bumped on any reviewed
# behavioral change — ``v2`` marks the reviewed activation that flipped the production behavior from
# UNAVAILABLE (sealed) to AVAILABLE, so a capability/activation/composition minted against the old
# ``v1`` (sealed) digest can never activate this executor.
PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID = "secp-002b-1b-pr5b/plan-only-executor/v2"


def plan_only_executor_implementation_digest() -> str:
    """The stable digest of the reviewed plan-only executor implementation identity."""
    return "sha256:" + hashlib.sha256(PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID.encode()).hexdigest()


# ============================================================================================
# THE PLAN-ONLY PROCESS SEAL — a CODE CONSTANT, never configuration (ADR-020 §C; ADR-022 §2).
#
# This constant is now False (the final reviewed PR5B activation), so PlanOnlyProcessExecutor CAN be
# constructed on the production path — but exclusively through :func:`issue_plan_only_executor`,
# which holds the production token and hands the executor an exact PlanOnlyExecutionContext carrying
# a controlled-live PlanOnlyCapability that the executor independently re-verifies. Direct
# construction (no token) is still refused. Crucially, unsealing the CODE does NOT arm production:
# the shipped ``build_plan_execution_composition()`` remains disabled and empty, so the durable
# orchestration still refuses at the composition gate — before any filesystem access, fresh
# attestation, rendering, resolver/secret contact, executor construction, or subprocess — until a
# separately reviewed deployment-local composition is supplied out of band.
#
# The generic SubprocessProcessExecutor seal (_B1A_SUBPROCESS_SEALED) and the apply/destroy seals
# are
# INDEPENDENT constants that stay True, and the command grammar admits only init/non-destroy
# plan/show, so a plan-only build can never apply or destroy.
#
# The token-gated test-only path (``PlanOnlyProcessExecutor.for_inert_fixture_test``) still exists
# so
# ``run`` can be exercised against a tiny inert local fixture without a production controlled-live
# capability; an architecture scanner asserts no shipped (non-test) module reaches that path or the
# private test token, and a test-only capability can never produce a controlled-live durable result.
# ============================================================================================
_PLAN_ONLY_PROCESS_SEALED = False

# Module-private construction tokens. Neither is importable by accident: the production issuer holds
# one and enforces the seal; the test-only classmethod holds the other and deliberately bypasses the
# seal (and nothing else).
_PLAN_ONLY_PROD_CONSTRUCTION_TOKEN = object()
_PLAN_ONLY_TEST_CONSTRUCTION_TOKEN = object()

# Hard caps for the plan-only subprocess (bounded, in-memory).
_DEFAULT_TIMEOUT_SECONDS = 300
_MAX_CAPTURED_OUTPUT_BYTES = 4 * 1024 * 1024


class PlanOnlyProcessError(RuntimeError):
    """Raised on any attempt to construct/use the sealed plan-only executor, or on a rejected
    argv."""

    def __init__(self, message: str, *, reason_code: str = "") -> None:
        self.reason_code = reason_code
        super().__init__(message)


# --- the plan-only command grammar (pure; testable without constructing the executor) ------------

# The only three subcommands the plan-only capability admits.
_PLAN_ONLY_SUBCOMMANDS = frozenset({"init", "plan", "show"})

# Flags/tokens that are NEVER permitted, even attached to an allowed subcommand.
_FORBIDDEN_SUBCOMMANDS = frozenset(
    {
        "apply",
        "destroy",
        "import",
        "refresh",
        "state",
        "output",
        "workspace",
        "providers",
        "console",
        "force-unlock",
        "taint",
        "untaint",
        "fmt",
        "validate",
        "test",
        "login",
        "logout",
        "graph",
        "get",
        "unlock",
    }
)

# Exact flag sets per subcommand (order-independent; every flag must be recognised).
_INIT_FLAGS = frozenset(
    {"-input=false", "-no-color", "-get=false", "-upgrade=false", "-lockfile=readonly"}
)
_PLAN_FLAGS = frozenset({"-input=false", "-no-color", "-lock=true"})
_SHELL_METACHARS = set(";|&$`<>\n\r\t\\\"'*?()[]{}!# ")


@dataclass(frozen=True)
class PlanOnlyCommand:
    """A validated plan-only argv (the ONLY shapes the plan-only executor would ever run in
    PR5B)."""

    kind: str  # "init" | "plan" | "show"
    argv: tuple[str, ...]


def _is_safe_token(token: str) -> bool:
    return bool(token) and not any(c in _SHELL_METACHARS for c in token) and ".." not in token


def validate_plan_only_command(
    argv: list[str] | tuple[str, ...],
    *,
    executable: str,
    workspace: str,
    plan_file: str,
    plugin_dir: str | None = None,
) -> PlanOnlyCommand:
    """Validate one argv against the plan-only grammar. Raises ``PlanOnlyProcessError`` on anything
    else.

    Permitted shapes ONLY (ADR-022 §4):

    * ``<exe> -chdir=<workspace> init -input=false -no-color -get=false -upgrade=false
      -lockfile=readonly -plugin-dir=<...>``
    * ``<exe> -chdir=<workspace> plan -input=false -no-color -lock=true -out=<plan_file>``
      (NEVER ``-destroy``)
    * ``<exe> -chdir=<workspace> show -json <plan_file>``

    Every apply/destroy/``plan -destroy``/import/refresh/state/output/workspace/providers/console/
    force-unlock/taint token, an arbitrary cwd or plan file, a shell metacharacter, ``..``, an
    unrecognised flag, a response file (``@file``), and environment interpolation are refused.
    """
    tokens = list(argv)
    if len(tokens) < 3:
        raise PlanOnlyProcessError("plan-only argv is too short")
    if tokens[0] != executable or not _is_safe_token(executable):
        raise PlanOnlyProcessError("plan-only argv must start with the exact pinned executable")
    if tokens[1] != f"-chdir={workspace}":
        raise PlanOnlyProcessError("plan-only argv must -chdir to the exact approved workspace")

    sub = tokens[2]
    rest = tokens[3:]
    if sub in _FORBIDDEN_SUBCOMMANDS or sub not in _PLAN_ONLY_SUBCOMMANDS:
        raise PlanOnlyProcessError(f"plan-only grammar refuses subcommand {sub!r}")

    # The plan file (when relevant) must be an ABSOLUTE, direct child of the exact workspace.
    if sub in ("plan", "show"):
        if not plan_file or not os.path.isabs(plan_file):
            raise PlanOnlyProcessError("plan-only plan file must be an absolute path")
        if posixpath.dirname(plan_file.replace("\\", "/")) != workspace.replace("\\", "/"):
            raise PlanOnlyProcessError(
                "plan-only plan file must be a direct child of the workspace"
            )

    for tok in rest:
        if not _is_safe_token(tok) and not tok.startswith(f"-out={plan_file}"):
            raise PlanOnlyProcessError("plan-only argv token failed the safe-token check")
        if tok.startswith("@"):
            raise PlanOnlyProcessError("plan-only argv refuses a response file")
        if tok in _FORBIDDEN_SUBCOMMANDS or tok.lstrip("-") in _FORBIDDEN_SUBCOMMANDS:
            raise PlanOnlyProcessError(f"plan-only argv refuses token {tok!r}")

    if sub == "init":
        flags = {t for t in rest if not t.startswith("-plugin-dir=")}
        plugin_dirs = [t for t in rest if t.startswith("-plugin-dir=")]
        if flags != _INIT_FLAGS or len(plugin_dirs) != 1:
            raise PlanOnlyProcessError("plan-only init flags are not the reviewed offline set")
        # The plugin dir is bound to the EXACT freshly-attested provider mirror; an arbitrary
        # -plugin-dir is refused (not merely required to look safe).
        if plugin_dir is not None and plugin_dirs[0] != f"-plugin-dir={plugin_dir}":
            raise PlanOnlyProcessError(
                "plan-only init -plugin-dir is not the exact attested mirror"
            )
    elif sub == "plan":
        if "-destroy" in rest:
            raise PlanOnlyProcessError("plan-only grammar refuses `plan -destroy`")
        out = [t for t in rest if t.startswith("-out=")]
        flags = {t for t in rest if not t.startswith("-out=")}
        if flags != _PLAN_FLAGS or len(out) != 1 or out[0] != f"-out={plan_file}":
            raise PlanOnlyProcessError("plan-only plan flags/-out are not the exact reviewed set")
    else:  # show
        if rest != ["-json", plan_file]:
            raise PlanOnlyProcessError("plan-only show must be `show -json <exact plan file>`")

    return PlanOnlyCommand(kind=sub, argv=tuple(tokens))


# --- capability-bound argv DERIVATION (the runner never hand-assembles an argv) -------------------


def build_init_command(*, executable: str, workspace: str, plugin_dir: str) -> PlanOnlyCommand:
    """Derive the exact reviewed offline ``init`` argv, then validate it (fail closed)."""
    argv = [
        executable,
        f"-chdir={workspace}",
        "init",
        "-input=false",
        "-no-color",
        "-get=false",
        "-upgrade=false",
        "-lockfile=readonly",
        f"-plugin-dir={plugin_dir}",
    ]
    return validate_plan_only_command(
        argv, executable=executable, workspace=workspace, plan_file="", plugin_dir=plugin_dir
    )


def build_plan_command(*, executable: str, workspace: str, plan_file: str) -> PlanOnlyCommand:
    """Derive the exact reviewed non-destroy ``plan -out=<plan_file>`` argv, then validate it."""
    argv = [
        executable,
        f"-chdir={workspace}",
        "plan",
        "-input=false",
        "-no-color",
        "-lock=true",
        f"-out={plan_file}",
    ]
    return validate_plan_only_command(
        argv, executable=executable, workspace=workspace, plan_file=plan_file
    )


def build_show_command(*, executable: str, workspace: str, plan_file: str) -> PlanOnlyCommand:
    """Derive the exact reviewed ``show -json <plan_file>`` argv, then validate it."""
    argv = [executable, f"-chdir={workspace}", "show", "-json", plan_file]
    return validate_plan_only_command(
        argv, executable=executable, workspace=workspace, plan_file=plan_file
    )


@dataclass(frozen=True)
class PlanOnlyProcessResult:
    """The bounded, secret-free result of one plan-only subprocess (in-memory only).

    It carries NO stderr (not even a tail): a plan-only failure yields a bounded reason code, never
    raw provider diagnostics. ``stdout`` is the strictly-decoded ``show`` JSON; for
    ``init``/``plan``
    it is empty (their bytes are never retained).
    """

    kind: str  # "init" | "plan" | "show"
    returncode: int
    stdout: str


# Signals used to terminate a process group with a bounded grace period.
_TERM_GRACE_SECONDS = 5
_REAP_TIMEOUT_SECONDS = 5
_STREAM_POLL_SECONDS = 0.2


def _signal_process_group(proc: subprocess.Popen, sig: int) -> bool:
    """Send ``sig`` to the whole process group (POSIX) or process (Windows). True if delivered."""
    try:
        if sys.platform != "win32":
            os.killpg(os.getpgid(proc.pid), sig)
        else:  # pragma: no cover - exercised only on Windows
            proc.kill()
    except (ProcessLookupError, OSError):  # already gone
        return False
    return True


def _terminate_process_group(proc: subprocess.Popen) -> bool:
    """TERM the group, wait a bounded grace, then KILL if still alive; reap. True iff proven dead.

    Returns False when death cannot be proven within the bounded reap window (the caller escalates
    to
    ``recovery_required``), so an uncertain provider child never leaves execution in a
    false-success.
    """
    import signal

    term = getattr(signal, "SIGTERM", signal.SIGINT)
    kill = getattr(signal, "SIGKILL", term)
    _signal_process_group(proc, term)
    try:
        proc.wait(timeout=_TERM_GRACE_SECONDS)
        return True
    except Exception:  # noqa: BLE001 - not dead yet; escalate to KILL
        pass
    _signal_process_group(proc, kill)
    try:
        proc.wait(timeout=_REAP_TIMEOUT_SECONDS)
        return True
    except Exception:  # noqa: BLE001 - death cannot be proven within the bounded window
        return False


class PlanOnlyExecutionContext:
    """A typed, worker-owned, NON-SERIALIZABLE binding of one plan-only execution's exact facts.

    Rather than passing independent raw strings/dicts, the orchestration builds ONE context binding:
    the exact attested absolute executable / provider mirror / CLI config path handles (each with
    its
    verified inode/device), the exact workspace, the exact transient plan file, the exact closed
    child
    environment (+ its contract version), the capability, the timeout and output limit, and the
    exact
    expected lease / attempt / operation-fingerprint identity. It cannot be pickled or persisted.
    """

    executable_handle: object
    provider_mirror_handle: object
    cli_config_handle: object
    module_bundle_handle: object
    workspace: str
    plan_file: str
    env: dict[str, str]
    env_contract_version: str
    capability: object
    timeout: int
    max_output_bytes: int
    expected_lease_id: object
    expected_attempt_id: object
    expected_attempt_number: int
    expected_operation_fingerprint: str
    now: object

    __slots__ = (
        "executable_handle",
        "provider_mirror_handle",
        "cli_config_handle",
        "module_bundle_handle",
        "workspace",
        "plan_file",
        "env",
        "env_contract_version",
        "capability",
        "timeout",
        "max_output_bytes",
        "expected_lease_id",
        "expected_attempt_id",
        "expected_attempt_number",
        "expected_operation_fingerprint",
        "now",
    )

    def __init__(
        self,
        *,
        executable_handle: object,
        provider_mirror_handle: object,
        cli_config_handle: object,
        module_bundle_handle: object,
        workspace: str,
        plan_file: str,
        env: dict[str, str],
        env_contract_version: str,
        capability: object,
        timeout: int,
        max_output_bytes: int,
        expected_lease_id: object,
        expected_attempt_id: object,
        expected_attempt_number: int,
        expected_operation_fingerprint: str,
        now: object,
    ) -> None:
        object.__setattr__(self, "executable_handle", executable_handle)
        object.__setattr__(self, "provider_mirror_handle", provider_mirror_handle)
        object.__setattr__(self, "cli_config_handle", cli_config_handle)
        object.__setattr__(self, "module_bundle_handle", module_bundle_handle)
        object.__setattr__(self, "workspace", workspace)
        object.__setattr__(self, "plan_file", plan_file)
        object.__setattr__(self, "env", dict(env))
        object.__setattr__(self, "env_contract_version", env_contract_version)
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "timeout", int(timeout))
        object.__setattr__(self, "max_output_bytes", int(max_output_bytes))
        object.__setattr__(self, "expected_lease_id", expected_lease_id)
        object.__setattr__(self, "expected_attempt_id", expected_attempt_id)
        object.__setattr__(self, "expected_attempt_number", int(expected_attempt_number))
        object.__setattr__(self, "expected_operation_fingerprint", expected_operation_fingerprint)
        object.__setattr__(self, "now", now)

    @property
    def executable(self) -> str:
        return str(self.executable_handle.path)  # type: ignore[attr-defined]

    @property
    def provider_mirror(self) -> str:
        return str(self.provider_mirror_handle.path)  # type: ignore[attr-defined]

    @property
    def cli_config(self) -> str:
        return str(self.cli_config_handle.path)  # type: ignore[attr-defined]

    def __repr__(self) -> str:
        return "PlanOnlyExecutionContext(<redacted>)"

    __str__ = __repr__

    def __getstate__(self) -> NoReturn:
        raise TypeError("PlanOnlyExecutionContext cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PlanOnlyExecutionContext cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PlanOnlyExecutionContext cannot be pickled")


_HASH_CHUNK = 1 << 20  # 1 MiB streaming chunk


def _digest_open_fd(fd: int) -> str:
    """SHA-256 the OPENED descriptor from offset 0 (never re-open the pathname)."""
    os.lseek(fd, 0, 0)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, _HASH_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _recheck_handle(handle: object, *, expect_dir: bool) -> None:
    """Re-verify a pinned path handle immediately before spawn; refuse identity/type/content drift.

    For a FILE handle carrying a ``content_digest`` (e.g. the CLI configuration the child re-reads
    by
    pathname), the digest is re-verified by hashing a fresh NO-FOLLOW descriptor — so a same-path
    replacement is caught even when the removed inode is immediately reused (an inode/device compare
    alone is defeated by inode reuse). Directory handles (the provider mirror) keep the
    identity+type
    re-check; because the child re-resolves the mirror by pathname, that check is a best-effort
    detection, NOT closure of the child's own path-read TOCTOU (documented in :meth:`run`).
    """
    import stat as stat_lib

    path = getattr(handle, "path", None)
    if not isinstance(path, str) or not os.path.isabs(path):
        raise PlanOnlyProcessError("attested path invalid", reason_code="attested_path_changed")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise PlanOnlyProcessError(
            "attested path missing", reason_code="attested_path_changed"
        ) from exc
    if stat_lib.S_ISLNK(st.st_mode):
        raise PlanOnlyProcessError(
            "attested path is a symlink", reason_code="attested_path_changed"
        )
    if sys.platform != "win32":
        if st.st_ino != getattr(handle, "st_ino", None) or st.st_dev != getattr(
            handle, "st_dev", None
        ):
            raise PlanOnlyProcessError(
                "attested path identity changed", reason_code="attested_path_changed"
            )
    if expect_dir and not stat_lib.S_ISDIR(st.st_mode):
        raise PlanOnlyProcessError("attested dir type changed", reason_code="attested_path_changed")
    if not expect_dir and not stat_lib.S_ISREG(st.st_mode):
        raise PlanOnlyProcessError(
            "attested file type changed", reason_code="attested_path_changed"
        )
    expected_digest = getattr(handle, "content_digest", "")
    if not expect_dir and isinstance(expected_digest, str) and expected_digest:
        # The open itself must map to the bounded reason code — a post-lstat drift that makes the
        # fresh no-follow open fail (a symlink → ELOOP, an unreadable file → EACCES) fails CLOSED as
        # ``attested_path_changed``, never a raw OSError (which would carry the path and skip the
        # attempt's terminal transition).
        try:
            fd = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            )
        except OSError as exc:
            raise PlanOnlyProcessError(
                "attested file missing or symlinked", reason_code="attested_path_changed"
            ) from exc
        try:
            if not stat_lib.S_ISREG(os.fstat(fd).st_mode):
                raise PlanOnlyProcessError(
                    "attested file type changed", reason_code="attested_path_changed"
                )
            actual = _digest_open_fd(fd)
        finally:
            os.close(fd)
        if not hmac.compare_digest(actual, expected_digest):
            raise PlanOnlyProcessError(
                "attested file content changed", reason_code="attested_path_changed"
            )


def _open_pinned_executable(handle: object) -> tuple[int, str, tuple[int, ...]]:
    """Open the pinned executable through a retained NO-FOLLOW descriptor and bind execution to it.

    Returns ``(fd, exec_target, pass_fds)``. On Linux with ``/proc`` available the child executes
    the
    EXACT opened object via ``/proc/self/fd/<fd>`` (an ``fexecve``-equivalent: the pathname is never
    re-resolved at exec, so a same-path swap between the check and the spawn cannot take effect, and
    inode reuse is irrelevant because the content digest is authoritative). Elsewhere it falls back
    to path execution (``fd == -1``) — the strongest available check, with a documented residual
    path-resolution race. Fails closed with ``executable_not_pinned`` / ``attested_path_changed``.

    Verified on the retained descriptor before it is handed to the child: a regular file, no
    setuid/setgid/group-/world-writable bits, and an exact match of the reviewed ``content_digest``.
    """
    import stat as stat_lib

    path = getattr(handle, "path", None)
    expected_digest = getattr(handle, "content_digest", "")
    if not isinstance(path, str) or not os.path.isabs(path) or not _is_safe_token(path):
        raise PlanOnlyProcessError(
            "attested executable path invalid", reason_code="executable_not_pinned"
        )
    if not isinstance(expected_digest, str) or not expected_digest:
        raise PlanOnlyProcessError(
            "attested executable has no reviewed digest", reason_code="executable_not_pinned"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)  # NO-FOLLOW: a symlink at the final component is refused (ELOOP)
    except OSError as exc:
        raise PlanOnlyProcessError(
            "attested executable missing or symlinked", reason_code="attested_path_changed"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat_lib.S_ISREG(st.st_mode):
            raise PlanOnlyProcessError(
                "attested executable is not a regular file", reason_code="attested_path_changed"
            )
        if sys.platform != "win32" and st.st_mode & (
            stat_lib.S_ISUID | stat_lib.S_ISGID | stat_lib.S_IWGRP | stat_lib.S_IWOTH
        ):
            raise PlanOnlyProcessError(
                "attested executable permissions changed", reason_code="attested_path_changed"
            )
        if not hmac.compare_digest(_digest_open_fd(fd), expected_digest):
            raise PlanOnlyProcessError(
                "attested executable content changed", reason_code="attested_path_changed"
            )
    except BaseException:
        os.close(fd)
        raise
    if sys.platform.startswith("linux") and os.path.isdir("/proc/self/fd"):
        return fd, f"/proc/self/fd/{fd}", (fd,)
    # Fallback (non-Linux / no procfs): execute by pathname. Residual path-resolution race
    # documented.
    os.close(fd)
    return -1, path, ()


class PlanOnlyProcessExecutor:
    """The narrow plan-only process executor (B1B-PR5B, ADR-022 §2/§4).

    With ``_PLAN_ONLY_PROCESS_SEALED`` now False (reviewed PR5B activation), construction is
    permitted ONLY through the two token-gated paths: :func:`issue_plan_only_executor` (production;
    requires a controlled-live capability) and :meth:`for_inert_fixture_test` (test-only inert
    fixture; requires a test-only capability). A DIRECT, token-less construction is still refused,
    and if the code is ever re-sealed every path is refused again. Either way the executor is the
    FINAL enforcement boundary (below); unsealing the code does not arm production, because the
    shipped composition stays disabled and the orchestration refuses at its gate.

    The executor is the FINAL enforcement boundary — it does not trust the orchestration. It
    requires
    an exact :class:`PlanOnlyExecutionContext` carrying a mandatory :class:`PlanOnlyCapability`, and
    independently re-checks the capability type, its ``controlled_live`` / ``test_only``
    classification
    against the construction mode, its capability/authorization/dossier expiry, the process contract
    version + exact process implementation registration/digest, and the exact lease / attempt /
    operation-fingerprint identity — so a forged look-alike, a wrong-classification, or a capability
    minted for another lease/attempt is refused. :meth:`run` launches with ``shell=False``, the
    exact
    attested absolute executable, the exact closed child environment (re-validated key set), a fresh
    process group, and genuinely bounded streaming I/O.
    """

    __slots__ = ("_ctx",)

    def __init__(self, *, context: object = None, _token: object = None) -> None:
        # 1. The seal + construction mode. _PLAN_ONLY_PROCESS_SEALED is now False (reviewed PR5B
        #    activation); the seal branch below remains as the guard that fires again if the code is
        #    ever re-sealed. Even with the seal False, a direct (token-less) construction is
        #    refused — the only production path is issue_plan_only_executor (production token).
        if _token is _PLAN_ONLY_TEST_CONSTRUCTION_TOKEN:
            mode = "test"
        elif _PLAN_ONLY_PROCESS_SEALED:
            raise PlanOnlyProcessError(
                "PlanOnlyProcessExecutor is SEALED (_PLAN_ONLY_PROCESS_SEALED is True) and cannot "
                "be constructed on any shipped path (even with a valid capability, even directly). "
                "Unsealing is a deliberate code-and-review change to _PLAN_ONLY_PROCESS_SEALED.",
                reason_code="plan_only_sealed",
            )
        elif _token is _PLAN_ONLY_PROD_CONSTRUCTION_TOKEN:
            mode = "production"
        else:
            raise PlanOnlyProcessError(
                "PlanOnlyProcessExecutor cannot be constructed directly; it is issued only by "
                "issue_plan_only_executor after the authoritative plan-only gate",
                reason_code="plan_only_sealed",
            )
        if not isinstance(context, PlanOnlyExecutionContext):
            raise PlanOnlyProcessError(
                "plan-only executor requires an exact PlanOnlyExecutionContext",
                reason_code="capability_invalid",
            )
        self._verify_capability(context, mode=mode)
        self._verify_context(context)
        self._ctx = context

    @staticmethod
    def _verify_capability(context: PlanOnlyExecutionContext, *, mode: str) -> None:
        from datetime import UTC, datetime

        from secp_api.plan_activation_contract import PLAN_ONLY_CAPABILITY_CONTRACT_VERSION

        from secp_worker.plan_gen.capability import PlanOnlyCapability

        cap = context.capability
        if type(cap) is not PlanOnlyCapability:
            raise PlanOnlyProcessError(
                "capability is not the exact PlanOnlyCapability type",
                reason_code="capability_invalid",
            )
        act = cap.activation
        # Classifications cannot cross: production requires controlled_live, test requires
        # test_only.
        if mode == "production" and not cap.is_controlled_live:
            raise PlanOnlyProcessError(
                "production executor requires a controlled_live capability",
                reason_code="capability_binding_drift",
            )
        if mode == "test" and not act.is_test_only:
            raise PlanOnlyProcessError(
                "inert test executor requires a test_only capability",
                reason_code="capability_binding_drift",
            )
        now = context.now if isinstance(context.now, datetime) else datetime.now(UTC)
        for expiry, code in (
            (act.expires_at, "capability_invalid"),
            (act.authorization_expiry, "capability_invalid"),
            (act.activation_dossier_expiry, "capability_invalid"),
        ):
            if _as_utc(expiry) <= now:
                raise PlanOnlyProcessError("capability/binding expired", reason_code=code)
        if act.plan_only_capability_contract_version != PLAN_ONLY_CAPABILITY_CONTRACT_VERSION:
            raise PlanOnlyProcessError(
                "plan-only capability contract mismatch", reason_code="capability_invalid"
            )
        if act.process_implementation_id != PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID:
            raise PlanOnlyProcessError(
                "process implementation registration mismatch",
                reason_code="capability_binding_drift",
            )
        if act.process_implementation_digest != plan_only_executor_implementation_digest():
            raise PlanOnlyProcessError(
                "process implementation digest mismatch", reason_code="capability_binding_drift"
            )
        # A valid capability minted for ANOTHER lease/attempt/operation is refused.
        if str(act.execution_lease_id) != str(context.expected_lease_id):
            raise PlanOnlyProcessError(
                "capability lease mismatch", reason_code="capability_binding_drift"
            )
        if str(act.attempt_id) != str(context.expected_attempt_id):
            raise PlanOnlyProcessError(
                "capability attempt mismatch", reason_code="capability_binding_drift"
            )
        if int(act.attempt_number) != int(context.expected_attempt_number):
            raise PlanOnlyProcessError(
                "capability attempt number mismatch", reason_code="capability_binding_drift"
            )
        if act.operation_fingerprint != context.expected_operation_fingerprint:
            raise PlanOnlyProcessError(
                "capability operation fingerprint mismatch",
                reason_code="capability_binding_drift",
            )

    @staticmethod
    def _verify_context(context: PlanOnlyExecutionContext) -> None:
        from secp_api.plan_activation_contract import PLAN_SECRET_ENV_CONTRACT_VERSION

        from secp_worker.plan_gen.runtime_inputs import PLAN_ONLY_CHILD_ENV_KEYS

        workspace = context.workspace
        if not workspace or not os.path.isabs(workspace) or not _is_safe_token(workspace):
            raise PlanOnlyProcessError(
                "plan-only workspace must be absolute + safe", reason_code="workspace_unsafe"
            )
        exe = context.executable
        if not exe or not os.path.isabs(exe) or not _is_safe_token(exe):
            raise PlanOnlyProcessError(
                "plan-only executable must be absolute + safe", reason_code="executable_not_pinned"
            )
        plan_file = context.plan_file
        if (
            not plan_file
            or not os.path.isabs(plan_file)
            or posixpath.dirname(plan_file.replace("\\", "/")) != workspace.replace("\\", "/")
        ):
            raise PlanOnlyProcessError(
                "plan file must be an absolute direct child of the workspace",
                reason_code="workspace_unsafe",
            )
        mirror = context.provider_mirror
        if not mirror or not os.path.isabs(mirror) or not _is_safe_token(mirror):
            raise PlanOnlyProcessError(
                "provider mirror must be absolute + safe", reason_code="workspace_unsafe"
            )
        if context.env_contract_version != PLAN_SECRET_ENV_CONTRACT_VERSION:
            raise PlanOnlyProcessError(
                "child env contract mismatch", reason_code="secret_env_contract_violation"
            )
        env = context.env
        if not isinstance(env, dict) or set(env) != PLAN_ONLY_CHILD_ENV_KEYS:
            raise PlanOnlyProcessError(
                "child env is not the exact closed key set",
                reason_code="secret_env_contract_violation",
            )

    @classmethod
    def for_inert_fixture_test(cls, *, context: object) -> PlanOnlyProcessExecutor:
        """TEST-ONLY: construct (independent of the seal) to exercise :meth:`run` on the inert
        fixture.

        It uses the private test token so it works whether the code seal is True or False, and it
        requires a ``test_only`` capability — so it can never produce a controlled-live durable
        result
        or a real pending approval. It must never be referenced by a shipped (non-test) module (an
        architecture scanner enforces this), grants no apply/destroy power, and contacts no
        provider.
        """
        return cls(context=context, _token=_PLAN_ONLY_TEST_CONSTRUCTION_TOKEN)

    def run(self, command: PlanOnlyCommand) -> PlanOnlyProcessResult:
        """Run one validated plan-only command; return a bounded result or raise fail-closed."""
        ctx = self._ctx
        # Defense in depth: re-validate the argv against the EXACT pinned exe/workspace/plan/mirror.
        validated = validate_plan_only_command(
            command.argv,
            executable=ctx.executable,
            workspace=ctx.workspace,
            plan_file=ctx.plan_file,
            plugin_dir=ctx.provider_mirror,
        )
        # Re-verify the attested mirror/CLI identity+content, then pin the executable to a retained
        # NO-FOLLOW descriptor and execute THAT exact object (never re-resolving the pathname at
        # exec). The provider mirror + CLI config are re-resolved by the CHILD (tofu) by pathname,
        # so
        # their re-checks are best-effort detection; only the executable — which WE exec — is fully
        # bound to its opened object. This closes the reported inode-reuse TOCTOU on the executable.
        _recheck_handle(ctx.provider_mirror_handle, expect_dir=True)
        _recheck_handle(ctx.cli_config_handle, expect_dir=False)
        exe_fd, exec_target, pass_fds = _open_pinned_executable(ctx.executable_handle)

        new_session = sys.platform != "win32"
        creationflags = 0
        if sys.platform == "win32":  # pragma: no cover - exercised only on Windows
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        try:
            try:
                proc = subprocess.Popen(  # noqa: S603 - shell=False, validated argv, explicit env
                    list(validated.argv),
                    executable=exec_target,
                    cwd=ctx.workspace,
                    env=ctx.env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    pass_fds=pass_fds,  # ONLY the pinned executable fd is inherited (minimal)
                    start_new_session=new_session,
                    creationflags=creationflags,
                )
            except (OSError, ValueError) as exc:
                raise PlanOnlyProcessError(
                    "plan-only process could not be spawned", reason_code="process_spawn_failed"
                ) from exc

            capture = validated.kind == "show"
            try:
                returncode, stdout_bytes = self._pump_bounded(proc, capture_stdout=capture)
            except _OutputLimitExceeded as exc:
                _terminate_process_group(proc)
                raise PlanOnlyProcessError(
                    "plan-only process produced too much output",
                    reason_code="process_output_too_large",
                ) from exc
            except _RunTimeout as exc:
                proven_dead = _terminate_process_group(proc)
                code = "process_timed_out" if proven_dead else "process_uncertain_termination"
                raise PlanOnlyProcessError("plan-only process timed out", reason_code=code) from exc
            except BaseException:
                # Cancellation/anything after spawn must never strand a provider child.
                _terminate_process_group(proc)
                raise
        finally:
            if exe_fd >= 0:
                os.close(exe_fd)  # the child holds its own inherited copy; close ours

        stdout = ""
        if capture:
            try:
                stdout = stdout_bytes.decode("utf-8")  # STRICT: invalid UTF-8 is refused.
            except UnicodeDecodeError as exc:
                raise PlanOnlyProcessError(
                    "plan-only show output is not valid UTF-8", reason_code="show_json_invalid"
                ) from exc
        return PlanOnlyProcessResult(kind=validated.kind, returncode=returncode, stdout=stdout)

    def _pump_bounded(self, proc: subprocess.Popen, *, capture_stdout: bool) -> tuple[int, bytes]:
        """Stream stdout/stderr incrementally, enforcing the byte + time bounds WHILE reading.

        Retains at most ``max_output_bytes`` of stdout (only when ``capture_stdout``); stderr
        content
        is counted but never retained. Raises :class:`_OutputLimitExceeded` / :class:`_RunTimeout`.
        """
        import time

        deadline = time.monotonic() + self._ctx.timeout
        limit = self._ctx.max_output_bytes
        stdout_buf = bytearray()
        stderr_len = 0

        if sys.platform == "win32":  # pragma: no cover - the real path is POSIX; Windows fallback
            try:
                out_b, err_b = proc.communicate(timeout=self._ctx.timeout)
            except subprocess.TimeoutExpired as exc:
                raise _RunTimeout from exc
            if len(out_b) > limit or len(err_b) > limit:
                raise _OutputLimitExceeded
            return proc.returncode, (out_b if capture_stdout else b"")

        import select

        streams = {proc.stdout: "out", proc.stderr: "err"}
        open_fds = [f for f in streams if f is not None]
        stdout_len = 0
        while open_fds:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _RunTimeout
            ready, _, _ = select.select(open_fds, [], [], min(remaining, _STREAM_POLL_SECONDS))
            for fh in ready:
                chunk = os.read(fh.fileno(), 65536)
                if not chunk:
                    open_fds.remove(fh)
                    continue
                if streams[fh] == "out":
                    stdout_len += len(chunk)
                    if stdout_len > limit:
                        raise _OutputLimitExceeded
                    if capture_stdout:  # retain ONLY for show; init/plan bytes are discarded
                        stdout_buf += chunk
                else:
                    stderr_len += len(chunk)  # counted, never retained
                    if stderr_len > limit:
                        raise _OutputLimitExceeded
        # Reap with a bounded wait so the returncode is real.
        try:
            returncode = proc.wait(timeout=max(0.0, deadline - time.monotonic()) + 1.0)
        except subprocess.TimeoutExpired as exc:
            raise _RunTimeout from exc
        return returncode, bytes(stdout_buf)


class _OutputLimitExceeded(Exception):
    """Internal: the bounded output limit was exceeded while streaming."""


class _RunTimeout(Exception):
    """Internal: the wall-clock timeout elapsed while streaming."""


def _as_utc(value: object):  # noqa: ANN202
    from datetime import UTC, datetime

    from secp_api.readiness_contract import as_utc

    if not isinstance(value, datetime):
        return datetime.now(UTC)
    return as_utc(value)


def issue_plan_only_executor(*, context: object) -> PlanOnlyProcessExecutor:
    """Construct the plan-only executor on the PRODUCTION path (the only shipped construction path).

    Holds the production token and requires an exact :class:`PlanOnlyExecutionContext` carrying a
    mandatory ``controlled_live`` :class:`PlanOnlyCapability`, which ``__init__`` independently
    re-verifies (type/classification/expiry/contract/exact implementation registration+digest/exact
    lease-attempt-fingerprint). With ``_PLAN_ONLY_PROCESS_SEALED`` now False this constructs a real
    executor for a valid context and refuses an invalid one; if the code is re-sealed it is refused
    unconditionally. Reaching this in production still requires a reviewed, enabled composition —
    the
    shipped default is disabled, so ordinary startup never gets here.
    """
    return PlanOnlyProcessExecutor(context=context, _token=_PLAN_ONLY_PROD_CONSTRUCTION_TOKEN)
