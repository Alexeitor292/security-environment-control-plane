"""The SEALED plan-only process boundary + command grammar (B1B-PR5A, ADR-022 §2/§4).

This is a SEPARATE, narrow seam from the generic ``SubprocessProcessExecutor`` (which stays sealed
in both PR5A and PR5B). ``PlanOnlyProcessExecutor`` has its OWN code seal constant,
``_PLAN_ONLY_PROCESS_SEALED``. In PR5A it is ``True`` — the plan-only executor cannot be constructed
or invoked. Unsealing plan-only in PR5B is a reviewed change to THIS constant only; the generic
subprocess seal and the apply/destroy seals stay ``True`` code constants.

The plan-only command grammar (:func:`validate_plan_only_command`) is a pure validator: it admits
only ``init`` (offline), a non-destroy ``plan``, and ``show -json`` against an exact transient plan
file, bound to a pinned executable and an approved ephemeral workspace. It rejects apply, destroy,
``plan -destroy``, and every other subcommand/flag/token — fail-closed, before any process would be
constructed.
"""

from __future__ import annotations

from dataclasses import dataclass

# ============================================================================================
# THE PLAN-ONLY PROCESS SEAL — a CODE CONSTANT, never configuration (ADR-020 §C; ADR-022 §2).
#
# While this is True, PlanOnlyProcessExecutor cannot be constructed — even with a valid capability,
# even directly. Unsealing plan-only (PR5B) is a deliberate code-and-review change to THIS constant.
# The generic SubprocessProcessExecutor seal (_B1A_SUBPROCESS_SEALED) and the future apply/destroy
# seals are INDEPENDENT constants that stay True, so a plan-only build can never apply or destroy.
# ============================================================================================
_PLAN_ONLY_PROCESS_SEALED = True


class PlanOnlyProcessError(RuntimeError):
    """Raised on any attempt to construct/use the sealed plan-only executor, or on a rejected
    argv."""


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


class PlanOnlyProcessExecutor:
    """The narrow plan-only process executor — SEALED in PR5A (ADR-022 §2).

    While ``_PLAN_ONLY_PROCESS_SEALED`` is True, ``__init__`` refuses construction unconditionally —
    even with a valid capability, even directly. It never routes through the generic
    ``SubprocessProcessExecutor`` and can never apply or destroy (the grammar admits no such
    tokens). Unsealing is a deliberate code-and-review change to the seal constant for PR5B.
    """

    def __init__(self, *, capability: object = None) -> None:
        if _PLAN_ONLY_PROCESS_SEALED:
            raise PlanOnlyProcessError(
                "PlanOnlyProcessExecutor is SEALED in SECP-002B-1B-PR5A and cannot be constructed "
                "(even with a valid capability, even directly). Real OpenTofu plan-only execution "
                "is unavailable; unsealing is a deliberate code-and-review change for a reviewed "
                "PR5B, never a configuration setting, a flag, or an injected executor."
            )
        # pragma: no cover - unreachable while sealed
        self._capability = capability  # pragma: no cover

    def run(self, command: PlanOnlyCommand) -> None:  # pragma: no cover - never reachable in PR5A
        raise PlanOnlyProcessError("PlanOnlyProcessExecutor cannot run while sealed")
