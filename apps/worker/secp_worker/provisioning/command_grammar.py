"""The permitted OpenTofu command set — one derivation, shared by the producer and the executor.

ADR-030 §3 requires the executable command set to be "expressed as a **derived grammar** rather
than a hand-maintained list, so a reviewed operation and an executable command are the same fact".
This module is that grammar, and the phrasing matters: it is not a list the executor checks argv
against, it is the *only* place argv is built. ``OpenTofuRunner`` calls it to produce a command and
``SubprocessProcessExecutor`` calls it to re-derive what the command must have been. A command that
this module cannot produce is one the executor cannot run, because there is no second builder.

WHY NOT AN ALLOWLIST
---------------------
An allowlist of permitted verbs is a second artifact that has to be kept in step with the first. The
repository has already been bitten five times by a quantity pinned in two places where the copies
drifted, and an allowlist that drifts *open* is a hole nothing reports. A shared builder cannot
drift: adding a flag to a command adds it to the accepted set in the same edit, and the review of
that edit is the review of both.

WHY THE RE-DERIVATION IS NOT CIRCULAR
--------------------------------------
The executor must not check a spec against values taken from the same spec — that compares a value
to itself. So the inputs to :func:`build_argv` are split by who owns them:

* ``executable`` and ``mirror_identity`` come from the **toolchain profile the control plane
  authorized**, never from the spec being checked;
* ``workdir`` is the executor's own private workspace, and a spec naming a directory outside it is
  refused before any comparison;
* the plan file is *derived* from ``workdir`` (:func:`plan_file_for`) rather than supplied, so there
  is no caller-controlled path component anywhere in the argv.

Given those, argv is a total function of facts the caller does not control. That is what makes
byte-equality a real check rather than a restatement.
"""

from __future__ import annotations

from enum import Enum

#: The single plan artifact a prepared operation produces, derived from the workspace rather than
#: named by a caller. A caller-supplied plan path would be the one component of the argv an attacker
#: could still choose, and "apply this file" is the whole of what an apply does.
PLAN_FILENAME = "plan.tfplan"

#: Where the provider mirror lives on a worker. A directory the worker owns, not a configurable
#: root: a settable mirror path is a settable provider, which is a settable apply.
PROVIDER_MIRROR_ROOT = "/opt/secp/provider-mirror"


class OpenTofuStep(Enum):
    """The reviewed lifecycle steps, and the label each one travels under.

    ``destroy`` is deliberately the *apply* form: a destroy applies an already-generated destroy
    plan, so its argv is an apply of a plan file that was produced with ``-destroy``. There is no
    ``tofu destroy`` invocation in this grammar at all, which is what stops a destroy being
    regenerated at execution time from anything other than the reviewed change set.
    """

    init = "init"
    plan = "plan"
    destroy_plan = "destroy-plan"
    show = "show"
    apply = "apply"
    destroy = "destroy"


#: Every label the grammar can produce. Derived from the enum, so a new step is in the accepted set
#: the moment it exists rather than when someone remembers to add it here.
PERMITTED_LABELS: frozenset[str] = frozenset(step.value for step in OpenTofuStep)


class CommandGrammarError(Exception):
    """A command outside the grammar. The message names the rule, never the argv."""


def plan_file_for(workdir: str) -> str:
    """The one plan path for a workspace. Derived, never supplied."""
    return f"{workdir}/{PLAN_FILENAME}"


def step_for_label(label: str) -> OpenTofuStep:
    """The step a label denotes, or a refusal. No default, no prefix matching."""
    try:
        return OpenTofuStep(label)
    except ValueError:
        raise CommandGrammarError(f"label is not a reviewed OpenTofu step: {label!r}") from None


def build_argv(
    step: OpenTofuStep,
    *,
    executable: str,
    workdir: str,
    mirror_identity: str,
) -> list[str]:
    """The argv for one reviewed step. Total in its inputs — no branching on anything else.

    Every command is fully non-interactive (``-input=false``) and unstyled (``-no-color``): a
    command that could prompt is one that hangs a worker, and colour codes corrupt the canonical
    plan JSON the change-set hash is taken over.
    """
    plan_file = plan_file_for(workdir)
    chdir = f"-chdir={workdir}"

    if step is OpenTofuStep.init:
        # Offline in four independent ways -- no module fetch, no upgrade, a read-only lockfile and
        # a local plugin directory. Any one of them alone would still leave a path to the network.
        return [
            executable,
            chdir,
            "init",
            "-input=false",
            "-no-color",
            "-get=false",
            "-upgrade=false",
            "-lockfile=readonly",
            f"-plugin-dir={PROVIDER_MIRROR_ROOT}/{mirror_identity}",
        ]

    if step in (OpenTofuStep.plan, OpenTofuStep.destroy_plan):
        argv = [
            executable,
            chdir,
            "plan",
            "-input=false",
            "-no-color",
            "-lock=true",
            f"-out={plan_file}",
        ]
        if step is OpenTofuStep.destroy_plan:
            argv.append("-destroy")
        return argv

    if step is OpenTofuStep.show:
        return [executable, chdir, "show", "-json", plan_file]

    # apply and destroy: both apply an EXACT prepared plan file. The difference is which plan was
    # generated, which is a fact of the plan step, not of this one -- so they are the same argv, and
    # that is the property that stops an apply becoming a destroy or a destroy re-planning.
    return [
        executable,
        chdir,
        "apply",
        "-input=false",
        "-no-color",
        "-lock=true",
        plan_file,
    ]


__all__ = [
    "PERMITTED_LABELS",
    "PLAN_FILENAME",
    "PROVIDER_MIRROR_ROOT",
    "CommandGrammarError",
    "OpenTofuStep",
    "build_argv",
    "plan_file_for",
    "step_for_label",
]
