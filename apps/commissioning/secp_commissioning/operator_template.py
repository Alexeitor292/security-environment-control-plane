"""The fixed, executable-owned operator entrypoint template + its pinned digest (SECP-PR5C).

Rendered verbatim (interpolates NOTHING). It fails closed unless a separately-reviewed, root-
controlled deployment package supplies the typed controlled-live compositions + run hook; it uses
the
reviewed ``build_operator_worker_registration`` factory (which resolves the operator task queue via
the reviewed resolver and returns ONE atomic (task_queue, workflows, activities) object) — it never
assembles the queue/workflows/activities itself, never injects a raw-dict composition, and embeds no
deployment value or secret. This milestone renders + installs it DISABLED; commissioning never runs
it. The template digest is an executable-owned IMPLEMENTATION identity pinned into the plan +
evidence, so a tampered entrypoint is detected.
"""

from __future__ import annotations

import hashlib

OPERATOR_ENTRYPOINT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Deployment-local controlled-live operator worker entrypoint.

RENDERED by secp_commissioning (SECP-PR5C). PREPARED and DISABLED — this milestone never starts it.
It contains NO deployment value and NO secret. The controlled-live compositions and the run hook are
supplied ONLY by a separately-reviewed, root-controlled deployment package installed OUT OF BAND;
until then this entrypoint FAILS CLOSED with ``controlled_live_composition_not_installed``.

It uses the reviewed ``build_operator_worker_registration`` factory (which resolves the operator
task
queue via the reviewed resolver and returns ONE atomic (task_queue, workflows, activities) object) —
it NEVER assembles the queue/workflows/activities itself and NEVER injects a raw-dict composition.
"""

from __future__ import annotations

import sys

CONTROLLED_LIVE_COMPOSITION_NOT_INSTALLED = "controlled_live_composition_not_installed"


def _load_deployment_package():
    # The typed, fully-constructed controlled-live compositions + the worker run hook come ONLY from
    # a separately reviewed deployment package. Its ABSENCE (this milestone) is the fail-closed
    # state.
    try:
        from secp_operator_deployment import compositions, runner
    except ModuleNotFoundError:
        return None
    return compositions, runner


def build_registration():
    from secp_api.config import get_settings
    from secp_worker.operator_bootstrap import build_operator_worker_registration

    package = _load_deployment_package()
    if package is None:
        raise SystemExit(CONTROLLED_LIVE_COMPOSITION_NOT_INSTALLED)
    compositions, _runner = package
    comps = compositions.build_controlled_live_compositions()  # typed; never a raw dict
    settings = get_settings()
    # The queue is resolved INSIDE the factory via the reviewed resolver; we pass none ourselves.
    return build_operator_worker_registration(
        settings=settings,
        plan_execution_composition=comps.plan_execution,
        readiness_composition=comps.readiness,
        eligibility_composition=comps.eligibility,
    )


def main() -> int:
    package = _load_deployment_package()
    if package is None:
        sys.stderr.write(CONTROLLED_LIVE_COMPOSITION_NOT_INSTALLED + "\\n")
        return 3
    registration = build_registration()
    _compositions, runner = package
    # Starting the operator worker from the atomic registration is the deployment package's job.
    return int(runner.run_operator_worker(registration))


if __name__ == "__main__":
    raise SystemExit(main())
'''

ENTRYPOINT_TEMPLATE_BYTES = OPERATOR_ENTRYPOINT_TEMPLATE.encode("utf-8")


def entrypoint_template_digest() -> str:
    """The executable-owned ``sha256:`` identity of the rendered operator entrypoint template."""
    return "sha256:" + hashlib.sha256(ENTRYPOINT_TEMPLATE_BYTES).hexdigest()
