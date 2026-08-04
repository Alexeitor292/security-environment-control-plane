"""The probes that produce the queues stage's raw observations, and nothing else.

:mod:`secp_acceptance.queues` decides what an observation MEANS. This module decides how one is
OBTAINED. Keeping them apart is deliberate: a Temporal version bump changes the probe that fills
the projection, never the logic that judges it, and the judging logic is already pinned by tests
that need no host at all.

THE PROJECTION IS THE CONTRACT BETWEEN THE TWO
----------------------------------------------
Every function here returns a plain mapping in exactly the shape ``queues`` validates, and the
validators refuse anything else — a missing key, a wrong type, an over-long identity list all
resolve to ``answered: False`` rather than to a silently empty poller set. So the seam is checkable
hermetically: run the probe against a stubbed client, feed its output to the real validator, and
assert the two agree. That test is the reason this module exists as a module rather than as inline
code in the stage.

WHY THE SCRIPT IS A CONSTANT AND THE QUEUE NAMES ARE A FILE
------------------------------------------------------------
:meth:`~secp_acceptance.hosts.Host.exec_as_script` delivers a harness-authored constant on stdin to
``sh -s``; it never interpolates a value the harness received from a host. Queue names are values
the harness READ (from a product constant and, when one exists, from an installed profile), so
interpolating them into the script would break exactly that property. They are written to a file
with :meth:`~secp_acceptance.hosts.Host.write_file` — harness-held bytes, no shell — and the script
reads the file. The script therefore contains no value that varies between runs.

WHAT THE PROBE MAY DO
---------------------
Read-only Temporal calls: describe a task queue, count executions. It starts no worker, submits no
workflow, and never touches an operator queue except to ask the server who is polling it. The
prohibition is structural rather than documented — the script below contains no start/execute verb
at all, which :func:`assert_probe_is_read_only` checks as text.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from secp_acceptance import AcceptanceError
from secp_acceptance.queues import MAX_POLLERS

#: Where the harness writes the probe's inputs inside the host, and where the script reads them.
#: A fixed path owned by the harness — never composed from anything a host reported.
PROBE_INPUT_PATH = "/tmp/secp-acceptance-queue-probe-input.json"  # noqa: S108
PROBE_SCRIPT_PATH = "/tmp/secp-acceptance-queue-probe.py"  # noqa: S108

#: Verbs that would make the probe a participant rather than an observer. Checked as text against
#: the script source, so a future edit that adds one fails the harness build rather than the run.
#:
#: EACH ENTRY IS A CALL-SHAPED TOKEN, NOT A BARE WORD, and that is a correction rather than a
#: style. This list held ``"poll"``, which matched ``pollers`` — the read-only field the probe
#: exists to read — so the guard refused the very probe it was written to protect. A substring is
#: not a verb: ``pollers`` is data, ``start_workflow(`` is an act. The same shape as a systemd
#: classifier guard in this package that matched ``active`` inside ``_classify_active``.
FORBIDDEN_PROBE_VERBS: tuple[str, ...] = (
    "start_workflow(",
    "execute_workflow(",
    "execute_update(",
    "signal_workflow(",
    ".signal(",
    "start_worker(",
    "Worker(",
)

#: The probe. A harness-authored constant, executed by the host's system interpreter, reading its
#: inputs from a file and writing ONE line of JSON. Every failure is caught and reported as
#: ``answered: false`` with a bounded cause — the caller must never see a traceback, and a probe
#: that crashed must never be indistinguishable from a queue with no pollers.
TEMPORAL_PROBE_SOURCE = """
import json, sys

OUT = {"answered": False, "cause": "acceptance_observation_unavailable", "queues": {}}

try:
    with open("__INPUT__", "r") as fh:
        request = json.load(fh)
    host = request["temporal_host"]
    namespace = request["namespace"]
    wanted = request["queues"]
except Exception:
    sys.stdout.write(json.dumps(OUT) + "\\n")
    raise SystemExit(0)

try:
    import asyncio
    from temporalio.client import Client
    from temporalio.service import RPCError
except Exception:
    OUT["cause"] = "acceptance_observation_unavailable"
    sys.stdout.write(json.dumps(OUT) + "\\n")
    raise SystemExit(0)


async def main():
    client = await Client.connect(host, namespace=namespace)
    answer = {}
    for role, queue in wanted.items():
        entry = {"answered": False, "cause": "acceptance_observation_unavailable", "pollers": []}
        try:
            described = await client.workflow_service.describe_task_queue(
                {"namespace": namespace, "task_queue": {"name": queue}, "task_queue_type": 1}
            )
            entry["answered"] = True
            entry["cause"] = None
            entry["pollers"] = [str(p.identity) for p in getattr(described, "pollers", [])]
        except RPCError:
            entry["answered"] = False
            entry["cause"] = "acceptance_observation_unavailable"
        except Exception:
            entry["answered"] = False
            entry["cause"] = "acceptance_observation_malformed"
        answer[role] = entry
    return answer


try:
    OUT["queues"] = asyncio.run(main())
    OUT["answered"] = True
    OUT["cause"] = None
except Exception:
    OUT["answered"] = False
    OUT["cause"] = "acceptance_observation_unavailable"

sys.stdout.write(json.dumps(OUT) + "\\n")
"""


def probe_source(*, input_path: str = PROBE_INPUT_PATH) -> str:
    """The probe source with its ONE placeholder resolved.

    ``input_path`` is a harness-owned constant, not a host-reported value, so substituting it does
    not reintroduce the interpolation the script exists to avoid. It is a parameter only so the
    hermetic tests can point the probe at a temporary file.
    """
    return TEMPORAL_PROBE_SOURCE.replace("__INPUT__", input_path)


def assert_probe_is_read_only(source: str | None = None) -> None:
    """The probe must contain no verb that could start or submit anything.

    Structural, not documentary: this reads the actual source. A probe that acquired a
    ``start_workflow`` would be a participant in the thing it is supposed to be observing, and on
    the operator queue that is the single act this whole program exists to prevent.
    """
    text = probe_source() if source is None else source
    found = [verb for verb in FORBIDDEN_PROBE_VERBS if verb in text]
    if found:
        raise AcceptanceError("acceptance_proof_would_be_vacuous")


def probe_request(*, temporal_host: str, namespace: str, queues: Mapping[str, str]) -> bytes:
    """The probe's input document, as harness-held bytes for :meth:`Host.write_file`."""
    if not queues:
        raise AcceptanceError("acceptance_proof_would_be_vacuous")
    return json.dumps(
        {"temporal_host": temporal_host, "namespace": namespace, "queues": dict(queues)},
        sort_keys=True,
    ).encode("utf-8")


def parse_probe_output(raw: str) -> dict[str, dict]:
    """Reduce the probe's stdout to ``role -> projection`` for :func:`queues.observe_pollers`.

    A probe that produced nothing usable yields an UNANSWERED projection per requested role, never
    an empty mapping: an empty mapping would reach
    :func:`~secp_acceptance.queues.resolve_operator_isolation` as "no queues probed", which is
    already refused as vacuous — but it would reach the ORDINARY check as a missing key, and the
    two deserve the same explicit treatment rather than one of them relying on a downstream guard.
    """
    try:
        document = json.loads(raw)
    except ValueError:
        raise AcceptanceError("acceptance_observation_malformed") from None
    if not isinstance(document, Mapping):
        raise AcceptanceError("acceptance_observation_malformed")
    queues = document.get("queues")
    if document.get("answered") is not True or not isinstance(queues, Mapping):
        raise AcceptanceError("acceptance_observation_unavailable")
    projections: dict[str, dict] = {}
    for role, entry in queues.items():
        if not isinstance(role, str) or not isinstance(entry, Mapping):
            raise AcceptanceError("acceptance_observation_malformed")
        pollers = entry.get("pollers")
        if entry.get("answered") is True and isinstance(pollers, Sequence):
            if len(pollers) > MAX_POLLERS:
                projections[role] = {
                    "answered": False,
                    "cause": "acceptance_observation_malformed",
                }
                continue
            projections[role] = {"answered": True, "pollers": list(pollers)}
        else:
            cause = entry.get("cause")
            projections[role] = {
                "answered": False,
                "cause": cause if isinstance(cause, str) else "acceptance_observation_unavailable",
            }
    return projections


__all__ = [
    "FORBIDDEN_PROBE_VERBS",
    "PROBE_INPUT_PATH",
    "PROBE_SCRIPT_PATH",
    "TEMPORAL_PROBE_SOURCE",
    "assert_probe_is_read_only",
    "parse_probe_output",
    "probe_request",
    "probe_source",
]
