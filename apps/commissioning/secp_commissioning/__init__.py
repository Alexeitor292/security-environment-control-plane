"""SECP-PR5C — Commissioning Automation Foundation (ADR-023).

A versioned, testable commissioning engine that turns the manual PR5B validation prototypes into a
reusable, idempotent, evidence-producing installer. It is callable identically by a standalone
administrator CLI (``python -m secp_commissioning ...``) and, later, by the web onboarding wizard
(via the same engine + deterministic JSON output).

This foundation STOPS AT PREPARED, NEVER ACTIVATED. Nothing here starts an operator worker, submits
a workflow, runs OpenTofu, resolves a credential, or contacts Proxmox / OpenBao / remote state /
Temporal / PostgreSQL. Planning and rendering perform no writes and no network contact;
``install-prepared`` writes ONLY root-owned deployment-local material and installs DISABLED,
unstarted service definitions. There is deliberately NO ``activate`` command in this milestone.
"""

from __future__ import annotations

# The commissioning tool's own version (distinct from the descriptor CONTRACT version). Bumped when
# the engine's behaviour changes; recorded in evidence so a prepared deployment is traceable to the
# exact tool that produced it.
TOOL_VERSION = "0.1.0"

__all__ = ["TOOL_VERSION"]
