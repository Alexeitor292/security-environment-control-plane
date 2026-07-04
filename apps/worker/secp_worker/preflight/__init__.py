"""Worker-owned app-owned read-only staging-preflight execution (SECP-B2-0).

Worker/plugin-only. This package is the ONLY place a read-only staging preflight is executed. It
claims durable queued preflight intent, re-verifies authoritative bindings + the live-read
authorization, and only then would resolve a secret and run the sealed GET-only collection path.

In this PR no production secret resolver exists, so a sealed injected resolver makes every
preflight fail closed as ``credential_unavailable``: no transport is constructed and nothing real
is contacted. A later, separately reviewed activation PR must supply a production secret resolver
(and enable collection) before a deliberate live preflight can return ``ready``.
"""

__all__ = [
    "activation_gate",
    "backends",
    "consumer",
    "fingerprint",
    "identity",
    "lease",
    "orchestration",
    "reverify",
    "runtime",
    "sealed_secret_resolver",
    "secret_resolution",
]
