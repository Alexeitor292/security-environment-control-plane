"""Worker boundary (Charter Layer 4 — orchestration).

Privileged / side-effecting plugin operations (apply, reset, destroy) execute
here, never in the API (Charter Invariants 6, 7). The same orchestration logic is
invoked either inline (dev/test) or durably via Temporal (ADR-005).
"""

__version__ = "0.1.0"
