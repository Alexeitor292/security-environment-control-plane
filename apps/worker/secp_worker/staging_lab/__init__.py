"""Worker-owned fake staging-lab execution seam (SECP-002B-1B-9).

Fake-only. This package simulates desired-vs-observed state for a disposable staging lab and
produces logical resource observations only. It constructs no transport, opens no socket, spawns
no subprocess, resolves no secret, and imports no provider/network-capable code. A later,
separately reviewed adapter PR is required for any real provisioning.
"""

__all__ = ["consumer", "executor"]
