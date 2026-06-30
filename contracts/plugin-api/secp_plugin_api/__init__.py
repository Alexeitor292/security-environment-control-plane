"""Versioned plugin contracts for the Security Environment Control Platform.

The control plane talks to *capabilities*, never to a specific vendor. Every
integration — real or simulated — implements the same versioned contract. See
ADR-003 (plugin contract).

The current contract version is ``v1``.
"""

from secp_plugin_api import v1

__all__ = ["v1"]
