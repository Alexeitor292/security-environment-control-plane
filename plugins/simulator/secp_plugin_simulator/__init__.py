"""Simulator Plugin — the reference implementation of the v1 plugin contract.

This is NOT a throwaway mock. It implements the exact same contract that real
provider plugins (Proxmox, OpenTofu runner, Ansible runner, Wazuh, CTFd) will
implement, and it is the target of the contract conformance suite. It creates
only simulated topology via the contract's ResourcePort — never real
infrastructure. See ADR-003 and the design doc §12.
"""

from secp_plugin_simulator.plugin import SimulatorPlugin

__all__ = ["SimulatorPlugin"]
