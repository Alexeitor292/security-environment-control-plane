"""Worker-only, READ-ONLY Proxmox target enrollment + discovery (SECP-B5).

This package performs the first real integration capability SECP will use after merge: a
worker-owned,
read-only enrollment/discovery job against the operator's Proxmox host through the deployment-local
SSH
bootstrap bundle. It is behaviorally and architecturally incapable of mutating infrastructure:

- it uses ONLY the shared, mutation-free :mod:`secp_worker.ssh_channel` hardened SSH primitives plus
a
  CLOSED set of read-only probes (``pvesh get`` / ``pveversion`` / fixed sysfs ``cat``) — no write
  verb, arbitrary command, path, user, or option is representable;
- it NEVER imports the deployment mutation executor/transport, mutation ops, host-helper installer,
  artifact pipeline, OpenBao handoff, or the deployment apply engine (an architecture test proves
  it);
- its shipped composition is SEALED (the probe source refuses), so nothing is contacted until a
  worker-local bootstrap bundle is mounted;
- it persists ONLY typed, bounded, secret-free discovery evidence and closed reason codes — never
raw
  host output, SSH metadata, credentials, keys, tokens, endpoints, or network addresses.

The discovery-derived candidate plan produced here is NOT executable in this PR: live deployment
apply
remains sealed pending controlled integration enablement.
"""
