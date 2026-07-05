# SECP Staging Live Activation Readiness

Status: operator readiness reference (SECP-B2-5-pre). This document is **non-secret and
descriptive only**. It defines the out-of-Git, one-time bootstrap state that must exist before the
first deliberate staging canaries and the first read-only staging preflight are ever run. It
contains **no commands, values, endpoints, hostnames, IP addresses, ports, certificate content,
secret references, tokens, CA names, or credentials** — every concrete value lives only on the
isolated staging control plane, established by an operator out of band, and is attested to SECP as
secret-free evidence (see the companion machine-checkable checklist).

Nothing in this repository performs any step described here. The staging-live adapters
(`secp_worker.staging_live`) are code-ready but unwired: no normal runtime imports them, the shipped
defaults are sealed, and no environment variable, configuration key, database flag, or API/UI
control can enable them.

## 1. Purpose and non-goals

The goal is to reach a state where a human operator, on an isolated staging control plane, can
explicitly invoke — in order — (1) an OpenBao authentication/readiness canary, (2) one authenticated
allowlisted Proxmox read (GET) canary, and (3) the first complete read-only staging preflight, each
against a disposable nested target, with every trust root established and revocable.

Non-goals: this is **not** equivalent to dedicated-hardware or hypervisor-level isolation; the
staging target must not execute untrusted workloads; it provisions only bounded, reversible staging
resources. No production control plane, production database, home, corporate, or public network is
ever in the path.

## 2. Isolated staging control plane

A self-contained staging control plane (staging-only API, staging database, staging worker) runs on
an isolated staging control-plane VM. It must never use the production SECP database or any
production control-plane service. All authoritative records (target, onboarding, live-read
authorization, resolver-activation authorization, worker-identity registration, lease, live-preflight
evidence) are loaded from the isolated staging database, which is authoritative only for this
isolated staging environment. No caller-supplied records can substitute for the staging database.

## 3. Disposable nested Proxmox target

The target is a disposable, nested Proxmox instance that can be destroyed and rebuilt at will. It
holds only synthetic, bounded, reversible staging resources. It is reachable from the staging worker
over exactly one approved API flow on one isolated NIC and nothing else.

## 4. Network isolation and egress

The target-facing plane has no default gateway and no DNS. There is no route to any home, corporate,
production-control-plane, LAN, WAN, or public network. Egress is default-deny; only the single
approved staging worker → staging target read flow and the staging worker → staging OpenBao
authentication flow are permitted, both on the isolated plane. Any other connection attempt must
fail closed.

## 5. Trust roots and identity material

A private staging certificate authority — created solely for this isolated staging environment — is
the only trust anchor. The staging worker holds deployment-local private key material and a
short-lived certificate issued by that private staging CA. The private material is never placed in
Git, never read from an environment variable by the application, and is provided only through an
injected deployment-local provider on the isolated worker. The corresponding public verification
anchor is registered as the worker identity's durable anchor in the staging database.

## 6. OpenBao authentication and policy

The staging worker authenticates to a staging OpenBao instance using mutual TLS bound to the
private staging CA and the deployment-local certificate. OpenBao enforces a least-privilege policy
that permits reading only the single synthetic staging credential path and nothing else. The
authentication/readiness canary proves this authentication succeeds without reading or returning any
secret.

## 7. Least-privilege staging read credential

The only credential resolvable for the staging preflight is a least-privilege, staging-only Proxmox
**read** credential, stored solely in staging OpenBao and referenced by an opaque vault locator in
the staging database. It grants read-only inventory access to the disposable target and nothing
else. A synthetic canary secret is used to prove resolution wiring without exposing the real read
credential.

## 8. Revocation and kill-switch drill

Before any canary, the operator rehearses immediate revocation: revoking the worker certificate at
the private staging CA, revoking the OpenBao authentication role, revoking the resolver-activation
authorization in the staging database, and severing the isolated NIC. Each revocation must
independently cause the next attempted operation to fail closed. This kill-switch drill is
re-verified and its outcome attested as evidence.

## 9. Evidence recorded in SECP

Every trust root above is attested to the staging SECP as **secret-free** evidence: the private CA
trust-root fingerprint (a hash, never the certificate), the worker identity registration and its
approved evidence, the resolver-activation authorization and its evidence, the OpenBao policy scope
attestation, the egress default-deny attestation, and the kill-switch drill outcome. No secret,
endpoint, hostname, or certificate content is recorded — only server-generated identifiers,
versions, pinned labels, closed status codes, and deterministic hashes, exactly as the immutable
live-preflight evidence boundary (SECP-B2-4.5) permits.

## 10. Canary and preflight order

The first real contact must occur in this order, each requiring an explicit human decision
immediately beforehand:

1. **OpenBao authentication/readiness canary** — proves worker identity, activation authorization,
   lease, and OpenBao authentication, resolving no secret and contacting no Proxmox.
2. **Proxmox read (GET) canary** — only after (1) succeeds; resolves the least-privilege staging read
   credential and performs exactly one allowlisted GET through the hardened read-only transport,
   persisting only safe facts as evidence.
3. **First complete read-only staging preflight** — only after (2) succeeds.

Because the Proxmox credential is resolved through OpenBao, no Proxmox contact can occur before
OpenBao authentication.

## 11. What must never enter Git

No commands, real endpoints, hostnames, IP addresses, ports, certificate or key content, CSRs,
secret references with real values, tokens, CA names, or credentials may ever be committed. Concrete
values exist only on the isolated staging control plane. This repository holds only the sealed,
unwired adapters and secret-free, machine-checkable evidence expectations.
