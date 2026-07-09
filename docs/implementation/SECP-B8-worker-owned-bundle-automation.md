# SECP-B8 — Worker-Owned Live Discovery Bundle Automation

Completes the first-time product flow so the **only** host-side manual action is running the
app-generated Proxmox bootstrap script. Everything else — the worker's SSH + admission key material,
the mounted discovery bundle, and its `known_hosts` pinning — is generated and owned by the
**worker**, driven from the control plane's **secret-free** state. This automates away the manual
`SECP-B6` bundle assembly (hand-writing `manifest.json` / `id_key` / `known_hosts` / `binding.json`)
without weakening any B5/B6/B7 fail-closed invariant.

## What changed (why the smoke test hit `probe_source_sealed`)

A clean first-time run proved the app / bootstrap / live-read-authorization side worked, but discovery
failed `probe_source_sealed` (worker `mode=SEALED`) because **no worker-owned bundle/profile
automation existed** — B7 automated only the control-plane side. B8 adds the worker side.

## The single remaining manual step

Run the app-generated Proxmox bootstrap script (as root) on the Proxmox host, once. That script (from
the wizard) provisions the scoped read-only account + forced-command wrapper + audit role, authorizes
the **worker's** SSH public key, and prints a bounded, secret-free proof block. That is the only
host-side action.

Worker-side deployment config (not host-side) enables the automation:
`SECP_DISCOVERY_WORKER_MANAGED_BUNDLE=true` + `SECP_DISCOVERY_CONTROLLED_INTEGRATION_ENABLED=true` +
the B6 admission material (HTTPS endpoint + CA bundle). In the dev stack this is the
`infra/dev/docker-compose.discovery-live.yml` override.

## The new first-time flow

1. **Worker generates + owns its keys.** On startup (worker-managed profile enabled) the worker
   generates an SSH Ed25519 keypair and an Ed25519 admission keypair under its persistent, worker-only
   key dir (`0700`; private keys `0600`). The private halves **never** leave the worker and are never
   uploaded. It publishes **only** the PUBLIC material (SSH public key + admission anchor) to the
   control plane as a `WorkerDiscoveryNode` (`POST`/`GET
   /api/v1/target-discovery/read-only-bootstrap/worker-nodes`). The publication path **rejects private
   keys** and validates the anchor.
2. **Wizard auto-populates the worker public key.** The bootstrap wizard reads the published worker
   node and fills the "Worker SSH public key" field — the operator never runs `ssh-keygen`.
3. **Run the generated Proxmox script** (the one manual step). Paste the full proof block back into
   the wizard on completion. The proof now also carries the host's **public key line**; the control
   plane validates it, cross-checks its fingerprint (fail closed on mismatch), and stores it
   (non-secret) so the worker can pin `known_hosts` without contacting Proxmox.
4. **Grant substrate eligibility if needed.** If creating the live-read authorization fails with
   `readonly_preflight_substrate_ineligible`, a target-admin (`staging_substrate:manage`) grants it
   via the guided wizard action (`POST
   /api/v1/target-discovery/read-only-bootstrap/targets/{id}/substrate-eligibility`). It is **never**
   auto-granted.
5. **Bind** the session to a separately-approved live-read authorization (unchanged from B7).
6. **Worker assembles its bundle automatically.** Once a target is completed + bound and the host
   public key is captured, the worker's bundle-prep loop fetches the control plane's **secret-free**
   bundle descriptor and writes the four-file mounted bundle (`manifest.json` / `id_key` /
   `known_hosts` / `binding.json`) atomically into its worker-private mount. The `id_key` is the
   worker's own private key (local only); `known_hosts` is synthesized from the captured host public
   key (fingerprint verified by construction).
7. **Discovery runs.** The strict mounted-bundle source validates the worker-written bundle and, with
   the B6 control-plane admission + endpoint binding, performs the gated read-only discovery. The
   candidate plan stays **non-executable**; live apply stays sealed.

If discovery still can't reach the host, the wizard surfaces the exact **worker-side** prerequisite
(profile flag / admission material / bundle) instead of a mysterious `probe_source_sealed`, and the
`GET .../enrollments/{id}/readiness` diagnostic reports the exact missing **control-plane**
prerequisite.

## Preserved safety invariants

- The **API** never stores/reads an SSH private key, never SSHes to Proxmox, never runs a probe /
  `pvesh` / subprocess / provider command. It composes secret-free desired state only.
- The **worker** private key stays worker-owned; only PUBLIC material reaches the control plane.
- The worker contacts Proxmox **only** when every gate holds: active onboarding, active substrate
  eligibility, completed + bound bootstrap session, approved + unexpired live-read authorization,
  matching endpoint-binding hash, approved worker identity, and a **valid** mounted bundle.
- **Worker-managed mount mode** relaxes *only* the filesystem read-only requirement (a self-writing
  worker cannot satisfy it). Every other strict protection is retained: descriptor pinning
  (`O_NOFOLLOW` + fd snapshot), owner `== uid`, no group/other permissions, single hardlink,
  same-device, bounded size, and the worker-private validated copy handed to ssh. A post-validation
  swap is still defeated by the pinned descriptor.
- No root SSH runtime account (reserved accounts are refused). No arbitrary command execution.
  Candidate plans remain non-executable. Live apply remains sealed. Everything fails closed.

See `apps/worker/secp_worker/bundle_manager.py`, `apps/worker/secp_worker/discovery_bundle_runtime.py`,
`apps/worker/secp_worker/mounted_bundle.py` (worker-managed mode), and
`apps/api/secp_api/services/bootstrap_discovery.py` (host public key capture, bundle descriptor,
readiness). Prior manual flow: `docs/implementation/SECP-B6-discovery-bundle-mount.md`.
