# Target-contact authorization packets

Two packets, two independent decisions. **Approval of Packet 1 does not approve Packet 2, and
neither approves an OpenTofu apply.**

Nothing in this document has been executed. No host has been contacted, no credential created, no
ACL modified.

Every Proxmox behaviour cited here comes from Proxmox source (`git.proxmox.com`) or the published
docs, read at `master` / docs 9.2.4. **`pve-network` has no `stable-9` branch**, so nothing below is
pinned to 9.1.x specifically — the two items that sit closest to the 9.1 boundary are flagged
`probe-required`.

---

## The finding that shapes both packets

`pvesh` refuses to run as a non-root uid **before any ACL is consulted**:
`PVE/CLI/pvesh.pm` calls `setup_default_cli_env()` with no username; `PVE/RESTEnvironment.pm` then
defaults the username to the PAM-realm superuser authid and dies unless the process euid is 0. The
check is a string compare against that one authid, so no ACL grant can satisfy it.

SECP creates its probe account as `useradd --system --create-home --shell /usr/sbin/nologin`
(`discovery_bootstrap_contract.py:306`) and the wrapper runs `exec pvesh get …` bare, with no `sudo`
(`:217, :220, :225, :229, :233, :238`). `command -v sudo` is checked at `:295` and no sudoers rule is
ever written.

So the existing SSH discovery path cannot execute, and making it work would mean running `pvesh` as
root — which puts the entire safety boundary on our command grammar while bypassing Proxmox's own
identity and ACL model. Hence the pivot to an API token, where the ACL actually governs.

---

## The empty-list problem, and how the preflight solves it

A privilege-denied SDN **index** read returns **HTTP 200 with `[]`**, not a 403 — the handlers are
declared `user => 'all'` and skip rows via `check_any(..., noerr=1)`. At the wire, *"this cluster has
no SDN zones"* and *"this credential may not see SDN zones"* are identical bytes.

Two endpoints break the tie:

- **`GET /api2/json/access/permissions`** — a privilege-separated token may call it **about itself
  with no privilege at all**. The handler defaults `userid` to the caller's own authid and only
  requires `Sys.Audit` on `/access` when asked about someone else. It returns
  `{"data": {"<acl-path>": {"<Privilege>": <propagate 0|1>}}}` — the privilege **key's presence** is
  the grant; the value is the propagate flag.
- **`GET /api2/json/cluster/sdn`** — a declarative `check => ['perm','/sdn',['SDN.Audit']]`, so it
  **cannot** return 200-with-empty for a permission reason. 200 confirms `SDN.Audit`; 403 denies it
  definitively.

**Preflight sequence:**

```text
S0  GET /version                     200 = token authenticates (no ACL involved)
S1  GET /access/permissions          the authority map, self-scoped, no privilege needed
S2  GET /cluster/sdn                 200 = SDN.Audit CONFIRMED by the server's own enforcement
                                     403 = denied, definitively
                                     Disagreement with S1 means our parse is wrong — do not proceed
S3  only now read the indexes; an empty list is evidence of absence ONLY if S2 was 200
S4  GET /access/permissions?path=/sdn/zones/<zone>   per-object authority, once a name is known
S5  GET /cluster/sdn/vnets/<vnet>/subnets            HARD-gated, so 403 vs 200-[] is unambiguous
S6  compare /cluster/sdn/zones (filtered) against /nodes/{node}/sdn/zones (NOT filtered)
    a zone present node-side and absent cluster-side PROVES per-object filtering
```

**What remains unprovable, and must be recorded as such rather than assumed away:**

1. **Object-level `NoAccess` is invisible.** `get_effective_permissions` drops any path whose
   privilege map is empty, so a zone denied by an explicit `NoAccess` ACL and a zone with no ACL
   entry produce byte-identical output. You must already know the name to test it.
2. Therefore "map says `SDN.Audit` propagates from `/sdn`" + "index is `[]`" ⇒ genuinely empty
   **only if** no deeper `NoAccess` exists, which cannot be ruled out from the map.
3. `/access/acl` is **not** a workaround — it is `user => 'all'` with the same silent-filter trap and
   returns `[]` to a read-only token.
4. The token **cannot read its own definition**, so it cannot discover its own `privsep` flag: the
   `self` check is a literal string compare and a token authid `u@r!t` never equals `u@r`.
5. Exact status codes (403 for denial, 501 for unimplemented) are **probe-required** — pin them on
   first contact rather than assuming.

Partial visibility must therefore **block** collision-sensitive planning. It is not a degraded
answer; it is an unknown one.

---

# Packet 1 — read-only credential provisioning

**This is a Proxmox configuration mutation and requires explicit approval.**

**The exact values are code, not prose.** `secp_api/proxmox_discovery_credential_proposal.py` holds
the account, role and token names and renders the exact commands; the privilege list is computed by
`privileges_required()` from the required-fact table. Read them with:

```
uv run python -c "from secp_api.proxmox_discovery_credential_proposal import *; \
print(unauthorized_notice()); print(*provisioning_commands(), sep=chr(10))"
```

This document deliberately carries none of those literals: `docs/proxmox/*.md` is guarded against
concrete infrastructure values, and an approval artifact made of literals cannot live here. Prose is
also the wrong home for a derived privilege set — a hand-maintained list drifts from the fact table
silently, and it always drifts toward asking for more.

| | |
| --- | --- |
| Backing user | a dedicated realm user with no shell and no SSH — never a superuser |
| Role name | `SECPDiscoveryReadOnly` |
| Privilege set | derived: exactly the audit privileges the required-fact table needs, nothing else |
| Token id | `<discovery-user>!<token-name>` |
| Privilege separation | `privsep=1` |
| ACL path | `/` |
| Propagation | `1` |

**Why the whole role at `/` rather than a narrower role at `/sdn`.** `PVE::AccessControl::roles`
does `$roles = $new; # overwrite previous settings` at each deeper level — the docs state it as
*"Deeper-level permissions override inherited upper-level permissions."* So an additional ACL entry
at `/sdn` would **replace**, not union with, the role inherited from `/` for everything at or below
`/sdn`. Roles at the *same* level do union. One role at `/` is therefore both simpler and safer.
This is a decision, not a fact — it should be confirmed by the S1/S2 preflight before being relied
on.

**Privilege set is derived, not chosen.** It is computed from the required-fact table
(`discovery_required_facts.py`), so the grant is exactly what the required facts need. A test
asserts no write-class privilege appears anywhere in that table.

**Explicitly NOT granted:** `Sys.Modify`, `VM.Allocate`, `VM.Config.*`, `VM.PowerMgmt`,
`Datastore.Allocate`, `SDN.Allocate`, `Permissions.Modify`, `Realm.*`, `User.Modify`, or any
built-in administrator role.

**`SDN.Allocate` is a write-class privilege and is deliberately absent**, which costs us three
endpoints. `GET /cluster/sdn/zones/{zone}`, `/controllers/{controller}` and `/ipams/{ipam}` each
require it — a genuine asymmetry in the SDN API, where the *index* is `SDN.Audit` but the
*single-object read* is `SDN.Allocate`. Every field those endpoints return is already in the
corresponding index response, so they are dropped rather than accommodated.

### Exact commands (NOT executed)

Five `pveum` commands, rendered by `provisioning_commands()`. A test asserts every one of them
begins with `pveum`, contains no `pvesh`, no shell chaining, and no pipe — and that nothing anywhere
in the repository calls the renderer.

The token needs **its own** ACL entry: under `privsep=1`, `roles` checks `$acl->{tokens}` before
`$acl->{users}`, so a token with no entries of its own resolves to nothing. Effective permissions
are then the **intersection** of the token's and the user's.

> One caveat worth stating because it would silently defeat the design: Proxmox skips the
> intersection entirely when the backing user is the PAM-realm superuser. A privilege-separated
> token backed by that account is **not** intersected. That is why the backing user is a dedicated,
> purpose-made realm user — asserted by test, not by convention.

### Rollback (NOT executed)

Five commands, rendered by `rollback_commands()`. A test asserts they name every object
provisioning creates, and that the token is removed before the user that owns it.

### Expected effective permissions

`GET /access/permissions` called by the token about itself should return `Sys.Audit`, `VM.Audit`,
`Datastore.Audit` and `SDN.Audit` at `/` with propagate `1`. **That expectation is to be verified by
the preflight, not assumed** — S1 and S2 must agree before any index result is trusted.

---

# Packet 2 — live read-only discovery

**Separate approval. Approval of Packet 1 does not authorise this.**

| | |
| --- | --- |
| API authority | `<enrolled-target-host>:<api-port>` plus the `/api2/json` base path — host and port come from the enrolled `ExecutionTarget`, never from a caller |
| TLS | pinned deployment-local CA bundle. **Not** ambient system trust |
| Auth header | Proxmox's API-token authorization scheme, carrying `<token-id>=<secret>`; the secret is never logged, chained into an exception, or written anywhere |
| Credential | opaque `vault:` reference resolved **only** inside the privileged worker |
| CSRF | not required — token auth short-circuits the check for every method, and GET never needs it |
| Connect / read timeout | bounded, from `hardened_http` |
| Response cap | `MAX_RESPONSE_BYTES` (64 KiB), streamed and refused past the cap |
| Redirects | refused, never followed |
| Proxy from environment | refused (`trust_env=False`, no injectable client) |
| Evidence signing | Ed25519 detached, `secp.target-discovery.observation/v1`, verified against `WorkerIdentityRegistration.verification_anchor_fingerprint` |

### Every admitted GET operation

```text
PREFLIGHT
  GET /api2/json/version                                        no privilege
  GET /api2/json/access/permissions                             no privilege (self)
  GET /api2/json/cluster/sdn                                    SDN.Audit @ /sdn      HARD
HOST AND CLUSTER
  GET /api2/json/cluster/status                                 Sys.Audit @ /         HARD
  GET /api2/json/nodes                                          no privilege
  GET /api2/json/nodes/{node}/version                           no privilege
  GET /api2/json/nodes/{node}/status                            Sys.Audit @ /nodes/{node}
  GET /api2/json/nodes/{node}/apt/versions                      Sys.Audit @ /nodes/{node}
  GET /api2/json/nodes/{node}/network                           no privilege
INVENTORY
  GET /api2/json/cluster/resources?type=vm                      VM.Audit              filtered
  GET /api2/json/nodes/{node}/storage                           Datastore.Audit       filtered
  GET /api2/json/nodes/{node}/storage/{storage}/content         Datastore.Audit       HARD
FIREWALL
  GET /api2/json/cluster/firewall/groups                        no privilege
  GET /api2/json/cluster/firewall/options                       Sys.Audit @ /         HARD
SDN
  GET /api2/json/cluster/sdn/zones?pending=1                    SDN.Audit             filtered
  GET /api2/json/cluster/sdn/vnets?pending=1                    SDN.Audit             filtered
  GET /api2/json/cluster/sdn/vnets/{vnet}/subnets?pending=1     SDN.Audit             HARD
  GET /api2/json/cluster/sdn/controllers?pending=1              SDN.Audit             filtered
  GET /api2/json/cluster/sdn/ipams/pve/status                   SDN.Audit             filtered
  GET /api2/json/cluster/sdn/fabrics/all?pending=1              SDN.Audit + Sys.Audit filtered
  GET /api2/json/nodes/{node}/sdn/zones                         (declared, NOT enforced)
  GET /api2/json/nodes/{node}/sdn/zones/{zone}/bridges          SDN.Audit   probe-required
```

`filtered` = returns 200 with a partial or empty list on denial. **Never evidence of absence** until
the preflight has established authority.

`probe-required`: `/nodes/{node}/sdn/zones/{zone}/bridges` was added 2025-11-14 with fixes on
11-17/18 — right at the 9.1 release boundary. Expect 501 if the target predates it.

### Host-local SSH — no longer required for the MVP

The API supplies what SSH was reaching for, so the SSH channel is **dropped from Packet 2**:

| Fact | Was | Now | Privilege |
| --- | --- | --- | --- |
| Exact PVE patch version | `pveversion` over SSH | `GET /version` → `data.version` (e.g. `9.1.1`) | none |
| Release / build id | `pveversion` | `GET /version` → `data.release`, `data.repoid` | none |
| Running kernel | `/nodes/{n}/status` parse | `GET /nodes/{node}/status` → `data['current-kernel']` | Sys.Audit |
| Node versions | not collected | `GET /nodes/{node}/version` | none |
| Package inventory | `pveversion -v` | `GET /nodes/{node}/apt/versions` | Sys.Audit |

**One fact has no API equivalent: nested-virtualization support**
(`cat /sys/module/kvm_intel/parameters/nested`). It gated no unsafe condition, so it was **removed**
along with the `cat` capability that existed solely to read it — the probe, the eligibility gate and
the allowlist entry are all gone (`target_discovery/probes.py`, `engine.py`). If it is ever needed
again it returns as a single fixed host-local read — never `pvesh`, never sudo, never root.

### Data retained / discarded

Retained: node names, storage ids, VMIDs, bridge names, VLAN tags, CIDRs, SDN object ids and pending
state, version strings, per-probe result digests, the exact rendered request paths, the token
**identifier**, the opaque credential reference, target TLS identity, timestamps, observation states.

Discarded and never written: the token secret, any raw response body beyond its digest, guest
configuration beyond identity, and anything not in the required-fact table.

### Proofs

- **No mutation method is representable.** The transport has no `method` parameter and no
  `post`/`put`/`patch`/`delete`; its only public callable is `get`. Asserted by test.
- **No arbitrary path.** Paths must match the plugin's closed allowlist; query parameters are
  refused unless explicitly allowlisted.
- **No OpenTofu.** The transport's import table contains no `plan_gen`, no `provisioning`, no
  `subprocess`. Asserted by AST test.
- **No SSH, no `pvesh`.** Same test.
- **The token cannot reach a log or a traceback.** Every failure is re-raised `from None` as a
  closed reason code, because `httpx.HTTPStatusError` carries `.request.headers` — including the
  `Authorization` header.
- **The transport cannot be serialized**, so it cannot be written to a Temporal payload or a file.
- **The API process cannot resolve the credential** — enforced by the existing architecture
  boundary tests.

### Not authorised by this packet

Any `POST`/`PUT`/`DELETE`; `PUT /cluster/sdn` (the SDN apply); any guest, storage, firewall or
network change; any OpenTofu `init`, `plan` or `apply`; any provider plugin execution; any
permission change.

---

# Open decisions blocking the last link — for Juan

The discovery chain is complete from credential resolution to a signed snapshot, and
`verify_discovery_snapshot` verifies one against an `ExpectedWorkerRegistration`. **What has no
production caller is the code that loads that registration from the database**, and it is blocked on
two questions rather than on effort. Both are recorded here rather than worked around, because every
workaround available is the injectable-authority hole this whole chain exists to close.

`ExpectedWorkerRegistration` has six fields. Four are already durable:

| Field | Durable source |
| --- | --- |
| `worker_installation_id` | `WorkerEnrollmentState.worker_installation_id` |
| `verification_anchor_fingerprint` | `WorkerEnrollmentState.worker_key_id` |
| `worker_release_fingerprint` | `WorkerEnrollmentState.release_digest` |
| `organization_identity` | `WorkerEnrollmentState.organization_id` |

Two are not.

### 1. `worker_role` has no durable home, and may not get one in enrollment

The binding signs `worker_role` (`"proxmox_privileged"`) and the verifier compares it against the
registration. No table stores it. The obvious place — the enrollment row — is closed to it: the
management plane is provider-neutral by machine-enforced rule, and no Proxmox concept may appear in
any management identity, release, evidence, enrollment or config surface
(`tests/test_management_plane_boundary.py`).

**Recommendation.** Treat `worker_role` as a constant the *discovery contract* declares rather than a
per-worker database fact: every worker performing Proxmox discovery is `proxmox_privileged` by
definition of the operation. The comparison still catches a signer claiming a different role, needs
no column, and keeps the provider concept inside the provider-specific contract where it belongs.
The alternative — a new column on a control-plane-side worker table — costs a migration and puts a
provider string one import away from the neutral plane.

### 2. `target_identity` needs a worker-to-target binding that does not exist

`ExpectedWorkerRegistration.target_identity` asserts which target this worker is registered to act
on. Nothing binds the two: `ExecutionTarget` (`models.py:627`) has no worker column,
`TargetOnboarding` (`models.py:681`) carries only org and target, and `WorkerEnrollmentState`
(`worker_enrollment_models.py:189`) carries only org and site label. The worker→target link exists
today only inside a `DiscoveryResolutionContract`, which is per-operation and not durable.

**Recommendation.** Derive it from the operation being verified rather than storing a new binding:
the `WorkflowRun`/operation row already names the execution target, and the verifier already takes
`expected_target_identity` separately. That makes the registration's `target_identity` redundant
with a value the control plane holds anyway, and the field should be dropped from the registration
rather than sourced. Dropping it changes the verifier's comparison set, which is a trust-contract
change and therefore Juan's.

### Why neither was implemented anyway

Both have a "just pass it in" answer, and both of those answers reintroduce exactly the defect the
rest of this work removed: a caller supplying the value that authority is checked against. The
binding factory was removed for this reason; a caller-supplied expectation would be the same hole
one layer up.

**Nothing below this line is authorised, scheduled, or partially done.** No migration has been
authored, no column added, no verifier field changed.
