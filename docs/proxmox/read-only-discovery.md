# Read-Only Proxmox Discovery (SECP-002A)

Discovery imports a **read-only** snapshot of an approved Proxmox cluster's
inventory into provider-neutral records. It performs no mutation and is never run
against a real endpoint in SECP-002A (fakes / mock transport only).

## Flow (normal operation)

```
Admin registers ExecutionTarget (plugin=proxmox, non-secret config, opaque secret_ref)
        │  API: validate secret_ref SYNTAX only; persist immutable target; audit
        ▼
Admin requests discovery (API)
        │  API: create ProviderInventorySnapshot(status=queued) + WorkflowRun(queued);
        │       audit discovery.requested; enqueue Discover workflow (Temporal)
        ▼
Worker executes Discover workflow
        │  resolve secret_ref via SecretResolver (worker only, just-in-time)
        │  plugin.validate(target) -> TargetValidationResult
        │  plugin.discover(DiscoveryRequest) using GET-only transport
        │  filter resources through scope policy
        │  normalize -> DiscoveredResource[]
        │  persist ProviderInventoryResource[]; finalize snapshot (immutable);
        │  audit discovery.started / discovery.completed (or discovery.failed)
        ▼
Admin views sanitized snapshot (API: inventory:read)
```

The **API never** calls the Proxmox plugin and **never** resolves the secret
reference. All provider contact happens in the worker.

Correction pass: the API also never submits to Temporal before commit. A discovery
request atomically creates the queued snapshot, queued `WorkflowRun`, and durable
`workflow_dispatch_outbox` row. A worker-side publisher reads only committed
outbox rows, submits the Discover workflow, marks success as `submitted`, and
leaves publish failures durable as `failed` and retryable.

## Resource normalization (provider-neutral)

Proxmox concepts map onto generic `DiscoveredResource` records (no Proxmox-specific
columns):

| Proxmox concept (GET) | Generic `resource_type` | `provider_external_id` | `parent_ref` |
| --- | --- | --- | --- |
| `/nodes` | `node` | node name | cluster |
| `/nodes/{n}/qemu` | `vm` | `{node}/{vmid}` | node |
| `/nodes/{n}/lxc` | `container` | `{node}/{vmid}` | node |
| `/nodes/{n}/storage` | `storage` | `{node}/{storage}` | node |
| `/cluster/resources?type=...` | as above | composite | cluster/node |
| `/cluster/sdn/vnets` (read) | `network` | vnet id | sdn-zone |

Only fields needed for inventory are kept: id, display name, status, and a small
generic `attributes` map (e.g. `maxmem`, `cores`, `type`) — **never** secrets,
tokens, or guest credentials. The exact endpoint set is conservative and read-only.

## Scope policy

An `ExecutionTarget.scope_policy` may restrict discovery to specific nodes / pools /
resource types. Resources are filtered through the scope policy **before**
persistence, so out-of-scope inventory is never stored.

## Allowed HTTP

- **GET only.** The transport raises `MutatingRequestRefused` for any other method
  **before** sending. This is enforced in the transport, not merely by convention.
- No guest-agent endpoints, no `/nodes/{n}/{type}/{id}/status/start|stop`, no
  `/nodes/{n}/tasks/...` actions, no config `PUT`/`POST`, no console/VNC.

## Testing strategy

- A `FakeProxmoxTransport` returns canned JSON for GET paths and **fails the test**
  if any non-GET method is attempted.
- `test_proxmox_plugin.py` proves: GET-only; non-GET refused before send;
  normalization correctness; scope filtering; `validate`/`health`/`discover`/
  `status` behavior; `apply`/`reset`/`destroy` raise `UnsupportedCapabilityError`.
- No real hostnames/IPs/credentials appear in fixtures (placeholders like
  `proxmox.example.test`, RFC-5737/RFC-1918 documentation ranges only).

## Explicit non-actions

Discovery does not, and the plugin cannot: create/modify/delete anything; start/stop
guests; call the guest agent; run tasks; mutate config; open consoles; or touch any
network/storage/firewall resource. Provisioning is SECP-002B.
