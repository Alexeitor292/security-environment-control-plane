# SECP Rive Motion Pack — Authoring & Export

Status: **Rive runtime assets are NOT yet exported.** The Rive MCP server was
reachable during PR-10 but exposed no authoring/export tools in this session, so
no `.riv` binaries were fabricated. Every wrapper renders a complete CSS/SVG
fallback (see `rive-motion.css` + `wrappers.tsx`) that is the ground truth and
remains permanently if a `.riv` is missing or fails to load. When the assets are
authored and dropped into `apps/web/public/rive/`, `RiveOrFallback` will overlay
them automatically — no code change required.

The React runtime (`RiveCanvas.tsx`) is lazy-loaded, so the Rive dependency is
code-split out of the main bundle and only fetched when an animated wrapper
mounts under non-reduced-motion.

## Runtime contract each artboard must satisfy

- One artboard, one state machine, the exact input names/types below.
- Inputs are already mapped from real page state by `rive-state.ts` — the
  animation must not re-interpret them. Numeric `status` inputs use the index
  maps in `wrappers.tsx`.
- Decorative only: no product copy, no secret-looking strings, no fabricated
  IPs/hashes baked into artwork.
- Keep loops subtle and bounded. The paused/first-frame state must be meaningful
  on its own (it is what reduced-motion users and failed loads see).
- State must not be conveyed by color alone — mirror the fallback's per-state
  shape differences.

## Artboards, state machines, inputs

| Artboard | State machine | Inputs | Notes |
|---|---|---|---|
| `SealedLock` | `LockState` | `sealed` (bool), `authorized` (bool), `active` (bool), `refused` (bool), `pulse` (trigger) | authorized must NOT look like active execution; sealed is the resting default |
| `AuthorizationPulse` | `AuthorizationState` | `status` (number: 0 draft, 1 pending, 2 approved, 3 expired, 4 revoked, 5 refused), `pulse` (trigger) | pending may pulse; approved is steady (a decision, not traffic) |
| `PacketFlow` | `FlowState` | `running` (bool), `readOnly` (bool), `denied` (bool), `sealed` (bool) | sealed shows NO flowing traffic; denied is not a completed path; read-only ≠ write/apply |
| `TopologyNode` | `NodeState` | `selected` (bool), `isolated` (bool), `compromised` (bool), `sealed` (bool) | each state needs a distinct shape, not just hue; precedence: compromised > sealed > isolated > selected > default |
| `ApprovalStamp` | `ApprovalState` | `status` (number: 0 pending, 1 approved, 2 rejected, 3 stale), `play` (trigger) | approved communicates "decision recorded", never execution |
| `WorkerBundle` | `BundleState` | `preparing` (bool), `ready` (bool), `failed` (bool), `sealed` (bool) | ready = bundle prepared, NOT discovery completed |
| `DiscoveryScan` | `DiscoveryState` | `status` (number: 0 queued, 1 running, 2 completed, 3 failed) | queued must not animate like running; completed does not imply eligible |

## Expected runtime output paths

- `apps/web/public/rive/sealed-lock.riv`
- `apps/web/public/rive/authorization-pulse.riv`
- `apps/web/public/rive/packet-flow.riv`
- `apps/web/public/rive/topology-node-state.riv`
- `apps/web/public/rive/approval-stamp.riv`
- `apps/web/public/rive/worker-bundle.riv`
- `apps/web/public/rive/discovery-scan.riv`

## Shortest manual export procedure (Rive Desktop / rive.app)

1. Open (or create) a document; add one artboard per row above with the exact
   artboard name.
2. On each artboard add the named state machine and the exact inputs/types.
   Draw states that mirror the fallback shapes (`rive-motion.css`).
3. For each artboard: **Export → Runtime (.riv)**, selecting only that artboard's
   state machine.
4. Save each file to the corresponding path under `apps/web/public/rive/` using
   the exact filename above.
5. No code change is needed — reload the app; `RiveOrFallback` picks up each
   asset and the fallback stays as the safety net.
