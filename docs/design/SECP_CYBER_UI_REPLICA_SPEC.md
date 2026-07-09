# SECP Cyber UI Replica Spec

## Goal

Recreate the SECP cyber command UI concept as a real production frontend.

Do not make a fake static screenshot. Build reusable React components, design tokens, backgrounds, icons, and page layouts that match the visual direction of:

docs/design/reference/secp-cyber-ui-reference.png

## Visual Target

The UI should feel like a premium cyber range command center:

- dark navy/black canvas
- neon cyan, blue, purple, green, and red status accents
- glass panels
- glowing borders
- high-tech grid backgrounds
- holographic globe / cyber mesh hero
- custom hex/cube security icons
- dense but readable dashboard cards
- futuristic Packet Tracer-style topology canvas
- high-confidence enterprise security product feel

## Required Page Families

1. Overview Command Center
2. Target Inventory
3. Target Detail
4. Target Onboarding Wizard
5. RO Discovery Bootstrap
6. Target Discovery
7. Staging Labs
8. Live Access Authorizations
9. Approvals
10. Audit Log
11. Cyber Range Topology Builder / Packet Tracer Clone
12. Provider Deployment Hub
13. Proxmox Provider Setup
14. Kubernetes Provider Setup
15. Local Hosting / IaaS Deployment Flow
16. Worker Operations
17. Settings / Plugins

## Hard Product Truth Rules

- SECP is sealed by default.
- Never imply real infrastructure was contacted unless backend state proves it.
- Never imply approval executes anything.
- Never show secrets, tokens, private keys, or raw credentials.
- API does not SSH/probe infrastructure.
- Worker-owned actions must be labeled honestly.
- Candidate plans are non-executable.
- Live apply remains sealed.
- Preserve closed-code safety/error language.
- No backend free-form error strings should be rendered directly where closed-code copy exists.
- Disabled actions should explain the missing permission or missing gate.

## Design System Requirements

Create reusable primitives:

- AppShell
- Sidebar
- TopStatusBar
- CyberCard
- StatusBadge
- EvidenceBadge
- DecisionCard
- MetricTile
- ActionTile
- CyberButton
- CyberInput
- CyberSelect
- CyberTable
- StepRail
- AccessChain
- ClosedCodeError
- EmptyState
- CyberPageHeader
- CyberHeroPanel
- CyberSectionGrid

Create cyber background components:

- CyberGridBackground
- HolographicGlobePanel
- SealedVaultPanel
- PacketFlowBackground
- ProviderMeshBackground
- TopologyGridBackground

Create icon language:

- SECP logo mark
- target
- Proxmox
- Kubernetes
- cloud provider
- worker
- resolver
- authorization
- lock/sealed
- audit ledger
- packet node
- firewall
- router
- switch
- team
- evidence
- candidate plan

## Rive Usage

Use Rive for small animated runtime assets only, not full page layouts.

Target Rive assets:

1. sealed-lock.riv
2. authorization-pulse.riv
3. packet-flow.riv
4. topology-node-state.riv
5. approval-stamp.riv

React must include safe CSS/SVG fallbacks if .riv files are missing.

## Exactness Standard

Match the concept image in:

- layout hierarchy
- dark cyber command theme
- panel density
- glowing card treatment
- icon style
- status colors
- wizard card style
- topology canvas feel
- dashboard composition

But improve the implementation so it is responsive, accessible, and backed by real app state.

## Accessibility

- keyboard navigable
- visible focus states
- sufficient contrast
- reduced-motion support
- no text hidden only in images
- mobile/tablet fallback layouts

## Validation

Run:

- npm run typecheck
- npm run lint
- npm test
- npm run build

Use Playwright MCP to capture screenshots of major pages after changes.
