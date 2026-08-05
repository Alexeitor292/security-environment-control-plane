# Spatial migration — per-file SHA-256 attestation

Point-in-time record of every file migrated from the spatial prototype, hashed on
both sides.

## What this does and does not prove

It proves the bytes in this repository are the bytes in the donor tree, for every
file rather than just the binaries. It catches the class of drift that review
cannot see: a dropped or doubled UTF-8 BOM, a CRLF/LF rewrite, an editor
re-encoding, a partial copy. None of those appear in a diff or fail a typecheck.

It does **not** prove the files are correct, and it is **not** a standing guard —
it was produced once and nothing re-runs it. The standing guards are:

| Guard | Protects |
| --- | --- |
| `src/spatial/scene/model-integrity.test.ts` | the glTF model is a real, whole glTF binary |
| `src/spatial/migration-completeness.test.ts` | no page orphaned, no route lost |
| `src/spatial/security-claims.test.ts` | no page asserts an unobserved security property |
| `src/spatial/authorization-boundary.test.ts` | no mutating adapter method reachable without a gate |
| `src/spatial/route-guard.test.ts` | the spatial workspace mounts only inside the auth boundary |

## Summary

| | Count |
| --- | ---: |
| Migrated files hashed | 211 |
| **Identical to donor** | **200** |
| Intentionally modified (all listed below, with reason) | 11 |
| Added by this branch | 9 |

Line endings: all 202 migrated text files are LF-only on both sides.
UTF-8 BOMs: 9 donor files carry one; all 9 preserved byte-for-byte.

## The 11 files that differ, and why

Every one was edited in place from the donor original. Nothing was regenerated,
reformatted, renamed, lint-fixed or prettier-run. Donor source was landed
byte-identical first (commit P7-C.1); all modification came afterwards in
separate, reviewable commits.

**Adapter boundary (6 files) — `SECP-P7-C.2`.** Made fixture data observable at
runtime. The two copies of the boundary (`prototype-suite/core` and the
`deployments/prototype` fork) received identical edits, which is why their hashes
match each other on both sides.

**Security claims (5 files) — `SECP-P7-C.8`.** Removed assertions about
enforcement that no page can observe, and that were in several cases already
false. See §4.1 of the migration matrix.

| File | Reason | Donor | Repo |
| --- | --- | --- | --- |
| `apps/prototype-suite/core/integrations/adapter.ts` | adapter boundary | `78822d29…` | `a4e2cdeb…` |
| `apps/prototype-suite/core/integrations/AdapterContext.tsx` | adapter boundary | `d3b56542…` | `16c4a868…` |
| `apps/prototype-suite/core/integrations/mock-adapter.ts` | adapter boundary | `7e084dd1…` | `6ea9a127…` |
| `apps/deployments/prototype/integrations/adapter.ts` | adapter boundary | `78822d29…` | `a4e2cdeb…` |
| `apps/deployments/prototype/integrations/AdapterContext.tsx` | adapter boundary | `d3b56542…` | `16c4a868…` |
| `apps/deployments/prototype/integrations/mock-adapter.ts` | adapter boundary | `7e084dd1…` | `6ea9a127…` |
| `apps/prototype-suite/core/features/infrastructure/ProvidersPage.tsx` | security claims | `71100a0b…` | `fa8b2b85…` |
| `apps/prototype-suite/core/features/infrastructure/InventoryPage.tsx` | security claims | `2321b156…` | `384ecb31…` |
| `apps/prototype-suite/core/features/infrastructure/TargetsPage.tsx` | security claims | `7f366524…` | `855c2c6b…` |
| `apps/prototype-suite/core/features/deployments/DeploymentAdvancedPage.tsx` | security claims | `b39da4e2…` | `943b2f2a…` |
| `apps/deployments/prototype/features/deployments/DeploymentAdvancedPage.tsx` | security claims | `b39da4e2…` | `943b2f2a…` |

None of the 11 carries a UTF-8 BOM in the donor, so no in-place edit could have
disturbed one.

## The 9 files added by this branch

`integrations/provenance.tsx`, `integrations/provenance.css`,
`integrations/provenance.render.test.tsx`, `SpatialWorkspace.tsx`,
`migration-completeness.test.ts`, `route-guard.test.ts`,
`security-claims.test.ts`, `authorization-boundary.test.ts`,
`scene/model-integrity.test.ts`.

## Excluded from migration

- **16 backup droppings** (`*.pre-<desc>-<timestamp>`, `*.20260803-102820.bak`).
  Not source. Enumerated in the pull request.
- **`public/models/server-rack-new.glb`** (22,615,248 B). Referenced by nothing:
  `scene/config/scene.ts` points at `/models/server-rack.glb`, `ServerRack.tsx`
  holds the only `useGLTF` call site, and no source file, `index.html` or donor
  backup directory names the other model. Excluded so a permanent 22.6 MB blob
  does not enter every future clone for an asset no code path reaches. The model
  the donor actually renders is migrated byte-identical, so the scene is
  unchanged. Git LFS was considered and rejected: at 6.1 MB it is unwarranted,
  and a misconfigured LFS checkout leaves a ~130-byte pointer that fails silently
  at runtime as an empty scene.

`hero.png` is referenced by nothing but IS kept: 13 KB is a negligible permanent
cost and byte-level traceability is worth more. The same cost-weighted rule
points the other way at 22.6 MB.

## Binary assets

Verified at four points — donor working tree, repo working tree, the blob as
stored by git (`git cat-file blob`), and the `dist/` output of a production
build — all matching.

```
668dd1e44e02df1146dc324454093caaca7153865a390fa264b4e4332b98a1ae  public/models/server-rack.glb
b45fa506195cfcdef406ba9f0c77b36ddc1a7c224040926ec70abc2fdea7b93a  public/icons.svg
61bc9a161de58248288e6905425d7180f0624c2865007b97d763fdac12043a66  public/favicon.svg
881ffbcaafc212e49addad08846a5b82761355fa20624253af3477ba33262c5c  src/spatial/assets/hero.png
```

## Full table

`OK` = repo byte-identical to donor. Source paths are relative to
`apps/web/src/spatial/`.

| Status | SHA-256 | Path |
| --- | --- | --- |
| OK | `c3b317b6212a050d67d8196ba798345463b880cfb2b9565d57ddc8f42df60810` | `src/spatial/App.tsx` |
| OK | `cc5978972bd75334aeff8079b28c2c462d580fb4a02c0a48372379058f4145e1` | `src/spatial/apps/activity/ActivityApp.css` |
| OK | `8ebb0d7034b6514de106f6c725a8d84da38fbb812bbc05fb87dcdd6197f51f8e` | `src/spatial/apps/activity/ActivityApp.tsx` |
| OK | `d520860db08ff8dc4f80cf9d94fbcc70d23eca51b00b1ceaaca0c60465de18dd` | `src/spatial/apps/administration/AdministrationApp.tsx` |
| OK | `f1cd20a09eae170d646c277e054ba95afa262981d112cb704c9dfefd638897d4` | `src/spatial/apps/cyber-ranges/CyberRangesApp.css` |
| OK | `24164c602aa14b0d2fdfb6812a1e1e0c2793b123d6c961413c34f43fe17720e7` | `src/spatial/apps/cyber-ranges/CyberRangesApp.tsx` |
| OK | `06afa113e4e8ae37d255862e2d8ae16ca0dbbd38b112f4cee188da04ef58e8b8` | `src/spatial/apps/deployments/DeploymentsApp.css` |
| OK | `2e67ad03e1006f609c81207e319823e7aeeaa9a1d5884d4d96205e6e66a055c4` | `src/spatial/apps/deployments/DeploymentsApp.tsx` |
| OK | `83d44c0088e9b5258f3dfde1caeac62636f55fedb330c4db57cde077ce137dac` | `src/spatial/apps/deployments/prototype/app/AppStateContext.tsx` |
| OK | `375371f61ecaa6f27987b03a9ff4ce0220f7944ed26edca416897edd647207fa` | `src/spatial/apps/deployments/prototype/components/Accordion.tsx` |
| OK | `53d8aa2e81f6e8982a509619d17068c3e977146ac78ee38b0a686c54e53e741f` | `src/spatial/apps/deployments/prototype/components/AdvancedToggle.tsx` |
| OK | `a2eea0f621463bfd137608e15a924eaf163e62fb5af09983991bf9c3addfb3b0` | `src/spatial/apps/deployments/prototype/components/AlertsList.tsx` |
| OK | `1ab0388d07a1c927919689329a98fc79a7b1466343b445037429fbdf6f20d4d2` | `src/spatial/apps/deployments/prototype/components/Button.tsx` |
| OK | `1ae07fed9d34f765f3dedc46ba060f014c208256216dcbad68cf4ef148a8d9a7` | `src/spatial/apps/deployments/prototype/components/CapabilityNotice.tsx` |
| OK | `0e9b5041dbd200f6549336e028688c272a28f38d115e44c4212afbc4b7cc8107` | `src/spatial/apps/deployments/prototype/components/Card.tsx` |
| OK | `a7002a8f42c45464c3660f330ac7d5389afac19d836c945cda6a2402eb60d500` | `src/spatial/apps/deployments/prototype/components/DangerousOperationDialog.tsx` |
| OK | `63abddebf79e3cd997283933e09efcc8b7f68fff478a20e8ee93ab0549d1ca1b` | `src/spatial/apps/deployments/prototype/components/DataTable.tsx` |
| OK | `019dff5db8b6862dc809127057d4b61dda7dee563e2b5435be3e73d108b83ce3` | `src/spatial/apps/deployments/prototype/components/Drawer.tsx` |
| OK | `4f00010bc5fc5a5a0e3d8246962999f847e12b5fdfd062a0279dfa8acbcb9703` | `src/spatial/apps/deployments/prototype/components/FilterBar.tsx` |
| OK | `c8b785b394d71c772c8da1522332eeac4574c54524d9ce948271ff907ab8027a` | `src/spatial/apps/deployments/prototype/components/index.ts` |
| OK | `acdc89fe2f8b1448487609ac2a24d2aadd934b501c04395dc294455c50b42eb1` | `src/spatial/apps/deployments/prototype/components/KeyValueGrid.tsx` |
| OK | `2704e1702a62c979e64b539a0b47c771fe98a3b31ce654a7abac1ffc6b2ad533` | `src/spatial/apps/deployments/prototype/components/MetricTile.tsx` |
| OK | `fba7b876567c4647fec38a707a0d0f180ee72a70362b8fa14da5917daded3a85` | `src/spatial/apps/deployments/prototype/components/PageHeader.tsx` |
| OK | `170e5ab26b40aefc67080a9f66a8f2141d480ee27efeaa951eaaebe7c3ca920a` | `src/spatial/apps/deployments/prototype/components/pop-button.css` |
| OK | `92a4537e55a4c87c798c66e9029af216ca90cbe6d557e7396d0690141f73ffe6` | `src/spatial/apps/deployments/prototype/components/PopButton.tsx` |
| OK | `1edbe05315f7d5161763598417cb85d66ddf4687a8f9fe0127382de7b0ad512c` | `src/spatial/apps/deployments/prototype/components/ProviderBadge.tsx` |
| OK | `84f36cfb56926420a6a3a5b35237509773d2ffde86751df294a6f4aff722b4ef` | `src/spatial/apps/deployments/prototype/components/ResourceInspector.tsx` |
| OK | `15dc163a3c9a57c893035614a892c6c65e302b5cf6c60d7b6609cd35b2cb1a53` | `src/spatial/apps/deployments/prototype/components/States.tsx` |
| OK | `fca977a17a59dc4c9305a816f12152e915846a5b0181155d035ce8dc49fd1a6d` | `src/spatial/apps/deployments/prototype/components/StatusBadge.tsx` |
| OK | `57d92382bc0cdea93ddd5100f0c04ef02757b4de1723d1b3f24e1924621b7ccd` | `src/spatial/apps/deployments/prototype/components/Tabs.tsx` |
| OK | `04f13988f59ee4e5beab6224523c6a6e5916bee57d331aad2150bb84f1d7bd0f` | `src/spatial/apps/deployments/prototype/components/Timeline.tsx` |
| OK | `9e75f5cdaff4827f776a47b878b41470845540ad347c8200dbdb84992bb8ddcc` | `src/spatial/apps/deployments/prototype/components/TopologyCanvas.tsx` |
| OK | `63ef7f7f3af6edb50a6a160358f76d8d14e54804c78beccb0b43eb8a3b5ea738` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentActivityPage.tsx` |
| MODIFIED | `943b2f2a656fdbfd8a4a7b1c69c49efe59759098d93fd195305f5e95eeb7896a` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentAdvancedPage.tsx` |
| OK | `dbead89dfee8616a3417bc151984accc1d187e5043040b9997c590f3c561a9e0` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentCard.tsx` |
| OK | `861f45d980977ceacec44c5713c92617f069ea24d80ae8ebc536a3b5ac0f057d` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentMonitoringPage.tsx` |
| OK | `b75540380d27d880c0dee5669eaa977d0081d2544661e621d48171744fd76a09` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentOperationsPage.tsx` |
| OK | `38ae0268f3fea66a3dfb816427dd97cde9c1604f2d7c4a9a0e512e92b18c32c4` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentPortfolioPage.tsx` |
| OK | `866023896027ca009b087c20a2bd099980e08571c70cea0d5d36e54b07d2c597` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentResourcesPage.tsx` |
| OK | `abac4fd2e79c30699933270dd49502e3634c41dbaaa319b832c17e4ee4adb843` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentSummaryPage.tsx` |
| OK | `de4ab809d9271960f943ebd0a99cd20cd98852a22357b10dc8fe6dd54954961a` | `src/spatial/apps/deployments/prototype/features/deployments/DeploymentTopologyPage.tsx` |
| MODIFIED | `a4e2cdebc398c2f401e09e45a0b086c83dcf3c8ed89bffcc1b553715dbad3b42` | `src/spatial/apps/deployments/prototype/integrations/adapter.ts` |
| MODIFIED | `16c4a86879b394b46f1a0772df18cda9a0a9b3307fd4844b1ec524cba3ae88e1` | `src/spatial/apps/deployments/prototype/integrations/AdapterContext.tsx` |
| MODIFIED | `6ea9a12731dcd3067091c2a76cc73c6112b5d0190355cf71e616983757ff3e3a` | `src/spatial/apps/deployments/prototype/integrations/mock-adapter.ts` |
| OK | `1ae30b8d85c6e68795ed3c91ff081820ada02da534ffc7ce1f4b1c0b3a672a4a` | `src/spatial/apps/deployments/prototype/layouts/DeploymentWorkspaceLayout.tsx` |
| OK | `0b93cf461086668246b64eb2a6dcc1d4dc6439708ec07467e914740a6bad16df` | `src/spatial/apps/deployments/prototype/mocks/capabilities.ts` |
| OK | `0487bec811d46adc68f59cad3c439d94b406b53697d2473ebddd35a00c7d345f` | `src/spatial/apps/deployments/prototype/mocks/deployments.ts` |
| OK | `93411f1122a09b1ba375f7c9a3cd55624f176290759c0583b64ee504d8a0e0e8` | `src/spatial/apps/deployments/prototype/mocks/events.ts` |
| OK | `828b5f2660a1bafaf42181cd74b3538f0b4af42c3616c6c299ec92a565bbee1c` | `src/spatial/apps/deployments/prototype/mocks/governance.ts` |
| OK | `88b9386969a7b183add5ff3dbe746b0a06e5a34e747c588d47d9da99a6826dbb` | `src/spatial/apps/deployments/prototype/mocks/index.ts` |
| OK | `ead3cf68dd8b532f3c638b6ad76b3a80579671acde7dbc20f39adecc9ec8d5f4` | `src/spatial/apps/deployments/prototype/mocks/infrastructure.ts` |
| OK | `3c7a0216b2ccd233437ce56c425da4263c41dd74c74b30ae45383a017190e8ef` | `src/spatial/apps/deployments/prototype/mocks/operations.ts` |
| OK | `19650f96a3dbb31b1602196970d176c6652681e63cb227f8be69f413d767d390` | `src/spatial/apps/deployments/prototype/mocks/scenarios.ts` |
| OK | `e81ee68a98974478035670e7eb28249a99acc3952979a9fbc94eaa0e94e43b83` | `src/spatial/apps/deployments/prototype/mocks/topology.ts` |
| OK | `827fb6292c9da9659c4ee89a299ffba94f864b28f3eb7a00b8f0ea841b164244` | `src/spatial/apps/deployments/prototype/models/types.ts` |
| OK | `b2c984d30cd0e6315367ef38bdc3d770f2198e6070d9b73c0e0469f0b9ec8918` | `src/spatial/apps/infrastructure/CapabilityState.tsx` |
| OK | `6303920279138704c864e0eee6aa821d8e9ccc4ccfe7677cf7c48534d4e9a398` | `src/spatial/apps/infrastructure/InfrastructureApp.css` |
| OK | `0f161b5c1b15500c6b03e57221a873c2784e52c95d20c20f8096641e4614b794` | `src/spatial/apps/infrastructure/InfrastructureApp.tsx` |
| OK | `93e9afa680e952f1dbcf4568e4ea7955bf13ef9c6ac2f81993bb66693c3fe346` | `src/spatial/apps/infrastructure/SpatialInfrastructureApp.tsx` |
| OK | `83d44c0088e9b5258f3dfde1caeac62636f55fedb330c4db57cde077ce137dac` | `src/spatial/apps/prototype-suite/core/app/AppStateContext.tsx` |
| OK | `375371f61ecaa6f27987b03a9ff4ce0220f7944ed26edca416897edd647207fa` | `src/spatial/apps/prototype-suite/core/components/Accordion.tsx` |
| OK | `53d8aa2e81f6e8982a509619d17068c3e977146ac78ee38b0a686c54e53e741f` | `src/spatial/apps/prototype-suite/core/components/AdvancedToggle.tsx` |
| OK | `a2eea0f621463bfd137608e15a924eaf163e62fb5af09983991bf9c3addfb3b0` | `src/spatial/apps/prototype-suite/core/components/AlertsList.tsx` |
| OK | `1ab0388d07a1c927919689329a98fc79a7b1466343b445037429fbdf6f20d4d2` | `src/spatial/apps/prototype-suite/core/components/Button.tsx` |
| OK | `1ae07fed9d34f765f3dedc46ba060f014c208256216dcbad68cf4ef148a8d9a7` | `src/spatial/apps/prototype-suite/core/components/CapabilityNotice.tsx` |
| OK | `0e9b5041dbd200f6549336e028688c272a28f38d115e44c4212afbc4b7cc8107` | `src/spatial/apps/prototype-suite/core/components/Card.tsx` |
| OK | `9b1f35fc2bff9967474b2818df61fbdb4e6f7bfd416980ac380427ce63c8a98e` | `src/spatial/apps/prototype-suite/core/components/ConnectivityMatrix.tsx` |
| OK | `a7002a8f42c45464c3660f330ac7d5389afac19d836c945cda6a2402eb60d500` | `src/spatial/apps/prototype-suite/core/components/DangerousOperationDialog.tsx` |
| OK | `63abddebf79e3cd997283933e09efcc8b7f68fff478a20e8ee93ab0549d1ca1b` | `src/spatial/apps/prototype-suite/core/components/DataTable.tsx` |
| OK | `019dff5db8b6862dc809127057d4b61dda7dee563e2b5435be3e73d108b83ce3` | `src/spatial/apps/prototype-suite/core/components/Drawer.tsx` |
| OK | `4f00010bc5fc5a5a0e3d8246962999f847e12b5fdfd062a0279dfa8acbcb9703` | `src/spatial/apps/prototype-suite/core/components/FilterBar.tsx` |
| OK | `485b77d7d1b53a0ff629664869ac4c51b5c532e2da0db70c15f2461c90fcb83c` | `src/spatial/apps/prototype-suite/core/components/index.ts` |
| OK | `acdc89fe2f8b1448487609ac2a24d2aadd934b501c04395dc294455c50b42eb1` | `src/spatial/apps/prototype-suite/core/components/KeyValueGrid.tsx` |
| OK | `2704e1702a62c979e64b539a0b47c771fe98a3b31ce654a7abac1ffc6b2ad533` | `src/spatial/apps/prototype-suite/core/components/MetricTile.tsx` |
| OK | `fba7b876567c4647fec38a707a0d0f180ee72a70362b8fa14da5917daded3a85` | `src/spatial/apps/prototype-suite/core/components/PageHeader.tsx` |
| OK | `5855349e73381fcdec65359c2b1f89d80d04113cf56a0b858e1d49c861dcd94d` | `src/spatial/apps/prototype-suite/core/components/PhaseTimeline.tsx` |
| OK | `318682ce3378ec5b1e205862c24e476a0c4911888b54cd152f536cf0bbeaccd7` | `src/spatial/apps/prototype-suite/core/components/PopButton.tsx` |
| OK | `11012aceca22ff8a39e4f21e3a935818de51b049f09609e0dcdf2725275d5a2c` | `src/spatial/apps/prototype-suite/core/components/prototype/PrototypeBanner.tsx` |
| OK | `1edbe05315f7d5161763598417cb85d66ddf4687a8f9fe0127382de7b0ad512c` | `src/spatial/apps/prototype-suite/core/components/ProviderBadge.tsx` |
| OK | `84f36cfb56926420a6a3a5b35237509773d2ffde86751df294a6f4aff722b4ef` | `src/spatial/apps/prototype-suite/core/components/ResourceInspector.tsx` |
| OK | `d78aa009a3465cda2c276fb5621eaf620a21bc2deaac45f4e56be25dc567ac29` | `src/spatial/apps/prototype-suite/core/components/Scoreboard.tsx` |
| OK | `15dc163a3c9a57c893035614a892c6c65e302b5cf6c60d7b6609cd35b2cb1a53` | `src/spatial/apps/prototype-suite/core/components/States.tsx` |
| OK | `fca977a17a59dc4c9305a816f12152e915846a5b0181155d035ce8dc49fd1a6d` | `src/spatial/apps/prototype-suite/core/components/StatusBadge.tsx` |
| OK | `57d92382bc0cdea93ddd5100f0c04ef02757b4de1723d1b3f24e1924621b7ccd` | `src/spatial/apps/prototype-suite/core/components/Tabs.tsx` |
| OK | `04f13988f59ee4e5beab6224523c6a6e5916bee57d331aad2150bb84f1d7bd0f` | `src/spatial/apps/prototype-suite/core/components/Timeline.tsx` |
| OK | `9e75f5cdaff4827f776a47b878b41470845540ad347c8200dbdb84992bb8ddcc` | `src/spatial/apps/prototype-suite/core/components/TopologyCanvas.tsx` |
| OK | `a48537efc274ce76528985f2043452543c88ccd59ed23784b0d0847adf2a7e2d` | `src/spatial/apps/prototype-suite/core/components/Wizard.tsx` |
| OK | `3a46b132e87d91b42a3943889c9117cd4264b607feb3810461263a4d8c567da9` | `src/spatial/apps/prototype-suite/core/features/command-center/CommandCenterPage.tsx` |
| OK | `63ef7f7f3af6edb50a6a160358f76d8d14e54804c78beccb0b43eb8a3b5ea738` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentActivityPage.tsx` |
| MODIFIED | `943b2f2a656fdbfd8a4a7b1c69c49efe59759098d93fd195305f5e95eeb7896a` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentAdvancedPage.tsx` |
| OK | `dbead89dfee8616a3417bc151984accc1d187e5043040b9997c590f3c561a9e0` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentCard.tsx` |
| OK | `861f45d980977ceacec44c5713c92617f069ea24d80ae8ebc536a3b5ac0f057d` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentMonitoringPage.tsx` |
| OK | `b75540380d27d880c0dee5669eaa977d0081d2544661e621d48171744fd76a09` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentOperationsPage.tsx` |
| OK | `38ae0268f3fea66a3dfb816427dd97cde9c1604f2d7c4a9a0e512e92b18c32c4` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentPortfolioPage.tsx` |
| OK | `866023896027ca009b087c20a2bd099980e08571c70cea0d5d36e54b07d2c597` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentResourcesPage.tsx` |
| OK | `abac4fd2e79c30699933270dd49502e3634c41dbaaa319b832c17e4ee4adb843` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentSummaryPage.tsx` |
| OK | `de4ab809d9271960f943ebd0a99cd20cd98852a22357b10dc8fe6dd54954961a` | `src/spatial/apps/prototype-suite/core/features/deployments/DeploymentTopologyPage.tsx` |
| OK | `281b655070c20a62faf478a0d2331c5a0b6091efc4ed477f6649a677706eb7a2` | `src/spatial/apps/prototype-suite/core/features/events/ControlRoomPage.tsx` |
| OK | `2a3681caf53cf56f8c4ec1f02b74af7a4488845415489ee65d9d3787a89f8961` | `src/spatial/apps/prototype-suite/core/features/events/EventCard.tsx` |
| OK | `0392dd2a920238d3179eaf76798eb7c4526c3fa8feab7043e163109ee36be92f` | `src/spatial/apps/prototype-suite/core/features/events/EventOperationsPage.tsx` |
| OK | `0b3213451966baccc2e22ba1d1e92a107d40ced1f0e5ae96e503e0aa4390a60b` | `src/spatial/apps/prototype-suite/core/features/events/EventOverviewPage.tsx` |
| OK | `037e6046f4f8346d5bb393a344c4a31b0f09e838f702852d658a696e8b28ce15` | `src/spatial/apps/prototype-suite/core/features/events/EventReportsPage.tsx` |
| OK | `2e2ebb8e7d07a48d563a97f478ddaf069613557b911b6a64f18d0d6d32f4854c` | `src/spatial/apps/prototype-suite/core/features/events/EventScoringPage.tsx` |
| OK | `7bbd2b56c0ea46ca333dadb2271e9f04ea07ba207ca38b7aef005fe7f3b6646d` | `src/spatial/apps/prototype-suite/core/features/events/EventsListPage.tsx` |
| OK | `03eaa0e0837e386457f13c4ca240f47c350199c92141a9a318aee43032519b83` | `src/spatial/apps/prototype-suite/core/features/events/EventTopologyPage.tsx` |
| OK | `d68a02e780ee1e1f98b8d513ecd8919019efbc15f2b08f8e7f572c68f3246320` | `src/spatial/apps/prototype-suite/core/features/events/NewEventWizardPage.tsx` |
| OK | `c04df5c07d2b923a5cd84ed5d588c44411f76ffd8bd8604cb33e77c778ce5a5d` | `src/spatial/apps/prototype-suite/core/features/events/PhaseTransitionPreview.tsx` |
| OK | `54973bc69188a9b76539a949cd228ada28ec6e4c3e78f71f5e058ab4aac14b08` | `src/spatial/apps/prototype-suite/core/features/events/TeamsAccessPage.tsx` |
| MODIFIED | `384ecb31b72b40e1c32c2380ab8327a1eeb2c035a79faa8d3d2456d75aadc315` | `src/spatial/apps/prototype-suite/core/features/infrastructure/InventoryPage.tsx` |
| OK | `0ea673503381fb714c365210642ab8326483fc5d4ba9481185acd4d0edbd3d8b` | `src/spatial/apps/prototype-suite/core/features/infrastructure/PlacementPage.tsx` |
| MODIFIED | `fa8b2b8574dd40e9e2adff675abf570f66b76a7cd029f21e4055fa62437bdfc6` | `src/spatial/apps/prototype-suite/core/features/infrastructure/ProvidersPage.tsx` |
| MODIFIED | `855c2c6b3d8d2661b158fb44f12a04bf6ef242e977b08763736584d38e4b5653` | `src/spatial/apps/prototype-suite/core/features/infrastructure/TargetsPage.tsx` |
| OK | `d13e777715b45576b5bb12ff8d2e6a64bccf461f4e7eb4c68f2bf5878c0a20cb` | `src/spatial/apps/prototype-suite/core/features/infrastructure/WorkersPage.tsx` |
| OK | `309ed08a5ec51a1afaf419d785e5bd4f866c5153e3baa20e54e3a4ff74c4d6f3` | `src/spatial/apps/prototype-suite/core/features/platform/AuditPage.tsx` |
| OK | `6a225d52e239c4f3919e03c87f0f1db4b73352be757afe63d7c52121cf010a37` | `src/spatial/apps/prototype-suite/core/features/platform/IdentityPage.tsx` |
| OK | `cf3c55727f10bad4682902f4465d79518fb42e7d52525641222139d55b97c8ea` | `src/spatial/apps/prototype-suite/core/features/platform/IntegrationsPage.tsx` |
| OK | `a66ef2188d08ee63e99885d26d9d87a057a29cd2bebbcf34655e1d7b14d3b058` | `src/spatial/apps/prototype-suite/core/features/platform/OrganizationsPage.tsx` |
| OK | `6f0eab7e2de20e718bbcb03bd7e7ac01d47f656d6ba6bc5c4fb77ac2c6def7b8` | `src/spatial/apps/prototype-suite/core/features/platform/PlatformOverviewPage.tsx` |
| OK | `9b24b3c4f7c980c08104465ec0ad87d603ef87de525d192be5733dd32b27f73a` | `src/spatial/apps/prototype-suite/core/features/platform/RetentionPage.tsx` |
| OK | `c4688bd84ec6e5f0f73225c244cd1e324f57adfb672630fcbe9ca445f5bfc57f` | `src/spatial/apps/prototype-suite/core/features/platform/SecretsPage.tsx` |
| OK | `5beb2aa688ce8842ed647c0c03c66a7c2759fcdb197d10668d9c0d87be426bb3` | `src/spatial/apps/prototype-suite/core/features/platform/SettingsPage.tsx` |
| OK | `e0a696964c0d19ee15131e732b8e0f5f2b23bc5ee72b916e2545801f0bd892a2` | `src/spatial/apps/prototype-suite/core/features/platform/WorkflowsPage.tsx` |
| OK | `731577e0fca2683f62b9f44c136ee0201375148611c1a22eebd7917c01d513df` | `src/spatial/apps/prototype-suite/core/features/reports/ReportsPage.tsx` |
| OK | `016530f1e38618e8b5ad0f3e7fed0bd2915cb9adefa341ff2795657e47a12e45` | `src/spatial/apps/prototype-suite/core/features/scenarios/NewScenarioPage.tsx` |
| OK | `68e1463718528459c06345b81f6732faa5582ee45e02aaa4df0dc8fdafbc771d` | `src/spatial/apps/prototype-suite/core/features/scenarios/ScenarioBuilderPage.tsx` |
| OK | `2d60124ea6d1cdf1c6395996d15f8fc43316dcf2805101be0824274f0e93718b` | `src/spatial/apps/prototype-suite/core/features/scenarios/ScenarioLibraryPage.tsx` |
| OK | `018e795b3c6ab37a7565c6943325056056066c5a5406ecce22ef72251e1b8aaf` | `src/spatial/apps/prototype-suite/core/features/scenarios/ScenarioOverviewPage.tsx` |
| OK | `81f3c24c23c7da2d2a42f606c4af575717851109b823d5f1f33128f295f0ea02` | `src/spatial/apps/prototype-suite/core/features/scenarios/ScenarioValidationPage.tsx` |
| OK | `ae24e2666d1a6ed3ff20db5580330d1d3136616215ea0f74602906da16591792` | `src/spatial/apps/prototype-suite/core/features/scenarios/ScenarioVersionsPage.tsx` |
| MODIFIED | `a4e2cdebc398c2f401e09e45a0b086c83dcf3c8ed89bffcc1b553715dbad3b42` | `src/spatial/apps/prototype-suite/core/integrations/adapter.ts` |
| MODIFIED | `16c4a86879b394b46f1a0772df18cda9a0a9b3307fd4844b1ec524cba3ae88e1` | `src/spatial/apps/prototype-suite/core/integrations/AdapterContext.tsx` |
| MODIFIED | `6ea9a12731dcd3067091c2a76cc73c6112b5d0190355cf71e616983757ff3e3a` | `src/spatial/apps/prototype-suite/core/integrations/mock-adapter.ts` |
| OK | `3a460e0b434671f6c6e0a0db62ff870d475a11f03681a3217bebf9bd7f55f30d` | `src/spatial/apps/prototype-suite/core/layouts/DeploymentWorkspaceLayout.tsx` |
| OK | `46748c8e1ddefda7ede8b03a36131160f58e6378e3beeb5bae2a64301deec3b0` | `src/spatial/apps/prototype-suite/core/layouts/EventWorkspaceLayout.tsx` |
| OK | `51e060af494ff440e5a5e5da10612f404d426d6c77cc22bb5bbb5754ebf4e6b8` | `src/spatial/apps/prototype-suite/core/layouts/ScenarioWorkspaceLayout.tsx` |
| OK | `07b2becf2fd34d99af734b210f995071ea5d7cde81426f122533d94797e2b7b2` | `src/spatial/apps/prototype-suite/core/layouts/SectionLayout.tsx` |
| OK | `0b93cf461086668246b64eb2a6dcc1d4dc6439708ec07467e914740a6bad16df` | `src/spatial/apps/prototype-suite/core/mocks/capabilities.ts` |
| OK | `0487bec811d46adc68f59cad3c439d94b406b53697d2473ebddd35a00c7d345f` | `src/spatial/apps/prototype-suite/core/mocks/deployments.ts` |
| OK | `93411f1122a09b1ba375f7c9a3cd55624f176290759c0583b64ee504d8a0e0e8` | `src/spatial/apps/prototype-suite/core/mocks/events.ts` |
| OK | `828b5f2660a1bafaf42181cd74b3538f0b4af42c3616c6c299ec92a565bbee1c` | `src/spatial/apps/prototype-suite/core/mocks/governance.ts` |
| OK | `88b9386969a7b183add5ff3dbe746b0a06e5a34e747c588d47d9da99a6826dbb` | `src/spatial/apps/prototype-suite/core/mocks/index.ts` |
| OK | `ead3cf68dd8b532f3c638b6ad76b3a80579671acde7dbc20f39adecc9ec8d5f4` | `src/spatial/apps/prototype-suite/core/mocks/infrastructure.ts` |
| OK | `3c7a0216b2ccd233437ce56c425da4263c41dd74c74b30ae45383a017190e8ef` | `src/spatial/apps/prototype-suite/core/mocks/operations.ts` |
| OK | `19650f96a3dbb31b1602196970d176c6652681e63cb227f8be69f413d767d390` | `src/spatial/apps/prototype-suite/core/mocks/scenarios.ts` |
| OK | `e81ee68a98974478035670e7eb28249a99acc3952979a9fbc94eaa0e94e43b83` | `src/spatial/apps/prototype-suite/core/mocks/topology.ts` |
| OK | `827fb6292c9da9659c4ee89a299ffba94f864b28f3eb7a00b8f0ea841b164244` | `src/spatial/apps/prototype-suite/core/models/types.ts` |
| OK | `e0f889d499ee58d701861eb58ebe8708d25bc032145c819f5bb526517441abad` | `src/spatial/apps/prototype-suite/core/PrototypeSuite.css` |
| OK | `4f75561efc8a7beded74217fdee6c653a48d0f8c9e1c675a9b3f83cea3392e13` | `src/spatial/apps/prototype-suite/PrototypeSuiteApp.tsx` |
| OK | `7d3076b465928cecdb1314b59f45a4a09b718c6932f14b284d2017c2f273b2cb` | `src/spatial/apps/reports/ReportsApp.tsx` |
| OK | `efe92415d9617bb3c21f5b05e7b0ef253e4aa355e797da985af507d7e59bc26c` | `src/spatial/apps/scenarios/ScenariosApp.tsx` |
| OK | `fd86cb5c027489dec4e403b284e7a7f1129efb64ca8b3773164569971d667d39` | `src/spatial/apps/settings/SettingsApp.css` |
| OK | `686ecbeee5e7e805eafede78f444dc9ce8cfecec194d7180dcd4d77749278ecc` | `src/spatial/apps/settings/SettingsApp.tsx` |
| OK | `881ffbcaafc212e49addad08846a5b82761355fa20624253af3477ba33262c5c` | `src/spatial/assets/hero.png` |
| OK | `35ef61ed53b323ae94a16a8ec659b3d0af3880698791133f23b084085ab1c2e5` | `src/spatial/assets/react.svg` |
| OK | `5be21acd42eb7b896e517f4e0f0f11eb5c5d9e54fbbcebe9453f033008fcca6f` | `src/spatial/assets/vite.svg` |
| NEW | `7dd4e0ebd3cb046f120c7380861865e30d053d2abba08045448fc2171664933d` | `src/spatial/authorization-boundary.test.ts` |
| OK | `eebea67b9dfcaa3ae582edaaffd49210fc6561359f662c18b7b1d445b01ba5cb` | `src/spatial/components/ai-core/AiCoreButton.css` |
| OK | `c3bb5384e727c2b4fd8f02e053d014d462b10197f93d16b782da3679acc4f3dd` | `src/spatial/components/ai-core/AiCoreButton.tsx` |
| OK | `61807efaad9ed6498a62312d5dba331f83e94bb15c1ead91fafe4ccd176f5fc5` | `src/spatial/components/ai-core/AiCoreOrb.css` |
| OK | `044aaaa91c65b772ba54aba01d2deb93c72a1713240dc69bbe2ec77a52b3cdd8` | `src/spatial/components/ai-core/AiCoreOrb.tsx` |
| OK | `b7bbe7d4ad29a1523613966599797bf589ce4352a2a3881d9ac4655cc3c40b35` | `src/spatial/components/ai-core/AiPromptBox.css` |
| OK | `ee7f94f87af4997962f0dea89909bfe02e1f3de1f92ecb9ef490144a959996c7` | `src/spatial/components/ai-core/AiPromptBox.tsx` |
| OK | `d0cfde12150ada7d881aebeedde5daf0351d784fb510baf0c4d1198a20ebdc58` | `src/spatial/components/ai-core/CommandMenuOverlay.tsx` |
| OK | `3d4eb6ec87414c940bffc2ffc8505bce660d9b414646fcb678c894b63ab30ee3` | `src/spatial/components/ai-core/GradientOrb.tsx` |
| OK | `cb16e756d01fc182a80d2c7846453cd501e2ea47c101db2eb266a1935f52445e` | `src/spatial/components/ai-core/index.ts` |
| OK | `31ea85f59ef0e55c8d510c75f4972abc9e6ea3a3caa7ecc36f6f1ab1e9d3fbe7` | `src/spatial/components/liquid-glass/index.ts` |
| OK | `0479e766eb5683076b15b6006038bf526959b7ce9d6399a7d7b8272b93fd511d` | `src/spatial/components/liquid-glass/LiquidGlass.css` |
| OK | `b3f1a94eb66e0f70124a8ebf715b77dba9f9f6c6d4884cdcc0d922996bb7dea1` | `src/spatial/components/liquid-glass/LiquidGlass.tsx` |
| OK | `3c29d49a2ce99993baaca6f1a0bd553c4d4451aa74d35e57e7034508279b8893` | `src/spatial/data/fixtures/capabilities.ts` |
| OK | `82f5700664bae57e1eecff3f6ec4a1c609ce9a87915fc61e5a36fd2a3341ff67` | `src/spatial/data/fixtures/infrastructure.ts` |
| OK | `469748013077225b301b3fccc501626b26754d46ddfa2ea41ff8bbfd38789d05` | `src/spatial/data/index.ts` |
| OK | `6f953b7fa6c30ec20b98a8fc176440e852e2b7e1ebcac08cea281487f7ce67c1` | `src/spatial/data/models/index.ts` |
| OK | `212e4610c1ab62012971a7170669e758697c2bd680200c8c495f2c902d58b3d6` | `src/spatial/data/models/infrastructure.ts` |
| OK | `3d6e0a837227d8b88a7872de84d5c0d7b91f430287b6f1dbf530232dd035f989` | `src/spatial/data/selectors/infrastructureSelectors.ts` |
| OK | `7bf3d3ad14b801dd9d8d0beb2a7a9d21e44fa5539bdb8f1b06b52d2e2c442df5` | `src/spatial/index.css` |
| NEW | `b12c8a2ad57601d4719ebf483cbf7e2d7bb69d83e4d3421491a83281d9a7df1c` | `src/spatial/integrations/provenance.css` |
| NEW | `be1378bb9b4588dfe3451fddc88ab2f700dc8a27e702247223821d0c1c37053d` | `src/spatial/integrations/provenance.render.test.tsx` |
| NEW | `a239c9c5f01120b73bd8cae7f3d1495d2d768fe10f846ae04fc6bd4255076969` | `src/spatial/integrations/provenance.tsx` |
| OK | `450162ddc542ec127d517cb584a5b7c5b0d6b62d1b4e0f6622fd25f0326bba1c` | `src/spatial/main.tsx` |
| NEW | `27fd1168b036f910d46bd040709af8d23139417cf8cb00d06dde7b1f37991f7d` | `src/spatial/migration-completeness.test.ts` |
| NEW | `13f51b7af38bb2e1fd27e0e26cf7819f6ceb4bfb4de54d1fa8b25a6a14498743` | `src/spatial/route-guard.test.ts` |
| OK | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `src/spatial/scene/components/.gitkeep` |
| OK | `813f5b1adcd4d8cabef240bb6e28191633672f1579005994d9e73470c0a49f5c` | `src/spatial/scene/components/CameraRig.tsx` |
| OK | `fa1ea1b78332ad02b9bf78ee0a76b8995917b582b2a073d55aa794bbc6656861` | `src/spatial/scene/components/DatacenterEnvironment.tsx` |
| OK | `3834621bf9888297b7c90115aa366597a5a115ce4d20742a9869d768677893d0` | `src/spatial/scene/components/ServerLane.tsx` |
| OK | `127e8d0538bd72950c813e3b529fb83d0354cafaa857bc09e713bb3fe2adccda` | `src/spatial/scene/components/ServerRack.tsx` |
| OK | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `src/spatial/scene/config/.gitkeep` |
| OK | `dc08842a88c4b535bbe4041863c76ccf95992a4b05701f5675f9bc8afdaafbb8` | `src/spatial/scene/config/scene.ts` |
| OK | `b831135796f7ee163e693acca185504960ca4f5e41cf5cdac69cbfc3bac69369` | `src/spatial/scene/containers/LocalContainerScene.css` |
| OK | `79933c9ebd6af892174809352105deda8ec28db82c0fe23e07b0a550fe57d7b7` | `src/spatial/scene/containers/LocalContainerScene.tsx` |
| OK | `43c95f8c20aec75669dac70bc7bd6fa202e64d569881dba163f4cdcada58d45e` | `src/spatial/scene/EnrollmentScene.tsx` |
| OK | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `src/spatial/scene/hooks/.gitkeep` |
| OK | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `src/spatial/scene/lib/.gitkeep` |
| NEW | `3948272b32b024b69a2db80fc02112b52675a92136c05008394bf064037774d9` | `src/spatial/scene/model-integrity.test.ts` |
| OK | `cdff56193ffef3c5e8e5db49a6b6e49ec46afdd8d3068e45051b1b241cb90ff7` | `src/spatial/scene/SceneIntroCompletionProbe.tsx` |
| OK | `31944a69443ecbece5b8ee4a1fd83c07e742db02e200d40e82f4f49b0be387de` | `src/spatial/scene/SceneReadyProbe.tsx` |
| NEW | `048eab361c36caafa44ea953f54bfaf8c0777498307dfe6c11506f1b7e196967` | `src/spatial/security-claims.test.ts` |
| OK | `2d13cc066648adf326d0a644f110f363347a341fa8bbe7bb0d8cdf17e0de00f3` | `src/spatial/shell/appRegistry.ts` |
| OK | `1a253a2a4801c44fdd16b706c047acef8a603637c2d12bb67a54f5f20b03417b` | `src/spatial/shell/DynamicIsland.css` |
| OK | `56c357810b0504f700ec55c54991c63895df841e0d4fa3474dc87eeeb04ac7fb` | `src/spatial/shell/DynamicIsland.tsx` |
| OK | `aa08e0f34b5c90e221502b805af6c3797b9b3fba19711b8b471e5af92c253c64` | `src/spatial/shell/global-search/SpatialGlobalSearch.css` |
| OK | `29951d751683a2618d804579ce1c9894351d0992912d86ae8ddbaecf95e63c17` | `src/spatial/shell/global-search/SpatialGlobalSearch.tsx` |
| OK | `838d0013067a6e948cf0417e11c97a87a7115a4f83a14839e970eec9998ce857` | `src/spatial/shell/HomeAppGrid.tsx` |
| OK | `1052a550c1b51d5a1b60de21dfb5dd92ded1e44ff1062574de3d7cf8ea11a0ee` | `src/spatial/shell/HomeAppIcon.tsx` |
| OK | `65f6e263e6a12e52024448977797ae38ea6dccbaceced12c1c91a1d734f95312` | `src/spatial/shell/SecpAppHost.tsx` |
| OK | `98f776caf4d55b37395794cff8c34ec43f30eb39e456cccabffebfc98fff5d36` | `src/spatial/shell/SecpGlyph.tsx` |
| OK | `8256fc5a5184ab5eb728b8a866725bc948b79d66621236c97557e5635b3861f4` | `src/spatial/shell/SecpHome.tsx` |
| OK | `2b71e1f75cef4b48c85a1fe6a687585ac49cb8d14b6a7608b4087a6e45cd1f65` | `src/spatial/shell/SecpShell.css` |
| OK | `86b9bed941d5bcfcc2344c82e53e690138e37f50b5cc49e5c1f9665a35ac6356` | `src/spatial/shell/SecpShell.tsx` |
| OK | `3729b5334676a902372ef9c0c14f9abc4ef34f8757ca5c440d80b47543f57fbd` | `src/spatial/shell/shellData.ts` |
| OK | `246bf4d00fe974db93a8475493212727d52a51f5643ec8fc422b7ff4bb13bdba` | `src/spatial/shell/shellTypes.ts` |
| OK | `b6b1c6f9d7a3b5059b18be7b6efdec9dcaadf3c13db6e16f3bf8dff3b1858fb7` | `src/spatial/shell/SystemDock.tsx` |
| OK | `498c62021e5c878822f6f19d2c4eb4e77c000249353f2c6bf162f1502572c593` | `src/spatial/shell/WidgetGrid.tsx` |
| OK | `c323cae42f4b228d2d057da0d890126dcf7cfafc7a1de862e0325d6cbe751af1` | `src/spatial/shell/widgets/AiSummaryWidget.tsx` |
| OK | `f905c0792709531f124d142e58020d0daeaef78b1d2b7fecaabef4238d882ad1` | `src/spatial/shell/widgets/DeploymentsWidget.tsx` |
| OK | `0b2f696b0b2e68ec7bf58abf1f9794756a61e4faadd744dc31cb899732a438a2` | `src/spatial/shell/widgets/DiscoveryWidget.tsx` |
| OK | `04dce8925a908cdcfe512e5418241867b00676b3c145fb3f65fe9fa3e2604da6` | `src/spatial/shell/widgets/EnvironmentHealthWidget.tsx` |
| NEW | `1147b1edbdd3bf7243e092a3b8388cc1acbaa1715391f88704952941aff90623` | `src/spatial/SpatialWorkspace.tsx` |
| OK | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `src/spatial/types/.gitkeep` |
| OK | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `src/spatial/ui/.gitkeep` |
| OK | `668dd1e44e02df1146dc324454093caaca7153865a390fa264b4e4332b98a1ae` | `public/models/server-rack.glb` |
| OK | `b45fa506195cfcdef406ba9f0c77b36ddc1a7c224040926ec70abc2fdea7b93a` | `public/icons.svg` |
| OK | `61bc9a161de58248288e6905425d7180f0624c2865007b97d763fdac12043a66` | `public/favicon.svg` |

Generated 2026-08-05 during SECP-P7-C.
