# The OpenAPI contract

`openapi.json` is the control-plane API's contract. It is **exported from the live FastAPI
application**, never edited, and it is the single source of truth for every client.

```
apps/api/secp_api  --(scripts/export_openapi.py)-->  contracts/openapi/openapi.json
                   --(apps/web/scripts/generate-api-types.mjs)-->  apps/web/src/api/generated/openapi.ts
```

## Regenerating

Both steps, in order, after any change to a router or a response model:

```bash
python scripts/export_openapi.py
cd apps/web && npm run generate:api
```

Commit the document and the generated TypeScript together. They are two links of one chain and a
tree carrying one without the other is a tree whose contract disagrees with its client.

## The staleness gate

Each link has a `--check` mode that regenerates and compares **bytes**, and writes nothing:

| Link | Command | CI job / step |
| --- | --- | --- |
| app → document | `python scripts/export_openapi.py --check` | `backend-static` / *OpenAPI artifact is in step with the application* |
| document → TypeScript | `npm run generate:api:check` | `frontend` / *Generated API types are in step with the contract* |

Both fail red on any difference. A document that lags the code has cost this programme real time
more than once, so drift is a gate rather than something a reviewer might notice.

Byte-comparison only works because generation is deterministic: the exporter sorts keys at every
level (so re-ordering `include_router` calls moves nothing), pins the settings that reach the
document, and `openapi-typescript` is pinned to an exact version in `apps/web/package-lock.json`.
`tests/test_openapi_artifact.py` proves the export is reproducible under a deliberately hostile
environment.

## What is NOT in here

Seven Proxmox response members are declared `dict[str, Any]` in `secp_api.schemas_proxmox` because
the API copies them verbatim out of what a worker recorded — a Pydantic model over them would
silently drop keys the worker went to the trouble of writing. OpenAPI can only publish those as
open objects, so they arrive in TypeScript as `{ [key: string]: unknown }`.

They are narrowed at runtime by `apps/web/src/api/recorded.ts`, and the set of them is held to a
declared list by `test_the_opaque_members_are_exactly_the_declared_ones` — a NEW opaque member
fails CI, so leaving a field untyped is a decision somebody makes rather than something that
happens.
