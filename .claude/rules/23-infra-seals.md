---
paths:
  - "infra/**"
  - "**/docker-compose*.yml"
  - "**/Dockerfile"
  - ".env.example"
---

# Infrastructure artefacts and seals

## Hard-deny

- `infra/ci/**` — the trusted-ancestry attestation is a security control (see `21-tests-ci.md`).
- Any OpenTofu/Terraform `apply` or `destroy`.
- Any real endpoint, credential, hostname or public IP in an authored file
  (`tests/test_no_real_endpoints.py`).

## What infra/ actually is

`infra/` is small (15 tracked files) and is **not** where production capability lives:

- `infra/dev` — a genuine 8-service local stack (postgres, minio, keycloak, temporal,
  temporal-ui, api, worker, web) plus four override files selecting fake/mock/controlled-live
  profiles.
- `infra/production` — **placeholder only**: a README and `oidc.env.example`. It deploys nothing:
  no Compose or Kubernetes manifest, no production web build, no TLS or ingress artefact. The
  name is misleading.
- `infra/ci` — the trusted-ancestry attestation script.

The real production deployment machinery is importable Python in `apps/management` and
`apps/deployment/secp_discovery_activation`, not YAML in `infra/`.

## The dev stack is a singleton

One fixed Compose project name and fixed host ports (5432 / 7233 / 5173). **At most one agent may
run it at a time**, and a git worktree does not partition it. A fresh worktree also has no `.env`
and no `.venv` (both gitignored), while the dev Compose interpolates ~15 bare `${VAR}` references.

## Enforced properties

- The dev Compose stack may contain only development-safe services
  (`tests/test_compose_config.py:19-75`).
- `.env.example` carries only placeholder secrets; `.env` is gitignored and must never be read,
  quoted or committed.
- Never widen a Compose file to mount host paths, add privileged containers, or expose an
  environment workload to a management, corporate or public network. Charter Invariant 17:
  environment workloads must not reach those networks by default. For a platform whose payload is
  deliberately vulnerable systems and offensive tooling, this is the containment boundary — treat
  any change that could breach it as an architecture escalation, not a config tweak.
