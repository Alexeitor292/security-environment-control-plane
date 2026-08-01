# `secp-cli` — the operator CLI's identity-provider client

`secpctl auth login` (ADR-028 §3) obtains an operator access token with the OAuth 2.0 Device
Authorization Grant (RFC 8628). That requires exactly one **public** client on the reviewed OIDC
issuer, with the client id `secp-cli`.

This directory holds that client **as code**. Nothing about it is a click-path, and nothing about it
varies per deployment.

| File | What it is |
| --- | --- |
| `secp-cli-client.json` | The Keycloak `ClientRepresentation`. The single source of truth. |
| `test-realm-skeleton.json` | The disposable realm the integration test imports the artifact into. |
| `../dev/keycloak/realm-secp.json` | The development realm, which **embeds this artifact verbatim**. |
| `../../scripts/keycloak/secp_cli_client.py` | `plan` / `apply` / `verify`, idempotent, stdlib only. |

The artifact carries **no hostname, no origin, no redirect URI and no secret** — the device grant has
no browser redirect, so there is nothing in it to vary. The same bytes deploy to development, to the
disposable test realm, and to production. `tests/test_keycloak_secp_cli_deployment.py` fails if the
development realm's copy ever diverges from it, and if a URL ever appears inside it.

## Deploying it

```sh
# 1. Offline: exactly what would be deployed. Opens no socket.
python scripts/keycloak/secp_cli_client.py plan

# 2. Dry run against a real realm. Reads only; reports every change it would make.
export SECP_KEYCLOAK_ADMIN=... SECP_KEYCLOAK_ADMIN_PASSWORD=...
python scripts/keycloak/secp_cli_client.py apply \
    --base-url https://idp.example.com --realm secp

# 3. Apply. Requires BOTH flags.
python scripts/keycloak/secp_cli_client.py apply \
    --base-url https://idp.example.com --realm secp --write --confirm

# 4. Verify — the client, the RFC 8414 discovery document, and the RFC 7009 revocation endpoint.
python scripts/keycloak/secp_cli_client.py verify \
    --base-url https://idp.example.com --realm secp
```

`apply` is a dry run unless both `--write` and `--confirm` are given, and a plaintext `http://` base
URL is refused unless `--insecure-http` is passed (it exists for a disposable containerised realm).
The administrator credential is read from the environment only; there is deliberately no
`--password` flag, so it cannot land in a shell history or a process listing. Nothing prints the
password, the admin token, or a client secret.

Running `apply --write --confirm` twice is expected: the second run reports an **empty action list**
and issues zero mutating requests. That is how you can tell "already correct" from "just corrected".

## Why a reconciler and not a `PUT`

Keycloak's Admin REST API **ignores** three fields on a client *update*, and they are the three that
carry this client's security posture:

* `defaultClientScopes` and `optionalClientScopes` — assigned through dedicated sub-resources;
* `protocolMappers` — likewise.

So re-`PUT`ing the representation onto a client that was first created through the admin console
changes nothing at all: the `roles` scope the console attached stays attached forever, and the
audience mapper never appears. The reconciler drives those sub-resources directly and reconciles
each to an **exact set** — a scope or mapper that is present and not desired is *removed*, not left
alone.

## The setting that is easy to lose and expensive to lose

The `roles` client scope must **not** be attached. This is a size requirement, not a policy one, and
it is easy to miss because everything works until it does not:

* `roles` adds `realm_access` / `resource_access` claims;
* on a deployment with many roles the issued access token grows past what an OS keystore record
  holds — `CRED_MAX_CREDENTIAL_BLOB_SIZE` is 2560 bytes on Windows, and `secpctl` applies that bound
  on *every* platform so a credential that stores on one workstation stores on all of them;
* the grant then **completes**, the token **verifies**, and `secpctl auth login` refuses with
  `secpctl_credential_too_large` — *after* the operator has already approved interactively, which is
  the worst possible place to fail.

`fullScopeAllowed: false` is the second, independent control on the same failure: it stops the
client's own role scope-mappings from inflating the token even if `roles` were reattached. Keycloak's
own default for it is `true`.

`secpctl` needs no role claims. The database is the sole authority for organization, role and
permission, and a token claim never determines them.

Measured against a real Keycloak 25 realm whose operator carries 48 realm roles:

| Posture | access token | keystore record | 2560-byte bound |
| --- | --- | --- | --- |
| this artifact | 1133 B | 1226 B | fits, with headroom |
| Keycloak console defaults (`roles` + `fullScopeAllowed`) | 3023 B | 3116 B | **refused** |

The artifact's token size does not move when the role count changes; the console-default one does.

## Proving it, for real

`apps/management/tests/test_keycloak_device_flow_integration.py` creates a throwaway Keycloak
container, imports this artifact into it, and drives a genuine device grant — including the operator
approving through the provider's own sign-in and confirmation pages — then destroys the container.
It also runs the *console-default* posture through the same flow and asserts it refuses with
`secpctl_credential_too_large` after the approval, so the control is demonstrated to be load-bearing
rather than asserted to be.

```sh
SECP_TEST_KEYCLOAK_DEVICE_FLOW=1 pytest \
    apps/management/tests/test_keycloak_device_flow_integration.py
```

It needs Docker and takes a couple of minutes. CI runs it as `backend-keycloak-device-flow`, which
additionally refuses a skipped or under-collected result.

## Development

The dev stack already ships it: `infra/dev/docker-compose.yml` mounts
`infra/dev/keycloak/realm-secp.json`, whose `secp-cli` entry is this artifact verbatim.

```sh
cd infra/dev && docker compose up -d keycloak
python ../../scripts/keycloak/secp_cli_client.py verify \
    --base-url http://localhost:8081 --realm secp --insecure-http
```
