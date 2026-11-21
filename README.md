# Lilauth

A small, server-rendered dashboard for lilboard and lilvault credentials. List
credentials and grants, mint a new agent on either or both configured backends,
and revoke agent credentials individually. Copy each new token from the result
page: Lilauth does not store generated tokens or show them in any later response.
Give each token to its intended agent securely; agents call the upstreams
directly. Lilauth is not an agent proxy. The UI uses the Tiny Club tokens
from lilboard's `@lilco/ui` in `src/style.css`, embedded with a CSP hash. It
remains dependency-free, server-rendered HTML; one CSP-hashed inline script
shows vault selectors for lilvault and submits their grants.

## Run locally

Use Node **24 LTS** (24.7 or later, preferably the latest patch). There are no npm
dependencies or install step. Generate a password hash locally; use a long,
unique password. With Bash and shell tracing off:

```bash
(
  umask 077
  mkdir -p secrets
  set -o noclobber
  IFS= read -rs -p 'Admin password: ' password
  printf '\n' >&2
  printf '%s' "$password" | node scripts/hash-password.mjs > secrets/admin-password.hash
)
```

The helper reads the exact password from stdin (12–1024 bytes, no trailing
newline) and writes only its PHC Argon2id hash. It won't overwrite an existing
file in the example above. The server expects the helper's profile: Argon2id
v19, 64 MiB, 3 passes, parallelism 1, a 16-byte salt and a 32-byte digest.
Keep the hash private. Do not configure a plaintext password.

Set the following before starting (showing lilboard alone; see below for
lilvault). Put each management token in its own private file, containing only
its 64 hex characters and an optional newline. These files are read at startup,
never written by Lilauth, and must be readable by the server user.

```bash
export LILCO_AUTH_MODE=local
export LILCO_ADMIN_USERNAME=operator
export LILCO_ADMIN_PASSWORD_HASH_FILE=./secrets/admin-password.hash
export LILCO_LILBOARD_ORIGIN=https://board.example
export LILCO_LILBOARD_MANAGEMENT_TOKEN_FILE=./secrets/lilboard.token
export LILCO_PUBLIC_ORIGIN=http://127.0.0.1:3000
export LILCO_INSECURE_LOOPBACK=1
npm start
```

Open `http://127.0.0.1:3000`. Plain HTTP cookies require the explicit loopback
exception above. It only works when the listener IP and port match the HTTP
loopback origin (`127.0.0.1` or `[::1]`). `LILCO_LISTEN_HOST` and `LILCO_PORT`
default to `127.0.0.1` and `3000`. Configure at least one upstream. Each requires
both its origin and token file; an origin is a canonical `http://` or `https://`
origin (no paths, queries, fragments, or embedded credentials). Configure distinct
management tokens if using both. Lilauth rejects invalid startup configuration
without contacting upstreams; list requests check upstream availability and
credentials after sign-in. Upstream requests do not follow redirects and have
five-second deadlines.

## Upstream management credentials

| Backend | Startup settings | What the dashboard actually needs |
| --- | --- | --- |
| lilboard | `LILCO_LILBOARD_ORIGIN`, `LILCO_LILBOARD_MANAGEMENT_TOKEN_FILE` | A real `kind=admin` actor token on the server runtime, for `GET`/`POST /api/auth/agents` and `DELETE /api/auth/agents/{name}`. The Cloudflare Worker runtime does not implement this surface. |
| lilvault | `LILCO_LILVAULT_ORIGIN`, `LILCO_LILVAULT_MANAGEMENT_TOKEN_FILE` | An agent token with the reserved `auth:manage` permission, for `GET`/`POST /v1/auth/agents`, `GET /v1/auth/vaults`, and `DELETE /v1/auth/agents/{name}`. Enable `[auth] keys_dir` upstream for mint and revoke. |

- **lilboard:** Bootstrap a dedicated admin per the lilboard README (for
  example, a `<name>.admin.token` in the upstream keys directory). The token can
  write to all boards and manage credentials, including minting admins. There
  is no narrower management-only or board-specific credential today. Dashboard
  mints are always `kind=agent`: they have all-board write access, not admin
  rights. Reads are open at lilboard. Person and admin actors are list-only here.
- **lilvault:** Provision a dedicated manager per lilvault's key-directory
  documentation. `auth:manage` alone does not grant access to vault contents,
  but it can mint credentials with data access to any configured vault, mint
  other managers, and revoke credentials. Do not grant the dashboard any
  additional vault access. The dashboard lists grantable vault IDs through
  the manager-only `/v1/auth/vaults` endpoint; for each, choose No access,
  Read, or Read-write. If that listing fails, lilvault minting is disabled in
  the UI. `auth:manage` cannot be minted here. Existing managers are list-only.

Copy only the dedicated management token file for each configured upstream to
Lilauth. Do not mount either upstream's credential directory, permissions, or
DB. Lilauth never changes operator-configured files and has no DB of its own.
The UI's restrictions do not make these upstream management tokens less
powerful if stolen. Use HTTPS to upstreams unless the connection is on a
private, trusted network; HTTP sends the bearer token in cleartext.

## TLS and optional container example

Run with `LILCO_PUBLIC_ORIGIN` set to the external HTTPS origin and leave
`LILCO_INSECURE_LOOPBACK` unset. Lilauth listens on HTTP behind a trusted TLS
terminator; only the proxy should reach that listener. Reserve a dedicated
hostname for Lilauth (for example, `lilauth.example.com`), with no other apps
on that hostname, even on other ports. Browser cookies are not scoped by
port. Pass the browser's `Origin` header through unchanged. Don't cache admin
responses or record passwords, cookies, token files, or request/response
bodies in proxy logs. The supplied Dockerfile runs unprivileged on Node 24 LTS.
`compose.example.yml` publishes the listener on host loopback for a local TLS
proxy, and mounts the three files individually and read-only; make each file
readable by the container's `node` user (UID 1000 in this image), not broadly
readable. Supply the non-secret Compose variables or remove a backend's two
environment entries and its mount. Inside the container, `localhost` means the
container itself, not another upstream service.

There is one environment-configured local admin, no signup or user database,
and no default credentials. Sessions are in memory, expire after eight hours,
support sign-out, and are capped at 32 (oldest evicted first). Cookies are
HttpOnly, SameSite=Strict and Secure outside explicit loopback mode. Form
mutations require an exact public origin and a session CSRF token. Login
verifications run one at a time and five failures in a minute throttle sign-in
globally, independent of peer IP and spoofable proxy headers. This limits
password guesses but can let a caller temporarily deny sign-in. Restrict access
to the dashboard to trusted operators.

## Lifecycle restrictions

**Run a single Lilauth replica as the exclusive writer of the configured
upstreams' credentials.** Do not mutate their credentials concurrently through
other dashboards, API/CLI tools, token files, or reload/reseed mechanisms. Use
out-of-band bootstrap or recovery only while Lilauth is stopped. Before each
change Lilauth freshly lists that backend's credentials, blocks overlapping
changes per backend, refuses to mint existing names, and only revokes confirmed
agent credentials. The upstream APIs are unconditional; these checks are not an
atomic upstream guarantee and cannot prevent races with external writers.

Minting on both backends is not atomic. The result shows each outcome and any
confirmed newly minted tokens. On an unknown write outcome (such as a timeout,
server failure, or malformed success), Lilauth pauses writes to that backend;
reads and the other backend remain available. There is no automatic retry.
An operator must confirm the outstanding operation has ended and reconcile the
upstream state before restarting Lilauth, which clears the in-memory pause.
A token can be lost if the upstream created it without returning it. Revoke the
orphaned credential after recovery and mint a new one. Revocation is immediate
on the selected backend.

**Deferred:** atomic lifecycle operations and rotation need upstream support.
Both POST endpoints replace existing names rather than offering create-only
or conditional replacement; lilvault updates the token and permissions files
separately. No rotation is offered. OIDC, multiple admins, and shared sessions
are also deferred.

## Checks

`npm test` runs socket-level tests with local fake upstreams, not live services.
