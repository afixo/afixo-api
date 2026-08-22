# afixo-api

The session boundary of [Afixo](../FINAL_REPORT.md): a Cloudflare Worker that
sits between the public site (`afixo-web`, which reaches it through a service
binding) and the private Rust gateway (`afixo-services`, reached through a
Cloudflare Tunnel behind Access). No public URL, no framework, zero runtime
dependencies. Nothing public resolves to the tunnel; this Worker is the only
way in, and it runs in two modes keyed by the request's hostname:

```
console  browser ─/api/v1/*─► afixo-web ─API binding─► afixo-api ─► https://origin.afixo.io/v1/* ─► tunnel ─► gateway:8080
machine  requester ─https://api.afixo.io/*─► afixo-web ─API binding, original URL─► afixo-api ─► https://origin-api.afixo.io/* ─► tunnel ─► gateway:8081
```

- **Console** — the dashboard's `/api/v1/*`: turns a sealed `__Host-` cookie
  into a bearer token, enforces CSRF, presents the Access service token,
  relays everything else.
- **Machine** — `api.afixo.io` (a custom domain on `afixo-web`, handed over
  with the original URL): the product's API for requesters. Five routes
  (`POST /oauth/token`, `GET /v1/disclose/*`, `GET /v1/purposes`,
  `GET /v1/health`, `OPTIONS` on those), the requester's own `Authorization`
  passed through untouched, no cookies, no CSRF, everything else `404`.

The design — cookies, sealing, CSRF, why there is no refresh at the edge and
no KV, and the machine mode — is in [docs/session.md](docs/session.md); which
hostnames sit behind Cloudflare Access and which must not is in
[docs/access.md](docs/access.md). Operational rules for anyone (human or
agent) editing this repo are in [CLAUDE.md](CLAUDE.md).

## Run locally

```sh
pnpm install
cp .dev.vars.example .dev.vars      # fill SESSION_KEY (32 random bytes, base64url); Access secrets stay empty
pnpm dev                            # wrangler dev on http://localhost:8787, console origin = http://localhost:8080
```

`pnpm dev` alone only answers `/api/*`. The full local front door is
`afixo-web`'s `wrangler dev`, which binds its `API` service to this Worker.
Locally the dashboard's API Explorer calls the gateway's machine listener
(`:8081`) directly, so machine mode is exercised by the tests rather than by
`wrangler dev` (`MACHINE_HOSTS=api.localhost` is there to keep the types stable).

## Check

```sh
pnpm check          # typecheck + tests (vitest, inside workerd)
pnpm test:watch
pnpm types          # regenerate worker-configuration.d.ts after editing wrangler.jsonc — commit it
```

## Configure & deploy

Vars live in `wrangler.jsonc`, restated per environment:

| Var | production | staging |
|---|---|---|
| `ORIGIN_URL` (console listener) | `https://origin.afixo.io` | `https://origin-staging.afixo.io` |
| `ALLOWED_ORIGINS` | `https://afixo.io,https://www.afixo.io` | `https://staging.afixo.io` |
| `MACHINE_HOSTS` | `api.afixo.io` | `api-staging.afixo.io` |
| `MACHINE_ORIGIN_URL` (machine listener) | `https://origin-api.afixo.io` | `https://origin-api-staging.afixo.io` |

Secrets (`SESSION_KEY`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`) are
declared in `wrangler.jsonc#secrets.required` and pushed once per environment:

```sh
pnpm secrets:push staging           # reads .secrets.staging (gitignored), validates, `wrangler secret put`
pnpm secrets:push production
pnpm run deploy:staging             # `afixo-api-staging`, --env staging
pnpm run deploy                     # production (top-level wrangler environment)
```

`pnpm run deploy`, not `pnpm deploy` — the latter is pnpm's own command.
CI (`.github/workflows/ci.yml`) typechecks, tests and dry-run-deploys every PR
and push to `master`. `deploy.yml` deploys **staging on every push to
`master`**; production is a deliberate promotion — *Run workflow* and pick
`production`, which uses the `production` GitHub environment (put a required
reviewer on it). Both need the `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID` secrets. Deploy this Worker **before** `afixo-web`
the first time: the service binding needs a target.

## Verify a deployment

```sh
# 1. the site itself (Cloudflare only, never touches the cluster)
curl -sI https://afixo.io/ | head -1                                                              # 200
# 2. the console path end to end — 401 means the gateway was reached through this Worker
curl -s -o /dev/null -w '%{http_code}\n' https://afixo.io/api/v1/auth/me                         # 401
# 3. the tunnel hostnames without a service token — "403 403" is the CORRECT answer
for h in origin origin-api; do curl -s -o /dev/null -w "$h %{http_code}\n" https://$h.afixo.io/v1/health; done
# 4. the origin with the token
curl -s https://origin.afixo.io/v1/health -H "CF-Access-Client-Id: $ID" -H "CF-Access-Client-Secret: $SECRET"   # 200
# 5. the machine path end to end — an OAuth error from the gateway is right; never 404, never an Access page
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.afixo.io/oauth/token                # 400/401
# 6. this Worker has no public URL
curl -s -o /dev/null -w '%{http_code}\n' https://afixo-api.<account>.workers.dev/api/v1/health   # not 200
# 7. the session actually seals — a 302 to /app, three __Host- cookies, exactly one HttpOnly, no token anywhere
curl -sD - -o /dev/null 'https://afixo.io/api/v1/auth/github/callback?code=…&state=…' | grep -i 'location\|set-cookie'
# 8. a foreign Origin cannot write
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://afixo.io/api/v1/auth/logout -H 'origin: https://evil.test'   # 403
```

| Symptom | Fault |
|---|---|
| 2 gives 502/530 | tunnel down, or `ORIGIN_URL` / Access token wrong |
| 3 gives 200 | Access is not enforcing — the policy action must be *Service Auth* |
| 4 gives 403 | the Worker's service token is stale, or the policy names a different one |
| 5 gives 404 | `MACHINE_HOSTS` does not list the hostname `afixo-web` forwards, or `afixo-web` rewrote the URL |
| 5 gives 502 | `MACHINE_ORIGIN_URL` wrong, or its Access application does not include the Worker's token |
| 5 gives an Access page | `api.afixo.io` must never be an Access application |
| every write gives 403 | `ALLOWED_ORIGINS`, or the client is not sending `X-CSRF-Token` |
