# afixo-api

The session boundary of [Afixo](../FINAL_REPORT.md): a Cloudflare Worker that
sits between the public site (`afixo-web`, which reaches it through a service
binding) and the private Rust gateway (`afixo-services`, reached through a
Cloudflare Tunnel behind Access). It turns a sealed `__Host-` cookie into a
bearer token, enforces CSRF, presents the Access service token, and relays
everything else. No public URL, no framework, zero runtime dependencies.

```
browser ─/api/v1/*─► afixo-web ─service binding─► afixo-api ─► https://origin.afixo.io/v1/* ─► tunnel ─► gateway:8080
```

The design — cookies, sealing, CSRF, why there is no refresh at the edge and
no KV — is in [docs/session.md](docs/session.md). Operational rules for
anyone (human or agent) editing this repo are in [CLAUDE.md](CLAUDE.md).

## Run locally

```sh
pnpm install
cp .dev.vars.example .dev.vars      # fill SESSION_KEY (32 random bytes, base64url); Access secrets stay empty
pnpm dev                            # wrangler dev on http://localhost:8787, origin = http://localhost:8080
```

`pnpm dev` alone only answers `/api/*`. The full local front door is
`afixo-web`'s `wrangler dev`, which binds its `API` service to this Worker.

## Check

```sh
pnpm check          # typecheck + tests (vitest, inside workerd)
pnpm test:watch
pnpm types          # regenerate worker-configuration.d.ts after editing wrangler.jsonc — commit it
```

## Deploy

```sh
pnpm secrets:push production        # once: reads .secrets.production (gitignored), validates, `wrangler secret put`
pnpm run deploy                     # production (top-level wrangler environment)
pnpm run deploy:staging             # `afixo-api-staging`, --env staging
```

`pnpm run deploy`, not `pnpm deploy` — the latter is pnpm's own command.
CI (`.github/workflows/ci.yml`) typechecks, tests and dry-run-deploys every PR
and push to `master`; `deploy.yml` deploys `master` to production and, via
*Run workflow*, to staging. It needs the `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID` repository secrets. Deploy this Worker **before**
`afixo-web` the first time: the service binding needs a target.

## Verify a deployment

```sh
# 1. the site itself (Cloudflare only, never touches the cluster)
curl -sI https://afixo.io/ | head -1                                                              # 200
# 2. the API path end to end — 401 means the origin was reached through this Worker
curl -s -o /dev/null -w '%{http_code}\n' https://afixo.io/api/v1/auth/me                         # 401
# 3. the origin without a service token — 403 is the CORRECT answer
curl -s -o /dev/null -w '%{http_code}\n' https://origin.afixo.io/v1/health                       # 403
# 4. the origin with the token
curl -s https://origin.afixo.io/v1/health -H "CF-Access-Client-Id: $ID" -H "CF-Access-Client-Secret: $SECRET"   # 200
# 5. the machine listener stays open (no Access page; an OAuth error from the gateway is right)
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
| every write gives 403 | `ALLOWED_ORIGINS`, or the client is not sending `X-CSRF-Token` |
