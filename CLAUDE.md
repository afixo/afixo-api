# afixo-api

## What this is

The session boundary of Afixo: a Cloudflare Worker (TypeScript, zero runtime dependencies, hand-written
router) between the public site `afixo-web` and the private Rust gateway. It has **no public route** — only
`afixo-web` reaches it, over a service binding — and runs in **two modes keyed by `new URL(request.url).hostname`**:

    console  browser ─/api/v1/*─► afixo-web ─API binding─► afixo-api ─► ${ORIGIN_URL}/v1/* ─► tunnel ─► gateway:8080
    machine  requester ─https://api.afixo.io/*─► afixo-web ─API binding, original URL─► afixo-api ─► ${MACHINE_ORIGIN_URL}/* ─► tunnel ─► gateway:8081

- **Console** (hostname ∉ `MACHINE_HOSTS`): the dashboard's `/api/v1/*`. Sealed cookie ↔ bearer, CSRF, Access
  headers. Everything below is about this mode unless it says otherwise.
- **Machine** (hostname ∈ `MACHINE_HOSTS`; `api.afixo.io`): the product's API for requesters. Allowlist only —
  `POST /oauth/token`, `GET /v1/disclose/*`, `GET /v1/purposes`, `GET /v1/health`, `OPTIONS` on those (CORS
  preflight, answered by this Worker from `ALLOWED_ORIGINS` — Access would reject a credential-less OPTIONS at the origin) — to `${MACHINE_ORIGIN_URL}${path}`, no prefix stripping; all else `404`.

## Hard rules (security invariants — never "simplify" these away)

- **The browser never holds a token.** Access + refresh tokens exist only inside `__Host-afixo_session`,
  AES-256-GCM sealed with the `SESSION_KEY` secret (`src/seal.ts`). `unseal()` returns null on any failure.
- **No refresh at the edge.** A 401 from the origin passes through untouched. Only `POST /api/v1/auth/refresh`
  refreshes, and the browser single-flights it. Worker invocations cannot coordinate; two concurrent refreshes
  trip the origin's reuse detection and kill the session.
- **No KV, no Durable Object for sessions.** The cookie is the store. KV is eventually consistent and would
  replay a rotated refresh token.
- **`__Host-` cookies only**: `Secure; Path=/`, no `Domain`, `SameSite=Strict` — except the cosmetic state cookie, which is `Lax` so the `302 /app` that continues GitHub's cross-site redirect still carries it in Safari (`docs/session.md`). Session cookie is `HttpOnly`;
  csrf and state cookies are readable. The state cookie is cosmetic — nothing authorises on it.
- **CSRF has two layers** on every non-GET/HEAD/OPTIONS, checked before routing (`src/index.ts`):
  (1) `Origin` ∈ `ALLOWED_ORIGINS`, missing ⇒ `403 forbidden_origin`; (2) with a session cookie,
  `X-CSRF-Token` must equal `__Host-afixo_csrf`, constant-time ⇒ else `403 csrf`.
- **No public URL**: `workers_dev: false`, `preview_urls: false`, no `routes`, staging has `"routes": []`.
  Do not add routes or a workers.dev URL. Anything outside `/api/v1/` answers 404.
- **Authorization ownership is per mode — never mix them.** Console mode never passes a client `Authorization`
  through: it strips it and injects the bearer from the sealed cookie. Machine mode passes the requester's own
  `Authorization` through unchanged and never reads, sets or clears a cookie, runs no Origin/CSRF check, and
  never goes to `ORIGIN_URL`; `/api/*` on a machine host is `404` (`src/handlers/machine.ts`).
- On both hops `Cookie`, `X-CSRF-Token`, client `CF-Access-Client-*` and hop-by-hop headers are stripped;
  `Set-Cookie` from the origin is stripped on the way back. Origin redirects are relayed, never followed.
- Access headers are attached only when **both** `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` are set.
- **Never log a token, a cookie value or a secret.** Logs are one JSON line: event, method, path,
  `X-Request-Id`, error message. Nothing else.

## Commands

```sh
pnpm install                      # node 24, pnpm 11 (packageManager field); lockfile is committed
pnpm dev                          # wrangler dev, reads .dev.vars
pnpm check                        # typecheck + test — run before handing work back
pnpm typecheck | pnpm test | pnpm test:watch   # tsc --noEmit (src + test); vitest inside workerd (vitest-pool-workers)
pnpm types                        # regenerate worker-configuration.d.ts from wrangler.jsonc; commit it (CI checks it)
pnpm wrangler deploy --dry-run --outdir dist --env=""   # bundle without credentials (what CI does)
pnpm run deploy | pnpm run deploy:staging               # `run` is required: `pnpm deploy` is pnpm's own command
pnpm secrets:push production|staging                    # scripts/push-secrets.sh
```

## Layout

```
src/index.ts          fetch entry: request id, mode split by hostname, /api/ gate, CSRF, dispatch — nothing else
src/router.ts         method + exact/prefix path → handler
src/env.ts            Env type re-export, parseAllowedOrigins(), parseMachineHosts()
src/seal.ts           seal()/unseal(): 0x01 ‖ iv(12) ‖ ct ‖ tag(16), base64url
src/cookies.ts        names, parse, Set-Cookie strings (incl. clearing), state cookie codec, csrf token
src/csrf.ts           isMutating(), originAllowed(), csrfValid() (constant-time)
src/origin.ts         forwardToOrigin() / forwardToMachineOrigin(), originFetch(), relay(): header policy per hop, Access headers
src/http.ts           json()/noContent()/redirect(), X-Request-Id
src/b64url.ts         base64url codec
src/handlers/auth.ts  githubCallback, refresh, logout
src/handlers/proxy.ts passthrough (bearer injection)
src/handlers/machine.ts  machine mode: route allowlist, 404, forward with the requester's Authorization
test/                 unit tests per module + worker.test.ts / machine.test.ts (integration via exports.default.fetch, mocked origin)
docs/session.md       the cookie / sealing / CSRF / refresh design and its reasons
docs/access.md        Cloudflare Access: service tokens, which hostnames are protected and which must not be
scripts/push-secrets.sh, .github/workflows/{ci,deploy}.yml, wrangler.jsonc, worker-configuration.d.ts (generated)
```

## Config & secrets

- **Vars** (in `wrangler.jsonc`, restated per environment): `ORIGIN_URL`, `ALLOWED_ORIGINS` (comma-separated
  bare origins), `MACHINE_HOSTS` (comma-separated hostnames), `MACHINE_ORIGIN_URL`. Production = top-level
  config; `env.staging` = `afixo-api-staging` (`api-staging.afixo.io` → `origin-api-staging.afixo.io`).
- **Secrets** (never in git): `SESSION_KEY` (32 random bytes, base64url), `CF_ACCESS_CLIENT_ID`,
  `CF_ACCESS_CLIENT_SECRET`. Declared in `wrangler.jsonc#secrets.required`, which is what `wrangler types`
  uses for `Env` and what makes `wrangler deploy` refuse to ship while one is missing.
- Local: `cp .dev.vars.example .dev.vars`, generate a key with
  `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`. Leave Access empty.
- Deployed: write `.secrets.<env>` (gitignored, `KEY=VALUE`), then `pnpm secrets:push <env>` — it validates the
  key length and pipes each value to `wrangler secret put` on stdin.
- CI/CD needs the GitHub secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
- Tests get their bindings from `vitest.config.ts` (`miniflare.bindings`), not from `.dev.vars`.

## Cross-repo pointers

- `afixo-web` binds to this Worker as `API` (`services: [{ binding: "API", service: "afixo-api" }]`, staging →
  `afixo-api-staging`) and forwards `/api/*` — and every request on its `api.afixo.io` custom domain — with
  `env.API.fetch(request)`: the incoming Request, original URL (the hostname picks our mode), and its
  `redirect: "manual"` is what lets our 302s reach the browser. Its client adds `X-CSRF-Token` on non-GET and
  single-flights `/api/v1/auth/refresh` on 401. Deploy this Worker before `afixo-web` the first time.
- `afixo-services` is the origin: the gateway's console listener (`:8080`, `origin.afixo.io`) and machine
  listener (`:8081`, `origin-api.afixo.io`), both through the tunnel behind Access *Service Auth* — nothing
  public resolves to the tunnel (`docs/access.md`). REST surface and session JSON shape:
  `afixo-services/docs/api.md` (canonical); cookies and CSRF: `docs/session.md` here (canonical).
- Product spec: FINAL_REPORT.md in the workspace root (`../FINAL_REPORT.md` when checked out beside the
  other repos). Edge pattern background: `../architecture.md`.

## Git rules

- **Never `git push`.** Remote is `git@github.com:afixo/afixo-api.git`; default branch `master`.
- **Always ask before `git commit`.** Leave changes in the working tree and report them.

## Verification (after any change to the edge)

```sh
curl -sI https://afixo.io/ | head -1                                                              # 1. site: 200
curl -s -o /dev/null -w '%{http_code}\n' https://afixo.io/api/v1/auth/me                         # 2. console path: 401 = gateway reached
for h in origin origin-api; do curl -s -o /dev/null -w "$h %{http_code}\n" https://$h.afixo.io/v1/health; done   # 3. tunnel hosts, no token: 403 403 is CORRECT
curl -s https://origin.afixo.io/v1/health -H "CF-Access-Client-Id: $ID" -H "CF-Access-Client-Secret: $SECRET"   # 4. with token: 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.afixo.io/oauth/token                # 5. machine path through the Worker: 400/401 from the gateway — never 404, never an Access page
curl -s -o /dev/null -w '%{http_code}\n' https://afixo-api.<account>.workers.dev/api/v1/health   # 6. this Worker is invisible: not 200
curl -sD - -o /dev/null 'https://afixo.io/api/v1/auth/github/callback?code=…&state=…' | grep -i 'location\|set-cookie'   # 7. seals: 302 /app, 3 __Host- cookies, 1 HttpOnly, no token
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://afixo.io/api/v1/auth/logout -H 'origin: https://evil.test'     # 8. foreign Origin: 403
```
