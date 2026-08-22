# afixo-api

## What this is

The session boundary of Afixo: a Cloudflare Worker (TypeScript, zero runtime dependencies, hand-written
router) between the public site `afixo-web` and the private Rust gateway. It turns the browser's sealed
cookie into a bearer token, enforces CSRF and presents the Cloudflare Access service token to the origin.
It has **no public route** — only `afixo-web` reaches it, through a service binding, and only for `/api/*`.

    browser ─/api/v1/*─► afixo-web ─service binding (API)─► afixo-api ─► https://origin.afixo.io/v1/* ─► tunnel ─► gateway:8080

## Hard rules (security invariants — never "simplify" these away)

- **The browser never holds a token.** Access + refresh tokens exist only inside `__Host-afixo_session`,
  AES-256-GCM sealed with the `SESSION_KEY` secret (`src/seal.ts`). `unseal()` returns null on any failure.
- **No refresh at the edge.** A 401 from the origin passes through untouched. Only `POST /api/v1/auth/refresh`
  refreshes, and the browser single-flights it. Worker invocations cannot coordinate; two concurrent refreshes
  trip the origin's reuse detection and kill the session.
- **No KV, no Durable Object for sessions.** The cookie is the store. KV is eventually consistent and would
  replay a rotated refresh token.
- **`__Host-` cookies only**: `Secure; Path=/`, no `Domain`, `SameSite=Strict`. Session cookie is `HttpOnly`;
  csrf and state cookies are readable. The state cookie is cosmetic — nothing authorises on it.
- **CSRF has two layers** on every non-GET/HEAD/OPTIONS, checked before routing (`src/index.ts`):
  (1) `Origin` ∈ `ALLOWED_ORIGINS`, missing ⇒ `403 forbidden_origin`; (2) with a session cookie,
  `X-CSRF-Token` must equal `__Host-afixo_csrf`, constant-time ⇒ else `403 csrf`.
- **No public URL**: `workers_dev: false`, `preview_urls: false`, no `routes`, staging has `"routes": []`.
  Do not add routes or a workers.dev URL. Anything outside `/api/v1/` answers 404.
- Client `Authorization`, `Cookie`, `X-CSRF-Token` and `CF-Access-Client-*` are stripped before the origin
  hop; `Set-Cookie` from the origin is stripped on the way back. Origin redirects are relayed, never followed.
- Access headers are attached only when **both** `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` are set.
- **Never log a token, a cookie value or a secret.** Logs are one JSON line: event, method, path,
  `X-Request-Id`, error message. Nothing else.

## Commands

```sh
pnpm install                      # node 24, pnpm 11 (packageManager field); lockfile is committed
pnpm dev                          # wrangler dev, reads .dev.vars
pnpm check                        # typecheck + test — run before handing work back
pnpm typecheck                    # tsc --noEmit (src + test)
pnpm test | pnpm test:watch       # vitest inside workerd (@cloudflare/vitest-pool-workers)
pnpm types                        # regenerate worker-configuration.d.ts from wrangler.jsonc; commit it (CI checks it)
pnpm wrangler deploy --dry-run --outdir dist --env=""   # bundle without credentials (what CI does)
pnpm run deploy | pnpm run deploy:staging               # `run` is required: `pnpm deploy` is pnpm's own command
pnpm secrets:push production|staging                    # scripts/push-secrets.sh
```

## Layout

```
src/index.ts          fetch entry: request id, /api/ gate, CSRF, dispatch — nothing else
src/router.ts         method + exact/prefix path → handler
src/env.ts            Env type re-export, parseAllowedOrigins()
src/seal.ts           seal()/unseal(): 0x01 ‖ iv(12) ‖ ct ‖ tag(16), base64url
src/cookies.ts        names, parse, Set-Cookie strings (incl. clearing), state cookie codec, csrf token
src/csrf.ts           isMutating(), originAllowed(), csrfValid() (constant-time)
src/origin.ts         forwardToOrigin(), originFetch(), relay(): path rewrite, header policy, Access headers
src/http.ts           json()/noContent()/redirect(), X-Request-Id
src/b64url.ts         base64url codec
src/handlers/auth.ts  githubCallback, refresh, logout
src/handlers/proxy.ts passthrough (bearer injection)
test/                 unit tests per module + worker.test.ts (integration via exports.default.fetch, mocked origin)
docs/session.md       the cookie / sealing / CSRF / refresh design and its reasons
scripts/push-secrets.sh, .github/workflows/{ci,deploy}.yml, wrangler.jsonc, worker-configuration.d.ts (generated)
```

## Config & secrets

- **Vars** (in `wrangler.jsonc`, restated per environment): `ORIGIN_URL`, `ALLOWED_ORIGINS` (comma-separated
  bare origins). Production = top-level config; `env.staging` = `afixo-api-staging`.
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
  `afixo-api-staging`) and forwards `/api/*` with `env.API.fetch(request)` — the incoming Request, whose
  `redirect: "manual"` is what lets our 302s reach the browser. Its client adds `X-CSRF-Token` on non-GET and
  single-flights `/api/v1/auth/refresh` on 401. Deploy this Worker before `afixo-web` the first time.
- `afixo-services` is the origin: the gateway's console listener (`:8080`) reached as `origin.afixo.io`
  through the tunnel, behind Access *Service Auth*. REST surface and session JSON shape:
  `afixo-services/docs/api.md` (canonical); cookies and CSRF: `docs/session.md` here (canonical).
- Product spec: FINAL_REPORT.md in the workspace root (`../FINAL_REPORT.md` when checked out beside the
  other repos). Edge pattern background: `../architecture.md`.

## Git rules

- **Never `git push`.** Remote is `git@github.com:afixo/afixo-api.git`; default branch `master`.
- **Always ask before `git commit`.** Leave changes in the working tree and report them.

## Verification (after any change to the edge)

```sh
curl -sI https://afixo.io/ | head -1                                                              # 1. site: 200
curl -s -o /dev/null -w '%{http_code}\n' https://afixo.io/api/v1/auth/me                         # 2. API path: 401 = origin reached
curl -s -o /dev/null -w '%{http_code}\n' https://origin.afixo.io/v1/health                       # 3. origin, no token: 403 is CORRECT
curl -s https://origin.afixo.io/v1/health -H "CF-Access-Client-Id: $ID" -H "CF-Access-Client-Secret: $SECRET"   # 4. with token: 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.afixo.io/oauth/token                # 5. machine listener open: 400/401, not an Access page
curl -s -o /dev/null -w '%{http_code}\n' https://afixo-api.<account>.workers.dev/api/v1/health   # 6. this Worker is invisible: not 200
curl -sD - -o /dev/null 'https://afixo.io/api/v1/auth/github/callback?code=…&state=…' | grep -i 'location\|set-cookie'   # 7. seals: 302 /app, 3 __Host- cookies, 1 HttpOnly, no token
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://afixo.io/api/v1/auth/logout -H 'origin: https://evil.test'     # 8. foreign Origin: 403
```
