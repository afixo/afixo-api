# The session boundary

How a browser session works across `afixo-web`, `afixo-api` (this Worker) and
the gateway — and why it is built this way. This document is the canonical
description of the cookies and the CSRF rules; the gateway's REST surface and
the session JSON it answers are canonical in `afixo-services/docs/api.md`.

## Two surfaces, one Worker

`afixo-web` owns every public hostname and hands two surfaces to this Worker
over its `API` binding, always with the original URL. Which rules apply is
decided by `new URL(request.url).hostname`, before anything else:

| Hostname | Mode | Forwarded to | Who owns `Authorization` at the hop |
|---|---|---|---|
| anything not in `MACHINE_HOSTS` (`afixo.io`, `www.afixo.io`), `/api/v1/*` only | console | `${ORIGIN_URL}/v1/*` → tunnel → gateway `:8080` | the Worker: sealed cookie → bearer, plus the Access service token |
| `MACHINE_HOSTS` (`api.afixo.io`; staging `api-staging.afixo.io`) | machine | `${MACHINE_ORIGIN_URL}${path}` → tunnel → gateway `:8081` | the requester: its own bearer / Basic credentials pass through untouched, plus the Access service token |

Nothing public resolves to the tunnel (`origin.afixo.io`, `origin-api.afixo.io`
and their `-staging` twins are only reachable with the service token); this
Worker is the only way to either listener. `api.afixo.io` is a custom domain on
`afixo-web`, not a tunnel hostname, and is never an Access application — see
`docs/access.md`.

The rest of this document is console mode: the session. **Machine mode has no
session.** It is the product's API for requesters (OAuth2 client-credentials
clients) and deliberately inverts two rules: it passes the client's
`Authorization` through unchanged (the gateway validates it) and it never
touches a cookie — no reading, no setting, no CSRF, no Origin check. CORS headers on real
responses come from the gateway's machine listener (relayed); browser
preflights are answered by this Worker from `ALLOWED_ORIGINS`, because a
preflight carries no credentials and the Access-protected origin would refuse
it. Only five routes exist: `POST /oauth/token`, `GET /v1/disclose/*`,
`GET /v1/purposes`, `GET /v1/health`, and `OPTIONS` on any of those paths.
Everything else on a machine host — `/api/*` included, and the whole console
surface — is `404 {"error":"not_found"}` without touching any origin, and a
machine-host request never goes to `ORIGIN_URL`. What the two hops share:
hop-by-hop, `Cookie`, `X-CSRF-Token` and client `CF-Access-Client-*` headers
are stripped; the Access service token and `X-Request-Id` are added; redirects
are relayed, never followed; the body streams through; `Set-Cookie` never
comes back.

## The one rule

**The browser never holds a token.** The gateway keeps its existing auth
(`Authorization: Bearer <access>`, opaque 15-minute access tokens, 7-day refresh
tokens rotated on every use). This Worker translates between a sealed cookie and
that bearer, in both directions:

```
login     browser ──GET /api/v1/auth/github/callback?code&state──► afixo-api ──► origin
                                        afixo-api seals {access, refresh, exp} ◄──┘
          browser ◄── 302 /app + Set-Cookie ×3 ──────────────────┘

request   browser ──cookie──► afixo-api   opens the cookie, drops any client Authorization,
                                         injects its own `Bearer <access>` + the Access service token
                              afixo-api ──► origin
```

## The three cookies

| Cookie | Flags | Holds |
|---|---|---|
| `__Host-afixo_session` | `HttpOnly; Secure; SameSite=Strict; Path=/` | sealed JSON `{"a":access,"r":refresh,"e":access_exp_unix}` |
| `__Host-afixo_csrf` | `Secure; SameSite=Strict; Path=/` — readable | 32 random bytes, base64url |
| `__Host-afixo_state` | `Secure; SameSite=Lax; Path=/` — readable | base64url JSON `{"sub","handle","roles":["subject"],"exp":refresh_exp_unix}` |

All three are set together on login, re-set together on refresh, and cleared
together on logout or any failure. They share one lifetime: `Max-Age` runs out
when the refresh token does, because after that none of them is useful.

**`__Host-` is not decoration.** Browsers accept a `__Host-` cookie only when
it is `Secure`, has `Path=/` and carries no `Domain`. That makes it impossible
for a sibling hostname — `origin.afixo.io`, `api.afixo.io` — to set or
overwrite it. This architecture hands out sibling hostnames, so this matters.
It still works under `wrangler dev`: browsers treat `http://localhost` as a
secure context.

**The state cookie is cosmetic.** `afixo-web` reads it to decide whether to
render `/app/*` or bounce to `/login`, and which nav links to show. Nothing
authorises on it; the origin answers 401/403 regardless of what it claims. It
is deliberately not signed — a signature would imply a trust it does not carry.

## Sealing

`SESSION_KEY` is a Worker secret: 32 random bytes, base64url. The session
cookie is AES-256-GCM via `crypto.subtle`:

```
wire = base64url( 0x01 ‖ iv(12 random bytes) ‖ ciphertext ‖ tag(16) )     no padding
```

- The leading byte is a format version, checked before decryption. It is the
  one thing that can change without re-issuing every cookie (a version 0x02
  would be opened by its own code path; 0x01 cookies would keep working until
  they expire).
- `unseal()` answers `null` for every failure — bad base64url, wrong version,
  too short, wrong key, tampered bytes, unexpected plaintext shape. No caller,
  and therefore no client, learns which.
- A cookie that does not open is treated exactly like no cookie: the request is
  forwarded without `Authorization`, the origin answers 401, the browser tries
  a refresh (which also fails to open the cookie and clears everything), and
  the user is back at `/login`. No special case, no oracle.

**Why not KV.** The session store *is* the cookie. KV is eventually
consistent; the gateway rotates refresh tokens on every refresh and treats a
replay as theft (the whole token family is revoked). A stale KV read during a
rotation would present an already-spent token and destroy a healthy session. A
Durable Object would be correct and would cost money for nothing. The stateless
sealed cookie has neither problem, and the 4 KB cookie limit is nowhere near:
two opaque tokens seal to well under 300 bytes.

## No refresh at the edge

When the access token expires the origin answers 401 and this Worker **passes
it through untouched**. It never refreshes on the client's behalf, even though
it holds the refresh token and could.

Worker invocations cannot coordinate. Two concurrent requests that both hit an
expired access token would both refresh; the first rotation invalidates the
second's token, the origin's reuse detection fires, and the session dies. A
browser tab *can* single-flight — `afixo-web`'s client does: on 401 it issues
one `POST /api/v1/auth/refresh`, queues the rest, retries once, and on a second
401 sends the user to `/login`. The retry lives where a mutex can exist.

`POST /api/v1/auth/refresh` is the only place this Worker touches the refresh
token: open the cookie → `POST ${ORIGIN_URL}/v1/auth/refresh {"refresh_token"}`
→ seal the new pair → re-set session + state cookies (the csrf value is kept,
its `Max-Age` extended) → `204`. A 401 from the origin means the token is
spent or revoked: clear all three cookies and answer 401. Any other failure is
relayed with the cookies left alone — the access token may still be good.

## CSRF, in two layers

Cookies are ambient, so every non-`GET`/`HEAD`/`OPTIONS` request is checked
before routing:

1. **`Origin` must be in `ALLOWED_ORIGINS`.** Comma-separated, each entry a
   bare origin (`scheme://host[:port]`). A missing `Origin` is a rejection:
   `403 {"error":"forbidden_origin"}`. This layer covers the pre-session
   endpoints, so it is what actually blocks login-CSRF.
2. **With a session cookie present, `X-CSRF-Token` must equal
   `__Host-afixo_csrf`**, compared in constant time. Otherwise
   `403 {"error":"csrf"}`. `afixo-web`'s client reads the cookie and adds the
   header on every non-GET; same-origin requests never preflight, so the
   custom header costs nothing.

`SameSite=Strict` on the session and csrf cookies is the third layer. The
refresh and logout endpoints are POSTs and go through the same checks as
everything else. The state cookie alone is `Lax`: a login ends with GitHub
redirecting cross-site to the callback, and the `302 /app` that follows is part
of that cross-site navigation. Safari withholds Strict cookies for the whole
redirect chain, so with a Strict state cookie the `/app` gate bounced a freshly
signed-in user back to `/login` (Chromium is lenient here). The state cookie is
unsigned and cosmetic — nothing authorises on it — so Lax costs nothing.

## The endpoints

| Route | Behaviour |
|---|---|
| `GET /api/v1/auth/github/login` | plain pass-through; the origin's `302` to GitHub is relayed, not followed |
| `GET /api/v1/auth/github/callback?code&state` | forward; origin answers `{access_token, refresh_token, access_expires_at, refresh_expires_at, subject:{id,handle,…}, roles, redirect_to}`; seal → three cookies → `302` to `redirect_to` if it is a same-origin absolute path (`/app/…`), else `/app`. Any failure: cookies cleared, `302 /login?error=<code>` where `<code>` is the origin's `error` field if it is a clean snake_case code, else `upstream_<status>` / `bad_session` / `sealing_failed` |
| `POST /api/v1/auth/refresh` | see above |
| `POST /api/v1/auth/logout` | CSRF rules apply; forwarded with the bearer as a best effort; cookies always cleared → `204` |
| `* /api/v1/*` | translate + forward: `/api/v1/x` → `${ORIGIN_URL}/v1/x`; hop-by-hop, `Authorization`, `Cookie`, `X-CSRF-Token` and any client `CF-Access-Client-*` stripped; bearer + Access headers + `X-Request-Id` added; origin response relayed minus hop-by-hop and `Set-Cookie` |
| anything else | `404 {"error":"not_found"}` — only `afixo-web` calls this Worker, and only for `/api/v1/*`. A path under `/api/` but outside `/api/v1/` never reaches the origin |

Timestamps from the origin are accepted as unix seconds, unix milliseconds or
ISO-8601; they are stored as unix seconds.

## What the Worker never does

- Never logs a token, a cookie value or a secret. Error logs carry method,
  path, `X-Request-Id` and an error message, as one JSON line.
- Never trusts the state cookie for anything.
- Never follows a redirect from the origin (`redirect: "manual"`).
- Never attaches Access headers unless **both** `CF_ACCESS_CLIENT_ID` and
  `CF_ACCESS_CLIENT_SECRET` are non-empty (local dev has neither).
- Never has a public URL: `workers_dev: false`, `preview_urls: false`, no routes.
- Never passes a client `Authorization` to the console listener, and never
  rewrites the requester's on the machine hop.
- Never sends a machine-host request to the console listener, and never
  forwards `/api/*` from a machine host.

## What the other repos rely on

- `afixo-web` forwards `/api/*` — and every request on its `api.afixo.io`
  custom domain — with `env.API.fetch(request)`, passing the incoming `Request`
  through with its original URL: the hostname is how this Worker picks the
  mode, so `MACHINE_HOSTS` must list exactly what `afixo-web` forwards. An
  incoming Request has `redirect: "manual"`, which is what lets the Worker's
  own `302`s reach the browser. A hand-built `new Request(...)` without
  `redirect: "manual"` would follow them inside the binding instead.
- `afixo-web`'s client: same-origin `/api/v1/...`, `X-CSRF-Token` from the
  readable cookie on non-GET, single-flight refresh on 401, retry once.
- The gateway's console listener (`:8080`, reached as `origin.afixo.io`
  behind Cloudflare Access *Service Auth*) answers the session JSON above on
  callback and refresh, and `401` for a spent refresh token. Its machine
  listener (`:8081`, `origin-api.afixo.io`, same Access rule) validates
  requester bearers and client credentials itself and answers CORS for
  `https://afixo.io`, so the dashboard's API Explorer can call `api.afixo.io`
  exactly as an integrator would.
