# Cloudflare Access setup (dashboard)

How the Access-protected hostnames in front of the gateway are configured, and the service
token this Worker presents on both of its hops. Written against the Cloudflare One dashboard
as of 2026-08-22 — the nav moved recently, older docs still say *Access › Service Auth*.

Everything below happens at **one.dash.cloudflare.com** (or dash.cloudflare.com → Zero Trust).

## What is being protected, and what is not

| Hostname | What it is | Access app? | Why |
|---|---|---|---|
| `origin.afixo.io` → tunnel → `gateway:8080` | console listener | **Yes** — Service Auth only | Only `afixo-api` may reach it, with a service token. No human login path at all. |
| `origin-api.afixo.io` → tunnel → `gateway:8081` | machine listener | **Yes** — Service Auth only | Same token, same rule. The gateway checks the requester's bearer, but only `afixo-api` may carry it there. |
| `api.afixo.io` → `afixo-web` → `afixo-api` (machine mode) | the public machine API | **No** | A **Worker custom domain, not a tunnel hostname**. Third parties authenticate with bearers at the gateway; an Access app here would break every API client. |
| `afixo.io`, `www.afixo.io` → `afixo-web` | the public site | **No** | |
| `staging.afixo.io` → `afixo-web-staging` | pre-production dashboard | **Yes** — Allow, email-gated | A real hostname serving a pre-production dashboard. Should not be world-readable. |
| `api-staging.afixo.io` → `afixo-web-staging` → `afixo-api-staging` | staging machine API | **No** | Same as `api.afixo.io`. |
| `origin-staging.afixo.io`, `origin-api-staging.afixo.io` → staging tunnel | staging listeners | **Yes** — Service Auth only | Same as production, with the staging token. |

Nothing public resolves to the tunnel: the four `origin*` hostnames are the tunnel's only
ingress rules, every one of them sits behind a Service Auth policy, and every public hostname
is a Worker custom domain.

Access is **deny by default**: an application with zero policies rejects every request.
That is the desired end state for `origin.afixo.io` — a Service Auth policy and nothing else
means there is no identity provider path, so no person can log in even by accident.

## 1. Create the service tokens

Two tokens, one per environment. Never share one across environments — revoking a
compromised staging token must not take production down with it.

1. **Zero Trust › Access controls › Service credentials › Service Tokens**.
2. **Create Service Token**.
3. Name it `afixo-api-production`. The name is what appears in the Access logs and is the unit
   of revocation, so make it identify the caller, not the callee.
4. **Service Token Duration** — `1 year` is the sensible default. Non-expiring exists; prefer
   not to. Whatever you pick, put the expiry date in a calendar: an expired token is a silent
   total outage of every logged-in page, surfacing as `403` from the origin hop.
5. **Generate token**. Copy both values now — **the Client Secret is displayed exactly once**.
   - Client ID looks like `88bf3b6d86161464f6509f7219099e57.access`
   - Client Secret is 64 hex characters
6. Paste them into `.secrets.production` (gitignored):
   ```
   CF_ACCESS_CLIENT_ID=88bf3b6d86161464f6509f7219099e57.access
   CF_ACCESS_CLIENT_SECRET=<64 hex chars>
   ```
7. Repeat as `afixo-api-staging` → `.secrets.staging`.

Then push them to the Workers:

```sh
pnpm secrets:push production
pnpm secrets:push staging
```

> `src/origin.ts` attaches the `CF-Access-Client-*` headers only when **both** values are
> non-empty. One filled and one left as `REPLACE_ME` does not half-work — it silently sends no
> Access headers at all and the origin answers 403.

## 2. Protect `origin.afixo.io` and `origin-api.afixo.io` with a Service Auth policy

The tunnel public hostname must already exist and resolve before Access can sit in front of it.

1. **Zero Trust › Access controls › Applications › Add an application › Self-hosted**.
2. Name: `afixo-origin-console`.
3. Public hostname: `origin.afixo.io`. Leave the path empty — the whole host is protected.
4. Under **Access policies**, create a new policy:

   | Action | Rule type | Selector | Value |
   |---|---|---|---|
   | Service Auth | Include | Service Token | `afixo-api-production` |

5. Save the policy, add it to the application, save the application.
6. The same again for the machine listener: application `afixo-origin-machine`, hostname
   `origin-api.afixo.io`, the **same** `afixo-api-production` token — the Worker presents one
   service token on both of its hops (console and machine).

**Add no Allow policy.** The absence of one is the security property: with only a Service Auth
policy there is no login flow to phish and no session cookie to steal. If you later need to
poke the console by hand, add a *temporary* Allow policy and remove it, rather than leaving a
standing human path open.

Two traps:

- **Never create a second Access application for the same hostname** to bolt on service-token
  auth. Cloudflare's own docs call this out — two apps matching one hostname conflict. Add the
  policy to the existing app instead.
- **Never create a wildcard `*.afixo.io` application.** It would swallow `api.afixo.io` and
  `afixo.io` and take the whole product offline.

Repeat for `origin-staging.afixo.io` (`afixo-origin-console-staging`) and
`origin-api-staging.afixo.io` (`afixo-origin-machine-staging`), both with the
`afixo-api-staging` token. `api.afixo.io` and `api-staging.afixo.io` get **no** application:
they are Worker custom domains, not tunnel hostnames, and the requester's bearer is checked by
the gateway.

## 3. Protect `staging.afixo.io` with an email policy

1. **Add an application › Self-hosted**, name `afixo-web-staging`, hostname `staging.afixo.io`.
2. Policy:

   | Action | Rule type | Selector | Value |
   |---|---|---|---|
   | Allow | Include | Emails | `<your-email>` |

3. If no identity provider is configured, **One-time PIN** works out of the box — Access emails
   a code. That is enough for a single-operator staging environment.
4. Session duration: the 24 h default is fine. It is unrelated to the app's own session cookies.

This does not disturb `afixo-api`: Access sets its own `CF_Authorization` cookie, `parseCookies`
only looks for the three `__Host-afixo_*` names, and `src/origin.ts` strips `cookie` wholesale
before the origin hop.

> **Worth testing rather than assuming.** The session cookies are `SameSite=Strict`, and
> browsers withhold Strict cookies across a redirect chain whose initiator was cross-site — which
> is the shape of the Access IdP bounce. If the staging dashboard reads as logged-out immediately
> after an Access login and correct after one click, that is this, and `SameSite=Lax` on the
> session cookie is the usual remedy.

## 4. Policy evaluation order

Worth knowing before adding a second policy anywhere: **Bypass and Service Auth are evaluated
first**, top to bottom, then Block and Allow in their own order. Once an Allow or Block matches,
evaluation stops. So a Service Auth policy always gets its say before any human policy on the
same application.

## 5. Verify

```sh
# no token → Access rejects it on BOTH tunnel hostnames. "403 403" is the CORRECT answer here.
for h in origin origin-api; do curl -s -o /dev/null -w "$h %{http_code}\n" "https://$h.afixo.io/v1/health"; done

# with the token → 200 from the gateway (either hostname)
curl -s https://origin-api.afixo.io/v1/health \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET"

# machine API, end to end through afixo-web and this Worker: expect 400/401 from the gateway —
# NOT an Access login page (api.afixo.io must never be an Access app) and NOT a 404
# (MACHINE_HOSTS must list the hostname afixo-web forwards)
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.afixo.io/oauth/token

# console, end to end through the Worker: 401 means the origin was reached and answered
curl -s -o /dev/null -w '%{http_code}\n' https://afixo.io/api/v1/auth/me
```

If either end-to-end call returns `502 origin_unreachable`, the Worker could not reach that
listener at all (`ORIGIN_URL` / `MACHINE_ORIGIN_URL`, tunnel). If it returns `403`, the Access
headers are missing or wrong — check that both secrets are set on the Worker
(`pnpm wrangler secret list`) and that the hostname's application includes this token.

Authentication decisions are logged under **Zero Trust › Insights › Logs › Access**, per
application and per policy. That is the first place to look when a request is refused.

## 6. Rotation

Service tokens are rotated by creating a new one and deleting the old:

1. Create `afixo-api-production-2`.
2. Add it to the same Service Auth policy as a second Include value.
3. Update `.secrets.production`, run `pnpm secrets:push production`, redeploy.
4. Confirm traffic flows, then remove the old token from the policy and delete it.

Rotating `SESSION_KEY` is a different and more disruptive operation — it invalidates every live
session, because `unseal()` fails on every existing cookie. See `docs/session.md`.

## Do not enable "Require Access protection"

Cloudflare added an account-wide opt-in (2026-01-22) that blocks traffic to **every** hostname in
the account that has no Access application. With this setup that would take down `afixo.io`,
`www.afixo.io`, `api.afixo.io` and `api-staging.afixo.io` at once. Leave it off, or add explicit
hostname exemptions for all four before turning it on.
