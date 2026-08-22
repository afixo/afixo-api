/**
 * afixo-api — the session boundary, in two modes keyed by hostname.
 *
 *   console  browser ─/api/v1/*─► afixo-web ─API binding─► afixo-api ─► ${ORIGIN_URL}/v1/* ─► tunnel ─► gateway:8080
 *   machine  requester ─https://api.afixo.io/*─► afixo-web ─API binding─► afixo-api ─► ${MACHINE_ORIGIN_URL}/* ─► tunnel ─► gateway:8081
 *
 * This module only dispatches. The rules live next to what they protect:
 * csrf.ts, seal.ts, cookies.ts, origin.ts, handlers/*.
 */
import { CSRF_COOKIE, SESSION_COOKIE, parseCookies } from "./cookies";
import { csrfValid, isMutating, originAllowed } from "./csrf";
import { type Env, parseAllowedOrigins, parseMachineHosts } from "./env";
import { githubCallback, logout, refresh } from "./handlers/auth";
import { handleMachine } from "./handlers/machine";
import { passthrough } from "./handlers/proxy";
import { json, requestIdFrom } from "./http";
import { Router } from "./router";

const router = new Router()
  .on("GET", "/api/v1/auth/github/callback", githubCallback)
  .on("POST", "/api/v1/auth/refresh", refresh)
  .on("POST", "/api/v1/auth/logout", logout)
  .prefix("*", "/api/v1/", passthrough);

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const requestId = requestIdFrom(request);
    const url = new URL(request.url);

    try {
      // Machine mode (api.afixo.io): its own allowlist, no cookies, no CSRF — see handlers/machine.ts.
      if (parseMachineHosts(env.MACHINE_HOSTS).has(url.hostname)) {
        return await handleMachine(request, env, url, requestId);
      }

      // Console mode: afixo-web only ever hands us /api/*; anything else is a wiring mistake.
      if (!url.pathname.startsWith("/api/")) return json(404, { error: "not_found" }, requestId);

      if (!env.SESSION_KEY || !env.ORIGIN_URL) {
        console.error(JSON.stringify({ level: "error", event: "misconfigured", requestId, missing: missingConfig(env) }));
        return json(500, { error: "misconfigured" }, requestId);
      }

      const cookies = parseCookies(request.headers.get("Cookie"));

      if (isMutating(request.method)) {
        if (!originAllowed(request, parseAllowedOrigins(env.ALLOWED_ORIGINS))) {
          return json(403, { error: "forbidden_origin" }, requestId);
        }
        if (cookies.has(SESSION_COOKIE) && !csrfValid(request.headers.get("X-CSRF-Token"), cookies.get(CSRF_COOKIE))) {
          return json(403, { error: "csrf" }, requestId);
        }
      }

      const handler = router.match(request.method, url.pathname);
      if (!handler) return json(404, { error: "not_found" }, requestId);
      return await handler({ request, env, ctx, url, requestId, cookies });
    } catch (err) {
      // Never the request, never a cookie, never a token: method, path, id and the message only.
      console.error(
        JSON.stringify({
          level: "error",
          event: "unhandled",
          requestId,
          method: request.method,
          path: url.pathname,
          message: err instanceof Error ? err.message : String(err),
        }),
      );
      return json(500, { error: "internal" }, requestId);
    }
  },
} satisfies ExportedHandler<Env>;

function missingConfig(env: Env): string[] {
  const missing: string[] = [];
  if (!env.SESSION_KEY) missing.push("SESSION_KEY");
  if (!env.ORIGIN_URL) missing.push("ORIGIN_URL");
  return missing;
}
