/**
 * Machine mode — the product's own API surface (`api.afixo.io`), served to
 * requesters (OAuth2 client-credentials clients), not to browsers with cookies.
 *
 * `api.afixo.io` is a custom domain on afixo-web, which hands every request on
 * that host to this Worker over the `API` binding with the original URL.
 * Nothing public resolves to the tunnel: this Worker is the only path to the
 * gateway's machine listener (`MACHINE_ORIGIN_URL`, behind Access).
 *
 * Rules of this mode:
 *  - an explicit route allowlist; everything else — including /api/* and the
 *    whole console surface — is 404 without touching any origin;
 *  - the requester's own Authorization passes through unchanged;
 *  - no cookies, no CSRF. CORS headers on real responses come from the gateway
 *    (relayed); browser preflights (OPTIONS on an allowed path) are answered
 *    HERE, from ALLOWED_ORIGINS — a preflight carries no credentials, so the
 *    Access-protected origin would reject it, and it needs nothing from the
 *    gateway anyway;
 *  - never the console origin (`ORIGIN_URL`).
 */
import { originAllowed } from "../csrf";
import { type Env, parseAllowedOrigins } from "../env";
import { REQUEST_ID_HEADER, json } from "../http";
import { forwardToMachineOrigin } from "../origin";

interface MachineRoute {
  method: "GET" | "POST";
  path: string;
  /** `pathname.startsWith(path)` instead of equality */
  prefix?: boolean;
}

const ROUTES: readonly MachineRoute[] = [
  { method: "POST", path: "/oauth/token" },
  { method: "GET", path: "/v1/disclose/", prefix: true },
  { method: "GET", path: "/v1/purposes" },
  { method: "GET", path: "/v1/health" },
];

/** The listed method, or OPTIONS (CORS preflight) on the same path. Nothing else — not even HEAD. */
export function machineRouteAllowed(method: string, pathname: string): boolean {
  const m = method.toUpperCase();
  return ROUTES.some(
    (route) =>
      (route.prefix ? pathname.startsWith(route.path) : pathname === route.path) &&
      (m === route.method || m === "OPTIONS"),
  );
}

const CORS_ALLOW_METHODS = "GET, POST";
const CORS_ALLOW_HEADERS = "authorization, content-type";
const CORS_MAX_AGE = "600";

/**
 * A browser preflight, answered locally. The allowed browser origins are the
 * dashboard's (`ALLOWED_ORIGINS` — the same list console mode uses for CSRF);
 * anything else is refused without the origin ever being contacted.
 */
export function preflight(request: Request, env: Env, requestId: string): Response {
  if (!originAllowed(request, parseAllowedOrigins(env.ALLOWED_ORIGINS))) {
    return json(403, { error: "forbidden_origin" }, requestId);
  }
  // originAllowed() parsed and matched it, so this cannot throw.
  const origin = new URL(request.headers.get("Origin") as string).origin;
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": CORS_ALLOW_METHODS,
      "access-control-allow-headers": CORS_ALLOW_HEADERS,
      "access-control-max-age": CORS_MAX_AGE,
      vary: "Origin",
      [REQUEST_ID_HEADER]: requestId,
    },
  });
}

export async function handleMachine(request: Request, env: Env, url: URL, requestId: string): Promise<Response> {
  if (!env.MACHINE_ORIGIN_URL) {
    console.error(JSON.stringify({ level: "error", event: "misconfigured", requestId, missing: ["MACHINE_ORIGIN_URL"] }));
    return json(500, { error: "misconfigured" }, requestId);
  }
  if (!machineRouteAllowed(request.method, url.pathname)) return json(404, { error: "not_found" }, requestId);
  if (request.method.toUpperCase() === "OPTIONS") return preflight(request, env, requestId);
  return forwardToMachineOrigin(request, env, requestId);
}
