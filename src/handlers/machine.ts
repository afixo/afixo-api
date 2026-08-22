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
 *  - no cookies, no Origin/CSRF checks. CORS is the gateway's job; its
 *    preflights (OPTIONS on an allowed path) are simply forwarded;
 *  - never the console origin (`ORIGIN_URL`).
 */
import type { Env } from "../env";
import { json } from "../http";
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

export async function handleMachine(request: Request, env: Env, url: URL, requestId: string): Promise<Response> {
  if (!env.MACHINE_ORIGIN_URL) {
    console.error(JSON.stringify({ level: "error", event: "misconfigured", requestId, missing: ["MACHINE_ORIGIN_URL"] }));
    return json(500, { error: "misconfigured" }, requestId);
  }
  if (!machineRouteAllowed(request.method, url.pathname)) return json(404, { error: "not_found" }, requestId);
  return forwardToMachineOrigin(request, env, requestId);
}
