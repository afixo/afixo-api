/**
 * The three translated auth endpoints (DESIGN §4). Everything else under
 * /api/ is the pass-through in ./proxy.ts.
 *
 * Origin session JSON (callback and refresh answer the same shape):
 *   { access_token, refresh_token, access_expires_at, refresh_expires_at,
 *     subject: { id, handle, display_name }, roles: [...] }
 */
import {
  CSRF_COOKIE,
  SESSION_COOKIE,
  STATE_COOKIE,
  clearSessionCookies,
  decodeState,
  newCsrfToken,
  sessionCookies,
  type StateCookie,
} from "../cookies";
import { json, noContent, redirect } from "../http";
import { forwardToOrigin, originFetch, relay } from "../origin";
import type { RouteContext } from "../router";
import { seal, unseal } from "../seal";

export interface OriginSession {
  access: string;
  refresh: string;
  /** unix seconds */
  accessExp: number;
  /** unix seconds */
  refreshExp: number;
  subject?: { id: string; handle: string };
  roles?: string[];
  /** in-app path to land on after login; only ever a same-origin absolute path */
  redirectTo?: string;
}

/** `/app/policies` yes; `//evil`, `https://…`, `app` no. */
export function safeRedirectPath(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return undefined;
  }
  return value;
}

/** Accepts unix seconds, unix milliseconds (heuristic: > 1e11) or an ISO-8601 string. */
export function toUnixSeconds(value: unknown): number | null {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value <= 0) return null;
    return Math.floor(value > 1e11 ? value / 1000 : value);
  }
  if (typeof value === "string" && value.length > 0) {
    const asNumber = Number(value);
    if (Number.isFinite(asNumber)) return toUnixSeconds(asNumber);
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
  }
  return null;
}

export function parseOriginSession(data: unknown): OriginSession | null {
  if (typeof data !== "object" || data === null) return null;
  const v = data as Record<string, unknown>;
  const access = v["access_token"];
  const refresh = v["refresh_token"];
  const accessExp = toUnixSeconds(v["access_expires_at"]);
  const refreshExp = toUnixSeconds(v["refresh_expires_at"]);
  if (typeof access !== "string" || !access || typeof refresh !== "string" || !refresh) return null;
  if (accessExp === null || refreshExp === null) return null;

  const session: OriginSession = { access, refresh, accessExp, refreshExp };
  const subject = v["subject"];
  if (typeof subject === "object" && subject !== null) {
    const s = subject as Record<string, unknown>;
    if (typeof s["id"] === "string" && typeof s["handle"] === "string") {
      session.subject = { id: s["id"], handle: s["handle"] };
    }
  }
  const roles = v["roles"];
  if (Array.isArray(roles) && roles.length > 0 && roles.every((r) => typeof r === "string")) {
    session.roles = roles as string[];
  }
  const redirectTo = safeRedirectPath(v["redirect_to"]);
  if (redirectTo) session.redirectTo = redirectTo;
  return session;
}

const ERROR_CODE = /^[a-z0-9_]{1,64}$/;

/** Map an origin failure to a `?error=<code>` the login page can show. Never leaks a body. */
async function errorCodeOf(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: unknown };
    if (typeof body.error === "string" && ERROR_CODE.test(body.error)) return body.error;
  } catch {
    // not JSON — fall through
  }
  return `upstream_${response.status}`;
}

function loginError(code: string, requestId: string): Response {
  return redirect(`/login?error=${encodeURIComponent(code)}`, requestId, { cookies: clearSessionCookies() });
}

/**
 * GET /api/v1/auth/github/callback?code&state
 * Forward to the origin, seal its answer into the three cookies, send the
 * browser to /app. Any failure clears the cookies and lands on /login?error=.
 */
export async function githubCallback({ request, env, requestId }: RouteContext): Promise<Response> {
  const response = await forwardToOrigin(request, env, { requestId });
  if (!response.ok) return loginError(await errorCodeOf(response), requestId);

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    return loginError("bad_session", requestId);
  }
  const session = parseOriginSession(data);
  const now = Math.floor(Date.now() / 1000);
  if (!session || !session.subject || session.refreshExp <= now) return loginError("bad_session", requestId);

  let sealed: string;
  try {
    sealed = await seal({ a: session.access, r: session.refresh, e: session.accessExp }, env.SESSION_KEY);
  } catch (err) {
    console.error(
      JSON.stringify({ level: "error", event: "seal_failed", requestId, message: err instanceof Error ? err.message : String(err) }),
    );
    return loginError("sealing_failed", requestId);
  }

  const state: StateCookie = {
    sub: session.subject.id,
    handle: session.subject.handle,
    roles: session.roles ?? ["subject"],
    exp: session.refreshExp,
  };
  // The origin validated `redirect_to` (it came from /auth/github/login?redirect_to=…); re-checked here anyway.
  const landing = session.redirectTo ?? "/app";
  return redirect(landing, requestId, { cookies: sessionCookies({ sealed, csrf: newCsrfToken(), state }) });
}

/**
 * POST /api/v1/auth/refresh  (body ignored; CSRF rules already applied)
 * Open the cookie, trade the refresh token at the origin, reseal the new
 * pair. The csrf token keeps its value. Origin 401 → everything cleared → 401.
 */
export async function refresh({ env, cookies, requestId }: RouteContext): Promise<Response> {
  const sealed = cookies.get(SESSION_COOKIE);
  const current = sealed ? await unseal(sealed, env.SESSION_KEY) : null;
  if (!current) return json(401, { error: "no_session" }, requestId, { cookies: clearSessionCookies() });

  let response: Response;
  try {
    response = await originFetch(env, "/v1/auth/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refresh_token: current.r }),
      requestId,
    });
  } catch (err) {
    console.error(
      JSON.stringify({ level: "error", event: "origin_unreachable", requestId, path: "/v1/auth/refresh", message: err instanceof Error ? err.message : String(err) }),
    );
    return json(502, { error: "origin_unreachable" }, requestId);
  }

  if (response.status === 401) {
    // The refresh token is spent, revoked or unknown: the session is over.
    let body: unknown = { error: "invalid_token" };
    try {
      body = await response.json();
    } catch {
      // keep the default
    }
    return json(401, body, requestId, { cookies: clearSessionCookies() });
  }
  // Anything else non-2xx is relayed as-is; the cookies stay (the access token may still be valid).
  if (!response.ok) return relay(response, requestId);

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    return json(502, { error: "bad_upstream_session" }, requestId);
  }
  const next = parseOriginSession(data);
  if (!next) return json(502, { error: "bad_upstream_session" }, requestId);

  const resealed = await seal({ a: next.access, r: next.refresh, e: next.accessExp }, env.SESSION_KEY);
  const previous = decodeState(cookies.get(STATE_COOKIE));
  const state: StateCookie = {
    sub: next.subject?.id ?? previous?.sub ?? "",
    handle: next.subject?.handle ?? previous?.handle ?? "",
    roles: next.roles ?? previous?.roles ?? ["subject"],
    exp: next.refreshExp,
  };
  // The CSRF check guarantees the csrf cookie exists whenever a session cookie does; the fallback is for types.
  const csrf = cookies.get(CSRF_COOKIE) ?? newCsrfToken();
  return noContent(requestId, { cookies: sessionCookies({ sealed: resealed, csrf, state }) });
}

/**
 * POST /api/v1/auth/logout  (CSRF rules already applied)
 * Tell the origin to revoke the session if we can; clear the cookies regardless.
 */
export async function logout({ request, env, cookies, requestId }: RouteContext): Promise<Response> {
  const sealed = cookies.get(SESSION_COOKIE);
  const session = sealed ? await unseal(sealed, env.SESSION_KEY) : null;
  if (session) {
    // Best effort: the answer does not matter, the cookies go either way.
    const response = await forwardToOrigin(request, env, { bearer: session.a, requestId });
    await response.body?.cancel();
  }
  return noContent(requestId, { cookies: clearSessionCookies() });
}
