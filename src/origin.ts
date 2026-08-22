/**
 * The hop to the private origin (gateway console listener behind Cloudflare
 * Access, reached via the tunnel at ORIGIN_URL).
 *
 *   /api/v1/<rest>  →  ${ORIGIN_URL}/v1/<rest>
 *
 * At this hop the Worker owns authentication: whatever the browser sent as
 * Authorization / Cookie is dropped, the bearer from the sealed session (if
 * any) is injected, and the Access service token is attached.
 */
import type { Env } from "./env";
import { REQUEST_ID_HEADER, json } from "./http";

const HOP_BY_HOP = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

/** Never forwarded from the browser. */
const REQUEST_STRIPPED = new Set([
  ...HOP_BY_HOP,
  "host",
  "authorization", // the Worker decides the bearer
  "cookie", // the session must never reach the origin
  "x-csrf-token", // consumed here
  "cf-access-client-id", // a client must not be able to smuggle Access credentials
  "cf-access-client-secret",
]);

/** Never returned to the browser: the origin cannot set cookies on afixo.io. */
const RESPONSE_STRIPPED = [...HOP_BY_HOP, "set-cookie", "set-cookie2"];

export interface ForwardOptions {
  /** access token to inject as `Authorization: Bearer` */
  bearer?: string | undefined;
  requestId: string;
}

export function originBase(env: Env): string {
  return env.ORIGIN_URL.replace(/\/+$/, "");
}

/** `https://afixo.io/api/v1/personas?x=1` → `${ORIGIN_URL}/v1/personas?x=1` */
export function toOriginUrl(env: Env, url: URL): string {
  const path = url.pathname.replace(/^\/api(?=\/|$)/, "");
  return `${originBase(env)}${path || "/"}${url.search}`;
}

function accessHeaders(env: Env): Record<string, string> {
  // Only when BOTH are set: local dev (no Access in front of localhost:8080) sends nothing.
  if (env.CF_ACCESS_CLIENT_ID && env.CF_ACCESS_CLIENT_SECRET) {
    return {
      "cf-access-client-id": env.CF_ACCESS_CLIENT_ID,
      "cf-access-client-secret": env.CF_ACCESS_CLIENT_SECRET,
    };
  }
  return {};
}

/** Headers for the origin hop: the client's (minus the stripped set) + Access + bearer + request id. */
export function originHeaders(env: Env, opts: ForwardOptions, from?: Headers): Headers {
  const headers = new Headers();
  if (from) {
    for (const [name, value] of from) {
      if (!REQUEST_STRIPPED.has(name)) headers.set(name, value);
    }
  }
  for (const [name, value] of Object.entries(accessHeaders(env))) headers.set(name, value);
  if (opts.bearer) headers.set("authorization", `Bearer ${opts.bearer}`);
  headers.set(REQUEST_ID_HEADER, opts.requestId);
  return headers;
}

/**
 * A request the Worker makes on its own behalf (refresh, logout). `path` is
 * origin-relative (`/v1/auth/refresh`). Throws on network failure.
 */
export function originFetch(
  env: Env,
  path: string,
  init: Omit<RequestInit, "headers" | "redirect"> & ForwardOptions & { headers?: Record<string, string> },
): Promise<Response> {
  const { bearer, requestId, headers: extra, ...rest } = init;
  const headers = originHeaders(env, { bearer, requestId });
  for (const [name, value] of Object.entries(extra ?? {})) headers.set(name, value);
  return fetch(`${originBase(env)}${path}`, { ...rest, headers, redirect: "manual" });
}

/**
 * Pass-through: forward the browser's request to the origin and relay the
 * answer. Redirects are relayed, not followed (the GitHub login hop is a 302
 * that the browser must see). A network failure becomes 502.
 */
export async function forwardToOrigin(request: Request, env: Env, opts: ForwardOptions): Promise<Response> {
  const url = new URL(request.url);
  const bodyless = request.method === "GET" || request.method === "HEAD";
  const upstream = new Request(toOriginUrl(env, url), {
    method: request.method,
    headers: originHeaders(env, opts, request.headers),
    body: bodyless ? null : request.body,
    redirect: "manual",
  });

  let response: Response;
  try {
    response = await fetch(upstream);
  } catch (err) {
    console.error(
      JSON.stringify({
        level: "error",
        event: "origin_unreachable",
        requestId: opts.requestId,
        method: request.method,
        path: url.pathname,
        message: err instanceof Error ? err.message : String(err),
      }),
    );
    return json(502, { error: "origin_unreachable" }, opts.requestId);
  }
  return relay(response, opts.requestId);
}

/** Copy an origin response for the browser: status + body untouched, hop-by-hop and set-cookie removed. */
export function relay(response: Response, requestId: string): Response {
  const headers = new Headers(response.headers);
  for (const name of RESPONSE_STRIPPED) headers.delete(name);
  headers.set(REQUEST_ID_HEADER, requestId);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
