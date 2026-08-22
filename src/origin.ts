/**
 * The hops to the private gateway, reached through the tunnel behind
 * Cloudflare Access. Nothing public resolves to the tunnel; these two hops
 * are the only way in.
 *
 *   console mode   /api/v1/<rest>  →  ${ORIGIN_URL}/v1/<rest>          gateway :8080 (console listener)
 *   machine mode   /<path>         →  ${MACHINE_ORIGIN_URL}/<path>     gateway :8081 (machine listener)
 *
 * Shared by both hops: hop-by-hop headers, Cookie, X-CSRF-Token and any
 * client-supplied CF-Access-Client-* never go upstream; the Access service
 * token and X-Request-Id are added; redirects are relayed, never followed;
 * the body streams through; Set-Cookie never comes back.
 *
 * What differs is who owns Authorization. On the console hop the Worker
 * does: the client's header is dropped and the bearer from the sealed session
 * is injected. On the machine hop the requester does: its own bearer / Basic
 * client credentials travel unchanged — the one place this Worker does not
 * decide auth.
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

/** Never forwarded from the client, on either hop. (Authorization is decided per hop, below.) */
const REQUEST_STRIPPED = new Set([
  ...HOP_BY_HOP,
  "host",
  "cookie", // the session must never reach the origin
  "x-csrf-token", // consumed here
  "cf-access-client-id", // a client must not be able to smuggle Access credentials
  "cf-access-client-secret",
]);

/** Never returned to the client: the origin cannot set cookies on afixo.io. */
const RESPONSE_STRIPPED = [...HOP_BY_HOP, "set-cookie", "set-cookie2"];

export interface ForwardOptions {
  /** console hop: access token from the sealed session, injected as `Authorization: Bearer` */
  bearer?: string | undefined;
  requestId: string;
}

export interface HopOptions extends ForwardOptions {
  /** machine hop: the requester's own Authorization travels unchanged */
  keepClientAuthorization?: boolean;
}

export type Hop = "console" | "machine";

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export function originBase(env: Env): string {
  return stripTrailingSlash(env.ORIGIN_URL);
}

export function machineOriginBase(env: Env): string {
  return stripTrailingSlash(env.MACHINE_ORIGIN_URL);
}

/** console: `https://afixo.io/api/v1/personas?x=1` → `${ORIGIN_URL}/v1/personas?x=1` */
export function toOriginUrl(env: Env, url: URL): string {
  const path = url.pathname.replace(/^\/api(?=\/|$)/, "");
  return `${originBase(env)}${path || "/"}${url.search}`;
}

/** machine: `https://api.afixo.io/v1/disclose/alice?purpose=shipping` → `${MACHINE_ORIGIN_URL}/v1/disclose/alice?purpose=shipping` — no prefix to strip */
export function toMachineOriginUrl(env: Env, url: URL): string {
  return `${machineOriginBase(env)}${url.pathname}${url.search}`;
}

function accessHeaders(env: Env): Record<string, string> {
  // Only when BOTH are set: local dev (no Access in front of localhost) sends nothing.
  if (env.CF_ACCESS_CLIENT_ID && env.CF_ACCESS_CLIENT_SECRET) {
    return {
      "cf-access-client-id": env.CF_ACCESS_CLIENT_ID,
      "cf-access-client-secret": env.CF_ACCESS_CLIENT_SECRET,
    };
  }
  return {};
}

/** Headers for a hop: the client's (minus the stripped set, minus Authorization unless kept) + Access + bearer + request id. */
export function hopHeaders(env: Env, opts: HopOptions, from?: Headers): Headers {
  const headers = new Headers();
  if (from) {
    for (const [name, value] of from) {
      if (REQUEST_STRIPPED.has(name)) continue;
      if (name === "authorization" && !opts.keepClientAuthorization) continue;
      headers.set(name, value);
    }
  }
  for (const [name, value] of Object.entries(accessHeaders(env))) headers.set(name, value);
  if (opts.bearer) headers.set("authorization", `Bearer ${opts.bearer}`);
  headers.set(REQUEST_ID_HEADER, opts.requestId);
  return headers;
}

/**
 * A request the Worker makes on its own behalf to the console listener
 * (refresh, logout). `path` is origin-relative (`/v1/auth/refresh`). Throws on
 * network failure.
 */
export function originFetch(
  env: Env,
  path: string,
  init: Omit<RequestInit, "headers" | "redirect"> & ForwardOptions & { headers?: Record<string, string> },
): Promise<Response> {
  const { bearer, requestId, headers: extra, ...rest } = init;
  const headers = hopHeaders(env, { bearer, requestId });
  for (const [name, value] of Object.entries(extra ?? {})) headers.set(name, value);
  return fetch(`${originBase(env)}${path}`, { ...rest, headers, redirect: "manual" });
}

/**
 * Console pass-through: the browser's request goes to the console listener
 * with the Worker's own Authorization (or none).
 */
export function forwardToOrigin(request: Request, env: Env, opts: ForwardOptions): Promise<Response> {
  const url = new URL(request.url);
  const headers = hopHeaders(env, { requestId: opts.requestId, bearer: opts.bearer }, request.headers);
  return forward("console", toOriginUrl(env, url), request, headers, opts.requestId);
}

/**
 * Machine pass-through: the requester's request goes to the machine listener
 * with the requester's own Authorization intact.
 */
export function forwardToMachineOrigin(request: Request, env: Env, requestId: string): Promise<Response> {
  const url = new URL(request.url);
  const headers = hopHeaders(env, { requestId, keepClientAuthorization: true }, request.headers);
  return forward("machine", toMachineOriginUrl(env, url), request, headers, requestId);
}

/**
 * Forward and relay. Redirects are relayed, not followed (the GitHub login
 * hop is a 302 the browser must see). A network failure becomes 502.
 */
async function forward(hop: Hop, target: string, request: Request, headers: Headers, requestId: string): Promise<Response> {
  const bodyless = request.method === "GET" || request.method === "HEAD";
  const upstream = new Request(target, {
    method: request.method,
    headers,
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
        hop,
        requestId,
        method: request.method,
        path: new URL(request.url).pathname,
        message: err instanceof Error ? err.message : String(err),
      }),
    );
    return json(502, { error: "origin_unreachable" }, requestId);
  }
  return relay(response, requestId);
}

/** Copy an origin response for the client: status + body untouched, hop-by-hop and set-cookie removed. */
export function relay(response: Response, requestId: string): Response {
  const headers = new Headers(response.headers);
  for (const name of RESPONSE_STRIPPED) headers.delete(name);
  headers.set(REQUEST_ID_HEADER, requestId);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
