/** Small response helpers. Every response from this Worker carries X-Request-Id. */

export const REQUEST_ID_HEADER = "X-Request-Id";

/** Reuse a well-formed client/edge request id, otherwise mint one. Never echo arbitrary bytes into logs or headers. */
export function requestIdFrom(request: Request): string {
  const given = request.headers.get(REQUEST_ID_HEADER);
  return given && /^[A-Za-z0-9._-]{1,128}$/.test(given) ? given : crypto.randomUUID();
}

export interface ResponseExtras {
  /** Set-Cookie values, one per cookie */
  cookies?: string[];
  headers?: HeadersInit;
}

function baseHeaders(requestId: string, extras?: ResponseExtras): Headers {
  const headers = new Headers(extras?.headers);
  headers.set("cache-control", "no-store");
  headers.set(REQUEST_ID_HEADER, requestId);
  for (const cookie of extras?.cookies ?? []) headers.append("set-cookie", cookie);
  return headers;
}

export function json(status: number, body: unknown, requestId: string, extras?: ResponseExtras): Response {
  const headers = baseHeaders(requestId, extras);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

export function noContent(requestId: string, extras?: ResponseExtras): Response {
  return new Response(null, { status: 204, headers: baseHeaders(requestId, extras) });
}

/** 302 with a relative Location — the browser resolves it against afixo.io. */
export function redirect(location: string, requestId: string, extras?: ResponseExtras): Response {
  const headers = baseHeaders(requestId, extras);
  headers.set("location", location);
  return new Response(null, { status: 302, headers });
}
