import { vi } from "vitest";

export type OriginHandler = (request: Request) => Response | Promise<Response>;

export interface OriginCall {
  /** the request as the Worker sent it (url, method, headers, redirect mode) */
  request: Request;
  /** its body, read inside the Worker's I/O context */
  body: string;
}

export interface OriginMock {
  /** every request the Worker sent to the origin, in order */
  calls: OriginCall[];
  restore(): void;
}

/**
 * Stand in for the origin by replacing the isolate-global `fetch`. Test files
 * and the Worker under test share one isolate, so the Worker's origin hop
 * lands here. (The old `fetchMock` from `cloudflare:test` was removed with
 * Vitest 4; this is the documented replacement.)
 *
 * The body is read here, inside the Worker's invocation: workerd forbids
 * touching a stream from a different I/O context, so the test could not read
 * it later.
 */
export function mockOrigin(handler: OriginHandler): OriginMock {
  const calls: OriginCall[] = [];
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const request = input instanceof Request && init === undefined ? input : new Request(input, init);
    const body = await request.clone().text();
    calls.push({ request, body });
    return handler(request);
  });
  return { calls, restore: () => spy.mockRestore() };
}

/** The JSON the gateway answers on callback / refresh (DESIGN §4). */
export function originSession(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    access_token: `acc_${crypto.randomUUID()}`,
    refresh_token: `ref_${crypto.randomUUID()}`,
    access_expires_at: now + 15 * 60,
    refresh_expires_at: now + 7 * 24 * 3600,
    subject: { id: "sub_123", handle: "valentin", display_name: "Valentin" },
    roles: ["subject"],
    ...overrides,
  };
}

export interface ParsedCookie {
  value: string;
  attrs: string[];
  raw: string;
}

/** name → parsed Set-Cookie, for assertions on the Worker's responses */
export function setCookies(response: Response): Map<string, ParsedCookie> {
  const out = new Map<string, ParsedCookie>();
  for (const raw of response.headers.getSetCookie()) {
    const [pair, ...attrs] = raw.split(";").map((s) => s.trim());
    const eq = pair!.indexOf("=");
    out.set(pair!.slice(0, eq), { value: pair!.slice(eq + 1), attrs, raw });
  }
  return out;
}
