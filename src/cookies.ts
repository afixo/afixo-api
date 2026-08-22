/**
 * The three cookies this Worker owns (DESIGN §3). All carry the `__Host-`
 * prefix, which browsers only honour with `Secure`, `Path=/` and no `Domain`:
 * a sibling hostname (origin.afixo.io, api.afixo.io) can never set or
 * overwrite them.
 */
import { b64urlDecode, b64urlEncode } from "./b64url";

export const SESSION_COOKIE = "__Host-afixo_session";
export const CSRF_COOKIE = "__Host-afixo_csrf";
export const STATE_COOKIE = "__Host-afixo_state";

/** Readable by afixo-web for its UI gate. Cosmetic only — never trusted for authorisation. */
export interface StateCookie {
  sub: string;
  handle: string;
  roles: string[];
  /** refresh-token expiry, unix seconds */
  exp: number;
}

export function parseCookies(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name && !out.has(name)) out.set(name, value);
  }
  return out;
}

export interface CookieOptions {
  httpOnly?: boolean;
  /** seconds; 0 clears the cookie */
  maxAge?: number;
}

// RFC 6265 cookie-octet: printable US-ASCII minus CTLs, space, `"`, `,`, `;`, `\`.
const COOKIE_OCTETS = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/;

export function serializeCookie(name: string, value: string, opts: CookieOptions = {}): string {
  if (!COOKIE_OCTETS.test(value)) throw new Error(`cookie ${name}: value contains illegal characters`);
  const parts = [`${name}=${value}`, "Path=/", "Secure", "SameSite=Strict"];
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAge))}`);
  return parts.join("; ");
}

/** A `__Host-` cookie can only be cleared with the same Secure + Path=/ attributes it was set with. */
export function clearCookie(name: string, httpOnly = false): string {
  return serializeCookie(name, "", { httpOnly, maxAge: 0 });
}

export interface SessionCookieSet {
  /** output of seal() */
  sealed: string;
  csrf: string;
  state: StateCookie;
}

/**
 * The three Set-Cookie values for a live session. All expire together with
 * the refresh token (`state.exp`): after that point none of them is useful.
 */
export function sessionCookies(set: SessionCookieSet, nowSeconds = Date.now() / 1000): string[] {
  const maxAge = Math.max(0, set.state.exp - nowSeconds);
  return [
    serializeCookie(SESSION_COOKIE, set.sealed, { httpOnly: true, maxAge }),
    serializeCookie(CSRF_COOKIE, set.csrf, { maxAge }),
    serializeCookie(STATE_COOKIE, encodeState(set.state), { maxAge }),
  ];
}

export function clearSessionCookies(): string[] {
  return [clearCookie(SESSION_COOKIE, true), clearCookie(CSRF_COOKIE), clearCookie(STATE_COOKIE)];
}

export function encodeState(state: StateCookie): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(state)));
}

export function decodeState(value: string | undefined): StateCookie | null {
  if (!value) return null;
  const bytes = b64urlDecode(value);
  if (!bytes) return null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== "object" || parsed === null) return null;
    const v = parsed as Record<string, unknown>;
    if (typeof v["sub"] !== "string" || typeof v["handle"] !== "string") return null;
    if (typeof v["exp"] !== "number" || !Number.isFinite(v["exp"])) return null;
    if (!Array.isArray(v["roles"]) || !v["roles"].every((r) => typeof r === "string")) return null;
    return { sub: v["sub"], handle: v["handle"], roles: v["roles"] as string[], exp: v["exp"] };
  } catch {
    return null;
  }
}

/** 32 random bytes, base64url — the double-submit token. */
export function newCsrfToken(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
}
