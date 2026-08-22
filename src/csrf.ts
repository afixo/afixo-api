/**
 * CSRF, two layers (DESIGN §4), applied to every non-GET/HEAD/OPTIONS request:
 *
 *  1. `Origin` must be on the allowlist. A missing Origin is a rejection. This
 *     layer covers pre-session endpoints, so it is what blocks login-CSRF.
 *  2. Once a session cookie exists, `X-CSRF-Token` must equal the readable
 *     csrf cookie, compared in constant time.
 *
 * `SameSite=Strict` on the cookies is the third layer.
 */

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isMutating(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

/** `allowlist` holds normalised origins (`scheme://host[:port]`), see parseAllowedOrigins(). */
export function originAllowed(request: Request, allowlist: ReadonlySet<string>): boolean {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  let normalised: string;
  try {
    normalised = new URL(origin).origin;
  } catch {
    return false;
  }
  // Opaque origins (`Origin: null`, sandboxed frames, some redirects) never match.
  if (normalised === "null") return false;
  return allowlist.has(normalised);
}

export function csrfValid(headerToken: string | null, cookieToken: string | undefined): boolean {
  if (!headerToken || !cookieToken) return false;
  return timingSafeEqual(headerToken, cookieToken);
}

/** Constant-time string equality: no early exit, runs over the longer input. */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  let diff = ab.length ^ bb.length;
  const n = Math.max(ab.length, bb.length);
  for (let i = 0; i < n; i++) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}
