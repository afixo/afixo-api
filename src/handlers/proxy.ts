/**
 * `* /api/v1/*` — translate and forward (DESIGN §4).
 *
 * Open the session cookie, inject the access token as the bearer, relay the
 * origin's answer untouched. A 401 from the origin passes straight through:
 * the browser single-flights `POST /api/v1/auth/refresh` and retries once.
 * Nothing is refreshed implicitly here — see docs/session.md for why.
 *
 * A cookie that does not open (tampered, rotated key) is treated exactly like
 * no cookie: forwarded without Authorization, so the origin answers 401.
 */
import { SESSION_COOKIE } from "../cookies";
import { forwardToOrigin } from "../origin";
import type { Handler } from "../router";
import { unseal } from "../seal";

export const passthrough: Handler = async ({ request, env, cookies, requestId }) => {
  const sealed = cookies.get(SESSION_COOKIE);
  const session = sealed ? await unseal(sealed, env.SESSION_KEY) : null;
  return forwardToOrigin(request, env, { bearer: session?.a, requestId });
};
