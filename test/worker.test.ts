/**
 * Integration tests: the Worker as afixo-web sees it through the service
 * binding (`exports.default.fetch`), with the origin stood in by mockOrigin().
 */
import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";
import { CSRF_COOKIE, SESSION_COOKIE, STATE_COOKIE, decodeState, encodeState, newCsrfToken } from "../src/cookies";
import { seal, unseal, type SessionPayload } from "../src/seal";
import { mockOrigin, originSession, setCookies, type OriginMock } from "./helpers/origin";

const SITE = "https://afixo.io";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * Call the Worker the way afixo-web does. `redirect: "manual"` matters: an
 * incoming browser Request already carries it, and without it the loopback
 * Fetcher would follow the Worker's own 302s back into the Worker.
 */
function app(path: string, init?: RequestInit): Promise<Response> {
  return exports.default.fetch(new Request(`${SITE}${path}`, { ...init, redirect: "manual" }));
}

/** A browser that is logged in: sealed session + csrf + state cookies. */
async function loggedIn(payload?: Partial<SessionPayload>) {
  const now = Math.floor(Date.now() / 1000);
  const session: SessionPayload = { a: "acc_live", r: "ref_live", e: now + 900, ...payload };
  const sealed = await seal(session, env.SESSION_KEY);
  const csrf = newCsrfToken();
  const state = { sub: "sub_123", handle: "valentin", roles: ["subject"], exp: now + 7 * 86400 };
  return {
    session,
    csrf,
    state,
    cookie: `${SESSION_COOKIE}=${sealed}; ${CSRF_COOKIE}=${csrf}; ${STATE_COOKIE}=${encodeState(state)}`,
  };
}

let origin: OriginMock | undefined;
afterEach(() => {
  origin?.restore();
  origin = undefined;
});

describe("routing", () => {
  it("answers 404 JSON outside /api/ without touching the origin", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/health");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
    expect(origin.calls).toHaveLength(0);
  });

  it("answers 404 under /api/ but outside /api/v1/ without touching the origin", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/healthz");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
    expect(origin.calls).toHaveLength(0);
  });
});

describe("CSRF", () => {
  it("POST without Origin → 403 forbidden_origin", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/v1/personas", { method: "POST", body: "{}" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden_origin" });
    expect(origin.calls).toHaveLength(0);
  });

  it("POST from a foreign Origin → 403 forbidden_origin", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/v1/personas", { method: "POST", body: "{}", headers: { Origin: "https://evil.test" } });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden_origin" });
    expect(origin.calls).toHaveLength(0);
  });

  it("POST from an allowed Origin without a session is forwarded without Authorization; the origin's 401 passes through", async () => {
    origin = mockOrigin(() => Response.json({ error: "invalid_token", message: "no bearer" }, { status: 401 }));
    const res = await app("/api/v1/personas", {
      method: "POST",
      body: JSON.stringify({ name: "work" }),
      headers: { Origin: SITE, "content-type": "application/json", Authorization: "Bearer forged" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_token", message: "no bearer" });
    expect(origin.calls).toHaveLength(1);
    const sent = origin.calls[0]!;
    expect(sent.request.headers.get("authorization")).toBeNull();
    expect(JSON.parse(sent.body)).toEqual({ name: "work" });
  });

  it("POST with a session but no X-CSRF-Token → 403 csrf", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const me = await loggedIn();
    const res = await app("/api/v1/personas", { method: "POST", body: "{}", headers: { Origin: SITE, Cookie: me.cookie } });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "csrf" });
    expect(origin.calls).toHaveLength(0);
  });

  it("POST with a session and a wrong X-CSRF-Token → 403 csrf", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const me = await loggedIn();
    const res = await app("/api/v1/personas", {
      method: "POST",
      body: "{}",
      headers: { Origin: SITE, Cookie: me.cookie, "X-CSRF-Token": `${me.csrf.slice(0, -1)}x` },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "csrf" });
    expect(origin.calls).toHaveLength(0);
  });

  it("POST with a session and the matching token is forwarded with the bearer", async () => {
    origin = mockOrigin(() => Response.json({ id: "p1" }, { status: 201 }));
    const me = await loggedIn();
    const res = await app("/api/v1/personas", {
      method: "POST",
      body: "{}",
      headers: { Origin: SITE, Cookie: me.cookie, "X-CSRF-Token": me.csrf },
    });
    expect(res.status).toBe(201);
    expect(origin.calls[0]!.request.headers.get("authorization")).toBe(`Bearer ${me.session.a}`);
    expect(origin.calls[0]!.request.headers.get("x-csrf-token")).toBeNull();
  });

  it("GET needs neither Origin nor token", async () => {
    origin = mockOrigin(() => Response.json([]));
    const res = await app("/api/v1/personas");
    expect(res.status).toBe(200);
    expect(origin.calls).toHaveLength(1);
  });
});

describe("pass-through", () => {
  it("rewrites /api/v1/x to ORIGIN_URL/v1/x, keeps the query, injects bearer + Access + request id, strips cookie/authorization", async () => {
    origin = mockOrigin(() => Response.json({ ok: true }));
    const me = await loggedIn();
    const res = await app("/api/v1/audit?limit=10&cursor=abc", {
      headers: { Cookie: me.cookie, Authorization: "Bearer forged", "X-Request-Id": "req-123.a", "Accept": "application/json" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-request-id")).toBe("req-123.a");

    const sent = origin.calls[0]!.request;
    expect(sent.url).toBe(`${env.ORIGIN_URL}/v1/audit?limit=10&cursor=abc`);
    expect(sent.method).toBe("GET");
    expect(sent.redirect).toBe("manual");
    expect(sent.headers.get("authorization")).toBe(`Bearer ${me.session.a}`);
    expect(sent.headers.get("cookie")).toBeNull();
    expect(sent.headers.get("cf-access-client-id")).toBe(env.CF_ACCESS_CLIENT_ID);
    expect(sent.headers.get("cf-access-client-secret")).toBe(env.CF_ACCESS_CLIENT_SECRET);
    expect(sent.headers.get("x-request-id")).toBe("req-123.a");
    expect(sent.headers.get("accept")).toBe("application/json");
  });

  it("never lets a client smuggle Access credentials", async () => {
    origin = mockOrigin(() => new Response("ok"));
    await app("/api/v1/health", { headers: { "CF-Access-Client-Id": "forged", "CF-Access-Client-Secret": "forged" } });
    expect(origin.calls[0]!.request.headers.get("cf-access-client-id")).toBe(env.CF_ACCESS_CLIENT_ID);
    expect(origin.calls[0]!.request.headers.get("cf-access-client-secret")).toBe(env.CF_ACCESS_CLIENT_SECRET);
  });

  it("relays status, body and headers but strips set-cookie", async () => {
    origin = mockOrigin(
      () =>
        new Response("teapot", {
          status: 418,
          headers: { "content-type": "text/plain", "x-upstream": "yes", "set-cookie": "evil=1; Path=/" },
        }),
    );
    const res = await app("/api/v1/anything");
    expect(res.status).toBe(418);
    expect(await res.text()).toBe("teapot");
    expect(res.headers.get("x-upstream")).toBe("yes");
    expect(res.headers.get("content-type")).toBe("text/plain");
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it("relays a 302 (GitHub login) instead of following it", async () => {
    const location = "https://github.com/login/oauth/authorize?client_id=x&state=y";
    origin = mockOrigin(() => new Response(null, { status: 302, headers: { location } }));
    const res = await app("/api/v1/auth/github/login");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(location);
  });

  it("forwards without Authorization when the session cookie does not open", async () => {
    origin = mockOrigin(() => Response.json({ error: "invalid_token" }, { status: 401 }));
    const res = await app("/api/v1/auth/me", { headers: { Cookie: `${SESSION_COOKIE}=AAAAtampered` } });
    expect(res.status).toBe(401);
    expect(origin.calls[0]!.request.headers.get("authorization")).toBeNull();
  });

  it("answers 502 origin_unreachable when the origin cannot be reached", async () => {
    origin = mockOrigin(() => {
      throw new TypeError("connect ECONNREFUSED");
    });
    const res = await app("/api/v1/auth/me");
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "origin_unreachable" });
  });

  it("mints an X-Request-Id when the client sends none or a malformed one", async () => {
    origin = mockOrigin(() => new Response("ok"));
    const res = await app("/api/v1/health", { headers: { "X-Request-Id": "not a valid id: spaces, punctuation; too loose" } });
    const id = res.headers.get("x-request-id");
    expect(id).toMatch(UUID);
    expect((await app("/api/v1/health")).headers.get("x-request-id")).toMatch(UUID);
    expect(origin.calls[0]!.request.headers.get("x-request-id")).toBe(id);
  });
});

describe("GET /api/v1/auth/github/callback", () => {
  it("seals the origin's session into three cookies and sends the browser to /app", async () => {
    const upstream = originSession();
    origin = mockOrigin(() => Response.json(upstream));
    const res = await app("/api/v1/auth/github/callback?code=abc&state=xyz");

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/app");
    expect(await res.text()).toBe(""); // no token in the body
    expect(origin.calls[0]!.request.url).toBe(`${env.ORIGIN_URL}/v1/auth/github/callback?code=abc&state=xyz`);

    const cookies = setCookies(res);
    expect([...cookies.keys()].sort()).toEqual([CSRF_COOKIE, SESSION_COOKIE, STATE_COOKIE].sort());
    for (const c of cookies.values()) {
      expect(c.attrs).toEqual(expect.arrayContaining(["Path=/", "Secure"]));
      expect(c.raw).not.toMatch(/Domain/i);
      expect(c.raw).not.toContain("Max-Age=0");
    }
    // Only the cosmetic gate cookie is Lax (it must survive the redirect that continues GitHub's cross-site navigation).
    expect(cookies.get(SESSION_COOKIE)!.attrs).toContain("SameSite=Strict");
    expect(cookies.get(CSRF_COOKIE)!.attrs).toContain("SameSite=Strict");
    expect(cookies.get(STATE_COOKIE)!.attrs).toContain("SameSite=Lax");
    expect(cookies.get(SESSION_COOKIE)!.attrs).toContain("HttpOnly");
    expect(cookies.get(CSRF_COOKIE)!.attrs).not.toContain("HttpOnly");
    expect(cookies.get(STATE_COOKIE)!.attrs).not.toContain("HttpOnly");

    // The session cookie opens to exactly {a, r, e}; the raw tokens appear nowhere in the response.
    const sealed = cookies.get(SESSION_COOKIE)!.value;
    expect(await unseal(sealed, env.SESSION_KEY)).toEqual({
      a: upstream.access_token,
      r: upstream.refresh_token,
      e: upstream.access_expires_at,
    });
    expect(JSON.stringify([...res.headers])).not.toContain(upstream.access_token);
    expect(cookies.get(CSRF_COOKIE)!.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(decodeState(cookies.get(STATE_COOKIE)!.value)).toEqual({
      sub: "sub_123",
      handle: "valentin",
      roles: ["subject"],
      exp: upstream.refresh_expires_at,
    });

    // ...and the cookie it set is what the pass-through later turns into the bearer.
    origin.restore();
    origin = mockOrigin(() => Response.json({ id: "sub_123" }));
    const me = await app("/api/v1/auth/me", { headers: { Cookie: `${SESSION_COOKIE}=${sealed}` } });
    expect(me.status).toBe(200);
    expect(origin.calls[0]!.request.headers.get("authorization")).toBe(`Bearer ${upstream.access_token}`);
  });

  it("accepts ISO-8601 expiries", async () => {
    const exp = new Date((Math.floor(Date.now() / 1000) + 3600) * 1000);
    origin = mockOrigin(() =>
      Response.json(originSession({ access_expires_at: exp.toISOString(), refresh_expires_at: exp.toISOString() })),
    );
    const res = await app("/api/v1/auth/github/callback?code=abc&state=xyz");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/app");
    const state = decodeState(setCookies(res).get(STATE_COOKIE)!.value);
    expect(state?.exp).toBe(Math.floor(exp.getTime() / 1000));
  });

  it("lands on the origin's validated redirect_to, but only a same-origin absolute path", async () => {
    origin = mockOrigin(() => Response.json(originSession({ redirect_to: "/app/policies" })));
    let res = await app("/api/v1/auth/github/callback?code=abc&state=xyz");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/app/policies");

    for (const bad of ["//evil.test/x", "https://evil.test", "app", "/a\\b", ""]) {
      origin.restore();
      origin = mockOrigin(() => Response.json(originSession({ redirect_to: bad })));
      res = await app("/api/v1/auth/github/callback?code=abc&state=xyz");
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe("/app");
    }
  });

  it("on an origin error clears the cookies and lands on /login?error=<code>", async () => {
    origin = mockOrigin(() => Response.json({ error: "invalid_state", message: "state mismatch" }, { status: 400 }));
    const res = await app("/api/v1/auth/github/callback?code=abc&state=bad");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/login?error=invalid_state");
    const cookies = setCookies(res);
    expect(cookies.size).toBe(3);
    for (const c of cookies.values()) {
      expect(c.value).toBe("");
      expect(c.attrs).toContain("Max-Age=0");
    }
  });

  it("falls back to a generic code when the origin's error is not usable", async () => {
    origin = mockOrigin(() => new Response("<html>bad gateway</html>", { status: 502 }));
    const res = await app("/api/v1/auth/github/callback?code=abc&state=xyz");
    expect(res.headers.get("location")).toBe("/login?error=upstream_502");
  });

  it("treats an unusable session body as bad_session", async () => {
    origin = mockOrigin(() => Response.json({ access_token: "a" })); // no refresh token, no expiries
    const res = await app("/api/v1/auth/github/callback?code=abc&state=xyz");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/login?error=bad_session");
    expect(setCookies(res).get(SESSION_COOKIE)!.attrs).toContain("Max-Age=0");
  });
});

describe("POST /api/v1/auth/refresh", () => {
  it("trades the refresh token, reseals the new pair, keeps the csrf value → 204", async () => {
    const me = await loggedIn();
    const next = originSession();
    origin = mockOrigin(() => Response.json(next));
    const res = await app("/api/v1/auth/refresh", {
      method: "POST",
      headers: { Origin: SITE, Cookie: me.cookie, "X-CSRF-Token": me.csrf },
    });
    expect(res.status).toBe(204);

    const sent = origin.calls[0]!;
    expect(sent.request.url).toBe(`${env.ORIGIN_URL}/v1/auth/refresh`);
    expect(sent.request.method).toBe("POST");
    expect(sent.request.headers.get("content-type")).toBe("application/json");
    expect(sent.request.headers.get("authorization")).toBeNull();
    expect(sent.request.headers.get("cf-access-client-id")).toBe(env.CF_ACCESS_CLIENT_ID);
    expect(JSON.parse(sent.body)).toEqual({ refresh_token: me.session.r });

    const cookies = setCookies(res);
    expect(cookies.size).toBe(3);
    expect(await unseal(cookies.get(SESSION_COOKIE)!.value, env.SESSION_KEY)).toEqual({
      a: next.access_token,
      r: next.refresh_token,
      e: next.access_expires_at,
    });
    expect(cookies.get(CSRF_COOKIE)!.value).toBe(me.csrf);
    expect(decodeState(cookies.get(STATE_COOKIE)!.value)?.exp).toBe(next.refresh_expires_at);
  });

  it("origin 401 → all cookies cleared → 401", async () => {
    const me = await loggedIn();
    origin = mockOrigin(() => Response.json({ error: "invalid_token", message: "refresh token reused" }, { status: 401 }));
    const res = await app("/api/v1/auth/refresh", {
      method: "POST",
      headers: { Origin: SITE, Cookie: me.cookie, "X-CSRF-Token": me.csrf },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_token", message: "refresh token reused" });
    const cookies = setCookies(res);
    expect(cookies.size).toBe(3);
    for (const c of cookies.values()) expect(c.attrs).toContain("Max-Age=0");
  });

  it("without a session → 401 no_session, nothing sent to the origin", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/v1/auth/refresh", { method: "POST", headers: { Origin: SITE } });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "no_session" });
    expect(origin.calls).toHaveLength(0);
  });

  it("still requires the CSRF token", async () => {
    const me = await loggedIn();
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/v1/auth/refresh", { method: "POST", headers: { Origin: SITE, Cookie: me.cookie } });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "csrf" });
    expect(origin.calls).toHaveLength(0);
  });
});

describe("POST /api/v1/auth/logout", () => {
  it("forwards with the bearer and clears the cookies → 204", async () => {
    const me = await loggedIn();
    origin = mockOrigin(() => new Response(null, { status: 204 }));
    const res = await app("/api/v1/auth/logout", {
      method: "POST",
      headers: { Origin: SITE, Cookie: me.cookie, "X-CSRF-Token": me.csrf },
    });
    expect(res.status).toBe(204);
    expect(origin.calls[0]!.request.url).toBe(`${env.ORIGIN_URL}/v1/auth/logout`);
    expect(origin.calls[0]!.request.headers.get("authorization")).toBe(`Bearer ${me.session.a}`);
    const cookies = setCookies(res);
    expect(cookies.size).toBe(3);
    for (const c of cookies.values()) expect(c.attrs).toContain("Max-Age=0");
  });

  it("clears the cookies even when the origin fails", async () => {
    const me = await loggedIn();
    origin = mockOrigin(() => {
      throw new TypeError("connect ECONNREFUSED");
    });
    const res = await app("/api/v1/auth/logout", {
      method: "POST",
      headers: { Origin: SITE, Cookie: me.cookie, "X-CSRF-Token": me.csrf },
    });
    expect(res.status).toBe(204);
    expect(setCookies(res).size).toBe(3);
  });

  it("without a session just clears the cookies, no origin call", async () => {
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/v1/auth/logout", { method: "POST", headers: { Origin: SITE } });
    expect(res.status).toBe(204);
    expect(origin.calls).toHaveLength(0);
    expect(setCookies(res).size).toBe(3);
  });

  it("still obeys the Origin allowlist", async () => {
    const me = await loggedIn();
    origin = mockOrigin(() => new Response("nope"));
    const res = await app("/api/v1/auth/logout", { method: "POST", headers: { Cookie: me.cookie, "X-CSRF-Token": me.csrf } });
    expect(res.status).toBe(403);
    expect(origin.calls).toHaveLength(0);
  });
});
