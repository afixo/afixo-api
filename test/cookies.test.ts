import { describe, expect, it } from "vitest";
import {
  CSRF_COOKIE,
  SESSION_COOKIE,
  STATE_COOKIE,
  clearCookie,
  clearSessionCookies,
  decodeState,
  encodeState,
  newCsrfToken,
  parseCookies,
  serializeCookie,
  sessionCookies,
  type StateCookie,
} from "../src/cookies";

describe("parseCookies", () => {
  it("parses a Cookie header", () => {
    const cookies = parseCookies(`${SESSION_COOKIE}=abc; ${CSRF_COOKIE}=def ; x=1=2;bare; =novalue`);
    expect(cookies.get(SESSION_COOKIE)).toBe("abc");
    expect(cookies.get(CSRF_COOKIE)).toBe("def");
    expect(cookies.get("x")).toBe("1=2");
    expect(cookies.has("bare")).toBe(false);
    expect(cookies.size).toBe(3);
  });

  it("keeps the first occurrence of a duplicated name", () => {
    expect(parseCookies("a=1; a=2").get("a")).toBe("1");
  });

  it("handles a missing header", () => {
    expect(parseCookies(null).size).toBe(0);
    expect(parseCookies("").size).toBe(0);
  });
});

describe("serializeCookie", () => {
  it("always emits the __Host- requirements: Path=/, Secure, SameSite=Strict, no Domain", () => {
    const c = serializeCookie(CSRF_COOKIE, "tok");
    expect(c).toBe(`${CSRF_COOKIE}=tok; Path=/; Secure; SameSite=Strict`);
    expect(c).not.toMatch(/Domain/i);
  });

  it("adds HttpOnly and Max-Age on request", () => {
    expect(serializeCookie(SESSION_COOKIE, "v", { httpOnly: true, maxAge: 61.9 })).toBe(
      `${SESSION_COOKIE}=v; Path=/; Secure; SameSite=Strict; HttpOnly; Max-Age=61`,
    );
  });

  it("refuses values that would break the header", () => {
    expect(() => serializeCookie("x", "a;b")).toThrow();
    expect(() => serializeCookie("x", "a b")).toThrow();
    expect(() => serializeCookie("x", "a\r\nSet-Cookie: y=1")).toThrow();
  });
});

describe("clearing", () => {
  it("clears with Max-Age=0 and the same __Host- attributes", () => {
    expect(clearCookie(STATE_COOKIE)).toBe(`${STATE_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`);
    const all = clearSessionCookies();
    expect(all).toHaveLength(3);
    for (const c of all) {
      expect(c).toMatch(/^__Host-afixo_(session|csrf|state)=; /);
      expect(c).toContain("Max-Age=0");
      expect(c).toContain("Secure");
      expect(c).toContain("Path=/");
    }
    expect(all[0]).toContain("HttpOnly");
  });
});

describe("serializeCookie sameSite", () => {
  it("is Strict by default and Lax only when asked", () => {
    expect(serializeCookie("x", "1")).toContain("SameSite=Strict");
    expect(serializeCookie("x", "1", { sameSite: "Lax" })).toContain("SameSite=Lax");
  });
});

describe("sessionCookies", () => {
  const state: StateCookie = { sub: "sub_1", handle: "valentin", roles: ["subject"], exp: 1_000_000 };

  it("emits the three cookies with the right flags and a shared lifetime", () => {
    const [session, csrf, st] = sessionCookies({ sealed: "SEALED", csrf: "CSRF", state }, 1_000_000 - 3600);
    expect(session).toBe(`${SESSION_COOKIE}=SEALED; Path=/; Secure; SameSite=Strict; HttpOnly; Max-Age=3600`);
    expect(csrf).toBe(`${CSRF_COOKIE}=CSRF; Path=/; Secure; SameSite=Strict; Max-Age=3600`);
    expect(st).toBe(`${STATE_COOKIE}=${encodeState(state)}; Path=/; Secure; SameSite=Lax; Max-Age=3600`);
    expect(csrf).not.toContain("HttpOnly"); // readable by afixo-web
    expect(st).not.toContain("HttpOnly");
  });

  it("never emits a negative Max-Age", () => {
    const [session] = sessionCookies({ sealed: "S", csrf: "C", state }, 1_000_000 + 10);
    expect(session).toContain("Max-Age=0");
  });
});

describe("state cookie", () => {
  it("round-trips as base64url JSON", () => {
    const state: StateCookie = { sub: "sub_1", handle: "valentin", roles: ["subject"], exp: 123 };
    const encoded = encodeState(state);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(JSON.parse(atob(encoded.replace(/-/g, "+").replace(/_/g, "/")))).toEqual(state);
    expect(decodeState(encoded)).toEqual(state);
  });

  it("rejects garbage and wrong shapes", () => {
    expect(decodeState(undefined)).toBeNull();
    expect(decodeState("")).toBeNull();
    expect(decodeState("!!!")).toBeNull();
    expect(decodeState(btoa("[1,2]"))).toBeNull();
    expect(decodeState(btoa(JSON.stringify({ sub: 1, handle: "x", roles: [], exp: 1 })))).toBeNull();
    expect(decodeState(btoa(JSON.stringify({ sub: "s", handle: "x", roles: "subject", exp: 1 })))).toBeNull();
  });
});

describe("newCsrfToken", () => {
  it("is 32 random bytes as base64url", () => {
    const a = newCsrfToken();
    const b = newCsrfToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
  });
});
