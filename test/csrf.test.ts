import { describe, expect, it } from "vitest";
import { csrfValid, isMutating, originAllowed, timingSafeEqual } from "../src/csrf";
import { parseAllowedOrigins } from "../src/env";

const allow = parseAllowedOrigins("https://afixo.io, https://www.afixo.io/ ,http://localhost:4321");

function post(headers: Record<string, string> = {}): Request {
  return new Request("https://afixo.io/api/v1/personas", { method: "POST", headers });
}

describe("isMutating", () => {
  it("exempts GET, HEAD and OPTIONS only", () => {
    for (const m of ["GET", "HEAD", "OPTIONS", "get"]) expect(isMutating(m)).toBe(false);
    for (const m of ["POST", "PUT", "PATCH", "DELETE", "post"]) expect(isMutating(m)).toBe(true);
  });
});

describe("parseAllowedOrigins", () => {
  it("normalises entries to bare origins and drops junk", () => {
    expect([...allow]).toEqual(["https://afixo.io", "https://www.afixo.io", "http://localhost:4321"]);
    expect([...parseAllowedOrigins("https://Afixo.IO/app/, nonsense, ,")]).toEqual(["https://afixo.io"]);
    expect(parseAllowedOrigins(undefined).size).toBe(0);
  });
});

describe("originAllowed", () => {
  it("accepts an allowlisted Origin", () => {
    expect(originAllowed(post({ Origin: "https://afixo.io" }), allow)).toBe(true);
    expect(originAllowed(post({ Origin: "http://localhost:4321" }), allow)).toBe(true);
  });

  it("rejects a missing Origin", () => {
    expect(originAllowed(post(), allow)).toBe(false);
  });

  it("rejects foreign, opaque and look-alike origins", () => {
    expect(originAllowed(post({ Origin: "https://evil.test" }), allow)).toBe(false);
    expect(originAllowed(post({ Origin: "null" }), allow)).toBe(false);
    expect(originAllowed(post({ Origin: "https://afixo.io.evil.test" }), allow)).toBe(false);
    expect(originAllowed(post({ Origin: "http://afixo.io" }), allow)).toBe(false); // scheme matters
    expect(originAllowed(post({ Origin: "https://afixo.io:8443" }), allow)).toBe(false); // port matters
    expect(originAllowed(post({ Origin: "garbage" }), allow)).toBe(false);
  });
});

describe("csrfValid", () => {
  it("requires header and cookie to match exactly", () => {
    expect(csrfValid("abc123", "abc123")).toBe(true);
    expect(csrfValid("abc123", "abc124")).toBe(false);
    expect(csrfValid("abc123", "abc1234")).toBe(false);
    expect(csrfValid(null, "abc123")).toBe(false);
    expect(csrfValid("abc123", undefined)).toBe(false);
    expect(csrfValid("", "")).toBe(false);
  });
});

describe("timingSafeEqual", () => {
  it("compares whole strings, including length", () => {
    expect(timingSafeEqual("", "")).toBe(true);
    expect(timingSafeEqual("a", "a")).toBe(true);
    expect(timingSafeEqual("a", "b")).toBe(false);
    expect(timingSafeEqual("abc", "ab")).toBe(false);
    expect(timingSafeEqual("ab", "abc")).toBe(false);
    expect(timingSafeEqual("héllo", "héllo")).toBe(true);
  });
});
