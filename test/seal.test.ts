import { describe, expect, it } from "vitest";
import { b64urlDecode, b64urlEncode } from "../src/b64url";
import { SEAL_VERSION, seal, unseal, type SessionPayload } from "../src/seal";

const KEY = b64urlEncode(new Uint8Array(32).fill(7));
const OTHER_KEY = b64urlEncode(new Uint8Array(32).fill(9));
const payload: SessionPayload = { a: "access-token", r: "refresh-token", e: 1_800_000_000 };

describe("seal / unseal", () => {
  it("round-trips the payload", async () => {
    const token = await seal(payload, KEY);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/); // base64url, no padding
    expect(await unseal(token, KEY)).toEqual(payload);
  });

  it("uses a fresh IV every time", async () => {
    const a = await seal(payload, KEY);
    const b = await seal(payload, KEY);
    expect(a).not.toBe(b);
    expect(await unseal(b, KEY)).toEqual(payload);
  });

  it("wire format is 0x01 ‖ iv(12) ‖ ciphertext ‖ tag(16)", async () => {
    const bytes = b64urlDecode(await seal(payload, KEY))!;
    expect(bytes[0]).toBe(SEAL_VERSION);
    expect(bytes.byteLength).toBe(1 + 12 + JSON.stringify(payload).length + 16);
  });

  it("returns null when the ciphertext is tampered with", async () => {
    const token = await seal(payload, KEY);
    const i = 20; // inside the ciphertext, away from the version/IV prefix and the final partial char
    const flipped = token[i] === "A" ? "B" : "A";
    const tampered = token.slice(0, i) + flipped + token.slice(i + 1);
    expect(await unseal(tampered, KEY)).toBeNull();
  });

  it("returns null under the wrong key", async () => {
    const token = await seal(payload, KEY);
    expect(await unseal(token, OTHER_KEY)).toBeNull();
  });

  it("returns null when truncated", async () => {
    const token = await seal(payload, KEY);
    expect(await unseal(token.slice(0, -8), KEY)).toBeNull();
    expect(await unseal(token.slice(0, 10), KEY)).toBeNull();
    expect(await unseal("", KEY)).toBeNull();
  });

  it("checks the version byte", async () => {
    const bytes = b64urlDecode(await seal(payload, KEY))!;
    bytes[0] = 0x02;
    expect(await unseal(b64urlEncode(bytes), KEY)).toBeNull();
  });

  it("returns null for anything that is not base64url", async () => {
    expect(await unseal("not base64!!", KEY)).toBeNull();
    expect(await unseal("YWJj=", KEY)).toBeNull(); // padding is not part of the format
  });

  it("returns null when the plaintext is not a session payload", async () => {
    // Seal something with the right key but the wrong shape, then try to open it as a session.
    const bogus = await seal({ a: "", r: "x", e: 1 }, KEY);
    expect(await unseal(bogus, KEY)).toBeNull();
  });

  it("refuses a key that is not 32 bytes (seal) and stays silent about it (unseal)", async () => {
    const shortKey = b64urlEncode(new Uint8Array(16));
    await expect(seal(payload, shortKey)).rejects.toThrow(/32 bytes/);
    const token = await seal(payload, KEY);
    expect(await unseal(token, shortKey)).toBeNull();
  });
});
