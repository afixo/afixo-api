/**
 * Session sealing: AES-256-GCM over the JSON token pair, via WebCrypto.
 *
 * Wire format (DESIGN §3):  base64url( 0x01 ‖ iv(12) ‖ ciphertext ‖ tag(16) ), no padding.
 *
 * `unseal` answers null for every kind of failure — bad encoding, wrong
 * version, wrong key, truncation, tampering, malformed plaintext — so a caller
 * (and therefore a client) can never tell *why* a cookie was rejected.
 */
import { b64urlDecode, b64urlEncode } from "./b64url";

export const SEAL_VERSION = 0x01;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/** What lives inside `__Host-afixo_session`. */
export interface SessionPayload {
  /** access token (bearer sent to the origin) */
  a: string;
  /** refresh token (only ever sent to `POST /v1/auth/refresh`) */
  r: string;
  /** access-token expiry, unix seconds */
  e: number;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function importKey(keyB64url: string): Promise<CryptoKey> {
  let pending = keyCache.get(keyB64url);
  if (!pending) {
    pending = (async () => {
      const raw = b64urlDecode(keyB64url);
      if (!raw || raw.byteLength !== KEY_BYTES) {
        throw new Error(`SESSION_KEY must be base64url of exactly ${KEY_BYTES} bytes`);
      }
      return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    })();
    keyCache.set(keyB64url, pending);
    pending.catch(() => keyCache.delete(keyB64url));
  }
  return pending;
}

export async function seal(payload: SessionPayload, keyB64url: string): Promise<string> {
  const key = await importKey(keyB64url);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: TAG_BYTES * 8 }, key, plaintext),
  );
  const out = new Uint8Array(1 + IV_BYTES + sealed.byteLength);
  out[0] = SEAL_VERSION;
  out.set(iv, 1);
  out.set(sealed, 1 + IV_BYTES);
  return b64urlEncode(out);
}

export async function unseal(token: string, keyB64url: string): Promise<SessionPayload | null> {
  try {
    const bytes = b64urlDecode(token);
    if (!bytes || bytes.byteLength < 1 + IV_BYTES + TAG_BYTES) return null;
    if (bytes[0] !== SEAL_VERSION) return null;
    const key = await importKey(keyB64url);
    const iv = bytes.slice(1, 1 + IV_BYTES);
    const sealed = bytes.slice(1 + IV_BYTES);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: TAG_BYTES * 8 },
      key,
      sealed,
    );
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    return isSessionPayload(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isSessionPayload(value: unknown): value is SessionPayload {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v["a"] === "string" &&
    v["a"].length > 0 &&
    typeof v["r"] === "string" &&
    v["r"].length > 0 &&
    typeof v["e"] === "number" &&
    Number.isFinite(v["e"])
  );
}
