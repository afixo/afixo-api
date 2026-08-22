/**
 * `Env` is the global interface that `wrangler types` generates into
 * worker-configuration.d.ts from wrangler.jsonc:
 *
 *   vars     ORIGIN_URL, ALLOWED_ORIGINS
 *   secrets  SESSION_KEY, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET   (from `secrets.required`)
 *
 * Re-exported here so modules import it explicitly instead of relying on the ambient global.
 */
type GeneratedEnv = Env;
export type { GeneratedEnv as Env };

let cached: { raw: string; origins: Set<string> } | undefined;

/**
 * `ALLOWED_ORIGINS` is comma-separated. Each entry is normalised to a bare
 * origin (`scheme://host[:port]`, lowercase host, no path) so that it compares
 * exactly against `new URL(request.headers.get("Origin")).origin`.
 * Entries that are not valid URLs are dropped — with a warning, once per isolate.
 */
export function parseAllowedOrigins(raw: string | undefined): ReadonlySet<string> {
  const text = raw ?? "";
  if (cached && cached.raw === text) return cached.origins;
  const origins = new Set<string>();
  for (const entry of text.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    try {
      const origin = new URL(trimmed).origin;
      if (origin === "null") throw new Error("opaque origin");
      origins.add(origin);
    } catch {
      console.warn(`ALLOWED_ORIGINS: ignoring invalid entry ${JSON.stringify(trimmed)}`);
    }
  }
  cached = { raw: text, origins };
  return origins;
}
