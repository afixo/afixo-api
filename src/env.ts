/**
 * `Env` is the global interface that `wrangler types` generates into
 * worker-configuration.d.ts from wrangler.jsonc:
 *
 *   vars     ORIGIN_URL, ALLOWED_ORIGINS            (console mode: the dashboard's /api/*)
 *            MACHINE_HOSTS, MACHINE_ORIGIN_URL      (machine mode: api.afixo.io)
 *   secrets  SESSION_KEY, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET   (from `secrets.required`)
 *
 * Re-exported here so modules import it explicitly instead of relying on the ambient global.
 */
type GeneratedEnv = Env;
export type { GeneratedEnv as Env };

let originsCache: { raw: string; origins: Set<string> } | undefined;

/**
 * `ALLOWED_ORIGINS` is comma-separated. Each entry is normalised to a bare
 * origin (`scheme://host[:port]`, lowercase host, no path) so that it compares
 * exactly against `new URL(request.headers.get("Origin")).origin`.
 * Entries that are not valid URLs are dropped — with a warning, once per isolate.
 */
export function parseAllowedOrigins(raw: string | undefined): ReadonlySet<string> {
  const text = raw ?? "";
  if (originsCache && originsCache.raw === text) return originsCache.origins;
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
  originsCache = { raw: text, origins };
  return origins;
}

let hostsCache: { raw: string; hosts: Set<string> } | undefined;

/**
 * `MACHINE_HOSTS` is comma-separated. A request whose URL hostname is listed
 * runs in machine mode (handlers/machine.ts); every other hostname is console
 * mode. Entries are hostnames: case is ignored, a stray scheme or port is
 * dropped, anything unparsable is dropped with a warning.
 */
export function parseMachineHosts(raw: string | undefined): ReadonlySet<string> {
  const text = raw ?? "";
  if (hostsCache && hostsCache.raw === text) return hostsCache.hosts;
  const hosts = new Set<string>();
  for (const entry of text.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    try {
      const url = trimmed.includes("://") ? new URL(trimmed) : new URL(`http://${trimmed}`);
      if (url.hostname) hosts.add(url.hostname);
    } catch {
      console.warn(`MACHINE_HOSTS: ignoring invalid entry ${JSON.stringify(trimmed)}`);
    }
  }
  hostsCache = { raw: text, hosts };
  return hosts;
}
