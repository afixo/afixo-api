import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/** Test-only values, not secrets. SESSION_KEY is bytes 0x00..0x1f as base64url. */
const TEST_SECRETS = {
  SESSION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  CF_ACCESS_CLIENT_ID: "test-access-client-id",
  CF_ACCESS_CLIENT_SECRET: "test-access-client-secret",
};

// wrangler.jsonc lists these under `secrets.required`. The plugin runs wrangler's config loader,
// which looks for them in .dev.vars / .env / process.env and warns when they are absent. Tests
// must not depend on a developer's .dev.vars, so they are provided here (and again below as
// explicit bindings, which is what the Worker actually sees).
for (const [name, value] of Object.entries(TEST_SECRETS)) process.env[name] = value;

/**
 * Tests run inside workerd (Miniflare) with the real wrangler.jsonc, so the
 * same crypto, Request/Response and fetch semantics as production apply.
 * `miniflare.bindings` overrides the vars and supplies the secrets.
 */
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ORIGIN_URL: "http://origin.test",
          ALLOWED_ORIGINS: "https://afixo.io, http://localhost:4321",
          ...TEST_SECRETS,
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
