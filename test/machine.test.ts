/**
 * Machine mode: requests on api.afixo.io (a custom domain on afixo-web, handed
 * to this Worker with the original URL). Requesters, not browsers — the
 * requester's own Authorization passes through, no cookies, no CSRF, a strict
 * route allowlist, and only ever the machine listener.
 */
import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";
import { parseMachineHosts } from "../src/env";
import { machineRouteAllowed } from "../src/handlers/machine";
import { mockOrigin, type OriginMock } from "./helpers/origin";

const MACHINE = "https://api.afixo.io";
const CONSOLE = "https://afixo.io";

function call(base: string, path: string, init?: RequestInit): Promise<Response> {
  return exports.default.fetch(new Request(`${base}${path}`, { ...init, redirect: "manual" }));
}
const api = (path: string, init?: RequestInit) => call(MACHINE, path, init);

let origin: OriginMock | undefined;
afterEach(() => {
  origin?.restore();
  origin = undefined;
});

describe("parseMachineHosts", () => {
  it("normalises hostnames and drops junk", () => {
    expect([...parseMachineHosts("api.afixo.io, API.Localhost:8787 ,, https://x.test/path, bad host")]).toEqual([
      "api.afixo.io",
      "api.localhost",
      "x.test",
    ]);
    expect(parseMachineHosts(undefined).size).toBe(0);
    expect(parseMachineHosts("").size).toBe(0);
  });
});

describe("machineRouteAllowed", () => {
  it("allows exactly the machine surface, plus OPTIONS on it", () => {
    const allowed: [string, string][] = [
      ["POST", "/oauth/token"],
      ["OPTIONS", "/oauth/token"],
      ["GET", "/v1/disclose/alice"],
      ["get", "/v1/disclose/alice"],
      ["OPTIONS", "/v1/disclose/alice"],
      ["GET", "/v1/purposes"],
      ["OPTIONS", "/v1/purposes"],
      ["GET", "/v1/health"],
      ["OPTIONS", "/v1/health"],
    ];
    for (const [m, p] of allowed) expect(machineRouteAllowed(m, p), `${m} ${p}`).toBe(true);

    const denied: [string, string][] = [
      ["GET", "/oauth/token"],
      ["DELETE", "/oauth/token"],
      ["POST", "/v1/disclose/alice"],
      ["HEAD", "/v1/health"],
      ["GET", "/v1/disclose"],
      ["GET", "/v1/personas"],
      ["OPTIONS", "/v1/personas"],
      ["POST", "/v1/auth/refresh"],
      ["GET", "/v1/auth/github/login"],
      ["GET", "/api/v1/health"],
      ["GET", "/api/v1/auth/me"],
      ["GET", "/"],
    ];
    for (const [m, p] of denied) expect(machineRouteAllowed(m, p), `${m} ${p}`).toBe(false);
  });
});

describe("machine mode", () => {
  it("forwards GET /v1/disclose/* to MACHINE_ORIGIN_URL with the requester's Authorization intact", async () => {
    const decision = { decision: "allow", persona: "work", fields: { email: "a@x.test" }, withheld: ["dob"], decision_id: "d1" };
    origin = mockOrigin(() =>
      Response.json(decision, {
        headers: { "access-control-allow-origin": "https://afixo.io", "set-cookie": "evil=1; Path=/" },
      }),
    );
    const res = await api("/v1/disclose/alice?purpose=shipping", {
      headers: {
        Authorization: "Bearer req_abc",
        Cookie: "__Host-afixo_session=whatever; __Host-afixo_csrf=x",
        "X-CSRF-Token": "x",
        "CF-Access-Client-Id": "forged",
        "CF-Access-Client-Secret": "forged",
        "X-Request-Id": "req-m1",
        Accept: "application/json",
      },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(decision);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://afixo.io");
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(res.headers.get("x-request-id")).toBe("req-m1");

    expect(origin.calls).toHaveLength(1);
    const sent = origin.calls[0]!.request;
    expect(sent.url).toBe(`${env.MACHINE_ORIGIN_URL}/v1/disclose/alice?purpose=shipping`);
    expect(sent.url.startsWith(env.ORIGIN_URL)).toBe(false);
    expect(sent.method).toBe("GET");
    expect(sent.redirect).toBe("manual");
    expect(sent.headers.get("authorization")).toBe("Bearer req_abc");
    expect(sent.headers.get("cookie")).toBeNull();
    expect(sent.headers.get("x-csrf-token")).toBeNull();
    expect(sent.headers.get("cf-access-client-id")).toBe(env.CF_ACCESS_CLIENT_ID);
    expect(sent.headers.get("cf-access-client-secret")).toBe(env.CF_ACCESS_CLIENT_SECRET);
    expect(sent.headers.get("x-request-id")).toBe("req-m1");
    expect(sent.headers.get("accept")).toBe("application/json");
  });

  it("forwards POST /oauth/token without an Origin header — no CSRF on this host", async () => {
    origin = mockOrigin(() => Response.json({ access_token: "tok", token_type: "Bearer", expires_in: 3600 }));
    const res = await api("/oauth/token", {
      method: "POST",
      body: "grant_type=client_credentials",
      headers: { "content-type": "application/x-www-form-urlencoded", Authorization: "Basic Y2xpZW50OnNlY3JldA==" },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });

    const sent = origin.calls[0]!;
    expect(sent.request.url).toBe(`${env.MACHINE_ORIGIN_URL}/oauth/token`);
    expect(sent.request.method).toBe("POST");
    expect(sent.request.headers.get("authorization")).toBe("Basic Y2xpZW50OnNlY3JldA==");
    expect(sent.request.headers.get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(sent.body).toBe("grant_type=client_credentials");
  });

  it("forwards CORS preflights on every allowed path", async () => {
    for (const path of ["/oauth/token", "/v1/disclose/alice", "/v1/purposes", "/v1/health"]) {
      origin?.restore();
      origin = mockOrigin(
        () =>
          new Response(null, {
            status: 204,
            headers: { "access-control-allow-origin": "https://afixo.io", "access-control-allow-methods": "GET, POST" },
          }),
      );
      const res = await api(path, {
        method: "OPTIONS",
        headers: { Origin: "https://afixo.io", "Access-Control-Request-Method": "POST" },
      });
      expect(res.status, path).toBe(204);
      expect(res.headers.get("access-control-allow-methods")).toBe("GET, POST");
      const sent = origin.calls[0]!.request;
      expect(sent.method).toBe("OPTIONS");
      expect(sent.url).toBe(`${env.MACHINE_ORIGIN_URL}${path}`);
      expect(sent.headers.get("origin")).toBe("https://afixo.io"); // the gateway needs it for CORS
      expect(sent.headers.get("access-control-request-method")).toBe("POST");
    }
  });

  it("forwards GET /v1/purposes and GET /v1/health", async () => {
    for (const path of ["/v1/purposes", "/v1/health"]) {
      origin?.restore();
      origin = mockOrigin(() => Response.json({ ok: path }));
      const res = await api(path);
      expect(res.status, path).toBe(200);
      expect(await res.json()).toEqual({ ok: path });
      expect(origin.calls[0]!.request.url).toBe(`${env.MACHINE_ORIGIN_URL}${path}`);
      expect(origin.calls[0]!.request.headers.get("authorization")).toBeNull();
    }
  });

  it("answers 404 for everything else without touching any origin", async () => {
    origin = mockOrigin(() => new Response("must not be called"));
    const cases: [string, string][] = [
      ["GET", "/v1/personas"],
      ["GET", "/api/v1/auth/me"],
      ["GET", "/api/v1/health"],
      ["POST", "/v1/auth/refresh"],
      ["GET", "/v1/auth/github/login"],
      ["POST", "/v1/disclose/alice"],
      ["HEAD", "/v1/health"],
      ["DELETE", "/oauth/token"],
      ["GET", "/oauth/token"],
      ["GET", "/v1/disclose"],
      ["GET", "/"],
    ];
    for (const [method, path] of cases) {
      const res = await api(path, { method, headers: { Authorization: "Bearer req_abc" } });
      expect(res.status, `${method} ${path}`).toBe(404);
      if (method !== "HEAD") expect(await res.json()).toEqual({ error: "not_found" });
    }
    expect(origin.calls).toHaveLength(0);
  });

  it("answers 502 origin_unreachable when the machine listener cannot be reached", async () => {
    origin = mockOrigin(() => {
      throw new TypeError("connect ECONNREFUSED");
    });
    const res = await api("/v1/health");
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "origin_unreachable" });
  });

  it("mints an X-Request-Id when the requester sends none", async () => {
    origin = mockOrigin(() => new Response("ok"));
    const res = await api("/v1/health");
    const id = res.headers.get("x-request-id");
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(origin.calls[0]!.request.headers.get("x-request-id")).toBe(id);
  });

  it("recognises every listed host, case-insensitively", async () => {
    origin = mockOrigin(() => new Response("ok"));
    expect((await call("https://API.AFIXO.IO", "/v1/health")).status).toBe(200);
    expect((await call("https://api.localhost", "/v1/health")).status).toBe(200);
    expect(origin.calls).toHaveLength(2);
    for (const c of origin.calls) expect(c.request.url).toBe(`${env.MACHINE_ORIGIN_URL}/v1/health`);
  });

  it("leaves console hosts under console rules", async () => {
    origin = mockOrigin(() => new Response("ok"));
    // the machine surface does not exist on a console host: 404 outside /api/, CSRF first under it
    expect((await call(CONSOLE, "/v1/health")).status).toBe(404);
    expect((await call(CONSOLE, "/oauth/token", { method: "POST" })).status).toBe(404);
    expect((await call(CONSOLE, "/api/oauth/token", { method: "POST" })).status).toBe(403); // no Origin
    expect((await call(CONSOLE, "/api/v1/disclose/alice", { headers: { Authorization: "Bearer req" } })).status).toBe(
      200,
    );
    expect(origin.calls).toHaveLength(1);
    expect(origin.calls[0]!.request.url).toBe(`${env.ORIGIN_URL}/v1/disclose/alice`);
    expect(origin.calls[0]!.request.headers.get("authorization")).toBeNull(); // console hop: the Worker owns auth
    origin.restore();
    origin = mockOrigin(() => new Response("ok"));
    // /api/* on a console host goes to the console listener, never the machine one
    expect((await call(CONSOLE, "/api/v1/health")).status).toBe(200);
    expect(origin.calls[0]!.request.url).toBe(`${env.ORIGIN_URL}/v1/health`);
  });
});
