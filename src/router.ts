/** Minimal matcher: method ("*" = any) + exact path or path prefix → handler. First registered match wins. */
import type { Env } from "./env";

export interface RouteContext {
  request: Request;
  env: Env;
  ctx: ExecutionContext;
  url: URL;
  requestId: string;
  /** parsed `Cookie` header */
  cookies: ReadonlyMap<string, string>;
}

export type Handler = (c: RouteContext) => Response | Promise<Response>;

interface Route {
  method: string;
  path: string;
  prefix: boolean;
  handler: Handler;
}

export class Router {
  readonly #routes: Route[] = [];

  /** exact path match */
  on(method: string, path: string, handler: Handler): this {
    this.#routes.push({ method: method.toUpperCase(), path, prefix: false, handler });
    return this;
  }

  /** `pathname.startsWith(path)` match */
  prefix(method: string, path: string, handler: Handler): this {
    this.#routes.push({ method: method.toUpperCase(), path, prefix: true, handler });
    return this;
  }

  match(method: string, pathname: string): Handler | undefined {
    const m = method.toUpperCase();
    for (const route of this.#routes) {
      if (route.method !== "*" && route.method !== m) continue;
      if (route.prefix ? pathname.startsWith(route.path) : pathname === route.path) return route.handler;
    }
    return undefined;
  }
}
