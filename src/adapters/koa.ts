/**
 * Koa adapter for Guardrail
 * @module adapters/koa
 */

import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import type { GuardrailConfig, ProtectOptions } from "../types/index";

/**
 * Internal helper to create Koa middleware
 */
function createKoaMiddleware(config: Partial<GuardrailConfig> = {}) {
  const guardrail = new Guardrail(config);

  return async (ctx: any, next: () => Promise<void>, options?: ProtectOptions) => {
    const webRequest = Guardrail.toWebRequest(ctx.req);
    const decision = await guardrail.protect(webRequest, options);

    // Set standard headers
    const headers = Guardrail.getSecurityHeaders(decision);
    for (const [key, value] of Object.entries(headers)) {
      ctx.set(key, value);
    }

    if (decision.isDenied()) {
      if (decision.reason.isRateLimit() || decision.reason.isQuota()) {
        ctx.status = 429;
        ctx.body = {
          error: "Rate limit exceeded",
          message: "Too many requests. Please try again later.",
          remaining: decision.reason.getRemaining() ?? 0,
        };
        return;
      }

      ctx.status = 403;
      ctx.body = {
        error: "Forbidden",
        message: "Request denied by security policy.",
        reason: decision.reason,
      };
      return;
    }

    ctx.state.guardrail = decision;
    await next();
  };
}

/**
 * Koa adapter for Guardrail
 */
export const guardrailKoa = Object.assign(
  (config: Partial<GuardrailConfig> = {}) => createKoaMiddleware(config),
  {
    api: (overrides: Partial<GuardrailConfig> = {}) =>
      createKoaMiddleware({ ...GuardrailPresets.api(), ...overrides }),
    web: (overrides: Partial<GuardrailConfig> = {}) =>
      createKoaMiddleware({ ...GuardrailPresets.web(), ...overrides }),
    strict: (overrides: Partial<GuardrailConfig> = {}) =>
      createKoaMiddleware({ ...GuardrailPresets.strict(), ...overrides }),
  }
);
