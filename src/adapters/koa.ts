/**
 * Koa adapter for Guardrail
 * @module adapters/koa
 */

import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import { buildQuotaRules } from "../utils/quota-builder";
import { resolveProtectOptions, formatDenialResponse } from "../utils/adapter-utils";
import type { GuardrailConfig, ProtectOptions, AdapterOptions, QuotaConfig } from "../types/index";

/**
 * Koa-specific middleware options
 */
export interface KoaGuardrailOptions extends GuardrailConfig, AdapterOptions<any> {}

/**
 * Internal helper to create Koa middleware
 */
function createKoaMiddleware(config: Partial<KoaGuardrailOptions> = {}) {
  const guardrail = new Guardrail(config);

  return async (ctx: any, next: () => Promise<void>, options: ProtectOptions = {}) => {
    try {
      // 1. Resolve Dynamic Options from Request
      const protectOptions = resolveProtectOptions(ctx, config, options);

      // 2. Evaluate Protection
      const webRequest = Guardrail.toWebRequest(ctx.req);
      const decision = await guardrail.protect(webRequest, protectOptions);

      // 3. Set standard headers
      const headers = Guardrail.getSecurityHeaders(decision);
      for (const [key, value] of Object.entries(headers)) {
        ctx.set(key, value);
      }

      // 4. Handle Denial
      if (decision.isDenied()) {
        const { status, body } = formatDenialResponse(decision);
        ctx.status = status;
        ctx.body = body;
        return;
      }

      // 5. Success - Attach decision to state
      ctx.state.guardrail = decision;
      await next();
    } catch (error) {
      console.error("[Guardrail Koa] Middleware error:", error);
      // Fail open for middleware stability
      await next();
    }
  };
}

/**
 * Koa adapter for Guardrail
 */
export const guardrailKoa = Object.assign(
  (config: Partial<KoaGuardrailOptions> = {}) => createKoaMiddleware(config),
  {
    /**
     * Standard API protection preset
     */
    api: (overrides: Partial<KoaGuardrailOptions> = {}) =>
      createKoaMiddleware({ ...GuardrailPresets.api(), ...overrides }),

    /**
     * Web application protection preset
     */
    web: (overrides: Partial<KoaGuardrailOptions> = {}) =>
      createKoaMiddleware({ ...GuardrailPresets.web(), ...overrides }),

    /**
     * Strict protection preset
     */
    strict: (overrides: Partial<KoaGuardrailOptions> = {}) =>
      createKoaMiddleware({ ...GuardrailPresets.strict(), ...overrides }),

    /**
     * Quota-based protection for SaaS apps
     */
    quota: (quotaConfig: QuotaConfig, overrides: Partial<KoaGuardrailOptions> = {}) =>
      createKoaMiddleware({
        ...overrides,
        rules: [...(overrides.rules || []), ...buildQuotaRules(quotaConfig)],
      }),

    /** Alias for quota */
    subscription: (quotaConfig: QuotaConfig, overrides: Partial<KoaGuardrailOptions> = {}) =>
      guardrailKoa.quota(quotaConfig, overrides),
  }
);

export { Guardrail } from "../core/guardrail";
export { window, bucket, bot, email, shield, filter } from "../rules/index";
export type * from "../types/index";
