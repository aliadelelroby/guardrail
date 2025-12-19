/**
 * Express.js adapter for Guardrail
 * @module adapters/express
 */

import type { Request as ExpressRequest, Response as ExpressResponse, NextFunction } from "express";
import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import { buildQuotaRules } from "../utils/quota-builder";
import { resolveProtectOptions, formatDenialResponse } from "../utils/adapter-utils";
import type { GuardrailConfig, ProtectOptions, AdapterOptions, QuotaConfig } from "../types/index";
import "./express.d";

/**
 * Express-specific middleware options
 */
export interface ExpressGuardrailOptions extends GuardrailConfig, AdapterOptions<ExpressRequest> {}

/**
 * Internal helper to create Express middleware
 */
function createExpressMiddleware(config: Partial<ExpressGuardrailOptions> = {}) {
  const guardrail = new Guardrail(config);

  return async (
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction,
    options: ProtectOptions = {}
  ): Promise<void> => {
    try {
      // 1. Resolve Dynamic Options from Request
      const protectOptions = resolveProtectOptions(req, config, options);

      // 2. Evaluate Protection
      const webRequest = Guardrail.toWebRequest(req);
      const decision = await guardrail.protect(webRequest, protectOptions);

      // 3. Set standard headers
      const headers = Guardrail.getSecurityHeaders(decision);
      for (const [key, value] of Object.entries(headers)) {
        res.set(key, value);
      }

      // 4. Handle Denial
      if (decision.isDenied()) {
        const { status, body } = formatDenialResponse(decision);
        res.status(status).json(body);
        return;
      }

      // 5. Success - Attach decision to request
      req.guardrail = decision;
      next();
    } catch (error) {
      console.error("[Guardrail Express] Middleware error:", error);
      // Fail open by default for middleware stability
      next();
    }
  };
}

/**
 * Express.js adapter for Guardrail
 */
export const guardrailExpress = Object.assign(
  (config: Partial<ExpressGuardrailOptions> = {}) => createExpressMiddleware(config),
  {
    /**
     * Standard API protection preset
     */
    api: (overrides: Partial<ExpressGuardrailOptions> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.api(), ...overrides }),

    /**
     * Web application protection preset
     */
    web: (overrides: Partial<ExpressGuardrailOptions> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.web(), ...overrides }),

    /**
     * Strict protection preset
     */
    strict: (overrides: Partial<ExpressGuardrailOptions> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.strict(), ...overrides }),

    /**
     * Quota-based protection for SaaS apps
     */
    quota: (quotaConfig: QuotaConfig, overrides: Partial<ExpressGuardrailOptions> = {}) =>
      createExpressMiddleware({
        ...overrides,
        rules: [...(overrides.rules || []), ...buildQuotaRules(quotaConfig)],
      }),

    /** Alias for quota */
    subscription: (quotaConfig: QuotaConfig, overrides: Partial<ExpressGuardrailOptions> = {}) =>
      guardrailExpress.quota(quotaConfig, overrides),
  }
);

export { Guardrail } from "../core/guardrail";
export { window, bucket, bot, email, shield, filter } from "../rules/index";
export type * from "../types/index";
