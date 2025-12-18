/**
 * Express.js adapter for Guardrail
 * @module adapters/express
 */

import type { Request as ExpressRequest, Response as ExpressResponse, NextFunction } from "express";
import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import type { GuardrailConfig, ProtectOptions } from "../types/index";
import "./express.d";

/**
 * Internal helper to create Express middleware
 */
function createExpressMiddleware(config: Partial<GuardrailConfig> = {}) {
  const guardrail = new Guardrail(config);

  return async (
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction,
    options?: ProtectOptions
  ): Promise<void> => {
    const webRequest = Guardrail.toWebRequest(req);
    const decision = await guardrail.protect(webRequest, options);

    // Set standard headers
    const headers = Guardrail.getSecurityHeaders(decision);
    for (const [key, value] of Object.entries(headers)) {
      res.set(key, value);
    }

    if (decision.isDenied()) {
      if (decision.reason.isRateLimit() || decision.reason.isQuota()) {
        res.status(429).json({
          error: "Rate limit exceeded",
          message: "Too many requests. Please try again later.",
          remaining: decision.reason.getRemaining() ?? 0,
        });
        return;
      }

      const isBot = decision.reason.isBot();
      const isShield = decision.reason.isShield();

      res.status(403).json({
        error: "Forbidden",
        message: isBot
          ? "Automated access is restricted."
          : isShield
            ? "Potential security threat detected."
            : "Request denied by security policy.",
        reason: decision.reason,
      });
      return;
    }

    req.guardrail = decision;
    next();
  };
}

/**
 * Express.js adapter for Guardrail
 */
export const guardrailExpress = Object.assign(
  (config: Partial<GuardrailConfig> = {}) => createExpressMiddleware(config),
  {
    api: (overrides: Partial<GuardrailConfig> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.api(), ...overrides }),
    web: (overrides: Partial<GuardrailConfig> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.web(), ...overrides }),
    strict: (overrides: Partial<GuardrailConfig> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.strict(), ...overrides }),
    auth: (overrides: Partial<GuardrailConfig> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.auth(), ...overrides }),
    payment: (overrides: Partial<GuardrailConfig> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.payment(), ...overrides }),
    ai: (overrides: Partial<GuardrailConfig> = {}) =>
      createExpressMiddleware({ ...GuardrailPresets.ai(), ...overrides }),
  }
);

export { Guardrail } from "../core/guardrail";
export type * from "../types/index";
