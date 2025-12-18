/**
 * Fastify adapter for Guardrail
 * @module adapters/fastify
 */

import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import type { GuardrailConfig, ProtectOptions } from "../types/index";

/**
 * Internal helper to create Fastify preHandler hook
 */
function createFastifyHook(config: Partial<GuardrailConfig> = {}) {
  const guardrail = new Guardrail(config);

  return async (request: any, reply: any, options?: ProtectOptions) => {
    const webRequest = Guardrail.toWebRequest(request.raw || request);
    const decision = await guardrail.protect(webRequest, options);

    // Set standard headers
    const headers = Guardrail.getSecurityHeaders(decision);
    for (const [key, value] of Object.entries(headers)) {
      reply.header(key, value);
    }

    if (decision.isDenied()) {
      if (decision.reason.isRateLimit() || decision.reason.isQuota()) {
        reply.code(429).send({
          error: "Rate limit exceeded",
          message: "Too many requests. Please try again later.",
          remaining: decision.reason.getRemaining() ?? 0,
        });
        return;
      }

      reply.code(403).send({
        error: "Forbidden",
        message: "Request denied by security policy.",
        reason: decision.reason,
      });
      return;
    }

    request.guardrail = decision;
  };
}

/**
 * Fastify adapter for Guardrail
 */
export const guardrailFastify = Object.assign(
  (config: Partial<GuardrailConfig> = {}) => createFastifyHook(config),
  {
    api: (overrides: Partial<GuardrailConfig> = {}) =>
      createFastifyHook({ ...GuardrailPresets.api(), ...overrides }),
    web: (overrides: Partial<GuardrailConfig> = {}) =>
      createFastifyHook({ ...GuardrailPresets.web(), ...overrides }),
    strict: (overrides: Partial<GuardrailConfig> = {}) =>
      createFastifyHook({ ...GuardrailPresets.strict(), ...overrides }),
  }
);
