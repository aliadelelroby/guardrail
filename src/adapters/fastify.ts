/**
 * Fastify adapter for Guardrail
 * @module adapters/fastify
 */

import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import { buildQuotaRules } from "../utils/quota-builder";
import { resolveProtectOptions, formatDenialResponse } from "../utils/adapter-utils";
import type { GuardrailConfig, ProtectOptions, AdapterOptions, QuotaConfig } from "../types/index";

/**
 * Fastify-specific hook options
 */
export interface FastifyGuardrailOptions extends GuardrailConfig, AdapterOptions<any> {}

/**
 * Internal helper to create Fastify preHandler hook
 */
function createFastifyHook(config: Partial<FastifyGuardrailOptions> = {}) {
  const guardrail = new Guardrail(config);

  return async (request: any, reply: any, options: ProtectOptions = {}) => {
    try {
      // 1. Resolve Dynamic Options from Request
      const protectOptions = resolveProtectOptions(request, config, options);

      // 2. Evaluate Protection
      const webRequest = Guardrail.toWebRequest(request.raw || request);
      const decision = await guardrail.protect(webRequest, protectOptions);

      // 3. Set standard headers
      const headers = Guardrail.getSecurityHeaders(decision);
      for (const [key, value] of Object.entries(headers)) {
        reply.header(key, value);
      }

      // 4. Handle Denial
      if (decision.isDenied()) {
        const { status, body } = formatDenialResponse(decision);
        reply.code(status).send(body);
        return;
      }

      // 5. Success - Attach decision to request
      request.guardrail = decision;
    } catch (error) {
      console.error("[Guardrail Fastify] Hook error:", error);
      // Fail open for hook stability
    }
  };
}

/**
 * Fastify adapter for Guardrail
 */
export const guardrailFastify = Object.assign(
  (config: Partial<FastifyGuardrailOptions> = {}) => createFastifyHook(config),
  {
    /**
     * Standard API protection preset
     */
    api: (overrides: Partial<FastifyGuardrailOptions> = {}) =>
      createFastifyHook({ ...GuardrailPresets.api(), ...overrides }),

    /**
     * Web application protection preset
     */
    web: (overrides: Partial<FastifyGuardrailOptions> = {}) =>
      createFastifyHook({ ...GuardrailPresets.web(), ...overrides }),

    /**
     * Strict protection preset
     */
    strict: (overrides: Partial<FastifyGuardrailOptions> = {}) =>
      createFastifyHook({ ...GuardrailPresets.strict(), ...overrides }),

    /**
     * Quota-based protection for SaaS apps
     */
    quota: (quotaConfig: QuotaConfig, overrides: Partial<FastifyGuardrailOptions> = {}) =>
      createFastifyHook({
        ...overrides,
        rules: [...(overrides.rules || []), ...buildQuotaRules(quotaConfig)],
      }),

    /** Alias for quota */
    subscription: (quotaConfig: QuotaConfig, overrides: Partial<FastifyGuardrailOptions> = {}) =>
      guardrailFastify.quota(quotaConfig, overrides),
  }
);

export { Guardrail } from "../core/guardrail";
export { window, bucket, bot, email, shield, filter } from "../rules/index";
export type * from "../types/index";
