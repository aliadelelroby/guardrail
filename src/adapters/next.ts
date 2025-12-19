/**
 * Next.js adapter for Guardrail
 * @module adapters/next
 */

import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import { buildQuotaRules } from "../utils/quota-builder";
import { resolveProtectOptions, formatDenialResponse } from "../utils/adapter-utils";
import type {
  GuardrailConfig,
  ProtectOptions,
  Decision,
  AdapterOptions,
  QuotaConfig,
} from "../types/index";

/**
 * Next.js Request type interface for Middleware/App Router
 */
interface NextRequest {
  url: string;
  method: string;
  headers: Headers;
  body: ReadableStream | null;
}

/**
 * Next.js-specific options
 */
export interface NextGuardrailOptions extends GuardrailConfig, AdapterOptions<any> {}

/**
 * Internal helper to create Next.js protection object
 */
function createNextAdapter(config: Partial<NextGuardrailOptions> = {}) {
  const guardrail = new Guardrail(config);

  const protect = async (request: any, options?: ProtectOptions): Promise<Decision> => {
    const webRequest = Guardrail.toWebRequest(request);
    const protectOptions = resolveProtectOptions(request, config, options);
    return guardrail.protect(webRequest, protectOptions);
  };

  return {
    protect,
    /**
     * Next.js Middleware helper
     */
    middleware: (overrides: Partial<NextGuardrailOptions> = {}) => {
      const instance = new Guardrail({ ...config, ...overrides });
      return async (req: NextRequest) => {
        const protectOptions = resolveProtectOptions(req, { ...config, ...overrides });
        const decision = await instance.protect(Guardrail.toWebRequest(req), protectOptions);

        if (decision.isDenied()) {
          const headers = Guardrail.getSecurityHeaders(decision);
          const { status, body } = formatDenialResponse(decision);

          return new Response(JSON.stringify(body), {
            status,
            headers: { ...headers, "Content-Type": "application/json" },
          });
        }
        return null; // Continue
      };
    },
  };
}

/**
 * Next.js adapter for Guardrail
 */
export const guardrailNext = Object.assign(
  (config: Partial<NextGuardrailOptions> = {}) => createNextAdapter(config),
  {
    /**
     * Standard API protection preset
     */
    api: (overrides: Partial<NextGuardrailOptions> = {}) =>
      createNextAdapter({ ...GuardrailPresets.api(), ...overrides }),

    /**
     * Web application protection preset
     */
    web: (overrides: Partial<NextGuardrailOptions> = {}) =>
      createNextAdapter({ ...GuardrailPresets.web(), ...overrides }),

    /**
     * Strict protection preset
     */
    strict: (overrides: Partial<NextGuardrailOptions> = {}) =>
      createNextAdapter({ ...GuardrailPresets.strict(), ...overrides }),

    /**
     * Quota-based protection for SaaS apps
     */
    quota: (quotaConfig: QuotaConfig, overrides: Partial<NextGuardrailOptions> = {}) =>
      createNextAdapter({
        ...overrides,
        rules: [...(overrides.rules || []), ...buildQuotaRules(quotaConfig)],
      }),

    /** Alias for quota */
    subscription: (quotaConfig: QuotaConfig, overrides: Partial<NextGuardrailOptions> = {}) =>
      guardrailNext.quota(quotaConfig, overrides),
  }
);

/**
 * Higher-order function to wrap Next.js API routes (Pages Router)
 */
export function protect(
  handler: (req: any, res: any) => Promise<void> | void,
  config: Partial<NextGuardrailOptions> = {}
) {
  const adapter = createNextAdapter(config);

  return async (req: any, res: any) => {
    const decision = await adapter.protect(req);

    const headers = Guardrail.getSecurityHeaders(decision);
    for (const [key, value] of Object.entries(headers)) {
      if (res.setHeader) {res.setHeader(key, value);}
    }

    if (decision.isDenied()) {
      const isRateLimit = decision.reason.isRateLimit() || decision.reason.isQuota();
      res.status(isRateLimit ? 429 : 403).json({
        error: isRateLimit ? "Rate limit exceeded" : "Forbidden",
        message: isRateLimit ? "Too many requests" : "Denied by security policy",
        reason: decision.reason,
      });
      return;
    }

    req.guardrail = decision;
    return handler(req, res);
  };
}

export { Guardrail } from "../core/guardrail";
export { window, bucket, bot, email, shield, filter } from "../rules/index";
export type * from "../types/index";
