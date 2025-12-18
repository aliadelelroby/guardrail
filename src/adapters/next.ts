/**
 * Next.js adapter for Guardrail
 * @module adapters/next
 */

import { Guardrail } from "../core/guardrail";
import { GuardrailPresets } from "../core/presets";
import type { GuardrailConfig, ProtectOptions, Decision } from "../types/index";

/**
 * Next.js Request type interface
 */
interface NextRequest {
  url: string;
  method: string;
  headers: Headers;
  body: ReadableStream | null;
}

/**
 * Internal helper to create Next.js protection object
 */
function createNextAdapter(config: Partial<GuardrailConfig> = {}) {
  const guardrail = new Guardrail(config);

  const protect = async (request: NextRequest, options?: ProtectOptions): Promise<Decision> => {
    const webRequest = Guardrail.toWebRequest(request);
    return guardrail.protect(webRequest, options);
  };

  return {
    protect,
    /**
     * Next.js Middleware helper
     */
    middleware: (overrides: Partial<GuardrailConfig> = {}) => {
      const instance = new Guardrail({ ...config, ...overrides });
      return async (req: NextRequest) => {
        const decision = await instance.protect(Guardrail.toWebRequest(req));

        if (decision.isDenied()) {
          const headers = Guardrail.getSecurityHeaders(decision);
          return new Response(
            JSON.stringify({
              error: decision.reason.isRateLimit() ? "Rate limit exceeded" : "Forbidden",
              message: decision.reason.isRateLimit()
                ? "Too many requests"
                : "Request denied by security policy",
            }),
            {
              status: decision.reason.isRateLimit() ? 429 : 403,
              headers: { ...headers, "Content-Type": "application/json" },
            }
          );
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
  (config: Partial<GuardrailConfig> = {}) => createNextAdapter(config),
  {
    api: (overrides: Partial<GuardrailConfig> = {}) =>
      createNextAdapter({ ...GuardrailPresets.api(), ...overrides }),
    web: (overrides: Partial<GuardrailConfig> = {}) =>
      createNextAdapter({ ...GuardrailPresets.web(), ...overrides }),
    strict: (overrides: Partial<GuardrailConfig> = {}) =>
      createNextAdapter({ ...GuardrailPresets.strict(), ...overrides }),
  }
);

/**
 * Higher-order function to wrap Next.js API routes
 */
export function withGuardrail(
  handler: (req: any, res: any) => Promise<void> | void,
  config: Partial<GuardrailConfig> = {}
) {
  const guardrail = new Guardrail(config);

  return async (req: any, res: any) => {
    const webRequest = Guardrail.toWebRequest(req);
    const decision = await guardrail.protect(webRequest);

    const headers = Guardrail.getSecurityHeaders(decision);
    for (const [key, value] of Object.entries(headers)) {
      if (res.setHeader) res.setHeader(key, value);
    }

    if (decision.isDenied()) {
      res.status(decision.reason.isRateLimit() ? 429 : 403).json({
        error: "Denied",
        reason: decision.reason,
      });
      return;
    }

    req.guardrail = decision;
    return handler(req, res);
  };
}

export { Guardrail } from "../core/guardrail";
export type * from "../types/index";
