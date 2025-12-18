/**
 * Shared utilities for framework adapters
 * @module utils/adapter-utils
 */

import type { Decision, ProtectOptions, AdapterOptions } from "../types/index";

/**
 * Resolves ProtectOptions from a request using provided extractors
 * @param req - The framework-specific request object
 * @param config - Adapter configuration containing extractors
 * @param baseOptions - Optional base options to merge with
 * @returns Resolved ProtectOptions
 */
export function resolveProtectOptions<T>(
  req: T,
  config: AdapterOptions<T>,
  baseOptions: ProtectOptions = {}
): ProtectOptions {
  const options: ProtectOptions = { ...baseOptions };

  if (!options.userId && config.userExtractor) {
    options.userId = config.userExtractor(req);
  }
  if (!options.email && config.emailExtractor) {
    options.email = config.emailExtractor(req);
  }
  if (!options.requested && config.tokensExtractor) {
    options.requested = config.tokensExtractor(req);
  }
  if (config.metadataExtractor) {
    const metadata = config.metadataExtractor(req);
    if (metadata) {
      options.metadata = { ...(options.metadata || {}), ...metadata };
    }
  }

  return options;
}

/**
 * Formats a standardized denial response for any framework
 * @param decision - The Guardrail decision
 * @returns An object with status and body
 */
export function formatDenialResponse(decision: Decision): { status: number; body: any } {
  const isRateLimit = decision.reason.isRateLimit() || decision.reason.isQuota();

  if (isRateLimit) {
    return {
      status: 429,
      body: {
        error: "Rate limit exceeded",
        message: "Too many requests. Please try again later.",
        remaining: decision.reason.getRemaining() ?? 0,
        reset: decision.results.find((r) => r.reset)?.reset,
      },
    };
  }

  if (decision.reason.isBot()) {
    return {
      status: 403,
      body: {
        error: "Forbidden",
        message: "Automated access is restricted.",
      },
    };
  }

  if (decision.reason.isShield()) {
    return {
      status: 403,
      body: {
        error: "Forbidden",
        message: "Potential security threat detected.",
      },
    };
  }

  if (decision.reason.isFilter()) {
    const filterResult = decision.results.find(
      (r) => r.rule === "filter" && r.conclusion === "DENY"
    );
    return {
      status: 403,
      body: {
        error: "Forbidden",
        message:
          filterResult?.reason === "FILTER"
            ? "Access restricted from your location or network."
            : "Request denied by filter policy.",
      },
    };
  }

  return {
    status: 403,
    body: {
      error: "Forbidden",
      message: "Request denied by security policy.",
    },
  };
}
