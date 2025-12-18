/**
 * Rule factory functions for easy rule creation
 * Re-exports rule factory functions and classes from individual rule modules
 * @module rules/index
 */

import { detectBot as botFactory } from "./bot-detection";
import { validateEmail as emailFactory } from "./email-validation";

// Export rule classes
export { BotDetectionRule } from "./bot-detection";
export type { BotDetectionResult, BotDetectionRuleConfig } from "./bot-detection";

export { ShieldRule, shield } from "./shield";
export type { ShieldRuleConfig, ShieldCategory, ShieldDetectionResult } from "./shield";

export { EmailValidationRule } from "./email-validation";
export type { EmailValidationRuleConfig, EmailValidationResult } from "./email-validation";

export { SlidingWindowRule } from "./sliding-window";
export { TokenBucketRule } from "./token-bucket";
export { FilterRule } from "./filter";

// Re-export factory functions for rate limiting and filter
import type { SlidingWindowConfig, TokenBucketConfig, FilterConfig } from "../types/index";

/**
 * Creates a sliding window rate limiting rule
 * @param config - Sliding window configuration
 * @returns Sliding window rule configuration
 */
export function window(
  config: Omit<SlidingWindowConfig, "type" | "mode"> & {
    mode?: SlidingWindowConfig["mode"];
    errorStrategy?: SlidingWindowConfig["errorStrategy"];
  }
): SlidingWindowConfig {
  return {
    type: "slidingWindow",
    mode: config.mode ?? "LIVE",
    errorStrategy: config.errorStrategy,
    interval: config.interval,
    max: config.max,
    by: config.by ?? ["ip.src"],
  };
}

/**
 * Creates a token bucket rate limiting rule
 * @param config - Token bucket configuration
 * @returns Token bucket rule configuration
 */
export function bucket(
  config: Omit<TokenBucketConfig, "type" | "mode"> & {
    mode?: TokenBucketConfig["mode"];
    errorStrategy?: TokenBucketConfig["errorStrategy"];
  }
): TokenBucketConfig {
  return {
    type: "tokenBucket",
    mode: config.mode ?? "LIVE",
    errorStrategy: config.errorStrategy,
    by: config.by ?? ["ip.src"],
    refillRate: config.refillRate,
    interval: config.interval,
    capacity: config.capacity,
  };
}

/**
 * Creates a bot detection rule
 */
export function bot(config: Parameters<typeof botFactory>[0] = {}): ReturnType<typeof botFactory> {
  return botFactory(config);
}

/**
 * Creates an email validation rule
 */
export function email(config: Parameters<typeof emailFactory>[0]): ReturnType<typeof emailFactory> {
  return emailFactory(config);
}

/**
 * Creates a filter rule
 * @param config - Filter configuration
 * @returns Filter rule configuration
 */
export function filter(
  config: Omit<FilterConfig, "type" | "mode"> & {
    mode?: FilterConfig["mode"];
    errorStrategy?: FilterConfig["errorStrategy"];
  }
): FilterConfig {
  return {
    type: "filter",
    mode: config.mode ?? "LIVE",
    errorStrategy: config.errorStrategy,
    allow: config.allow,
    deny: config.deny,
    by: config.by,
  };
}
