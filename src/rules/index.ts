/**
 * Rule factory functions for easy rule creation
 * Re-exports rule factory functions and classes from individual rule modules
 * @module rules/index
 */

// Export rule classes
export { BotDetectionRule, detectBot } from "./bot-detection";
export type { BotDetectionResult, BotDetectionRuleConfig } from "./bot-detection";

export { ShieldRule, shield } from "./shield";
export type { ShieldRuleConfig, ShieldCategory, ShieldDetectionResult } from "./shield";

export { EmailValidationRule, validateEmail } from "./email-validation";
export type { 
  EmailValidationRuleConfig, 
  EmailValidationResult,
} from "./email-validation";

export { SlidingWindowRule } from "./sliding-window";
export { TokenBucketRule } from "./token-bucket";
export { FilterRule } from "./filter";

// Re-export factory functions for rate limiting and filter
import type {
  SlidingWindowConfig,
  TokenBucketConfig,
  FilterConfig,
} from "../types/index";

/**
 * Creates a sliding window rate limiting rule
 * @param config - Sliding window configuration
 * @returns Sliding window rule configuration
 */
export function slidingWindow(
  config: Omit<SlidingWindowConfig, "type" | "mode"> & { mode?: SlidingWindowConfig["mode"] }
): SlidingWindowConfig {
  return {
    type: "slidingWindow",
    mode: config.mode ?? "LIVE",
    interval: config.interval,
    max: config.max,
    characteristics: config.characteristics ?? ["ip.src"],
  };
}

/**
 * Creates a token bucket rate limiting rule
 * @param config - Token bucket configuration
 * @returns Token bucket rule configuration
 */
export function tokenBucket(
  config: Omit<TokenBucketConfig, "type" | "mode"> & { mode?: TokenBucketConfig["mode"] }
): TokenBucketConfig {
  return {
    type: "tokenBucket",
    mode: config.mode ?? "LIVE",
    characteristics: config.characteristics,
    refillRate: config.refillRate,
    interval: config.interval,
    capacity: config.capacity,
  };
}

/**
 * Creates a filter rule
 * @param config - Filter configuration
 * @returns Filter rule configuration
 */
export function filter(
  config: Omit<FilterConfig, "type" | "mode"> & { mode?: FilterConfig["mode"] }
): FilterConfig {
  return {
    type: "filter",
    mode: config.mode ?? "LIVE",
    allow: config.allow,
    deny: config.deny,
    characteristics: config.characteristics,
  };
}
