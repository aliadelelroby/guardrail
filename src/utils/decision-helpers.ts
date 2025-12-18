/**
 * Helper utilities for Decision objects
 * @module utils/decision-helpers
 */

import type { DenialReason, RuleResult } from "../types/index";

/**
 * Decision reason helper class with type checking methods
 */
export class DecisionReason {
  private readonly rateLimitResult?: RuleResult;

  /**
   * Creates a new DecisionReason instance
   * @param reason - Denial reason if request was denied
   * @param rateLimitResult - Rate limit result if applicable
   */
  constructor(
    private readonly reason?: DenialReason,
    rateLimitResult?: RuleResult
  ) {
    this.rateLimitResult = rateLimitResult;
  }

  /**
   * Checks if denial is due to rate limiting
   * @returns True if reason is RATE_LIMIT
   */
  isRateLimit(): boolean {
    return this.reason === "RATE_LIMIT";
  }

  /**
   * Checks if denial is due to bot detection
   * @returns True if reason is BOT
   */
  isBot(): boolean {
    return this.reason === "BOT";
  }

  /**
   * Checks if denial is due to email validation
   * @returns True if reason is EMAIL
   */
  isEmail(): boolean {
    return this.reason === "EMAIL";
  }

  /**
   * Checks if denial is due to shield protection
   * @returns True if reason is SHIELD
   */
  isShield(): boolean {
    return this.reason === "SHIELD";
  }

  /**
   * Checks if denial is due to filter rule
   * @returns True if reason is FILTER
   */
  isFilter(): boolean {
    return this.reason === "FILTER";
  }

  /**
   * Checks if denial is due to quota exceeded
   * @returns True if reason is QUOTA
   */
  isQuota(): boolean {
    return this.reason === "QUOTA";
  }

  /**
   * Gets remaining quota/rate limit
   * @returns Remaining count or undefined
   */
  getRemaining(): number | undefined {
    return this.rateLimitResult?.remaining;
  }
}

/**
 * Finds rate limit result from rule results
 * @param results - Array of rule results
 * @returns Rate limit result or undefined
 */
export function findRateLimitResult(results: RuleResult[]): RuleResult | undefined {
  return results.find((r) => r.reason === "RATE_LIMIT" || r.reason === "QUOTA");
}

/**
 * Finds a result by rule name
 * @param results - Array of rule results
 * @param ruleName - Rule name to find
 * @returns Matching rule result or undefined
 */
export function findResultByRule(results: RuleResult[], ruleName: string): RuleResult | undefined {
  return results.find((r) => r.rule === ruleName);
}
