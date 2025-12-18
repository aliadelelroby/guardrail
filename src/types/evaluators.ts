/**
 * Type definitions for rule evaluators
 * @module types/evaluators
 */

import type { RuleResult, IPInfo } from "./index";

/**
 * Base interface for all rule evaluators
 */
export interface RuleEvaluator {
  /**
   * Evaluates the rule and returns a result
   * @param args - Variable arguments depending on rule type
   * @returns Promise resolving to rule evaluation result
   */
  evaluate(...args: unknown[]): Promise<RuleResult>;
}

/**
 * Token bucket rate limiting evaluator
 */
export interface TokenBucketEvaluator extends RuleEvaluator {
  /**
   * Evaluates token bucket rule
   * @param characteristics - Request characteristics for key generation
   * @param requested - Number of tokens requested (default: 1)
   * @returns Promise resolving to rule result
   */
  evaluate(
    characteristics: Record<string, string | number | undefined>,
    requested?: number
  ): Promise<RuleResult>;
}

/**
 * Sliding window rate limiting evaluator
 */
export interface SlidingWindowEvaluator extends RuleEvaluator {
  /**
   * Evaluates sliding window rule
   * @param characteristics - Request characteristics for key generation
   * @returns Promise resolving to rule result
   */
  evaluate(
    characteristics: Record<string, string | number | undefined>
  ): Promise<RuleResult>;
}

/**
 * Bot detection evaluator
 */
export interface BotDetectionEvaluator extends RuleEvaluator {
  /**
   * Evaluates bot detection rule
   * @param request - Web API Request object
   * @returns Promise resolving to rule result
   */
  evaluate(request: Request): Promise<RuleResult>;
}

/**
 * Email validation evaluator
 */
export interface EmailValidationEvaluator extends RuleEvaluator {
  /**
   * Evaluates email validation rule
   * @param email - Email address to validate
   * @returns Promise resolving to rule result
   */
  evaluate(email: string): Promise<RuleResult>;
}

/**
 * Shield protection evaluator
 */
export interface ShieldEvaluator extends RuleEvaluator {
  /**
   * Evaluates shield protection rule
   * @param request - Web API Request object
   * @returns Promise resolving to rule result
   */
  evaluate(request: Request): Promise<RuleResult>;
}

/**
 * Filter rule evaluator
 */
export interface FilterEvaluator extends RuleEvaluator {
  /**
   * Evaluates filter rule
   * @param request - Web API Request object
   * @param ipInfo - IP geolocation information
   * @param characteristics - Request characteristics
   * @returns Promise resolving to rule result
   */
  evaluate(
    request: Request,
    ipInfo: IPInfo,
    characteristics: Record<string, string | number | undefined>
  ): Promise<RuleResult>;
}

/**
 * Union type of all rule evaluators
 */
export type AnyRuleEvaluator =
  | TokenBucketEvaluator
  | SlidingWindowEvaluator
  | BotDetectionEvaluator
  | EmailValidationEvaluator
  | ShieldEvaluator
  | FilterEvaluator;
