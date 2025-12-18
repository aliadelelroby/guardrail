/**
 * Custom rule plugin system
 * @module types/custom-rules
 */

import type { RuleResult, ProtectOptions } from "./index";

/**
 * Evaluation context for custom rules
 */
export interface CustomRuleContext {
  request: Request;
  ip: string;
  ipInfo: import("./index").IPInfo;
  characteristics: Record<string, string | number | undefined>;
  options: ProtectOptions;
}

/**
 * Custom rule interface
 */
export interface CustomRule {
  /**
   * Unique rule type identifier
   */
  type: string;

  /**
   * Rule mode
   */
  mode: import("./index").Mode;

  /**
   * Evaluates the custom rule
   * @param context - Evaluation context
   * @returns Promise resolving to rule result
   */
  evaluate(context: CustomRuleContext): Promise<RuleResult>;
}

/**
 * Custom rule factory function
 */
export type CustomRuleFactory = (config: Record<string, unknown>) => CustomRule;
