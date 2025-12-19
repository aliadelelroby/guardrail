import type { QuotaConfig, GuardrailRule } from "../types/index";
import { window } from "../rules/index";

/**
 * Shared utility to build stacked quota rules
 */
export function buildQuotaRules(config: QuotaConfig): GuardrailRule[] {
  const rules: GuardrailRule[] = [];
  const by = config.by || ["userId"];

  if (config.burst) {
    rules.push(
      window({
        by,
        max: config.burst,
        interval: config.burstInterval || "1m",
      })
    );
  }

  if (config.daily) {
    rules.push(
      window({
        by,
        max: config.daily,
        interval: "1d",
      })
    );
  }

  if (config.monthly) {
    rules.push(
      window({
        by,
        max: config.monthly,
        interval: "1mo",
      })
    );
  }

  return rules;
}
