/**
 * Sliding window rate limiting algorithm implementation
 */

import type {
  SlidingWindowConfig,
  RuleResult,
  DecisionConclusion,
  StorageAdapter,
  DecisionContext,
} from "../types/index";
import { parseInterval } from "../utils/time";
import { generateFingerprint } from "../utils/fingerprint";
import { resolveValue } from "../utils/resolver";
import { safeJsonParse } from "../utils/safe-json";

export class SlidingWindowRule {
  constructor(
    private config: SlidingWindowConfig,
    private storage: StorageAdapter
  ) {}

  async evaluate(context: DecisionContext): Promise<RuleResult> {
    const max = await resolveValue(this.config.max, context, 100);

    const fingerprint = generateFingerprint(this.config.by || ["ip.src"], context.characteristics);

    // Create a unique discriminator for this rule instance to prevent key collisions
    const discriminator = typeof this.config.max === "string" ? `:${this.config.max}` : "";

    const key = `sliding-window:${this.config.interval}${discriminator}:${fingerprint}`;
    const intervalMs = parseInterval(this.config.interval);

    // 1. Use optimized atomic sliding window if supported by storage
    if (this.storage instanceof Object && "slidingWindow" in this.storage) {
      const result = await (this.storage as any).slidingWindow(key, max, intervalMs);
      const ruleResult: RuleResult = {
        rule: "slidingWindow",
        conclusion: result.allowed ? "ALLOW" : "DENY",
        reason: result.allowed ? undefined : "RATE_LIMIT",
        remaining: result.remaining,
        reset: result.reset,
      };
      return this.config.mode === "DRY_RUN" ? { ...ruleResult, conclusion: "ALLOW" } : ruleResult;
    }

    // 2. Fallback to standard array-based implementation for generic storage
    const now = Date.now();
    const windowStart = now - intervalMs;

    const timestampsStr = await this.storage.get(key);
    let timestamps: number[] = [];

    if (timestampsStr) {
      try {
        timestamps = safeJsonParse<number[]>(timestampsStr);
      } catch {
        timestamps = [];
      }
    }

    timestamps = timestamps.filter((ts) => ts > windowStart);

    const conclusion: DecisionConclusion = timestamps.length < max ? "ALLOW" : "DENY";

    if (conclusion === "ALLOW") {
      timestamps.push(now);
      await this.storage.set(key, JSON.stringify(timestamps), intervalMs * 2);
    }

    const remaining = Math.max(0, max - timestamps.length);
    const reset = timestamps.length > 0 ? timestamps[0] + intervalMs : now + intervalMs;

    const result: RuleResult = {
      rule: "slidingWindow",
      conclusion,
      reason: conclusion === "DENY" ? "RATE_LIMIT" : undefined,
      remaining,
      reset,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }
}
