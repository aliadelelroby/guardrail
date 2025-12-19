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
        limit: max,
        reset: result.reset,
      };
      return this.config.mode === "DRY_RUN" ? { ...ruleResult, conclusion: "ALLOW" } : ruleResult;
    }

    // 2. Optimized fallback for generic storage using time-bucketed counters
    // This is more memory-efficient than storing all timestamps
    // Use optimistic locking to prevent race conditions
    const maxRetries = 5;
    let retries = 0;
    let state: WindowState;
    let now = Date.now();
    let count = 0;
    let conclusion: DecisionConclusion = "DENY";

    // Use time buckets (1 second granularity) for better memory efficiency
    const bucketSize = 1000; // 1 second buckets

    interface WindowState {
      buckets: Map<number, number>; // bucket timestamp -> count
      lastCleanup: number;
    }

    while (retries < maxRetries) {
      const stateKey = `${key}:state`;
      const stateStr = await this.storage.get(stateKey);

      if (stateStr) {
        try {
          const parsed = safeJsonParse<{ buckets: Array<[number, number]>; lastCleanup: number }>(
            stateStr
          );
          state = {
            buckets: new Map(parsed.buckets),
            lastCleanup: parsed.lastCleanup || now,
          };
        } catch {
          state = { buckets: new Map(), lastCleanup: now };
        }
      } else {
        state = { buckets: new Map(), lastCleanup: now };
      }

      // Re-read timestamp to ensure consistency
      now = Date.now();
      const currentWindowStart = now - intervalMs;

      // Cleanup old buckets periodically (every 10% of window or when needed)
      const cutoff = Math.floor(currentWindowStart / bucketSize) * bucketSize;
      for (const [bucketTime] of state.buckets.entries()) {
        if (bucketTime < cutoff) {
          state.buckets.delete(bucketTime);
        }
      }
      // Update cleanup time if we cleaned up or if it's been too long
      if (state.buckets.size === 0 || now - state.lastCleanup > intervalMs * 0.1) {
        state.lastCleanup = now;
      }

      // Count requests in current window
      count = 0;
      const currentBucket = Math.floor(now / bucketSize) * bucketSize;
      const oldestBucket = Math.floor(currentWindowStart / bucketSize) * bucketSize;

      for (const [bucketTime, bucketCount] of state.buckets.entries()) {
        if (bucketTime >= oldestBucket && bucketTime <= currentBucket) {
          count += bucketCount;
        }
      }

      conclusion = count < max ? "ALLOW" : "DENY";

      if (conclusion === "ALLOW") {
        // Increment current bucket
        const currentCount = state.buckets.get(currentBucket) || 0;
        state.buckets.set(currentBucket, currentCount + 1);
        count += 1;

        // Store state (convert Map to array for JSON serialization)
        const bucketsArray = Array.from(state.buckets.entries());
        const newStateStr = JSON.stringify({
          buckets: bucketsArray,
          lastCleanup: state.lastCleanup,
        });

        // Optimistic update: verify state hasn't changed
        const currentStateStr = await this.storage.get(stateKey);
        if (currentStateStr === stateStr) {
          // State hasn't changed, safe to update
          await this.storage.set(stateKey, newStateStr, intervalMs * 2);
          break; // Success, exit retry loop
        } else {
          // State changed, retry
          retries++;
          if (retries >= maxRetries) {
            // After max retries, use current state but don't update
            // This is a fallback to prevent infinite loops
            if (currentStateStr) {
              try {
                const parsed = safeJsonParse<{
                  buckets: Array<[number, number]>;
                  lastCleanup: number;
                }>(currentStateStr);
                state = {
                  buckets: new Map(parsed.buckets),
                  lastCleanup: parsed.lastCleanup || now,
                };
              } catch {
                // Keep current state
              }
            }
            break;
          }
          continue;
        }
      } else {
        // DENY - no state update needed, safe to exit
        break;
      }
    }

    const remaining = Math.max(0, max - count);
    const reset = now + intervalMs;

    const result: RuleResult = {
      rule: "slidingWindow",
      conclusion,
      reason: conclusion === "DENY" ? "RATE_LIMIT" : undefined,
      remaining,
      limit: max,
      reset,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }
}
