/**
 * Token bucket rate limiting algorithm implementation
 * @module rules/token-bucket
 */

import type {
  TokenBucketConfig,
  RuleResult,
  DecisionConclusion,
  StorageAdapter,
  DecisionContext,
} from "../types/index";
import { parseInterval } from "../utils/time";
import { generateFingerprint } from "../utils/fingerprint";
import { resolveValue } from "../utils/resolver";
import { safeJsonParse } from "../utils/safe-json";

/**
 * Token bucket state stored in storage
 */
interface TokenBucketState {
  tokens: number;
  lastRefill: number;
}

/**
 * Token bucket rate limiting rule implementation
 */
export class TokenBucketRule {
  /**
   * Creates a new TokenBucketRule instance
   * @param config - Token bucket configuration
   * @param storage - Storage adapter for state persistence
   */
  constructor(
    private readonly config: TokenBucketConfig,
    private readonly storage: StorageAdapter
  ) {}

  /**
   * Evaluates the token bucket rule
   * @param context - Decision context for dynamic value resolution
   * @param requested - Number of tokens requested (default: 1)
   * @returns Promise resolving to rule result
   */
  async evaluate(context: DecisionContext, requested: number = 1): Promise<RuleResult> {
    const capacity = await resolveValue(this.config.capacity, context, 100);
    const refillRate = await resolveValue(this.config.refillRate, context, 10);

    const fingerprint = generateFingerprint(this.config.by || ["ip.src"], context.characteristics);

    // Create a unique discriminator for this rule instance to prevent key collisions
    const discriminator =
      typeof this.config.capacity === "string" ? `:${this.config.capacity}` : "";

    const key = `token-bucket:${this.config.interval}${discriminator}:${fingerprint}`;
    const intervalMs = parseInterval(this.config.interval);

    // 1. Use optimized atomic token bucket if supported by storage
    if (this.storage instanceof Object && "tokenBucket" in this.storage) {
      const result = await (this.storage as any).tokenBucket(
        key,
        capacity,
        refillRate,
        intervalMs,
        requested
      );
      const ruleResult: RuleResult = {
        rule: "tokenBucket",
        conclusion: result.allowed ? "ALLOW" : "DENY",
        reason: result.allowed ? undefined : "QUOTA",
        remaining: result.remaining,
        limit: capacity,
        reset: result.reset,
      };
      return this.config.mode === "DRY_RUN" ? { ...ruleResult, conclusion: "ALLOW" } : ruleResult;
    }

    // 2. Fallback to standard implementation for generic storage
    // Use optimistic locking to prevent race conditions
    const maxRetries = 5;
    let retries = 0;
    let state: TokenBucketState = { tokens: capacity, lastRefill: Date.now() };
    let now = Date.now();
    let conclusion: DecisionConclusion = "DENY";

    while (retries < maxRetries) {
      const stateStr = await this.storage.get(key);

      if (stateStr) {
        try {
          state = safeJsonParse<TokenBucketState>(stateStr);
        } catch {
          state = { tokens: capacity, lastRefill: now };
        }
      } else {
        state = {
          tokens: capacity,
          lastRefill: now,
        };
      }

      // Re-read timestamp to ensure consistency
      now = Date.now();

      const timePassed = now - state.lastRefill;
      const refills = Math.floor(timePassed / intervalMs);
      const tokensToAdd = refills * refillRate;

      if (tokensToAdd > 0) {
        state.tokens = Math.min(capacity, state.tokens + tokensToAdd);
        state.lastRefill = now - (timePassed % intervalMs);
      }

      conclusion = state.tokens >= requested ? "ALLOW" : "DENY";

      if (conclusion === "ALLOW") {
        state.tokens -= requested;
        const newStateStr = JSON.stringify(state);

        // Optimistic update: verify state hasn't changed
        const currentStateStr = await this.storage.get(key);
        if (currentStateStr === stateStr) {
          // State hasn't changed, safe to update
          await this.storage.set(key, newStateStr, intervalMs * 2);
          break; // Success, exit retry loop
        } else {
          // State changed, retry
          retries++;
          if (retries >= maxRetries) {
            // After max retries, use current state but don't update
            // This is a fallback to prevent infinite loops
            const currentState = currentStateStr
              ? safeJsonParse<TokenBucketState>(currentStateStr)
              : { tokens: capacity, lastRefill: now };
            state = currentState;
            break;
          }
          continue;
        }
      } else {
        // DENY - no state update needed, safe to exit
        break;
      }
    }

    const remaining = Math.max(0, state.tokens);
    const reset = now + intervalMs;

    const result: RuleResult = {
      rule: "tokenBucket",
      conclusion,
      reason: conclusion === "DENY" ? "QUOTA" : undefined,
      remaining,
      limit: capacity,
      reset,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }
}
