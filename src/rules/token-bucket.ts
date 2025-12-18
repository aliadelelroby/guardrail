/**
 * Token bucket rate limiting algorithm implementation
 * @module rules/token-bucket
 */

import type {
  TokenBucketConfig,
  RuleResult,
  DecisionConclusion,
  StorageAdapter,
} from "../types/index";
import { parseInterval } from "../utils/time";
import { generateFingerprint } from "../utils/fingerprint";

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
   * @param characteristics - Request characteristics for key generation
   * @param requested - Number of tokens requested (default: 1)
   * @returns Promise resolving to rule result
   */
  async evaluate(
    characteristics: Record<string, string | number | undefined>,
    requested: number = 1
  ): Promise<RuleResult> {
    const fingerprint = generateFingerprint(this.config.characteristics, characteristics);
    const key = `token-bucket:${fingerprint}`;

    const intervalMs = parseInterval(this.config.interval);
    const now = Date.now();

    const stateStr = await this.storage.get(key);
    let state: TokenBucketState;

    if (stateStr) {
      state = JSON.parse(stateStr);
    } else {
      state = {
        tokens: this.config.capacity,
        lastRefill: now,
      };
    }

    const timePassed = now - state.lastRefill;
    const refills = Math.floor(timePassed / intervalMs);
    const tokensToAdd = refills * this.config.refillRate;

    if (tokensToAdd > 0) {
      state.tokens = Math.min(this.config.capacity, state.tokens + tokensToAdd);
      state.lastRefill = now - (timePassed % intervalMs);
    }

    const conclusion: DecisionConclusion = state.tokens >= requested ? "ALLOW" : "DENY";

    if (conclusion === "ALLOW") {
      state.tokens -= requested;
      await this.storage.set(key, JSON.stringify(state), intervalMs * 2);
    }

    const remaining = Math.max(0, state.tokens);
    const reset = now + intervalMs;

    const result: RuleResult = {
      rule: "tokenBucket",
      conclusion,
      reason: conclusion === "DENY" ? "QUOTA" : undefined,
      remaining,
      reset,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }
}
