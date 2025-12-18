/**
 * Sliding window rate limiting algorithm implementation
 */

import type {
  SlidingWindowConfig,
  RuleResult,
  DecisionConclusion,
  StorageAdapter,
} from "../types/index";
import { parseInterval } from "../utils/time";
import { generateFingerprint } from "../utils/fingerprint";

export class SlidingWindowRule {
  constructor(
    private config: SlidingWindowConfig,
    private storage: StorageAdapter
  ) {}

  async evaluate(
    characteristics: Record<string, string | number | undefined>
  ): Promise<RuleResult> {
    const fingerprint = generateFingerprint(
      this.config.characteristics || ["ip.src"],
      characteristics
    );
    const key = `sliding-window:${fingerprint}`;
    const intervalMs = parseInterval(this.config.interval);
    const now = Date.now();
    const windowStart = now - intervalMs;

    const timestampsStr = await this.storage.get(key);
    let timestamps: number[] = [];

    if (timestampsStr) {
      timestamps = JSON.parse(timestampsStr);
    }

    timestamps = timestamps.filter((ts) => ts > windowStart);

    const conclusion: DecisionConclusion =
      timestamps.length < this.config.max ? "ALLOW" : "DENY";

    if (conclusion === "ALLOW") {
      timestamps.push(now);
      await this.storage.set(
        key,
        JSON.stringify(timestamps),
        intervalMs * 2
      );
    }

    const remaining = Math.max(0, this.config.max - timestamps.length);
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
