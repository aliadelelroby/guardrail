import { describe, it, expect } from "vitest";
import { DecisionReason, findRateLimitResult, findResultByRule } from "./decision-helpers";
import type { RuleResult } from "../types/index";

describe("DecisionReason", () => {
  it("should identify rate limit reasons", () => {
    const reason = new DecisionReason("RATE_LIMIT");

    expect(reason.isRateLimit()).toBe(true);
    expect(reason.isBot()).toBe(false);
  });

  it("should identify bot reasons", () => {
    const reason = new DecisionReason("BOT");

    expect(reason.isBot()).toBe(true);
    expect(reason.isRateLimit()).toBe(false);
  });

  it("should identify email reasons", () => {
    const reason = new DecisionReason("EMAIL");

    expect(reason.isEmail()).toBe(true);
  });

  it("should identify shield reasons", () => {
    const reason = new DecisionReason("SHIELD");

    expect(reason.isShield()).toBe(true);
  });

  it("should identify filter reasons", () => {
    const reason = new DecisionReason("FILTER");

    expect(reason.isFilter()).toBe(true);
  });

  it("should identify quota reasons", () => {
    const reason = new DecisionReason("QUOTA");

    expect(reason.isQuota()).toBe(true);
  });

  it("should return remaining from rate limit result", () => {
    const rateLimitResult: RuleResult = {
      rule: "slidingWindow",
      conclusion: "DENY",
      reason: "RATE_LIMIT",
      remaining: 2,
    };

    const reason = new DecisionReason("RATE_LIMIT", rateLimitResult);

    expect(reason.getRemaining()).toBe(2);
  });
});

describe("findRateLimitResult", () => {
  it("should find rate limit results", () => {
    const results: RuleResult[] = [
      { rule: "shield", conclusion: "ALLOW" },
      { rule: "slidingWindow", conclusion: "DENY", reason: "RATE_LIMIT", remaining: 3 },
    ];

    const result = findRateLimitResult(results);

    expect(result).toBeDefined();
    expect(result?.rule).toBe("slidingWindow");
  });

  it("should find quota results", () => {
    const results: RuleResult[] = [
      { rule: "tokenBucket", conclusion: "DENY", reason: "QUOTA", remaining: 100 },
    ];

    const result = findRateLimitResult(results);

    expect(result).toBeDefined();
    expect(result?.rule).toBe("tokenBucket");
  });
});

describe("findResultByRule", () => {
  it("should find result by rule name", () => {
    const results: RuleResult[] = [
      { rule: "shield", conclusion: "ALLOW" },
      { rule: "detectBot", conclusion: "DENY", reason: "BOT" },
    ];

    const result = findResultByRule(results, "detectBot");

    expect(result).toBeDefined();
    expect(result?.rule).toBe("detectBot");
    expect(result?.reason).toBe("BOT");
  });

  it("should return undefined if rule not found", () => {
    const results: RuleResult[] = [
      { rule: "shield", conclusion: "ALLOW" },
    ];

    const result = findResultByRule(results, "nonexistent");

    expect(result).toBeUndefined();
  });
});
