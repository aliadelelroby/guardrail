import { describe, it, expect, beforeEach } from "vitest";
import { TokenBucketRule } from "./token-bucket";
import { tokenBucket } from "./index";
import { MemoryStorage } from "../storage/memory";

describe("TokenBucketRule", () => {
  let storage: MemoryStorage;
  let rule: TokenBucketRule;

  beforeEach(() => {
    storage = new MemoryStorage();
    rule = new TokenBucketRule(
      tokenBucket({
        characteristics: ["userId"],
        refillRate: 100,
        interval: "1h",
        capacity: 500,
      }),
      storage
    );
  });

  it("should allow requests when tokens available", async () => {
    const characteristics = { userId: "user1" };

    const result = await rule.evaluate(characteristics, 200);

    expect(result.conclusion).toBe("ALLOW");
    expect(result.remaining).toBe(300);
  });

  it("should deny requests when tokens insufficient", async () => {
    const characteristics = { userId: "user1" };

    await rule.evaluate(characteristics, 300);
    const result = await rule.evaluate(characteristics, 300);

    expect(result.conclusion).toBe("DENY");
    expect(result.reason).toBe("QUOTA");
    expect(result.remaining).toBe(200);
  });

  it("should track different users separately", async () => {
    const user1 = { userId: "user1" };
    const user2 = { userId: "user2" };

    await rule.evaluate(user1, 500); // Exhaust user1's quota
    const result = await rule.evaluate(user2, 200); // Should work for user2

    expect(result.conclusion).toBe("ALLOW");
  });

  it("should handle default requested amount", async () => {
    const characteristics = { userId: "user1" };

    const result = await rule.evaluate(characteristics);

    expect(result.conclusion).toBe("ALLOW");
    expect(result.remaining).toBe(499);
  });

  it("should allow in DRY_RUN mode", async () => {
    const dryRunRule = new TokenBucketRule(
      tokenBucket({
        characteristics: ["userId"],
        refillRate: 100,
        interval: "1h",
        capacity: 1,
        mode: "DRY_RUN",
      }),
      storage
    );

    const characteristics = { userId: "user1" };

    await dryRunRule.evaluate(characteristics, 100);
    const result = await dryRunRule.evaluate(characteristics, 100);

    expect(result.conclusion).toBe("ALLOW");
  });
});
