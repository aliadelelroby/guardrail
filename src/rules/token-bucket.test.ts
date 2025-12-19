import { describe, it, expect, beforeEach } from "vitest";
import { TokenBucketRule } from "./token-bucket";
import { bucket } from "./index";
import { MemoryStorage } from "../storage/memory";

describe("TokenBucketRule", () => {
  let storage: MemoryStorage;
  let rule: TokenBucketRule;

  beforeEach(() => {
    storage = new MemoryStorage();
    rule = new TokenBucketRule(
      bucket({
        by: ["userId"],
        refillRate: 100,
        interval: "1h",
        capacity: 500,
      }),
      storage
    );
  });

  it("should allow requests when tokens available", async () => {
    const context = {
      characteristics: { userId: "user1" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    const result = await rule.evaluate(context, 200);

    expect(result.conclusion).toBe("ALLOW");
    expect(result.remaining).toBe(300);
  });

  it("should deny requests when tokens insufficient", async () => {
    const context = {
      characteristics: { userId: "user1" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    await rule.evaluate(context, 300);
    const result = await rule.evaluate(context, 300);

    expect(result.conclusion).toBe("DENY");
    expect(result.reason).toBe("QUOTA");
    expect(result.remaining).toBe(200);
  });

  it("should track different users separately", async () => {
    const context1 = {
      characteristics: { userId: "user1" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;
    const context2 = {
      characteristics: { userId: "user2" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    await rule.evaluate(context1, 500); // Exhaust user1's quota
    const result = await rule.evaluate(context2, 200); // Should work for user2

    expect(result.conclusion).toBe("ALLOW");
  });

  it("should handle default requested amount", async () => {
    const context = {
      characteristics: { userId: "user1" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    const result = await rule.evaluate(context);

    expect(result.conclusion).toBe("ALLOW");
    expect(result.remaining).toBe(499);
  });

  it("should allow in DRY_RUN mode", async () => {
    const dryRunRule = new TokenBucketRule(
      bucket({
        by: ["userId"],
        refillRate: 100,
        interval: "1h",
        capacity: 1,
        mode: "DRY_RUN",
      }),
      storage
    );

    const context = {
      characteristics: { userId: "user1" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    await dryRunRule.evaluate(context, 100);
    const result = await dryRunRule.evaluate(context, 100);

    expect(result.conclusion).toBe("ALLOW");
  });
});
