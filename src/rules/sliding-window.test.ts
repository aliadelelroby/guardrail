import { describe, it, expect, beforeEach } from "vitest";
import { SlidingWindowRule } from "./sliding-window";
import { window } from "./index";
import { MemoryStorage } from "../storage/memory";

describe("SlidingWindowRule", () => {
  let storage: MemoryStorage;
  let rule: SlidingWindowRule;

  beforeEach(() => {
    storage = new MemoryStorage();
    rule = new SlidingWindowRule(
      window({
        interval: "1m",
        max: 3,
        by: ["ip.src"],
      }),
      storage
    );
  });

  it("should allow requests within limit", async () => {
    const context = {
      characteristics: { "ip.src": "1.2.3.4" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    const result1 = await rule.evaluate(context);
    const result2 = await rule.evaluate(context);
    const result3 = await rule.evaluate(context);

    expect(result1.conclusion).toBe("ALLOW");
    expect(result2.conclusion).toBe("ALLOW");
    expect(result3.conclusion).toBe("ALLOW");
  });

  it("should deny requests exceeding limit", async () => {
    const context = {
      characteristics: { "ip.src": "1.2.3.4" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    await rule.evaluate(context);
    await rule.evaluate(context);
    await rule.evaluate(context);
    const result4 = await rule.evaluate(context);

    expect(result4.conclusion).toBe("DENY");
    expect(result4.reason).toBe("RATE_LIMIT");
    expect(result4.remaining).toBe(0);
  });

  it("should track different IPs separately", async () => {
    const context1 = {
      characteristics: { "ip.src": "1.2.3.4" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;
    const context2 = {
      characteristics: { "ip.src": "5.6.7.8" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    await rule.evaluate(context1);
    await rule.evaluate(context1);
    await rule.evaluate(context1);
    await rule.evaluate(context1); // Should be denied for IP1

    const result = await rule.evaluate(context2); // Should be allowed for IP2

    expect(result.conclusion).toBe("ALLOW");
  });

  it("should return remaining count", async () => {
    const context = {
      characteristics: { "ip.src": "1.2.3.4" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    const result1 = await rule.evaluate(context);
    expect(result1.remaining).toBe(2);

    const result2 = await rule.evaluate(context);
    expect(result2.remaining).toBe(1);

    const result3 = await rule.evaluate(context);
    expect(result3.remaining).toBe(0);
  });

  it("should allow in DRY_RUN mode", async () => {
    const dryRunRule = new SlidingWindowRule(
      window({ interval: "1m", max: 1, mode: "DRY_RUN" }),
      storage
    );

    const context = {
      characteristics: { "ip.src": "1.2.3.4" },
      options: {},
      metadata: {},
      ip: {} as any,
    } as any;

    await dryRunRule.evaluate(context);
    const result = await dryRunRule.evaluate(context);

    expect(result.conclusion).toBe("ALLOW");
  });
});
