import { describe, it, expect, beforeEach } from "vitest";
import { SlidingWindowRule } from "./sliding-window";
import { slidingWindow } from "./index";
import { MemoryStorage } from "../storage/memory";

describe("SlidingWindowRule", () => {
  let storage: MemoryStorage;
  let rule: SlidingWindowRule;

  beforeEach(() => {
    storage = new MemoryStorage();
    rule = new SlidingWindowRule(
      slidingWindow({
        interval: "1m",
        max: 3,
        characteristics: ["ip.src"],
      }),
      storage
    );
  });

  it("should allow requests within limit", async () => {
    const characteristics = { "ip.src": "1.2.3.4" };

    const result1 = await rule.evaluate(characteristics);
    const result2 = await rule.evaluate(characteristics);
    const result3 = await rule.evaluate(characteristics);

    expect(result1.conclusion).toBe("ALLOW");
    expect(result2.conclusion).toBe("ALLOW");
    expect(result3.conclusion).toBe("ALLOW");
  });

  it("should deny requests exceeding limit", async () => {
    const characteristics = { "ip.src": "1.2.3.4" };

    await rule.evaluate(characteristics);
    await rule.evaluate(characteristics);
    await rule.evaluate(characteristics);
    const result4 = await rule.evaluate(characteristics);

    expect(result4.conclusion).toBe("DENY");
    expect(result4.reason).toBe("RATE_LIMIT");
    expect(result4.remaining).toBe(0);
  });

  it("should track different IPs separately", async () => {
    const ip1 = { "ip.src": "1.2.3.4" };
    const ip2 = { "ip.src": "5.6.7.8" };

    await rule.evaluate(ip1);
    await rule.evaluate(ip1);
    await rule.evaluate(ip1);
    await rule.evaluate(ip1); // Should be denied for IP1

    const result = await rule.evaluate(ip2); // Should be allowed for IP2

    expect(result.conclusion).toBe("ALLOW");
  });

  it("should return remaining count", async () => {
    const characteristics = { "ip.src": "1.2.3.4" };

    const result1 = await rule.evaluate(characteristics);
    expect(result1.remaining).toBe(2);

    const result2 = await rule.evaluate(characteristics);
    expect(result2.remaining).toBe(1);

    const result3 = await rule.evaluate(characteristics);
    expect(result3.remaining).toBe(0);
  });

  it("should allow in DRY_RUN mode", async () => {
    const dryRunRule = new SlidingWindowRule(
      slidingWindow({ interval: "1m", max: 1, mode: "DRY_RUN" }),
      storage
    );

    const characteristics = { "ip.src": "1.2.3.4" };

    await dryRunRule.evaluate(characteristics);
    const result = await dryRunRule.evaluate(characteristics);

    expect(result.conclusion).toBe("ALLOW");
  });
});
