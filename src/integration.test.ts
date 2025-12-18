import { describe, it, expect } from "vitest";
import { guardrail } from "./index";
import { shield, detectBot, slidingWindow, tokenBucket, validateEmail } from "./rules/index";
import { MemoryStorage } from "./storage/memory";

describe("Integration Tests", () => {
  it("should work with multiple rules", async () => {
    const gr = guardrail({
      rules: [
        shield(),
        detectBot({ allow: [] }),
        slidingWindow({ interval: "1m", max: 5 }),
      ],
    });

    const request = new Request("https://example.com/api", {
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const decision = await gr.protect(request);

    expect(decision.isAllowed()).toBe(true);
  });

  it("should deny on first rule violation", async () => {
    const gr = guardrail({
      rules: [
        shield(),
        detectBot({ allow: [] }),
      ],
    });

    const request = new Request("https://example.com/api?q=SELECT * FROM users", {
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const decision = await gr.protect(request);

    expect(decision.isDenied()).toBe(true);
    expect(decision.reason.isShield()).toBe(true);
  });

  it("should handle email validation", async () => {
    const gr = guardrail({
      rules: [
        validateEmail({
          block: ["DISPOSABLE", "INVALID"],
        }),
      ],
    });

    const request = new Request("https://example.com/api");
    const decision = await gr.protect(request, {
      email: "user@10minutemail.com",
    });

    expect(decision.isDenied()).toBe(true);
    expect(decision.reason.isEmail()).toBe(true);
  });

  it("should handle token bucket for AI quota", async () => {
    const gr = guardrail({
      rules: [
        tokenBucket({
          characteristics: ["userId"],
          refillRate: 1000,
          interval: "1h",
          capacity: 5000,
        }),
      ],
    });

    // Use POST to bypass request caching
    const createRequest = () =>
      new Request("https://example.com/api", {
        method: "POST",
        headers: { "x-forwarded-for": "10.0.0.5" },
      });

    // First request - should allow
    const decision1 = await gr.protect(createRequest(), {
      userId: "user1",
      requested: 2000,
    });

    expect(decision1.isAllowed()).toBe(true);

    // Second request - should allow
    const decision2 = await gr.protect(createRequest(), {
      userId: "user1",
      requested: 2000,
    });

    expect(decision2.isAllowed()).toBe(true);

    // Third request - should deny (exceeds capacity)
    const decision3 = await gr.protect(createRequest(), {
      userId: "user1",
      requested: 2000,
    });

    expect(decision3.isDenied()).toBe(true);
    expect(decision3.reason.isQuota()).toBe(true);
    expect(decision3.reason.getRemaining()).toBe(1000);
  });

  it("should work with custom storage", async () => {
    const storage = new MemoryStorage();
    const gr = guardrail({
      storage,
      rules: [slidingWindow({ interval: "1m", max: 3 })],
    });

    // Use POST to bypass request caching
    const createRequest = () =>
      new Request("https://example.com/api", {
        method: "POST",
        headers: { "x-forwarded-for": "10.0.0.10" },
      });

    // Make 3 requests
    for (let i = 0; i < 3; i++) {
      const decision = await gr.protect(createRequest());
      expect(decision.isAllowed()).toBe(true);
    }

    // 4th request should be denied
    const decision = await gr.protect(createRequest());
    expect(decision.isDenied()).toBe(true);
  });

  it("should handle DRY_RUN mode", async () => {
    const gr = guardrail({
      rules: [
        detectBot({ allow: [], mode: "DRY_RUN" }),
        slidingWindow({ interval: "1m", max: 1, mode: "DRY_RUN" }),
      ],
    });

    const request = new Request("https://example.com/api", {
      headers: {
        "user-agent": "Googlebot",
      },
    });

    // Should allow even though it's a bot and exceeds rate limit
    const decision1 = await gr.protect(request);
    expect(decision1.isAllowed()).toBe(true);

    const decision2 = await gr.protect(request);
    expect(decision2.isAllowed()).toBe(true);
  });
});
