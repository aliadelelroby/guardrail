import { describe, it, expect, beforeEach, vi } from "vitest";
import { Guardrail } from "./guardrail";
import { shield, detectBot, slidingWindow, tokenBucket } from "../rules/index";

describe("Guardrail", () => {
  let guardrail: Guardrail;

  beforeEach(() => {
    guardrail = new Guardrail({
      rules: [shield(), detectBot({ allow: [] }), slidingWindow({ interval: "1m", max: 5 })],
    });
  });

  it("should initialize with zero config (defaults to api preset)", async () => {
    const gr = new Guardrail();
    const request = new Request("https://example.com/api");
    const decision = await gr.protect(request);
    expect(decision).toBeDefined();
    expect(decision.results.length).toBeGreaterThan(0);
  });

  it("should convert Express-like request to Web Request using toWebRequest", () => {
    const mockReq = {
      protocol: "https",
      get: (name: string) => (name === "host" ? "example.com" : undefined),
      originalUrl: "/api/test",
      method: "POST",
      headers: { "x-test": "value" },
      body: { foo: "bar" },
    };

    const webReq = Guardrail.toWebRequest(mockReq);
    expect(webReq.url).toBe("https://example.com/api/test");
    expect(webReq.method).toBe("POST");
    expect(webReq.headers.get("x-test")).toBe("value");
  });

  it("should generate security headers from a decision", async () => {
    const request = new Request("https://example.com/api");
    const decision = await guardrail.protect(request);
    const headers = Guardrail.getSecurityHeaders(decision);

    expect(headers["X-Guardrail-Id"]).toBe(decision.id);
    expect(headers["X-Guardrail-Conclusion"]).toBe(decision.conclusion);
    expect(headers["X-RateLimit-Remaining"]).toBeDefined();
  });

  it("should check health of dependencies", async () => {
    const health = await guardrail.checkHealth();
    expect(health.status).toBeDefined();
    expect(health.storage).toBeDefined();
    expect(health.ipService).toBeDefined();
  });

  it("should allow valid requests", async () => {
    const request = new Request("https://example.com/api", {
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const decision = await guardrail.protect(request);

    expect(decision.isAllowed()).toBe(true);
    expect(decision.isDenied()).toBe(false);
  });

  it("should deny bot requests", async () => {
    const request = new Request("https://example.com/api", {
      method: "GET",
      headers: {
        "user-agent": "Googlebot",
      },
    });

    const decision = await guardrail.protect(request);

    expect(decision.isDenied()).toBe(true);
    expect(decision.reason.isBot()).toBe(true);
  });

  it("should deny rate limited requests", async () => {
    // Create a new guardrail instance for this test to ensure clean state
    const rateLimitGuardrail = new Guardrail({
      rules: [slidingWindow({ interval: "1m", max: 5 })],
    });

    // Use POST to bypass caching and unique IP
    const createRequest = () =>
      new Request("https://example.com/api", {
        method: "POST",
        headers: {
          "user-agent": "Mozilla/5.0",
          "x-forwarded-for": "192.168.1.100",
        },
      });

    // Make 5 requests (max is 5)
    for (let i = 0; i < 5; i++) {
      const decision = await rateLimitGuardrail.protect(createRequest());
      expect(decision.isAllowed()).toBe(true);
    }

    // 6th request should be denied
    const decision = await rateLimitGuardrail.protect(createRequest());

    expect(decision.isDenied()).toBe(true);
    expect(decision.reason.isRateLimit()).toBe(true);
  });

  it("should handle token bucket quota", async () => {
    const gr = new Guardrail({
      rules: [
        tokenBucket({
          characteristics: ["userId"],
          refillRate: 100,
          interval: "1h",
          capacity: 500,
        }),
      ],
    });

    // Use POST to bypass request caching
    const request1 = new Request("https://example.com/api", {
      method: "POST",
      headers: { "x-forwarded-for": "10.0.0.1" },
    });
    const decision1 = await gr.protect(request1, {
      userId: "user1",
      requested: 300,
    });

    expect(decision1.isAllowed()).toBe(true);

    const request2 = new Request("https://example.com/api", {
      method: "POST",
      headers: { "x-forwarded-for": "10.0.0.1" },
    });
    const decision2 = await gr.protect(request2, {
      userId: "user1",
      requested: 300,
    });

    expect(decision2.isAllowed()).toBe(false);
    expect(decision2.reason.isQuota()).toBe(true);
    expect(decision2.reason.getRemaining()).toBe(200);
  });

  it("should include IP information", async () => {
    const request = new Request("https://example.com/api", {
      headers: {
        "x-forwarded-for": "8.8.8.8",
      },
    });

    const decision = await guardrail.protect(request);

    expect(decision.ip).toBeDefined();
    expect(decision.characteristics["ip.src"]).toBe("8.8.8.8");
  });

  it("should handle custom characteristics", async () => {
    const request = new Request("https://example.com/api");
    const decision = await guardrail.protect(request, {
      userId: "user123",
      email: "test@example.com",
    });

    expect(decision.characteristics.userId).toBe("user123");
    expect(decision.characteristics.email).toBe("test@example.com");
  });
});
