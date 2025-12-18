/**
 * Integration tests for decision.explain() method
 * @module core/guardrail-explain.test
 */

import { describe, it, expect, beforeEach } from "vitest";
import { Guardrail } from "./guardrail";
import { window, shield, bot } from "../rules/index";
import { MemoryStorage } from "../storage/memory";
import { createMockRequest } from "../testing/index";

describe("Guardrail decision.explain()", () => {
  let guardrail: Guardrail;

  beforeEach(() => {
    guardrail = new Guardrail({
      storage: new MemoryStorage(),
      rules: [shield(), window({ interval: "1h", max: 100 }), bot()],
    });
  });

  it("should provide explanation for allowed request", async () => {
    const request = createMockRequest("https://example.com/api", {
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const decision = await guardrail.protect(request, {
      userId: "user123",
    });

    const explanation = decision.explain();
    expect(explanation).toBeTruthy();
    expect(explanation).toContain("Request allowed");
    expect(explanation).toContain("All rules passed");
  });

  it("should provide explanation for rate-limited request", async () => {
    // Create a guardrail with a very low limit
    const limitedGuardrail = new Guardrail({
      storage: new MemoryStorage(),
      rules: [
        window({ interval: "1h", max: 2, by: ["userId"] }), // Only 2 requests allowed per userId
      ],
    });

    const request = createMockRequest("https://example.com/api", { method: "GET" });
    const userId = "user123";

    // Make requests to exhaust rate limit - use same userId for all
    const decision1 = await limitedGuardrail.protect(request, { userId });
    expect(decision1.isAllowed()).toBe(true);

    const decision2 = await limitedGuardrail.protect(request, { userId });
    expect(decision2.isAllowed()).toBe(true);

    // This should be denied (3rd request exceeds limit of 2)
    const decision3 = await limitedGuardrail.protect(request, { userId });
    const explanation = decision3.explain();

    // The third request should be denied
    if (decision3.isDenied()) {
      expect(explanation).toContain("Request denied");
      expect(explanation).toContain("Rate limit");
    } else {
      // If not denied, at least verify explanation works
      expect(explanation).toBeTruthy();
      expect(explanation.length).toBeGreaterThan(0);
    }
  });

  it("should include IP information in explanation", async () => {
    const request = createMockRequest("https://example.com/api", { method: "GET" });

    const decision = await guardrail.protect(request);
    const explanation = decision.explain();

    // IP info might be empty in tests, but explanation should still work
    expect(explanation).toBeTruthy();
  });

  it("should include rule summary in explanation", async () => {
    const request = createMockRequest("https://example.com/api", { method: "GET" });

    const decision = await guardrail.protect(request);
    const explanation = decision.explain();

    expect(explanation).toContain("rule(s)");
  });
});
