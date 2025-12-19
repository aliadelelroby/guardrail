/**
 * Tests for decision explanation utilities
 * @module utils/decision-explainer.test
 */

import { describe, it, expect } from "vitest";
import { explainDecision } from "./decision-explainer";
import type { Decision } from "../types/index";
import { DecisionReason } from "./decision-helpers";

describe("explainDecision", () => {
  it("should explain an allowed request", () => {
    const decision: Decision = {
      id: "test-1",
      conclusion: "ALLOW",
      reason: new DecisionReason(),
      results: [
        { rule: "shield", conclusion: "ALLOW" },
        { rule: "window", conclusion: "ALLOW", remaining: 45 },
      ],
      ip: {
        country: "US",
        countryName: "United States",
        city: "New York",
        hasCountry: () => true,
        hasCountryName: () => true,
        hasCity: () => true,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: { userId: "user123" },
      isAllowed: () => true,
      isDenied: () => false,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Request allowed");
    expect(explanation).toContain("All rules passed");
    expect(explanation).toContain("United States");
    expect(explanation).toContain("not VPN/Proxy");
  });

  it("should explain a denied request with rate limit", () => {
    const rateLimitResult = {
      rule: "window",
      conclusion: "DENY" as const,
      reason: "RATE_LIMIT" as const,
      remaining: 0,
    };

    const decision: Decision = {
      id: "test-2",
      conclusion: "DENY",
      reason: new DecisionReason("RATE_LIMIT", rateLimitResult),
      results: [rateLimitResult],
      ip: {
        hasCountry: () => false,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => false,
      isDenied: () => true,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Request denied");
    expect(explanation).toContain("Rate limit exceeded");
    expect(explanation).toContain("0 remaining");
  });

  it("should explain a denied request with bot detection", () => {
    const decision: Decision = {
      id: "test-3",
      conclusion: "DENY",
      reason: new DecisionReason("BOT"),
      results: [
        { rule: "shield", conclusion: "ALLOW" },
        { rule: "bot", conclusion: "DENY", reason: "BOT" },
      ],
      ip: {
        country: "US",
        hasCountry: () => true,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => false,
      isDenied: () => true,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Request denied");
    expect(explanation).toContain("Bot detected");
    expect(explanation).toContain("1 rule(s) passed");
    expect(explanation).toContain("1 rule(s) failed");
  });

  it("should explain quota exceeded", () => {
    const quotaResult = {
      rule: "window",
      conclusion: "DENY" as const,
      reason: "QUOTA" as const,
      remaining: 5,
    };

    const decision: Decision = {
      id: "test-4",
      conclusion: "DENY",
      reason: new DecisionReason("QUOTA", quotaResult),
      results: [quotaResult],
      ip: {
        hasCountry: () => false,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => false,
      isDenied: () => true,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Quota exceeded");
    expect(explanation).toContain("5 remaining");
  });

  it("should explain shield protection", () => {
    const decision: Decision = {
      id: "test-5",
      conclusion: "DENY",
      reason: new DecisionReason("SHIELD"),
      results: [{ rule: "shield", conclusion: "DENY", reason: "SHIELD" }],
      ip: {
        hasCountry: () => false,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => false,
      isDenied: () => true,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Attack detected");
  });

  it("should explain email validation", () => {
    const decision: Decision = {
      id: "test-6",
      conclusion: "DENY",
      reason: new DecisionReason("EMAIL"),
      results: [{ rule: "validateEmail", conclusion: "DENY", reason: "EMAIL" }],
      ip: {
        hasCountry: () => false,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => false,
      isDenied: () => true,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Invalid or disposable email");
  });

  it("should explain filter rule", () => {
    const decision: Decision = {
      id: "test-7",
      conclusion: "DENY",
      reason: new DecisionReason("FILTER"),
      results: [{ rule: "filter", conclusion: "DENY", reason: "FILTER" }],
      ip: {
        hasCountry: () => false,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => false,
      isDenied: () => true,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Filter rule matched");
  });

  it("should handle IP with proxy and Tor", () => {
    const decision: Decision = {
      id: "test-8",
      conclusion: "ALLOW",
      reason: new DecisionReason(),
      results: [],
      ip: {
        country: "RU",
        hasCountry: () => true,
        hasCountryName: () => false,
        hasCity: () => false,
        hasRegion: () => false,
        hasContinent: () => false,
        hasContinentName: () => false,
        hasLatitude: () => false,
        hasLongitude: () => false,
        hasPostalCode: () => false,
        hasTimezone: () => false,
        hasASN: () => false,
        hasASNName: () => false,
        hasASNDomain: () => false,
        hasASNCountry: () => false,
        hasService: () => false,
        isVpn: () => false,
        isProxy: () => true,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => true,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => true,
      isDenied: () => false,
      explain: () => explainDecision(decision),
    };

    const explanation = decision.explain();
    expect(explanation).toContain("Proxy");
    expect(explanation).toContain("Tor");
  });
});
