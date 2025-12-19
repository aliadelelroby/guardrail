/**
 * Tests for debug visualizer utilities
 * @module utils/debug-visualizer.test
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { visualizeDecision, visualizeTimeline, logDecision } from "./debug-visualizer";
import type { Decision } from "../types/index";
import { DecisionReason } from "./decision-helpers";

describe("visualizeDecision", () => {
  it("should visualize an allowed request", () => {
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
      explain: () => "Request allowed: All rules passed.",
    };

    const output = visualizeDecision(decision);
    expect(output).toContain("Guardrail Decision: test-1");
    expect(output).toContain("Request ALLOWED");
    expect(output).toContain("Rule Evaluation Tree");
    expect(output).toContain("shield");
    expect(output).toContain("window");
    expect(output).toContain("United States");
    expect(output).toContain("New York");
  });

  it("should visualize a denied request", () => {
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
      explain: () => "Request denied: Rate limit exceeded.",
    };

    const output = visualizeDecision(decision);
    expect(output).toContain("Request DENIED");
    expect(output).toContain("Rate Limit");
    expect(output).toContain("window");
  });

  it("should handle IP with VPN", () => {
    const decision: Decision = {
      id: "test-3",
      conclusion: "ALLOW",
      reason: new DecisionReason(),
      results: [],
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
        isVpn: () => true,
        isProxy: () => false,
        isHosting: () => false,
        isRelay: () => false,
        isTor: () => false,
      },
      metadata: {},
      characteristics: {},
      isAllowed: () => true,
      isDenied: () => false,
      explain: () => "Request allowed.",
    };

    const output = visualizeDecision(decision, { showIP: true });
    expect(output).toContain("VPN");
  });

  it("should work without color", () => {
    const decision: Decision = {
      id: "test-4",
      conclusion: "ALLOW",
      reason: new DecisionReason(),
      results: [],
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
      isAllowed: () => true,
      isDenied: () => false,
      explain: () => "Request allowed.",
    };

    const output = visualizeDecision(decision, { color: false });
    expect(output).toBeTruthy();
    expect(output).toContain("Request ALLOWED");
  });
});

describe("visualizeTimeline", () => {
  it("should visualize rule evaluation timeline", () => {
    const results = [
      { rule: "shield", conclusion: "ALLOW" as const },
      { rule: "window", conclusion: "ALLOW" as const, remaining: 45 },
      { rule: "bot", conclusion: "DENY" as const, reason: "BOT" as const },
    ];

    const output = visualizeTimeline(results);
    expect(output).toContain("Evaluation Timeline");
    expect(output).toContain("shield");
    expect(output).toContain("window");
    expect(output).toContain("bot");
  });
});

describe("logDecision", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("should log decision to console", () => {
    const decision: Decision = {
      id: "test-5",
      conclusion: "ALLOW",
      reason: new DecisionReason(),
      results: [],
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
      isAllowed: () => true,
      isDenied: () => false,
      explain: () => "Request allowed.",
    };

    logDecision(decision);
    expect(console.log).toHaveBeenCalled();
  });

  it("should include timeline when option is enabled", () => {
    const decision: Decision = {
      id: "test-6",
      conclusion: "ALLOW",
      reason: new DecisionReason(),
      results: [{ rule: "shield", conclusion: "ALLOW" }],
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
      isAllowed: () => true,
      isDenied: () => false,
      explain: () => "Request allowed.",
    };

    logDecision(decision, { timeline: true });
    expect(console.log).toHaveBeenCalledTimes(2); // Decision + timeline
  });
});
