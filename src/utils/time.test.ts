import { describe, it, expect } from "vitest";
import { parseInterval, getCurrentTimestamp, getSecondsUntil } from "./time";

describe("parseInterval", () => {
  it("should parse seconds", () => {
    expect(parseInterval("30s")).toBe(30000);
  });

  it("should parse minutes", () => {
    expect(parseInterval("5m")).toBe(300000);
  });

  it("should parse hours", () => {
    expect(parseInterval("2h")).toBe(7200000);
  });

  it("should parse days", () => {
    expect(parseInterval("1d")).toBe(86400000);
  });

  it("should throw on invalid format", () => {
    expect(() => parseInterval("invalid")).toThrow();
  });
});

describe("getCurrentTimestamp", () => {
  it("should return current timestamp", () => {
    const timestamp = getCurrentTimestamp();
    const now = Date.now();

    expect(timestamp).toBeGreaterThan(now - 1000);
    expect(timestamp).toBeLessThanOrEqual(now);
  });
});

describe("getSecondsUntil", () => {
  it("should calculate seconds until future time", () => {
    const future = Date.now() + 5000; // 5 seconds from now
    const seconds = getSecondsUntil(future);

    expect(seconds).toBeGreaterThanOrEqual(4);
    expect(seconds).toBeLessThanOrEqual(5);
  });
});
