/**
 * Tests for request replay CLI utilities
 * @module cli/replay.test
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { readFileSync } from "fs";
import { replayRequests, formatReplayResults, parseLogFile, type ReplayOptions } from "./replay";
import type { GuardrailConfig } from "../types/index";

// Mock fs
vi.mock("fs", async () => {
  const actual = await vi.importActual("fs");
  return {
    ...actual,
    readFileSync: vi.fn(),
    existsSync: vi.fn(() => true),
  };
});

describe("parseLogFile", () => {
  it("should parse JSON lines format", () => {
    const logContent = `{"method":"GET","url":"https://example.com/api","headers":{"user-agent":"test"}}
{"method":"POST","url":"https://example.com/api/users","body":{"name":"test"}}`;

    const entries = parseLogFile(logContent);
    expect(entries).toHaveLength(2);
    expect(entries[0].method).toBe("GET");
    expect(entries[0].url).toBe("https://example.com/api");
    expect(entries[1].method).toBe("POST");
  });

  it("should skip empty lines", () => {
    const logContent = `{"method":"GET","url":"https://example.com/api"}

{"method":"POST","url":"https://example.com/api/users"}`;

    const entries = parseLogFile(logContent);
    expect(entries).toHaveLength(2);
  });

  it("should skip invalid JSON lines", () => {
    const logContent = `{"method":"GET","url":"https://example.com/api"}
invalid json
{"method":"POST","url":"https://example.com/api/users"}`;

    const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const entries = parseLogFile(logContent);
    expect(entries).toHaveLength(2);
    expect(consoleWarnSpy).toHaveBeenCalled();
    consoleWarnSpy.mockRestore();
  });

  it("should skip entries without method or url", () => {
    const logContent = `{"method":"GET","url":"https://example.com/api"}
{"invalid":"entry"}`;

    const entries = parseLogFile(logContent);
    expect(entries).toHaveLength(1);
  });
});

describe("replayRequests", () => {
  const mockReadFileSync = readFileSync as any;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should replay requests from log file", async () => {
    const logContent = `{"method":"GET","url":"https://example.com/api","options":{"userId":"user1"}}`;

    mockReadFileSync.mockReturnValue(logContent);

    const config: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    const options: ReplayOptions = {
      logFile: "requests.jsonl",
      config,
      output: "json",
    };

    const results = await replayRequests(options);
    expect(results).toHaveLength(1);
    expect(results[0].entry.method).toBe("GET");
    expect(results[0].decision).toBeDefined();
  });

  it("should throw error if no config provided", async () => {
    const logContent = `{"method":"GET","url":"https://example.com/api"}`;
    mockReadFileSync.mockReturnValue(logContent);

    const options: ReplayOptions = {
      logFile: "requests.jsonl",
    };

    await expect(replayRequests(options)).rejects.toThrow("No configuration provided");
  });

  it("should filter by decision type", async () => {
    const logContent = `{"method":"GET","url":"https://example.com/api"}
{"method":"POST","url":"https://example.com/api"}`;

    mockReadFileSync.mockReturnValue(logContent);

    const config: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    const options: ReplayOptions = {
      logFile: "requests.jsonl",
      config,
      filter: "allow",
    };

    const results = await replayRequests(options);
    // All should be allowed with default config
    expect(results.every((r) => r.decision.isAllowed())).toBe(true);
  });

  it("should compare with alternative config", async () => {
    const logContent = `{"method":"GET","url":"https://example.com/api"}`;
    mockReadFileSync.mockReturnValue(logContent);

    const config: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    const compareConfig: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 50, // Different limit
        },
      ],
    };

    const options: ReplayOptions = {
      logFile: "requests.jsonl",
      config,
      compareConfig,
    };

    const results = await replayRequests(options);
    expect(results[0].comparison).toBeDefined();
    expect(results[0].comparison?.changed).toBeDefined();
  });
});

describe("formatReplayResults", () => {
  it("should format as JSON", () => {
    const results: any[] = [
      {
        entry: { method: "GET", url: "https://example.com/api" },
        decision: { isAllowed: () => true, isDenied: () => false },
        duration: 10,
      },
    ];

    const output = formatReplayResults(results, "json");
    expect(output).toContain('"method"');
    expect(output).toContain("GET");
  });

  it("should format as table", () => {
    const results: any[] = [
      {
        entry: { method: "GET", url: "https://example.com/api" },
        decision: { isAllowed: () => true, isDenied: () => false },
        duration: 10,
      },
    ];

    const output = formatReplayResults(results, "table");
    expect(output).toContain("Method");
    expect(output).toContain("GET");
  });

  it("should format as detailed", () => {
    const results: any[] = [
      {
        entry: { method: "GET", url: "https://example.com/api" },
        decision: {
          isAllowed: () => true,
          isDenied: () => false,
          explain: () => "Request allowed.",
        },
        duration: 10,
      },
    ];

    const output = formatReplayResults(results, "detailed");
    expect(output).toContain("Request 1");
    expect(output).toContain("GET");
    expect(output).toContain("ALLOW");
  });

  it("should show comparison in detailed format", () => {
    const results: any[] = [
      {
        entry: { method: "GET", url: "https://example.com/api" },
        decision: {
          isAllowed: () => true,
          isDenied: () => false,
          explain: () => "Request allowed.",
        },
        duration: 10,
        comparison: {
          decision: {
            isAllowed: () => false,
            isDenied: () => true,
          },
          duration: 15,
          changed: true,
        },
      },
    ];

    const output = formatReplayResults(results, "detailed");
    expect(output).toContain("Comparison");
    expect(output).toContain("Changed: Yes");
  });
});
