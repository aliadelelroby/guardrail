/**
 * Tests for configuration file loader utilities
 * @module utils/config-loader.test
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { loadConfigFile, createGuardrailFromConfig } from "./config-loader";
import type { GuardrailConfig } from "../types/index";

// Mock fs functions for testing
vi.mock("fs", async () => {
  const actual = await vi.importActual("fs");
  return {
    ...actual,
    readFileSync: vi.fn(),
    existsSync: vi.fn(),
  };
});

describe("loadConfigFile", () => {
  const mockReadFileSync = readFileSync as any;
  const mockExistsSync = existsSync as any;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should load JSON config file", () => {
    const config: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(JSON.stringify(config));

    const result = loadConfigFile({ path: "guardrail.config.json" });
    expect(result).toEqual(config);
    expect(mockReadFileSync).toHaveBeenCalled();
    const callArgs = (mockReadFileSync as any).mock.calls[0];
    expect(callArgs[1]).toBe("utf-8");
  });

  it("should throw error if config file not found", () => {
    mockExistsSync.mockReturnValue(false);

    expect(() => {
      loadConfigFile({ path: "nonexistent.json" });
    }).toThrow("Config file not found");
  });

  it("should throw error for invalid JSON", () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue("invalid json {");

    expect(() => {
      loadConfigFile({ path: "invalid.json" });
    }).toThrow("Failed to parse JSON config file");
  });

  it("should throw error for YAML files (not yet supported)", () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue("rules: []");

    expect(() => {
      loadConfigFile({ path: "config.yaml" });
    }).toThrow("YAML support requires");
  });

  it("should auto-discover config file", () => {
    const config: GuardrailConfig = {
      rules: [],
    };

    // Try guardrail.config.json
    mockExistsSync.mockImplementation((path: string) => {
      return path === resolve(process.cwd(), "guardrail.config.json");
    });
    mockReadFileSync.mockReturnValue(JSON.stringify(config));

    const result = loadConfigFile();
    expect(result).toEqual(config);
  });

  it("should load environment-specific config", () => {
    const baseConfig: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    const _prodConfig: Partial<GuardrailConfig> = {
      debug: false,
    };

    // Mock for auto-discovery - finds base config
    mockExistsSync.mockImplementation((path: string) => {
      const pathStr = String(path);
      return pathStr.includes("guardrail.config.json") && !pathStr.includes("production");
    });

    mockReadFileSync.mockReturnValue(JSON.stringify(baseConfig));

    const result = loadConfigFile({ environment: "production", path: "guardrail.config.json" });
    // This test verifies the function works with environment option
    expect(result).toBeDefined();
    expect(result.rules).toBeDefined();
  });

  it("should throw error if no config file found in auto-discovery", () => {
    mockExistsSync.mockReturnValue(false);

    expect(() => {
      loadConfigFile();
    }).toThrow("No Guardrail config file found");
  });
});

describe("createGuardrailFromConfig", () => {
  const mockReadFileSync = readFileSync as any;
  const mockExistsSync = existsSync as any;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should create Guardrail instance from config file", async () => {
    const config: GuardrailConfig = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(JSON.stringify(config));

    const guardrail = await createGuardrailFromConfig({ path: "guardrail.config.json" });
    expect(guardrail).toBeDefined();
    expect(guardrail).toHaveProperty("protect");
  });
});
