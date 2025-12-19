/**
 * Integration tests for configuration validation
 * @module core/guardrail-validation.test
 */

import { describe, it, expect } from "vitest";
import { Guardrail } from "./guardrail";
import { ConfigValidationError } from "../utils/config-validator";
import { window } from "../rules/index";

describe("Guardrail configuration validation", () => {
  it("should throw error for invalid mode", () => {
    expect(() => {
      new Guardrail({
        mode: "INVALID" as any,
      });
    }).toThrow(ConfigValidationError);
  });

  it("should throw error for invalid errorHandling", () => {
    expect(() => {
      new Guardrail({
        errorHandling: "INVALID" as any,
      });
    }).toThrow(ConfigValidationError);
  });

  it("should throw error for invalid evaluationStrategy", () => {
    expect(() => {
      new Guardrail({
        evaluationStrategy: "INVALID" as any,
      });
    }).toThrow(ConfigValidationError);
  });

  it("should throw error for invalid rule configuration", () => {
    expect(() => {
      new Guardrail({
        rules: [
          {
            type: "slidingWindow",
            // Missing required fields
          } as any,
        ],
      });
    }).toThrow(ConfigValidationError);
  });

  it("should accept valid configuration", () => {
    expect(() => {
      new Guardrail({
        rules: [
          window({
            interval: "1h",
            max: 100,
          }),
        ],
      });
    }).not.toThrow();
  });

  it("should throw error with detailed field information", () => {
    let error: unknown;
    try {
      new Guardrail({
        rules: [
          {
            type: "slidingWindow",
            interval: "1h",
            // Missing max
          } as any,
        ],
      });
    } catch (e) {
      error = e;
    }

    expect(error).toBeDefined();
    expect(error).toBeInstanceOf(Error);
    // The error message should contain information about the missing field
    if (error instanceof Error) {
      expect(error.message).toContain("max");
    }
  });
});
