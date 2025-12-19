/**
 * Tests for configuration validation utilities
 * @module utils/config-validator.test
 */

import { describe, it, expect } from "vitest";
import { validateConfig, formatValidationErrors, ConfigValidationError } from "./config-validator";
import type { GuardrailConfig } from "../types/index";

describe("validateConfig", () => {
  it("should validate a valid configuration", () => {
    const config: Partial<GuardrailConfig> = {
      mode: "LIVE",
      errorHandling: "FAIL_OPEN",
      evaluationStrategy: "SEQUENTIAL",
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("should reject invalid mode", () => {
    const config: Partial<GuardrailConfig> = {
      mode: "INVALID" as any,
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].field).toBe("mode");
  });

  it("should reject invalid errorHandling", () => {
    const config: Partial<GuardrailConfig> = {
      errorHandling: "INVALID" as any,
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("errorHandling");
  });

  it("should reject invalid evaluationStrategy", () => {
    const config: Partial<GuardrailConfig> = {
      evaluationStrategy: "INVALID" as any,
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("evaluationStrategy");
  });

  it("should reject non-array rules", () => {
    const config: Partial<GuardrailConfig> = {
      rules: "not-an-array" as any,
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("rules");
  });

  it("should validate rules array", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
        },
        {
          type: "tokenBucket",
          capacity: 1000,
          refillRate: 100,
        },
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(true);
  });

  it("should reject rule without type", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          interval: "1h",
          max: 100,
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("rules[0].type");
  });

  it("should reject invalid rule type", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "invalidType",
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("rules[0].type");
  });

  it("should reject slidingWindow without interval", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "slidingWindow",
          max: 100,
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.field === "rules[0].interval")).toBe(true);
  });

  it("should reject slidingWindow without max", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.field === "rules[0].max")).toBe(true);
  });

  it("should reject tokenBucket without capacity", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "tokenBucket",
          refillRate: 100,
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.field === "rules[0].capacity")).toBe(true);
  });

  it("should reject tokenBucket without refillRate", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "tokenBucket",
          capacity: 1000,
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.field === "rules[0].refillRate")).toBe(true);
  });

  it("should reject validateEmail without block array", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "validateEmail",
        } as any,
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.field === "rules[0].block")).toBe(true);
  });

  it("should validate whitelist configuration", () => {
    const config: Partial<GuardrailConfig> = {
      whitelist: {
        ips: ["1.2.3.4"],
        userIds: ["user1"],
        countries: ["US"],
        emailDomains: ["example.com"],
      },
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(true);
  });

  it("should reject whitelist with non-array ips", () => {
    const config: Partial<GuardrailConfig> = {
      whitelist: {
        ips: "not-an-array" as any,
      },
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("whitelist.ips");
  });

  it("should validate blacklist configuration", () => {
    const config: Partial<GuardrailConfig> = {
      blacklist: {
        ips: ["1.2.3.4"],
        userIds: ["user1"],
        countries: ["CN"],
        emailDomains: ["spam.com"],
      },
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(true);
  });

  it("should validate resilience configuration", () => {
    const config: Partial<GuardrailConfig> = {
      resilience: {
        storage: {
          threshold: 5,
          timeout: 30000,
        },
        ip: {
          threshold: 3,
          timeout: 60000,
        },
      },
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(true);
  });

  it("should reject resilience.storage.threshold < 1", () => {
    const config: Partial<GuardrailConfig> = {
      resilience: {
        storage: {
          threshold: 0,
        },
      },
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("resilience.storage.threshold");
  });

  it("should reject resilience.storage.timeout < 0", () => {
    const config: Partial<GuardrailConfig> = {
      resilience: {
        storage: {
          timeout: -1,
        },
      },
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("resilience.storage.timeout");
  });

  it("should reject invalid rule mode", () => {
    const config: Partial<GuardrailConfig> = {
      rules: [
        {
          type: "slidingWindow",
          interval: "1h",
          max: 100,
          mode: "INVALID" as any,
        },
      ],
    };

    const result = validateConfig(config);
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe("rules[0].mode");
  });
});

describe("formatValidationErrors", () => {
  it("should format validation errors", () => {
    const errors = [
      new ConfigValidationError("Invalid mode", "mode", "INVALID"),
      new ConfigValidationError("Missing field", "rules[0].type"),
    ];

    const formatted = formatValidationErrors(errors);
    expect(formatted).toContain("2 error(s)");
    expect(formatted).toContain("[mode]");
    expect(formatted).toContain("Invalid mode");
    expect(formatted).toContain("INVALID");
  });

  it("should handle empty errors array", () => {
    const formatted = formatValidationErrors([]);
    expect(formatted).toContain("valid");
  });
});

describe("ConfigValidationError", () => {
  it("should create error with message, field, and value", () => {
    const error = new ConfigValidationError("Test error", "testField", "testValue");
    expect(error.message).toBe("Test error");
    expect(error.field).toBe("testField");
    expect(error.value).toBe("testValue");
    expect(error.name).toBe("ConfigValidationError");
  });
});
