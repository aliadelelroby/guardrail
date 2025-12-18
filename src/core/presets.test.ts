import { describe, it, expect } from "vitest";
import { GuardrailPresets } from "./presets";

describe("GuardrailPresets", () => {
  it("should create API preset", () => {
    const config = GuardrailPresets.api();
    expect(config.rules).toHaveLength(3);
    expect(config.errorHandling).toBe("FAIL_OPEN");
    expect(config.evaluationStrategy).toBe("SEQUENTIAL");
  });

  it("should create Web preset", () => {
    const config = GuardrailPresets.web();
    expect(config.rules).toHaveLength(3);
    expect(config.errorHandling).toBe("FAIL_OPEN");
    expect(config.evaluationStrategy).toBe("PARALLEL");

    // Check for bot allowances
    const botRule = config.rules.find((r) => r.type === "detectBot");
    // Since we don't have easy access to the internal config of the created rule object (it's a Rule instance),
    // we just verify the rule exists.
    expect(botRule).toBeDefined();
  });

  it("should create Strict preset", () => {
    const config = GuardrailPresets.strict();
    expect(config.rules).toHaveLength(3);
    expect(config.errorHandling).toBe("FAIL_CLOSED");
    expect(config.evaluationStrategy).toBe("SHORT_CIRCUIT");
  });

  it("should create AI preset", () => {
    const config = GuardrailPresets.ai();
    expect(config.rules).toHaveLength(3);
    const hasTokenBucket = config.rules.some((r) => r.type === "tokenBucket");
    expect(hasTokenBucket).toBe(true);
  });

  it("should create Payment preset", () => {
    const config = GuardrailPresets.payment();
    expect(config.rules).toHaveLength(4);
    expect(config.errorHandling).toBe("FAIL_OPEN");
    const hasEmailValidation = config.rules.some((r) => r.type === "validateEmail");
    expect(hasEmailValidation).toBe(true);
  });

  it("should create Auth preset", () => {
    const config = GuardrailPresets.auth();
    expect(config.rules).toHaveLength(4);
    const hasEmailValidation = config.rules.some((r) => r.type === "validateEmail");
    expect(hasEmailValidation).toBe(true);
  });

  it("should create Development preset", () => {
    const config = GuardrailPresets.development();
    expect(config.rules).toHaveLength(3);
    expect(config.debug).toBe(true);
    expect(config.errorHandling).toBe("FAIL_OPEN");
  });
});
