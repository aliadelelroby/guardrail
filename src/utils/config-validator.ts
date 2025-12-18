/**
 * Configuration validation utilities
 * @module utils/config-validator
 */

import type {
  GuardrailConfig,
  GuardrailRule,
  Mode,
  ErrorHandlingMode,
  EvaluationStrategy,
} from "../types/index";

/**
 * Configuration validation error
 */
export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public readonly field?: string,
    public readonly value?: unknown
  ) {
    super(message);
    this.name = "ConfigValidationError";
  }
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: ConfigValidationError[];
}

/**
 * Validates a Guardrail configuration
 */
export function validateConfig(config: Partial<GuardrailConfig>): ValidationResult {
  const errors: ConfigValidationError[] = [];

  // Validate mode
  if (config.mode !== undefined) {
    const validModes: Mode[] = ["LIVE", "DRY_RUN"];
    if (!validModes.includes(config.mode)) {
      errors.push(
        new ConfigValidationError(
          `Invalid mode: "${config.mode}". Must be one of: ${validModes.join(", ")}`,
          "mode",
          config.mode
        )
      );
    }
  }

  // Validate error handling
  if (config.errorHandling !== undefined) {
    const validModes: ErrorHandlingMode[] = ["FAIL_OPEN", "FAIL_CLOSED"];
    if (!validModes.includes(config.errorHandling)) {
      errors.push(
        new ConfigValidationError(
          `Invalid errorHandling: "${config.errorHandling}". Must be one of: ${validModes.join(", ")}`,
          "errorHandling",
          config.errorHandling
        )
      );
    }
  }

  // Validate evaluation strategy
  if (config.evaluationStrategy !== undefined) {
    const validStrategies: EvaluationStrategy[] = ["SEQUENTIAL", "PARALLEL", "SHORT_CIRCUIT"];
    if (!validStrategies.includes(config.evaluationStrategy)) {
      errors.push(
        new ConfigValidationError(
          `Invalid evaluationStrategy: "${config.evaluationStrategy}". Must be one of: ${validStrategies.join(", ")}`,
          "evaluationStrategy",
          config.evaluationStrategy
        )
      );
    }
  }

  // Validate rules
  if (config.rules !== undefined) {
    if (!Array.isArray(config.rules)) {
      errors.push(new ConfigValidationError("rules must be an array", "rules", config.rules));
    } else {
      config.rules.forEach((rule, index) => {
        const ruleErrors = validateRule(rule, index);
        errors.push(...ruleErrors);
      });
    }
  }

  // Validate whitelist
  if (config.whitelist !== undefined) {
    const whitelistErrors = validateListConfig(config.whitelist, "whitelist");
    errors.push(...whitelistErrors);
  }

  // Validate blacklist
  if (config.blacklist !== undefined) {
    const blacklistErrors = validateListConfig(config.blacklist, "blacklist");
    errors.push(...blacklistErrors);
  }

  // Validate resilience config
  if (config.resilience !== undefined) {
    if (typeof config.resilience !== "object" || config.resilience === null) {
      errors.push(
        new ConfigValidationError("resilience must be an object", "resilience", config.resilience)
      );
    } else {
      if (config.resilience.storage) {
        if (config.resilience.storage.threshold !== undefined) {
          if (
            typeof config.resilience.storage.threshold !== "number" ||
            config.resilience.storage.threshold < 1
          ) {
            errors.push(
              new ConfigValidationError(
                "resilience.storage.threshold must be a positive number",
                "resilience.storage.threshold",
                config.resilience.storage.threshold
              )
            );
          }
        }
        if (config.resilience.storage.timeout !== undefined) {
          if (
            typeof config.resilience.storage.timeout !== "number" ||
            config.resilience.storage.timeout < 0
          ) {
            errors.push(
              new ConfigValidationError(
                "resilience.storage.timeout must be a non-negative number",
                "resilience.storage.timeout",
                config.resilience.storage.timeout
              )
            );
          }
        }
      }
      if (config.resilience.ip) {
        if (config.resilience.ip.threshold !== undefined) {
          if (
            typeof config.resilience.ip.threshold !== "number" ||
            config.resilience.ip.threshold < 1
          ) {
            errors.push(
              new ConfigValidationError(
                "resilience.ip.threshold must be a positive number",
                "resilience.ip.threshold",
                config.resilience.ip.threshold
              )
            );
          }
        }
        if (config.resilience.ip.timeout !== undefined) {
          if (
            typeof config.resilience.ip.timeout !== "number" ||
            config.resilience.ip.timeout < 0
          ) {
            errors.push(
              new ConfigValidationError(
                "resilience.ip.timeout must be a non-negative number",
                "resilience.ip.timeout",
                config.resilience.ip.timeout
              )
            );
          }
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validates a single rule
 */
function validateRule(rule: unknown, index: number): ConfigValidationError[] {
  const errors: ConfigValidationError[] = [];

  if (typeof rule !== "object" || rule === null) {
    errors.push(
      new ConfigValidationError(`Rule at index ${index} must be an object`, `rules[${index}]`, rule)
    );
    return errors;
  }

  const ruleObj = rule as Partial<GuardrailRule>;

  // Validate rule type
  if (!ruleObj.type) {
    errors.push(
      new ConfigValidationError(
        `Rule at index ${index} is missing required field "type"`,
        `rules[${index}].type`,
        undefined
      )
    );
  } else {
    const validTypes = [
      "tokenBucket",
      "slidingWindow",
      "detectBot",
      "validateEmail",
      "shield",
      "filter",
      "custom",
    ];
    if (!validTypes.includes(ruleObj.type)) {
      errors.push(
        new ConfigValidationError(
          `Invalid rule type "${ruleObj.type}" at index ${index}. Must be one of: ${validTypes.join(", ")}`,
          `rules[${index}].type`,
          ruleObj.type
        )
      );
    }
  }

  // Validate rule mode
  if (ruleObj.mode !== undefined) {
    const validModes: Mode[] = ["LIVE", "DRY_RUN"];
    if (!validModes.includes(ruleObj.mode)) {
      errors.push(
        new ConfigValidationError(
          `Invalid mode "${ruleObj.mode}" for rule at index ${index}. Must be one of: ${validModes.join(", ")}`,
          `rules[${index}].mode`,
          ruleObj.mode
        )
      );
    }
  }

  // Type-specific validation
  if (ruleObj.type === "slidingWindow") {
    if (!ruleObj.interval) {
      errors.push(
        new ConfigValidationError(
          `slidingWindow rule at index ${index} is missing required field "interval"`,
          `rules[${index}].interval`,
          undefined
        )
      );
    }
    if (ruleObj.max === undefined) {
      errors.push(
        new ConfigValidationError(
          `slidingWindow rule at index ${index} is missing required field "max"`,
          `rules[${index}].max`,
          undefined
        )
      );
    }
  }

  if (ruleObj.type === "tokenBucket") {
    if (ruleObj.capacity === undefined) {
      errors.push(
        new ConfigValidationError(
          `tokenBucket rule at index ${index} is missing required field "capacity"`,
          `rules[${index}].capacity`,
          undefined
        )
      );
    }
    if (ruleObj.refillRate === undefined) {
      errors.push(
        new ConfigValidationError(
          `tokenBucket rule at index ${index} is missing required field "refillRate"`,
          `rules[${index}].refillRate`,
          undefined
        )
      );
    }
  }

  if (ruleObj.type === "validateEmail") {
    if (!ruleObj.block || !Array.isArray(ruleObj.block) || ruleObj.block.length === 0) {
      errors.push(
        new ConfigValidationError(
          `validateEmail rule at index ${index} is missing required field "block" (array)`,
          `rules[${index}].block`,
          ruleObj.block
        )
      );
    }
  }

  return errors;
}

/**
 * Validates whitelist/blacklist configuration
 */
function validateListConfig(list: unknown, fieldName: string): ConfigValidationError[] {
  const errors: ConfigValidationError[] = [];

  if (typeof list !== "object" || list === null) {
    errors.push(new ConfigValidationError(`${fieldName} must be an object`, fieldName, list));
    return errors;
  }

  const listObj = list as Record<string, unknown>;

  // Validate arrays
  const arrayFields = ["ips", "userIds", "countries", "emailDomains"];
  for (const field of arrayFields) {
    if (listObj[field] !== undefined) {
      if (!Array.isArray(listObj[field])) {
        errors.push(
          new ConfigValidationError(
            `${fieldName}.${field} must be an array`,
            `${fieldName}.${field}`,
            listObj[field]
          )
        );
      } else {
        // Validate array elements
        const arr = listObj[field] as unknown[];
        arr.forEach((item, index) => {
          if (typeof item !== "string") {
            errors.push(
              new ConfigValidationError(
                `${fieldName}.${field}[${index}] must be a string`,
                `${fieldName}.${field}[${index}]`,
                item
              )
            );
          }
        });
      }
    }
  }

  return errors;
}

/**
 * Formats validation errors into a human-readable message
 */
export function formatValidationErrors(errors: ConfigValidationError[]): string {
  if (errors.length === 0) {
    return "Configuration is valid.";
  }

  const lines: string[] = [];
  lines.push(`Configuration validation failed with ${errors.length} error(s):\n`);

  errors.forEach((error, index) => {
    lines.push(`${index + 1}. ${error.field ? `[${error.field}] ` : ""}${error.message}`);
    if (error.value !== undefined) {
      lines.push(`   Value: ${JSON.stringify(error.value)}`);
    }
  });

  return lines.join("\n");
}
