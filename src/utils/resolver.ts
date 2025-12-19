/**
 * Resolver for dynamic configuration values
 * @module utils/resolver
 */

import type { DynamicValue, DecisionContext } from "../types/index";

/**
 * Forbidden keys for path resolution to prevent prototype pollution
 */
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Maximum depth for path resolution
 */
const MAX_PATH_DEPTH = 10;

/**
 * Safely resolves a nested path from an object
 */
function getSafePath(obj: any, path: string): any {
  if (!obj || typeof obj !== "object") {
    return undefined;
  }

  const parts = path.split(".");

  // Limit path depth to prevent deep traversal attacks
  if (parts.length > MAX_PATH_DEPTH) {
    console.warn(`[Guardrail] Path depth exceeds maximum: ${path}`);
    return undefined;
  }

  let current = obj;

  for (const part of parts) {
    if (FORBIDDEN_KEYS.has(part)) {
      console.warn(`[Guardrail] Blocked forbidden path access: ${path}`);
      return undefined;
    }

    // Validate part doesn't contain dangerous characters
    if (!/^[a-zA-Z0-9_$]+$/.test(part)) {
      console.warn(`[Guardrail] Invalid path component: ${part}`);
      return undefined;
    }

    if (current && typeof current === "object" && part in current) {
      current = current[part];
    } else {
      return undefined;
    }
  }

  return current;
}

/**
 * Validates that a function is safe to execute
 * This is a basic check - functions should NEVER come from untrusted sources
 */
function isFunctionSafe(fn: unknown): boolean {
  if (typeof fn !== "function") {
    return false;
  }
  // Check if function is a native function (safer than user-defined)
  const fnString = fn.toString();

  // Block functions that contain dangerous patterns
  const dangerousPatterns = [
    /eval\s*\(/,
    /Function\s*\(/,
    /new Function/,
    /require\s*\(/,
    /import\s*\(/,
    /process\./,
    /global\./,
    /__dirname/,
    /__filename/,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(fnString)) {
      console.warn("[Guardrail] Blocked potentially unsafe function");
      return false;
    }
  }

  return true;
}

/**
 * Resolves a dynamic value based on the current context
 * Supports:
 * 1. Static values (returned as is)
 * 2. Functions (executed with context, can be async) - WARNING: Only use functions from trusted sources
 * 3. Path strings (looked up in metadata, options, or characteristics)
 *
 * @param value - The dynamic value to resolve
 * @param context - The evaluation context
 * @param defaultValue - Fallback value if resolution fails
 * @returns The resolved value
 * @note Functions should NEVER come from untrusted sources (user input, external APIs, etc.)
 */
export async function resolveValue<T>(
  value: DynamicValue<T>,
  context: DecisionContext,
  defaultValue: T
): Promise<T> {
  if (value === undefined || value === null) {
    return defaultValue;
  }

  // 1. Function resolver
  if (typeof value === "function") {
    // SECURITY WARNING: Function execution from configuration
    // Functions should only come from trusted, internal sources
    // Never accept functions from user input, external APIs, or untrusted config files

    // Basic safety check
    if (!isFunctionSafe(value)) {
      console.warn("[Guardrail] Unsafe function blocked in dynamic value resolver");
      return defaultValue;
    }

    try {
      // Set timeout for function execution to prevent DoS
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("Function execution timeout")), 5000);
      });

      // Type assertion: value is a function that takes DecisionContext
      const func = value as (context: DecisionContext) => T | Promise<T>;
      const result = await Promise.race([Promise.resolve(func(context)), timeoutPromise]);

      return result instanceof Promise ? await result : (result as T);
    } catch (error) {
      if (error instanceof Error && error.message.includes("timeout")) {
        console.warn("[Guardrail] Dynamic value resolver function timed out");
      } else {
        console.warn("[Guardrail] Dynamic value resolver function failed:", error);
      }
      return defaultValue;
    }
  }

  // 2. String path resolver
  if (typeof value === "string") {
    const path = value as string;

    // Security: We primarily resolve from metadata to keep a clean separation
    // between system internals and user-provided configuration.

    // 1. Try metadata (Preferred)
    const metadataResult = getSafePath(context.metadata, path);
    if (metadataResult !== undefined) {
      return metadataResult as T;
    }

    // 2. Try options (Backwards compatibility and convenience)
    const optionsResult = getSafePath(context.options, path);
    if (optionsResult !== undefined) {
      return optionsResult as T;
    }

    // 3. Try characteristics (For simple IP/Agent based logic)
    const characteristicsResult = getSafePath(context.characteristics, path);
    if (characteristicsResult !== undefined) {
      return characteristicsResult as T;
    }

    // 4. Special case: absolute paths if they start with metadata/options/characteristics
    if (path.startsWith("metadata.")) {
      return getSafePath(context.metadata, path.slice(9)) ?? defaultValue;
    }
    if (path.startsWith("options.")) {
      return getSafePath(context.options, path.slice(8)) ?? defaultValue;
    }
    if (path.startsWith("characteristics.")) {
      return getSafePath(context.characteristics, path.slice(16)) ?? defaultValue;
    }

    return defaultValue;
  }

  // 3. Static value
  return value as T;
}
