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
 * Enhanced with more comprehensive pattern matching and obfuscation detection
 */
function isFunctionSafe(fn: unknown): boolean {
  if (typeof fn !== "function") {
    return false;
  }

  // Check if function is a native function (safer than user-defined)
  const fnString = fn.toString();

  // Block functions that contain dangerous patterns
  // Enhanced patterns to catch obfuscated code
  const dangerousPatterns = [
    // Direct dangerous calls
    /eval\s*\(/i,
    /Function\s*\(/i,
    /new Function/i,
    /require\s*\(/i,
    /import\s*\(/i,
    /process\./i,
    /global\./i,
    /__dirname/i,
    /__filename/i,
    // Obfuscated patterns
    /\beval\b/i,
    /\bFunction\b.*\(/i,
    // File system access
    /fs\./i,
    /readFile/i,
    /writeFile/i,
    /exec/i,
    /spawn/i,
    /child_process/i,
    // Network access
    /http\./i,
    /https\./i,
    /fetch\s*\(/i,
    /XMLHttpRequest/i,
    // Shell access
    /shell/i,
    /cmd/i,
    /powershell/i,
    // Dangerous object access
    /constructor\.prototype/i,
    /Object\.prototype/i,
    // Base64/hex encoded eval attempts (common obfuscation)
    /atob\s*\(/i,
    /btoa\s*\(/i,
    /fromCharCode/i,
    // Dynamic code execution
    /setTimeout\s*\(.*['"]/i,
    /setInterval\s*\(.*['"]/i,
    // Prototype pollution attempts
    /__proto__/i,
    /constructor\[/i,
  ];

  // Check for dangerous patterns
  for (const pattern of dangerousPatterns) {
    if (pattern.test(fnString)) {
      console.warn("[Guardrail] Blocked potentially unsafe function pattern:", pattern.toString());
      return false;
    }
  }

  // Check for suspiciously long or complex functions (potential obfuscation)
  // Simple functions are typically < 500 characters
  if (fnString.length > 5000) {
    console.warn("[Guardrail] Blocked suspiciously long function (potential obfuscation)");
    return false;
  }

  // Check for excessive use of escape sequences (common in obfuscated code)
  const escapeSequenceCount = (fnString.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi) || []).length;
  if (escapeSequenceCount > 10) {
    console.warn(
      "[Guardrail] Blocked function with excessive escape sequences (potential obfuscation)"
    );
    return false;
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
      // Reduced timeout from 5s to 2s for better security
      const timeoutMs = 2000;
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("Function execution timeout")), timeoutMs);
      });

      // Type assertion: value is a function that takes DecisionContext
      const func = value as (context: DecisionContext) => T | Promise<T>;

      // Track execution start time for monitoring
      const startTime = Date.now();
      const result = await Promise.race([Promise.resolve(func(context)), timeoutPromise]);
      const executionTime = Date.now() - startTime;

      // Warn if function takes too long (even if under timeout)
      if (executionTime > 1000) {
        console.warn(
          `[Guardrail] Dynamic value resolver function took ${executionTime}ms (slow execution)`
        );
      }

      return result instanceof Promise ? await result : (result as T);
    } catch (error) {
      const timeoutMs = 2000; // Re-declare for error handler
      if (error instanceof Error && error.message.includes("timeout")) {
        console.warn(`[Guardrail] Dynamic value resolver function timed out after ${timeoutMs}ms`);
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
