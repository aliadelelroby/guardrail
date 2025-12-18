/**
 * Safe JSON parsing utilities with protection against prototype pollution and DoS
 * @module utils/safe-json
 */

/**
 * Safely parses JSON with protection against prototype pollution and deep nesting
 * @param jsonString - JSON string to parse
 * @param maxDepth - Maximum nesting depth (default: 100)
 * @returns Parsed object
 * @throws {Error} If JSON is invalid or exceeds depth limit
 */
export function safeJsonParse<T>(jsonString: string, maxDepth: number = 100): T {
  if (typeof jsonString !== "string") {
    throw new Error("JSON string must be a string");
  }

  // Limit input size to prevent memory exhaustion
  const MAX_JSON_SIZE = 10 * 1024 * 1024; // 10MB
  if (jsonString.length > MAX_JSON_SIZE) {
    throw new Error(`JSON string exceeds maximum size of ${MAX_JSON_SIZE} bytes`);
  }

  // Pre-check depth by counting braces/brackets (more reliable than reviver)
  let braceDepth = 0;
  let inString = false;
  let escapeNext = false;
  let maxBraceDepth = 0;

  for (let i = 0; i < jsonString.length; i++) {
    const char = jsonString[i];

    if (escapeNext) {
      escapeNext = false;
      continue;
    }

    if (char === "\\") {
      escapeNext = true;
      continue;
    }

    if (char === '"') {
      inString = !inString;
      continue;
    }

    if (inString) {
      continue;
    }

    if (char === "{" || char === "[") {
      braceDepth++;
      maxBraceDepth = Math.max(maxBraceDepth, braceDepth);
      if (braceDepth > maxDepth) {
        throw new Error(`JSON nesting depth exceeds maximum of ${maxDepth}`);
      }
    } else if (char === "}" || char === "]") {
      braceDepth--;
    }
  }

  // Use reviver for prototype pollution protection
  const reviver = (key: string, value: unknown): unknown => {
    // Prevent prototype pollution
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      return undefined;
    }

    return value;
  };

  try {
    const parsed = JSON.parse(jsonString, reviver);
    return parsed as T;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON: ${error.message}`);
    }
    throw error;
  }
}
