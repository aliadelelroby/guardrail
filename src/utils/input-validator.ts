/**
 * Input validation utilities
 * @module utils/input-validator
 */

/**
 * Validates and sanitizes string input
 * @param input - Input to validate
 * @param maxLength - Maximum allowed length
 * @param allowEmpty - Whether empty strings are allowed
 * @returns Sanitized input
 * @throws {Error} If input is invalid
 */
export function validateString(
  input: unknown,
  maxLength: number = 10000,
  allowEmpty: boolean = false
): string {
  if (typeof input !== "string") {
    throw new Error("Input must be a string");
  }

  if (!allowEmpty && input.trim().length === 0) {
    throw new Error("Input cannot be empty");
  }

  if (input.length > maxLength) {
    throw new Error(`Input exceeds maximum length of ${maxLength} characters`);
  }

  // Remove null bytes
  return input.replace(/\0/g, "");
}

/**
 * Validates URL input
 * @param input - URL to validate
 * @param allowedProtocols - Allowed URL protocols (default: http, https)
 * @returns Validated URL
 * @throws {Error} If URL is invalid
 */
export function validateUrl(
  input: unknown,
  allowedProtocols: string[] = ["http:", "https:"]
): string {
  const urlString = validateString(input, 2048);

  try {
    const url = new URL(urlString);

    if (!allowedProtocols.includes(url.protocol)) {
      throw new Error(`URL protocol must be one of: ${allowedProtocols.join(", ")}`);
    }

    return urlString;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error("Invalid URL format");
    }
    throw error;
  }
}

/**
 * Validates numeric input
 * @param input - Number to validate
 * @param min - Minimum value
 * @param max - Maximum value
 * @returns Validated number
 * @throws {Error} If number is invalid
 */
export function validateNumber(input: unknown, min?: number, max?: number): number {
  if (typeof input !== "number" || isNaN(input) || !isFinite(input)) {
    throw new Error("Input must be a valid number");
  }

  if (min !== undefined && input < min) {
    throw new Error(`Number must be at least ${min}`);
  }

  if (max !== undefined && input > max) {
    throw new Error(`Number must be at most ${max}`);
  }

  return input;
}

/**
 * Validates array input
 * @param input - Array to validate
 * @param maxLength - Maximum array length
 * @returns Validated array
 * @throws {Error} If array is invalid
 */
export function validateArray<T>(input: unknown, maxLength: number = 1000): T[] {
  if (!Array.isArray(input)) {
    throw new Error("Input must be an array");
  }

  if (input.length > maxLength) {
    throw new Error(`Array length exceeds maximum of ${maxLength}`);
  }

  return input as T[];
}

/**
 * Validates object input
 * @param input - Object to validate
 * @param maxKeys - Maximum number of keys
 * @returns Validated object
 * @throws {Error} If object is invalid
 */
export function validateObject(input: unknown, maxKeys: number = 1000): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("Input must be an object");
  }

  const keys = Object.keys(input);
  if (keys.length > maxKeys) {
    throw new Error(`Object has too many keys (maximum: ${maxKeys})`);
  }

  return input as Record<string, unknown>;
}
