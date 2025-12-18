/**
 * Key sanitization utilities for Redis and storage keys
 * @module utils/key-sanitizer
 */

/**
 * Maximum key length (Redis key limit is 512MB, but we use a reasonable limit)
 */
const MAX_KEY_LENGTH = 256;

/**
 * Characters that are unsafe in Redis keys
 */
const UNSAFE_KEY_CHARS = /[^\w\-:.]/g;

/**
 * Sanitizes a key component to prevent injection and collision attacks
 * @param value - Value to sanitize
 * @param maxLength - Maximum length for this component (default: 100)
 * @returns Sanitized key component
 */
export function sanitizeKeyComponent(value: string | number, maxLength: number = 100): string {
  const str = String(value);

  // Remove null bytes
  let sanitized = str.replace(/\0/g, "");

  // Remove unsafe characters
  sanitized = sanitized.replace(UNSAFE_KEY_CHARS, "_");

  // Limit length
  if (sanitized.length > maxLength) {
    // Use hash for very long values to prevent key collision while maintaining uniqueness
    const hash = simpleHash(sanitized);
    sanitized = sanitized.substring(0, maxLength - 9) + "_" + hash;
  }

  return sanitized;
}

/**
 * Simple hash function for key components (non-cryptographic, for collision prevention)
 */
function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(36).substring(0, 8);
}

/**
 * Validates and sanitizes a complete Redis key
 * @param key - Key to validate
 * @returns Sanitized key
 * @throws {Error} If key is invalid
 */
export function validateRedisKey(key: string): string {
  if (!key || typeof key !== "string") {
    throw new Error("Redis key must be a non-empty string");
  }

  if (key.length > MAX_KEY_LENGTH) {
    throw new Error(`Redis key exceeds maximum length of ${MAX_KEY_LENGTH} characters`);
  }

  // Remove null bytes
  let sanitized = key.replace(/\0/g, "");

  // Replace unsafe characters
  sanitized = sanitized.replace(UNSAFE_KEY_CHARS, "_");

  // Ensure key doesn't start or end with special characters
  sanitized = sanitized.replace(/^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$/g, "");

  if (sanitized.length === 0) {
    throw new Error("Redis key becomes empty after sanitization");
  }

  return sanitized;
}

/**
 * Validates a key prefix
 * @param prefix - Prefix to validate
 * @returns Sanitized prefix
 * @throws {Error} If prefix is invalid
 */
export function validateKeyPrefix(prefix: string): string {
  if (!prefix || typeof prefix !== "string") {
    throw new Error("Key prefix must be a non-empty string");
  }

  if (prefix.length > 50) {
    throw new Error("Key prefix exceeds maximum length of 50 characters");
  }

  // Key prefix should only contain safe characters
  if (!/^[a-zA-Z0-9_\-:]+$/.test(prefix)) {
    throw new Error(
      "Key prefix contains invalid characters. Only alphanumeric, underscore, hyphen, and colon are allowed"
    );
  }

  return prefix;
}
