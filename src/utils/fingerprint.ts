/**
 * Fingerprint utilities for generating unique keys based on characteristics
 * @module utils/fingerprint
 */

import { validateIPAllowPrivate } from "./ip-validator";
import { sanitizeKeyComponent } from "./key-sanitizer";

/**
 * Maximum length for fingerprint components
 */
const MAX_FINGERPRINT_COMPONENT_LENGTH = 100;

/**
 * Generates a fingerprint string from characteristics and values
 * @param characteristics - List of characteristic names
 * @param values - Map of characteristic values
 * @returns Fingerprint string
 * @throws {Error} If no characteristics have values
 */
export function generateFingerprint(
  characteristics: string[],
  values: Record<string, string | number | undefined>
): string {
  const parts = characteristics
    .map((char) => {
      const value = values[char];
      if (value === undefined || value === null) {
        return null;
      }

      // Sanitize both the characteristic name and value to prevent injection
      const sanitizedChar = sanitizeKeyComponent(char, 50);
      const sanitizedValue = sanitizeKeyComponent(value, MAX_FINGERPRINT_COMPONENT_LENGTH);

      return `${sanitizedChar}:${sanitizedValue}`;
    })
    .filter((part): part is string => part !== null);

  if (parts.length === 0) {
    throw new Error("At least one characteristic must have a value");
  }

  // Join with pipe character (already sanitized, so safe)
  const fingerprint = parts.join("|");

  // Final validation: ensure total length is reasonable
  if (fingerprint.length > 500) {
    throw new Error("Fingerprint exceeds maximum length");
  }

  return fingerprint;
}

/**
 * Extracts and validates IP address from a Request object
 * Checks x-forwarded-for and x-real-ip headers
 * @param request - Web API Request object
 * @returns Validated IP address or "unknown" if not found/invalid
 */
export function extractIPFromRequest(request: Request): string {
  let ip: string | null = null;

  // Check x-forwarded-for header (first IP in the chain)
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    // x-forwarded-for can contain multiple IPs separated by commas
    const ips = forwarded.split(",").map((ip) => ip.trim());
    if (ips.length > 0) {
      ip = ips[0];
  }
  }

  // Fallback to x-real-ip if x-forwarded-for is not available
  if (!ip) {
  const realIP = request.headers.get("x-real-ip");
  if (realIP) {
      ip = realIP.trim();
    }
  }

  // Validate IP address format
  if (ip) {
    try {
      // Use validateIPAllowPrivate since we want to allow private IPs for fingerprinting
      return validateIPAllowPrivate(ip);
    } catch {
      // If validation fails, return unknown
      return "unknown";
    }
  }

  return "unknown";
}

/**
 * Extracts user agent from a Request object
 * @param request - Web API Request object
 * @returns User agent string or "unknown" if not found
 */
export function extractUserAgent(request: Request): string {
  return request.headers.get("user-agent") || "unknown";
}
