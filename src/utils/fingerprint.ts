/**
 * Fingerprint utilities for generating unique keys based on characteristics
 * @module utils/fingerprint
 */

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
      return `${char}:${String(value)}`;
    })
    .filter((part): part is string => part !== null);

  if (parts.length === 0) {
    throw new Error("At least one characteristic must have a value");
  }

  return parts.join("|");
}

/**
 * Extracts IP address from a Request object
 * Checks x-forwarded-for and x-real-ip headers
 * @param request - Web API Request object
 * @returns IP address or "unknown" if not found
 */
export function extractIPFromRequest(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }

  const realIP = request.headers.get("x-real-ip");
  if (realIP) {
    return realIP.trim();
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
