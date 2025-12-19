/**
 * IP address validation utilities
 * @module utils/ip-validator
 */

/**
 * Validates if a string is a valid IPv4 address
 */
function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) {return false;}

  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) {return false;}
    if (part !== num.toString()) {return false;} // Prevent leading zeros
  }

  return true;
}

/**
 * Validates if a string is a valid IPv6 address (simplified check)
 */
function isValidIPv6(ip: string): boolean {
  // Basic IPv6 validation - check for valid format
  // IPv6 can be in various formats, this is a simplified check
  if (ip.includes("::")) {
    // Compressed format
    const parts = ip.split("::");
    if (parts.length > 2) {return false;}
    const allParts = parts.join(":").split(":");
    if (allParts.length > 8) {return false;}
    for (const part of allParts) {
      if (part && !/^[0-9a-fA-F]{1,4}$/.test(part)) {return false;}
    }
    return true;
  } else {
    // Full format
    const parts = ip.split(":");
    if (parts.length !== 8) {return false;}
    for (const part of parts) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {return false;}
    }
    return true;
  }
}

/**
 * Checks if an IP address is in a private/internal range
 */
function isPrivateIP(ip: string): boolean {
  if (!isValidIPv4(ip)) {return false;}

  const parts = ip.split(".").map(Number);
  const [a, b] = parts;

  // 10.0.0.0/8
  if (a === 10) {return true;}

  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) {return true;}

  // 192.168.0.0/16
  if (a === 192 && b === 168) {return true;}

  // 127.0.0.0/8 (loopback)
  if (a === 127) {return true;}

  // 169.254.0.0/16 (link-local)
  if (a === 169 && b === 254) {return true;}

  // 0.0.0.0/8 (this network)
  if (a === 0) {return true;}

  // 224.0.0.0/4 (multicast)
  if (a >= 224 && a <= 239) {return true;}

  // 240.0.0.0/4 (reserved)
  if (a >= 240 && a <= 255) {return true;}

  return false;
}

/**
 * Checks if an IPv6 address is in a private/internal range
 */
function isPrivateIPv6(ip: string): boolean {
  if (!isValidIPv6(ip)) {return false;}

  // ::1 (loopback)
  if (ip === "::1" || ip.toLowerCase() === "::1") {return true;}

  // fc00::/7 (unique local)
  if (/^[fF][cCdD][0-9a-fA-F]/.test(ip)) {return true;}

  // fe80::/10 (link-local)
  if (/^[fF][eE][89aAbB][0-9a-fA-F]/.test(ip)) {return true;}

  // ::ffff:0:0/96 (IPv4-mapped)
  if (ip.startsWith("::ffff:")) {
    const ipv4Part = ip.substring(7);
    return isPrivateIP(ipv4Part);
  }

  return false;
}

/**
 * Validates and sanitizes an IP address
 * @param ip - IP address to validate
 * @returns Validated IP address or throws error
 * @throws {Error} If IP is invalid or in private range
 */
export function validateIP(ip: string): string {
  if (!ip || typeof ip !== "string") {
    throw new Error("IP address must be a non-empty string");
  }

  // Trim whitespace
  const trimmed = ip.trim();

  // Check for invalid characters
  if (!/^[0-9a-fA-F:.]+$/.test(trimmed)) {
    throw new Error("IP address contains invalid characters");
  }

  // Check if it's IPv4
  if (trimmed.includes(".")) {
    if (!isValidIPv4(trimmed)) {
      throw new Error("Invalid IPv4 address format");
    }
    if (isPrivateIP(trimmed)) {
      throw new Error("Private/internal IP addresses are not allowed");
    }
    return trimmed;
  }

  // Check if it's IPv6
  if (trimmed.includes(":")) {
    if (!isValidIPv6(trimmed)) {
      throw new Error("Invalid IPv6 address format");
    }
    if (isPrivateIPv6(trimmed)) {
      throw new Error("Private/internal IP addresses are not allowed");
    }
    return trimmed;
  }

  throw new Error("Invalid IP address format");
}

/**
 * Validates an IP address but allows private IPs (for internal use)
 * @param ip - IP address to validate
 * @returns Validated IP address or throws error
 */
export function validateIPAllowPrivate(ip: string): string {
  if (!ip || typeof ip !== "string") {
    throw new Error("IP address must be a non-empty string");
  }

  const trimmed = ip.trim();

  if (!/^[0-9a-fA-F:.]+$/.test(trimmed)) {
    throw new Error("IP address contains invalid characters");
  }

  if (trimmed.includes(".")) {
    if (!isValidIPv4(trimmed)) {
      throw new Error("Invalid IPv4 address format");
    }
    return trimmed;
  }

  if (trimmed.includes(":")) {
    if (!isValidIPv6(trimmed)) {
      throw new Error("Invalid IPv6 address format");
    }
    return trimmed;
  }

  throw new Error("Invalid IP address format");
}
