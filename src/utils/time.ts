/**
 * Time utility functions for parsing intervals and time calculations
 * @module utils/time
 */

/**
 * Parses an interval string into milliseconds
 * @param interval - Interval string (e.g., "1h", "30m", "5s", "2d")
 * @returns Interval in milliseconds
 * @throws {Error} If interval format is invalid
 */
export function parseInterval(interval: string): number {
  const match = interval.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`Invalid interval format: ${interval}. Use format like "1h", "30m", "5s"`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  const multipliers: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return value * multipliers[unit];
}

/**
 * Gets current timestamp in milliseconds
 * @returns Current timestamp
 */
export function getCurrentTimestamp(): number {
  return Date.now();
}

/**
 * Calculates seconds until a given timestamp
 * @param ms - Target timestamp in milliseconds
 * @returns Seconds until target timestamp (rounded up)
 */
export function getSecondsUntil(ms: number): number {
  return Math.ceil((ms - Date.now()) / 1000);
}
