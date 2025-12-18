/**
 * Redis storage adapter for distributed deployments
 * @module storage/redis
 */

import type { StorageAdapter } from "../types/index";
import Redis from "ioredis";

/**
 * Validates Redis connection URL to prevent SSRF
 * @param url - Redis URL to validate
 * @throws {Error} If URL is invalid or points to disallowed hosts
 */
function validateRedisUrl(url: string): void {
  if (!url || typeof url !== "string") {
    throw new Error("Redis URL must be a non-empty string");
  }

  try {
    const parsed = new URL(url);

    // Only allow redis:// and rediss:// schemes
    if (parsed.protocol !== "redis:" && parsed.protocol !== "rediss:") {
      throw new Error("Redis URL must use redis:// or rediss:// scheme");
    }

    // Block private/internal IP addresses to prevent SSRF
    const hostname = parsed.hostname;
    if (!hostname) {
      throw new Error("Redis URL must include a hostname");
    }

    // Check for private IP patterns
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("10.") ||
      hostname.startsWith("172.16.") ||
      hostname.startsWith("172.17.") ||
      hostname.startsWith("172.18.") ||
      hostname.startsWith("172.19.") ||
      hostname.startsWith("172.20.") ||
      hostname.startsWith("172.21.") ||
      hostname.startsWith("172.22.") ||
      hostname.startsWith("172.23.") ||
      hostname.startsWith("172.24.") ||
      hostname.startsWith("172.25.") ||
      hostname.startsWith("172.26.") ||
      hostname.startsWith("172.27.") ||
      hostname.startsWith("172.28.") ||
      hostname.startsWith("172.29.") ||
      hostname.startsWith("172.30.") ||
      hostname.startsWith("172.31.")
    ) {
      // Allow localhost/private IPs only if explicitly configured (for development)
      // In production, this should be restricted
      if (process.env.NODE_ENV === "production") {
        throw new Error("Private IP addresses are not allowed for Redis in production");
      }
    }

    // Validate port if present
    if (parsed.port) {
      const port = parseInt(parsed.port, 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error("Invalid Redis port number");
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Invalid Redis URL: ${error.message}`);
    }
    throw new Error("Invalid Redis URL format");
  }
}

/**
 * Redis-based storage implementation for distributed rate limiting
 * Suitable for multi-instance deployments
 */
export class RedisStorage implements StorageAdapter {
  private readonly client: Redis;

  /**
   * Creates a new RedisStorage instance
   * @param redisUrl - Optional Redis connection URL (defaults to localhost:6379)
   * @throws {Error} If Redis URL is invalid or points to disallowed hosts
   * @note Redis URL should never come from untrusted sources (user input, etc.)
   */
  constructor(redisUrl?: string) {
    if (redisUrl) {
      validateRedisUrl(redisUrl);
      this.client = new Redis(redisUrl);
    } else {
      // Default to localhost (safe for development)
      this.client = new Redis();
    }
  }

  /**
   * Gets a value by key
   * @param key - Storage key
   * @returns Promise resolving to value or null if not found
   */
  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  /**
   * Sets a value with optional TTL
   * @param key - Storage key
   * @param value - Value to store
   * @param ttl - Time to live in milliseconds (converted to seconds for Redis)
   */
  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      await this.client.setex(key, Math.ceil(ttl / 1000), value);
    } else {
      await this.client.set(key, value);
    }
  }

  /**
   * Increments a numeric value
   * @param key - Storage key
   * @param amount - Amount to increment (default: 1)
   * @returns Promise resolving to new value
   */
  async increment(key: string, amount: number = 1): Promise<number> {
    return this.client.incrby(key, amount);
  }

  /**
   * Decrements a numeric value
   * @param key - Storage key
   * @param amount - Amount to decrement (default: 1)
   * @returns Promise resolving to new value
   */
  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.client.decrby(key, amount);
  }

  /**
   * Deletes a key
   * @param key - Storage key to delete
   */
  async delete(key: string): Promise<void> {
    await this.client.del(key);
  }

  /**
   * Disconnects from Redis
   */
  disconnect(): void {
    this.client.disconnect();
  }
}
