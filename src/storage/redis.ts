/**
 * Redis storage adapter for distributed deployments
 * @module storage/redis
 */

import type { StorageAdapter } from "../types/index";
import Redis from "ioredis";

/**
 * Redis-based storage implementation for distributed rate limiting
 * Suitable for multi-instance deployments
 */
export class RedisStorage implements StorageAdapter {
  private readonly client: Redis;

  /**
   * Creates a new RedisStorage instance
   * @param redisUrl - Optional Redis connection URL (defaults to localhost:6379)
   */
  constructor(redisUrl?: string) {
    this.client = redisUrl ? new Redis(redisUrl) : new Redis();
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
