/**
 * In-memory storage adapter for development and single-instance deployments
 * @module storage/memory
 */

import type { StorageAdapter } from "../types/index";
import { LRUCache } from "lru-cache";
import { safeJsonParse } from "../utils/safe-json";

/**
 * Cache entry with expiration timestamp
 */
interface CacheEntry {
  value: string;
}

/**
 * In-memory storage implementation using LRU cache
 * Suitable for development and single-instance deployments
 */
export class MemoryStorage implements StorageAdapter {
  private readonly cache: LRUCache<string, CacheEntry>;

  /**
   * Creates a new MemoryStorage instance
   * @param maxSize - Maximum number of entries in cache (default: 10000)
   */
  constructor(maxSize: number = 10000) {
    this.cache = new LRUCache<string, CacheEntry>({
      max: maxSize,
      ttl: 24 * 60 * 60 * 1000, // Default 24h TTL for memory safety
      ttlAutopurge: true,
      updateAgeOnGet: false,
    });
  }

  /**
   * Gets a value by key
   * @param key - Storage key
   * @returns Promise resolving to value or null if not found/expired
   */
  async get(key: string): Promise<string | null> {
    const entry = this.cache.get(key);
    if (!entry) {
      return null;
    }

    return entry.value;
  }

  /**
   * Sets a value with optional TTL
   * @param key - Storage key
   * @param value - Value to store
   * @param ttl - Time to live in milliseconds
   */
  async set(key: string, value: string, ttl?: number): Promise<void> {
    const entry: CacheEntry = {
      value,
    };

    // Node.js setTimeout limit is 2^31-1 ms. Cap TTL to avoid overflow warnings.
    const cappedTtl = ttl !== undefined ? Math.min(ttl, 2147483647) : undefined;

    this.cache.set(key, entry, { ttl: cappedTtl });
  }

  /**
   * Increments a numeric value
   * @param key - Storage key
   * @param amount - Amount to increment (default: 1)
   * @returns Promise resolving to new value
   */
  async increment(key: string, amount: number = 1): Promise<number> {
    const current = await this.get(key);
    const currentValue = current ? parseInt(current, 10) : 0;
    const newValue = currentValue + amount;
    await this.set(key, String(newValue));
    return newValue;
  }

  /**
   * Decrements a numeric value
   * @param key - Storage key
   * @param amount - Amount to decrement (default: 1)
   * @returns Promise resolving to new value
   */
  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.increment(key, -amount);
  }

  /**
   * Deletes a key
   * @param key - Storage key to delete
   */
  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }

  /**
   * Pushes a value to a list stored at key
   */
  async push(key: string, value: string, ttl?: number): Promise<void> {
    const current = await this.get(key);
    let list: string[] = [];
    if (current) {
      try {
        list = safeJsonParse<string[]>(current);
      } catch {
        list = [];
      }
    }
    list.push(value);
    await this.set(key, JSON.stringify(list), ttl);
  }

  /**
   * Gets a range of values from a list stored at key
   */
  async range(key: string, start: number, end: number): Promise<string[]> {
    const current = await this.get(key);
    if (!current) {return [];}
    try {
      const list = safeJsonParse<string[]>(current);
      return list.slice(start, end < 0 ? undefined : end + 1);
    } catch {
      return [];
    }
  }

  /**
   * Trims a list stored at key to specified range
   */
  async trim(key: string, start: number, end: number): Promise<void> {
    const current = await this.get(key);
    if (!current) {return;}
    try {
      const list = safeJsonParse<string[]>(current);
      const trimmed = list.slice(start, end < 0 ? undefined : end + 1);
      await this.set(key, JSON.stringify(trimmed));
    } catch {
      // Ignore parse errors
    }
  }
}
