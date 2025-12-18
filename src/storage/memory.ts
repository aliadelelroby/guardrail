/**
 * In-memory storage adapter for development and single-instance deployments
 * @module storage/memory
 */

import type { StorageAdapter } from "../types/index";
import { LRUCache } from "lru-cache";

/**
 * Cache entry with expiration timestamp
 */
interface CacheEntry {
  value: string;
  expiresAt?: number;
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
      ttl: 0,
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

    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.cache.delete(key);
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
      expiresAt: ttl ? Date.now() + ttl : undefined,
    };
    this.cache.set(key, entry);
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
}
