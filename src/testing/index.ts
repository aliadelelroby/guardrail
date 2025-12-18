/**
 * Testing utilities for Guardrail
 * @module testing
 */

import type { GuardrailConfig, StorageAdapter, IPGeolocationService, IPInfo } from "../types/index";
import { Guardrail } from "../core/guardrail";

/**
 * Mock storage implementation for testing
 */
export class MockStorage implements StorageAdapter {
  private data: Map<string, { value: string; expiresAt?: number }> = new Map();

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    this.data.set(key, {
      value,
      expiresAt: ttl ? Date.now() + ttl : undefined,
    });
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    const current = await this.get(key);
    const value = current ? parseInt(current, 10) + amount : amount;
    await this.set(key, String(value));
    return value;
  }

  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.increment(key, -amount);
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  /**
   * Clears all stored data
   */
  clear(): void {
    this.data.clear();
  }

  /**
   * Gets all keys
   */
  keys(): string[] {
    return Array.from(this.data.keys());
  }
}

/**
 * Mock IP geolocation service for testing
 */
export class MockIPGeolocation implements IPGeolocationService {
  private ipMap: Map<string, IPInfo> = new Map();

  /**
   * Sets IP information for testing
   */
  setIP(ip: string, info: IPInfo): void {
    this.ipMap.set(ip, info);
  }

  async lookup(ip: string): Promise<IPInfo> {
    return this.ipMap.get(ip) || {};
  }

  /**
   * Clears all IP mappings
   */
  clear(): void {
    this.ipMap.clear();
  }
}

/**
 * Creates a test Guardrail instance
 * @param config - Configuration (must include rules)
 * @returns Guardrail instance with mock dependencies
 */
export function createTestGuardrail(
  config: Omit<GuardrailConfig, "storage" | "ipService"> &
    Partial<Pick<GuardrailConfig, "storage" | "ipService">>
): {
  guardrail: Guardrail;
  storage: MockStorage;
  ipService: MockIPGeolocation;
} {
  const storage = new MockStorage();
  const ipService = new MockIPGeolocation();

  const guardrail = new Guardrail({
    ...config,
    storage: config.storage ?? storage,
    ipService: config.ipService ?? ipService,
  });

  return { guardrail, storage, ipService };
}

/**
 * Creates a mock request for testing
 */
export function createMockRequest(
  url: string = "https://example.com",
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  } = {}
): Request {
  return new Request(url, {
    method: options.method || "GET",
    headers: options.headers || {},
    body: options.body,
  });
}
