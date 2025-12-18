/**
 * Atomic Redis Storage with Lua scripts
 * Provides race-condition-free rate limiting operations
 * @module storage/redis-atomic
 */

import type { StorageAdapter } from "../types/index";
import Redis from "ioredis";

/**
 * Lua scripts for atomic rate limiting operations
 */
const LUA_SCRIPTS = {
  /**
   * Token bucket atomic operation
   * KEYS[1] = bucket key
   * ARGV[1] = capacity
   * ARGV[2] = refill rate (tokens per interval)
   * ARGV[3] = interval in milliseconds
   * ARGV[4] = requested tokens
   * ARGV[5] = current timestamp
   * Returns: [allowed (0/1), remaining tokens, reset time]
   */
  tokenBucket: `
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local refillRate = tonumber(ARGV[2])
    local interval = tonumber(ARGV[3])
    local requested = tonumber(ARGV[4])
    local now = tonumber(ARGV[5])
    
    -- Get current bucket state
    local bucket = redis.call('HMGET', key, 'tokens', 'lastRefill')
    local tokens = tonumber(bucket[1])
    local lastRefill = tonumber(bucket[2])
    
    -- Initialize if bucket doesn't exist
    if not tokens then
      tokens = capacity
      lastRefill = now
    end
    
    -- Calculate tokens to add based on time passed
    local timePassed = now - lastRefill
    local intervalsElapsed = math.floor(timePassed / interval)
    local tokensToAdd = intervalsElapsed * refillRate
    
    -- Refill tokens (capped at capacity)
    tokens = math.min(capacity, tokens + tokensToAdd)
    
    -- Update lastRefill time
    if intervalsElapsed > 0 then
      lastRefill = lastRefill + (intervalsElapsed * interval)
    end
    
    -- Check if we have enough tokens
    local allowed = 0
    if tokens >= requested then
      tokens = tokens - requested
      allowed = 1
    end
    
    -- Calculate reset time (when bucket will be full again)
    local tokensNeeded = capacity - tokens
    local intervalsNeeded = math.ceil(tokensNeeded / refillRate)
    local resetTime = lastRefill + (intervalsNeeded * interval)
    
    -- Save state
    redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', lastRefill)
    redis.call('PEXPIRE', key, interval * 10) -- Keep for 10 intervals
    
    return {allowed, math.floor(tokens), resetTime}
  `,

  /**
   * Sliding window atomic operation
   * KEYS[1] = window key
   * ARGV[1] = max requests
   * ARGV[2] = window size in milliseconds
   * ARGV[3] = current timestamp
   * Returns: [allowed (0/1), current count, reset time]
   */
  slidingWindow: `
    local key = KEYS[1]
    local max = tonumber(ARGV[1])
    local windowSize = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    
    -- Remove expired entries
    local windowStart = now - windowSize
    redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)
    
    -- Get current count
    local count = redis.call('ZCARD', key)
    
    -- Check if under limit
    local allowed = 0
    if count < max then
      -- Add this request with current timestamp as score
      redis.call('ZADD', key, now, now .. ':' .. math.random())
      count = count + 1
      allowed = 1
    end
    
    -- Get oldest entry for reset time calculation
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local resetTime = now + windowSize
    if oldest[2] then
      resetTime = tonumber(oldest[2]) + windowSize
    end
    
    -- Set expiry on the key
    redis.call('PEXPIRE', key, windowSize + 1000)
    
    return {allowed, tonumber(max) - count, resetTime}
  `,

  /**
   * Fixed window atomic operation
   * KEYS[1] = window key
   * ARGV[1] = max requests
   * ARGV[2] = window size in milliseconds
   * ARGV[3] = current timestamp
   * Returns: [allowed (0/1), remaining count, reset time]
   */
  fixedWindow: `
    local key = KEYS[1]
    local max = tonumber(ARGV[1])
    local windowSize = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    
    -- Calculate window boundaries
    local windowStart = math.floor(now / windowSize) * windowSize
    local windowKey = key .. ':' .. windowStart
    
    -- Get or initialize count
    local count = tonumber(redis.call('GET', windowKey)) or 0
    
    -- Check if under limit
    local allowed = 0
    if count < max then
      count = redis.call('INCR', windowKey)
      -- Set expiry if this is a new window
      if count == 1 then
        redis.call('PEXPIRE', windowKey, windowSize + 1000)
      end
      allowed = 1
    else
      count = count + 1 -- For remaining calculation
    end
    
    local resetTime = windowStart + windowSize
    
    return {allowed, max - count + 1, resetTime}
  `,

  /**
   * Concurrent request limiter
   * KEYS[1] = concurrency key
   * ARGV[1] = max concurrent
   * ARGV[2] = request ID
   * ARGV[3] = timeout in milliseconds
   * ARGV[4] = current timestamp
   * Returns: [allowed (0/1), current count]
   */
  acquireConcurrency: `
    local key = KEYS[1]
    local maxConcurrent = tonumber(ARGV[1])
    local requestId = ARGV[2]
    local timeout = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])
    
    -- Remove expired entries
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
    
    -- Get current count
    local count = redis.call('ZCARD', key)
    
    -- Check if under limit
    local allowed = 0
    if count < maxConcurrent then
      -- Add this request with expiry time as score
      redis.call('ZADD', key, now + timeout, requestId)
      allowed = 1
      count = count + 1
    end
    
    return {allowed, count}
  `,

  /**
   * Release concurrent request slot
   */
  releaseConcurrency: `
    local key = KEYS[1]
    local requestId = ARGV[1]
    
    return redis.call('ZREM', key, requestId)
  `,
};

/**
 * Redis storage options
 */
export interface AtomicRedisStorageOptions {
  /** Redis connection URL or options */
  redis?: string | Redis;
  /** Key prefix for all guardrail keys */
  keyPrefix?: string;
  /** Enable cluster mode */
  cluster?: boolean;
}

/**
 * Token bucket result
 */
export interface TokenBucketResult {
  allowed: boolean;
  remaining: number;
  reset: number;
}

/**
 * Sliding window result
 */
export interface SlidingWindowResult {
  allowed: boolean;
  remaining: number;
  reset: number;
}

/**
 * Atomic Redis Storage using Lua scripts for race-condition-free rate limiting
 */
export class AtomicRedisStorage implements StorageAdapter {
  private readonly client: Redis;
  private readonly keyPrefix: string;
  private scriptsLoaded = false;
  private scriptShas: Record<string, string> = {};

  constructor(options: AtomicRedisStorageOptions = {}) {
    if (options.redis instanceof Redis) {
      this.client = options.redis;
    } else {
      this.client = options.redis ? new Redis(options.redis) : new Redis();
    }
    this.keyPrefix = options.keyPrefix || "guardrail:";
  }

  /**
   * Loads Lua scripts into Redis
   */
  private async ensureScriptsLoaded(): Promise<void> {
    if (this.scriptsLoaded) return;

    for (const [name, script] of Object.entries(LUA_SCRIPTS)) {
      const sha = await this.client.script("LOAD", script) as string;
      this.scriptShas[name] = sha;
    }
    this.scriptsLoaded = true;
  }

  /**
   * Helper to execute Lua script with retry on NOSCRIPT error
   */
  private async executeScript(
    scriptName: keyof typeof LUA_SCRIPTS,
    keys: string[],
    args: (string | number)[]
  ): Promise<any> {
    await this.ensureScriptsLoaded();

    try {
      return await this.client.evalsha(
        this.scriptShas[scriptName],
        keys.length,
        ...keys,
        ...args
      );
    } catch (error: any) {
      if (error?.message?.includes("NOSCRIPT")) {
        this.scriptsLoaded = false;
        await this.ensureScriptsLoaded();
        // Retry once
        return await this.client.evalsha(
          this.scriptShas[scriptName],
          keys.length,
          ...keys,
          ...args
        );
      }
      throw error;
    }
  }

  /**
   * Executes token bucket rate limiting atomically
   */
  async tokenBucket(
    key: string,
    capacity: number,
    refillRate: number,
    intervalMs: number,
    requested: number = 1
  ): Promise<TokenBucketResult> {
    const fullKey = this.keyPrefix + key;
    const now = Date.now();

    const result = (await this.executeScript("tokenBucket", [fullKey], [
      capacity,
      refillRate,
      intervalMs,
      requested,
      now,
    ])) as [number, number, number];

    return {
      allowed: result[0] === 1,
      remaining: result[1],
      reset: result[2],
    };
  }

  /**
   * Executes sliding window rate limiting atomically
   */
  async slidingWindow(
    key: string,
    max: number,
    windowMs: number
  ): Promise<SlidingWindowResult> {
    const fullKey = this.keyPrefix + key;
    const now = Date.now();

    const result = (await this.executeScript("slidingWindow", [fullKey], [
      max,
      windowMs,
      now,
    ])) as [number, number, number];

    return {
      allowed: result[0] === 1,
      remaining: Math.max(0, result[1]),
      reset: result[2],
    };
  }

  /**
   * Executes fixed window rate limiting atomically
   */
  async fixedWindow(
    key: string,
    max: number,
    windowMs: number
  ): Promise<SlidingWindowResult> {
    const fullKey = this.keyPrefix + key;
    const now = Date.now();

    const result = (await this.executeScript("fixedWindow", [fullKey], [
      max,
      windowMs,
      now,
    ])) as [number, number, number];

    return {
      allowed: result[0] === 1,
      remaining: Math.max(0, result[1]),
      reset: result[2],
    };
  }

  /**
   * Acquires a concurrent request slot
   */
  async acquireConcurrency(
    key: string,
    maxConcurrent: number,
    requestId: string,
    timeoutMs: number = 30000
  ): Promise<{ allowed: boolean; current: number }> {
    const fullKey = this.keyPrefix + "concurrent:" + key;
    const now = Date.now();

    const result = (await this.executeScript("acquireConcurrency", [fullKey], [
      maxConcurrent,
      requestId,
      timeoutMs,
      now,
    ])) as [number, number];

    return {
      allowed: result[0] === 1,
      current: result[1],
    };
  }

  /**
   * Releases a concurrent request slot
   */
  async releaseConcurrency(key: string, requestId: string): Promise<void> {
    const fullKey = this.keyPrefix + "concurrent:" + key;

    await this.executeScript("releaseConcurrency", [fullKey], [requestId]);
  }

  // Standard StorageAdapter methods for backwards compatibility

  async get(key: string): Promise<string | null> {
    return this.client.get(this.keyPrefix + key);
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      await this.client.setex(this.keyPrefix + key, Math.ceil(ttl / 1000), value);
    } else {
      await this.client.set(this.keyPrefix + key, value);
    }
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    return this.client.incrby(this.keyPrefix + key, amount);
  }

  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.client.decrby(this.keyPrefix + key, amount);
  }

  async delete(key: string): Promise<void> {
    await this.client.del(this.keyPrefix + key);
  }

  /**
   * Disconnects from Redis
   */
  disconnect(): void {
    this.client.disconnect();
  }

  /**
   * Checks if connected to Redis
   */
  isConnected(): boolean {
    return this.client.status === "ready";
  }

  /**
   * Gets Redis client info
   */
  async getInfo(): Promise<string> {
    return this.client.info();
  }
}
