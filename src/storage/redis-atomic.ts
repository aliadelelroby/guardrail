/**
 * Atomic Redis Storage with Lua scripts
 * Provides race-condition-free rate limiting operations
 * @module storage/redis-atomic
 */

import type { StorageAdapter } from "../types/index";
import Redis from "ioredis";
import { validateKeyPrefix, sanitizeKeyComponent } from "../utils/key-sanitizer";

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
  private clockOffset: number = 0; // Offset between local time and Redis server time
  private lastClockSync: number = 0;
  private readonly clockSyncInterval = 60000; // Sync every minute
  private syncFailureCount: number = 0; // Track consecutive sync failures for exponential backoff

  constructor(options: AtomicRedisStorageOptions = {}) {
    if (options.redis instanceof Redis) {
      this.client = options.redis;
    } else {
      this.client = options.redis ? new Redis(options.redis) : new Redis();
    }
    // Validate and sanitize key prefix
    const prefix = options.keyPrefix || "guardrail:";
    this.keyPrefix = validateKeyPrefix(prefix);

    // Perform initial clock sync
    void this.syncClock();
  }

  /**
   * Synchronizes local clock with Redis server time to handle clock skew
   *
   * NOTE: For production deployments, ensure all servers (application and Redis) are synchronized
   * using NTP (Network Time Protocol) to minimize clock drift. This sync is a fallback mechanism.
   */
  private async syncClock(): Promise<void> {
    // Exponential backoff: skip sync if we've had recent failures
    if (this.syncFailureCount > 0) {
      const backoffMs = Math.min(1000 * Math.pow(2, this.syncFailureCount - 1), 60000); // Max 60s
      if (Date.now() - this.lastClockSync < backoffMs) {
        return; // Skip this sync attempt
      }
    }

    try {
      const localBefore = Date.now();
      const redisTime = await this.client.time();
      const localAfter = Date.now();

      // Redis TIME returns [seconds, microseconds]
      const redisMs = redisTime[0] * 1000 + Math.floor(redisTime[1] / 1000);
      const localMid = (localBefore + localAfter) / 2;

      this.clockOffset = redisMs - localMid;
      this.lastClockSync = Date.now();
      this.syncFailureCount = 0; // Reset failure count on success

      // Warn if clock skew is significant (>1 second)
      if (Math.abs(this.clockOffset) > 1000) {
        console.warn(
          `[Guardrail] Clock skew detected: ${this.clockOffset}ms difference between local and Redis server time. This may affect rate limiting accuracy. Consider synchronizing servers with NTP.`
        );
      }
    } catch (error) {
      // If TIME command fails, use local time (fallback)
      this.syncFailureCount += 1;
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Only warn on first failure or every 10th failure to avoid log spam
      if (this.syncFailureCount === 1 || this.syncFailureCount % 10 === 0) {
        console.warn(
          `[Guardrail] Failed to sync with Redis server time (attempt ${this.syncFailureCount}): ${errorMessage}. Using local time. Ensure Redis is accessible and servers are NTP-synchronized.`
        );
      }

      // Reset offset on failure (use local time)
      this.clockOffset = 0;
    }
  }

  /**
   * Gets current time adjusted for clock skew (uses Redis time when available)
   */
  private async getAdjustedTime(): Promise<number> {
    // Re-sync clock if it's been more than 1 minute
    if (Date.now() - this.lastClockSync > this.clockSyncInterval) {
      await this.syncClock();
    }

    // Use Redis time if offset is significant, otherwise use local time
    if (Math.abs(this.clockOffset) > 100) {
      try {
        const redisTime = await this.client.time();
        const redisMs = redisTime[0] * 1000 + Math.floor(redisTime[1] / 1000);
        return redisMs;
      } catch {
        // Fallback to local time with offset
        return Date.now() + this.clockOffset;
      }
    }

    return Date.now();
  }

  /**
   * Loads Lua scripts into Redis
   */
  private async ensureScriptsLoaded(): Promise<void> {
    if (this.scriptsLoaded) {
      return;
    }

    for (const [name, script] of Object.entries(LUA_SCRIPTS)) {
      const sha = (await this.client.script("LOAD", script)) as string;
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
      return await this.client.evalsha(this.scriptShas[scriptName], keys.length, ...keys, ...args);
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
    // Sanitize key component to prevent injection
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    const fullKey = this.keyPrefix + sanitizedKey;
    const now = await this.getAdjustedTime();

    const result = (await this.executeScript(
      "tokenBucket",
      [fullKey],
      [capacity, refillRate, intervalMs, requested, now]
    )) as [number, number, number];

    return {
      allowed: result[0] === 1,
      remaining: result[1],
      reset: result[2],
    };
  }

  /**
   * Executes sliding window rate limiting atomically
   */
  async slidingWindow(key: string, max: number, windowMs: number): Promise<SlidingWindowResult> {
    // Sanitize key component to prevent injection
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    const fullKey = this.keyPrefix + sanitizedKey;
    const now = await this.getAdjustedTime();

    const result = (await this.executeScript("slidingWindow", [fullKey], [max, windowMs, now])) as [
      number,
      number,
      number,
    ];

    return {
      allowed: result[0] === 1,
      remaining: Math.max(0, result[1]),
      reset: result[2],
    };
  }

  /**
   * Executes fixed window rate limiting atomically
   */
  async fixedWindow(key: string, max: number, windowMs: number): Promise<SlidingWindowResult> {
    // Sanitize key component to prevent injection
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    const fullKey = this.keyPrefix + sanitizedKey;
    const now = await this.getAdjustedTime();

    const result = (await this.executeScript("fixedWindow", [fullKey], [max, windowMs, now])) as [
      number,
      number,
      number,
    ];

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
    // Validate requestId format (should be UUID or similar)
    if (!requestId || typeof requestId !== "string") {
      throw new Error("requestId must be a non-empty string");
    }
    if (requestId.length > 128) {
      throw new Error("requestId exceeds maximum length of 128 characters");
    }
    // Sanitize requestId to prevent injection
    const sanitizedRequestId = sanitizeKeyComponent(requestId, 128);

    // Sanitize key component
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    const fullKey = this.keyPrefix + "concurrent:" + sanitizedKey;
    const now = Date.now();

    const result = (await this.executeScript(
      "acquireConcurrency",
      [fullKey],
      [maxConcurrent, sanitizedRequestId, timeoutMs, now]
    )) as [number, number];

    return {
      allowed: result[0] === 1,
      current: result[1],
    };
  }

  /**
   * Releases a concurrent request slot
   */
  async releaseConcurrency(key: string, requestId: string): Promise<void> {
    // Validate requestId
    if (!requestId || typeof requestId !== "string") {
      throw new Error("requestId must be a non-empty string");
    }
    if (requestId.length > 128) {
      throw new Error("requestId exceeds maximum length of 128 characters");
    }
    const sanitizedRequestId = sanitizeKeyComponent(requestId, 128);

    // Sanitize key
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    const fullKey = this.keyPrefix + "concurrent:" + sanitizedKey;

    await this.executeScript("releaseConcurrency", [fullKey], [sanitizedRequestId]);
  }

  // Standard StorageAdapter methods for backwards compatibility

  async get(key: string): Promise<string | null> {
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    return this.client.get(this.keyPrefix + sanitizedKey);
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    if (ttl) {
      await this.client.setex(this.keyPrefix + sanitizedKey, Math.ceil(ttl / 1000), value);
    } else {
      await this.client.set(this.keyPrefix + sanitizedKey, value);
    }
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    return this.client.incrby(this.keyPrefix + sanitizedKey, amount);
  }

  async decrement(key: string, amount: number = 1): Promise<number> {
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    return this.client.decrby(this.keyPrefix + sanitizedKey, amount);
  }

  async delete(key: string): Promise<void> {
    const sanitizedKey = sanitizeKeyComponent(key, 200);
    await this.client.del(this.keyPrefix + sanitizedKey);
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
