/**
 * IP geolocation service implementation
 * Uses free IP geolocation APIs with fallback support
 * @module services/ip-geolocation
 */

import type { IPGeolocationService, IPInfo, StorageAdapter } from "../types/index";
import { validateIP } from "../utils/ip-validator";
import { safeJsonParse } from "../utils/safe-json";

// Maximum response size for external API calls (1MB)
const MAX_API_RESPONSE_SIZE = 1024 * 1024;

interface IPApiCoResponse {
  country_code?: string;
  country_name?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  postal?: string;
  timezone?: string;
  asn?: number;
  org?: string;
  error?: boolean;
  reason?: string;
}

interface IPApiComResponse {
  countryCode?: string;
  country?: string;
  regionName?: string;
  city?: string;
  lat?: number;
  lon?: number;
  zip?: string;
  timezone?: string;
  as?: number;
  org?: string;
}

/**
 * IP geolocation provider interface
 */
interface IPGeolocationProvider {
  name: string;
  lookup(ip: string, timeoutMs?: number): Promise<IPInfo>;
  isHealthy(): boolean;
}

/**
 * IP geolocation service using free APIs with caching and fallback chain
 */
export class IPGeolocation implements IPGeolocationService {
  private readonly storage?: StorageAdapter;
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();
  private readonly cacheTtl: number;
  private readonly providers: IPGeolocationProvider[] = [];
  private providerHealth = new Map<
    string,
    { failures: number; lastFailure: number; healthy: boolean }
  >();

  /**
   * Creates a new IPGeolocation instance
   * @param storage - Optional storage adapter for distributed caching
   * @param cacheTtl - Cache TTL in milliseconds (default: 24 hours)
   */
  constructor(storage?: StorageAdapter, cacheTtl: number = 24 * 60 * 60 * 1000) {
    this.storage = storage;
    this.cacheTtl = cacheTtl;

    // Initialize providers with health tracking
    this.providers = [
      {
        name: "ipapi.co",
        lookup: (ip: string, timeoutMs?: number) => this.fetchFromIpApiCo(ip, timeoutMs),
        isHealthy: () => this.isProviderHealthy("ipapi.co"),
      },
      {
        name: "ip-api.com",
        lookup: (ip: string, timeoutMs?: number) => this.fetchFromIpApiCom(ip, timeoutMs),
        isHealthy: () => this.isProviderHealthy("ip-api.com"),
      },
    ];

    // Initialize health tracking
    for (const provider of this.providers) {
      this.providerHealth.set(provider.name, { failures: 0, lastFailure: 0, healthy: true });
    }
  }

  /**
   * Checks if a provider is healthy (not too many recent failures)
   * Improved health tracking with automatic recovery mechanism
   */
  private isProviderHealthy(name: string): boolean {
    const health = this.providerHealth.get(name);
    if (!health) {
      return true;
    }

    // Provider is unhealthy if it has 3+ failures in the last 5 minutes
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    const isRecentlyFailed = health.lastFailure > fiveMinutesAgo;

    // Automatic recovery: if provider has been healthy for 10 minutes, reset failure count
    const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
    if (!isRecentlyFailed && health.lastFailure < tenMinutesAgo && health.failures > 0) {
      // Provider has recovered - reset failure count
      health.failures = 0;
      health.healthy = true;
      this.providerHealth.set(name, health);
    }

    if (health.failures >= 3 && isRecentlyFailed) {
      return false;
    }

    // Reset failures if last failure was more than 5 minutes ago
    if (health.lastFailure < fiveMinutesAgo && health.failures > 0) {
      health.failures = 0;
      health.healthy = true;
      this.providerHealth.set(name, health);
    }

    return health.healthy;
  }

  /**
   * Records a provider failure
   * Improved tracking with automatic recovery threshold
   */
  private recordProviderFailure(name: string): void {
    const health = this.providerHealth.get(name) || { failures: 0, lastFailure: 0, healthy: true };
    health.failures += 1;
    health.lastFailure = Date.now();

    // Cap failure count to prevent unbounded growth
    // After 10 consecutive failures, mark as permanently unhealthy until manual reset
    if (health.failures > 10) {
      health.failures = 10; // Cap at 10
    }

    if (health.failures >= 3) {
      health.healthy = false;
    }
    this.providerHealth.set(name, health);
  }

  /**
   * Records a provider success
   * Improved recovery mechanism with faster reset on consecutive successes
   */
  private recordProviderSuccess(name: string): void {
    const health = this.providerHealth.get(name) || { failures: 0, lastFailure: 0, healthy: true };
    const timeSinceLastFailure = Date.now() - health.lastFailure;

    // Faster recovery: reduce failure count more aggressively on success
    // If we have 2+ consecutive successes, reset failure count faster
    if (health.failures > 0) {
      if (timeSinceLastFailure > 2 * 60 * 1000) {
        // If it's been more than 2 minutes since last failure, reset completely
        health.failures = 0;
        health.healthy = true;
      } else {
        // Otherwise, reduce by 2 for faster recovery
        health.failures = Math.max(0, health.failures - 2);
        if (health.failures === 0) {
          health.healthy = true;
        }
      }
    } else {
      health.healthy = true;
    }

    this.providerHealth.set(name, health);
  }

  /**
   * Looks up IP geolocation information
   * @param ip - IP address to lookup
   * @returns Promise resolving to IP information
   */
  async lookup(ip: string): Promise<IPInfo> {
    // Validate IP address format and block private IPs to prevent SSRF
    try {
      validateIP(ip);
    } catch (error) {
      // If validation fails (invalid format or private IP), return default info
      return this.getDefaultIPInfo();
    }

    // 1. Try local memory cache
    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    // 2. Try distributed storage cache if available
    if (this.storage) {
      try {
        const stored = await this.storage.get(`ip-cache:${ip}`);
        if (stored) {
          const data = safeJsonParse<IPInfo>(stored);
          // Update local cache
          this.cache.set(ip, {
            data,
            expires: Date.now() + this.cacheTtl,
          });
          return data;
        }
      } catch (e) {
        console.warn("[Guardrail] Failed to read from IP storage cache:", e);
      }
    }

    // Try providers in order, skipping unhealthy ones
    const healthyProviders = this.providers.filter((p) => p.isHealthy());
    const allProviders = healthyProviders.length > 0 ? healthyProviders : this.providers;

    // Overall timeout for entire lookup operation (15 seconds)
    // Prevents excessive delays if all providers are slow/failing
    const overallTimeoutMs = 15000;
    const lookupStartTime = Date.now();

    for (let i = 0; i < allProviders.length; i++) {
      // Check overall timeout before trying next provider
      const elapsed = Date.now() - lookupStartTime;
      if (elapsed >= overallTimeoutMs) {
        console.warn(
          `[Guardrail] IP geolocation lookup exceeded overall timeout (${overallTimeoutMs}ms). Using default info.`
        );
        return this.getDefaultIPInfo();
      }

      const provider = allProviders[i];
      try {
        // Calculate remaining time for this provider attempt
        const remainingTime = overallTimeoutMs - elapsed;
        if (remainingTime <= 0) {
          break; // No time left
        }

        // Use remaining time for provider timeout (max 10s, but respect overall timeout)
        const providerTimeout = Math.min(remainingTime, 10000);
        const info = await provider.lookup(ip, providerTimeout);

        // Record success
        this.recordProviderSuccess(provider.name);

        // Update local cache
        this.cache.set(ip, {
          data: info,
          expires: Date.now() + this.cacheTtl,
        });

        // Update distributed storage cache if available
        if (this.storage) {
          try {
            await this.storage.set(`ip-cache:${ip}`, JSON.stringify(info), this.cacheTtl);
          } catch (e) {
            console.warn("[Guardrail] Failed to write to IP storage cache:", e);
          }
        }

        return info;
      } catch (error) {
        // Record failure
        this.recordProviderFailure(provider.name);

        const errorMessage = error instanceof Error ? error.message : String(error);
        const isRateLimit = errorMessage.includes("429") || errorMessage.includes("rate limit");

        if (isRateLimit) {
          console.warn(
            `[Guardrail] IP Geolocation provider ${provider.name} rate limit hit. Trying next provider...`
          );
        } else {
          console.warn(
            `[Guardrail] IP Geolocation provider ${provider.name} failed: ${errorMessage}. Trying next provider...`
          );
        }

        // Exponential backoff before trying next provider (except for last provider)
        // But respect overall timeout
        if (i < allProviders.length - 1) {
          const elapsed = Date.now() - lookupStartTime;
          const remainingTime = overallTimeoutMs - elapsed;
          if (remainingTime > 0) {
            const backoffMs = Math.min(
              100 * Math.pow(2, i),
              Math.min(2000, remainingTime - 100) // Don't exceed remaining time (leave 100ms buffer)
            );
            if (backoffMs > 0) {
              await new Promise((resolve) => setTimeout(resolve, backoffMs));
            }
          }
        }

        // Continue to next provider
        continue;
      }
    }

    // All providers failed, return default
    console.warn(
      `[Guardrail] All IP geolocation providers failed for ${ip}. Using default info. Consider using a premium provider for production: https://guardrail.dev/docs/ip-intelligence`
    );
    return this.getDefaultIPInfo();
  }

  /**
   * Fetches IP info from ipapi.co
   */
  private async fetchFromIpApiCo(ip: string, timeoutMs: number = 10000): Promise<IPInfo> {
    // IP is already validated in lookup(), but validate again for safety
    try {
      validateIP(ip);
    } catch {
      throw new Error("Invalid IP address");
    }

    // Use URL encoding to prevent injection
    const encodedIP = encodeURIComponent(ip);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetch(`https://ipapi.co/${encodedIP}/json/`, {
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (response.status === 429) {
          throw new Error("HTTP 429: Rate limit exceeded");
        }
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        // Use helper function to read response with size limits
        const responseText = await this.readResponseWithLimit(response);
        const data = safeJsonParse<IPApiCoResponse>(responseText);

        if (data.error) {
          throw new Error(data.reason || "API Error");
        }

        return {
          country: data.country_code,
          countryName: data.country_name,
          region: data.region,
          city: data.city,
          latitude: data.latitude,
          longitude: data.longitude,
          postalCode: data.postal,
          timezone: data.timezone,
          asn: data.asn,
          asnName: data.org,
          asnType: this.inferASNType(data.org || ""),
        };
      } catch (fetchError) {
        if (fetchError instanceof Error && fetchError.name === "AbortError") {
          throw new Error("API request timeout");
        }
        throw fetchError;
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes("429")) {
        throw e;
      }
      if (e instanceof Error && e.name === "AbortError") {
        throw new Error("API request timeout");
      }
      throw e;
    }
  }

  /**
   * Fetches IP info from ip-api.com
   */
  private async fetchFromIpApiCom(ip: string, timeoutMs: number = 10000): Promise<IPInfo> {
    const encodedIP = encodeURIComponent(ip);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`https://ip-api.com/json/${encodedIP}`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (response.status === 429) {
        throw new Error("HTTP 429: Rate limit exceeded");
      }
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      // Use helper function to read response with size limits
      const responseText = await this.readResponseWithLimit(response);
      const data = safeJsonParse<IPApiComResponse>(responseText);

      return {
        country: data.countryCode,
        countryName: data.country,
        region: data.regionName,
        city: data.city,
        latitude: data.lat,
        longitude: data.lon,
        postalCode: data.zip,
        timezone: data.timezone,
        asn: data.as,
        asnName: data.org,
        asnType: this.inferASNType(data.org || ""),
      };
    } catch (fetchError) {
      clearTimeout(timeoutId);
      if (fetchError instanceof Error && fetchError.name === "AbortError") {
        throw new Error("API request timeout");
      }
      throw fetchError;
    }
  }

  /**
   * Safely reads a fetch response with size limits
   */
  private async readResponseWithLimit(response: Response): Promise<string> {
    const contentLength = response.headers.get("content-length");
    if (contentLength) {
      const size = parseInt(contentLength, 10);
      if (!isNaN(size) && size > MAX_API_RESPONSE_SIZE) {
        throw new Error("API response too large");
      }
    }

    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error("No response body");
    }

    let responseText = "";
    let totalSize = 0;
    const decoder = new TextDecoder();

    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }

        totalSize += value.length;
        if (totalSize > MAX_API_RESPONSE_SIZE) {
          void reader.cancel();
          throw new Error("API response exceeds size limit");
        }

        responseText += decoder.decode(value, { stream: true });
      }
      responseText += decoder.decode();
    } finally {
      reader.releaseLock();
    }

    return responseText;
  }

  private inferASNType(org: string): "isp" | "hosting" | "business" | "education" {
    const orgLower = org.toLowerCase();
    if (
      orgLower.includes("hosting") ||
      orgLower.includes("datacenter") ||
      orgLower.includes("server") ||
      orgLower.includes("cloud")
    ) {
      return "hosting";
    }
    if (orgLower.includes("university") || orgLower.includes("edu")) {
      return "education";
    }
    if (
      orgLower.includes("inc") ||
      orgLower.includes("corp") ||
      orgLower.includes("llc") ||
      orgLower.includes("ltd")
    ) {
      return "business";
    }
    return "isp";
  }

  private getDefaultIPInfo(): IPInfo {
    return {};
  }
}
