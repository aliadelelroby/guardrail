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
 * IP geolocation service using free APIs with caching
 */
export class IPGeolocation implements IPGeolocationService {
  private readonly storage?: StorageAdapter;
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();
  private readonly cacheTtl: number;

  /**
   * Creates a new IPGeolocation instance
   * @param storage - Optional storage adapter for distributed caching
   * @param cacheTtl - Cache TTL in milliseconds (default: 24 hours)
   */
  constructor(storage?: StorageAdapter, cacheTtl: number = 24 * 60 * 60 * 1000) {
    this.storage = storage;
    this.cacheTtl = cacheTtl;
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

    try {
      const info = await this.fetchIPInfo(ip);

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
      if (error instanceof Error && error.message.includes("429")) {
        console.warn(
          `[Guardrail] IP Geolocation rate limit hit (HTTP 429). Falling back to basic info. Consider using a premium provider for production: https://guardrail.dev/docs/ip-intelligence`
        );
      } else {
        console.warn(`[Guardrail] Failed to fetch IP info for ${ip}:`, error);
      }
      return this.getDefaultIPInfo();
    }
  }

  private async fetchIPInfo(ip: string): Promise<IPInfo> {
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
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

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

      const encodedIP = encodeURIComponent(ip);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

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
