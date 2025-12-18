/**
 * IP geolocation service implementation
 * Uses free IP geolocation APIs with fallback support
 * @module services/ip-geolocation
 */

import type { IPGeolocationService, IPInfo } from "../types/index";

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
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();
  private readonly cacheTtl: number;

  /**
   * Creates a new IPGeolocation instance
   * @param cacheTtl - Cache TTL in milliseconds (default: 1 hour)
   */
  constructor(cacheTtl: number = 60 * 60 * 1000) {
    this.cacheTtl = cacheTtl;
  }

  /**
   * Looks up IP geolocation information
   * @param ip - IP address to lookup
   * @returns Promise resolving to IP information
   */
  async lookup(ip: string): Promise<IPInfo> {
    if (
      ip === "unknown" ||
      ip === "127.0.0.1" ||
      ip.startsWith("192.168.") ||
      ip.startsWith("10.")
    ) {
      return this.getDefaultIPInfo();
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      const info = await this.fetchIPInfo(ip);
      this.cache.set(ip, {
        data: info,
        expires: Date.now() + this.cacheTtl,
      });
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
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      if (response.status === 429) {
        throw new Error("HTTP 429: Rate limit exceeded");
      }
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = (await response.json()) as IPApiCoResponse;

      if ((data as any).error) {
        throw new Error((data as any).reason || "API Error");
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
    } catch (e: any) {
      if (e.message.includes("429")) throw e;

      try {
        const response = await fetch(`https://ip-api.com/json/${ip}`);
        if (response.status === 429) {
          throw new Error("HTTP 429: Rate limit exceeded");
        }
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const data = (await response.json()) as IPApiComResponse;

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
      } catch (innerE: any) {
        throw innerE;
      }
    }
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
