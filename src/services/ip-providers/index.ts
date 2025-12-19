/**
 * Pluggable IP Geolocation Providers
 * Supports multiple IP intelligence services for better accuracy and reliability
 * @module services/ip-providers
 */

import type { IPGeolocationService, IPInfo } from "../../types/index";
import { safeJsonParse } from "../../utils/safe-json";
import { validateIP } from "../../utils/ip-validator";

// Maximum response size for external API calls (1MB)
const MAX_API_RESPONSE_SIZE = 1024 * 1024;

/**
 * Safely reads a fetch response with size limits
 */
async function readResponseWithLimit(response: Response): Promise<string> {
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

/**
 * Configuration for MaxMind GeoIP2 service
 */
export interface MaxMindConfig {
  /** Account ID from MaxMind */
  accountId: string;
  /** License key from MaxMind */
  licenseKey: string;
  /** Service type: 'country', 'city', 'insights' */
  serviceType?: "country" | "city" | "insights";
}

/**
 * Configuration for IPinfo.io service
 */
export interface IPinfoConfig {
  /** API token from IPinfo.io */
  token: string;
}

/**
 * Configuration for IPQualityScore service
 */
export interface IPQualityScoreConfig {
  /** API key from IPQualityScore */
  apiKey: string;
  /** Enable fraud scoring (may slow down requests) */
  enableFraudScoring?: boolean;
  /** Strictness level 0-3 */
  strictness?: 0 | 1 | 2 | 3;
}

/**
 * Configuration for IP2Location service
 */
export interface IP2LocationConfig {
  /** API key from IP2Location */
  apiKey: string;
  /** Package type */
  package?:
    | "WS1"
    | "WS2"
    | "WS3"
    | "WS4"
    | "WS5"
    | "WS6"
    | "WS7"
    | "WS8"
    | "WS9"
    | "WS10"
    | "WS11"
    | "WS12"
    | "WS13"
    | "WS14"
    | "WS15"
    | "WS16"
    | "WS17"
    | "WS18"
    | "WS19"
    | "WS20"
    | "WS21"
    | "WS22"
    | "WS23"
    | "WS24"
    | "WS25";
}

interface MaxMindApiResponse {
  country?: { iso_code?: string; names?: { en?: string } };
  subdivisions?: Array<{ iso_code?: string }>;
  city?: { names?: { en?: string } };
  continent?: { code?: string; names?: { en?: string } };
  location?: {
    latitude?: number;
    longitude?: number;
    time_zone?: string;
    accuracy_radius?: number;
  };
  postal?: { code?: string };
  traits?: {
    autonomous_system_number?: number;
    autonomous_system_organization?: string;
    hosting_provider?: boolean;
    is_anonymous_vpn?: boolean;
    is_anonymous_proxy?: boolean;
    is_tor_exit_node?: boolean;
    is_residential_proxy?: boolean;
  };
}

/**
 * MaxMind GeoIP2 provider
 * Requires a MaxMind account with GeoIP2 web service access
 * @see https://www.maxmind.com/en/geoip2-precision-services
 */
export class MaxMindProvider implements IPGeolocationService {
  private readonly accountId: string;
  private readonly licenseKey: string;
  private readonly serviceType: string;
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();
  private readonly cacheTtl = 60 * 60 * 1000; // 1 hour

  constructor(config: MaxMindConfig) {
    this.accountId = config.accountId;
    this.licenseKey = config.licenseKey;
    this.serviceType = config.serviceType || "city";
  }

  async lookup(ip: string): Promise<IPInfo> {
    // Validate IP address to prevent SSRF
    try {
      validateIP(ip);
    } catch {
      return {};
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      const auth = Buffer.from(`${this.accountId}:${this.licenseKey}`).toString("base64");
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      try {
        const response = await fetch(
          `https://geoip.maxmind.com/geoip/v2.1/${this.serviceType}/${ip}`,
          {
            headers: {
              Authorization: `Basic ${auth}`,
              "Content-Type": "application/json",
            },
            signal: controller.signal,
          }
        );
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`MaxMind API error: ${response.status}`);
        }

        const responseText = await readResponseWithLimit(response);
        const data = safeJsonParse<MaxMindApiResponse>(responseText);

        const info: IPInfo = {
          country: data.country?.iso_code,
          countryName: data.country?.names?.en,
          region: data.subdivisions?.[0]?.iso_code,
          city: data.city?.names?.en,
          continent: data.continent?.code,
          continentName: data.continent?.names?.en,
          latitude: data.location?.latitude,
          longitude: data.location?.longitude,
          postalCode: data.postal?.code,
          timezone: data.location?.time_zone,
          accuracyRadius: data.location?.accuracy_radius,
          asn: data.traits?.autonomous_system_number,
          asnName: data.traits?.autonomous_system_organization,
          isHosting: data.traits?.hosting_provider,
          isVpn: data.traits?.is_anonymous_vpn,
          isProxy: data.traits?.is_anonymous_proxy,
          isTor: data.traits?.is_tor_exit_node,
          isRelay: data.traits?.is_residential_proxy,
        };

        this.cache.set(ip, { data: info, expires: Date.now() + this.cacheTtl });
        return info;
      } catch (fetchError) {
        if (fetchError instanceof Error && fetchError.name === "AbortError") {
          throw new Error("API request timeout");
        }
        throw fetchError;
      }
    } catch (error) {
      console.warn(`MaxMind lookup failed for ${ip}:`, error);
      return {};
    }
  }
}

interface IPinfoApiResponse {
  country?: string;
  region?: string;
  city?: string;
  loc?: string;
  postal?: string;
  timezone?: string;
  asn?: { asn?: string; name?: string; domain?: string; type?: string };
  org?: string;
  privacy?: { hosting?: boolean; vpn?: boolean; proxy?: boolean; tor?: boolean; relay?: boolean };
}

/**
 * IPinfo.io provider
 * Provides IP geolocation with ASN and company data
 * @see https://ipinfo.io/
 */
export class IPinfoProvider implements IPGeolocationService {
  private readonly token: string;
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();
  private readonly cacheTtl = 60 * 60 * 1000;

  constructor(config: IPinfoConfig) {
    this.token = config.token;
  }

  async lookup(ip: string): Promise<IPInfo> {
    // Validate IP address to prevent SSRF
    try {
      validateIP(ip);
    } catch {
      return {};
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      // Use URL encoding to prevent injection
      const encodedIP = encodeURIComponent(ip);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      try {
        const response = await fetch(`https://ipinfo.io/${encodedIP}?token=${this.token}`, {
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`IPinfo API error: ${response.status}`);
        }

        const responseText = await readResponseWithLimit(response);
        const data = safeJsonParse<IPinfoApiResponse>(responseText);
        const [lat, lon] = (data.loc || ",").split(",").map(Number);

        const info: IPInfo = {
          country: data.country,
          region: data.region,
          city: data.city,
          latitude: lat || undefined,
          longitude: lon || undefined,
          postalCode: data.postal,
          timezone: data.timezone,
          asn: data.asn?.asn ? parseInt(data.asn.asn.replace("AS", ""), 10) : undefined,
          asnName: data.asn?.name || data.org,
          asnDomain: data.asn?.domain,
          asnType: data.asn?.type as IPInfo["asnType"],
          isHosting: data.privacy?.hosting,
          isVpn: data.privacy?.vpn,
          isProxy: data.privacy?.proxy,
          isTor: data.privacy?.tor,
          isRelay: data.privacy?.relay,
        };

        this.cache.set(ip, { data: info, expires: Date.now() + this.cacheTtl });
        return info;
      } catch (fetchError) {
        if (fetchError instanceof Error && fetchError.name === "AbortError") {
          throw new Error("API request timeout");
        }
        throw fetchError;
      }
    } catch (error) {
      console.warn(`IPinfo lookup failed for ${ip}:`, error);
      return {};
    }
  }
}

interface IPQualityScoreApiResponse {
  success: boolean;
  message?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  zip_code?: string;
  timezone?: string;
  ASN?: number;
  ISP?: string;
  host?: string;
  is_crawler?: boolean;
  vpn?: boolean;
  proxy?: boolean;
  tor?: boolean;
  active_vpn?: boolean;
  recent_abuse?: boolean;
}

/**
 * IPQualityScore provider
 * Provides advanced fraud scoring and VPN/proxy detection
 * @see https://www.ipqualityscore.com/
 */
export class IPQualityScoreProvider implements IPGeolocationService {
  private readonly apiKey: string;
  private readonly enableFraudScoring: boolean;
  private readonly strictness: number;
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();
  private readonly cacheTtl = 60 * 60 * 1000;

  constructor(config: IPQualityScoreConfig) {
    this.apiKey = config.apiKey;
    this.enableFraudScoring = config.enableFraudScoring ?? true;
    this.strictness = config.strictness ?? 1;
  }

  async lookup(ip: string): Promise<IPInfo> {
    // Validate IP address to prevent SSRF
    try {
      validateIP(ip);
    } catch {
      return {};
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      // Use URL encoding to prevent injection
      const encodedIP = encodeURIComponent(ip);
      const params = new URLSearchParams({
        strictness: String(this.strictness),
        allow_public_access_points: "true",
        fast: this.enableFraudScoring ? "false" : "true",
        lighter_penalties: "true",
      });

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      try {
        const response = await fetch(
          `https://ipqualityscore.com/api/json/ip/${this.apiKey}/${encodedIP}?${params}`,
          { signal: controller.signal }
        );
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`IPQualityScore API error: ${response.status}`);
        }

        const responseText = await readResponseWithLimit(response);
        const data = safeJsonParse<IPQualityScoreApiResponse>(responseText);

        if (!data.success) {
          throw new Error(`IPQualityScore error: ${data.message}`);
        }

        const info: IPInfo = {
          country: data.country_code,
          region: data.region,
          city: data.city,
          latitude: data.latitude,
          longitude: data.longitude,
          postalCode: data.zip_code,
          timezone: data.timezone,
          asn: data.ASN,
          asnName: data.ISP,
          asnType: this.inferASNType(data.ISP || "", data.host || ""),
          isHosting:
            data.is_crawler || data.host?.includes("hosting") || data.host?.includes("server"),
          isVpn: data.vpn,
          isProxy: data.proxy,
          isTor: data.tor,
          isRelay: data.active_vpn || data.recent_abuse,
        };

        this.cache.set(ip, { data: info, expires: Date.now() + this.cacheTtl });
        return info;
      } catch (fetchError) {
        if (fetchError instanceof Error && fetchError.name === "AbortError") {
          throw new Error("API request timeout");
        }
        throw fetchError;
      }
    } catch (error) {
      console.warn(`IPQualityScore lookup failed for ${ip}:`, error);
      return {};
    }
  }

  private inferASNType(isp: string, host: string): IPInfo["asnType"] {
    const combined = `${isp} ${host}`.toLowerCase();
    if (
      combined.includes("hosting") ||
      combined.includes("datacenter") ||
      combined.includes("cloud")
    ) {
      return "hosting";
    }
    if (combined.includes("university") || combined.includes("edu")) {
      return "education";
    }
    if (combined.includes("inc") || combined.includes("corp") || combined.includes("llc")) {
      return "business";
    }
    return "isp";
  }
}

/**
 * Fallback provider that chains multiple providers
 * Tries each provider in order until one succeeds
 */
export class FallbackIPProvider implements IPGeolocationService {
  constructor(private readonly providers: IPGeolocationService[]) {
    if (providers.length === 0) {
      throw new Error("At least one provider must be specified");
    }
  }

  async lookup(ip: string): Promise<IPInfo> {
    for (const provider of this.providers) {
      try {
        const result = await provider.lookup(ip);
        if (result.country || result.city || result.isVpn !== undefined) {
          return result;
        }
      } catch {
        // Try next provider
        continue;
      }
    }
    return {};
  }
}

/**
 * Caching wrapper for any IP provider
 * Adds configurable caching with TTL
 */
export class CachingIPProvider implements IPGeolocationService {
  private readonly cache = new Map<string, { data: IPInfo; expires: number }>();

  constructor(
    private readonly provider: IPGeolocationService,
    private readonly cacheTtl: number = 60 * 60 * 1000
  ) {}

  async lookup(ip: string): Promise<IPInfo> {
    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    const result = await this.provider.lookup(ip);
    this.cache.set(ip, { data: result, expires: Date.now() + this.cacheTtl });

    // Cleanup old entries periodically
    if (this.cache.size > 10000) {
      const now = Date.now();
      for (const [key, value] of this.cache.entries()) {
        if (value.expires < now) {
          this.cache.delete(key);
        }
      }
    }

    return result;
  }

  /**
   * Clears the cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Gets cache statistics
   */
  getCacheStats(): { size: number; hits: number; misses: number } {
    return { size: this.cache.size, hits: 0, misses: 0 };
  }
}

export {
  MaxMindProvider as MaxMindIPProvider,
  IPinfoProvider as IPinfoIPProvider,
  IPQualityScoreProvider as IPQualityScoreIPProvider,
};
