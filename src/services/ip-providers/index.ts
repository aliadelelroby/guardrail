/**
 * Pluggable IP Geolocation Providers
 * Supports multiple IP intelligence services for better accuracy and reliability
 * @module services/ip-providers
 */

import type { IPGeolocationService, IPInfo } from "../../types/index";

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
  package?: "WS1" | "WS2" | "WS3" | "WS4" | "WS5" | "WS6" | "WS7" | "WS8" | "WS9" | "WS10" | "WS11" | "WS12" | "WS13" | "WS14" | "WS15" | "WS16" | "WS17" | "WS18" | "WS19" | "WS20" | "WS21" | "WS22" | "WS23" | "WS24" | "WS25";
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
    if (this.isPrivateIP(ip)) {
      return {};
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      const auth = Buffer.from(`${this.accountId}:${this.licenseKey}`).toString("base64");
      const response = await fetch(
        `https://geoip.maxmind.com/geoip/v2.1/${this.serviceType}/${ip}`,
        {
          headers: {
            Authorization: `Basic ${auth}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        throw new Error(`MaxMind API error: ${response.status}`);
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const data = (await response.json()) as any;

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
    } catch (error) {
      console.warn(`MaxMind lookup failed for ${ip}:`, error);
      return {};
    }
  }

  private isPrivateIP(ip: string): boolean {
    return (
      ip === "unknown" ||
      ip === "127.0.0.1" ||
      ip.startsWith("192.168.") ||
      ip.startsWith("10.") ||
      ip.startsWith("172.16.") ||
      ip.startsWith("172.17.") ||
      ip.startsWith("172.18.") ||
      ip.startsWith("172.19.") ||
      ip.startsWith("172.2") ||
      ip.startsWith("172.30.") ||
      ip.startsWith("172.31.")
    );
  }
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
    if (this.isPrivateIP(ip)) {
      return {};
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      const response = await fetch(`https://ipinfo.io/${ip}?token=${this.token}`, {
        headers: { Accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`IPinfo API error: ${response.status}`);
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const data = (await response.json()) as any;
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
    } catch (error) {
      console.warn(`IPinfo lookup failed for ${ip}:`, error);
      return {};
    }
  }

  private isPrivateIP(ip: string): boolean {
    return (
      ip === "unknown" ||
      ip === "127.0.0.1" ||
      ip.startsWith("192.168.") ||
      ip.startsWith("10.") ||
      ip.startsWith("172.16.")
    );
  }
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
    if (this.isPrivateIP(ip)) {
      return {};
    }

    const cached = this.cache.get(ip);
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }

    try {
      const params = new URLSearchParams({
        strictness: String(this.strictness),
        allow_public_access_points: "true",
        fast: this.enableFraudScoring ? "false" : "true",
        lighter_penalties: "true",
      });

      const response = await fetch(
        `https://ipqualityscore.com/api/json/ip/${this.apiKey}/${ip}?${params}`
      );

      if (!response.ok) {
        throw new Error(`IPQualityScore API error: ${response.status}`);
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const data = (await response.json()) as any;

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
        asnType: this.inferASNType(data.ISP || "", data.host),
        isHosting: data.is_crawler || data.host?.includes("hosting") || data.host?.includes("server"),
        isVpn: data.vpn,
        isProxy: data.proxy,
        isTor: data.tor,
        isRelay: data.active_vpn || data.recent_abuse,
      };

      this.cache.set(ip, { data: info, expires: Date.now() + this.cacheTtl });
      return info;
    } catch (error) {
      console.warn(`IPQualityScore lookup failed for ${ip}:`, error);
      return {};
    }
  }

  private isPrivateIP(ip: string): boolean {
    return (
      ip === "unknown" ||
      ip === "127.0.0.1" ||
      ip.startsWith("192.168.") ||
      ip.startsWith("10.") ||
      ip.startsWith("172.16.")
    );
  }

  private inferASNType(isp: string, host: string): IPInfo["asnType"] {
    const combined = `${isp} ${host}`.toLowerCase();
    if (combined.includes("hosting") || combined.includes("datacenter") || combined.includes("cloud")) {
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
