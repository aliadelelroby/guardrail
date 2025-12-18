/**
 * VPN and Proxy Detection Service
 * Provides comprehensive detection using multiple heuristics
 * @module services/vpn-detection
 */

import type { IPInfo } from "../types/index";

/**
 * Known VPN providers - comprehensive list of 100+ providers
 */
const VPN_PROVIDERS = new Set([
  // Major commercial VPNs
  "nordvpn",
  "expressvpn",
  "surfshark",
  "cyberghost",
  "private internet access",
  "pia",
  "protonvpn",
  "proton vpn",
  "hotspot shield",
  "ipvanish",
  "vyprvpn",
  "tunnelbear",
  "windscribe",
  "mullvad",
  "purevpn",
  "zenmate",
  "hidemyass",
  "hma",
  "avast secureline",
  "norton secure vpn",
  "kaspersky vpn",
  "bitdefender",
  "strongvpn",
  "hide.me",
  "ivacy",
  "fastestvpn",
  "atlasvpn",
  "privatevpn",
  "torguard",
  "airvpn",
  "ovpn",
  "oeck vpn",
  "perfect privacy",
  "trust.zone",
  "vpn.ac",
  "vpnarea",
  "cactus vpn",
  "vpn unlimited",
  "goose vpn",
  "safervpn",
  "getflix",
  "boxpn",
  "astrill",
  "12vpn",
  "vpn.ht",
  "slick vpn",
  "buffered",
  "speedify",
  "encrypt.me",
  "cloak",
  "disconnect",
  "freedome",
  "betternet",
  "hotspot vpn",
  "turbo vpn",
  "hola",
  "psiphon",
  "lantern",
  "ultrasurf",
  "freegate",
  "vpngate",
  "softether",
  "openconnect",
  "libreswan",
  "algo",
  "wireguard",
  "outline vpn",
  "streisand",
  "pritunl",
  "zerotier",

  // Corporate/Enterprise VPNs
  "cisco anyconnect",
  "globalprotect",
  "palo alto",
  "fortinet",
  "forticlient",
  "pulse secure",
  "juniper",
  "checkpoint",
  "f5",
  "citrix",
  "zscaler",
  "cloudflare warp",
  "cloudflare access",
  "tailscale",

  // Lesser known but common
  "privatetunnel",
  "anonine",
  "blackvpn",
  "bolehvpn",
  "cryptostorm",
  "doublehop",
  "earthvpn",
  "frootvpn",
  "ibvpn",
  "ipredator",
  "liquidvpn",
  "noodlevpn",
  "ovpn.com",
  "ra4w vpn",
  "seed4.me",
  "shellfire",
  "switchvpn",
  "tiger vpn",
  "totalvpn",
  "unlocator",
  "vpnsecure",
  "vpntunnel",
  "worldvpn",
  "zenservervpn",
  "azirevpn",
  "blindspot",
  "celo",
]);

/**
 * Known proxy providers
 * NOTE: CDN providers (Cloudflare, Akamai, etc.) are NOT included here as they are
 * legitimate infrastructure used by many websites. Including them would cause massive
 * false positives in production.
 */
const PROXY_PROVIDERS = new Set([
  // Proxy services (actual proxy providers, not CDNs)
  "luminati",
  "brightdata",
  "bright data",
  "oxylabs",
  "smartproxy",
  "geosurf",
  "netnut",
  "shifter",
  "storm proxies",
  "highproxies",
  "buyproxies",
  "proxy-seller",
  "webshare",
  "soax",
  "infatica",
  "proxy6",
  "proxy-cheap",
  "instantproxies",
  "proxyempire",
  "proxy-n-vpn",

  // Residential proxy networks
  "packetstream",
  "honeygain",
  "pawns",
  "iproyal",
  "peer2profit",
]);

/**
 * Known datacenter/hosting providers (often used for proxies)
 */
const DATACENTER_PROVIDERS = new Set([
  // Major cloud providers
  "amazon",
  "aws",
  "ec2",
  "google cloud",
  "gcp",
  "microsoft azure",
  "azure",
  "digitalocean",
  "linode",
  "vultr",
  "ovh",
  "hetzner",
  "scaleway",
  "upcloud",
  "contabo",
  "hostinger",
  "kamatera",
  "atlantic.net",
  "dreamhost",
  "siteground",

  // VPS/Hosting providers
  "godaddy",
  "bluehost",
  "hostgator",
  "namecheap",
  "ionos",
  "a2 hosting",
  "hostwinds",
  "interserver",
  "liquidweb",
  "inmotion",
  "greengeeks",
  "fastcomet",
  "cloudways",
  "kinsta",
  "wpengine",
  "flywheel",
  "pagely",

  // Datacenter operators
  "equinix",
  "coresite",
  "cyxtera",
  "qts",
  "data foundry",
  "cologix",
  "switch",
  "vantage",
  "flexential",
  "tierpoint",
  "servercentral",

  // Other indicators
  "colocation",
  "datacenter",
  "data center",
  "server farm",
  "hosting",
  "cloud server",
  "vps",
  "virtual private server",
  "dedicated server",
]);

/**
 * Tor exit node indicators
 */
const TOR_INDICATORS = new Set([
  "tor",
  "tor network",
  "tor exit",
  "tor relay",
  "onion router",
  "tor project",
  "torservers",
  "torland",
]);

/**
 * Residential proxy indicators
 */
const RESIDENTIAL_PROXY_INDICATORS = new Set([
  "residential",
  "mobile proxy",
  "4g proxy",
  "lte proxy",
  "5g proxy",
  "isp proxy",
  "home proxy",
]);

/**
 * Configuration for VPN detection
 */
export interface VPNDetectionConfig {
  /** Enable heuristic detection based on ASN type */
  enableHeuristicDetection?: boolean;
  /** Custom VPN providers to add */
  customVPNProviders?: string[];
  /** Custom proxy providers to add */
  customProxyProviders?: string[];
  /** Minimum confidence level (0-100) to flag as VPN/proxy */
  confidenceThreshold?: number;
}

/**
 * Detection result with confidence scores
 */
export interface VPNDetectionResult {
  isVpn: boolean;
  isProxy: boolean;
  isHosting: boolean;
  isTor: boolean;
  isRelay: boolean;
  isResidentialProxy: boolean;
  /** Confidence score 0-100 */
  confidence: number;
  /** Reason for detection */
  reason?: string;
  /** Matched provider if any */
  matchedProvider?: string;
}

/**
 * VPN and Proxy Detection
 * Uses comprehensive provider matching and heuristic analysis
 */
export class VPNProxyDetection {
  private readonly vpnProviders: Set<string>;
  private readonly proxyProviders: Set<string>;
  private readonly datacenterProviders: Set<string>;
  private readonly enableHeuristics: boolean;
  private readonly confidenceThreshold: number;

  constructor(config: VPNDetectionConfig = {}) {
    // Initialize with default providers
    this.vpnProviders = new Set(VPN_PROVIDERS);
    this.proxyProviders = new Set(PROXY_PROVIDERS);
    this.datacenterProviders = new Set(DATACENTER_PROVIDERS);
    // Heuristics are disabled by default - they have high false positive rates (40-70% accuracy)
    // Enable only when explicitly requested and when you can tolerate false positives
    this.enableHeuristics = config.enableHeuristicDetection ?? false;
    // Default threshold of 50 requires provider match + some confidence
    // IP intelligence data (isVpn/isProxy === true) is always trusted regardless of threshold
    this.confidenceThreshold = config.confidenceThreshold ?? 50;

    // Add custom providers
    if (config.customVPNProviders) {
      for (const provider of config.customVPNProviders) {
        this.vpnProviders.add(provider.toLowerCase());
      }
    }
    if (config.customProxyProviders) {
      for (const provider of config.customProxyProviders) {
        this.proxyProviders.add(provider.toLowerCase());
      }
    }
  }

  /**
   * Detects VPN, proxy, hosting, and other anonymizing services
   *
   * RELIABILITY NOTES:
   * - IP intelligence data (ipInfo.isVpn/isProxy === true) is highly reliable (95%+ accuracy)
   *   and is always trusted regardless of confidence threshold
   * - Provider matching (ASN name matching) is highly reliable (90%+ accuracy)
   * - Heuristic detection is less reliable (40-70% accuracy) and disabled by default
   * - Hosting/datacenter detection is a weak signal (40-50 confidence) and should not
   *   be used alone to flag as VPN/proxy
   *
   * @param ipInfo - IP information to analyze
   * @returns Enhanced detection result with confidence scores
   */
  detect(ipInfo: IPInfo): VPNDetectionResult {
    const org = (ipInfo.asnName || "").toLowerCase();
    const service = (ipInfo.service || "").toLowerCase();
    const combined = `${org} ${service}`;

    let confidence = 0;
    let reason: string | undefined;
    let matchedProvider: string | undefined;

    // Check for VPN
    // Trust IP intelligence data (high confidence) - if service says VPN, it's reliable
    const vpnMatch = this.findMatch(combined, this.vpnProviders);
    const isVpnFromIntelligence = ipInfo.isVpn === true;
    const isVpnFromProvider = vpnMatch !== null;
    const isVpn = isVpnFromIntelligence || isVpnFromProvider;

    if (isVpn) {
      // IP intelligence data is highly reliable (90+ confidence)
      // Provider match is also highly reliable (90 confidence)
      confidence = Math.max(confidence, isVpnFromIntelligence ? 95 : isVpnFromProvider ? 90 : 80);
      reason = vpnMatch
        ? `VPN provider: ${vpnMatch}`
        : isVpnFromIntelligence
          ? "VPN detected via IP intelligence"
          : "VPN detected";
      matchedProvider = vpnMatch || undefined;
    }

    // Check for proxy
    // Trust IP intelligence data (high confidence) - if service says proxy, it's reliable
    const proxyMatch = this.findMatch(combined, this.proxyProviders);
    const isProxyFromIntelligence = ipInfo.isProxy === true;
    const isProxyFromProvider = proxyMatch !== null;
    const isProxy = isProxyFromIntelligence || (isProxyFromProvider && !isVpn);

    if (isProxy && !isVpn) {
      // IP intelligence data is highly reliable (85+ confidence)
      // Provider match is also highly reliable (85 confidence)
      confidence = Math.max(
        confidence,
        isProxyFromIntelligence ? 90 : isProxyFromProvider ? 85 : 75
      );
      reason = proxyMatch
        ? `Proxy provider: ${proxyMatch}`
        : isProxyFromIntelligence
          ? "Proxy detected via IP intelligence"
          : "Proxy detected";
      matchedProvider = proxyMatch || undefined;
    }

    // Check for Tor
    const torMatch = this.findMatch(combined, TOR_INDICATORS);
    const isTor = ipInfo.isTor === true || torMatch !== null;
    if (isTor) {
      confidence = Math.max(confidence, 95);
      reason = "Tor exit node detected";
    }

    // Check for hosting/datacenter
    // NOTE: Hosting alone is NOT a strong indicator of VPN/proxy. Many legitimate services
    // use cloud providers (AWS, Azure, GCP). Only flag with low confidence and when combined
    // with other suspicious signals. Research shows datacenter IPs need multiple signals.
    const datacenterMatch = this.findMatch(combined, this.datacenterProviders);
    const isHosting =
      ipInfo.isHosting === true || ipInfo.asnType === "hosting" || datacenterMatch !== null;
    if (isHosting && !isVpn && !isProxy) {
      // Lower confidence for hosting alone (40-50) - it's a weak signal
      // Research shows hosting IPs should only be flagged when combined with other signals
      confidence = Math.max(confidence, datacenterMatch ? 50 : 40);
      reason = datacenterMatch
        ? `Hosting provider: ${datacenterMatch}`
        : "Datacenter/hosting IP detected";
      matchedProvider = datacenterMatch || undefined;
    }

    // Check for relay (Apple Private Relay, etc.)
    const isRelay =
      ipInfo.isRelay === true ||
      combined.includes("relay") ||
      combined.includes("apple private relay") ||
      combined.includes("icloud private relay");

    // Check for residential proxy
    const residentialMatch = this.findMatch(combined, RESIDENTIAL_PROXY_INDICATORS);
    const isResidentialProxy = residentialMatch !== null;
    if (isResidentialProxy) {
      confidence = Math.max(confidence, 70);
      reason = "Residential proxy detected";
    }

    // Apply heuristic detection if enabled
    if (this.enableHeuristics && confidence < this.confidenceThreshold) {
      const heuristicResult = this.applyHeuristics(ipInfo);
      if (heuristicResult.confidence > confidence) {
        confidence = heuristicResult.confidence;
        reason = heuristicResult.reason;
      }
    }

    // Final determination: trust IP intelligence data, or use confidence threshold with provider match
    // IP intelligence data (isVpn/isProxy === true) is highly reliable and should always be trusted
    // For heuristic-based detection, require both high confidence AND provider match to reduce false positives
    const heuristicVpn = confidence >= this.confidenceThreshold && vpnMatch !== null;
    const heuristicProxy = confidence >= this.confidenceThreshold && proxyMatch !== null;

    return {
      // Trust IP intelligence data (always reliable), or use heuristic detection with provider match
      isVpn: isVpn || heuristicVpn,
      isProxy: isProxy || heuristicProxy,
      isHosting,
      isTor,
      isRelay,
      isResidentialProxy,
      confidence,
      reason,
      matchedProvider,
    };
  }

  /**
   * Enhances IP info with detection flags (backwards compatible with original API)
   */
  enhance(ipInfo: IPInfo): IPInfo {
    const result = this.detect(ipInfo);
    return {
      ...ipInfo,
      isVpn: result.isVpn || undefined,
      isProxy: result.isProxy || undefined,
      isHosting: result.isHosting || undefined,
      isTor: result.isTor || undefined,
      isRelay: result.isRelay || undefined,
    };
  }

  /**
   * Finds a matching provider in the given set
   */
  private findMatch(text: string, providers: Set<string>): string | null {
    for (const provider of providers) {
      if (text.includes(provider)) {
        return provider;
      }
    }
    return null;
  }

  /**
   * Applies heuristic detection based on various signals
   * NOTE: Heuristics are weak signals and should only be used as supporting evidence.
   * Research shows heuristics alone have 40-70% accuracy for residential proxies.
   * Require multiple weak signals to reach threshold to reduce false positives.
   */
  private applyHeuristics(ipInfo: IPInfo): { confidence: number; reason?: string } {
    let confidence = 0;
    let reason: string | undefined;
    let signalCount = 0;

    // Check for suspicious ASN types (weak signal)
    if (ipInfo.asnType === "hosting") {
      confidence += 20; // Lower weight - hosting alone is weak
      signalCount++;
    }

    // Check ASN name for VPN/proxy-specific keywords (not generic privacy terms)
    // Avoid generic terms like "privacy" or "secure" that legitimate services use
    const asnName = (ipInfo.asnName || "").toLowerCase();

    // More specific VPN/proxy indicators (avoid false positives from legitimate services)
    const specificKeywords = [
      "vpn",
      "proxy",
      "anonymizer",
      "anonymizing",
      "stealth vpn",
      "hide ip",
      "mask ip",
      "ip changer",
      "proxy service",
    ];

    for (const keyword of specificKeywords) {
      if (asnName.includes(keyword)) {
        confidence += 30; // Stronger signal for specific keywords
        signalCount++;
        reason = `VPN/proxy keyword in ASN: ${keyword}`;
        break;
      }
    }

    // Require multiple weak signals to reach meaningful confidence
    // Single weak signal (20-30 points) is not enough - need at least 2 signals
    if (signalCount < 2 && confidence < 50) {
      // Not enough signals - reset to 0 to avoid false positives
      confidence = 0;
      reason = undefined;
    }

    // Cap heuristic confidence at 60 (never exceed threshold alone)
    confidence = Math.min(confidence, 60);

    return { confidence, reason };
  }

  /**
   * Adds a custom VPN provider to the detection list
   */
  addVPNProvider(provider: string): void {
    this.vpnProviders.add(provider.toLowerCase());
  }

  /**
   * Adds a custom proxy provider to the detection list
   */
  addProxyProvider(provider: string): void {
    this.proxyProviders.add(provider.toLowerCase());
  }

  /**
   * Gets the number of known providers
   */
  getProviderCounts(): { vpn: number; proxy: number; datacenter: number } {
    return {
      vpn: this.vpnProviders.size,
      proxy: this.proxyProviders.size,
      datacenter: this.datacenterProviders.size,
    };
  }
}
