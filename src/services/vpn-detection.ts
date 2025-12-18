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
  "nordvpn", "expressvpn", "surfshark", "cyberghost", "private internet access",
  "pia", "protonvpn", "proton vpn", "hotspot shield", "ipvanish", "vyprvpn",
  "tunnelbear", "windscribe", "mullvad", "purevpn", "zenmate", "hidemyass",
  "hma", "avast secureline", "norton secure vpn", "kaspersky vpn", "bitdefender",
  "strongvpn", "hide.me", "ivacy", "fastestvpn", "atlasvpn", "privatevpn",
  "torguard", "airvpn", "ovpn", "oeck vpn", "perfect privacy", "trust.zone",
  "vpn.ac", "vpnarea", "cactus vpn", "vpn unlimited", "goose vpn", "safervpn",
  "getflix", "boxpn", "astrill", "12vpn", "vpn.ht", "slick vpn", "buffered",
  "speedify", "encrypt.me", "cloak", "disconnect", "freedome", "betternet",
  "hotspot vpn", "turbo vpn", "hola", "psiphon", "lantern", "ultrasurf",
  "freegate", "vpngate", "softether", "openconnect", "libreswan", "algo",
  "wireguard", "outline vpn", "streisand", "pritunl", "zerotier",
  
  // Corporate/Enterprise VPNs
  "cisco anyconnect", "globalprotect", "palo alto", "fortinet", "forticlient",
  "pulse secure", "juniper", "checkpoint", "f5", "citrix", "zscaler",
  "cloudflare warp", "cloudflare access", "tailscale",
  
  // Lesser known but common
  "privatetunnel", "anonine", "blackvpn", "bolehvpn", "cryptostorm",
  "doublehop", "earthvpn", "frootvpn", "ibvpn", "ipredator", "liquidvpn",
  "noodlevpn", "ovpn.com", "ra4w vpn", "seed4.me", "shellfire",
  "switchvpn", "tiger vpn", "totalvpn", "unlocator", "vpnsecure",
  "vpntunnel", "worldvpn", "zenservervpn", "azirevpn", "blindspot", "celo",
]);

/**
 * Known proxy and CDN providers
 */
const PROXY_PROVIDERS = new Set([
  // CDN providers
  "cloudflare", "akamai", "fastly", "maxcdn", "keycdn", "stackpath",
  "bunnycdn", "jsdelivr", "unpkg", "cdnjs", "cloudfront", "azure cdn",
  "google cloud cdn", "limelight", "edgecast", "level3", "incapsula",
  "imperva", "sucuri",
  
  // Proxy services
  "luminati", "brightdata", "bright data", "oxylabs", "smartproxy",
  "geosurf", "netnut", "shifter", "storm proxies", "highproxies",
  "buyproxies", "proxy-seller", "webshare", "soax", "infatica",
  "proxy6", "proxy-cheap", "instantproxies", "proxyempire", "proxy-n-vpn",
  
  // Residential proxy networks
  "packetstream", "honeygain", "pawns", "iproyal", "peer2profit",
]);

/**
 * Known datacenter/hosting providers (often used for proxies)
 */
const DATACENTER_PROVIDERS = new Set([
  // Major cloud providers
  "amazon", "aws", "ec2", "google cloud", "gcp", "microsoft azure", "azure",
  "digitalocean", "linode", "vultr", "ovh", "hetzner", "scaleway", "upcloud",
  "contabo", "hostinger", "kamatera", "atlantic.net", "dreamhost", "siteground",
  
  // VPS/Hosting providers
  "godaddy", "bluehost", "hostgator", "namecheap", "ionos", "a2 hosting",
  "hostwinds", "interserver", "liquidweb", "inmotion", "greengeeks",
  "fastcomet", "cloudways", "kinsta", "wpengine", "flywheel", "pagely",
  
  // Datacenter operators
  "equinix", "coresite", "cyxtera", "qts", "data foundry", "cologix",
  "switch", "vantage", "flexential", "tierpoint", "servercentral",
  
  // Other indicators
  "colocation", "datacenter", "data center", "server farm", "hosting",
  "cloud server", "vps", "virtual private server", "dedicated server",
]);

/**
 * Tor exit node indicators
 */
const TOR_INDICATORS = new Set([
  "tor", "tor network", "tor exit", "tor relay", "onion router",
  "tor project", "torservers", "torland",
]);

/**
 * Residential proxy indicators
 */
const RESIDENTIAL_PROXY_INDICATORS = new Set([
  "residential", "mobile proxy", "4g proxy", "lte proxy", "5g proxy",
  "isp proxy", "home proxy",
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
    this.enableHeuristics = config.enableHeuristicDetection ?? true;
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
    const vpnMatch = this.findMatch(combined, this.vpnProviders);
    const isVpn = ipInfo.isVpn === true || vpnMatch !== null;
    if (isVpn) {
      confidence = Math.max(confidence, vpnMatch ? 90 : 80);
      reason = vpnMatch ? `VPN provider: ${vpnMatch}` : "VPN detected via IP intelligence";
      matchedProvider = vpnMatch || undefined;
    }

    // Check for proxy
    const proxyMatch = this.findMatch(combined, this.proxyProviders);
    const isProxy = ipInfo.isProxy === true || proxyMatch !== null;
    if (isProxy && !isVpn) {
      confidence = Math.max(confidence, proxyMatch ? 85 : 75);
      reason = proxyMatch ? `Proxy provider: ${proxyMatch}` : "Proxy detected via IP intelligence";
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
    const datacenterMatch = this.findMatch(combined, this.datacenterProviders);
    const isHosting = ipInfo.isHosting === true || 
                      ipInfo.asnType === "hosting" || 
                      datacenterMatch !== null;
    if (isHosting && !isVpn && !isProxy) {
      confidence = Math.max(confidence, datacenterMatch ? 70 : 60);
      reason = datacenterMatch 
        ? `Hosting provider: ${datacenterMatch}` 
        : "Datacenter/hosting IP detected";
      matchedProvider = datacenterMatch || undefined;
    }

    // Check for relay (Apple Private Relay, etc.)
    const isRelay = ipInfo.isRelay === true || 
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

    return {
      isVpn: isVpn || confidence >= this.confidenceThreshold && (vpnMatch !== null),
      isProxy: isProxy || confidence >= this.confidenceThreshold && (proxyMatch !== null),
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
   */
  private applyHeuristics(ipInfo: IPInfo): { confidence: number; reason?: string } {
    let confidence = 0;
    let reason: string | undefined;

    // High port diversity or unusual port usage patterns (would require additional data)
    
    // Check for suspicious ASN types
    if (ipInfo.asnType === "hosting") {
      confidence = Math.max(confidence, 40);
      reason = "Hosting ASN type detected";
    }

    // Geographic anomalies (timezone vs location mismatch would require additional data)

    // Check for common VPN port patterns in hostname (if available)
    const asnName = (ipInfo.asnName || "").toLowerCase();
    
    // Look for generic VPN/proxy related keywords
    const suspiciousKeywords = ["anonymous", "privacy", "secure", "hide", "mask", "stealth"];
    for (const keyword of suspiciousKeywords) {
      if (asnName.includes(keyword)) {
        confidence = Math.max(confidence, 50);
        reason = `Suspicious keyword in ASN: ${keyword}`;
        break;
      }
    }

    // Check for IP ranges commonly used by VPNs (would require IP range database)

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
