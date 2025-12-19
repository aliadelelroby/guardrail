/**
 * Bot Detection with behavioral analysis
 * Provides multi-signal bot detection beyond User-Agent matching
 * @module rules/bot-detection
 */

import type { BotDetectionConfig, RuleResult, DecisionConclusion } from "../types/index";
import { extractUserAgent } from "../utils/fingerprint";

/**
 * Well-known bot User-Agent patterns
 */
const WELL_KNOWN_BOTS = [
  // Search engines
  "Googlebot",
  "Bingbot",
  "Slurp",
  "DuckDuckBot",
  "Baiduspider",
  "YandexBot",
  "Sogou",
  "Exabot",
  "facebot",
  "ia_archiver",

  // SEO/Marketing bots
  "AhrefsBot",
  "SemrushBot",
  "MJ12bot",
  "DotBot",
  "Barkrowler",
  "BLEXBot",
  "CCBot",
  "Omgilibot",
  "linkdexbot",
  "spbot",
  "SeznamBot",
  "gigabot",
  "MegaIndex",
  "BacklinkCrawler",
  "netEstate",
  "Screaming Frog",

  // AI crawlers
  "ChatGPT-User",
  "anthropic-ai",
  "Claude-Web",
  "GPTBot",
  "Google-Extended",
  "PerplexityBot",
  "Bytespider",
  "TikTokSpider",
  "cohere-ai",
  "Diffbot",

  // Social media bots
  "FacebookBot",
  "facebookexternalhit",
  "Applebot",
  "Twitterbot",
  "LinkedInBot",
  "WhatsApp",
  "TelegramBot",
  "DiscordBot",
  "Slackbot",
  "PinterestBot",
  "Snapchat",
  "Instagram",
  "reddit bot",
  "tumblr",
  "Embedly",

  // Development tools
  "curl",
  "Wget",
  "python-requests",
  "Go-http-client",
  "Java",
  "Apache-HttpClient",
  "okhttp",
  "PostmanRuntime",
  "insomnia",
  "HTTPie",
  "rest-client",
  "axios",
  "node-fetch",
  "undici",
  "got",
  "request",
  "superagent",
  "needle",

  // Scraping frameworks
  "scrapy",
  "Puppeteer",
  "Playwright",
  "HeadlessChrome",
  "PhantomJS",
  "Selenium",
  "webdriver",
  "Nightmare",
  "Splash",
  "HtmlUnit",
  "HttpUnit",

  // Monitoring/Uptime bots
  "UptimeRobot",
  "Pingdom",
  "StatusCake",
  "Site24x7",
  "Datadog",
  "NewRelic",
  "AppDynamics",
  "Dynatrace",
  "Prometheus",
  "Zabbix",
  "Nagios",

  // Feed readers
  "Feedly",
  "NewsBlur",
  "Feedbin",
  "Inoreader",
  "The Old Reader",
  "FreshRSS",

  // Security scanners
  "Nessus",
  "Nikto",
  "sqlmap",
  "WPScan",
  "Acunetix",
  "Burp",
  "ZAP",
  "Nmap",
  "Masscan",
  "Shodan",
  "Censys",

  // Generic bot indicators
  "bot",
  "crawler",
  "spider",
  "scraper",
  "fetch",
  "scan",
  "check",
  "monitor",
  "probe",
  "search",
  "index",
  "archive",
];

// Note: SUSPICIOUS_HEADER_PATTERNS and BrowserSignals are reserved for future
// client-side fingerprinting integration

/**
 * Bot detection result with confidence
 */
export interface BotDetectionResult {
  isBot: boolean;
  botType?: "crawler" | "scraper" | "automation" | "unknown";
  botName?: string;
  confidence: number;
  signals: string[];
}

/**
 * Bot detection configuration with extended options
 */
export interface BotDetectionRuleConfig extends BotDetectionConfig {
  /** Enable header analysis */
  analyzeHeaders?: boolean;
  /** Minimum bot confidence to block (0-100) */
  confidenceThreshold?: number;
  /** Enable browser fingerprint validation */
  validateFingerprint?: boolean;
  /** Challenge suspicious requests instead of blocking */
  challengeMode?: boolean;
}

/**
 * Bot Detection Rule
 * Uses multiple signals beyond User-Agent to detect bots
 */
export class BotDetectionRule {
  private readonly config: BotDetectionRuleConfig;
  private readonly analyzeHeaders: boolean;
  private readonly confidenceThreshold: number;

  constructor(config: BotDetectionRuleConfig) {
    this.config = config;
    this.analyzeHeaders = config.analyzeHeaders ?? true;
    this.confidenceThreshold = config.confidenceThreshold ?? 70;
    // Note: validateFingerprint is reserved for future client-side integration
  }

  async evaluate(request: Request): Promise<RuleResult & { detection?: BotDetectionResult }> {
    const detection = this.detectBot(request);

    let conclusion: DecisionConclusion = "ALLOW";

    if (detection.isBot) {
      // Check if this bot is explicitly allowed
      const isAllowed = this.config.allow.some(
        (bot) =>
          detection.botName?.toLowerCase().includes(bot.toLowerCase()) ||
          detection.signals.some((s) => s.toLowerCase().includes(bot.toLowerCase()))
      );

      // Check if this bot is explicitly blocked
      const isBlocked = this.config.block?.some(
        (bot) =>
          detection.botName?.toLowerCase().includes(bot.toLowerCase()) ||
          detection.signals.some((s) => s.toLowerCase().includes(bot.toLowerCase()))
      );

      if (isBlocked || (!isAllowed && this.config.allow.length === 0)) {
        if (detection.confidence >= this.confidenceThreshold) {
          conclusion = "DENY";
        }
      }
    }

    const result: RuleResult & { detection?: BotDetectionResult } = {
      rule: "detectBot",
      conclusion,
      reason: conclusion === "DENY" ? "BOT" : undefined,
      detection,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }

  /**
   * Performs comprehensive bot detection
   */
  private detectBot(request: Request): BotDetectionResult {
    const userAgent = extractUserAgent(request);
    const signals: string[] = [];
    let confidence = 0;
    let botName: string | undefined;
    let botType: BotDetectionResult["botType"];

    // 1. User-Agent pattern matching
    const uaLower = userAgent.toLowerCase();
    for (const bot of WELL_KNOWN_BOTS) {
      if (uaLower.includes(bot.toLowerCase())) {
        signals.push(`User-Agent match: ${bot}`);
        botName = bot;
        confidence = Math.max(confidence, 80);

        // Determine bot type
        if (["Googlebot", "Bingbot", "DuckDuckBot"].some((b) => bot.includes(b))) {
          botType = "crawler";
        } else if (["scrapy", "Puppeteer", "Playwright", "Selenium"].some((b) => bot.includes(b))) {
          botType = "automation";
        } else if (["curl", "Wget", "python-requests"].some((b) => bot.includes(b))) {
          botType = "scraper";
        }
        break;
      }
    }

    // 2. Header analysis
    if (this.analyzeHeaders) {
      const headerSignals = this.analyzeRequestHeaders(request);
      signals.push(...headerSignals.signals);
      confidence = Math.max(confidence, headerSignals.confidence);
    }

    // 3. User-Agent anomaly detection
    const uaAnomalies = this.detectUserAgentAnomalies(userAgent);
    if (uaAnomalies.length > 0) {
      signals.push(...uaAnomalies);
      confidence = Math.max(confidence, 50 + uaAnomalies.length * 10);
    }

    // 4. Empty or missing User-Agent
    if (!userAgent || userAgent.trim() === "") {
      signals.push("Empty User-Agent");
      confidence = Math.max(confidence, 90);
      botType = "unknown";
    }

    // 5. Check for headless browser indicators
    const headlessSignals = this.detectHeadlessBrowser(userAgent, request);
    if (headlessSignals.length > 0) {
      signals.push(...headlessSignals);
      confidence = Math.max(confidence, 85);
      botType = "automation";
    }

    return {
      isBot: confidence >= 50 || signals.length > 0,
      botType: botType || (signals.length > 0 ? "unknown" : undefined),
      botName,
      confidence,
      signals,
    };
  }

  /**
   * Analyzes request headers for bot indicators
   */
  private analyzeRequestHeaders(request: Request): { signals: string[]; confidence: number } {
    const signals: string[] = [];
    let confidence = 0;

    // Check for missing common browser headers
    const acceptLanguage = request.headers.get("accept-language");
    const acceptEncoding = request.headers.get("accept-encoding");
    const accept = request.headers.get("accept");
    const _connection = request.headers.get("connection"); // Reserved for future use
    const secFetchMode = request.headers.get("sec-fetch-mode");
    const secFetchDest = request.headers.get("sec-fetch-dest");
    void _connection; // Suppress unused warning

    if (!acceptLanguage) {
      signals.push("Missing Accept-Language header");
      confidence = Math.max(confidence, 30);
    }

    if (!acceptEncoding) {
      signals.push("Missing Accept-Encoding header");
      confidence = Math.max(confidence, 25);
    }

    if (!accept || accept === "*/*") {
      signals.push("Generic or missing Accept header");
      confidence = Math.max(confidence, 20);
    }

    // Modern browsers send Sec-Fetch-* headers
    if (!secFetchMode && !secFetchDest) {
      signals.push("Missing Sec-Fetch headers (older client or bot)");
      confidence = Math.max(confidence, 15);
    }

    // Check for header ordering anomalies (bots often have unusual ordering)
    const headerCount = [...request.headers.keys()].length;
    if (headerCount < 3) {
      signals.push("Unusually few headers");
      confidence = Math.max(confidence, 40);
    }

    // Check for suspicious patterns
    const via = request.headers.get("via");
    if (via) {
      signals.push(`Via header present: ${via}`);
      confidence = Math.max(confidence, 20);
    }

    return { signals, confidence };
  }

  /**
   * Detects User-Agent anomalies
   */
  private detectUserAgentAnomalies(userAgent: string): string[] {
    const anomalies: string[] = [];

    // Check for outdated browser versions
    const chromeMatch = userAgent.match(/Chrome\/(\d+)/);
    if (chromeMatch) {
      const version = parseInt(chromeMatch[1], 10);
      if (version < 70) {
        anomalies.push(`Outdated Chrome version: ${version}`);
      }
    }

    // Check for impossible combinations
    if (
      userAgent.includes("Chrome") &&
      userAgent.includes("Safari") &&
      !userAgent.includes("Edg")
    ) {
      // This is actually normal for Chrome, but some bots get it wrong
      if (userAgent.includes("MSIE") || userAgent.includes("Trident")) {
        anomalies.push("Impossible browser combination");
      }
    }

    // Check for truncated User-Agent
    if (userAgent.length < 50 && userAgent.includes("Mozilla")) {
      anomalies.push("Unusually short User-Agent for a browser");
    }

    // Check for random/gibberish User-Agent
    if (/^[a-zA-Z0-9]{20,}$/.test(userAgent)) {
      anomalies.push("Random-looking User-Agent");
    }

    // Check for common bot fingerprints
    if (userAgent.includes("compatible;") && !userAgent.includes("MSIE")) {
      anomalies.push("Uses 'compatible' without being IE");
    }

    return anomalies;
  }

  /**
   * Detects headless browser indicators
   */
  private detectHeadlessBrowser(userAgent: string, request: Request): string[] {
    const signals: string[] = [];

    // Check for headless indicators in User-Agent
    const headlessPatterns = [
      "HeadlessChrome",
      "PhantomJS",
      "Headless",
      "puppeteer",
      "playwright",
      "webdriver",
    ];

    for (const pattern of headlessPatterns) {
      if (userAgent.toLowerCase().includes(pattern.toLowerCase())) {
        signals.push(`Headless browser detected: ${pattern}`);
      }
    }

    // Check for webdriver header
    const webdriverHeader = request.headers.get("webdriver");
    if (webdriverHeader) {
      signals.push("WebDriver header present");
    }

    return signals;
  }
}

/**
 * Creates a bot detection rule
 */
export function detectBot(
  config: Partial<Omit<BotDetectionRuleConfig, "type" | "mode">> & {
    mode?: "LIVE" | "DRY_RUN";
    errorStrategy?: BotDetectionRuleConfig["errorStrategy"];
  } = {}
): BotDetectionRuleConfig {
  return {
    type: "detectBot",
    mode: config.mode ?? "LIVE",
    errorStrategy: config.errorStrategy,
    allow: config.allow ?? [],
    block: config.block,
    analyzeHeaders: config.analyzeHeaders,
    confidenceThreshold: config.confidenceThreshold,
    validateFingerprint: config.validateFingerprint,
    challengeMode: config.challengeMode,
  };
}
