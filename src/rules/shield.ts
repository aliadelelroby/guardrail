/**
 * Shield Protection Rule
 * Provides comprehensive attack detection including OWASP Top 10
 * @module rules/shield
 */

import type { ShieldConfig, RuleResult, DecisionConclusion } from "../types/index";

/* eslint-disable no-control-regex */
/**
 * SQL Injection patterns - comprehensive detection
 */
const SQL_INJECTION_PATTERNS = [
  // Basic SQL keywords with word boundaries
  /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE|REPLACE|MERGE)\b/i,
  // Comment-based injection
  /(--|#|\/\*|\*\/|;--)/i,
  // String-based injection
  /('|"|`|\\'|\\"|\\`)(\s*(OR|AND)\s*('|"|`|1|true))/i,
  // Encoded injection attempts
  /(%27|%22|%60|%3D|%3B|%2D%2D)/i,
  // Boolean-based blind injection
  /\b(OR|AND)\s+\d+\s*=\s*\d+/i,
  /\b(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/i,
  // UNION-based injection
  /UNION(\s+ALL)?\s+SELECT/i,
  // Stacked queries
  /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)/i,
  // Time-based blind injection
  /(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\s*\(/i,
  // Error-based injection
  /(EXTRACTVALUE|UPDATEXML|XMLTYPE)\s*\(/i,
  // Database-specific functions
  /(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)/i,
  // Information schema access
  /INFORMATION_SCHEMA\./i,
  // System table access
  /(SYS\.|SYSOBJECTS|SYSCOLUMNS)/i,
  // HAVING/GROUP BY injection
  /\bHAVING\s+\d+\s*[<>=]/i,
  // ORDER BY injection
  /ORDER\s+BY\s+\d+/i,
];

/**
 * XSS patterns - comprehensive detection
 */
const XSS_PATTERNS = [
  // Script tags
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /<script[^>]*>/gi,
  // Event handlers
  /\bon\w+\s*=\s*["']?[^"']*["']?/gi,
  /\bon\w+\s*=/gi,
  // JavaScript protocol
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /livescript\s*:/gi,
  // Data URI with script
  /data\s*:\s*text\/html/gi,
  // SVG-based XSS
  /<svg[^>]*\s+onload\s*=/gi,
  /<svg[^>]*>[\s\S]*?<script/gi,
  // Iframe injection
  /<iframe[^>]*>/gi,
  // Object/Embed injection
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  // Base tag hijacking
  /<base[^>]*>/gi,
  // Link injection
  /<link[^>]*>/gi,
  // Meta refresh
  /<meta[^>]*http-equiv\s*=\s*["']?refresh/gi,
  // Form action hijacking
  /<form[^>]*action\s*=/gi,
  // Expression (IE)
  /expression\s*\(/gi,
  // Import
  /@import/gi,
  // Behavior (IE)
  /behavior\s*:/gi,
  // Binding (Firefox)
  /-moz-binding\s*:/gi,
  // HTML entities that could be XSS
  /&#x?[0-9a-f]+;?/gi,
  // Unicode escapes
  /\\u[0-9a-f]{4}/gi,
  // Encoded event handlers
  /%6F%6E/gi, // "on"
];

/**
 * Command injection patterns
 */
const COMMAND_INJECTION_PATTERNS = [
  // Shell metacharacters
  /[;&|`$(){}[\]<>]/,
  // Command substitution
  /\$\([^)]+\)/,
  /`[^`]+`/,
  // Shell commands
  /\b(cat|ls|pwd|whoami|id|uname|ps|kill|rm|mv|cp|chmod|chown|wget|curl|nc|netcat|bash|sh|zsh|perl|python|ruby|php|node)\b/i,
  // Common attack commands
  /\b(ping|nslookup|dig|traceroute|telnet|ssh|ftp|tftp|scp|rsync)\b/i,
  // Windows commands
  /\b(cmd|powershell|wscript|cscript|reg|net|tasklist|taskkill|systeminfo)\b/i,
  // Path traversal in commands
  /\.\.[/\\]/,
  // Null byte injection
  /%00/,
  // Newline injection
  /[\r\n]/,
  // Environment variable access
  /\$\{[^}]+\}/,
  /\$[A-Z_]+/,
];

/**
 * Path traversal patterns
 */
const PATH_TRAVERSAL_PATTERNS = [
  // Basic traversal
  /\.\.[/\\]/,
  // Encoded traversal
  /(%2e%2e|%252e%252e)[/\\%]/i,
  /(%c0%ae|%c1%9c)/i, // Overlong UTF-8
  // Null byte injection
  /%00/,
  /\x00/,
  // Windows-specific
  /\.\.\\|\.\.%5c/i,
  // URL encoding variations
  /\.\.%2f|\.\.%255c/i,
];

/**
 * LDAP injection patterns
 */
const LDAP_INJECTION_PATTERNS = [
  /[()\\*|&=!<>~]/,
  /\x00/,
  /%00/,
];

/**
 * XML/XXE injection patterns
 */
const XXE_PATTERNS = [
  /<!DOCTYPE[^>]*\[/i,
  /<!ENTITY/i,
  /SYSTEM\s+["']/i,
  /PUBLIC\s+["']/i,
  /file:\/\//i,
  /expect:\/\//i,
  /php:\/\//i,
];

/**
 * Header injection patterns
 */
const HEADER_INJECTION_PATTERNS = [
  /[\r\n]/,
  /%0d|%0a/i,
  /\\r|\\n/,
];

/**
 * Log injection patterns
 */
const LOG_INJECTION_PATTERNS = [
  /[\r\n]/,
  /%0d|%0a/i,
  // Log forging patterns
  /\d{4}-\d{2}-\d{2}/,
  /\[\w+\]/,
];

/**
 * Request anomaly patterns
 */
const ANOMALY_PATTERNS = [
  // Extremely long values (potential buffer overflow)
  /.{10000,}/,
  // Repeated patterns (potential DoS)
  /(.)\1{100,}/,
  // Binary/null content
  /[\x00-\x08\x0b\x0c\x0e-\x1f]/,
];

/**
 * Shield configuration with extended options
 */
export interface ShieldRuleConfig extends ShieldConfig {
  /** Detection categories to enable */
  categories?: ShieldCategory[];
  /** Custom patterns to add */
  customPatterns?: RegExp[];
  /** Patterns to exclude (whitelist) */
  excludePatterns?: RegExp[];
  /** Scan request body */
  scanBody?: boolean;
  /** Scan request headers */
  scanHeaders?: boolean;
  /** Maximum body size to scan (bytes) */
  maxBodySize?: number;
  /** Headers to skip scanning */
  skipHeaders?: string[];
  /** Log matched patterns */
  logMatches?: boolean;
}

/**
 * Shield detection categories
 */
export type ShieldCategory =
  | "sql-injection"
  | "xss"
  | "command-injection"
  | "path-traversal"
  | "ldap-injection"
  | "xxe"
  | "header-injection"
  | "log-injection"
  | "anomaly";

/**
 * Shield detection result
 */
export interface ShieldDetectionResult {
  detected: boolean;
  category?: ShieldCategory;
  pattern?: string;
  location?: "url" | "body" | "headers" | "query";
  matchedValue?: string;
}

/**
 * Pattern category mapping
 */
const CATEGORY_PATTERNS: Record<ShieldCategory, RegExp[]> = {
  "sql-injection": SQL_INJECTION_PATTERNS,
  "xss": XSS_PATTERNS,
  "command-injection": COMMAND_INJECTION_PATTERNS,
  "path-traversal": PATH_TRAVERSAL_PATTERNS,
  "ldap-injection": LDAP_INJECTION_PATTERNS,
  "xxe": XXE_PATTERNS,
  "header-injection": HEADER_INJECTION_PATTERNS,
  "log-injection": LOG_INJECTION_PATTERNS,
  "anomaly": ANOMALY_PATTERNS,
};

/**
 * Shield Protection Rule
 */
export class ShieldRule {
  private readonly config: ShieldRuleConfig;
  private readonly categories: Set<ShieldCategory>;
  private readonly patterns: Map<ShieldCategory, RegExp[]>;
  private readonly scanBody: boolean;
  private readonly scanHeaders: boolean;
  private readonly maxBodySize: number;
  private readonly skipHeaders: Set<string>;

  constructor(config: ShieldRuleConfig) {
    this.config = config;
    this.categories = new Set(
      config.categories || [
        "sql-injection",
        "xss",
        "command-injection",
        "path-traversal",
      ]
    );
    this.patterns = new Map();
    this.scanBody = config.scanBody ?? true;
    this.scanHeaders = config.scanHeaders ?? true;
    this.maxBodySize = config.maxBodySize ?? 1024 * 1024; // 1MB default
    this.skipHeaders = new Set(
      (config.skipHeaders || ["authorization", "cookie"]).map((h) => h.toLowerCase())
    );

    // Build pattern map
    for (const category of this.categories) {
      const categoryPatterns = [...CATEGORY_PATTERNS[category]];
      if (config.customPatterns) {
        categoryPatterns.push(...config.customPatterns);
      }
      this.patterns.set(category, categoryPatterns);
    }
  }

  async evaluate(request: Request): Promise<RuleResult & { detection?: ShieldDetectionResult }> {
    const detection = await this.detect(request);

    const conclusion: DecisionConclusion = detection.detected ? "DENY" : "ALLOW";

    const result: RuleResult & { detection?: ShieldDetectionResult } = {
      rule: "shield",
      conclusion,
      reason: conclusion === "DENY" ? "SHIELD" : undefined,
      detection,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }

  /**
   * Performs comprehensive attack detection
   */
  private async detect(request: Request): Promise<ShieldDetectionResult> {
    // Check URL
    const urlResult = this.scanText(request.url, "url");
    if (urlResult.detected) return urlResult;

    // Check query parameters
    try {
      const url = new URL(request.url);
      const queryString = url.searchParams.toString();
      if (queryString) {
        const queryResult = this.scanText(decodeURIComponent(queryString), "query");
        if (queryResult.detected) return queryResult;
      }
    } catch {
      // Invalid URL, scan as-is
    }

    // Check headers
    if (this.scanHeaders) {
      for (const [name, value] of request.headers.entries()) {
        if (this.skipHeaders.has(name.toLowerCase())) continue;
        const headerResult = this.scanText(value, "headers");
        if (headerResult.detected) return headerResult;
      }
    }

    // Check body
    if (this.scanBody && request.body) {
      try {
        const clonedRequest = request.clone();
        const bodyText = await clonedRequest.text();
        
        if (bodyText.length <= this.maxBodySize) {
          const bodyResult = this.scanText(bodyText, "body");
          if (bodyResult.detected) return bodyResult;
        }
      } catch {
        // Body not readable, skip
      }
    }

    return { detected: false };
  }

  /**
   * Scans text for malicious patterns
   */
  private scanText(
    text: string,
    location: ShieldDetectionResult["location"]
  ): ShieldDetectionResult {
    // Check exclusions first
    if (this.config.excludePatterns) {
      for (const pattern of this.config.excludePatterns) {
        if (pattern.test(text)) {
          return { detected: false };
        }
      }
    }

    // Check each category
    for (const [category, patterns] of this.patterns) {
      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match) {
          return {
            detected: true,
            category,
            pattern: pattern.source,
            location,
            matchedValue: match[0].substring(0, 100), // Limit length
          };
        }
      }
    }

    return { detected: false };
  }
}

/**
 * Creates a shield rule
 */
export function shield(
  config: Omit<ShieldRuleConfig, "type" | "mode"> & { mode?: "LIVE" | "DRY_RUN" } = {}
): ShieldRuleConfig {
  return {
    type: "shield",
    mode: config.mode || "LIVE",
    ...config,
  };
}
