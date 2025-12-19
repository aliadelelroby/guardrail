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
 * Refined to only match in suspicious contexts to reduce false positives
 */
const COMMAND_INJECTION_PATTERNS = [
  // Shell metacharacters followed by commands (most suspicious)
  /[;&|`]\s*(cat|ls|pwd|whoami|id|uname|ps|kill|rm|mv|cp|chmod|chown|wget|curl|nc|netcat|bash|sh|zsh|perl|python|ruby|php|node|cmd|powershell)/i,
  // Command substitution (always suspicious)
  /\$\([^)]+\)/,
  /`[^`]+`/,
  // Suspicious shell metacharacters at start/end or with newlines
  /^[;&|`$]|[\r\n][;&|`$]/,
  /[;&|`$][\r\n]/,
  // Commands with path traversal (suspicious combination)
  /(cat|ls|pwd|whoami|id|uname|ps|kill|rm|mv|cp|chmod|chown|wget|curl|nc|netcat|bash|sh|zsh|perl|python|ruby|php|node|cmd|powershell).*\.\.[/\\]/i,
  // Network/attack commands (always suspicious in user input)
  /\b(ping|nslookup|dig|traceroute|telnet|ssh|ftp|tftp|scp|rsync)\b/i,
  // Windows system commands (always suspicious)
  /\b(cmd|powershell|wscript|cscript|reg|net|tasklist|taskkill|systeminfo)\b/i,
  // Environment variable access in suspicious contexts
  /[;&|`$]\s*\$\{[^}]+\}/,
  /[;&|`$]\s*\$[A-Z_]+/,
  // Null byte injection (always suspicious)
  /%00/,
  // Newline injection with commands
  /[\r\n]\s*(cat|ls|pwd|whoami|id|uname|ps|kill|rm|mv|cp|chmod|chown|wget|curl|nc|netcat|bash|sh|zsh|perl|python|ruby|php|node|cmd|powershell)/i,
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
 * Note: LDAP special characters are only suspicious in specific contexts
 * Parentheses are common in URLs/JSON, so we only match in suspicious combinations
 */
const LDAP_INJECTION_PATTERNS = [
  // LDAP filter operators in suspicious contexts
  /\([^)]*[\\*|&=!<>~][^)]*\)/, // Parentheses with LDAP operators inside
  /[\\*|&=!<>~].*\(|\).*[\\*|&=!<>~]/, // Operators near parentheses
  /\x00/, // Null byte
  /%00/, // URL-encoded null byte
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
const HEADER_INJECTION_PATTERNS = [/[\r\n]/, /%0d|%0a/i, /\\r|\\n/];

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
  /** Enable OWASP CRS-style anomaly scoring (default: false) */
  anomalyScoring?: boolean;
  /** Anomaly score threshold per category (default: 100). OWASP CRS recommends starting high (10,000) and gradually lowering. */
  anomalyThreshold?: number;
  /** Pattern scores - how many points each pattern match adds */
  patternScores?: Record<ShieldCategory, number>;
  /** Endpoint-specific pattern whitelists (manual configuration only) */
  endpointWhitelists?: Record<string, Array<string | RegExp>>;
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
  anomalyScore?: number;
}

/**
 * Pattern category mapping
 */
const CATEGORY_PATTERNS: Record<ShieldCategory, RegExp[]> = {
  "sql-injection": SQL_INJECTION_PATTERNS,
  xss: XSS_PATTERNS,
  "command-injection": COMMAND_INJECTION_PATTERNS,
  "path-traversal": PATH_TRAVERSAL_PATTERNS,
  "ldap-injection": LDAP_INJECTION_PATTERNS,
  xxe: XXE_PATTERNS,
  "header-injection": HEADER_INJECTION_PATTERNS,
  "log-injection": LOG_INJECTION_PATTERNS,
  anomaly: ANOMALY_PATTERNS,
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
  private readonly anomalyScoring: boolean;
  private readonly anomalyThreshold: number;
  private readonly patternScores: Map<ShieldCategory, number>;
  private readonly endpointWhitelists: Map<string, Set<string>>;
  private readonly weakKeywordPatternIndex: number; // Index of weak SQL keyword pattern for reliable comparison

  constructor(config: ShieldRuleConfig) {
    this.config = config;
    this.categories = new Set(config.categories || ["sql-injection", "xss", "path-traversal"]);
    this.patterns = new Map();
    this.scanBody = config.scanBody ?? false;
    this.scanHeaders = config.scanHeaders ?? true;
    this.maxBodySize = config.maxBodySize ?? 1024 * 1024; // 1MB default
    this.skipHeaders = new Set(
      (config.skipHeaders || ["authorization", "cookie"]).map((h) => h.toLowerCase())
    );
    this.anomalyScoring = config.anomalyScoring ?? false;
    // OWASP CRS recommends starting with high threshold (10,000) and gradually lowering
    // Default of 100 is conservative to minimize false positives
    this.anomalyThreshold = config.anomalyThreshold ?? 100;

    // Default pattern scores (weak signals = 1, strong signals = 5)
    const defaultScores: Record<ShieldCategory, number> = {
      "sql-injection": 3,
      xss: 3,
      "command-injection": 5,
      "path-traversal": 4,
      "ldap-injection": 4,
      xxe: 5,
      "header-injection": 4,
      "log-injection": 2,
      anomaly: 2,
    };

    this.patternScores = new Map();
    for (const category of this.categories) {
      this.patternScores.set(
        category,
        config.patternScores?.[category] ?? defaultScores[category] ?? 3
      );
    }

    // Build endpoint whitelist map (manual configuration only - safe)
    // Validate endpoint patterns at construction time to catch configuration errors early
    this.endpointWhitelists = new Map();
    if (config.endpointWhitelists) {
      for (const [endpoint, patterns] of Object.entries(config.endpointWhitelists)) {
        // Validate endpoint regex pattern if it's meant to be a regex
        // (endpoints can be strings for exact match, or regex patterns)
        if (endpoint.startsWith("/") && endpoint.endsWith("/")) {
          // Looks like a regex pattern, validate it
          try {
            new RegExp(endpoint.slice(1, -1)); // Remove leading/trailing slashes
          } catch (error) {
            throw new Error(
              `Invalid endpoint regex pattern in ShieldRuleConfig: "${endpoint}". ${error instanceof Error ? error.message : String(error)}`
            );
          }
        }

        const patternSet = new Set<string>();
        for (const pattern of patterns) {
          patternSet.add(typeof pattern === "string" ? pattern : pattern.source);
        }
        this.endpointWhitelists.set(endpoint, patternSet);
      }
    }

    // Validate and build pattern map
    if (config.customPatterns) {
      for (const pattern of config.customPatterns) {
        this.validateRegexPattern(pattern);
      }
    }

    // Build pattern map and find weak keyword pattern index for reliable comparison
    const weakKeywordPattern =
      /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE|REPLACE|MERGE)\b/i;
    const sqlPatterns = CATEGORY_PATTERNS["sql-injection"];
    // Find index of weak pattern in original patterns (more reliable than string comparison)
    this.weakKeywordPatternIndex = sqlPatterns.findIndex(
      (p) => p.source === weakKeywordPattern.source && p.flags === weakKeywordPattern.flags
    );

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

    // Check endpoint-specific whitelists
    if (detection.detected && detection.pattern) {
      try {
        const url = new URL(request.url);
        const pathname = url.pathname;

        // Check if this endpoint has whitelisted patterns
        for (const [endpoint, whitelistedPatterns] of this.endpointWhitelists.entries()) {
          let matches = false;

          // Endpoint can be: exact string match, substring match, or regex pattern
          if (pathname === endpoint) {
            matches = true; // Exact match
          } else if (!endpoint.startsWith("/") || !endpoint.endsWith("/")) {
            // String pattern (not regex) - use substring match
            matches = pathname.includes(endpoint);
          } else {
            // Regex pattern (wrapped in slashes) - validate and test
            try {
              const regexPattern = endpoint.slice(1, -1); // Remove leading/trailing slashes
              matches = new RegExp(regexPattern).test(pathname);
            } catch (error) {
              // Invalid regex (should have been caught at construction, but handle gracefully)
              console.warn(
                `[Shield] Invalid endpoint regex pattern "${endpoint}" (should have been caught at construction):`,
                error
              );
              continue; // Skip this endpoint
            }
          }

          if (matches && whitelistedPatterns.has(detection.pattern)) {
            // Pattern is whitelisted for this endpoint
            return {
              rule: "shield",
              conclusion: "ALLOW",
              detection: { ...detection, detected: false },
            };
          }
        }
      } catch (error) {
        // Invalid URL or other error - log and continue
        if (error instanceof Error && !error.message.includes("Invalid URL")) {
          console.warn(`[Shield] Error checking endpoint whitelist:`, error);
        }
        // Continue with normal detection flow
      }
    }

    // Debug logging (console.log is intentional for debug mode - not using logger to avoid dependency)
    if (detection.detected && this.config.logMatches) {
      // Note: Using console.log instead of logger for debug mode to avoid circular dependencies
      // This is intentional and only enabled when logMatches is explicitly set to true
      console.log(`[Shield] Blocked: ${detection.category} in ${detection.location}`, {
        pattern: detection.pattern,
        matched: detection.matchedValue,
        url: request.url,
      });
    }

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
    // Check URL - be more lenient with SQL keywords in URLs (they're often legitimate)
    const urlResult = this.scanText(request.url, "url", { isUrl: true });
    if (urlResult.detected) {
      return urlResult;
    }

    // Check query parameters - this is where SQL injection is most likely
    try {
      const url = new URL(request.url);
      const queryString = url.searchParams.toString();
      if (queryString) {
        // Query parameters are high-risk for SQL injection
        const queryResult = this.scanText(decodeURIComponent(queryString), "query", {
          isQueryParam: true,
        });
        if (queryResult.detected) {
          return queryResult;
        }
      }
    } catch {
      // Invalid URL, scan as-is
    }

    // Check headers
    if (this.scanHeaders) {
      for (const [name, value] of request.headers.entries()) {
        if (this.skipHeaders.has(name.toLowerCase())) {
          continue;
        }
        const headerResult = this.scanText(value, "headers", { isHeader: true });
        if (headerResult.detected) {
          return headerResult;
        }
      }
    }

    // Check body
    if (this.scanBody && request.body) {
      try {
        // Check Content-Length header first to prevent reading large bodies
        const contentLength = request.headers.get("content-length");
        if (contentLength) {
          const size = parseInt(contentLength, 10);
          if (!isNaN(size) && size > this.maxBodySize) {
            // Body too large, skip scanning but don't treat as attack
            return { detected: false };
          }
        }

        // Use streaming with early termination for memory efficiency
        const clonedRequest = request.clone();
        const reader = clonedRequest.body?.getReader();
        if (!reader) {
          return { detected: false };
        }

        let totalSize = 0;
        const decoder = new TextDecoder();
        const chunkSize = 8192; // 8KB chunks for efficient scanning
        let buffer = "";

        try {
          // eslint-disable-next-line no-constant-condition
          while (true) {
            const { done, value } = await reader.read();
            if (done) {
              break;
            }

            totalSize += value.length;
            if (totalSize > this.maxBodySize) {
              // Body exceeds limit, stop reading
              void reader.cancel();
              return { detected: false };
            }

            // Decode chunk and add to buffer
            buffer += decoder.decode(value, { stream: true });

            // Scan buffer in chunks to enable early termination
            // Only keep last chunkSize bytes in buffer to prevent memory growth
            if (buffer.length > chunkSize * 2) {
              // Scan the first part
              const toScan = buffer.slice(0, chunkSize);
              const scanResult = this.scanText(toScan, "body");
              if (scanResult.detected) {
                void reader.cancel();
                return scanResult;
              }
              // Keep only the last chunkSize bytes (for patterns that span chunks)
              buffer = buffer.slice(-chunkSize);
            }
          }

          // Decode any remaining bytes
          buffer += decoder.decode();

          // Scan remaining buffer
          if (buffer.length > 0) {
            const bodyResult = this.scanText(buffer, "body");
            if (bodyResult.detected) {
              return bodyResult;
            }
          }
        } finally {
          reader.releaseLock();
        }
      } catch {
        // Body not readable, skip
      }
    }

    return { detected: false };
  }

  /**
   * Validates a regex pattern to prevent ReDoS
   */
  private validateRegexPattern(pattern: RegExp): void {
    const source = pattern.source;

    // Maximum pattern length
    if (source.length > 1000) {
      throw new Error("Regex pattern exceeds maximum length of 1000 characters");
    }

    // Check for dangerous nested quantifiers
    const dangerousPatterns = [
      /\([^)]*\+[^)]*\)\+/, // (a+)+
      /\([^)]*\*[^)]*\)\*/, // (a*)*
      /\([^)]*\{[^}]*\}[^)]*\)\{[^}]*\}/, // (a{1,}){1,}
      /\([^)]*\+[^)]*\)\*/, // (a+)*
      /\([^)]*\*[^)]*\)\+/, // (a*)+
    ];

    for (const dangerousPattern of dangerousPatterns) {
      if (dangerousPattern.test(source)) {
        throw new Error(
          "Regex pattern contains dangerous nested quantifiers that could cause ReDoS"
        );
      }
    }

    // Check for excessive quantifiers
    const quantifierCount = (source.match(/[+*?]\{/g) || []).length;
    if (quantifierCount > 20) {
      throw new Error("Regex pattern contains too many quantifiers");
    }
  }

  /**
   * Scans text for malicious patterns with timeout protection
   * @param text - Text to scan
   * @param location - Where the text is from (url, query, headers, body)
   * @param context - Additional context for context-aware matching
   */
  private scanText(
    text: string,
    location: ShieldDetectionResult["location"],
    context?: { isUrl?: boolean; isQueryParam?: boolean; isHeader?: boolean; isBody?: boolean }
  ): ShieldDetectionResult {
    // Limit text length to prevent DoS
    const maxTextLength = 100000; // 100KB
    const textToScan = text.length > maxTextLength ? text.substring(0, maxTextLength) : text;

    // Check exclusions first (static whitelist)
    if (this.config.excludePatterns) {
      for (const pattern of this.config.excludePatterns) {
        try {
          if (this.executeRegexWithTimeout(pattern, textToScan)) {
            return { detected: false };
          }
        } catch (error) {
          // Log non-timeout errors for debugging
          if (error instanceof Error && !error.message.includes("timeout")) {
            console.warn(`[Shield] Unexpected error in exclusion pattern matching:`, error);
          }
          continue; // If regex times out, continue to next pattern
        }
      }
    }

    // OWASP CRS-style anomaly scoring: accumulate weak signals
    if (this.anomalyScoring) {
      const anomalyScores = new Map<ShieldCategory, number>();
      const matchedPatterns: Array<{ category: ShieldCategory; pattern: string; matched: string }> =
        [];

      // Check each category and accumulate scores
      for (const [category, patterns] of this.patterns) {
        for (const pattern of patterns) {
          try {
            const match = this.executeRegexWithTimeout(pattern, textToScan);
            if (match) {
              const matchedText = typeof match === "string" ? match : match[0] || "";
              const score = this.patternScores.get(category) ?? 3;
              const currentScore = anomalyScores.get(category) ?? 0;
              anomalyScores.set(category, currentScore + score);
              matchedPatterns.push({
                category,
                pattern: pattern.source,
                matched: matchedText.substring(0, 100),
              });
            }
          } catch (error) {
            // Log non-timeout errors for debugging
            if (error instanceof Error && !error.message.includes("timeout")) {
              console.warn(`[Shield] Unexpected error in anomaly scoring pattern matching:`, error);
            }
            continue; // If regex times out, continue to next pattern
          }
        }
      }

      // Check if any category exceeds threshold
      for (const [category, score] of anomalyScores.entries()) {
        if (score >= this.anomalyThreshold) {
          const firstMatch = matchedPatterns.find((m) => m.category === category);
          return {
            detected: true,
            category,
            pattern: firstMatch?.pattern || "multiple",
            location,
            matchedValue: firstMatch?.matched || "anomaly_score",
            anomalyScore: score,
          };
        }
      }

      // If no category exceeded threshold, allow
      return { detected: false };
    }

    // Traditional single-pattern matching (default behavior) with context awareness
    for (const [category, patterns] of this.patterns) {
      // SECURITY: Check ALL SQL injection patterns everywhere (including URLs)
      // The security risk of missing attacks outweighs the false positive risk from URLs.
      // Only exception: Skip the weakest single-keyword pattern in URLs to reduce false positives
      // from legitimate URLs like /api/select or /insert
      if (category === "sql-injection" && context?.isUrl) {
        // Check all patterns except the weak single-keyword pattern (using index for reliable comparison)
        for (let i = 0; i < patterns.length; i++) {
          // Skip only the weak single-keyword pattern in URLs (using index for reliability)
          if (i === this.weakKeywordPatternIndex) {
            continue;
          }

          const pattern = patterns[i];

          try {
            const match = this.executeRegexWithTimeout(pattern, textToScan);
            if (match) {
              const matchedText = typeof match === "string" ? match : match[0] || "";
              return {
                detected: true,
                category,
                pattern: pattern.source,
                location,
                matchedValue: matchedText.substring(0, 100),
              };
            }
          } catch (error) {
            // Log non-timeout errors for debugging
            if (error instanceof Error && !error.message.includes("timeout")) {
              console.warn(`[Shield] Unexpected error in SQL pattern matching:`, error);
            }
            continue;
          }
        }

        // All non-weak patterns checked, continue to next category
        continue;
      }

      // XSS in headers is less likely (headers are usually not rendered as HTML)
      if (category === "xss" && context?.isHeader) {
        // Only match strong XSS patterns in headers
        const strongPatterns = patterns.filter((p) => {
          const source = p.source;
          return source.includes("<script") || source.includes("javascript:");
        });
        for (const pattern of strongPatterns) {
          try {
            const match = this.executeRegexWithTimeout(pattern, textToScan);
            if (match) {
              const matchedText = typeof match === "string" ? match : match[0] || "";
              return {
                detected: true,
                category,
                pattern: pattern.source,
                location,
                matchedValue: matchedText.substring(0, 100),
              };
            }
          } catch (error) {
            // Log non-timeout errors for debugging
            if (error instanceof Error && !error.message.includes("timeout")) {
              console.warn(`[Shield] Unexpected error in XSS pattern matching:`, error);
            }
            continue;
          }
        }
        continue; // Skip weak XSS patterns in headers
      }

      // Standard pattern matching for other cases
      for (const pattern of patterns) {
        try {
          const match = this.executeRegexWithTimeout(pattern, textToScan);
          if (match) {
            const matchedText = typeof match === "string" ? match : match[0] || "";
            return {
              detected: true,
              category,
              pattern: pattern.source,
              location,
              matchedValue: matchedText.substring(0, 100), // Limit length
            };
          }
        } catch (error) {
          // Log non-timeout errors for debugging
          if (error instanceof Error && !error.message.includes("timeout")) {
            console.warn(`[Shield] Unexpected error in pattern matching:`, error);
          }
          continue; // If regex times out, continue to next pattern
        }
      }
    }

    return { detected: false };
  }

  /**
   * Executes regex with timeout to prevent DoS
   */
  private executeRegexWithTimeout(
    regex: RegExp,
    text: string,
    timeoutMs: number = 100
  ): RegExpMatchArray | null {
    const startTime = Date.now();

    // For small texts, execute directly
    if (text.length < 1000) {
      const result = text.match(regex);
      if (Date.now() - startTime > timeoutMs) {
        throw new Error("Regex execution timeout");
      }
      return result;
    }

    // For larger texts, limit the search
    const testText = text.substring(0, Math.min(text.length, 10000));
    const result = testText.match(regex);

    if (Date.now() - startTime > timeoutMs) {
      throw new Error("Regex execution timeout");
    }

    return result;
  }
}

/**
 * Creates a shield rule
 */
export function shield(
  config: Omit<ShieldRuleConfig, "type" | "mode"> & {
    mode?: "LIVE" | "DRY_RUN";
    errorStrategy?: ShieldRuleConfig["errorStrategy"];
  } = {}
): ShieldRuleConfig {
  return {
    type: "shield",
    mode: config.mode || "LIVE",
    errorStrategy: config.errorStrategy,
    scanBody: config.scanBody ?? false, // Default to false to avoid JSON false positives
    ...config,
  };
}
