/**
 * Guardrail configuration presets for common use cases
 * @module core/presets
 */

import type { GuardrailConfig } from "../types/index";
import { shield, bot, window, bucket, email } from "../rules/index";

/**
 * Pre-configured security policies for different environment types
 */
export const GuardrailPresets = {
  /**
   * Standard API protection
   * - Block common web attacks (SQLi, XSS, etc.)
   * - Block common zero-value bots
   * - moderate rate limit (100 requests / minute)
   */
  api: (): GuardrailConfig => ({
    rules: [
      shield(),
      bot({ allow: [] }), // Block generic bots
      window({ interval: "1m", max: 100 }),
    ],
    errorHandling: "FAIL_OPEN",
    evaluationStrategy: "SEQUENTIAL",
  }),

  /**
   * Browser/Web Application protection
   * - Block common web attacks
   * - Allow search engine crawlers (Google, Bing, etc.)
   * - Higher rate limit for assets (1000 requests / minute)
   */
  web: (): GuardrailConfig => ({
    rules: [
      shield({
        scanBody: true,
        scanHeaders: true,
      }),
      bot({
        allow: ["Googlebot", "Bingbot", "DuckDuckBot", "Baiduspider", "YandexBot"],
      }),
      window({ interval: "1m", max: 1000 }),
    ],
    errorHandling: "FAIL_OPEN",
    evaluationStrategy: "PARALLEL",
  }),

  /**
   * Strict security for sensitive endpoints
   * - Aggressive attack blocking
   * - Block all bots including search engines
   * - Strict rate limit (10 requests / minute)
   * - Fail closed (deny access if systems fail)
   */
  strict: (): GuardrailConfig => ({
    rules: [
      shield({
        mode: "LIVE",
        categories: ["sql-injection", "xss", "command-injection", "path-traversal", "xxe"],
      }),
      bot({
        allow: [],
        analyzeHeaders: true,
        confidenceThreshold: 80,
      }),
      window({ interval: "1m", max: 10 }),
    ],
    errorHandling: "FAIL_CLOSED",
    evaluationStrategy: "SHORT_CIRCUIT",
  }),

  /**
   * AI / LLM Model protection
   * - Token bucket rate limiting (ideal for token usage quotas)
   * - Blocks bots to prevent scraping/abuse
   * - Moderate shield protection
   */
  ai: (): GuardrailConfig => ({
    rules: [
      shield(),
      bot({ allow: [] }),
      // Default: 1000 tokens/min capacity, refilling 10 per second approx.
      // Users should override this with their specific token logic
      bucket({
        refillRate: 10,
        interval: "1s",
        capacity: 1000,
        by: ["ip.src"],
      }),
    ],
    errorHandling: "FAIL_OPEN",
    evaluationStrategy: "PARALLEL",
  }),

  /**
   * Payment / Checkout protection
   * - Strict validation for emails (no disposable/temporary emails)
   * - Aggressive attack blocking (SQLi/XSS prevention)
   * - Stricter rate limiting to prevent card testing/stuffing
   */
  payment: (): GuardrailConfig => ({
    rules: [
      shield({
        mode: "LIVE",
        scanBody: true,
        scanHeaders: true,
      }),
      bot({ allow: [] }),
      email({
        block: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS"],
      }),
      window({ interval: "1m", max: 20 }), // Strict limit for payments
    ],
    errorHandling: "FAIL_OPEN", // balanced security and availability
    evaluationStrategy: "SEQUENTIAL",
  }),

  /**
   * Authentication (Login/Signup) protection
   * - Prevents credential stuffing
   * - Validates emails
   * - Strict rate limiting
   */
  auth: (): GuardrailConfig => ({
    rules: [
      shield(),
      bot({ allow: [] }),
      email({
        block: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS"],
      }),
      window({ interval: "1m", max: 10 }), // Prevent brute force
    ],
    errorHandling: "FAIL_OPEN",
    evaluationStrategy: "SEQUENTIAL",
  }),

  /**
   * Development mode
   * - Log-only (DRY_RUN) for all rules
   * - Debug logging enabled
   */
  development: (): GuardrailConfig => ({
    rules: [
      shield({ mode: "DRY_RUN" }),
      bot({ mode: "DRY_RUN", allow: [] }),
      window({ mode: "DRY_RUN", interval: "1m", max: 100 }),
    ],
    debug: true,
    errorHandling: "FAIL_OPEN",
  }),
};
