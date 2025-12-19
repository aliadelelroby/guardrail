/**
 * Guardrail - Advanced rate limiting and security protection library
 * An open-source alternative to Arcjet
 * @packageDocumentation
 */

import { Guardrail } from "./core/guardrail";
import type { GuardrailConfig } from "./types/index";

export { Guardrail } from "./core/guardrail";
export { loadConfigFile, createGuardrailFromConfig } from "./utils/config-loader";
export {
  validateConfig,
  formatValidationErrors,
  ConfigValidationError,
} from "./utils/config-validator";
export { explainDecision } from "./utils/decision-explainer";
export { visualizeDecision, logDecision, visualizeTimeline } from "./utils/debug-visualizer";
export { replayRequests, formatReplayResults } from "./cli/replay";
export { GuardrailBuilder, createGuardrailBuilder } from "./core/guardrail-builder";
export { GuardrailPresets } from "./core/presets";

// Storage adapters
export { MemoryStorage } from "./storage/memory";
export { RedisStorage } from "./storage/redis";
export { AtomicRedisStorage } from "./storage/redis-atomic";
export type {
  AtomicRedisStorageOptions,
  TokenBucketResult,
  SlidingWindowResult,
} from "./storage/redis-atomic";

// IP Services
export { IPGeolocation } from "./services/ip-geolocation";
export {
  MaxMindProvider,
  IPinfoProvider,
  IPQualityScoreProvider,
  FallbackIPProvider,
  CachingIPProvider,
} from "./services/ip-providers/index";
export type {
  MaxMindConfig,
  IPinfoConfig,
  IPQualityScoreConfig,
} from "./services/ip-providers/index";

// VPN Detection
export { VPNProxyDetection } from "./services/vpn-detection";
export type { VPNDetectionConfig, VPNDetectionResult } from "./services/vpn-detection";

// Utilities
export { CircuitBreaker } from "./utils/circuit-breaker";
export {
  InMemoryMetricsCollector,
  NoOpMetricsCollector,
  type MetricsCollector,
} from "./utils/metrics";
export { ConsoleLogger, type Logger } from "./utils/logger";
export { GuardrailEventEmitter, type GuardrailEventUnion } from "./utils/events";
export { MiddlewareChain, type Middleware } from "./utils/middleware";
export { evaluateExpression } from "./utils/expression-evaluator";

// Prometheus/StatsD/DataDog metrics
export {
  PrometheusMetricsCollector,
  StatsDMetricsCollector,
  DataDogMetricsCollector,
} from "./utils/prometheus-exporter";
export type { PrometheusMetricConfig, PrometheusMetricType } from "./utils/prometheus-exporter";

// Rules - factory functions and classes
export {
  shield,
  bot,
  window,
  bucket,
  email,
  filter,
  BotDetectionRule,
  ShieldRule,
  EmailValidationRule,
  SlidingWindowRule,
  TokenBucketRule,
  FilterRule,
} from "./rules/index";

// Rule types
export type { BotDetectionResult, BotDetectionRuleConfig } from "./rules/bot-detection";

export type { ShieldRuleConfig, ShieldCategory, ShieldDetectionResult } from "./rules/shield";

export type { EmailValidationRuleConfig, EmailValidationResult } from "./rules/email-validation";

// Core types
export type {
  GuardrailConfig,
  Decision,
  DecisionReason,
  ProtectOptions,
  Rule,
  RuleResult,
  IPInfo,
  EnhancedIPInfo,
  Mode,
  DecisionConclusion,
  DenialReason,
  StorageAdapter,
  IPGeolocationService,
  TokenBucketConfig,
  SlidingWindowConfig,
  BotDetectionConfig,
  EmailValidationConfig,
  ShieldConfig,
  FilterConfig,
  GuardrailRule,
  GuardrailRuleType,
  EmailBlockReason,
  ErrorHandlingMode,
  EvaluationStrategy,
  WhitelistConfig,
  BlacklistConfig,
  CustomRuleConfig,
} from "./types/index";

export type { CustomRule, CustomRuleFactory, CustomRuleContext } from "./types/custom-rules";

export {
  GuardrailError,
  StorageError,
  RuleEvaluationError,
  ConfigurationError,
  IPGeolocationError,
  ExpressionEvaluationError,
  CircuitBreakerError,
} from "./errors/index";

export {
  createTestGuardrail,
  MockStorage,
  MockIPGeolocation,
  createMockRequest,
} from "./testing/index";

// NOTE: NestJS adapter is exported separately via '@guardrail-dev/core/nestjs'
// to avoid decorator evaluation issues at import time

/**
 * Creates a new Guardrail instance with the provided configuration
 * @param config - Guardrail configuration
 * @returns New Guardrail instance
 * @example
 * ```typescript
 * const rail = guardrail({
 *   rules: [
 *     bucket({
 *       interval: "1h",
 *       refillRate: 100,
 *       capacity: 1000,
 *       by: ["ip.src"]
 *     })
 *   ]
 * });
 * ```
 */
export function guardrail(config: GuardrailConfig): Guardrail {
  return new Guardrail(config);
}
