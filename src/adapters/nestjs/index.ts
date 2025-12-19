/**
 * Nest.js adapter for Guardrail
 * @module adapters/nestjs
 */

export { GuardrailModule, type GuardrailModuleOptions } from "./guardrail.module";
export { GuardrailGuard } from "./guardrail.guard";
export {
  Limit,
  TokenBucket,
  Shield,
  Bot,
  Email,
  Filter,
  BlockVPN,
  BlockCountry,
  WhitelistIPs,
  Quota,
  Result,
  IPInfo,
  Tokens,
  SkipGuardrail,
  Preset,
  UseGuardrail,
  GuardrailOptions,
  byTier,
} from "./decorators";
export type { QuotaConfig } from "../../types/index";
export { GuardrailInterceptor, GuardrailInterceptorOptions } from "./guardrail.interceptor";
export { Guardrail } from "../../core/guardrail";

// Export types from core, excluding conflicting names
export type {
  Mode,
  DecisionConclusion,
  RateLimitReason,
  BotReason,
  EmailReason,
  ShieldReason,
  FilterReason,
  QuotaReason,
  DenialReason,
  EnhancedIPInfo,
  DecisionReason,
  RuleResult,
  ProtectOptions,
  ErrorHandlingMode,
  EvaluationStrategy,
  GuardrailConfig,
  WhitelistConfig,
  BlacklistConfig,
  Rule,
  GuardrailRuleType,
  StorageAdapter,
  IPGeolocationService,
  TokenBucketConfig,
  SlidingWindowConfig,
  BotDetectionConfig,
  EmailValidationConfig,
  EmailBlockReason,
  ShieldConfig,
  FilterConfig,
  GuardrailRule,
  CustomRuleConfig,
} from "../../types/index";
