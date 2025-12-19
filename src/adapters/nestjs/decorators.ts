/**
 * Nest.js decorators for Guardrail
 * @module adapters/nestjs/decorators
 */

import { SetMetadata, createParamDecorator, type ExecutionContext } from "@nestjs/common";
import { resolveValue } from "../../utils/resolver";
import { buildQuotaRules } from "../../utils/quota-builder";
import type {
  GuardrailRule,
  SlidingWindowConfig,
  TokenBucketConfig,
  BotDetectionConfig,
  EmailValidationConfig,
  ShieldConfig,
  FilterConfig,
  ProtectOptions,
  DecisionContext,
  QuotaConfig,
} from "../../types/index";
import { window, bucket, bot, email, shield, filter } from "../../rules/index";

/**
 * Metadata key for guardrail rules
 */
export const GUARDRAIL_RULES = "guardrail:rules";

/**
 * Metadata key for guardrail options
 */
export const GUARDRAIL_OPTIONS = "guardrail:options";

/**
 * Metadata key for skipping guardrail
 */
export const SKIP_GUARDRAIL = "guardrail:skip";

/**
 * Metadata key for guardrail preset
 */
export const GUARDRAIL_PRESET = "guardrail:preset";

/**
 * Generic decorator to add one or more guardrail rules to a route.
 * This decorator is additive, meaning it can be used multiple times on the same method or class.
 */
export const UseGuardrail = (...rules: GuardrailRule[]) => {
  return (target: any, key?: string | symbol, _descriptor?: TypedPropertyDescriptor<any>) => {
    const decoratorTarget = key ? target[key] : target;
    const existingRules = Reflect.getMetadata(GUARDRAIL_RULES, decoratorTarget) || [];
    Reflect.defineMetadata(GUARDRAIL_RULES, [...existingRules, ...rules], decoratorTarget);
  };
};

/**
 * Decorator to set guardrail protection options (userId, email, etc.)
 */
export const GuardrailOptions = (options: ProtectOptions) =>
  SetMetadata(GUARDRAIL_OPTIONS, options);

/**
 * Decorator to skip all guardrail checks for a route
 */
export const SkipGuardrail = () => SetMetadata(SKIP_GUARDRAIL, true);

/**
 * Decorator to apply a named preset
 */
export const Preset = (
  name: "api" | "web" | "strict" | "ai" | "payment" | "auth" | "development"
) => SetMetadata(GUARDRAIL_PRESET, name);

/**
 * Decorator for rate limiting using sliding window
 */
export const Limit = (
  config: Omit<SlidingWindowConfig, "type" | "mode"> & { mode?: SlidingWindowConfig["mode"] }
) => {
  return UseGuardrail(window(config));
};

/**
 * Decorator for rate limiting using token bucket
 */
export const TokenBucket = (
  config: Omit<TokenBucketConfig, "type" | "mode"> & { mode?: TokenBucketConfig["mode"] }
) => {
  return UseGuardrail(bucket(config));
};

/**
 * Decorator for bot detection
 */
export const Bot = (
  config: Omit<BotDetectionConfig, "type" | "mode"> & { mode?: BotDetectionConfig["mode"] }
) => {
  return UseGuardrail(bot(config));
};

/**
 * Decorator for email validation
 */
export const Email = (
  config: Omit<EmailValidationConfig, "type" | "mode"> & { mode?: EmailValidationConfig["mode"] }
) => {
  return UseGuardrail(email(config));
};

/**
 * Decorator for shield attack protection
 */
export const Shield = (
  config?: Omit<ShieldConfig, "type" | "mode"> & { mode?: ShieldConfig["mode"] }
) => {
  return UseGuardrail(shield(config));
};

/**
 * Decorator for filter rules
 */
export const Filter = (
  config: Omit<FilterConfig, "type" | "mode"> & { mode?: FilterConfig["mode"] }
) => {
  return UseGuardrail(filter(config));
};

/**
 * Shortcut decorator for blocking VPN/Proxy
 */
export const BlockVPN = () => Filter({ deny: ["ip.src.vpn == true", "ip.src.proxy == true"] });

/**
 * Shortcut decorator for blocking specific countries
 */
export const BlockCountry = (countries: string[]) =>
  Filter({ deny: countries.map((c) => `ip.src.country == "${c}"`) });

/**
 * Shortcut decorator for whitelisting IPs
 */
export const WhitelistIPs = (ips: string[]) =>
  Filter({ allow: ips.map((ip) => `ip.src == "${ip}"`) });

/**
 * High-level decorator for managing user quotas and subscriptions.
 * Automatically tracks by userId and supports stacked limits.
 */
export const Quota = (config: QuotaConfig) => {
  return UseGuardrail(...buildQuotaRules(config));
};

/**
 * Parameter decorator to inject the Guardrail decision
 */
export const Result = createParamDecorator((_data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.guardrail;
});

/**
 * Parameter decorator to inject IP info
 */
export const IPInfo = createParamDecorator((_data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.guardrail?.ip;
});

/**
 * Parameter decorator to inject requested tokens
 */
export const Tokens = createParamDecorator((_data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.guardrail?.characteristics?.requested;
});

/**
 * Utility to define limits based on common tiers
 * @param tiers - Mapping of tier names to limits
 * @param metadataPath - Path in options to find the tier (default: 'metadata.tier' or 'tier')
 */
export function byTier(
  tiers: Record<string, number>,
  metadataPath: string = "tier"
): (context: DecisionContext) => Promise<number> {
  return async (context: DecisionContext) => {
    // 1. Try specified path
    const tier = await resolveValue<string>(metadataPath, context, "free");
    return tiers[tier] ?? tiers["free"] ?? 0;
  };
}

// Re-export resolveValue for custom resolvers
export { resolveValue };
