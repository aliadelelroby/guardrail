/**
 * Nest.js decorators for Guardrail
 * @module adapters/nestjs/decorators
 */

import { SetMetadata, createParamDecorator, ExecutionContext } from "@nestjs/common";
import type {
  GuardrailRule,
  SlidingWindowConfig,
  TokenBucketConfig,
  BotDetectionConfig,
  EmailValidationConfig,
  ShieldConfig,
  FilterConfig,
  ProtectOptions,
} from "../../types/index";
import {
  slidingWindow,
  tokenBucket,
  detectBot,
  validateEmail,
  shield,
  filter,
} from "../../rules/index";

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
 * Generic decorator to add one or more guardrail rules to a route
 */
export const UseGuardrail = (...rules: GuardrailRule[]) => SetMetadata(GUARDRAIL_RULES, rules);

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
export const GuardrailPreset = (
  name: "api" | "web" | "strict" | "ai" | "payment" | "auth" | "development"
) => SetMetadata(GUARDRAIL_PRESET, name);

/**
 * Decorator for rate limiting using sliding window
 */
export const RateLimit = (
  config: Omit<SlidingWindowConfig, "type" | "mode"> & { mode?: SlidingWindowConfig["mode"] }
) => {
  return UseGuardrail(slidingWindow(config));
};

/**
 * Decorator for rate limiting using token bucket
 */
export const TokenBucket = (
  config: Omit<TokenBucketConfig, "type" | "mode"> & { mode?: TokenBucketConfig["mode"] }
) => {
  return UseGuardrail(tokenBucket(config));
};

/**
 * Decorator for bot detection
 */
export const DetectBot = (
  config: Omit<BotDetectionConfig, "type" | "mode"> & { mode?: BotDetectionConfig["mode"] }
) => {
  return UseGuardrail(detectBot(config));
};

/**
 * Decorator for email validation
 */
export const ValidateEmail = (
  config: Omit<EmailValidationConfig, "type" | "mode"> & { mode?: EmailValidationConfig["mode"] }
) => {
  return UseGuardrail(validateEmail(config));
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
export const GuardrailVPNBlock = () =>
  Filter({ deny: ["ip.src.vpn == true", "ip.src.proxy == true"] });

/**
 * Shortcut decorator for blocking specific countries
 */
export const GuardrailCountryBlock = (countries: string[]) =>
  Filter({ deny: countries.map((c) => `ip.src.country == "${c}"`) });

/**
 * Shortcut decorator for whitelisting IPs
 */
export const WhitelistIPs = (ips: string[]) =>
  Filter({ allow: ips.map((ip) => `ip.src == "${ip}"`) });

/**
 * Parameter decorator to inject the Guardrail decision
 */
export const Decision = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.guardrail;
});

/**
 * Parameter decorator to inject IP info
 */
export const IPInfo = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.guardrail?.ip;
});

/**
 * Parameter decorator to inject requested tokens
 */
export const RequestedTokens = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.guardrail?.characteristics?.requested;
});
