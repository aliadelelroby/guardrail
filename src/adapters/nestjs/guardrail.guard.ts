/**
 * Nest.js Guard for Guardrail protection
 * @module adapters/nestjs
 */

import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { Injectable, Optional } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Guardrail } from "../../core/guardrail";
import { GuardrailPresets } from "../../core/presets";
import type { ProtectOptions, RuleResult, GuardrailRule, Decision } from "../../types/index";
import type { NestRequest, NestResponse } from "./types";
import { GUARDRAIL_OPTIONS, GUARDRAIL_RULES, SKIP_GUARDRAIL, GUARDRAIL_PRESET } from "./decorators";
import type { GuardrailModuleOptions } from "./guardrail.module";

/**
 * Guardrail guard for Nest.js
 */
@Injectable()
export class GuardrailGuard implements CanActivate {
  constructor(
    private readonly guardrail: Guardrail,
    private readonly reflector: Reflector,
    @Optional() private readonly moduleOptions?: GuardrailModuleOptions
  ) {}

  /**
   * Checks if the request can be activated
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. Check for SkipGuardrail
    const isSkipped =
      this.reflector.get<boolean>(SKIP_GUARDRAIL, context.getHandler()) ||
      this.reflector.get<boolean>(SKIP_GUARDRAIL, context.getClass());

    if (isSkipped) {
      return true;
    }

    const request = context.switchToHttp().getRequest<NestRequest>();
    const response = context.switchToHttp().getResponse<NestResponse>();

    // 2. Resolve Options
    const decoratorOptions =
      this.reflector.get<ProtectOptions>(GUARDRAIL_OPTIONS, context.getHandler()) ||
      this.reflector.get<ProtectOptions>(GUARDRAIL_OPTIONS, context.getClass()) ||
      {};

    const options: ProtectOptions = { ...decoratorOptions };
    if (!options.userId && this.moduleOptions?.userExtractor) {
      options.userId = this.moduleOptions.userExtractor(request);
    }
    if (!options.email && this.moduleOptions?.emailExtractor) {
      options.email = this.moduleOptions.emailExtractor(request);
    }

    // 3. Resolve Rules (Merging module, class, and method rules)
    const classRules =
      this.reflector.get<GuardrailRule[]>(GUARDRAIL_RULES, context.getClass()) || [];
    const methodRules =
      this.reflector.get<GuardrailRule[]>(GUARDRAIL_RULES, context.getHandler()) || [];
    const presetName =
      this.reflector.get<string>(GUARDRAIL_PRESET, context.getHandler()) ||
      this.reflector.get<string>(GUARDRAIL_PRESET, context.getClass());

    let finalRules: GuardrailRule[] = [];

    if (presetName && presetName in GuardrailPresets) {
      const preset = GuardrailPresets[presetName as keyof typeof GuardrailPresets]();
      finalRules = [...preset.rules];
    } else if (methodRules.length > 0 || classRules.length > 0) {
      // Merge rules: method rules override class rules of same type if needed,
      // but here we just concatenate for simplicity as Guardrail handles multiple rules.
      finalRules = [...classRules, ...methodRules];
    } else if (this.moduleOptions?.autoProtect) {
      // Auto-protect with API preset if no rules defined
      finalRules = [...GuardrailPresets.api().rules];
    }

    const webRequest = this.createWebRequest(request);

    let decision: Decision;
    if (finalRules.length > 0) {
      // Create a temporary instance for specific rules if they differ from global
      const tempGuardrail = new Guardrail({
        ...this.moduleOptions,
        rules: finalRules,
      });
      decision = await tempGuardrail.protect(webRequest, options);
    } else {
      decision = await this.guardrail.protect(webRequest, options);
    }

    (request as NestRequest & { guardrail?: typeof decision }).guardrail = decision;

    // 4. Set Headers
    this.setGuardrailHeaders(response, decision);

    // 5. Handle Denial
    if (decision.isDenied()) {
      this.handleDenial(response, decision);
      return false;
    }

    return true;
  }

  /**
   * Sets Guardrail headers on the response
   */
  private setGuardrailHeaders(response: NestResponse, decision: Decision): void {
    const setHeader = (name: string, value: string) => {
      if (response.set) response.set(name, value);
      else if (response.header) response.header(name, value);
    };

    setHeader("X-Guardrail-Id", decision.id);
    setHeader("X-Guardrail-Conclusion", decision.conclusion);

    const rateLimitResult = decision.results.find(
      (r) => (r.rule === "slidingWindow" || r.rule === "tokenBucket") && r.remaining !== undefined
    );

    if (rateLimitResult && rateLimitResult.remaining !== undefined) {
      setHeader("X-RateLimit-Remaining", rateLimitResult.remaining.toString());
      if (rateLimitResult.reset) {
        setHeader("X-RateLimit-Reset", Math.ceil(rateLimitResult.reset / 1000).toString());
      }
    }
  }

  /**
   * Handles request denial with appropriate status and message
   */
  private handleDenial(response: NestResponse, decision: Decision): void {
    if (decision.reason.isRateLimit() || decision.reason.isQuota()) {
      response.status(429).json({
        error: "Rate limit exceeded",
        message: "Too many requests. Please try again later.",
        remaining: decision.reason.getRemaining() ?? 0,
      });
    } else if (decision.reason.isBot()) {
      response.status(403).json({
        error: "Forbidden",
        message: "Automated access is restricted.",
      });
    } else if (decision.reason.isShield()) {
      response.status(403).json({
        error: "Forbidden",
        message: "Potential security threat detected.",
      });
    } else if (decision.reason.isFilter()) {
      // Check if it's VPN/Country block
      const filterResult = decision.results.find(
        (r) => r.rule === "filter" && r.conclusion === "DENY"
      );
      response.status(403).json({
        error: "Forbidden",
        message:
          filterResult?.reason === "FILTER"
            ? "Access restricted from your location or network."
            : "Request denied by filter policy.",
      });
    } else {
      response.status(403).json({
        error: "Forbidden",
        message: "Request denied by security policy.",
      });
    }
  }

  /**
   * Creates a Web API Request from Nest.js request
   */
  private createWebRequest(request: NestRequest): Request {
    const protocol = request.protocol || "http";
    const host =
      request.get?.("host") || (request.headers.host as string | undefined) || "localhost";
    const url = request.originalUrl || request.url || "/";
    const fullUrl = `${protocol}://${host}${url}`;

    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      if (value !== undefined) {
        headers[key] = Array.isArray(value) ? value.join(", ") : value;
      }
    }

    return new Request(fullUrl, {
      method: request.method,
      headers,
      body:
        request.method !== "GET" && request.method !== "HEAD"
          ? JSON.stringify(request.body)
          : undefined,
    });
  }
}
