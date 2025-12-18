/**
 * Nest.js Guard for Guardrail protection
 * @module adapters/nestjs
 */

import {
  Injectable,
  Optional,
  type CanActivate,
  type ExecutionContext,
  Logger,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { LRUCache } from "lru-cache";
import { Guardrail } from "../../core/guardrail";
import { GuardrailPresets } from "../../core/presets";
import type { ProtectOptions, GuardrailRule, Decision } from "../../types/index";
import type { NestRequest, NestResponse } from "./types";
import { GUARDRAIL_OPTIONS, GUARDRAIL_RULES, SKIP_GUARDRAIL, GUARDRAIL_PRESET } from "./decorators";
import { GuardrailModuleOptions } from "./guardrail.module";

import { resolveProtectOptions, formatDenialResponse } from "../../utils/adapter-utils";

/**
 * Guardrail guard for Nest.js
 */
@Injectable()
export class GuardrailGuard implements CanActivate {
  private static readonly logger = new Logger(GuardrailGuard.name);
  private static readonly instanceCache = new LRUCache<string, Guardrail>({
    max: 100, // Maximum 100 cached instances
    ttl: 1000 * 60 * 60, // 1 hour TTL
    // Cleanup callback to prevent memory leaks - call destroy() when instances are evicted
    dispose: (value) => {
      try {
        value.destroy();
      } catch (error) {
        // Log but don't throw - cleanup errors shouldn't break the application
        GuardrailGuard.logger.warn("Error cleaning up Guardrail instance", error);
      }
    },
  });

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

    const options = resolveProtectOptions(request, this.moduleOptions || {}, decoratorOptions);

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
      finalRules = [...(preset.rules || [])];
    } else if (methodRules.length > 0 || classRules.length > 0) {
      finalRules = [...classRules, ...methodRules];
    } else if (this.moduleOptions?.autoProtect) {
      finalRules = [...(GuardrailPresets.api().rules || [])];
    }

    const webRequest = this.createWebRequest(request);

    let decision: Decision;
    if (finalRules.length > 0) {
      // Use cached instance if rules are the same
      const rulesKey = JSON.stringify(finalRules);
      let tempGuardrail = GuardrailGuard.instanceCache.get(rulesKey);

      if (!tempGuardrail) {
        tempGuardrail = new Guardrail({
          ...this.moduleOptions,
          storage: this.guardrail.getStorage(),
          ipService: this.guardrail.getIPService(),
          rules: finalRules,
        });
        GuardrailGuard.instanceCache.set(rulesKey, tempGuardrail);
      }

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
      if (response.set) {
        response.set(name, value);
      } else if (response.header) {
        response.header(name, value);
      }
    };

    const headers = Guardrail.getSecurityHeaders(decision);
    for (const [name, value] of Object.entries(headers)) {
      setHeader(name, value);
    }
  }

  /**
   * Handles request denial with appropriate status and message
   */
  private handleDenial(response: NestResponse, decision: Decision): void {
    const { status, body } = formatDenialResponse(decision);
    response.status(status).json(body);
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
