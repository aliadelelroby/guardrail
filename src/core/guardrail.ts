/**
 * Main Guardrail class that orchestrates all rules and protection mechanisms
 * @class Guardrail
 */

import type {
  GuardrailConfig,
  Decision,
  ProtectOptions,
  RuleResult,
  GuardrailRule,
  DenialReason,
  StorageAdapter,
  IPGeolocationService,
  ErrorHandlingMode,
  EvaluationStrategy,
  CustomRuleConfig,
} from "../types/index";
import type { CustomRule, CustomRuleFactory } from "../types/custom-rules";
import { MemoryStorage } from "../storage/memory";
import { IPGeolocation } from "../services/ip-geolocation";
import { VPNProxyDetection } from "../services/vpn-detection";
import { TokenBucketRule } from "../rules/token-bucket";
import { SlidingWindowRule } from "../rules/sliding-window";
import { BotDetectionRule } from "../rules/bot-detection";
import { EmailValidationRule } from "../rules/email-validation";
import { ShieldRule } from "../rules/shield";
import { FilterRule } from "../rules/filter";
import { extractIPFromRequest } from "../utils/fingerprint";
import { EnhancedIPInfo } from "../utils/ip-info";
import { DecisionReason, findRateLimitResult } from "../utils/decision-helpers";
import { randomUUID } from "crypto";
import type {
  AnyRuleEvaluator,
  TokenBucketEvaluator,
  SlidingWindowEvaluator,
  BotDetectionEvaluator,
  EmailValidationEvaluator,
  ShieldEvaluator,
  FilterEvaluator,
} from "../types/evaluators";
import { RuleEvaluationError, IPGeolocationError } from "../errors/index";
import { CircuitBreaker } from "../utils/circuit-breaker";
import { InMemoryMetricsCollector, type MetricsCollector } from "../utils/metrics";
import { ConsoleLogger, type Logger } from "../utils/logger";
import { GuardrailEventEmitter, type GuardrailEventUnion } from "../utils/events";
import { MiddlewareChain, type Middleware } from "../utils/middleware";

import { GuardrailPresets } from "./presets";
import { AtomicRedisStorage } from "../storage/redis-atomic";

import pc from "picocolors";

/**
 * Rule entry with its evaluator
 */
interface RuleEntry {
  rule: GuardrailRule;
  evaluator: AnyRuleEvaluator;
}

/**
 * Evaluation context
 */
interface EvaluationContext {
  request: Request;
  characteristics: Record<string, string | number | undefined>;
  enhancedIPInfo: import("../types/index").IPInfo;
  options: ProtectOptions;
}

/**
 * Main Guardrail class for request protection and rate limiting
 */
export class Guardrail {
  private readonly storage: StorageAdapter;
  private readonly ipService: IPGeolocationService;
  private readonly vpnDetector: VPNProxyDetection;
  private readonly rules: RuleEntry[] = [];
  private readonly errorHandling: ErrorHandlingMode;
  private readonly evaluationStrategy: EvaluationStrategy;
  private readonly debug: boolean;
  private readonly whitelist?: GuardrailConfig["whitelist"];
  private readonly blacklist?: GuardrailConfig["blacklist"];
  private readonly storageCircuitBreaker: CircuitBreaker;
  private readonly ipCircuitBreaker: CircuitBreaker;
  private readonly metrics: MetricsCollector;
  private readonly logger: Logger;
  private readonly events: GuardrailEventEmitter;
  private readonly middleware: MiddlewareChain;
  private readonly customRuleFactories: Map<string, CustomRuleFactory> = new Map();
  private readonly requestCache: Map<string, { decision: Decision; expires: number }> = new Map();

  /**
   * Generates standard security headers from a decision
   */
  static getSecurityHeaders(decision: Decision): Record<string, string> {
    const headers: Record<string, string> = {
      "X-Guardrail-Id": decision.id,
      "X-Guardrail-Conclusion": decision.conclusion,
    };

    const rateLimitResult = decision.results.find(
      (r) => (r.rule === "slidingWindow" || r.rule === "tokenBucket") && r.remaining !== undefined
    );

    if (rateLimitResult && rateLimitResult.remaining !== undefined) {
      headers["X-RateLimit-Remaining"] = rateLimitResult.remaining.toString();
      if (rateLimitResult.reset) {
        headers["X-RateLimit-Reset"] = Math.ceil(rateLimitResult.reset / 1000).toString();
      }
    }

    return headers;
  }

  /**
   * Creates a Web API Request from common framework request objects
   */
  static toWebRequest(req: {
    protocol?: string;
    headers?: Record<string, unknown>;
    get?: (name: string) => string | undefined;
    originalUrl?: string;
    url?: string;
    method?: string;
    body?: unknown;
    raw?: unknown;
  }): Request {
    // If it's already a Web Request, return it
    if (req instanceof Request) return req as unknown as Request;

    const actualReq = (req.raw || req) as {
      protocol?: string;
      headers?: Record<string, unknown>;
      get?: (name: string) => string | undefined;
      originalUrl?: string;
      url?: string;
      method?: string;
      body?: unknown;
    };

    // Handle Express/Connect/Nest/Fastify style requests
    const protocol = actualReq.protocol || "http";
    const host = actualReq.get?.("host") || (actualReq.headers?.host as string) || "localhost";
    const url = actualReq.originalUrl || actualReq.url || "/";
    const fullUrl = url.startsWith("http") ? url : `${protocol}://${host}${url}`;

    const headers: Record<string, string> = {};
    if (actualReq.headers) {
      if (actualReq.headers instanceof Headers) {
        actualReq.headers.forEach((value, key) => {
          headers[key] = value;
        });
      } else {
        for (const [key, value] of Object.entries(actualReq.headers)) {
          if (value !== undefined) {
            headers[key] = Array.isArray(value) ? value.join(", ") : (value as string);
          }
        }
      }
    }

    return new Request(fullUrl, {
      method: actualReq.method || "GET",
      headers,
      body:
        actualReq.method !== "GET" && actualReq.method !== "HEAD" && actualReq.body
          ? typeof actualReq.body === "string"
            ? actualReq.body
            : JSON.stringify(actualReq.body)
          : undefined,
    });
  }

  /**
   * Creates a new Guardrail instance
   * @param config - Guardrail configuration
   */
  constructor(config: Partial<GuardrailConfig> = {}) {
    const finalConfig = this.resolveConfig(config);

    this.storage = finalConfig.storage ?? this.autoDiscoverStorage() ?? new MemoryStorage();
    this.ipService = finalConfig.ipService ?? new IPGeolocation();
    this.vpnDetector = new VPNProxyDetection();
    this.errorHandling = finalConfig.errorHandling ?? "FAIL_OPEN";
    this.evaluationStrategy = finalConfig.evaluationStrategy ?? "SEQUENTIAL";
    this.debug = finalConfig.debug ?? false;
    this.whitelist = finalConfig.whitelist;
    this.blacklist = finalConfig.blacklist;

    this.storageCircuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      resetTimeout: 30000,
    });

    this.ipCircuitBreaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeout: 60000,
    });

    this.metrics = this.debug
      ? new InMemoryMetricsCollector()
      : new (class {
          increment() {}
          gauge() {}
          histogram() {}
          getMetrics() {
            return [];
          }
          reset() {}
        })();

    this.logger = new ConsoleLogger(this.debug);
    this.events = new GuardrailEventEmitter();
    this.middleware = new MiddlewareChain();

    for (const rule of finalConfig.rules) {
      this.addRule(rule);
    }
  }

  /**
   * Resolves configuration with zero-config defaults
   */
  private resolveConfig(config: Partial<GuardrailConfig>): GuardrailConfig {
    if (!config.rules || config.rules.length === 0) {
      return {
        ...GuardrailPresets.api(),
        ...config,
      } as GuardrailConfig;
    }
    return config as GuardrailConfig;
  }

  /**
   * Automatically discovers storage based on environment variables
   */
  private autoDiscoverStorage(): StorageAdapter | undefined {
    // Check for common Redis environment variables
    const redisUrl =
      process?.env?.REDIS_URL || process?.env?.UPSTASH_REDIS_REST_URL || process?.env?.REDIS_HOST;

    if (redisUrl) {
      try {
        return new AtomicRedisStorage({
          redis: redisUrl,
          keyPrefix: "guardrail:",
        });
      } catch (error) {
        console.warn("Failed to auto-initialize Redis storage:", error);
      }
    }
    return undefined;
  }

  /**
   * Checks the health of the guardrail instance and its dependencies
   */
  async checkHealth(): Promise<{
    status: "healthy" | "unhealthy";
    storage: "connected" | "disconnected" | "not_applicable";
    ipService: "operational" | "degraded" | "error";
  }> {
    let storageStatus: "connected" | "disconnected" | "not_applicable" = "not_applicable";
    if (this.storage instanceof AtomicRedisStorage) {
      storageStatus = this.storage.isConnected() ? "connected" : "disconnected";
    }

    let ipStatus: "operational" | "degraded" | "error" = "operational";
    try {
      await this.ipService.lookup("8.8.8.8");
    } catch {
      ipStatus = "error";
    }

    return {
      status: storageStatus === "disconnected" || ipStatus === "error" ? "unhealthy" : "healthy",
      storage: storageStatus,
      ipService: ipStatus,
    };
  }

  /**
   * Adds a middleware to the chain
   */
  use(middleware: Middleware): void {
    this.middleware.use(middleware);
  }

  /**
   * Registers an event handler
   */
  on(
    eventType: GuardrailEventUnion["type"],
    handler: (event: GuardrailEventUnion) => void | Promise<void>
  ): () => void {
    return this.events.on(eventType, handler);
  }

  /**
   * Registers a custom rule factory
   */
  registerCustomRule(type: string, factory: CustomRuleFactory): void {
    this.customRuleFactories.set(type, factory);
  }

  /**
   * Gets metrics collector
   */
  getMetrics(): MetricsCollector {
    return this.metrics;
  }

  /**
   * Adds a rule to the guardrail instance
   */
  private addRule(rule: GuardrailRule): void {
    const evaluator = this.createEvaluator(rule);
    this.rules.push({ rule, evaluator });
  }

  /**
   * Creates an evaluator for a given rule
   */
  private createEvaluator(rule: GuardrailRule): AnyRuleEvaluator {
    switch (rule.type) {
      case "tokenBucket":
        return new TokenBucketRule(rule, this.storage);
      case "slidingWindow":
        return new SlidingWindowRule(rule, this.storage);
      case "detectBot":
        return new BotDetectionRule(rule);
      case "validateEmail":
        return new EmailValidationRule(rule);
      case "shield":
        return new ShieldRule(rule);
      case "filter":
        return new FilterRule(rule);
      case "custom": {
        const customRule = rule as CustomRuleConfig;
        const factory = this.customRuleFactories.get(customRule.ruleType);
        if (!factory) {
          throw new Error(`Custom rule type '${customRule.ruleType}' not registered`);
        }
        return factory(customRule.config) as unknown as AnyRuleEvaluator;
      }
      default: {
        const _exhaustive: never = rule;
        throw new Error(`Unknown rule type: ${(_exhaustive as GuardrailRule).type}`);
      }
    }
  }

  /**
   * Checks whitelist/blacklist before evaluation
   */
  private checkLists(
    ip: string,
    userId?: string,
    email?: string,
    country?: string
  ): { allowed: boolean; reason?: string } {
    if (this.whitelist) {
      if (this.whitelist.ips?.includes(ip)) {
        return { allowed: true };
      }
      if (userId && this.whitelist.userIds?.includes(userId)) {
        return { allowed: true };
      }
      if (country && this.whitelist.countries?.includes(country)) {
        return { allowed: true };
      }
      if (email) {
        const domain = email.split("@")[1];
        if (domain && this.whitelist.emailDomains?.includes(domain)) {
          return { allowed: true };
        }
      }
    }

    if (this.blacklist) {
      if (this.blacklist.ips?.includes(ip)) {
        return { allowed: false, reason: "IP blacklisted" };
      }
      if (userId && this.blacklist.userIds?.includes(userId)) {
        return { allowed: false, reason: "User blacklisted" };
      }
      if (country && this.blacklist.countries?.includes(country)) {
        return { allowed: false, reason: "Country blacklisted" };
      }
      if (email) {
        const domain = email.split("@")[1];
        if (domain && this.blacklist.emailDomains?.includes(domain)) {
          return { allowed: false, reason: "Email domain blacklisted" };
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Evaluates all rules against a request
   */
  async protect(request: Request, options: ProtectOptions = {}): Promise<Decision> {
    const startTime = Date.now();
    const decisionId = randomUUID();
    this.metrics.increment("guardrail.requests.total");

    const cacheKey = this.getCacheKey(request, options);
    if (cacheKey) {
      const cached = this.requestCache.get(cacheKey);
      if (cached && cached.expires > Date.now()) {
        this.metrics.increment("guardrail.requests.cached");
        return cached.decision;
      }
    }

    try {
      const ip = extractIPFromRequest(request);
      let ipInfo: import("../types/index").IPInfo;

      try {
        ipInfo = await this.ipCircuitBreaker.execute(
          () => this.ipService.lookup(ip),
          "ip-geolocation"
        );
        this.metrics.increment("guardrail.ip_lookup.success");
      } catch (error) {
        this.metrics.increment("guardrail.ip_lookup.error");
        this.logger.error(`IP lookup failed for ${ip}:`, error);
        await this.events.emit({
          type: "ip-lookup.error",
          timestamp: Date.now(),
          decisionId,
          error: error instanceof Error ? error : new Error(String(error)),
          context: { ip },
        });

        if (this.errorHandling === "FAIL_CLOSED") {
          throw new IPGeolocationError(`IP lookup failed for ${ip}`, ip, error as Error);
        }

        ipInfo = {};
      }

      const enhancedIPInfo = this.vpnDetector.detect(ipInfo);

      const listCheck = this.checkLists(ip, options.userId, options.email, ipInfo.country);

      if (!listCheck.allowed) {
        this.metrics.increment("guardrail.decisions.denied", { reason: "blacklist" });
        return this.createDenyDecision(decisionId, "FILTER", ipInfo, {
          "ip.src": ip,
          userId: options.userId,
          email: options.email,
          ...options,
        });
      }

      if (listCheck.allowed && this.whitelist) {
        this.metrics.increment("guardrail.decisions.allowed", { reason: "whitelist" });
        return this.createAllowDecision(decisionId, ipInfo, {
          "ip.src": ip,
          userId: options.userId,
          email: options.email,
          ...options,
        });
      }

      const characteristics: Record<string, string | number | undefined> = {
        "ip.src": ip,
        userId: options.userId,
        email: options.email,
        ...options,
      };

      const context: EvaluationContext = {
        request,
        characteristics,
        enhancedIPInfo,
        options,
      };

      await this.middleware.execute({ request, options });

      const results = await this.evaluateRules(context);
      const conclusion = this.determineConclusion(results);
      const denialReason = this.getDenialReason(results);

      const enhancedIP = new EnhancedIPInfo(enhancedIPInfo);
      const rateLimitResult = findRateLimitResult(results);
      const reason = new DecisionReason(denialReason, rateLimitResult);

      const decision = this.createDecision({
        id: decisionId,
        conclusion,
        reason,
        results,
        ip: enhancedIP,
        characteristics,
      });

      const duration = Date.now() - startTime;
      this.metrics.histogram("guardrail.request.duration", duration);

      const summary = `${conclusion === "ALLOW" ? pc.green("PASS") : pc.red("BLOCK")} ${pc.bold(
        request.method
      )} ${new URL(request.url).pathname} - ${pc.gray(decisionId)} (${duration}ms)${
        conclusion === "DENY" ? ` - Reason: ${pc.yellow(denialReason || "unknown")}` : ""
      }`;
      this.logger.info(summary);

      this.metrics.increment(
        `guardrail.decisions.${conclusion.toLowerCase()}`,
        conclusion === "DENY" ? { reason: denialReason || "unknown" } : {}
      );

      await this.events.emit({
        type: conclusion === "ALLOW" ? "decision.allowed" : "decision.denied",
        timestamp: Date.now(),
        decisionId,
        decision,
      });

      this.logger.debug(`Decision ${conclusion} for request ${decisionId}`, {
        duration,
        results: results.length,
      });

      if (cacheKey) {
        this.requestCache.set(cacheKey, {
          decision,
          expires: Date.now() + 1000,
        });
        setTimeout(() => {
          if (cacheKey) {
            this.requestCache.delete(cacheKey);
          }
        }, 2000);
      }

      return decision;
    } catch (error) {
      this.metrics.increment("guardrail.errors.total");
      const duration = Date.now() - startTime;
      this.logger.error(`Request failed after ${duration}ms:`, error);

      if (this.errorHandling === "FAIL_CLOSED") {
        throw error;
      }

      this.logger.error(`Error in protect:`, error);
      return this.createAllowDecision(
        decisionId,
        {},
        {
          "ip.src": extractIPFromRequest(request),
          ...options,
        }
      );
    }
  }

  /**
   * Evaluates all rules based on strategy
   */
  private async evaluateRules(context: EvaluationContext): Promise<RuleResult[]> {
    if (this.evaluationStrategy === "PARALLEL") {
      return this.evaluateRulesParallel(context);
    } else if (this.evaluationStrategy === "SHORT_CIRCUIT") {
      return this.evaluateRulesShortCircuit(context);
    } else {
      return this.evaluateRulesSequential(context);
    }
  }

  /**
   * Sequential evaluation (default)
   */
  private async evaluateRulesSequential(context: EvaluationContext): Promise<RuleResult[]> {
    const results: RuleResult[] = [];

    for (const { rule, evaluator } of this.rules) {
      await this.events.emit({
        type: "rule.evaluate",
        timestamp: Date.now(),
        ruleType: rule.type,
      });

      const result = await this.evaluateRule(rule, evaluator, context);
      results.push(result);

      await this.events.emit({
        type: result.conclusion === "ALLOW" ? "rule.allow" : "rule.deny",
        timestamp: Date.now(),
        ruleType: rule.type,
        result,
      });
    }

    return results;
  }

  /**
   * Parallel evaluation
   */
  private async evaluateRulesParallel(context: EvaluationContext): Promise<RuleResult[]> {
    const evaluations = this.rules.map(async ({ rule, evaluator }) => {
      await this.events.emit({
        type: "rule.evaluate",
        timestamp: Date.now(),
        ruleType: rule.type,
      });

      const result = await this.evaluateRule(rule, evaluator, context);

      await this.events.emit({
        type: result.conclusion === "ALLOW" ? "rule.allow" : "rule.deny",
        timestamp: Date.now(),
        ruleType: rule.type,
        result,
      });

      return result;
    });

    return Promise.all(evaluations);
  }

  /**
   * Short-circuit evaluation (stops on first DENY)
   */
  private async evaluateRulesShortCircuit(context: EvaluationContext): Promise<RuleResult[]> {
    const results: RuleResult[] = [];

    for (const { rule, evaluator } of this.rules) {
      await this.events.emit({
        type: "rule.evaluate",
        timestamp: Date.now(),
        ruleType: rule.type,
      });

      const result = await this.evaluateRule(rule, evaluator, context);
      results.push(result);

      await this.events.emit({
        type: result.conclusion === "ALLOW" ? "rule.allow" : "rule.deny",
        timestamp: Date.now(),
        ruleType: rule.type,
        result,
      });

      if (result.conclusion === "DENY") {
        break;
      }
    }

    return results;
  }

  /**
   * Determines final conclusion from results
   */
  private determineConclusion(results: RuleResult[]): "ALLOW" | "DENY" {
    return results.some((r) => r.conclusion === "DENY") ? "DENY" : "ALLOW";
  }

  /**
   * Gets denial reason from results
   */
  private getDenialReason(results: RuleResult[]): DenialReason | undefined {
    const denied = results.find((r) => r.conclusion === "DENY");
    return denied?.reason;
  }

  /**
   * Evaluates a single rule
   */
  private async evaluateRule(
    rule: GuardrailRule,
    evaluator: AnyRuleEvaluator,
    context: EvaluationContext
  ): Promise<RuleResult> {
    const startTime = Date.now();

    try {
      let result: RuleResult;

      switch (rule.type) {
        case "tokenBucket": {
          const tokenEvaluator = evaluator as TokenBucketEvaluator;
          result = await this.storageCircuitBreaker.execute(
            () => tokenEvaluator.evaluate(context.characteristics, context.options.requested),
            "storage"
          );
          break;
        }
        case "slidingWindow": {
          const slidingEvaluator = evaluator as SlidingWindowEvaluator;
          result = await this.storageCircuitBreaker.execute(
            () => slidingEvaluator.evaluate(context.characteristics),
            "storage"
          );
          break;
        }
        case "detectBot": {
          const botEvaluator = evaluator as BotDetectionEvaluator;
          result = await botEvaluator.evaluate(context.request);
          break;
        }
        case "validateEmail": {
          if (context.options.email) {
            const emailEvaluator = evaluator as EmailValidationEvaluator;
            result = await emailEvaluator.evaluate(context.options.email);
          } else {
            result = {
              rule: "validateEmail",
              conclusion: "ALLOW",
            };
          }
          break;
        }
        case "shield": {
          const shieldEvaluator = evaluator as ShieldEvaluator;
          result = await shieldEvaluator.evaluate(context.request);
          break;
        }
        case "filter": {
          const filterEvaluator = evaluator as FilterEvaluator;
          result = await filterEvaluator.evaluate(
            context.request,
            context.enhancedIPInfo,
            context.characteristics
          );
          break;
        }
        case "custom": {
          const customRule = evaluator as unknown as CustomRule;
          const ip = extractIPFromRequest(context.request);
          result = await customRule.evaluate({
            request: context.request,
            ip,
            ipInfo: context.enhancedIPInfo,
            characteristics: context.characteristics,
            options: context.options,
          });
          break;
        }
        default: {
          const _exhaustive: never = rule;
          result = {
            rule: (_exhaustive as GuardrailRule).type,
            conclusion: "ALLOW",
          };
        }
      }

      const duration = Date.now() - startTime;
      this.metrics.histogram(`guardrail.rule.${rule.type}.duration`, duration);

      return result;
    } catch (error) {
      this.metrics.increment(`guardrail.rule.${rule.type}.error`);
      this.logger.error(`Error evaluating rule ${rule.type}:`, error);

      await this.events.emit({
        type: "storage.error",
        timestamp: Date.now(),
        error: error instanceof Error ? error : new Error(String(error)),
        context: { ruleType: rule.type },
      });

      if (this.errorHandling === "FAIL_CLOSED") {
        throw new RuleEvaluationError(
          `Rule evaluation failed: ${rule.type}`,
          rule.type,
          error as Error
        );
      }

      return {
        rule: rule.type,
        conclusion: "ALLOW",
      };
    }
  }

  /**
   * Creates an allow decision
   */
  private createAllowDecision(
    id: string,
    ipInfo: import("../types/index").IPInfo,
    characteristics: Record<string, string | number | undefined>
  ): Decision {
    const enhancedIP = new EnhancedIPInfo(ipInfo);
    const reason = new DecisionReason(undefined, undefined);

    return this.createDecision({
      id,
      conclusion: "ALLOW",
      reason,
      results: [],
      ip: enhancedIP,
      characteristics,
    });
  }

  /**
   * Creates a deny decision
   */
  private createDenyDecision(
    id: string,
    reasonType: DenialReason,
    ipInfo: import("../types/index").IPInfo,
    characteristics: Record<string, string | number | undefined>
  ): Decision {
    const enhancedIP = new EnhancedIPInfo(ipInfo);
    const reason = new DecisionReason(reasonType, undefined);

    return this.createDecision({
      id,
      conclusion: "DENY",
      reason,
      results: [
        {
          rule: "filter",
          conclusion: "DENY",
          reason: reasonType,
        },
      ],
      ip: enhancedIP,
      characteristics,
    });
  }

  /**
   * Generates cache key for request deduplication
   */
  private getCacheKey(request: Request, options: ProtectOptions): string | null {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return null;
    }
    const ip = extractIPFromRequest(request);
    const userId = options.userId || "";
    return `${request.url}:${ip}:${userId}`;
  }

  /**
   * Creates a decision object
   */
  private createDecision(data: {
    id: string;
    conclusion: "ALLOW" | "DENY";
    reason: DecisionReason;
    results: RuleResult[];
    ip: EnhancedIPInfo;
    characteristics: Record<string, string | number | undefined>;
  }): Decision {
    return {
      ...data,
      isAllowed(): boolean {
        return this.conclusion === "ALLOW";
      },
      isDenied(): boolean {
        return this.conclusion === "DENY";
      },
    };
  }
}
