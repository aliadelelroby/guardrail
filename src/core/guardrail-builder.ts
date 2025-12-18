/**
 * Fluent builder pattern for Guardrail configuration
 * @module core/guardrail-builder
 */

import type {
  GuardrailConfig,
  GuardrailRule,
  StorageAdapter,
  IPGeolocationService,
  WhitelistConfig,
  BlacklistConfig,
} from "../types/index";
import {
  shield,
  detectBot,
  slidingWindow,
  tokenBucket,
  validateEmail,
  filter,
} from "../rules/index";

/**
 * Fluent builder for Guardrail configuration
 */
export class GuardrailBuilder {
  private rules: GuardrailRule[] = [];
  private config: Partial<GuardrailConfig> = {};

  /**
   * Sets the default mode for rules
   */
  mode(mode: GuardrailConfig["mode"]): this {
    this.config.mode = mode;
    return this;
  }

  /**
   * Adds a shield rule
   */
  shield(config?: Parameters<typeof shield>[0]): this {
    this.rules.push(shield(config));
    return this;
  }

  /**
   * Adds a bot detection rule
   */
  detectBot(config?: Parameters<typeof detectBot>[0]): this {
    this.rules.push(detectBot(config));
    return this;
  }

  /**
   * Adds a sliding window rate limit rule
   */
  slidingWindow(config: Parameters<typeof slidingWindow>[0]): this {
    this.rules.push(slidingWindow(config));
    return this;
  }

  /**
   * Adds a token bucket rate limit rule
   */
  tokenBucket(config: Parameters<typeof tokenBucket>[0]): this {
    this.rules.push(tokenBucket(config));
    return this;
  }

  /**
   * Adds an email validation rule
   */
  validateEmail(config: Parameters<typeof validateEmail>[0]): this {
    this.rules.push(validateEmail(config));
    return this;
  }

  /**
   * Adds a filter rule
   */
  filter(config: Parameters<typeof filter>[0]): this {
    this.rules.push(filter(config));
    return this;
  }

  /**
   * Sets the storage adapter
   */
  storage(storage: StorageAdapter): this {
    this.config.storage = storage;
    return this;
  }

  /**
   * Sets the IP geolocation service
   */
  ipService(service: IPGeolocationService): this {
    this.config.ipService = service;
    return this;
  }

  /**
   * Sets error handling mode
   */
  errorHandling(mode: GuardrailConfig["errorHandling"]): this {
    this.config.errorHandling = mode;
    return this;
  }

  /**
   * Sets evaluation strategy
   */
  evaluationStrategy(strategy: GuardrailConfig["evaluationStrategy"]): this {
    this.config.evaluationStrategy = strategy;
    return this;
  }

  /**
   * Enables debug mode
   */
  debug(enabled: boolean = true): this {
    this.config.debug = enabled;
    return this;
  }

  /**
   * Sets whitelist configuration
   */
  whitelist(config: WhitelistConfig): this {
    this.config.whitelist = config;
    return this;
  }

  /**
   * Sets blacklist configuration
   */
  blacklist(config: BlacklistConfig): this {
    this.config.blacklist = config;
    return this;
  }

  /**
   * Adds a custom rule
   */
  rule(rule: GuardrailRule): this {
    this.rules.push(rule);
    return this;
  }

  /**
   * Builds the final Guardrail configuration
   */
  build(): GuardrailConfig {
    if (this.rules.length === 0) {
      throw new Error("At least one rule must be configured");
    }

    return {
      ...this.config,
      rules: this.rules,
    } as GuardrailConfig;
  }
}

/**
 * Creates a new Guardrail builder
 */
export function createGuardrailBuilder(): GuardrailBuilder {
  return new GuardrailBuilder();
}
