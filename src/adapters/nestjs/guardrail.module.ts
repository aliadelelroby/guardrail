/**
 * Nest.js Module for Guardrail
 * @module adapters/nestjs
 */

import {
  Global,
  Module,
  type DynamicModule,
  type Provider,
  type FactoryProvider,
} from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR, Reflector, HttpAdapterHost } from "@nestjs/core";
import { Guardrail } from "../../core/guardrail";
import type { GuardrailConfig } from "../../types/index";
import { GuardrailGuard } from "./guardrail.guard";
import { GuardrailInterceptor } from "./guardrail.interceptor";
import { RouteProtectionLogger } from "./route-protection-logger";

/**
 * Guardrail module configuration
 */
export interface GuardrailModuleOptions extends GuardrailConfig {
  /**
   * Use guardrail as a global guard
   */
  useGuard?: boolean;

  /**
   * Use guardrail as a global interceptor
   */
  useInterceptor?: boolean;

  /**
   * Global user extractor for NestJS requests
   */
  userExtractor?: (request: any) => string | undefined;

  /**
   * Global email extractor for NestJS requests
   */
  emailExtractor?: (request: any) => string | undefined;

  /**
   * Global tokens/units extractor for NestJS requests (for token bucket)
   */
  tokensExtractor?: (request: any) => number | undefined;

  /**
   * Global metadata extractor for NestJS requests
   */
  metadataExtractor?: (request: any) => Record<string, any> | undefined;

  /**
   * Automatically protect all routes with the 'api' preset if no decorators are present.
   * Default: false
   */
  autoProtect?: boolean;

  /**
   * Automatically allow localhost/private IPs in development mode.
   * When true, automatically whitelists 127.0.0.1, ::1, and localhost.
   * Default: true if NODE_ENV !== "production", false otherwise
   */
  allowPrivateIPs?: boolean;

  /**
   * Show route protection details during application startup.
   * When enabled, logs which routes are protected, skipped, or unprotected.
   * Default: true if debug mode is enabled, false otherwise
   */
  showRouteProtection?: boolean;
}

/**
 * Guardrail module for Nest.js
 */
@Global()
@Module({})
export class GuardrailModule {
  /**
   * Creates a dynamic module with Guardrail configuration
   * @param options - Guardrail module options
   */
  static forRoot(options: GuardrailModuleOptions): DynamicModule {
    const {
      useGuard = false,
      useInterceptor = false,
      userExtractor: _userExtractor,
      emailExtractor: _emailExtractor,
      allowPrivateIPs = process.env.NODE_ENV !== "production",
      ...guardrailConfig
    } = options;

    // Auto-whitelist localhost/private IPs in development mode
    if (allowPrivateIPs) {
      const localhostIPs = ["127.0.0.1", "::1", "localhost"];
      const existingWhitelist = guardrailConfig.whitelist?.ips || [];
      const mergedWhitelist = [...new Set([...localhostIPs, ...existingWhitelist])];

      guardrailConfig.whitelist = {
        ...guardrailConfig.whitelist,
        ips: mergedWhitelist,
      };
    }

    const providers: Provider[] = [
      {
        provide: Guardrail,
        useFactory: (): Guardrail => new Guardrail(guardrailConfig),
        inject: [],
      },
      {
        provide: "GUARDRAIL_MODULE_OPTIONS",
        useValue: options,
      },
      {
        provide: Reflector,
        useFactory: (): Reflector => new Reflector(),
        inject: [],
      },
    ];

    if (useGuard) {
      providers.push({
        provide: APP_GUARD,
        useFactory: (guardrail: Guardrail, reflector: Reflector): GuardrailGuard =>
          new GuardrailGuard(guardrail, reflector, options),
        inject: [Guardrail, Reflector],
      });
    }

    if (useInterceptor) {
      providers.push({
        provide: APP_INTERCEPTOR,
        useFactory: (guardrail: Guardrail, reflector: Reflector): GuardrailInterceptor =>
          new GuardrailInterceptor(guardrail, reflector),
        inject: [Guardrail, Reflector],
      });
    }

    // Add route protection logger if enabled
    if (options.showRouteProtection ?? options.debug) {
      providers.push({
        provide: RouteProtectionLogger,
        useFactory: (
          reflector: Reflector,
          httpAdapterHost: HttpAdapterHost
        ): RouteProtectionLogger => {
          return new RouteProtectionLogger(reflector, options, httpAdapterHost);
        },
        inject: [Reflector, HttpAdapterHost],
      });
    }

    return {
      module: GuardrailModule,
      providers,
      exports: [
        Guardrail,
        ...((options.showRouteProtection ?? options.debug) ? [RouteProtectionLogger] : []),
      ],
    };
  }

  /**
   * Creates a module for async configuration
   * @param options - Async module options
   */
  static forRootAsync(options: {
    useFactory: (...args: unknown[]) => Promise<GuardrailModuleOptions> | GuardrailModuleOptions;
    inject?: Array<string | symbol | (abstract new (...args: unknown[]) => unknown)>;
  }): DynamicModule {
    const guardrailProvider: FactoryProvider<Guardrail> = {
      provide: Guardrail,
      useFactory: async (...args: unknown[]): Promise<Guardrail> => {
        const config = await options.useFactory(...args);
        const {
          useGuard: _useGuard,
          useInterceptor: _useInterceptor,
          allowPrivateIPs = process.env.NODE_ENV !== "production",
          ...guardrailConfig
        } = config;

        // Auto-whitelist localhost/private IPs in development mode
        if (allowPrivateIPs) {
          const localhostIPs = ["127.0.0.1", "::1", "localhost"];
          const existingWhitelist = guardrailConfig.whitelist?.ips || [];
          const mergedWhitelist = [...new Set([...localhostIPs, ...existingWhitelist])];

          guardrailConfig.whitelist = {
            ...guardrailConfig.whitelist,
            ips: mergedWhitelist,
          };
        }

        return new Guardrail(guardrailConfig);
      },
      inject: options.inject || [],
    };

    const reflectorProvider: FactoryProvider<Reflector> = {
      provide: Reflector,
      useFactory: (): Reflector => new Reflector(),
      inject: [],
    };

    const providers: Array<FactoryProvider<unknown>> = [guardrailProvider, reflectorProvider];

    return {
      module: GuardrailModule,
      providers,
      exports: [Guardrail],
    };
  }
}
