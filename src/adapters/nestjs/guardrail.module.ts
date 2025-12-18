/**
 * Nest.js Module for Guardrail
 * @module adapters/nestjs
 */

import type { DynamicModule, FactoryProvider } from "@nestjs/common";
import { Global, Module } from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR, Reflector } from "@nestjs/core";
import { Guardrail } from "../../core/guardrail";
import type { GuardrailConfig } from "../../types/index";
import { GuardrailGuard } from "./guardrail.guard";
import { GuardrailInterceptor } from "./guardrail.interceptor";

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
   * Automatically protect all routes with the 'api' preset if no decorators are present.
   * Default: false
   */
  autoProtect?: boolean;
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
      userExtractor,
      emailExtractor,
      ...guardrailConfig
    } = options;

    const providers: Array<FactoryProvider<unknown>> = [
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

    return {
      module: GuardrailModule,
      providers,
      exports: [Guardrail],
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
        const { useGuard: _useGuard, useInterceptor: _useInterceptor, ...guardrailConfig } = config;
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
