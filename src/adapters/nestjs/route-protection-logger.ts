/**
 * Route Protection Logger for Guardrail
 * Scans and logs route protection information after application initialization
 * @module adapters/nestjs/route-protection-logger
 */

import { Injectable, type OnApplicationBootstrap, RequestMethod } from "@nestjs/common";
import { PATH_METADATA, METHOD_METADATA } from "@nestjs/common/constants";
import { Reflector, DiscoveryService, MetadataScanner } from "@nestjs/core";
import type { GuardrailModuleOptions } from "./guardrail.module";
import {
  getRouteProtectionInfo,
  logRouteProtection,
  type RouteProtectionInfo,
} from "./route-inspector";

/**
 * Service to log route protection information
 * This service scans all routes and logs their Guardrail protection status
 * automatically after the application has bootstrapped.
 *
 * No manual setup required - it works automatically when enabled via
 * `showRouteProtection` or `debug` options in GuardrailModule.
 */
@Injectable()
export class RouteProtectionLogger implements OnApplicationBootstrap {
  private static logged = false;

  constructor(
    private readonly reflector: Reflector,
    private readonly options: GuardrailModuleOptions,
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    // Only log once, and only if enabled
    if (RouteProtectionLogger.logged || !(this.options.showRouteProtection ?? this.options.debug)) {
      return;
    }

    // DiscoveryService is available immediately during OnApplicationBootstrap
    // No retry logic needed - controllers are already registered at this point
    RouteProtectionLogger.logged = true;
    this.logRoutes();
  }

  private logRoutes(): void {
    try {
      const routes = this.scanAllRoutes();

      if (this.options.debug && routes.length === 0) {
        console.warn(
          "[Guardrail] No routes found for protection logging. This might be normal if routes are registered after bootstrap."
        );
        return;
      }

      logRouteProtection(routes, { debug: this.options.debug });
    } catch (error) {
      if (this.options.debug) {
        console.warn("[Guardrail] Could not log route protection:", error);
      }
    }
  }

  private scanAllRoutes(): RouteProtectionInfo[] {
    const routes: RouteProtectionInfo[] = [];

    try {
      const controllers = this.discoveryService.getControllers();

      controllers.forEach((wrapper) => {
        const { instance } = wrapper;
        if (!instance) return;

        const controllerClass = instance.constructor;
        const controllerPath = this.reflector.get<string>(PATH_METADATA, controllerClass) || "";

        // Scan all methods in the controller
        this.metadataScanner.scanFromPrototype(
          instance,
          Object.getPrototypeOf(instance),
          (methodName) => {
            const methodHandler = instance[methodName];
            if (typeof methodHandler !== "function") return;

            const methodPath = this.reflector.get<string>(PATH_METADATA, methodHandler);
            const requestMethod = this.reflector.get<RequestMethod>(METHOD_METADATA, methodHandler);

            if (methodPath !== undefined && requestMethod !== undefined) {
              // Build full path
              const fullPath = this.buildRoutePath(controllerPath, methodPath);

              // Get protection info using controller class and method handler
              const protectionInfo = getRouteProtectionInfo(
                controllerClass,
                methodHandler,
                this.reflector,
                this.options
              );

              routes.push({
                method: RequestMethod[requestMethod],
                path: fullPath,
                controller: controllerClass.name,
                handler: methodName,
                ...protectionInfo,
              });
            }
          }
        );
      });
    } catch (error) {
      if (this.options.debug) {
        console.warn("[Guardrail] Route scanning error:", error);
      }
    }

    return routes;
  }

  private buildRoutePath(controllerPath: string, methodPath: string): string {
    const parts = [controllerPath, methodPath].filter(Boolean);
    return (
      "/" +
      parts
        .join("/")
        .replace(/^\/+|\/+$/g, "")
        .replace(/\/+/g, "/")
    );
  }
}
