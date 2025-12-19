/**
 * Route Protection Logger for Guardrail
 * Scans and logs route protection information after application initialization
 * @module adapters/nestjs/route-protection-logger
 */

import { Injectable, type OnApplicationBootstrap } from "@nestjs/common";
import { Reflector, HttpAdapterHost } from "@nestjs/core";
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
    private readonly httpAdapterHost: HttpAdapterHost
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    // Only log once, and only if enabled
    if (RouteProtectionLogger.logged || !(this.options.showRouteProtection ?? this.options.debug)) {
      return;
    }

    // Wait a bit for all routes to be fully registered
    // OnApplicationBootstrap runs after modules are initialized but routes
    // might still be registering, so we add a small delay
    setTimeout(() => {
      if (!RouteProtectionLogger.logged) {
        RouteProtectionLogger.logged = true;
        this.logRoutes();
      }
    }, 100);
  }

  private logRoutes(): void {
    try {
      const routes = this.scanAllRoutes();
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
      const httpAdapter = this.httpAdapterHost.httpAdapter;
      if (!httpAdapter) {
        return routes;
      }

      const router = httpAdapter.getInstance();
      const routerStack = router._router?.stack || [];

      for (const layer of routerStack) {
        if (layer.route) {
          const route = layer.route;
          const methods = Object.keys(route.methods).filter((m) => m !== "_all");

          for (const method of methods) {
            const path = route.path;
            const handler = layer.handle;

            // Get protection info
            let protectionInfo;
            try {
              if (handler && typeof handler === "function") {
                // Try to get metadata from the handler
                protectionInfo = getRouteProtectionInfo(
                  handler.constructor || handler,
                  handler,
                  this.reflector,
                  this.options
                );
              } else {
                protectionInfo = {
                  isProtected: false,
                  isSkipped: false,
                  rules: [],
                  ruleDetails: [],
                };
              }
            } catch {
              protectionInfo = {
                isProtected: false,
                isSkipped: false,
                rules: [],
                ruleDetails: [],
              };
            }

            routes.push({
              method: method.toUpperCase(),
              path,
              controller: handler?.constructor?.name || handler?.name || "Unknown",
              handler: handler?.name || "unknown",
              ...protectionInfo,
            });
          }
        }
      }
    } catch (error) {
      if (this.options.debug) {
        console.warn("[Guardrail] Route scanning error:", error);
      }
    }

    return routes;
  }
}
