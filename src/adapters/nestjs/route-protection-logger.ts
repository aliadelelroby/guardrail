/**
 * Route Protection Logger for Guardrail
 * Scans and logs route protection information after application initialization
 * @module adapters/nestjs/route-protection-logger
 */

import { Injectable, type OnModuleInit } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { INestApplication } from "@nestjs/common";
import type { GuardrailModuleOptions } from "./guardrail.module";
import { getRouteProtectionInfo, logRouteProtection, type RouteProtectionInfo } from "./route-inspector";


/**
 * Service to log route protection information
 * This service scans all routes and logs their Guardrail protection status
 * 
 * Usage: Inject this service in your main.ts after app creation:
 * ```typescript
 * const app = await NestFactory.create(AppModule);
 * const logger = app.get(RouteProtectionLogger);
 * logger.setApp(app);
 * await app.listen(3000);
 * ```
 */
@Injectable()
export class RouteProtectionLogger implements OnModuleInit {
  private static logged = false;
  private appInstance?: INestApplication;

  constructor(
    private readonly reflector: Reflector,
    private readonly options: GuardrailModuleOptions
  ) {}

  /**
   * Sets the application instance (called from main.ts)
   */
  setApp(app: INestApplication): void {
    this.appInstance = app;
  }

  async onModuleInit(): Promise<void> {
    // Only log once, and only if enabled
    if (
      RouteProtectionLogger.logged ||
      !(this.options.showRouteProtection ?? this.options.debug)
    ) {
      return;
    }

    // If app instance is not set, wait a bit and try again
    if (!this.appInstance) {
      setTimeout(() => {
        if (this.appInstance && !RouteProtectionLogger.logged) {
          this.logRoutes();
        }
      }, 500);
      return;
    }

    RouteProtectionLogger.logged = true;

    // Wait for all routes to be registered
    setTimeout(() => {
      this.logRoutes();
    }, 300);
  }

  private logRoutes(): void {
    if (!this.appInstance) {
      return;
    }

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

    if (!this.appInstance) {
      return routes;
    }

    try {
      const router = this.appInstance.getHttpAdapter().getInstance();
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
