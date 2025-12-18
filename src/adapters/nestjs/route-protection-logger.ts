/**
 * Route Protection Logger for Guardrail
 * Scans routes and populates GuardrailLogger with protection information
 * @module adapters/nestjs/route-protection-logger
 */

import { Injectable, type OnModuleInit, RequestMethod, Logger as NestLogger } from "@nestjs/common";
import { PATH_METADATA, METHOD_METADATA } from "@nestjs/common/constants";
import { Reflector, DiscoveryService, MetadataScanner } from "@nestjs/core";
import type { GuardrailModuleOptions } from "./guardrail.module";
import { getRouteProtectionInfo } from "./route-inspector";
import { GuardrailLogger } from "./guardrail-logger";

/**
 * Service to populate route protection information in GuardrailLogger
 * This service scans all routes early (OnModuleInit) and stores protection info
 * so GuardrailLogger can display it when RouterExplorer logs each route.
 *
 * No manual setup required - it works automatically when enabled via
 * `showRouteProtection` or `debug` options in GuardrailModule.
 */
@Injectable()
export class RouteProtectionLogger implements OnModuleInit {
  private static initialized = false;
  private readonly logger = new NestLogger(RouteProtectionLogger.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly options: GuardrailModuleOptions,
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
    private readonly guardrailLogger: GuardrailLogger
  ) {}

  async onModuleInit(): Promise<void> {
    if (
      RouteProtectionLogger.initialized ||
      !(this.options.showRouteProtection ?? this.options.debug)
    ) {
      return;
    }

    RouteProtectionLogger.initialized = true;
    this.populateRouteProtection();
  }

  private populateRouteProtection(): void {
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
              const fullPath = this.buildRoutePath(controllerPath, methodPath);
              const protectionInfo = getRouteProtectionInfo(
                controllerClass,
                methodHandler,
                this.reflector,
                {
                  autoProtect: this.options.autoProtect,
                  rules: this.options.rules || [],
                }
              );

              // Store protection info in logger with full details
              this.guardrailLogger.setRouteProtection(fullPath, RequestMethod[requestMethod], {
                isProtected: protectionInfo.isProtected,
                isSkipped: protectionInfo.isSkipped,
                ruleDetails: protectionInfo.ruleDetails,
                rules: protectionInfo.rules as unknown[],
              });
            }
          }
        );
      });
    } catch (error) {
      if (this.options.debug) {
        this.logger.warn("Route scanning error", error);
      }
    }
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
