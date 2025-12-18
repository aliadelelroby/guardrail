/**
 * Route Inspector for Guardrail
 * Scans and displays Guardrail protection details for all routes
 * @module adapters/nestjs/route-inspector
 */

import type { INestApplication } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { GuardrailRule } from "../../types/index";
import { GUARDRAIL_RULES, GUARDRAIL_OPTIONS, SKIP_GUARDRAIL, GUARDRAIL_PRESET } from "./decorators";
import { GuardrailPresets } from "../../core/presets";
import pc from "picocolors";

/**
 * Route protection information
 */
export interface RouteProtectionInfo {
  method: string;
  path: string;
  controller: string;
  handler: string;
  isProtected: boolean;
  isSkipped: boolean;
  preset?: string;
  rules: GuardrailRule[];
  options?: Record<string, unknown>;
  ruleDetails: Array<{
    type: string;
    description: string;
    config?: Record<string, unknown>;
  }>;
}

/**
 * Inspects all routes and returns Guardrail protection information
 */
export function inspectGuardrailRoutes(
  app: INestApplication,
  _reflector: Reflector
): RouteProtectionInfo[] {
  const routes: RouteProtectionInfo[] = [];
  const router = app.getHttpAdapter().getInstance();

  // Get all registered routes from NestJS
  // Note: This is a simplified approach - in production, you might want to use
  // NestJS's RouterExplorer or a more sophisticated route discovery mechanism
  try {
    const routesData = router._router?.stack || [];

    for (const layer of routesData) {
      if (layer.route) {
        const route = layer.route;
        const methods = Object.keys(route.methods).filter((m) => m !== "_all");

        for (const method of methods) {
          const path = route.path;

          // Try to extract controller and handler from layer
          const handler = layer.handle?.name || "unknown";
          const controller = layer.regexp?.toString() || "unknown";

          // Get Guardrail metadata (this is a simplified approach)
          // In a real implementation, we'd need to map routes to their actual handlers
          routes.push({
            method: method.toUpperCase(),
            path,
            controller,
            handler,
            isProtected: false,
            isSkipped: false,
            rules: [],
            ruleDetails: [],
          });
        }
      }
    }
  } catch (error) {
    // If route inspection fails, return empty array
    console.warn("[Guardrail] Could not inspect routes:", error);
  }

  return routes;
}

/**
 * Gets protection info for a specific route handler
 */
export function getRouteProtectionInfo(
  target: any,
  handler: any,
  reflector: Reflector,
  moduleOptions?: { autoProtect?: boolean; rules?: GuardrailRule[] }
): {
  isProtected: boolean;
  isSkipped: boolean;
  preset?: string;
  rules: GuardrailRule[];
  options?: Record<string, unknown>;
  ruleDetails: Array<{ type: string; description: string; config?: Record<string, unknown> }>;
} {
  // Check if skipped
  const isSkipped =
    reflector.get<boolean>(SKIP_GUARDRAIL, handler) ||
    reflector.get<boolean>(SKIP_GUARDRAIL, target);

  if (isSkipped) {
    return {
      isProtected: false,
      isSkipped: true,
      rules: [],
      ruleDetails: [],
    };
  }

  // Get rules
  const classRules = reflector.get<GuardrailRule[]>(GUARDRAIL_RULES, target) || [];
  const methodRules = reflector.get<GuardrailRule[]>(GUARDRAIL_RULES, handler) || [];
  const moduleRules = moduleOptions?.rules || [];
  const presetName =
    reflector.get<string>(GUARDRAIL_PRESET, handler) ||
    reflector.get<string>(GUARDRAIL_PRESET, target);

  let finalRules: GuardrailRule[] = [];

  if (presetName && presetName in GuardrailPresets) {
    const preset = GuardrailPresets[presetName as keyof typeof GuardrailPresets]();
    finalRules = [...(preset.rules || []), ...moduleRules];
  } else if (methodRules.length > 0 || classRules.length > 0) {
    finalRules = [...moduleRules, ...classRules, ...methodRules];
  } else if (moduleOptions?.autoProtect) {
    finalRules = [...(GuardrailPresets.api().rules || []), ...moduleRules];
  } else if (moduleRules.length > 0) {
    // If only module rules exist, use them
    finalRules = [...moduleRules];
  }

  // Get options
  const options =
    reflector.get<Record<string, unknown>>(GUARDRAIL_OPTIONS, handler) ||
    reflector.get<Record<string, unknown>>(GUARDRAIL_OPTIONS, target) ||
    undefined;

  // Generate rule details
  const ruleDetails = finalRules.map((rule) => {
    let description = "";
    const config: Record<string, unknown> = {};

    switch (rule.type) {
      case "shield":
        description = "Attack Protection (SQLi, XSS, Command Injection, etc.)";
        if (rule.mode) config.mode = rule.mode;
        if ("scanBody" in rule) config.scanBody = rule.scanBody;
        if ("scanHeaders" in rule) config.scanHeaders = rule.scanHeaders;
        break;
      case "slidingWindow":
        description = `Rate Limit: ${rule.max} requests per ${rule.interval}`;
        config.max = rule.max;
        config.interval = rule.interval;
        break;
      case "tokenBucket":
        description = `Token Bucket: ${rule.capacity} capacity, ${rule.refillRate} tokens per ${rule.interval}`;
        config.capacity = rule.capacity;
        config.refillRate = rule.refillRate;
        config.interval = rule.interval;
        break;
      case "detectBot":
        description = "Bot Detection";
        if ("allow" in rule && Array.isArray(rule.allow)) {
          config.allowedBots = rule.allow.length;
        }
        break;
      case "validateEmail":
        description = "Email Validation";
        if ("block" in rule && Array.isArray(rule.block)) {
          config.blockedTypes = rule.block;
        }
        break;
      case "filter":
        description = "IP/Request Filtering";
        if ("allow" in rule && Array.isArray(rule.allow)) {
          config.allowRules = rule.allow.length;
        }
        if ("deny" in rule && Array.isArray(rule.deny)) {
          config.denyRules = rule.deny.length;
        }
        break;
      default:
        description = `Custom Rule: ${rule.type}`;
    }

    return {
      type: rule.type,
      description,
      config: Object.keys(config).length > 0 ? config : undefined,
    };
  });

  return {
    isProtected: finalRules.length > 0,
    isSkipped: false,
    preset: presetName,
    rules: finalRules,
    options,
    ruleDetails,
  };
}

/**
 * Logs route protection information in a formatted way
 */
export function logRouteProtection(
  routes: RouteProtectionInfo[],
  options?: { debug?: boolean }
): void {
  if (!options?.debug) {
    return;
  }

  const protectedRoutes = routes.filter((r) => r.isProtected);
  const skippedRoutes = routes.filter((r) => r.isSkipped);
  const unprotectedRoutes = routes.filter((r) => !r.isProtected && !r.isSkipped);

  if (routes.length === 0) {
    return; // No routes to display
  }

  const headerLine = "┌─────────────────────────────────────────────────────────┐";
  const titleLine = "│ Guardrail Route Protection Summary" + " ".repeat(23) + "│";
  const separatorLine = "├─────────────────────────────────────────────────────────┤";
  const footerLine = "└─────────────────────────────────────────────────────────┘";

  console.log("\n" + pc.bold(pc.cyan(headerLine)));
  console.log(pc.bold(pc.cyan(titleLine)));
  console.log(pc.bold(pc.cyan(separatorLine)));

  const totalStr = ` Total Routes: ${pc.bold(String(routes.length))}`;
  const totalPadding = " ".repeat(60 - totalStr.length - 2);
  console.log(pc.bold(pc.cyan("│")) + totalStr + totalPadding + pc.bold(pc.cyan("│")));

  const protectedStr = ` Protected: ${pc.green(String(protectedRoutes.length))}`;
  const protectedPadding = " ".repeat(60 - protectedStr.length - 2);
  console.log(pc.bold(pc.cyan("│")) + protectedStr + protectedPadding + pc.bold(pc.cyan("│")));

  const skippedStr = ` Skipped: ${pc.yellow(String(skippedRoutes.length))}`;
  const skippedPadding = " ".repeat(60 - skippedStr.length - 2);
  console.log(pc.bold(pc.cyan("│")) + skippedStr + skippedPadding + pc.bold(pc.cyan("│")));

  const unprotectedStr = ` Unprotected: ${pc.gray(String(unprotectedRoutes.length))}`;
  const unprotectedPadding = " ".repeat(60 - unprotectedStr.length - 2);
  console.log(pc.bold(pc.cyan("│")) + unprotectedStr + unprotectedPadding + pc.bold(pc.cyan("│")));

  console.log(pc.bold(pc.cyan(footerLine)));

  if (protectedRoutes.length > 0) {
    console.log("\n" + pc.bold(pc.green("Protected Routes:")));
    for (const route of protectedRoutes) {
      const methodStr = route.method.padEnd(6);
      const pathStr = route.path.padEnd(30);
      const controllerStr = `(${route.controller})`;
      console.log(`  ${pc.cyan(methodStr)} ${pc.bold(pathStr)} ${pc.gray(controllerStr)}`);
      if (route.preset) {
        console.log(`    ${pc.dim(`Preset: ${route.preset}`)}`);
      }
      for (const detail of route.ruleDetails) {
        console.log(`    ${pc.green("✓")} ${pc.dim(detail.description)}`);
        if (detail.config) {
          const configStr = Object.entries(detail.config)
            .map(([k, v]) => `${k}=${v}`)
            .join(", ");
          console.log(`      ${pc.dim(configStr)}`);
        }
      }
    }
  }

  if (skippedRoutes.length > 0) {
    console.log("\n" + pc.bold(pc.yellow("Skipped Routes:")));
    for (const route of skippedRoutes) {
      const methodStr = route.method.padEnd(6);
      const pathStr = route.path.padEnd(30);
      const controllerStr = `(${route.controller})`;
      console.log(`  ${pc.cyan(methodStr)} ${pc.bold(pathStr)} ${pc.gray(controllerStr)}`);
    }
  }

  if (unprotectedRoutes.length > 0 && unprotectedRoutes.length < 50) {
    // Only show unprotected routes if there aren't too many
    console.log("\n" + pc.bold(pc.gray("Unprotected Routes:")));
    for (const route of unprotectedRoutes.slice(0, 10)) {
      const methodStr = route.method.padEnd(6);
      const pathStr = route.path.padEnd(30);
      const controllerStr = `(${route.controller})`;
      console.log(`  ${pc.cyan(methodStr)} ${pc.bold(pathStr)} ${pc.gray(controllerStr)}`);
    }
    if (unprotectedRoutes.length > 10) {
      console.log(`  ${pc.dim(`... and ${unprotectedRoutes.length - 10} more`)}`);
    }
  }

  console.log("");
}
