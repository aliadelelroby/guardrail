/**
 * Guardrail Logger for NestJS
 * Intercepts RouterExplorer logs and prepends Guardrail protection information
 * @module adapters/nestjs/guardrail-logger
 */

import { ConsoleLogger } from "@nestjs/common";
import pc from "picocolors";

/**
 * Custom logger that intercepts RouterExplorer logs and adds Guardrail protection info
 */
export class GuardrailLogger extends ConsoleLogger {
  private routeProtectionMap = new Map<string, string>();

  /**
   * Sets route protection information for a specific route
   */
  setRouteProtection(
    path: string,
    method: string,
    protectionInfo: {
      isProtected: boolean;
      isSkipped: boolean;
      ruleDetails: Array<{
        type: string;
        description: string;
        config?: Record<string, unknown>;
      }>;
      rules?: unknown[];
    }
  ): void {
    const key = `${method}:${path}`;
    const parts: string[] = [];

    if (protectionInfo.isSkipped) {
      parts.push(pc.yellow("Skipped"));
    } else if (protectionInfo.isProtected) {
      parts.push(pc.green("Protected"));

      // Extract detailed information from rules
      const details: string[] = [];

      // Process each rule detail
      for (const ruleDetail of protectionInfo.ruleDetails) {
        const { type, config } = ruleDetail;

        switch (type) {
          case "slidingWindow":
            if (config?.max && config?.interval) {
              details.push(`${config.max}/${config.interval}`);
            }
            break;
          case "tokenBucket":
            if (config?.capacity && config?.refillRate && config?.interval) {
              details.push(`bucket:${config.capacity}/${config.refillRate}${config.interval}`);
            }
            break;
          case "filter":
            // Extract country/IP restrictions from filter rules
            const filterRules = protectionInfo.rules?.find(
              (r) => typeof r === "object" && r !== null && "type" in r && r.type === "filter"
            ) as { type: string; allow?: string[]; deny?: string[] } | undefined;
            if (filterRules) {
              const countryRestrictions = this.extractCountryRestrictions(filterRules);
              if (countryRestrictions) {
                details.push(countryRestrictions);
              }
            }
            break;
          case "shield":
            if (config?.mode) {
              details.push(`shield:${config.mode}`);
            }
            break;
          case "detectBot":
            details.push("bot-detection");
            break;
          case "validateEmail":
            details.push("email-validation");
            break;
        }
      }

      // If we have details, show them; otherwise show rule types
      if (details.length > 0) {
        parts.push(`(${details.join(", ")})`);
      } else {
        const ruleTypes = protectionInfo.ruleDetails.map((r) => r.type).join(", ");
        if (ruleTypes) {
          parts.push(`(${ruleTypes})`);
        }
      }
    } else {
      parts.push(pc.gray("Unprotected"));
    }

    this.routeProtectionMap.set(key, parts.join(" "));
  }

  /**
   * Extracts country restrictions from filter rules
   */
  private extractCountryRestrictions(filterRule: {
    type: string;
    allow?: string[];
    deny?: string[];
  }): string | null {
    const restrictions: string[] = [];

    // Check allow rules
    if (Array.isArray(filterRule.allow)) {
      const countries = this.extractCountriesFromExpressions(filterRule.allow as string[]);
      if (countries.length > 0) {
        restrictions.push(`countries:${countries.join(",")}`);
      }
    }

    // Check deny rules
    if (Array.isArray(filterRule.deny)) {
      const deniedCountries = this.extractCountriesFromExpressions(filterRule.deny as string[]);
      if (deniedCountries.length > 0) {
        restrictions.push(`blocked:${deniedCountries.join(",")}`);
      }
    }

    return restrictions.length > 0 ? restrictions.join(" ") : null;
  }

  /**
   * Extracts country codes from filter expressions
   */
  private extractCountriesFromExpressions(expressions: string[]): string[] {
    const countries = new Set<string>();

    for (const expr of expressions) {
      // Match patterns like: ip.src.country eq "US", ip.src.country == "US", ip.src.country in ["US", "CA"]
      const eqMatch = expr.match(/ip\.src\.country\s*(?:eq|==)\s*["']([A-Z]{2})["']/i);
      if (eqMatch) {
        countries.add(eqMatch[1].toUpperCase());
      }

      // Match in array patterns: ip.src.country in ["US", "CA", "GB"]
      const inMatch = expr.match(/ip\.src\.country\s+in\s+\[(.*?)\]/i);
      if (inMatch) {
        const countryList = inMatch[1]
          .match(/["']([A-Z]{2})["']/gi)
          ?.map((c) => c.replace(/["']/g, "").toUpperCase());
        if (countryList) {
          countryList.forEach((c) => countries.add(c));
        }
      }

      // Match ne/!= patterns for deny: ip.src.country ne "US"
      const neMatch = expr.match(/ip\.src\.country\s*(?:ne|!=)\s*["']([A-Z]{2})["']/i);
      if (neMatch) {
        countries.add(neMatch[1].toUpperCase());
      }
    }

    return Array.from(countries);
  }

  log(message: any, context?: string): void {
    // Check if this is a RouterExplorer log
    if (context === "RouterExplorer" && typeof message === "string") {
      // Extract route info from message like "Mapped {/api/users, GET} route"
      const match = message.match(/Mapped \{([^,]+),\s*(\w+)\}\s*route/);
      if (match) {
        const path = match[1];
        const method = match[2];
        const key = `${method}:${path}`;
        const protection = this.routeProtectionMap.get(key);

        if (protection) {
          // Log Guardrail info first using NestJS logger
          super.log(pc.bold(`${path} ${protection}`), "Guardrail");
        }
      }
    }

    // Log the original RouterExplorer message
    super.log(message, context);
  }
}
