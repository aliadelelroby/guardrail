/**
 * Filter rule - allows or denies based on expressions
 */

import type { FilterConfig, RuleResult, DecisionConclusion, IPInfo } from "../types/index";
import { extractIPFromRequest, extractUserAgent } from "../utils/fingerprint";
import { evaluateExpression } from "../utils/expression-evaluator";

export class FilterRule {
  constructor(private config: FilterConfig) {}

  async evaluate(
    request: Request,
    ipInfo: IPInfo,
    characteristics: Record<string, string | number | undefined>
  ): Promise<RuleResult> {
    const context = this.buildContext(request, ipInfo, characteristics);

    let conclusion: DecisionConclusion = "ALLOW";

    if (this.config.deny && this.config.deny.length > 0) {
      const shouldDeny = this.config.deny.some((expr) => this.evaluateExpression(expr, context));
      if (shouldDeny) {
        conclusion = "DENY";
      }
    }

    if (this.config.allow && this.config.allow.length > 0 && conclusion === "ALLOW") {
      const shouldAllow = this.config.allow.some((expr) => this.evaluateExpression(expr, context));
      if (!shouldAllow) {
        conclusion = "DENY";
      }
    }

    const result: RuleResult = {
      rule: "filter",
      conclusion,
      reason: conclusion === "DENY" ? "FILTER" : undefined,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }

  private buildContext(
    request: Request,
    ipInfo: IPInfo,
    characteristics: Record<string, string | number | undefined>
  ): Record<string, unknown> {
    const ip = extractIPFromRequest(request);
    const userAgent = extractUserAgent(request);

    const context: Record<string, unknown> = {
      ip_src: ip,
      ip_src_country: ipInfo.country,
      ip_src_region: ipInfo.region,
      ip_src_city: ipInfo.city,
      ip_src_continent: ipInfo.continent,
      ip_src_vpn: ipInfo.isVpn,
      ip_src_proxy: ipInfo.isProxy,
      ip_src_hosting: ipInfo.isHosting,
      ip_src_relay: ipInfo.isRelay,
      ip_src_tor: ipInfo.isTor,
      ip_src_asnum_type: ipInfo.asnType,
      http_request_headers_user_agent: userAgent,
    };

    // Add characteristics with safe keys
    for (const [key, value] of Object.entries(characteristics)) {
      const safeKey = key.replace(/[^a-zA-Z0-9_]/g, "_");
      context[safeKey] = value;
    }

    return context;
  }

  /**
   * Evaluates a filter expression safely
   * @param expression - Expression string
   * @param context - Evaluation context
   * @returns Evaluation result
   */
  private evaluateExpression(expression: string, context: Record<string, unknown>): boolean {
    try {
      let normalized = expression
        .replace(/ip\.src\.country/g, "ip_src_country")
        .replace(/ip\.src\.region/g, "ip_src_region")
        .replace(/ip\.src\.city/g, "ip_src_city")
        .replace(/ip\.src\.continent/g, "ip_src_continent")
        .replace(/ip\.src\.vpn/g, "ip_src_vpn")
        .replace(/ip\.src\.proxy/g, "ip_src_proxy")
        .replace(/ip\.src\.hosting/g, "ip_src_hosting")
        .replace(/ip\.src\.relay/g, "ip_src_relay")
        .replace(/ip\.src\.tor/g, "ip_src_tor")
        .replace(/ip\.src\.asnum\.type/g, "ip_src_asnum_type")
        .replace(/ip\.src/g, "ip_src")
        .replace(/http\.request\.headers\["user-agent"\]/g, "http_request_headers_user_agent");

      normalized = normalized
        .replace(/\bin\b/g, " in ")
        .replace(/\beq\b/g, " == ")
        .replace(/\bne\b/g, " != ")
        .replace(/\band\b/g, " and ")
        .replace(/\bor\b/g, " or ")
        .replace(/\bnot\b/g, " not ")
        .replace(/\{([^}]+)\}/g, (_, ips) => {
          const ipList = ips
            .split(/\s+/)
            .map((ip: string) => `"${ip.trim()}"`)
            .join(", ");
          return `[${ipList}]`;
        });

      return evaluateExpression(normalized, context);
    } catch {
      return false;
    }
  }
}
