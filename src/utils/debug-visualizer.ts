/**
 * Visual debug utilities for Guardrail
 * @module utils/debug-visualizer
 */

import type { Decision, RuleResult } from "../types/index";
import pc from "picocolors";

/**
 * Debug visualization options
 */
export interface DebugVisualizerOptions {
  /** Enable color output */
  color?: boolean;
  /** Show detailed rule evaluation */
  detailed?: boolean;
  /** Show timeline */
  timeline?: boolean;
  /** Show IP information */
  showIP?: boolean;
}

/**
 * Visualizes a decision as a structured tree
 */
export function visualizeDecision(
  decision: Decision,
  options: DebugVisualizerOptions = {}
): string {
  const { color = true, detailed = true, showIP = true } = options;

  const output: string[] = [];
  const c = color
    ? pc
    : {
        green: String,
        red: String,
        yellow: String,
        blue: String,
        gray: String,
        dim: String,
        bold: String,
      };

  // Header
  output.push("");
  output.push(c.bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
  output.push(c.bold(`  Guardrail Decision: ${decision.id}`));
  output.push(c.bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
  output.push("");

  // Conclusion
  if (decision.isAllowed()) {
    output.push(c.green("✓ Request ALLOWED"));
  } else {
    output.push(c.red("✗ Request DENIED"));
    if (decision.reason) {
      const reasonText = getReasonText(decision.reason);
      output.push(c.red(`  Reason: ${reasonText}`));
    }
  }
  output.push("");

  // Rule evaluation tree
  if (detailed && decision.results.length > 0) {
    output.push(c.bold("Rule Evaluation Tree:"));
    output.push("");
    decision.results.forEach((result, index) => {
      const isLast = index === decision.results.length - 1;
      const prefix = isLast ? "└─" : "├─";
      const ruleName = result.rule;

      if (result.conclusion === "ALLOW") {
        output.push(`  ${prefix} ${c.green("✓")} ${c.bold(ruleName)} ${c.green("(ALLOWED)")}`);
        if (result.remaining !== undefined) {
          output.push(`     ${c.gray(`Remaining: ${result.remaining}`)}`);
        }
      } else {
        output.push(`  ${prefix} ${c.red("✗")} ${c.bold(ruleName)} ${c.red("(DENIED)")}`);
        if (result.reason) {
          output.push(`     ${c.red(`Reason: ${result.reason}`)}`);
        }
        if (result.remaining !== undefined) {
          output.push(`     ${c.gray(`Remaining: ${result.remaining}`)}`);
        }
      }
    });
    output.push("");
  }

  // IP Information
  if (showIP && decision.ip) {
    output.push(c.bold("IP Information:"));
    output.push("");
    const ipInfo = formatIPInfo(decision.ip, c);
    output.push(...ipInfo);
    output.push("");
  }

  // Summary
  const passed = decision.results.filter((r) => r.conclusion === "ALLOW").length;
  const failed = decision.results.filter((r) => r.conclusion === "DENY").length;
  output.push(c.bold("Summary:"));
  output.push(
    `  ${c.green(`✓ ${passed} rule(s) passed`)} ${failed > 0 ? c.red(`✗ ${failed} rule(s) failed`) : ""}`
  );
  output.push("");

  // Explanation
  output.push(c.bold("Explanation:"));
  output.push(`  ${c.dim(decision.explain())}`);
  output.push("");

  output.push(c.bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
  output.push("");

  return output.join("\n");
}

/**
 * Gets human-readable reason text
 */
function getReasonText(reason: Decision["reason"]): string {
  if (reason.isRateLimit()) {
    const remaining = reason.getRemaining();
    return `Rate Limit${remaining !== undefined ? ` (${remaining} remaining)` : ""}`;
  }
  if (reason.isQuota()) {
    const remaining = reason.getRemaining();
    return `Quota Exceeded${remaining !== undefined ? ` (${remaining} remaining)` : ""}`;
  }
  if (reason.isBot()) {return "Bot Detected";}
  if (reason.isShield()) {return "Attack Detected";}
  if (reason.isEmail()) {return "Invalid Email";}
  if (reason.isFilter()) {return "Filter Rule Matched";}
  return "Unknown";
}

/**
 * Formats IP information for display
 */
function formatIPInfo(ip: Decision["ip"], c: any): string[] {
  const lines: string[] = [];

  if (ip.hasCountry()) {
    const country = ip.countryName || ip.country;
    lines.push(`  Country: ${c.blue(country || "Unknown")}`);
  }

  if (ip.hasCity()) {
    lines.push(`  City: ${c.blue(ip.city || "Unknown")}`);
  }

  const securityFlags: string[] = [];
  if (ip.isVpn()) {securityFlags.push("VPN");}
  if (ip.isProxy()) {securityFlags.push("Proxy");}
  if (ip.isTor()) {securityFlags.push("Tor");}
  if (ip.isHosting()) {securityFlags.push("Hosting");}

  if (securityFlags.length > 0) {
    lines.push(`  Security: ${c.yellow(securityFlags.join(", "))}`);
  } else {
    lines.push(`  Security: ${c.green("Clean")}`);
  }

  return lines;
}

/**
 * Visualizes rule evaluation timeline
 */
export function visualizeTimeline(results: RuleResult[]): string {
  const output: string[] = [];

  output.push("");
  output.push(pc.bold("Evaluation Timeline:"));
  output.push("");

  results.forEach((result, index) => {
    const timestamp = Date.now() - (results.length - index) * 10; // Simulated timestamps
    const time = new Date(timestamp).toISOString().split("T")[1].split(".")[0];
    const status = result.conclusion === "ALLOW" ? pc.green("✓") : pc.red("✗");
    output.push(`  [${pc.gray(time)}] ${status} ${pc.bold(result.rule)}`);
  });

  output.push("");
  return output.join("\n");
}

/**
 * Logs a decision with visual formatting
 */
export function logDecision(decision: Decision, options: DebugVisualizerOptions = {}): void {
  const visualization = visualizeDecision(decision, options);
  console.log(visualization);

  if (options.timeline) {
    const timeline = visualizeTimeline(decision.results);
    console.log(timeline);
  }
}
