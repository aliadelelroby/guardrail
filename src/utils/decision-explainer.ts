/**
 * Decision explanation utilities
 * @module utils/decision-explainer
 */

import type { Decision, RuleResult } from "../types/index";

/**
 * Generates a human-readable explanation of a decision
 * @param decision - The decision to explain
 * @returns Human-readable explanation string
 */
export function explainDecision(decision: Decision): string {
  const parts: string[] = [];

  // Main conclusion
  if (decision.isAllowed()) {
    parts.push("Request allowed: All rules passed.");
  } else {
    const denialReason = getDenialReasonText(decision);
    parts.push(`Request denied: ${denialReason}`);
  }

  // Rule results summary
  const ruleSummary = getRuleSummary(decision.results);
  if (ruleSummary) {
    parts.push(ruleSummary);
  }

  // Rate limit/quota status
  const rateLimitStatus = getRateLimitStatus(decision);
  if (rateLimitStatus) {
    parts.push(rateLimitStatus);
  }

  // IP information
  const ipInfo = getIPInfoText(decision.ip);
  if (ipInfo) {
    parts.push(ipInfo);
  }

  return parts.join(" ");
}

/**
 * Gets human-readable denial reason text
 */
function getDenialReasonText(decision: Decision): string {
  const reason = decision.reason;

  if (reason.isRateLimit()) {
    const remaining = reason.getRemaining();
    if (remaining !== undefined) {
      return `Rate limit exceeded (${remaining} remaining)`;
    }
    return "Rate limit exceeded";
  }

  if (reason.isQuota()) {
    const remaining = reason.getRemaining();
    if (remaining !== undefined) {
      return `Quota exceeded (${remaining} remaining)`;
    }
    return "Quota exceeded";
  }

  if (reason.isBot()) {
    return "Bot detected";
  }

  if (reason.isShield()) {
    return "Attack detected (shield protection)";
  }

  if (reason.isEmail()) {
    return "Invalid or disposable email";
  }

  if (reason.isFilter()) {
    return "Filter rule matched";
  }

  return "Request denied";
}

/**
 * Gets summary of rule evaluation results
 */
function getRuleSummary(results: RuleResult[]): string {
  if (results.length === 0) {
    return "";
  }

  const passed = results.filter((r) => r.conclusion === "ALLOW").length;
  const failed = results.filter((r) => r.conclusion === "DENY").length;

  if (failed === 0) {
    return `All ${passed} rule(s) passed.`;
  }

  const failedRules = results
    .filter((r) => r.conclusion === "DENY")
    .map((r) => r.rule)
    .join(", ");

  return `${passed} rule(s) passed, ${failed} rule(s) failed (${failedRules}).`;
}

/**
 * Gets rate limit/quota status text
 */
function getRateLimitStatus(decision: Decision): string {
  const rateLimitResult = decision.results.find(
    (r) => r.reason === "RATE_LIMIT" || r.reason === "QUOTA"
  );

  if (!rateLimitResult) {
    return "";
  }

  const remaining = rateLimitResult.remaining;
  if (remaining === undefined) {
    return "";
  }

  const type = rateLimitResult.reason === "QUOTA" ? "Quota" : "Rate limit";
  return `${type}: ${remaining} remaining.`;
}

/**
 * Gets IP information text
 */
function getIPInfoText(ip: Decision["ip"]): string {
  const parts: string[] = [];

  if (ip.hasCountry()) {
    const country = ip.countryName || ip.country;
    parts.push(country || "");
  }

  if (ip.hasCity()) {
    parts.push(ip.city || "");
  }

  const location = parts.filter(Boolean).join(", ");
  const securityFlags: string[] = [];

  if (ip.isVpn()) {
    securityFlags.push("VPN");
  }
  if (ip.isProxy()) {
    securityFlags.push("Proxy");
  }
  if (ip.isTor()) {
    securityFlags.push("Tor");
  }
  if (ip.isHosting()) {
    securityFlags.push("Hosting");
  }

  const securityText =
    securityFlags.length > 0
      ? ` (${securityFlags.join(", ")})`
      : securityFlags.length === 0 && location
        ? " (not VPN/Proxy)"
        : "";

  if (location || securityText) {
    return `IP: ${location || "Unknown"}${securityText}.`;
  }

  return "";
}
