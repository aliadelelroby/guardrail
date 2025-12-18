/**
 * Request Replay CLI Tool
 * Allows replaying requests from logs to test different configurations
 * @module cli/replay
 */

import { readFileSync, existsSync } from "fs";
import { parse, resolve, isAbsolute, normalize } from "path";
import { Guardrail } from "../core/guardrail";
import type { GuardrailConfig, ProtectOptions } from "../types/index";
import { safeJsonParse } from "../utils/safe-json";

/**
 * Request log entry format
 */
export interface RequestLogEntry {
  /** Request method */
  method: string;
  /** Request URL */
  url: string;
  /** Request headers */
  headers?: Record<string, string>;
  /** Request body (optional) */
  body?: unknown;
  /** Protection options used */
  options?: ProtectOptions;
  /** Timestamp of original request */
  timestamp?: number;
}

/**
 * Replay options
 */
export interface ReplayOptions {
  /** Path to log file */
  logFile: string;
  /** Guardrail configuration to use for replay */
  config?: GuardrailConfig;
  /** Config file path (alternative to inline config) */
  configFile?: string;
  /** Compare with another config */
  compareConfig?: GuardrailConfig;
  /** Compare config file path */
  compareConfigFile?: string;
  /** Output format */
  output?: "json" | "table" | "detailed";
  /** Filter by decision (allow/deny) */
  filter?: "allow" | "deny" | "all";
}

/**
 * Replay result
 */
export interface ReplayResult {
  /** Original log entry */
  entry: RequestLogEntry;
  /** Decision from replay */
  decision: Awaited<ReturnType<Guardrail["protect"]>>;
  /** Duration in milliseconds */
  duration: number;
  /** Comparison result if compare config provided */
  comparison?: {
    decision: Awaited<ReturnType<Guardrail["protect"]>>;
    duration: number;
    changed: boolean;
  };
}

/**
 * Validates that a resolved path stays within the allowed directory
 */
function validateFilePath(resolvedPath: string, baseDir: string = process.cwd()): void {
  const normalizedPath = normalize(resolvedPath);
  const normalizedBase = normalize(baseDir);

  if (!normalizedPath.startsWith(normalizedBase)) {
    throw new Error(`Path traversal detected: resolved path is outside base directory`);
  }

  const relativePath = normalizedPath.substring(normalizedBase.length);
  if (relativePath.includes("..")) {
    throw new Error(`Path traversal detected: path contains ".." sequences`);
  }
}

/**
 * Replays requests from a log file
 */
export async function replayRequests(options: ReplayOptions): Promise<ReplayResult[]> {
  // Validate and load log file
  const logFilePath = isAbsolute(options.logFile)
    ? normalize(options.logFile)
    : resolve(process.cwd(), options.logFile);
  validateFilePath(logFilePath);
  if (!existsSync(logFilePath)) {
    throw new Error("Log file not found");
  }
  const logContent = readFileSync(logFilePath, "utf-8");
  const entries: RequestLogEntry[] = parseLogFile(logContent);

  // Load configurations
  const config =
    options.config || (options.configFile ? loadConfigFile(options.configFile) : undefined);
  const compareConfig =
    options.compareConfig ||
    (options.compareConfigFile ? loadConfigFile(options.compareConfigFile) : undefined);

  if (!config) {
    throw new Error("No configuration provided. Use --config or --config-file");
  }

  const guardrail = new Guardrail(config);
  const compareGuardrail = compareConfig ? new Guardrail(compareConfig) : undefined;

  const results: ReplayResult[] = [];

  for (const entry of entries) {
    // Filter by decision type if specified
    if (options.filter && options.filter !== "all") {
      // We'll check after replay
    }

    const request = new Request(entry.url, {
      method: entry.method,
      headers: entry.headers,
      body: entry.body ? JSON.stringify(entry.body) : undefined,
    });

    // Replay with main config
    const startTime = Date.now();
    const decision = await guardrail.protect(request, entry.options);
    const duration = Date.now() - startTime;

    // Apply filter
    if (options.filter === "allow" && decision.isDenied()) {continue;}
    if (options.filter === "deny" && decision.isAllowed()) {continue;}

    const result: ReplayResult = {
      entry,
      decision,
      duration,
    };

    // Compare with alternative config if provided
    if (compareGuardrail) {
      const compareStartTime = Date.now();
      const compareDecision = await compareGuardrail.protect(request, entry.options);
      const compareDuration = Date.now() - compareStartTime;

      result.comparison = {
        decision: compareDecision,
        duration: compareDuration,
        changed: decision.conclusion !== compareDecision.conclusion,
      };
    }

    results.push(result);
  }

  return results;
}

/**
 * Parses a log file into request entries
 * Supports JSON lines format (one JSON object per line)
 */
export function parseLogFile(content: string): RequestLogEntry[] {
  const lines = content.trim().split("\n");
  const entries: RequestLogEntry[] = [];

  for (const line of lines) {
    if (!line.trim()) {continue;}

    try {
      const entry = safeJsonParse<RequestLogEntry>(line);
      if (entry.method && entry.url) {
        entries.push(entry);
      }
    } catch (error) {
      console.warn(`Failed to parse log line`, error);
    }
  }

  return entries;
}

/**
 * Loads a configuration file
 */
function loadConfigFile(path: string): GuardrailConfig {
  // Validate path
  const configFilePath = isAbsolute(path) ? normalize(path) : resolve(process.cwd(), path);
  validateFilePath(configFilePath);
  if (!existsSync(configFilePath)) {
    throw new Error("Config file not found");
  }

  const content = readFileSync(configFilePath, "utf-8");
  const ext = parse(configFilePath).ext.toLowerCase();

  if (ext === ".json") {
    return safeJsonParse<GuardrailConfig>(content);
  } else if (ext === ".yaml" || ext === ".yml") {
    // For YAML support, we'd need a YAML parser
    // For now, throw an error suggesting JSON
    throw new Error("YAML support requires a YAML parser. Please use JSON format for now.");
  } else {
    throw new Error(`Unsupported config file format: ${ext}. Use .json or .yaml`);
  }
}

/**
 * Formats replay results for output
 */
export function formatReplayResults(
  results: ReplayResult[],
  format: "json" | "table" | "detailed" = "table"
): string {
  if (format === "json") {
    return JSON.stringify(results, null, 2);
  }

  if (format === "table") {
    return formatAsTable(results);
  }

  return formatDetailed(results);
}

/**
 * Formats results as a table
 */
function formatAsTable(results: ReplayResult[]): string {
  const lines: string[] = [];
  lines.push("Method | URL | Decision | Duration | Changed");
  lines.push("-------|-----|----------|----------|--------");

  for (const result of results) {
    const method = result.entry.method.padEnd(6);
    const url = result.entry.url.substring(0, 40).padEnd(40);
    const decision = result.decision.isAllowed() ? "ALLOW" : "DENY";
    const duration = `${result.duration}ms`.padEnd(8);
    const changed = result.comparison?.changed ? "✓" : "-";

    lines.push(`${method} | ${url} | ${decision} | ${duration} | ${changed}`);
  }

  return lines.join("\n");
}

/**
 * Formats results with detailed information
 */
function formatDetailed(results: ReplayResult[]): string {
  const lines: string[] = [];

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    lines.push(`\nRequest ${i + 1}:`);
    lines.push(`  Method: ${result.entry.method}`);
    lines.push(`  URL: ${result.entry.url}`);
    lines.push(`  Decision: ${result.decision.isAllowed() ? "ALLOW" : "DENY"}`);
    lines.push(`  Duration: ${result.duration}ms`);
    lines.push(`  Explanation: ${result.decision.explain()}`);

    if (result.comparison) {
      lines.push(`  Comparison:`);
      lines.push(`    Decision: ${result.comparison.decision.isAllowed() ? "ALLOW" : "DENY"}`);
      lines.push(`    Duration: ${result.comparison.duration}ms`);
      lines.push(`    Changed: ${result.comparison.changed ? "Yes" : "No"}`);
    }
  }

  return lines.join("\n");
}
