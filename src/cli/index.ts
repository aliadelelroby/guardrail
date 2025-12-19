#!/usr/bin/env node
/**
 * Guardrail CLI
 * @module cli
 */

import { replayRequests, formatReplayResults } from "./replay";
import { safeJsonParse } from "../utils/safe-json";

const args = process.argv.slice(2);

if (args[0] === "replay") {
  const options: Parameters<typeof replayRequests>[0] = {
    logFile: "",
    output: "table",
    filter: "all",
  };

  // Parse arguments
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    if (arg === "--log" || arg === "-l") {
      options.logFile = nextArg;
      i++;
    } else if (arg === "--config" || arg === "-c") {
      try {
        if (!nextArg || typeof nextArg !== "string") {
          throw new Error("Config JSON string is required");
        }
        options.config = safeJsonParse(nextArg);
        i++;
      } catch (error) {
        console.error(
          "Invalid JSON config:",
          error instanceof Error ? error.message : "Unknown error"
        );
        process.exit(1);
      }
    } else if (arg === "--config-file" || arg === "-f") {
      options.configFile = nextArg;
      i++;
    } else if (arg === "--compare-config") {
      try {
        if (!nextArg || typeof nextArg !== "string") {
          throw new Error("Compare config JSON string is required");
        }
        options.compareConfig = safeJsonParse(nextArg);
        i++;
      } catch (error) {
        console.error(
          "Invalid JSON compare config:",
          error instanceof Error ? error.message : "Unknown error"
        );
        process.exit(1);
      }
    } else if (arg === "--compare-config-file") {
      options.compareConfigFile = nextArg;
      i++;
    } else if (arg === "--output" || arg === "-o") {
      options.output = nextArg as "json" | "table" | "detailed";
      i++;
    } else if (arg === "--filter") {
      options.filter = nextArg as "allow" | "deny" | "all";
      i++;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`
Guardrail CLI - Request Replay Tool

Usage:
  guardrail replay [options]

Options:
  --log, -l <file>              Path to request log file (JSON lines format)
  --config, -c <json>           Guardrail configuration as JSON string
  --config-file, -f <file>      Path to Guardrail config file (JSON)
  --compare-config <json>       Configuration to compare against (JSON string)
  --compare-config-file <file>  Path to comparison config file
  --output, -o <format>         Output format: json, table, detailed (default: table)
  --filter <type>               Filter results: allow, deny, all (default: all)
  --help, -h                    Show this help message

Examples:
  guardrail replay --log requests.jsonl --config-file config.json
  guardrail replay --log requests.jsonl --config '{"rules":[]}' --output detailed
  guardrail replay --log requests.jsonl --config-file config.json --compare-config-file config-v2.json
      `);
      process.exit(0);
    }
  }

  if (!options.logFile) {
    console.error("Error: --log file is required");
    process.exit(1);
  }

  // Validate file path to prevent path traversal
  if (options.logFile.includes("..") || options.logFile.includes("\0")) {
    console.error("Error: Invalid file path");
    process.exit(1);
  }

  if (
    options.configFile &&
    (options.configFile.includes("..") || options.configFile.includes("\0"))
  ) {
    console.error("Error: Invalid config file path");
    process.exit(1);
  }

  if (
    options.compareConfigFile &&
    (options.compareConfigFile.includes("..") || options.compareConfigFile.includes("\0"))
  ) {
    console.error("Error: Invalid compare config file path");
    process.exit(1);
  }

  replayRequests(options)
    .then((results) => {
      const output = formatReplayResults(results, options.output);
      console.log(output);
    })
    .catch((error) => {
      console.error("Error:", error.message);
      process.exit(1);
    });
} else {
  console.log(`
Guardrail CLI

Available commands:
  replay    Replay requests from log files

Use 'guardrail <command> --help' for command-specific help.
  `);
  process.exit(0);
}
