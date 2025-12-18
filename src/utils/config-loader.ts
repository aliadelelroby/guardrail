/**
 * Configuration file loader utilities
 * @module utils/config-loader
 */

import { readFileSync, existsSync } from "fs";
import { resolve, dirname, extname, isAbsolute, normalize } from "path";
import type { GuardrailConfig } from "../types/index";
import { safeJsonParse } from "./safe-json";
import { sanitizeError } from "./error-sanitizer";

/**
 * Options for loading configuration
 */
export interface LoadConfigOptions {
  /** Path to config file */
  path?: string;
  /** Environment name (dev, staging, prod, etc.) */
  environment?: string;
  /** Working directory for relative paths */
  cwd?: string;
}

/**
 * Validates that a resolved path stays within the allowed directory
 * @param resolvedPath - The resolved absolute path
 * @param baseDir - The base directory that paths must stay within
 * @returns true if path is safe, throws error if not
 */
function validatePath(resolvedPath: string, baseDir: string): void {
  const normalizedPath = normalize(resolvedPath);
  const normalizedBase = normalize(baseDir);

  // Ensure the resolved path is within the base directory
  if (!normalizedPath.startsWith(normalizedBase)) {
    throw new Error("Path traversal detected: resolved path is outside base directory");
  }

  // Additional check: ensure no .. sequences in the relative path
  const relativePath = normalizedPath.substring(normalizedBase.length);
  if (relativePath.includes("..")) {
    throw new Error("Path traversal detected: path contains invalid sequences");
  }
}

/**
 * Loads Guardrail configuration from a file
 */
export function loadConfigFile(options: LoadConfigOptions = {}): GuardrailConfig {
  const cwd = options.cwd || process.cwd();
  const env = options.environment || process.env.NODE_ENV || "development";

  // Normalize environment name (development -> dev, production -> prod, etc.)
  const envName = env === "production" ? "production" : env === "development" ? "development" : env;

  // Determine config file path
  let configPath: string;

  if (options.path) {
    const inputPath = options.path;
    // Resolve the path
    configPath = isAbsolute(inputPath) ? normalize(inputPath) : resolve(cwd, inputPath);
    // Validate it stays within allowed directory
    validatePath(configPath, cwd);
  } else {
    // Try to find config file automatically
    const possiblePaths = [
      resolve(cwd, `guardrail.config.${env}.json`),
      resolve(cwd, `guardrail.config.${env}.yaml`),
      resolve(cwd, `guardrail.config.${env}.yml`),
      resolve(cwd, "guardrail.config.json"),
      resolve(cwd, "guardrail.config.yaml"),
      resolve(cwd, "guardrail.config.yml"),
    ];

    configPath = possiblePaths.find((path) => existsSync(path)) || "";

    if (!configPath) {
      throw new Error("No Guardrail config file found in current directory");
    }
    // Validate auto-discovered path
    validatePath(configPath, cwd);
  }

  if (!existsSync(configPath)) {
    throw new Error("Config file not found");
  }

  const ext = extname(configPath).toLowerCase();
  const content = readFileSync(configPath, "utf-8");

  let config: GuardrailConfig;

  if (ext === ".json") {
    try {
      config = safeJsonParse<GuardrailConfig>(content);
    } catch (error) {
      const message = sanitizeError(error);
      throw new Error(`Failed to parse JSON config file: ${message}`);
    }
  } else if (ext === ".yaml" || ext === ".yml") {
    // For YAML, we'd need a YAML parser library
    // For now, provide a helpful error
    throw new Error(
      `YAML support requires a YAML parser. Please install 'js-yaml' or 'yaml' package, or use JSON format.\n` +
        `To add YAML support, install: npm install js-yaml @types/js-yaml`
    );
  } else {
    throw new Error(`Unsupported config file format: ${ext}. Use .json or .yaml`);
  }

  // Apply environment-specific overrides if environment config exists
  if (!options.path && envName !== "development") {
    const envConfigPath = resolve(dirname(configPath), `guardrail.config.${envName}.json`);
    // Validate environment config path
    validatePath(envConfigPath, cwd);
    if (existsSync(envConfigPath) && extname(envConfigPath) === ".json") {
      try {
        const envContent = readFileSync(envConfigPath, "utf-8");
        const envConfig = safeJsonParse<Partial<GuardrailConfig>>(envContent);
        config = mergeConfigs(config, envConfig);
      } catch (error) {
        const message = sanitizeError(error);
        console.warn(`Failed to load environment config: ${message}`);
      }
    }
  }

  return config;
}

/**
 * Merges two configurations, with the second taking precedence
 */
function mergeConfigs(base: GuardrailConfig, override: Partial<GuardrailConfig>): GuardrailConfig {
  return {
    ...base,
    ...override,
    // Merge rules arrays
    rules: override.rules !== undefined ? override.rules : base.rules,
    // Merge whitelist
    whitelist: override.whitelist
      ? {
          ...base.whitelist,
          ...override.whitelist,
          ips: override.whitelist.ips || base.whitelist?.ips,
          userIds: override.whitelist.userIds || base.whitelist?.userIds,
          countries: override.whitelist.countries || base.whitelist?.countries,
          emailDomains: override.whitelist.emailDomains || base.whitelist?.emailDomains,
        }
      : base.whitelist,
    // Merge blacklist
    blacklist: override.blacklist
      ? {
          ...base.blacklist,
          ...override.blacklist,
          ips: override.blacklist.ips || base.blacklist?.ips,
          userIds: override.blacklist.userIds || base.blacklist?.userIds,
          countries: override.blacklist.countries || base.blacklist?.countries,
          emailDomains: override.blacklist.emailDomains || base.blacklist?.emailDomains,
        }
      : base.blacklist,
    // Merge resilience config
    resilience: override.resilience
      ? {
          ...base.resilience,
          ...override.resilience,
          storage: override.resilience.storage
            ? { ...base.resilience?.storage, ...override.resilience.storage }
            : base.resilience?.storage,
          ip: override.resilience.ip
            ? { ...base.resilience?.ip, ...override.resilience.ip }
            : base.resilience?.ip,
        }
      : base.resilience,
  };
}

/**
 * Creates a Guardrail instance from a config file
 * Note: This function uses dynamic import to avoid circular dependencies
 */
export async function createGuardrailFromConfig(options: LoadConfigOptions = {}) {
  const { Guardrail } = await import("../core/guardrail");
  const config = loadConfigFile(options);
  return new Guardrail(config);
}
