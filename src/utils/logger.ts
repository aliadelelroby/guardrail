/**
 * Logger utility for Guardrail
 * @module utils/logger
 */

import pc from "picocolors";

/**
 * Log levels
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * Logger interface
 */
export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

/**
 * Console logger implementation with pretty colors
 */
export class ConsoleLogger implements Logger {
  constructor(private readonly enabled: boolean = false) {}

  private getTimestamp(): string {
    return new Date().toLocaleTimeString();
  }

  private formatPrefix(level: string, colorFn: (str: string) => string): string {
    return `${pc.gray(this.getTimestamp())} ${colorFn(pc.bold(`[Guardrail ${level}]`))}`;
  }

  debug(message: string, ...args: unknown[]): void {
    if (this.enabled) {
      console.debug(`${this.formatPrefix("DEBUG", pc.cyan)} ${message}`, ...args);
    }
  }

  info(message: string, ...args: unknown[]): void {
    if (this.enabled) {
      console.info(`${this.formatPrefix("INFO", pc.green)} ${message}`, ...args);
    }
  }

  warn(message: string, ...args: unknown[]): void {
    if (this.enabled) {
      console.warn(`${this.formatPrefix("WARN", pc.yellow)} ${message}`, ...args);
    }
  }

  error(message: string, ...args: unknown[]): void {
    if (this.enabled) {
      console.error(`${this.formatPrefix("ERROR", pc.red)} ${pc.bold(message)}`, ...args);
    }
  }
}

/**
 * No-op logger for when logging is disabled
 */
export class NoOpLogger implements Logger {
  debug(): void {}
  info(): void {}
  warn(): void {}
  error(): void {}
}
