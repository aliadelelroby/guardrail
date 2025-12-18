/**
 * NestJS Logger Adapter for Guardrail
 * Wraps NestJS LoggerService to implement Guardrail's Logger interface
 * @module adapters/nestjs/nestjs-logger-adapter
 */

import type { LoggerService } from "@nestjs/common";
import type { Logger } from "../../utils/logger";

/**
 * Adapter that wraps NestJS LoggerService to work with Guardrail's Logger interface
 */
export class NestJSLoggerAdapter implements Logger {
  constructor(
    private readonly nestLogger: LoggerService,
    private readonly context: string = "Guardrail"
  ) {}

  debug(message: string, ...args: unknown[]): void {
    if (this.nestLogger.debug) {
      this.nestLogger.debug(message, this.context, ...args);
    } else {
      this.nestLogger.log(message, this.context, ...args);
    }
  }

  info(message: string, ...args: unknown[]): void {
    this.nestLogger.log(message, this.context, ...args);
  }

  warn(message: string, ...args: unknown[]): void {
    this.nestLogger.warn(message, this.context, ...args);
  }

  error(message: string, ...args: unknown[]): void {
    this.nestLogger.error(message, this.context, ...args);
  }
}
