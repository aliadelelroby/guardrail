/**
 * Middleware system for Guardrail
 * @module utils/middleware
 */

import type { Decision, ProtectOptions } from "../types/index";

/**
 * Middleware context
 */
export interface MiddlewareContext {
  request: Request;
  options: ProtectOptions;
  decision?: Decision;
}

/**
 * Middleware function type
 */
export type Middleware = (context: MiddlewareContext, next: () => Promise<void>) => Promise<void>;

/**
 * Middleware chain executor
 */
export class MiddlewareChain {
  private middlewares: Middleware[] = [];

  /**
   * Adds a middleware to the chain
   * @param middleware - Middleware function
   */
  use(middleware: Middleware): void {
    this.middlewares.push(middleware);
  }

  /**
   * Executes the middleware chain
   * @param context - Middleware context
   */
  async execute(context: MiddlewareContext): Promise<void> {
    let index = 0;

    const next = async (): Promise<void> => {
      if (index < this.middlewares.length) {
        const middleware = this.middlewares[index++];
        await middleware(context, next);
      }
    };

    await next();
  }

  /**
   * Clears all middlewares from the chain
   */
  clear(): void {
    this.middlewares = [];
  }
}
