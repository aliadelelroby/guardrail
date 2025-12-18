/**
 * Circuit breaker pattern implementation for resilient operations
 * @module utils/circuit-breaker
 */

import { CircuitBreakerError } from "../errors/index";

/**
 * Circuit breaker states
 */
export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  /** Failure threshold before opening circuit */
  failureThreshold: number;
  /** Time in milliseconds to wait before attempting half-open */
  resetTimeout: number;
  /** Success threshold in half-open state to close circuit */
  successThreshold: number;
  /** Time window in milliseconds for tracking failures */
  timeoutWindow: number;
  /** Operation timeout in milliseconds (default: no timeout) */
  operationTimeout?: number;
}

/**
 * Default circuit breaker configuration
 */
const DEFAULT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  resetTimeout: 60000,
  successThreshold: 2,
  timeoutWindow: 60000,
  operationTimeout: undefined, // No timeout by default
};

/**
 * Circuit breaker implementation
 */
export class CircuitBreaker {
  private state: CircuitState = "CLOSED";
  private failures: number[] = [];
  private successes = 0;
  private lastFailureTime?: number;
  private readonly config: CircuitBreakerConfig;

  /**
   * Creates a new circuit breaker
   * @param config - Circuit breaker configuration
   */
  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Executes a function with circuit breaker protection
   * @param fn - Function to execute
   * @param serviceName - Service name for error messages
   * @returns Promise resolving to function result
   * @throws {CircuitBreakerError} If circuit is open
   * @throws {Error} If operation times out (if operationTimeout is configured)
   */
  async execute<T>(fn: () => Promise<T>, serviceName: string): Promise<T> {
    if (this.state === "OPEN") {
      if (this.shouldAttemptReset()) {
        this.state = "HALF_OPEN";
        this.successes = 0;
      } else {
        throw new CircuitBreakerError(serviceName);
      }
    }

    try {
      let result: T;

      // Apply timeout if configured
      if (this.config.operationTimeout && this.config.operationTimeout > 0) {
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(
            () =>
              reject(
                new Error(
                  `Circuit breaker operation timeout after ${this.config.operationTimeout}ms for ${serviceName}`
                )
              ),
            this.config.operationTimeout!
          );
        });

        result = await Promise.race([Promise.resolve(fn()), timeoutPromise]);
      } else {
        result = await fn();
      }

      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Records a successful operation
   */
  private onSuccess(): void {
    this.cleanOldFailures();

    if (this.state === "HALF_OPEN") {
      this.successes++;
      if (this.successes >= this.config.successThreshold) {
        this.state = "CLOSED";
        this.failures = [];
        this.successes = 0;
      }
    } else {
      this.failures = [];
    }
  }

  /**
   * Records a failed operation
   */
  private onFailure(): void {
    const now = Date.now();
    this.cleanOldFailures();
    this.failures.push(now);

    // Optimization: Keep only necessary history
    if (this.failures.length > this.config.failureThreshold) {
      this.failures = this.failures.slice(-this.config.failureThreshold);
    }

    this.lastFailureTime = now;

    if (this.state === "HALF_OPEN") {
      this.state = "OPEN";
      this.successes = 0;
    } else if (this.failures.length >= this.config.failureThreshold) {
      this.state = "OPEN";
    }
  }

  /**
   * Checks if circuit should attempt reset
   */
  private shouldAttemptReset(): boolean {
    if (!this.lastFailureTime) {
      return false;
    }
    return Date.now() - this.lastFailureTime >= this.config.resetTimeout;
  }

  /**
   * Removes failures outside the timeout window
   */
  private cleanOldFailures(): void {
    const now = Date.now();
    this.failures = this.failures.filter((time) => now - time < this.config.timeoutWindow);
  }

  /**
   * Gets current circuit state
   */
  getState(): CircuitState {
    return this.state;
  }

  /**
   * Manually resets the circuit breaker
   */
  reset(): void {
    this.state = "CLOSED";
    this.failures = [];
    this.successes = 0;
    this.lastFailureTime = undefined;
  }
}
