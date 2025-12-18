/**
 * Error types for Guardrail
 * @module errors
 */

/**
 * Base error class for all Guardrail errors
 */
export class GuardrailError extends Error {
  /**
   * Creates a new GuardrailError
   * @param message - Error message
   * @param cause - Optional cause error
   */
  constructor(
    message: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = "GuardrailError";
    Object.setPrototypeOf(this, GuardrailError.prototype);
  }
}

/**
 * Storage operation error
 */
export class StorageError extends GuardrailError {
  /**
   * Creates a new StorageError
   * @param message - Error message
   * @param operation - Storage operation that failed
   * @param cause - Optional cause error
   */
  constructor(
    message: string,
    public readonly operation: string,
    cause?: Error
  ) {
    super(message, cause);
    this.name = "StorageError";
    Object.setPrototypeOf(this, StorageError.prototype);
  }
}

/**
 * Rule evaluation error
 */
export class RuleEvaluationError extends GuardrailError {
  /**
   * Creates a new RuleEvaluationError
   * @param message - Error message
   * @param ruleType - Type of rule that failed
   * @param cause - Optional cause error
   */
  constructor(
    message: string,
    public readonly ruleType: string,
    cause?: Error
  ) {
    super(message, cause);
    this.name = "RuleEvaluationError";
    Object.setPrototypeOf(this, RuleEvaluationError.prototype);
  }
}

/**
 * Configuration error
 */
export class ConfigurationError extends GuardrailError {
  /**
   * Creates a new ConfigurationError
   * @param message - Error message
   * @param field - Configuration field that caused the error
   */
  constructor(
    message: string,
    public readonly field?: string
  ) {
    super(message);
    this.name = "ConfigurationError";
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/**
 * IP geolocation error
 */
export class IPGeolocationError extends GuardrailError {
  /**
   * Creates a new IPGeolocationError
   * @param message - Error message
   * @param ip - IP address that failed lookup
   * @param cause - Optional cause error
   */
  constructor(
    message: string,
    public readonly ip: string,
    cause?: Error
  ) {
    super(message, cause);
    this.name = "IPGeolocationError";
    Object.setPrototypeOf(this, IPGeolocationError.prototype);
  }
}

/**
 * Expression evaluation error
 */
export class ExpressionEvaluationError extends GuardrailError {
  /**
   * Creates a new ExpressionEvaluationError
   * @param message - Error message
   * @param expression - Expression that failed
   * @param cause - Optional cause error
   */
  constructor(
    message: string,
    public readonly expression: string,
    cause?: Error
  ) {
    super(message, cause);
    this.name = "ExpressionEvaluationError";
    Object.setPrototypeOf(this, ExpressionEvaluationError.prototype);
  }
}

/**
 * Circuit breaker error - indicates circuit is open
 */
export class CircuitBreakerError extends GuardrailError {
  /**
   * Creates a new CircuitBreakerError
   * @param service - Service name that circuit is open for
   */
  constructor(public readonly service: string) {
    super(`Circuit breaker is open for ${service}`);
    this.name = "CircuitBreakerError";
    Object.setPrototypeOf(this, CircuitBreakerError.prototype);
  }
}
