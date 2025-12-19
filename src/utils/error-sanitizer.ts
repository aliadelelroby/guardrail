/**
 * Error sanitization utilities to prevent information disclosure
 * @module utils/error-sanitizer
 */

/**
 * Checks if we're in production mode
 */
function isProduction(): boolean {
  return process.env.NODE_ENV === "production";
}

/**
 * Sanitizes error messages to prevent information disclosure
 * @param error - Error object or message
 * @param includeDetails - Whether to include detailed error information (default: false in production)
 * @returns Sanitized error message
 */
export function sanitizeError(error: unknown, includeDetails: boolean = !isProduction()): string {
  if (error instanceof Error) {
    // In production, don't expose stack traces or internal paths
    if (isProduction() && !includeDetails) {
      // Return generic error message
      return "An error occurred. Please check your configuration and try again.";
    }

    // In development or when details are requested, include more info
    let message = error.message;

    // Remove file system paths
    message = message.replace(/\/[^\s]+/g, "[path]");

    // Remove absolute paths
    message = message.replace(/[A-Z]:\\[^\s]+/g, "[path]");

    // Remove user home directory references
    const homeDir = process.env.HOME || process.env.USERPROFILE || "";
    if (homeDir) {
      message = message.replace(
        new RegExp(homeDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"),
        "[home]"
      );
    }

    return message;
  }

  if (typeof error === "string") {
    // Sanitize string errors
    let message = error;
    message = message.replace(/\/[^\s]+/g, "[path]");
    message = message.replace(/[A-Z]:\\[^\s]+/g, "[path]");
    return message;
  }

  return "An unknown error occurred";
}

/**
 * Creates a safe error object for user-facing errors
 */
export function createSafeError(message: string, originalError?: unknown): Error {
  const safeMessage = sanitizeError(message, false);
  const error = new Error(safeMessage);
  if (originalError && !isProduction()) {
    // In development, preserve original error as a property
    (error as any).originalError = originalError;
  }
  return error;
}
