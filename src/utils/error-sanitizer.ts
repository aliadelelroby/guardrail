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

    // Remove file system paths (Unix-style)
    message = message.replace(/\/[^\s"']+/g, "[path]");
    // Remove paths in quotes
    message = message.replace(/["']\/[^"']+["']/g, '"[path]"');

    // Remove absolute paths (Windows-style)
    message = message.replace(/[A-Z]:\\[^\s"']+/gi, "[path]");
    // Remove Windows paths in quotes
    message = message.replace(/["'][A-Z]:\\[^"']+["']/gi, '"[path]"');

    // Remove UNC paths (\\server\share)
    message = message.replace(/\\\\[^\s"']+/g, "[path]");

    // Remove user home directory references
    const homeDir = process.env.HOME || process.env.USERPROFILE || "";
    if (homeDir) {
      const escapedHomeDir = homeDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      message = message.replace(new RegExp(escapedHomeDir, "gi"), "[home]");
    }

    // Remove common sensitive patterns
    // API keys, tokens
    message = message.replace(
      /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][\s:=]+[A-Za-z0-9_-]{20,}/g,
      "[api-key]"
    );
    message = message.replace(/[Tt][Oo][Kk][Ee][Nn][\s:=]+[A-Za-z0-9_-]{20,}/g, "[token]");
    message = message.replace(/[Ss][Ee][Cc][Rr][Ee][Tt][\s:=]+[A-Za-z0-9_-]{20,}/g, "[secret]");

    // Email addresses
    message = message.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/g, "[email]");

    // IP addresses (but keep localhost/127.0.0.1 for debugging)
    message = message.replace(
      /\b(?!(?:127\.0\.0\.1|localhost)\b)(?:\d{1,3}\.){3}\d{1,3}\b/g,
      "[ip]"
    );

    // URLs with credentials
    message = message.replace(/https?:\/\/[^:\s]+:[^@\s]+@[^\s]+/g, "[url-with-credentials]");

    return message;
  }

  if (typeof error === "string") {
    // Sanitize string errors using the same patterns
    let message = error;

    // Remove file system paths (Unix-style)
    message = message.replace(/\/[^\s"']+/g, "[path]");
    message = message.replace(/["']\/[^"']+["']/g, '"[path]"');

    // Remove absolute paths (Windows-style)
    message = message.replace(/[A-Z]:\\[^\s"']+/gi, "[path]");
    message = message.replace(/["'][A-Z]:\\[^"']+["']/gi, '"[path]"');

    // Remove UNC paths
    message = message.replace(/\\\\[^\s"']+/g, "[path]");

    // Remove user home directory references
    const homeDir = process.env.HOME || process.env.USERPROFILE || "";
    if (homeDir) {
      const escapedHomeDir = homeDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      message = message.replace(new RegExp(escapedHomeDir, "gi"), "[home]");
    }

    // Remove sensitive patterns
    message = message.replace(
      /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][\s:=]+[A-Za-z0-9_-]{20,}/g,
      "[api-key]"
    );
    message = message.replace(/[Tt][Oo][Kk][Ee][Nn][\s:=]+[A-Za-z0-9_-]{20,}/g, "[token]");
    message = message.replace(/[Ss][Ee][Cc][Rr][Ee][Tt][\s:=]+[A-Za-z0-9_-]{20,}/g, "[secret]");
    message = message.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/g, "[email]");
    message = message.replace(
      /\b(?!(?:127\.0\.0\.1|localhost)\b)(?:\d{1,3}\.){3}\d{1,3}\b/g,
      "[ip]"
    );
    message = message.replace(/https?:\/\/[^:\s]+:[^@\s]+@[^\s]+/g, "[url-with-credentials]");

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
