/**
 * Type definitions for Nest.js adapter
 * @module adapters/nestjs/types
 */

/**
 * Nest.js request interface
 * Compatible with Express request used by Nest.js
 */
export interface NestRequest {
  protocol?: string;
  method: string;
  originalUrl?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  get?: (name: string) => string | undefined;
}

/**
 * Nest.js response interface
 */
export interface NestResponse {
  status: (code: number) => NestResponse;
  json: (body: unknown) => NestResponse;
  set?: (name: string, value: string) => NestResponse;
  header?: (name: string, value: string) => NestResponse;
}
