/**
 * Nest.js Interceptor for Guardrail protection
 * @module adapters/nestjs
 */

import {
  Injectable,
  SetMetadata,
  type NestInterceptor,
  type ExecutionContext,
  type CallHandler,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable, type Observer } from "rxjs";
import { tap } from "rxjs/operators";
import { Guardrail } from "../../core/guardrail";
import type { ProtectOptions, Decision } from "../../types/index";
import type { NestRequest } from "./types";

/**
 * Metadata key for guardrail interceptor options
 */
export const GUARDRAIL_INTERCEPTOR_OPTIONS = "guardrail:interceptor:options";

/**
 * Decorator to set guardrail interceptor options
 * @param options - Protection options
 */
export const GuardrailInterceptorOptions = (options: ProtectOptions) =>
  SetMetadata(GUARDRAIL_INTERCEPTOR_OPTIONS, options);

/**
 * Guardrail interceptor for Nest.js
 * Automatically protects requests and attaches decision to request object
 */
@Injectable()
export class GuardrailInterceptor implements NestInterceptor {
  constructor(
    private readonly guardrail: Guardrail,
    private readonly reflector: Reflector
  ) {}

  /**
   * Intercepts the request
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<NestRequest>();
    const options =
      this.reflector.get<ProtectOptions>(GUARDRAIL_INTERCEPTOR_OPTIONS, context.getHandler()) ||
      this.reflector.get<ProtectOptions>(GUARDRAIL_INTERCEPTOR_OPTIONS, context.getClass()) ||
      {};

    const webRequest = this.createWebRequest(request);

    return new Observable((observer: Observer<unknown>) => {
      this.guardrail
        .protect(webRequest, options)
        .then((decision: Decision) => {
          (request as NestRequest & { guardrail?: Decision }).guardrail = decision;
          next
            .handle()
            .pipe(
              tap({
                next: (value: unknown) => observer.next(value),
                error: (err: Error) => observer.error(err),
                complete: () => observer.complete(),
              })
            )
            .subscribe(observer);
        })
        .catch((error: Error) => {
          observer.error(error);
        });
    });
  }

  /**
   * Creates a Web API Request from Nest.js request
   */
  private createWebRequest(request: NestRequest): Request {
    const protocol = request.protocol || "http";
    const host =
      request.get?.("host") || (request.headers.host as string | undefined) || "localhost";
    const url = request.originalUrl || request.url || "/";
    const fullUrl = `${protocol}://${host}${url}`;

    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      if (value !== undefined) {
        headers[key] = Array.isArray(value) ? value.join(", ") : value;
      }
    }

    return new Request(fullUrl, {
      method: request.method,
      headers,
      body:
        request.method !== "GET" && request.method !== "HEAD"
          ? JSON.stringify(request.body)
          : undefined,
    });
  }
}
