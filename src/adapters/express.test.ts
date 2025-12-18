/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, type Mock } from "vitest";
import { guardrailExpress } from "./express";
import { shield, detectBot, slidingWindow } from "../rules/index";
import type { Request, Response, NextFunction } from "express";
import type { Decision } from "../types/index";

interface MockRequest extends Partial<Request> {
  guardrail?: Decision;
}

interface MockResponse {
  status: Mock<[code: number], MockResponse>;
  json: Mock;
  set: Mock;
}

describe("guardrailExpress", () => {
  it("should provide shortcut factories", () => {
    expect(guardrailExpress.api).toBeDefined();
    expect(guardrailExpress.web).toBeDefined();
    expect(guardrailExpress.strict).toBeDefined();
  });

  it("should protect Express requests using middleware", async () => {
    const middleware = guardrailExpress.api();

    const req: any = {
      protocol: "https",
      get: (header: string) => (header === "host" ? "example.com" : undefined),
      originalUrl: "/api",
      method: "GET",
      headers: { "user-agent": "Mozilla/5.0" },
    };

    const res: any = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
      set: vi.fn(),
    };

    const next: NextFunction = vi.fn();

    await middleware(req as Request, res as Response, next);

    expect(next).toHaveBeenCalled();
    expect(req.guardrail).toBeDefined();
    expect(res.set).toHaveBeenCalledWith("X-Guardrail-Id", expect.any(String));
  });

  it("should return 403 for denied requests", async () => {
    const middleware = guardrailExpress({
      rules: [detectBot({ allow: [] })],
    });

    const req: any = {
      protocol: "https",
      get: () => "example.com",
      originalUrl: "/api",
      method: "GET",
      headers: { "user-agent": "Googlebot" },
    };

    const res: any = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
      set: vi.fn(),
    };

    const next: NextFunction = vi.fn();

    await middleware(req as Request, res as Response, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });
});
