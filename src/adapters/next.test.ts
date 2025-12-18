/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from "vitest";
import { guardrailNext, withGuardrail } from "./next";
import { detectBot } from "../rules/index";

describe("guardrailNext", () => {
  it("should provide middleware helper", async () => {
    const gn = guardrailNext.api();
    const middleware = gn.middleware();

    const request = {
      url: "https://example.com/api",
      method: "GET",
      headers: new Headers({ "user-agent": "Mozilla/5.0" }),
    };

    const response = await middleware(request as any);
    expect(response).toBeNull(); // null means continue
  });

  it("should return Response for denied requests in middleware", async () => {
    const gn = guardrailNext({
      rules: [detectBot({ allow: [] })],
    });
    const middleware = gn.middleware();

    const request = {
      url: "https://example.com/api",
      method: "GET",
      headers: new Headers({ "user-agent": "Googlebot" }),
    };

    const response = await middleware(request as any);
    expect(response).toBeInstanceOf(Response);
    expect(response?.status).toBe(403);
  });

  it("should wrap API routes with withGuardrail", async () => {
    const handler = async (req: any, res: any) => {
      res.json({ success: true });
    };

    const wrapped = withGuardrail(handler, { rules: [] });

    const req = {
      url: "https://example.com/api",
      method: "GET",
      headers: { "user-agent": "Mozilla/5.0" },
    };

    const res = {
      status: (code: number) => ({ json: (body: any) => ({ code, body }) }),
      setHeader: () => {},
      json: (body: any) => body,
    };

    await wrapped(req as any, res as any);
    // If it didn't throw/fail, it passed
  });
});
