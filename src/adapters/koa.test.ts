import { describe, it, expect, vi } from "vitest";
import { guardrailKoa } from "./koa";

describe("guardrailKoa", () => {
  it("should provide shortcut factories", () => {
    expect(guardrailKoa.api).toBeDefined();
    expect(guardrailKoa.web).toBeDefined();
    expect(guardrailKoa.strict).toBeDefined();
  });

  it("should protect Koa requests using middleware", async () => {
    const middleware = guardrailKoa.api();

    const ctx: any = {
      req: {
        protocol: "https",
        get: () => "example.com",
        url: "/api",
        method: "GET",
        headers: { "user-agent": "Mozilla/5.0" },
      },
      set: vi.fn(),
      state: {},
    };

    const next = vi.fn().mockResolvedValue(undefined);

    await middleware(ctx, next);

    expect(ctx.state.guardrail).toBeDefined();
    expect(ctx.set).toHaveBeenCalledWith("X-Guardrail-Id", expect.any(String));
    expect(next).toHaveBeenCalled();
  });
});
