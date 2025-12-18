import { describe, it, expect, vi } from "vitest";
import { guardrailFastify } from "./fastify";

describe("guardrailFastify", () => {
  it("should provide shortcut factories", () => {
    expect(guardrailFastify.api).toBeDefined();
    expect(guardrailFastify.web).toBeDefined();
    expect(guardrailFastify.strict).toBeDefined();
  });

  it("should protect Fastify requests using preHandler hook", async () => {
    const hook = guardrailFastify.api();

    const request: any = {
      raw: {
        protocol: "https",
        get: () => "example.com",
        url: "/api",
        method: "GET",
        headers: { "user-agent": "Mozilla/5.0" },
      },
    };

    const reply: any = {
      header: vi.fn().mockReturnThis(),
      code: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    };

    await hook(request, reply);

    expect(request.guardrail).toBeDefined();
    expect(reply.header).toHaveBeenCalledWith("X-Guardrail-Id", expect.any(String));
  });
});
