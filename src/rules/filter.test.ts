import { describe, it, expect } from "vitest";
import { FilterRule } from "./filter";
import { filter } from "./index";
import type { IPInfo } from "../../types/index";

describe("FilterRule", () => {
  const mockIPInfo: IPInfo = {
    country: "US",
    region: "California",
    city: "San Francisco",
    isVpn: false,
    isProxy: false,
  };

  it("should allow requests matching allow expression", async () => {
    const rule = new FilterRule(
      filter({
        allow: ['ip.src.country eq "US"'],
      })
    );

    const request = new Request("https://example.com/api", {
      headers: {
        "x-forwarded-for": "1.2.3.4",
      },
    });

    const result = await rule.evaluate(request, mockIPInfo, {
      "ip.src": "1.2.3.4",
    });

    expect(result.conclusion).toBe("ALLOW");
  });

  it("should deny requests not matching allow expression", async () => {
    const rule = new FilterRule(
      filter({
        allow: ['ip.src.country eq "US"'],
      })
    );

    const request = new Request("https://example.com/api");
    const ipInfo: IPInfo = { country: "CA" };

    const result = await rule.evaluate(request, ipInfo, {
      "ip.src": "1.2.3.4",
    });

    expect(result.conclusion).toBe("DENY");
    expect(result.reason).toBe("FILTER");
  });

  it("should deny requests matching deny expression", async () => {
    const rule = new FilterRule(
      filter({
        deny: ['ip.src.country ne "US"'],
      })
    );

    const request = new Request("https://example.com/api");
    const ipInfo: IPInfo = { country: "CA" };

    const result = await rule.evaluate(request, ipInfo, {
      "ip.src": "1.2.3.4",
    });

    expect(result.conclusion).toBe("DENY");
    expect(result.reason).toBe("FILTER");
  });

  it("should allow in DRY_RUN mode", async () => {
    const rule = new FilterRule(
      filter({
        deny: ['ip.src.country ne "US"'],
        mode: "DRY_RUN",
      })
    );

    const request = new Request("https://example.com/api");
    const ipInfo: IPInfo = { country: "CA" };

    const result = await rule.evaluate(request, ipInfo, {
      "ip.src": "1.2.3.4",
    });

    expect(result.conclusion).toBe("ALLOW");
  });
});
