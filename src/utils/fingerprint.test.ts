import { describe, it, expect } from "vitest";
import { generateFingerprint, extractIPFromRequest, extractUserAgent } from "./fingerprint";

describe("generateFingerprint", () => {
  it("should generate fingerprint from characteristics", () => {
    const fingerprint = generateFingerprint(
      ["userId", "ip.src"],
      { userId: "user123", "ip.src": "1.2.3.4" }
    );

    expect(fingerprint).toBe("userId:user123|ip.src:1.2.3.4");
  });

  it("should filter out undefined values", () => {
    const fingerprint = generateFingerprint(
      ["userId", "ip.src"],
      { userId: "user123", "ip.src": undefined }
    );

    expect(fingerprint).toBe("userId:user123");
  });

  it("should throw if no characteristics have values", () => {
    expect(() => {
      generateFingerprint(["userId"], { userId: undefined });
    }).toThrow();
  });
});

describe("extractIPFromRequest", () => {
  it("should extract IP from x-forwarded-for header", () => {
    const request = new Request("https://example.com", {
      headers: {
        "x-forwarded-for": "1.2.3.4, 5.6.7.8",
      },
    });

    const ip = extractIPFromRequest(request);

    expect(ip).toBe("1.2.3.4");
  });

  it("should extract IP from x-real-ip header", () => {
    const request = new Request("https://example.com", {
      headers: {
        "x-real-ip": "1.2.3.4",
      },
    });

    const ip = extractIPFromRequest(request);

    expect(ip).toBe("1.2.3.4");
  });

  it("should return unknown if no IP headers", () => {
    const request = new Request("https://example.com");
    const ip = extractIPFromRequest(request);

    expect(ip).toBe("unknown");
  });
});

describe("extractUserAgent", () => {
  it("should extract user agent from request", () => {
    const request = new Request("https://example.com", {
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const ua = extractUserAgent(request);

    expect(ua).toBe("Mozilla/5.0");
  });

  it("should return unknown if no user agent", () => {
    const request = new Request("https://example.com");
    const ua = extractUserAgent(request);

    expect(ua).toBe("unknown");
  });
});
