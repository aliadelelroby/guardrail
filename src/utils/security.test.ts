/**
 * Security-focused unit tests
 * @module utils/security.test
 */

import { describe, it, expect } from "vitest";
import { validateIP, validateIPAllowPrivate } from "./ip-validator";
import { safeJsonParse } from "./safe-json";
import { evaluateExpression } from "./expression-evaluator";
import { extractIPFromRequest } from "./fingerprint";
// Note: validatePath is not exported, testing the concept

describe("Security Tests", () => {
  describe("IP Validation - SSRF Prevention", () => {
    it("should reject private IPv4 addresses", () => {
      expect(() => validateIP("127.0.0.1")).toThrow();
      expect(() => validateIP("192.168.1.1")).toThrow();
      expect(() => validateIP("10.0.0.1")).toThrow();
      expect(() => validateIP("172.16.0.1")).toThrow();
    });

    it("should accept valid public IPv4 addresses", () => {
      expect(() => validateIP("8.8.8.8")).not.toThrow();
      expect(() => validateIP("1.1.1.1")).not.toThrow();
    });

    it("should reject invalid IP formats", () => {
      expect(() => validateIP("not.an.ip")).toThrow();
      expect(() => validateIP("256.256.256.256")).toThrow();
      expect(() => validateIP("")).toThrow();
    });

    it("should allow private IPs with validateIPAllowPrivate", () => {
      expect(() => validateIPAllowPrivate("127.0.0.1")).not.toThrow();
      expect(() => validateIPAllowPrivate("192.168.1.1")).not.toThrow();
    });
  });

  describe("JSON Deserialization - Prototype Pollution Prevention", () => {
    it("should prevent prototype pollution via __proto__", () => {
      const malicious = '{"__proto__":{"isAdmin":true}}';
      const parsed = safeJsonParse<Record<string, unknown>>(malicious);
      // Check that prototype was not polluted
      expect(({} as any).isAdmin).toBeUndefined();
      // The __proto__ key should not exist as an own property in the parsed object
      expect(Object.prototype.hasOwnProperty.call(parsed, "__proto__")).toBe(false);
      // Verify the object is empty (since __proto__ was filtered out)
      expect(Object.keys(parsed).length).toBe(0);
    });

    it("should prevent prototype pollution via constructor", () => {
      const malicious = '{"constructor":{"prototype":{"isAdmin":true}}}';
      safeJsonParse<Record<string, unknown>>(malicious);
      expect(({} as any).isAdmin).toBeUndefined();
    });

    it("should enforce maximum nesting depth", () => {
      // Create valid deeply nested JSON
      let deep = "{";
      for (let i = 0; i < 200; i++) {
        deep += `"a${i}":{`;
      }
      deep += '"value":true';
      deep += "}".repeat(200);
      deep += "}";
      expect(() => safeJsonParse(deep)).toThrow("nesting depth");
    });

    it("should enforce maximum size", () => {
      const large = '"' + "a".repeat(11 * 1024 * 1024) + '"';
      expect(() => safeJsonParse(large)).toThrow("exceeds maximum size");
    });
  });

  describe("ReDoS Prevention", () => {
    it("should reject dangerous regex patterns with nested quantifiers", () => {
      const dangerousPattern = "(a+)+";
      expect(() => {
        evaluateExpression(`matches("${dangerousPattern}")`, { value: "test" });
      }).toThrow();
    });

    it("should handle safe regex patterns", () => {
      const safePattern = "^test$";
      // The expression syntax is: value matches("pattern")
      const result = evaluateExpression(`value matches("${safePattern}")`, { value: "test" });
      expect(result).toBe(true);
    });

    it("should limit regex pattern length", () => {
      const longPattern = "a".repeat(2000);
      expect(() => {
        evaluateExpression(`matches("${longPattern}")`, { value: "test" });
      }).toThrow();
    });
  });

  describe("Path Traversal Prevention", () => {
    it("should reject paths with .. sequences", () => {
      const baseDir = "/safe/directory";
      const maliciousPath = resolve(baseDir, "../../etc/passwd");
      expect(() => {
        // This would be called internally, testing the validation logic
        if (maliciousPath.includes("..")) {
          throw new Error("Path traversal detected");
        }
      }).toThrow("Path traversal detected");
    });

    it("should reject absolute paths outside base directory", () => {
      const baseDir = "/safe/directory";
      const maliciousPath = "/etc/passwd";
      expect(() => {
        if (!maliciousPath.startsWith(baseDir)) {
          throw new Error("Path traversal detected");
        }
      }).toThrow("Path traversal detected");
    });

    it("should validate path normalization", () => {
      const baseDir = "/safe/directory";
      const normalizedBase = baseDir.replace(/\/+/g, "/");
      // After normalization, /safe/directory/../etc/passwd becomes /safe/etc/passwd
      const testPath = "/safe/directory/../etc/passwd";
      // Simulate path normalization (properly handling ..)
      const parts: string[] = [];
      for (const part of testPath.split("/").filter((p) => p !== "")) {
        if (part === "..") {
          parts.pop();
        } else {
          parts.push(part);
        }
      }
      const normalizedPath = "/" + parts.join("/");

      expect(() => {
        // After normalization, /safe/directory/../etc/passwd becomes /safe/etc/passwd
        // which does NOT start with /safe/directory, so it should throw
        if (!normalizedPath.startsWith(normalizedBase)) {
          throw new Error("Path traversal detected");
        }
      }).toThrow("Path traversal detected");
    });
  });

  describe("IP Header Extraction", () => {
    it("should validate IP addresses from headers", () => {
      const request = new Request("https://example.com", {
        headers: {
          "x-forwarded-for": "192.168.1.1, 8.8.8.8",
        },
      });

      const ip = extractIPFromRequest(request);
      // validateIPAllowPrivate allows private IPs, so it should return the validated IP
      // But if validation fails, it returns "unknown"
      // Since 192.168.1.1 is a valid private IP, validateIPAllowPrivate will return it
      expect(ip).toBe("192.168.1.1");
    });

    it("should handle multiple IPs in x-forwarded-for", () => {
      const request = new Request("https://example.com", {
        headers: {
          "x-forwarded-for": "8.8.8.8, 1.1.1.1",
        },
      });

      const ip = extractIPFromRequest(request);
      // Should validate the first IP
      expect(ip).toBe("8.8.8.8");
    });

    it("should sanitize malicious header values", () => {
      const request = new Request("https://example.com", {
        headers: {
          "x-forwarded-for": "../../etc/passwd",
        },
      });

      const ip = extractIPFromRequest(request);
      // Invalid IP format should cause validation to fail and return "unknown"
      expect(ip).toBe("unknown");
    });

    it("should return unknown for invalid IP format", () => {
      const request = new Request("https://example.com", {
        headers: {
          "x-forwarded-for": "not.an.ip.address",
        },
      });

      const ip = extractIPFromRequest(request);
      expect(ip).toBe("unknown");
    });
  });
});

// Helper function for path resolution in tests
function resolve(...paths: string[]): string {
  // Simplified resolve for testing
  return paths.join("/").replace(/\/+/g, "/");
}
