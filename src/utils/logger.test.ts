import { describe, it, expect, vi } from "vitest";
import { ConsoleLogger } from "./logger";

describe("ConsoleLogger", () => {
  it("should log messages when enabled", () => {
    const spy = vi.spyOn(console, "info").mockImplementation(() => {});
    const logger = new ConsoleLogger(true);

    logger.info("test message");

    expect(spy).toHaveBeenCalled();
    expect(spy.mock.calls[0][0]).toContain("[Guardrail INFO]");
    expect(spy.mock.calls[0][0]).toContain("test message");

    spy.mockRestore();
  });

  it("should not log messages when disabled", () => {
    const spy = vi.spyOn(console, "info").mockImplementation(() => {});
    const logger = new ConsoleLogger(false);

    logger.info("test message");

    expect(spy).not.toHaveBeenCalled();

    spy.mockRestore();
  });
});
