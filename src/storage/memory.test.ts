import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "./memory";

describe("MemoryStorage", () => {
  let storage: MemoryStorage;

  beforeEach(() => {
    storage = new MemoryStorage();
  });

  it("should store and retrieve values", async () => {
    await storage.set("key1", "value1");
    const value = await storage.get("key1");

    expect(value).toBe("value1");
  });

  it("should return null for non-existent keys", async () => {
    const value = await storage.get("nonexistent");

    expect(value).toBeNull();
  });

  it("should increment values", async () => {
    await storage.set("counter", "5");
    const newValue = await storage.increment("counter", 3);

    expect(newValue).toBe(8);
    expect(await storage.get("counter")).toBe("8");
  });

  it("should increment from zero if key doesn't exist", async () => {
    const value = await storage.increment("newcounter", 5);

    expect(value).toBe(5);
  });

  it("should decrement values", async () => {
    await storage.set("counter", "10");
    const newValue = await storage.decrement("counter", 3);

    expect(newValue).toBe(7);
  });

  it("should delete keys", async () => {
    await storage.set("key1", "value1");
    await storage.delete("key1");

    const value = await storage.get("key1");
    expect(value).toBeNull();
  });

  it("should expire keys after TTL", async () => {
    await storage.set("key1", "value1", 100); // 100ms TTL

    expect(await storage.get("key1")).toBe("value1");

    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(await storage.get("key1")).toBeNull();
  });
});
