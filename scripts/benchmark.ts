/**
 * Performance benchmark for Guardrail core
 */

import { Guardrail } from "../src/index";
import { MemoryStorage } from "../src/storage/memory";

async function runBenchmark() {
  console.log("--- Guardrail Performance Benchmark ---");

  const storage = new MemoryStorage();
  const guardrail = new Guardrail({
    storage,
    debug: false,
    rules: [
      {
        type: "slidingWindow",
        mode: "LIVE",
        interval: "1m",
        max: 1000,
        by: ["ip.src"],
      },
    ],
  });

  const request = new Request("http://localhost/test", {
    headers: { "x-forwarded-for": "1.2.3.4" },
  });

  // Warmup
  for (let i = 0; i < 100; i++) {
    await guardrail.protect(request);
  }

  const iterations = 1000;
  const start = performance.now();

  for (let i = 0; i < iterations; i++) {
    await guardrail.protect(request);
  }

  const end = performance.now();
  const total = end - start;
  const avg = total / iterations;

  console.log(`Iterations: ${iterations}`);
  console.log(`Total Time: ${total.toFixed(2)}ms`);
  console.log(`Avg Time per Request: ${avg.toFixed(4)}ms`);
  console.log(`Requests per Second: ${(1000 / avg).toFixed(0)}`);

  process.exit(0);
}

runBenchmark().catch(console.error);
