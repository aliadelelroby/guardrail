<p align="center">
  <img src="https://raw.githubusercontent.com/aliadelelroby/guardrail/main/docs/logo.svg" alt="Guardrail Logo" width="80" height="80">
</p>

<h1 align="center">Guardrail</h1>

<p align="center">
  <strong>The open-source security and rate limiting toolkit for modern applications</strong>
</p>

<p align="center">
  <a href="https://github.com/aliadelelroby/guardrail">Documentation</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="https://github.com/aliadelelroby/guardrail/issues">Report Bug</a>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/@guardrail-dev/core?style=flat-square&color=171717" alt="npm version">
  <img src="https://img.shields.io/npm/dm/@guardrail-dev/core?style=flat-square&color=171717" alt="npm downloads">
  <img src="https://img.shields.io/github/license/aliadelelroby/guardrail?style=flat-square&color=171717" alt="license">
</p>

---

## Why Guardrail?

Guardrail is a **100% open-source** alternative to Arcjet. It runs entirely on your infrastructure with no vendor lock-in, no usage-based pricing, and no data leaving your servers.

|                  | Proprietary Solutions | **Guardrail**       |
| ---------------- | --------------------- | ------------------- |
| **Source Code**  | Closed                | MIT Licensed        |
| **Deployment**   | Cloud only            | Self-hosted         |
| **Pricing**      | Usage-based           | Free                |
| **Data Privacy** | Third-party servers   | Your infrastructure |

## Features

- **Zero-Config** — Get started instantly with built-in presets and auto-discovery
- **Rate Limiting** — Token bucket & sliding window algorithms with atomic Redis operations
- **Bot Detection** — Multi-signal detection including User-Agent, headers, and behavioral analysis
- **IP Intelligence** — Pluggable providers (MaxMind, IPinfo, IPQualityScore) with VPN/proxy detection
- **Email Validation** — Block disposable (500+ domains), free, role-based, and invalid emails
- **Attack Protection** — OWASP-compliant detection for SQL injection, XSS, command injection, XXE, and more
- **Framework Support** — Next.js, Express.js, Nest.js, Fastify & Koa adapters
- **Observability** — Prometheus, StatsD, and DataDog metrics integration with pretty-printed logs
- **Circuit Breaker** — Resilient storage and service operations with automatic recovery

## Installation

```bash
npm install @guardrail-dev/core
```

## Quick Start (Zero Config)

Guardrail is designed to be developer-first. You can start protecting your app with literally one line of code.

```typescript
import { guardrail } from "@guardrail-dev/core";

// 1. Zero-config (uses API preset + auto-detects Redis from environment)
const gr = guardrail();

export async function POST(req: Request) {
  const decision = await gr.protect(req);
  if (decision.isDenied()) return new Response("Forbidden", { status: 403 });
  return new Response("OK");
}
```

## Presets

Apply full security profiles instantly using semantic presets:

- **`GuardrailPresets.api()`**: Standard protection for APIs (Rate limit: 100/min, Block generic bots)
- **`GuardrailPresets.web()`**: Optimized for web apps (Rate limit: 1000/min, Allow search engines)
- **`GuardrailPresets.strict()`**: High security mode (Rate limit: 10/min, Block all bots, Fail closed)
- **`GuardrailPresets.auth()`**: Login protection (Rate limit: 10/min, prevent brute force)
- **`GuardrailPresets.payment()`**: Payment security (Rate limit: 20/min, strict email validation)
- **`GuardrailPresets.ai()`**: AI Quota control (Token bucket throttling, prevent scraping)

## Framework Integration

### Nest.js (Ultimate Decorators)

Guardrail provides a declarative, decorator-first experience for NestJS.

```typescript
// app.module.ts
@Module({
  imports: [
    GuardrailModule.forRoot({
      autoProtect: true, // Automatically protect all routes!
      useGuard: true,
    }),
  ],
})
export class AppModule {}

// orders.controller.ts
@Controller("orders")
export class OrdersController {
  @Post()
  @RateLimit({ max: 5, interval: "1m" })
  @Shield()
  @GuardrailVPNBlock()
  async create(@Decision() decision: Decision) {
    return { id: "123" };
  }
}
```

### Express.js

Simple middleware factories with auto-handling responses.

```typescript
import { guardrailExpress } from "@guardrail-dev/core/express";

// One-liner API protection
app.use(guardrailExpress.api());

// Route-specific with custom rules
app.post("/login", guardrailExpress.auth({ debug: true }));
```

### Next.js

Seamless integration for Middleware and API Routes.

```typescript
// middleware.ts
export const middleware = guardrailNext.api().middleware();

// app/api/data/route.ts
export default withGuardrail(async (req, res) => {
  // Secured automatically
});
```

### Fastify & Koa

Consistent APIs for every major framework.

```typescript
// Fastify
fastify.addHook("preHandler", guardrailFastify.api());

// Koa
app.use(guardrailKoa.web());
```

## Auto-Discovery

Guardrail automatically configures itself based on your environment:

- **Storage**: Automatically connects to Redis if `REDIS_URL` or `UPSTASH_REDIS_REST_URL` is found.
- **IP Intelligence**: Uses high-performance fallback chain by default.
- **Logging**: Pretty-prints security audits in development mode.

## Rules

### Rate Limiting

```typescript
import { slidingWindow, tokenBucket } from "@guardrail-dev/core";

// Sliding window - simple request counting
slidingWindow({
  interval: "10m",
  max: 100,
});

// Token bucket - for AI quota control
tokenBucket({
  characteristics: ["userId"],
  refillRate: 2000,
  interval: "1h",
  capacity: 5000,
});
```

### Bot Detection

```typescript
import { detectBot } from "@guardrail-dev/core";

// Basic detection (User-Agent only)
detectBot({ allow: [] }); // Block all bots

// Advanced detection (headers, fingerprinting, behavioral analysis)
detectBot({
  allow: ["Googlebot"],
  analyzeHeaders: true,
  confidenceThreshold: 70,
  validateFingerprint: true,
});
```

### Shield (Attack Protection)

```typescript
import { shield } from "@guardrail-dev/core";

// Basic protection
shield();
shield({ mode: "DRY_RUN" }); // Test without blocking

// Enhanced protection with category selection
shield({
  categories: ["sql-injection", "xss", "command-injection", "path-traversal", "xxe"],
  scanBody: true,
  scanHeaders: true,
  logMatches: true,
});
```

### Email Validation

```typescript
import { validateEmail } from "@guardrail-dev/core";

// Basic validation
validateEmail({
  block: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS", "FREE"],
});

// Enhanced validation with typo detection and role-based blocking
validateEmail({
  block: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS", "ROLE_BASED", "TYPO_DOMAIN"],
  detectTypos: true,
  customDisposableDomains: ["custom-temp-domain.com"],
});
```

### Filter Rules

```typescript
import { filter } from "@guardrail-dev/core";

filter({
  deny: [
    'ip.src.country ne "US"', // Block non-US traffic
    "ip.src.vpn == true", // Block VPN users
  ],
});
```

## IP Intelligence

### Using Built-in Provider (Free APIs)

```typescript
const decision = await gr.protect(req);

// Geolocation
console.log(decision.ip.country); // "US"
console.log(decision.ip.countryName); // "United States"
console.log(decision.ip.city); // "San Francisco"

// Network detection
console.log(decision.ip.isVpn()); // true/false
console.log(decision.ip.isProxy()); // true/false
console.log(decision.ip.isHosting()); // true/false
```

### Using Premium IP Providers

For production use, we recommend using premium IP intelligence providers:

```typescript
import {
  guardrail,
  MaxMindProvider,
  IPinfoProvider,
  FallbackIPProvider,
} from "@guardrail-dev/core";

// MaxMind GeoIP2
const gr = guardrail({
  ipService: new MaxMindProvider({
    accountId: process.env.MAXMIND_ACCOUNT_ID!,
    licenseKey: process.env.MAXMIND_LICENSE_KEY!,
    serviceType: "insights", // or "city", "country"
  }),
  rules: [
    /* ... */
  ],
});

// IPinfo.io
const gr = guardrail({
  ipService: new IPinfoProvider({
    token: process.env.IPINFO_TOKEN!,
  }),
  rules: [
    /* ... */
  ],
});

// Fallback chain (tries each until success)
const gr = guardrail({
  ipService: new FallbackIPProvider([
    new MaxMindProvider({ accountId: "...", licenseKey: "..." }),
    new IPinfoProvider({ token: "..." }),
  ]),
  rules: [
    /* ... */
  ],
});
```

### VPN/Proxy Detection

```typescript
import { VPNProxyDetection } from "@guardrail-dev/core";

const vpnDetector = new VPNProxyDetection({
  enableHeuristicDetection: true,
  confidenceThreshold: 50,
  customVPNProviders: ["my-internal-vpn"],
});

// Get detection counts
console.log(vpnDetector.getProviderCounts());
// { vpn: 100+, proxy: 50+, datacenter: 100+ }
```

## Storage Backends

### Memory Storage (Single Instance)

```typescript
import { guardrail, MemoryStorage } from "@guardrail-dev/core";

const gr = guardrail({
  storage: new MemoryStorage(10000), // Max 10k entries
  rules: [
    /* ... */
  ],
});
```

> ⚠️ **Note**: Memory storage does not sync across Node.js cluster workers or multiple instances. Use Redis for distributed deployments.

### Redis Storage (Distributed)

```typescript
import { guardrail, RedisStorage, AtomicRedisStorage } from "@guardrail-dev/core";

// Basic Redis storage
const gr = guardrail({
  storage: new RedisStorage(process.env.REDIS_URL),
  rules: [
    /* ... */
  ],
});

// Atomic Redis storage (recommended for high concurrency)
const gr = guardrail({
  storage: new AtomicRedisStorage({
    redis: process.env.REDIS_URL,
    keyPrefix: "guardrail:",
  }),
  rules: [
    /* ... */
  ],
});
```

The `AtomicRedisStorage` uses Lua scripts for race-condition-free rate limiting operations.

## Observability

### Prometheus Metrics

```typescript
import { guardrail, PrometheusMetricsCollector } from "@guardrail-dev/core";

const metrics = new PrometheusMetricsCollector({
  prefix: "guardrail_",
  defaultLabels: { service: "my-api" },
});

// Use with guardrail
const gr = guardrail({
  rules: [
    /* ... */
  ],
  debug: true,
});

// Expose /metrics endpoint
app.get("/metrics", (req, res) => {
  res.set("Content-Type", "text/plain");
  res.send(metrics.export());
});
```

### StatsD / DataDog

```typescript
import { StatsDMetricsCollector, DataDogMetricsCollector } from "@guardrail-dev/core";

// StatsD
const statsD = new StatsDMetricsCollector({
  host: "127.0.0.1",
  port: 8125,
  prefix: "guardrail.",
});
statsD.start();

// DataDog (with API support)
const datadog = new DataDogMetricsCollector({
  host: "127.0.0.1",
  port: 8125,
  apiKey: process.env.DD_API_KEY,
});
```

### Events

```typescript
const gr = guardrail({
  rules: [
    /* ... */
  ],
  debug: true,
});

gr.on("decision.denied", (event) => {
  console.log("Denied:", event.decision);
});

gr.on("rule.evaluate", (event) => {
  console.log("Evaluating:", event.ruleType);
});

gr.on("storage.error", (event) => {
  console.error("Storage error:", event.error);
});
```

## Configuration

```typescript
const gr = guardrail({
  rules: [
    /* ... */
  ],

  // Error handling
  errorHandling: "FAIL_CLOSED", // or "FAIL_OPEN" (default)

  // Evaluation strategy
  evaluationStrategy: "PARALLEL", // or "SEQUENTIAL", "SHORT_CIRCUIT"

  // Debug mode
  debug: true,

  // Whitelist & Blacklist
  whitelist: {
    ips: ["1.2.3.4"],
    userIds: ["admin"],
    countries: ["US", "CA"],
  },
  blacklist: {
    ips: ["5.6.7.8"],
    countries: ["XX"],
  },
});
```

## Testing

```typescript
import { createTestGuardrail } from "@guardrail-dev/core/testing";
import { shield, slidingWindow } from "@guardrail-dev/core";

const { guardrail, ipService } = createTestGuardrail({
  rules: [shield(), slidingWindow({ interval: "1m", max: 100 })],
});

// Mock IP data
ipService.setIP("1.2.3.4", {
  country: "US",
  countryName: "United States",
});

const decision = await guardrail.protect(req);
```

## Known Limitations

### IP Geolocation

- **Default provider uses free APIs** with rate limits (ipapi.co: 1000/day, ip-api.com: 45/min)
- **Recommendation**: Use `MaxMindProvider`, `IPinfoProvider`, or `IPQualityScoreProvider` for production

### VPN/Proxy Detection

- Detection is based on ASN name matching against a comprehensive (100+) but not exhaustive list
- **Recommendation**: Use `IPQualityScoreProvider` for advanced fraud detection

### Bot Detection

- Basic detection uses User-Agent matching only
- **Recommendation**: Use `detectBot()` with configuration for header analysis and behavioral signals
- Client-side fingerprinting requires a separate implementation

### Rate Limiting

- `MemoryStorage` does not sync across Node.js cluster workers
- **Recommendation**: Use `AtomicRedisStorage` for distributed deployments

### Attack Protection

- Guardrail is **not a replacement** for enterprise WAF solutions (Cloudflare, AWS WAF)
- Use `shield()` with configuration for comprehensive OWASP coverage

## Contributing

We welcome contributions. Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT © Ali Adel Elroby
