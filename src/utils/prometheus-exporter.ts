/**
 * Prometheus-compatible Metrics Exporter
 * Exports guardrail metrics in Prometheus format
 * @module utils/prometheus-exporter
 */

import type { MetricDataPoint, MetricsCollector } from "./metrics";

/**
 * Prometheus metric types
 */
export type PrometheusMetricType = "counter" | "gauge" | "histogram" | "summary";

/**
 * Prometheus metric configuration
 */
export interface PrometheusMetricConfig {
  name: string;
  help: string;
  type: PrometheusMetricType;
  labelNames?: string[];
  buckets?: number[]; // For histograms
}

/**
 * Histogram bucket data
 */
interface HistogramData {
  buckets: Map<number, number>;
  sum: number;
  count: number;
}

/**
 * Default histogram buckets for request duration (in ms)
 */
const DEFAULT_DURATION_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/**
 * Prometheus-compatible metrics collector
 */
export class PrometheusMetricsCollector implements MetricsCollector {
  private readonly counters = new Map<string, number>();
  private readonly gauges = new Map<string, number>();
  private readonly histograms = new Map<string, HistogramData>();
  private readonly metricConfigs = new Map<string, PrometheusMetricConfig>();
  private readonly prefix: string;
  private readonly defaultLabels: Record<string, string>;

  constructor(options: {
    prefix?: string;
    defaultLabels?: Record<string, string>;
  } = {}) {
    this.prefix = options.prefix || "guardrail_";
    this.defaultLabels = options.defaultLabels || {};

    // Register default metrics
    this.registerDefaultMetrics();
  }

  /**
   * Registers default guardrail metrics
   */
  private registerDefaultMetrics(): void {
    this.registerMetric({
      name: "requests_total",
      help: "Total number of requests processed",
      type: "counter",
      labelNames: ["conclusion", "rule", "reason"],
    });

    this.registerMetric({
      name: "request_duration_milliseconds",
      help: "Request processing duration in milliseconds",
      type: "histogram",
      buckets: DEFAULT_DURATION_BUCKETS,
    });

    this.registerMetric({
      name: "decisions_total",
      help: "Total number of decisions by conclusion",
      type: "counter",
      labelNames: ["conclusion", "reason"],
    });

    this.registerMetric({
      name: "rule_evaluations_total",
      help: "Total number of rule evaluations",
      type: "counter",
      labelNames: ["rule", "conclusion"],
    });

    this.registerMetric({
      name: "rule_duration_milliseconds",
      help: "Rule evaluation duration in milliseconds",
      type: "histogram",
      labelNames: ["rule"],
      buckets: [1, 2, 5, 10, 25, 50, 100, 250, 500],
    });

    this.registerMetric({
      name: "rate_limit_remaining",
      help: "Remaining rate limit quota",
      type: "gauge",
      labelNames: ["rule", "key"],
    });

    this.registerMetric({
      name: "ip_lookup_total",
      help: "Total IP lookups",
      type: "counter",
      labelNames: ["status"],
    });

    this.registerMetric({
      name: "storage_operations_total",
      help: "Total storage operations",
      type: "counter",
      labelNames: ["operation", "status"],
    });

    this.registerMetric({
      name: "circuit_breaker_state",
      help: "Circuit breaker state (0=closed, 1=open, 0.5=half-open)",
      type: "gauge",
      labelNames: ["name"],
    });

    this.registerMetric({
      name: "cache_hits_total",
      help: "Total cache hits",
      type: "counter",
    });

    this.registerMetric({
      name: "cache_misses_total",
      help: "Total cache misses",
      type: "counter",
    });

    this.registerMetric({
      name: "errors_total",
      help: "Total errors",
      type: "counter",
      labelNames: ["type"],
    });
  }

  /**
   * Registers a custom metric
   */
  registerMetric(config: PrometheusMetricConfig): void {
    this.metricConfigs.set(config.name, config);
  }

  /**
   * Gets the full metric name with prefix
   */
  private getFullName(name: string): string {
    return this.prefix + name;
  }

  /**
   * Generates a label key from name and labels
   */
  private getLabelKey(name: string, labels?: Record<string, string>): string {
    const merged = { ...this.defaultLabels, ...labels };
    if (!merged || Object.keys(merged).length === 0) {
      return name;
    }
    const labelStr = Object.entries(merged)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${this.escapeLabel(v)}"`)
      .join(",");
    return `${name}{${labelStr}}`;
  }

  /**
   * Escapes label values for Prometheus format
   */
  private escapeLabel(value: string): string {
    return value
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n");
  }

  increment(name: string, labels?: Record<string, string>): void {
    const key = this.getLabelKey(name, labels);
    this.counters.set(key, (this.counters.get(key) || 0) + 1);
  }

  gauge(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getLabelKey(name, labels);
    this.gauges.set(key, value);
  }

  histogram(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getLabelKey(name, labels);
    const config = this.metricConfigs.get(name);
    const buckets = config?.buckets || DEFAULT_DURATION_BUCKETS;

    let data = this.histograms.get(key);
    if (!data) {
      data = {
        buckets: new Map(buckets.map((b) => [b, 0])),
        sum: 0,
        count: 0,
      };
      this.histograms.set(key, data);
    }

    data.sum += value;
    data.count += 1;

    // Increment all buckets where value <= bucket threshold
    for (const bucket of buckets) {
      if (value <= bucket) {
        data.buckets.set(bucket, (data.buckets.get(bucket) || 0) + 1);
      }
    }
  }

  getMetrics(): MetricDataPoint[] {
    const metrics: MetricDataPoint[] = [];

    for (const [key, value] of this.counters.entries()) {
      metrics.push({
        name: key,
        value,
        timestamp: Date.now(),
      });
    }

    for (const [key, value] of this.gauges.entries()) {
      metrics.push({
        name: key,
        value,
        timestamp: Date.now(),
      });
    }

    return metrics;
  }

  reset(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
  }

  /**
   * Exports all metrics in Prometheus text format
   */
  export(): string {
    const lines: string[] = [];
    const exportedMetrics = new Set<string>();

    // Export counters
    for (const [key, value] of this.counters.entries()) {
      const baseName = this.extractBaseName(key);
      const fullName = this.getFullName(baseName);

      if (!exportedMetrics.has(baseName)) {
        const config = this.metricConfigs.get(baseName);
        if (config) {
          lines.push(`# HELP ${fullName} ${config.help}`);
          lines.push(`# TYPE ${fullName} counter`);
        }
        exportedMetrics.add(baseName);
      }

      const labels = this.extractLabels(key);
      const labelStr = labels ? `{${labels}}` : "";
      lines.push(`${fullName}${labelStr} ${value}`);
    }

    // Export gauges
    for (const [key, value] of this.gauges.entries()) {
      const baseName = this.extractBaseName(key);
      const fullName = this.getFullName(baseName);

      if (!exportedMetrics.has(baseName)) {
        const config = this.metricConfigs.get(baseName);
        if (config) {
          lines.push(`# HELP ${fullName} ${config.help}`);
          lines.push(`# TYPE ${fullName} gauge`);
        }
        exportedMetrics.add(baseName);
      }

      const labels = this.extractLabels(key);
      const labelStr = labels ? `{${labels}}` : "";
      lines.push(`${fullName}${labelStr} ${value}`);
    }

    // Export histograms
    for (const [key, data] of this.histograms.entries()) {
      const baseName = this.extractBaseName(key);
      const fullName = this.getFullName(baseName);

      if (!exportedMetrics.has(baseName)) {
        const config = this.metricConfigs.get(baseName);
        if (config) {
          lines.push(`# HELP ${fullName} ${config.help}`);
          lines.push(`# TYPE ${fullName} histogram`);
        }
        exportedMetrics.add(baseName);
      }

      const baseLabels = this.extractLabels(key);

      // Export bucket values
      let cumulativeCount = 0;
      const sortedBuckets = [...data.buckets.entries()].sort(([a], [b]) => a - b);
      for (const [bucket, count] of sortedBuckets) {
        cumulativeCount += count;
        const bucketLabel = baseLabels 
          ? `${baseLabels},le="${bucket}"`
          : `le="${bucket}"`;
        lines.push(`${fullName}_bucket{${bucketLabel}} ${cumulativeCount}`);
      }

      // Export +Inf bucket
      const infLabel = baseLabels ? `${baseLabels},le="+Inf"` : `le="+Inf"`;
      lines.push(`${fullName}_bucket{${infLabel}} ${data.count}`);

      // Export sum and count
      const labelStr = baseLabels ? `{${baseLabels}}` : "";
      lines.push(`${fullName}_sum${labelStr} ${data.sum}`);
      lines.push(`${fullName}_count${labelStr} ${data.count}`);
    }

    return lines.join("\n");
  }

  /**
   * Extracts base metric name from key
   */
  private extractBaseName(key: string): string {
    const braceIndex = key.indexOf("{");
    return braceIndex === -1 ? key : key.substring(0, braceIndex);
  }

  /**
   * Extracts labels from key
   */
  private extractLabels(key: string): string | null {
    const match = key.match(/\{(.+)\}/);
    return match ? match[1] : null;
  }

  /**
   * Creates an HTTP handler for /metrics endpoint
   */
  createHandler(): (req: Request) => Response {
    return () => {
      const body = this.export();
      return new Response(body, {
        headers: {
          "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
        },
      });
    };
  }
}

/**
 * StatsD-compatible metrics collector
 */
export class StatsDMetricsCollector implements MetricsCollector {
  private readonly host: string;
  private readonly port: number;
  private readonly prefix: string;
  private readonly buffer: string[] = [];
  private readonly flushInterval: number;
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: {
    host?: string;
    port?: number;
    prefix?: string;
    flushInterval?: number;
  } = {}) {
    this.host = options.host || "127.0.0.1";
    this.port = options.port || 8125;
    this.prefix = options.prefix || "guardrail.";
    this.flushInterval = options.flushInterval || 1000;
  }

  /**
   * Starts the flush timer
   */
  start(): void {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => this.flush(), this.flushInterval);
  }

  /**
   * Stops the flush timer
   */
  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    this.flush();
  }

  increment(name: string, labels?: Record<string, string>): void {
    const taggedName = this.formatName(name, labels);
    this.buffer.push(`${taggedName}:1|c`);
  }

  gauge(name: string, value: number, labels?: Record<string, string>): void {
    const taggedName = this.formatName(name, labels);
    this.buffer.push(`${taggedName}:${value}|g`);
  }

  histogram(name: string, value: number, labels?: Record<string, string>): void {
    const taggedName = this.formatName(name, labels);
    this.buffer.push(`${taggedName}:${value}|h`);
  }

  getMetrics(): MetricDataPoint[] {
    return [];
  }

  reset(): void {
    this.buffer.length = 0;
  }

  /**
   * Formats metric name with tags (DogStatsD format)
   */
  private formatName(name: string, labels?: Record<string, string>): string {
    let fullName = this.prefix + name;
    if (labels && Object.keys(labels).length > 0) {
      const tags = Object.entries(labels)
        .map(([k, v]) => `${k}:${v}`)
        .join(",");
      fullName += `|#${tags}`;
    }
    return fullName;
  }

  /**
   * Flushes buffered metrics (placeholder - actual UDP sending would require native module)
   */
  private flush(): void {
    if (this.buffer.length === 0) return;

    // In a real implementation, this would send via UDP
    // For now, we log to console in debug mode
    console.debug(`StatsD flush to ${this.host}:${this.port}:`, this.buffer.slice(0, 10));
    this.buffer.length = 0;
  }
}

/**
 * DataDog-compatible metrics collector (extends StatsD)
 */
export class DataDogMetricsCollector extends StatsDMetricsCollector {
  private readonly apiKey?: string;

  constructor(options: {
    host?: string;
    port?: number;
    prefix?: string;
    flushInterval?: number;
    apiKey?: string;
  } = {}) {
    super({
      host: options.host || "127.0.0.1",
      port: options.port || 8125,
      prefix: options.prefix || "guardrail.",
      flushInterval: options.flushInterval,
    });
    this.apiKey = options.apiKey;
  }

  /**
   * Sends metrics directly to DataDog API (bypasses DogStatsD)
   */
  async sendToAPI(metrics: MetricDataPoint[]): Promise<void> {
    if (!this.apiKey) {
      throw new Error("DataDog API key required for direct API submission");
    }

    const series = metrics.map((m) => ({
      metric: m.name,
      points: [[Math.floor((m.timestamp || Date.now()) / 1000), m.value]],
      tags: m.labels
        ? Object.entries(m.labels).map(([k, v]) => `${k}:${v}`)
        : [],
    }));

    const response = await fetch("https://api.datadoghq.com/api/v1/series", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "DD-API-KEY": this.apiKey,
      },
      body: JSON.stringify({ series }),
    });

    if (!response.ok) {
      throw new Error(`DataDog API error: ${response.status}`);
    }
  }
}
