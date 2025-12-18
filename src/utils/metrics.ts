/**
 * Metrics and observability system
 * @module utils/metrics
 */

/**
 * Metric types
 */
export type MetricType = "counter" | "gauge" | "histogram" | "summary";

/**
 * Metric data point
 */
export interface MetricDataPoint {
  name: string;
  value: number;
  labels?: Record<string, string>;
  timestamp?: number;
}

/**
 * Metrics collector interface
 */
export interface MetricsCollector {
  /**
   * Increments a counter metric
   */
  increment(name: string, labels?: Record<string, string>): void;

  /**
   * Sets a gauge metric value
   */
  gauge(name: string, value: number, labels?: Record<string, string>): void;

  /**
   * Records a histogram value
   */
  histogram(name: string, value: number, labels?: Record<string, string>): void;

  /**
   * Gets all collected metrics
   */
  getMetrics(): MetricDataPoint[];

  /**
   * Resets all metrics
   */
  reset(): void;
}

/**
 * In-memory metrics collector
 */
export class InMemoryMetricsCollector implements MetricsCollector {
  private metrics: Map<string, MetricDataPoint> = new Map();

  /**
   * Creates a metric key from name and labels
   */
  private getKey(name: string, labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) {
      return name;
    }
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(",");
    return `${name}{${labelStr}}`;
  }

  increment(name: string, labels?: Record<string, string>): void {
    const key = this.getKey(name, labels);
    const existing = this.metrics.get(key);
    if (existing) {
      existing.value += 1;
    } else {
      this.metrics.set(key, {
        name,
        value: 1,
        labels,
        timestamp: Date.now(),
      });
    }
  }

  gauge(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getKey(name, labels);
    this.metrics.set(key, {
      name,
      value,
      labels,
      timestamp: Date.now(),
    });
  }

  histogram(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getKey(name, labels);
    const existing = this.metrics.get(key);
    if (existing) {
      existing.value = Math.max(existing.value, value);
    } else {
      this.metrics.set(key, {
        name,
        value,
        labels,
        timestamp: Date.now(),
      });
    }
  }

  getMetrics(): MetricDataPoint[] {
    return Array.from(this.metrics.values());
  }

  reset(): void {
    this.metrics.clear();
  }

  /**
   * Gets a specific metric value
   */
  getMetric(name: string, labels?: Record<string, string>): number | undefined {
    const key = this.getKey(name, labels);
    return this.metrics.get(key)?.value;
  }
}

/**
 * No-op metrics collector for when metrics are disabled
 */
export class NoOpMetricsCollector implements MetricsCollector {
  increment(): void {}
  gauge(): void {}
  histogram(): void {}
  getMetrics(): MetricDataPoint[] {
    return [];
  }
  reset(): void {}
}
