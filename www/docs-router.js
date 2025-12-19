// Simple client-side router for documentation pages
class DocsRouter {
  constructor() {
    this.routes = new Map();
    this.currentPage = null;
    this.init();
  }

  init() {
    // Register all routes
    this.register("index", "pages/index.html");
    this.register("getting-started", "pages/getting-started.html");
    this.register("installation", "pages/installation.html");

    // Core API
    this.register("api-guardrail", "pages/api/guardrail.html");
    this.register("api-protect", "pages/api/protect.html");
    this.register("api-checkHealth", "pages/api/checkHealth.html");
    this.register("api-getStorage", "pages/api/getStorage.html");
    this.register("api-getIPService", "pages/api/getIPService.html");
    this.register("api-getMetrics", "pages/api/getMetrics.html");
    this.register("api-on", "pages/api/on.html");
    this.register("api-addRule", "pages/api/addRule.html");
    this.register("api-explain", "pages/api/explain.html");

    // Rules
    this.register("rule-shield", "pages/rules/shield.html");
    this.register("rule-bot", "pages/rules/bot.html");
    this.register("rule-window", "pages/rules/window.html");
    this.register("rule-bucket", "pages/rules/bucket.html");
    this.register("rule-email", "pages/rules/email.html");
    this.register("rule-filter", "pages/rules/filter.html");

    // Adapters
    this.register("adapter-express", "pages/adapters/express.html");
    this.register("adapter-next", "pages/adapters/next.html");
    this.register("adapter-nestjs", "pages/adapters/nestjs.html");
    this.register("adapter-fastify", "pages/adapters/fastify.html");
    this.register("adapter-koa", "pages/adapters/koa.html");

    // Features & Guides
    this.register("feature-quota", "pages/features/quota.html");
    this.register("feature-debug", "pages/features/debug.html");
    this.register("feature-replay", "pages/features/replay.html");
    this.register("feature-config-file", "pages/features/config-file.html");
    this.register("feature-validation", "pages/features/validation.html");

    // Storage
    this.register("storage-memory", "pages/storage/memory.html");
    this.register("storage-redis", "pages/storage/redis.html");
    this.register("storage-atomic-redis", "pages/storage/atomic-redis.html");

    // Services
    this.register("service-ip-geolocation", "pages/services/ip-geolocation.html");
    this.register("service-vpn-detection", "pages/services/vpn-detection.html");
    this.register("service-ip-providers", "pages/services/ip-providers.html");

    // Utilities
    this.register("util-circuit-breaker", "pages/utils/circuit-breaker.html");
    this.register("util-metrics", "pages/utils/metrics.html");
    this.register("util-logger", "pages/utils/logger.html");
    this.register("util-events", "pages/utils/events.html");

    // Configuration & Advanced
    this.register("configuration", "pages/configuration.html");
    this.register("presets", "pages/presets.html");
    this.register("testing", "pages/testing.html");
    this.register("examples", "pages/examples.html");

    // Handle initial load and navigation
    window.addEventListener("popstate", () => this.handleRoute());
    this.handleRoute();

    // Handle sidebar link clicks
    document.addEventListener("click", (e) => {
      const link = e.target.closest("[data-route]");
      if (link) {
        e.preventDefault();
        const route = link.getAttribute("data-route");
        this.navigate(route);
      }
    });
  }

  register(name, path) {
    this.routes.set(name, path);
  }

  navigate(route) {
    if (this.routes.has(route)) {
      const path = this.routes.get(route);
      this.loadPage(path);
      window.history.pushState({ route }, "", `docs.html#${route}`);
      this.updateActiveLink(route);
    }
  }

  handleRoute() {
    const hash = window.location.hash.slice(1) || "index";
    if (this.routes.has(hash)) {
      const path = this.routes.get(hash);
      this.loadPage(path);
      this.updateActiveLink(hash);
    } else {
      this.navigate("index");
    }
  }

  async loadPage(path) {
    try {
      // Ensure path is relative to current location
      const fullPath = path.startsWith("/") ? path : `./${path}`;
      const response = await fetch(fullPath);
      if (!response.ok) {
        throw new Error(`Failed to load page: ${path} (${response.status} ${response.statusText})`);
      }
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");

      // Try to find .docs-content wrapper first (for full HTML pages)
      let content = doc.querySelector(".docs-content");

      if (!content) {
        // For HTML fragments, DOMParser automatically wraps them in html/body tags
        // So doc.body should contain our fragment content
        const body = doc.body;
        if (body && (body.children.length > 0 || body.innerHTML.trim())) {
          content = body;
        } else {
          // Fallback: use raw HTML directly (shouldn't normally happen)
          content = { innerHTML: html };
        }
      }

      if (content) {
        const currentContent = document.querySelector(".docs-content");
        if (currentContent) {
          currentContent.innerHTML = content.innerHTML;
        }
      }

      // Update page title
      const title = doc.querySelector("title");
      if (title) {
        document.title = title.textContent;
      }

      // Scroll to top
      window.scrollTo({ top: 0, behavior: "smooth" });

      // Re-initialize code copy buttons
      this.initCodeCopy();
    } catch (error) {
      console.error("Error loading page:", error, "Path:", path);
      const currentContent = document.querySelector(".docs-content");
      if (currentContent) {
        currentContent.innerHTML = `
          <div class="docs-section">
            <h2>Page Not Found</h2>
            <p>The requested documentation page could not be loaded: <code>${path}</code></p>
            <p>Error: ${error.message}</p>
            <a href="docs.html#index" data-route="index">Return to Home</a>
          </div>
        `;
      }
    }
  }

  updateActiveLink(route) {
    document.querySelectorAll(".docs-nav-link").forEach((link) => {
      link.classList.remove("active");
      if (link.getAttribute("data-route") === route) {
        link.classList.add("active");
      }
    });
  }

  initCodeCopy() {
    document.querySelectorAll(".docs-code-copy").forEach((btn) => {
      btn.addEventListener("click", async function () {
        const code = this.closest(".docs-code").querySelector("pre code");
        if (code) {
          try {
            await navigator.clipboard.writeText(code.textContent);
            const originalText = this.textContent;
            this.textContent = "Copied!";
            setTimeout(() => {
              this.textContent = originalText;
            }, 2000);
          } catch (err) {
            console.error("Failed to copy:", err);
          }
        }
      });
    });
  }
}

// Initialize router when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    window.docsRouter = new DocsRouter();
  });
} else {
  window.docsRouter = new DocsRouter();
}
