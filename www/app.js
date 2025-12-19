// Guardrail Website JavaScript

document.addEventListener("DOMContentLoaded", () => {
  // Mobile navigation toggle
  const navToggle = document.querySelector(".nav-toggle");
  const navMobile = document.querySelector(".nav-mobile");

  if (navToggle && navMobile) {
    navToggle.addEventListener("click", () => {
      navMobile.classList.toggle("active");
      const isOpen = navMobile.classList.contains("active");
      navToggle.setAttribute("aria-expanded", isOpen);
    });

    // Close mobile nav when clicking a link
    const mobileLinks = navMobile.querySelectorAll(".nav-mobile-link");
    mobileLinks.forEach((link) => {
      link.addEventListener("click", () => {
        navMobile.classList.remove("active");
        navToggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  // Copy to clipboard functionality
  const installCopy = document.querySelector(".install-copy");
  const installCode = document.querySelector(".install-code");

  if (installCopy && installCode) {
    installCopy.addEventListener("click", async () => {
      const text = "npm install @guardrail-dev/core";

      try {
        await navigator.clipboard.writeText(text);

        // Visual feedback
        const originalHTML = installCopy.innerHTML;
        installCopy.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
        `;
        installCopy.style.color = "#22c55e";

        setTimeout(() => {
          installCopy.innerHTML = originalHTML;
          installCopy.style.color = "";
        }, 2000);
      } catch (err) {
        console.error("Failed to copy:", err);
      }
    });
  }

  // Docs code copy buttons
  const codeBlocks = document.querySelectorAll(".docs-code");
  codeBlocks.forEach((block) => {
    const copyBtn = block.querySelector(".docs-code-copy");
    const code = block.querySelector("pre code");

    if (copyBtn && code) {
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(code.textContent);

          const originalText = copyBtn.textContent;
          copyBtn.textContent = "Copied!";

          setTimeout(() => {
            copyBtn.textContent = originalText;
          }, 2000);
        } catch (err) {
          console.error("Failed to copy:", err);
        }
      });
    }
  });

  // Docs sidebar toggle for mobile
  const docsMenuToggle = document.querySelector(".docs-menu-toggle");
  const docsSidebar = document.querySelector(".docs-sidebar");
  const docsSidebarOverlay = document.querySelector(".docs-sidebar-overlay");

  const toggleSidebar = (isOpen) => {
    if (isOpen) {
      docsSidebar.classList.add("active");
      if (docsSidebarOverlay) {
        docsSidebarOverlay.classList.add("active");
        docsSidebarOverlay.setAttribute("aria-hidden", "false");
      }
      document.body.style.overflow = "hidden";
    } else {
      docsSidebar.classList.remove("active");
      if (docsSidebarOverlay) {
        docsSidebarOverlay.classList.remove("active");
        docsSidebarOverlay.setAttribute("aria-hidden", "true");
      }
      document.body.style.overflow = "";
    }
  };

  if (docsMenuToggle && docsSidebar) {
    docsMenuToggle.addEventListener("click", (e) => {
      e.stopPropagation();
      const isOpen = !docsSidebar.classList.contains("active");
      toggleSidebar(isOpen);
    });

    // Close sidebar when clicking overlay
    if (docsSidebarOverlay) {
      docsSidebarOverlay.addEventListener("click", () => {
        toggleSidebar(false);
      });
    }

    // Close sidebar when clicking outside
    document.addEventListener("click", (e) => {
      if (
        docsSidebar.classList.contains("active") &&
        !docsSidebar.contains(e.target) &&
        !docsMenuToggle.contains(e.target)
      ) {
        toggleSidebar(false);
      }
    });

    // Close sidebar when clicking a link
    const sidebarLinks = docsSidebar.querySelectorAll(".docs-nav-link");
    sidebarLinks.forEach((link) => {
      link.addEventListener("click", () => {
        toggleSidebar(false);
      });
    });
  }

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault();

      const targetId = this.getAttribute("href");
      if (targetId === "#") return;

      const target = document.querySelector(targetId);
      if (target) {
        const navHeight = 64;
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight;

        window.scrollTo({
          top: targetPosition,
          behavior: "smooth",
        });

        // Update URL without jumping
        history.pushState(null, null, targetId);
      }
    });
  });

  // Active section highlighting for docs
  const observerOptions = {
    root: null,
    rootMargin: "-100px 0px -66% 0px",
    threshold: 0,
  };

  const docsSections = document.querySelectorAll(".docs-section[id]");
  const docsNavLinks = document.querySelectorAll(".docs-nav-link");

  if (docsSections.length > 0 && docsNavLinks.length > 0) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute("id");

          docsNavLinks.forEach((link) => {
            link.classList.remove("active");
            if (link.getAttribute("href") === `#${id}`) {
              link.classList.add("active");
            }
          });
        }
      });
    }, observerOptions);

    docsSections.forEach((section) => {
      observer.observe(section);
    });
  }

  // Handle initial hash in URL
  const initialHash = window.location.hash;
  if (initialHash) {
    const target = document.querySelector(initialHash);
    if (target) {
      setTimeout(() => {
        const navHeight = 64;
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight;
        window.scrollTo({
          top: targetPosition,
          behavior: "auto",
        });
      }, 100);
    }
  }
});
