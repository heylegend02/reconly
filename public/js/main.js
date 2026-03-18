(() => {
  const OUTPUT_PLACEHOLDER_HTML = `
    <h3>Execution Output</h3>
    <pre>Run this tool to view results.</pre>
  `;

  const clearModuleSectionState = (section) => {
    section.querySelectorAll("form").forEach((form) => {
      form.reset();
      form.querySelectorAll("input[type='file']").forEach((input) => {
        // Some browsers preserve file inputs when hidden/shown.
        input.value = "";
      });
    });

    const output = section.querySelector(".module-output");
    if (output) {
      output.innerHTML = OUTPUT_PLACEHOLDER_HTML;
    }
  };

  const initLiveDateTime = () => {
    const el = document.querySelector("[data-live-datetime]");
    if (!el) {
      return;
    }

    const formatter = new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    const update = () => {
      el.textContent = formatter.format(new Date());
    };

    update();
    setInterval(update, 1000);
  };

  const flash = document.querySelector(".flash");
  if (flash) {
    setTimeout(() => {
      flash.style.transition = "opacity 300ms ease";
      flash.style.opacity = "0";
      setTimeout(() => flash.remove(), 320);
    }, 5500);
  }

  const initFunctionSidebarViews = () => {
    const layouts = document.querySelectorAll(".ops-layout");
    layouts.forEach((layout) => {
      const links = Array.from(layout.querySelectorAll(".function-nav-link[data-target]"));
      const sections = Array.from(layout.querySelectorAll(".function-section[id]"));
      const opsContent = layout.querySelector(".ops-content");

      if (links.length === 0 || sections.length === 0 || !opsContent) {
        return;
      }

      const sectionMap = new Map(sections.map((section) => [section.id, section]));
      const fallback = sections[0].id;
      const fromHash = window.location.hash.replace("#", "");
      const fromServer = opsContent.dataset.activeSection || "";
      let activeSectionId = null;

      const setActiveSection = (sectionId, options = {}) => {
        const { updateHash = true, clearStateOnSwitch = false } = options;
        const activeId = sectionMap.has(sectionId) ? sectionId : fallback;
        const hasSwitched = Boolean(activeSectionId && activeSectionId !== activeId);
        const activeLink = links.find((link) => link.dataset.target === activeId) || null;
        const activeModuleKey = activeLink?.dataset.moduleKey || "";

        if (clearStateOnSwitch && hasSwitched) {
          sections.forEach((section) => clearModuleSectionState(section));
        }

        sections.forEach((section) => {
          section.hidden = section.id !== activeId;
        });

        links.forEach((link) => {
          const isActive = link.dataset.target === activeId;
          link.classList.toggle("active-link", isActive);
          link.setAttribute("aria-pressed", isActive ? "true" : "false");
        });

        if (updateHash) {
          const url = new URL(window.location.href);
          if (activeModuleKey) {
            url.searchParams.set("module", activeModuleKey);
          }
          url.hash = activeId;
          const nextUrl = `${url.pathname}${url.search}${url.hash}`;
          const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
          if (currentUrl !== nextUrl) {
            history.replaceState(null, "", nextUrl);
          }
        }

        activeSectionId = activeId;
      };

      links.forEach((link) => {
        link.addEventListener("click", (event) => {
          const targetId = link.dataset.target || "";
          if (!sectionMap.has(targetId)) {
            return;
          }
          event.preventDefault();
          setActiveSection(targetId, { clearStateOnSwitch: true });
        });
      });

      window.addEventListener("hashchange", () => {
        const hashSection = window.location.hash.replace("#", "");
        if (sectionMap.has(hashSection)) {
          setActiveSection(hashSection, { updateHash: false, clearStateOnSwitch: true });
        }
      });

      if (sectionMap.has(fromServer)) {
        setActiveSection(fromServer, { updateHash: false });
      } else if (sectionMap.has(fromHash)) {
        setActiveSection(fromHash, { updateHash: false });
      } else {
        setActiveSection(fallback, { updateHash: false });
      }
    });
  };

  const initSessionAutoLogout = () => {
    const authTopbar = document.querySelector(".topbar[data-authenticated-user='true']");
    if (!authTopbar) {
      return;
    }

    const timeoutMs = 5 * 60 * 1000;
    let timer = null;
    let internalNavigation = false;
    let beaconSent = false;

    const armTimer = () => {
      if (timer) {
        clearTimeout(timer);
      }
      timer = setTimeout(() => {
        internalNavigation = true;
        window.location.href = "/logout?reason=inactive";
      }, timeoutMs);
    };

    const markInternalNavigation = () => {
      internalNavigation = true;
    };

    const sendCloseLogoutBeacon = () => {
      if (internalNavigation || beaconSent) {
        return;
      }
      beaconSent = true;

      try {
        if (navigator.sendBeacon) {
          navigator.sendBeacon("/logout-beacon", new Blob([], { type: "application/json" }));
          return;
        }
      } catch (_error) {
        // Fallback to keepalive fetch below.
      }

      fetch("/logout-beacon", {
        method: "POST",
        credentials: "same-origin",
        keepalive: true,
      }).catch(() => {
        // Ignore beacon failures.
      });
    };

    ["mousemove", "keydown", "click", "scroll", "touchstart", "pointerdown"].forEach((eventName) => {
      window.addEventListener(eventName, armTimer, { passive: true });
    });

    document.addEventListener(
      "click",
      (event) => {
        const link = event.target.closest("a[href]");
        if (!link) {
          return;
        }
        if (link.target === "_blank" || link.hasAttribute("download")) {
          return;
        }
        const href = link.getAttribute("href") || "";
        if (href.startsWith("#")) {
          return;
        }
        markInternalNavigation();
      },
      true
    );

    document.addEventListener(
      "submit",
      () => {
        markInternalNavigation();
      },
      true
    );

    window.addEventListener("pagehide", sendCloseLogoutBeacon);
    armTimer();
  };

  initLiveDateTime();
  initFunctionSidebarViews();
  initSessionAutoLogout();
})();
