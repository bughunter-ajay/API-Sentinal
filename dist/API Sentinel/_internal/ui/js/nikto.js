/**
 * Nikto Web Server Scanner — Frontend Controller
 * Communicates with Nikto Backend (Port 8799)
 * Manages Target Setup, Live Findings, Real-Time Terminal Streaming, and Report Generation.
 */

(function () {
  "use strict";

  const API_BASE = "http://127.0.0.1:8799";

  const state = {
    status: "idle", // idle, running, completed, stopped, error
    target: "",
    base_url: "",
    serverBanner: "Unknown",
    ipAddress: "",
    findings: [],
    selectedFindingIndex: -1,
    activeFilter: "ALL",
    searchTerm: "",
    logOffset: 0,
    pollingTimer: null,
    stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    installedInfo: null,
    activeTerminalMode: "clean", // "clean" (Console) or "verbose" (Verbose Live Feed)
    autoScroll: true,
    verboseLogs: [],
    maxVerboseLines: 250,
  };

  function escapeHtml(str) {
    if (typeof str !== "string") return str == null ? "" : String(str);
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function extractReference(f) {
    if (!f) return "";
    if (f.reference_url && typeof f.reference_url === "string") return f.reference_url.trim();
    if (Array.isArray(f.references) && f.references.length > 0 && f.references[0]) {
      return String(f.references[0]).trim();
    }
    const combined = `${f.title || ""} ${f.description || ""} ${f.evidence || ""}`;
    const m = combined.match(/(?:See|Reference):\s*(https?:\/\/[^\s"',]+)/i);
    if (m && m[1]) {
      return m[1].replace(/[.,;)]+$/, "").trim();
    }
    return "";
  }

  function getCleanTitle(f) {
    if (!f) return "";
    let title = f.title || f.id || "";
    // Clean out "See: https://..." or "Reference: https://..."
    title = title.replace(/\.?\s*(?:See|Reference):\s*https?:\/\/\S+/gi, "").trim();
    if (title && !title.endsWith(".") && !title.endsWith(":") && !title.endsWith(";")) {
      title += ".";
    }
    return title;
  }

  function getCleanDescription(f) {
    if (!f) return "No description provided.";
    let desc = f.description || f.title || "";
    // Clean out "See: https://..." or "Reference: https://..." from description
    desc = desc.replace(/\.?\s*(?:See|Reference):\s*https?:\/\/\S+/gi, "").trim();
    if (desc && !desc.endsWith(".") && !desc.endsWith(":") && !desc.endsWith(";")) {
      desc += ".";
    }
    return desc || "No description provided.";
  }

  function getNiktoKnowledge(f) {
    if (!f) {
      return {
        category: "Server Configuration & Hygiene",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-16",
        impact: "Exposes server configuration anomalies or potentially unhardened endpoint behavior that may assist attackers in reconnaissance and exploitation.",
        recommended: "Inspect the identified resource, review access control policies, and verify against server security baseline.",
        nginx: "# Review endpoint configuration:\nlocation /path {\n    # Restrict permissions or deny public access\n}",
        apache: '# Review endpoint directives:\n<Directory "/path">\n    # Restrict permissions or require authentication\n</Directory>'
      };
    }

    const text = `${f.title || ""} ${f.description || ""} ${f.evidence || ""} ${f.id || ""}`.toLowerCase();

    // 1. Clickjacking / X-Frame-Options
    if (text.includes("x-frame-options") || text.includes("anti-clickjacking") || text.includes("clickjacking")) {
      return {
        category: "Missing Security Header",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-1021",
        impact: "The application is vulnerable to Clickjacking (UI Redressing). Attackers can frame this application inside an invisible <iframe> on an attacker-controlled site to trick authenticated users into clicking sensitive buttons or triggering unintended transactions.",
        recommended: "DENY (if framing never allowed) or SAMEORIGIN (allow framing only by same origin).",
        nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
        apache: 'Header always set X-Frame-Options "SAMEORIGIN"'
      };
    }

    // 2. MIME Sniffing / X-Content-Type-Options
    if (text.includes("x-content-type-options") || text.includes("mime type") || text.includes("mime sniffing") || text.includes("nosniff")) {
      return {
        category: "MIME Sniffing Vulnerability",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-79 / CWE-16",
        impact: "Without nosniff, browsers may inspect (sniff) content and treat non-executable files (like user-uploaded images or text) as executable HTML/JavaScript, leading to Cross-Site Scripting (XSS).",
        recommended: "nosniff",
        nginx: 'add_header X-Content-Type-Options "nosniff" always;',
        apache: 'Header always set X-Content-Type-Options "nosniff"'
      };
    }

    // 3. Strict-Transport-Security / HSTS
    if (text.includes("strict-transport-security") || text.includes("hsts") || (text.includes("ssl") && text.includes("transport-security"))) {
      return {
        category: "Insecure Transport / Missing HSTS",
        owasp: "A02:2021 - Cryptographic Failures",
        cwe: "CWE-319",
        impact: "Enables SSL-stripping and man-in-the-middle (MITM) attacks. Without HSTS, initial HTTP requests or unencrypted links can be intercepted and redirected to eavesdropping proxies on local Wi-Fi or networks.",
        recommended: "max-age=31536000; includeSubDomains; preload",
        nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
      };
    }

    // 4. Referrer-Policy
    if (text.includes("referrer-policy") || text.includes("referer-policy")) {
      return {
        category: "Referrer Information Leakage",
        owasp: "A01:2021 - Broken Access Control",
        cwe: "CWE-200",
        impact: "Sensitive parameters (tokens, session IDs, private query parameters, or internal URLs) may leak to external third-party sites via the HTTP Referer request header during user navigation.",
        recommended: "strict-origin-when-cross-origin or no-referrer",
        nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
      };
    }

    // 5. Content Security Policy (CSP)
    if (text.includes("content-security-policy") || text.includes("csp")) {
      return {
        category: "Missing Content Security Policy (CSP)",
        owasp: "A03:2021 - Injection / XSS",
        cwe: "CWE-79",
        impact: "Lack of a restrictive Content Security Policy permits unauthorized inline scripts, external malicious script loading, and unauthorized data exfiltration, drastically increasing XSS risk.",
        recommended: "default-src 'self'; frame-ancestors 'self'; script-src 'self';",
        nginx: 'add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\';" always;',
        apache: 'Header always set Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\';"'
      };
    }

    // 6. Permissions-Policy / Feature-Policy
    if (text.includes("permissions-policy") || text.includes("feature-policy")) {
      return {
        category: "Browser Feature Permissions",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-16",
        impact: "Allows embedded third-party iframes to access hardware and sensitive browser APIs (camera, microphone, geolocation, payment, usb) without explicit restrictions.",
        recommended: "camera=(), microphone=(), geolocation=()",
        nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        apache: 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"'
      };
    }

    // 7. Wildcard Certificate / TLS
    if (text.includes("wildcard") && (text.includes("certificate") || text.includes("ssl") || text.includes("cert"))) {
      return {
        category: "TLS / Certificate Policy",
        owasp: "A02:2021 - Cryptographic Failures",
        cwe: "CWE-295",
        impact: "Wildcard certificates (*.domain.com) share a single private key across all subdomains. A compromise on any staging or legacy server using this key compromises the security of all subdomains.",
        recommended: "Use separate SSL/TLS certificates per subdomain using automated ACME / Let's Encrypt tooling.",
        nginx: "# Configure discrete SSL certificate per virtual host:\nssl_certificate /etc/ssl/certs/subdomain.crt;\nssl_certificate_key /etc/ssl/private/subdomain.key;",
        apache: "# VirtualHost discrete certificate:\nSSLCertificateFile /etc/ssl/certs/subdomain.crt\nSSLCertificateKeyFile /etc/ssl/private/subdomain.key"
      };
    }

    // 8. Cookies (HttpOnly / Secure / SameSite)
    if (text.includes("cookie") && (text.includes("httponly") || text.includes("secure") || text.includes("samesite"))) {
      return {
        category: "Insecure Cookie Flags",
        owasp: "A01:2021 - Broken Access Control",
        cwe: "CWE-614 / CWE-1004",
        impact: "Cookies missing Secure can be intercepted over plaintext HTTP. Cookies missing HttpOnly can be accessed and stolen via client-side JavaScript (XSS attacks).",
        recommended: "Secure; HttpOnly; SameSite=Lax (or Strict)",
        nginx: 'proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";',
        apache: 'Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"'
      };
    }

    // 9. CORS misconfiguration
    if (text.includes("cors") || text.includes("access-control-allow-origin") || text.includes("cross-domain")) {
      return {
        category: "Permissive CORS Policy",
        owasp: "A01:2021 - Broken Access Control",
        cwe: "CWE-942",
        impact: "Wildcard or misconfigured Access-Control-Allow-Origin headers allow malicious websites to issue authenticated cross-origin requests and read sensitive API response payloads.",
        recommended: "Explicit origin whitelist instead of '*' or echoing request origin.",
        nginx: 'add_header Access-Control-Allow-Origin "https://yourdomain.com" always;',
        apache: 'Header always set Access-Control-Allow-Origin "https://yourdomain.com"'
      };
    }

    // 10. Directory Listing / Index of
    if (text.includes("directory indexing") || text.includes("directory listing") || text.includes("index of /")) {
      return {
        category: "Directory Listing Enabled",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-548",
        impact: "Automatic directory listings expose all files and folders in directory paths, allowing attackers to discover unlinked source files, backups, and logs.",
        recommended: "Disable automatic directory indexing (autoindex off / Options -Indexes).",
        nginx: "autoindex off;",
        apache: "Options -Indexes"
      };
    }

    // 11. Dangerous HTTP Methods (TRACE, OPTIONS, PUT, DELETE)
    if (text.includes("trace method") || text.includes("http method") || text.includes("dangerous method")) {
      return {
        category: "Dangerous HTTP Methods",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-650",
        impact: "Insecure HTTP methods such as TRACE enable Cross-Site Tracing (XST) to steal HTTP-only credentials; uncontrolled PUT/DELETE allow unauthorized file manipulation.",
        recommended: "Limit allowed methods to GET, POST, HEAD, OPTIONS.",
        nginx: "if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$ ) {\n    return 405;\n}",
        apache: "<LimitExcept GET POST HEAD OPTIONS>\n    Require all denied\n</LimitExcept>"
      };
    }

    // 12. Information Disclosure / Server Banners
    if (text.includes("uncommon header") || text.includes("x-powered-by") || text.includes("server banner") || text.includes("reveals") || text.includes("version")) {
      return {
        category: "Information Disclosure",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-200",
        impact: "Exposes server software, exact version numbers, and framework details, giving attackers precise intelligence to lookup known CVEs and exploit version-specific vulnerabilities.",
        recommended: "Suppress server tokens, banner strings, and framework disclosure headers.",
        nginx: "server_tokens off;\nproxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;",
        apache: "ServerSignature Off\nServerTokens Prod\nHeader unset X-Powered-By"
      };
    }

    // 13. Sensitive Files (.git, .env, backups, dumps)
    if (text.includes(".git") || text.includes(".env") || text.includes("backup") || text.includes("dump") || text.includes("archive") || text.includes(".sql") || text.includes(".tar") || text.includes(".zip")) {
      return {
        category: "Sensitive File & Source Code Exposure",
        owasp: "A05:2021 - Security Misconfiguration",
        cwe: "CWE-538",
        impact: "Direct access to version control repositories, environment files, or backups allows attackers to download source code, database dumps, passwords, and private API keys.",
        recommended: "Block direct web access to dotfiles (.git, .env) and backup extensions immediately.",
        nginx: "location ~ /\\.(?!well-known).* {\n    deny all;\n    return 404;\n}",
        apache: '<FilesMatch "^\\.(?!well-known)">\n    Require all denied\n</FilesMatch>'
      };
    }

    // 14. Fallback Default
    return {
      category: "Server Configuration & Hygiene",
      owasp: "A05:2021 - Security Misconfiguration",
      cwe: "CWE-16",
      impact: "Exposes server configuration anomalies or potentially unhardened endpoint behavior that may assist attackers in reconnaissance and exploitation.",
      recommended: "Inspect the identified resource, review access control policies, and verify against server security baseline.",
      nginx: "# Review endpoint configuration:\nlocation /path {\n    # Restrict permissions or deny public access\n}",
      apache: '# Review endpoint directives:\n<Directory "/path">\n    # Restrict permissions or require authentication\n</Directory>'
    };
  }

  // ── Initialization & Sub-Tab Navigation ────────────────────────────────────

  document.addEventListener("DOMContentLoaded", () => {
    initNiktoModule();
  });

  async function initNiktoModule() {
    checkBinaryStatus();
    initVResize();
    renderStats();
    renderTable();
    checkInitialScanStatus();
  }

  async function checkInitialScanStatus() {
    try {
      const res = await fetch(`${API_BASE}/api/scan/status`);
      if (res.ok) {
        const s = await res.json();
        if (s.status === "running") {
          state.target = s.target || "";
          state.status = "running";
          state.serverBanner = s.server_banner || state.serverBanner;
          state.ipAddress = s.ip_address || state.ipAddress;
          state.stats = s.stats || state.stats;

          const targetPill = document.getElementById("nikto-active-target-pill");
          if (targetPill && s.target) targetPill.textContent = s.target;

          const bannerPill = document.getElementById("nikto-active-banner-pill");
          if (bannerPill && s.server_banner) bannerPill.textContent = s.server_banner;

          setScanningState(true);
          startPolling();
          fetchResults();
        }
      }
    } catch (_) {}
  }

  async function checkBinaryStatus(force = false) {
    try {
      const endpoint = force ? `${API_BASE}/api/engine/refresh` : `${API_BASE}/api/info`;
      const res = await fetch(endpoint, { method: force ? "POST" : "GET" });
      if (res.ok) {
        const info = await res.json();
        state.installedInfo = info;

        // Top Navigation Badge
        const badge = document.getElementById("nikto-top-engine-badge");
        if (badge) {
          if (info.installed) {
            badge.textContent = `🟢 ${info.nikto_version || "Nikto 2.6.x Active"}`;
            badge.style.color = "var(--green, #3fb950)";
            badge.style.borderColor = "rgba(63,185,80,0.4)";
          } else {
            badge.textContent = "⚠️ Perl/Nikto Missing";
            badge.style.color = "var(--yellow, #d29922)";
            badge.style.borderColor = "rgba(210,153,34,0.4)";
          }
        }

        // Settings / Server Info Tab Panel Elements
        const perlPathEl = document.getElementById("nikto-engine-perl-path");
        const perlVerEl = document.getElementById("nikto-engine-perl-ver");
        const scriptPathEl = document.getElementById("nikto-engine-script-path");
        const verEl = document.getElementById("nikto-engine-ver");
        const rulesEl = document.getElementById("nikto-engine-rules-count");
        const gitStatusEl = document.getElementById("nikto-engine-git-status");
        const gitCommitEl = document.getElementById("nikto-engine-git-commit");

        if (perlPathEl) perlPathEl.textContent = info.perl_path || "Not found";
        if (perlVerEl) perlVerEl.textContent = info.perl_version ? `v${info.perl_version}` : (info.perl_installed ? "Installed" : "Missing");
        if (scriptPathEl) scriptPathEl.textContent = info.nikto_path || "Not found";
        if (verEl) verEl.textContent = info.nikto_version || "Nikto 2.6.x";
        if (rulesEl) rulesEl.textContent = `${info.rules_count || 7240}+ Signatures`;
        if (gitStatusEl) gitStatusEl.textContent = info.source === "bundled" ? "Bundled Repository" : "System Executable";
        if (gitCommitEl) gitCommitEl.textContent = info.git_commit || "origin/main branch";
      }
    } catch (e) {
      console.warn("Nikto status check error:", e);
    }
  }

  async function updateEngine() {
    const consoleEl = document.getElementById("nikto-settings-console");
    if (consoleEl) {
      consoleEl.textContent = `[*] Checking for updates from official Nikto GitHub repository...\n[*] Running: git pull origin main in nikto_backend/nikto\n`;
    }

    try {
      const res = await fetch(`${API_BASE}/api/engine/update`, { method: "POST" });
      const data = await res.json();
      if (consoleEl) {
        consoleEl.textContent += `[+] Output:\n${data.output || "Already up to date."}\n\n[✓] ${data.message}\n`;
      }
      showToast(data.message, data.success ? "success" : "warning");
      checkBinaryStatus(true);
    } catch (e) {
      if (consoleEl) {
        consoleEl.textContent += `[!] Update failed: ${e.message}\n`;
      }
      showToast(`Update failed: ${e.message}`, "error");
    }
  }

  async function verifyEngine() {
    const consoleEl = document.getElementById("nikto-settings-console");
    if (consoleEl) {
      consoleEl.textContent = `[*] Validating Nikto database syntax and plugin integrity...\n[*] Running: perl nikto.pl -dbcheck\n`;
    }

    try {
      const res = await fetch(`${API_BASE}/api/engine/verify`, { method: "POST" });
      const data = await res.json();
      if (consoleEl) {
        consoleEl.textContent += `[+] Database Integrity Check Results:\n${data.output || data.message}\n\n[✓] Verification completed.\n`;
      }
      showToast("Database syntax check completed.", "info");
    } catch (e) {
      if (consoleEl) {
        consoleEl.textContent += `[!] Verify failed: ${e.message}\n`;
      }
      showToast(`Verification error: ${e.message}`, "error");
    }
  }

  function switchTab(tabName) {
    const tabs = ["setup", "results", "terminal", "engine"];
    tabs.forEach((t) => {
      const btn = document.getElementById(`nikto-tab-btn-${t}`);
      const view = document.getElementById(`nikto-view-${t}`);
      if (btn) btn.classList.toggle("active", t === tabName);
      if (view) view.classList.toggle("active", t === tabName);
    });

    if (tabName === "terminal" && state.autoScroll) {
      setTimeout(() => {
        const pane = state.activeTerminalMode === "verbose"
          ? document.getElementById("nikto-terminal-verbose-logs")
          : document.getElementById("nikto-terminal-logs");
        if (pane) pane.scrollTop = pane.scrollHeight;
      }, 50);
    }
  }

  // ── cURL Extraction ────────────────────────────────────────────────────────

  async function parseCurl() {
    if (state.status === "running") {
      showToast("Scan is in progress. Configuration is locked.", "warning");
      return;
    }

    const inp = document.getElementById("nikto-curl-input");
    if (!inp || !inp.value.trim()) {
      alert("Please paste a raw cURL command first.");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/parse-curl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ curl: inp.value }),
      });
      const data = await res.json();
      if (data.success && data.url) {
        const targetInp = document.getElementById("nikto-target-input");
        const portInp = document.getElementById("nikto-port-input");
        const sslCheck = document.getElementById("nikto-ssl-check");

        if (targetInp) targetInp.value = data.url;
        if (portInp && data.port) portInp.value = data.port;
        if (sslCheck) sslCheck.checked = !!data.ssl;

        showToast("Extracted Target URL and Port from cURL!", "success");
      } else {
        alert(data.error || "Could not parse target from cURL.");
      }
    } catch (e) {
      alert("Backend connection error: " + e.message);
    }
  }

  // ── Start / Stop Scanning ──────────────────────────────────────────────────

  async function startScan() {
    if (state.status === "running") return;

    const targetInp = document.getElementById("nikto-target-input");
    const target = targetInp ? targetInp.value.trim() : "";
    if (!target) {
      alert("Please enter a Target Host or URL (e.g. https://target.com)");
      if (targetInp) targetInp.focus();
      return;
    }

    const portInp = document.getElementById("nikto-port-input");
    const port = portInp && portInp.value ? parseInt(portInp.value, 10) : null;
    const sslCheck = document.getElementById("nikto-ssl-check");
    const isSsl = sslCheck ? sslCheck.checked : target.startsWith("https://");

    // Collect selected tuning checkboxes
    const tuningBoxes = document.querySelectorAll(".nikto-tuning-cb:checked");
    const tuning = Array.from(tuningBoxes)
      .map((cb) => cb.value)
      .join("");

    const pauseSel = document.getElementById("nikto-pause-select");
    const pause = pauseSel ? parseInt(pauseSel.value, 10) : 0;

    const evasionSel = document.getElementById("nikto-evasion-select");
    const evasion = evasionSel ? evasionSel.value : "";

    const maxtimeSel = document.getElementById("nikto-maxtime-select");
    const maxtime = maxtimeSel ? maxtimeSel.value : "30m";

    const uaInp = document.getElementById("nikto-ua-input");
    const userAgent = uaInp && uaInp.value.trim() ? uaInp.value.trim() : null;

    const isVerbose = true; // Always enable verbose stream by default

    // UI Updates
    setScanningState(true);
    state.target = target;
    state.findings = [];
    state.selectedFindingIndex = -1;
    state.logOffset = 0;
    renderStats();
    renderTable();
    clearTerminalLogs();
    clearInspector();

    const targetPill = document.getElementById("nikto-active-target-pill");
    if (targetPill) targetPill.textContent = target;

    const bannerPill = document.getElementById("nikto-active-banner-pill");
    if (bannerPill) bannerPill.textContent = "Detecting...";

    // Switch to Results Tab
    switchTab("results");

    try {
      const res = await fetch(`${API_BASE}/api/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target,
          port: port,
          ssl: isSsl,
          tuning: tuning || "123bde",
          pause: pause,
          evasion: evasion || null,
          maxtime: maxtime,
          user_agent: userAgent,
          verbose: isVerbose,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        alert(data.detail || "Failed to start Nikto scan.");
        setScanningState(false);
        return;
      }

      startPolling();
    } catch (e) {
      alert("Failed to communicate with Nikto backend (Port 8799): " + e.message);
      setScanningState(false);
    }
  }

  async function stopScan() {
    try {
      await fetch(`${API_BASE}/api/scan/stop`, { method: "POST" });
      setScanningState(false);
      showToast("Scan stopped by user.", "info");
    } catch (e) {
      console.error(e);
    }
  }

  function setScanningState(isScanning) {
    state.status = isScanning ? "running" : "idle";

    const startBtn = document.getElementById("btn-nikto-start");
    const stopBtn = document.getElementById("btn-nikto-stop");
    const progressStrip = document.getElementById("nikto-scan-progress-strip");
    const statusPill = document.getElementById("nikto-scan-status-pill");
    const termStatus = document.getElementById("nikto-terminal-status");

    if (startBtn) startBtn.style.display = isScanning ? "none" : "inline-flex";
    if (stopBtn) stopBtn.style.display = isScanning ? "inline-flex" : "none";
    if (progressStrip) progressStrip.style.display = isScanning ? "block" : "none";

    if (statusPill) {
      statusPill.textContent = isScanning ? "Scanning..." : "Completed";
      statusPill.style.color = isScanning ? "var(--yellow, #d29922)" : "var(--green, #3fb950)";
    }
    if (termStatus) {
      termStatus.textContent = isScanning ? "● Running" : "● Connected";
      termStatus.style.color = isScanning ? "var(--yellow, #d29922)" : "var(--green, #3fb950)";
    }

    setSetupFormLocked(isScanning);
  }

  function setSetupFormLocked(isLocked) {
    const setupPane = document.getElementById("nikto-view-setup");
    if (!setupPane) return;

    // 1. Lock/Unlock all form controls inside setup pane (inputs, selects, textareas, checkboxes)
    const formControls = setupPane.querySelectorAll("input, select, textarea");
    formControls.forEach((el) => {
      el.disabled = isLocked;
    });

    // 2. Lock/Unlock tuning category cards/labels (.nikto-tuning-item)
    const tuningLabels = setupPane.querySelectorAll(".nikto-tuning-item");
    tuningLabels.forEach((lbl) => {
      if (isLocked) {
        lbl.classList.add("nikto-disabled");
      } else {
        lbl.classList.remove("nikto-disabled");
      }
    });

    // 3. Reset Defaults button
    const resetBtn = document.getElementById("btn-nikto-reset");
    if (resetBtn) {
      resetBtn.disabled = isLocked;
      if (isLocked) {
        resetBtn.classList.add("nikto-btn-disabled");
      } else {
        resetBtn.classList.remove("nikto-btn-disabled");
      }
    }

    // 4. Auto-extract link
    const extractBtn = document.getElementById("nikto-curl-extract-btn");
    if (extractBtn) {
      if (isLocked) {
        extractBtn.classList.add("nikto-link-disabled");
      } else {
        extractBtn.classList.remove("nikto-link-disabled");
      }
    }

    // 5. Tuning action buttons (Select All, Default Safe, Clear)
    const tuningBtns = setupPane.querySelectorAll(".btn-nikto-secondary");
    tuningBtns.forEach((btn) => {
      if (btn.id !== "btn-nikto-stop") { // Never lock Stop Scan button!
        btn.disabled = isLocked;
        if (isLocked) {
          btn.classList.add("nikto-btn-disabled");
        } else {
          btn.classList.remove("nikto-btn-disabled");
        }
      }
    });

    // 6. In-progress notification banner at top of setup pane
    let notice = document.getElementById("nikto-setup-locked-notice");
    if (!notice) {
      notice = document.createElement("div");
      notice.id = "nikto-setup-locked-notice";
      notice.className = "nikto-setup-locked-banner";
      notice.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:13px;animation:nikto-pulse 1.5s infinite;">🔒</span>
          <span><b>Target &amp; Setup Locked:</b> A scan is currently running. All parameters are non-editable to prevent configuration conflicts.</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:11px;opacity:0.9;">Click <b>"Stop Scan"</b> below to abort and unlock.</span>
        </div>
      `;
      const scrollPane = setupPane.querySelector(".nikto-scroll-pane");
      if (scrollPane) {
        scrollPane.insertBefore(notice, scrollPane.firstChild);
      }
    }

    if (notice) {
      notice.style.display = isLocked ? "flex" : "none";
    }

    // 7. Card styling for locked visual cues
    const cards = setupPane.querySelectorAll(".nikto-card");
    cards.forEach((card) => {
      if (isLocked) {
        card.classList.add("nikto-card-locked");
      } else {
        card.classList.remove("nikto-card-locked");
      }
    });
  }

  // ── Terminal Console (Clean vs Verbose Live Feed) ─────────────────────────

  function switchTerminalMode(mode) {
    state.activeTerminalMode = mode;

    const btnClean = document.getElementById("nikto-btn-term-clean");
    const btnVerbose = document.getElementById("nikto-btn-term-verbose");
    const paneClean = document.getElementById("nikto-terminal-logs");
    const paneVerbose = document.getElementById("nikto-terminal-verbose-logs");
    const counter = document.getElementById("nikto-verbose-counter");

    if (mode === "clean") {
      if (btnClean) {
        btnClean.style.background = "var(--blue, #58a6ff)";
        btnClean.style.color = "#ffffff";
      }
      if (btnVerbose) {
        btnVerbose.style.background = "transparent";
        btnVerbose.style.color = "var(--text2, #8b949e)";
      }
      if (paneClean) {
        paneClean.style.display = "block";
        if (state.autoScroll) paneClean.scrollTop = paneClean.scrollHeight;
      }
      if (paneVerbose) paneVerbose.style.display = "none";
      if (counter) counter.style.display = "none";
    } else {
      if (btnClean) {
        btnClean.style.background = "transparent";
        btnClean.style.color = "var(--text2, #8b949e)";
      }
      if (btnVerbose) {
        btnVerbose.style.background = "var(--blue, #58a6ff)";
        btnVerbose.style.color = "#ffffff";
      }
      if (paneClean) paneClean.style.display = "none";
      if (paneVerbose) {
        paneVerbose.style.display = "block";
        if (state.autoScroll) paneVerbose.scrollTop = paneVerbose.scrollHeight;
      }
      if (counter) {
        counter.style.display = "inline-flex";
        counter.textContent = `Ring Buffer: ${state.verboseLogs.length}/${state.maxVerboseLines}`;
      }
    }
  }

  function toggleAutoScroll(enabled) {
    state.autoScroll = !!enabled;
    const chk = document.getElementById("nikto-autoscroll-toggle");
    if (chk) chk.checked = state.autoScroll;
    const label = document.getElementById("nikto-autoscroll-label");
    if (label) {
      label.title = `Toggle auto-scroll when new logs arrive (Currently ${state.autoScroll ? "ON" : "OFF"})`;
      label.style.borderColor = state.autoScroll ? "var(--blue, #58a6ff)" : "var(--border, #30363d)";
    }
    if (state.autoScroll) {
      const pane = state.activeTerminalMode === "verbose"
        ? document.getElementById("nikto-terminal-verbose-logs")
        : document.getElementById("nikto-terminal-logs");
      if (pane) pane.scrollTop = pane.scrollHeight;
    }
  }

  function formatVerboseLogLine(msg) {
    const safe = escapeHtml(msg);
    // Format: V:Thu Oct 15 20:21:36 2026 [plugin] - - 404 for GET: /path
    const vMatch = safe.match(/^(V:[^\[]+)(\[[^\]]+\])(.*?\s+)(\d{3})(\s+for\s+[A-Z]+:\s*)(.*)$/);
    if (vMatch) {
      const timePart = `<span style="color:#6e7681;font-size:10px;">${vMatch[1]}</span>`;
      const pluginPart = `<span style="color:#58a6ff;font-weight:600;">${vMatch[2]}</span>`;
      const sepPart = `<span style="color:#6e7681;">${vMatch[3]}</span>`;
      const code = vMatch[4];
      let codeColor = "#8b949e";
      if (code.startsWith("2")) codeColor = "#3fb950";
      else if (code.startsWith("3")) codeColor = "#58a6ff";
      else if (code.startsWith("4")) codeColor = "#d29922";
      else if (code.startsWith("5")) codeColor = "#f85149";
      const codePart = `<span style="color:${codeColor};font-weight:700;">${code}</span>`;
      const methodPart = `<span style="color:#6e7681;">${vMatch[5]}</span>`;
      const urlPart = `<span style="color:#7ee787;word-break:break-all;">${vMatch[6]}</span>`;
      return `${timePart}${pluginPart}${sepPart}${codePart}${methodPart}${urlPart}`;
    }

    // Format: V:Thu Oct 15 ... [Plugins] -- Running recon for "..." plugin
    const rMatch = safe.match(/^(V:[^\[]+)(\[[^\]]+\])(\s*--\s*Running\s+recon.*)$/);
    if (rMatch) {
      const timePart = `<span style="color:#6e7681;font-size:10px;">${rMatch[1]}</span>`;
      const pluginPart = `<span style="color:#d2a8ff;font-weight:600;">${rMatch[2]}</span>`;
      const reconPart = `<span style="color:#79c0ff;font-style:italic;">${rMatch[3]}</span>`;
      return `${timePart}${pluginPart}${reconPart}`;
    }

    if (safe.startsWith("V:")) {
      return `<span style="color:#8b949e;">${safe}</span>`;
    }
    return safe;
  }

  // ── Polling & Terminal Logs ────────────────────────────────────────────────

  function startPolling() {
    if (state.pollingTimer) clearInterval(state.pollingTimer);

    state.pollingTimer = setInterval(async () => {
      // 1. Poll Status
      try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 3000);
        const statusRes = await fetch(`${API_BASE}/api/scan/status`, { signal: ctrl.signal });
        clearTimeout(tid);

        if (statusRes.ok) {
          const s = await statusRes.json();
          state.status = s.status;
          state.serverBanner = s.server_banner || state.serverBanner;
          state.ipAddress = s.ip_address || state.ipAddress;
          state.stats = s.stats || state.stats;

          const bannerPill = document.getElementById("nikto-active-banner-pill");
          if (bannerPill && state.serverBanner && state.serverBanner !== "Unknown") {
            bannerPill.textContent = state.serverBanner;
          }

          const elapsedEl = document.getElementById("nikto-progress-elapsed-text");
          if (elapsedEl) elapsedEl.textContent = `${s.elapsed_seconds || 0}s`;

          const itemsCountEl = document.getElementById("nikto-progress-items-count");
          if (itemsCountEl) itemsCountEl.textContent = `${s.total_findings || 0} Items`;

          renderStats();

          // Fetch structured findings if count increased
          if (s.total_findings !== state.findings.length) {
            fetchResults();
          }

          // If scan finished
          if (s.status !== "running") {
            clearInterval(state.pollingTimer);
            state.pollingTimer = null;
            setScanningState(false);
            fetchResults();
          }
        }
      } catch (err) {
        // Status timeout or network error
      }

      // 2. Poll Incremental Logs (Decoupled)
      try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 3000);
        const logsRes = await fetch(`${API_BASE}/api/scan/logs?offset=${state.logOffset}`, { signal: ctrl.signal });
        clearTimeout(tid);

        if (logsRes.ok) {
          const l = await logsRes.json();
          if (l.lines && l.lines.length > 0) {
            state.logOffset += l.lines.length;
            appendTerminalLogs(l.lines);
          }
        }
      } catch (err) {
        // Logs timeout or network error
      }
    }, 1000);
  }

  async function fetchResults() {
    try {
      const res = await fetch(`${API_BASE}/api/scan/results`);
      if (res.ok) {
        const data = await res.json();
        state.findings = data.findings || [];
        state.stats = data.stats || state.stats;
        renderStats();
        renderTable();

        const badge = document.getElementById("nikto-badge-findings");
        if (badge) {
          badge.textContent = state.findings.length;
          badge.classList.toggle("has-findings", state.findings.length > 0);
        }
      }
    } catch (e) {
      console.warn("Results fetch error:", e);
    }
  }

  function appendTerminalLogs(lines) {
    const termClean = document.getElementById("nikto-terminal-logs");
    const termVerbose = document.getElementById("nikto-terminal-verbose-logs");

    lines.forEach((line) => {
      const clean = line.trim();
      const isVerboseHit = clean.startsWith("V:");

      if (isVerboseHit) {
        // Route to Verbose Feed (Rolling Ring Buffer max 250)
        state.verboseLogs.push(line);
        if (state.verboseLogs.length > state.maxVerboseLines) {
          state.verboseLogs.shift();
        }

        if (termVerbose) {
          const div = document.createElement("div");
          div.className = "nikto-log-line";
          div.innerHTML = formatVerboseLogLine(line);
          termVerbose.appendChild(div);

          while (termVerbose.childNodes.length > state.maxVerboseLines) {
            termVerbose.removeChild(termVerbose.firstChild);
          }
        }
      } else {
        // Route to Clean Console (Findings & Milestones)
        if (termClean) {
          const div = document.createElement("div");
          div.className = "nikto-log-line";

          if (clean.startsWith("+ ")) {
            div.classList.add("nikto-log-success");
          } else if (clean.startsWith("[*]")) {
            div.classList.add("nikto-log-info");
          } else if (clean.startsWith("[!]")) {
            div.classList.add("nikto-log-warn");
          } else if (clean.toLowerCase().includes("error")) {
            div.classList.add("nikto-log-err");
          }

          div.textContent = line;
          termClean.appendChild(div);

          while (termClean.childNodes.length > 500) {
            termClean.removeChild(termClean.firstChild);
          }
        }
      }
    });

    const counter = document.getElementById("nikto-verbose-counter");
    if (counter) {
      counter.textContent = `Ring Buffer: ${state.verboseLogs.length}/${state.maxVerboseLines}`;
    }

    if (state.autoScroll) {
      if (termClean && state.activeTerminalMode === "clean") {
        termClean.scrollTop = termClean.scrollHeight;
      }
      if (termVerbose && state.activeTerminalMode === "verbose") {
        termVerbose.scrollTop = termVerbose.scrollHeight;
      }
    }
  }

  function clearTerminalLogs() {
    state.verboseLogs = [];
    const termClean = document.getElementById("nikto-terminal-logs");
    if (termClean) {
      termClean.innerHTML = '<div class="nikto-log-line" style="color:var(--text3);">[Terminal Console Ready] Waiting for scan to launch...</div>';
    }
    const termVerbose = document.getElementById("nikto-terminal-verbose-logs");
    if (termVerbose) {
      termVerbose.innerHTML = '<div class="nikto-log-line" style="color:var(--text3,#6e7681);">[Live Activity Feed Ready] Live HTTP probe hits (-Display 3PV) will stream here (rolling window of last 250 requests)...</div>';
    }
    const counter = document.getElementById("nikto-verbose-counter");
    if (counter) counter.textContent = `Ring Buffer: 0/${state.maxVerboseLines}`;
  }

  function copyTerminalLogs(btnEl) {
    const targetBtn = btnEl || (window.event?.target?.closest ? window.event.target.closest("button") : null);
    let text = "";
    if (state.activeTerminalMode === "verbose") {
      text = state.verboseLogs.join("\n");
      if (!text) {
        const c = document.getElementById("nikto-terminal-verbose-logs");
        if (c) text = c.innerText;
      }
    } else {
      const c = document.getElementById("nikto-terminal-logs");
      if (c) text = c.innerText;
    }

    if (text) {
      if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          showCopyFeedback(targetBtn);
        }).catch(() => {
          showToast("Failed to copy logs to clipboard.", "error");
        });
      } else {
        showToast("Clipboard API not available.", "warn");
      }
    } else {
      showToast("Terminal is empty.", "info");
    }
  }

  function showCopyFeedback(btn) {
    if (!btn) return;
    const origHtml = btn.innerHTML;
    btn.innerHTML = "✓ Copied!";
    btn.style.color = "var(--green, #3fb950)";
    btn.style.borderColor = "var(--green, #3fb950)";
    setTimeout(() => {
      btn.innerHTML = origHtml;
      btn.style.color = "";
      btn.style.borderColor = "";
    }, 1500);
  }

  // ── Findings Table & Inspector ─────────────────────────────────────────────

  function getFilteredFindings() {
    const filter = state.activeFilter;
    const q = state.searchTerm.toLowerCase().trim();

    return state.findings.filter((f) => {
      const matchSev = filter === "ALL" || (f.severity || "INFO").toUpperCase() === filter;
      const refUrl = extractReference(f);
      const matchQuery =
        !q ||
        (f.title || "").toLowerCase().includes(q) ||
        (f.url || "").toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q) ||
        refUrl.toLowerCase().includes(q);
      return matchSev && matchQuery;
    });
  }

  function renderTable() {
    const tbody = document.getElementById("nikto-table-body");
    if (!tbody) return;

    const items = getFilteredFindings();

    const prevBtn = document.getElementById("nikto-nav-prev-btn");
    const nextBtn = document.getElementById("nikto-nav-next-btn");
    const posPill = document.getElementById("nikto-nav-pos-pill");

    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text3);padding:24px;font-size:11.5px;">${
        state.status === "running"
          ? "Scan in progress... Discovered items will appear here in real-time."
          : "No findings discovered. Enter target and start Nikto scan."
      }</td></tr>`;
      if (prevBtn) prevBtn.disabled = true;
      if (nextBtn) nextBtn.disabled = true;
      if (posPill) posPill.textContent = "- / -";
      return;
    }

    tbody.innerHTML = items
      .map((f, i) => {
        const sev = (f.severity || "INFO").toUpperCase();
        const isSelected = i === state.selectedFindingIndex;
        const cleanTitle = getCleanTitle(f);
        return `
        <tr class="nikto-row ${isSelected ? "selected" : ""}" data-idx="${i}">
          <td class="nikto-col-idx">${i + 1}</td>
          <td class="nikto-col-sev"><span class="nikto-badge nikto-badge-${sev.toLowerCase()}">${sev}</span></td>
          <td class="nikto-col-finding" style="font-weight:600;font-size:11.5px;color:var(--text);">${escapeHtml(cleanTitle)}</td>
          <td class="nikto-col-url"><span class="nikto-target-url">${escapeHtml(f.url || "-")}</span></td>
        </tr>
      `;
      })
      .join("");

    tbody.querySelectorAll(".nikto-row").forEach((row) => {
      row.addEventListener("click", () => {
        const idx = parseInt(row.getAttribute("data-idx"), 10);
        selectFinding(idx);
      });
    });

    // Update navigation controls
    if (state.selectedFindingIndex >= 0 && state.selectedFindingIndex < items.length) {
      if (prevBtn) prevBtn.disabled = state.selectedFindingIndex <= 0;
      if (nextBtn) nextBtn.disabled = state.selectedFindingIndex >= items.length - 1;
      if (posPill) posPill.textContent = `${state.selectedFindingIndex + 1} / ${items.length}`;
    } else {
      if (prevBtn) prevBtn.disabled = true;
      if (nextBtn) nextBtn.disabled = items.length <= 1;
      if (posPill) posPill.textContent = `- / ${items.length}`;
    }
  }

  function selectFinding(idx) {
    const items = getFilteredFindings();
    if (!items.length) return;

    if (idx < 0) idx = 0;
    if (idx >= items.length) idx = items.length - 1;

    state.selectedFindingIndex = idx;
    const f = items[idx];
    if (!f) return;

    // Highlight row in table
    const tbody = document.getElementById("nikto-table-body");
    if (tbody) {
      tbody.querySelectorAll(".nikto-row").forEach((row) => {
        const rIdx = parseInt(row.getAttribute("data-idx"), 10);
        row.classList.toggle("selected", rIdx === idx);
      });
    }

    // Update nav buttons and counter pill
    const prevBtn = document.getElementById("nikto-nav-prev-btn");
    const nextBtn = document.getElementById("nikto-nav-next-btn");
    const posPill = document.getElementById("nikto-nav-pos-pill");

    if (prevBtn) prevBtn.disabled = idx <= 0;
    if (nextBtn) nextBtn.disabled = idx >= items.length - 1;
    if (posPill) posPill.textContent = `${idx + 1} / ${items.length}`;

    const pane = document.getElementById("nikto-inspect-content");
    if (!pane) return;

    const sev = (f.severity || "INFO").toUpperCase();
    const curl = f.curl_command || `curl -i -k '${f.url}'`;
    const cleanTitle = getCleanTitle(f);
    const cleanDesc = getCleanDescription(f);
    const evidence = f.evidence || "No raw evidence captured.";
    const refUrl = extractReference(f);
    const kb = getNiktoKnowledge(f);

    pane.innerHTML = `
      <div class="nikto-inspect-topbar">
        <!-- Row 1: Severity + Title on Left, Copy Buttons permanently pinned on Right -->
        <div class="nikto-inspect-title-row">
          <div class="nikto-inspect-title-left">
            <span class="nikto-badge nikto-badge-${sev.toLowerCase()}">${sev}</span>
            <span class="nikto-inspect-top-title" title="${escapeHtml(cleanTitle)}">${escapeHtml(cleanTitle)}</span>
          </div>
          <div class="nikto-inspect-actions">
            <button class="btn-nikto-secondary" style="padding:3px 8px;font-size:10.5px;white-space:nowrap;" onclick="window.niktoCopySnippet('curl', ${idx}, this)" title="Copy reproduction cURL">📋 Copy cURL</button>
            <button class="btn-nikto-secondary" style="padding:3px 8px;font-size:10.5px;white-space:nowrap;" onclick="window.niktoCopySnippet('url', ${idx}, this)" title="Copy matched target URL">🔗 Copy URL</button>
            <button class="btn-nikto-secondary" style="padding:3px 8px;font-size:10.5px;white-space:nowrap;" onclick="window.niktoCopySnippet('evidence', ${idx}, this)" title="Copy raw evidence">📑 Copy Evidence</button>
            ${refUrl ? `<a href="${escapeHtml(refUrl)}" target="_blank" rel="noopener noreferrer" class="btn-nikto-secondary" style="text-decoration:none;display:inline-flex;align-items:center;gap:4px;padding:3px 8px;font-size:10.5px;white-space:nowrap;" title="Open official documentation in a new tab">🌐 Docs ↗</a>` : ""}
          </div>
        </div>

        <!-- Row 2: Tag Pills cleanly positioned underneath the Title -->
        <div class="nikto-inspect-tags-row">
          ${f.osvdb ? `<span class="nikto-id-badge">${escapeHtml(f.osvdb)}</span>` : (f.id ? `<span class="nikto-id-badge">${escapeHtml(f.id)}</span>` : "")}
          <span class="nikto-tag-pill nikto-tag-cat" title="Vulnerability Category">🏷️ ${escapeHtml(kb.category)}</span>
          <span class="nikto-tag-pill nikto-tag-owasp" title="OWASP Top 10 Classification">🛡️ ${escapeHtml(kb.owasp)}</span>
          <span class="nikto-tag-pill nikto-tag-cwe" title="Common Weakness Enumeration">🎯 ${escapeHtml(kb.cwe)}</span>
        </div>
      </div>

      <div class="nikto-inspect-split-grid">
        <!-- LEFT COLUMN: Problem Identification, Impact & Evidence -->
        <div class="nikto-inspect-col">
          <!-- Box 1: Finding Overview & Security Threat Analysis -->
          <div class="nikto-inspect-box">
            <div class="nikto-inspect-box-title" style="display:flex;justify-content:space-between;align-items:center;">
              <span>🔎 Vulnerability Overview &amp; Impact</span>
              <span style="font-size:9.5px;color:var(--text3);font-family:var(--mono);font-weight:600;">#${idx + 1} of ${items.length}</span>
            </div>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px;">
              <!-- Title Card -->
              <div>
                <div class="nikto-inspect-sublabel" style="color:var(--blue, #58a6ff);">
                  <span>🏷️</span> FINDING TITLE
                </div>
                <div class="nikto-inspect-title-card">
                  ${escapeHtml(cleanTitle)}
                </div>
              </div>
              <!-- Description Card -->
              <div>
                <div class="nikto-inspect-sublabel" style="color:var(--text3, #8b949e);">
                  <span>📝</span> SCANNER OBSERVATION &amp; DETAILS
                </div>
                <div class="nikto-inspect-desc-card">
                  ${escapeHtml(cleanDesc)}
                </div>
              </div>
              <!-- Threat & Risk Card -->
              <div>
                <div class="nikto-inspect-sublabel" style="color:#f97316;">
                  <span>⚠️</span> SECURITY THREAT &amp; RISK IMPACT
                </div>
                <div class="nikto-inspect-impact-card">
                  ${escapeHtml(kb.impact)}
                </div>
              </div>
            </div>
          </div>

          <!-- Box 2: Matched Target Endpoint -->
          <div class="nikto-inspect-box">
            <div class="nikto-inspect-box-title" style="display:flex;justify-content:space-between;align-items:center;">
              <span>🎯 Matched Target Endpoint</span>
              <button class="btn-nikto-secondary" style="padding:2px 7px;font-size:10px;" onclick="window.niktoCopySnippet('url', ${idx}, this)">🔗 Copy</button>
            </div>
            <div class="nikto-inspect-endpoint-card">
              <span class="nikto-method-badge">${escapeHtml(f.method || "GET")}</span>
              <a href="${escapeHtml(f.url)}" target="_blank" rel="noopener noreferrer" class="nikto-target-url" style="text-decoration:none;font-size:11.5px;word-break:break-all;" title="Open URL in new tab">
                ${escapeHtml(f.url)}
              </a>
            </div>
          </div>

          <!-- Box 3: Raw Finding Output / Evidence -->
          <div class="nikto-inspect-box">
            <div class="nikto-inspect-box-title" style="display:flex;justify-content:space-between;align-items:center;">
              <span>📑 Raw Nikto Scanner Output / Evidence</span>
              <button class="btn-nikto-secondary" style="padding:2px 7px;font-size:10px;" onclick="window.niktoCopySnippet('evidence', ${idx}, this)">📑 Copy</button>
            </div>
            <pre class="nikto-code-block">${escapeHtml(evidence)}</pre>
          </div>
        </div>

        <!-- RIGHT COLUMN: Remediation, Server Hardening & Reproduction -->
        <div class="nikto-inspect-col">
          <!-- Box 4: Remediation & Server Hardening Guidance -->
          <div class="nikto-inspect-box" style="border-left:3px solid #38bdf8;">
            <div class="nikto-inspect-box-title" style="color:#38bdf8;display:flex;justify-content:space-between;align-items:center;">
              <span style="display:flex;align-items:center;gap:6px;">
                <span>🛠️</span> SMART REMEDIATION &amp; SERVER HARDENING
              </span>
              <button class="btn-nikto-secondary" style="padding:2px 7px;font-size:10px;" onclick="window.niktoCopySnippet('recom', ${idx}, this)">📋 Copy Recommended</button>
            </div>

            <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px;">
              <!-- Recommended Baseline -->
              <div>
                <div class="nikto-inspect-sublabel" style="color:var(--text3);">
                  <span>⚡</span> RECOMMENDED VALUE / DIRECTIVE
                </div>
                <div class="nikto-inspect-recom-card">
                  ${escapeHtml(kb.recommended)}
                </div>
              </div>

              <!-- Nginx Server Snippet -->
              <div class="nikto-server-snippet-wrap">
                <div class="nikto-server-snippet-head">
                  <span style="display:flex;align-items:center;gap:5px;">
                    <span>🟢</span> <b>Nginx</b> Configuration (<code>nginx.conf</code>)
                  </span>
                  <button class="btn-nikto-secondary" style="padding:2px 6px;font-size:9.5px;" onclick="window.niktoCopySnippet('nginx', ${idx}, this)" title="Copy Nginx snippet">📋 Copy</button>
                </div>
                <pre class="nikto-server-snippet-code">${escapeHtml(kb.nginx)}</pre>
              </div>

              <!-- Apache Server Snippet -->
              <div class="nikto-server-snippet-wrap">
                <div class="nikto-server-snippet-head">
                  <span style="display:flex;align-items:center;gap:5px;">
                    <span>🔴</span> <b>Apache</b> Configuration (<code>.htaccess / httpd.conf</code>)
                  </span>
                  <button class="btn-nikto-secondary" style="padding:2px 6px;font-size:9.5px;" onclick="window.niktoCopySnippet('apache', ${idx}, this)" title="Copy Apache snippet">📋 Copy</button>
                </div>
                <pre class="nikto-server-snippet-code">${escapeHtml(kb.apache)}</pre>
              </div>
            </div>
          </div>

          <!-- Box 5: Advisory & RFC Documentation (if available) -->
          ${
            refUrl
              ? `
          <div class="nikto-inspect-box nikto-ref-box">
            <div class="nikto-inspect-box-title" style="color:#3fb950;display:flex;justify-content:space-between;align-items:center;">
              <span style="display:flex;align-items:center;gap:6px;">
                <span>📖</span> OFFICIAL ADVISORY &amp; RFC GUIDANCE (SEE)
              </span>
              <button class="btn-nikto-secondary" style="padding:2px 7px;font-size:10px;" onclick="window.niktoCopySnippet('ref', ${idx}, this)">📋 Copy Link</button>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-top:4px;flex-wrap:wrap;">
              <span style="font-size:11px;color:var(--text3);">Advisory reference:</span>
              <a href="${escapeHtml(refUrl)}" target="_blank" rel="noopener noreferrer" class="nikto-ref-link" style="flex:1;min-width:0;">
                <span>🔗</span>
                <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(refUrl)}</span>
                <span style="font-size:10px;opacity:0.75;margin-left:auto;">↗</span>
              </a>
            </div>
          </div>
          `
              : ""
          }

          <!-- Box 6: Reproduction cURL Command -->
          <div class="nikto-inspect-box">
            <div class="nikto-inspect-box-title" style="display:flex;justify-content:space-between;align-items:center;">
              <span>⚡ Reproduction cURL Command</span>
              <button class="btn-nikto-secondary" style="padding:2px 7px;font-size:10px;" onclick="window.niktoCopySnippet('curl', ${idx}, this)">📋 Copy</button>
            </div>
            <pre class="nikto-code-block" style="color:var(--blue, #58a6ff);cursor:pointer;margin-top:2px;" onclick="window.niktoCopySnippet('curl', ${idx}, this)" title="Click to copy cURL">${escapeHtml(curl)}</pre>
          </div>
        </div>
      </div>
    `;
  }

  function navigateFinding(direction) {
    const items = getFilteredFindings();
    if (!items.length) return;

    let cur = (state.selectedFindingIndex === null || state.selectedFindingIndex === undefined || state.selectedFindingIndex < 0) ? 0 : state.selectedFindingIndex;
    let targetIdx = cur + direction;
    if (targetIdx < 0) targetIdx = 0;
    if (targetIdx >= items.length) targetIdx = items.length - 1;

    selectFinding(targetIdx);

    const tbody = document.getElementById("nikto-table-body");
    if (tbody) {
      const row = tbody.querySelector(`.nikto-row[data-idx="${targetIdx}"]`);
      if (row) {
        row.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    }
  }

  function clearInspector() {
    const pane = document.getElementById("nikto-inspect-content");
    if (pane) {
      pane.innerHTML = `<div style="text-align:center;color:var(--text3);margin:auto;font-size:11.5px;">Select an item from the table above to view full details and cURL.</div>`;
    }
    const posPill = document.getElementById("nikto-nav-pos-pill");
    if (posPill) posPill.textContent = "- / -";
    const prevBtn = document.getElementById("nikto-nav-prev-btn");
    const nextBtn = document.getElementById("nikto-nav-next-btn");
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
  }

  // ── Stat Cards & Filtering ─────────────────────────────────────────────────

  function renderStats() {
    const s = state.stats;
    const map = {
      "nikto-stat-total": s.total,
      "nikto-stat-crit": s.critical,
      "nikto-stat-high": s.high,
      "nikto-stat-med": s.medium,
      "nikto-stat-low": s.low,
      "nikto-stat-info": s.info,
    };
    for (const [id, val] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el) el.textContent = val || 0;
    }
  }

  function filterBySev(sev) {
    state.activeFilter = sev;
    const sevs = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    sevs.forEach((s) => {
      const card = document.getElementById(`nikto-card-filter-${s}`);
      if (card) card.classList.toggle("active", s === sev);
    });

    const label = document.getElementById("nikto-active-filter-label");
    if (label) label.textContent = `Showing: ${sev}`;

    renderTable();
  }

  function search(val) {
    state.searchTerm = val || "";
    renderTable();
  }

  // ── Draggable Split Resizer ────────────────────────────────────────────────

  function initVResize() {
    const resizer = document.getElementById("nikto-vresize-bar");
    const topPane = document.getElementById("nikto-table-pane");
    const botPane = document.getElementById("nikto-inspect-pane");
    if (!resizer || !topPane || !botPane) return;

    let isDragging = false;
    let startY = 0;
    let startTopHeight = 0;

    resizer.addEventListener("mousedown", (e) => {
      isDragging = true;
      startY = e.clientY;
      startTopHeight = topPane.getBoundingClientRect().height;
      resizer.classList.add("dragging");
      document.body.style.userSelect = "none";
      document.body.style.cursor = "row-resize";
    });

    document.addEventListener("mousemove", (e) => {
      if (!isDragging) return;
      const dy = e.clientY - startY;
      const newHeight = Math.max(90, startTopHeight + dy);
      topPane.style.flex = "none";
      topPane.style.height = `${newHeight}px`;
    });

    document.addEventListener("mouseup", () => {
      if (isDragging) {
        isDragging = false;
        resizer.classList.remove("dragging");
        document.body.style.userSelect = "";
        document.body.style.cursor = "";
      }
    });
  }

  // ── Report Export ──────────────────────────────────────────────────────────

  async function exportReport() {
    if (!state.target && !state.findings.length) {
      showToast("⚠️ No scan results available to export.", "warning");
      return;
    }

    showToast("⏳ Saving Nikto HTML report to Downloads...", "info");

    try {
      // 1. Direct Backend Save to local user Downloads folder
      const res = await fetch(`${API_BASE}/api/scan/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: state.target,
          findings: state.findings,
          stats: state.stats,
          banner: state.serverBanner,
        }),
      });

      if (!res.ok) {
        throw new Error("Save endpoint returned status " + res.status);
      }

      const data = await res.json();
      if (data && data.success) {
        showToast(`✅ Saved to Downloads: ${data.filename}`, "success");
        appendTerminalLogs([`[Report] ✅ Successfully saved report: ${data.path}`]);

        // If pywebview has native save API, also sync with it safely
        if (window.pywebview?.api?.save_file && data.html) {
          try {
            await window.pywebview.api.save_file(data.html, data.filename);
          } catch (_) {}
        }
        return;
      }
    } catch (e) {
      console.warn("Backend save-report failed, falling back to pywebview api / browser save", e);
    }

    // Fallback: If backend save-report wasn't reached or returned error
    try {
      const res = await fetch(`${API_BASE}/api/scan/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: state.target,
          findings: state.findings,
          stats: state.stats,
          banner: state.serverBanner,
        }),
      });

      if (!res.ok) throw new Error("Export returned status " + res.status);
      const htmlText = await res.text();
      const cleanHost = (state.target || "Target").replace(/[^a-zA-Z0-9]/g, "_");
      const filename = `Nikto_Audit_${cleanHost}_${Date.now()}.html`;

      // If in pywebview, use native pywebview save_file dialog (NEVER use a.click() which overwrites app!)
      if (window.pywebview?.api?.save_file) {
        await window.pywebview.api.save_file(htmlText, filename);
        showToast(`✅ Report saved: ${filename}`, "success");
        return;
      }

      // Only in standard browser (non-webview) do safe blob download
      const blob = new Blob([htmlText], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1500);
      showToast("Nikto HTML Report downloaded successfully!", "success");
    } catch (err) {
      showToast("❌ Report export failed: " + err.message, "error");
    }
  }

  // ── Clipboard Helpers ──────────────────────────────────────────────────────

  function copyCurl(idx, btn) {
    const f = (getFilteredFindings()[idx]) || state.findings[idx];
    if (!f) return;
    const cmd = f.curl_command || `curl -i -k '${f.url}'`;
    navigator.clipboard.writeText(cmd).then(() => {
      flashBtn(btn, "Copied!");
    });
  }

  function copyUrl(idx, btn) {
    const f = (getFilteredFindings()[idx]) || state.findings[idx];
    if (!f || !f.url) return;
    navigator.clipboard.writeText(f.url).then(() => {
      flashBtn(btn, "Copied URL!");
    });
  }

  function copyEvidence(idx, btn) {
    const f = (getFilteredFindings()[idx]) || state.findings[idx];
    if (!f) return;
    navigator.clipboard.writeText(f.evidence || f.description || "").then(() => {
      flashBtn(btn, "Copied Evidence!");
    });
  }

  function copyText(text, btn) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      flashBtn(btn, "Copied!");
    }).catch(() => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        flashBtn(btn, "Copied!");
      } catch (e) {
        showToast("Failed to copy", "error");
      }
    });
  }

  function copyRef(idx, btn) {
    const f = (getFilteredFindings()[idx]) || state.findings[idx];
    if (!f) return;
    const ref = extractReference(f);
    if (!ref) return;
    copyText(ref, btn);
  }

  function copySnippet(kind, idx, btn) {
    const items = getFilteredFindings();
    const f = items[idx] || state.findings[idx];
    if (!f) return;
    const kb = getNiktoKnowledge(f);
    let text = "";
    let label = "Copied!";
    if (kind === "nginx") {
      text = kb.nginx || "";
      label = "Copied Nginx!";
    } else if (kind === "apache") {
      text = kb.apache || "";
      label = "Copied Apache!";
    } else if (kind === "curl") {
      text = f.curl_command || `curl -i -k '${f.url}'`;
      label = "Copied cURL!";
    } else if (kind === "url") {
      text = f.url || "";
      label = "Copied URL!";
    } else if (kind === "evidence") {
      text = f.evidence || f.description || "";
      label = "Copied Evidence!";
    } else if (kind === "ref") {
      text = extractReference(f);
      label = "Copied Link!";
    } else if (kind === "recom") {
      text = kb.recommended || "";
      label = "Copied!";
    }
    if (text) {
      navigator.clipboard.writeText(text).then(() => {
        flashBtn(btn, label);
      }).catch(() => {
        copyText(text, btn);
      });
    }
  }

  function flashBtn(btn, msg) {
    if (!btn) return;
    const old = btn.textContent;
    btn.textContent = `✓ ${msg}`;
    setTimeout(() => {
      btn.textContent = old;
    }, 1500);
  }

  function showToast(msg, type) {
    if (typeof window.showToast === "function") {
      window.showToast(msg, type);
    } else {
      console.log(`[Toast ${type}]: ${msg}`);
    }
  }

  function resetNiktoForm() {
    if (state.status === "running") {
      showToast("Cannot reset configuration while scan is in progress.", "warning");
      return;
    }

    const curlInp = document.getElementById("nikto-curl-input");
    const targetInp = document.getElementById("nikto-target-input");
    const portInp = document.getElementById("nikto-port-input");
    const sslCheck = document.getElementById("nikto-ssl-check");
    const pauseSel = document.getElementById("nikto-pause-select");
    const evasionSel = document.getElementById("nikto-evasion-select");
    const maxtimeSel = document.getElementById("nikto-maxtime-select");
    const uaInp = document.getElementById("nikto-ua-input");

    if (curlInp) curlInp.value = "";
    if (targetInp) targetInp.value = "";
    if (portInp) portInp.value = "";
    if (sslCheck) sslCheck.checked = true;
    if (pauseSel) pauseSel.value = "0";
    if (evasionSel) evasionSel.value = "";
    if (maxtimeSel) maxtimeSel.value = "30m";
    if (uaInp) uaInp.value = "";

    // Reset tuning to default safe
    tuningSelect("default");

    showToast("Nikto configuration reset to defaults.", "info");
  }

  function tuningSelect(mode) {
    if (state.status === "running") return;

    const cbs = document.querySelectorAll(".nikto-tuning-cb");
    const defaultVals = new Set(["1", "2", "3", "b", "d", "e"]);
    cbs.forEach((cb) => {
      if (mode === "all") {
        cb.checked = true;
      } else if (mode === "none") {
        cb.checked = false;
      } else if (mode === "default") {
        cb.checked = defaultVals.has(cb.value);
      }
    });
  }

  // ── Keyboard Navigation (ArrowUp / ArrowDown) ─────────────────────────────

  window.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;

    // Check if nikto tab is active in top navigation
    const niktoTabBtn = document.querySelector('.tab-btn[data-tool="nikto"]');
    if (niktoTabBtn && !niktoTabBtn.classList.contains("active")) return;

    // Check if on Results sub-tab (#nikto-view-results)
    const resultsView = document.getElementById("nikto-view-results");
    if (!resultsView || !resultsView.classList.contains("active")) return;

    // Don't intercept if user is typing in input, select or textarea
    const tag = (document.activeElement && document.activeElement.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

    const items = getFilteredFindings();
    if (!items.length) return;

    e.preventDefault();
    navigateFinding(e.key === "ArrowDown" ? 1 : -1);
  });

  // ── Global Window Exports ──────────────────────────────────────────────────

  window.niktoSwitchTab = switchTab;
  window.niktoParseCurl = parseCurl;
  window.niktoStartScan = startScan;
  window.niktoStopScan = stopScan;
  window.niktoResetForm = resetNiktoForm;
  window.niktoTuningSelect = tuningSelect;
  window.niktoFilterBySev = filterBySev;
  window.niktoSearch = search;
  window.niktoExportReport = exportReport;
  window.niktoExportHtmlReport = exportReport;
  window.niktoCopyCurl = copyCurl;
  window.niktoCopyUrl = copyUrl;
  window.niktoCopyEvidence = copyEvidence;
  window.niktoCopyRef = copyRef;
  window.niktoCopyText = copyText;
  window.niktoCopySnippet = copySnippet;
  window.niktoNavigateFinding = navigateFinding;
  window.niktoSwitchTerminalMode = switchTerminalMode;
  window.niktoToggleAutoScroll = toggleAutoScroll;
  window.niktoClearTerminal = clearTerminalLogs;
  window.niktoCopyTerminalLogs = copyTerminalLogs;
  window.niktoRefreshEngine = () => checkBinaryStatus(true);
  window.niktoUpdateEngine = updateEngine;
  window.niktoVerifyEngine = verifyEngine;
})();
