/**
 * Nuclei Scanner UI Controller — API Sentinel (Port 8797)
 * Professional Cyberpunk / Hacker Architecture
 * Fully Interactive Filter Cards, Zero-Crash HTML Export & Clickable Engine Settings
 */

(function () {
  const NUCLEI_API = "http://127.0.0.1:8797";

  const state = {
    activeTab: "setup", // setup | results | terminal | engine
    activeSourceMode: "curl", // curl | swagger | har | multi
    baseUrl: "",
    swaggerOriginalBaseUrl: "",
    swaggerEndpoints: [],
    harOriginalBaseUrl: "",
    harEndpoints: [],
    targets: [],
    headers: {},
    selectedTags: ["api", "misconfig", "exposure"],
    currentJobId: null,
    pollTimer: null,
    eventSource: null,
    findings: [],
    selectedFindingIndex: -1,
    stats: { total_targets: 0, findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    activeFilter: "ALL",
    searchTerm: "",
    binaryInfo: null,
    installPollTimer: null,
    activeTerminalMode: "clean",
    verboseLogs: [],
    maxVerboseLines: 200,
    autoScroll: false,
    isScanning: false,
  };

  // ── Initialization ─────────────────────────────────────────────────────────

  function initNuclei() {
    checkBinaryStatus(false);
    bindVResize();
    bindExplicitButtons();
    updateActiveSourceSummary();
  }

  function bindExplicitButtons() {
    // Explicit event listeners as fallback to inline onclick
    const checkBtn = document.getElementById("btn-nuclei-check-status");
    if (checkBtn) {
      checkBtn.addEventListener("click", () => checkBinaryStatus(true));
    }
    const installBtn = document.getElementById("btn-nuclei-install-action");
    if (installBtn) {
      installBtn.addEventListener("click", () => triggerAutoInstall());
    }
    const updateBtn = document.getElementById("btn-nuclei-update-templates-action");
    if (updateBtn) {
      updateBtn.addEventListener("click", () => updateTemplates());
    }
  }

  // ── Tab Switching ──────────────────────────────────────────────────────────

  function switchTab(tabId) {
    state.activeTab = tabId;

    ["setup", "results", "terminal", "engine"].forEach((t) => {
      const btn = document.getElementById(`nuclei-tab-btn-${t}`);
      const view = document.getElementById(`nuclei-view-${t}`);
      if (btn) btn.classList.toggle("active", t === tabId);
      if (view) view.classList.toggle("active", t === tabId);
    });
  }

  // ── Source Mode (cURL | Swagger | HAR | Multi-URL) ─────────────────────────

  function setSourceMode(mode) {
    if (state.isScanning) return;
    state.activeSourceMode = mode;
    document.querySelectorAll(".nuclei-source-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-mode") === mode);
    });

    const cPane = document.getElementById("nuclei-mode-pane-curl");
    const sPane = document.getElementById("nuclei-mode-pane-swagger");
    const hPane = document.getElementById("nuclei-mode-pane-har");
    const mPane = document.getElementById("nuclei-mode-pane-multi");

    if (cPane) cPane.style.display = mode === "curl" ? "block" : "none";
    if (sPane) sPane.style.display = mode === "swagger" ? "block" : "none";
    if (hPane) hPane.style.display = mode === "har" ? "block" : "none";
    if (mPane) mPane.style.display = mode === "multi" ? "block" : "none";

    // Synchronize Base URL and active targets for the selected mode
    const bInput = document.getElementById("nuclei-base-url");
    if (mode === "har" && state.harOriginalBaseUrl) {
      if (bInput) {
        bInput.value = state.harOriginalBaseUrl;
        bInput.dataset.autoFilled = "true";
      }
      state.baseUrl = state.harOriginalBaseUrl;
      updateBaseUrlBadge("auto");
      recomputeHarTargets(state.baseUrl);
    } else if (mode === "swagger" && state.swaggerOriginalBaseUrl) {
      if (bInput) {
        bInput.value = state.swaggerOriginalBaseUrl;
        bInput.dataset.autoFilled = "true";
      }
      state.baseUrl = state.swaggerOriginalBaseUrl;
      updateBaseUrlBadge("auto");
      recomputeSwaggerTargets(state.baseUrl);
    }

    updateActiveSourceSummary();
  }

  function updateActiveSourceSummary() {
    const badge = document.getElementById("nuclei-active-source-badge");
    const desc = document.getElementById("nuclei-active-source-desc");
    if (!badge) return;

    if (state.activeSourceMode === "curl") {
      badge.textContent = "Active Source: 📄 cURL Command";
      badge.style.color = "var(--blue, #58a6ff)";
      badge.style.background = "rgba(88, 166, 255, 0.15)";
      badge.style.borderColor = "rgba(88, 166, 255, 0.3)";
      if (desc) desc.textContent = "Scan will execute against the parsed cURL target host and path.";
    } else if (state.activeSourceMode === "swagger") {
      const cnt = state.swaggerEndpoints?.length || 0;
      badge.textContent = `Active Source: 📁 Swagger / OpenAPI (${cnt} Endpoints)`;
      badge.style.color = "var(--purple, #bc8cff)";
      badge.style.background = "rgba(188, 140, 255, 0.15)";
      badge.style.borderColor = "rgba(188, 140, 255, 0.3)";
      if (desc) desc.textContent = cnt > 0 ? `Scan will execute against all ${cnt} endpoints loaded from Swagger.` : "Paste a Swagger URL/spec or upload a file to extract endpoints.";
    } else if (state.activeSourceMode === "har") {
      const cnt = state.harEndpoints?.length || 0;
      badge.textContent = `Active Source: 📦 HAR Network Archive (${cnt} Endpoints)`;
      badge.style.color = "var(--green, #3fb950)";
      badge.style.background = "rgba(63, 185, 80, 0.15)";
      badge.style.borderColor = "rgba(63, 185, 80, 0.3)";
      if (desc) desc.textContent = cnt > 0 ? `Scan will execute against all ${cnt} unique API routes extracted from HAR.` : "Upload a .har file to extract recorded API endpoints.";
    } else if (state.activeSourceMode === "multi") {
      const rawLines = (document.getElementById("nuclei-multi-input")?.value || "").split("\n").filter((l) => l.trim()).length;
      badge.textContent = `Active Source: 🌐 Multi-Target Batch (${rawLines} URLs)`;
      badge.style.color = "var(--yellow, #d29922)";
      badge.style.background = "rgba(210, 153, 34, 0.15)";
      badge.style.borderColor = "rgba(210, 153, 34, 0.3)";
      if (desc) desc.textContent = "Scan will execute against each target endpoint entered in the batch textarea.";
    }
  }

  // ── Profile Toggle ─────────────────────────────────────────────────────────

  function toggleProfile(cardEl, tag) {
    if (state.isScanning) return;
    const idx = state.selectedTags.indexOf(tag);
    const activeText = cardEl.querySelector(".nuclei-profile-header span:last-child");

    if (idx >= 0) {
      state.selectedTags.splice(idx, 1);
      cardEl.classList.remove("active");
      if (activeText) {
        activeText.textContent = "Inactive";
        activeText.style.color = "var(--text3)";
      }
    } else {
      state.selectedTags.push(tag);
      cardEl.classList.add("active");
      if (activeText) {
        activeText.textContent = "✓ Active";
        activeText.style.color = "var(--blue)";
      }
    }
  }

  // ── Engine Binary Check & 1-Click Install ──────────────────────────────────

  async function checkBinaryStatus(showToastMsg = false) {
    const checkBtn = document.getElementById("btn-nuclei-check-status");
    if (checkBtn) {
      checkBtn.innerHTML = "⏳ Checking...";
      checkBtn.disabled = true;
    }

    try {
      const res = await fetch(`${NUCLEI_API}/api/binary-info`);
      if (res.ok) {
        const data = await res.json();
        state.binaryInfo = data;
        updateEngineUI(data);

        const feedbackBox = document.getElementById("nuclei-status-feedback-box");
        if (feedbackBox) {
          feedbackBox.style.display = "block";
          feedbackBox.innerHTML = `<div>✅ Status checked at ${new Date().toLocaleTimeString()} — ${
            data.installed
              ? `Official Nuclei ${data.version || "Active"} (${data.templates_count || 0} templates)`
              : "Native Baseline Probes Active"
          }</div>`;
        }

        if (showToastMsg) {
          showToast(
            data.installed
              ? `🟢 Official Nuclei Engine Ready (${data.version || "Installed"})`
              : "⚡ Native API Baseline Mode Active",
            "success"
          );
        }
      } else {
        if (showToastMsg) showToast("⚠️ Backend returned status " + res.status, "warn");
      }
    } catch (e) {
      console.warn("[Nuclei] Binary check error:", e);
      if (showToastMsg) showToast("❌ Could not reach Nuclei backend (Port 8797)", "error");
    } finally {
      if (checkBtn) {
        checkBtn.innerHTML = "🔄 Check Status";
        checkBtn.disabled = false;
      }
    }
  }

  function updateEngineUI(info) {
    const topBadge = document.getElementById("nuclei-top-engine-badge");
    const modeText = document.getElementById("nuclei-engine-mode-text");
    const verText = document.getElementById("nuclei-engine-version-text");
    const pathText = document.getElementById("nuclei-engine-path-text");
    const tmplText = document.getElementById("nuclei-engine-templates-text");

    if (info && info.installed) {
      if (topBadge) {
        topBadge.textContent = "🟢 Official Nuclei Engine";
        topBadge.style.color = "var(--green)";
        topBadge.style.borderColor = "var(--green)";
        topBadge.style.background = "rgba(63, 185, 80, 0.15)";
      }
      if (modeText) {
        modeText.textContent = "🟢 Official Nuclei CLI (Full Engine)";
        modeText.style.color = "var(--green)";
      }
      if (verText) {
        verText.textContent = info.version || "Installed";
        verText.style.color = "var(--text)";
      }
      if (pathText) {
        pathText.textContent = info.binary_path || "/opt/homebrew/bin/nuclei";
      }
      if (tmplText) {
        tmplText.textContent = `${(info.templates_count || 14000).toLocaleString()} Community Templates`;
        tmplText.style.color = "var(--green)";
      }
    } else {
      if (topBadge) {
        topBadge.textContent = "⚡ Native Baseline";
        topBadge.style.color = "var(--yellow)";
        topBadge.style.borderColor = "var(--yellow)";
        topBadge.style.background = "rgba(210, 153, 34, 0.15)";
      }
      if (modeText) {
        modeText.textContent = "⚡ Native API Baseline Mode";
        modeText.style.color = "var(--yellow)";
      }
      if (verText) {
        verText.textContent = "Not Installed";
        verText.style.color = "var(--text3)";
      }
      if (pathText) {
        pathText.textContent = "None (Using built-in Python runner)";
      }
      if (tmplText) {
        tmplText.textContent = "10 Native High-Priority Security Rules";
        tmplText.style.color = "var(--text)";
      }
    }
  }

  async function triggerAutoInstall() {
    const installBtn = document.getElementById("btn-nuclei-install-action");
    const logBox = document.getElementById("nuclei-install-logs-box");

    if (installBtn) {
      installBtn.disabled = true;
      installBtn.innerHTML = "⏳ Installing Nuclei...";
    }
    if (logBox) {
      logBox.style.display = "block";
      logBox.innerHTML = `<div>[${new Date().toLocaleTimeString()}] 🚀 Launching Homebrew installation ('brew install nuclei')...</div>`;
    }

    appendTerminalLog(`[Installer] Starting Homebrew install in background ('brew install nuclei')...`);

    try {
      const res = await fetch(`${NUCLEI_API}/api/install-nuclei`, { method: "POST" });
      const data = await res.json();
      showToast("🚀 Installation running in background...", "info");

      if (state.installPollTimer) clearInterval(state.installPollTimer);
      state.installPollTimer = setInterval(async () => {
        try {
          const sRes = await fetch(`${NUCLEI_API}/api/install-status`);
          const sData = await sRes.json();
          if (logBox && sData.logs) {
            logBox.innerHTML = sData.logs.map((l) => `<div>${escapeHtml(l)}</div>`).join("");
            logBox.scrollTop = logBox.scrollHeight;
          }
          if (sData.status === "completed") {
            clearInterval(state.installPollTimer);
            showToast("🎉 Nuclei installation complete!", "success");
            if (installBtn) {
              installBtn.disabled = false;
              installBtn.innerHTML = "⬇️ Run 1-Click Install";
            }
            appendTerminalLog(`[Installer] ✅ Nuclei installation successfully completed.`);
            checkBinaryStatus(true);
          } else if (sData.status === "failed") {
            clearInterval(state.installPollTimer);
            showToast("❌ Installation failed. Check logs.", "error");
            if (installBtn) {
              installBtn.disabled = false;
              installBtn.innerHTML = "⬇️ Run 1-Click Install";
            }
            appendTerminalLog(`[Installer] ❌ Nuclei installation failed.`);
          }
        } catch (pe) {
          console.warn("Poll install error:", pe);
        }
      }, 1000);
    } catch (e) {
      showToast("❌ Could not trigger install: " + e.message, "error");
      if (installBtn) {
        installBtn.disabled = false;
        installBtn.innerHTML = "⬇️ Run 1-Click Install";
      }
    }
  }

  async function updateTemplates() {
    const updateBtn = document.getElementById("btn-nuclei-update-templates-action");
    const logBox = document.getElementById("nuclei-templates-logs-box");

    if (updateBtn) {
      updateBtn.disabled = true;
      updateBtn.innerHTML = "⏳ Updating Templates...";
    }
    if (logBox) {
      logBox.style.display = "block";
      logBox.innerHTML = `<div>[${new Date().toLocaleTimeString()}] 🔄 Fetching latest ProjectDiscovery community security templates...</div>`;
    }

    showToast("⏳ Updating Nuclei templates...", "info");
    appendTerminalLog(`[Templates] Running 'nuclei -update-templates'...`);

    try {
      const res = await fetch(`${NUCLEI_API}/api/update-templates`, { method: "POST" });
      const data = await res.json();
      if (data.success) {
        showToast("✅ Templates updated successfully!", "success");
        if (logBox) {
          logBox.innerHTML = `<div>${escapeHtml(data.output || "Templates up to date.")}</div>`;
        }
        appendTerminalLog(`[Templates] ✅ Update completed: ${data.output || "Success"}`);
        checkBinaryStatus(false);
      } else {
        showToast("⚠️ Template update: " + (data.output || "Error"), "warn");
        if (logBox) {
          logBox.innerHTML = `<div>⚠️ ${escapeHtml(data.output || "Failed to update templates")}</div>`;
        }
      }
    } catch (e) {
      showToast("❌ Update error: " + e.message, "error");
      if (logBox) {
        logBox.innerHTML = `<div>❌ Error: ${escapeHtml(e.message)}</div>`;
      }
    } finally {
      if (updateBtn) {
        updateBtn.disabled = false;
        updateBtn.innerHTML = "🔄 Update Templates Now";
      }
    }
  }

  // ── Auto Parsing Handlers ──────────────────────────────────────────────────

  async function parseCurlInput() {
    const txt = (document.getElementById("nuclei-curl-input")?.value || "").trim();
    if (!txt) {
      showToast("⚠️ Paste a cURL command first.", "warn");
      return;
    }

    try {
      const res = await fetch(`${NUCLEI_API}/api/parse-curl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ curl: txt }),
      });
      const data = await res.json();
      if (data.success) {
        if (data.base_url) {
          const bInput = document.getElementById("nuclei-base-url");
          if (bInput) bInput.value = data.base_url;
          state.baseUrl = data.base_url;
        }
        if (data.url) {
          state.targets = [data.url];
        }
        if (data.headers) {
          state.headers = data.headers;
          const hInput = document.getElementById("nuclei-headers-input");
          if (hInput) {
            hInput.value = Object.entries(data.headers)
              .map(([k, v]) => `${k}: ${v}`)
              .join("\n");
          }
        }
        showToast("✅ Extracted: Base URL & Headers populated!", "success");
      }
    } catch (e) {
      showToast("❌ Failed to parse cURL: " + e.message, "error");
    }
  }

  function applyParsedSwaggerData(data, sourceLabel) {
    const detectedBase = (data.base_url || data.detected_base_url || "").trim();
    state.swaggerOriginalBaseUrl = detectedBase;
    state.swaggerEndpoints = data.endpoints || [];

    const bInput = document.getElementById("nuclei-base-url");
    // If input is empty or was previously auto-detected, update with detectedBase
    if (bInput && (!bInput.value.trim() || bInput.dataset.autoFilled === "true" || !state.baseUrlOverride)) {
      bInput.value = detectedBase;
      bInput.dataset.autoFilled = "true";
      state.baseUrl = detectedBase;
      updateBaseUrlBadge("auto");
    } else {
      state.baseUrl = (bInput?.value || detectedBase || "").trim();
      updateBaseUrlBadge(state.baseUrl === detectedBase ? "auto" : "custom");
    }

    recomputeSwaggerTargets(state.baseUrl);

    const countEl = document.getElementById("nuclei-swagger-count");
    const countMsg = document.getElementById("nuclei-swagger-count-msg");
    const numEl = document.getElementById("nuclei-swagger-endpoints-num");
    if (countEl) {
      countEl.style.display = "flex";
      const src = sourceLabel ? `from ${sourceLabel}` : "from Swagger specification";
      if (countMsg) countMsg.textContent = `✅ Successfully extracted ${state.targets.length} endpoints ${src}!`;
      if (numEl) numEl.textContent = state.targets.length;
    }
    renderSwaggerEndpointsPreview();
    showToast(`✅ Extracted ${state.targets.length} endpoints ready for scan!`, "success");
  }

  function recomputeSwaggerTargets(customBaseUrl) {
    const base = (customBaseUrl !== undefined ? customBaseUrl : (document.getElementById("nuclei-base-url")?.value || state.baseUrl || "")).trim();
    state.baseUrl = base;
    const cleanBase = base.replace(/\/+$/, "");

    if (!state.swaggerEndpoints || !state.swaggerEndpoints.length) {
      return;
    }

    state.targets = state.swaggerEndpoints.map((e) => {
      if (typeof e === "string") {
        if (!cleanBase) return e;
        try {
          const u = new URL(e);
          return cleanBase + u.pathname + u.search;
        } catch (_) {
          return cleanBase + (e.startsWith("/") ? e : "/" + e);
        }
      }

      // If endpoint has clean path (e.g. "/rest/travel-perdiem-policies")
      const normPath = e.path || "";
      if (cleanBase && normPath) {
        return cleanBase + (normPath.startsWith("/") ? normPath : "/" + normPath);
      }

      // If full_url is present, and we have cleanBase, replace the original base URL in full_url
      if (e.full_url) {
        if (cleanBase && state.swaggerOriginalBaseUrl) {
          const origClean = state.swaggerOriginalBaseUrl.replace(/\/+$/, "");
          if (e.full_url.startsWith(origClean)) {
            return cleanBase + e.full_url.slice(origClean.length);
          }
        }
        if (cleanBase) {
          try {
            const u = new URL(e.full_url);
            return cleanBase + u.pathname + u.search;
          } catch (_) {}
        }
        return e.full_url;
      }

      return normPath;
    }).filter(Boolean);

    renderSwaggerEndpointsPreview();
  }

  function onBaseUrlChange(newVal) {
    state.baseUrl = (newVal || "").trim();
    const bInput = document.getElementById("nuclei-base-url");
    if (bInput) bInput.dataset.autoFilled = "false";
    state.baseUrlOverride = true;

    if (state.activeSourceMode === "swagger" && state.swaggerEndpoints?.length) {
      recomputeSwaggerTargets(state.baseUrl);
    } else if (state.activeSourceMode === "har" && state.harEndpoints?.length) {
      recomputeHarTargets(state.baseUrl);
    }
    const origBase = state.activeSourceMode === "har" ? state.harOriginalBaseUrl : state.swaggerOriginalBaseUrl;
    updateBaseUrlBadge(state.baseUrl && state.baseUrl !== origBase ? "custom" : "auto");
  }

  function updateBaseUrlBadge(type) {
    const badge = document.getElementById("nuclei-base-url-status");
    if (!badge) return;
    if (type === "custom") {
      badge.textContent = "● Override Active";
      badge.style.color = "var(--blue, #58a6ff)";
    } else {
      badge.textContent = "● Auto-detected";
      badge.style.color = "var(--green, #238636)";
    }
  }

  function updateAuthBadge(headers) {
    const badge = document.getElementById("nuclei-auth-status");
    if (!badge) return;
    const count = headers ? Object.keys(headers).length : 0;
    if (count === 0) {
      badge.textContent = "Bearer token or Header: Value";
      badge.style.color = "var(--text2, #8b949e)";
    } else if (headers && (headers["Authorization"] || headers["authorization"])) {
      badge.textContent = `● Auth Token Active (${count > 1 ? count + " headers" : "Bearer"})`;
      badge.style.color = "var(--green, #238636)";
    } else {
      badge.textContent = `● ${count} Custom Header${count > 1 ? "s" : ""} Set`;
      badge.style.color = "var(--green, #238636)";
    }
  }

  function parseHeadersInput(text) {
    if (!text || !text.trim()) return {};
    const headers = {};
    const rawLines = text.split("\n").map((l) => l.trim()).filter(Boolean);

    let pendingAuthBearer = false;
    let accumulatedToken = "";

    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i];

      // Standard Header: Value
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        const k = line.slice(0, colonIdx).trim();
        const v = line.slice(colonIdx + 1).trim();
        if (k && v) {
          if (k.toLowerCase() === "authorization" && v.toLowerCase() === "bearer") {
            pendingAuthBearer = true;
            continue;
          }
          headers[k] = v;
          continue;
        }
      }

      // Line is just "Bearer" or "bearer"
      if (line.toLowerCase() === "bearer") {
        pendingAuthBearer = true;
        continue;
      }

      // Line starts with "Bearer " (e.g. "Bearer eyJhbGciOi...")
      if (line.toLowerCase().startsWith("bearer ")) {
        const token = line.slice(7).trim();
        headers["Authorization"] = "Bearer " + token;
        continue;
      }

      // Line starts with "Basic "
      if (line.toLowerCase().startsWith("basic ")) {
        headers["Authorization"] = line;
        continue;
      }

      // If pending Bearer, this line is the token (or first chunk of multi-line token)
      if (pendingAuthBearer) {
        accumulatedToken += line;
        while (i + 1 < rawLines.length && !rawLines[i + 1].includes(":") && !rawLines[i + 1].includes(" ")) {
          i++;
          accumulatedToken += rawLines[i];
        }
        headers["Authorization"] = "Bearer " + accumulatedToken;
        pendingAuthBearer = false;
        continue;
      }

      // Raw JWT (starts with eyJ)
      if (line.startsWith("eyJ")) {
        let jwt = line;
        while (i + 1 < rawLines.length && !rawLines[i + 1].includes(":") && !rawLines[i + 1].includes(" ")) {
          i++;
          jwt += rawLines[i];
        }
        headers["Authorization"] = "Bearer " + jwt;
        continue;
      }
    }

    return headers;
  }

  function onHeadersChange(text) {
    state.tokenOverriddenByUser = true;
    const hInput = document.getElementById("nuclei-headers-input");
    if (hInput) hInput.dataset.autoFilled = "false";
    const headers = parseHeadersInput(text);
    state.headers = headers;
    updateAuthBadge(headers);
  }

  function toggleSwaggerEndpoints() {
    const el = document.getElementById("nuclei-swagger-endpoints-preview");
    if (!el) return;
    if (el.style.display === "none" || !el.style.display) {
      el.style.display = "block";
      renderSwaggerEndpointsPreview();
    } else {
      el.style.display = "none";
    }
  }

  function renderSwaggerEndpointsPreview() {
    const el = document.getElementById("nuclei-swagger-endpoints-preview");
    if (!el) return;
    if (!state.targets || !state.targets.length) {
      el.innerHTML = '<div style="color:var(--text2,#8b949e);padding:6px;">No endpoints loaded yet.</div>';
      return;
    }
    const html = state.targets.slice(0, 100).map((t, idx) => {
      return `<div style="padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;gap:8px;align-items:center;">
        <span style="color:var(--text2,#8b949e);font-size:10px;width:24px;">#${idx + 1}</span>
        <span style="color:var(--blue,#58a6ff);word-break:break-all;">${escapeHtml(t)}</span>
      </div>`;
    }).join("");
    const moreText = state.targets.length > 100 ? `<div style="margin-top:6px;color:var(--yellow,#d29922);font-size:11px;">...and ${state.targets.length - 100} more endpoints</div>` : "";
    el.innerHTML = html + moreText;
  }

  async function uploadSwaggerFile(input) {
    if (state.isScanning) return;
    const file = input?.files?.[0];
    if (!file) return;

    const fnEl = document.getElementById("nuclei-swagger-filename");
    if (fnEl) {
      const sizeKb = (file.size / 1024).toFixed(1);
      fnEl.innerHTML = `<span style="color:var(--blue,#58a6ff);font-weight:600;">📄 ${escapeHtml(file.name)}</span> <span style="font-size:11px;color:var(--text2,#8b949e);">(${sizeKb} KB)</span>`;
    }
    const resetBtn = document.getElementById("nuclei-swagger-file-reset");
    if (resetBtn) resetBtn.style.display = "block";

    showToast(`⏳ Reading and parsing "${file.name}"...`, "info");

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result;
      if (!content || !content.trim()) {
        showToast("⚠️ The selected file is empty.", "warn");
        return;
      }

      // Preview snippet into text box if convenient
      const sTextInput = document.getElementById("nuclei-swagger-text");
      if (sTextInput && content.length < 50000) {
        sTextInput.value = content.length > 300 ? content.slice(0, 300) + "..." : content;
      }

      try {
        const res = await fetch(`${NUCLEI_API}/api/parse-swagger`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ spec_text: content, headers: state.headers }),
        });
        const data = await res.json();
        if (data.success) {
          applyParsedSwaggerData(data, `"${file.name}"`);
        } else {
          showToast("❌ Could not parse Swagger: " + (data.error || "Invalid specification"), "error");
        }
      } catch (err) {
        showToast("❌ Failed to parse Swagger file: " + err.message, "error");
      }
    };
    reader.onerror = () => {
      showToast("❌ Error reading local file.", "error");
    };
    reader.readAsText(file);
  }

  function clearSwaggerFile() {
    if (state.isScanning) return;
    const inp = document.getElementById("nuclei-swagger-file-input");
    if (inp) inp.value = "";
    const fnEl = document.getElementById("nuclei-swagger-filename");
    if (fnEl) {
      fnEl.innerHTML = `Drop swagger (.json / .yaml) here or click to browse`;
    }
    const resetBtn = document.getElementById("nuclei-swagger-file-reset");
    if (resetBtn) resetBtn.style.display = "none";
    const countEl = document.getElementById("nuclei-swagger-count");
    if (countEl) countEl.style.display = "none";
    const previewEl = document.getElementById("nuclei-swagger-endpoints-preview");
    if (previewEl) previewEl.style.display = "none";
    state.targets = [];
    showToast("Cleared loaded Swagger file.", "info");
  }

  async function parseSwaggerInput() {
    const sUrl = (document.getElementById("nuclei-swagger-url")?.value || "").trim();
    const sText = (document.getElementById("nuclei-swagger-text")?.value || "").trim();

    if (!sUrl && !sText) {
      showToast("⚠️ Enter Swagger URL, paste spec JSON/YAML, or upload a local file.", "warn");
      return;
    }

    try {
      showToast("⏳ Parsing Swagger specification...", "info");
      const res = await fetch(`${NUCLEI_API}/api/parse-swagger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ spec_url: sUrl, spec_text: sText, headers: state.headers }),
      });
      const data = await res.json();
      if (data.success) {
        applyParsedSwaggerData(data, sUrl ? "URL" : "spec");
      } else {
        showToast("❌ Failed to parse Swagger: " + (data.error || "Unknown error"), "error");
      }
    } catch (e) {
      showToast("❌ Failed to parse Swagger: " + e.message, "error");
    }
  }

  // ── HAR Archive Handling ───────────────────────────────────────────────────

  function applyParsedHarData(data, sourceLabel) {
    const detectedBase = (data.detected_base_url || "").trim();
    state.harOriginalBaseUrl = detectedBase;
    state.harEndpoints = data.endpoints || [];
    state.harTokenFound = !!data.token_found;
    state.harTokenExpired = !!data.token_expired;
    state.tokenOverriddenByUser = false;

    // In HAR mode, adopt HAR's detected base URL so endpoints map correctly
    const bInput = document.getElementById("nuclei-base-url");
    if (bInput && detectedBase) {
      bInput.value = detectedBase;
      bInput.dataset.autoFilled = "true";
      state.baseUrl = detectedBase;
      updateBaseUrlBadge("auto");
    }

    // Auto-populate auth headers if found in HAR
    const hInput = document.getElementById("nuclei-headers-input");
    if (data.headers && Object.keys(data.headers).length > 0) {
      if (hInput) {
        const lines = Object.entries(data.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
        hInput.value = lines;
        hInput.dataset.autoFilled = "true";
        state.headers = Object.assign({}, data.headers);
        updateAuthBadge(state.headers);
      }
    } else {
      if (hInput && (hInput.dataset.autoFilled === "true" || !state.tokenOverriddenByUser)) {
        hInput.value = "";
        hInput.dataset.autoFilled = "false";
        state.headers = {};
        updateAuthBadge({});
      }
    }

    // Manage Banners: Active Token vs Expired Token vs No Token
    const successEl = document.getElementById("nuclei-har-token-success");
    const successMsg = document.getElementById("nuclei-har-token-success-msg");
    const alertEl = document.getElementById("nuclei-har-token-alert");
    const alertDesc = document.getElementById("nuclei-har-token-alert-desc");
    const missingEl = document.getElementById("nuclei-har-token-missing");

    if (data.token_found) {
      if (data.token_expired) {
        if (successEl) successEl.style.display = "none";
        if (missingEl) missingEl.style.display = "none";
        if (alertEl) {
          alertEl.style.display = "block";
          if (alertDesc) {
            const expStr = data.auth_inspection?.exp_readable || "previously";
            alertDesc.innerHTML = `The JWT token in this HAR archive expired on <strong style="color:var(--red,#f85149);">${escapeHtml(expStr)}</strong>. Endpoints were extracted successfully. To run an authenticated scan, please paste a fresh token in <strong>Section 2 (Custom Request Headers)</strong> below.`;
          }
        }
      } else {
        if (alertEl) alertEl.style.display = "none";
        if (missingEl) missingEl.style.display = "none";
        if (successEl) {
          successEl.style.display = "flex";
          if (successMsg) {
            successMsg.textContent = `🟢 Active Authentication Token (${data.token_type || "Token"}) detected & auto-populated in Section 2!`;
          }
        }
      }
    } else {
      // No token found in HAR at all
      if (successEl) successEl.style.display = "none";
      if (alertEl) alertEl.style.display = "none";
      if (missingEl) missingEl.style.display = "block";
    }

    recomputeHarTargets(state.baseUrl);

    const countEl = document.getElementById("nuclei-har-count");
    const countMsg = document.getElementById("nuclei-har-count-msg");
    const numEl = document.getElementById("nuclei-har-endpoints-num");
    if (countEl) {
      countEl.style.display = "flex";
      const src = sourceLabel ? `from "${sourceLabel}"` : "from HAR archive";
      const dupInfo = (data.duplicates_removed || 0) > 0 ? ` (Filtered out ${data.duplicates_removed} duplicate API calls)` : "";
      if (countMsg) countMsg.textContent = `✅ Extracted ${state.targets.length} unique endpoints ${src}!${dupInfo}`;
      if (numEl) numEl.textContent = state.targets.length;
    }

    // Always ensure dropzone shows file name and reset button is visible
    const fnEl = document.getElementById("nuclei-har-filename");
    const resetBtn = document.getElementById("nuclei-har-file-reset");
    if (fnEl && sourceLabel) {
      fnEl.innerHTML = `<span style="color:var(--blue,#58a6ff);font-weight:600;">📦 ${escapeHtml(sourceLabel)}</span> <span style="font-size:11px;color:var(--text2,#8b949e);">(${state.targets.length} Endpoints)</span>`;
    }
    if (resetBtn) resetBtn.style.display = "block";

    renderHarEndpointsPreview();
    updateActiveSourceSummary();

    if (!data.token_found) {
      showToast(`⚠️ Extracted ${state.targets.length} endpoints! No auth token found in HAR.`, "warn");
    } else if (data.token_expired) {
      showToast(`⚠️ Extracted ${state.targets.length} endpoints! Note: Token in HAR is expired.`, "warn");
    } else {
      showToast(`✅ Extracted ${state.targets.length} unique endpoints ready for scan!`, "success");
    }
  }

  function recomputeHarTargets(customBaseUrl) {
    const base = (customBaseUrl !== undefined ? customBaseUrl : (document.getElementById("nuclei-base-url")?.value || state.baseUrl || "")).trim();
    state.baseUrl = base;
    const cleanBase = base.replace(/\/+$/, "");

    if (!state.harEndpoints || !state.harEndpoints.length) {
      return;
    }

    state.targets = state.harEndpoints.map((e) => {
      if (typeof e === "string") {
        if (!cleanBase) return e;
        try {
          const u = new URL(e);
          return cleanBase + u.pathname + u.search;
        } catch (_) {
          return cleanBase + (e.startsWith("/") ? e : "/" + e);
        }
      }

      const rawUrl = e.url || "";
      if (cleanBase && rawUrl) {
        if (state.harOriginalBaseUrl) {
          const origClean = state.harOriginalBaseUrl.replace(/\/+$/, "");
          if (rawUrl.startsWith(origClean)) {
            return cleanBase + rawUrl.slice(origClean.length);
          }
        }
        try {
          const u = new URL(rawUrl);
          return cleanBase + u.pathname + u.search;
        } catch (_) {}
      }
      return rawUrl || (e.path ? cleanBase + (e.path.startsWith("/") ? e.path : "/" + e.path) : "");
    }).filter(Boolean);

    renderHarEndpointsPreview();
  }

  function toggleHarEndpoints() {
    const el = document.getElementById("nuclei-har-endpoints-preview");
    if (!el) return;
    if (el.style.display === "none" || !el.style.display) {
      el.style.display = "block";
      renderHarEndpointsPreview();
    } else {
      el.style.display = "none";
    }
  }

  function renderHarEndpointsPreview() {
    const el = document.getElementById("nuclei-har-endpoints-preview");
    if (!el) return;
    if (!state.targets || !state.targets.length) {
      el.innerHTML = '<div style="color:var(--text2,#8b949e);padding:6px;">No endpoints loaded yet.</div>';
      return;
    }
    const html = state.targets.slice(0, 100).map((t, idx) => {
      return `<div style="padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;gap:8px;align-items:center;">
        <span style="color:var(--text2,#8b949e);font-size:10px;width:24px;">#${idx + 1}</span>
        <span style="color:var(--blue,#58a6ff);word-break:break-all;">${escapeHtml(t)}</span>
      </div>`;
    }).join("");
    const moreText = state.targets.length > 100 ? `<div style="margin-top:6px;color:var(--yellow,#d29922);font-size:11px;">...and ${state.targets.length - 100} more endpoints</div>` : "";
    el.innerHTML = html + moreText;
  }

  // ── Robust Client-Side HAR Parser Fallback ────────────────────────────────

  function parseHarClientSide(harText) {
    if (!harText || !harText.trim()) return null;
    let parsed;
    try {
      parsed = JSON.parse(harText);
    } catch (_) {
      return null;
    }
    const entries = parsed?.log?.entries || [];
    if (!Array.isArray(entries)) return null;

    const seenExact = new Set();
    const seenRoutes = new Set();
    const endpoints = [];
    const baseCounts = {};
    const detectedHeaders = {};
    let duplicatesRemoved = 0;
    let tokenFound = false;
    let tokenExpired = false;
    let tokenType = "none";
    let detectedAuth = "";

    const staticExtRegex = /\.(png|jpg|jpeg|gif|svg|ico|webp|css|woff2?|ttf|eot|mp4|mp3|txt|xml|map|js|jsx|ts|tsx)(\?.*)?$/i;
    const jwtRegex = /eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]+/;

    for (const entry of entries) {
      const req = entry.request;
      if (!req || !req.url) continue;
      const rawUrl = req.url.trim();
      if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) continue;

      let u;
      try {
        u = new URL(rawUrl);
      } catch (_) {
        continue;
      }

      if (staticExtRegex.test(u.pathname)) continue;

      // Extract auth tokens
      const headersList = req.headers || [];
      for (const h of headersList) {
        const hn = (h.name || "").trim();
        const hv = (h.value || "").trim();
        if (!hn || !hv) continue;
        const hnLower = hn.toLowerCase();

        const jMatch = hv.match(jwtRegex);
        if (jMatch) {
          detectedHeaders["Authorization"] = "Bearer " + jMatch[0];
          tokenFound = true;
          tokenType = "Bearer JWT";
          try {
            const pB64 = jMatch[0].split(".")[1];
            let pNorm = pB64.replace(/-/g, "+").replace(/_/g, "/");
            while (pNorm.length % 4) pNorm += "=";
            const payload = JSON.parse(atob(pNorm));
            if (payload.exp && Date.now() / 1000 > payload.exp) {
              tokenExpired = true;
            }
          } catch (_) {}
        } else if (hnLower === "authorization") {
          detectedHeaders["Authorization"] = hv;
          tokenFound = true;
          tokenType = "Authorization Header";
        } else if (/auth|token|api-key/i.test(hnLower)) {
          detectedHeaders[hn] = hv;
          tokenFound = true;
          tokenType = hn;
        } else if (hnLower === "cookie" && /session|token|auth|jwt/i.test(hv)) {
          detectedHeaders["Cookie"] = hv;
          if (!detectedAuth) {
            detectedAuth = hv;
            tokenFound = true;
            tokenType = "Session Cookie";
          }
        }
      }

      const base = `${u.protocol}//${u.host}`;
      baseCounts[base] = (baseCounts[base] || 0) + 1;

      if (seenExact.has(rawUrl)) {
        duplicatesRemoved++;
        continue;
      }
      seenExact.add(rawUrl);

      const normPath = u.pathname
        .replace(/\/[0-9a-fA-F-]{36}/g, "/{uuid}")
        .replace(/\/\d+/g, "/{id}");
      const routeKey = `${u.host}::${normPath}`;
      if (seenRoutes.has(routeKey)) {
        duplicatesRemoved++;
        continue;
      }
      seenRoutes.add(routeKey);

      endpoints.push({
        method: (req.method || "GET").toUpperCase(),
        url: rawUrl,
        path: u.pathname,
        query: u.search ? u.search.slice(1) : "",
        base_url: base,
      });
    }

    let dominantBase = "";
    if (Object.keys(baseCounts).length) {
      dominantBase = Object.entries(baseCounts).sort((a, b) => b[1] - a[1])[0][0];
    }

    return {
      success: true,
      total_entries: entries.length,
      total_endpoints: endpoints.length,
      duplicates_removed: duplicatesRemoved,
      detected_base_url: dominantBase,
      token_found: tokenFound,
      token_expired: tokenExpired,
      token_type: tokenType,
      detected_auth: detectedAuth,
      headers: detectedHeaders,
      endpoints: endpoints,
    };
  }

  async function uploadHarFile(input) {
    if (state.isScanning) return;
    const file = input?.files?.[0];
    if (!file) return;

    // Reset input value so selecting the same file again triggers onchange
    input.value = "";

    const fnEl = document.getElementById("nuclei-har-filename");
    const resetBtn = document.getElementById("nuclei-har-file-reset");
    const sizeKb = (file.size / 1024).toFixed(1);
    if (fnEl) {
      fnEl.innerHTML = `<span style="color:var(--yellow,#d29922);font-weight:600;">⏳ Reading & parsing ${escapeHtml(file.name)}</span> <span style="font-size:11px;color:var(--text2,#8b949e);">(${sizeKb} KB)</span>`;
    }
    if (resetBtn) resetBtn.style.display = "block";

    showToast(`⏳ Reading and parsing "${file.name}"...`, "info");

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result;
      if (!content || !content.trim()) {
        showToast("⚠️ The selected HAR file is empty.", "warn");
        if (fnEl) fnEl.textContent = `Drop browser network export (.har) here or click to browse`;
        if (resetBtn) resetBtn.style.display = "none";
        return;
      }

      let parsedSuccess = false;

      // 1. Try Backend HAR API (Port 8797)
      try {
        const res = await fetch(`${NUCLEI_API}/api/parse-har`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ har_text: content }),
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.success && Array.isArray(data.endpoints) && data.endpoints.length > 0) {
            applyParsedHarData(data, file.name);
            parsedSuccess = true;
          }
        }
      } catch (err) {
        console.warn("[HAR] Backend parse unavailable on 8797, falling back to local browser parser:", err);
      }

      // 2. Client-side Fallback parser (guarantees View Endpoints always appears even if backend 8797 is offline)
      if (!parsedSuccess) {
        try {
          const localData = parseHarClientSide(content);
          if (localData && localData.success && localData.endpoints?.length) {
            applyParsedHarData(localData, file.name);
            parsedSuccess = true;
          }
        } catch (localErr) {
          console.error("[HAR] Local parse error:", localErr);
        }
      }

      if (parsedSuccess) {
        if (fnEl) {
          fnEl.innerHTML = `<span style="color:var(--blue,#58a6ff);font-weight:600;">📦 ${escapeHtml(file.name)}</span> <span style="font-size:11px;color:var(--text2,#8b949e);">(${sizeKb} KB)</span>`;
        }
        if (resetBtn) resetBtn.style.display = "block";
      } else {
        showToast("❌ Could not parse HAR archive. Please verify file format.", "error");
        if (fnEl) fnEl.textContent = `Drop browser network export (.har) here or click to browse`;
        if (resetBtn) resetBtn.style.display = "none";
      }
    };
    reader.onerror = () => {
      showToast("❌ Error reading local HAR file.", "error");
    };
    reader.readAsText(file);
  }

  function clearHarFile() {
    if (state.isScanning) return;
    const inp = document.getElementById("nuclei-har-file-input");
    if (inp) inp.value = "";
    const fnEl = document.getElementById("nuclei-har-filename");
    if (fnEl) {
      fnEl.innerHTML = `Drop browser network export (.har) here or click to browse`;
    }
    const resetBtn = document.getElementById("nuclei-har-file-reset");
    if (resetBtn) resetBtn.style.display = "none";
    const alertEl = document.getElementById("nuclei-har-token-alert");
    if (alertEl) alertEl.style.display = "none";
    const missingEl = document.getElementById("nuclei-har-token-missing");
    if (missingEl) missingEl.style.display = "none";
    const successEl = document.getElementById("nuclei-har-token-success");
    if (successEl) successEl.style.display = "none";
    const countEl = document.getElementById("nuclei-har-count");
    if (countEl) countEl.style.display = "none";
    const previewEl = document.getElementById("nuclei-har-endpoints-preview");
    if (previewEl) previewEl.style.display = "none";
    state.targets = [];
    state.harEndpoints = [];
    state.harOriginalBaseUrl = "";
    state.harTokenFound = false;
    state.harTokenExpired = false;
    state.tokenOverriddenByUser = false;
    updateActiveSourceSummary();
    showToast("Cleared loaded HAR file.", "info");
  }

  // ── Authentication Pre-Scan Verification Modal Handlers ────────────────────

  function showAuthConfirmModal(type) {
    const modal = document.getElementById("nuclei-auth-modal");
    if (!modal) return;
    const titleEl = document.getElementById("nuclei-auth-modal-title");
    const descEl = document.getElementById("nuclei-auth-modal-desc");
    const iconEl = document.getElementById("nuclei-auth-modal-icon");

    if (type === "missing") {
      if (iconEl) iconEl.textContent = "⚠️";
      if (titleEl) titleEl.textContent = "No Authentication Token Detected";
      if (descEl) {
        descEl.innerHTML = `No valid Authorization token was detected in the HAR archive, and no token was provided in Section 2.<br><br>
        <strong>Risk:</strong> Running this scan unauthenticated may cause protected endpoints to return <span style="color:var(--red,#f85149);font-weight:700;">401 Unauthorized</span> or <span style="color:var(--red,#f85149);font-weight:700;">403 Forbidden</span>, preventing deep vulnerability discovery.<br><br>
        Would you like to add an Authorization token in Section 2 first?`;
      }
    } else if (type === "expired") {
      if (iconEl) iconEl.textContent = "⏰";
      if (titleEl) titleEl.textContent = "Authentication Token is Expired";
      if (descEl) {
        descEl.innerHTML = `The JWT token extracted from this HAR archive is <span style="color:var(--red,#f85149);font-weight:700;">Expired</span>.<br><br>
        Scanning with an expired token will cause the server to reject requests. Please provide a <strong>fresh Bearer token</strong> in Section 2.<br><br>
        Would you like to update your token in Section 2 before scanning?`;
      }
    }
    modal.style.display = "flex";
  }

  function closeAuthConfirmModal() {
    const modal = document.getElementById("nuclei-auth-modal");
    if (modal) modal.style.display = "none";
  }

  function focusTokenInput() {
    closeAuthConfirmModal();
    switchTab("setup");
    const hInput = document.getElementById("nuclei-headers-input");
    if (hInput) {
      hInput.scrollIntoView({ behavior: "smooth", block: "center" });
      hInput.focus();
      hInput.style.borderColor = "var(--blue, #58a6ff)";
      hInput.style.boxShadow = "0 0 12px rgba(88, 166, 255, 0.4)";
      setTimeout(() => {
        hInput.style.borderColor = "";
        hInput.style.boxShadow = "";
      }, 2500);
    }
  }

  function proceedScanWithoutToken() {
    closeAuthConfirmModal();
    state.bypassAuthCheck = true;
    startScan();
  }

  // ── Scan Launch & SSE Stream ───────────────────────────────────────────────

  async function startScan() {
    const rawBaseUrl = (document.getElementById("nuclei-base-url")?.value || "").trim();
    state.baseUrl = rawBaseUrl;

    let targets = [];
    if (state.activeSourceMode === "curl") {
      await parseCurlInput();
      targets = state.targets.length ? state.targets : [state.baseUrl].filter(Boolean);
    } else if (state.activeSourceMode === "swagger") {
      recomputeSwaggerTargets(state.baseUrl);
      targets = state.targets.length ? state.targets : [state.baseUrl].filter(Boolean);

      // Robust re-base if target host still differs from overridden base URL
      if (state.baseUrl) {
        const cleanBase = state.baseUrl.replace(/\/+$/, "");
        targets = targets.map((t) => {
          if (typeof t !== "string") return t;
          try {
            const tUrl = new URL(t);
            const bUrl = new URL(cleanBase);
            if (tUrl.origin !== bUrl.origin) {
              if (state.swaggerOriginalBaseUrl) {
                const origBase = state.swaggerOriginalBaseUrl.replace(/\/+$/, "");
                if (t.startsWith(origBase)) {
                  return cleanBase + t.slice(origBase.length);
                }
              }
              return cleanBase + tUrl.pathname + tUrl.search;
            }
          } catch (_) {}
          if (!t.startsWith("http://") && !t.startsWith("https://")) {
            return cleanBase + (t.startsWith("/") ? t : "/" + t);
          }
          return t;
        });
        state.targets = targets;
      }
    } else if (state.activeSourceMode === "har") {
      recomputeHarTargets(state.baseUrl);
      targets = state.targets.length ? state.targets : [state.baseUrl].filter(Boolean);

      if (state.baseUrl) {
        const cleanBase = state.baseUrl.replace(/\/+$/, "");
        targets = targets.map((t) => {
          if (typeof t !== "string") return t;
          try {
            const tUrl = new URL(t);
            const bUrl = new URL(cleanBase);
            if (tUrl.origin !== bUrl.origin) {
              if (state.harOriginalBaseUrl) {
                const origBase = state.harOriginalBaseUrl.replace(/\/+$/, "");
                if (t.startsWith(origBase)) {
                  return cleanBase + t.slice(origBase.length);
                }
              }
              return cleanBase + tUrl.pathname + tUrl.search;
            }
          } catch (_) {}
          if (!t.startsWith("http://") && !t.startsWith("https://")) {
            return cleanBase + (t.startsWith("/") ? t : "/" + t);
          }
          return t;
        });
        state.targets = targets;
      }
    } else if (state.activeSourceMode === "multi") {
      const lines = (document.getElementById("nuclei-multi-input")?.value || "")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      targets = lines;
      state.targets = targets;
      if (!state.baseUrl && targets.length) {
        try {
          const u = new URL(targets[0]);
          state.baseUrl = `${u.protocol}//${u.host}`;
          const bInput = document.getElementById("nuclei-base-url");
          if (bInput) bInput.value = state.baseUrl;
        } catch (_) {}
      }
    }

    // Deduplicate target URLs while preserving order
    targets = Array.from(new Set(targets.map((t) => (typeof t === "string" ? t.trim() : t)).filter(Boolean)));
    state.targets = targets;

    if (!targets.length && state.baseUrl) {
      targets = [state.baseUrl];
    }

    if (!targets.length) {
      showToast("⚠️ Provide at least one target URL or endpoint to scan.", "warn");
      return;
    }

    // Parse custom headers with smart multi-line / Bearer token detection
    const rawHeadersText = (document.getElementById("nuclei-headers-input")?.value || "").trim();
    const headers = parseHeadersInput(rawHeadersText);
    state.headers = headers;

    // Pre-Scan Auth Verification: Prevent accidental unauthenticated scans
    if (state.activeSourceMode === "har" && !state.bypassAuthCheck) {
      const hasAuth = Object.keys(state.headers).some((k) => /auth|token|cookie|key|bearer/i.test(k));
      if (!hasAuth) {
        showAuthConfirmModal("missing");
        return;
      }
      if (state.harTokenExpired && !state.tokenOverriddenByUser) {
        showAuthConfirmModal("expired");
        return;
      }
    }
    state.bypassAuthCheck = false;

    // Reset findings & stats
    state.findings = [];
    state.selectedFindingIndex = -1;
    state.stats = { total_targets: targets.length, findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    updateStatsDisplay();
    renderTable();
    clearInspector();

    // UI State Update
    const startBtn = document.getElementById("btn-nuclei-start");
    const stopBtn = document.getElementById("btn-nuclei-stop");
    if (startBtn) startBtn.style.display = "none";
    if (stopBtn) stopBtn.style.display = "inline-flex";

    const targetPill = document.getElementById("nuclei-active-target-pill");
    if (targetPill) targetPill.textContent = state.baseUrl || targets[0];

    const statusPill = document.getElementById("nuclei-scan-status-pill");
    if (statusPill) {
      statusPill.textContent = "Scanning...";
      statusPill.style.color = "var(--blue)";
      statusPill.style.background = "rgba(88, 166, 255, 0.15)";
    }

    // Reset and reveal live progress bar strip
    const pStrip = document.getElementById("nuclei-scan-progress-strip");
    if (pStrip) pStrip.style.display = "block";
    const pFill = document.getElementById("nuclei-scan-progress-fill");
    if (pFill) {
      pFill.style.width = "0%";
      pFill.style.background = "linear-gradient(90deg, #238636, #3fb950, #58a6ff)";
      pFill.style.boxShadow = "0 0 10px rgba(63,185,80,0.4)";
    }
    const pPct = document.getElementById("nuclei-progress-pct-text");
    if (pPct) pPct.textContent = "0%";
    const pStatus = document.getElementById("nuclei-progress-status-text");
    if (pStatus) pStatus.textContent = "Scanning Active...";
    const pProbes = document.getElementById("nuclei-progress-probe-info");
    if (pProbes) pProbes.textContent = `0 / ${targets.length} Probes`;
    const pRps = document.getElementById("nuclei-progress-rps-info");
    if (pRps) pRps.textContent = "0 RPS";

    // Lock all input boxes during scan
    setInputsDisabled(true);

    switchTab("results");

    // Reset verbose feed
    state.verboseLogs = [];
    const vLogsEl = document.getElementById("nuclei-terminal-verbose-logs");
    if (vLogsEl) {
      vLogsEl.innerHTML = `<div class="nuclei-log-line" style="color:var(--text3,#6e7681);">[Live Activity Feed Ready] Live HTTP probe requests streaming...</div>`;
    }
    const counterEl = document.getElementById("nuclei-verbose-counter");
    if (counterEl) counterEl.textContent = `Ring Buffer: 0/${state.maxVerboseLines}`;

    appendTerminalLog(`\n============================================================`);
    appendTerminalLog(`[${new Date().toLocaleTimeString()}] 🚀 Initiating Nuclei Security Scan...`);
    appendTerminalLog(`[Config] Target Host: ${state.baseUrl || targets[0]} | Profiles: ${state.selectedTags.join(", ")}`);
    appendTerminalLog(`[Config] Total Endpoints: ${targets.length}`);
    if (targets.length > 0) {
      appendTerminalLog(`[Config] 📍 Sample Target: ${targets[0]}`);
    }
    if (headers["Authorization"]) {
      const authPreview = headers["Authorization"].length > 25 ? headers["Authorization"].slice(0, 25) + "..." : headers["Authorization"];
      appendTerminalLog(`[Auth] 🔑 Authorization Header: ${authPreview}`);
    } else if (Object.keys(headers).length > 0) {
      appendTerminalLog(`[Auth] 📋 Custom Headers Attached: ${Object.keys(headers).join(", ")}`);
    } else {
      appendTerminalLog(`[Auth] ⚠️ No Authorization header attached.`);
    }

    const rlSelect = document.getElementById("nuclei-rate-limit-select");
    const chosenRateLimit = rlSelect ? parseInt(rlSelect.value, 10) : 15;
    state.rateLimit = chosenRateLimit;
    appendTerminalLog(`[Engine] ⏱️ Scan Speed: ${chosenRateLimit} req/sec ${chosenRateLimit <= 5 ? '(Stealth Anti-Ban Delay active)' : ''}`);

    try {
      const res = await fetch(`${NUCLEI_API}/api/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_type: state.activeSourceMode,
          base_url: state.baseUrl,
          targets: targets,
          headers: state.headers,
          tags: state.selectedTags,
          rate_limit: chosenRateLimit,
          timeout: 10,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Scan request failed.");
      }

      const data = await res.json();
      state.currentJobId = data.job_id;
      showToast("🚀 Scan started! Streaming live security telemetry...", "info");

      connectSSE(data.job_id);
    } catch (e) {
      setInputsDisabled(false);
      showToast("❌ Could not start scan: " + e.message, "error");
      appendTerminalLog(`[Error] Scan launch failed: ${e.message}`);
      if (startBtn) startBtn.style.display = "inline-flex";
      if (stopBtn) stopBtn.style.display = "none";
      if (statusPill) {
        statusPill.textContent = "Failed";
        statusPill.style.color = "var(--red)";
      }
    }
  }

  function connectSSE(jobId) {
    if (state.eventSource) {
      state.eventSource.close();
    }

    const sseUrl = `${NUCLEI_API}/api/scan/stream/${jobId}`;
    const es = new EventSource(sseUrl);
    state.eventSource = es;

    es.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleStreamMessage(msg);
      } catch (err) {
        console.warn("SSE parse error:", err);
      }
    };

    es.onerror = () => {
      console.warn("SSE connection error; falling back to polling.");
      es.close();
      state.eventSource = null;
      startPolling(jobId);
    };
  }

  function startPolling(jobId) {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(async () => {
      try {
        const res = await fetch(`${NUCLEI_API}/api/scan/status/${jobId}`);
        if (res.ok) {
          const job = await res.json();
          state.stats = job.stats || state.stats;
          state.findings = job.findings || [];
          updateStatsDisplay();
          renderTable();

          if (["completed", "stopped", "failed"].includes(job.status)) {
            clearInterval(state.pollTimer);
            state.pollTimer = null;
            onScanFinished(job.status);
          }
        }
      } catch (pe) {
        console.warn("Poll status error:", pe);
      }
    }, 1200);
  }

  function handleStreamMessage(msg) {
    if (msg.type === "log") {
      appendTerminalLog(msg.message);
    } else if (msg.type === "verbose") {
      appendVerboseLog(msg.message);
    } else if (msg.type === "stats_tick") {
      if (msg.progress) {
        updateProgressBar(msg.progress);
      }
    } else if (msg.type === "finding") {
      state.findings.push(msg.data);
      if (msg.stats) state.stats = msg.stats;
      updateStatsDisplay();
      renderTable();
      appendTerminalLog(`[FINDING] [${(msg.data.severity || "INFO").toUpperCase()}] ${msg.data.name || msg.data.id} -> ${msg.data.matched_at}`);
    } else if (msg.type === "progress") {
      if (msg.stats) {
        state.stats = msg.stats;
        if (msg.stats.progress_percent) {
          updateProgressBar({
            percent: msg.stats.progress_percent,
            current: msg.stats.requests_probed,
            total: msg.stats.requests_total,
            rps: msg.stats.rps,
          });
        }
      }
      updateStatsDisplay();
    } else if (msg.type === "done") {
      if (msg.stats) state.stats = msg.stats;
      updateStatsDisplay();
      const finalTot = (msg.progress?.total) || (msg.stats?.requests_total) || (state.targets?.length) || 0;
      updateProgressBar({ 
        percent: 100, 
        status: "completed",
        current: finalTot,
        total: finalTot
      });
      if (state.eventSource) {
        state.eventSource.close();
        state.eventSource = null;
      }
      onScanFinished(msg.status || "completed");
    }
  }

  async function stopScan() {
    if (!state.currentJobId) return;
    try {
      await fetch(`${NUCLEI_API}/api/scan/stop/${state.currentJobId}`, { method: "POST" });
      showToast("⏹️ Stopping scan...", "warn");
      appendTerminalLog(`[Control] Stop request sent to scan engine.`);
    } catch (e) {
      showToast("❌ Could not stop scan: " + e.message, "error");
    }
  }

  function onScanFinished(finalStatus) {
    setInputsDisabled(false);
    const finalTot = state.stats?.requests_total || state.targets?.length || 0;
    updateProgressBar({ 
      percent: 100, 
      status: finalStatus,
      current: finalTot,
      total: finalTot
    });

    const startBtn = document.getElementById("btn-nuclei-start");
    const stopBtn = document.getElementById("btn-nuclei-stop");
    if (startBtn) startBtn.style.display = "inline-flex";
    if (stopBtn) stopBtn.style.display = "none";

    const statusPill = document.getElementById("nuclei-scan-status-pill");
    if (statusPill) {
      statusPill.textContent = finalStatus.toUpperCase();
      statusPill.style.color = finalStatus === "completed" ? "var(--green)" : "var(--yellow)";
      statusPill.style.background = finalStatus === "completed" ? "rgba(63, 185, 80, 0.15)" : "rgba(210, 153, 34, 0.15)";
    }

    appendTerminalLog(`\n[${new Date().toLocaleTimeString()}] 🏁 Scan process finished (${finalStatus}). Total findings: ${state.findings.length}`);
    showToast(`🏁 Nuclei scan finished! Found ${state.findings.length} findings.`, "success");
  }

  // ── Results Table & Inspector ──────────────────────────────────────────────

  function renderTable() {
    const tbody = document.getElementById("nuclei-table-body");
    if (!tbody) return;

    const filter = state.activeFilter;
    const q = state.searchTerm.toLowerCase().trim();

    const items = state.findings.filter((f) => {
      const matchSev = filter === "ALL" || (f.severity || "INFO").toUpperCase() === filter;
      const matchQuery =
        !q ||
        (f.name || "").toLowerCase().includes(q) ||
        (f.matched_at || "").toLowerCase().includes(q) ||
        (f.id || "").toLowerCase().includes(q);
      return matchSev && matchQuery;
    });

    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;color:var(--text3);padding:24px;font-size:11.5px;">No findings matching current filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = items
      .map((f, i) => {
        const sev = (f.severity || "INFO").toUpperCase();
        const isSelected = i === state.selectedFindingIndex;
        return `
        <tr class="nuclei-row ${isSelected ? "selected" : ""}" data-idx="${i}">
          <td style="width:85px;"><span class="nuclei-badge nuclei-badge-${sev.toLowerCase()}">${sev}</span></td>
          <td style="font-weight:600;font-size:11.5px;color:var(--text);width:300px;">${escapeHtml(f.name || f.id)}</td>
          <td><span class="nuclei-target-url">${escapeHtml(f.matched_at || "-")}</span></td>
        </tr>
      `;
      })
      .join("");

    tbody.querySelectorAll(".nuclei-row").forEach((row) => {
      row.addEventListener("click", () => {
        const idx = parseInt(row.getAttribute("data-idx"), 10);
        selectFinding(idx);
      });
    });
  }

  function selectFinding(idx) {
    state.selectedFindingIndex = idx;
    const f = state.findings[idx];
    if (!f) return;

    renderTable(); // Update row highlight

    const pane = document.getElementById("nuclei-inspect-content");
    if (!pane) return;

    const sev = (f.severity || "INFO").toUpperCase();
    const curl = f.curl_command || `curl -i '${f.matched_at}'`;
    const desc = f.description || "No description provided.";
    const extra = (f.extracted_results || []).join("\n") || "No extraction evidence.";
    const tagBadges = (f.tags && f.tags.length)
      ? f.tags.slice(0, 4).map(t => `<span style="font-size:10px;padding:1px 6px;border-radius:3px;background:var(--bg3);border:1px solid var(--border);color:var(--text3);font-family:var(--mono);">${escapeHtml(t)}</span>`).join(" ")
      : "";

    pane.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:8px;flex-wrap:wrap;gap:8px;">
        <div style="font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span class="nuclei-badge nuclei-badge-${sev.toLowerCase()}">${sev}</span>
          <span>${escapeHtml(f.name || f.id)}</span>
          ${tagBadges ? `<span style="display:inline-flex;gap:4px;margin-left:4px;">${tagBadges}</span>` : ""}
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <button class="btn-nuclei-secondary" style="padding:3px 8px;font-size:10.5px;" onclick="window.nucleiCopyCurl(${idx}, this)">📋 Copy cURL</button>
          <button class="btn-nuclei-secondary" style="padding:3px 8px;font-size:10.5px;" onclick="window.nucleiCopyUrl(${idx}, this)">🔗 Copy URL</button>
          <button class="btn-nuclei-secondary" style="padding:3px 8px;font-size:10.5px;" onclick="window.nucleiCopyEvidence(${idx}, this)">📑 Copy Evidence</button>
        </div>
      </div>

      <div class="nuclei-inspect-box">
        <div class="nuclei-inspect-box-title">Vulnerability Description & Impact</div>
        <div style="line-height:1.45;font-size:11.5px;color:var(--text);">${escapeHtml(desc)}</div>
      </div>

      <div class="nuclei-inspect-box">
        <div class="nuclei-inspect-box-title">Matched Target Endpoint</div>
        <div class="nuclei-target-url" style="font-size:11px;">${escapeHtml(f.matched_at)}</div>
      </div>

      <div class="nuclei-inspect-box">
        <div class="nuclei-inspect-box-title">Evidence & Extracted Response Data</div>
        <pre class="nuclei-code-block">${escapeHtml(extra)}</pre>
      </div>

      <div class="nuclei-inspect-box">
        <div class="nuclei-inspect-box-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>Reproduction cURL Command</span>
          <button class="btn-nuclei-secondary" style="padding:2px 7px;font-size:10px;" onclick="window.nucleiCopyCurl(${idx}, this)">📋 Copy</button>
        </div>
        <pre class="nuclei-code-block" style="color:var(--blue);cursor:pointer;" onclick="window.nucleiCopyCurl(${idx}, this)" title="Click to copy cURL">${escapeHtml(curl)}</pre>
      </div>
    `;
  }

  function clearInspector() {
    const pane = document.getElementById("nuclei-inspect-content");
    if (pane) {
      pane.innerHTML = `<div style="text-align:center;color:var(--text3);margin:auto;">Select a finding from the table above to view full details, evidence, and cURL commands.</div>`;
    }
  }

  // ── Stats Display & Interactive Stat-Card Filters ──────────────────────────

  function updateStatsDisplay() {
    const s = state.stats;
    const map = {
      "nuclei-stat-total": s.findings,
      "nuclei-stat-crit": s.critical,
      "nuclei-stat-high": s.high,
      "nuclei-stat-med": s.medium,
      "nuclei-stat-low": s.low,
      "nuclei-stat-info": s.info,
    };
    for (const [id, val] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el) el.textContent = val || 0;
    }

    const badge = document.getElementById("nuclei-badge-findings");
    if (badge) {
      badge.textContent = s.findings || 0;
      badge.classList.toggle("has-findings", (s.findings || 0) > 0);
    }
  }

  function filterBySev(sev) {
    state.activeFilter = sev;

    // Treat stat cards as the filter buttons!
    const sevs = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    sevs.forEach((s) => {
      const card = document.getElementById(`nuclei-card-filter-${s}`);
      if (card) {
        card.classList.toggle("active", s === sev);
      }
    });

    const activeFilterLbl = document.getElementById("nuclei-active-filter-label");
    if (activeFilterLbl) {
      activeFilterLbl.textContent = `Showing: ${sev}`;
    }

    renderTable();
  }

  function searchFindings(q) {
    state.searchTerm = q;
    renderTable();
  }

  // ── Input Lock / Disable Handler ──────────────────────────────────────────

  function setInputsDisabled(disabled) {
    state.isScanning = !!disabled;

    // 1. Source tab buttons
    document.querySelectorAll(".nuclei-source-btn").forEach((btn) => {
      btn.style.pointerEvents = disabled ? "none" : "";
      btn.style.opacity = disabled ? "0.6" : "";
    });

    // 2. cURL input & auto-extract link
    const curlInput = document.getElementById("nuclei-curl-input");
    if (curlInput) curlInput.disabled = disabled;
    const extractLink = document.getElementById("nuclei-curl-extract-link");
    if (extractLink) {
      extractLink.style.pointerEvents = disabled ? "none" : "";
      extractLink.style.opacity = disabled ? "0.5" : "";
    }

    // 3. Swagger inputs & dropzone
    const dropzone = document.getElementById("nuclei-swagger-dropzone");
    if (dropzone) {
      dropzone.style.pointerEvents = disabled ? "none" : "";
      dropzone.style.opacity = disabled ? "0.6" : "";
    }
    const sFileInput = document.getElementById("nuclei-swagger-file-input");
    if (sFileInput) sFileInput.disabled = disabled;
    const sFileBtn = document.getElementById("nuclei-swagger-file-btn");
    if (sFileBtn) sFileBtn.disabled = disabled;
    const sClearBtn = document.getElementById("nuclei-swagger-clear-btn");
    if (sClearBtn) sClearBtn.disabled = disabled;
    const sUrlInput = document.getElementById("nuclei-swagger-url");
    if (sUrlInput) sUrlInput.disabled = disabled;
    const sTextInput = document.getElementById("nuclei-swagger-text");
    if (sTextInput) sTextInput.disabled = disabled;
    document.querySelectorAll("#nuclei-mode-pane-swagger button").forEach((b) => {
      b.disabled = disabled;
    });

    // 3b. HAR inputs & dropzone
    const hDropzone = document.getElementById("nuclei-har-dropzone");
    if (hDropzone) {
      hDropzone.style.pointerEvents = disabled ? "none" : "";
      hDropzone.style.opacity = disabled ? "0.6" : "";
    }
    const hFileInput = document.getElementById("nuclei-har-file-input");
    if (hFileInput) hFileInput.disabled = disabled;
    const hFileBtn = document.getElementById("nuclei-har-file-btn");
    if (hFileBtn) hFileBtn.disabled = disabled;
    const hClearBtn = document.getElementById("nuclei-har-clear-btn");
    if (hClearBtn) hClearBtn.disabled = disabled;
    document.querySelectorAll("#nuclei-mode-pane-har button").forEach((b) => {
      b.disabled = disabled;
    });

    // 4. Multi targets input
    const multiInput = document.getElementById("nuclei-multi-input");
    if (multiInput) multiInput.disabled = disabled;

    // 5. Base Target Host & Auth Headers
    const baseInput = document.getElementById("nuclei-base-url");
    if (baseInput) baseInput.disabled = disabled;
    const headersInput = document.getElementById("nuclei-headers-input");
    if (headersInput) headersInput.disabled = disabled;

    // 6. Security profile cards
    document.querySelectorAll(".nuclei-profile-card").forEach((card) => {
      card.style.pointerEvents = disabled ? "none" : "";
      card.style.opacity = disabled ? "0.65" : "";
      card.style.cursor = disabled ? "not-allowed" : "pointer";
    });
  }

  // ── Terminal Console (Clean vs Verbose Live Feed) ─────────────────────────

  function switchTerminalMode(mode) {
    state.activeTerminalMode = mode;

    const btnClean = document.getElementById("nuclei-btn-term-clean");
    const btnVerbose = document.getElementById("nuclei-btn-term-verbose");
    const paneClean = document.getElementById("nuclei-terminal-logs");
    const paneVerbose = document.getElementById("nuclei-terminal-verbose-logs");
    const counter = document.getElementById("nuclei-verbose-counter");

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
        paneVerbose.scrollTop = paneVerbose.scrollHeight;
      }
      if (counter) {
        counter.style.display = "inline-flex";
        counter.textContent = `Ring Buffer: ${state.verboseLogs.length}/${state.maxVerboseLines}`;
      }
    }
  }

  function toggleAutoScroll(enabled) {
    state.autoScroll = !!enabled;
    const chk = document.getElementById("nuclei-autoscroll-toggle");
    if (chk) chk.checked = state.autoScroll;
    const label = document.getElementById("nuclei-autoscroll-label");
    if (label) {
      label.title = `Toggle auto-scroll when new logs arrive (Currently ${state.autoScroll ? "ON" : "OFF"})`;
      label.style.borderColor = state.autoScroll ? "var(--blue, #58a6ff)" : "var(--border, #30363d)";
    }
    if (state.autoScroll) {
      const container = document.getElementById("nuclei-terminal-logs");
      if (container) container.scrollTop = container.scrollHeight;
    }
  }

  function appendTerminalLog(msg) {
    const container = document.getElementById("nuclei-terminal-logs");
    if (!container) return;
    const d = document.createElement("div");
    d.className = "nuclei-log-line";
    d.textContent = msg;
    container.appendChild(d);
    if (state.autoScroll) {
      container.scrollTop = container.scrollHeight;
    }
  }

  function formatVerboseLogLine(msg) {
    const safe = escapeHtml(msg);
    // Format [VER] [template-id] Sent HTTP request to https://...
    const verMatch = safe.match(/^(\[VER\])\s*(\[[^\]]+\])?\s*(Sent HTTP request to)\s*(https?:\/\/[^\s]+)(.*)$/);
    if (verMatch) {
      const tag = `<span style="color:#a371f7;font-weight:400;opacity:0.85;">${verMatch[1]}</span>`;
      const tmpl = verMatch[2] ? `<span style="color:#58a6ff;font-weight:400;opacity:0.9;"> ${verMatch[2]}</span>` : "";
      const action = `<span style="color:#6e7681;font-weight:400;"> ${verMatch[3]} </span>`;
      const url = `<span style="color:#7ee787;font-weight:400;word-break:break-all;opacity:0.85;">${verMatch[4]}</span>`;
      const rest = verMatch[5] ? `<span style="color:#79c0ff;font-weight:400;opacity:0.75;">${verMatch[5]}</span>` : "";
      return `${tag}${tmpl}${action}${url}${rest}`;
    }
    if (safe.includes("|") && (safe.includes("RPS:") || safe.includes("Requests:"))) {
      return `<span style="color:#e3b341;font-weight:400;opacity:0.85;">${safe}</span>`;
    }
    return `<span style="color:#8b949e;font-weight:400;">${safe}</span>`;
  }

  function appendVerboseLog(msg) {
    state.verboseLogs.push(msg);
    if (state.verboseLogs.length > state.maxVerboseLines) {
      state.verboseLogs.shift();
    }

    const counter = document.getElementById("nuclei-verbose-counter");
    if (counter) {
      counter.textContent = `Ring Buffer: ${state.verboseLogs.length}/${state.maxVerboseLines}`;
    }

    const container = document.getElementById("nuclei-terminal-verbose-logs");
    if (!container) return;

    const d = document.createElement("div");
    d.className = "nuclei-log-line";
    d.innerHTML = formatVerboseLogLine(msg);
    container.appendChild(d);

    // Strict DOM pruning: never exceed maxVerboseLines nodes to keep UI buttery smooth
    while (container.children.length > state.maxVerboseLines) {
      container.removeChild(container.firstChild);
    }

    container.scrollTop = container.scrollHeight;
  }

  function updateProgressBar(prog) {
    if (!prog) return;
    const pStrip = document.getElementById("nuclei-scan-progress-strip");
    if (pStrip) pStrip.style.display = "block";

    const pFill = document.getElementById("nuclei-scan-progress-fill");
    const pPct = document.getElementById("nuclei-progress-pct-text");
    const pProbes = document.getElementById("nuclei-progress-probe-info");
    const pRps = document.getElementById("nuclei-progress-rps-info");
    const pStatus = document.getElementById("nuclei-progress-status-text");

    const pct = Math.max(0, Math.min(100, parseInt(prog.percent !== undefined ? prog.percent : 0, 10)));
    if (pFill) pFill.style.width = `${pct}%`;
    if (pPct) pPct.textContent = `${pct}%`;

    const totalEndpoints = state.targets?.length || 1;
    if (prog.status === "completed" || pct >= 100) {
      if (pProbes) {
        if (prog.total && prog.total > totalEndpoints) {
          pProbes.textContent = `${prog.total.toLocaleString()} Requests (${totalEndpoints} Endpoints)`;
        } else {
          pProbes.textContent = `${totalEndpoints} / ${totalEndpoints} Endpoints Probed`;
        }
      }
      if (pRps) pRps.textContent = "0 RPS";
      if (pStatus) {
        pStatus.textContent = "Scan Completed";
        if (pFill) {
          pFill.style.background = "var(--green, #238636)";
          pFill.style.boxShadow = "0 0 14px rgba(46, 160, 67, 0.6)";
        }
      }
    } else {
      if (prog.current !== undefined && prog.total !== undefined && prog.total > 0) {
        if (prog.total > totalEndpoints) {
          pProbes.textContent = `${prog.current.toLocaleString()} / ${prog.total.toLocaleString()} Requests (${totalEndpoints} Endpoints)`;
        } else {
          pProbes.textContent = `${prog.current} / ${totalEndpoints} Probes`;
        }
      } else if (prog.current !== undefined) {
        pProbes.textContent = `${prog.current} / ${totalEndpoints} Probes`;
      }
      if (prog.rps !== undefined && prog.rps > 0) {
        if (pRps) pRps.textContent = `${prog.rps} RPS`;
      }
      if (pStatus && pct > 0 && pct < 100) {
        pStatus.textContent = "Scanning Endpoints...";
      }
    }
  }

  function updateStatsTicker(msg) {
    // Probe tag removed per user preference; function kept for backward safety
  }

  function clearTerminal() {
    if (state.activeTerminalMode === "verbose") {
      state.verboseLogs = [];
      const c = document.getElementById("nuclei-terminal-verbose-logs");
      if (c) c.innerHTML = "";
      const counter = document.getElementById("nuclei-verbose-counter");
      if (counter) counter.textContent = `Ring Buffer: 0/${state.maxVerboseLines}`;
    } else {
      const c = document.getElementById("nuclei-terminal-logs");
      if (c) c.innerHTML = "";
    }
  }

  function copyToClipboardWithFeedback(text, btnEl, successMsg) {
    if (!text) {
      showToast("Nothing to copy.", "warn");
      return;
    }

    const onCopied = () => {
      showToast(successMsg || "📋 Copied to clipboard!", "success");
      if (btnEl) highlightCopiedButton(btnEl);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onCopied).catch(() => {
        fallbackCopyText(text, onCopied);
      });
    } else {
      fallbackCopyText(text, onCopied);
    }
  }

  function fallbackCopyText(text, onCopied) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      ta.style.top = "-9999px";
      ta.setAttribute("readonly", "");
      document.body.appendChild(ta);
      ta.select();
      const successful = document.execCommand("copy");
      document.body.removeChild(ta);
      if (successful) {
        if (typeof onCopied === "function") onCopied();
      } else {
        showToast("⚠️ Could not copy to clipboard.", "error");
      }
    } catch (err) {
      showToast("❌ Clipboard error: " + err.message, "error");
    }
  }

  function highlightCopiedButton(btn) {
    if (!btn) return;
    const origHtml = btn.dataset.origHtml || btn.innerHTML;
    btn.dataset.origHtml = origHtml;

    btn.innerHTML = `✓ Copied!`;
    btn.style.borderColor = "var(--green, #3fb950)";
    btn.style.color = "var(--green, #3fb950)";
    btn.style.background = "rgba(63, 185, 80, 0.18)";
    btn.style.boxShadow = "0 0 8px rgba(63, 185, 80, 0.4)";
    btn.style.fontWeight = "700";

    clearTimeout(btn._copiedTimer);
    btn._copiedTimer = setTimeout(() => {
      btn.innerHTML = origHtml;
      btn.style.borderColor = "";
      btn.style.color = "";
      btn.style.background = "";
      btn.style.boxShadow = "";
      btn.style.fontWeight = "";
    }, 1800);
  }

  function copyCurl(idx, btnEl) {
    const targetBtn = btnEl || (window.event?.target?.closest ? window.event.target.closest("button") : null);
    const findingIdx = typeof idx === "number" ? idx : state.selectedFindingIndex;
    const f = state.findings[findingIdx];
    if (!f) return;
    const curl = f.curl_command || `curl -i '${f.matched_at}'`;
    copyToClipboardWithFeedback(curl, targetBtn, "📋 cURL command copied!");
  }

  function copyUrl(idx, btnEl) {
    const targetBtn = btnEl || (window.event?.target?.closest ? window.event.target.closest("button") : null);
    const findingIdx = typeof idx === "number" ? idx : state.selectedFindingIndex;
    const f = state.findings[findingIdx];
    if (!f) return;
    copyToClipboardWithFeedback(f.matched_at || "", targetBtn, "🔗 Target URL copied!");
  }

  function copyEvidence(idx, btnEl) {
    const targetBtn = btnEl || (window.event?.target?.closest ? window.event.target.closest("button") : null);
    const findingIdx = typeof idx === "number" ? idx : state.selectedFindingIndex;
    const f = state.findings[findingIdx];
    if (!f) return;
    const evidence =
      f.extracted_results && f.extracted_results.length
        ? f.extracted_results.join("\n")
        : f.curl_command || f.matched_at;
    copyToClipboardWithFeedback(evidence, targetBtn, "📑 Evidence copied!");
  }

  function copyTerminalLogs(btnEl) {
    const targetBtn = btnEl || (window.event?.target?.closest ? window.event.target.closest("button") : null);
    let text = "";
    if (state.activeTerminalMode === "verbose") {
      text = state.verboseLogs.join("\n");
      if (!text) {
        const c = document.getElementById("nuclei-terminal-verbose-logs");
        if (c) text = c.innerText;
      }
    } else {
      const c = document.getElementById("nuclei-terminal-logs");
      if (c) text = c.innerText;
    }
    if (text) {
      copyToClipboardWithFeedback(text, targetBtn, "📋 Terminal logs copied!");
    } else {
      showToast("Console is empty.", "info");
    }
  }

  // ── Vertical Drag Resizing ─────────────────────────────────────────────────

  function bindVResize() {
    const bar = document.getElementById("nuclei-vresize-bar");
    const topPane = document.getElementById("nuclei-table-pane");
    const botPane = document.getElementById("nuclei-inspect-pane");
    if (!bar || !topPane || !botPane) return;

    let isDragging = false;
    let startY = 0;
    let startTopH = 0;

    bar.addEventListener("mousedown", (e) => {
      isDragging = true;
      startY = e.clientY;
      startTopH = topPane.getBoundingClientRect().height;
      bar.classList.add("dragging");
      document.body.style.cursor = "row-resize";
      document.body.style.userSelect = "none";
    });

    window.addEventListener("mousemove", (e) => {
      if (!isDragging) return;
      const dy = e.clientY - startY;
      const newTopH = Math.max(100, startTopH + dy);
      topPane.style.flex = "none";
      topPane.style.height = `${newTopH}px`;
      botPane.style.flex = "1";
    });

    window.addEventListener("mouseup", () => {
      if (!isDragging) return;
      isDragging = false;
      bar.classList.remove("dragging");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    });
  }

  // ── Safe HTML Report Export (Zero-Crash, Saves Directly to Downloads) ──────

  async function exportReport() {
    if (!state.findings.length) {
      showToast("⚠️ No findings available to export.", "warn");
      return;
    }

    showToast("⏳ Saving HTML report to Downloads...", "info");

    try {
      const res = await fetch(`${NUCLEI_API}/api/scan/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "API Sentinel — Nuclei Security Report",
          target_url: state.baseUrl || (state.targets[0] || ""),
          findings: state.findings,
          stats: state.stats,
        }),
      });

      if (!res.ok) {
        throw new Error("Backend save endpoint returned status " + res.status);
      }

      const data = await res.json();
      if (data.success) {
        appendTerminalLog(`[Report] ✅ Successfully saved report: ${data.path}`);
        showToast(`✅ Saved to Downloads: ${data.filename}`, "success");

        // If pywebview has native save API, also sync with it safely
        if (window.pywebview?.api?.save_file && data.html) {
          try {
            await window.pywebview.api.save_file(data.html, data.filename);
          } catch (_) {}
        }
      } else {
        showToast("❌ Could not save report.", "error");
      }
    } catch (e) {
      showToast("❌ Export failed: " + e.message, "error");
    }
  }

  // ── Utilities & Cross-Tool Integrations ────────────────────────────────────

  function showToast(msg, type) {
    if (typeof window.showToast === "function") {
      window.showToast(msg, type);
    } else {
      console.log(`[Toast ${type}] ${msg}`);
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function escapeJs(str) {
    if (!str) return "";
    return String(str).replace(/'/g, "\\'").replace(/\n/g, "\\n");
  }

  // Expose global methods
  window.nucleiSwitchTab = switchTab;
  window.nucleiSetSourceMode = setSourceMode;
  window.nucleiToggleProfile = toggleProfile;
  window.nucleiCheckBinary = () => checkBinaryStatus(true);
  window.nucleiAutoInstall = triggerAutoInstall;
  window.nucleiUpdateTemplates = updateTemplates;
  window.nucleiParseCurl = parseCurlInput;
  window.nucleiParseSwagger = parseSwaggerInput;
  window.nucleiUploadSwaggerFile = uploadSwaggerFile;
  window.nucleiClearSwaggerFile = clearSwaggerFile;
  window.nucleiToggleSwaggerEndpoints = toggleSwaggerEndpoints;
  window.nucleiUploadHarFile = uploadHarFile;
  window.nucleiClearHarFile = clearHarFile;
  window.nucleiToggleHarEndpoints = toggleHarEndpoints;
  window.nucleiOnBaseUrlChange = onBaseUrlChange;
  window.nucleiOnHeadersChange = onHeadersChange;
  window.nucleiStartScan = startScan;
  window.nucleiStopScan = stopScan;
  window.nucleiFilterBySev = filterBySev;
  window.nucleiSearch = searchFindings;
  window.nucleiInspect = selectFinding;
  window.nucleiExportReport = exportReport;
  window.nucleiSwitchTerminalMode = switchTerminalMode;
  window.nucleiClearTerminal = clearTerminal;
  window.nucleiCopyCurl = copyCurl;
  window.nucleiCopyUrl = copyUrl;
  window.nucleiCopyEvidence = copyEvidence;
  window.nucleiCopyText = (txt, btnEl) => {
    const targetBtn = btnEl || (window.event?.target?.closest ? window.event.target.closest("button") : null);
    copyToClipboardWithFeedback(txt, targetBtn, "📋 Copied to clipboard!");
  };
  window.nucleiCopyTerminalLogs = (btnEl) => copyTerminalLogs(btnEl);
  // ── Global Module Reset ───────────────────────────────────────────────────

  function resetModule() {
    if (state.isScanning) {
      showToast("⚠️ Cannot reset while a scan is in progress. Stop scan first.", "warn");
      return;
    }

    // 1. Reset state
    state.activeSourceMode = "curl";
    state.baseUrl = "";
    state.baseUrlOverride = false;
    state.swaggerOriginalBaseUrl = "";
    state.swaggerEndpoints = [];
    state.harOriginalBaseUrl = "";
    state.harEndpoints = [];
    state.targets = [];
    state.headers = {};
    state.harTokenFound = false;
    state.harTokenExpired = false;
    state.tokenOverriddenByUser = false;
    state.findings = [];
    state.selectedFindingIndex = -1;
    state.stats = { total_targets: 0, findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    state.currentJobId = null;

    // 2. Reset Source Mode tabs
    setSourceMode("curl");

    // 3. Clear cURL inputs
    const curlInput = document.getElementById("nuclei-curl-input");
    if (curlInput) curlInput.value = "";

    // 4. Clear Swagger inputs & previews
    clearSwaggerFile();
    const swUrl = document.getElementById("nuclei-swagger-url");
    if (swUrl) swUrl.value = "";
    const swRaw = document.getElementById("nuclei-swagger-text");
    if (swRaw) swRaw.value = "";

    // 5. Clear HAR inputs & previews
    clearHarFile();

    // 6. Clear Multi-Target input
    const multiInput = document.getElementById("nuclei-multi-input");
    if (multiInput) multiInput.value = "";

    // 7. Clear Section 2: Base URL & Auth Headers
    const bInput = document.getElementById("nuclei-base-url");
    if (bInput) {
      bInput.value = "";
      bInput.dataset.autoFilled = "false";
    }
    updateBaseUrlBadge("auto");

    const hInput = document.getElementById("nuclei-headers-input");
    if (hInput) {
      hInput.value = "";
      hInput.dataset.autoFilled = "false";
    }
    updateAuthBadge({});

    // 8. Reset Profiles (default: api, misconfig, exposure)
    state.selectedTags = ["api", "misconfig", "exposure"];
    document.querySelectorAll(".nuclei-profile-card").forEach((card) => {
      const tag = card.getAttribute("data-tag");
      const activeText = card.querySelector(".nuclei-profile-header span:last-child");
      if (state.selectedTags.includes(tag)) {
        card.classList.add("active");
        if (activeText) {
          activeText.textContent = "✓ Active";
          activeText.style.color = "var(--blue)";
        }
      } else {
        card.classList.remove("active");
        if (activeText) {
          activeText.textContent = "Inactive";
          activeText.style.color = "var(--text3)";
        }
      }
    });

    // 9. Reset Results UI & Progress Bar
    updateStatsDisplay();
    renderTable();
    clearInspector();
    const pStrip = document.getElementById("nuclei-scan-progress-strip");
    if (pStrip) pStrip.style.display = "none";
    const statusPill = document.getElementById("nuclei-scan-status-pill");
    if (statusPill) {
      statusPill.textContent = "Idle";
      statusPill.style.color = "var(--text2)";
      statusPill.style.background = "var(--bg3)";
    }
    const targetPill = document.getElementById("nuclei-active-target-pill");
    if (targetPill) targetPill.textContent = "None";

    // 10. Clear Terminal
    clearTerminal();

    // 11. Feedback
    showToast("🔄 Nuclei Scanner completely reset!", "info");
    updateActiveSourceSummary();
  }

  window.nucleiResetModule = resetModule;
  window.nucleiFocusTokenInput = focusTokenInput;
  window.nucleiProceedScanWithoutToken = proceedScanWithoutToken;
  window.nucleiCloseAuthModal = closeAuthConfirmModal;
  window.nucleiToggleAutoScroll = toggleAutoScroll;

  window.nucleiSendToRepeater = (url) => {
    if (typeof window.switchTool === "function") {
      window.switchTool("av");
      // Switch to details tab in API Validator if available
      const detTabBtn = document.querySelector('[data-tab="details"]');
      if (detTabBtn) detTabBtn.click();

      // Enable request edit mode if hidden
      const btnEdit = document.getElementById("btn-edit-req");
      if (btnEdit && document.getElementById("det-req-edit")?.hidden) {
        btnEdit.click();
      }

      const urlInput = document.getElementById("det-url-edit");
      if (urlInput) {
        urlInput.value = url;
        urlInput.dispatchEvent(new Event("input", { bubbles: true }));
        urlInput.focus();
      }
      const detUrl = document.getElementById("det-url");
      if (detUrl) detUrl.textContent = url;

      showToast("⚡ Endpoint loaded into API Validator (Repeater)!", "success");
    }
  };

  window.nucleiSendToFuzzer = (url, curl) => {
    if (typeof window.switchTool === "function") {
      window.switchTool("fuzzer");
      if (typeof window.fuzzSwitchTab === "function") {
        window.fuzzSwitchTab("setup");
      }
      const fuzzInput = document.getElementById("fuzz-curl-input");
      if (fuzzInput) {
        fuzzInput.value = curl || `curl -i '${url}'`;
        fuzzInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
      showToast("🎯 Target loaded into API Fuzzer!", "success");
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initNuclei);
  } else {
    initNuclei();
  }
})();
