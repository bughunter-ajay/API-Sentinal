/**
 * ULTRONSCAN - COMMIX PRO WORKSPACE CONTROLLER
 * Advanced OS Command Injection & RCE Testing Engine
 */

(function() {
  const state = {
    endpoints: [],
    selectedEndpoint: null,
    isScanning: false,
    pollTimer: null,
    lastLogId: 0,
    lastVerboseId: 0,
    verboseLogs: [],
    maxVerboseLines: 200,
    autoScroll: true,
    findings: [],
    activeTab: "terminal", // terminal | verbose | findings
    cooldownCountdownTimer: null
  };

  // DOM Elements
  let dropzone, fileInput, queueTableBody, queueStatsEl, queueStatusPill;
  let btnScanToggle, btnSelectParam, btnSelectAll, btnDeselectAll;
  let terminalBox, verboseBox, findingsBox, findingsCountBadge, scanProgressBadge;
  let delayInput, levelSelect, tamperSelect, proxyInput, cfgTechnique, cfgPreset;
  let forceSslCb, randomAgentCb, btnClearQueue;
  let replyInput, btnSendReply;
  let cmdPreviewText, btnCopyCli;

  function initElements() {
    dropzone = document.getElementById("commix-har-dropzone");
    fileInput = document.getElementById("commix-har-file-input");
    queueTableBody = document.getElementById("commix-queue-table-body");
    queueStatsEl = document.getElementById("commix-queue-stats");
    queueStatusPill = document.getElementById("commix-queue-status-pill");

    btnScanToggle = document.getElementById("btn-commix-scan-toggle");
    btnSelectParam = document.getElementById("btn-commix-sel-param");
    btnSelectAll = document.getElementById("btn-commix-sel-all");
    btnDeselectAll = document.getElementById("btn-commix-desel-all");

    terminalBox = document.getElementById("commix-terminal-view");
    verboseBox = document.getElementById("commix-terminal-verbose-view");
    findingsBox = document.getElementById("commix-findings-view");
    findingsCountBadge = document.getElementById("commix-findings-badge");
    scanProgressBadge = document.getElementById("commix-scan-progress-badge");

    delayInput = document.getElementById("commix-cfg-delay");
    levelSelect = document.getElementById("commix-cfg-level");
    cfgTechnique = document.getElementById("commix-cfg-technique");
    tamperSelect = document.getElementById("commix-cfg-tamper");
    proxyInput = document.getElementById("commix-cfg-proxy");
    cfgPreset = document.getElementById("commix-cfg-preset");
    forceSslCb = document.getElementById("commix-cfg-force-ssl");
    randomAgentCb = document.getElementById("commix-cfg-random-agent");
    btnClearQueue = document.getElementById("btn-commix-clear-queue");

    replyInput = document.getElementById("commix-terminal-reply-input");
    btnSendReply = document.getElementById("btn-commix-send-reply");

    cmdPreviewText = document.getElementById("commix-cmd-preview-text");
    btnCopyCli = document.getElementById("btn-commix-copy-cli");

    setupEvents();
    updateCmdPreview();
  }

  function setScanButtonState(isScanning) {
    if (!btnScanToggle) return;
    if (isScanning) {
      btnScanToggle.className = "cyber-btn danger";
      btnScanToggle.textContent = "⏹ Stop";
      btnScanToggle.title = "Stop active Commix scan";
    } else {
      btnScanToggle.className = "cyber-btn";
      btnScanToggle.textContent = "▶ Start";
      btnScanToggle.title = "Start Commix scan";
    }
  }

  function setScanControlsDisabled(disabled) {
    if (delayInput) delayInput.disabled = disabled;
    if (levelSelect) levelSelect.disabled = disabled;
    if (cfgTechnique) cfgTechnique.disabled = disabled;
    if (tamperSelect) tamperSelect.disabled = disabled;
    if (proxyInput) proxyInput.disabled = disabled;
    if (cfgPreset) cfgPreset.disabled = disabled;
    if (forceSslCb) forceSslCb.disabled = disabled;
    if (randomAgentCb) randomAgentCb.disabled = disabled;

    if (btnClearQueue) {
      btnClearQueue.disabled = disabled;
      btnClearQueue.style.opacity = disabled ? "0.4" : "1";
      btnClearQueue.style.pointerEvents = disabled ? "none" : "auto";
      btnClearQueue.style.cursor = disabled ? "not-allowed" : "pointer";
    }

    const btnCurl = document.getElementById("btn-commix-curl-import");
    if (btnCurl) {
      btnCurl.disabled = disabled;
      btnCurl.style.opacity = disabled ? "0.4" : "1";
      btnCurl.style.pointerEvents = disabled ? "none" : "auto";
      btnCurl.style.cursor = disabled ? "not-allowed" : "pointer";
    }

    if (dropzone) {
      dropzone.style.opacity = disabled ? "0.4" : "1";
      dropzone.style.pointerEvents = disabled ? "none" : "auto";
      dropzone.style.cursor = disabled ? "not-allowed" : "pointer";
    }
    if (fileInput) fileInput.disabled = disabled;

    if (btnSelectParam) {
      btnSelectParam.disabled = disabled;
      btnSelectParam.style.opacity = disabled ? "0.4" : "1";
      btnSelectParam.style.pointerEvents = disabled ? "none" : "auto";
    }
    if (btnSelectAll) {
      btnSelectAll.disabled = disabled;
      btnSelectAll.style.opacity = disabled ? "0.4" : "1";
      btnSelectAll.style.pointerEvents = disabled ? "none" : "auto";
    }
    if (btnDeselectAll) {
      btnDeselectAll.disabled = disabled;
      btnDeselectAll.style.opacity = disabled ? "0.4" : "1";
      btnDeselectAll.style.pointerEvents = disabled ? "none" : "auto";
    }

    const checkboxes = queueTableBody ? queueTableBody.querySelectorAll(".ep-checkbox") : [];
    checkboxes.forEach(cb => {
      cb.disabled = disabled;
      cb.style.cursor = disabled ? "not-allowed" : "pointer";
    });
  }

  function updateScanStatusPill(type, text) {
    if (!queueStatusPill) return;
    queueStatusPill.className = "queue-status-pill " + type;
    queueStatusPill.textContent = (text || type).toUpperCase();
  }

  function startCooldownCountdown(targetEpoch) {
    stopCooldownCountdown();
    function tick() {
      const now = Date.now() / 1000;
      const left = Math.max(0, Math.ceil(targetEpoch - now));
      if (left > 0) {
        updateScanStatusPill("cooldown", `COOLDOWN ${left}s`);
      } else {
        stopCooldownCountdown();
      }
    }
    tick();
    state.cooldownCountdownTimer = setInterval(tick, 1000);
  }

  function stopCooldownCountdown() {
    if (state.cooldownCountdownTimer) {
      clearInterval(state.cooldownCountdownTimer);
      state.cooldownCountdownTimer = null;
    }
  }

  function playScanSound(isVuln = false) {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (isVuln) {
        osc.frequency.setValueAtTime(440, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.2);
        gain.gain.setValueAtTime(0.3, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0.01, ctx.currentTime + 0.35);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.35);
      } else {
        osc.frequency.setValueAtTime(600, ctx.currentTime);
        gain.gain.setValueAtTime(0.1, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0.01, ctx.currentTime + 0.1);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.1);
      }
    } catch (e) {}
  }

  function setupEvents() {
    if (dropzone) {
      dropzone.addEventListener("click", () => {
        if (state.isScanning) {
          window.showToast("Cannot import HAR while scan is active!", "error");
          return;
        }
        fileInput.click();
      });

      dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        if (!state.isScanning) dropzone.classList.add("dragover");
      });
      dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
      dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (state.isScanning) {
          window.showToast("Cannot import HAR while scan is active!", "error");
          return;
        }
        if (e.dataTransfer.files.length) handleHarFile(e.dataTransfer.files[0]);
      });
    }

    if (fileInput) {
      fileInput.addEventListener("change", (e) => {
        if (e.target.files.length) handleHarFile(e.target.files[0]);
      });
    }

    if (btnScanToggle) {
      btnScanToggle.addEventListener("click", () => {
        if (state.isScanning) stopScan();
        else startScan();
      });
    }

    if (btnSelectParam) btnSelectParam.addEventListener("click", () => setSelection(e => e.has_params));
    if (btnSelectAll) btnSelectAll.addEventListener("click", () => setSelection(() => true));
    if (btnDeselectAll) btnDeselectAll.addEventListener("click", () => setSelection(() => false));

    const configInputs = [delayInput, levelSelect, cfgTechnique, tamperSelect, proxyInput, forceSslCb, randomAgentCb];
    configInputs.forEach(el => {
      if (el) {
        el.addEventListener("input", updateCmdPreview);
        el.addEventListener("change", updateCmdPreview);
      }
    });

    if (cfgPreset) {
      cfgPreset.addEventListener("change", () => {
        const val = cfgPreset.value;
        if (val === "fast") {
          if (delayInput) delayInput.value = "0";
          if (levelSelect) levelSelect.value = "1";
          if (cfgTechnique) cfgTechnique.value = "c";
        } else if (val === "stealth") {
          if (delayInput) delayInput.value = "2.0";
          if (levelSelect) levelSelect.value = "1";
          if (tamperSelect) tamperSelect.value = "space2comment";
        } else if (val === "deep") {
          if (delayInput) delayInput.value = "0.5";
          if (levelSelect) levelSelect.value = "3";
          if (cfgTechnique) cfgTechnique.value = "";
        }
        updateCmdPreview();
      });
    }

    if (btnClearQueue) {
      btnClearQueue.addEventListener("click", async () => {
        if (state.isScanning) {
          window.showToast("Cannot reset queue while scan is running!", "error");
          return;
        }
        state.endpoints = [];
        state.selectedEndpoint = null;
        state.findings = [];
        state.lastLogId = 0;
        state.lastVerboseId = 0;
        state.verboseLogs = [];
        hideScanProgress();
        updateFindingsBadge();
        renderQueueTable();

        const dropTitle = document.getElementById("commix-har-drop-title");
        if (dropTitle) dropTitle.textContent = "Drop .har File";
        if (fileInput) fileInput.value = "";

        if (terminalBox) {
          terminalBox.innerHTML = `
            <div class="terminal-line">
              <span class="t-time">[00:00:00]</span>
              <span class="t-text SUCCESS">⚡ ULTRONSCAN COMMIX ENGINE INITIALIZED & READY.</span>
            </div>
            <div class="terminal-line">
              <span class="t-time">[00:00:00]</span>
              <span class="t-text INFO">Queue cleared. Ready for next audit batch.</span>
            </div>
          `;
        }
        if (verboseBox) {
          verboseBox.innerHTML = `
            <div class="verbose-item">
              <div class="v-main-line">
                <span class="v-time">[00:00:00]</span>
                <span class="v-tag">[VER]</span>
                <span class="v-badge">[READY]</span>
                <span class="v-action">Live probe hit stream active</span>
                <span class="v-url">— Waiting for scan to launch...</span>
              </div>
            </div>
          `;
        }
        renderFindings();
        updateScanStatusPill("idle", "IDLE");

        try {
          await fetch(`${API_BASE}/api/commix/reset`, { method: "POST" });
        } catch (e) {}

        window.showToast("Commix queue & session reset successfully.", "info");
      });
    }

    if (btnCopyCli) {
      btnCopyCli.addEventListener("click", () => {
        const text = cmdPreviewText ? cmdPreviewText.textContent : "";
        window.copyToClipboard(text, "Commix CLI command copied!");
      });
    }

    const btnAutoScroll = document.getElementById("btn-commix-auto-scroll");
    if (btnAutoScroll) {
      btnAutoScroll.addEventListener("click", () => {
        state.autoScroll = !state.autoScroll;
        btnAutoScroll.style.color = state.autoScroll ? "var(--neon-green)" : "var(--text-muted)";
        window.showToast(`Auto-Scroll ${state.autoScroll ? 'Enabled' : 'Disabled'}`, "info");
      });
    }

    const btnCopyLogs = document.getElementById("btn-commix-copy-logs");
    if (btnCopyLogs) {
      btnCopyLogs.addEventListener("click", () => {
        const currentView = state.activeTab === "verbose" ? verboseBox : terminalBox;
        if (!currentView) return;
        const text = currentView.innerText;
        window.copyToClipboard(text, "Console logs copied to clipboard!");
      });
    }

    const btnClearLogs = document.getElementById("btn-commix-clear-logs");
    if (btnClearLogs) {
      btnClearLogs.addEventListener("click", () => {
        if (state.activeTab === "verbose") {
          if (verboseBox) verboseBox.innerHTML = "";
          state.verboseLogs = [];
        } else {
          if (terminalBox) terminalBox.innerHTML = "";
        }
        window.showToast("Console cleared", "info");
      });
    }

    const btnSaveReport = document.getElementById("btn-commix-save-report");
    if (btnSaveReport) {
      btnSaveReport.addEventListener("click", openCommixReportModal);
    }

    if (replyInput && btnSendReply) {
      btnSendReply.addEventListener("click", sendInteractiveReply);
      replyInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") sendInteractiveReply();
      });
    }

    const btnCurlImport = document.getElementById("btn-commix-curl-import");
    if (btnCurlImport) {
      btnCurlImport.addEventListener("click", () => {
        if (state.isScanning) {
          window.showToast("Cannot import cURL while scan is in progress!", "error");
          return;
        }
        window.openModal("curl-modal");
      });
    }
  }

  async function sendInteractiveReply() {
    if (!replyInput) return;
    const text = replyInput.value.trim();
    if (!text) return;

    try {
      const res = await fetch(`${API_BASE}/api/commix/reply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to send response");

      appendLogs([{
        id: ++state.lastLogId,
        time: new Date().toTimeString().split(" ")[0],
        text: `❯ USER INPUT: ${text}`,
        level: "USER"
      }]);
      replyInput.value = "";
    } catch (err) {
      window.showToast(err.message, "error");
    }
  }

  function updateCmdPreview() {
    if (!cmdPreviewText) return;
    const parts = ["commix", "-r <target_request.txt>", "--batch", "-v 1"];

    const delayVal = parseFloat(delayInput ? delayInput.value : "0.5");
    if (!isNaN(delayVal) && delayVal > 0) parts.push(`--delay=${delayVal}`);

    const lvl = parseInt(levelSelect ? levelSelect.value : "1", 10);
    if (!isNaN(lvl) && lvl > 1) parts.push(`--level=${lvl}`);

    const tech = cfgTechnique ? cfgTechnique.value : "";
    if (tech) parts.push(`--technique=${tech}`);

    const tamper = tamperSelect ? tamperSelect.value : "";
    if (tamper) parts.push(`--tamper=${tamper}`);

    const proxy = proxyInput ? proxyInput.value.trim() : "";
    if (proxy) parts.push(`--proxy="${proxy}"`);

    if (forceSslCb && forceSslCb.checked) parts.push("--force-ssl");
    if (randomAgentCb && randomAgentCb.checked) parts.push("--random-agent");

    cmdPreviewText.textContent = parts.join(" ");
  }

  async function handleHarFile(file) {
    if (!file || !file.name.endsWith(".har")) {
      window.showToast("Please provide a valid .har archive", "error");
      return;
    }

    const dropTitle = document.getElementById("commix-har-drop-title");
    if (dropTitle) dropTitle.textContent = "Parsing " + file.name + "...";

    try {
      const text = await file.text();
      const res = await fetch(`${API_BASE}/api/har/parse`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ har_text: text })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "HAR parsing failed");

      state.endpoints = data.endpoints || [];
      renderQueueTable();

      if (dropTitle) dropTitle.textContent = file.name;
      window.showToast(`Loaded ${state.endpoints.length} endpoints from ${file.name}`, "success");
    } catch (err) {
      if (dropTitle) dropTitle.textContent = "Drop .har File";
      window.showToast(err.message, "error");
    }
  }

  function renderQueueTable() {
    if (!queueTableBody) return;
    queueTableBody.innerHTML = "";

    if (state.endpoints.length === 0) {
      queueTableBody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align:center; padding: 40px; color: var(--text-muted);">
            No endpoints loaded. Drag and drop a .har file or paste a cURL command above.
          </td>
        </tr>
      `;
      updateQueueStats();
      return;
    }

    state.endpoints.forEach((ep) => {
      const tr = document.createElement("tr");
      tr.id = `q-row-cmx-${ep.id}`;
      tr.className = `queue-row ${ep.has_params ? 'has-params' : ''}`;

      // Checkbox
      const tdCheck = document.createElement("td");
      tdCheck.style.width = "36px";
      tdCheck.style.textAlign = "center";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "ep-checkbox";
      cb.checked = !!ep.selected;
      cb.disabled = !!state.isScanning;
      cb.style.accentColor = "var(--neon-cyan)";
      cb.style.cursor = state.isScanning ? "not-allowed" : "pointer";
      
      cb.addEventListener("click", (e) => e.stopPropagation());
      cb.addEventListener("change", (e) => {
        ep.selected = e.target.checked;
        if (ep.selected) tr.classList.add("selected-row");
        else tr.classList.remove("selected-row");
        updateQueueStats();
      });
      tdCheck.appendChild(cb);

      // Method badge
      const tdMethod = document.createElement("td");
      tdMethod.style.width = "70px";
      tdMethod.innerHTML = `<span class="method-badge ${ep.method}">${ep.method}</span>`;

      // Path / URL
      const tdPath = document.createElement("td");
      tdPath.className = "url-cell";
      tdPath.title = ep.url || "";
      const displayUrl = ep.path && ep.query_string ? `${ep.path}?${ep.query_string}` : (ep.path || ep.url);
      tdPath.innerHTML = `<span style="color:var(--text-main); font-family:var(--font-mono); font-size:12px;">${escapeHtml(displayUrl || '/')}</span>`;

      // Parameters detected
      const tdParams = document.createElement("td");
      tdParams.style.width = "160px";
      if (ep.has_params) {
        const paramListStr = (ep.param_names || []).slice(0, 3).join(", ");
        const moreCount = (ep.param_names || []).length - 3;
        const moreBadge = moreCount > 0 ? ` +${moreCount}` : '';
        tdParams.innerHTML = `<span class="param-count-badge" style="color:var(--neon-cyan); border-color:var(--neon-cyan);">⚡ ${escapeHtml(paramListStr)}${moreBadge}</span>`;
      } else {
        tdParams.innerHTML = `<span class="param-count-badge zero">None</span>`;
      }

      // Status badge
      const tdStatus = document.createElement("td");
      tdStatus.style.width = "90px";
      tdStatus.id = `status-cmx-${ep.id}`;
      tdStatus.innerHTML = `<span class="status-badge wait">WAIT</span>`;

      tr.appendChild(tdCheck);
      tr.appendChild(tdMethod);
      tr.appendChild(tdPath);
      tr.appendChild(tdParams);
      tr.appendChild(tdStatus);

      // Click to view raw details modal
      tr.addEventListener("click", (e) => {
        if (e.target.closest("input[type='checkbox']") || e.target.closest("td:first-child")) return;
        showEndpointDetails(ep);
      });

      queueTableBody.appendChild(tr);
    });

    updateQueueStats();
  }

  function setSelection(filterFn) {
    if (state.isScanning) return;
    state.endpoints.forEach(ep => {
      ep.selected = filterFn(ep);
    });
    renderQueueTable();
  }

  function updateQueueStats() {
    if (!queueStatsEl) return;
    const total = state.endpoints.length;
    const selected = state.endpoints.filter(e => e.selected).length;
    queueStatsEl.textContent = `(${selected}/${total} selected)`;
  }

  function showEndpointDetails(ep) {
    const titleEl = document.getElementById("ep-modal-title");
    const rawEl = document.getElementById("ep-modal-raw");
    const curlEl = document.getElementById("ep-modal-curl");

    if (titleEl) titleEl.textContent = `${ep.method} ${ep.url}`;
    if (rawEl) rawEl.value = ep.raw_request || "";
    if (curlEl) curlEl.value = ep.curl_command || "";

    window.openModal("endpoint-modal");
  }

  function updateScanProgress(percent) {
    if (!scanProgressBadge) return;
    const pct = Math.max(0, Math.min(100, Math.round(percent)));
    scanProgressBadge.textContent = `${pct}%`;
    scanProgressBadge.style.display = "inline-flex";
  }

  function hideScanProgress() {
    if (scanProgressBadge) {
      scanProgressBadge.style.display = "none";
      scanProgressBadge.textContent = "0%";
    }
  }

  async function startScan() {
    const selected = state.endpoints.filter(e => e.selected);
    if (selected.length === 0) {
      window.showToast("No endpoints selected for Commix scan!", "error");
      return;
    }

    const payload = {
      endpoints: selected,
      delay: parseFloat(delayInput ? delayInput.value : "0.5") || 0.5,
      level: parseInt(levelSelect ? levelSelect.value : "1", 10) || 1,
      technique: cfgTechnique ? (cfgTechnique.value || null) : null,
      tamper: tamperSelect ? (tamperSelect.value || null) : null,
      proxy: proxyInput ? (proxyInput.value.trim() || null) : null,
      force_ssl: forceSslCb ? forceSslCb.checked : false,
      random_agent: randomAgentCb ? randomAgentCb.checked : true,
      batch: true
    };

    try {
      const res = await fetch(`${API_BASE}/api/commix/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to start Commix scan");

      state.isScanning = true;
      setScanButtonState(true);
      setScanControlsDisabled(true);
      updateScanStatusPill("running", "SCANNING");
      switchCommixRightTab("terminal");
      updateScanProgress(0);

      window.showToast("Commix OS Command Injection scan started!", "success");
      startPolling();
    } catch (err) {
      window.showToast(err.message, "error");
    }
  }

  async function stopScan() {
    try {
      const res = await fetch(`${API_BASE}/api/commix/stop`, { method: "POST" });
      const data = await res.json();
      window.showToast(data.message || "Stopping Commix scan...", "info");
      updateScanStatusPill("stopped", "STOPPING");
    } catch (err) {
      window.showToast(err.message, "error");
    }
  }

  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(pollStatus, 600);
  }

  async function pollStatus() {
    try {
      const res = await fetch(`${API_BASE}/api/commix/status?since_log_id=${state.lastLogId}&since_verbose_id=${state.lastVerboseId}`);
      if (!res.ok) return;
      const data = await res.json();

      // Logs
      if (data.new_logs && data.new_logs.length > 0) {
        appendLogs(data.new_logs);
        state.lastLogId = data.new_logs[data.new_logs.length - 1].id;
      }

      // Verbose Stream
      if (data.new_verbose && data.new_verbose.length > 0) {
        appendVerboseLogs(data.new_verbose);
        state.lastVerboseId = data.new_verbose[data.new_verbose.length - 1].id;
      }

      // Findings
      if (data.findings && data.findings.length !== state.findings.length) {
        const isNew = data.findings.length > state.findings.length;
        state.findings = data.findings;
        updateFindingsBadge();
        renderFindings();
        if (isNew) {
          playScanSound(true);
          window.showToast("🚨 Commix confirmed OS Command Injection (RCE)!", "error");
        }
      }

      // Queue Progress %
      if (data.progress != null && (data.status === "running" || data.status === "cooldown")) {
        updateScanProgress(data.progress);
      }

      // Row status sync
      updateRowStatuses(data);

      // Cooldown handling
      if (data.status === "cooldown" && data.cooldown && data.cooldown.active) {
        const remaining = data.cooldown.remaining || 0;
        startCooldownCountdown((Date.now() / 1000) + remaining);
      } else if (data.status !== "cooldown") {
        stopCooldownCountdown();
      }

      // Scan termination check
      if (data.status === "completed" || data.status === "stopped" || data.status === "error" || data.status === "idle") {
        if (state.isScanning) {
          state.isScanning = false;
          setScanButtonState(false);
          setScanControlsDisabled(false);
          stopCooldownCountdown();

          if (data.status === "completed") {
            updateScanProgress(100);
            updateScanStatusPill("completed", "DONE");
            playScanSound(false);
            window.showToast("Commix scan completed successfully!", "success");
          } else if (data.status === "stopped") {
            updateScanStatusPill("stopped", "STOPPED");
            window.showToast("Commix scan stopped by user.", "info");
          } else if (data.status === "error") {
            updateScanStatusPill("error", "ERROR");
            window.showToast("Commix scan terminated with an error.", "error");
          } else {
            updateScanStatusPill("idle", "IDLE");
          }
        }
      }
    } catch (err) {}
  }

  function appendLogs(logs) {
    if (!terminalBox) return;
    const fragment = document.createDocumentFragment();

    logs.forEach(l => {
      const line = document.createElement("div");
      line.className = "terminal-line";

      const timeSpan = document.createElement("span");
      timeSpan.className = "t-time";
      timeSpan.textContent = `[${l.time}]`;

      const textSpan = document.createElement("span");
      textSpan.className = `t-text ${l.level || 'INFO'}`;
      textSpan.textContent = " " + l.text;

      line.appendChild(timeSpan);
      line.appendChild(textSpan);
      fragment.appendChild(line);
    });

    terminalBox.appendChild(fragment);
    if (state.autoScroll) {
      terminalBox.scrollTop = terminalBox.scrollHeight;
    }
  }

  function appendVerboseLogs(vLogs) {
    if (!verboseBox) return;
    const fragment = document.createDocumentFragment();

    vLogs.forEach(v => {
      state.verboseLogs.push(v);
      if (state.verboseLogs.length > state.maxVerboseLines) {
        state.verboseLogs.shift();
        if (verboseBox.firstChild) verboseBox.removeChild(verboseBox.firstChild);
      }

      const item = document.createElement("div");
      item.className = "verbose-item";

      const badgeClass = v.tag === "RCE-Payload" ? "vuln" : (v.tag === "Attack-Vector" ? "testing" : "probe");

      item.innerHTML = `
        <div class="v-main-line">
          <span class="v-time">[${v.time}]</span>
          <span class="v-tag">[CMX]</span>
          <span class="v-badge ${badgeClass}">[${escapeHtml(v.tag)}]</span>
          <span class="v-action">${escapeHtml(v.action)}</span>
          <span class="v-url">${escapeHtml(v.target)}</span>
        </div>
        ${v.detail ? `<div class="v-detail-line">${escapeHtml(v.detail)}</div>` : ''}
      `;

      fragment.appendChild(item);
    });

    verboseBox.appendChild(fragment);
    if (state.autoScroll) {
      verboseBox.scrollTop = verboseBox.scrollHeight;
    }
  }

  function updateRowStatuses(data) {
    const curIdx = data.current_index;
    const selectedEps = state.endpoints.filter(e => e.selected);

    selectedEps.forEach((ep, idx) => {
      const row = document.getElementById(`q-row-cmx-${ep.id}`);
      const stEl = document.getElementById(`status-cmx-${ep.id}`);
      if (!row || !stEl) return;

      const isFoundVuln = (data.findings || []).some(f => f.endpoint_id === ep.id);
      const queueItem = (data.queue || []).find(q => q.id === ep.id);
      const isSkipped = (queueItem && queueItem.status === "skipped") || ep.status === "skipped";

      if (isFoundVuln) {
        row.className = "queue-row vulnerable";
        stEl.innerHTML = `<span class="status-badge vuln">VULN</span>`;
      } else if (isSkipped) {
        row.className = "queue-row skipped";
        stEl.innerHTML = `<span class="status-badge skipped">SKIPPED</span>`;
      } else if (data.is_running && idx === curIdx) {
        row.className = "queue-row scanning";
        stEl.innerHTML = `<span class="status-badge scan">TESTING</span>`;
      } else if (idx < curIdx || (!data.is_running && data.status === "completed")) {
        row.className = "queue-row clean";
        stEl.innerHTML = `<span class="status-badge clean">SAFE</span>`;
      } else {
        stEl.innerHTML = `<span class="status-badge wait">WAIT</span>`;
      }
    });
  }

  function updateFindingsBadge() {
    if (!findingsCountBadge) return;
    const count = state.findings.length;
    findingsCountBadge.textContent = count;
    findingsCountBadge.style.display = count > 0 ? "inline-flex" : "none";
  }

  function getCurlCommandForFinding(f) {
    if (f.curl_command) return f.curl_command;
    const ep = state.endpoints.find(e => e.id === f.endpoint_id || e.url === f.url);
    if (ep && ep.curl_command) return ep.curl_command;
    return `curl -X ${f.method || 'GET'} "${f.url || ''}"`;
  }

  function renderFindings() {
    if (!findingsBox) return;

    if (state.findings.length === 0) {
      findingsBox.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🛡️</div>
          <div style="font-size: 14px; font-weight: 700; color: var(--neon-cyan);">No Vulnerabilities Yet</div>
          <div style="font-size: 12px; color: var(--text-muted); max-width: 320px;">
            Identified OS command injection points and execution proofs will appear here during testing.
          </div>
        </div>
      `;
      return;
    }

    findingsBox.innerHTML = "";
    state.findings.forEach(f => {
      const card = document.createElement("div");
      card.className = "vuln-card";

      let paramsHtml = "";
      (f.vulnerable_params || []).forEach(p => {
        const techs = (p.techniques || []).map(t => `
          <div class="param-tech">
            ↳ <strong style="color:var(--neon-cyan);">${escapeHtml(t.title || t.type || 'Command Injection')}</strong>
            <div class="param-payload-line">Payload: <code>${escapeHtml(t.payload || '')}</code></div>
          </div>
        `).join("");
        paramsHtml += `
          <div class="vuln-param-item">
            <span class="param-title">⚡ Parameter '${escapeHtml(p.param)}' (${p.location || 'GET'}) is injectable</span>
            ${techs}
          </div>
        `;
      });

      card.innerHTML = `
        <div class="vuln-card-head">
          <div class="vuln-method-url">
            <span class="method-badge ${f.method}">${f.method}</span>
            <span style="color:var(--neon-cyan);">${escapeHtml(f.url)}</span>
          </div>
          <span class="vuln-dbms-badge" style="color:var(--neon-cyan); border-color:var(--neon-cyan);">💻 OS: ${escapeHtml(f.os || 'Linux/Unix')}</span>
        </div>
        <div class="vuln-details-box">
          ${paramsHtml}
        </div>
        <div class="vuln-actions-bar">
          <button class="vuln-enum-btn btn-exploit-user" title="Retrieve current OS user account">
            👤 Current User
          </button>
          <button class="vuln-enum-btn btn-exploit-file" title="Read system file (e.g. /etc/passwd)">
            📄 Read /etc/passwd
          </button>
          <button class="vuln-enum-btn btn-exploit-cmd" title="Execute arbitrary OS command">
            💻 Run OS Cmd
          </button>
          <button class="vuln-copy-btn btn-copy-commix" title="Copy Commix command">
            📋 Copy Commix
          </button>
          <button class="vuln-copy-btn btn-copy-curl" title="Copy cURL command">
            📋 Copy cURL
          </button>
        </div>
      `;

      // Event listeners
      const btnCurl = card.querySelector(".btn-copy-curl");
      if (btnCurl) {
        btnCurl.addEventListener("click", (e) => {
          e.stopPropagation();
          const curlCmd = getCurlCommandForFinding(f);
          window.copyToClipboard(curlCmd, "cURL command copied!");
        });
      }

      const btnCommix = card.querySelector(".btn-copy-commix");
      if (btnCommix) {
        btnCommix.addEventListener("click", (e) => {
          e.stopPropagation();
          window.copyToClipboard(f.commix_command || "", "Commix command copied!");
        });
      }

      const btnUser = card.querySelector(".btn-exploit-user");
      if (btnUser) {
        btnUser.addEventListener("click", (e) => {
          e.stopPropagation();
          runCommixExploit(f.id, "current-user");
        });
      }

      const btnFile = card.querySelector(".btn-exploit-file");
      if (btnFile) {
        btnFile.addEventListener("click", (e) => {
          e.stopPropagation();
          const targetFile = prompt("Enter system file path to read via Commix:", "/etc/passwd");
          if (targetFile) {
            runCommixExploit(f.id, "file-read", targetFile);
          }
        });
      }

      const btnCmd = card.querySelector(".btn-exploit-cmd");
      if (btnCmd) {
        btnCmd.addEventListener("click", (e) => {
          e.stopPropagation();
          const cmd = prompt("Enter OS command to execute on target system:", "id");
          if (cmd) {
            runCommixExploit(f.id, "os-cmd", cmd);
          }
        });
      }

      findingsBox.appendChild(card);
    });
  }

  async function runCommixExploit(findingId, action, payload = "") {
    try {
      const res = await fetch(`${API_BASE}/api/commix/exploit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId, action: action, payload: payload })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Exploitation failed to launch");

      state.isScanning = true;
      setScanButtonState(true);
      updateScanStatusPill("running", "EXPLOITING");
      switchCommixRightTab("terminal");
      startPolling();
      window.showToast(`Launched ${action.toUpperCase()} exploitation! Live stream in Console...`, "success");
    } catch (err) {
      window.showToast(err.message, "error");
    }
  }

  function openCommixReportModal() {
    if (state.findings.length === 0 && state.endpoints.length === 0) {
      window.showToast("No scan data available to export", "info");
      return;
    }

    const now = new Date();
    const ts = now.getFullYear() +
      String(now.getMonth() + 1).padStart(2, "0") +
      String(now.getDate()).padStart(2, "0") + "_" +
      String(now.getHours()).padStart(2, "0") +
      String(now.getMinutes()).padStart(2, "0") +
      String(now.getSeconds()).padStart(2, "0");

    const defaultPath = `~/Downloads/ultronscan_commix_report_${ts}.html`;
    const pathInput = document.getElementById("report-custom-path");
    if (pathInput) pathInput.value = defaultPath;

    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const vulnCount = state.findings.length;
      const targetUrl = state.endpoints[0]?.url || "Target APIs";
      summaryEl.innerHTML = `
        <div style="color:var(--text-main); margin-bottom:4px;"><strong>Target:</strong> ${escapeHtml(targetUrl)}</div>
        <div style="margin-bottom:4px;"><strong>Endpoints Scanned:</strong> ${scannedCount}</div>
        <div style="color:${vulnCount > 0 ? 'var(--neon-red)' : 'var(--neon-green)'};">
          <strong>Identified Vulnerabilities:</strong> ${vulnCount} ${vulnCount > 0 ? '🚨 (OS Command Injection Confirmed)' : '✅ (Target Safe)'}
        </div>
      `;
    }

    window.openModal("report-save-modal");
  }

  // Right Tabs Switcher for Commix
  window.switchCommixRightTab = function(tabName) {
    state.activeTab = tabName;
    const tabTerminal = document.getElementById("commix-tab-btn-terminal");
    const tabVerbose = document.getElementById("commix-tab-btn-verbose");
    const tabFindings = document.getElementById("commix-tab-btn-findings");

    const viewTerminal = document.getElementById("commix-terminal-view");
    const viewVerbose = document.getElementById("commix-terminal-verbose-view");
    const viewFindings = document.getElementById("commix-findings-view");

    if (tabTerminal) tabTerminal.className = "out-tab-btn" + (tabName === "terminal" ? " active" : "");
    if (tabVerbose) tabVerbose.className = "out-tab-btn" + (tabName === "verbose" ? " active" : "");
    if (tabFindings) tabFindings.className = "out-tab-btn" + (tabName === "findings" ? " active" : "");

    if (viewTerminal) viewTerminal.style.display = tabName === "terminal" ? "block" : "none";
    if (viewVerbose) viewVerbose.style.display = tabName === "verbose" ? "block" : "none";
    if (viewFindings) viewFindings.style.display = tabName === "findings" ? "block" : "none";
  };

  // cURL import hook for Commix
  window.commixParseCurlModal = async function() {
    if (state.isScanning) {
      window.showToast("Cannot import cURL while scan is in progress!", "error");
      return;
    }
    const txtArea = document.getElementById("curl-modal-input");
    const curlText = txtArea?.value?.trim();
    if (!curlText) {
      window.showToast("Please paste a valid cURL command", "error");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/curl/parse`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ curl_text: curlText })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "cURL parse failed");

      state.endpoints.unshift(data.endpoint);
      renderQueueTable();
      window.closeModal("curl-modal");
      window.showToast("cURL command imported into Commix queue!", "success");
      txtArea.value = "";
    } catch (err) {
      window.showToast(err.message, "error");
    }
  };

  // Commix Report Save Hook
  window.saveCommixReportToSelectedPath = async function(revealInFinder = true) {
    const pathInput = document.getElementById("report-custom-path");
    const chosenPath = pathInput?.value?.trim() || "~/Downloads";

    try {
      const res = await fetch(`${API_BASE}/api/commix/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Commix OS Command Injection Security Audit Report",
          target: state.endpoints[0]?.url || "Target APIs",
          findings: state.findings,
          stats: {
            scanned_count: state.endpoints.filter(e => e.selected).length,
            vulnerable_count: state.findings.length
          },
          custom_path: chosenPath,
          reveal_in_finder: !!revealInFinder
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to save report");

      window.closeModal("report-save-modal");
      window.showToast(`✅ ${data.message || 'Report saved successfully!'} (Revealed in Finder)`, "success");
    } catch (err) {
      window.showToast(err.message, "error");
    }
  };

  // Commix Report Open in Browser Hook
  window.openCommixReportInBrowser = async function() {
    const pathInput = document.getElementById("report-custom-path");
    const chosenPath = pathInput?.value?.trim() || "~/Downloads";

    try {
      const res = await fetch(`${API_BASE}/api/commix/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Commix OS Command Injection Security Audit Report",
          target: state.endpoints[0]?.url || "Target APIs",
          findings: state.findings,
          stats: {
            scanned_count: state.endpoints.filter(e => e.selected).length,
            vulnerable_count: state.findings.length
          },
          custom_path: chosenPath,
          open_in_browser: true
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to open report");

      window.closeModal("report-save-modal");
      window.showToast(`🌐 Report opened in default browser!`, "success");
    } catch (err) {
      window.showToast(err.message, "error");
    }
  };

  function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
  }

  // Initialize on DOM load
  document.addEventListener("DOMContentLoaded", initElements);
})();
