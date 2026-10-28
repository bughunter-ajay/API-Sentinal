// ── JS Analyser ───────────────────────────────────────────────────────────────
const JSA_BASE = "http://127.0.0.1:8792";

let _jsaEndpoints       = [];   // parsed from HAR / cURL / AV capture
let _jsaChecked         = {};   // {method::url: bool}
let _jsaJobId           = null;
let _jsaPollTimer       = null;
let _jsaAllFindings     = [];
let _jsaVisibleRows     = [];   // currently-rendered (filtered) findings — context menu indexes into this
let _jsaLastJob         = null;
let _jsaFilterText      = "";   // capture-tab URL filter
let _jsaTableFilterText = "";   // results-tab free-text filter
let _jsaCtxFinding      = null;
let _jsaLogRendered     = 0;    // how many of the CURRENT job's logs are already in the DOM
let _jsaScanLogs        = [];   // cumulative structured log entries across the whole session — source of truth for expand/collapse
let _jsaPendingHar      = null; // HAR parsed from the file picker, held while the token-update modal is open

// Hidden by Reset so the live 2s poll (jsaSyncFromCapture) cannot silently
// refill the same traffic the moment _jsaChecked is cleared. IDs cover the
// current AV buffer; method::url keys also cover HAR/cURL rows (no id) and
// the same API recaptured under a new id while browsing continues.
let _jsaDismissedIds  = new Set();
let _jsaDismissedKeys = new Set();
// Bumped on every Reset so in-flight /jsa/scan + progress polls cannot
// write findings/logs back after the UI has already been cleared.
let _jsaEpoch = 0;

// ── Continuous auto-scan ("Start") state ──────────────────────────────────────
let _jsaScanRunning   = false;   // true from Start click until Abort/no-more-work
let _jsaStartedOnce   = false;   // switches the capture-count display to live counts
let _jsaActiveInclude = [];      // active include filter terms (lowercased)
let _jsaActiveExclude = [];      // active exclude filter terms (lowercased)
let _jsaScannedPaths  = new Set(); // method::basepath already scanned/claimed this session
let _jsaScannedCount  = 0;
let _jsaSkippedCount  = 0;
let _jsaCurrentBatch  = [];      // endpoint objects in the in-flight batch, for onBatchDone

// ── Tab switch ────────────────────────────────────────────────────────────────
function jsaSwitchTab(tab) {
  document.getElementById("jsa-tab-capture").classList.toggle("active", tab === "capture");
  document.getElementById("jsa-tab-scanning").classList.toggle("active", tab === "scanning");
  document.getElementById("jsa-tab-results").classList.toggle("active", tab === "results");
  const tabTerm = document.getElementById("jsa-tab-terminal");
  if (tabTerm) tabTerm.classList.toggle("active", tab === "terminal");
  const tabEng = document.getElementById("jsa-tab-engine");
  if (tabEng) tabEng.classList.toggle("active", tab === "engine");

  document.getElementById("jsa-tab-capture-content").style.display  = tab === "capture"  ? "flex" : "none";
  document.getElementById("jsa-tab-scanning-content").style.display = tab === "scanning" ? "flex" : "none";
  document.getElementById("jsa-tab-results-content").style.display  = tab === "results"  ? "flex" : "none";
  const termContent = document.getElementById("jsa-tab-terminal-content");
  if (termContent) termContent.style.display = tab === "terminal" ? "flex" : "none";
  const engContent = document.getElementById("jsa-tab-engine-content");
  if (engContent) engContent.style.display = tab === "engine" ? "flex" : "none";

  if (tab === "terminal") jsaRenderTerminalPane();
  if (tab === "engine") jsaCheckEngineStatus(false);
}

// ── Terminal Console ──────────────────────────────────────────────────────────
let _jsaTerminalLogs = [];
let _jsaTerminalFilter = "all";

function jsaAppendTerminalLog(msg, category = "info") {
  const timeStr = new Date().toLocaleTimeString();
  _jsaTerminalLogs.push({ time: timeStr, msg, category });
  if (_jsaTerminalLogs.length > 500) _jsaTerminalLogs.shift();
  jsaRenderTerminalPane();
}

function jsaRenderTerminalPane() {
  const pane = document.getElementById("jsa-terminal-pane");
  if (!pane) return;
  const counter = document.getElementById("jsa-terminal-counter");
  if (counter) counter.textContent = `${_jsaTerminalLogs.length} lines`;

  const filtered = _jsaTerminalLogs.filter(l => {
    if (_jsaTerminalFilter === "secrets") return l.category === "secret";
    if (_jsaTerminalFilter === "entropy") return l.category === "entropy";
    return true;
  });

  if (!filtered.length) {
    pane.innerHTML = `<div style="color:var(--text3)">[Terminal Ready] No log lines matching filter '${_jsaTerminalFilter}'.</div>`;
    return;
  }

  const colorMap = {
    info: "#8b949e",
    secret: "#f85149",
    entropy: "#3fb950",
    replay: "#58a6ff",
    warn: "#d29922",
    error: "#f85149",
  };

  pane.innerHTML = filtered.map(item => {
    const col = colorMap[item.category] || "#3fb950";
    const badge = item.category.toUpperCase();
    let textCol = "#3fb950";
    if (item.category === "secret" || item.category === "error") {
      textCol = "#ff7b72";
    } else if (item.category === "warn") {
      textCol = "#d29922";
    }
    return `<div style="display:flex;gap:8px;line-height:1.45"><span style="color:#6e7681;flex-shrink:0">[${item.time}]</span> <span style="color:${col};font-weight:700;flex-shrink:0">[${badge}]</span> <span style="color:${textCol}">${jsaEsc(item.msg)}</span></div>`;
  }).join("");

  const autoscroll = document.getElementById("jsa-terminal-autoscroll");
  if (autoscroll && autoscroll.checked) {
    pane.scrollTop = pane.scrollHeight;
  }
}

function jsaSwitchTerminalMode(mode) {
  _jsaTerminalFilter = mode;
  ["all", "secrets", "entropy"].forEach(m => {
    const b = document.getElementById(`jsa-term-mode-${m}`);
    if (b) {
      if (m === mode) {
        b.style.background = "var(--bg3)";
        b.style.color = "var(--text)";
        b.style.border = "1px solid var(--border)";
      } else {
        b.style.background = "transparent";
        b.style.color = "var(--text3)";
        b.style.border = "none";
      }
    }
  });
  jsaRenderTerminalPane();
}

function jsaClearTerminalLogs() {
  _jsaTerminalLogs = [];
  jsaRenderTerminalPane();
}

function jsaCopyTerminalLogs() {
  if (!_jsaTerminalLogs.length) {
    if (typeof showToast === "function") showToast("Terminal is empty.", "info");
    return;
  }
  const text = _jsaTerminalLogs.map(l => `[${l.time}] [${l.category.toUpperCase()}] ${l.msg}`).join("\n");
  navigator.clipboard.writeText(text);
  if (typeof showToast === "function") showToast("📋 Terminal logs copied!", "success");
  else alert("Terminal logs copied to clipboard!");
}

// ── Engine Settings & Installer ──────────────────────────────────────────────
let _jsaInstallPollTimer = null;

async function jsaCheckEngineStatus(notify = false) {
  try {
    const res = await fetch(`${JSA_BASE}/jsa/engine/status`);
    if (!res.ok) throw new Error("Status check failed");
    const data = await res.json();

    const topBadge = document.getElementById("jsa-top-engine-badge");
    const modeVal = document.getElementById("jsa-engine-mode-val");
    const verVal = document.getElementById("jsa-engine-version-val");
    const binVal = document.getElementById("jsa-engine-binary-val");
    const detVal = document.getElementById("jsa-engine-detectors-val");
    const msgEl = document.getElementById("jsa-engine-status-msg");

    if (data.installed) {
      if (topBadge) {
        topBadge.textContent = "🦝 TruffleHog CLI + Native";
        topBadge.style.color = "#58a6ff";
        topBadge.style.borderColor = "#58a6ff";
        topBadge.style.background = "rgba(88, 166, 255, 0.15)";
      }
      if (modeVal) {
        modeVal.textContent = "🟢 Official TruffleHog CLI Linked";
        modeVal.style.color = "#58a6ff";
      }
      if (verVal) verVal.textContent = data.version || "Installed";
      if (binVal) binVal.textContent = data.binary_path || "/opt/homebrew/bin/trufflehog";
    } else {
      if (topBadge) {
        topBadge.textContent = "⚡ Native Secret Engine (181+ Detectors)";
        topBadge.style.color = "#3fb950";
        topBadge.style.borderColor = "#3fb950";
        topBadge.style.background = "rgba(63, 185, 80, 0.15)";
      }
      if (modeVal) {
        modeVal.textContent = "⚡ Native In-Memory Engine";
        modeVal.style.color = "#3fb950";
      }
      if (verVal) verVal.textContent = "Native v2.4 (Compiled In-Memory)";
      if (binVal) binVal.textContent = "None (Built-in Zero-Config)";
    }

    if (detVal) {
      detVal.textContent = `${data.native_detectors || 181} Detectors + Shannon Entropy`;
    }

    if (notify && msgEl) {
      msgEl.style.display = "block";
      msgEl.style.background = "rgba(63, 185, 80, 0.15)";
      msgEl.style.color = "#3fb950";
      msgEl.textContent = `✓ Checked: Engine active (${data.installed ? 'TruffleHog CLI Detected: ' + data.version : 'Using Native Engine with 181+ Detectors'})`;
      setTimeout(() => { if (msgEl) msgEl.style.display = "none"; }, 4000);
    }
  } catch (e) {
    console.warn("jsaCheckEngineStatus error:", e);
  }
}

async function jsaRunEngineInstall() {
  const btn = document.getElementById("jsa-btn-engine-install");
  const logBox = document.getElementById("jsa-engine-install-logs");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Installing..."; }
  if (logBox) {
    logBox.style.display = "block";
    logBox.textContent = `[${new Date().toLocaleTimeString()}] 🚀 Launching Homebrew: 'brew install trufflehog'...\n`;
  }
  jsaAppendTerminalLog("Starting 1-Click Install: 'brew install trufflehog'", "replay");

  try {
    const res = await fetch(`${JSA_BASE}/jsa/engine/install`, { method: "POST" });
    const data = await res.json();

    if (_jsaInstallPollTimer) clearInterval(_jsaInstallPollTimer);
    _jsaInstallPollTimer = setInterval(async () => {
      try {
        const pollRes = await fetch(`${JSA_BASE}/jsa/engine/install-status`);
        const pollData = await pollRes.json();
        if (logBox && pollData.logs) {
          logBox.textContent = pollData.logs.join("\n");
          logBox.scrollTop = logBox.scrollHeight;
        }
        if (pollData.status === "completed") {
          clearInterval(_jsaInstallPollTimer);
          if (btn) { btn.disabled = false; btn.textContent = "⬇️ Run 1-Click Install"; }
          jsaAppendTerminalLog("✅ TruffleHog installation completed!", "entropy");
          if (typeof showToast === "function") showToast("🎉 TruffleHog installed successfully!", "success");
          jsaCheckEngineStatus(true);
        } else if (pollData.status === "failed") {
          clearInterval(_jsaInstallPollTimer);
          if (btn) { btn.disabled = false; btn.textContent = "⬇️ Run 1-Click Install"; }
          jsaAppendTerminalLog("❌ TruffleHog install failed.", "warn");
          if (typeof showToast === "function") showToast("Installation failed. Check logs.", "error");
        }
      } catch (_) {}
    }, 1000);
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = "⬇️ Run 1-Click Install"; }
    alert("Error launching install: " + e.message);
  }
}

async function jsaRunEngineUpdate() {
  const btn = document.getElementById("jsa-btn-engine-update");
  const logBox = document.getElementById("jsa-engine-install-logs");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Checking..."; }
  if (logBox) {
    logBox.style.display = "block";
    logBox.textContent = `[${new Date().toLocaleTimeString()}] 🔍 Checking for TruffleHog CLI updates...\n`;
  }
  jsaAppendTerminalLog("Checking for TruffleHog updates: 'brew upgrade trufflehog'", "replay");
  try {
    const res = await fetch(`${JSA_BASE}/jsa/engine/update`, { method: "POST" });
    const data = await res.json().catch(() => null);
    if (!data) {
      const errTxt = `Server returned status ${res.status}`;
      if (logBox) logBox.textContent += `❌ ${errTxt}\n`;
      jsaAppendTerminalLog(`[ERROR] ${errTxt}`, "error");
      if (typeof showToast === "function") showToast("Update check failed: " + errTxt, "error");
      else alert("Update check error: " + errTxt);
      return;
    }

    if (!data.installed) {
      const msg = data.message || "TruffleHog CLI is not installed yet. Click 'Run 1-Click Install' first, or continue using the Native Engine.";
      if (logBox) {
        logBox.textContent += `ℹ️ ${msg}\n💡 Note: Native Engine with 181+ detectors is actively protecting all scans.\n`;
      }
      jsaAppendTerminalLog(`[INFO] ${msg}`, "info");
      if (typeof showToast === "function") showToast(msg, "info");
      else alert(msg);
    } else if (data.success) {
      const msg = data.message || "TruffleHog is up to date!";
      if (logBox) logBox.textContent += `✅ ${data.output || msg}\n`;
      jsaAppendTerminalLog(`[UPDATE] ${data.output || msg}`, "entropy");
      if (typeof showToast === "function") showToast(msg, "success");
      else alert(msg);
    } else {
      const msg = data.message || data.output || "Update completed.";
      if (logBox) logBox.textContent += `⚠️ ${msg}\n`;
      jsaAppendTerminalLog(`[WARN] ${msg}`, "param");
      if (typeof showToast === "function") showToast(msg, "warn");
      else alert(msg);
    }
    jsaCheckEngineStatus(false);
  } catch (e) {
    if (logBox) logBox.textContent += `❌ Error: ${e.message}\n`;
    jsaAppendTerminalLog(`[ERROR] Update check failed: ${e.message}`, "error");
    if (typeof showToast === "function") {
      showToast("Update check error: " + e.message, "error");
    } else {
      alert("Update check error: " + e.message);
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "🔄 Check & Upgrade TruffleHog"; }
  }
}


// ── HAR import ────────────────────────────────────────────────────────────────
function jsaSetupHarInput() {
  const inp = document.getElementById("jsa-har-file-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    try {
      const text = await file.text();
      const har  = JSON.parse(text);
      jsaShowHarTokenModal(har);
    } catch(e) {
      alert("HAR parse error: " + e.message);
    }
    inp.value = "";
  };
}

// Holds the freshly-parsed HAR until the user decides, via the token modal,
// whether to swap in a fresh Authorization token or keep what was captured.
function jsaShowHarTokenModal(har) {
  _jsaPendingHar = har;
  document.getElementById("jsa-har-token-input").value = "";
  document.getElementById("jsa-har-token-modal").style.display = "flex";
  setTimeout(() => document.getElementById("jsa-har-token-input")?.focus(), 50);
}
function jsaConfirmHarToken() {
  const token = document.getElementById("jsa-har-token-input").value.trim();
  document.getElementById("jsa-har-token-modal").style.display = "none";
  jsaLoadFromHar(_jsaPendingHar, token || null);
  _jsaPendingHar = null;
}
function jsaSkipHarToken() {
  document.getElementById("jsa-har-token-modal").style.display = "none";
  jsaLoadFromHar(_jsaPendingHar, null);
  _jsaPendingHar = null;
}

// Sets the Authorization header's token across every imported endpoint.
// Keeps the original scheme prefix (e.g. "Bearer ") when the user pastes a
// bare token; uses their input verbatim if it already looks like a full
// header value (contains a space, e.g. "Bearer eyJ...").
//
// If the captured request never had an Authorization header at all (common
// with HAR entries captured while logged out, or where auth rides on a
// cookie instead), this used to silently do nothing — the token the user
// typed into the modal never made it onto the request, and every replay
// came back 401 "Missing Credentials" with no indication why. Now it ADDS
// the header when none exists, defaulting to the Bearer scheme.
function jsaApplyNewToken(headers, newToken) {
  const existingKey = Object.keys(headers).find(k => k.toLowerCase() === "authorization");
  if (existingKey) {
    const m = headers[existingKey].match(/^(\S+)\s+/);
    headers[existingKey] = (!newToken.includes(" ") && m) ? `${m[1]} ${newToken}` : newToken;
  } else {
    headers["Authorization"] = newToken.includes(" ") ? newToken : `Bearer ${newToken}`;
  }
}

/** Pull status / headers / body from a HAR entry's recorded response (no live hit). */
function jsaExtractHarResponse(entry) {
  const rs = entry?.response || {};
  const status = typeof rs.status === "number" ? rs.status : (rs.status != null ? parseInt(rs.status, 10) || null : null);
  const headers = {};
  for (const h of (rs.headers || [])) {
    if (!h || !h.name || String(h.name).startsWith(":")) continue;
    headers[h.name] = h.value != null ? String(h.value) : "";
  }
  let body = "";
  const content = rs.content || {};
  if (content.text != null && content.text !== "") {
    body = String(content.text);
    if (String(content.encoding || "").toLowerCase() === "base64") {
      try {
        // Decode to binary string then to UTF-8 where possible (JSON/JS/text HARs).
        const bin = atob(body);
        try {
          body = new TextDecoder("utf-8", { fatal: false }).decode(
            Uint8Array.from(bin, c => c.charCodeAt(0))
          );
        } catch (e) {
          body = bin;
        }
      } catch (e) { /* keep base64 text as-is */ }
    }
  }
  return { status, headers, body };
}

function jsaOnRecordedToggle() {
  const on = !!document.getElementById("jsa-recorded-cb")?.checked;
  const hint = document.getElementById("jsa-run-hint");
  if (hint) {
    hint.textContent = on
      ? "Recorded mode: selected endpoints are scanned offline using the HAR’s stored response — no live API calls."
      : "Each selected request is sent live — both the request itself and the real response are scanned for exposed secrets.";
  }
}

function jsaLoadFromHar(har, newToken) {
  const entries = har?.log?.entries || [];
  // Unlike Method Tampering, we deliberately do NOT skip .js URLs here —
  // a directly-captured JS file is exactly the kind of thing this tool
  // wants to scan, not noise to filter out.
  const STATIC = /\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|webp)(\?|$)/i;
  const seen = new Set();
  _jsaEndpoints = []; _jsaChecked = {};

  for (const entry of entries) {
    const rq     = entry.request || {};
    const url    = rq.url || "";
    const method = (rq.method || "GET").toUpperCase();
    if (!url.startsWith("http") || STATIC.test(url)) continue;
    const key = method + "::" + url;
    if (seen.has(key)) continue;
    seen.add(key);

    const headers = {};
    for (const h of (rq.headers || [])) {
      if (!h.name.startsWith(":") && !["host","content-length","accept-encoding"].includes(h.name.toLowerCase()))
        headers[h.name] = h.value;
    }
    // Token update only rewrites request Authorization — recorded response stays as in HAR.
    if (newToken) jsaApplyNewToken(headers, newToken);
    let body = null;
    const postData = rq.postData;
    if (postData && postData.text) {
      try { body = JSON.parse(postData.text); } catch(e) { body = postData.text; }
    }

    const recorded = jsaExtractHarResponse(entry);
    _jsaEndpoints.push({
      url, method, headers, body,
      has_recorded: true,
      recorded_status: recorded.status,
      recorded_headers: recorded.headers,
      recorded_body: recorded.body,
    });
    _jsaChecked[key] = true;
  }

  document.getElementById("jsa-capture-count").textContent = `${_jsaEndpoints.length} endpoints`;
  jsaRenderEndpointList();
  jsaUpdateLiveCounts();
  jsaOnRecordedToggle();
}

// ── From AV Capture ───────────────────────────────────────────────────────────
function jsaLoadFromCapture() {
  const avState = window._avState;
  const reqs = avState?.requests || [];
  if (!reqs.length) {
    alert("No requests in API Validator capture.\n\nCapture requests in API Validator Pro tab first, or import a HAR / cURL.");
    return;
  }
  // Explicit reload — Reset hid these from auto-sync; the user asked for them back.
  _jsaDismissedIds.clear();
  _jsaDismissedKeys.clear();
  const seen = new Set();
  _jsaEndpoints = []; _jsaChecked = {};
  for (const r of reqs) {
    const url = r.url || "";
    const method = (r.method || "GET").toUpperCase();
    if (!url.startsWith("http")) continue;
    const key = method + "::" + url;
    if (seen.has(key)) continue;
    seen.add(key);
    _jsaEndpoints.push({ id: r.id, url, method, headers: { ...(r.headers || {}) }, body: r.body ?? null });
    _jsaChecked[key] = true;
  }
  document.getElementById("jsa-capture-count").textContent = `${_jsaEndpoints.length} endpoints (from AV)`;
  jsaRenderEndpointList();
  jsaUpdateLiveCounts();
}

// Live incremental sync — unlike jsaLoadFromCapture() (manual button, full
// reset) this only APPENDS endpoints not already known, leaving existing
// checked-state untouched, so it's safe to call on a timer.
function jsaSyncFromCapture() {
  const reqs = window._avState?.requests || [];
  if (!reqs.length) return;
  let added = 0;
  for (const r of reqs) {
    const url = r.url || "";
    if (!url.startsWith("http")) continue;
    if (r.id && _jsaDismissedIds.has(r.id)) continue;
    const method = (r.method || "GET").toUpperCase();
    const key = method + "::" + url;
    if (_jsaDismissedKeys.has(key)) continue;
    if (Object.prototype.hasOwnProperty.call(_jsaChecked, key)) continue;
    _jsaEndpoints.push({ id: r.id, url, method, headers: { ...(r.headers || {}) }, body: r.body ?? null });
    // While Start is running: auto-check only filter matches (same as Start).
    // Idle: default checked so manual Run can use them.
    _jsaChecked[key] = _jsaScanRunning
      ? jsaMatchesActiveFilter({ url, method })
      : true;
    added++;
  }
  if (added > 0) {
    document.getElementById("jsa-capture-count").textContent = `${_jsaEndpoints.length} endpoints`;
    jsaRenderEndpointList();
    jsaUpdateLiveCounts();
    // A continuous Start session picks up freshly-synced endpoints immediately
    // rather than waiting for the next sync tick.
    if (_jsaScanRunning) jsaProcessQueue();
  }
}
window.jsaSyncFromCapture = jsaSyncFromCapture;

// ── Continuous-scan helpers ───────────────────────────────────────────────────
// Same "ignore the query string" convention Method Tampering/Soft Delete/IDOR
// already use when deduping captured endpoints — different query values on
// the same path are treated as the same API for scan-once purposes.
function jsaBaseKey(ep) {
  return ep.method + "::" + ep.url.split("?")[0];
}
function jsaMatchesActiveFilter(ep) {
  const u = ep.url.toLowerCase();
  const passInc = !_jsaActiveInclude.length || _jsaActiveInclude.some(t => u.includes(t));
  const passExc = !_jsaActiveExclude.length || !_jsaActiveExclude.some(t => u.includes(t));
  return passInc && passExc;
}
// Merges a new job's findings into the running cumulative set, deduping the
// same way the backend already dedupes within a single job.
function jsaMergeFindings(existing, incoming) {
  const seen = new Set(existing.map(f => `${f.type}||${f.value}||${f.url}||${f.source}`));
  const merged = existing.slice();
  (incoming || []).forEach(f => {
    const key = `${f.type}||${f.value}||${f.url}||${f.source}`;
    if (!seen.has(key)) { seen.add(key); merged.push(f); }
  });
  const sevOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  merged.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
  return merged;
}
function jsaSetStartButtonRunning(running) {
  const startBtn = document.getElementById("jsa-start-btn");
  const abortBtn = document.getElementById("jsa-capture-abort-btn");
  if (startBtn) {
    startBtn.disabled = running;
    startBtn.textContent = running ? "⏳ In Progress" : "🚀 Start";
  }
  if (abortBtn) abortBtn.style.display = running ? "inline-block" : "none";
}
function jsaUpdateLiveCounts() {
  const plain = document.getElementById("jsa-capture-count");
  const live  = document.getElementById("jsa-scan-counts");
  if (!live) return;
  if (!_jsaStartedOnce) { live.style.display = "none"; if (plain) plain.style.display = "inline"; return; }
  if (plain) plain.style.display = "none";
  const total      = _jsaEndpoints.filter(ep => jsaMatchesActiveFilter(ep)).length;
  const inProgress = _jsaEndpoints.filter(ep => ep.status === "queued").length;
  live.style.display = "inline";
  live.textContent = `Total: ${total} · ✅ Scanned: ${_jsaScannedCount} · ⏭ Skipped: ${_jsaSkippedCount} · ⏳ In Progress: ${inProgress}`;
}

// Core continuous loop: claims new filter-matching, non-duplicate, unprocessed
// endpoints and submits them as one batch. Called again automatically once
// that batch finishes (and whenever fresh endpoints arrive via sync), so a
// single Start click keeps going until Abort or there's nothing left to do.
function jsaProcessQueue() {
  if (!_jsaScanRunning || _jsaJobId) return; // already idle, or a batch is already in flight

  const toScan = [];
  for (const ep of _jsaEndpoints) {
    if (ep.status) continue;
    if (!jsaMatchesActiveFilter(ep)) continue;
    // Respect checkboxes — Start auto-selects matches; user can uncheck to skip
    const key = ep.method + "::" + ep.url;
    if (_jsaChecked[key] === false) continue;
    const baseKey = jsaBaseKey(ep);
    if (_jsaScannedPaths.has(baseKey)) {
      ep.status = "duplicate";
      _jsaSkippedCount++;
      continue;
    }
    _jsaScannedPaths.add(baseKey);
    ep.status = "queued";
    toScan.push(ep);
  }

  jsaRenderEndpointList();
  jsaUpdateLiveCounts();
  if (!toScan.length) return; // nothing new right now — next sync tick may bring more

  _jsaCurrentBatch = toScan;
  jsaSwitchTab("scanning");
  _jsaSubmitAndPoll(toScan, jsaOnBatchDone);
}

function jsaOnBatchDone(data) {
  const batch = _jsaCurrentBatch;
  _jsaCurrentBatch = [];
  if (data) {
    batch.forEach(ep => { ep.status = "scanned"; });
    _jsaScannedCount += batch.length;
    _jsaAllFindings = jsaMergeFindings(_jsaAllFindings, data.findings);
    _jsaLastJob = data;
    jsaShowResults(); // moves Results out of its "no results yet" placeholder
  } else {
    // Submission itself failed (e.g. backend unreachable) — release the claim
    // so these get retried on the next pass instead of being stuck forever.
    batch.forEach(ep => { _jsaScannedPaths.delete(jsaBaseKey(ep)); ep.status = undefined; });
  }
  jsaRenderEndpointList();
  jsaUpdateLiveCounts();

  if (_jsaScanRunning) jsaProcessQueue();
  else jsaSetStartButtonRunning(false);
}

// ── cURL import ───────────────────────────────────────────────────────────────
function jsaShowCurlImport() {
  document.getElementById("jsa-curl-modal").style.display = "flex";
  setTimeout(() => document.getElementById("jsa-curl-input")?.focus(), 50);
}
function jsaCloseCurlImport() {
  document.getElementById("jsa-curl-modal").style.display = "none";
}
function jsaConfirmCurlImport() {
  const inp  = document.getElementById("jsa-curl-input");
  const text = (inp.value || "").trim();
  if (!text) return;
  const parsed = _jsaParseCurl(text);
  if (!parsed) { alert("Not a valid cURL command"); return; }
  const key = parsed.method + "::" + parsed.url;
  if (!(key in _jsaChecked)) {
    _jsaEndpoints.push({ url: parsed.url, method: parsed.method, headers: parsed.headers, body: parsed.body });
  }
  _jsaChecked[key] = true;
  document.getElementById("jsa-capture-count").textContent = `${_jsaEndpoints.length} endpoints`;
  jsaRenderEndpointList();
  jsaUpdateLiveCounts();
  inp.value = "";
  jsaCloseCurlImport();
}

// ── Swagger / OpenAPI import ─────────────────────────────────────────────────
let _jsaCurrentBaseUrl = "";
let _jsaDetectedBaseUrl = "";

function _jsaDetectBaseUrlFromSpec(text) {
  if (!text) return "";
  try {
    const data = JSON.parse(text);
    if (data.servers && Array.isArray(data.servers) && data.servers[0]?.url) {
      return data.servers[0].url.trim();
    }
    if (data.host) {
      const scheme = (data.schemes && data.schemes[0]) || "https";
      const bp = (data.basePath && data.basePath !== "/") ? ("/" + data.basePath.replace(/^\/+|\/+$/g, "")) : "";
      return `${scheme}://${data.host.trim()}${bp}`;
    }
  } catch (_) {
    const mUrl = text.match(/^\s*(?:-\s*)?url:\s*['"]?(https?:\/\/[^\s'"]+)['"]?/mi);
    if (mUrl) return mUrl[1].trim();
    const mHost = text.match(/^\s*host:\s*['"]?([^\s'"]+)['"]?/mi);
    if (mHost) return `https://${mHost[1].trim()}`;
  }
  return "";
}

function _jsaUpdateModalDetectedBase(detected) {
  if (!detected) return;
  _jsaDetectedBaseUrl = detected;
  const baseInp = document.getElementById("jsa-swagger-base-url-input");
  const detBadge = document.getElementById("jsa-swagger-detected-base");
  if (baseInp && !baseInp.value) baseInp.value = detected;
  if (detBadge) {
    detBadge.style.display = "inline-block";
    detBadge.textContent = `● Detected: ${detected}`;
  }
}

function jsaOnSwaggerUrlInput(val) {
  val = (val || "").trim();
  if (val.startsWith("http://") || val.startsWith("https://")) {
    try {
      const u = new URL(val);
      _jsaUpdateModalDetectedBase(u.origin);
    } catch (_) {}
  }
}

function jsaOnSwaggerTextInput(val) {
  const detected = _jsaDetectBaseUrlFromSpec(val);
  if (detected) _jsaUpdateModalDetectedBase(detected);
}

function jsaSetupSwaggerInput() {
  const inp = document.getElementById("jsa-swagger-file-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0];
    if (!file) return;
    try {
      const nameEl = document.getElementById("jsa-swagger-file-name");
      if (nameEl) nameEl.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      const text = await file.text();
      const txtInp = document.getElementById("jsa-swagger-text-input");
      if (txtInp) txtInp.value = text;
      const detected = _jsaDetectBaseUrlFromSpec(text);
      if (detected) _jsaUpdateModalDetectedBase(detected);
      const st = document.getElementById("jsa-swagger-status");
      if (st) {
        st.style.display = "block";
        st.style.background = "rgba(63, 185, 80, 0.15)";
        st.style.color = "#3fb950";
        st.textContent = `✓ Loaded ${file.name} (${(file.size / 1024).toFixed(1)} KB)${detected ? ' · Base: ' + detected : ''}`;
      }
    } catch (e) {
      alert("Error reading file: " + e.message);
    }
    inp.value = "";
  };
}

function jsaShowSwaggerImport() {
  const modal = document.getElementById("jsa-swagger-modal");
  if (modal) modal.style.display = "flex";
  const st = document.getElementById("jsa-swagger-status");
  if (st) { st.style.display = "none"; st.textContent = ""; }
  setTimeout(() => document.getElementById("jsa-swagger-url-input")?.focus(), 50);
}

function jsaCloseSwaggerImport() {
  const modal = document.getElementById("jsa-swagger-modal");
  if (modal) modal.style.display = "none";
}

function _jsaGetSwaggerSource() {
  const url = (document.getElementById("jsa-swagger-url-input")?.value || "").trim();
  const text = (document.getElementById("jsa-swagger-text-input")?.value || "").trim();
  const token = (document.getElementById("jsa-swagger-token-input")?.value || "").trim();
  const baseUrl = (document.getElementById("jsa-swagger-base-url-input")?.value || "").trim();
  return { url, text, token, baseUrl };
}

async function jsaRunSwaggerOfflineAudit() {
  const { url, text } = _jsaGetSwaggerSource();
  const st = document.getElementById("jsa-swagger-status");
  const offlineBtn = document.getElementById("jsa-swagger-offline-btn");

  if (!url && !text) {
    if (st) {
      st.style.display = "block";
      st.style.background = "rgba(248, 81, 73, 0.15)";
      st.style.color = "#f85149";
      st.textContent = "Please provide either a Swagger/OpenAPI URL or paste/select spec text.";
    }
    return;
  }

  if (st) {
    st.style.display = "block";
    st.style.background = "rgba(88, 166, 255, 0.15)";
    st.style.color = "#58a6ff";
    st.textContent = "⏳ Auditing Swagger spec for exposed secrets & credentials…";
  }
  if (offlineBtn) offlineBtn.disabled = true;

  try {
    const entropyCb = document.getElementById("jsa-include-entropy-cb");
    const piiCb = document.getElementById("jsa-include-pii-cb");
    const infraCb = document.getElementById("jsa-include-infra-cb");

    const resp = await fetch(`${JSA_BASE}/jsa/scan-text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: text || null,
        spec_url: (!text && url) ? url : null,
        source_name: url ? `Swagger (${url})` : "Swagger Spec",
        enable_entropy: !!(entropyCb && entropyCb.checked),
        include_pii: !!(piiCb && piiCb.checked),
        include_infra: !!(infraCb && infraCb.checked)
      })
    });

    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Audit failed");

    const findings = data.findings || [];
    if (findings.length > 0) {
      _jsaAllFindings = jsaMergeFindings(_jsaAllFindings, findings);
      jsaShowResults();
      jsaSwitchTab("results");
      jsaCloseSwaggerImport();
      if (typeof showToast === "function") {
        showToast(`🔍 Swagger Spec Audit: Found ${findings.length} secret(s)!`, "warning");
      } else {
        alert(`Swagger Spec Audit Complete: Found ${findings.length} secret(s)! Check Results tab.`);
      }
    } else {
      if (st) {
        st.style.display = "block";
        st.style.background = "rgba(63, 185, 80, 0.15)";
        st.style.color = "#3fb950";
        st.textContent = `✓ No secrets or credentials found in this Swagger spec (${data.total || 0} findings).`;
      }
    }
  } catch (err) {
    if (st) {
      st.style.display = "block";
      st.style.background = "rgba(248, 81, 73, 0.15)";
      st.style.color = "#f85149";
      st.textContent = "Error: " + err.message;
    }
  } finally {
    if (offlineBtn) offlineBtn.disabled = false;
  }
}

function jsaParseAuthHeadersInput(raw) {
  raw = (raw || "").trim();
  if (!raw) return { token: null, headers: {} };

  const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length === 1 && !lines[0].includes(":") && !lines[0].toLowerCase().startsWith("authorization")) {
    return { token: lines[0], headers: {} };
  }

  const headers = {};
  let token = null;
  const hasColons = lines.some(l => l.includes(":") && !l.startsWith(":"));

  if (hasColons) {
    for (const line of lines) {
      if (line.startsWith(":")) continue; // Skip HTTP/2 pseudo headers
      const ci = line.indexOf(":");
      if (ci > 0) {
        const k = line.slice(0, ci).trim();
        const v = line.slice(ci + 1).trim();
        if (k.toLowerCase() === "authorization") {
          token = v;
        } else {
          headers[k] = v;
        }
      }
    }
  } else {
    // Alternating key / value lines copied directly from Chrome/Brave DevTools Network table
    for (let i = 0; i < lines.length; i++) {
      const key = lines[i];
      if (key.startsWith(":")) {
        i++; // skip pseudo-header and its value
        continue;
      }
      const val = lines[i + 1] || "";
      i++;
      if (key.toLowerCase() === "authorization") {
        token = val;
      } else {
        headers[key] = val;
      }
    }
  }

  return { token, headers };
}

async function jsaConfirmSwaggerLiveImport() {
  const { url, text, token, baseUrl } = _jsaGetSwaggerSource();
  const st = document.getElementById("jsa-swagger-status");
  const liveBtn = document.getElementById("jsa-swagger-live-btn");

  if (!url && !text) {
    if (st) {
      st.style.display = "block";
      st.style.background = "rgba(248, 81, 73, 0.15)";
      st.style.color = "#f85149";
      st.textContent = "Please provide either a Swagger/OpenAPI URL or paste/select spec text.";
    }
    return;
  }

  if (st) {
    st.style.display = "block";
    st.style.background = "rgba(88, 166, 255, 0.15)";
    st.style.color = "#58a6ff";
    st.textContent = "⏳ Parsing Swagger/OpenAPI spec and extracting endpoints…";
  }
  if (liveBtn) liveBtn.disabled = true;

  try {
    const { token: finalAuthToken, headers: extraHeaders } = jsaParseAuthHeadersInput(token);

    const resp = await fetch(`${JSA_BASE}/jsa/parse-swagger`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        spec_url: url || null,
        spec_text: text || null,
        auth_token: finalAuthToken || null,
        headers: extraHeaders,
        base_url: baseUrl || null
      })
    });

    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Failed to parse Swagger spec");

    const endpoints = data.endpoints || [];
    if (!endpoints.length) {
      throw new Error("No usable API endpoints found in this Swagger/OpenAPI specification.");
    }

    const effectiveBase = (baseUrl || data.effective_base_url || data.detected_base_url || "").trim().replace(/\/+$/, "");
    _jsaCurrentBaseUrl = effectiveBase;
    _jsaDetectedBaseUrl = (data.detected_base_url || "").trim().replace(/\/+$/, "");

    const mainBaseInp = document.getElementById("jsa-base-url-input");
    if (mainBaseInp && effectiveBase) {
      mainBaseInp.value = effectiveBase;
    }

    let addedCount = 0;
    endpoints.forEach(ep => {
      let finalUrl = ep.url;
      if (effectiveBase) {
        const normPath = ep.path.startsWith("/") ? ep.path : "/" + ep.path;
        if (_jsaDetectedBaseUrl && ep.url.startsWith(_jsaDetectedBaseUrl)) {
          finalUrl = effectiveBase + ep.url.slice(_jsaDetectedBaseUrl.length);
        } else if (!ep.url.startsWith("http://") && !ep.url.startsWith("https://")) {
          finalUrl = effectiveBase + normPath;
        }
      }
      finalUrl = finalUrl.replace(/\{[^\}]+\}/g, "1");

      const mUpper = (ep.method || "GET").toUpperCase();
      const epHeaders = { ...(ep.headers || {}) };
      let epBody = ep.body;
      if (["POST", "PUT", "PATCH"].includes(mUpper)) {
        if (!Object.keys(epHeaders).some(k => k.toLowerCase() === "content-type")) {
          epHeaders["Content-Type"] = "application/json";
        }
        if (epBody === null || epBody === undefined) {
          epBody = "{}";
        }
      }

      const key = mUpper + "::" + finalUrl;
      if (!(key in _jsaChecked)) {
        _jsaEndpoints.push({
          url: finalUrl,
          originalUrl: ep.url,
          path: ep.path || "",
          method: mUpper,
          headers: epHeaders,
          body: epBody,
          summary: ep.summary || "",
          source: "swagger"
        });
        _jsaChecked[key] = true;
        addedCount++;
      }
    });

    document.getElementById("jsa-capture-count").textContent = `${_jsaEndpoints.length} endpoints`;
    jsaRenderEndpointList();
    jsaUpdateLiveCounts();
    jsaCloseSwaggerImport();
    jsaSwitchTab("capture");

    if (typeof showToast === "function") {
      showToast(`📄 Imported ${addedCount} endpoints with Base URL: ${effectiveBase || 'default'} (${_jsaEndpoints.length} total)`, "success");
    } else {
      alert(`Imported ${addedCount} endpoints from ${data.title || 'Swagger'} (total: ${_jsaEndpoints.length}).`);
    }
  } catch (err) {
    if (st) {
      st.style.display = "block";
      st.style.background = "rgba(248, 81, 73, 0.15)";
      st.style.color = "#f85149";
      st.textContent = "Error: " + err.message;
    }
  } finally {
    if (liveBtn) liveBtn.disabled = false;
  }
}

// ── Base URL Toolbar Updater ──────────────────────────────────────────────────
function jsaApplyBaseUrl(customBase) {
  const inp = document.getElementById("jsa-base-url-input");
  const raw = customBase !== undefined ? customBase : (inp ? inp.value : "");
  const newBase = (raw || "").trim().replace(/\/+$/, "");

  if (!newBase) {
    if (typeof showToast === "function") showToast("Please enter a valid Base URL (e.g. https://qa.visionwaves.com)", "warn");
    else alert("Please enter a valid Base URL.");
    return;
  }

  if (!_jsaEndpoints.length) {
    _jsaCurrentBaseUrl = newBase;
    if (inp) inp.value = newBase;
    if (typeof showToast === "function") showToast(`Base URL set to ${newBase}`, "info");
    return;
  }

  // Detect current base / origin across loaded endpoints
  let currentOrigin = _jsaCurrentBaseUrl || _jsaDetectedBaseUrl || "";
  if (!currentOrigin) {
    for (const ep of _jsaEndpoints) {
      const uStr = ep.originalUrl || ep.url || "";
      if (uStr.startsWith("http://") || uStr.startsWith("https://")) {
        try {
          const u = new URL(uStr);
          currentOrigin = u.origin;
          break;
        } catch (_) {}
      }
    }
  }

  const oldChecked = { ..._jsaChecked };
  _jsaChecked = {};
  let count = 0;

  _jsaEndpoints.forEach(ep => {
    if (!ep.originalUrl) ep.originalUrl = ep.url;
    const oldUrl = ep.url;
    let path = ep.path || "";
    if (!path) {
      try {
        const u = new URL(ep.originalUrl || ep.url);
        path = u.pathname + u.search;
      } catch (_) {
        path = ep.url.replace(/^https?:\/\/[^\/]+/, "");
      }
    }

    let updatedUrl = newBase + (path.startsWith("/") ? path : "/" + path);
    if (currentOrigin && (ep.originalUrl || ep.url).startsWith(currentOrigin)) {
      const remainder = (ep.originalUrl || ep.url).slice(currentOrigin.length);
      updatedUrl = newBase + (remainder.startsWith("/") ? remainder : "/" + remainder);
    }
    updatedUrl = updatedUrl.replace(/\{[^\}]+\}/g, "1");

    ep.url = updatedUrl;
    count++;

    const oldKey = (ep.method || "GET").toUpperCase() + "::" + oldUrl;
    const isChecked = oldKey in oldChecked ? oldChecked[oldKey] : true;
    const newKey = (ep.method || "GET").toUpperCase() + "::" + updatedUrl;
    _jsaChecked[newKey] = isChecked;
  });

  _jsaCurrentBaseUrl = newBase;
  if (inp) inp.value = newBase;

  const swgBaseInp = document.getElementById("jsa-swagger-base-url-input");
  if (swgBaseInp) swgBaseInp.value = newBase;

  jsaRenderEndpointList();
  jsaUpdateLiveCounts();

  if (typeof showToast === "function") {
    showToast(`🌐 Updated Base URL to ${newBase} for ${count} endpoint(s)!`, "success");
  } else {
    alert(`Updated Base URL to ${newBase} for ${count} endpoint(s).`);
  }
}

// ── Start (filter live capture by URL, auto-select matches, run now) ─────────
function jsaShowStartModal() {
  document.getElementById("jsa-start-error").style.display = "none";
  document.getElementById("jsa-start-modal").style.display = "flex";
  setTimeout(() => document.getElementById("jsa-start-include")?.focus(), 50);
}
function jsaCloseStartModal() {
  document.getElementById("jsa-start-modal").style.display = "none";
}
function jsaConfirmStart() {
  const errEl = document.getElementById("jsa-start-error");
  // Pull the freshest capture first, so Start never works off a stale list.
  jsaSyncFromCapture();

  if (!_jsaEndpoints.length) {
    errEl.textContent = "No captured or imported endpoints yet.";
    errEl.style.display = "block";
    return;
  }

  const inc = document.getElementById("jsa-start-include").value.trim();
  const exc = document.getElementById("jsa-start-exclude").value.trim();
  _jsaActiveInclude = inc ? inc.split(",").map(s => s.trim().toLowerCase()).filter(Boolean) : [];
  _jsaActiveExclude = exc ? exc.split(",").map(s => s.trim().toLowerCase()).filter(Boolean) : [];

  if (!_jsaEndpoints.some(ep => jsaMatchesActiveFilter(ep))) {
    errEl.textContent = "No endpoints matched that filter.";
    errEl.style.display = "block";
    return;
  }

  errEl.style.display = "none";
  jsaCloseStartModal();

  // Align checkboxes with Start filters (matches modal: auto-select matches).
  // Non-matching rows are unchecked so the list shows exactly what will scan.
  _jsaEndpoints.forEach(ep => {
    _jsaChecked[ep.method + "::" + ep.url] = jsaMatchesActiveFilter(ep);
  });
  jsaRenderEndpointList();

  // Continuous mode: keeps auto-scanning checked + filter-matching, not-yet-seen
  // endpoints as they arrive from live capture sync, until Abort. Doesn't reset
  // already-scanned/duplicate status — only Reset clears that — so clicking
  // Start again (e.g. after Abort) resumes where it left off.
  _jsaScanRunning = true;
  _jsaStartedOnce = true;
  jsaSetStartButtonRunning(true);
  jsaUpdateLiveCounts();
  jsaProcessQueue();
}

// Minimal self-contained cURL parser — just enough to extract method/url/headers/body.
function _jsaParseCurl(text) {
  const s = text.trim().replace(/\\\r?\n/g, " ");
  if (!/^curl\b/i.test(s)) return null;

  const tokens = [];
  let i = 0;
  while (i < s.length) {
    while (s[i] === " ") i++;
    if (i >= s.length) break;
    if (s[i] === "'" || s[i] === '"') {
      const q = s[i]; let val = ""; i++;
      while (i < s.length && s[i] !== q) val += s[i++];
      i++; tokens.push(val);
    } else {
      let val = "";
      while (i < s.length && s[i] !== " ") val += s[i++];
      tokens.push(val);
    }
  }

  const SKIP = new Set(["-k","--insecure","--compressed","-s","--silent","-L","--location","-v","--verbose"]);
  let method = null, url = null, body = null;
  const headers = {};
  for (let j = 0; j < tokens.length; j++) {
    const t = tokens[j];
    if (j === 0) continue;
    if (SKIP.has(t)) continue;
    if (t === "-X" || t === "--request") { method = (tokens[++j] || "").toUpperCase(); continue; }
    if (t === "-H" || t === "--header") {
      const h = tokens[++j] || ""; const ci = h.indexOf(":");
      if (ci > 0) headers[h.slice(0, ci).trim()] = h.slice(ci + 1).trim();
      continue;
    }
    if (t === "-d" || t === "--data" || t === "--data-raw" || t === "--data-binary") { body = tokens[++j] || ""; continue; }
    if (!t.startsWith("-") && !url) { url = t; continue; }
  }
  if (!url) return null;
  if (!method) method = body ? "POST" : "GET";
  let parsedBody = body;
  if (body) { try { parsedBody = JSON.parse(body); } catch(e) {} }
  return { method, url, headers, body: parsedBody };
}

// ── Endpoint list rendering ───────────────────────────────────────────────────
function jsaRenderEndpointList() {
  const list  = document.getElementById("jsa-endpoint-list");
  const empty = document.getElementById("jsa-endpoint-empty");
  const filter = _jsaFilterText.toLowerCase();

  if (!_jsaEndpoints.length) {
    list.style.display = "none"; empty.style.display = "flex"; return;
  }
  list.style.display = "flex"; empty.style.display = "none";

  const bInp = document.getElementById("jsa-base-url-input");
  if (bInp && !bInp.value && _jsaEndpoints.length > 0) {
    for (const ep of _jsaEndpoints) {
      const uStr = ep.originalUrl || ep.url || "";
      if (uStr.startsWith("http://") || uStr.startsWith("https://")) {
        try {
          const u = new URL(uStr);
          bInp.value = u.origin;
          _jsaCurrentBaseUrl = u.origin;
          break;
        } catch (_) {}
      }
    }
  }

  const filtered = filter
    ? _jsaEndpoints.filter(ep => ep.url.toLowerCase().includes(filter))
    : _jsaEndpoints;

  const MC = {GET:"#3fb950",POST:"#ffa657",PUT:"#d29922",PATCH:"#a5d6ff",DELETE:"#f85149"};
  const TAGS = {
    scanned:   `<span class="jsa-ep-tag jsa-ep-tag-scanned">✅ Scanned</span>`,
    duplicate: `<span class="jsa-ep-tag jsa-ep-tag-dup">⏭ Skipped</span>`,
    queued:    `<span class="jsa-ep-tag jsa-ep-tag-queued">⏳ Scanning</span>`,
  };

  list.innerHTML = filtered.map(ep => {
    const key = ep.method + "::" + ep.url;
    const checked = _jsaChecked[key] !== false;
    const mc = MC[ep.method] || "#8b949e";
    const tag = TAGS[ep.status] || "";
    return `
      <div class="mt-ep-row ${checked ? "mt-ep-checked" : ""}" onclick="jsaToggleEp('${key.replace(/'/g,"\\'")}', this)">
        <input type="checkbox" class="mt-ep-cb" ${checked ? "checked" : ""}
               onclick="event.stopPropagation(); jsaToggleEp('${key.replace(/'/g,"\\'")}', this.closest('.mt-ep-row'))">
        <span class="mt-ep-method" style="color:${mc};background:${mc}22;border:1px solid ${mc}55">${ep.method}</span>
        <span class="mt-ep-url" title="${jsaEsc(ep.url)}">${jsaEsc(ep.url)}</span>
        ${tag}
      </div>`;
  }).join("");

  const sel = Object.values(_jsaChecked).filter(Boolean).length;
  const btn = document.getElementById("jsa-run-btn");
  if (btn) btn.textContent = `🚀 Run JS & Secret Analyser (${sel} selected)`;
}

function jsaToggleEp(key, row) {
  _jsaChecked[key] = !_jsaChecked[key];
  row.classList.toggle("mt-ep-checked", _jsaChecked[key]);
  const cb = row.querySelector(".mt-ep-cb"); if (cb) cb.checked = _jsaChecked[key];
  const sel = Object.values(_jsaChecked).filter(Boolean).length;
  const btn = document.getElementById("jsa-run-btn");
  if (btn) btn.textContent = `🚀 Run JS & Secret Analyser (${sel} selected)`;
}
function jsaSelectAll() {
  const filter = _jsaFilterText.toLowerCase();
  const targets = filter ? _jsaEndpoints.filter(ep => ep.url.toLowerCase().includes(filter)) : _jsaEndpoints;
  targets.forEach(ep => { _jsaChecked[ep.method + "::" + ep.url] = true; });
  jsaRenderEndpointList();
}
function jsaDeselectAll() {
  const filter = _jsaFilterText.toLowerCase();
  const targets = filter ? _jsaEndpoints.filter(ep => ep.url.toLowerCase().includes(filter)) : _jsaEndpoints;
  targets.forEach(ep => { _jsaChecked[ep.method + "::" + ep.url] = false; });
  jsaRenderEndpointList();
}
function jsaFilterCapture() {
  _jsaFilterText = document.getElementById("jsa-url-filter-input").value;
  jsaRenderEndpointList();
}

// ── Run scan ──────────────────────────────────────────────────────────────────
async function jsaRunSelected() {
  if (_jsaJobId) { alert("A scan is already running. Wait for it to finish, or Abort first."); return; }
  let selected = _jsaEndpoints.filter(ep => _jsaChecked[ep.method + "::" + ep.url]);
  if (!selected.length) { alert("Select at least one endpoint."); return; }

  const useRecorded = !!document.getElementById("jsa-recorded-cb")?.checked;
  if (useRecorded) {
    const withRec = selected.filter(ep => ep.has_recorded);
    if (!withRec.length) {
      alert("Analyse Recorded Result is on, but none of the selected endpoints have a HAR recorded response.\n\nImport a HAR (not just cURL / AV), or uncheck the box for a live scan.");
      return;
    }
    if (withRec.length < selected.length) {
      const skipped = selected.length - withRec.length;
      if (!confirm(`${skipped} selected endpoint(s) have no recorded response and will be skipped.\n\nContinue with ${withRec.length} recorded endpoint(s)?`)) {
        return;
      }
      selected = withRec;
    }
  }

  const btn = document.getElementById("jsa-run-btn");
  btn.disabled = true; btn.textContent = "⏳ Starting...";
  jsaSwitchTab("scanning");

  _jsaSubmitAndPoll(selected, (data) => {
    if (data) {
      // Counts as "scanned" for the continuous flow's dedup too, so Start
      // won't redo work already covered by a manual run.
      selected.forEach(ep => { ep.status = "scanned"; _jsaScannedPaths.add(jsaBaseKey(ep)); });
      _jsaScannedCount += selected.length;
      _jsaAllFindings = jsaMergeFindings(_jsaAllFindings, data.findings);
      _jsaLastJob = data;
      jsaRenderEndpointList();
      jsaUpdateLiveCounts();
      jsaSwitchTab("results");
      jsaShowResults();
    } else {
      alert("Is the JS Analyser backend running (port 8792)?");
    }
    btn.disabled = false;
    const sel = Object.values(_jsaChecked).filter(Boolean).length;
    btn.textContent = `🚀 Run JS & Secret Analyser (${sel} selected)`;
  }, { use_recorded: useRecorded });
}

// ── Scanning / polling ────────────────────────────────────────────────────────
// Shared by both the manual "Run JS & Secret Analyser" button and the continuous
// "Start" loop — submits one batch, polls it to completion, then hands the
// final job data (or null on failure) to the caller-supplied callback.
// opts.use_recorded: when true, backend scans HAR-stored responses (no live hit).
// Continuous Start always passes false / omits this (live only).
async function _jsaSubmitAndPoll(endpoints, onDone, opts = {}) {
  const epoch = _jsaEpoch;
  const useRecorded = !!opts.use_recorded;
  try {
    const piiCb = document.getElementById("jsa-include-pii-cb");
    const infraCb = document.getElementById("jsa-include-infra-cb");
    const entropyCb = document.getElementById("jsa-include-entropy-cb");
    const resp = await fetch(`${JSA_BASE}/jsa/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoints: endpoints.map(ep => {
          const row = {
            url: ep.url,
            method: ep.method,
            headers: ep.headers || {},
            body: ep.body,
          };
          if (useRecorded) {
            row.recorded_status = ep.recorded_status ?? null;
            row.recorded_body = ep.recorded_body ?? "";
            row.recorded_headers = ep.recorded_headers || {};
          }
          return row;
        }),
        include_pii: !!(piiCb && piiCb.checked),
        include_infra: !!(infraCb && infraCb.checked),
        enable_entropy: !!(entropyCb && entropyCb.checked),
        use_recorded: useRecorded,
      }),
    });
    const data = await resp.json();
    if (epoch !== _jsaEpoch) return;
    if (!resp.ok) throw new Error(data.detail || "Scan start failed");
    _jsaJobId = data.job_id;
    jsaAppendTerminalLog(`[BATCH START] Replaying & Scanning batch of ${endpoints.length} endpoint(s)... (Job ID: ${_jsaJobId})`, "replay");

    // Note: the log list itself is deliberately NOT cleared here — each new
    // batch's job starts its own logs array from zero on the backend, but the
    // DOM list keeps every prior batch's rows so the feed reads as one
    // continuous scan history. Only Reset clears it.
    document.getElementById("jsa-scan-fill").style.width = "0%";
    document.getElementById("jsa-scan-stats").textContent = `0 / ${data.total} endpoints`;
    document.getElementById("jsa-abort-btn").style.display = "inline-block";
    document.getElementById("jsa-abort-btn").disabled = false;
    _jsaLogRendered = 0; // resets per-batch — tracks position within THIS job's own logs array

    _jsaPollTimer = setInterval(async () => {
      if (epoch !== _jsaEpoch) {
        clearInterval(_jsaPollTimer);
        _jsaPollTimer = null;
        return;
      }
      const jobId = _jsaJobId;
      if (!jobId) {
        clearInterval(_jsaPollTimer);
        _jsaPollTimer = null;
        return;
      }
      try {
        const r2 = await fetch(`${JSA_BASE}/jsa/progress/${jobId}`);
        const d2 = await r2.json();
        if (epoch !== _jsaEpoch) return;
        if (!r2.ok) { clearInterval(_jsaPollTimer); _jsaPollTimer = null; return; }

        document.getElementById("jsa-scan-fill").style.width = d2.progress + "%";
        document.getElementById("jsa-scan-stats").textContent =
          `${d2.completed} / ${d2.total} endpoints · ${d2.findings.length} finding(s) · ${d2.elapsed}s`;
        jsaAppendScanLogs(d2.logs);

        if (d2.status === "done" || d2.status === "aborted") {
          clearInterval(_jsaPollTimer);
          _jsaPollTimer = null;
          if (epoch !== _jsaEpoch) return;
          _jsaJobId = null;
          document.getElementById("jsa-abort-btn").style.display = "none";
          jsaAppendTerminalLog(`[BATCH FINISHED] Status: ${d2.status.toUpperCase()} · Completed: ${d2.completed}/${d2.total} endpoints · Findings: ${d2.findings.length}`, "info");
          onDone(d2);
        }
      } catch(e) {}
    }, 800);
  } catch(e) {
    if (epoch !== _jsaEpoch) return;
    _jsaJobId = null;
    jsaAppendTerminalLog(`[ERROR] Batch submission failed: ${e.message}`, "warn");
    onDone(null);
  }
}

// Appends only the NEW log entries since the last poll, rather than re-rendering
// the whole feed every tick — keeps it cheap even with hundreds of endpoints.
function jsaAppendScanLogs(logs) {
  if (!logs || logs.length <= _jsaLogRendered) return;
  const list = document.getElementById("jsa-scan-log-list");
  const newEntries = logs.slice(_jsaLogRendered);
  const startIdx = _jsaScanLogs.length;
  _jsaScanLogs.push(...newEntries);

  newEntries.forEach(l => {
    const cat = (l.findings > 0) ? "secret" : (l.error ? "warn" : "replay");
    const summary = `${l.method || 'GET'} ${l.url} -> ${l.status || 'ERR'} | Findings: ${l.findings || 0}`;
    jsaAppendTerminalLog(summary, cat);
  });

  const html = newEntries.map((l, i) => jsaRenderLogRow(l, startIdx + i)).join("");
  list.insertAdjacentHTML("beforeend", html);
  _jsaLogRendered = logs.length;
}

function jsaRenderLogRow(l, idx) {
  const ok = !l.error && l.status != null && l.status >= 200 && l.status < 400;
  const statusColor = l.error ? "#f85149" : (ok ? "#3fb950" : "#d29922");
  const statusLabel = l.error ? "ERR" : (l.status != null ? l.status : "…");
  const findColor = l.findings > 0 ? "#e3b341" : "var(--text3)";
  return `<div class="jsa-scan-log-entry">
    <div class="jsa-scan-log-row" onclick="jsaToggleLogDetail(${idx})">
      <span class="jsa-scan-log-status" style="color:${statusColor}">${statusLabel}</span>
      <span class="jsa-scan-log-method">${jsaEsc(l.method || "GET")}</span>
      <span class="jsa-scan-log-url" title="${jsaEsc(l.url)}">${jsaEsc(l.url)}</span>
      <span class="jsa-scan-log-findings" style="color:${findColor}">${l.findings > 0 ? `🔑 ${l.findings}` : "—"}</span>
    </div>
    <div class="jsa-scan-log-detail" id="jsa-log-detail-${idx}" style="display:none"></div>
  </div>`;
}

// Click a scan log row to expand it into Request / Response panels — lets
// the user manually eyeball exactly what was sent and what came back.
function jsaToggleLogDetail(idx) {
  const detail = document.getElementById(`jsa-log-detail-${idx}`);
  if (!detail) return;
  if (detail.style.display !== "none") { detail.style.display = "none"; return; }
  const l = _jsaScanLogs[idx];
  if (!l) return;
  detail.innerHTML = jsaRenderLogDetailHtml(l, idx);
  detail.style.display = "block";
}

// Raw (unescaped) text behind each rendered <pre> in an expanded log row,
// keyed by the pre's element id — lets search/copy work off the real text
// instead of re-parsing HTML-escaped innerHTML.
const _jsaPreRaw = {};

function jsaRenderLogDetailHtml(l, idx) {
  const reqHeaders = Object.entries(l.req_headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)";
  const reqBody = l.req_body
    ? (typeof l.req_body === "string" ? l.req_body : JSON.stringify(l.req_body, null, 2))
    : "";
  const respColor = l.error || !(l.status >= 200 && l.status < 400) ? "#f85149" : "#3fb950";
  const respLabel = l.error ? "Error" : String(l.status);
  const respBody = l.error ? `Error: ${l.error}` : (l.resp_body || "(empty)");

  const reqHeadId = `jsa-pre-reqh-${idx}`;
  const reqBodyId = `jsa-pre-reqb-${idx}`;
  const respId = `jsa-pre-resp-${idx}`;
  _jsaPreRaw[reqHeadId] = reqHeaders;
  _jsaPreRaw[reqBodyId] = reqBody;
  _jsaPreRaw[respId] = respBody;

  const truncNote = (typeof respBody === "string" && /\[truncated/.test(respBody))
    ? `<div class="jsa-log-trunc-note">Body truncated for display — search uses the stored window (finding value kept when possible).</div>`
    : "";

  const tools = (panelId) => `
    <div class="jsa-log-detail-tools">
      <input type="text" class="jsa-log-detail-search" placeholder="🔍 Search in panel…"
             onclick="event.stopPropagation()"
             onkeydown="jsaDetailSearchKeydown('${panelId}', event)"
             oninput="jsaFilterDetailPanel('${panelId}', this.value)">
      <span class="jsa-log-detail-matches" id="${panelId}-matches"></span>
      <button type="button" class="jsa-log-detail-copy" onclick="event.stopPropagation(); jsaCopyDetailPanel('${panelId}', this)">📋 Copy</button>
    </div>`;

  return `
    <div class="jsa-log-detail-grid">
      <div class="jsa-log-detail-panel" id="jsa-req-panel-${idx}">
        <div class="jsa-log-detail-head">
          <div class="jsa-log-detail-label">📤 Request</div>
          ${tools(`jsa-req-panel-${idx}`)}
        </div>
        <pre class="jsa-log-detail-pre" id="${reqHeadId}">${jsaEsc(reqHeaders)}</pre>
        ${reqBody ? `<div class="jsa-log-detail-sec">Body</div><pre class="jsa-log-detail-pre" id="${reqBodyId}">${jsaEsc(reqBody)}</pre>` : ""}
      </div>
      <div class="jsa-log-detail-panel" id="jsa-resp-panel-${idx}">
        <div class="jsa-log-detail-head">
          <div class="jsa-log-detail-label" style="color:${respColor}">📥 Response · ${jsaEsc(respLabel)}</div>
          ${tools(`jsa-resp-panel-${idx}`)}
        </div>
        ${truncNote}
        <pre class="jsa-log-detail-pre" id="${respId}">${jsaEsc(respBody)}</pre>
      </div>
    </div>`;
}

/** Per-panel search cursor: Enter / Shift+Enter cycles matches. */
const _jsaDetailSearch = {};

/** Build a RegExp for panel search; falls back to phone/whitespace-flexible. */
function jsaBuildSearchRegex(query) {
  const q = (query || "").trim();
  if (!q) return null;
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [esc(q)];
  if (/\s/.test(q)) {
    patterns.push(q.trim().split(/\s+/).map(esc).join("\\s+"));
    patterns.push(esc(q.replace(/\s+/g, "")));
  }
  const digits = q.replace(/\D/g, "");
  if (digits.length >= 7) {
    patterns.push("\\+?" + digits.split("").map(esc).join("[\\s\\-().]*"));
  }
  // Dedupe while preserving order
  const uniq = [...new Set(patterns)];
  try { return new RegExp(uniq.join("|"), "gi"); }
  catch (_) {
    try { return new RegExp(esc(q), "gi"); }
    catch (_2) { return null; }
  }
}

/** Build highlighted HTML from raw text (escape-safe; caps matches). */
function jsaHighlightRaw(raw, query) {
  const text = String(raw ?? "");
  const q = (query || "").trim();
  if (!q) return { html: jsaEsc(text), hits: 0 };
  const re = jsaBuildSearchRegex(q);
  if (!re) return { html: jsaEsc(text), hits: 0 };

  const maxHits = 200;
  let out = "", last = 0, hits = 0, m;
  while ((m = re.exec(text)) !== null) {
    out += jsaEsc(text.slice(last, m.index));
    out += `<mark class="jsa-log-search-hit">${jsaEsc(m[0])}</mark>`;
    last = m.index + m[0].length;
    hits++;
    if (m[0].length === 0) re.lastIndex++; // guard zero-width matches
    if (hits >= maxHits) break;
  }
  out += jsaEsc(text.slice(last));
  return { html: out, hits };
}

function jsaScrollToDetailHit(mark) {
  if (!mark) return;
  const pre = mark.closest(".jsa-log-detail-pre");
  if (!pre) return;
  const preRect = pre.getBoundingClientRect();
  const hitRect = mark.getBoundingClientRect();
  pre.scrollTop += (hitRect.top - preRect.top) - pre.clientHeight * 0.25;
}

function jsaUpdateDetailMatchBadge(panelId) {
  const panel = document.getElementById(panelId);
  const badge = document.getElementById(`${panelId}-matches`);
  const st = _jsaDetailSearch[panelId];
  if (!badge || !st) return;
  if (!st.query) {
    badge.textContent = "";
    badge.classList.remove("jsa-log-detail-matches-empty");
    return;
  }
  if (!st.total) {
    badge.textContent = "no match";
    badge.classList.add("jsa-log-detail-matches-empty");
    return;
  }
  badge.textContent = `${st.idx + 1} / ${st.total}`;
  badge.classList.remove("jsa-log-detail-matches-empty");
  if (panel) {
    panel.querySelectorAll(".jsa-log-search-hit").forEach((m, i) => {
      m.classList.toggle("jsa-log-search-cur", i === st.idx);
    });
  }
}

function jsaFocusDetailMatch(panelId, doScroll) {
  const panel = document.getElementById(panelId);
  const st = _jsaDetailSearch[panelId];
  if (!panel || !st || !st.total) {
    jsaUpdateDetailMatchBadge(panelId);
    return;
  }
  const marks = panel.querySelectorAll(".jsa-log-search-hit");
  if (!marks.length) return;
  st.idx = ((st.idx % marks.length) + marks.length) % marks.length;
  jsaUpdateDetailMatchBadge(panelId);
  if (doScroll !== false) jsaScrollToDetailHit(marks[st.idx]);
}

function jsaDetailSearchStep(panelId, dir) {
  const st = _jsaDetailSearch[panelId];
  if (!st || !st.total) return;
  st.idx = (st.idx + dir + st.total) % st.total;
  jsaFocusDetailMatch(panelId, true);
}

function jsaDetailSearchKeydown(panelId, e) {
  e.stopPropagation();
  if (e.key === "Enter") {
    e.preventDefault();
    const st = _jsaDetailSearch[panelId];
    if (st && st.total) jsaDetailSearchStep(panelId, e.shiftKey ? -1 : 1);
    else {
      const inp = e.target;
      jsaFilterDetailPanel(panelId, inp && inp.value);
    }
  }
}

// Highlights matches of `query` inside every <pre> within the given panel —
// scoped per-panel so Request/Response each search independently.
function jsaFilterDetailPanel(panelId, query) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const q = (query || "").trim();
  let totalHits = 0;

  panel.querySelectorAll(".jsa-log-detail-pre").forEach(pre => {
    const raw = _jsaPreRaw[pre.id] != null ? _jsaPreRaw[pre.id] : (pre.textContent || "");
    const { html, hits } = jsaHighlightRaw(raw, q);
    pre.innerHTML = html;
    totalHits += hits;
  });

  _jsaDetailSearch[panelId] = { query: q, idx: 0, total: totalHits };
  jsaFocusDetailMatch(panelId, true);
}

async function jsaCopyDetailPanel(panelId, btn) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const parts = [];
  panel.querySelectorAll(".jsa-log-detail-pre").forEach(pre => {
    parts.push(_jsaPreRaw[pre.id] != null ? _jsaPreRaw[pre.id] : pre.textContent);
  });
  try {
    await navigator.clipboard.writeText(parts.join("\n\n"));
    const original = btn.textContent;
    btn.textContent = "✅ Copied";
    setTimeout(() => { btn.textContent = original; }, 1200);
  } catch (e) {}
}

// ── Abort ─────────────────────────────────────────────────────────────────────
async function jsaAbortScan() {
  // Stops the continuous Start loop immediately — no further batches will be
  // queued once the current one (if any) finishes or is aborted below.
  _jsaScanRunning = false;

  if (!_jsaJobId) {
    // Nothing in flight (e.g. between batches) — just flip the UI back now.
    jsaSetStartButtonRunning(false);
    return;
  }
  const btns = [document.getElementById("jsa-abort-btn"), document.getElementById("jsa-capture-abort-btn")]
    .filter(Boolean);
  btns.forEach(b => { b.disabled = true; b.textContent = "⏳ Aborting..."; });
  try {
    await fetch(`${JSA_BASE}/jsa/abort/${_jsaJobId}`, { method: "POST" });
  } catch(e) {}
  // jsaOnBatchDone() picks up the "aborted" status on its own and, seeing
  // _jsaScanRunning is now false, calls jsaSetStartButtonRunning(false) —
  // just restore the button labels here in case the job had already finished.
  setTimeout(() => { btns.forEach(b => { b.disabled = false; b.textContent = "⏹ Abort"; }); }, 1500);
}

// ── Results ───────────────────────────────────────────────────────────────────
function jsaShowResults() {
  document.getElementById("jsa-results-wrap").style.display = "flex";
  document.getElementById("jsa-results-empty").style.display = "none";
  jsaRefreshTypeFilter();
  jsaApplyFilters();
}

/** Populate Type dropdown from current findings; keep selection if still valid. */
function jsaRefreshTypeFilter() {
  const sel = document.getElementById("jsa-type-filter");
  if (!sel) return;
  const prev = sel.value;
  const types = [...new Set(_jsaAllFindings.map(f => f.type).filter(Boolean))].sort(
    (a, b) => a.localeCompare(b)
  );
  sel.innerHTML = `<option value="">All Types</option>` +
    types.map(t => `<option value="${jsaEscAttr(t)}">${jsaEsc(t)}</option>`).join("");
  sel.value = types.includes(prev) ? prev : "";
}

function jsaEscAttr(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}

function jsaApplyFilters() {
  const q    = _jsaTableFilterText.toLowerCase();
  const type = document.getElementById("jsa-type-filter")?.value || "";
  const sev  = document.getElementById("jsa-sev-filter").value;
  const src  = document.getElementById("jsa-src-filter").value;
  let rows = _jsaAllFindings;
  if (type) rows = rows.filter(f => f.type === type);
  if (sev) rows = rows.filter(f => f.severity === sev);
  if (src) rows = rows.filter(f => f.source === src);
  if (q) rows = rows.filter(f =>
    f.type.toLowerCase().includes(q) || f.value.toLowerCase().includes(q) ||
    (f.host||"").toLowerCase().includes(q) || f.url.toLowerCase().includes(q));
  jsaRenderTable(rows);
}
function jsaFilterTable() {
  _jsaTableFilterText = document.getElementById("jsa-filter-input").value;
  jsaApplyFilters();
}

function jsaRenderTable(rows) {
  _jsaVisibleRows = rows;
  const tbody = document.getElementById("jsa-results-tbody");
  if (!rows.length) { tbody.innerHTML = `<tr><td colspan="6" class="mt-empty-row">No findings.</td></tr>`; return; }

  const SC = {HIGH:"#f85149",MEDIUM:"#d29922",LOW:"#58a6ff"};
  tbody.innerHTML = rows.map((f, i) => {
    const sevColor = SC[f.severity] || "#8b949e";
    const srcColor = f.source === "Request" ? "#3fb950" : "#1f9d8a";
    return `
      <tr class="jsa-result-row" onclick="jsaToggleResultDetail(${i})"
          oncontextmenu="jsaShowCtxMenu(event, ${i}); return false;" style="cursor:pointer">
        <td><span class="jsa-sev-badge" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${f.severity}</span></td>
        <td class="jsa-td-type">${jsaEsc(f.type)}</td>
        <td class="jsa-td-value" title="${jsaEsc(f.value)}">${jsaEsc(f.value)}</td>
        <td><span class="jsa-src-badge" style="background:${srcColor}22;color:${srcColor};border:1px solid ${srcColor}55">${f.source}</span></td>
        <td class="jsa-td-host">${jsaEsc(f.host||"")}</td>
        <td class="jsa-td-url" title="${jsaEsc(f.url)}">${jsaEsc(f.url)}</td>
      </tr>
      <tr class="jsa-result-detail-row" id="jsa-result-detail-${i}" style="display:none">
        <td colspan="6" class="jsa-result-detail-cell"></td>
      </tr>`;
  }).join("");
}

/** Request/response context for a finding — backend fields, else scan log / capture. */
function jsaResolveFindingContext(f) {
  if (!f) return null;
  if (f.req_headers || f.resp_body != null || f.req_body != null) {
    return {
      url: f.url,
      method: f.method || "GET",
      req_headers: f.req_headers || {},
      req_body: f.req_body,
      resp_body: f.resp_body || "",
      status: f.status,
      error: f.error || null,
    };
  }
  for (let i = _jsaScanLogs.length - 1; i >= 0; i--) {
    const l = _jsaScanLogs[i];
    if (l && l.url === f.url) return l;
  }
  const ep = _jsaEndpoints.find(e => e.url === f.url);
  if (ep) {
    return {
      url: ep.url,
      method: ep.method || "GET",
      req_headers: ep.headers || {},
      req_body: ep.body,
      resp_body: "(response not stored — expand after a fresh scan for full body)",
      status: null,
      error: null,
    };
  }
  return {
    url: f.url, method: "GET", req_headers: {}, req_body: "",
    resp_body: "(no request data available)", status: null, error: null,
  };
}

function jsaBuildCurlFromCtx(ctx) {
  if (!ctx) return "";
  const method = (ctx.method || "GET").toUpperCase();
  const url = ctx.url || "";
  const q = s => String(s).replace(/'/g, `'\\''`);
  let c = method === "GET" ? `curl '${q(url)}'` : `curl -X ${method} '${q(url)}'`;
  for (const [k, v] of Object.entries(ctx.req_headers || {})) {
    if (/^(content-length|host|connection|transfer-encoding)$/i.test(k)) continue;
    c += ` \\\n  -H '${q(k)}: ${q(v)}'`;
  }
  if (ctx.req_body != null && ctx.req_body !== "" && ["POST", "PUT", "PATCH"].includes(method)) {
    const b = typeof ctx.req_body === "string" ? ctx.req_body : JSON.stringify(ctx.req_body);
    if (b && b !== "null") c += ` \\\n  --data-raw '${q(b)}'`;
  }
  return c;
}

function jsaToggleResultDetail(idx) {
  const row = document.getElementById(`jsa-result-detail-${idx}`);
  if (!row) return;
  const isOpen = row.style.display !== "none";
  document.querySelectorAll(".jsa-result-detail-row").forEach(r => { r.style.display = "none"; });
  document.querySelectorAll("#jsa-results-tbody .jsa-result-row").forEach(r => r.classList.remove("jsa-row-selected"));
  if (isOpen) return;

  const f = _jsaVisibleRows[idx];
  if (!f) return;
  const ctx = jsaResolveFindingContext(f);
  const cell = row.querySelector("td");
  const detailId = `res${idx}`;
  cell.innerHTML = `
    <div class="jsa-result-detail-bar">
      <span class="jsa-result-detail-meta">${jsaEsc((ctx.method || "GET").toUpperCase())} · ${jsaEsc(f.source)} · ${jsaEsc(f.type)}</span>
      <button type="button" class="btn-sm as-rd-curl-btn"
              onclick="event.stopPropagation(); jsaCopyFindingCurl(${idx}, this)"
              title="Copy this request as cURL">📋 Copy cURL</button>
    </div>
    ${jsaRenderLogDetailHtml(ctx, detailId)}`;
  row.style.display = "table-row";
  row.previousElementSibling?.classList.add("jsa-row-selected");

  // Auto-highlight the finding value in Request/Response so the hit is visible
  // without guessing the right search term (e.g. type "IBAN Exposed" ≠ body text).
  const needle = (f.value || "").trim();
  if (needle) {
    const reqPid = `jsa-req-panel-${detailId}`;
    const respPid = `jsa-resp-panel-${detailId}`;
    const reqInp = document.querySelector(`#${reqPid} .jsa-log-detail-search`);
    const respInp = document.querySelector(`#${respPid} .jsa-log-detail-search`);
    if (respInp) { respInp.value = needle; jsaFilterDetailPanel(respPid, needle); }
    if (reqInp)  { reqInp.value = needle;  jsaFilterDetailPanel(reqPid, needle); }
  }
}

function jsaCopyFindingCurl(idx, btn) {
  const f = _jsaVisibleRows[idx];
  if (!f) return;
  const curl = jsaBuildCurlFromCtx(jsaResolveFindingContext(f));
  if (!curl) return;
  const orig = btn ? btn.textContent : "";
  const done = () => {
    if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
  };
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(curl).then(done).catch(() => { jsaCopy(curl); done(); });
  } else {
    jsaCopy(curl);
    done();
  }
}

// ── Right-click context menu ──────────────────────────────────────────────────
function jsaShowCtxMenu(e, idx) {
  _jsaCtxFinding = _jsaVisibleRows[idx];
  const menu = document.getElementById("jsa-ctx-menu");
  if (!menu) return;
  menu.style.display = "block";
  const mw = menu.offsetWidth || 180, mh = menu.offsetHeight || 220;
  menu.style.left = Math.min(e.pageX, window.innerWidth  - mw - 8) + "px";
  menu.style.top  = Math.min(e.pageY, window.innerHeight - mh - 8) + "px";
}
function jsaHideCtxMenu() {
  const menu = document.getElementById("jsa-ctx-menu");
  if (menu) menu.style.display = "none";
}
document.addEventListener("click", jsaHideCtxMenu);
document.addEventListener("scroll", jsaHideCtxMenu, true);

function jsaCopy(text) {
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
  };
  if (navigator.clipboard) navigator.clipboard.writeText(text).catch(fallback);
  else fallback();
}
function jsaCtxCopyValue()    { if (_jsaCtxFinding) jsaCopy(_jsaCtxFinding.value); jsaHideCtxMenu(); }
function jsaCtxCopyUrl()      { if (_jsaCtxFinding) jsaCopy(_jsaCtxFinding.url);   jsaHideCtxMenu(); }
function jsaCtxCopyValueUrl() { if (_jsaCtxFinding) jsaCopy(`${_jsaCtxFinding.value}\n${_jsaCtxFinding.url}`); jsaHideCtxMenu(); }
function jsaCtxCopyRow() {
  if (!_jsaCtxFinding) return;
  const f = _jsaCtxFinding;
  jsaCopy([f.severity, f.type, f.value, f.source, f.host || "", f.url].join("\t"));
  jsaHideCtxMenu();
}
function jsaCtxCopyCurl() {
  if (!_jsaCtxFinding) return;
  const curl = jsaBuildCurlFromCtx(jsaResolveFindingContext(_jsaCtxFinding));
  if (curl) jsaCopy(curl);
  jsaHideCtxMenu();
}


// ── Export HTML ───────────────────────────────────────────────────────────────
async function jsaDownloadHtml() {
  const findings = _jsaAllFindings || [];
  if (!findings.length) return;
  const html = jsaGenerateHtml(findings, _jsaLastJob);
  const ts = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
  if (window.pywebview?.api?.save_file) {
    await window.pywebview.api.save_file(html, `js_analyser_${ts}.html`);
  } else {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }));
    a.download = `js_analyser_${ts}.html`; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }
}

function jsaFmtExportBody(v) {
  if (v == null || v === "") return "";
  return typeof v === "string" ? v : JSON.stringify(v, null, 2);
}

function jsaHighlightExport(text, needle) {
  const raw = String(text ?? "");
  if (!raw) return "";
  const n = (needle || "").trim();
  if (!n || n.length > 500) return jsaEsc(raw);
  const lower = raw.toLowerCase();
  const nLower = n.toLowerCase();
  let out = "", last = 0, hits = 0, idx;
  while (hits < 80 && (idx = lower.indexOf(nLower, last)) !== -1) {
    out += jsaEsc(raw.slice(last, idx));
    out += `<mark>${jsaEsc(raw.slice(idx, idx + n.length))}</mark>`;
    last = idx + n.length;
    hits++;
  }
  return out + jsaEsc(raw.slice(last));
}

function jsaGenerateHtml(findings, job) {
  const ts = new Date().toLocaleString();
  const SC = { HIGH: "#f85149", MEDIUM: "#d29922", LOW: "#58a6ff" };
  const sevBadge = s => {
    const c = SC[s] || "#8b949e";
    return `<span class="sev" style="background:${c}22;color:${c};border:1px solid ${c}55">${jsaEsc(s || "")}</span>`;
  };
  const srcBadge = s => {
    const c = s === "Request" ? "#3fb950" : "#1f9d8a";
    return `<span class="src" style="background:${c}22;color:${c};border:1px solid ${c}55">${jsaEsc(s || "")}</span>`;
  };
  const high = findings.filter(f => f.severity === "HIGH").length;
  const med  = findings.filter(f => f.severity === "MEDIUM").length;
  const low  = findings.filter(f => f.severity === "LOW").length;
  const endpointsScanned = _jsaScannedPaths.size
    || _jsaScannedCount
    || (job && job.total)
    || 0;
  const detailHtml = (f) => {
    const ctx = jsaResolveFindingContext(f) || {};
    const method = (ctx.method || f.method || "GET").toUpperCase();
    const reqHeaders = Object.entries(ctx.req_headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)";
    const reqBody = jsaFmtExportBody(ctx.req_body) || "(empty)";
    const respColor = ctx.error || !(ctx.status >= 200 && ctx.status < 400) ? "#f85149" : "#3fb950";
    const respLabel = ctx.error ? "Error" : (ctx.status != null ? String(ctx.status) : "—");
    const respBody = ctx.error ? `Error: ${ctx.error}` : (jsaFmtExportBody(ctx.resp_body) || "(empty)");
    const needle = (f.value || "").trim();
    return `
      <div class="detail-meta">${sevBadge(f.severity)} ${srcBadge(f.source)} · ${jsaEsc(method)} · ${jsaEsc(f.type)}</div>
      <div class="dl">
        <div><div class="k">Value</div><div class="v gold">${jsaEsc(f.value)}</div></div>
        <div><div class="k">URL</div><div class="v blue">${jsaEsc(f.url)}</div></div>
      </div>
      <div class="panels">
        <div class="panel">
          <div class="panel-label">Request</div>
          <div class="sec">Headers</div>
          <pre>${jsaHighlightExport(reqHeaders, needle)}</pre>
          <div class="sec">Request Body</div>
          <pre>${jsaHighlightExport(reqBody, needle)}</pre>
        </div>
        <div class="panel">
          <div class="panel-label" style="color:${respColor}">Response · ${jsaEsc(respLabel)}</div>
          <div class="sec">Response Body</div>
          <pre>${jsaHighlightExport(respBody, needle)}</pre>
        </div>
      </div>`;
  };
  const rows = findings.map((f, i) => `<tr class="row" id="r${i}" onclick="toggle(${i})">
      <td>${sevBadge(f.severity)}</td>
      <td class="td-type" title="${jsaEsc(f.type)}">${jsaEsc(f.type)}</td>
      <td class="td-value" title="${jsaEsc(f.value)}">${jsaEsc(f.value)}</td>
      <td>${srcBadge(f.source)}</td>
      <td class="td-host" title="${jsaEsc(f.host || "")}">${jsaEsc(f.host || "")}</td>
      <td class="td-url" title="${jsaEsc(f.url)}">${jsaEsc(f.url)}</td>
    </tr>
    <tr class="detail" id="d${i}">
      <td colspan="6">${detailHtml(f)}</td>
    </tr>`).join("");
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JS &amp; Secret Analyser Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{width:100%;overflow-x:hidden}
  body{font-family:Inter,-apple-system,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
  h1{font-size:20px;font-weight:800;background:linear-gradient(135deg,#a371f7,#79c0ff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .meta{color:#8b949e;font-size:11px;font-family:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;margin-top:6px}
  .cards{display:flex;gap:8px;margin:16px 0;flex-wrap:wrap}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:8px 16px;text-align:center;min-width:80px}
  .card h3{font-size:20px;font-weight:800;margin-bottom:2px;line-height:1.1}
  .card p{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
  .card.red h3{color:#f85149}.card.orange h3{color:#d29922}.card.blue h3{color:#58a6ff}
  .wrap{background:#0d1117;border:1px solid #30363d;border-radius:8px;overflow:hidden;width:100%}
  table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:12px}
  th:nth-child(1){width:9%}th:nth-child(2){width:17%}th:nth-child(3){width:27%}
  th:nth-child(4){width:9%}th:nth-child(5){width:14%}th:nth-child(6){width:24%}
  th{padding:8px 10px;text-align:left;background:#161b22;border-bottom:1px solid #30363d;
     color:#3fb950;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;
     white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  td{padding:7px 10px;border-bottom:1px solid #30363d;vertical-align:middle;overflow:hidden;max-width:0}
  tr.row{cursor:pointer}
  tr.row:hover td,tr.row.selected td{background:#161b22}
  tr.detail{display:none}
  tr.detail.open{display:table-row}
  tr.detail td{max-width:none;overflow:visible;white-space:normal;vertical-align:top;
    padding:12px 14px 16px;background:#010409;border-bottom:1px solid #30363d}
  .detail-meta{font-size:11px;font-weight:600;color:#8b949e;margin-bottom:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .dl{display:grid;gap:10px}
  .dl .k{font-size:10px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
  .dl .v{word-break:break-all;white-space:pre-wrap;line-height:1.45;font-size:12px;color:#c9d1d9}
  .dl .v.gold{font-family:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;color:#e3b341}
  .dl .v.blue{font-family:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#79c0ff}
  .sev,.src{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.02em;white-space:nowrap}
  .td-type{color:#ffffff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .td-value{font-family:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;color:#e3b341;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .td-host{color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .td-url{font-family:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#79c0ff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .panels{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px}
  .panel{min-width:0;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 12px}
  .panel-label{font-size:11px;font-weight:700;color:#c9d1d9;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px}
  .sec{font-size:10px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin:8px 0 4px}
  .panel pre{margin:0;height:220px;overflow:auto;background:#161b22;border:1px solid #30363d;border-radius:6px;
    padding:8px 10px;font-size:11px;font-family:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;
    color:#c9d1d9;white-space:pre-wrap;word-break:break-word}
  mark{background:#e3b34155;color:#e3b341;padding:0 2px;border-radius:2px}
  @media(max-width:900px){.panels{grid-template-columns:1fr}}
</style>
</head><body>
<h1>JS &amp; Secret Analyser Report</h1>
<p class="meta">Generated: ${jsaEsc(ts)} · Endpoints scanned: ${endpointsScanned} · Findings: ${findings.length}</p>
<div class="cards">
  <div class="card red"><h3>${high}</h3><p>HIGH</p></div>
  <div class="card orange"><h3>${med}</h3><p>MEDIUM</p></div>
  <div class="card blue"><h3>${low}</h3><p>LOW</p></div>
</div>
<div class="wrap">
<table>
  <thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Source</th><th>Host</th><th>URL</th></tr></thead>
  <tbody>${rows || `<tr><td colspan="6" style="text-align:center;color:#8b949e;padding:24px">No findings.</td></tr>`}</tbody>
</table>
</div>
<script>
function toggle(i){
  var d=document.getElementById('d'+i), r=document.getElementById('r'+i);
  if(!d) return;
  var open=d.classList.contains('open');
  document.querySelectorAll('tr.detail').forEach(function(el){el.classList.remove('open')});
  document.querySelectorAll('tr.row').forEach(function(el){el.classList.remove('selected')});
  if(!open){ d.classList.add('open'); if(r) r.classList.add('selected'); }
}
</script>
</body></html>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function jsaEsc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function jsaRememberDismissed(id, method, url) {
  if (id) _jsaDismissedIds.add(id);
  if (url) _jsaDismissedKeys.add((method || "GET").toUpperCase() + "::" + url);
}

function jsaReset() {
  // Invalidate any in-flight scan POST / progress poll before clearing state,
  // otherwise the next 800ms tick silently puts findings and endpoints back.
  _jsaEpoch++;
  clearInterval(_jsaPollTimer);
  _jsaPollTimer = null;
  const jobToAbort = _jsaJobId;
  _jsaJobId = null;
  if (jobToAbort) fetch(`${JSA_BASE}/jsa/abort/${jobToAbort}`, { method: "POST" }).catch(() => {});

  // Hide current JSA rows AND the whole current AV buffer from auto-sync.
  // Same APIs recaptured under a new id (live browsing) stay hidden too.
  _jsaEndpoints.forEach(ep => jsaRememberDismissed(ep.id, ep.method, ep.url));
  (window._avState?.requests || []).forEach(r => jsaRememberDismissed(r.id, r.method, r.url));

  _jsaEndpoints = []; _jsaChecked = {};
  _jsaAllFindings = []; _jsaVisibleRows = []; _jsaLastJob = null;
  _jsaFilterText = ""; _jsaTableFilterText = ""; _jsaLogRendered = 0; _jsaScanLogs = [];
  _jsaScanRunning = false; _jsaStartedOnce = false;
  _jsaActiveInclude = []; _jsaActiveExclude = [];
  _jsaScannedPaths.clear(); _jsaScannedCount = 0; _jsaSkippedCount = 0; _jsaCurrentBatch = [];
  _jsaPendingHar = null; _jsaCtxFinding = null;

  const cc = document.getElementById("jsa-capture-count"); if (cc) { cc.textContent = "0 endpoints"; cc.style.display = "inline"; }
  const lc = document.getElementById("jsa-scan-counts"); if (lc) lc.style.display = "none";
  const fi = document.getElementById("jsa-url-filter-input"); if (fi) fi.value = "";
  const list = document.getElementById("jsa-endpoint-list");
  if (list) { list.innerHTML = ""; list.style.display = "none"; }
  const empty = document.getElementById("jsa-endpoint-empty"); if (empty) empty.style.display = "flex";
  const wrap = document.getElementById("jsa-results-wrap"); if (wrap) wrap.style.display = "none";
  const re = document.getElementById("jsa-results-empty"); if (re) re.style.display = "flex";
  const tbody = document.getElementById("jsa-results-tbody"); if (tbody) tbody.innerHTML = "";
  const logList = document.getElementById("jsa-scan-log-list"); if (logList) logList.innerHTML = "";
  const fill = document.getElementById("jsa-scan-fill"); if (fill) fill.style.width = "0%";
  const stats = document.getElementById("jsa-scan-stats"); if (stats) stats.textContent = "0 / 0 endpoints";
  const abortBtn = document.getElementById("jsa-abort-btn");
  if (abortBtn) { abortBtn.style.display = "none"; abortBtn.disabled = false; abortBtn.textContent = "⏹ Abort"; }
  const capAbort = document.getElementById("jsa-capture-abort-btn");
  if (capAbort) { capAbort.disabled = false; capAbort.textContent = "⏹ Abort"; }
  const tf = document.getElementById("jsa-filter-input"); if (tf) tf.value = "";
  const typ = document.getElementById("jsa-type-filter");
  if (typ) { typ.innerHTML = `<option value="">All Types</option>`; typ.value = ""; }
  const sev = document.getElementById("jsa-sev-filter"); if (sev) sev.value = "";
  const src = document.getElementById("jsa-src-filter"); if (src) src.value = "";
  const btn = document.getElementById("jsa-run-btn");
  if (btn) { btn.disabled = false; btn.textContent = "🚀 Run JS & Secret Analyser (0 selected)"; }
  const harInp = document.getElementById("jsa-har-file-input"); if (harInp) harInp.value = "";
  const recCb = document.getElementById("jsa-recorded-cb"); if (recCb) recCb.checked = false;
  jsaOnRecordedToggle();
  const curlModal = document.getElementById("jsa-curl-modal"); if (curlModal) curlModal.style.display = "none";
  const startModal = document.getElementById("jsa-start-modal"); if (startModal) startModal.style.display = "none";
  const tokenModal = document.getElementById("jsa-har-token-modal"); if (tokenModal) tokenModal.style.display = "none";
  const swgModal = document.getElementById("jsa-swagger-modal"); if (swgModal) swgModal.style.display = "none";
  const swgUrl = document.getElementById("jsa-swagger-url-input"); if (swgUrl) swgUrl.value = "";
  const swgTxt = document.getElementById("jsa-swagger-text-input"); if (swgTxt) swgTxt.value = "";
  const swgTok = document.getElementById("jsa-swagger-token-input"); if (swgTok) swgTok.value = "";
  const swgBase = document.getElementById("jsa-swagger-base-url-input"); if (swgBase) swgBase.value = "";
  const detBase = document.getElementById("jsa-swagger-detected-base"); if (detBase) { detBase.style.display = "none"; detBase.textContent = ""; }
  const mainBase = document.getElementById("jsa-base-url-input"); if (mainBase) mainBase.value = "";
  _jsaCurrentBaseUrl = "";
  _jsaDetectedBaseUrl = "";
  const swgFile = document.getElementById("jsa-swagger-file-input"); if (swgFile) swgFile.value = "";
  const swgName = document.getElementById("jsa-swagger-file-name"); if (swgName) swgName.textContent = "No file selected";
  const swgSt = document.getElementById("jsa-swagger-status"); if (swgSt) { swgSt.style.display = "none"; swgSt.textContent = ""; }
  const ctxMenu = document.getElementById("jsa-ctx-menu"); if (ctxMenu) ctxMenu.style.display = "none";
  jsaSetStartButtonRunning(false);
  jsaSwitchTab("capture");
}
window.jsaReset = jsaReset;
window.jsaShowSwaggerImport = jsaShowSwaggerImport;
window.jsaCloseSwaggerImport = jsaCloseSwaggerImport;
window.jsaRunSwaggerOfflineAudit = jsaRunSwaggerOfflineAudit;
window.jsaConfirmSwaggerLiveImport = jsaConfirmSwaggerLiveImport;
window.jsaApplyBaseUrl = jsaApplyBaseUrl;
window.jsaOnSwaggerUrlInput = jsaOnSwaggerUrlInput;
window.jsaOnSwaggerTextInput = jsaOnSwaggerTextInput;
window.jsaSwitchTerminalMode = jsaSwitchTerminalMode;
window.jsaClearTerminalLogs = jsaClearTerminalLogs;
window.jsaCopyTerminalLogs = jsaCopyTerminalLogs;
window.jsaCheckEngineStatus = jsaCheckEngineStatus;
window.jsaRunEngineInstall = jsaRunEngineInstall;
window.jsaRunEngineUpdate = jsaRunEngineUpdate;

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  jsaSetupHarInput();
  jsaSetupSwaggerInput();
  jsaCheckEngineStatus(false);
  // Keep the capture list live while this tab is open — same gating pattern
  // Auth Validator already uses for its own AV-capture polling.
  setInterval(() => {
    if (window._activeTool === "jsa") jsaSyncFromCapture();
  }, 2000);
});
