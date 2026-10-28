/* ── Params Tamper — Parameter Tampering Tester ──────────────────────────── */
"use strict";

const PT_BACKEND = "http://127.0.0.1:8772";

function $pt(id) { return document.getElementById("pt-" + id); }

// ── State ─────────────────────────────────────────────────────────────────────
let _ptCurl          = "";
let _ptParams        = [];      // [{source, name, value}]
let _ptChecked       = new Set(); // "source::name"
let _ptRandomFormats = {};        // {name: format_string}  — params to randomize per-request
let _ptJobId         = null;
let _ptFindings      = [];
let _ptPollTimer     = null;
let _ptFilterRisk    = "all";
let _ptInited        = false;
let _ptAvRequests    = [];   // cache for AV modal
let _ptScanning      = false;
let _ptLastPollDone  = -1;
let _ptDetailFinding = null;
let _ptCtxFinding    = null;
let _ptPreRaw        = {};
let _ptDetailSearch  = {};

// ── HTML escape ───────────────────────────────────────────────────────────────
function _ptEsc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Init ──────────────────────────────────────────────────────────────────────
function ptInit() {
  if (_ptInited) return;
  _ptInited = true;

  const parseBtn   = $pt("btn-parse");
  const fromAvBtn  = $pt("btn-from-av");
  const clearBtn   = $pt("btn-clear-curl");
  const selAllBtn  = $pt("btn-sel-all");
  const deselBtn   = $pt("btn-desel-all");
  const runBtn     = $pt("btn-run");

  if (parseBtn)  parseBtn.addEventListener("click",  ptParseCurl);
  if (fromAvBtn) fromAvBtn.addEventListener("click", ptFromAV);
  if (clearBtn)  clearBtn.addEventListener("click",  ptClearCurl);
  if (selAllBtn) selAllBtn.addEventListener("click", ptSelectAll);
  if (deselBtn)  deselBtn.addEventListener("click",  ptDeselectAll);
  if (runBtn)    runBtn.addEventListener("click",    ptRunScan);

  // Allow Enter in curl textarea to not submit but parse on Ctrl+Enter
  const ta = $pt("curl-input");
  if (ta) {
    ta.addEventListener("keydown", e => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") ptParseCurl();
    });
  }

  // Include Header toggle — show/hide header params without re-parsing
  const includeHdr = $pt("opt-include-header");
  if (includeHdr) includeHdr.addEventListener("change", ptOnIncludeHeaderToggle);

  const paramSearch = $pt("param-search");
  if (paramSearch) paramSearch.addEventListener("input", ptOnParamSearchInput);

  // AV modal search
  const avSearch = $pt("av-search");
  if (avSearch) avSearch.addEventListener("input", ptFilterAvModal);

}

// ── Tab switching ─────────────────────────────────────────────────────────────
function ptGoTab(tab) {
  const capture = $pt("pane-capture");
  const results = $pt("pane-results");
  const tabCapt = $pt("tab-capture");
  const tabRes  = $pt("tab-results");

  if (capture) capture.style.display = tab === "capture" ? "" : "none";
  if (results) results.style.display = tab === "results" ? "" : "none";

  if (tabCapt) tabCapt.classList.toggle("active", tab === "capture");
  if (tabRes)  tabRes.classList.toggle("active",  tab === "results");
}

// ── Parse cURL ────────────────────────────────────────────────────────────────
async function ptParseCurl() {
  if (_ptScanning) {
    ptShowParseError("Scan in progress — Abort first to parse a new cURL.");
    return;
  }
  const ta = $pt("curl-input");
  if (!ta) return;
  const curl = ta.value.trim();
  if (!curl) {
    ptShowParseError("Paste a cURL command first.");
    return;
  }
  ptClearParseError();
  _ptCurl = curl;

  try {
    const resp = await fetch(`${PT_BACKEND}/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ curl }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      ptShowParseError(data.detail || "Parse failed");
      return;
    }

    _ptParams        = data.params || [];
    // Default: only body / query / nested selected — headers off unless Include Header
    _ptChecked = new Set(
      _ptParams
        .filter(p => p.source !== "header")
        .map(p => `${p.source}::${p.name}`)
    );
    _ptBaselineOk    = false;   // new parse → reset baseline state
    _ptRandomFormats = {};
    ptClearBaselineResult();
    const runBtnReset = $pt("btn-run");
    if (runBtnReset) runBtnReset.textContent = "🚀 Start Scan";

    // Show endpoint info (visible count respects Include Header)
    ptUpdateEndpointInfo(data.method, data.endpoint);

    // Render param list
    ptRenderParamList();

    // Show/hide baseline button: not needed for GET (read-only, no unique-value risk)
    const baselineWrap = $pt("baseline-wrap");
    if (baselineWrap) {
      baselineWrap.style.display = data.method === "GET" ? "none" : "";
    }

    // Show sections
    const ps = $pt("params-section");
    if (ps) ps.style.display = "";
    const rb = $pt("run-bar");
    if (rb) rb.style.display = "";

    ptUpdateRunLabel();
  } catch (err) {
    ptShowParseError("Network error: " + err.message);
  }
}

function ptShowParseError(msg) {
  const el = $pt("parse-error");
  if (el) { el.textContent = msg; el.style.display = ""; }
}
function ptClearParseError() {
  const el = $pt("parse-error");
  if (el) { el.textContent = ""; el.style.display = "none"; }
}

function ptClearBaselineResult() {
  const res = $pt("baseline-result");
  if (res) { res.textContent = ""; res.style.display = "none"; }
  const warn = document.getElementById("pt-baseline-warn");
  if (warn) warn.style.display = "none";
}

/** Clear cURL input and the Parameters Detected panel (keeps Results). */
function ptClearCurl() {
  if (_ptScanning) {
    alert("Scan in progress — Abort first before clearing.");
    return;
  }
  const ta = $pt("curl-input");
  if (ta) ta.value = "";

  _ptCurl          = "";
  _ptParams        = [];
  _ptChecked       = new Set();
  _ptBaselineOk    = false;
  _ptRandomFormats = {};
  ptClearBaselineResult();
  ptClearParseError();

  const search = $pt("param-search");
  if (search) search.value = "";

  const psList = $pt("params-list");
  if (psList) psList.innerHTML = "";

  const ps = $pt("params-section");
  if (ps) ps.style.display = "none";

  const rb = $pt("run-bar");
  if (rb) rb.style.display = "none";

  const badge = $pt("param-count-badge");
  if (badge) { badge.textContent = "0"; badge.style.display = "none"; }

  const epInfo = $pt("endpoint-info");
  if (epInfo) epInfo.textContent = "";

  const baselineWrap = $pt("baseline-wrap");
  if (baselineWrap) baselineWrap.style.display = "none";

  ptUpdateRunLabel();
}

function _ptIncludeHeaders() {
  return !!$pt("opt-include-header")?.checked;
}

function _ptParamSearchQuery() {
  return ($pt("param-search")?.value || "").trim().toLowerCase();
}

function _ptParamsByHeaderFilter() {
  if (_ptIncludeHeaders()) return _ptParams.slice();
  return _ptParams.filter(p => p.source !== "header");
}

function _ptVisibleParams() {
  let list = _ptParamsByHeaderFilter();
  const q = _ptParamSearchQuery();
  if (q) {
    list = list.filter(p => {
      const name = String(p.name ?? "").toLowerCase();
      const val  = String(p.value ?? "").toLowerCase();
      return name.includes(q) || val.includes(q);
    });
  }
  return list;
}

function ptUpdateEndpointInfo(method, endpoint) {
  const epInfo = $pt("endpoint-info");
  if (!epInfo) return;
  const vis = _ptParamsByHeaderFilter().length;
  const total = _ptParams.length;
  const hdrN = _ptParams.filter(p => p.source === "header").length;
  const m = method || _ptBaselineMethod || "";
  const ep = endpoint || "";
  let msg = `${m}  ${ep}  ·  ${vis} param(s) detected`.trim();
  if (!_ptIncludeHeaders() && hdrN > 0) {
    msg += `  (${hdrN} header hidden)`;
  } else if (vis !== total) {
    msg += `  / ${total} total`;
  }
  const q = _ptParamSearchQuery();
  if (q) {
    msg += `  ·  showing ${_ptVisibleParams().length} match`;
  }
  epInfo.textContent = msg;
}

function ptOnIncludeHeaderToggle() {
  if (!_ptIncludeHeaders()) {
    // Drop header selections when hiding
    [..._ptChecked].forEach(key => {
      if (key.startsWith("header::")) _ptChecked.delete(key);
    });
  }
  ptRenderParamList();
  ptUpdateEndpointInfo();
  ptUpdateRunLabel();
}

// Keep endpoint "showing N match" in sync while typing search
function ptOnParamSearchInput() {
  ptRenderParamList();
  ptUpdateEndpointInfo();
}

// ── Render param list ─────────────────────────────────────────────────────────
function ptRenderParamList() {
  const list = $pt("params-list");
  if (!list) return;
  list.innerHTML = "";

  const visible = _ptVisibleParams();

  visible.forEach(p => {
    const key        = `${p.source}::${p.name}`;
    const checked    = _ptChecked.has(key);
    const isRandom   = p.name in _ptRandomFormats;
    const fmtVal     = _ptRandomFormats[p.name] || _ptDefaultFmt(p.name, String(p.value ?? ""));

    const srcClass = p.source === "query"
      ? "pt-src-query"
      : p.source === "header"
        ? "pt-src-header"
        : (p.source === "body_nested" ? "pt-src-body-nested" : "pt-src-body");
    const srcLabel = p.source === "body_nested" ? "nested" : p.source;

    const row = document.createElement("div");
    row.className = "pt-param-row" + (isRandom ? " pt-param-row-rand" : "");
    row.innerHTML = `
      <input type="checkbox" data-key="${_ptEsc(key)}" ${checked ? "checked" : ""}>
      <span class="pt-src-badge ${srcClass}">${_ptEsc(srcLabel)}</span>
      <span class="pt-param-name" title="${_ptEsc(p.name)}">${_ptEsc(p.name)}</span>
      <span class="pt-param-val">${_ptEsc(String(p.value ?? "").substring(0, 50))}</span>
      <button class="pt-rand-btn${isRandom ? " pt-rand-active" : ""}" title="Randomize this param on every request (prevents duplicate/uniqueness errors)"
              data-pname="${_ptEsc(p.name)}">🎲</button>
      <span class="pt-rand-fmt-wrap" style="${isRandom ? "" : "display:none"}">
        <input class="pt-rand-fmt-input" data-pname="${_ptEsc(p.name)}"
               value="${_ptEsc(fmtVal)}"
               placeholder="{alphanum:8}"
               title="Format: {alphanum:N}, {alpha:N}, {num:N}, {uuid}, {email}, {name}">
        <span class="pt-rand-fmt-label">per request</span>
      </span>
    `;

    // Checkbox
    const cb = row.querySelector("input[type=checkbox]");
    cb.addEventListener("change", () => {
      if (cb.checked) _ptChecked.add(key);
      else            _ptChecked.delete(key);
      ptUpdateRunLabel();
    });

    // 🎲 toggle
    const randBtn = row.querySelector(".pt-rand-btn");
    randBtn.addEventListener("click", e => {
      e.stopPropagation();
      const name    = randBtn.dataset.pname;
      const fmtWrap = row.querySelector(".pt-rand-fmt-wrap");
      if (name in _ptRandomFormats) {
        delete _ptRandomFormats[name];
        randBtn.classList.remove("pt-rand-active");
        row.classList.remove("pt-param-row-rand");
        if (fmtWrap) fmtWrap.style.display = "none";
      } else {
        const fmt = row.querySelector(".pt-rand-fmt-input")?.value.trim()
                    || _ptDefaultFmt(name, String(p.value ?? ""));
        _ptRandomFormats[name] = fmt;
        randBtn.classList.add("pt-rand-active");
        row.classList.add("pt-param-row-rand");
        if (fmtWrap) fmtWrap.style.display = "";
      }
      ptUpdateRunLabel();
    });

    // Format input — live update the state
    const fmtInput = row.querySelector(".pt-rand-fmt-input");
    if (fmtInput) {
      fmtInput.addEventListener("input", () => {
        const name = fmtInput.dataset.pname;
        if (name in _ptRandomFormats) {
          _ptRandomFormats[name] = fmtInput.value.trim() || _ptDefaultFmt(name, "");
        }
      });
    }

    list.appendChild(row);
  });

  // Count badge = visible (search-filtered) params
  const badge = $pt("param-count-badge");
  if (badge) badge.textContent = visible.length;

  if (visible.length === 0 && _ptParams.length > 0) {
    const empty = document.createElement("div");
    empty.className = "pt-param-empty";
    empty.style.cssText = "padding:14px;text-align:center;color:var(--text3);font-size:11px";
    empty.textContent = _ptParamSearchQuery()
      ? "No parameters match this search."
      : "No parameters to show.";
    list.appendChild(empty);
  }
}

// ── Select / deselect all ─────────────────────────────────────────────────────
function ptSelectAll() {
  const visible = _ptVisibleParams();
  visible.forEach(p => _ptChecked.add(`${p.source}::${p.name}`));
  const list = $pt("params-list");
  if (list) list.querySelectorAll("input[type=checkbox]").forEach(cb => cb.checked = true);
  ptUpdateRunLabel();
}

function ptDeselectAll() {
  const visible = _ptVisibleParams();
  // With an active search, only uncheck the filtered rows
  if (_ptParamSearchQuery()) {
    visible.forEach(p => _ptChecked.delete(`${p.source}::${p.name}`));
  } else {
    _ptChecked.clear();
  }
  const list = $pt("params-list");
  if (list) list.querySelectorAll("input[type=checkbox]").forEach(cb => cb.checked = false);
  ptUpdateRunLabel();
}

function ptUpdateRunLabel() {
  const lbl = $pt("run-count-label");
  if (!lbl) return;
  const randCount = Object.keys(_ptRandomFormats).length;
  lbl.textContent = `${_ptChecked.size} param(s) selected`
    + (randCount > 0 ? `  ·  🎲 ${randCount} randomized` : "");
}

// Suggest a sensible default random format for a given param name + current value
function _ptDefaultFmt(paramName, currentVal) {
  const n = (paramName || "").toLowerCase();
  if (n.includes("email"))             return "{email}";
  if (n.includes("uuid") || n.includes("guid")) return "{uuid}";
  if (n.includes("phone") || n.includes("mobile")) return "{num:10}";
  // For name/title fields: keep a readable prefix + random suffix
  const prefix = (currentVal || "").replace(/\s+/g, "").substring(0, 6) || "Test";
  return `${prefix}{alphanum:6}`;
}

// ── Baseline preflight test ───────────────────────────────────────────────────
let _ptBaselineOk  = false;   // true once user has confirmed a 2xx baseline
let _ptBaselineMethod = "";   // detected method from last parse

function ptShowBaselineWarn() {
  // Inject a warning below the run bar if not already there
  let warn = document.getElementById("pt-baseline-warn");
  if (!warn) {
    warn = document.createElement("div");
    warn.id = "pt-baseline-warn";
    warn.className = "pt-baseline-warn-box";
    const rb = $pt("run-bar");
    if (rb) rb.after(warn);
  }
  warn.innerHTML = `
    <span class="pt-bwarn-icon">⚠</span>
    <span class="pt-bwarn-text">
      Baseline not verified. Click <strong>🧪 Test Baseline</strong> first.
      If it returns a non-2xx (e.g. 422 because <code>name</code> must be unique),
      update your cURL to use a fresh / valid value so the baseline succeeds —
      otherwise every mutation that returns 200 will look like a status-upgrade finding.
    </span>
    <button class="pt-bwarn-dismiss" onclick="this.closest('#pt-baseline-warn').style.display='none'">✕</button>
  `;
  warn.style.display = "";
}

async function ptTestBaseline() {
  const btn = $pt("btn-baseline");
  const res = $pt("baseline-result");

  // Always read from the live textarea — user may have edited it after parsing
  const ta = $pt("curl-input");
  const liveCurl = (ta ? ta.value.trim() : "") || _ptCurl;
  if (!liveCurl) { alert("Paste a cURL first."); return; }

  if (btn) { btn.disabled = true; btn.textContent = "Testing…"; }
  if (res)  { res.style.display = "none"; }

  try {
    const resp = await fetch(`${PT_BACKEND}/preflight`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ curl: liveCurl }),
    });
    const data = await resp.json();

    if (res) {
      res.style.display = "";
      if (data.error && !data.status) {
        // connection/parse error
        res.className = "pt-baseline-result pt-baseline-error";
        res.textContent = `✕ ${data.error}`;
        _ptBaselineOk = false;
      } else if (data.ok) {
        // Sync _ptCurl with the live textarea so the scan uses the same cURL
        // that was just cached on the backend
        _ptCurl = liveCurl;
        if (ta) ta.value = liveCurl;  // keep textarea in sync

        res.className = "pt-baseline-result pt-baseline-ok";
        res.textContent = `✓ Baseline ${data.status} OK  (${data.length} B) — locked in as reference`;
        _ptBaselineOk = true;
        // Clear any previous block warning
        const warn = document.getElementById("pt-baseline-warn");
        if (warn) warn.style.display = "none";
        // Update scan button to indicate baseline mode
        const runBtn = $pt("btn-run");
        if (runBtn) runBtn.textContent = "🚀 Start Scan (using baseline)";
      } else {
        res.className = "pt-baseline-result pt-baseline-warn";
        res.textContent = `⚠ ${data.status} — update cURL to get 200 (unique name, valid payload, etc.)`;
        _ptBaselineOk = false;
        // Reset scan button
        const runBtn = $pt("btn-run");
        if (runBtn) runBtn.textContent = "🚀 Start Scan";
      }
    }
  } catch (e) {
    if (res) {
      res.style.display = "";
      res.className = "pt-baseline-result pt-baseline-error";
      res.textContent = `✕ Network error: ${e.message}`;
    }
    _ptBaselineOk = false;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "🧪 Test Baseline"; }
  }
}

// ── From AV Capture modal ─────────────────────────────────────────────────────
async function ptFromAV() {
  try {
    const resp = await fetch("http://127.0.0.1:8765/capture/requests");
    if (!resp.ok) throw new Error("AV backend error");
    const data = await resp.json();
    _ptAvRequests = Array.isArray(data) ? data : (data.requests || data.entries || []);
  } catch (e) {
    alert("Could not fetch from AV Capture: " + e.message);
    return;
  }

  const modal = $pt("av-modal");
  if (modal) modal.style.display = "";

  const searchEl = $pt("av-search");
  if (searchEl) searchEl.value = "";

  ptRenderAvModal(_ptAvRequests);
}

function ptRenderAvModal(requests) {
  const listEl = $pt("av-modal-list");
  if (!listEl) return;
  listEl.innerHTML = "";

  if (!requests || requests.length === 0) {
    listEl.innerHTML = '<div style="padding:16px;color:var(--text3);font-size:11px;text-align:center">No requests captured yet.</div>';
    return;
  }

  requests.forEach(req => {
    const method = (req.method || "GET").toUpperCase();
    const url    = req.url || "";
    const item   = document.createElement("div");
    item.className = "pt-av-item";
    item.innerHTML = `
      <span class="pt-src-badge pt-src-${method.toLowerCase() === "get" ? "query" : "body"}" style="flex-shrink:0">${_ptEsc(method)}</span>
      <span style="font-size:10px;color:var(--text);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1" title="${_ptEsc(url)}">${_ptEsc(url)}</span>
    `;
    item.addEventListener("click", () => ptPickAvRequest(req));
    listEl.appendChild(item);
  });
}

function ptFilterAvModal() {
  const q = ($pt("av-search")?.value || "").toLowerCase();
  const filtered = q
    ? _ptAvRequests.filter(r => (r.url || "").toLowerCase().includes(q))
    : _ptAvRequests;
  ptRenderAvModal(filtered);
}

function ptPickAvRequest(req) {
  const curl = ptBuildCurlFromRequest(req);
  const ta   = $pt("curl-input");
  if (ta) ta.value = curl;
  _ptCurl = curl;
  ptCloseAvModal();
}

function ptCloseAvModal() {
  const modal = $pt("av-modal");
  if (modal) modal.style.display = "none";
}

function ptCurlArg(s) {
  s = s == null ? "" : String(s);
  if (!/'/.test(s) && !/[\n\r]/.test(s)) return "'" + s + "'";
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r") + '"';
}

function ptBuildCurlFromRequest(req) {
  const method  = (req.method || "GET").toUpperCase();
  const url     = req.url || "";
  const headers = req.headers || {};
  const body    = req.rawBody || req.body || "";
  const skipName = /^(content-length|host|connection|transfer-encoding|accept-encoding|content-encoding|keep-alive|proxy-connection|te|trailer|upgrade|http2-settings|upgrade-insecure-requests)$/i;
  const skipPrefix = /^(sec-ch-|sec-fetch-|sec-gpc)/i;

  const lines = [`curl --http1.1 -X ${method} ${ptCurlArg(url)}`];
  const seen = new Set();
  Object.entries(headers).forEach(([k, v]) => {
    if (!k || k.startsWith(":") || skipName.test(k) || skipPrefix.test(k)) return;
    const lk = k.toLowerCase();
    if (seen.has(lk)) return;
    seen.add(lk);
    lines.push(`  -H ${ptCurlArg(k + ": " + v)}`);
  });
  if (body) {
    const bodyStr = typeof body === "string" ? body : JSON.stringify(body);
    if (bodyStr && bodyStr !== "null") {
      if (!seen.has("content-type") && /^\s*[\[{]/.test(bodyStr)) {
        lines.push(`  -H ${ptCurlArg("Content-Type: application/json")}`);
      }
      lines.push(`  --data-raw ${ptCurlArg(bodyStr)}`);
    }
  }
  return lines.join(" \\\n");
}

// ── Scan UI lock / progress ───────────────────────────────────────────────────
function ptSetScanningUI(on) {
  _ptScanning = !!on;
  const root = document.getElementById("tool-pt");
  if (root) root.classList.toggle("is-scanning", _ptScanning);

  const runBtn = $pt("btn-run");
  if (runBtn) {
    runBtn.disabled = _ptScanning;
    runBtn.textContent = _ptScanning ? "⏳ Scanning…" : "🚀 Start Scan";
  }

  ["btn-abort", "btn-abort-results"].forEach(id => {
    const btn = $pt(id);
    if (!btn) return;
    btn.style.display = _ptScanning ? "" : "none";
    btn.disabled = false;
    btn.textContent = "✕ Abort";
  });

  const prog = $pt("scan-progress-inline");
  if (prog) prog.style.display = _ptScanning ? "flex" : "none";

  const newBtn = $pt("btn-new-scan");
  if (newBtn) newBtn.disabled = _ptScanning;
}

function _ptSetScanPct(pct, label) {
  const pctEl   = $pt("scan-pct");
  const fillEl  = $pt("scan-bar-fill");
  const labelEl = $pt("scan-label");
  if (pctEl)  pctEl.textContent  = `${Math.min(100, Math.max(0, pct | 0))}%`;
  if (fillEl) fillEl.style.width = `${Math.min(100, Math.max(0, pct | 0))}%`;
  if (labelEl) labelEl.textContent = label || "";
}

function _ptShowAbortedBanner() {
  const existing = document.getElementById("pt-aborted-warn");
  if (existing) existing.remove();
  const warn = document.createElement("div");
  warn.id = "pt-aborted-warn";
  warn.style.cssText = "background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.35);border-radius:6px;color:#f85149;padding:10px 14px;font-size:12px;margin:0 0 8px;flex-shrink:0";
  warn.textContent = "⏹ Scan aborted — showing partial results.";
  const prog = $pt("scan-progress-inline");
  const pane = $pt("pane-results");
  if (prog && prog.parentElement) prog.parentElement.insertBefore(warn, prog.nextSibling);
  else if (pane) pane.insertBefore(warn, pane.firstChild);
}

// ── Run scan ──────────────────────────────────────────────────────────────────
async function ptRunScan() {
  if (_ptScanning) {
    alert("A scan is already running. Abort it before starting another.");
    return;
  }

  // Always prefer the live textarea value over the possibly-stale _ptCurl
  const ta = $pt("curl-input");
  if (ta && ta.value.trim()) _ptCurl = ta.value.trim();

  if (!_ptCurl) {
    alert("Parse a cURL command first.");
    return;
  }
  if (_ptChecked.size === 0) {
    alert("Select at least one parameter to test.");
    return;
  }

  // For non-GET requests: require a successful baseline before scanning
  // to prevent false positives from an already-failing original request
  const isGet = _ptCurl.trim().match(/^curl\s+["']?https?:/i) &&
                !_ptCurl.match(/-X\s+(POST|PUT|PATCH|DELETE)/i);
  if (!isGet && !_ptBaselineOk) {
    ptShowBaselineWarn();
    return;
  }

  // Build selected_params: [[source, name], ...]
  const selected = [];
  _ptChecked.forEach(key => {
    const [source, ...nameParts] = key.split("::");
    selected.push([source, nameParts.join("::")]);
  });

  // Read options
  const ctxAware = $pt("opt-ctx")?.checked ?? true;
  const threads  = parseInt($pt("opt-threads")?.value || "8", 10);
  const timeout  = parseInt($pt("opt-timeout")?.value || "10", 10);
  const delay    = parseFloat($pt("opt-delay")?.value || "0") || 0;

  window._ptLastAborted = false;
  const existingAbort = document.getElementById("pt-aborted-warn");
  if (existingAbort) existingAbort.remove();

  _ptFindings = [];
  _ptLastPollDone = -1;
  ptRenderResults();
  _ptSetScanPct(0, "Starting scan…");
  ptSetScanningUI(true);
  ptGoTab("results");

  try {
    const resp = await fetch(`${PT_BACKEND}/scan/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        curl: _ptCurl,
        selected_params: selected,
        options: {
          context_aware: ctxAware,
          threads: threads,
          timeout: timeout,
          delay: delay,
        },
        // Send randomized param formats so backend generates fresh values per request
        random_formats: Object.keys(_ptRandomFormats).length > 0
          ? { ..._ptRandomFormats }
          : null,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      ptSetScanningUI(false);
      alert("Scan start failed: " + (data.detail || "Unknown error"));
      return;
    }
    _ptJobId = data.job_id;
  } catch (e) {
    ptSetScanningUI(false);
    alert("Network error starting scan: " + e.message);
    return;
  }

  // Start polling — stream findings into Results as they arrive
  if (_ptPollTimer) clearInterval(_ptPollTimer);
  _ptPollTimer = setInterval(_ptPoll, 1000);
  _ptPoll();
}

// ── Poll scan status ──────────────────────────────────────────────────────────
async function _ptPoll() {
  if (!_ptJobId) return;
  try {
    const resp = await fetch(`${PT_BACKEND}/scan/status/${_ptJobId}`);
    if (!resp.ok) return;
    const data = await resp.json();

    const pct    = data.pct || 0;
    const done   = data.done || 0;
    const total  = data.total || 0;
    let label    = total > 0 ? `${done} / ${total} tests` : "Preparing…";
    if (data.aborted && data.status !== "done") label = "Aborting…";

    _ptSetScanPct(pct, label);

    // Stream results table while scan is running
    if (done !== _ptLastPollDone || data.status === "done") {
      _ptLastPollDone = done;
      await ptLoadResults({ preserveScroll: true });
    }

    if (data.status === "done" || data.status === "error") {
      clearInterval(_ptPollTimer);
      _ptPollTimer = null;

      if (data.status === "error") {
        ptSetScanningUI(false);
        alert("Scan error: " + (data.error || "Unknown error"));
        return;
      }

      _ptSetScanPct(100, data.aborted ? "⏹ Aborted — partial results" : "Scan complete");
      await ptLoadResults({ preserveScroll: true });
      window._ptLastAborted = !!data.aborted;
      ptSetScanningUI(false);
      ptGoTab("results");

      // Keep a brief completion label, then hide the progress strip
      const prog = $pt("scan-progress-inline");
      if (prog) {
        prog.style.display = "flex";
        setTimeout(() => {
          if (!_ptScanning && prog) prog.style.display = "none";
        }, data.aborted ? 4000 : 2500);
      }
      if (data.aborted) _ptShowAbortedBanner();
    }
  } catch (e) {
    // Network hiccup — keep polling
  }
}

// ── Load & render results ─────────────────────────────────────────────────────
async function ptLoadResults(opts = {}) {
  if (!_ptJobId) return;
  try {
    const resp = await fetch(`${PT_BACKEND}/scan/results/${_ptJobId}`);
    if (!resp.ok) return;
    const data = await resp.json();
    _ptFindings = data.findings || [];
    ptRenderResults({ preserveScroll: !!opts.preserveScroll });
  } catch (e) {
    // Ignore
  }
}

function _ptIsSqlFinding(f) {
  if (!f) return false;
  if (f.sql_disclosure) return true;
  const ev = String(f.evidence || "").toLowerCase();
  const kw = String(f.keywords || "").toLowerCase();
  return ev.includes("sql_disclosure:") ||
         kw.includes("sql error") ||
         kw.includes("unknown column") ||
         kw.includes("sql syntax");
}

function ptRenderResults(opts = {}) {
  // Summary cards
  let high = 0, medium = 0, possible = 0, noIssue = 0, sqlN = 0;
  _ptFindings.forEach(f => {
    const r = f.risk_level || "";
    if (r === "High Risk")   high++;
    else if (r === "Medium Risk") medium++;
    else if (r === "Possible")    possible++;
    else                          noIssue++;
    if (_ptIsSqlFinding(f)) sqlN++;
  });

  const el = id => document.getElementById(id);
  const setTxt = (id, n) => { const nEl = el(id); if (nEl) nEl.textContent = n; };
  setTxt("pt-res-all", _ptFindings.length);
  setTxt("pt-res-sql", sqlN);
  setTxt("pt-res-high", high);
  setTxt("pt-res-med", medium);
  setTxt("pt-res-pos", possible);
  setTxt("pt-res-ok", noIssue);
  _ptSyncFilterCards();

  // Badge on tab
  const badge = $pt("results-badge");
  if (badge) {
    const notable = high + medium + possible;
    badge.textContent = notable;
    badge.style.display = notable > 0 ? "" : "none";
  }

  // Table
  const wrap = $pt("results-table-wrap");
  const scrollTop = (opts.preserveScroll && wrap) ? wrap.scrollTop : 0;
  const tbody = $pt("results-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  let filtered;
  if (_ptFilterRisk === "sql") {
    filtered = _ptFindings.filter(_ptIsSqlFinding);
  } else if (_ptFilterRisk === "all") {
    filtered = _ptFindings.slice();
  } else {
    filtered = _ptFindings.filter(f => f.risk_level === _ptFilterRisk);
  }

  // Live scan: skip No Issue noise so the table stays usable for manual review
  if (_ptScanning && _ptFilterRisk === "all") {
    filtered = filtered.filter(f => f.risk_level !== "No Issue");
  }

  const _riskOrd = { "High Risk": 0, "Medium Risk": 1, "Possible": 2, "No Issue": 3 };
  filtered.sort((a, b) =>
    (_riskOrd[a.risk_level] ?? 4) - (_riskOrd[b.risk_level] ?? 4)
  );

  if (filtered.length === 0) {
    const emptyMsg = _ptScanning
      ? "Scanning… issues will appear here as tests complete (No Issue rows hidden until scan ends)."
      : "No findings for selected filter.";
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:24px">${emptyMsg}</td></tr>`;
    if (opts.preserveScroll && wrap) wrap.scrollTop = scrollTop;
    return;
  }

  filtered.forEach((f, i) => {
    const rl   = f.risk_level  || "No Issue";
    const conf = f.confidence  || "";

    const riskCls = {
      "High Risk":   "pt-risk-high",
      "Medium Risk": "pt-risk-med",
      "Possible":    "pt-risk-pos",
      "No Issue":    "pt-risk-ok",
    }[rl] || "pt-risk-ok";

    const confCls = {
      "Confirmed": "pt-conf-confirmed",
      "Likely":    "pt-conf-likely",
      "Possible":  "pt-conf-possible",
    }[conf] || "pt-conf-ok";

    const origS = f.orig_status ?? "?";
    const mutS  = f.mut_status  ?? "?";

    const tr = document.createElement("tr");
    tr.className = "pt-result-row";
    tr.title = "Click to view request / response detail · right-click to copy cURL";
    tr.innerHTML = `
      <td style="color:var(--text3);text-align:center;font-size:10px">${i + 1}</td>
      <td><code style="font-size:10px;color:var(--blue)">${_ptEsc(f.param_name)}</code></td>
      <td><span class="pt-src-badge ${f.param_source === "query" ? "pt-src-query" : (f.param_source === "body_nested" ? "pt-src-body-nested" : "pt-src-body")}">${_ptEsc(f.param_source)}</span></td>
      <td style="font-size:10px;color:var(--text3);font-family:var(--mono)">${_ptEsc(f.mutation_type)}</td>
      <td style="font-family:var(--mono);font-size:10px">${_ptEsc(origS)} → ${_ptEsc(mutS)}</td>
      <td><span class="pt-risk-badge ${riskCls}">${_ptEsc(rl)}</span></td>
      <td class="${confCls}" style="font-size:10px">${_ptEsc(conf)}</td>
      <td style="font-size:10px;color:var(--text3)" title="${_ptEsc(f.evidence)}">${_ptEsc((f.evidence || "").substring(0, 80))}</td>
      <td style="text-align:center;white-space:nowrap">
        <button type="button" class="btn-sm as-rd-curl-btn pt-copy-curl-btn"
                title="Copy mutated request as cURL">📋 cURL</button>
      </td>
    `;
    const copyBtn = tr.querySelector(".pt-copy-curl-btn");
    if (copyBtn) {
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        ptCopyText(ptFindingCurl(f, "mut"), copyBtn);
      });
    }
    tr.addEventListener("click", () => ptShowDetail(f));
    tr.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      ptShowCtxMenu(e, f);
    });
    tbody.appendChild(tr);
  });

  if (opts.preserveScroll && wrap) wrap.scrollTop = scrollTop;
}

// ── Filter results (summary cards act as filters) ─────────────────────────────
function ptFilterResults(risk) {
  _ptFilterRisk = risk || "all";
  _ptSyncFilterCards();
  ptRenderResults({ preserveScroll: true });
}

function _ptSyncFilterCards() {
  const cards = document.querySelectorAll("#pt-results-summary-cards .pt-sum-card");
  cards.forEach((card) => {
    const risk = card.getAttribute("data-risk") || "";
    card.classList.toggle("active", risk === _ptFilterRisk);
  });
}

// ── Export ────────────────────────────────────────────────────────────────────
async function ptExport(format) {
  if (!_ptJobId) {
    alert("No scan results to export.");
    return;
  }
  const url = `${PT_BACKEND}/export/${format}/${_ptJobId}`;
  const msgEl = $pt("export-msg");

  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("Export request failed");
    const content = await resp.text();
    const filename = `pt_report.${format}`;

    if (window.pywebview && window.pywebview.api && window.pywebview.api.save_file) {
      const result = await window.pywebview.api.save_file(content, filename);
      if (result && result.ok) {
        if (msgEl) {
          msgEl.textContent = `Saved: ${result.filename}`;
          setTimeout(() => { if (msgEl) msgEl.textContent = ""; }, 3000);
        }
      }
    } else {
      // Fallback: blob download
      const mime = format === "csv" ? "text/csv" : "text/html";
      const blob = new Blob([content], { type: mime });
      const a    = document.createElement("a");
      a.href     = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      URL.revokeObjectURL(a.href);
    }
  } catch (e) {
    alert("Export failed: " + e.message);
  }
}

// ── Abort scan ────────────────────────────────────────────────────────────────
async function ptAbortScan() {
  if (!_ptScanning && !_ptJobId) return;

  ["btn-abort", "btn-abort-results"].forEach(id => {
    const btn = $pt(id);
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Aborting…";
    }
  });
  const labelEl = $pt("scan-label");
  if (labelEl) labelEl.textContent = "Abort requested — stopping workers…";

  if (_ptJobId) {
    try {
      await fetch(`${PT_BACKEND}/scan/abort/${_ptJobId}`, { method: "POST" });
    } catch (_) { /* poll will still finish */ }
  }
  // Keep polling until backend reports status=done with partial findings
}
window.ptAbortScan = ptAbortScan;

// ── Reset ─────────────────────────────────────────────────────────────────────
function ptReset() {
  if (_ptScanning) {
    alert("Stop the running scan (Abort) before starting a new one.");
    return;
  }

  // Stop polling
  if (_ptPollTimer) { clearInterval(_ptPollTimer); _ptPollTimer = null; }

  // Clear state
  _ptCurl        = "";
  _ptParams      = [];
  _ptChecked     = new Set();
  _ptJobId       = null;
  _ptFindings    = [];
  _ptFilterRisk  = "all";
  _ptBaselineOk    = false;
  _ptRandomFormats = {};
  _ptLastPollDone  = -1;
  _ptDetailFinding = null;
  _ptCtxFinding    = null;
  _ptPreRaw        = {};
  _ptDetailSearch  = {};
  ptHideCtxMenu();
  ptCloseDetail();
  ptClearBaselineResult();
  ptSetScanningUI(false);

  // Clear UI
  const ta = $pt("curl-input");
  if (ta) ta.value = "";

  const psList = $pt("params-list");
  if (psList) psList.innerHTML = "";

  const ps = $pt("params-section");
  if (ps) ps.style.display = "none";

  const rb = $pt("run-bar");
  if (rb) rb.style.display = "none";

  const prog = $pt("scan-progress-inline");
  if (prog) prog.style.display = "none";

  const abortedWarn = document.getElementById("pt-aborted-warn");
  if (abortedWarn) abortedWarn.remove();

  const tbody = $pt("results-tbody");
  if (tbody) tbody.innerHTML = "";

  const badge = $pt("results-badge");
  if (badge) { badge.textContent = "0"; badge.style.display = "none"; }

  ptClearParseError();
  ptUpdateRunLabel();

  // Reset summary / filter cards
  ["pt-res-all","pt-res-sql","pt-res-high","pt-res-med","pt-res-pos","pt-res-ok"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = "0";
  });
  _ptSyncFilterCards();

  // Go back to capture tab
  ptGoTab("capture");
}

// ── Detail Modal ──────────────────────────────────────────────────────────────

function ptShowDetail(f) {
  const modal = document.getElementById("pt-detail-modal");
  if (!modal) return;
  _ptDetailFinding = f;

  // ── Header ──────────────────────────────────────────────────────────────
  const paramEl = document.getElementById("pt-detail-param-name");
  if (paramEl) paramEl.textContent = f.param_name || "";

  const mutLbl = document.getElementById("pt-detail-mutation-lbl");
  if (mutLbl) mutLbl.textContent = f.mutation_type || "";

  const riskBadge = document.getElementById("pt-detail-risk-badge");
  if (riskBadge) {
    const rl = f.risk_level || "No Issue";
    riskBadge.textContent = rl;
    riskBadge.className = "pt-risk-badge " + ({
      "High Risk":   "pt-risk-high",
      "Medium Risk": "pt-risk-med",
      "Possible":    "pt-risk-pos",
      "No Issue":    "pt-risk-ok",
    }[rl] || "pt-risk-ok");
  }

  const confBadge = document.getElementById("pt-detail-conf-badge");
  if (confBadge) {
    const conf = f.confidence || "";
    confBadge.textContent = conf;
    confBadge.className = "pt-detail-conf-badge " + ({
      "Confirmed": "pt-dconf-confirmed",
      "Likely":    "pt-dconf-likely",
      "Possible":  "pt-dconf-possible",
    }[conf] || "pt-dconf-ok");
  }

  // ── Status pills ─────────────────────────────────────────────────────────
  const origStatusEl = document.getElementById("pt-detail-orig-status");
  if (origStatusEl) {
    const s = String(f.orig_status ?? "?");
    origStatusEl.textContent = s;
    origStatusEl.className = "pt-detail-status-pill " + _ptStatusPillClass(s);
  }

  const mutStatusEl = document.getElementById("pt-detail-mut-status");
  if (mutStatusEl) {
    const s = String(f.mut_status ?? "?");
    mutStatusEl.textContent = s;
    mutStatusEl.className = "pt-detail-status-pill " + _ptStatusPillClass(s);
  }

  // ── Byte length notes ────────────────────────────────────────────────────
  const origLenEl = document.getElementById("pt-detail-orig-len");
  if (origLenEl) {
    origLenEl.textContent = f.orig_length != null ? `${f.orig_length} B` : "";
  }

  const mutLenEl = document.getElementById("pt-detail-mut-len");
  if (mutLenEl) {
    mutLenEl.textContent = f.mut_length != null ? `${f.mut_length} B` : "";
  }

  // ── Diff pill ────────────────────────────────────────────────────────────
  const diffPill = document.getElementById("pt-detail-diff-pill");
  if (diffPill) {
    const pct = f.diff_pct;
    if (pct != null && pct !== 0) {
      diffPill.textContent = `body +${pct}% diff`;
      diffPill.style.display = "";
      diffPill.className = "pt-detail-diff-pill" + (pct > 20 ? " pt-detail-diff-notable" : "");
    } else {
      diffPill.style.display = "none";
    }
  }

  // ── Request / Response blocks ────────────────────────────────────────────
  _ptPaintDetailPres(f);

  // ── Footer ───────────────────────────────────────────────────────────────
  const evEl = document.getElementById("pt-detail-evidence-full");
  if (evEl) evEl.textContent = f.evidence ? `🔍 ${f.evidence}` : "";

  const diffMeta = document.getElementById("pt-detail-meta-diff");
  if (diffMeta) {
    const parts = [];
    if (f.diff_pct != null) parts.push(`Body diff: ${f.diff_pct}%`);
    if (f.orig_length != null && f.mut_length != null) {
      const delta = f.mut_length - f.orig_length;
      const sign  = delta >= 0 ? "+" : "";
      parts.push(`Δ bytes: ${sign}${delta}`);
    }
    diffMeta.textContent = parts.join("  ·  ");
  }

  const timeMeta = document.getElementById("pt-detail-meta-time");
  if (timeMeta) {
    timeMeta.textContent = f.time_delta != null ? `Δ time: ${Number(f.time_delta).toFixed(2)}s` : "";
  }

  modal.style.display = "";
}

function ptCloseDetail() {
  const modal = document.getElementById("pt-detail-modal");
  if (modal) modal.style.display = "none";
  _ptDetailFinding = null;
}

function _ptCurlFromHttpDump(dump) {
  if (!dump || dump === "(no data)") return "";
  const lines = String(dump).split(/\r?\n/);
  const first = (lines[0] || "").trim();
  const m = first.match(/^([A-Z]+)\s+(\S+)/);
  if (!m) return "";
  const headers = {};
  let i = 1;
  for (; i < lines.length; i++) {
    if (!lines[i].trim()) { i++; break; }
    const ci = lines[i].indexOf(":");
    if (ci > 0) headers[lines[i].slice(0, ci).trim()] = lines[i].slice(ci + 1).trim();
  }
  return ptBuildCurlFromRequest({
    method: m[1],
    url: m[2],
    headers,
    body: lines.slice(i).join("\n").trim(),
  });
}

function ptFindingCurl(f, which) {
  if (!f) return "";
  if (which === "orig") {
    if (f.orig_curl) return f.orig_curl;
    const fromDump = _ptCurlFromHttpDump(f.orig_request);
    if (fromDump) return fromDump;
    return _ptCurl || "";
  }
  if (f.mut_curl) return f.mut_curl;
  return _ptCurlFromHttpDump(f.mut_request);
}

function ptCopyText(text, btn) {
  if (!text) return;
  const orig = btn ? btn.textContent : "";
  const done = () => {
    if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
  };
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
  };
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => { fallback(); done(); });
  } else {
    fallback();
    done();
  }
}

function ptCopyFindingCurl(which, btn) {
  ptCopyText(ptFindingCurl(_ptDetailFinding, which), btn);
}

function ptShowCtxMenu(e, f) {
  _ptCtxFinding = f;
  const menu = document.getElementById("pt-ctx-menu");
  if (!menu) return;
  menu.style.display = "block";
  const mw = menu.offsetWidth || 200, mh = menu.offsetHeight || 80;
  menu.style.left = Math.min(e.pageX, window.innerWidth  - mw - 8) + "px";
  menu.style.top  = Math.min(e.pageY, window.innerHeight - mh - 8) + "px";
}
function ptHideCtxMenu() {
  const menu = document.getElementById("pt-ctx-menu");
  if (menu) menu.style.display = "none";
}
function ptCtxCopyCurl(which) {
  ptCopyText(ptFindingCurl(_ptCtxFinding, which));
  ptHideCtxMenu();
}
document.addEventListener("click", ptHideCtxMenu);
document.addEventListener("scroll", ptHideCtxMenu, true);

window.ptCopyFindingCurl = ptCopyFindingCurl;
window.ptCtxCopyCurl = ptCtxCopyCurl;

// ── Helpers for detail modal ──────────────────────────────────────────────────

function _ptFindingKeywords(f) {
  if (!f || !f.keywords) return [];
  return Array.isArray(f.keywords)
    ? f.keywords
    : String(f.keywords).split(",").map(k => k.trim()).filter(Boolean);
}

function _ptPaintDetailPres(f) {
  _ptPreRaw["pt-detail-orig-req"]  = _ptFormatRequest(f, "orig");
  _ptPreRaw["pt-detail-mut-req"]   = _ptFormatRequest(f, "mut");
  _ptPreRaw["pt-detail-orig-resp"] = f.orig_response || "(empty)";
  _ptPreRaw["pt-detail-mut-resp"]  = f.mut_response || "(empty)";
  _ptDetailSearch = {};

  const leakHint = document.getElementById("pt-detail-leak-hint");
  if (leakHint) leakHint.style.display = _ptFindingKeywords(f).length ? "" : "none";

  ["orig-req", "orig-resp", "mut-req", "mut-resp"].forEach(key => {
    const inp = document.getElementById("pt-search-" + key);
    if (inp) inp.value = "";
    const badge = document.getElementById("pt-detail-" + key + "-matches");
    if (badge) { badge.textContent = ""; badge.classList.remove("pt-detail-matches-empty"); }
    _ptRestorePre("pt-detail-" + key);
  });
}

function _ptRestorePre(preId) {
  const pre = document.getElementById(preId);
  if (!pre) return;
  const raw = _ptPreRaw[preId] != null ? _ptPreRaw[preId] : "";
  const f = _ptDetailFinding;
  if (preId === "pt-detail-mut-req" && f) {
    pre.innerHTML = _ptHighlightPayload(_ptEsc(raw), _ptEsc(f.mut_value || ""));
  } else if (preId === "pt-detail-mut-resp" && f) {
    pre.innerHTML = _ptHighlightKeywords(_ptEsc(raw), _ptFindingKeywords(f));
  } else {
    pre.textContent = raw;
  }
}

function _ptHighlightSearch(raw, query) {
  const text = String(raw ?? "");
  const q = (query || "").trim();
  if (!q) return { html: _ptEsc(text), hits: 0 };
  let re;
  try {
    re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
  } catch (_) {
    return { html: _ptEsc(text), hits: 0 };
  }
  let out = "", last = 0, hits = 0, m;
  const maxHits = 200;
  while ((m = re.exec(text)) !== null) {
    out += _ptEsc(text.slice(last, m.index));
    out += `<mark class="pt-search-hit">${_ptEsc(m[0])}</mark>`;
    last = m.index + m[0].length;
    hits++;
    if (!m[0].length) re.lastIndex++;
    if (hits >= maxHits) break;
  }
  out += _ptEsc(text.slice(last));
  return { html: out, hits };
}

function ptFilterDetailPre(preId, query) {
  const pre = document.getElementById(preId);
  if (!pre) return;
  const q = (query || "").trim();
  const badge = document.getElementById(preId + "-matches");
  if (!q) {
    _ptRestorePre(preId);
    _ptDetailSearch[preId] = { idx: 0, total: 0 };
    if (badge) { badge.textContent = ""; badge.classList.remove("pt-detail-matches-empty"); }
    return;
  }
  const raw = _ptPreRaw[preId] != null ? _ptPreRaw[preId] : (pre.textContent || "");
  const { html, hits } = _ptHighlightSearch(raw, q);
  pre.innerHTML = html;
  _ptDetailSearch[preId] = { idx: 0, total: hits };
  if (badge) {
    badge.textContent = hits ? `1/${hits}` : "0";
    badge.classList.toggle("pt-detail-matches-empty", !hits);
  }
  const first = pre.querySelector("mark.pt-search-hit");
  if (first) {
    first.classList.add("pt-search-cur");
    first.scrollIntoView({ block: "nearest" });
  }
}

function ptDetailSearchKeydown(preId, e) {
  if (e.key !== "Enter") return;
  e.preventDefault();
  const pre = document.getElementById(preId);
  if (!pre) return;
  const marks = [...pre.querySelectorAll("mark.pt-search-hit")];
  if (!marks.length) return;
  const st = _ptDetailSearch[preId] || { idx: 0, total: marks.length };
  st.idx = e.shiftKey ? st.idx - 1 : st.idx + 1;
  if (st.idx < 0) st.idx = marks.length - 1;
  if (st.idx >= marks.length) st.idx = 0;
  _ptDetailSearch[preId] = st;
  marks.forEach((m, i) => m.classList.toggle("pt-search-cur", i === st.idx));
  marks[st.idx].scrollIntoView({ block: "nearest" });
  const badge = document.getElementById(preId + "-matches");
  if (badge) {
    badge.textContent = `${st.idx + 1}/${marks.length}`;
    badge.classList.remove("pt-detail-matches-empty");
  }
}

window.ptFilterDetailPre = ptFilterDetailPre;
window.ptDetailSearchKeydown = ptDetailSearchKeydown;

function _ptFormatRequest(f, which) {
  const dump = (which === "mut" ? f.mut_request : f.orig_request) || "";
  const bodyJson = which === "mut" ? f.mut_request_body_json : f.orig_request_body_json;
  if (!dump && !bodyJson) return "(no data)";
  if (!bodyJson) return dump;
  const parts = dump.split(/\n\n/);
  const header = parts[0] || dump;
  const dumpBody = parts.slice(1).join("\n\n");
  if (String(bodyJson).length >= dumpBody.length) return header + "\n\n" + bodyJson;
  return dump || bodyJson;
}

function _ptStatusPillClass(status) {
  if (!status || status === "?") return "pt-spill-unknown";
  const first = String(status)[0];
  if (first === "2") return "pt-spill-2xx";
  if (first === "3") return "pt-spill-3xx";
  if (first === "4") return "pt-spill-4xx";
  if (first === "5") return "pt-spill-5xx";
  return "pt-spill-unknown";
}

function _ptHighlightPayload(escapedText, escapedPayload) {
  if (!escapedPayload || escapedPayload.length < 2) return escapedText;
  // Only highlight first 2 occurrences to avoid huge DOM for short payloads
  let count = 0;
  return escapedText.replace(
    new RegExp(escapedPayload.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"),
    match => {
      if (count++ < 2) return `<mark class="pt-hl-payload">${match}</mark>`;
      return match;
    }
  );
}

function _ptHighlightKeywords(escapedText, keywords) {
  if (!keywords || keywords.length === 0) return escapedText;
  let result = escapedText;
  // Escape each keyword for regex, highlight up to 6 unique ones
  const seen = new Set();
  keywords.slice(0, 6).forEach(kw => {
    if (!kw || seen.has(kw)) return;
    seen.add(kw);
    const escapedKw = _ptEsc(kw).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (escapedKw.length < 2) return;
    result = result.replace(
      new RegExp(escapedKw, "gi"),
      m => `<mark class="pt-hl-leak">${m}</mark>`
    );
  });
  return result;
}
