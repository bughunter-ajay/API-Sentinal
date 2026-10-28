// ════════════════════════════════════════════════════════════════════════
//  XSS Security Tester — frontend  (backend: 127.0.0.1:8790)
//  Flow: Capture → Scanning → Results → Dashboard
// ════════════════════════════════════════════════════════════════════════

const XSS_BASE = "http://127.0.0.1:8790";

// Multi-entry state
let _xssEntries         = [];   // [{id,method,url,curl,params,checked,randomFmts,status,jobId}]
let _xssSelEntryId      = null; // entry shown in right config panel
let _xssCheckedEntryIds = new Set(); // entry IDs ticked for scanning
let _xssScanQueue       = [];   // ordered entry IDs to scan
let _xssScanQueueIdx    = 0;

// Scan runtime
let _xssJobId              = null;
let _xssPollTimer          = null;
let _xssElapsed            = 0;   // total scan duration in seconds (for dashboard)
let _xssResults            = [];   // accumulated across all entries (for Results tab)
let _xssCurrentJobResults  = [];   // current polling job only (for Scanning tab probe detail)
let _xssFilter             = "ALL";
let _xssScanType           = null;
let _xssScanState          = "idle";
let _xssProbeLog             = [];
let _xssSelResultIdx         = null;
let _xssSelProbeIdx          = null;
let _xssAvEntries            = [];
let _xssCurrentScanningParam = null; // param name being actively scanned right now
let _xssMode                 = "stored"; // "stored" | "reflected"
let _xssParamFilter          = "";       // capture-panel param search (right side)

function _xssEsc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;");
}

// ─── Tab switching ────────────────────────────────────────────────────────────

function xssGoTab(tab) {
  ["capture","scanning","results","dashboard"].forEach(t => {
    const btn = document.getElementById(`xss-tab-${t}`);
    const pnl = document.getElementById(`xss-panel-${t}`);
    if (btn) btn.classList.toggle("active", t === tab);
    if (pnl) pnl.style.display = t === tab ? "flex" : "none";
  });
  if (tab === "dashboard") _xssRenderDashboard();
}

// ─── XSS Mode (Stored / Reflected) ───────────────────────────────────────────

function xssSetMode(mode) {
  if (_xssMode === mode) return;

  // Block switch mid-scan
  if (_xssScanState === "running" || _xssScanState === "stopped") {
    alert("Abort or finish the current scan before switching modes.");
    return;
  }

  _xssMode = mode;

  // Update toggle button styles
  const sBtn = document.getElementById("xss-mode-btn-stored");
  const rBtn = document.getElementById("xss-mode-btn-reflected");
  if (sBtn) {
    sBtn.style.background = mode === "stored" ? "#1f6feb" : "transparent";
    sBtn.style.color      = mode === "stored" ? "#fff"    : "var(--text3)";
  }
  if (rBtn) {
    rBtn.style.background = mode === "reflected" ? "#d29922" : "transparent";
    rBtn.style.color      = mode === "reflected" ? "#fff"    : "var(--text3)";
  }

  // ── Clear scan state only — APIs stay intact ──
  if (_xssPollTimer) { clearInterval(_xssPollTimer); _xssPollTimer = null; }
  _xssJobId                = null;
  _xssScanQueue            = [];
  _xssScanQueueIdx         = 0;
  _xssCurrentScanningParam = null;
  _xssResults              = [];
  _xssCurrentJobResults    = [];
  _xssElapsed              = 0;
  _xssProbeLog             = [];
  _xssSelResultIdx         = null;
  _xssSelProbeIdx          = null;

  // Reset each entry's scan state (status → pending, clear results/ticks)
  // APIs and params are preserved so user can re-scan same APIs in new mode
  _xssEntries.forEach(e => {
    e.status        = "pending";
    e.results       = [];
    e.scannedParams = new Set();
    delete e._scanningParams;
    // Re-add to checked so Run button enables
    _xssCheckedEntryIds.add(e.id);
  });

  // Reset Results tab badge
  const rtBtn = document.getElementById("xss-tab-results");
  if (rtBtn) rtBtn.textContent = "📊 Results";

  // Re-render everything clean
  _xssRenderEntryList();
  _xssUpdateRunBtn();
  _xssUpdateStopBtn("done");

  // Clear scanning tab feed
  const feed = document.getElementById("xss-scan-feed");
  if (feed) feed.innerHTML = "";
  const scanSum = document.getElementById("xss-scan-summary");
  if (scanSum) scanSum.innerHTML = "";
  _xssSetProgress(0, "Ready", "");

  // Clear results tab
  const rdList = document.getElementById("xss-rd-list");
  if (rdList) rdList.innerHTML = "";
  const rdDetail = document.getElementById("xss-rd-detail");
  if (rdDetail) rdDetail.innerHTML = "";

  // Re-render dashboard (empty state)
  if (document.getElementById("xss-panel-dashboard")?.style.display !== "none") {
    _xssRenderDashboard();
  }

  // Update mode badges (scanning + results tabs)
  const isRefl = mode === "reflected";
  const badgeText   = isRefl ? "⚡ Reflected" : "🗃 Stored (+persist)";
  const badgeColor  = isRefl ? "#d29922" : "#79c0ff";
  const badgeBg     = isRefl ? "rgba(210,153,34,.12)"  : "rgba(31,111,235,.12)";
  const badgeBorder = isRefl ? "rgba(210,153,34,.35)"  : "rgba(31,111,235,.3)";
  const badgeTitle  = isRefl
    ? "Canary reflection in the same response (baseline-filtered)"
    : "Payload library + re-fetch original URL for persisted XSS (baseline FP filter on)";
  ["xss-mode-badge","xss-results-mode-badge"].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent       = id === "xss-mode-badge" ? badgeText + " XSS Mode" : badgeText;
    el.style.color       = badgeColor;
    el.style.background  = badgeBg;
    el.style.borderColor = badgeBorder;
    el.title             = badgeTitle;
  });

  _xssSyncScanTypeVisibility();
}

/** Quick/Full only applies to Stored mode — hide in Reflected to avoid confusion. */
function _xssSyncScanTypeVisibility() {
  const wrap = document.getElementById("xss-scan-type-wrap");
  if (!wrap) return;
  const show = _xssMode !== "reflected";
  wrap.style.display = show ? "inline-flex" : "none";
  wrap.title = show
    ? ""
    : "Scan Type applies only to Stored mode (Reflected uses a fixed canary set)";
}

// ─── Stop/Resume/Done button ──────────────────────────────────────────────────

function _xssUpdateStopBtn(state) {
  const btn      = document.getElementById("xss-stop-btn");
  const abortBtn = document.getElementById("xss-abort-btn");
  if (!btn) return;
  _xssScanState = state;
  btn.disabled  = false;
  btn.style.opacity = "1";
  switch (state) {
    case "running":
      btn.textContent       = "⏹ Stop";
      btn.style.background  = "rgba(218,54,51,.15)";
      btn.style.color       = "var(--red2)";
      btn.style.borderColor = "rgba(218,54,51,.3)";
      btn.onclick = xssStopScan;
      if (abortBtn) abortBtn.style.display = "inline-flex";
      break;
    case "stopped":
      btn.textContent       = "▶ Resume";
      btn.style.background  = "rgba(63,185,80,.15)";
      btn.style.color       = "var(--green)";
      btn.style.borderColor = "rgba(63,185,80,.35)";
      btn.onclick = xssResumeScan;
      if (abortBtn) abortBtn.style.display = "inline-flex";
      break;
    case "done":
      btn.textContent       = "✅ Done";
      btn.style.background  = "rgba(63,185,80,.10)";
      btn.style.color       = "var(--green)";
      btn.style.borderColor = "rgba(63,185,80,.25)";
      btn.disabled  = true;
      btn.style.opacity = "0.6";
      btn.onclick = null;
      if (abortBtn) abortBtn.style.display = "none";
      break;
  }
  _xssUpdateRunBtn();
}

function xssAbortScan() {
  if (!confirm("Abort scan? The current entry will be marked as failed and the remaining queue will be cleared.")) return;
  // Stop polling
  if (_xssPollTimer) { clearInterval(_xssPollTimer); _xssPollTimer = null; }
  // Tell backend to stop the current job
  if (_xssJobId) fetch(`${XSS_BASE}/xss/scan/stop/${_xssJobId}`, { method: "POST" }).catch(() => {});
  // Mark current running entry as error
  const entryId = _xssScanQueue[_xssScanQueueIdx];
  const entry   = _xssEntries.find(e => e.id === entryId);
  if (entry && entry.status === "running") {
    entry.status = "error";
    if (entry._scanningParams) delete entry._scanningParams;
  }
  // Mark all remaining in-queue entries back to pending
  for (let i = _xssScanQueueIdx + 1; i < _xssScanQueue.length; i++) {
    const e = _xssEntries.find(x => x.id === _xssScanQueue[i]);
    if (e && e.status === "in-queue") e.status = "pending";
  }
  // Clear queue and reset scan state
  _xssScanQueue    = [];
  _xssScanQueueIdx = 0;
  _xssJobId        = null;
  _xssCurrentScanningParam = null;
  _xssSetCaptureLocked(false);
  _xssUpdateStopBtn("done");
  _xssEntries.forEach(e => _xssCheckedEntryIds.add(e.id));
  _xssUpdateRunBtn();
  _xssRenderEntryList();
}

// ─── Run button ───────────────────────────────────────────────────────────────

function _xssUpdateRunBtn() {
  const btn = document.getElementById("xss-scan-btn");
  if (!btn) return;
  const scanning = _xssScanState === "running" || _xssScanState === "stopped";

  if (scanning) {
    btn.disabled      = true;
    btn.style.opacity = "0.45";
    btn.textContent   = _xssScanState === "stopped" ? "⏸ Scan paused" : "🔄 Scanning…";
    btn.title         = "Wait until the current scan finishes (or abort it) before starting another.";
    btn.onclick       = null;
    return;
  }

  const ready = _xssEntries.filter(e =>
    _xssCheckedEntryIds.has(e.id) && e.checked.size > 0
  ).length;
  btn.disabled      = ready === 0;
  btn.style.opacity = ready === 0 ? "0.45" : "1";
  btn.textContent   = `🎯 Run XSS Scan (${ready} API${ready !== 1 ? "s" : ""})`;
  btn.title         = "";
  btn.onclick       = xssStartScan;
}

function xssAddToQueue() {
  const toQueue = _xssEntries.filter(e =>
    _xssCheckedEntryIds.has(e.id) && e.checked.size > 0 &&
    (e.status === "pending" || e.status === "scanned" || e.status === "error")
  );
  if (!toQueue.length) return;
  toQueue.forEach(e => {
    e.status = "in-queue";
    _xssScanQueue.push(e.id);
  });
  _xssRenderEntryList();
  _xssUpdateRunBtn();
}

function _xssSetCaptureLocked(locked) {
  // Dim import buttons visually; Reset button locked during scan
  const resetBtn = document.getElementById("xss-reset-btn");
  if (resetBtn) { resetBtn.disabled = locked; resetBtn.style.opacity = locked ? "0.45" : "1"; }
  document.querySelectorAll(".btn-import").forEach(b => {
    b.style.opacity = locked ? "0.7" : "1";
    b.title = locked ? "Scan in progress — imported API stays pending until you add it to queue" : "";
  });
}

// ─── From AV Capture ─────────────────────────────────────────────────────────

function xssFromAV() {
  _xssErrHide();
  const reqs = (window._avState && window._avState.requests) || [];
  const list = reqs.filter(q => q.url && !_xssIsStatic(q.url));
  if (!list.length) {
    _xssErr("No requests in AV Capture. Capture some traffic in API Validator Pro first.");
    return;
  }
  // Deduplicate by method + URL
  const seen = new Set();
  _xssAvEntries = [];
  list.forEach(r => {
    const key = (r.method || "GET").toUpperCase() + ":" + r.url;
    if (seen.has(key)) return;
    seen.add(key);
    _xssAvEntries.push(r);
  });
  xssShowAvModal();
}

// ─── AV Capture modal ─────────────────────────────────────────────────────────

function xssShowAvModal() {
  const search = document.getElementById("xss-av-search");
  if (search) search.value = "";
  _xssRenderAvList("");
  const m = document.getElementById("xss-av-modal");
  if (m) m.style.display = "flex";
  setTimeout(() => { if (search) search.focus(); }, 60);
}

function xssCloseAvModal() {
  const m = document.getElementById("xss-av-modal");
  if (m) m.style.display = "none";
}

function xssSkipAvModal() {
  if (!_xssAvEntries.length) return;
  xssCloseAvModal();
  xssSelectAvReq(_xssAvEntries.length - 1);
}

// Add ALL AV entries at once
async function xssLoadAllAv() {
  xssCloseAvModal();
  for (const r of _xssAvEntries) await _xssAddEntry(_xssBuildCurl(r));
}

function xssFilterAvList(q) {
  _xssRenderAvList(q.toLowerCase());
}

function _xssRenderAvList(q) {
  const el = document.getElementById("xss-av-list");
  if (!el) return;
  const filtered = _xssAvEntries.filter(r =>
    !q || (r.url || "").toLowerCase().includes(q) || (r.method || "").toLowerCase().includes(q)
  );
  if (!filtered.length) {
    el.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text3);font-size:12px">No matching requests.</div>`;
    return;
  }
  const M_COL = { GET:"#3fb950", POST:"#79c0ff", PUT:"#ffa657", DELETE:"#f85149", PATCH:"#d29922" };
  el.innerHTML = filtered.map(r => {
    const method = (r.method || "GET").toUpperCase();
    const mCol   = M_COL[method] || "#8b949e";
    const origIdx = _xssAvEntries.indexOf(r);
    return `<div onclick="xssSelectAvReq(${origIdx})"
                 style="display:flex;align-items:flex-start;gap:10px;padding:9px 12px;
                        border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s"
                 onmouseover="this.style.background='var(--bg3)'"
                 onmouseout="this.style.background=''">
      <span style="color:${mCol};font-weight:700;font-size:10px;font-family:var(--mono);flex-shrink:0;min-width:46px;margin-top:1px">${method}</span>
      <span style="font-size:11px;color:var(--text);word-break:break-all;line-height:1.5">${_xssEsc(r.url)}</span>
    </div>`;
  }).join("");
}

async function xssSelectAvReq(idx) {
  const r = _xssAvEntries[idx];
  if (!r) return;
  xssCloseAvModal();
  await _xssAddEntry(_xssBuildCurl(r));
}

function _xssIsStatic(url) {
  return /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp)(\?|$)/i.test(url);
}

function _xssBuildCurl(req) {
  const method = (req.method || "GET").toUpperCase();
  let c = method === "GET" ? `curl '${req.url}'` : `curl -X ${method} '${req.url}'`;
  for (const [k, v] of Object.entries(req.headers || {})) {
    c += ` \\\n  -H '${k}: ${v}'`;
  }
  if (req.body) {
    const bodyStr = typeof req.body === "object" ? JSON.stringify(req.body) : String(req.body);
    if (bodyStr && bodyStr !== "null") c += ` \\\n  --data-raw '${bodyStr}'`;
  }
  return c;
}

// ─── Import cURL modal ────────────────────────────────────────────────────────

function xssShowCurlImport() {
  const m   = document.getElementById("xss-curl-modal");
  const inp = document.getElementById("xss-curl-modal-input");
  const err = document.getElementById("xss-curl-modal-error");
  if (inp) inp.value = "";
  if (err) { err.style.display = "none"; err.textContent = ""; }
  if (m) m.style.display = "flex";
  setTimeout(() => { if (inp) inp.focus(); }, 60);
}

function xssCloseCurlModal() {
  const m = document.getElementById("xss-curl-modal");
  if (m) m.style.display = "none";
}

async function xssImportCurl() {
  const inp   = document.getElementById("xss-curl-modal-input");
  const errEl = document.getElementById("xss-curl-modal-error");
  const curl  = (inp ? inp.value : "").trim();
  if (!curl) {
    if (errEl) { errEl.textContent = "Paste a cURL command first."; errEl.style.display = "block"; }
    return;
  }
  if (errEl) errEl.style.display = "none";
  const ok = await _xssAddEntry(curl);
  if (ok) xssCloseCurlModal();
  else if (errEl) {
    errEl.textContent = "Parse failed. Check the cURL command.";
    errEl.style.display = "block";
  }
}

// ─── Entry management ─────────────────────────────────────────────────────────

function _xssUUID() {
  return (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
}

async function _xssAddEntry(curl) {
  _xssErrHide();
  if (!curl) { _xssErr("No cURL to parse."); return false; }
  try {
    const r = await fetch(`${XSS_BASE}/xss/parse`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ curl }),
    });
    if (!r.ok) { _xssErr((await r.json()).detail || "Parse failed."); return false; }
    const d = await r.json();
    const entry = {
      id: _xssUUID(),
      method: d.method || "GET",
      url: d.url || "",
      curl,
      params: d.params || [],
      checked: new Set((d.params || []).map(p => p.name)),
      randomFmts: {},
      status: "pending",
      jobId: null,
      scannedParams: new Set(), // params that were actually scanned
    };
    _xssEntries.push(entry);
    _xssCheckedEntryIds.add(entry.id);
    // Always stays "pending" — user manually adds to queue via "Add to Queue" button
    _xssRenderEntryList();
    xssSelectEntry(entry.id);
    _xssUpdateRunBtn();
    return true;
  } catch(e) {
    _xssErr("Could not reach XSS backend (port 8790).");
    return false;
  }
}

function _xssRenderEntryList() {
  const empty   = document.getElementById("xss-entry-empty");
  const listEl  = document.getElementById("xss-entry-list");
  const countEl = document.getElementById("xss-entry-count");
  if (!listEl) return;

  if (!_xssEntries.length) {
    if (empty)  empty.style.display  = "flex";
    if (listEl) listEl.style.display = "none";
    if (countEl) countEl.textContent = "";
    return;
  }
  if (empty)  empty.style.display  = "none";
  if (listEl) listEl.style.display = "block";
  if (countEl) countEl.textContent = `(${_xssEntries.length})`;

  const M_COL = { GET:"#3fb950", POST:"#79c0ff", PUT:"#ffa657", DELETE:"#f85149", PATCH:"#d29922" };
  listEl.innerHTML = _xssEntries.map(e => {
    const mCol = M_COL[e.method] || "#8b949e";
    const chk  = _xssCheckedEntryIds.has(e.id) ? "checked" : "";
    const sel  = _xssSelEntryId === e.id ? " xss-entry-selected" : "";
    const badge = `<span class="xss-status-badge xss-status-${e.status}">${e.status}</span>`;
    const xssCnt = e.results && e.results.filter(r => r.confirmed).length;
    const xssBadge = (e.status === "scanned" && xssCnt > 0)
      ? `<span style="font-size:9px;font-weight:700;color:#f85149;flex-shrink:0">⚡${xssCnt}</span>` : "";
    return `<div class="xss-entry-row${sel}" onclick="xssEntryRowClick('${e.id}')">
      <input type="checkbox" ${chk} onclick="event.stopPropagation()"
             onchange="xssToggleEntryCheck('${e.id}',this.checked)"
             style="accent-color:var(--blue);flex-shrink:0">
      <span style="color:${mCol};font-weight:700;font-size:10px;font-family:var(--mono);flex-shrink:0;min-width:38px">${e.method}</span>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);font-size:11px"
            title="${_xssEsc(e.url)}">${_xssEsc(e.url)}</span>
      ${xssBadge}
      ${badge}
    </div>`;
  }).join("");
}

function xssSelectEntry(id) {
  _xssSelEntryId = id;
  const entry = _xssEntries.find(e => e.id === id);
  _xssRenderEntryList(); // update highlight

  const placeholder = document.getElementById("xss-entry-config-placeholder");
  const content     = document.getElementById("xss-entry-config-content");
  if (!entry) {
    if (placeholder) placeholder.style.display = "flex";
    if (content)     content.style.display     = "none";
    return;
  }
  if (placeholder) placeholder.style.display = "none";
  if (content)     content.style.display     = "flex";

  const title = document.getElementById("xss-cfg-title");
  if (title) title.textContent = `${entry.method} ${entry.url}`;

  _xssRenderParamsList({ params: entry.params, url: entry.url, method: entry.method, header_count: 0 }, entry);
}

function xssEntryRowClick(id) {
  const wasChecked = _xssCheckedEntryIds.has(id);
  xssToggleEntryCheck(id, !wasChecked);
  xssSelectEntry(id);
}

function xssToggleEntryCheck(id, on) {
  if (on) _xssCheckedEntryIds.add(id); else _xssCheckedEntryIds.delete(id);
  _xssRenderEntryList();
  _xssUpdateRunBtn();
}

function _xssSelectAllEntries(on) {
  _xssEntries.forEach(e => {
    if (on) _xssCheckedEntryIds.add(e.id); else _xssCheckedEntryIds.delete(e.id);
  });
  _xssRenderEntryList();
  _xssUpdateRunBtn();
}

function xssRemoveEntry(id, evt) {
  if (evt) evt.stopPropagation();
  _xssEntries = _xssEntries.filter(e => e.id !== id);
  _xssCheckedEntryIds.delete(id);
  if (_xssSelEntryId === id) {
    _xssSelEntryId = _xssEntries.length ? _xssEntries[_xssEntries.length - 1].id : null;
    if (_xssSelEntryId) xssSelectEntry(_xssSelEntryId);
    else {
      const ph = document.getElementById("xss-entry-config-placeholder");
      const ct = document.getElementById("xss-entry-config-content");
      if (ph) ph.style.display = "flex";
      if (ct) ct.style.display = "none";
    }
  }
  _xssRenderEntryList();
  _xssUpdateRunBtn();
}

function _xssErr(msg) {
  const e = document.getElementById("xss-parse-error");
  if (e) { e.textContent = "⚠ " + msg; e.style.display = "inline"; }
}
function _xssErrHide() {
  const e = document.getElementById("xss-parse-error");
  if (e) { e.style.display = "none"; e.textContent = ""; }
}

// ─── Params list rendering ────────────────────────────────────────────────────

function _xssVisibleParams(params) {
  const q = (_xssParamFilter || "").trim().toLowerCase();
  if (!q) return params || [];
  return (params || []).filter(p =>
    String(p.name || "").toLowerCase().includes(q) ||
    String(p.location || "").toLowerCase().includes(q)
  );
}

function xssFilterParams(val) {
  _xssParamFilter = val == null ? "" : String(val);
  const inp = document.getElementById("xss-params-filter");
  if (inp && inp.value !== _xssParamFilter) inp.value = _xssParamFilter;
  const entry = _xssEntries.find(e => e.id === _xssSelEntryId);
  _xssRenderParamsList(null, entry);
}

function _xssRenderParamsList(d, entry) {
  if (!entry) entry = _xssEntries.find(e => e.id === _xssSelEntryId);
  const list = document.getElementById("xss-params-list");
  const cnt  = document.getElementById("xss-params-count");
  const inp  = document.getElementById("xss-params-filter");
  if (inp && inp.value !== _xssParamFilter) inp.value = _xssParamFilter;

  const params = entry ? entry.params : (d.params || []);
  const visible = _xssVisibleParams(params);
  if (cnt) {
    const n = params.length;
    const v = visible.length;
    const q = (_xssParamFilter || "").trim();
    cnt.textContent = q && v !== n
      ? `${v} / ${n} param${n !== 1 ? "s" : ""}`
      : `${n} param${n !== 1 ? "s" : ""}`;
  }

  if (!list) return;
  if (!params.length) {
    list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:12px">No injectable parameters found.</div>`;
    return;
  }
  if (!visible.length) {
    list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:12px">No params match “${_xssEsc(_xssParamFilter.trim())}”.</div>`;
    return;
  }
  list.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr style="color:var(--text3);border-bottom:1px solid var(--border);background:var(--bg2);position:sticky;top:0;z-index:1">
          <th style="padding:6px 8px;text-align:left;width:24px"></th>
          <th style="padding:6px 8px;text-align:left">Parameter</th>
          <th style="padding:6px 8px;text-align:left;width:60px">Loc</th>
          <th style="padding:6px 8px;text-align:left">Random Format</th>
        </tr>
      </thead>
      <tbody>${visible.map(p => _xssParamRow(p, entry)).join("")}</tbody>
    </table>`;
}

function _xssParamRow(p, entry) {
  const chk       = entry && entry.checked.has(p.name) ? "checked" : "";
  const fmtVal    = entry ? (entry.randomFmts[p.name] || "") : "";
  const locCol    = p.location === "query" ? "#3fb950" : p.location === "body" ? "#79c0ff" : "#ffa657";
  const eid       = entry ? entry.id : "";
  const isScanned = entry && entry.scannedParams && entry.scannedParams.has(p.name);
  const isCurrent = entry && entry._scanningParams && entry._scanningParams.has(p.name)
                    && _xssCurrentScanningParam === p.name;
  const isQueued  = entry && entry._scanningParams && entry._scanningParams.has(p.name)
                    && !isCurrent && !isScanned;
  const indicator = isCurrent
    ? `<span title="Scanning now…" style="color:#d29922;font-size:10px;margin-left:5px;display:inline-block;animation:xss-pulse .8s ease-in-out infinite">⚡</span>`
    : isScanned
    ? `<span title="Already scanned" style="color:#3fb950;font-size:11px;margin-left:4px;font-weight:700">✓</span>`
    : isQueued
    ? `<span title="In scan queue" style="color:#d29922;font-size:9px;margin-left:4px;opacity:.6">●</span>`
    : "";
  const isChecked = entry && entry.checked.has(p.name);
  return `<tr style="border-bottom:1px solid var(--border);cursor:pointer"
              onclick="xssParamRowClick('${eid}','${_xssEsc(p.name)}')">
    <td style="padding:5px 8px">
      <input type="checkbox" ${chk}
             onclick="event.stopPropagation()"
             onchange="xssToggleParam('${eid}','${_xssEsc(p.name)}',this.checked)"
             style="accent-color:var(--blue)">
    </td>
    <td style="padding:5px 8px"><code style="color:var(--text);font-size:11px">${_xssEsc(p.name)}</code>${indicator}</td>
    <td style="padding:5px 8px">
      <span style="color:${locCol};font-size:9px;font-weight:700">${p.location.toUpperCase()}</span>
    </td>
    <td style="padding:5px 8px" onclick="event.stopPropagation()">
      <input type="text" value="${_xssEsc(fmtVal)}"
        placeholder="e.g. {alphanum:8}"
        oninput="_xssSetFmt('${eid}','${_xssEsc(p.name)}',this.value)"
        style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;
               color:var(--text);font-family:var(--mono);font-size:10px;padding:2px 6px">
    </td>
  </tr>`;
}

// Lightweight refresh: only re-renders the params table body (updates ticks/indicators
// without resetting scroll or checkbox state lost on full re-render)
function _xssRefreshParamTicks(entry) {
  const tbody = document.querySelector("#xss-params-list tbody");
  if (!tbody || !entry) return;
  const rows = tbody.querySelectorAll("tr");
  rows.forEach(row => {
    const codeEl = row.querySelector("td:nth-child(2) code");
    if (!codeEl) return;
    const pname   = codeEl.textContent;
    const isScanned = entry.scannedParams && entry.scannedParams.has(pname);
    const isCurrent = entry._scanningParams && entry._scanningParams.has(pname)
                      && _xssCurrentScanningParam === pname;
    const isQueued  = entry._scanningParams && entry._scanningParams.has(pname)
                      && !isCurrent && !isScanned;
    // Remove any existing indicator span and re-insert
    const existing = row.querySelector("td:nth-child(2) span");
    if (existing) existing.remove();
    const td = row.querySelector("td:nth-child(2)");
    if (!td) return;
    if (isCurrent) {
      td.insertAdjacentHTML("beforeend",
        `<span title="Scanning now…" style="color:#d29922;font-size:10px;margin-left:5px;display:inline-block;animation:xss-pulse .8s ease-in-out infinite">⚡</span>`);
    } else if (isScanned) {
      td.insertAdjacentHTML("beforeend",
        `<span title="Already scanned" style="color:#3fb950;font-size:11px;margin-left:4px;font-weight:700">✓</span>`);
    } else if (isQueued) {
      td.insertAdjacentHTML("beforeend",
        `<span title="In scan queue" style="color:#d29922;font-size:9px;margin-left:4px;opacity:.6">●</span>`);
    }
  });
}

function xssParamRowClick(entryId, name) {
  const entry = _xssEntries.find(e => e.id === entryId);
  if (!entry) return;
  const on = !entry.checked.has(name);
  if (on) entry.checked.add(name); else entry.checked.delete(name);
  // Sync the checkbox in the DOM without full re-render
  const rows = document.querySelectorAll("#xss-params-list tbody tr");
  rows.forEach(row => {
    const codeEl = row.querySelector("td:nth-child(2) code");
    if (codeEl && codeEl.textContent === name) {
      const cb = row.querySelector("input[type=checkbox]");
      if (cb) cb.checked = on;
    }
  });
  _xssUpdateRunBtn();
}

function xssToggleParam(entryId, name, on) {
  const entry = _xssEntries.find(e => e.id === entryId);
  if (!entry) return;
  if (on) entry.checked.add(name); else entry.checked.delete(name);
  _xssUpdateRunBtn();
}

function _xssSelectAll(on) {
  const entry = _xssEntries.find(e => e.id === _xssSelEntryId);
  if (!entry) return;
  const targets = _xssVisibleParams(entry.params);
  targets.forEach(p => { if (on) entry.checked.add(p.name); else entry.checked.delete(p.name); });
  _xssRenderParamsList(null, entry);
  _xssUpdateRunBtn();
}

function _xssSetFmt(entryId, name, val) {
  const entry = _xssEntries.find(e => e.id === entryId);
  if (!entry) return;
  if (val.trim()) entry.randomFmts[name] = val.trim();
  else delete entry.randomFmts[name];
}

// ─── Start scan (multi-entry queue) ──────────────────────────────────────────

function xssStartScan() {
  if (_xssScanState === "running" || _xssScanState === "stopped") return;
  _xssErrHide();
  const ready = _xssEntries.filter(e => _xssCheckedEntryIds.has(e.id) && e.checked.size > 0);
  if (!ready.length) { _xssErr("Select at least one API with params to test."); return; }

  const scanTypeEl = document.getElementById("xss-scan-type-sel");
  _xssScanType = scanTypeEl ? scanTypeEl.value : "quick";

  // Mark queued entries as in-queue
  ready.forEach(e => { e.status = "in-queue"; e.jobId = null; });
  _xssRenderEntryList();
  _xssSetCaptureLocked(true);

  // Build queue
  _xssScanQueue    = ready.map(e => e.id);
  _xssScanQueueIdx = 0;

  // Reset global accumulated state
  _xssResults = []; _xssFilter = "ALL"; _xssProbeLog = []; _xssSelResultIdx = null;

  // Reset UI
  xssGoTab("scanning");
  _xssUpdateStopBtn("running");
  const feed = document.getElementById("xss-probe-list");
  if (feed) feed.innerHTML = "";
  xssCloseProbeDetail();
  const cards = document.getElementById("xss-summary-cards");
  if (cards) cards.innerHTML = "";
  const tbody = document.getElementById("xss-results-tbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text3)">Scan in progress…</td></tr>`;
  const det = document.getElementById("xss-result-detail");
  if (det) det.style.display = "none";
  const title = document.getElementById("xss-results-title");
  if (title) title.textContent = "Results";

  _xssRunNextInQueue();
}

async function _xssRunNextInQueue() {
  if (_xssScanQueueIdx >= _xssScanQueue.length) {
    _xssUpdateStopBtn("done");
    _xssSetCaptureLocked(false);
    // Re-check all entries so "Run XSS Scan" button re-enables for re-scanning
    _xssEntries.forEach(e => _xssCheckedEntryIds.add(e.id));
    _xssUpdateRunBtn();
    const rtBtn = document.getElementById("xss-tab-results");
    const xssC  = _xssResults.filter(r => r.confirmed).length;
    if (rtBtn) rtBtn.textContent = xssC > 0 ? `📊 Results · ⚡${xssC}` : "📊 Results";
    // Don't force tab switch — let user stay on current tab
    return;
  }

  const entryId = _xssScanQueue[_xssScanQueueIdx];
  const entry   = _xssEntries.find(e => e.id === entryId);
  if (!entry) { _xssScanQueueIdx++; _xssRunNextInQueue(); return; }

  const total   = _xssScanQueue.length;
  const current = _xssScanQueueIdx + 1;
  _xssSetProgress(0, `API ${current}/${total}: ${entry.url}`, "");

  entry.status = "running";
  entry._scanningParams = new Set([...entry.checked]); // snapshot params being scanned now
  _xssRenderEntryList();

  const scanTypeEl = document.getElementById("xss-scan-type-sel");
  const delayEl    = document.getElementById("xss-delay-input");
  const timeoutEl  = document.getElementById("xss-timeout-input");
  const scanType   = scanTypeEl ? scanTypeEl.value : "quick";
  const delay      = delayEl ? (parseFloat(delayEl.value) || 0.3) : 0.3;
  const reqTimeout = timeoutEl ? (parseInt(timeoutEl.value) || 10) : 10;
  const selected   = entry.params.filter(p => entry.checked.has(p.name));

  try {
    const r = await fetch(`${XSS_BASE}/xss/scan/start`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        curl: entry.curl, selected_params: selected,
        random_formats: entry.randomFmts, scan_type: scanType, delay, timeout: reqTimeout,
        mode: _xssMode,
      }),
    });
    if (!r.ok) {
      entry.status = "error";
      _xssRenderEntryList();
      _xssScanQueueIdx++; _xssRunNextInQueue();
      return;
    }
    const d = await r.json();
    entry.jobId = d.job_id;
    _xssJobId   = d.job_id;
    _xssProbeLog = []; _xssCurrentJobResults = [];
    const probeFeed = document.getElementById("xss-probe-list");
    if (probeFeed) probeFeed.innerHTML = "";
    _xssPollTimer = setInterval(_xssPoll, 800);
  } catch(e) {
    entry.status = "error";
    _xssRenderEntryList();
    _xssScanQueueIdx++; _xssRunNextInQueue();
  }
}

// ─── Stop / Resume ────────────────────────────────────────────────────────────

function xssStopScan() {
  if (_xssPollTimer) { clearInterval(_xssPollTimer); _xssPollTimer = null; }
  if (_xssJobId) fetch(`${XSS_BASE}/xss/scan/pause/${_xssJobId}`, { method: "POST" }).catch(() => {});
  _xssUpdateStopBtn("stopped");
  _xssSetCaptureLocked(false); // allow browsing capture while paused
  _xssUpdateRunBtn();
}

async function xssResumeScan() {
  if (!_xssJobId) return;
  _xssUpdateStopBtn("running");
  _xssSetCaptureLocked(true);
  _xssUpdateRunBtn();
  try {
    await fetch(`${XSS_BASE}/xss/scan/resume/${_xssJobId}`, { method: "POST" });
    _xssPollTimer = setInterval(_xssPoll, 800);
  } catch(e) {
    _xssUpdateStopBtn("stopped");
    _xssSetCaptureLocked(false);
    _xssUpdateRunBtn();
  }
}

// ─── Progress helpers ─────────────────────────────────────────────────────────

function _xssSetProgress(pct, label, liveBadge) {
  const fill  = document.getElementById("xss-progress-fill");
  const pctEl = document.getElementById("xss-progress-pct");
  const lbl   = document.getElementById("xss-progress-label");
  const live  = document.getElementById("xss-issue-live");
  if (fill)  fill.style.width   = pct + "%";
  if (pctEl) pctEl.textContent  = Math.round(pct) + "%";
  if (lbl)   { lbl.textContent  = label; lbl.title = label; }
  if (live)  live.textContent   = liveBadge;
}

// ─── Poll ─────────────────────────────────────────────────────────────────────

async function _xssPoll() {
  if (!_xssJobId) return;
  try {
    const r = await fetch(`${XSS_BASE}/xss/scan/progress/${_xssJobId}`);
    const d = await r.json();

    if (d.error) {
      clearInterval(_xssPollTimer); _xssPollTimer = null;
      _xssUpdateStopBtn("done");
      return;
    }

    // Per-job results (replace per-entry slice, keep others)
    const curEntryId = _xssScanQueue[_xssScanQueueIdx];
    const curEntry   = _xssEntries.find(e => e.id === curEntryId);
    const jobResults = d.results || [];
    _xssCurrentJobResults = jobResults; // scoped to current job for probe detail lookup
    // Rebuild _xssResults: results from already-scanned entries + current job
    const prevResults = _xssEntries
      .filter(e => e.status === "scanned" && e.results)
      .flatMap(e => e.results);
    _xssResults = [...prevResults, ...jobResults];

    const cur   = _xssScanQueueIdx + 1;
    const tot   = _xssScanQueue.length;
    const pct   = d.progress || 0;
    const apiLbl = curEntry ? `[${cur}/${tot}] ${curEntry.method} ${curEntry.url}` : `[${cur}/${tot}]`;
    const label = `${apiLbl} · ${d.completed}/${d.total} · ${d.xss_count} XSS · ${d.elapsed}s` +
                  (d.stop_reason === "401_unauthorized" ? " · ⚠ Token expired!" : "");
    const badge = d.xss_count > 0 ? `⚡ ${d.xss_count} XSS` : "";
    _xssSetProgress(pct, label, badge);

    // Accumulate feed
    if (d.feed && d.feed.length) {
      _xssProbeLog = d.feed;
      _xssRenderProbeList();
      // Track the param currently being scanned (last probe in feed)
      const lastProbe = d.feed[d.feed.length - 1];
      _xssCurrentScanningParam = lastProbe ? lastProbe.param : null;
      // Live-update param list ticks if the scanning entry is currently selected
      const scanningEntryId = _xssScanQueue[_xssScanQueueIdx];
      if (scanningEntryId && scanningEntryId === _xssSelEntryId) {
        const scanningEntry = _xssEntries.find(e => e.id === scanningEntryId);
        if (scanningEntry) _xssRefreshParamTicks(scanningEntry);
      }
    }

    // Update results and dashboard
    _xssRenderResultsSummary(d);
    _xssRenderDashboard();

    // Update results tab title
    const title = document.getElementById("xss-results-title");
    if (title) title.textContent = `Results · ${_xssResults.length} tests · ${d.xss_count || 0} XSS`;

    if (d.status === "done" || d.status === "error") {
      clearInterval(_xssPollTimer); _xssPollTimer = null;

      // Mark current entry done
      const entryId = _xssScanQueue[_xssScanQueueIdx];
      const entry   = _xssEntries.find(e => e.id === entryId);
      if (entry) {
        entry.status  = d.status === "done" ? "scanned" : "error";
        entry.results = [..._xssCurrentJobResults]; // only this entry's results, not accumulated
        // Record which params were just scanned
        if (entry._scanningParams) {
          entry._scanningParams.forEach(p => entry.scannedParams.add(p));
          delete entry._scanningParams;
        }
        // Refresh param list so green ticks appear without needing to re-click
        _xssCurrentScanningParam = null;
        if (entry.id === _xssSelEntryId) _xssRefreshParamTicks(entry);
      }
      _xssRenderEntryList();

      // Advance queue
      _xssScanQueueIdx++;
      _xssRunNextInQueue();
    }
  } catch(e) {
    clearInterval(_xssPollTimer); _xssPollTimer = null;
    const entryId = _xssScanQueue[_xssScanQueueIdx];
    const entry   = _xssEntries.find(e => e.id === entryId);
    if (entry) entry.status = "error";
    _xssRenderEntryList();
    _xssScanQueueIdx++;
    _xssRunNextInQueue();
  }
}

// ─── Probe list ───────────────────────────────────────────────────────────────

function _xssRenderProbeList() {
  const el  = document.getElementById("xss-probe-list");
  const cnt = document.getElementById("xss-probe-count");
  if (!el) return;
  if (cnt) cnt.textContent = `(${_xssProbeLog.length})`;

  // Show current API label in probe section header
  const curEntryId = _xssScanQueue[_xssScanQueueIdx];
  const curEntry   = _xssEntries.find(e => e.id === curEntryId);
  const apiLabelEl = document.getElementById("xss-probe-api-label");
  if (apiLabelEl && curEntry) {
    const M_COL = { GET:"#3fb950",POST:"#79c0ff",PUT:"#ffa657",DELETE:"#f85149",PATCH:"#d29922" };
    const mCol  = M_COL[curEntry.method] || "#8b949e";
    const cur   = _xssScanQueueIdx + 1;
    const tot   = _xssScanQueue.length;
    apiLabelEl.innerHTML = `<span style="color:${mCol};font-weight:700;margin-right:4px">${curEntry.method}</span>` +
      `<span style="color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_xssEsc(curEntry.url)}">${_xssEsc(curEntry.url)}</span>` +
      `<span style="color:var(--text3);margin-left:6px;flex-shrink:0">(${cur}/${tot})</span>`;
  }

  el.innerHTML = _xssProbeLog.slice().reverse().map(f => {
    const sc  = (typeof f.status === "number" && f.status >= 200 && f.status < 300) ? "var(--green)"
              : (typeof f.status === "number" && f.status >= 400 && f.status < 500) ? "#d29922"
              : "var(--red)";
    const sel = _xssSelProbeIdx === f.idx ? " xss-probe-selected" : "";
    return `<div class="xss-probe-row${sel}" onclick="xssSelectProbe(${f.idx})">
      <span style="flex-shrink:0">${f.dot}</span>
      <span style="color:#79c0ff;min-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_xssEsc(f.param)}</span>
      <span style="color:var(--text3);min-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_xssEsc(f.cat)}</span>
      <span style="color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_xssEsc(f.payload_short)}</span>
      <span style="color:${sc};font-weight:700;min-width:34px;text-align:right;flex-shrink:0">${_xssEsc(f.status)}</span>
    </div>`;
  }).join("");
}

// ─── Probe detail panel ───────────────────────────────────────────────────────

function _xssHighlightPayload(body, sentPayload) {
  if (!body)         return "<em style='color:var(--text3)'>(no body)</em>";
  if (!sentPayload)  return _xssEsc(body);

  const MARK = `<mark style="background:#d29922;color:#0d1117;border-radius:2px;padding:0 1px">`;

  // Helper: search raw body for needle, wrap found span in mark
  function tryMark(needle) {
    const i = body.indexOf(needle);
    if (i === -1) return null;
    return _xssEsc(body.slice(0, i)) + MARK + _xssEsc(needle) + "</mark>" + _xssEsc(body.slice(i + needle.length));
  }

  // Try 1: exact match (works for URL-injected params)
  let result = tryMark(sentPayload);
  if (result) return result;

  // Try 2: JSON-escaped variant (body came from json.dumps — double-quotes become \")
  const jsonEscaped = sentPayload.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  result = tryMark(jsonEscaped);
  if (result) return result;

  // Try 3: partial match on first 30 chars (handles minor encoding diffs)
  const partial = sentPayload.slice(0, 30);
  if (partial.length >= 8) {
    const i = body.indexOf(partial);
    if (i !== -1) {
      // Highlight from start of partial to estimated end
      const end = Math.min(i + sentPayload.length + 20, body.length);
      const snippet = body.slice(i, end);
      return _xssEsc(body.slice(0, i)) + MARK + _xssEsc(snippet) + "</mark>" + _xssEsc(body.slice(end));
    }
  }

  return _xssEsc(body);
}

function xssSelectProbe(idx) {
  // Always look up from current job results to avoid idx collisions across entries
  const r = _xssCurrentJobResults.find(x => x.idx === idx);
  if (!r) return;

  _xssSelProbeIdx = idx;

  const placeholder = document.getElementById("xss-probe-detail-placeholder");
  const panels      = document.getElementById("xss-probe-detail-panels");
  const reqTitle    = document.getElementById("xss-probe-req-title");
  const reqBody     = document.getElementById("xss-probe-req-body");
  const respBody    = document.getElementById("xss-probe-resp-body");
  const respStatus  = document.getElementById("xss-probe-resp-status");
  const curlBtn     = document.getElementById("xss-copy-curl-btn");

  if (placeholder) placeholder.style.display = "none";
  if (panels)      panels.style.display      = "flex";
  if (reqTitle)    reqTitle.textContent = `📤 REQUEST — ${r.param} · ${r.category}`;

  // Build request text: URL line first (payload may be injected there for query params),
  // then body. Highlight payload wherever it appears.
  const urlLine  = r.sent_url  ? `${r.method || "GET"} ${r.sent_url}` : "";
  const bodyPart = r.sent_body || "";
  const reqText  = urlLine + (urlLine && bodyPart ? "\n\n" : "") + (bodyPart || (urlLine ? "" : "(no body)"));
  // Use sent_payload (actual marked value injected) for accurate highlighting
  if (reqBody) reqBody.innerHTML = _xssHighlightPayload(reqText, r.sent_payload || r.payload);

  if (respBody)   respBody.textContent    = (r.response_body || "").slice(0, 6000) || "(empty)";
  if (respStatus) respStatus.textContent  = String(r.status);
  if (curlBtn)    curlBtn.setAttribute("data-curl", r.sent_curl || "");

  _xssRenderProbeList();
}

function xssCloseProbeDetail() {
  _xssSelProbeIdx = null;
  const placeholder = document.getElementById("xss-probe-detail-placeholder");
  const panels      = document.getElementById("xss-probe-detail-panels");
  if (placeholder) placeholder.style.display = "flex";
  if (panels)      panels.style.display      = "none";
  _xssRenderProbeList();
}

function xssCopyProbeCurl() {
  const btn  = document.getElementById("xss-copy-curl-btn");
  const curl = btn ? (btn.getAttribute("data-curl") || "") : "";
  if (!curl) return;
  const orig = btn ? btn.textContent : "";
  navigator.clipboard.writeText(curl)
    .then(() => {
      if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
    })
    .catch(() => {
      const ta = document.createElement("textarea");
      ta.value = curl; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
    });
}

function xssCopyResultCurl() {
  const btn  = document.getElementById("xss-rd-copy-curl-btn");
  const curl = btn ? (btn.getAttribute("data-curl") || "") : "";
  if (!curl) return;
  const orig = btn ? btn.textContent : "";
  navigator.clipboard.writeText(curl)
    .then(() => {
      if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
    })
    .catch(() => {
      const ta = document.createElement("textarea");
      ta.value = curl; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
    });
}

function xssCopyResultUrl() {
  const btn = document.getElementById("xss-rd-copy-url-btn");
  const url = btn ? (btn.getAttribute("data-url") || "") : "";
  if (!url) return;
  const orig = btn ? btn.textContent : "";
  navigator.clipboard.writeText(url)
    .then(() => {
      if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
    })
    .catch(() => {
      const ta = document.createElement("textarea");
      ta.value = url; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
    });
}

// ─── Results summary cards ────────────────────────────────────────────────────

function _xssRenderResultsSummary(d) {
  if (d && d.elapsed) _xssElapsed = d.elapsed;
  // Keep results-mode-badge in sync
  const isRefl = _xssMode === "reflected";
  const rmb = document.getElementById("xss-results-mode-badge");
  if (rmb) {
    rmb.textContent       = isRefl ? "⚡ Reflected" : "🗃 Stored (+persist)";
    rmb.title             = isRefl
      ? "Canary reflection in the same response (baseline-filtered)"
      : "Payload library + re-fetch original URL for persisted XSS (baseline FP filter on)";
    rmb.style.color       = isRefl ? "#d29922" : "#79c0ff";
    rmb.style.background  = isRefl ? "rgba(210,153,34,.12)"  : "rgba(31,111,235,.12)";
    rmb.style.borderColor = isRefl ? "rgba(210,153,34,.35)"  : "rgba(31,111,235,.3)";
  }
  const f     = _xssResults;
  const xss   = f.filter(r => r.confirmed).length;
  const waf   = f.filter(r => r.reason === "waf_block").length;
  const err   = f.filter(r => r.status === "ERROR").length;
  const clean = f.length - xss - waf - err;

  const cards = document.getElementById("xss-summary-cards");
  if (cards) {
    cards.innerHTML = `
      <div class="as-sev-card" style="border:1px solid rgba(248,81,73,.3)">
        <div style="font-size:20px;font-weight:800;color:#f85149">${xss}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">XSS FOUND</div>
      </div>
      <div class="as-sev-card" style="border:1px solid rgba(63,185,80,.25)">
        <div style="font-size:20px;font-weight:800;color:var(--green)">${clean}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">CLEAN</div>
      </div>
      <div class="as-sev-card" style="border:1px solid var(--border)">
        <div style="font-size:20px;font-weight:800;color:var(--text2)">${waf}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">WAF BLOCKED</div>
      </div>
      <div class="as-sev-card" style="border:1px solid rgba(210,153,34,.25)">
        <div style="font-size:20px;font-weight:800;color:#d29922">${err}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">ERRORS</div>
      </div>
      <div class="as-sev-card" style="border:1px solid var(--border)">
        <div style="font-size:20px;font-weight:800;color:var(--text)">${f.length}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">TOTAL</div>
      </div>
      <div class="as-sev-card" style="border:1px solid var(--border)">
        <div style="font-size:20px;font-weight:800;color:var(--text)">${d.elapsed || 0}s</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">DURATION</div>
      </div>`;
  }

  _xssRenderTable();
}

// ─── Filter + table ───────────────────────────────────────────────────────────

function xssFilter(k) {
  _xssFilter = k;
  document.querySelectorAll("#xss-filter-row .as-filter-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-f") === k);
  });
  _xssRenderTable();
}

function _xssRenderTable() {
  const tbody = document.getElementById("xss-results-tbody");
  if (!tbody) return;

  let rows = _xssResults;
  if      (_xssFilter === "XSS")   rows = rows.filter(r => r.confirmed);
  else if (_xssFilter === "WAF")   rows = rows.filter(r => r.reason === "waf_block");
  else if (_xssFilter === "CLEAN") rows = rows.filter(r => !r.confirmed && r.reason !== "waf_block" && r.status !== "ERROR");
  else if (_xssFilter === "ERROR") rows = rows.filter(r => r.status === "ERROR");

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:24px">No results for this filter.</td></tr>`;
    return;
  }

  const CTX_COL = {
    js_context:"#ffa657", css_context:"#d29922",
    attr_context:"#79c0ff", html_context:"#3fb950",
    unknown:"#6e7681", blocked:"#6e7681",
  };

  tbody.innerHTML = rows.map((r, i) => {
    const stc = (typeof r.status === "number" && r.status >= 200 && r.status < 300) ? "#3fb950"
              : (typeof r.status === "number" && r.status >= 400 && r.status < 500) ? "#d29922" : "#f85149";
    let badge, badgeBg;
    if (r.confirmed) {
      const conf = r.confidence;
      badgeBg = conf === "HIGH" ? "#f85149" : conf === "MEDIUM" ? "#d29922" : conf === "LOW" ? "#58a6ff" : "#f85149";
      badge   = conf && conf !== "NONE" ? `XSS·${conf}` : "XSS";
    } else if (r.reason === "waf_block") { badge = "BLOCKED"; badgeBg = "#6e7681"; }
    else if (r.status === "ERROR")     { badge = "ERROR";   badgeBg = "#d29922"; }
    else                               { badge = "CLEAN";   badgeBg = "#1f6feb"; }
    const ctxCol  = CTX_COL[r.context] || "#8b949e";
    const origIdx = _xssResults.indexOf(r);
    const hl = _xssSelResultIdx === origIdx ? "background:rgba(88,166,255,.08);" : "";
    return `
      <tr class="mt-result-row" onclick="xssSelectResult(${origIdx})" style="cursor:pointer;${hl}">
        <td style="color:var(--text3);font-family:var(--mono);font-size:11px;padding:7px 8px">${r.idx}</td>
        <td style="padding:7px 8px">
          <code style="color:#79c0ff;font-size:11px">${_xssEsc(r.param)}</code>
          <span style="color:var(--text3);font-size:10px"> (${r.location})</span>
        </td>
        <td style="padding:7px 8px"><span style="color:var(--text2);font-size:10px">${_xssEsc(r.category)}</span></td>
        <td style="padding:7px 8px"><code style="font-size:10px;color:var(--text2)">${_xssEsc(r.payload.length > 60 ? r.payload.slice(0,60) + "…" : r.payload)}</code></td>
        <td style="padding:7px 8px"><span style="color:${stc};font-family:var(--mono);font-size:11px;font-weight:700">${_xssEsc(r.status)}</span></td>
        <td style="padding:7px 8px"><span style="color:${ctxCol};font-size:10px;font-weight:600">${r.context}</span></td>
        <td style="padding:7px 8px"><span style="background:${badgeBg}22;color:${badgeBg};border:1px solid ${badgeBg}44;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">${badge}</span></td>
      </tr>`;
  }).join("");
}

// ─── Result detail panel ──────────────────────────────────────────────────────

function xssSelectResult(idx) {
  if (_xssSelResultIdx === idx) { _xssCloseDetail(); return; }
  const r = _xssResults[idx];
  if (!r) return;
  _xssSelResultIdx = idx;

  const detail      = document.getElementById("xss-result-detail");
  const reqTitle    = document.getElementById("xss-rd-req-title");
  const reqBody     = document.getElementById("xss-rd-req-body");
  const respBody    = document.getElementById("xss-rd-resp-body");
  const curlBtn     = document.getElementById("xss-rd-copy-curl-btn");
  const urlBtn      = document.getElementById("xss-rd-copy-url-btn");
  const confLabel = (r.confidence && r.confidence !== "NONE") ? ` · ${r.confidence}` : "";
  const reasonLbl = r.reason === "stored_persist_marker" ? " · STORED persist"
                  : (r.reason || "").startsWith("marker_") ? " · reflect"
                  : r.reason ? ` · ${r.reason}` : "";
  if (reqTitle) reqTitle.textContent =
    `📤 REQUEST — ${r.param} · ${r.category} · ${r.status}${confLabel}${reasonLbl}`;
  if (reqBody)  reqBody.textContent  = r.sent_body || "(no body)";
  if (respBody) respBody.textContent = (r.response_body || "").slice(0, 3000) || "(empty)";
  if (curlBtn)  curlBtn.setAttribute("data-curl", r.sent_curl || "");
  // Show "Copy URL" only when there's a meaningful test URL (GET reflected, query injection)
  if (urlBtn) {
    const hasUrl = r.sent_url && r.sent_url !== (r.sent_url.split("?")[0]);
    urlBtn.setAttribute("data-url", r.sent_url || "");
    urlBtn.style.display = r.sent_url ? "inline-flex" : "none";
  }
  if (detail)   detail.style.display = "flex";

  // Re-render table to update highlight
  _xssRenderTable();
}

function _xssCloseDetail() {
  _xssSelResultIdx = null;
  const detail = document.getElementById("xss-result-detail");
  if (detail) detail.style.display = "none";
  _xssRenderTable();
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

function _xssRenderDashboard() {
  const meta    = document.getElementById("xss-dash-meta");
  const content = document.getElementById("xss-dash-content");
  if (!content) return;

  const f = _xssResults;
  if (!f.length) {
    if (meta) meta.textContent = "";
    content.innerHTML = `<div style="padding:60px;text-align:center;color:var(--text3);font-size:13px">
      <div style="font-size:48px;margin-bottom:16px;opacity:.15">📊</div>
      <div style="font-weight:600;margin-bottom:6px">No scan data yet</div>
      <div style="font-size:11px;opacity:.6">Run a scan to see the vulnerability dashboard</div></div>`;
    return;
  }

  const xssCnt   = f.filter(r => r.confirmed).length;
  const wafCnt   = f.filter(r => r.reason === "waf_block").length;
  const errCnt   = f.filter(r => r.status === "ERROR").length;
  const cleanCnt = f.length - xssCnt - wafCnt - errCnt;
  const total    = f.length;
  const vulnRate = total > 0 ? (xssCnt / total * 100) : 0;
  if (meta) meta.textContent = `${xssCnt} XSS · ${total} tests · ${_xssScanType || "quick"} scan`;

  // ── Data grouping ──
  const cats = {};
  f.forEach(r => {
    if (!cats[r.category]) cats[r.category] = { total:0, xss:0, params: new Set() };
    cats[r.category].total++;
    if (r.confirmed) cats[r.category].xss++;
    cats[r.category].params.add(r.param);
  });
  const sortedCats = Object.entries(cats).sort((a,b) => b[1].xss - a[1].xss || b[1].total - a[1].total);
  const maxCatTotal = Math.max(...sortedCats.map(([,c]) => c.total), 1);
  const maxCatXss   = Math.max(...sortedCats.map(([,c]) => c.xss), 1);

  const apiStats = _xssEntries
    .filter(e => e.results && e.results.length > 0)
    .map(e => {
      const xss  = e.results.filter(r => r.confirmed).length;
      const waf  = e.results.filter(r => r.reason === "waf_block").length;
      const path = e.url.replace(/^https?:\/\/[^/]+/, "") || "/";
      return { method:e.method, path, fullUrl:e.url, total:e.results.length, xss, waf };
    }).sort((a,b) => b.xss - a.xss);
  const maxApiXss = Math.max(...apiStats.map(a => a.xss), 1);

  const paramMap = {};
  f.forEach(r => {
    if (!paramMap[r.param]) paramMap[r.param] = { total:0, xss:0, location:r.location||"?" };
    paramMap[r.param].total++;
    if (r.confirmed) paramMap[r.param].xss++;
  });
  const sortedParams  = Object.entries(paramMap).sort((a,b) => b[1].xss-a[1].xss||b[1].total-a[1].total).slice(0,10);
  const maxParamTotal = Math.max(...sortedParams.map(([,p]) => p.total), 1);
  const maxParamXss   = Math.max(...sortedParams.map(([,p]) => p.xss), 1);

  const statusMap = {};
  f.forEach(r => { const k = String(r.status||"?"); statusMap[k]=(statusMap[k]||0)+1; });
  const sortedStatus = Object.entries(statusMap).sort((a,b)=>b[1]-a[1]).slice(0,7);
  const maxStatusCnt = Math.max(...sortedStatus.map(([,v])=>v), 1);

  const ctxMap = {};
  f.filter(r=>r.confirmed).forEach(r => { const k=r.context||"unknown"; ctxMap[k]=(ctxMap[k]||0)+1; });
  const ctxEntries = Object.entries(ctxMap).sort((a,b)=>b[1]-a[1]);
  const ctxTotal   = ctxEntries.reduce((s,[,v])=>s+v, 0);

  const M_COL    = { GET:"#3fb950",POST:"#79c0ff",PUT:"#ffa657",DELETE:"#f85149",PATCH:"#d29922" };
  const CTX_COL  = ["#f85149","#d29922","#ffa657","#79c0ff","#a371f7","#3fb950","#58a6ff"];
  const CAT_COLORS = ["#f85149","#d29922","#ffa657","#79c0ff","#a371f7","#3fb950","#58a6ff","#db61a2"];
  const LOC_COL  = { query:"#3fb950",body:"#79c0ff",header:"#ffa657" };

  // ── SVG helpers ──
  function _svgDonut(segs, sz, sw) {
    const r=( sz-sw)/2, cx=sz/2, cy=sz/2, circ=2*Math.PI*r;
    const tot=segs.reduce((s,g)=>s+g.val,0)||1;
    let off=circ*.25;
    const arcs=segs.map(g=>{
      const d=(g.val/tot)*circ;
      const a=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${g.color}"
        stroke-width="${sw}" stroke-dasharray="${d.toFixed(2)} ${(circ-d).toFixed(2)}"
        stroke-dashoffset="${(circ-off%circ).toFixed(2)}" stroke-linecap="butt"/>`;
      off+=d; return a;
    }).join("");
    return `<svg width="${sz}" height="${sz}" viewBox="0 0 ${sz} ${sz}" style="transform:rotate(-90deg)">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,.04)" stroke-width="${sw}"/>
      ${arcs}</svg>`;
  }

  function _svgPie(segs, sz) {
    const depth = 22;
    const W = sz, H = sz + depth + 14;
    const cx = W / 2;
    const cy = sz * 0.44; // shift center up to leave room for depth below
    const rx = sz / 2 - 6;
    const ry = rx * 0.46; // squish for 3D tilt perspective

    const tot = segs.reduce((s,g) => s+g.val, 0) || 1;
    let a = -Math.PI / 2;
    const slices = segs.map((g, i) => {
      const start = a;
      const sl = (g.val / tot) * 2 * Math.PI;
      a += sl;
      return { color: g.color, val: g.val, start, end: a, mid: start + sl/2, sl, i };
    });

    const ex = ang => cx + rx * Math.cos(ang);
    const ey = ang => cy + ry * Math.sin(ang);

    // Painter's algorithm: sort back-to-front by mid-angle y
    const sorted = [...slices].sort((a, b) => Math.sin(a.mid) - Math.sin(b.mid));

    const uid = "p3d_" + (Math.random()*9999|0);

    const defs = `
      <filter id="${uid}sf"><feGaussianBlur stdDeviation="5"/></filter>
      <clipPath id="${uid}clip">
        <rect x="${(cx-rx-2).toFixed(0)}" y="${(cy-1).toFixed(0)}"
              width="${(rx*2+4).toFixed(0)}" height="${(ry+depth+22).toFixed(0)}"/>
      </clipPath>
      ${slices.map(s => `
        <linearGradient id="${uid}wg${s.i}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stop-color="${s.color}" stop-opacity="0.85"/>
          <stop offset="100%" stop-color="${s.color}" stop-opacity="0.3"/>
        </linearGradient>
        <radialGradient id="${uid}tg${s.i}" cx="38%" cy="32%" r="68%">
          <stop offset="0%"   stop-color="${s.color}" stop-opacity="1"/>
          <stop offset="100%" stop-color="${s.color}" stop-opacity="0.72"/>
        </radialGradient>`).join("")}`;

    // Side walls (only bottom-facing, clipped)
    const walls = sorted.map(s => {
      if (s.val === tot) {
        return `<ellipse cx="${cx}" cy="${(cy+depth).toFixed(1)}" rx="${rx}" ry="${ry}"
          fill="url(#${uid}wg${s.i})" clip-path="url(#${uid}clip)"/>`;
      }
      const x1=ex(s.start).toFixed(1), y1=ey(s.start).toFixed(1);
      const x2=ex(s.end).toFixed(1),   y2=ey(s.end).toFixed(1);
      const large = s.sl > Math.PI ? 1 : 0;
      return `<path clip-path="url(#${uid}clip)"
        d="M ${x1} ${y1}
           A ${rx} ${ry} 0 ${large} 1 ${x2} ${y2}
           L ${x2} ${(+y2+depth).toFixed(1)}
           A ${rx} ${ry} 0 ${large} 0 ${x1} ${(+y1+depth).toFixed(1)} Z"
        fill="url(#${uid}wg${s.i})" stroke="rgba(0,0,0,.18)" stroke-width="0.6"/>`;
    }).join("");

    // Top surfaces
    const tops = sorted.map(s => {
      if (s.val === tot) {
        return `<ellipse cx="${cx}" cy="${cy.toFixed(1)}" rx="${rx}" ry="${ry}"
          fill="url(#${uid}tg${s.i})" stroke="rgba(0,0,0,.2)" stroke-width="1"/>`;
      }
      const x1=ex(s.start).toFixed(1), y1=ey(s.start).toFixed(1);
      const x2=ex(s.end).toFixed(1),   y2=ey(s.end).toFixed(1);
      const large = s.sl > Math.PI ? 1 : 0;
      return `<path d="M ${cx} ${cy.toFixed(1)} L ${x1} ${y1} A ${rx} ${ry} 0 ${large} 1 ${x2} ${y2} Z"
        fill="url(#${uid}tg${s.i})" stroke="rgba(0,0,0,.3)" stroke-width="1.5"/>`;
    }).join("");

    return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
      <defs>${defs}</defs>
      <ellipse cx="${cx}" cy="${(cy+ry+depth+8).toFixed(0)}"
               rx="${(rx*0.72).toFixed(0)}" ry="${(ry*0.38).toFixed(0)}"
               fill="rgba(0,0,0,.45)" filter="url(#${uid}sf)"/>
      ${walls}
      ${tops}
    </svg>`;
  }

  // ── Stat cards ──
  const vulnPct = vulnRate.toFixed(1);
  const riskLevel = vulnRate > 20 ? ["CRITICAL","#f85149"] : vulnRate > 5 ? ["HIGH","#d29922"] : vulnRate > 0 ? ["MEDIUM","#ffa657"] : ["SAFE","#3fb950"];
  const statCards = [
    {label:"XSS FOUND",  val:xssCnt,               color:"#f85149",bg:"rgba(248,81,73,.1)", border:"rgba(248,81,73,.35)", glow:"rgba(248,81,73,.2)", icon:"⚡"},
    {label:"CLEAN",      val:cleanCnt,              color:"#3fb950",bg:"rgba(63,185,80,.08)",border:"rgba(63,185,80,.3)",  glow:"rgba(63,185,80,.15)",icon:"✓"},
    {label:"WAF BLOCKED",val:wafCnt,                color:"#8b949e",bg:"rgba(110,118,129,.1)",border:"rgba(110,118,129,.25)",glow:"none",             icon:"🛡"},
    {label:"TOTAL TESTS",val:total,                 color:"#79c0ff",bg:"rgba(121,192,255,.07)",border:"rgba(121,192,255,.25)",glow:"rgba(121,192,255,.15)",icon:"📊"},
    {label:"VULN RATE",  val:vulnPct+"%",           color:riskLevel[1],bg:`rgba(0,0,0,.2)`,border:riskLevel[1]+"55",     glow:riskLevel[1]+"22",    icon:"📈"},
    {label:"DURATION",   val:(_xssElapsed||0)+"s",  color:"#a371f7",bg:"rgba(163,113,247,.08)",border:"rgba(163,113,247,.3)",glow:"rgba(163,113,247,.15)",icon:"⏱"},
  ].map(({label,val,color,bg,border,glow,icon})=>`
    <div style="background:${bg};border:1px solid ${border};border-radius:12px;padding:14px 16px;
                position:relative;overflow:hidden;min-width:0;
                box-shadow:0 0 16px ${glow},inset 0 1px 0 rgba(255,255,255,.06)">
      <div style="position:absolute;top:-4px;right:8px;font-size:32px;opacity:.1;line-height:1;pointer-events:none">${icon}</div>
      <div style="font-size:26px;font-weight:800;color:${color};font-family:var(--mono);line-height:1;
                  text-shadow:0 0 20px ${color}66">${val}</div>
      <div style="font-size:9px;font-weight:700;color:var(--text3);letter-spacing:.1em;margin-top:6px;text-transform:uppercase">${label}</div>
      <div style="position:absolute;bottom:0;left:0;right:0;height:2px;background:linear-gradient(90deg,${color}88,transparent)"></div>
    </div>`).join("");

  // ── API breakdown (gradient bars) ──
  const apiBars = apiStats.length ? apiStats.map(a=>{
    const xPct=a.xss>0?Math.round(a.xss/maxApiXss*100):0;
    const tPct=Math.round(a.total/Math.max(...apiStats.map(x=>x.total),1)*100);
    const mc=M_COL[a.method]||"#8b949e";
    const col=a.xss>0?"#f85149":"#3fb950";
    const hitRate=a.total>0?(a.xss/a.total*100).toFixed(0):0;
    return `
    <div style="margin-bottom:14px;padding:10px 12px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:8px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="background:${mc}22;color:${mc};font-size:9px;font-weight:800;font-family:var(--mono);
                     padding:2px 7px;border-radius:4px;border:1px solid ${mc}44;flex-shrink:0">${a.method}</span>
        <span style="font-size:10px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
              title="${_xssEsc(a.fullUrl)}">${_xssEsc(a.path)}</span>
        <span style="font-size:11px;font-family:var(--mono);font-weight:800;color:${col};flex-shrink:0;
                     text-shadow:0 0 8px ${col}88">${a.xss>0?"⚡"+a.xss:"✓ 0"}</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <div style="flex:1">
          <div style="height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden;margin-bottom:3px">
            <div style="height:100%;width:${tPct}%;background:rgba(255,255,255,.12);border-radius:3px"></div>
          </div>
          <div style="height:8px;background:rgba(255,255,255,.05);border-radius:4px;overflow:hidden;position:relative">
            <div style="height:100%;width:${xPct}%;border-radius:4px;
                        background:linear-gradient(90deg,${col},${col}66);
                        box-shadow:0 0 6px ${col}55;transition:width .5s ease"></div>
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0;min-width:52px">
          <div style="font-size:9px;color:var(--text3)">${a.total} tests</div>
          <div style="font-size:9px;color:${col};font-weight:700">${hitRate}% hit</div>
        </div>
      </div>
    </div>`;
  }).join("") : `<div style="color:var(--text3);font-size:11px;padding:20px 0;text-align:center;opacity:.5">
    No API data — scan completes per entry</div>`;

  // ── Category SVG bar chart ──
  const catChart = sortedCats.map(([cat,c],i)=>{
    const col       = c.xss>0 ? (CAT_COLORS[i%CAT_COLORS.length]) : "#3fb950";
    const xssPct    = Math.round(c.xss/maxCatXss*100);
    const totalPct  = Math.round(c.total/maxCatTotal*100);
    const successPct= c.total>0?Math.round(c.xss/c.total*100):0;
    const params    = Array.from(c.params).slice(0,3).join(", ");
    return `
    <div style="margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <div style="width:8px;height:8px;border-radius:2px;background:${col};flex-shrink:0;box-shadow:0 0 5px ${col}88"></div>
        <span style="font-size:10px;font-weight:600;color:var(--text);flex:1;font-family:var(--mono)">${_xssEsc(cat)}</span>
        <span style="font-size:9px;color:var(--text3);min-width:50px;text-align:right">${c.total} tests</span>
        <span style="font-size:10px;font-weight:800;color:${col};min-width:36px;text-align:right;text-shadow:0 0 8px ${col}66">${c.xss>0?"⚡"+c.xss:"✓"}</span>
      </div>
      <div style="position:relative;height:14px;background:rgba(255,255,255,.04);border-radius:4px;overflow:hidden;margin-bottom:2px">
        <div style="position:absolute;inset:0;width:${totalPct}%;background:rgba(255,255,255,.06);border-radius:4px"></div>
        <div style="position:absolute;inset:0;width:${xssPct}%;background:linear-gradient(90deg,${col},${col}55);border-radius:4px;box-shadow:0 0 8px ${col}44"></div>
        ${c.xss>0?`<span style="position:absolute;right:5px;top:50%;transform:translateY(-50%);font-size:9px;color:rgba(255,255,255,.6)">${successPct}% hit</span>`:""}
      </div>
      ${c.xss>0&&params?`<div style="font-size:9px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-left:16px">${_xssEsc(params)}</div>`:""}
    </div>`;
  }).join("");

  // ── Param chart ──
  const paramChart = sortedParams.map(([name,p])=>{
    const lc      = LOC_COL[p.location]||"#8b949e";
    const col     = p.xss>0?"#f85149":"rgba(63,185,80,.5)";
    const xPct    = Math.round(p.xss/maxParamXss*100);
    const tPct    = Math.round(p.total/maxParamTotal*100);
    const hitPct  = p.total>0?Math.round(p.xss/p.total*100):0;
    return `
    <div style="margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">
        <span style="font-size:8px;font-weight:800;color:${lc};font-family:var(--mono);
                     background:${lc}18;padding:1px 5px;border-radius:3px;flex-shrink:0">${(p.location||"?").toUpperCase().slice(0,4)}</span>
        <code style="font-size:10px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_xssEsc(name)}</code>
        <span style="font-size:10px;font-weight:800;color:${p.xss>0?"#f85149":"#3fb950"};flex-shrink:0">${p.xss>0?"⚡"+p.xss:"✓"}</span>
      </div>
      <div style="position:relative;height:12px;background:rgba(255,255,255,.04);border-radius:3px;overflow:hidden">
        <div style="position:absolute;inset:0;width:${tPct}%;background:rgba(255,255,255,.07);border-radius:3px"></div>
        <div style="position:absolute;inset:0;width:${xPct}%;background:linear-gradient(90deg,${col},${col}55);border-radius:3px"></div>
        ${p.xss>0?`<span style="position:absolute;right:4px;top:50%;transform:translateY(-50%);font-size:8px;color:rgba(255,255,255,.5)">${hitPct}%</span>`:""}
      </div>
    </div>`;
  }).join("");

  // ── Status distribution ──
  const statusColors = {"200":"#3fb950","201":"#3fb950","204":"#3fb950","400":"#d29922","401":"#ffa657","403":"#ffa657","404":"#8b949e","422":"#d29922","500":"#f85149","503":"#f85149"};
  const statusBars = sortedStatus.map(([code,cnt])=>{
    const col = statusColors[code] || "#79c0ff";
    const pct = Math.round(cnt/maxStatusCnt*100);
    return `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:7px">
      <span style="font-size:10px;font-weight:700;font-family:var(--mono);color:${col};min-width:36px">${code}</span>
      <div style="flex:1;height:10px;background:rgba(255,255,255,.04);border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,${col},${col}55);border-radius:3px;box-shadow:0 0 6px ${col}44"></div>
      </div>
      <span style="font-size:10px;font-family:var(--mono);color:var(--text3);min-width:30px;text-align:right">${cnt}</span>
    </div>`;
  }).join("");

  // ── SVG Pie + legend for context ──
  const pieSegs = ctxEntries.map(([,v],i)=>({val:v,color:CTX_COL[i%CTX_COL.length]}));
  if(!pieSegs.length) pieSegs.push({val:1,color:"rgba(255,255,255,.06)"});
  const pieSvg = _svgPie(pieSegs, 110);
  const ctxLegend = ctxEntries.map(([ctx,cnt],i)=>{
    const col=CTX_COL[i%CTX_COL.length];
    const pct=ctxTotal>0?Math.round(cnt/ctxTotal*100):0;
    return `
    <div style="display:flex;align-items:center;gap:7px;margin-bottom:6px">
      <div style="width:10px;height:10px;border-radius:3px;background:${col};flex-shrink:0;box-shadow:0 0 5px ${col}77"></div>
      <span style="font-size:10px;color:var(--text);flex:1;font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_xssEsc(ctx)}</span>
      <span style="font-size:11px;font-weight:700;color:${col};font-family:var(--mono)">${cnt}</span>
      <span style="font-size:9px;color:var(--text3);min-width:28px;text-align:right">${pct}%</span>
    </div>`;
  }).join("");

  // ── Big detection donut ──
  const bigDonutSegs=[
    {val:xssCnt,  color:"#f85149"},
    {val:wafCnt,  color:"#6e7681"},
    {val:cleanCnt,color:"rgba(63,185,80,.3)"},
  ].filter(s=>s.val>0);
  if(!bigDonutSegs.length) bigDonutSegs.push({val:1,color:"rgba(255,255,255,.05)"});
  const bigDonut = _svgDonut(bigDonutSegs, 100, 15);

  // ── Risk badge for header ──
  const riskBadge = `<span style="font-size:9px;font-weight:800;padding:3px 8px;border-radius:6px;
    background:${riskLevel[1]}22;color:${riskLevel[1]};border:1px solid ${riskLevel[1]}44;letter-spacing:.08em">${riskLevel[0]}</span>`;

  content.innerHTML = `
  <style>
    .xd-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px;
             box-shadow:0 2px 12px rgba(0,0,0,.3),inset 0 1px 0 rgba(255,255,255,.04)}
    .xd-sec{font-size:9px;font-weight:700;color:var(--text3);letter-spacing:.1em;text-transform:uppercase;
            margin-bottom:12px;display:flex;align-items:center;gap:8px}
    .xd-sec::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}
  </style>

  <!-- ① Stat Cards -->
  <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:14px">${statCards}</div>

  <!-- ② API + Detection -->
  <div style="display:grid;grid-template-columns:3fr 2fr;gap:12px;margin-bottom:12px">

    <div class="xd-card">
      <div class="xd-sec">🔗 API Risk Breakdown</div>
      ${apiBars}
    </div>

    <div class="xd-card">
      <div class="xd-sec">🎯 Detection Overview ${riskBadge}</div>
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--border)">
        <div style="position:relative;flex-shrink:0">
          ${bigDonut}
          <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;pointer-events:none">
            <div style="font-size:16px;font-weight:900;color:#f85149;font-family:var(--mono);line-height:1;text-shadow:0 0 12px #f8514988">${vulnPct}%</div>
            <div style="font-size:8px;color:var(--text3);margin-top:2px">vuln</div>
          </div>
        </div>
        <div style="flex:1">
          ${[[`⚡ XSS Found`,xssCnt,"#f85149"],[`✓ Clean`,cleanCnt,"#3fb950"],[`🛡 WAF`,wafCnt,"#6e7681"],[`⚠ Errors`,errCnt,"#d29922"]]
            .map(([l,v,c])=>`
            <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03)">
              <span style="font-size:10px;color:var(--text3)">${l}</span>
              <span style="font-size:14px;font-weight:800;color:${c};font-family:var(--mono);text-shadow:0 0 10px ${c}55">${v}</span>
            </div>`).join("")}
        </div>
      </div>
      ${ctxEntries.length?`
        <div class="xd-sec">🧩 Injection Context</div>
        <div style="display:flex;gap:12px;align-items:center">
          <div style="flex-shrink:0">${pieSvg}</div>
          <div style="flex:1;min-width:0">${ctxLegend}</div>
        </div>
      `:""}
    </div>

  </div>

  <!-- ③ Category Chart (full width) -->
  <div class="xd-card" style="margin-bottom:12px">
    <div class="xd-sec">🏷 Attack Category Breakdown
      <span style="font-size:9px;color:var(--text3);font-weight:400;letter-spacing:0;text-transform:none">— bar = XSS hits vs total tests</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 20px">
      ${sortedCats.map(([cat,c],i)=>{
        const col=c.xss>0?(CAT_COLORS[i%CAT_COLORS.length]):"#3fb950";
        const xssPct=Math.round(c.xss/maxCatXss*100);
        const totPct=Math.round(c.total/maxCatTotal*100);
        const params=Array.from(c.params).slice(0,3).join(", ");
        return `
        <div style="margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:7px;margin-bottom:4px">
            <div style="width:7px;height:7px;border-radius:2px;background:${col};flex-shrink:0;box-shadow:0 0 4px ${col}88"></div>
            <span style="font-size:10px;font-weight:600;color:var(--text);flex:1;font-family:var(--mono)">${_xssEsc(cat)}</span>
            <span style="font-size:9px;color:var(--text3)">${c.total}</span>
            <span style="font-size:11px;font-weight:800;color:${col};min-width:32px;text-align:right">${c.xss>0?"⚡"+c.xss:"✓"}</span>
          </div>
          <div style="position:relative;height:16px;background:rgba(255,255,255,.04);border-radius:5px;overflow:hidden">
            <div style="position:absolute;inset:0;width:${totPct}%;background:rgba(255,255,255,.06);border-radius:5px"></div>
            <div style="position:absolute;inset:0;width:${xssPct}%;background:linear-gradient(90deg,${col}cc,${col}44);border-radius:5px;box-shadow:0 0 10px ${col}33;transition:width .5s"></div>
            ${c.xss>0?`<span style="position:absolute;left:6px;top:50%;transform:translateY(-50%);font-size:9px;color:rgba(255,255,255,.8);font-weight:700">
              ${c.total>0?Math.round(c.xss/c.total*100):0}% success</span>`
            :`<span style="position:absolute;left:6px;top:50%;transform:translateY(-50%);font-size:9px;color:rgba(255,255,255,.3)">clean</span>`}
          </div>
          ${c.xss>0&&params?`<div style="font-size:9px;color:var(--text3);padding-left:14px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_xssEsc(params)}</div>`:""}
        </div>`}).join("")}
    </div>
  </div>

  <!-- ④ Params + Status -->
  <div style="display:grid;grid-template-columns:3fr 2fr;gap:12px">

    <div class="xd-card">
      <div class="xd-sec">⚙ Parameter Risk
        <span style="font-size:9px;color:var(--text3);font-weight:400;letter-spacing:0;text-transform:none">— faded=total · bright=XSS</span>
      </div>
      ${paramChart}
    </div>

    <div class="xd-card">
      <div class="xd-sec">📶 HTTP Status Distribution</div>
      ${statusBars}
      <div style="margin-top:14px;padding-top:10px;border-top:1px solid var(--border)">
        <div class="xd-sec">🔢 Scan Summary</div>
        ${[
          ["APIs Scanned",  apiStats.length,  "#79c0ff"],
          ["Params Tested", Object.keys(paramMap).length, "#a371f7"],
          ["Categories",    sortedCats.length,"#d29922"],
          ["Scan Type",     _xssScanType||"quick","#3fb950"],
        ].map(([l,v,c])=>`
          <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03)">
            <span style="font-size:10px;color:var(--text3)">${l}</span>
            <span style="font-size:10px;font-weight:700;color:${c};font-family:var(--mono)">${v}</span>
          </div>`).join("")}
      </div>
    </div>

  </div>`;
}

// ─── Exports ──────────────────────────────────────────────────────────────────

async function xssExportCsv() {
  if (!_xssJobId) return;
  try {
    const r = await fetch(`${XSS_BASE}/xss/export/csv/${_xssJobId}`);
    const d = await r.json();
    _xssDownload(d.csv, d.filename || "xss_scan.csv", "text/csv");
    if (window.showExportToast) showExportToast(d.filename || "xss_scan.csv");
  } catch(e) {}
}

async function xssExportHtml() {
  if (!_xssJobId) return;
  try {
    const r = await fetch(`${XSS_BASE}/xss/export/html/${_xssJobId}`);
    const d = await r.json();
    _xssDownload(d.html, d.filename || "xss_scan.html", "text/html");
    if (window.showExportToast) showExportToast(d.filename || "xss_scan.html");
  } catch(e) {}
}

function _xssDownload(content, filename, mime) {
  if (window.pywebview && window.pywebview.api && window.pywebview.api.save_file) {
    window.pywebview.api.save_file(content, filename);
    return;
  }
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = filename; a.click();
  URL.revokeObjectURL(a.href);
}

// ─── Reset ────────────────────────────────────────────────────────────────────

function xssReset() {
  if (_xssPollTimer) { clearInterval(_xssPollTimer); _xssPollTimer = null; }
  if (_xssJobId) fetch(`${XSS_BASE}/xss/scan/stop/${_xssJobId}`, { method: "POST" }).catch(() => {});

  _xssEntries = []; _xssSelEntryId = null; _xssParamFilter = "";
  _xssCheckedEntryIds = new Set();
  const pf = document.getElementById("xss-params-filter");
  if (pf) pf.value = "";
  _xssScanQueue = []; _xssScanQueueIdx = 0;
  _xssJobId = null; _xssResults = []; _xssElapsed = 0; _xssCurrentScanningParam = null; _xssFilter = "ALL";
  _xssScanType = null; _xssScanState = "idle";
  _xssProbeLog = []; _xssSelResultIdx = null;
  _xssSelProbeIdx = null; _xssAvEntries = [];

  _xssErrHide();
  _xssRenderEntryList();

  // Reset config panel
  const ph = document.getElementById("xss-entry-config-placeholder");
  const ct = document.getElementById("xss-entry-config-content");
  if (ph) ph.style.display = "flex";
  if (ct) ct.style.display = "none";
  const paramsList = document.getElementById("xss-params-list");
  if (paramsList) paramsList.innerHTML = "";

  _xssSetProgress(0, "Starting scan…", "");
  const probe = document.getElementById("xss-probe-list");
  if (probe) probe.innerHTML = "";
  xssCloseProbeDetail();
  const probeCnt = document.getElementById("xss-probe-count");
  if (probeCnt) probeCnt.textContent = "";

  const stop = document.getElementById("xss-stop-btn");
  if (stop) {
    stop.textContent = "⏹ Stop"; stop.disabled = false; stop.style.opacity = "1";
    stop.style.background = "rgba(218,54,51,.15)";
    stop.style.color = "var(--red2)";
    stop.style.borderColor = "rgba(218,54,51,.3)";
    stop.onclick = xssStopScan;
  }

  const cards = document.getElementById("xss-summary-cards");
  if (cards) cards.innerHTML = "";
  const tbody = document.getElementById("xss-results-tbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text3)">No results yet — run a scan first.</td></tr>`;
  const det = document.getElementById("xss-result-detail");
  if (det) det.style.display = "none";
  const title = document.getElementById("xss-results-title");
  if (title) title.textContent = "Results";
  const rtBtn = document.getElementById("xss-tab-results");
  if (rtBtn) rtBtn.textContent = "📊 Results";

  const dash = document.getElementById("xss-dash-content");
  if (dash) dash.innerHTML = `<div style="padding:30px;text-align:center;color:var(--text3);font-size:12px">Run a scan to see the dashboard.</div>`;
  const dmeta = document.getElementById("xss-dash-meta");
  if (dmeta) dmeta.textContent = "";

  document.querySelectorAll("#xss-filter-row .as-filter-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-f") === "ALL");
  });

  _xssUpdateRunBtn();
  xssGoTab("capture");
}

window.xssReset = xssReset;

// ─── Drag-resize for scanning split pane ──────────────────────────────────────

(function _xssInitResize() {
  function initH(handleId, leftId, rightId) {
    const handle = document.getElementById(handleId);
    if (!handle) return;
    let dragging = false, startX = 0, startLeft = 0, startRight = 0;
    handle.addEventListener("mousedown", e => {
      const left  = document.getElementById(leftId);
      const right = document.getElementById(rightId);
      if (!left || !right) return;
      dragging  = true; startX = e.clientX;
      startLeft = left.getBoundingClientRect().width;
      startRight= right.getBoundingClientRect().width;
      handle.classList.add("as-dragging");
      document.body.style.cursor = "col-resize";
      e.preventDefault();
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      const left  = document.getElementById(leftId);
      const right = document.getElementById(rightId);
      if (!left || !right) return;
      const dx = e.clientX - startX;
      const nL = Math.max(120, startLeft + dx);
      const nR = Math.max(160, startRight - dx);
      left.style.flex  = "none"; left.style.width  = nL + "px";
      right.style.flex = "none"; right.style.width = nR + "px";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = "";
    });
  }

  function initV(handleId, topId, bottomId) {
    const handle = document.getElementById(handleId);
    if (!handle) return;
    let dragging = false, startY = 0, startTop = 0, startBot = 0;
    handle.addEventListener("mousedown", e => {
      const top = document.getElementById(topId);
      const bot = document.getElementById(bottomId);
      if (!top || !bot) return;
      dragging = true; startY = e.clientY;
      startTop = top.getBoundingClientRect().height;
      startBot = bot.getBoundingClientRect().height;
      handle.classList.add("as-dragging");
      document.body.style.cursor = "row-resize";
      e.preventDefault();
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      const top = document.getElementById(topId);
      const bot = document.getElementById(bottomId);
      if (!top || !bot) return;
      const dy = e.clientY - startY;
      top.style.flex = "none"; top.style.height = Math.max(60, startTop + dy) + "px";
      bot.style.flex = "none"; bot.style.height = Math.max(60, startBot - dy) + "px";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = "";
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initH("xss-hresize",     "xss-probe-panel-list",  "xss-probe-detail");
    initV("xss-vresize",     "xss-probe-req-panel",   "xss-probe-resp-panel");
    initH("xss-cap-hresize", "xss-entry-list-panel",  "xss-entry-config-panel");
    if (typeof _xssSyncScanTypeVisibility === "function") _xssSyncScanTypeVisibility();
  });
}());
