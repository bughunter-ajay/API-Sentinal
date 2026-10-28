// ── RSQL Security Tester Frontend ─────────────────────────────────────────────
const RSQL_BASE = "http://127.0.0.1:8774";

// ── State ─────────────────────────────────────────────────────────────────────
let _rsqlEntries       = [];     // all imported entries (HAR / AV)
let _rsqlSelected      = new Set(); // selected entry indices for Configure/Scan
let _rsqlToken         = "";     // auto-extracted token
let _rsqlBodyFields    = {};     // {fieldName: bool}  checked body fields
let _rsqlQueryFields   = {};     // {fieldName: bool}  checked query fields
let _rsqlSelCats       = {};     // {catKey: bool}  selected categories
let _rsqlCatsMeta      = {};     // loaded from /rsql/datasets
let _rsqlJobId         = null;
let _rsqlPollTimer     = null;
let _rsqlAllResults    = [];
let _rsqlLastSummary   = null;
let _rsqlActiveFilter  = "all";
let _rsqlConfigReady   = false;  // configure UI built from current selection
let _rsqlScanning      = false;  // block starting a second scan until Abort / done
let _rsqlLastPollDone  = -1;
let _rsqlLastAborted   = false;
let _rsqlExpandedKey   = null;   // stable key so live re-renders keep expand open

// ── Tab switch ────────────────────────────────────────────────────────────────
function rsqlSwitchTab(tab) {
  // Legacy alias
  if (tab === "capture") tab = "requests";

  const tabs = ["requests", "configure", "results"];
  if (!tabs.includes(tab)) tab = "requests";

  tabs.forEach((t) => {
    const btn = document.getElementById(`rsql-tab-${t}`);
    const pane = document.getElementById(`rsql-tab-${t}-content`);
    if (btn) btn.classList.toggle("active", t === tab);
    if (pane) pane.style.display = t === tab ? "flex" : "none";
  });

  if (tab === "configure") {
    _rsqlSyncConfigurePane();
  }
}

// ── Scan UI lock / inline progress ────────────────────────────────────────────
function rsqlSetScanningUI(on) {
  _rsqlScanning = !!on;
  const root = document.getElementById("tool-rsql");
  if (root) root.classList.toggle("is-scanning", _rsqlScanning);

  const runBtn = document.getElementById("rsql-run-btn");
  if (runBtn) {
    runBtn.disabled = _rsqlScanning;
    runBtn.textContent = _rsqlScanning ? "⏳ Scanning…" : "🚀 Run RSQL Scan";
  }

  ["rsql-btn-abort", "rsql-btn-abort-results"].forEach((id) => {
    const btn = document.getElementById(id);
    if (!btn) return;
    btn.style.display = _rsqlScanning ? "" : "none";
    btn.disabled = false;
    btn.textContent = "✕ Abort";
  });

  const prog = document.getElementById("rsql-scan-progress-inline");
  if (prog) prog.style.display = _rsqlScanning ? "flex" : "none";

  const cfgBtn = document.getElementById("rsql-btn-configure");
  if (cfgBtn && _rsqlScanning) cfgBtn.disabled = true;
}

function _rsqlSetScanPct(pct, label) {
  const pctEl = document.getElementById("rsql-scan-pct");
  const fillEl = document.getElementById("rsql-scan-bar-fill");
  const labelEl = document.getElementById("rsql-scan-label");
  const p = Math.min(100, Math.max(0, pct | 0));
  if (pctEl) pctEl.textContent = `${p}%`;
  if (fillEl) fillEl.style.width = `${p}%`;
  if (labelEl) labelEl.textContent = label || "";
}

function _rsqlShowAbortedBanner() {
  const existing = document.getElementById("rsql-aborted-warn");
  if (existing) existing.remove();
  const warn = document.createElement("div");
  warn.id = "rsql-aborted-warn";
  warn.style.cssText =
    "background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.35);border-radius:6px;color:#f85149;padding:10px 14px;font-size:12px;margin:0 0 8px;flex-shrink:0";
  warn.textContent = "⏹ Scan aborted — showing partial results.";
  const prog = document.getElementById("rsql-scan-progress-inline");
  const pane = document.getElementById("rsql-tab-results-content");
  if (prog && prog.parentElement) prog.parentElement.insertBefore(warn, prog.nextSibling);
  else if (pane) pane.insertBefore(warn, pane.firstChild);
}

async function rsqlAbortScan() {
  if (!_rsqlScanning && !_rsqlJobId) return;
  const btns = ["rsql-btn-abort", "rsql-btn-abort-results"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
  btns.forEach((b) => {
    b.disabled = true;
    b.textContent = "Aborting…";
  });
  _rsqlSetScanPct(
    parseInt(document.getElementById("rsql-scan-pct")?.textContent || "0", 10) || 0,
    "Abort requested — stopping…"
  );
  try {
    if (_rsqlJobId) {
      await fetch(`${RSQL_BASE}/rsql/stop/${_rsqlJobId}`, { method: "POST" });
    }
  } catch (_) { /* keep polling until backend marks done */ }
}
window.rsqlAbortScan = rsqlAbortScan;

function _rsqlGetSelectedEntries() {
  return [..._rsqlSelected]
    .filter((i) => i >= 0 && i < _rsqlEntries.length)
    .sort((a, b) => a - b)
    .map((i) => _rsqlEntries[i]);
}

function _rsqlCountBodyLeaves(body) {
  if (!body || typeof body !== "object") return 0;
  const out = {};
  _rsqlCollectBodyLeaves(body, "", out, 0, 6);
  return Object.keys(out).length;
}

// ── Load datasets from backend ────────────────────────────────────────────────
async function rsqlLoadDatasets() {
  try {
    const resp = await fetch(`${RSQL_BASE}/rsql/datasets`);
    if (!resp.ok) return;
    _rsqlCatsMeta = await resp.json();
    // Default: all selected
    Object.keys(_rsqlCatsMeta).forEach(k => { _rsqlSelCats[k] = true; });
    rsqlRenderCategoryGrid();
  } catch(e) { /* backend not ready yet */ }
}

// ── HAR import ────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const inp = document.getElementById("rsql-har-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    if (_rsqlScanning) {
      alert("A scan is already running. Abort it before importing a new HAR.");
      inp.value = "";
      rsqlSwitchTab("results");
      return;
    }
    try {
      const text = await file.text();
      const har  = JSON.parse(text);
      // Prefer Authorization from API-looking requests first; Chrome/Edge HAR
      // exports often strip Authorization unless "Export HAR (with sensitive data)".
      let autoToken = _rsqlExtractAuthFromHarEntries(har?.log?.entries || []);
      const STATIC_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp|zip)(\?|$)/i;
      // seenMap: method::baseUrl → index in entries[] so we can MERGE query params
      // from duplicate requests (first request to same URL might have no params,
      // a later one does — we must not discard the params).
      const seenMap = new Map();
      const entries = [];
      for (const e of (har?.log?.entries || [])) {
        const req = e.request || {};
        const url = req.url || "";
        if (!url.startsWith("http") || STATIC_RE.test(url)) continue;
        const baseUrl = url.split("?")[0];
        const key = (req.method || "GET").toUpperCase() + "::" + baseUrl;

        // Parse query params for this HAR entry
        const query = {};
        for (const q of (req.queryString || [])) {
          if (q.name) query[q.name] = q.value || "";
        }

        if (seenMap.has(key)) {
          // Already have an entry for this URL — MERGE any new query keys we haven't seen
          const existing = entries[seenMap.get(key)];
          for (const [k, v] of Object.entries(query)) {
            if (!(k in existing.query)) existing.query[k] = v;
          }
          continue;
        }

        seenMap.set(key, entries.length);

        const headers = {};
        for (const h of (req.headers || [])) {
          if (h.name && !h.name.startsWith(":") && h.name.toLowerCase() !== "content-length")
            headers[h.name] = h.value;
        }
        // Parse body
        let body = null, body_type = null;
        const postData = req.postData;
        if (postData) {
          const ct = (headers["Content-Type"] || headers["content-type"] || "").toLowerCase();
          if (ct.includes("json")) {
            try { body = JSON.parse(postData.text || ""); body_type = "json"; } catch(ex) {}
          } else if (ct.includes("form") || ct.includes("urlencoded")) {
            const p = new URLSearchParams(postData.text || "");
            body = Object.fromEntries(p.entries()); body_type = "form";
          }
        }
        entries.push({ method: (req.method || "GET").toUpperCase(), url, headers, body, body_type, query });
      }
      // Fallback: token from kept API entries (same source; helps if early loop missed)
      if (!autoToken) autoToken = _rsqlExtractAuthFromEntries(entries);
      _rsqlToken = autoToken;
      _rsqlSetEntries(entries, autoToken);
    } catch(ex) { alert("HAR parse error: " + ex.message); }
    inp.value = "";
  };
  // Load datasets when tool is first accessed
  rsqlLoadDatasets();
});

// ── Load from AV Capture ──────────────────────────────────────────────────────
function rsqlLoadFromAV() {
  if (_rsqlScanning) {
    alert("A scan is already running. Abort it before loading new requests.");
    rsqlSwitchTab("results");
    return;
  }
  const reqs = window._avState?.requests || [];
  if (!reqs.length) {
    alert("No requests in API Validator capture.\n\nImport cURL or capture requests first.");
    return;
  }
  let autoToken = "";
  for (const r of reqs) {
    const k = Object.keys(r.headers || {}).find(k => k.toLowerCase() === "authorization");
    if (k) { autoToken = r.headers[k]; break; }
  }
  const entries = reqs.map(r => ({
    method:    (r.method || "GET").toUpperCase(),
    url:       r.url || "",
    headers:   r.headers || {},
    body:      r.body || null,
    body_type: r.body_type || null,
    query:     r.query || {},
  })).filter(e => e.url.startsWith("http"));
  _rsqlToken = autoToken;
  _rsqlSetEntries(entries, autoToken);
}

// ── Import → Requests list ────────────────────────────────────────────────────
function _rsqlNormalizeEntryQueries(entries) {
  for (const e of entries) {
    if (!Object.keys(e.query || {}).length && e.url && e.url.includes("?")) {
      try {
        const urlObj = new URL(e.url);
        e.query = {};
        urlObj.searchParams.forEach((v, k) => { if (k) e.query[k] = v; });
      } catch (_) {}
    }
  }
}

function _rsqlExtractAuthFromHeaders(headers) {
  if (!headers) return "";
  if (Array.isArray(headers)) {
    for (const h of headers) {
      if (h && String(h.name || "").toLowerCase() === "authorization" && h.value) {
        return String(h.value).trim();
      }
    }
    return "";
  }
  const key = Object.keys(headers).find((k) => k.toLowerCase() === "authorization");
  return key && headers[key] ? String(headers[key]).trim() : "";
}

function _rsqlExtractAuthFromHarEntries(harEntries) {
  const STATIC_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp|zip)(\?|$)/i;
  let fallback = "";
  for (const entry of harEntries || []) {
    const url = entry?.request?.url || "";
    const tok = _rsqlExtractAuthFromHeaders(entry?.request?.headers || []);
    if (!tok) continue;
    // Prefer non-static API URLs
    if (url.startsWith("http") && !STATIC_RE.test(url)) return tok;
    if (!fallback) fallback = tok;
  }
  return fallback;
}

function _rsqlExtractAuthFromEntries(entries) {
  for (const e of entries || []) {
    const tok = _rsqlExtractAuthFromHeaders(e.headers || {});
    if (tok) return tok;
  }
  return "";
}

function rsqlSyncTokenHint() {
  const hint = document.getElementById("rsql-token-hint");
  const tokInp = document.getElementById("rsql-token-input");
  if (!hint || !tokInp) return;
  const val = (tokInp.value || "").trim() || (_rsqlToken || "").trim();
  if (val) {
    hint.style.display = "none";
    hint.classList.remove("is-ok");
    hint.textContent = "";
    return;
  }
  hint.classList.remove("is-ok");
  hint.style.display = "block";
  hint.textContent =
    "No Authorization header found in the imported HAR. " +
    "This is usually a sanitized Chrome/Edge export (not an expired JWT) — " +
    "DevTools → Settings → Network → enable “Allow to generate HAR with sensitive data”, " +
    "then Export HAR (with sensitive data). Or paste Bearer token here manually.";
}
window.rsqlSyncTokenHint = rsqlSyncTokenHint;

function _rsqlSetEntries(entries, token) {
  _rsqlNormalizeEntryQueries(entries);
  _rsqlEntries = entries;
  _rsqlToken = token || _rsqlExtractAuthFromEntries(entries) || "";
  _rsqlSelected = new Set();
  _rsqlConfigReady = false;
  _rsqlBodyFields = {};
  _rsqlQueryFields = {};

  // Single request → auto-select for convenience
  if (entries.length === 1) _rsqlSelected.add(0);

  const tokInp = document.getElementById("rsql-token-input");
  if (tokInp) tokInp.value = _rsqlToken;
  rsqlSyncTokenHint();

  const countEl = document.getElementById("rsql-entry-count");
  if (countEl) {
    countEl.textContent = entries.length
      ? `${entries.length} unique request(s) loaded`
      : "No requests loaded";
  }

  const empty = document.getElementById("rsql-empty-state");
  const listWrap = document.getElementById("rsql-request-list-wrap");
  const filterBar = document.getElementById("rsql-req-filter-bar");
  const selAll = document.getElementById("rsql-req-sel-all");
  const selNone = document.getElementById("rsql-req-sel-none");
  const cfgBtn = document.getElementById("rsql-btn-configure");

  if (empty) empty.style.display = entries.length ? "none" : "flex";
  if (listWrap) listWrap.style.display = entries.length ? "flex" : "none";
  if (filterBar) filterBar.style.display = entries.length ? "flex" : "none";
  if (selAll) selAll.style.display = entries.length ? "" : "none";
  if (selNone) selNone.style.display = entries.length ? "" : "none";
  if (cfgBtn) cfgBtn.disabled = _rsqlSelected.size === 0;

  const search = document.getElementById("rsql-req-search");
  if (search) search.value = "";

  // Reset configure pane until user confirms selection
  const cfgWrap = document.getElementById("rsql-config-wrap");
  const runFooter = document.getElementById("rsql-run-footer");
  const cfgEmpty = document.getElementById("rsql-configure-empty");
  if (cfgWrap) cfgWrap.style.display = "none";
  if (runFooter) runFooter.style.display = "none";
  if (cfgEmpty) cfgEmpty.style.display = "flex";

  rsqlRenderRequestList();
  rsqlSwitchTab("requests");
}

function rsqlRenderRequestList() {
  const tbody = document.getElementById("rsql-request-tbody");
  if (!tbody) return;

  if (!_rsqlEntries.length) {
    tbody.innerHTML = "";
    _rsqlUpdateSelCount();
    return;
  }

  tbody.innerHTML = _rsqlEntries.map((e, i) => {
    const method = (e.method || "GET").toUpperCase();
    let path = e.url || "";
    try {
      const u = new URL(e.url);
      path = u.pathname + (u.search || "");
    } catch (_) {}
    const qn = Object.keys(e.query || {}).length;
    const bn = _rsqlCountBodyLeaves(e.body);
    const checked = _rsqlSelected.has(i) ? "checked" : "";
    const hay = `${method} ${e.url || ""} ${path}`.toLowerCase();
    return `<tr class="rsql-req-row" data-idx="${i}" data-search="${escHtmlR(hay)}"
                onclick="rsqlRowClick(${i}, event)">
      <td><input type="checkbox" class="rsql-req-cb" data-idx="${i}" ${checked}
                 onclick="event.stopPropagation()"
                 onchange="rsqlToggleRequest(${i}, this.checked)"></td>
      <td><span class="rsql-req-method rsql-m-${method.toLowerCase()}">${escHtmlR(method)}</span></td>
      <td class="rsql-req-url" title="${escHtmlR(e.url || "")}"><code>${escHtmlR(path)}</code></td>
      <td class="rsql-req-meta"><span class="rsql-count-pill ${qn > 0 ? "rsql-count-query" : "rsql-count-zero"}">${qn}</span></td>
      <td class="rsql-req-meta"><span class="rsql-count-pill ${bn > 0 ? "rsql-count-body" : "rsql-count-zero"}">${bn}</span></td>
    </tr>`;
  }).join("");

  _rsqlUpdateSelCount();
  rsqlFilterRequestList();
}

function rsqlRowClick(idx, ev) {
  if (ev && ev.target && ev.target.closest && ev.target.closest("input")) return;
  const on = !_rsqlSelected.has(idx);
  rsqlToggleRequest(idx, on);
  const row = document.querySelector(`#rsql-request-tbody .rsql-req-row[data-idx="${idx}"]`);
  const cb = row && row.querySelector(".rsql-req-cb");
  if (cb) cb.checked = on;
}

function rsqlToggleRequest(idx, checked) {
  if (checked) _rsqlSelected.add(idx);
  else _rsqlSelected.delete(idx);
  _rsqlConfigReady = false;
  _rsqlUpdateSelCount();
}

function rsqlSelectAllRequests() {
  const tbody = document.getElementById("rsql-request-tbody");
  if (!tbody) return;
  tbody.querySelectorAll(".rsql-req-row:not(.rsql-req-hidden)").forEach((row) => {
    const idx = parseInt(row.getAttribute("data-idx"), 10);
    if (Number.isNaN(idx)) return;
    _rsqlSelected.add(idx);
    const cb = row.querySelector(".rsql-req-cb");
    if (cb) cb.checked = true;
  });
  _rsqlConfigReady = false;
  _rsqlUpdateSelCount();
}

function rsqlDeselectAllRequests() {
  const tbody = document.getElementById("rsql-request-tbody");
  if (!tbody) return;
  tbody.querySelectorAll(".rsql-req-row:not(.rsql-req-hidden)").forEach((row) => {
    const idx = parseInt(row.getAttribute("data-idx"), 10);
    if (Number.isNaN(idx)) return;
    _rsqlSelected.delete(idx);
    const cb = row.querySelector(".rsql-req-cb");
    if (cb) cb.checked = false;
  });
  _rsqlConfigReady = false;
  _rsqlUpdateSelCount();
}

function rsqlFilterRequestList() {
  const q = (document.getElementById("rsql-req-search")?.value || "").trim().toLowerCase();
  const tbody = document.getElementById("rsql-request-tbody");
  if (!tbody) return;
  tbody.querySelectorAll(".rsql-req-row").forEach((row) => {
    const hay = (row.getAttribute("data-search") || "").toLowerCase();
    row.classList.toggle("rsql-req-hidden", !!(q && !hay.includes(q)));
  });
}

function _rsqlUpdateSelCount() {
  const n = _rsqlSelected.size;
  const el = document.getElementById("rsql-req-sel-count");
  if (el) el.textContent = `${n} selected`;
  const cfgBtn = document.getElementById("rsql-btn-configure");
  if (cfgBtn) cfgBtn.disabled = n === 0;
}

function rsqlGoConfigure() {
  if (_rsqlScanning) {
    alert("A scan is already running. Abort it before re-configuring.");
    rsqlSwitchTab("results");
    return;
  }
  const selected = _rsqlGetSelectedEntries();
  if (!selected.length) {
    alert("Select at least one request to configure.");
    return;
  }
  _rsqlBuildConfigFromEntries(selected);
  _rsqlConfigReady = true;
  rsqlSwitchTab("configure");
}

function _rsqlSyncConfigurePane() {
  const selected = _rsqlGetSelectedEntries();
  const cfgEmpty = document.getElementById("rsql-configure-empty");
  const cfgWrap = document.getElementById("rsql-config-wrap");
  const runFooter = document.getElementById("rsql-run-footer");

  if (!selected.length) {
    if (cfgEmpty) cfgEmpty.style.display = "flex";
    if (cfgWrap) cfgWrap.style.display = "none";
    if (runFooter) runFooter.style.display = "none";
    return;
  }

  if (!_rsqlConfigReady) {
    _rsqlBuildConfigFromEntries(selected);
    _rsqlConfigReady = true;
  }

  if (cfgEmpty) cfgEmpty.style.display = "none";
  if (cfgWrap) cfgWrap.style.display = "flex";
  if (runFooter) runFooter.style.display = "flex";

  const banner = document.getElementById("rsql-configure-banner");
  if (banner) {
    banner.textContent = `${selected.length} request(s) selected — params below are from this selection only`;
  }
  rsqlUpdatePayloadCount();
}

/** Build Configure UI from selected entries only (param union). */
function _rsqlBuildConfigFromEntries(entries) {
  // Fill token from memory / selected request headers if the field is still empty
  if (!_rsqlToken) _rsqlToken = _rsqlExtractAuthFromEntries(entries) || "";
  const tokInp = document.getElementById("rsql-token-input");
  if (tokInp && !tokInp.value.trim() && _rsqlToken) tokInp.value = _rsqlToken;
  rsqlSyncTokenHint();

  const bodyFields = {};
  for (const e of entries) {
    if (e.body && typeof e.body === "object") {
      _rsqlCollectBodyLeaves(e.body, "", bodyFields, 0, 6);
    }
  }

  const queryFields = {};
  for (const e of entries) {
    for (const [k, v] of Object.entries(e.query || {})) {
      if (!(k in queryFields)) queryFields[k] = v;
    }
  }

  _rsqlBodyFields = {};
  _rsqlQueryFields = {};
  for (const k of Object.keys(bodyFields)) _rsqlBodyFields[k] = true;
  for (const k of Object.keys(queryFields)) _rsqlQueryFields[k] = true;

  const bodySection = document.getElementById("rsql-body-section");
  const bodyList = document.getElementById("rsql-body-params-list");
  const bodySearch = document.getElementById("rsql-body-param-search");
  if (bodySearch) bodySearch.value = "";
  if (bodySection && bodyList) {
    if (Object.keys(bodyFields).length) {
      bodySection.style.display = "block";
      bodyList.innerHTML = Object.entries(bodyFields).map(([k, v]) => {
        const vs = String(v ?? "");
        const search = `${k} ${vs}`.toLowerCase();
        return `
      <label class="rsql-param-row" data-search="${escHtmlR(search)}">
        <input type="checkbox" class="rsql-param-cb" data-field="${escHtmlR(k)}" data-type="body"
               checked onchange="rsqlToggleField('body',this.getAttribute('data-field'),this.checked)">
        <span class="rsql-param-name">${escHtmlR(k)}</span>
        <span class="rsql-param-val" title="${escHtmlR(vs)}">${escHtmlR(vs.substring(0,40))}</span>
      </label>`;
      }).join("");
    } else {
      bodySection.style.display = "none";
      bodyList.innerHTML = "";
    }
  }

  const querySection = document.getElementById("rsql-query-section");
  const queryList = document.getElementById("rsql-query-params-list");
  const querySearch = document.getElementById("rsql-query-param-search");
  if (querySearch) querySearch.value = "";
  if (querySection && queryList) {
    if (Object.keys(queryFields).length) {
      querySection.style.display = "block";
      queryList.innerHTML = Object.entries(queryFields).map(([k, v]) => {
        const vs = String(v ?? "");
        const search = `${k} ${vs}`.toLowerCase();
        return `
      <label class="rsql-param-row" data-search="${escHtmlR(search)}">
        <input type="checkbox" class="rsql-param-cb" data-field="${escHtmlR(k)}" data-type="query"
               checked onchange="rsqlToggleField('query',this.getAttribute('data-field'),this.checked)">
        <span class="rsql-param-name">${escHtmlR(k)}</span>
        <span class="rsql-param-val" title="${escHtmlR(vs)}">${escHtmlR(vs.substring(0,40))}</span>
      </label>`;
      }).join("");
    } else {
      querySection.style.display = "none";
      queryList.innerHTML = "";
    }
  }

  const hdr = document.getElementById("rsql-inject-headers");
  if (hdr && !Object.keys(bodyFields).length && !Object.keys(queryFields).length) {
    hdr.checked = true;
  }

  rsqlUpdatePayloadCount();
}

function rsqlToggleField(type, field, checked) {
  if (type === "body")  _rsqlBodyFields[field]  = checked;
  if (type === "query") _rsqlQueryFields[field] = checked;
  rsqlUpdatePayloadCount();
}

/** Walk JSON body to scalar leaves; paths like filter.rsql / items[0].name */
function _rsqlCollectBodyLeaves(obj, prefix, out, depth, maxDepth) {
  const skip = new Set([
    "modifiedtime", "createdtime", "creator", "creatorid",
    "lastmodifier", "lastmodifierid",
  ]);
  if (depth > maxDepth) {
    if (prefix && !(prefix in out)) {
      out[prefix] = typeof obj === "object" ? JSON.stringify(obj) : obj;
    }
    return;
  }
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    const keys = Object.keys(obj);
    if (!keys.length && prefix && !(prefix in out)) {
      out[prefix] = "{}";
      return;
    }
    for (const k of keys) {
      if (skip.has(String(k).toLowerCase())) continue;
      const path = prefix ? `${prefix}.${k}` : String(k);
      const v = obj[k];
      if (v !== null && typeof v === "object") {
        _rsqlCollectBodyLeaves(v, path, out, depth + 1, maxDepth);
      } else if (!(path in out)) {
        out[path] = v;
      }
    }
    return;
  }
  if (Array.isArray(obj)) {
    if (!obj.length && prefix && !(prefix in out)) {
      out[prefix] = "[]";
      return;
    }
    obj.forEach((v, i) => {
      const path = prefix ? `${prefix}[${i}]` : `[${i}]`;
      if (v !== null && typeof v === "object") {
        _rsqlCollectBodyLeaves(v, path, out, depth + 1, maxDepth);
      } else if (!(path in out)) {
        out[path] = v;
      }
    });
    return;
  }
  if (prefix && !(prefix in out)) out[prefix] = obj;
}

// ── Category grid ─────────────────────────────────────────────────────────────
function rsqlRenderCategoryGrid() {
  const grid = document.getElementById("rsql-cats-grid");
  if (!grid || !Object.keys(_rsqlCatsMeta).length) return;
  grid.innerHTML = Object.entries(_rsqlCatsMeta).map(([k, m]) => `
    <div class="rsql-cat-card ${_rsqlSelCats[k] ? "selected" : ""}"
         onclick="rsqlToggleCat('${k}', this)">
      <div class="rsql-cat-icon">${m.icon || "🔒"}</div>
      <div class="rsql-cat-name">${escHtmlR(m.label)}</div>
      <div class="rsql-cat-count">${m.count} payloads</div>
    </div>`).join("");
  rsqlUpdateCatsCount();
}

function rsqlToggleCat(key, el) {
  _rsqlSelCats[key] = !_rsqlSelCats[key];
  el.classList.toggle("selected", _rsqlSelCats[key]);
  rsqlUpdateCatsCount();
  rsqlUpdatePayloadCount();
}

function rsqlSelectAllCats() {
  Object.keys(_rsqlSelCats).forEach(k => _rsqlSelCats[k] = true);
  rsqlRenderCategoryGrid();
  rsqlUpdatePayloadCount();
}
function rsqlDeselectAllCats() {
  Object.keys(_rsqlSelCats).forEach(k => _rsqlSelCats[k] = false);
  rsqlRenderCategoryGrid();
  rsqlUpdatePayloadCount();
}

function rsqlUpdateCatsCount() {
  const el = document.getElementById("rsql-cats-count");
  if (!el) return;
  const sel = Object.values(_rsqlSelCats).filter(Boolean).length;
  const tot = Object.keys(_rsqlSelCats).length;
  el.textContent = `${sel} / ${tot} categories selected`;
}

function rsqlFilterParams(type) {
  const listId = type === "body" ? "rsql-body-params-list" : "rsql-query-params-list";
  const searchId = type === "body" ? "rsql-body-param-search" : "rsql-query-param-search";
  const q = (document.getElementById(searchId)?.value || "").trim().toLowerCase();
  const list = document.getElementById(listId);
  if (!list) return;
  list.querySelectorAll(".rsql-param-row").forEach((row) => {
    const hay = (row.getAttribute("data-search") || "").toLowerCase();
    row.classList.toggle("rsql-param-hidden", !!(q && !hay.includes(q)));
  });
}

function _rsqlVisibleParamFields(type) {
  const listId = type === "body" ? "rsql-body-params-list" : "rsql-query-params-list";
  const list = document.getElementById(listId);
  if (!list) return [];
  return Array.from(list.querySelectorAll(".rsql-param-row:not(.rsql-param-hidden) .rsql-param-cb"))
    .map((cb) => cb.getAttribute("data-field"))
    .filter(Boolean);
}

function rsqlSelectAllBody() {
  _rsqlVisibleParamFields("body").forEach((k) => {
    _rsqlBodyFields[k] = true;
    _syncCb("body", k, true);
  });
  rsqlUpdatePayloadCount();
}
function rsqlDeselectAllBody() {
  _rsqlVisibleParamFields("body").forEach((k) => {
    _rsqlBodyFields[k] = false;
    _syncCb("body", k, false);
  });
  rsqlUpdatePayloadCount();
}
function rsqlSelectAllQuery() {
  _rsqlVisibleParamFields("query").forEach((k) => {
    _rsqlQueryFields[k] = true;
    _syncCb("query", k, true);
  });
  rsqlUpdatePayloadCount();
}
function rsqlDeselectAllQuery() {
  _rsqlVisibleParamFields("query").forEach((k) => {
    _rsqlQueryFields[k] = false;
    _syncCb("query", k, false);
  });
  rsqlUpdatePayloadCount();
}

function _syncCb(type, field, checked) {
  // Match by attribute value (paths may contain [0] which breaks CSS selectors)
  document.querySelectorAll(`.rsql-param-cb[data-type="${type}"]`).forEach((cb) => {
    if (cb.getAttribute("data-field") === field) cb.checked = checked;
  });
}

// ── Payload count ─────────────────────────────────────────────────────────────
function rsqlUpdatePayloadCount() {
  const bodyFields   = Object.keys(_rsqlBodyFields).filter(k => _rsqlBodyFields[k]);
  const queryFields  = Object.keys(_rsqlQueryFields).filter(k => _rsqlQueryFields[k]);
  const injectHdrs   = document.getElementById("rsql-inject-headers")?.checked || false;
  const selCats      = Object.keys(_rsqlSelCats).filter(k => _rsqlSelCats[k]);

  let perReq = 0;
  for (const cat of selCats) {
    const m = _rsqlCatsMeta[cat];
    if (!m) continue;
    const isHdrCat = (cat === "rsql_header_injection");
    if (!isHdrCat) {
      perReq += bodyFields.length  * m.count;
      perReq += queryFields.length * m.count;
      if (injectHdrs) perReq += m.count;  // X-Filter header injection
    } else if (injectHdrs) {
      perReq += m.count;
    }
  }
  const reqCount = Math.max(_rsqlGetSelectedEntries().length, 0);
  const total    = perReq * (reqCount || 0);

  const el = document.getElementById("rsql-payload-count");
  if (el) {
    if (reqCount > 1 && perReq > 0) {
      // Show the breakdown so "272" doesn't look mysterious
      el.innerHTML =
        `<strong>${total.toLocaleString()}</strong> total payloads` +
        `<span style="color:var(--text3);font-size:10px;margin-left:6px">` +
        `(${reqCount} requests × ${perReq.toLocaleString()} per request)</span>`;
    } else {
      el.textContent = `${total.toLocaleString()} total payloads`;
    }
  }

  const btn = document.getElementById("rsql-run-btn");
  if (btn && !_rsqlScanning) btn.disabled = total === 0;
}

// ── Start scan ────────────────────────────────────────────────────────────────
async function rsqlStartScan() {
  if (_rsqlScanning) {
    alert("A scan is already running. Abort it before starting another.");
    rsqlSwitchTab("results");
    return;
  }

  const scanEntries = _rsqlGetSelectedEntries();
  if (!scanEntries.length) {
    alert("Select at least one request in the Requests tab.");
    rsqlSwitchTab("requests");
    return;
  }

  const bodyFields  = Object.keys(_rsqlBodyFields).filter(k => _rsqlBodyFields[k]);
  const queryFields = Object.keys(_rsqlQueryFields).filter(k => _rsqlQueryFields[k]);
  const injectHdrs  = document.getElementById("rsql-inject-headers")?.checked || false;
  const selCats     = Object.keys(_rsqlSelCats).filter(k => _rsqlSelCats[k]);
  const token       = document.getElementById("rsql-token-input")?.value.trim() || _rsqlToken || "";
  const delaySec    = parseFloat(document.getElementById("rsql-opt-delay")?.value || "0") || 0;

  if (!bodyFields.length && !queryFields.length && !injectHdrs) {
    alert("Select at least one injection target (body field, query param, or header injection)."); return;
  }
  if (!selCats.length) { alert("Select at least one attack category."); return; }

  _rsqlLastAborted = false;
  const existingAbort = document.getElementById("rsql-aborted-warn");
  if (existingAbort) existingAbort.remove();

  _rsqlAllResults = [];
  _rsqlLastPollDone = -1;
  _rsqlActiveFilter = "all";
  _rsqlLastSummary = null;
  _rsqlExpandedKey = null;
  _rsqlSetScanPct(0, "Starting scan…");
  rsqlSetScanningUI(true);

  // Show Results immediately so rows can stream in
  document.getElementById("rsql-results-empty").style.display = "none";
  document.getElementById("rsql-results-wrap").style.display = "flex";
  _rsqlRefreshResultsUI({ preserveScroll: false, resetFilter: true });
  rsqlSwitchTab("results");

  try {
    const resp = await fetch(`${RSQL_BASE}/rsql/scan`, {
      method:  "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        entries:        scanEntries,
        token,
        body_fields:    bodyFields,
        query_fields:   queryFields,
        inject_headers: injectHdrs,
        categories:     selCats,
        delay_sec:      delaySec,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      const det = data.detail;
      const msg = Array.isArray(det)
        ? det.map(e => e.msg || JSON.stringify(e)).join('; ')
        : (typeof det === 'string' ? det : JSON.stringify(det));
      throw new Error(msg || "Scan start failed");
    }
    _rsqlJobId = data.job_id;
    if (_rsqlPollTimer) clearInterval(_rsqlPollTimer);
    _rsqlPollTimer = setInterval(() => _rsqlPoll(data.total), 700);
    _rsqlPoll(data.total);
  } catch(ex) {
    rsqlSetScanningUI(false);
    alert("❌ Scan error:\n\n" + ex.message);
  }
}

// ── Polling — stream rows into Results (no modal) ─────────────────────────────
async function _rsqlPoll(total) {
  if (!_rsqlJobId) return;
  try {
    const resp = await fetch(`${RSQL_BASE}/rsql/progress/${_rsqlJobId}`);
    if (!resp.ok) return;
    const data = await resp.json();

    const done = data.completed || 0;
    const tot = data.total || total || 0;
    const pct = Math.min(data.progress || 0, 100);
    let label = tot > 0
      ? `${done.toLocaleString()} / ${tot.toLocaleString()} · ✅ ${data.pass_n}  🚨 ${data.vuln_n}  ⚠️ ${data.warn_n}  ❌ ${data.err_n} · ${data.elapsed}s`
      : "Preparing…";
    if (data.aborted && data.status !== "done") label = "Aborting…";
    _rsqlSetScanPct(pct, label);

    // Stream full result list as tests complete
    if (done !== _rsqlLastPollDone || data.status === "done") {
      _rsqlLastPollDone = done;
      try {
        const fullResp = await fetch(`${RSQL_BASE}/rsql/results/${_rsqlJobId}`);
        if (fullResp.ok) {
          const fullData = await fullResp.json();
          _rsqlAllResults = fullData.results || [];
          _rsqlLastSummary = { ...data, ...fullData };
        } else {
          _rsqlAllResults = data.results || _rsqlAllResults;
          _rsqlLastSummary = data;
        }
      } catch (_) {
        _rsqlAllResults = data.results || _rsqlAllResults;
      }
      _rsqlRefreshResultsUI({ preserveScroll: true, resetFilter: false });
      const badge = document.getElementById("rsql-results-badge");
      if (badge) {
        badge.textContent = _rsqlAllResults.length;
        badge.style.display = _rsqlAllResults.length ? "inline" : "none";
      }
    }

    if (data.status === "done") {
      clearInterval(_rsqlPollTimer);
      _rsqlPollTimer = null;
      _rsqlLastAborted = !!data.aborted;
      _rsqlSetScanPct(100, data.aborted ? "⏹ Aborted — partial results" : "Scan complete");
      // Final full refresh
      try {
        const fullResp = await fetch(`${RSQL_BASE}/rsql/results/${_rsqlJobId}`);
        if (fullResp.ok) {
          const fullData = await fullResp.json();
          _rsqlAllResults = fullData.results || [];
          _rsqlLastSummary = { ...data, ...fullData };
        }
      } catch (_) { /* keep last streamed set */ }
      rsqlSetScanningUI(false);
      _rsqlRefreshResultsUI({ preserveScroll: true, resetFilter: false });
      const prog = document.getElementById("rsql-scan-progress-inline");
      if (prog) {
        prog.style.display = "flex";
        setTimeout(() => {
          if (!_rsqlScanning && prog) prog.style.display = "none";
        }, data.aborted ? 4000 : 2500);
      }
      if (data.aborted) _rsqlShowAbortedBanner();
      const badge = document.getElementById("rsql-results-badge");
      if (badge) {
        badge.textContent = _rsqlAllResults.length;
        badge.style.display = _rsqlAllResults.length ? "inline" : "none";
      }
      // Re-enable configure from selection after scan ends
      const cfgBtn = document.getElementById("rsql-btn-configure");
      if (cfgBtn) cfgBtn.disabled = _rsqlSelected.size === 0;
    }
  } catch (_) { /* network hiccup — keep polling */ }
}

// ── Show results ──────────────────────────────────────────────────────────────
function _rsqlIsSqlOrLeak(r) {
  return r.result === "VULN" && (r.match_term === "sql" || r.match_term === "leak");
}

function _rsqlGetFilteredRows(type) {
  const t = type || _rsqlActiveFilter || "all";
  let rows =
    t === "all"       ? _rsqlAllResults.slice()
    : t === "vuln"      ? _rsqlAllResults.filter(r => r.result === "VULN")
    : t === "rsql-vuln" ? _rsqlAllResults.filter(r => r.result === "VULN" && r.match_term === "rsql")
    : t === "fiql-vuln" ? _rsqlAllResults.filter(r => r.result === "VULN" && r.match_term === "fiql")
    : t === "sql-leak"  ? _rsqlAllResults.filter(_rsqlIsSqlOrLeak)
    : t === "pass"      ? _rsqlAllResults.filter(r => r.result === "PASS")
    : t === "warn"      ? _rsqlAllResults.filter(r => r.result === "WARN")
    : t === "err"       ? _rsqlAllResults.filter(r => r.result === "ERROR")
    : t === "body"      ? _rsqlAllResults.filter(r => r.inject_type === "body")
    : t === "query"     ? _rsqlAllResults.filter(r => r.inject_type === "query")
    :                     _rsqlAllResults.filter(r => r.inject_type === "header");

  // Live scan: hide PASS noise so manual validation stays usable (PT-style)
  if (_rsqlScanning && t === "all") {
    rows = rows.filter(r => r.result !== "PASS");
  }
  if (_rsqlScanning) {
    const ord = { VULN: 0, WARN: 1, ERROR: 2, PASS: 3 };
    rows.sort((a, b) => (ord[a.result] ?? 9) - (ord[b.result] ?? 9));
  }
  return rows;
}

function _rsqlRefreshResultsUI(opts = {}) {
  const preserveScroll = !!opts.preserveScroll;
  if (opts.resetFilter) _rsqlActiveFilter = "all";

  document.getElementById("rsql-results-wrap").style.display = "flex";
  document.getElementById("rsql-results-empty").style.display = "none";

  const s = _rsqlLastSummary || {};
  const passN = s.pass_n ?? _rsqlAllResults.filter(r => r.result === "PASS").length;
  const vulnN = s.vuln_n ?? _rsqlAllResults.filter(r => r.result === "VULN").length;
  const warnN = s.warn_n ?? _rsqlAllResults.filter(r => r.result === "WARN").length;
  const errN  = s.err_n  ?? _rsqlAllResults.filter(r => r.result === "ERROR").length;

  const total = _rsqlAllResults.length;
  const rsqlVulnN = _rsqlAllResults.filter(r => r.result === "VULN" && r.match_term === "rsql").length;
  const fiqlVulnN = _rsqlAllResults.filter(r => r.result === "VULN" && r.match_term === "fiql").length;
  const sqlLeakN = _rsqlAllResults.filter(_rsqlIsSqlOrLeak).length;
  const bodyN = _rsqlAllResults.filter(r => r.inject_type === "body").length;
  const queryN = _rsqlAllResults.filter(r => r.inject_type === "query").length;
  const headerN = _rsqlAllResults.filter(r => r.inject_type === "header").length;

  const cards = [
    ["all", "All", total, "mt-card-blue"],
    ["vuln", "VULN", vulnN, vulnN > 0 ? "mt-card-red" : "mt-card-grey"],
    ["rsql-vuln", "RSQL", rsqlVulnN, rsqlVulnN > 0 ? "mt-card-red" : "mt-card-grey"],
    ["fiql-vuln", "FIQL", fiqlVulnN, fiqlVulnN > 0 ? "mt-card-orange" : "mt-card-grey"],
    ["sql-leak", "SQL+", sqlLeakN, sqlLeakN > 0 ? "mt-card-red" : "mt-card-grey"],
    ["pass", "PASS", passN, "mt-card-green"],
    ["warn", "WARN", warnN, "mt-card-orange"],
    ["err", "ERR", errN, "mt-card-grey"],
    ["body", "BODY", bodyN, "mt-card-blue"],
    ["query", "QUERY", queryN, "mt-card-blue"],
    ["header", "HEADER", headerN, "mt-card-blue"],
  ];

  document.getElementById("rsql-summary-cards").innerHTML =
    cards.map(([key, lbl, n, cls]) => `
      <button type="button" class="mt-card rsql-fcard ${cls}" data-filter="${key}"
              onclick="rsqlFilterResults('${key}')"
              title="${key === "sql-leak" ? "Filter: SQL errors & other leak disclosures" : "Filter: " + lbl}">
        <div class="mt-card-num">${Number(n).toLocaleString()}</div>
        <div class="mt-card-lbl">${lbl}</div>
      </button>`).join("");

  _rsqlSyncResultCards();
  _rsqlRenderTable(_rsqlGetFilteredRows(), { preserveScroll });
}

function rsqlFilterResults(type) {
  _rsqlActiveFilter = type || "all";
  _rsqlSyncResultCards();
  _rsqlRenderTable(_rsqlGetFilteredRows(), { preserveScroll: false });
}

function _rsqlSyncResultCards() {
  document.querySelectorAll("#rsql-summary-cards .rsql-fcard").forEach((card) => {
    card.classList.toggle("active", card.getAttribute("data-filter") === _rsqlActiveFilter);
  });
}

// ── cURL generation for a result row ─────────────────────────────────────────
function _rsqlGenCurl(r) {
  // Find matching original entry by URL
  const entry = _rsqlEntries.find(e => e.url === r.api_url) || _rsqlEntries[0] || {};
  const method = (entry.method || "GET").toUpperCase();

  // Build headers: start with original entry headers
  // Normalise to lowercase keys so HTTP/2 doesn't get duplicate headers
  // (HAR may store "authorization" lowercase; we add "Authorization" — same header, two keys)
  const hdrs = {};
  for (const [k, v] of Object.entries(entry.headers || {})) {
    if (k && !k.startsWith(":")) hdrs[k.toLowerCase()] = String(v);
  }
  // Override with the currently active token (single "authorization" key)
  const tok = document.getElementById("rsql-token-input")?.value.trim() || _rsqlToken || "";
  if (tok) hdrs["authorization"] = tok;
  // Remove content-length — curl sets it automatically
  delete hdrs["content-length"];

  // Build URL (may need query injection)
  let url = r.api_url;
  if (r.inject_type === "query") {
    try {
      const u = new URL(url);
      u.searchParams.set(r.field, r.test_value);
      url = u.toString();
    } catch(_) {}
    // Also remove the original query key from headers (it's in URL now)
  } else if (r.inject_type === "header") {
    hdrs[r.field] = String(r.test_value);
  }

  // Build body (for body injection, reconstruct from entry + injected field)
  let bodyStr = "";
  if (r.inject_type === "body") {
    const bodyObj = entry.body && typeof entry.body === "object" && !Array.isArray(entry.body)
      ? { ...entry.body }
      : {};
    bodyObj[r.field] = r.test_value;
    bodyStr = JSON.stringify(bodyObj);
  } else if (method !== "GET" && method !== "DELETE" && entry.body) {
    try { bodyStr = JSON.stringify(entry.body); } catch(_) {}
  }

  // Assemble cURL
  const q = s => `'${String(s).replace(/'/g, "'\\''")}'`;
  let curl = `curl -s -X ${method} ${q(url)}`;
  for (const [k, v] of Object.entries(hdrs)) {
    curl += ` \\\n  -H ${q(`${k}: ${v}`)}`;
  }
  if (bodyStr) curl += ` \\\n  -d ${q(bodyStr)}`;
  return curl;
}

function _rsqlCopyCurl(idx) {
  const rows = _rsqlGetFilteredRows();
  const r = rows[idx]; if (!r) return;
  const curl = _rsqlGenCurl(r);
  navigator.clipboard.writeText(curl).then(() => {
    const btn = document.getElementById(`rsql-curl-btn-${idx}`);
    if (btn) { const t = btn.textContent; btn.textContent = "✅ Copied!"; setTimeout(() => btn.textContent = t, 1500); }
  }).catch(() => prompt("Copy cURL:", curl));
}

// ── Highlight RSQL/FIQL keywords in response body ─────────────────────────────
function _rsqlHighlight(rawText) {
  const esc = escHtmlR(rawText);
  // Highlight RSQL/FIQL + common SQL/stack leak tokens
  return esc.replace(
    /(rsql|fiql|COMP_FIQL|COMP_ALT|ERR-DB-\d+|SQLException|SQLSTATE|sql syntax|ORA-\d+|NullPointerException|stack\s*trace|Traceback)/gi,
    '<mark style="background:#f8514940;color:#f85149;padding:0 2px;border-radius:2px;font-weight:700">$1</mark>'
  );
}

/** Highlight mutated query key=value inside full query string display. */
function _rsqlHighlightQuery(qs, field, value) {
  const raw = String(qs || "");
  if (!raw) {
    return `<span style="color:var(--text3)">(no query)</span>`;
  }
  const esc = escHtmlR(raw);
  const needle = escHtmlR(`${field}=${value}`);
  const marked = esc.split(needle).join(
    `<span style="color:#ffa657;font-weight:700">${needle}</span>`
  );
  return marked +
    `<div style="color:var(--text3);font-size:9px;margin-top:6px">ℹ Only <code>${escHtmlR(field)}</code> was mutated — other query params kept original values.</div>`;
}

/** Highlight mutated JSON field value in request body display. */
function _rsqlHighlightBodyField(body, field, value) {
  const raw = String(body || "(none)");
  let esc = escHtmlR(raw.substring(0, 1500));
  const leaf = String(field).split(".").pop().replace(/\[\d+\]/g, "");
  const valEsc = escHtmlR(String(value));
  // "field": "value" or "field": value
  const re = new RegExp(
    `(&quot;${escHtmlR(leaf)}&quot;\\s*:\\s*)(&quot;${valEsc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}&quot;|${valEsc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`,
    "g"
  );
  esc = esc.replace(re, `$1<span style="color:#ffa657;font-weight:700">$2</span>`);
  return esc +
    `<div style="color:var(--text3);font-size:9px;margin-top:6px">ℹ Only <code>${escHtmlR(field)}</code> was mutated — other body fields kept original values.</div>`;
}

// ── Results table ─────────────────────────────────────────────────────────────
function _rsqlRowKey(r) {
  // Stable across live re-renders / re-sorts (not display index)
  return [
    r.api_url || "",
    r.inject_type || "",
    r.field || "",
    r.case_id || "",
    r.test_value || "",
    r.status_code ?? "",
    r.result || "",
    r.match_term || "",
    r.elapsed_ms ?? "",
  ].join("\x1f");
}

function _rsqlRenderTable(rows, opts = {}) {
  const tbody = document.getElementById("rsql-results-tbody");
  if (!tbody) return;
  const wrap = document.getElementById("rsql-results-table-wrap");
  const scrollTop = opts.preserveScroll && wrap ? wrap.scrollTop : 0;

  if (!rows.length) {
    const emptyMsg = _rsqlScanning
      ? "Scanning… interesting findings appear here as tests complete (PASS rows hidden until scan ends — open PASS card to see them)."
      : "No results for this filter.";
    tbody.innerHTML = `<tr><td colspan="9" class="mt-empty-row">${emptyMsg}</td></tr>`;
    if (opts.preserveScroll && wrap) wrap.scrollTop = scrollTop;
    return;
  }

  // Show max 2000 rows for performance
  const display = rows.slice(0, 2000);
  const truncMsg = rows.length > 2000
    ? `<tr><td colspan="9" style="text-align:center;color:var(--text3);font-size:11px;padding:8px">
         Showing 2,000 of ${rows.length.toLocaleString()} rows — use CSV export for full results
       </td></tr>` : "";

  const RC = { PASS:"#3fb950", VULN:"#f85149", WARN:"#d29922", ERROR:"#6e7681" };
  const TC = { body:"#1f6feb", query:"#8957e5", header:"#d29922" };
  const stCl = n => { const c=parseInt(n); return isNaN(c)?"mt-status-err":c<300?"mt-status-2xx":c<400?"mt-status-4xx":"mt-status-5xx"; };

  tbody.innerHTML = display.map((r, i) => {
    const isVuln   = r.result === "VULN";
    const rCol     = RC[r.result] || "#8b949e";
    const tCol     = TC[r.inject_type] || "#8b949e";
    const uid      = `rsqlrow-${i}`;
    const rowKey   = _rsqlRowKey(r);
    const keyAttr  = escHtmlR(rowKey);
    const isOpen   = _rsqlExpandedKey === rowKey;
    const rowBg    = isVuln ? "background:#1a0808;" : r.result === "WARN" ? "background:#141000;" : "";
    return `
      <tr class="mt-result-row${isOpen ? " mt-row-selected" : ""}" data-row-key="${keyAttr}"
          onclick="rsqlToggleExpand('${uid}', this)"
          style="cursor:pointer;${rowBg}">
        <td class="mt-td-num">${i+1}</td>
        <td><span style="background:${tCol}22;color:${tCol};border:1px solid ${tCol}44;
                         padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;white-space:nowrap">
          ${r.inject_type.toUpperCase()}</span></td>
        <td style="font-family:var(--mono);font-size:11px;color:#ffa657;white-space:nowrap">${escHtmlR(r.field)}</td>
        <td style="font-size:10px;color:var(--text2);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${escHtmlR(r.category)}">${escHtmlR(r.category)}</td>
        <td style="font-size:10px;color:var(--yellow);font-family:var(--mono);white-space:nowrap">${escHtmlR(r.case_id)}</td>
        <td style="font-size:10px;color:var(--text3);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${escHtmlR(r.test_value)}">${escHtmlR(String(r.test_value).substring(0, 40))}</td>
        <td><span class="${stCl(r.status_code)} mt-status-badge">${r.status_code}</span></td>
        <td><span style="background:${rCol};color:#fff;padding:2px 8px;border-radius:4px;
                         font-size:10px;font-weight:700;white-space:nowrap">
          ${isVuln?"🚨 ":""}${r.result}</span></td>
        <td style="font-size:11px;color:var(--text3);white-space:nowrap">${r.elapsed_ms}ms</td>
      </tr>
      <tr class="mt-expand-row" id="${uid}" data-row-key="${keyAttr}"
          style="display:${isOpen ? "table-row" : "none"}">
        <td colspan="9" class="mt-expand-cell">
          <div class="rsql-expand-url">
            <span style="opacity:.5;margin-right:4px">🔗</span>
            <span style="user-select:all">${escHtmlR(r.api_url)}</span>
          </div>
          <div class="mt-response-grid">
            <div class="mt-resp-panel">
              <div class="mt-resp-label" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                <span>📤 Request Sent</span>
                <span class="mt-resp-method">${escHtmlR(r.inject_type.toUpperCase())}</span>
                <span class="mt-resp-method" style="color:${tCol}">${escHtmlR(r.field)}</span>
                <button type="button" id="rsql-curl-btn-${i}" class="rsql-copy-curl-btn"
                  onclick="event.stopPropagation();_rsqlCopyCurl(${i})"
                  title="Copy full cURL for manual validation">📋 Copy cURL</button>
              </div>
              ${r.inject_type === "header"
                ? `<pre class="mt-resp-body" style="white-space:pre-wrap">${escHtmlR(r.field)}: <span style="color:#ffa657;font-weight:700">${escHtmlR(String(r.test_value))}</span>\n\n<span style="color:var(--text3);font-size:9px">ℹ All original request headers are also sent automatically.</span></pre>`
                : r.inject_type === "query"
                  ? `<pre class="mt-resp-body" style="white-space:pre-wrap">${_rsqlHighlightQuery(r.request_body || "", r.field, r.test_value)}</pre>`
                  : `<pre class="mt-resp-body">${_rsqlHighlightBodyField(r.request_body || "(none)", r.field, r.test_value)}</pre>`
              }
            </div>
            <div class="mt-resp-panel">
              <div class="mt-resp-label">
                📥 Server Response
                <span class="mt-resp-method" style="color:${rCol}">${r.status_code}</span>
                ${r.match_term === "rsql"         ? `<span style="background:#f85149;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;margin-left:4px;font-weight:700">🚨 RSQL FOUND IN BODY</span>`   : ""}
                ${r.match_term === "fiql"         ? `<span style="background:#f85149;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;margin-left:4px;font-weight:700">🚨 FIQL FOUND IN BODY</span>`   : ""}
                ${r.match_term === "fiql_grammar" ? `<span style="background:#d29922;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;margin-left:4px;font-weight:700">⚠ FIQL GRAMMAR ERROR</span>` : ""}
                ${r.match_term === "sql"          ? `<span style="background:#f85149;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;margin-left:4px;font-weight:700">🚨 SQL / DB ERROR</span>` : ""}
                ${r.match_term === "leak"         ? `<span style="background:#f85149;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;margin-left:4px;font-weight:700">🚨 STACK / LEAK</span>` : ""}
              </div>
              <pre class="mt-resp-body">${_rsqlHighlight((r.response||"(empty)").substring(0,1500))}</pre>
            </div>
          </div>
        </td>
      </tr>`;
  }).join("") + truncMsg;

  if (opts.preserveScroll && wrap) wrap.scrollTop = scrollTop;
}

function rsqlToggleExpand(uid, rowEl) {
  const row = document.getElementById(uid); if (!row) return;
  const isOpen = row.style.display !== "none";
  const key = (rowEl || row.previousElementSibling)?.getAttribute("data-row-key")
    || row.getAttribute("data-row-key")
    || null;
  document.querySelectorAll("#tool-rsql .mt-expand-row").forEach(r => r.style.display = "none");
  document.querySelectorAll("#tool-rsql .mt-result-row").forEach(r => r.classList.remove("mt-row-selected"));
  if (!isOpen) {
    row.style.display = "table-row";
    (rowEl || row.previousElementSibling)?.classList.add("mt-row-selected");
    _rsqlExpandedKey = key;
  } else {
    _rsqlExpandedKey = null;
  }
}

// ── Export ────────────────────────────────────────────────────────────────────
async function rsqlDownloadCsv() {
  if (!_rsqlJobId) return;
  try {
    const resp = await fetch(`${RSQL_BASE}/rsql/csv/${_rsqlJobId}`);
    const text = await resp.text();
    const ts = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
    if (window.pywebview?.api?.save_file) {
      await window.pywebview.api.save_file(text, `rsql_report_${ts}.csv`);
    } else {
      const a = document.createElement("a");
      a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(text);
      a.download = `rsql_report_${ts}.csv`; a.click();
    }
  } catch(ex) { alert("CSV export failed: " + ex.message); }
}

async function rsqlDownloadHtml() {
  if (!_rsqlAllResults.length) return;
  const html = _rsqlGenHtml();
  const ts   = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
  if (window.pywebview?.api?.save_file) {
    await window.pywebview.api.save_file(html, `rsql_report_${ts}.html`);
  } else {
    const a = document.createElement("a");
    a.href = "data:text/html;charset=utf-8," + encodeURIComponent(html);
    a.download = `rsql_report_${ts}.html`; a.click();
  }
}

function _rsqlGenHtml() {
  const s    = _rsqlLastSummary || {};
  const ts   = new Date().toLocaleString();
  const total  = _rsqlAllResults.length;
  const vulnN  = s.vuln_n || 0;
  const passN  = s.pass_n || 0;
  const warnN  = s.warn_n || 0;
  const errN   = s.err_n  || 0;

  const RC = { PASS:"#238636", VULN:"#da3633", WARN:"#d29922", ERROR:"#6e7681" };
  const TC = { body:"#1f6feb", query:"#8957e5", header:"#d29922" };
  const stC = n => { const c=parseInt(n); return isNaN(c)?'#6e7681':c<300?'#238636':c<400?'#58a6ff':c<500?'#d29922':'#da3633'; };

  const rowsHtml = _rsqlAllResults.map((r, i) => {
    const isVuln = r.result === "VULN";
    const rc = RC[r.result] || "#6e7681";
    const tc = TC[r.inject_type] || "#6e7681";
    const uid = `r${i}`;
    return `
<tr data-result="${escHtmlR(r.result)}" data-type="${escHtmlR(r.inject_type)}"
    style="background:${isVuln?"#1a0808":""};cursor:pointer" onclick="tog('${uid}')">
  <td style="color:var(--text);font-size:11px">${i+1}</td>
  <td><span style="background:${tc};color:#fff;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700">${r.inject_type.toUpperCase()}</span></td>
  <td><code style="color:#ffa657;font-size:11px">${escHtmlR(r.field)}</code></td>
  <td style="font-size:10px;color:var(--text)">${escHtmlR(r.category)}</td>
  <td style="font-size:10px;color:#e3b341;font-family:monospace">${escHtmlR(r.case_id)}</td>
  <td style="font-size:11px;color:#ff7b72;max-width:150px;word-break:break-all">${escHtmlR(String(r.test_value).substring(0,60))}</td>
  <td style="font-size:10px;color:#79c0ff;max-width:180px;word-break:break-all"><a href="${escHtmlR(r.api_url)}" style="color:#79c0ff;text-decoration:none" title="${escHtmlR(r.api_url)}">${escHtmlR((r.api_url.split("//")[1]||r.api_url).substring(0,50))}</a></td>
  <td><span style="background:${stC(r.status_code)};color:#fff;border-radius:3px;padding:2px 6px;font-size:11px;font-weight:700">${r.status_code}</span></td>
  <td><span style="background:${rc};color:#fff;border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700">${isVuln?"🚨 ":""}${r.result}</span></td>
  <td style="font-size:11px;color:var(--text)">${r.elapsed_ms}ms</td>
</tr>
<tr id="${uid}" style="display:none;background:#0d1117">
  <td colspan="10">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px">
      <div><div style="font-size:11px;font-weight:700;color:#58a6ff;margin-bottom:4px">📤 Request Sent</div>
        <pre style="width:100%;height:160px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:10px;background:#161b22;border:1px solid #21262d;border-radius:4px;padding:8px;color:#c9d1d9;box-sizing:border-box">${escHtmlR((r.request_body||"").substring(0,1500))}</pre></div>
      <div><div style="font-size:11px;font-weight:700;color:${isVuln?"#f85149":"#58a6ff"};margin-bottom:4px">📥 Response ${isVuln?"⚠ RSQL FOUND":""}</div>
        <pre style="width:100%;height:160px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:10px;background:#161b22;border:1px solid ${isVuln?"#f85149":"#21262d"};border-radius:4px;padding:8px;color:#c9d1d9;box-sizing:border-box">${escHtmlR((r.response||"").substring(0,1500))}</pre></div>
    </div>
  </td>
</tr>`;
  }).join("");

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>RSQL Security Test Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#080c10;color:#c9d1d9;padding:24px;font-size:13px}
h1{font-size:22px;font-weight:800;background:linear-gradient(135deg,#da3633,#ff7b72,#ffa657);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{color:var(--text);font-size:11px;font-family:monospace;margin:4px 0 18px}
.cards{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}
.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 18px;text-align:center;min-width:90px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.c-tot::before{background:#58a6ff}.c-vuln::before{background:#da3633}.c-pass::before{background:#238636}.c-warn::before{background:#d29922}.c-err::before{background:#6e7681}.c-dur::before{background:#a371f7}
.card h3{font-size:22px;font-weight:800;margin-bottom:2px}.card p{font-size:9px;color:var(--text);text-transform:uppercase;letter-spacing:1px}
.c-tot h3{color:#58a6ff}.c-vuln h3{color:#da3633}.c-pass h3{color:#238636}.c-warn h3{color:#d29922}.c-err h3{color:var(--text)}.c-dur h3{color:#a371f7}
.banner-vuln{background:#da363320;border:1px solid #da3633;border-radius:8px;padding:10px 16px;margin-bottom:14px;color:#ff7b72;font-size:13px;font-weight:600}
.banner-safe{background:#23863620;border:1px solid #238636;border-radius:8px;padding:10px 16px;margin-bottom:14px;color:#3fb950;font-size:13px;font-weight:600}
hr{border:none;border-top:1px solid #21262d;margin:14px 0}
.filters{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.fb{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 10px;cursor:pointer;font-size:11px;font-family:'Segoe UI',sans-serif}
.fb.active{background:#1f6feb;color:#fff;border-color:#1f6feb}
.fb.fv{background:#da363320;color:#ff7b72;border-color:#da3633}
.fb.fv.active{background:#da3633;color:#fff}
table{border-collapse:collapse;width:100%;font-size:12px;border:1px solid #21262d;border-radius:6px;overflow:hidden}
th{background:#161b22;color:var(--text);padding:6px 10px;text-align:left;font-size:9px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #30363d;position:sticky;top:0}
td{padding:6px 10px;border-bottom:1px solid #161b22;vertical-align:middle}
tr:hover td{background:#161b22!important}
</style>
</head><body>
<h1>🔒 RSQL Security Test Report</h1>
<p class="sub">Generated: ${ts} &nbsp;|&nbsp; Total payloads: ${total.toLocaleString()}</p>
${vulnN > 0
  ? `<div class="banner-vuln">🚨 RSQL VULNERABILITY DETECTED: ${vulnN} response(s) contained "rsql" or "fiql" in body — these endpoints are exposing RSQL internals!</div>`
  : `<div class="banner-safe">✅ No RSQL exposure detected. None of the ${total.toLocaleString()} responses contained "rsql" or "fiql" in the body.</div>`}
<div class="cards">
  <div class="card c-tot"><h3>${total.toLocaleString()}</h3><p>Total</p></div>
  <div class="card c-vuln"><h3>${vulnN}</h3><p>🚨 VULN</p></div>
  <div class="card c-pass"><h3>${passN.toLocaleString()}</h3><p>✅ PASS</p></div>
  <div class="card c-warn"><h3>${warnN}</h3><p>⚠ WARN</p></div>
  <div class="card c-err"><h3>${errN}</h3><p>ERR</p></div>
  <div class="card c-dur"><h3>${s.elapsed||0}s</h3><p>Duration</p></div>
</div>
<hr>
<p style="font-size:11px;color:var(--text);margin-bottom:10px">
  <b style="color:#238636">PASS</b> = no rsql/fiql in response &nbsp;|&nbsp;
  <b style="color:#da3633">🚨 VULN</b> = rsql/fiql found in response body — VULNERABILITY &nbsp;|&nbsp;
  Click any row to expand request/response
</p>
<div class="filters">
  <button class="fb active" onclick="filter('ALL',this)">All (${total.toLocaleString()})</button>
  <button class="fb fv"     onclick="filter('VULN',this)">🚨 VULN (${vulnN})</button>
  <button class="fb"        onclick="filter('PASS',this)">✅ PASS (${passN.toLocaleString()})</button>
  <button class="fb"        onclick="filter('WARN',this)">⚠ WARN (${warnN})</button>
  <button class="fb"        onclick="filter('BODY',this)">Body Inject</button>
  <button class="fb"        onclick="filter('QUERY',this)">Query Inject</button>
  <button class="fb"        onclick="filter('HEADER',this)">Header Inject</button>
</div>
<div style="overflow-x:auto">
<table id="T">
  <thead><tr><th>#</th><th>TYPE</th><th>FIELD</th><th>CATEGORY</th><th>CASE ID</th><th>PAYLOAD</th><th>API URL</th><th>STATUS</th><th>RESULT</th><th>TIME</th></tr></thead>
  <tbody>${rowsHtml}</tbody>
</table>
</div>
<script>
function tog(id){var r=document.getElementById(id);if(r)r.style.display=r.style.display==='none'?'table-row':'none';}
function filter(f,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#T tr[id^="r"]').forEach(r=>r.style.display='none');
  document.querySelectorAll('#T tr[data-result]').forEach(function(row){
    var res=row.getAttribute('data-result').toUpperCase();
    var typ=row.getAttribute('data-type').toUpperCase();
    var show=f==='ALL'||res===f||typ===f;
    row.style.display=show?'':'none';
  });
}
<\/script>
</body></html>`;
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function rsqlReset() {
  if (_rsqlScanning) {
    alert("Stop the running scan (Abort) before starting a new one.");
    rsqlSwitchTab("results");
    return;
  }
  if (_rsqlPollTimer) clearInterval(_rsqlPollTimer);
  _rsqlPollTimer = null;
  _rsqlEntries = [];
  _rsqlSelected = new Set();
  _rsqlToken = "";
  _rsqlBodyFields = {};
  _rsqlQueryFields = {};
  _rsqlConfigReady = false;
  _rsqlJobId = null;
  _rsqlAllResults = [];
  _rsqlLastSummary = null;
  _rsqlActiveFilter = "all";
  _rsqlLastPollDone = -1;
  _rsqlLastAborted = false;
  _rsqlExpandedKey = null;
  rsqlSetScanningUI(false);

  const el = id => document.getElementById(id);
  if (el("rsql-entry-count")) el("rsql-entry-count").textContent = "No requests loaded";
  if (el("rsql-empty-state")) el("rsql-empty-state").style.display = "flex";
  if (el("rsql-request-list-wrap")) el("rsql-request-list-wrap").style.display = "none";
  if (el("rsql-req-filter-bar")) el("rsql-req-filter-bar").style.display = "none";
  if (el("rsql-req-sel-all")) el("rsql-req-sel-all").style.display = "none";
  if (el("rsql-req-sel-none")) el("rsql-req-sel-none").style.display = "none";
  if (el("rsql-btn-configure")) el("rsql-btn-configure").disabled = true;
  if (el("rsql-request-tbody")) el("rsql-request-tbody").innerHTML = "";
  if (el("rsql-req-search")) el("rsql-req-search").value = "";
  if (el("rsql-req-sel-count")) el("rsql-req-sel-count").textContent = "0 selected";
  if (el("rsql-configure-empty")) el("rsql-configure-empty").style.display = "flex";
  if (el("rsql-config-wrap")) el("rsql-config-wrap").style.display = "none";
  if (el("rsql-run-footer")) el("rsql-run-footer").style.display = "none";
  if (el("rsql-scan-progress-inline")) el("rsql-scan-progress-inline").style.display = "none";
  if (el("rsql-aborted-warn")) el("rsql-aborted-warn").remove();
  if (el("rsql-results-wrap")) el("rsql-results-wrap").style.display = "none";
  if (el("rsql-results-empty")) el("rsql-results-empty").style.display = "flex";
  if (el("rsql-token-input")) el("rsql-token-input").value = "";
  if (el("rsql-body-params-list")) el("rsql-body-params-list").innerHTML = "";
  if (el("rsql-query-params-list")) el("rsql-query-params-list").innerHTML = "";
  if (el("rsql-body-section")) el("rsql-body-section").style.display = "none";
  if (el("rsql-query-section")) el("rsql-query-section").style.display = "none";
  if (el("rsql-inject-headers")) el("rsql-inject-headers").checked = false;
  const badge = el("rsql-results-badge");
  if (badge) { badge.textContent = "0"; badge.style.display = "none"; }
  rsqlSwitchTab("requests");
}
window.rsqlReset = rsqlReset;

function escHtmlR(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
