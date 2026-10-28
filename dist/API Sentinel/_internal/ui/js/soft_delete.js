// ── Soft Delete Frontend ─────────────────────────────────────────────────────
const SD_BASE = "http://127.0.0.1:8769";

let _sdEndpoints   = [];
let _sdHarData     = null;
let _sdJobId       = null;
let _sdPollTimer   = null;
let _sdAllLogs     = [];
let _sdBypassLogs  = [];
let _sdLastJob     = null;
let _sdPendingHar  = null;
let _sdPendingReqs = null;
let _sdPendingSrc  = null;
let _sdBypassUrls  = {};  // uid -> bypass_url
let _sdCurls       = {};  // uid -> { orig: string, mod: string }
let _sdChecked     = {};  // {url: bool}
let _sdFilterText  = "";
let _sdAborting    = false;

// ── Tab switch ────────────────────────────────────────────────────────────────
function sdSwitchTab(tab) {
  document.getElementById("sd-tab-capture").classList.toggle("active", tab === "capture");
  document.getElementById("sd-tab-results").classList.toggle("active", tab === "results");
  document.getElementById("sd-tab-capture-content").style.display = tab === "capture" ? "flex" : "none";
  document.getElementById("sd-tab-results-content").style.display = tab === "results"  ? "flex" : "none";
}

// ── HAR input setup ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const inp = document.getElementById("sd-har-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    try {
      const text = await file.text();
      const har  = JSON.parse(text);
      let autoToken = "";
      for (const entry of (har?.log?.entries || [])) {
        for (const h of (entry?.request?.headers || [])) {
          if (h.name.toLowerCase() === "authorization") { autoToken = h.value; break; }
        }
        if (autoToken) break;
      }
      _sdPendingHar = har; _sdPendingSrc = "har";
      _sdShowTokenModal(autoToken, "Token auto-extracted from HAR. Replace if expired.");
    } catch(e) { alert("HAR parse error: " + e.message); }
    inp.value = "";
  };
});

// ── Token modal ───────────────────────────────────────────────────────────────
function _sdShowTokenModal(token, sub) {
  const modal = document.getElementById("sd-token-modal");
  const inp   = document.getElementById("sd-token-modal-input");
  const sub_  = document.getElementById("sd-token-sub");
  if (inp)  inp.value = token || "";
  if (sub_) sub_.textContent = sub || "";
  modal.style.display = "flex";
  setTimeout(() => inp?.focus(), 80);
}

function sdCancelToken() {
  document.getElementById("sd-token-modal").style.display = "none";
  _sdPendingHar = null; _sdPendingReqs = null; _sdPendingSrc = null;
}

function sdConfirmToken() {
  const token = document.getElementById("sd-token-modal-input").value.trim();
  document.getElementById("sd-token-modal").style.display = "none";
  const tf = document.getElementById("sd-token-input");
  if (tf) tf.value = token;
  if (_sdPendingSrc === "har" && _sdPendingHar) {
    _sdLoadFromHar(_sdPendingHar, token);
  } else if (_sdPendingSrc === "capture" && _sdPendingReqs) {
    _sdLoadFromReqs(_sdPendingReqs, token);
  }
  _sdPendingHar = null; _sdPendingReqs = null; _sdPendingSrc = null;
}

// ── Load from HAR ─────────────────────────────────────────────────────────────
function _sdLoadFromHar(har, token) {
  _sdHarData = har;
  _sdParseEndpoints(har.log?.entries || [], token);
}

function _sdParseEndpoints(entries, token) {
  const STATIC  = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp)(\?|$)/i;
  const SD_KEYS = ["deleted==false", "isDeleted==false"];
  const seen = new Set();
  _sdEndpoints = [];
  _sdChecked   = {};

  for (const entry of entries) {
    const rq  = (entry.request || entry); // support both HAR entry and raw req object
    const method = ((rq.method || "GET")).toUpperCase();
    if (method !== "GET") continue;
    const url = rq.url || "";
    if (!url.startsWith("http") || STATIC.test(url) || seen.has(url)) continue;
    const decoded = decodeURIComponent(url);
    const matchedFilter = SD_KEYS.find(k => decoded.includes(k) || url.includes(k));
    if (!matchedFilter) continue;
    seen.add(url);

    const hdrs = {};
    const rawHdrs = rq.headers || [];
    for (const h of rawHdrs) {
      const name  = h.name || h[0];
      const value = h.value || h[1];
      if (name && !name.startsWith(":") && name.toLowerCase() !== "content-length")
        hdrs[name] = value;
    }
    // inject token
    if (token) {
      const ak = Object.keys(hdrs).find(k => k.toLowerCase() === "authorization") || "Authorization";
      hdrs[ak] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
    }
    _sdEndpoints.push({ url, filter: matchedFilter, hdrs });
    _sdChecked[url] = true;
  }

  const count = _sdEndpoints.length;
  document.getElementById("sd-ep-count").textContent =
    count > 0 ? `${count} soft-delete URL(s) found` : "0 matching URLs (need deleted==false or isDeleted==false in params)";
  _sdRenderList();
}

// ── Load from AV ──────────────────────────────────────────────────────────────
function sdLoadFromAV() {
  const reqs = window._avState?.requests || [];
  if (!reqs.length) {
    alert("No requests in API Validator capture.\n\nImport cURL or capture requests in API Validator Pro first.");
    return;
  }
  let autoToken = "";
  for (const r of reqs) {
    const k = Object.keys(r.headers||{}).find(k => k.toLowerCase() === "authorization");
    if (k) { autoToken = r.headers[k]; break; }
  }
  _sdPendingReqs = reqs; _sdPendingSrc = "capture";
  _sdShowTokenModal(autoToken, `${reqs.length} requests from AV Capture. Replace token if expired.`);
}

function _sdLoadFromReqs(reqs, token) {
  // Build synthetic HAR-like entries from AV requests
  const entries = reqs.map(r => ({
    method:  r.method || "GET",
    url:     r.url || "",
    headers: Object.entries(r.headers || {}).map(([name,value]) => ({name,value})),
  }));
  // Build a real HAR so backend can scan it too
  _sdHarData = { log: { entries: entries.map(e => ({ request: e })) } };
  _sdParseEndpoints(entries, token);
  document.getElementById("sd-ep-count").textContent = _sdEndpoints.length > 0
    ? `${_sdEndpoints.length} soft-delete URL(s) (from AV)`
    : "No deleted==false / isDeleted==false APIs found in AV Capture";
}

// ── Render endpoint list ──────────────────────────────────────────────────────
function _sdRenderList() {
  const list  = document.getElementById("sd-endpoint-list");
  const empty = document.getElementById("sd-endpoint-empty");
  if (!_sdEndpoints.length) { list.style.display = "none"; empty.style.display = "flex"; return; }
  list.style.display = "flex"; empty.style.display = "none";

  const filter   = _sdFilterText.toLowerCase();
  const filtered = filter
    ? _sdEndpoints.filter(ep => ep.url.toLowerCase().includes(filter))
    : _sdEndpoints;

  list.innerHTML = filtered.map(ep => {
    const checked = _sdChecked[ep.url] !== false;
    const safeUrl = ep.url.replace(/'/g, "\\'");
    return `
    <div class="mt-ep-row ${checked ? "mt-ep-checked" : ""}" onclick="sdToggleEp('${safeUrl}', this)">
      <input type="checkbox" class="mt-ep-cb" ${checked ? "checked" : ""}
             onclick="event.stopPropagation(); sdToggleEp('${safeUrl}', this.closest('.mt-ep-row'))">
      <span class="mt-ep-method" style="color:#3fb950;background:rgba(63,185,80,.12);border:1px solid rgba(63,185,80,.3)">GET</span>
      <span class="mt-ep-url" title="${escHtml(ep.url)}">${escHtml(ep.url)}</span>
      <span style="font-size:10px;color:var(--yellow);font-family:var(--mono);flex-shrink:0;margin-left:8px">${ep.filter}</span>
    </div>`;
  }).join("");

  const sel = Object.values(_sdChecked).filter(Boolean).length;
  const btn = document.getElementById("sd-run-btn");
  if (btn) btn.textContent = `🚀 Run Soft Delete Scan (${sel} selected)`;
}

function sdToggleEp(url, row) {
  _sdChecked[url] = !_sdChecked[url];
  row.classList.toggle("mt-ep-checked", _sdChecked[url]);
  const cb = row.querySelector(".mt-ep-cb");
  if (cb) cb.checked = _sdChecked[url];
  const sel = Object.values(_sdChecked).filter(Boolean).length;
  const btn = document.getElementById("sd-run-btn");
  if (btn) btn.textContent = `🚀 Run Soft Delete Scan (${sel} selected)`;
}

function sdSelectAll() {
  const filter = _sdFilterText.toLowerCase();
  const targets = filter ? _sdEndpoints.filter(ep => ep.url.toLowerCase().includes(filter)) : _sdEndpoints;
  targets.forEach(ep => { _sdChecked[ep.url] = true; });
  _sdRenderList();
}

function sdDeselectAll() {
  const filter = _sdFilterText.toLowerCase();
  const targets = filter ? _sdEndpoints.filter(ep => ep.url.toLowerCase().includes(filter)) : _sdEndpoints;
  targets.forEach(ep => { _sdChecked[ep.url] = false; });
  _sdRenderList();
}

function sdFilterCapture() {
  _sdFilterText = document.getElementById("sd-url-filter-input").value;
  _sdRenderList();
}

// ── Run scan ──────────────────────────────────────────────────────────────────
async function sdRunScan() {
  if (!_sdEndpoints.length) { alert("No soft-delete URLs found. Import a HAR or load from AV Capture first."); return; }

  // Only scan selected endpoints
  const selected = _sdEndpoints.filter(ep => _sdChecked[ep.url] !== false);
  if (!selected.length) { alert("Select at least one endpoint to scan."); return; }

  // Rebuild a HAR from only the selected endpoints
  const filteredHar = {
    log: {
      entries: selected.map(ep => ({
        request: {
          method : "GET",
          url    : ep.url,
          headers: Object.entries(ep.hdrs).map(([name, value]) => ({ name, value })),
        }
      }))
    }
  };

  const token = document.getElementById("sd-token-input").value.trim();
  const btn   = document.getElementById("sd-run-btn");
  btn.disabled = true; btn.textContent = "⏳ Starting...";

  const blob = new Blob([JSON.stringify(filteredHar)], { type: "application/json" });
  const file = new File([blob], "scan.har", { type: "application/json" });
  const fd   = new FormData();
  fd.append("file", file);
  fd.append("token", token);

  try {
    const resp = await fetch(`${SD_BASE}/sd/scan`, { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Scan failed");
    _sdJobId = data.job_id;
    sdSwitchTab("results");
    _sdStartPolling(data.total);
  } catch(e) {
    alert("Error: " + e.message);
    btn.disabled = false; btn.textContent = "🚀 Run Soft Delete Scan";
  }
}

// ── Abort ─────────────────────────────────────────────────────────────────────
async function sdAbortScan() {
  if (!_sdJobId || _sdAborting) return;
  _sdAborting = true;
  const abortBtn = document.getElementById("sd-btn-abort");
  if (abortBtn) { abortBtn.disabled = true; abortBtn.textContent = "⏳ Aborting…"; }
  const title = document.getElementById("sd-scan-title");
  if (title) title.innerHTML = `<span>⏹ Aborting Scan…</span>`;
  const currEl = document.getElementById("sd-scan-current");
  if (currEl) currEl.textContent = "⏹ Abort requested — completing current request...";
  try {
    await fetch(`${SD_BASE}/sd/abort/${_sdJobId}`, { method: "POST" });
  } catch (_) { /* poll finishes with partial results */ }
}
window.sdAbortScan = sdAbortScan;

// ── Polling ───────────────────────────────────────────────────────────────────
function _sdStartPolling(total) {
  const overlay = document.getElementById("sd-scanning-overlay");
  const wrap    = document.getElementById("sd-results-wrap");
  overlay.style.display = "flex"; wrap.style.display = "none";
  document.getElementById("sd-results-empty").style.display = "none";
  document.getElementById("sd-scan-fill").style.width = "0%";
  const pctEl = document.getElementById("sd-running-pct");
  if (pctEl) pctEl.textContent = "0%";
  document.getElementById("sd-scan-stats").textContent = `0 / ${total} endpoints · 0 bypass(es) · 0.0s`;
  const currEl = document.getElementById("sd-scan-current");
  if (currEl) currEl.textContent = "Initializing test engine and analyzing endpoints...";
  const feedEl = document.getElementById("sd-scan-feed");
  if (feedEl) feedEl.innerHTML = `<div style="color:var(--text3);font-style:italic;padding:14px;text-align:center"><span class="sd-live-pulse-dot"></span> Initializing tests and analyzing endpoints...</div>`;
  const countEl = document.getElementById("sd-feed-count");
  if (countEl) countEl.textContent = "0 events";
  const pillEl = document.getElementById("sd-live-summary-pills");
  if (pillEl) {
    pillEl.innerHTML = `
      <span style="background:rgba(63,185,80,0.12);color:#3fb950;padding:2px 8px;border-radius:4px;border:1px solid rgba(63,185,80,0.25)">🔒 0 Secure</span>
      <span style="background:rgba(248,81,73,0.12);color:#f85149;padding:2px 8px;border-radius:4px;border:1px solid rgba(248,81,73,0.25)">⚠️ 0 Bypass</span>
    `;
  }
  const title = document.getElementById("sd-scan-title");
  if (title) title.innerHTML = `<span>🗑️ Testing Soft-Delete Bypass Variants...</span>`;
  const abortBtn = document.getElementById("sd-btn-abort");
  if (abortBtn) { abortBtn.disabled = false; abortBtn.textContent = "⏹ Abort Scan"; }
  _sdAborting = false;

  if (_sdPollTimer) clearInterval(_sdPollTimer);
  _sdPollTimer = setInterval(async () => {
    try {
      const resp = await fetch(`${SD_BASE}/sd/progress/${_sdJobId}`);
      const data = await resp.json();
      if (!resp.ok) {
        clearInterval(_sdPollTimer);
        overlay.style.display = "none";
        alert("Scan progress failed — backend may have stopped.");
        const btn = document.getElementById("sd-run-btn");
        if (btn) { btn.disabled = false; btn.textContent = "🚀 Run Soft Delete Scan"; }
        return;
      }
      const safePct = Math.max(0, Math.min(100, data.progress || 0));
      document.getElementById("sd-scan-fill").style.width = safePct + "%";
      if (pctEl) pctEl.textContent = safePct + "%";

      const abortNote = data.aborted ? " · aborting..." : "";
      document.getElementById("sd-scan-stats").textContent =
        `${data.completed} / ${data.total} endpoints · ${data.bypasses} bypass(es) · ${data.elapsed}s${abortNote}`;

      if (currEl && data.current_url) {
        currEl.textContent = `Testing: ${data.current_url}`;
        currEl.title = data.current_url;
      }

      // Render live feed
      const feed = data.feed || [];
      if (countEl) countEl.textContent = `${feed.length} events`;
      if (feedEl && feed.length) {
        let secCount = 0, bpCount = data.bypasses || 0;
        feedEl.innerHTML = feed.map(f => {
          const isBp = f.is_issue;
          if (!isBp) secCount++;
          const shortUrl = f.url.length > 55 ? f.url.substring(0, 52) + "…" : f.url;
          const statusCls = isBp ? "is-bypass" : (parseInt(f.mod_status) >= 400 || parseInt(f.orig_status) >= 400) ? "is-error" : "is-secure";
          const badge = isBp
            ? `<span style="background:#f85149;color:#fff;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px">⚠️ BYPASS</span>`
            : (parseInt(f.mod_status) >= 400 || parseInt(f.orig_status) >= 400)
              ? `<span style="background:#d29922;color:#fff;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px">🔴 ${f.mod_status}</span>`
              : `<span style="color:#3fb950;font-weight:700;font-size:9px">🔒 SECURE</span>`;

          return `
            <div class="sd-feed-line ${statusCls}">
              <span style="min-width:68px;display:inline-block">${badge}</span>
              <span style="color:var(--yellow);font-size:10px;min-width:90px;white-space:nowrap">${escHtml(f.bypass_val)}</span>
              <span style="color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(f.url)}">${escHtml(shortUrl)}</span>
              <span style="color:var(--text3);font-size:9px;white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis">${escHtml(f.summary || "")}</span>
              <span style="color:var(--text3);font-size:9px;min-width:32px;text-align:right">${f.time}s</span>
            </div>
          `;
        }).join("");
        // Keep feed scrolled to bottom
        feedEl.scrollTop = feedEl.scrollHeight;

        if (pillEl) {
          pillEl.innerHTML = `
            <span style="background:rgba(63,185,80,0.12);color:#3fb950;padding:2px 8px;border-radius:4px;border:1px solid rgba(63,185,80,0.25)">🔒 ${secCount} Secure</span>
            <span style="background:rgba(248,81,73,0.12);color:#f85149;padding:2px 8px;border-radius:4px;border:1px solid rgba(248,81,73,0.25)">⚠️ ${bpCount} Bypass</span>
          `;
        }
      }

      if (data.status === "done") {
        clearInterval(_sdPollTimer);
        _sdAllLogs = data.logs || []; _sdBypassLogs = data.results || []; _sdLastJob = data;
        overlay.style.display = "none";
        _sdShowResults(data);
        const btn = document.getElementById("sd-run-btn");
        if (btn) { btn.disabled = false; btn.textContent = "🚀 Run Soft Delete Scan"; }
        _sdAborting = false;
      }
    } catch (e) {
      clearInterval(_sdPollTimer);
      overlay.style.display = "none";
      alert("Scan poll error: " + (e.message || e));
      const btn = document.getElementById("sd-run-btn");
      if (btn) { btn.disabled = false; btn.textContent = "🚀 Run Soft Delete Scan"; }
      _sdAborting = false;
    }
  }, 800);
}

// ── Results ───────────────────────────────────────────────────────────────────
function _sdShowResults(data) {
  document.getElementById("sd-results-wrap").style.display = "flex";
  const bypasses = data.bypasses || 0;
  const secure  = _sdAllLogs.filter(l => !l.is_issue && (!l.skip_reason || l.skip_reason.toLowerCase().includes("secure") || l.skip_reason.toLowerCase().includes("ignored"))).length;
  const errored = _sdAllLogs.filter(l => { const ms=parseInt(l.mod_status),os=parseInt(l.orig_status); return (ms>=400||os>=400)&&!l.is_issue; }).length;

  document.getElementById("sd-summary-cards").innerHTML = `
    <div class="mt-card mt-card-red"><div class="mt-card-num">${bypasses}</div><div class="mt-card-lbl">BYPASS</div></div>
    <div class="mt-card mt-card-green"><div class="mt-card-num">${secure}</div><div class="mt-card-lbl">SECURE</div></div>
    <div class="mt-card mt-card-orange"><div class="mt-card-num">${errored}</div><div class="mt-card-lbl">4xx/5xx</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${data.total}</div><div class="mt-card-lbl">ENDPOINTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${_sdAllLogs.length}</div><div class="mt-card-lbl">TESTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${data.elapsed}s</div><div class="mt-card-lbl">DURATION</div></div>
  `;
  document.getElementById("sd-filter-all").textContent     = `All (${_sdAllLogs.length})`;
  document.getElementById("sd-filter-bypass").textContent  = `⚠️ Bypass (${bypasses})`;
  document.getElementById("sd-filter-secure").textContent  = `🔒 Secure (${secure})`;
  document.getElementById("sd-filter-errored").textContent = `🔴 4xx/5xx (${errored})`;
  document.querySelectorAll("#tool-sd .mt-filter-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("sd-filter-all").classList.add("active");
  _sdRenderTable(_sdAllLogs);

  const existingAbort = document.getElementById("sd-aborted-warn");
  if (existingAbort) existingAbort.remove();
  if (data.aborted) {
    const warn = document.createElement("div");
    warn.id = "sd-aborted-warn";
    warn.style.cssText = "background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.35);border-radius:6px;color:#f85149;padding:10px 14px;font-size:12px;margin-bottom:12px;flex-shrink:0";
    warn.textContent = "⏹ Scan aborted — showing partial results.";
    const wrap = document.getElementById("sd-results-wrap");
    if (wrap) wrap.insertBefore(warn, wrap.firstChild);
  }
}

function sdFilter(type) {
  document.querySelectorAll("#tool-sd .mt-filter-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("sd-filter-" + type)?.classList.add("active");
  const rows = type === "all"    ? _sdAllLogs
    : type === "bypass"  ? _sdAllLogs.filter(l => l.is_issue)
    : type === "secure"  ? _sdAllLogs.filter(l => !l.is_issue && (!l.skip_reason || /secure|ignored/i.test(l.skip_reason)))
    :                      _sdAllLogs.filter(l => { const ms=parseInt(l.mod_status),os=parseInt(l.orig_status); return (ms>=400||os>=400)&&!l.is_issue; });
  _sdRenderTable(rows);
}

// ── Helper to format JSON or return raw string ──────────────────────────────
function _sdFormatBody(body) {
  if (!body) return "";
  try {
    const parsed = typeof body === "string" ? JSON.parse(body) : body;
    return JSON.stringify(parsed, null, 2);
  } catch (_) {
    return String(body);
  }
}

function sdShellQuote(str) {
  return String(str || "").replace(/'/g, "'\\''");
}

function sdBuildCurl(url, headers) {
  if (!url) return "";
  let c = `curl -X GET '${sdShellQuote(url)}'`;
  for (const [k, v] of Object.entries(headers || {})) {
    if (/^(content-length|host|connection|transfer-encoding)$/i.test(k)) continue;
    c += ` \\\n  -H '${sdShellQuote(k)}: ${sdShellQuote(v)}'`;
  }
  return c;
}

function _sdGetFallbackHeaders() {
  const token = (document.getElementById("sd-token-input")?.value || "").trim();
  const h = {};
  if (token) {
    h["Authorization"] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
  }
  return h;
}

// ── Diff highlighting ─────────────────────────────────────────────────────────
function _sdHighlightDiff(orig, mod) {
  if (!orig && !mod) return { origHtml: "(empty)", modHtml: "(empty)" };
  if (!orig || !mod || orig === mod) {
    return {
      origHtml: escHtml(_sdFormatBody(orig || "(empty)")),
      modHtml:  escHtml(_sdFormatBody(mod  || "(empty)"))
    };
  }
  try {
    const oJ = typeof orig === "string" ? JSON.parse(orig) : orig;
    const mJ = typeof mod   === "string" ? JSON.parse(mod)  : mod;
    const oStr = JSON.stringify(oJ, null, 2);
    const mStr = JSON.stringify(mJ, null, 2);
    const oLines = oStr.split("\n");
    const mLines = mStr.split("\n");
    const oTrimmedSet = new Set(oLines.map(ol => ol.trim()));
    const oHtml = oLines.map(l => {
      const key = l.match(/"(deleted|isDeleted|deleted_at|deletedAt)"\s*:/i);
      return key ? `<span class="sd-diff-line-same">${escHtml(l)}</span>` : escHtml(l);
    }).join("\n");
    const mHtml = mLines.map(l => {
      const key = l.match(/"(deleted|isDeleted|deleted_at|deletedAt)"\s*:/i);
      if (key) return `<span class="sd-diff-line-bypass">${escHtml(l)}</span>`;
      const found = oTrimmedSet.has(l.trim());
      return found ? escHtml(l) : `<span class="sd-diff-line-added">${escHtml(l)}</span>`;
    }).join("\n");
    return { origHtml: oHtml, modHtml: mHtml };
  } catch(e) {
    return { origHtml: escHtml(_sdFormatBody(orig)), modHtml: escHtml(_sdFormatBody(mod)) };
  }
}

// ── Table ─────────────────────────────────────────────────────────────────────
function _sdRenderTable(rows) {
  const tbody = document.getElementById("sd-results-tbody");
  if (!rows.length) { tbody.innerHTML = `<tr><td colspan="9" class="mt-empty-row">No results.</td></tr>`; return; }
  const stCls = n => isNaN(parseInt(n)) ? "mt-status-err" : (200<=n&&n<300)?"mt-status-2xx":(400<=n&&n<500)?"mt-status-4xx":"mt-status-5xx";

  tbody.innerHTML = rows.map((r, i) => {
    const isBp  = r.is_issue;
    const badge = isBp
      ? `<span class="mt-sev-badge" style="background:#f85149;color:#fff">⚠️ BYPASS</span>`
      : r.skip_reason ? `<span style="color:var(--text3);font-size:11px">⏭ Skipped</span>`
      : `<span class="mt-clean-badge">🔒 Secure</span>`;
    const shortUrl = r.original_url.length > 50 ? r.original_url.substring(0,50)+"…" : r.original_url;
    const uid = `sdrow-${i}`;
    _sdBypassUrls[uid] = r.bypass_url || '';
    const origCurl = r.orig_curl || sdBuildCurl(r.original_url, r.headers || _sdGetFallbackHeaders());
    const modCurl  = r.bypass_curl || sdBuildCurl(r.bypass_url, r.headers || _sdGetFallbackHeaders());
    _sdCurls[uid] = { orig: origCurl, mod: modCurl };

    const { origHtml, modHtml } = isBp
      ? _sdHighlightDiff(r.orig_body, r.mod_body)
      : { origHtml: escHtml(_sdFormatBody(r.orig_body || "(empty)")), modHtml: escHtml(_sdFormatBody(r.mod_body || "(empty)")) };

    return `
      <tr class="${isBp ? 'mt-row-issue mt-row-high' : 'mt-row-clean'}" onclick="sdToggleExpand('${uid}')" style="cursor:pointer">
        <td class="mt-td-num">${i+1}</td>
        <td style="font-size:10px;font-family:var(--mono);color:var(--yellow)">${escHtml(r.filter)}</td>
        <td style="font-size:11px;color:var(--text2)">${escHtml(r.bypass_value)}</td>
        <td style="font-size:10px;color:var(--text3)">${escHtml(r.enc_type)}</td>
        <td class="mt-td-url" title="${escHtml(r.original_url)}">${escHtml(shortUrl)}</td>
        <td><span class="${stCls(r.orig_status)} mt-status-badge">${r.orig_status}</span></td>
        <td><span class="${stCls(r.mod_status)} mt-status-badge">${r.mod_status}</span></td>
        <td>${badge}</td>
        <td class="mt-td-reason" style="${isBp?'color:#f85149':''}">${escHtml(r.diff_summary || r.skip_reason || "—")}</td>
      </tr>
      <tr class="mt-expand-row" id="${uid}" style="display:none">
        <td colspan="9" class="mt-expand-cell">
          <div class="sd-resp-toolbar">
            <input class="sd-search-box" placeholder="🔍 Search in responses..." oninput="sdSearchResp(this, '${uid}')">
            <button class="sd-copy-btn" onclick="sdCopyBoth('${uid}')">📋 Copy Both</button>
            <button class="sd-copy-btn" onclick="sdToggleExpandPre('${uid}', this)">↕ Expand Full</button>
          </div>
          <div class="mt-response-grid">
            <div class="mt-resp-panel">
              <div class="mt-resp-label">
                <span>📥 Original Response <span class="mt-resp-method">${r.orig_status}</span></span>
                <div style="display:inline-flex;gap:6px;align-items:center">
                  <button class="sd-copy-btn-sm" onclick="sdCopyText(this, document.getElementById('${uid}-orig').textContent)">📋 Copy</button>
                  <button class="sd-copy-btn-sm" onclick="sdCopyCurl(this, '${uid}', 'orig')" title="Copy original request as cURL">📋 Copy cURL</button>
                </div>
              </div>
              <pre class="mt-resp-body sd-resp-pre" id="${uid}-orig">${origHtml}</pre>
            </div>
            <div class="mt-resp-panel">
              <div class="mt-resp-label">
                <span>📤 Bypass Response <span class="mt-resp-method" style="color:${isBp?'#f85149':'#3fb950'}">${r.mod_status}</span></span>
                <div style="display:inline-flex;gap:6px;align-items:center">
                  <button class="sd-copy-btn-sm" onclick="sdCopyText(this, document.getElementById('${uid}-mod').textContent)">📋 Copy</button>
                  <button class="sd-copy-btn-sm" onclick="sdCopyCurl(this, '${uid}', 'mod')" title="Copy bypass request as cURL">📋 Copy cURL</button>
                </div>
              </div>
              <pre class="mt-resp-body sd-resp-pre" id="${uid}-mod">${modHtml}</pre>
            </div>
          </div>
          <div class="sd-bypass-url">
            <span>🔗 Bypass URL: <span style="color:var(--yellow);font-family:var(--mono);font-size:10px">${escHtml(r.bypass_url)}</span></span>
            <div style="display:inline-flex;gap:6px;margin-left:auto">
              <button class="sd-copy-btn-sm" onclick="sdCopyText(this, _sdBypassUrls['${uid}'] || '')">📋 Copy URL</button>
              <button class="sd-copy-btn-sm" onclick="sdCopyCurl(this, '${uid}', 'mod')" title="Copy bypass request as cURL">📋 Copy cURL</button>
            </div>
          </div>
        </td>
      </tr>`;
  }).join("");
}

function sdToggleExpand(uid) {
  const row = document.getElementById(uid); if (!row) return;
  const isOpen = row.style.display !== "none";
  document.querySelectorAll("#tool-sd .mt-expand-row").forEach(r => r.style.display = "none");
  document.querySelectorAll("#tool-sd .mt-result-row").forEach(r => r.classList.remove("mt-row-selected"));
  if (!isOpen) { row.style.display = "table-row"; row.previousElementSibling?.classList.add("mt-row-selected"); }
}

function sdSearchResp(inp, uid) {
  const q = inp.value.trim();
  ["orig","mod"].forEach(side => {
    const pre = document.getElementById(`${uid}-${side}`);
    if (!pre) return;
    // Store original HTML once
    if (!pre.dataset.origHtml) pre.dataset.origHtml = pre.innerHTML;
    // Restore first
    pre.innerHTML = pre.dataset.origHtml;
    if (!q) return;
    // Now highlight on plain text
    const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex   = new RegExp(`(${escaped})`, "gi");
    // Walk text nodes only to avoid breaking HTML tags
    _sdHighlightTextNodes(pre, regex);
  });
}

function _sdHighlightTextNodes(node, regex) {
  if (node.nodeType === 3) { // text node
    const text = node.textContent;
    if (!regex.test(text)) return;
    regex.lastIndex = 0;
    const span = document.createElement("span");
    span.innerHTML = text.replace(regex,
      m => `<mark style="background:#e3b341;color:#080c10;border-radius:2px;padding:0 1px">${escHtml(m)}</mark>`
    );
    node.parentNode.replaceChild(span, node);
  } else if (node.nodeType === 1 && node.nodeName !== "MARK") {
    Array.from(node.childNodes).forEach(child => _sdHighlightTextNodes(child, regex));
  }
}

function sdCopyText(btn, text) {
  const t = text || "";
  const orig = btn.textContent;
  const done = () => {
    btn.textContent = "✅ Copied";
    btn.style.color = "var(--green)";
    setTimeout(() => { btn.textContent = orig; btn.style.color = ""; }, 1500);
  };
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(t).then(done).catch(() => {
      const ta = document.createElement("textarea");
      ta.value = t; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      done();
    });
  } else {
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    done();
  }
}

function sdCopyCurl(btn, uid, which) {
  const curls = _sdCurls[uid] || {};
  let curl = which === "orig" ? curls.orig : curls.mod;
  if (!curl) {
    const rowIdx = parseInt(String(uid).replace("sdrow-", ""), 10);
    const row = _sdAllLogs[rowIdx];
    if (row) {
      const u = which === "orig" ? row.original_url : (row.bypass_url || _sdBypassUrls[uid]);
      curl = sdBuildCurl(u, row.headers || _sdGetFallbackHeaders());
    }
  }
  if (!curl) return;

  const orig = btn.textContent;
  const done = () => {
    btn.textContent = "✅ Copied cURL";
    btn.style.color = "var(--green)";
    setTimeout(() => { btn.textContent = orig; btn.style.color = ""; }, 1500);
  };

  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(curl).then(done).catch(() => {
      const ta = document.createElement("textarea");
      ta.value = curl; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      done();
    });
  } else {
    const ta = document.createElement("textarea");
    ta.value = curl; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    done();
  }
}

function sdToggleExpandPre(uid, btn) {
  const origPre = document.getElementById(`${uid}-orig`);
  const modPre  = document.getElementById(`${uid}-mod`);
  const isExp = origPre?.classList.contains("sd-expanded");
  if (isExp) {
    origPre?.classList.remove("sd-expanded");
    modPre?.classList.remove("sd-expanded");
    if (btn) btn.textContent = "↕ Expand Full";
  } else {
    origPre?.classList.add("sd-expanded");
    modPre?.classList.add("sd-expanded");
    if (btn) btn.textContent = "↕ Collapse";
  }
}

function sdCopyBoth(uid) {
  const o = document.getElementById(`${uid}-orig`)?.textContent || "";
  const m = document.getElementById(`${uid}-mod`)?.textContent  || "";
  const btn = document.querySelector(`[onclick="sdCopyBoth('${uid}')"]`);
  const done = () => {
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = "✅ Copied!";
      setTimeout(() => btn.textContent = orig, 1500);
    }
  };
  const val = `=== ORIGINAL ===\n${o}\n\n=== BYPASS ===\n${m}`;
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(val).then(done).catch(() => {
      const ta = document.createElement("textarea");
      ta.value = val; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      done();
    });
  } else {
    const ta = document.createElement("textarea");
    ta.value = val; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    done();
  }
}

// ── Export ────────────────────────────────────────────────────────────────────
async function sdDownloadCsv() {
  if (!_sdJobId) return;
  try {
    const resp = await fetch(`${SD_BASE}/sd/csv/${_sdJobId}`);
    const text = await resp.text();
    const ts   = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
    if (window.pywebview?.api?.save_file) { await window.pywebview.api.save_file(text, `soft_delete_${ts}.csv`); }
    else { const a = document.createElement("a"); a.href = "data:text/csv;charset=utf-8,"+encodeURIComponent(text); a.download = `soft_delete_${ts}.csv`; a.click(); }
  } catch(e) { alert("CSV failed: " + e.message); }
}

async function sdDownloadHtml() {
  if (!_sdLastJob) return;
  const html = _sdGenHtml(_sdLastJob, _sdAllLogs);
  const ts   = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
  if (window.pywebview?.api?.save_file) { await window.pywebview.api.save_file(html, `soft_delete_${ts}.html`); }
  else { const a = document.createElement("a"); a.href = "data:text/html;charset=utf-8,"+encodeURIComponent(html); a.download = `soft_delete_${ts}.html`; a.click(); }
}

function _sdGenHtml(data, logs) {
  const ts       = new Date().toLocaleString();
  const bypasses = data.bypasses || 0;
  const secure   = logs.filter(l => !l.is_issue && (!l.skip_reason || l.skip_reason.toLowerCase().includes("secure"))).length;
  const errored  = logs.filter(l => { const ms=parseInt(l.mod_status),os=parseInt(l.orig_status); return (ms>=400||os>=400)&&!l.is_issue; }).length;

  const stColor = n => { const c=parseInt(n); return isNaN(c)?'#6e7681':c<300?'#3fb950':c<400?'#58a6ff':c<500?'#d29922':'#f85149'; };
  const badge = r => r.is_issue
    ? `<span style="background:#f85149;color:#fff;padding:2px 9px;border-radius:4px;font-size:10px;font-weight:700">⚠️ BYPASS</span>`
    : (parseInt(r.mod_status)>=400||parseInt(r.orig_status)>=400)
      ? `<span style="background:#d29922;color:#fff;padding:2px 9px;border-radius:4px;font-size:10px;font-weight:700">4xx/5xx</span>`
      : `<span style="color:#3fb950;font-size:11px;font-weight:700">🔒 Secure</span>`;

  // Build expand sections for each row (orig + bypass response side by side)
  const rows = logs.map((r, i) => {
    const isBp    = r.is_issue;
    const is4xx   = !isBp && (parseInt(r.mod_status)>=400 || parseInt(r.orig_status)>=400);
    const rowBg   = isBp ? '#1a0808' : is4xx ? '#1a1200' : '#0d1117';
    const borderL = isBp ? 'border-left:3px solid #f85149' : is4xx ? 'border-left:3px solid #d29922' : '';
    const uid     = `hr-${i}`;
    const hasResp = r.orig_body || r.mod_body;
    return `
    <tr style="background:${rowBg};${borderL};cursor:${hasResp?'pointer':''}" onclick="toggle('${uid}')">
      <td style="color:var(--text);width:32px">${i+1}</td>
      <td style="color:#e3b341;font-family:monospace;font-size:10px;white-space:nowrap">${escHtml(r.filter)}</td>
      <td style="font-size:11px;white-space:nowrap">${escHtml(r.bypass_value)}</td>
      <td style="font-size:10px;color:var(--text);white-space:nowrap">${escHtml(r.enc_type)}</td>
      <td style="font-size:10px;color:#79c0ff;font-family:monospace;word-break:break-all;max-width:320px">${escHtml(r.original_url)}</td>
      <td style="font-weight:700;color:${stColor(r.orig_status)};text-align:center;white-space:nowrap">${r.orig_status}</td>
      <td style="font-weight:700;color:${stColor(r.mod_status)};text-align:center;white-space:nowrap">${r.mod_status}</td>
      <td>${badge(r)}</td>
      <td style="font-size:11px;color:${isBp?'#f85149':'#6e7681'}">${escHtml(r.diff_summary||r.skip_reason||'')}</td>
    </tr>
    ${hasResp ? `<tr id="${uid}" style="display:none;background:#0a0d14">
      <td colspan="9" style="padding:0">
        <div style="display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #21262d">
          <div style="padding:10px 12px;border-right:1px solid #21262d">
            <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:6px">📥 Original Response — <span style="color:${stColor(r.orig_status)}">${r.orig_status}</span></div>
            <pre style="font-size:10px;color:#c9d1d9;background:#161b22;border:1px solid #30363d;border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:260px;overflow-y:auto;margin:0">${escHtml(_sdFormatBody(r.orig_body||'(empty)'))}</pre>
          </div>
          <div style="padding:10px 12px">
            <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:6px">📤 Bypass Response — <span style="color:${isBp?'#f85149':stColor(r.mod_status)}">${r.mod_status}</span></div>
            <pre style="font-size:10px;color:#c9d1d9;background:#161b22;border:1px solid ${isBp?'#f8514944':'#30363d'};border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:260px;overflow-y:auto;margin:0">${escHtml(_sdFormatBody(r.mod_body||'(empty)'))}</pre>
          </div>
        </div>
        <div style="padding:5px 12px;font-size:9px;font-family:monospace;color:var(--text);background:#0d1117;border-top:1px solid #21262d">
          🔗 ${escHtml(r.bypass_url)}
        </div>
      </td>
    </tr>` : ''}`;
  }).join("");

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Soft Delete Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#080c10;color:#c9d1d9;padding:24px;font-size:13px}
h1{font-size:22px;font-weight:800;background:linear-gradient(135deg,#7c3aed,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.meta{color:var(--text);font-size:10px;font-family:monospace;margin-top:4px;margin-bottom:18px}
.cards{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 18px;text-align:center;min-width:80px;position:relative;overflow:hidden}
.card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px}
.red::after{background:#f85149}.green::after{background:#3fb950}.orange::after{background:#d29922}.grey::after{background:#6e7681}
.card h3{font-size:20px;font-weight:800;margin-bottom:2px}
.red h3{color:#f85149}.green h3{color:#3fb950}.orange h3{color:#d29922}.grey h3{color:var(--text)}
.card p{font-size:9px;color:var(--text);text-transform:uppercase;letter-spacing:1px}
.filters{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.fbtn{background:#161b22;border:1px solid #30363d;color:var(--text);font-size:11px;padding:4px 12px;border-radius:12px;cursor:pointer;font-family:inherit}
.fbtn.active,.fbtn:hover{background:#21262d;color:#c9d1d9}
.fbtn.fa{background:rgba(248,81,73,.15);color:#f85149;border-color:#f85149}
.fbtn.fs{background:rgba(63,185,80,.12);color:#3fb950;border-color:#3fb950}
.fbtn.fe{background:rgba(210,153,34,.12);color:#d29922;border-color:#d29922}
table{border-collapse:collapse;width:100%;background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden;font-size:11px}
th{background:#161b22;color:var(--text);padding:8px 10px;text-align:left;border-bottom:1px solid #30363d;font-size:9px;text-transform:uppercase;letter-spacing:.5px;font-weight:700;position:sticky;top:0}
td{padding:7px 10px;border-bottom:1px solid #161b22;vertical-align:middle}
tr:hover td{background:#161b22}
tr[id]{display:none}
.hint{font-size:9px;color:var(--text);margin-top:8px;font-style:italic}
</style>
<script>
function toggle(id){var r=document.getElementById(id);r.style.display=r.style.display==='none'?'table-row':'none';}
function filter(type){
  var rows=document.querySelectorAll('tr[data-type]');
  rows.forEach(function(r){
    var show=type==='all'||r.dataset.type===type;
    r.style.display=show?'':'none';
    var next=r.nextElementSibling;
    if(next&&next.id)next.style.display='none';
  });
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('active','fa','fs','fe');});
  var btn=document.getElementById('fb-'+type);
  if(btn){btn.classList.add('active');if(type==='bypass')btn.classList.add('fa');else if(type==='secure')btn.classList.add('fs');else if(type==='errored')btn.classList.add('fe');}
}
</script>
</head><body>
<h1>🗑️ Soft Delete Filter Bypass Report</h1>
<p class="meta">Generated: ${ts} &nbsp;|&nbsp; Endpoints: ${data.total} &nbsp;|&nbsp; Tests: ${logs.length} &nbsp;|&nbsp; Duration: ${data.elapsed}s</p>
<div class="cards">
  <div class="card red"><h3>${bypasses}</h3><p>Bypass</p></div>
  <div class="card green"><h3>${secure}</h3><p>Secure</p></div>
  <div class="card orange"><h3>${errored}</h3><p>4xx/5xx</p></div>
  <div class="card grey"><h3>${data.total}</h3><p>Endpoints</p></div>
  <div class="card grey"><h3>${logs.length}</h3><p>Tests</p></div>
</div>
<div class="filters">
  <button class="fbtn active" id="fb-all" onclick="filter('all')">All (${logs.length})</button>
  <button class="fbtn" id="fb-bypass" onclick="filter('bypass')">⚠️ Bypass (${bypasses})</button>
  <button class="fbtn" id="fb-secure" onclick="filter('secure')">🔒 Secure (${secure})</button>
  <button class="fbtn" id="fb-errored" onclick="filter('errored')">🔴 4xx/5xx (${errored})</button>
</div>
<p class="hint">💡 Click on any row to expand original & bypass responses</p>
<table>
<thead><tr><th>#</th><th>Filter</th><th>Bypass Variant</th><th>Encoding</th><th>URL</th><th>Orig</th><th>Mod</th><th>Result</th><th>Summary</th></tr></thead>
<tbody>
${logs.map((r,i) => {
  const isBp  = r.is_issue;
  const is4xx = !isBp && (parseInt(r.mod_status)>=400||parseInt(r.orig_status)>=400);
  const type  = isBp ? 'bypass' : is4xx ? 'errored' : 'secure';
  const stC   = n => { const c=parseInt(n); return isNaN(c)?'#6e7681':c<300?'#3fb950':c<400?'#58a6ff':c<500?'#d29922':'#f85149'; };
  const rowBg = isBp ? '#1a0808' : is4xx ? '#1a1200' : '#0d1117';
  const bdrL  = isBp ? 'border-left:3px solid #f85149' : is4xx ? 'border-left:3px solid #d29922' : '';
  const bdg   = isBp ? '<span style="background:#f85149;color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">⚠️ BYPASS</span>'
              : is4xx ? '<span style="background:#d29922;color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">4xx/5xx</span>'
              : '<span style="color:#3fb950;font-size:11px;font-weight:700">🔒 Secure</span>';
  const uid   = `hr-${i}`;
  const hasR  = r.orig_body || r.mod_body;
  return `<tr data-type="${type}" style="background:${rowBg};${bdrL};cursor:${hasR?'pointer':'default'}" onclick="toggle('${uid}')">
    <td style="color:var(--text)">${i+1}</td>
    <td style="color:#e3b341;font-family:monospace;font-size:10px">${escHtml(r.filter)}</td>
    <td style="font-size:11px">${escHtml(r.bypass_value)}</td>
    <td style="font-size:10px;color:var(--text)">${escHtml(r.enc_type)}</td>
    <td style="font-size:10px;color:#79c0ff;font-family:monospace;word-break:break-all;max-width:300px">${escHtml(r.original_url)}</td>
    <td style="font-weight:700;color:${stC(r.orig_status)};text-align:center">${r.orig_status}</td>
    <td style="font-weight:700;color:${stC(r.mod_status)};text-align:center">${r.mod_status}</td>
    <td>${bdg}</td>
    <td style="font-size:11px;color:${isBp?'#f85149':'#6e7681'}">${escHtml(r.diff_summary||r.skip_reason||'')}</td>
  </tr>
  ${hasR ? `<tr id="${uid}">
    <td colspan="9" style="padding:0;background:#0a0d14">
      <div style="display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #21262d">
        <div style="padding:10px 12px;border-right:1px solid #21262d">
          <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:6px">📥 Original — ${r.orig_status}</div>
          <pre style="font-size:10px;color:#c9d1d9;background:#161b22;border:1px solid #30363d;border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:250px;overflow-y:auto;margin:0">${escHtml(_sdFormatBody(r.orig_body||'(empty)'))}</pre>
        </div>
        <div style="padding:10px 12px">
          <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:6px">📤 Bypass — <span style="color:${isBp?'#f85149':stC(r.mod_status)}">${r.mod_status}</span></div>
          <pre style="font-size:10px;color:#c9d1d9;background:#161b22;border:1px solid ${isBp?'#f8514966':'#30363d'};border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:250px;overflow-y:auto;margin:0">${escHtml(_sdFormatBody(r.mod_body||'(empty)'))}</pre>
        </div>
      </div>
      <div style="padding:5px 12px;font-size:9px;font-family:monospace;color:var(--text);border-top:1px solid #21262d">🔗 ${escHtml(r.bypass_url)}</div>
    </td>
  </tr>` : ''}`;
}).join("")}
</tbody></table>
</body></html>`;
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function sdReset() {
  clearInterval(_sdPollTimer);
  _sdEndpoints = []; _sdHarData = null; _sdJobId = null;
  _sdAllLogs = []; _sdBypassLogs = []; _sdLastJob = null;
  _sdBypassUrls = {}; _sdCurls = {};
  _sdChecked = {}; _sdFilterText = ""; _sdAborting = false;
  const ec = document.getElementById("sd-ep-count"); if (ec) ec.textContent = "0 endpoints";
  const fi = document.getElementById("sd-url-filter-input"); if (fi) fi.value = "";
  const list = document.getElementById("sd-endpoint-list"); if (list) { list.innerHTML = ""; list.style.display = "none"; }
  const empty = document.getElementById("sd-endpoint-empty"); if (empty) empty.style.display = "flex";
  const wrap = document.getElementById("sd-results-wrap"); if (wrap) wrap.style.display = "none";
  const re = document.getElementById("sd-results-empty"); if (re) re.style.display = "flex";
  const ov = document.getElementById("sd-scanning-overlay"); if (ov) ov.style.display = "none";
  const btn = document.getElementById("sd-run-btn"); if (btn) { btn.disabled = false; btn.textContent = "🚀 Run Soft Delete Scan"; }
  const tf = document.getElementById("sd-token-input"); if (tf) tf.value = "";
  sdSwitchTab("capture");
}
window.sdReset = sdReset;
window.sdCopyCurl = sdCopyCurl;
window.sdToggleExpandPre = sdToggleExpandPre;
window.sdCopyText = sdCopyText;
window.sdCopyBoth = sdCopyBoth;
window.sdBuildCurl = sdBuildCurl;

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
