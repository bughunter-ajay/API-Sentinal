// har_runner.js — Auth Validator Pro (Mac App version)
// Chrome APIs nahi — REST polling use karta hai
// All element IDs prefixed with "har-"
"use strict";

const HAR_BACKEND = "http://127.0.0.1:8766";
const AV_BACKEND  = "http://127.0.0.1:8765"; // Capture shared from AV backend

// ── Scoped $ ──────────────────────────────────────────────────────────────────
const $h = id => document.getElementById("har-" + id);

const MAX_HAR_USERS = 7;

const HAR_USER_COLORS = [
  { bg: "rgba(88,166,255,0.15)", text: "#58a6ff", border: "rgba(88,166,255,0.4)", hex: "#58a6ff" },  // User 1: Blue
  { bg: "rgba(163,113,247,0.15)", text: "#d2a8ff", border: "rgba(163,113,247,0.4)", hex: "#a371f7" }, // User 2: Purple
  { bg: "rgba(63,185,80,0.15)", text: "#56d364", border: "rgba(63,185,80,0.4)", hex: "#3fb950" },   // User 3: Green
  { bg: "rgba(240,136,62,0.15)", text: "#ffa657", border: "rgba(240,136,62,0.4)", hex: "#f0883e" }, // User 4: Orange
  { bg: "rgba(244,114,182,0.15)", text: "#f472b6", border: "rgba(244,114,182,0.4)", hex: "#f472b6" },// User 5: Pink
  { bg: "rgba(227,179,65,0.15)", text: "#e3b341", border: "rgba(227,179,65,0.4)", hex: "#e3b341" }, // User 6: Yellow
  { bg: "rgba(45,212,191,0.15)", text: "#2dd4bf", border: "rgba(45,212,191,0.4)", hex: "#2dd4bf" }, // User 7: Teal
];

function harGetUserColor(idx) {
  const i = Math.max(0, idx || 0);
  return HAR_USER_COLORS[i % HAR_USER_COLORS.length];
}

// ── State ─────────────────────────────────────────────────────────────────────
const harState = {
  requests:    [],
  filtered:    [],
  checkedIds:  new Set(),
  currentStep: 1,
  users: [
    { id: "user_1", name: "User 1 (Admin)", token: "", isUnauth: false },
    { id: "user_2", name: "User 2 (Regular)", token: "", isUnauth: false },
  ],
  tokenMode:   "multi_user",
  testResults: null,
  resultFilter:"all",
  resultUserFilter: "all",
  resultCompareFilter: "all",
  resultUrlQuery: "",
  activeResultsView: "table",
  diffActiveEndpoint: null,
  diffFilterPill: "all",
  diffQuery: "",
  sortCol:     null,
  sortDir:     "asc",
  pollTimer:   null,
};

// Ids hidden by this tool's own Reset button. The capture buffer itself is
// shared with API Validator Pro (same backend), so Reset can't delete these
// requests there — it just stops showing them in THIS tool going forward.
let _harDismissedIds = new Set();

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  harSetupStep1();
  harSetupStep2();
  harSetupStep3();

  // Poll for requests when HAR Runner is active tool AND capturing is ON
  setInterval(() => {
    if (window._activeTool === "har") {
      harLoadRequests();
      harSyncCaptureStatus();
    }
  }, 1500);

  harSetupTokenApiControls();   // Token step API selection controls

  // Expose for tool switcher and inline onclick
  window.harCheckBackend = harCheckBackend;
  window.harStepClick    = harStepClick;
  window.harClearAll     = harClearAll;
});

function harClearAll() {
  harState.requests    = [];
  harState.filtered    = [];
  harState.checkedIds.clear();
  harState.testResults = null;
  harState.sortCol     = null;
  harState.sortDir     = "asc";
  harState.currentStep = 1;
  harState.activeResultsView = "table";
  harState.diffActiveEndpoint = null;
  harState.diffFilterPill = "all";
  harState.diffQuery = "";
  const countBadge = $h("sizediff-count");
  if (countBadge) countBadge.style.display = "none";
  if ($h("view-btn-table")) $h("view-btn-table").classList.add("active");
  if ($h("view-btn-diff")) $h("view-btn-diff").classList.remove("active");
  if ($h("results-table-wrap")) $h("results-table-wrap").style.display = "";
  if ($h("results-filters")) $h("results-filters").style.display = "";
  if ($h("compare-diff-wrap")) $h("compare-diff-wrap").style.display = "none";
  harGoStep(1);
  harRenderList();
  harUpdateNextBtn();
}

// Scoped Reset button — clears this tool's own captured list, results,
// selections and config. Never clears the AV backend buffer directly: it's
// shared with API Validator Pro, so wiping it there would also empty that
// tool's view. Instead the currently-shown requests are just hidden from
// THIS tool going forward (_harDismissedIds) — API Validator keeps seeing
// them untouched, and the shared buffer itself is never modified.
function harResetTool() {
  harState.requests.forEach(r => _harDismissedIds.add(r.id));
  harState.requests    = [];
  harState.filtered    = [];
  harState.checkedIds.clear();
  harState.testResults = null;
  harState.resultFilter = "all";
  harState.resultUrlQuery = "";
  harState.sortCol     = null;
  harState.sortDir     = "asc";
  harState.activeResultsView = "table";
  harState.diffActiveEndpoint = null;
  harState.diffFilterPill = "all";
  harState.diffQuery = "";
  const urlSearch = $h("results-url-search");
  if (urlSearch) urlSearch.value = "";
  const countBadge = $h("sizediff-count");
  if (countBadge) countBadge.style.display = "none";
  if ($h("view-btn-table")) $h("view-btn-table").classList.add("active");
  if ($h("view-btn-diff")) $h("view-btn-diff").classList.remove("active");
  if ($h("results-table-wrap")) $h("results-table-wrap").style.display = "";
  if ($h("results-filters")) $h("results-filters").style.display = "";
  if ($h("compare-diff-wrap")) $h("compare-diff-wrap").style.display = "none";
  harState.currentStep = 1;
  harGoStep(1);
  harRenderList();
  harUpdateNextBtn();
}
window.harResetTool = harResetTool;

// Sync capture list into the Token step API selection section
function harSyncTokenApiList() {
  const reqs = harState.filtered.length ? harState.filtered : harState.requests;
  const listEl = document.getElementById("har-token-api-list");
  const countEl = document.getElementById("har-token-api-count");
  if (!listEl) return;

  listEl.innerHTML = "";
  if (!reqs.length) {
    listEl.innerHTML = '<div style="padding:8px 10px;color:var(--text3);font-size:11px">No APIs captured</div>';
    if (countEl) countEl.textContent = "0 selected";
    return;
  }

  reqs.forEach(req => {
    const checked = harState.checkedIds.has(req.id);
    const item = document.createElement("div");
    item.className = "request-item" + (checked ? " checked-item" : "");
    item.style.cssText = "display:flex;align-items:center;gap:8px;padding:5px 8px;cursor:pointer;border-bottom:1px solid rgba(48,54,61,.4)";

    const mc = harGetMethodClass(req.method);
    let urlDisplay = harEsc(req.url || "");
    try {
      const u = new URL(req.url);
      urlDisplay = `<span style="color:var(--text3)">${harEsc(u.protocol)}//${harEsc(u.host)}</span><span style="color:var(--blue)">${harEsc(u.pathname)}</span>${u.search ? `<span style="color:#79c0ff;font-weight:600">${harEsc(u.search)}</span>` : ""}`;
    } catch(e) {}

    item.innerHTML = `
      <input type="checkbox" class="req-checkbox" ${checked ? "checked" : ""} style="flex-shrink:0">
      <span class="method-badge method-${mc}" style="font-size:9px;padding:1px 5px">${harEsc(req.method)}</span>
      <span style="font-family:var(--mono);font-size:10px;color:var(--blue);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;flex:1" title="${harEsc(req.url)}">${urlDisplay}</span>
    `;

    const cb = item.querySelector(".req-checkbox");
    const toggle = () => {
      if (harState.checkedIds.has(req.id)) harState.checkedIds.delete(req.id);
      else harState.checkedIds.add(req.id);
      cb.checked = harState.checkedIds.has(req.id);
      item.classList.toggle("checked-item", cb.checked);
      harUpdateTokenCount();
      harUpdateNextBtn();
    };
    cb.addEventListener("change", e => { e.stopPropagation(); toggle(); });
    item.addEventListener("click", e => { if (e.target !== cb) toggle(); });
    listEl.appendChild(item);
  });

  harUpdateTokenCount();
}

function harGetSelectedRequests() {
  return (harState.requests || []).filter(r => harState.checkedIds.has(r.id));
}

function harUpdateTokenCount() {
  const countEl = document.getElementById("har-token-api-count");
  if (countEl) countEl.textContent = harGetSelectedRequests().length + " selected";
}

// ── Multi-tier API Signature & Dedup ─────────────────────────────────────────
function harHashString(s) {
  if (!s) return "0";
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = (((h << 5) + h) + s.charCodeAt(i)) & 0xffffffff;
  }
  return (h >>> 0).toString(16);
}

function harNormalizeUrl(rawUrl) {
  if (!rawUrl) return "";
  try {
    const withoutQuery = rawUrl.split("?")[0].split("#")[0].trim();
    const u = new URL(withoutQuery);
    const path = u.pathname.replace(/\/+$/, "") || "/";
    return `${u.protocol}//${u.host.toLowerCase()}${path}`;
  } catch(e) {
    return (rawUrl.split("?")[0].split("#")[0].trim()).replace(/\/+$/, "");
  }
}

function harExtractQueryKeys(req) {
  const keys = new Set();
  if (req && req.queryParams && typeof req.queryParams === "object") {
    Object.keys(req.queryParams).forEach(k => { if (k) keys.add(k.trim()); });
  }
  const rawUrl = req?.url || "";
  if (rawUrl.includes("?")) {
    try {
      const sp = new URL(rawUrl).searchParams;
      sp.forEach((_, k) => { if (k) keys.add(k.trim()); });
    } catch(e) {}
  }
  return Array.from(keys).sort();
}

function harExtractBodyPaths(body, prefix = "", depth = 0) {
  if (depth > 12 || body === null || body === undefined) return [];
  if (typeof body === "string") {
    const trimmed = body.trim();
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        body = JSON.parse(trimmed);
      } catch(e) {
        return [prefix || "_raw"];
      }
    } else if (trimmed.includes("=") && !trimmed.includes("\n") && !trimmed.startsWith("<")) {
      try {
        const sp = new URLSearchParams(trimmed);
        const keys = [];
        sp.forEach((_, k) => {
          if (k) keys.push(prefix ? `${prefix}.${k}` : k);
        });
        if (keys.length) return keys;
      } catch(e) {}
      return [prefix || "_raw"];
    } else {
      return [prefix || "_raw"];
    }
  }
  if (typeof body !== "object" || body === null) {
    return prefix ? [prefix] : [];
  }
  const paths = [];
  if (Array.isArray(body)) {
    if (!body.length) {
      if (prefix) paths.push(prefix);
    } else {
      body.forEach((item, idx) => {
        const sub = prefix ? `${prefix}[${idx}]` : `[${idx}]`;
        if (typeof item === "object" && item !== null) {
          paths.push(...harExtractBodyPaths(item, sub, depth + 1));
        } else {
          paths.push(sub);
        }
      });
    }
  } else {
    const keys = Object.keys(body);
    if (!keys.length) {
      if (prefix) paths.push(prefix);
    } else {
      keys.forEach(k => {
        const sub = prefix ? `${prefix}.${k}` : String(k);
        const v = body[k];
        if (typeof v === "object" && v !== null) {
          paths.push(...harExtractBodyPaths(v, sub, depth + 1));
        } else {
          paths.push(sub);
        }
      });
    }
  }
  return paths;
}

function harFindDiscriminator(body) {
  if (!body) return "";
  let obj = body;
  if (typeof obj === "string") {
    const trimmed = obj.trim();
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try { obj = JSON.parse(trimmed); } catch(e) { return ""; }
    } else {
      return "";
    }
  }
  if (typeof obj !== "object" || obj === null) return "";
  if (Array.isArray(obj)) {
    if (obj.length && typeof obj[0] === "object" && obj[0] !== null) obj = obj[0];
    else return "";
  }
  const discKeys = [
    "formName", "form_name", "entityType", "entity_type",
    "action", "operationName", "command", "cmd", "type"
  ];
  for (const k of discKeys) {
    if (k in obj && typeof obj[k] !== "object" && obj[k] !== null && obj[k] !== undefined) {
      const val = String(obj[k]).trim();
      if (val) return `${k}=${val}`;
    }
  }
  const em = obj.entityMap;
  if (em && typeof em === "object") {
    for (const k of ["identifier2", "entityType", "identifier1", "identifier3"]) {
      if (k in em && typeof em[k] !== "object" && em[k] !== null && em[k] !== undefined) {
        const val = String(em[k]).trim();
        if (val) return `entityMap.${k}=${val}`;
      }
    }
  }
  return "";
}

function harGetApiSignature(req) {
  if (!req) return "";
  const m = (req.method || "GET").toUpperCase().trim();
  const rawUrl = (req.url || "").trim();
  if (!rawUrl) return "";

  const u = harNormalizeUrl(rawUrl);
  const qKeys = harExtractQueryKeys(req);
  const qSig = qKeys.length ? `?${qKeys.join("&")}` : "";

  const b = (req.body !== undefined && req.body !== null) ? req.body : (req.payload || req.rawBody || null);
  const paths = harExtractBodyPaths(b);
  const uniquePaths = Array.from(new Set(paths.filter(Boolean))).sort();
  const pathsCount = uniquePaths.length;
  const pathsHash = pathsCount > 0 ? harHashString(uniquePaths.join(",")) : "";

  const disc = harFindDiscriminator(b);

  if (!qSig && pathsCount === 0 && !disc) {
    return `${m} ${u}`;
  }

  const parts = [`${m} ${u}${qSig}`];
  if (pathsCount > 0) parts.push(`params:${pathsCount}:${pathsHash}`);
  if (disc) parts.push(`disc:${disc}`);
  return parts.join("|");
}

function harSetupTokenApiControls() {
  const searchEl = document.getElementById("har-token-search");
  const kwEl     = document.getElementById("har-token-keyword");
  const dedupEl  = document.getElementById("har-token-dedup");
  const selAll   = document.getElementById("har-token-select-all");
  const deselAll = document.getElementById("har-token-deselect-all");

  const refilter = () => {
    const q = (searchEl?.value || "").toLowerCase();
    const kw = (kwEl?.value || "").toLowerCase();
    const dedup = dedupEl?.checked || false;
    let reqs = harState.requests;
    if (q)  reqs = reqs.filter(r => r.url.toLowerCase().includes(q));
    if (kw) reqs = reqs.filter(r => r.url.toLowerCase().includes(kw));
    if (dedup) {
      const seen = new Set();
      reqs = reqs.filter(r => {
        const key = harGetApiSignature(r);
        if (seen.has(key)) return false;
        seen.add(key); return true;
      });
    }
    harState.filtered = reqs;
    harSyncTokenApiList();
  };

  if (searchEl) searchEl.addEventListener("input", refilter);
  if (kwEl)     kwEl.addEventListener("input", refilter);
  if (dedupEl)  dedupEl.addEventListener("change", refilter);

  if (selAll) selAll.addEventListener("click", () => {
    const reqs = (harState.filtered !== null && harState.filtered !== undefined) ? harState.filtered : harState.requests;
    reqs.forEach(r => harState.checkedIds.add(r.id));
    harSyncTokenApiList();
    harUpdateNextBtn();
  });
  if (deselAll) deselAll.addEventListener("click", () => {
    const reqs = (harState.filtered !== null && harState.filtered !== undefined) ? harState.filtered : harState.requests;
    reqs.forEach(r => harState.checkedIds.delete(r.id));
    harSyncTokenApiList();
    harUpdateNextBtn();
  });
}

// Called from onclick in HTML — navigate to step if allowed
function harStepClick(n) {
  // Steps: 1=Capture, 2=Token, 3=Results
  if (n <= harState.currentStep) { harGoStep(n); return; }
  // Allow token step (2) if requests selected
  if (n === 2 && harState.checkedIds.size > 0) { harGoStep(2); return; }
  // Allow results step (3) only if results exist
  if (n === 3 && harState.testResults) { harGoStep(3); return; }
  // Otherwise ignore — not yet reached
}

// ── Backend check ─────────────────────────────────────────────────────────────
async function harCheckBackend() {
  const dot   = document.getElementById("backend-dot");
  const label = document.getElementById("backend-label");
  try {
    await fetch(`${HAR_BACKEND}/`);
    dot.className = "status-dot online";
    label.textContent = "Online";
  } catch(e) {
    dot.className = "status-dot offline";
    label.textContent = "Offline";
  }
}

// ── Load requests from shared AV capture ─────────────────────────────────────
async function harLoadRequests() {
  try {
    const resp = await fetch(`${AV_BACKEND}/capture/requests`).then(r => r.json());
    // .js files are captured for JS Analyser's use but are noise here —
    // harState isn't shared with other tools, so it's safe to drop them now.
    const incoming = (resp.requests || [])
      .filter(r => !_harDismissedIds.has(r.id))
      .filter(r => !(r.url || "").split("?")[0].toLowerCase().endsWith(".js"));

    if (harState.currentStep !== 1) return;

    const curr = harState.requests || [];
    let changed = curr.length !== incoming.length;
    if (!changed && curr.length > 0) {
      if (curr[0]?.id !== incoming[0]?.id || curr[curr.length - 1]?.id !== incoming[incoming.length - 1]?.id) {
        changed = true;
      }
    }
    if (changed || curr.length === 0) {
      harState.requests = incoming;
      harApplyFilter();
    }
  } catch(e) {}
}

// Sync capture button state
async function harSyncCaptureStatus() {
  try {
    const resp = await fetch(`${AV_BACKEND}/capture/status`).then(r => r.json());
    const harStatusEl = $h("har-capture-status-text");
    if (harStatusEl) {
      harStatusEl.textContent = resp.capturing ? "🔴 Capturing..." : "⏸ Capture paused";
      harStatusEl.style.color = resp.capturing ? "var(--red)" : "var(--text2)";
    }
    if (typeof updateCaptureUI === 'function') {
      updateCaptureUI();
    }
    const reqCount = $h("req-count");
    if (reqCount) {
      const count = (harState.filtered !== null && harState.filtered !== undefined)
        ? harState.filtered.length
        : harState.requests.length;
      reqCount.textContent = `${count} requests`;
    }
  } catch(e) {}
}

// ── Step navigation ───────────────────────────────────────────────────────────
function harGoStep(n) {
  harState.currentStep = n;
  document.querySelectorAll(".har-step-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll("#tool-har .har-step").forEach(el => {
    const s = parseInt(el.dataset.step);
    el.classList.remove("active", "done");
    if (s === n) el.classList.add("active");
    if (s < n)   el.classList.add("done");
  });
  const stepEl = document.getElementById(`har-step-${n}`);
  if (stepEl) stepEl.classList.add("active");
  // Step 2 = Token page — render users + selected APIs summary + update count
  if (n === 2) { harRenderUsers(); harRenderSelectedApis(); harUpdateTokenCount(); }
}

// ── STEP 1: Capture ───────────────────────────────────────────────────────────
function harSetupStep1() {
  $h("search-input").addEventListener("input", harApplyFilter);
  $h("method-filter").addEventListener("change", harApplyFilter);
  const dedupToggle = $h("dedup-toggle");
  if (dedupToggle) dedupToggle.addEventListener("change", harApplyFilter);
  const apimToggle = $h("apim-filter-toggle");
  if (apimToggle) apimToggle.addEventListener("change", harApplyFilter);
  $h("btn-next-1").addEventListener("click", () => harGoStep(2));

  $h("btn-select-all").addEventListener("click", () => {
    const visible = Array.isArray(harState.filtered) ? harState.filtered : (harState.requests || []);
    visible.forEach(r => harState.checkedIds.add(r.id));
    harRenderList();
    harUpdateNextBtn();
  });

  $h("btn-deselect-all").addEventListener("click", () => {
    const visible = Array.isArray(harState.filtered) ? harState.filtered : (harState.requests || []);
    visible.forEach(r => harState.checkedIds.delete(r.id));
    harRenderList();
    harUpdateNextBtn();
  });

  // Initial load
  harLoadRequests();

  // Import HAR
  $h("btn-import-har").addEventListener("click", () => {
    document.getElementById("har-har-file-input").value = "";
    document.getElementById("har-har-file-input").click();
  });

  document.getElementById("har-har-file-input").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        const har = JSON.parse(ev.target.result);
        const entries = har?.log?.entries || [];
        const imported = [];
        entries.forEach((entry, idx) => {
          const rq = entry.request || {};
          const method = (rq.method || "GET").toUpperCase();
          const url = rq.url || "";
          if (!url) return;
          const headers = {};
          (rq.headers || []).forEach(h => {
            if (!h || !h.name) return;
            if (String(h.name).startsWith(":")) return; // HTTP/2 pseudo-headers
            headers[h.name] = h.value;
          });
          const queryParams = {};
          (rq.queryString || []).forEach(q => { queryParams[q.name] = q.value; });
          let rawBody = null;
          if (rq.postData?.text) rawBody = rq.postData.text;
          // Some HARs put the real type only on postData.mimeType, not in headers
          const mime = (rq.postData && rq.postData.mimeType) ? String(rq.postData.mimeType).trim() : "";
          const hasCt = Object.keys(headers).some(k => k.toLowerCase() === "content-type");
          if (mime && !hasCt) headers["Content-Type"] = mime;
          const status = entry.response?.status || null;
          imported.push({
            id: `harfile-${Date.now()}-${idx}`,
            method, url, headers, queryParams,
            payload: rawBody, rawBody,
            body: null, body_type: null,
            status, statusText: String(status || ""),
            timestamp: Date.now() - idx * 10, source: "har",
          });
        });
        if (!imported.length) { alert("No entries found in HAR file"); return; }
        // Persist to shared backend store (avoids polling wipe)
        try {
          await fetch(`${AV_BACKEND}/capture/import`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(imported),
          });
        } catch(e) { console.warn("HAR import to backend failed:", e); }
        harState.requests = [...imported, ...harState.requests];
        harApplyFilter();
        const visibleCount = (harState.filtered !== null && harState.filtered !== undefined) ? harState.filtered.length : harState.requests.length;
        $h("req-count").textContent = `${visibleCount} requests`;
        alert(`✅ ${imported.length} APIs imported from HAR`);
      } catch(err) { alert("Invalid HAR file: " + err.message); }
    };
    reader.readAsText(file);
  });

  // Import cURL — use modal overlay (prompt() broken in pywebview)
  $h("btn-import-curl").addEventListener("click", () => {
    harOpenCurlModal();
  });
}

// cURL import modal (pywebview-safe, no prompt())
function harOpenCurlModal() {
  let modal = document.getElementById("har-curl-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "har-curl-modal";
    modal.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)";
    modal.innerHTML = `
      <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;width:560px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6)">
        <div style="padding:12px 14px;background:var(--bg3);border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
          <span style="font-weight:700;font-size:13px">📋 Import from cURL</span>
          <button id="har-curl-modal-close" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:14px;padding:2px 6px">✕</button>
        </div>
        <div style="padding:14px">
          <textarea id="har-curl-input" rows="8" style="width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px;font-family:var(--mono);font-size:11px;resize:vertical;outline:none" placeholder="curl 'https://...' -H 'Authorization: Bearer TOKEN' --data-raw '{}'"></textarea>
          <div id="har-curl-error" style="color:var(--red);font-size:11px;margin-top:6px;display:none"></div>
        </div>
        <div style="padding:10px 14px;background:var(--bg3);border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">
          <button id="har-curl-cancel" style="background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:5px 12px;cursor:pointer;font-size:11px">Cancel</button>
          <button id="har-curl-import-btn" style="background:var(--blue2);border:none;color:white;border-radius:6px;padding:5px 14px;cursor:pointer;font-size:12px;font-weight:700">📋 Parse & Import</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    document.getElementById("har-curl-modal-close").onclick = () => modal.style.display = "none";
    document.getElementById("har-curl-cancel").onclick = () => modal.style.display = "none";
    document.getElementById("har-curl-import-btn").onclick = async () => {
      const raw = document.getElementById("har-curl-input").value.trim();
      const errEl = document.getElementById("har-curl-error");
      if (!raw) { errEl.textContent = "Please paste a cURL command"; errEl.style.display = "block"; return; }
      try {
        const parts = raw.split(/(?=^curl\s)/m).filter(s => s.trim().startsWith("curl"));
        const reqs = (parts.length ? parts : [raw]).map(p => harParseCurl(p)).filter(r => r.url);
        if (!reqs.length) { errEl.textContent = "No valid URL found"; errEl.style.display = "block"; return; }
        // Persist to backend
        try {
          await fetch(`${AV_BACKEND}/capture/import`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(reqs),
          });
        } catch(e) { console.warn("cURL import to backend failed:", e); }
        harState.requests = [...reqs, ...harState.requests];
        harApplyFilter();
        const visibleCount = (harState.filtered !== null && harState.filtered !== undefined) ? harState.filtered.length : harState.requests.length;
        $h("req-count").textContent = `${visibleCount} requests`;
        modal.style.display = "none";
        alert(`✅ ${reqs.length} cURL request(s) imported`);
      } catch(e) { errEl.textContent = "Parse error: " + e.message; errEl.style.display = "block"; }
    };
  }
  modal.style.display = "flex";
  document.getElementById("har-curl-input").value = "";
  document.getElementById("har-curl-error").style.display = "none";
}

function harParseCurl(curlStr) {
  // Normalize line endings; join shell line-continuations (\ + newline)
  curlStr = curlStr.replace(/\r\n/g, "\n").replace(/\r/g, "\n")
                   .split("\\\n").join(" ").trim();

  let url = "";
  const urlM = curlStr.match(/https?:\/\/[^\s'"]+/);
  if (urlM) url = urlM[0].replace(/['"`]/g, "");

  let method = "GET";
  const mM = curlStr.match(/-X\s+['"]?(\w+)['"]?/i) ||
             curlStr.match(/--request\s+['"]?(\w+)['"]?/i);
  if (mM) method = mM[1].toUpperCase();

  const headers = {};
  const hdrRe = /(?:-H|--header)\s+(?:'([^']*)'|"([^"]*)")/g;
  let hm;
  while ((hm = hdrRe.exec(curlStr)) !== null) {
    const raw = hm[1] !== undefined ? hm[1] : hm[2];
    if (!raw) continue;
    const ci = raw.indexOf(":");
    if (ci > 0) headers[raw.substring(0, ci).trim()] = raw.substring(ci + 1).trim();
  }

  // Body — find data flag, extract quoted argument robustly
  let rawBody = null;
  const _flags = ["--data-raw", "--data-binary", "--data", "-d"];
  for (let _fi = 0; _fi < _flags.length && rawBody === null; _fi++) {
    const _f = _flags[_fi];
    const _pos = curlStr.indexOf(_f + " ");
    if (_pos < 0) continue;
    const _rest = curlStr.slice(_pos + _f.length + 1).trimStart();
    if (_rest.startsWith("$'")) {
      // $'...' bash ANSI-C quoting — one-pass unescape so \\n stays as \n (valid JSON)
      const _dm = _rest.match(/^\$'((?:[^'\\]|\\[\s\S])*?)(?:'|$)/);
      if (_dm) rawBody = _dm[1].replace(/\\(\\|'|"|n|t|r|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (m, c) => {
        if (c === '\\') return '\\';
        if (c === "'") return "'";
        if (c === '"') return '"';
        if (c === 'n')  return '\n';
        if (c === 't')  return '\t';
        if (c === 'r')  return '\r';
        if (c[0] === 'u' && c.length === 5) return String.fromCharCode(parseInt(c.slice(1), 16));
        if (c[0] === 'U' && c.length === 9) return String.fromCodePoint(parseInt(c.slice(1), 16));
        return m;
      });
    } else if (_rest.charAt(0) === "'") {
      const _e = _rest.indexOf("'", 1);
      if (_e > -1) rawBody = _rest.slice(1, _e);
    } else if (_rest.charAt(0) === '"') {
      const _e = _rest.indexOf('"', 1);
      if (_e > -1) rawBody = _rest.slice(1, _e);
    }
  }
  if (rawBody !== null && method === "GET") method = "POST";

  const queryParams = {};
  try { new URL(url).searchParams.forEach((v, k) => { queryParams[k] = v; }); } catch(e) {}

  return { id: "curl-" + Date.now(), method, url, headers, queryParams,
           payload: rawBody, rawBody, body: null, body_type: null,
           status: null, statusText: "", timestamp: Date.now(), source: "curl" };
}

function harApplyFilter() {
  const q = ($h("search-input")?.value || "").toLowerCase().trim();
  const m = $h("method-filter")?.value || "";
  const apimOnly = $h("apim-filter-toggle") ? $h("apim-filter-toggle").checked : true;
  const dedup = $h("dedup-toggle") ? $h("dedup-toggle").checked : false;

  let reqs = harState.requests;
  if (apimOnly) {
    reqs = reqs.filter(r => (r.url || "").toLowerCase().includes("apim"));
  }
  if (q) {
    reqs = reqs.filter(r => (r.url || "").toLowerCase().includes(q));
  }
  if (m) {
    reqs = reqs.filter(r => (r.method || "").toUpperCase() === m.toUpperCase());
  }
  if (dedup) {
    const seen = new Set();
    reqs = reqs.filter(r => {
      const sig = harGetApiSignature(r);
      if (seen.has(sig)) return false;
      seen.add(sig);
      return true;
    });
  }
  harState.filtered = reqs;

  // Only prune checkedIds that were deleted and no longer exist in requests
  const validIds = new Set((harState.requests || []).map(r => r.id));
  for (const id of harState.checkedIds) {
    if (!validIds.has(id)) {
      harState.checkedIds.delete(id);
    }
  }

  harRenderList();
}

function harRenderList() {
  const list   = $h("request-list");
  const empty  = $h("empty-state");
  const reqs   = harState.filtered;

  if (!reqs || !reqs.length) {
    empty.style.display = "flex";
    list.innerHTML = "";
    $h("req-count").textContent = "0 requests";
    harUpdateNextBtn();
    return;
  }
  empty.style.display = "none";
  $h("req-count").textContent = `${reqs.length} requests`;
  list.innerHTML = "";

  reqs.forEach(req => {
    const checked = harState.checkedIds.has(req.id);
    const item = document.createElement("div");
    item.className = `request-item${checked ? " checked-item" : ""}`;

    const mc = harGetMethodClass(req.method);
    const sc = harGetStatusClass(req.status);
    let urlDisplay = harEsc(req.url || "");
    try {
      const u = new URL(req.url);
      urlDisplay = `<span class="url-host" style="color:var(--text3)">${harEsc(u.protocol)}//${harEsc(u.host)}</span><span class="url-path">${harEsc(u.pathname)}</span>${u.search ? `<span class="url-query" style="color:#79c0ff;font-weight:600">${harEsc(u.search)}</span>` : ""}`;
    } catch(e) {}

    item.innerHTML = `
      <input type="checkbox" class="req-checkbox" ${checked ? "checked" : ""}>
      <span class="method-badge method-${mc}">${harEsc(req.method)}</span>
      <span class="req-url" title="${harEsc(req.url || "")}">${urlDisplay}</span>
      <span class="status-pill ${sc}">${req.status || "---"}</span>
      <button class="btn-delete-req" title="Delete API from list" aria-label="Delete API">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
          <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
          <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
        </svg>
      </button>
    `;

    const cb = item.querySelector(".req-checkbox");
    cb.addEventListener("change", e => {
      e.stopPropagation();
      if (e.target.checked) harState.checkedIds.add(req.id);
      else harState.checkedIds.delete(req.id);
      item.classList.toggle("checked-item", e.target.checked);
      harUpdateNextBtn();
    });

    const delBtn = item.querySelector(".btn-delete-req");
    if (delBtn) {
      delBtn.addEventListener("click", e => {
        e.stopPropagation();
        harDeleteRequest(req);
      });
    }

    item.addEventListener("click", e => {
      if (e.target === cb || e.target.closest(".btn-delete-req")) return;
      if (harState.checkedIds.has(req.id)) {
        harState.checkedIds.delete(req.id);
        cb.checked = false;
        item.classList.remove("checked-item");
      } else {
        harState.checkedIds.add(req.id);
        cb.checked = true;
        item.classList.add("checked-item");
      }
      harUpdateNextBtn();
    });

    list.appendChild(item);
  });
}

async function harDeleteRequest(req) {
  if (!req) return;

  const urlDisplay = (req.url || "").length > 55 ? (req.url.slice(0, 52) + "...") : (req.url || "");
  let ok = false;
  if (typeof showAvConfirm === "function") {
    try {
      ok = await showAvConfirm(
        "Delete API Request",
        `Are you sure you want to delete this API from the list?\n\n${req.method} ${urlDisplay}`,
        "Yes, Delete",
        true
      );
    } catch(e) {
      ok = window.confirm(`Are you sure you want to delete this API from the list?\n\n${req.method} ${urlDisplay}`);
    }
  } else {
    ok = window.confirm(`Are you sure you want to delete this API from the list?\n\n${req.method} ${urlDisplay}`);
  }
  if (!ok) return;

  _harDismissedIds.add(req.id);
  harState.checkedIds.delete(req.id);
  harState.requests = (harState.requests || []).filter(r => r.id !== req.id);
  if (Array.isArray(harState.filtered)) {
    harState.filtered = harState.filtered.filter(r => r.id !== req.id);
  }

  // Sync delete with backend so it is removed from shared capture store
  try {
    fetch(`${AV_BACKEND}/capture/delete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: req.id })
    }).catch(() => {});
  } catch(e) {}

  harRenderList();
  harUpdateNextBtn();
  if (typeof showConfigToast === "function") {
    showConfigToast(`🗑️ Deleted ${req.method} ${urlDisplay}`);
  }
}
window.harDeleteRequest = harDeleteRequest;

function harUpdateNextBtn() {
  const n = harGetSelectedRequests().length;
  $h("checked-count-label").textContent = `${n} selected`;
  $h("btn-next-1").disabled = n === 0;
}

// ── STEP 2: Token (Multi-User) ─────────────────────────────────────────────────
function harRenderUsers() {
  const container = $h("users-container");
  if (!container) return;
  container.innerHTML = "";

  const countBadge = $h("user-count-badge");
  if (countBadge) {
    countBadge.textContent = `${harState.users.length}/${MAX_HAR_USERS}`;
  }

  const addBtn = $h("btn-add-user");
  if (addBtn) {
    addBtn.disabled = harState.users.length >= MAX_HAR_USERS;
    addBtn.style.opacity = harState.users.length >= MAX_HAR_USERS ? "0.5" : "1";
    addBtn.style.cursor = harState.users.length >= MAX_HAR_USERS ? "not-allowed" : "pointer";
    addBtn.title = harState.users.length >= MAX_HAR_USERS ? "Maximum 7 users reached" : "Add another user token";
  }

  harState.users.forEach((user, idx) => {
    const color = harGetUserColor(idx);
    const card = document.createElement("div");
    card.className = "har-user-card";
    card.id = `har-user-card-${user.id}`;

    const canRemove = harState.users.length > 1;

    const getHintHtml = (u) => {
      if (u.isUnauth) {
        return u.token
          ? `<span style="color:#f85149;font-weight:600">🛡️ Unauthorized Role (Expected 403)</span> · Token present (${u.token.length} chars) · Returns 2xx = <b>🚨 Auth Bypass / IDOR</b>`
          : `<span style="color:#f85149;font-weight:600">🛡️ Anonymous User (Expected 401/403)</span> · No token · Returns 2xx = <b>🚨 Auth Bypass / IDOR</b>`;
      }
      return u.token ? `🔑 Token length: ${u.token.length} chars` : `⚠️ Empty token`;
    };

    card.innerHTML = `
      <div class="har-user-card-header">
        <div style="display:flex;align-items:center;gap:8px">
          <span class="har-user-tag" style="background:${color.bg};color:${color.text};border:1px solid ${color.border}">
            👤 User ${idx + 1}
          </span>
          <input type="text" class="har-user-role-input" maxlength="50" value="${harEsc(user.name)}" placeholder="Role / Name (e.g. Admin)" title="User Role or Name (max 50 characters)">
        </div>
        <div class="har-user-actions">
          <label style="font-size:11px;color:var(--text2);display:inline-flex;align-items:center;gap:4px;cursor:pointer;user-select:none;margin-right:4px" title="Mark as Unauthorized / Restricted user (Expected 403 Forbidden. If 2xx is returned, Auth Bypass / IDOR will be flagged)">
            <input type="checkbox" class="har-user-unauth-cb" ${user.isUnauth ? "checked" : ""}>
            <span class="har-unauth-lbl-text" style="${user.isUnauth ? 'color:#f85149;font-weight:700' : ''}">🛡️ Unauthorized (Expected 403)</span>
          </label>
          <button type="button" class="har-user-action-btn btn-paste-user" title="Paste token from clipboard">📋 Paste</button>
          <button type="button" class="har-user-action-btn btn-clear-user" title="Clear token">🗑️ Clear</button>
          ${canRemove ? `<button type="button" class="har-user-action-btn btn-remove-user" style="color:var(--red)" title="Remove this user">✕</button>` : ""}
        </div>
      </div>
      <textarea class="har-user-token-textarea" placeholder="Paste token for ${harEsc(user.name)} (leave blank if testing anonymous / no token)...">${harEsc(user.token)}</textarea>
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:10px;color:var(--text3)">
        <span class="har-user-status-hint">${getHintHtml(user)}</span>
      </div>
    `;

    const nameInput = card.querySelector(".har-user-role-input");
    nameInput.addEventListener("input", (e) => {
      const val = (e.target.value || "").slice(0, 50);
      if (e.target.value !== val) e.target.value = val;
      user.name = val.trim() || `User ${idx + 1}`;
      harUpdateRunBtnText();
    });

    const unauthCb = card.querySelector(".har-user-unauth-cb");
    const tokenTextarea = card.querySelector(".har-user-token-textarea");
    const hintSpan = card.querySelector(".har-user-status-hint");
    const unauthLbl = card.querySelector(".har-unauth-lbl-text");

    unauthCb.addEventListener("change", (e) => {
      user.isUnauth = e.target.checked;
      if (unauthLbl) {
        unauthLbl.style.color = user.isUnauth ? "#f85149" : "";
        unauthLbl.style.fontWeight = user.isUnauth ? "700" : "";
      }
      hintSpan.innerHTML = getHintHtml(user);
      harUpdateRunBtnText();
    });

    tokenTextarea.addEventListener("input", (e) => {
      user.token = e.target.value.trim().replace(/^Bearer\s+/i, "");
      hintSpan.innerHTML = getHintHtml(user);
      harUpdateRunBtnText();
    });

    const pasteBtn = card.querySelector(".btn-paste-user");
    pasteBtn.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        const cleaned = text.trim().replace(/^Bearer\s+/i, "");
        user.token = cleaned;
        tokenTextarea.value = cleaned;
        hintSpan.innerHTML = getHintHtml(user);
        harUpdateRunBtnText();
      } catch (err) {
        alert("Clipboard access denied — please paste manually");
      }
    });

    const clearBtn = card.querySelector(".btn-clear-user");
    clearBtn.addEventListener("click", () => {
      user.token = "";
      tokenTextarea.value = "";
      hintSpan.innerHTML = getHintHtml(user);
      harUpdateRunBtnText();
    });

    if (canRemove) {
      const removeBtn = card.querySelector(".btn-remove-user");
      removeBtn.addEventListener("click", () => {
        harState.users.splice(idx, 1);
        harRenderUsers();
        harUpdateRunBtnText();
      });
    }

    container.appendChild(card);
  });

  harUpdateRunBtnText();
}

function harUpdateRunBtnText() {
  const runBtn = $h("btn-run");
  if (!runBtn) return;
  const apiCount = harGetSelectedRequests().length;
  const userCount = harState.users.length;
  const total = apiCount * userCount;
  runBtn.innerHTML = `🚀 Run Tests (${apiCount} APIs × ${userCount} Users = ${total} Requests)`;
  runBtn.disabled = apiCount === 0 || userCount === 0;
}

function harSetupStep2() {
  const addBtn = $h("btn-add-user");
  if (addBtn) {
    addBtn.addEventListener("click", () => {
      if (harState.users.length >= MAX_HAR_USERS) {
        alert(`Maximum ${MAX_HAR_USERS} users allowed.`);
        return;
      }
      const newNum = harState.users.length + 1;
      harState.users.push({
        id: `user_${newNum}`,
        name: `User ${newNum}`,
        token: "",
        isUnauth: false,
      });
      harRenderUsers();
    });
  }

  $h("btn-back-1").addEventListener("click", () => harGoStep(1));
  $h("btn-run").addEventListener("click", harRunTests);

  harRenderUsers();
}

function harRenderSelectedApis() {
  const selectedReqs = harGetSelectedRequests();
  const container = $h("selected-apis-list");
  container.innerHTML = "";
  if (!selectedReqs.length) {
    container.innerHTML = `<div style="color:var(--text3);font-size:11px">No APIs selected</div>`;
    return;
  }
  selectedReqs.forEach(req => {
    const chip = document.createElement("div");
    chip.className = "selected-api-chip";
    const mc = harGetMethodClass(req.method);
    let path = req.url;
    try {
      const u = new URL(req.url);
      path = u.pathname + (u.search || "");
    } catch(e) {}
    chip.innerHTML = `
      <span class="method-badge method-${mc}">${harEsc(req.method)}</span>
      <span class="chip-url" title="${harEsc(req.url)}">${harEsc(path)}</span>
    `;
    container.appendChild(chip);
  });
}

// ── Run Tests (live feed + abort) ─────────────────────────────────────────────
let _harRunAbortController = null;
let _harRunUserAborted = false;
let _harAbortBound = false;

function harBindAbortButton() {
  if (_harAbortBound) return;
  const abortBtn = document.getElementById("har-btn-abort-run");
  if (!abortBtn) return;
  _harAbortBound = true;
  abortBtn.addEventListener("click", () => {
    _harRunUserAborted = true;
    abortBtn.disabled = true;
    abortBtn.textContent = "Aborting…";
    harAppendRunFeed("info", "Abort requested — stopping after current request…");
    const title = document.getElementById("har-running-title");
    if (title) title.textContent = "Aborting…";
    if (_harRunAbortController) _harRunAbortController.abort();
  });
}

function harResetRunningOverlay(title) {
  const titleEl = document.getElementById("har-running-title");
  if (titleEl) titleEl.textContent = title || "Running APIs...";
  harUpdateRunProgress(0, 0, 0, "Preparing...");
  const feed = document.getElementById("har-running-live-feed");
  if (feed) {
    feed.innerHTML = "";
    feed.classList.remove("has-lines");
  }
  const abortBtn = document.getElementById("har-btn-abort-run");
  if (abortBtn) {
    abortBtn.disabled = false;
    abortBtn.textContent = "Abort";
    abortBtn.classList.remove("is-hidden");
  }
}

function harUpdateRunProgress(pct, done, total, label) {
  const pctEl = document.getElementById("har-running-pct");
  const fill  = document.getElementById("har-running-progress-fill");
  const lab   = document.getElementById("har-running-progress-label");
  const safePct = Math.max(0, Math.min(100, pct));
  if (pctEl) pctEl.textContent = safePct + "%";
  if (fill)  fill.style.width = safePct + "%";
  if (lab) {
    lab.textContent = label || (
      safePct < 100
        ? `Firing ${done} / ${total} requests...`
        : `✅ ${total} requests complete`
    );
  }
}

function harAppendRunFeed(kind, text) {
  const feed = document.getElementById("har-running-live-feed");
  if (!feed) return;
  feed.classList.add("has-lines");
  const line = document.createElement("div");
  line.className = "feed-line feed-" + (kind || "info");
  line.textContent = text;
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
}

function harFeedKindForStatus(code, mode) {
  const sc = String(code);
  if (!/^\d+$/.test(sc)) return "fail";
  const n = parseInt(sc, 10);
  if (mode === "unauthorized" && n >= 200 && n < 300) return "fail"; // interesting for auth check
  if (n >= 200 && n < 300) return "pass";
  if (n >= 400 && n < 500) return "warn";
  if (n >= 500) return "fail";
  return "info";
}

function harShortPath(url) {
  try { return new URL(url).pathname; } catch (_) { return String(url || "").slice(0, 60); }
}

function harSummarizePartial(results, tokenMode) {
  return {
    total: results.length,
    success: results.filter(r => typeof r.status_code === "number" && r.status_code >= 200 && r.status_code < 300).length,
    client_errors: results.filter(r => typeof r.status_code === "number" && r.status_code >= 400 && r.status_code < 500).length,
    server_errors: results.filter(r => typeof r.status_code === "number" && r.status_code >= 500).length,
    network_errors: results.filter(r => typeof r.status_code !== "number").length,
    apis_run: new Set(results.map(r => `${r.method} ${r.url}`)).size,
    token_mode: tokenMode,
  };
}

async function harConsumeRunStream(payload, totalExpected, signal) {
  let results = [];
  let summary = null;
  let expected = totalExpected;
  let aborted = false;
  let finalPayload = null;

  const packPartial = (wasAborted) => ({
    aborted: !!wasAborted,
    results,
    summary: summary || harSummarizePartial(results, payload.token_mode),
  });

  const handleEvent = (ev) => {
    if (!ev || !ev.type) return;
    if (ev.type === "start") {
      expected = ev.total_expected || expected;
      const uCount = ev.users_count || (payload.users ? payload.users.length : 1);
      harAppendRunFeed("info", `${expected} request(s) queued across ${uCount} user(s) · mode: multi_user`);
      harUpdateRunProgress(0, 0, expected);
      return;
    }
    if (ev.type === "result") {
      const row = ev.result;
      results.push(row);
      summary = ev.summary || summary;
      expected = ev.total_expected || expected;
      const done = ev.done || results.length;
      const pct = expected ? Math.round((done / expected) * 100) : 0;
      harUpdateRunProgress(pct, done, expected);
      const userTag = row.user_name || row.user_id || "User";
      const sizeTag = row.response_size != null ? ` [${harFormatSize(row.response_size)}]` : "";
      const isUnauth = !!(row.is_unauth || row.mode === "unauthorized");
      const isBypass = isUnauth && typeof row.status_code === "number" && row.status_code >= 200 && row.status_code < 300;
      const feedKind = isBypass ? "fail" : harFeedKindForStatus(row.status_code, row.mode);
      const bypassTag = isBypass ? " 🚨 AUTH BYPASS (Expected 403)" : (isUnauth && row.status_code >= 400 ? " 🛡️ Protected" : "");
      harAppendRunFeed(
        feedKind,
        `[${userTag}] ${row.method} ${harShortPath(row.url)} → ${row.status_code} (${row.elapsed_ms}ms)${sizeTag}${bypassTag}`
      );
      return;
    }
    if (ev.type === "done") {
      aborted = !!ev.aborted;
      results = Array.isArray(ev.results) ? ev.results : results;
      summary = ev.summary || summary;
      finalPayload = { summary, results, aborted };
      return;
    }
    if (ev.type === "error") {
      throw new Error(ev.message || "Stream error");
    }
  };

  try {
    const resp = await fetch(`${HAR_BACKEND}/run-stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal,
    });
    if (!resp.ok) {
      const txt = await resp.text();
      throw new Error(`HTTP ${resp.status}: ${txt}`);
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (!line.trim()) continue;
        handleEvent(JSON.parse(line));
      }
    }
    if (buffer.trim()) handleEvent(JSON.parse(buffer));
  } catch (e) {
    if (e.name === "AbortError" || _harRunUserAborted) {
      return packPartial(true);
    }
    throw e;
  }

  return finalPayload || packPartial(_harRunUserAborted || aborted);
}

async function harRunTests() {
  const selectedReqs = harGetSelectedRequests();
  if (!selectedReqs.length) {
    alert("No APIs selected");
    return;
  }

  if (!harState.users || harState.users.length === 0) {
    alert("Please add at least one user in the Token tab.");
    return;
  }

  // Check if any users have empty tokens without checking unauth
  const emptyUsers = harState.users.filter(u => !u.isUnauth && !(u.token || "").trim());
  if (emptyUsers.length > 0) {
    const names = emptyUsers.map((u, i) => u.name || `User ${i + 1}`).join(", ");
    const proceed = confirm(
      `The following user(s) have an empty token:\n${names}\n\nDo you want to test them without an Authorization header (Unauthenticated)?\n\nClick OK to proceed, or Cancel to fill tokens.`
    );
    if (!proceed) return;
    emptyUsers.forEach(u => { u.isUnauth = true; });
    harRenderUsers();
  }

  const urlKeyword = "";
  const deduplicate = $h("dedup-toggle") ? $h("dedup-toggle").checked : true;

  const apis = selectedReqs.map(r => ({
    id:      r.id || null,
    method:  r.method,
    url:     r.url,
    headers: r.headers || {},
    payload: (r.rawBody || (typeof r.body === "string" ? r.body : (r.body ? JSON.stringify(r.body) : null)) || r.payload || null),
  }));

  const payload = {
    apis,
    users: harState.users.map((u, i) => ({
      id: u.id || `user_${i + 1}`,
      name: u.name || `User ${i + 1}`,
      token: (u.token || "").trim().replace(/^Bearer\s+/i, ""),
      is_unauth: !!u.isUnauth,
    })),
    token_mode: "multi_user",
    url_filter: urlKeyword,
    deduplicate,
  };

  harBindAbortButton();
  harGoStep(3);
  const overlay = document.getElementById("har-running-overlay");
  if (overlay) overlay.style.display = "flex";
  $h("results-content").style.display = "none";
  harResetRunningOverlay("Running Multi-User API Tests...");

  const totalExpected = selectedReqs.length * harState.users.length;
  _harRunUserAborted = false;
  _harRunAbortController = new AbortController();

  try {
    const data = await harConsumeRunStream(payload, totalExpected, _harRunAbortController.signal);
    const aborted = !!(data.aborted || _harRunUserAborted);
    const total = data.summary?.total || data.results?.length || 0;
    harUpdateRunProgress(
      100, total, total,
      aborted ? `⏹ Aborted — ${total} result(s)` : `✅ ${total} requests complete`
    );
    const title = document.getElementById("har-running-title");
    if (title) title.textContent = aborted ? "Scan aborted" : "Complete";
    if (aborted) harAppendRunFeed("warn", `Stopped early — showing ${total} completed request(s)`);
    await new Promise(r => setTimeout(r, aborted ? 450 : 280));
    harState.testResults = data;
    harRenderResults(data);
  } catch (e) {
    alert("Run failed: " + e.message + "\n\nMake sure HAR backend is running on port 8766");
  } finally {
    _harRunAbortController = null;
    const abortBtn = document.getElementById("har-btn-abort-run");
    if (abortBtn) {
      abortBtn.disabled = false;
      abortBtn.textContent = "Abort";
    }
    if (overlay) overlay.style.display = "none";
    $h("results-content").style.display = "flex";
  }
}

// ── Response Size & Size Diff Helpers ─────────────────────────────────────────
function harGetResultSize(r) {
  if (r && typeof r.response_size === "number") return r.response_size;
  if (!r || !r.response) return 0;
  try {
    return new TextEncoder().encode(r.response).length;
  } catch (_) {
    return r.response.length;
  }
}

function harFormatSize(bytes) {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function harComputeSizeDiff(results) {
  if (!Array.isArray(results) || !results.length) {
    return {
      diffKeys: new Set(),
      diffIndices: new Set(),
      diffCount: 0,
      sameKeys: new Set(),
      sameIndices: new Set(),
      sameCount: 0,
      users: [],
      endpointMap: new Map(),
      pairs: [],
      pairDiffMap: {},
      pairSameMap: {},
      allUsersDiffKeys: new Set(),
      allUsersSameKeys: new Set()
    };
  }

  // 1. Collect unique users in order
  const userMap = new Map();
  results.forEach(r => {
    const uid = r.user_id || "user_1";
    const uname = r.user_name || uid;
    if (!userMap.has(uid)) {
      userMap.set(uid, { id: uid, name: uname, index: userMap.size });
    }
  });
  const users = Array.from(userMap.values());

  // 2. Group by endpoint: method + url
  const endpointMap = new Map();
  results.forEach((r, idx) => {
    const method = (r.method || "GET").toUpperCase();
    const url = (r.url || "").trim();
    const key = `${method} ${url}`;
    let path = url;
    try {
      const u = new URL(url);
      path = u.pathname + (u.search || "");
    } catch(e) {}
    if (!endpointMap.has(key)) {
      endpointMap.set(key, { key, method, url, path, rows: [] });
    }
    const size = harGetResultSize(r);
    const sc = parseInt(r.status_code, 10);
    const is2xx = !isNaN(sc) && sc >= 200 && sc < 300;
    endpointMap.get(key).rows.push({
      r,
      idx,
      userId: r.user_id || "user_1",
      userName: r.user_name || "User",
      size,
      sc,
      is2xx
    });
  });

  // 3. Generate all pairwise user combinations: User 1 vs User 2, User 2 vs User 3, etc.
  const pairs = [];
  const pairDiffMap = {};
  const pairSameMap = {};
  for (let i = 0; i < users.length; i++) {
    for (let j = i + 1; j < users.length; j++) {
      const uA = users[i];
      const uB = users[j];
      const pKey = `${uA.id}__${uB.id}`;
      pairs.push({ key: pKey, userA: uA, userB: uB });
      pairDiffMap[pKey] = { endpoints: new Set(), indices: new Set(), userA: uA, userB: uB };
      pairSameMap[pKey] = { endpoints: new Set(), indices: new Set(), userA: uA, userB: uB };
    }
  }

  const diffKeys = new Set();
  const diffIndices = new Set();
  const sameKeys = new Set();
  const sameIndices = new Set();
  const allUsersDiffKeys = new Set();
  const allUsersSameKeys = new Set();

  endpointMap.forEach((group, key) => {
    const rows = group.rows;
    if (rows.length < 2) return;

    // Check overall size diff
    const allSizes = rows.map(x => x.size);
    const sizeSet = new Set(allSizes);
    if (sizeSet.size > 1) {
      diffKeys.add(key);
      rows.forEach(x => diffIndices.add(x.idx));
      if (sizeSet.size === rows.length && rows.length >= 3) {
        allUsersDiffKeys.add(key);
      }
    }

    // Check overall 2xx same (all 2xx users got exact same bytes)
    const ok2xx = rows.filter(x => x.is2xx);
    if (ok2xx.length >= 2 && new Set(ok2xx.map(x => x.size)).size === 1) {
      sameKeys.add(key);
      ok2xx.forEach(x => sameIndices.add(x.idx));
      if (ok2xx.length === rows.length) {
        allUsersSameKeys.add(key);
      }
    }

    // Pairwise check
    const byUser = {};
    rows.forEach(x => { byUser[x.userId] = x; });

    pairs.forEach(p => {
      const rowA = byUser[p.userA.id];
      const rowB = byUser[p.userB.id];
      if (rowA && rowB) {
        if (rowA.size !== rowB.size) {
          pairDiffMap[p.key].endpoints.add(key);
          pairDiffMap[p.key].indices.add(rowA.idx);
          pairDiffMap[p.key].indices.add(rowB.idx);
        } else {
          pairSameMap[p.key].endpoints.add(key);
          pairSameMap[p.key].indices.add(rowA.idx);
          pairSameMap[p.key].indices.add(rowB.idx);
        }
      }
    });
  });

  return {
    diffKeys,
    diffIndices,
    diffCount: diffIndices.size,
    sameKeys,
    sameIndices,
    sameCount: sameIndices.size,
    users,
    endpointMap,
    pairs,
    pairDiffMap,
    pairSameMap,
    allUsersDiffKeys,
    allUsersSameKeys
  };
}

// ── Step 3 Filter Populator ───────────────────────────────────────────────────
function harPopulateResultFilterSelects(results, metrics) {
  const userSelect = $h("results-user-filter");
  if (userSelect) {
    const currentVal = harState.resultUserFilter || "all";
    userSelect.innerHTML = `<option value="all">👤 All Users (${results.length})</option>`;
    metrics.users.forEach((u) => {
      const uCount = results.filter(r => (r.user_id || "user_1") === u.id).length;
      const opt = document.createElement("option");
      opt.value = u.id;
      opt.textContent = `👤 ${u.name} (${uCount})`;
      userSelect.appendChild(opt);
    });
    if (metrics.users.some(u => u.id === currentVal)) {
      userSelect.value = currentVal;
    } else {
      userSelect.value = "all";
      harState.resultUserFilter = "all";
    }
  }

  const compareSelect = $h("results-compare-filter");
  if (compareSelect) {
    const currentComp = harState.resultCompareFilter || "all";
    compareSelect.innerHTML = "";

    const optAll = document.createElement("option");
    optAll.value = "all";
    optAll.textContent = "🔍 All Comparisons";
    compareSelect.appendChild(optAll);

    const optAnyDiff = document.createElement("option");
    optAnyDiff.value = "any_diff";
    optAnyDiff.textContent = `⚖️ Any Size Diff (${metrics.diffKeys.size} APIs)`;
    compareSelect.appendChild(optAnyDiff);

    const optAllSame = document.createElement("option");
    optAllSame.value = "all_same";
    optAllSame.textContent = `🎯 All 2xx Same (${metrics.sameKeys.size} APIs)`;
    compareSelect.appendChild(optAllSame);

    if (metrics.pairs && metrics.pairs.length > 0) {
      // Group: Pairwise Differences
      const diffGroup = document.createElement("optgroup");
      diffGroup.label = "── Pairwise Size Diff (≠) ──";
      let hasDiffPairs = false;
      metrics.pairs.forEach(p => {
        const dCount = metrics.pairDiffMap[p.key]?.endpoints.size || 0;
        if (dCount > 0) {
          hasDiffPairs = true;
          const opt = document.createElement("option");
          opt.value = `diff__${p.key}`;
          opt.textContent = `${p.userA.name} ≠ ${p.userB.name} (${dCount} APIs)`;
          diffGroup.appendChild(opt);
        }
      });
      if (hasDiffPairs) compareSelect.appendChild(diffGroup);

      // Group: Pairwise Size Matches (Same)
      const sameGroup = document.createElement("optgroup");
      sameGroup.label = "── Pairwise Size Match (=) ──";
      let hasSamePairs = false;
      metrics.pairs.forEach(p => {
        const sCount = metrics.pairSameMap[p.key]?.endpoints.size || 0;
        if (sCount > 0) {
          hasSamePairs = true;
          const opt = document.createElement("option");
          opt.value = `same__${p.key}`;
          opt.textContent = `${p.userA.name} = ${p.userB.name} (${sCount} APIs)`;
          sameGroup.appendChild(opt);
        }
      });
      if (hasSamePairs) compareSelect.appendChild(sameGroup);
    }

    const allOptValues = Array.from(compareSelect.options).map(o => o.value);
    if (allOptValues.includes(currentComp)) {
      compareSelect.value = currentComp;
    } else {
      compareSelect.value = "all";
      harState.resultCompareFilter = "all";
    }
  }
}

// ── Results Setup & Rendering ─────────────────────────────────────────────────
function harSetupStep3() {
  $h("btn-back-2").addEventListener("click", () => harGoStep(1));
  $h("btn-csv").addEventListener("click",  harExportCsv);
  $h("btn-html").addEventListener("click", harExportHtml);

  harSetupDiffView();

  document.querySelectorAll(".har-rf-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      harState.resultFilter = btn.dataset.f;
      document.querySelectorAll(".har-rf-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      if (harState.testResults) harRenderResultsTable(harState.testResults.results);
    });
  });

  const userSelect = $h("results-user-filter");
  if (userSelect) {
    userSelect.addEventListener("change", () => {
      harState.resultUserFilter = userSelect.value;
      if (harState.testResults) harRenderResultsTable(harState.testResults.results);
    });
  }

  const compareSelect = $h("results-compare-filter");
  if (compareSelect) {
    compareSelect.addEventListener("change", () => {
      harState.resultCompareFilter = compareSelect.value;
      if (harState.testResults) harRenderResultsTable(harState.testResults.results);
    });
  }

  const urlSearch = $h("results-url-search");
  if (urlSearch) {
    urlSearch.addEventListener("input", () => {
      harState.resultUrlQuery = urlSearch.value || "";
      if (harState.testResults) harRenderResultsTable(harState.testResults.results);
    });
  }

  const thTime = $h("th-time");
  if (thTime) {
    thTime.addEventListener("click", () => {
      if (harState.sortCol === "time") {
        harState.sortDir = harState.sortDir === "asc" ? "desc" : "asc";
      } else {
        harState.sortCol = "time";
        harState.sortDir = "asc";
      }
      if (harState.testResults) harRenderResultsTable(harState.testResults.results);
    });
  }

  const thSize = $h("th-size");
  if (thSize) {
    thSize.addEventListener("click", () => {
      if (harState.sortCol === "size") {
        harState.sortDir = harState.sortDir === "asc" ? "desc" : "asc";
      } else {
        harState.sortCol = "size";
        harState.sortDir = "asc";
      }
      if (harState.testResults) harRenderResultsTable(harState.testResults.results);
    });
  }
}

function harRenderResults(data) {
  const { summary, results } = data;
  $h("sc-total").textContent = summary?.total || (results?.length || 0);
  $h("sc-ok").textContent    = summary?.success || 0;
  $h("sc-4xx").textContent   = summary?.client_errors || 0;
  $h("sc-5xx").textContent   = summary?.server_errors || 0;
  $h("sc-err").textContent   = summary?.network_errors || 0;

  const metrics = harComputeSizeDiff(results || []);
  const countBadge = $h("sizediff-count");
  if (countBadge) {
    countBadge.textContent = metrics.diffKeys.size;
    countBadge.style.display = metrics.diffKeys.size > 0 ? "inline-block" : "none";
  }
  const sameBadge = $h("sizesame-count");
  if (sameBadge) {
    sameBadge.textContent = metrics.sameKeys.size;
    sameBadge.style.display = metrics.sameKeys.size > 0 ? "inline-block" : "none";
  }

  // Update view toggle counts
  const allCountBadge = $h("count-all-reqs");
  if (allCountBadge) allCountBadge.textContent = results?.length || 0;
  const uniqueCountBadge = $h("count-unique-apis");
  if (uniqueCountBadge) uniqueCountBadge.textContent = metrics.endpointMap.size;

  harPopulateResultFilterSelects(results || [], metrics);

  harState.resultFilter = "all";
  harState.sortCol = null;
  harState.sortDir = "asc";
  document.querySelectorAll(".har-rf-btn").forEach(b => b.classList.toggle("active", b.dataset.f === "all"));
  harRenderResultsTable(results);

  if (harState.activeResultsView === "diff") {
    harRenderDiffView();
  }
}

function harRenderResultsTable(results) {
  const tbody  = $h("results-tbody");
  const filter = harState.resultFilter;
  const q = (harState.resultUrlQuery || "").trim().toLowerCase();

  const metrics = harComputeSizeDiff(results || []);
  const countBadge = $h("sizediff-count");
  if (countBadge) {
    countBadge.textContent = metrics.diffKeys.size;
    countBadge.style.display = metrics.diffKeys.size > 0 ? "inline-block" : "none";
  }
  const sameBadge = $h("sizesame-count");
  if (sameBadge) {
    sameBadge.textContent = metrics.sameKeys.size;
    sameBadge.style.display = metrics.sameKeys.size > 0 ? "inline-block" : "none";
  }

  const prepared = (results || []).map((r, idx) => {
    const isDiff = metrics.diffIndices.has(idx);
    const isSame = metrics.sameIndices.has(idx);
    return {
      ...r,
      _origIdx: idx,
      _size: harGetResultSize(r),
      _isSizeDiff: isDiff,
      _isSizeSame: isSame
    };
  });

  const filtered = prepared.filter(r => {
    const sc = String(r.status_code);
    let ok = true;
    if (filter === "2xx")               ok = sc.startsWith("2");
    else if (filter === "4xx")          ok = sc.startsWith("4");
    else if (filter === "5xx")          ok = sc.startsWith("5");
    else if (filter === "error")        ok = !sc.match(/^\d/);
    else if (filter === "size_diff")    ok = !!r._isSizeDiff;
    else if (filter === "size_same")    ok = !!r._isSizeSame;
    if (!ok) return false;

    // Filter by User
    if (harState.resultUserFilter && harState.resultUserFilter !== "all") {
      if ((r.user_id || "user_1") !== harState.resultUserFilter) return false;
    }

    // Filter by Compare Mode
    const compFilter = harState.resultCompareFilter || "all";
    const epKey = `${(r.method || "GET").toUpperCase()} ${(r.url || "").trim()}`;
    if (compFilter === "any_diff") {
      if (!metrics.diffKeys.has(epKey)) return false;
    } else if (compFilter === "all_same") {
      if (!metrics.sameKeys.has(epKey)) return false;
    } else if (compFilter.startsWith("diff__")) {
      const pKey = compFilter.replace("diff__", "");
      if (!metrics.pairDiffMap[pKey]?.endpoints.has(epKey)) return false;
    } else if (compFilter.startsWith("same__")) {
      const pKey = compFilter.replace("same__", "");
      if (!metrics.pairSameMap[pKey]?.endpoints.has(epKey)) return false;
    }

    // Search query
    if (!q) return true;
    const url = String(r.url || "").toLowerCase();
    let path = url;
    try { path = new URL(r.url).pathname.toLowerCase(); } catch (e) {}
    return url.includes(q) || path.includes(q);
  });

  // Sorting
  if (harState.sortCol === "time") {
    filtered.sort((a, b) => {
      const aVal = a.elapsed_ms || 0;
      const bVal = b.elapsed_ms || 0;
      return harState.sortDir === "asc" ? aVal - bVal : bVal - aVal;
    });
  } else if (harState.sortCol === "size") {
    filtered.sort((a, b) => {
      const aVal = a._size || 0;
      const bVal = b._size || 0;
      return harState.sortDir === "asc" ? aVal - bVal : bVal - aVal;
    });
  }

  // Update header sort indicator
  const thTime = $h("th-time");
  const iconTime = $h("sort-time-icon");
  const thSize = $h("th-size");
  const iconSize = $h("sort-size-icon");
  if (thTime && iconTime) {
    thTime.classList.toggle("sorted-asc", harState.sortCol === "time" && harState.sortDir === "asc");
    thTime.classList.toggle("sorted-desc", harState.sortCol === "time" && harState.sortDir === "desc");
    iconTime.textContent = harState.sortCol === "time" ? (harState.sortDir === "asc" ? "▲" : "▼") : "⬍";
  }
  if (thSize && iconSize) {
    thSize.classList.toggle("sorted-asc", harState.sortCol === "size" && harState.sortDir === "asc");
    thSize.classList.toggle("sorted-desc", harState.sortCol === "size" && harState.sortDir === "desc");
    iconSize.textContent = harState.sortCol === "size" ? (harState.sortDir === "asc" ? "▲" : "▼") : "⬍";
  }

  tbody.innerHTML = "";
  filtered.forEach((r, idx) => {
    const sc      = String(r.status_code);
    const scClass = sc.startsWith("2") ? "sc-2xx" : sc.startsWith("4") ? "sc-4xx" : sc.startsWith("5") ? "sc-5xx" : "sc-err";
    const mc      = harGetMethodClass(r.method);
    const detId   = `har-dr-${idx}`;
    let path = r.url;
    let urlDisplay = harEsc(r.url || "");
    try {
      const u = new URL(r.url);
      path = u.pathname + (u.search || "");
      urlDisplay = `<span style="color:var(--text3)">${harEsc(u.protocol)}//${harEsc(u.host)}</span><span style="color:var(--blue)">${harEsc(u.pathname)}</span>${u.search ? `<span style="color:#79c0ff;font-weight:600">${harEsc(u.search)}</span>` : ""}`;
    } catch(e) {}
    const reqPretty = harPrettyBody(r.request_body);
    const respPretty = harPrettyBody(r.response == null || r.response === "" ? "(no response)" : r.response);
    const reqPreId = `har-req-pre-${idx}`;
    const respPreId = `har-resp-pre-${idx}`;

    const sizeStr = harFormatSize(r._size);
    let sizeBadge = "";
    if (r._isSizeDiff) {
      sizeBadge += `<span style="font-size:9px;padding:1px 4px;border-radius:4px;background:rgba(163,113,247,0.2);color:#d2a8ff;font-weight:600;margin-left:3px" title="Response sizes differ across tested users for this API">DIFF</span>`;
    }
    if (r._isSizeSame) {
      sizeBadge += `<span style="font-size:9px;padding:1px 4px;border-radius:4px;background:rgba(56,189,248,0.2);color:#7dd3fc;font-weight:600;margin-left:3px" title="Response sizes are identical across users (2xx OK) — Potential BOLA/IDOR">SAME</span>`;
    }

    const uIdx = metrics.users.findIndex(u => u.id === (r.user_id || "user_1"));
    const uColor = harGetUserColor(uIdx >= 0 ? uIdx : 0);
    const uName = r.user_name || r.user_id || `User ${(uIdx >= 0 ? uIdx + 1 : 1)}`;

    const isRowUnauth = !!(r.is_unauth || r.mode === "unauthorized");
    const isRowBypass = isRowUnauth && !isNaN(parseInt(sc, 10)) && parseInt(sc, 10) >= 200 && parseInt(sc, 10) < 300;
    const isRowBlocked = isRowUnauth && !isNaN(parseInt(sc, 10)) && parseInt(sc, 10) >= 400;

    let bypassBadge = "";
    if (isRowBypass) {
      bypassBadge = `<span class="har-signal-bypass" style="margin-left:4px" title="CRITICAL: Unauthorized role received 2xx OK! Expected 403 Forbidden.">🚨 AUTH BYPASS</span>`;
    } else if (isRowBlocked) {
      bypassBadge = `<span class="har-signal-blocked" style="margin-left:4px" title="Access Control Enforced (${sc})">🛡️ Blocked</span>`;
    }

    const rowExtraClass = (r._isSizeDiff ? " is-diff-row" : (r._isSizeSame ? " is-same-row" : "")) + (isRowBypass ? " is-diff-row" : "");
    const tr = document.createElement("tr");
    tr.className = "data-row" + rowExtraClass;
    tr._origIdx = r._origIdx;
    tr.setAttribute("data-orig-idx", r._origIdx);
    tr.innerHTML = `
      <td style="color:var(--text3)">${idx+1}</td>
      <td><span class="sc-badge ${scClass}">${harEsc(sc)}</span></td>
      <td><span class="method-badge method-${mc}">${harEsc(r.method)}</span></td>
      <td style="white-space:nowrap"><div style="display:inline-flex;align-items:center;gap:6px"><span class="har-user-badge" style="background:${uColor.bg};color:${uColor.text};border:1px solid ${uColor.border}" title="${harEsc(uName)}">👤 ${harEsc(uName)}</span>${bypassBadge}</div></td>
      <td class="res-url" title="${harEsc(r.url)}">${urlDisplay}</td>
      <td style="color:var(--text3);font-size:10px;font-family:var(--mono)">${r.elapsed_ms}ms</td>
      <td style="color:var(--text2);font-size:10px;font-family:var(--mono);white-space:nowrap">${sizeStr}${sizeBadge}</td>
    `;

    // Multi-User Comparison Matrix for detail row
    const epKey = `${(r.method || "GET").toUpperCase()} ${(r.url || "").trim()}`;
    const epGroup = metrics.endpointMap.get(epKey);
    let matrixHtml = "";
    if (epGroup && epGroup.rows.length > 1) {
      const baselineRow = epGroup.rows[0];
      const baseSize = baselineRow.size;

      const matrixRows = epGroup.rows.map((rowItem, rIdx) => {
        const itemUIdx = metrics.users.findIndex(u => u.id === rowItem.userId);
        const col = harGetUserColor(itemUIdx >= 0 ? itemUIdx : rIdx);
        const itemSc = String(rowItem.sc);
        const scCls = itemSc.startsWith("2") ? "sc-2xx" : itemSc.startsWith("4") ? "sc-4xx" : itemSc.startsWith("5") ? "sc-5xx" : "sc-err";
        const isItemUnauth = !!(rowItem.r?.is_unauth || rowItem.r?.mode === "unauthorized");
        const isItemBypass = isItemUnauth && rowItem.is2xx;
        const isItemBlocked = isItemUnauth && !rowItem.is2xx;

        let deltaStr = "—";
        let signalTag = "";
        if (rIdx === 0) {
          deltaStr = '<span style="color:var(--text3)">Baseline</span>';
          signalTag = isItemBypass
            ? `<span class="har-signal-bypass">🚨 AUTH BYPASS (Expected 403, got ${itemSc})</span>`
            : (isItemBlocked ? `<span class="har-signal-blocked">🛡️ Protected (${itemSc})</span>` : '<span style="color:var(--text3);font-size:10px">Primary Reference</span>');
        } else {
          if (isItemBypass) {
            signalTag = `<span class="har-signal-bypass">🚨 AUTH BYPASS (Expected 403, got ${itemSc})</span>`;
          } else if (isItemBlocked) {
            signalTag = `<span class="har-signal-blocked">🛡️ Protected (${itemSc})</span>`;
          } else {
            const delta = rowItem.size - baseSize;
            if (delta === 0) {
              deltaStr = '<span style="color:#7dd3fc;font-weight:600">±0 B (0%)</span>';
              if (rowItem.is2xx && baselineRow.is2xx) {
                signalTag = '<span class="har-signal-idor">⚠️ SAME SIZE (Potential IDOR)</span>';
              } else {
                signalTag = '<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,0.06);color:var(--text2)">Identical Size</span>';
              }
            } else {
              const sign = delta > 0 ? "+" : "";
              const pct = baseSize > 0 ? ` (${sign}${((delta / baseSize) * 100).toFixed(1)}%)` : "";
              deltaStr = `<span style="color:#d2a8ff;font-weight:600">${sign}${harFormatSize(delta)}${pct}</span>`;
              if (rowItem.is2xx && baselineRow.is2xx) {
                signalTag = '<span class="har-signal-diff">✓ SIZE DIFF (Different Data)</span>';
              } else if (!rowItem.is2xx) {
                signalTag = `<span class="har-signal-blocked">🛡️ Blocked (${itemSc})</span>`;
              } else {
                signalTag = '<span class="har-signal-diff">Size Diff</span>';
              }
            }
          }
        }

        const isCurrentRow = rowItem.idx === r._origIdx;
        const rowClass = isCurrentRow ? "is-curr-req" : "";

        return `
          <tr class="${rowClass}" data-orig-idx="${rowItem.idx}" style="cursor:pointer" title="Click to view ${harEsc(rowItem.userName)} request & response">
            <td style="white-space:nowrap">
              <div style="display:inline-flex;align-items:center;gap:6px">
                <span class="har-user-badge" style="background:${col.bg};color:${col.text};border:1px solid ${col.border}">
                  👤 ${harEsc(rowItem.userName)}
                </span>
                <span class="har-curr-indicator-slot">${isCurrentRow ? '<span class="har-curr-indicator">● Current</span>' : ''}</span>
                <button type="button" class="har-matrix-jump-btn" data-jump-idx="${rowItem.idx}" title="Jump to row #${rowItem.idx + 1} in table">↗ #${rowItem.idx + 1}</button>
              </div>
            </td>
            <td><span class="sc-badge ${scCls}">${harEsc(itemSc)}</span></td>
            <td style="font-family:var(--mono);font-weight:600;white-space:nowrap">${harFormatSize(rowItem.size)} <span style="font-size:9px;color:var(--text3)">(${rowItem.size} B)</span></td>
            <td style="font-family:var(--mono);white-space:nowrap">${deltaStr}</td>
            <td style="color:var(--text3);font-family:var(--mono);white-space:nowrap">${rowItem.r.elapsed_ms}ms</td>
            <td style="white-space:nowrap">${signalTag}</td>
          </tr>
        `;
      }).join("");

      matrixHtml = `
        <div class="har-matrix-panel">
          <div class="har-matrix-header-title">
            <span style="font-size:11px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:6px">
              ⚖️ Multi-User Response Size Matrix (${epGroup.rows.length} Users Tested)
            </span>
            <span style="font-size:10px;color:var(--text3);font-family:var(--mono)">${harEsc(r.method)} ${harEsc(path)}</span>
          </div>
          <div class="har-matrix-table-wrap">
            <table class="har-matrix-table">
              <thead>
                <tr>
                  <th style="width:22%;min-width:180px">User</th>
                  <th style="width:10%;min-width:75px">Status</th>
                  <th style="width:18%;min-width:140px">Response Size</th>
                  <th style="width:18%;min-width:155px" title="Baseline: ${harEsc(baselineRow.userName)}">Delta vs Base</th>
                  <th style="width:12%;min-width:85px">Latency</th>
                  <th style="width:20%;min-width:165px">Comparison / Signal</th>
                </tr>
              </thead>
              <tbody>
                ${matrixRows}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    let currentActiveR = r;

    const detTr = document.createElement("tr");
    detTr.id = detId;
    detTr.className = "detail-row";
    detTr.style.display = "none";
    detTr.innerHTML = `
      <td colspan="7" class="detail-cell">
        ${matrixHtml}
        <div class="detail-grid">
          <div class="detail-panel har-det-req-panel">
            <div class="detail-panel-title">
              <span>📤 Request Body</span>
              <span class="har-req-size-hint">${harBodySizeHint(reqPretty)}</span>
              <button type="button" class="btn-sm har-copy-body-btn" title="Copy request body">Copy</button>
              <button type="button" class="btn-sm av-detail-expand-btn" title="Show the full body">↕ Full</button>
              <button type="button" class="btn-sm as-rd-curl-btn har-copy-curl-btn" title="Copy this request as cURL">Copy cURL</button>
              <input type="text" class="detail-search-input" placeholder="🔍 Search..." data-pre="${reqPreId}">
            </div>
            <div class="detail-pre-scroll"><pre class="detail-pre" id="${reqPreId}"></pre></div>
          </div>
          <div class="detail-panel har-det-resp-panel">
            <div class="detail-panel-title">
              <span class="har-resp-title-text">📥 Response Body (${sizeStr})</span>
              <span class="har-resp-size-hint">${harBodySizeHint(respPretty)}</span>
              <button type="button" class="btn-sm har-copy-body-btn" title="Copy response body">Copy</button>
              <button type="button" class="btn-sm av-detail-expand-btn" title="Show the full body">↕ Full</button>
              <button type="button" class="btn-sm as-rd-curl-btn har-copy-curl-btn" title="Copy this request as cURL">Copy cURL</button>
              <input type="text" class="detail-search-input" placeholder="🔍 Search..." data-pre="${respPreId}">
            </div>
            <div class="detail-pre-scroll"><pre class="detail-pre" id="${respPreId}"></pre></div>
          </div>
        </div>
      </td>
    `;

    const toggleDetail = () => {
      const open = detTr.style.display !== "none";
      detTr.style.display = open ? "none" : "table-row";
      tr.classList.toggle("is-expanded", !open);
    };
    tr.addEventListener("click", toggleDetail);

    tbody.appendChild(tr);
    tbody.appendChild(detTr);

    harFillDetailPre(document.getElementById(reqPreId), reqPretty);
    harFillDetailPre(document.getElementById(respPreId), respPretty);

    detTr.querySelectorAll(".har-copy-curl-btn").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        harCopyText(harBuildResultCurl(currentActiveR), e.currentTarget);
      });
    });
    detTr.querySelectorAll(".har-copy-body-btn").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        const preEl = btn.closest(".detail-panel")?.querySelector(".detail-pre");
        harCopyText(harDetailRaw(preEl), e.currentTarget);
      });
    });
    detTr.querySelectorAll(".av-detail-expand-btn").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        const panel = btn.closest(".detail-panel");
        const open = panel.classList.toggle("is-expanded");
        btn.textContent = open ? "Collapse" : "↕ Full";
      });
    });
    detTr.querySelectorAll(".detail-search-input").forEach(inp => {
      inp.addEventListener("click", e => e.stopPropagation());
      inp.addEventListener("input", () => harDetailSearch(inp.dataset.pre, inp.value));
    });

    if (epGroup && epGroup.rows.length > 1) {
      detTr.querySelectorAll(".har-matrix-table tbody tr").forEach(mTr => {
        mTr.addEventListener("click", e => {
          if (e.target.closest(".har-matrix-jump-btn")) return;
          const origIdx = parseInt(mTr.getAttribute("data-orig-idx"), 10);
          if (isNaN(origIdx)) return;
          const targetItem = epGroup.rows.find(x => x.idx === origIdx);
          if (!targetItem) return;

          currentActiveR = targetItem.r;

          // Update active highlights
          detTr.querySelectorAll(".har-matrix-table tbody tr").forEach(row => {
            row.classList.remove("is-curr-req");
            const slot = row.querySelector(".har-curr-indicator-slot");
            if (slot) slot.innerHTML = "";
          });
          mTr.classList.add("is-curr-req");
          const mySlot = mTr.querySelector(".har-curr-indicator-slot");
          if (mySlot) mySlot.innerHTML = '<span class="har-curr-indicator">● Current</span>';

          // Update body previews
          const newReqPretty = harPrettyBody(currentActiveR.request_body);
          const newRespPretty = harPrettyBody(currentActiveR.response == null || currentActiveR.response === "" ? "(no response)" : currentActiveR.response);
          const newSize = harGetResultSize(currentActiveR);
          const newSizeStr = harFormatSize(newSize);

          const reqPre = document.getElementById(reqPreId);
          const respPre = document.getElementById(respPreId);
          if (reqPre) harFillDetailPre(reqPre, newReqPretty);
          if (respPre) harFillDetailPre(respPre, newRespPretty);

          const reqHint = detTr.querySelector(".har-req-size-hint");
          if (reqHint) reqHint.innerHTML = harBodySizeHint(newReqPretty);
          const respHint = detTr.querySelector(".har-resp-size-hint");
          if (respHint) respHint.innerHTML = harBodySizeHint(newRespPretty);
          const respTitle = detTr.querySelector(".har-resp-title-text");
          if (respTitle) respTitle.textContent = `📥 Response Body (${newSizeStr})`;

          detTr.querySelectorAll(".detail-panel").forEach(p => {
            p.classList.remove("har-detail-updated");
            void p.offsetWidth;
            p.classList.add("har-detail-updated");
          });

          // Reapply search highlight if filter was typed
          detTr.querySelectorAll(".detail-search-input").forEach(inp => {
            if (inp.value) harDetailSearch(inp.dataset.pre, inp.value);
          });
        });
      });

      detTr.querySelectorAll(".har-matrix-jump-btn").forEach(btn => {
        btn.addEventListener("click", e => {
          e.stopPropagation();
          const jumpIdx = parseInt(btn.getAttribute("data-jump-idx"), 10);
          if (isNaN(jumpIdx)) return;
          const targetMainTr = Array.from(tbody.querySelectorAll("tr.data-row")).find(el => el._origIdx === jumpIdx);
          if (targetMainTr) {
            if (detTr.style.display !== "none") {
              toggleDetail();
            }
            targetMainTr.click();
            targetMainTr.scrollIntoView({ behavior: "smooth", block: "center" });
          }
        });
      });
    }
  });

  if (!filtered.length)
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:20px">No results match filter / search</td></tr>`;
}

// ── Export ────────────────────────────────────────────────────────────────────
async function harPyDownload(backendPath, payload, filename) {
  try {
    const resp = await fetch(`${HAR_BACKEND}${backendPath}`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    // pywebview: JSApi now properly initialized at window creation — always available
    if (window.pywebview && window.pywebview.api) {
      const result = await window.pywebview.api.save_file(text, filename);
      if (result && result.ok) {
        if (window.showExportToast) window.showExportToast(result.filename || filename);
      } else if (result && result.reason && result.reason !== "cancelled") {
        alert("Save failed: " + result.reason);
      }
      return;
    }
    // Plain browser fallback
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
  } catch(e) { alert("Export failed: " + e.message); }
}

async function harExportCsv() {
  if (!harState.testResults) return;
  await harPyDownload("/export/csv", harState.testResults, "har_runner_report.csv");
}

async function harExportHtml() {
  if (!harState.testResults) return;
  await harPyDownload("/export/html", harState.testResults, "har_runner_report.html");
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function harGetMethodClass(m) { return ["GET","POST","PUT","PATCH","DELETE"].includes(m) ? m : "OTHER"; }
function harGetStatusClass(s) {
  const c = parseInt(s);
  if (isNaN(c)) return "status-err";
  if (c < 300) return "status-2xx";
  if (c < 400) return "status-3xx";
  if (c < 500) return "status-4xx";
  return "status-5xx";
}
function harEsc(s) {
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function harPrettyBody(text) {
  if (typeof avPrettyBody === "function") return avPrettyBody(text);
  if (text == null || text === "") return "(no body)";
  const s = String(text);
  const t = s.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return s;
  try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) { return s; }
}

function harBodySizeHint(text) {
  if (typeof avBodySizeHint === "function") return avBodySizeHint(text);
  const n = String(text || "").length;
  if (n < 4096) return "";
  return `<span class="av-body-size">${Math.max(1, Math.round(n / 1024))} KB</span>`;
}

const _harDetailStore = new WeakMap();

function harFillDetailPre(pre, text) {
  if (!pre) return;
  if (typeof avFillDetailPre === "function") {
    avFillDetailPre(pre, text, "", []);
    return;
  }
  const raw = text == null ? "" : String(text);
  _harDetailStore.set(pre, raw);
  pre.textContent = raw;
}

function harDetailRaw(pre) {
  if (!pre) return "";
  if (typeof avDetailGetRaw === "function") return avDetailGetRaw(pre);
  if (_harDetailStore.has(pre)) return _harDetailStore.get(pre);
  return pre.textContent || "";
}

function harDetailSearch(preId, query) {
  if (typeof detailSearch === "function") {
    detailSearch(preId, query);
    return;
  }
  const pre = document.getElementById(preId);
  if (!pre) return;
  const raw = harDetailRaw(pre);
  const q = (query || "").trim();
  if (!q) { pre.textContent = raw; return; }
  const escQ = harEsc(q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  pre.innerHTML = harEsc(raw).replace(new RegExp(escQ, "gi"), m => `<mark class="detail-search-mark">${m}</mark>`);
}

function harCopyText(text, btn) {
  if (typeof avCopyText === "function") { avCopyText(text, btn); return; }
  if (!text) return;
  const orig = btn ? btn.textContent : "";
  const done = () => {
    if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => { btn.textContent = orig; }, 1400); }
  };
  try { navigator.clipboard.writeText(text).then(done); } catch (_) { done(); }
}

function harCurlArg(s) {
  if (typeof avCurlArg === "function") return avCurlArg(s);
  return "'" + String(s ?? "").replace(/'/g, `'\\''`) + "'";
}

function harBuildResultCurl(r) {
  const method = String(r.method || "GET").toUpperCase();
  const url = r.url || "";
  const headers = r.headers || {};
  const skipName = /^(content-length|host|connection|transfer-encoding|accept-encoding|content-encoding|keep-alive|proxy-connection|te|trailer|upgrade)$/i;
  const skipPrefix = /^(sec-ch-|sec-fetch-|sec-gpc)/i;
  const lines = [`curl --http1.1 -X ${method} ${harCurlArg(url)}`];
  const seen = new Set();
  Object.entries(headers).forEach(([k, v]) => {
    if (!k || String(k).startsWith(":") || skipName.test(k) || skipPrefix.test(k)) return;
    const lk = k.toLowerCase();
    if (seen.has(lk)) return;
    seen.add(lk);
    lines.push(`  -H ${harCurlArg(k + ": " + v)}`);
  });
  let bodyStr = r.request_body || "";
  if (typeof avCurlPayload === "function") bodyStr = avCurlPayload(r.request_body);
  if (bodyStr && bodyStr !== "(no body)") {
    if (!seen.has("content-type") && /^\s*[\[{]/.test(bodyStr)) {
      lines.push(`  -H ${harCurlArg("Content-Type: application/json")}`);
    }
    lines.push(`  --data-raw ${harCurlArg(bodyStr)}`);
  }
  return lines.join(" \\\n");
}

// ── Compare APIs & Responses (Split View) ─────────────────────────────────────
function harSetupDiffView() {
  const btnTable = $h("view-btn-table");
  const btnDiff = $h("view-btn-diff");
  const wrapTable = $h("results-table-wrap");
  const wrapDiff = $h("compare-diff-wrap");
  const filtersBar = $h("results-filters");

  if (btnTable && btnDiff) {
    btnTable.addEventListener("click", () => {
      harState.activeResultsView = "table";
      btnTable.classList.add("active");
      btnDiff.classList.remove("active");
      if (wrapTable) wrapTable.style.display = "";
      if (filtersBar) filtersBar.style.display = "";
      if (wrapDiff) wrapDiff.style.display = "none";
    });

    btnDiff.addEventListener("click", () => {
      harState.activeResultsView = "diff";
      btnDiff.classList.add("active");
      btnTable.classList.remove("active");
      if (wrapTable) wrapTable.style.display = "none";
      if (filtersBar) filtersBar.style.display = "none";
      if (wrapDiff) wrapDiff.style.display = "flex";
      harRenderDiffView();
    });
  }

  // Sidebar search
  const diffSearch = $h("diff-api-search");
  if (diffSearch) {
    diffSearch.addEventListener("input", () => {
      harState.diffQuery = (diffSearch.value || "").trim().toLowerCase();
      harRenderDiffSidebar();
    });
  }

  // Sidebar filter pills (all, diff, same)
  document.querySelectorAll(".har-diff-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      harState.diffFilterPill = pill.dataset.f;
      document.querySelectorAll(".har-diff-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      harRenderDiffSidebar();
    });
  });

  // User A and User B change events
  const selA = $h("diff-select-user-a");
  const selB = $h("diff-select-user-b");
  if (selA) {
    selA.addEventListener("change", () => harUpdateDiffPanels());
  }
  if (selB) {
    selB.addEventListener("change", () => harUpdateDiffPanels());
  }

  // Swap button
  const swapBtn = $h("diff-swap-btn");
  if (swapBtn && selA && selB) {
    swapBtn.addEventListener("click", () => {
      const valA = selA.value;
      const valB = selB.value;
      selA.value = valB;
      selB.value = valA;
      harUpdateDiffPanels();
    });
  }

  // Copy buttons
  const copyUrlBtn = $h("diff-copy-url");
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener("click", () => {
      const urlText = $h("diff-url-text")?.textContent || "";
      harCopyText(urlText, copyUrlBtn);
    });
  }

  const copyA = $h("diff-copy-a");
  if (copyA) {
    copyA.addEventListener("click", () => {
      const text = $h("diff-pre-a")?.textContent || "";
      harCopyText(text, copyA);
    });
  }
  const copyB = $h("diff-copy-b");
  if (copyB) {
    copyB.addEventListener("click", () => {
      const text = $h("diff-pre-b")?.textContent || "";
      harCopyText(text, copyB);
    });
  }

  // Pre search filtering
  const searchA = $h("diff-search-a");
  if (searchA) {
    searchA.addEventListener("input", () => {
      harDetailSearch("har-diff-pre-a", searchA.value);
    });
  }
  const searchB = $h("diff-search-b");
  if (searchB) {
    searchB.addEventListener("input", () => {
      harDetailSearch("har-diff-pre-b", searchB.value);
    });
  }
}

function harRenderDiffView() {
  if (!harState.testResults) return;
  harRenderDiffSidebar();
  if (harState.diffActiveEndpoint) {
    harRenderDiffContent(harState.diffActiveEndpoint);
  } else {
    const results = harState.testResults.results || [];
    const metrics = harComputeSizeDiff(results);
    const endpoints = Array.from(metrics.endpointMap.keys());
    if (endpoints.length > 0) {
      const firstDiff = endpoints.find(k => metrics.diffKeys.has(k) || metrics.sameKeys.has(k));
      const target = firstDiff || endpoints[0];
      harState.diffActiveEndpoint = target;
      harRenderDiffContent(target);
    } else {
      const placeholder = $h("diff-placeholder");
      const content = $h("diff-content");
      if (placeholder) placeholder.style.display = "flex";
      if (content) content.style.display = "none";
    }
  }
}

function harRenderDiffSidebar() {
  const container = $h("diff-api-list");
  if (!container || !harState.testResults) return;

  const results = harState.testResults.results || [];
  const metrics = harComputeSizeDiff(results);
  const q = (harState.diffQuery || "").toLowerCase();
  const filterPill = harState.diffFilterPill || "all";

  const entries = Array.from(metrics.endpointMap.entries());
  if (entries.length === 0) {
    container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3);font-size:11px">No API endpoints captured.</div>';
    return;
  }

  let html = "";
  let renderedCount = 0;

  for (const [epKey, group] of entries) {
    const isDiff = metrics.diffKeys.has(epKey);
    const isSame = metrics.sameKeys.has(epKey);

    if (filterPill === "diff" && !isDiff) continue;
    if (filterPill === "same" && !isSame) continue;

    if (q && !epKey.toLowerCase().includes(q) && !group.url.toLowerCase().includes(q)) {
      continue;
    }

    renderedCount++;
    const isSelected = harState.diffActiveEndpoint === epKey;
    const hasBypass = group.rows.some(r => (r.r?.is_unauth || r.r?.mode === "unauthorized") && r.is2xx);
    let tagHtml = "";
    if (hasBypass) {
      tagHtml = '<span class="har-diff-tag same" style="background:rgba(248,81,73,0.25);color:#f85149;border:1px solid rgba(248,81,73,0.5)">🚨 Bypass</span>';
    } else if (isSame) {
      tagHtml = '<span class="har-diff-tag same">⚠️ IDOR Risk</span>';
    } else if (isDiff) {
      tagHtml = '<span class="har-diff-tag diff">⚖️ Diff</span>';
    } else {
      tagHtml = '<span class="har-diff-tag neutral">● Normal</span>';
    }

    const sizes = group.rows.map(r => r.size);
    const minSize = Math.min(...sizes);
    const maxSize = Math.max(...sizes);
    const sizeRange = minSize === maxSize ? harFormatSize(minSize) : `${harFormatSize(minSize)} ~ ${harFormatSize(maxSize)}`;

    html += `
      <div class="har-diff-api-item ${isSelected ? 'active' : ''}" data-ep="${harEsc(epKey)}">
        <div class="har-diff-api-item-top">
          <span class="method-badge method-${group.method.toLowerCase()}">${harEsc(group.method)}</span>
          <span class="har-diff-api-item-url" title="${harEsc(group.url)}">${harEsc(group.path)}</span>
          ${tagHtml}
        </div>
        <div class="har-diff-api-item-meta">
          <span>👥 ${group.rows.length} Users</span>
          <span>${sizeRange}</span>
        </div>
      </div>
    `;
  }

  if (renderedCount === 0) {
    container.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3);font-size:11px">No matching APIs found.</div>';
    return;
  }

  container.innerHTML = html;

  container.querySelectorAll(".har-diff-api-item").forEach(item => {
    item.addEventListener("click", () => {
      const epKey = item.dataset.ep;
      harState.diffActiveEndpoint = epKey;
      container.querySelectorAll(".har-diff-api-item").forEach(i => i.classList.remove("active"));
      item.classList.add("active");
      harRenderDiffContent(epKey);
    });
  });
}

function harRenderDiffContent(epKey) {
  const placeholder = $h("diff-placeholder");
  const content = $h("diff-content");
  if (!placeholder || !content) return;

  if (!epKey || !harState.testResults) {
    placeholder.style.display = "flex";
    content.style.display = "none";
    return;
  }

  const results = harState.testResults.results || [];
  const metrics = harComputeSizeDiff(results);
  const epGroup = metrics.endpointMap.get(epKey);

  if (!epGroup || epGroup.rows.length === 0) {
    placeholder.style.display = "flex";
    content.style.display = "none";
    return;
  }

  placeholder.style.display = "none";
  content.style.display = "flex";

  // Header info
  const mBadge = $h("diff-method-badge");
  if (mBadge) {
    mBadge.textContent = epGroup.method;
    mBadge.className = `method-badge method-${epGroup.method.toLowerCase()}`;
  }
  const urlText = $h("diff-url-text");
  if (urlText) {
    urlText.textContent = epGroup.url;
    urlText.title = epGroup.url;
  }

  // Populate User A & User B dropdowns
  const selA = $h("diff-select-user-a");
  const selB = $h("diff-select-user-b");

  const prevA = selA ? selA.value : "0";
  const prevB = selB ? selB.value : (epGroup.rows.length > 1 ? "1" : "0");

  let optionsA = "";
  let optionsB = "";
  epGroup.rows.forEach((rowItem, idx) => {
    const scStr = String(rowItem.sc);
    const sizeStr = harFormatSize(rowItem.size);
    optionsA += `<option value="${idx}">👤 ${harEsc(rowItem.userName)} (${scStr}, ${sizeStr})</option>`;
    optionsB += `<option value="${idx}">👤 ${harEsc(rowItem.userName)} (${scStr}, ${sizeStr})</option>`;
  });

  if (selA) selA.innerHTML = optionsA;
  if (selB) selB.innerHTML = optionsB;

  // Restore or set sensible defaults
  const idxA = (parseInt(prevA, 10) < epGroup.rows.length) ? prevA : "0";
  let idxB = (parseInt(prevB, 10) < epGroup.rows.length) ? prevB : (epGroup.rows.length > 1 ? "1" : "0");
  if (idxA === idxB && epGroup.rows.length > 1) {
    idxB = (parseInt(idxA, 10) === 0) ? "1" : "0";
  }

  if (selA) selA.value = idxA;
  if (selB) selB.value = idxB;

  harUpdateDiffPanels();
}

function harUpdateDiffPanels() {
  const epKey = harState.diffActiveEndpoint;
  if (!epKey || !harState.testResults) return;

  const results = harState.testResults.results || [];
  const metrics = harComputeSizeDiff(results);
  const epGroup = metrics.endpointMap.get(epKey);
  if (!epGroup) return;

  const selA = $h("diff-select-user-a");
  const selB = $h("diff-select-user-b");
  const idxA = parseInt(selA ? selA.value : "0", 10) || 0;
  const idxB = parseInt(selB ? selB.value : "0", 10) || 0;

  const itemA = epGroup.rows[idxA] || epGroup.rows[0];
  const itemB = epGroup.rows[idxB] || epGroup.rows[epGroup.rows.length - 1];

  if (!itemA || !itemB) return;

  const uIdxA = metrics.users.findIndex(u => u.id === itemA.userId);
  const colA  = harGetUserColor(uIdxA >= 0 ? uIdxA : idxA);
  const uIdxB = metrics.users.findIndex(u => u.id === itemB.userId);
  const colB  = harGetUserColor(uIdxB >= 0 ? uIdxB : idxB);

  // Panel titles & metadata
  const titleA = $h("diff-panel-title-a");
  if (titleA) {
    titleA.innerHTML = `<span class="har-user-badge" style="background:${colA.bg};color:${colA.text};border:1px solid ${colA.border}">👤 ${harEsc(itemA.userName)}</span>`;
  }
  const metaA = $h("diff-panel-meta-a");
  if (metaA) {
    metaA.innerHTML = `Status: <b style="color:${itemA.is2xx ? 'var(--green)' : 'var(--red)'}">${itemA.sc}</b> · Size: <b>${harFormatSize(itemA.size)}</b> (${itemA.size} B) · Latency: <b>${itemA.r.elapsed_ms}ms</b>`;
  }

  const titleB = $h("diff-panel-title-b");
  if (titleB) {
    titleB.innerHTML = `<span class="har-user-badge" style="background:${colB.bg};color:${colB.text};border:1px solid ${colB.border}">👤 ${harEsc(itemB.userName)}</span>`;
  }
  const metaB = $h("diff-panel-meta-b");
  if (metaB) {
    metaB.innerHTML = `Status: <b style="color:${itemB.is2xx ? 'var(--green)' : 'var(--red)'}">${itemB.sc}</b> · Size: <b>${harFormatSize(itemB.size)}</b> (${itemB.size} B) · Latency: <b>${itemB.r.elapsed_ms}ms</b>`;
  }

  // Verdict Banner
  const banner = $h("diff-verdict-banner");
  if (banner) {
    const delta = itemB.size - itemA.size;
    const isBoth2xx = itemA.is2xx && itemB.is2xx;
    const isOneBlocked = (!itemA.is2xx && itemB.is2xx) || (itemA.is2xx && !itemB.is2xx);

    banner.className = "har-diff-verdict-banner";

    const isUnauthA = !!(itemA.r?.is_unauth || itemA.r?.mode === "unauthorized");
    const isUnauthB = !!(itemB.r?.is_unauth || itemB.r?.mode === "unauthorized");
    const isBypassA = isUnauthA && itemA.is2xx;
    const isBypassB = isUnauthB && itemB.is2xx;

    if (itemA.userId === itemB.userId) {
      banner.classList.add("har-verdict-match");
      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:16px">ℹ️</span>
          <span>Same user selected for both sides. Select 2 different users to compare responses.</span>
        </div>
      `;
    } else if (isBypassA || isBypassB) {
      banner.classList.add("har-verdict-idor");
      const bypassUser = isBypassA ? itemA : itemB;
      const otherUser = isBypassA ? itemB : itemA;
      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:18px">🚨</span>
          <div>
            <div><b>CRITICAL AUTH BYPASS:</b> ${harEsc(bypassUser.userName)} was marked Unauthorized (Expected 403), but received <b>HTTP ${bypassUser.sc} OK</b>!</div>
            <div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Endpoint returned full payload (${harFormatSize(bypassUser.size)}) without proper authorization enforcement. Baseline ${harEsc(otherUser.userName)} got ${otherUser.sc} (${harFormatSize(otherUser.size)}).</div>
          </div>
        </div>
        <span class="har-diff-tag same" style="font-size:11px;padding:3px 8px;background:rgba(248,81,73,0.25);color:#f85149;border:1px solid rgba(248,81,73,0.5)">🚨 AUTH BYPASS</span>
      `;
    } else if (isBoth2xx && delta === 0) {
      banner.classList.add("har-verdict-idor");
      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:18px">⚠️</span>
          <div>
            <div><b>POTENTIAL IDOR / DATA LEAK:</b> Both users received identical 200 OK responses (${harFormatSize(itemA.size)})</div>
            <div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Both ${harEsc(itemA.userName)} and ${harEsc(itemB.userName)} accessed the same payload size. Verify tenant isolation.</div>
          </div>
        </div>
        <span class="har-diff-tag same" style="font-size:11px;padding:3px 8px">IDOR SIGNAL</span>
      `;
    } else if (isBoth2xx && delta !== 0) {
      banner.classList.add("har-verdict-diff");
      const sign = delta > 0 ? "+" : "";
      const pct = itemA.size > 0 ? ` (${sign}${((delta / itemA.size) * 100).toFixed(1)}%)` : "";
      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:18px">✓</span>
          <div>
            <div><b>RESPONSE SIZE DIFF:</b> Different data returned (${harFormatSize(itemA.size)} vs ${harFormatSize(itemB.size)})</div>
            <div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Delta: <b>${sign}${harFormatSize(delta)}${pct}</b> · Both returned 2xx OK</div>
          </div>
        </div>
        <span class="har-diff-tag diff" style="font-size:11px;padding:3px 8px">SIZE DIFF</span>
      `;
    } else if (isOneBlocked) {
      banner.classList.add("har-verdict-blocked");
      const blockedUser = !itemA.is2xx ? itemA : itemB;
      const okUser = itemA.is2xx ? itemA : itemB;
      const isExpectedBlocked = !!(blockedUser.r?.is_unauth || blockedUser.r?.mode === "unauthorized");
      const blockTitle = isExpectedBlocked ? "PROTECTED (ACCESS CONTROL ENFORCED)" : "ACCESS CONTROL ENFORCED";
      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:18px">🛡️</span>
          <div>
            <div><b>${blockTitle}:</b> ${harEsc(blockedUser.userName)} was blocked (${blockedUser.sc}) as expected</div>
            <div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">${harEsc(okUser.userName)} received ${okUser.sc} (${harFormatSize(okUser.size)}), while ${harEsc(blockedUser.userName)} received HTTP ${blockedUser.sc}.</div>
          </div>
        </div>
        <span class="har-signal-blocked" style="font-size:11px;padding:3px 8px">BLOCKED (${blockedUser.sc})</span>
      `;
    } else {
      banner.classList.add("har-verdict-match");
      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:16px">●</span>
          <div>
            <div><b>Status:</b> ${itemA.sc} vs ${itemB.sc} · <b>Size:</b> ${harFormatSize(itemA.size)} vs ${harFormatSize(itemB.size)}</div>
            <div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Latency: ${itemA.r.elapsed_ms}ms vs ${itemB.r.elapsed_ms}ms</div>
          </div>
        </div>
      `;
    }
  }

  // Populate responses
  const preA = $h("diff-pre-a");
  const preB = $h("diff-pre-b");

  const rawA = itemA.r.response || "(no response)";
  const rawB = itemB.r.response || "(no response)";

  const prettyA = harPrettyBody(rawA);
  const prettyB = harPrettyBody(rawB);

  if (preA) harFillDetailPre(preA, prettyA);
  if (preB) harFillDetailPre(preB, prettyB);
}
