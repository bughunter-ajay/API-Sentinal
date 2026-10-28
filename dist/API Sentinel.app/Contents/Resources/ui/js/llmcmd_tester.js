// ── LLM / Command Injection ─────────────────────────────────────────────────────
const LC_BASE = "http://127.0.0.1:8793";

const LC_LLM_CATS = [
  ["direct_pi",        "Direct Injection"],
  ["indirect_pi",      "Indirect Injection"],
  ["jailbreak",        "Jailbreak"],
  ["instruction_leak", "Instruction Leak"],
  ["role_confusion",   "Role Escalation"],
  ["data_exfil",       "Data Exfiltration"],
  ["dos_llm",          "DoS / Token Exhaustion"],
  ["context_manip",    "Context Manipulation"],
  ["encoding_pi",      "Encoding Bypass"],
  ["tool_abuse",        "Tool Abuse"],
  ["rag_poisoning",     "RAG Poisoning"],
  ["parser_confusion",  "Parser Confusion"],
  ["sycophancy",        "Sycophancy / Emotional"],
  ["fewshot_poison",    "Few-Shot Poisoning"],
  ["binary_probe",      "Binary Probing"],
  ["cot_hijack",        "CoT Hijacking"],
  ["output_render",     "Output Rendering"],
  ["identity_spoof",    "Identity Spoofing"],
  ["composite_attack",  "Composite Attack"],
];

const LC_EXT_CATS = [
  ["data_leakage",  "Data Leakage"],
  ["server_access", "Server Access"],
  ["debug_probe",   "Debug Probe"],
  ["system_recon",  "System Recon"],
];

let _lcEndpoints   = [];   // parsed from HAR / cURL / AV capture
let _lcChecked     = {};   // {method::url: true} — presence tracking only, no per-row checkbox UI
let _lcJobId       = null;
let _lcPollTimer   = null;
let _lcAllFindings = [];
let _lcVisibleRows = [];   // currently-rendered (filtered) findings — context menu indexes into this
let _lcLastJob     = null;
let _lcFilterText  = "";   // capture-tab URL filter
let _lcTableFilterText = "";
let _lcCtxFinding  = null;
let _lcLogRendered = 0;    // how many of the CURRENT job's logs are already in the DOM
let _lcScanLogs    = [];   // cumulative structured log entries — source of truth for expand/collapse
let _lcPendingHar  = null;

let _lcDismissedIds = new Set();

// ── Single-endpoint scan ("Start") state ─────────────────────────────────────
let _lcScanRunning   = false;  // true while a job is in flight
let _lcStartedOnce    = false;
let _lcScannedCount  = 0;
let _lcCurrentEp     = null;   // the single endpoint object currently in flight
let _lcScanConfig    = { run_extended: false, extended_categories: [], run_llm: false, llm_categories: [], oob_host: "", selected_params: null };
let _lcParamRows     = [];     // [{method,url,location,name,score,reason,testable,tier,checked}] from /llmcmd/score-params
let _lcParamScope    = new Set(); // baseKey of endpoints covered by the last param-selection step

// ── Tab switch ────────────────────────────────────────────────────────────────
function lcSwitchTab(tab) {
  document.getElementById("lc-tab-capture").classList.toggle("active", tab === "capture");
  document.getElementById("lc-tab-scanning").classList.toggle("active", tab === "scanning");
  document.getElementById("lc-tab-results").classList.toggle("active", tab === "results");
  document.getElementById("lc-tab-capture-content").style.display  = tab === "capture"  ? "flex" : "none";
  document.getElementById("lc-tab-scanning-content").style.display = tab === "scanning" ? "flex" : "none";
  document.getElementById("lc-tab-results-content").style.display  = tab === "results"  ? "flex" : "none";
}

// ── HAR import ────────────────────────────────────────────────────────────────
function lcSetupHarInput() {
  const inp = document.getElementById("lc-har-file-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    try {
      const text = await file.text();
      const har  = JSON.parse(text);
      lcShowHarTokenModal(har);
    } catch(e) {
      alert("HAR parse error: " + e.message);
    }
    inp.value = "";
  };
}

function lcShowHarTokenModal(har) {
  _lcPendingHar = har;
  document.getElementById("lc-har-token-input").value = "";
  document.getElementById("lc-har-token-modal").style.display = "flex";
  setTimeout(() => document.getElementById("lc-har-token-input")?.focus(), 50);
}
function lcConfirmHarToken() {
  const token = document.getElementById("lc-har-token-input").value.trim();
  document.getElementById("lc-har-token-modal").style.display = "none";
  lcLoadFromHar(_lcPendingHar, token || null);
  _lcPendingHar = null;
}
function lcSkipHarToken() {
  document.getElementById("lc-har-token-modal").style.display = "none";
  lcLoadFromHar(_lcPendingHar, null);
  _lcPendingHar = null;
}

function lcApplyNewToken(headers, newToken) {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== "authorization") continue;
    const m = headers[key].match(/^(\S+)\s+/);
    headers[key] = (!newToken.includes(" ") && m) ? `${m[1]} ${newToken}` : newToken;
  }
}

function lcLoadFromHar(har, newToken) {
  const entries = har?.log?.entries || [];
  const STATIC = /\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|webp|js)(\?|$)/i;
  const seen = new Set();
  _lcEndpoints = []; _lcChecked = {};

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
    if (newToken) lcApplyNewToken(headers, newToken);
    let body = null;
    const postData = rq.postData;
    if (postData && postData.text) {
      try { body = JSON.parse(postData.text); } catch(e) { body = postData.text; }
    }

    _lcEndpoints.push({ url, method, headers, body });
    _lcChecked[key] = true;
  }

  document.getElementById("lc-capture-count").textContent = `${_lcEndpoints.length} endpoints`;
  lcRenderEndpointList();
  lcUpdateLiveCounts();
}

// ── From AV Capture ───────────────────────────────────────────────────────────
function lcLoadFromCapture() {
  const avState = window._avState;
  const reqs = avState?.requests || [];
  if (!reqs.length) {
    alert("No requests in API Validator capture.\n\nCapture requests in API Validator Pro tab first, or import a HAR / cURL.");
    return;
  }
  const seen = new Set();
  _lcEndpoints = []; _lcChecked = {};
  for (const r of reqs) {
    const url = r.url || "";
    const method = (r.method || "GET").toUpperCase();
    if (!url.startsWith("http")) continue;
    if (r.id && _lcDismissedIds.has(r.id)) continue;
    const key = method + "::" + url;
    if (seen.has(key)) continue;
    seen.add(key);
    _lcEndpoints.push({ id: r.id, url, method, headers: { ...(r.headers || {}) }, body: r.body ?? null });
    _lcChecked[key] = true;
  }
  document.getElementById("lc-capture-count").textContent = `${_lcEndpoints.length} endpoints (from AV)`;
  lcRenderEndpointList();
  lcUpdateLiveCounts();
}

function lcSyncFromCapture() {
  const reqs = window._avState?.requests || [];
  if (!reqs.length) return;
  let added = 0;
  for (const r of reqs) {
    const url = r.url || "";
    if (!url.startsWith("http")) continue;
    if (r.id && _lcDismissedIds.has(r.id)) continue;
    const method = (r.method || "GET").toUpperCase();
    const key = method + "::" + url;
    if (Object.prototype.hasOwnProperty.call(_lcChecked, key)) continue;
    _lcEndpoints.push({ id: r.id, url, method, headers: { ...(r.headers || {}) }, body: r.body ?? null });
    _lcChecked[key] = true;
    added++;
  }
  if (added > 0) {
    document.getElementById("lc-capture-count").textContent = `${_lcEndpoints.length} endpoints`;
    lcRenderEndpointList();
    lcUpdateLiveCounts();
  }
}
window.lcSyncFromCapture = lcSyncFromCapture;

// ── Continuous-scan helpers ───────────────────────────────────────────────────
function lcBaseKey(ep) {
  return ep.method + "::" + ep.url.split("?")[0];
}
function lcSetStartButtonRunning(running) {
  const startBtn = document.getElementById("lc-start-btn");
  const abortBtn = document.getElementById("lc-capture-abort-btn");
  if (startBtn) {
    startBtn.disabled = running;
    startBtn.textContent = running ? "⏳ In Progress" : "🚀 Start";
  }
  if (abortBtn) abortBtn.style.display = running ? "inline-block" : "none";
}
function lcUpdateLiveCounts() {
  const plain = document.getElementById("lc-capture-count");
  const live  = document.getElementById("lc-scan-counts");
  if (!live) return;
  if (!_lcStartedOnce) { live.style.display = "none"; if (plain) plain.style.display = "inline"; return; }
  if (plain) plain.style.display = "none";
  const total      = _lcEndpoints.length;
  const inProgress = _lcEndpoints.filter(ep => ep.status === "queued").length;
  live.style.display = "inline";
  live.textContent = `Total: ${total} · ✅ Scanned: ${_lcScannedCount} · ⏳ In Progress: ${inProgress} · 🚨 Confirmed: ${_lcAllFindings.length}`;
}

// One explicit endpoint, one job — the user re-ticks a checkbox and clicks
// Start again for the next API; nothing auto-continues after this finishes.
function lcOnScanDone(data) {
  const ep = _lcCurrentEp;
  _lcCurrentEp = null;
  _lcScanRunning = false;
  if (data) {
    ep.status = "scanned";
    _lcScannedCount++;
    // _lcAllFindings is already kept live during polling (see lcSubmitAndPoll)
    // — by the time the job reports done/aborted it's already merged in.
    _lcLastJob = data;
    lcShowResults();
  } else {
    ep.status = undefined;
  }
  lcRenderEndpointList();
  lcUpdateLiveCounts();
  lcSetStartButtonRunning(false);
}

function lcSortFindings(findings) {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, POTENTIAL_OOB: 4, BLOCKED: 5, SAFE: 6 };
  return findings.slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
}

// ── cURL import ───────────────────────────────────────────────────────────────
function lcShowCurlImport() {
  document.getElementById("lc-curl-modal").style.display = "flex";
  setTimeout(() => document.getElementById("lc-curl-input")?.focus(), 50);
}
function lcCloseCurlImport() {
  document.getElementById("lc-curl-modal").style.display = "none";
}
function lcConfirmCurlImport() {
  const inp  = document.getElementById("lc-curl-input");
  const text = (inp.value || "").trim();
  if (!text) return;
  const parsed = _lcParseCurl(text);
  if (!parsed) { alert("Not a valid cURL command"); return; }
  const key = parsed.method + "::" + parsed.url;
  if (!(key in _lcChecked)) {
    _lcEndpoints.push({ url: parsed.url, method: parsed.method, headers: parsed.headers, body: parsed.body });
  }
  _lcChecked[key] = true;
  document.getElementById("lc-capture-count").textContent = `${_lcEndpoints.length} endpoints`;
  lcRenderEndpointList();
  lcUpdateLiveCounts();
  inp.value = "";
  lcCloseCurlImport();
}

function _lcParseCurl(text) {
  // Prefer the upgraded AV parseCurl (same as API Validator / APISphere).
  if (typeof parseCurl === "function") {
    try {
      const r = parseCurl(text);
      return {
        method: r.method || (r.body ? "POST" : "GET"),
        url: r.url,
        headers: r.headers || {},
        body: r.body != null ? r.body : (r.payload != null ? r.payload : null),
      };
    } catch (e) {
      return null;
    }
  }
  // Fallback if popup.js helpers are unavailable
  const hasHelpers = typeof _avNormalizeCurlText === "function" &&
                     typeof _avTokenizeCurl === "function" &&
                     typeof _avExpandCurlTokens === "function";
  const s = hasHelpers ? _avNormalizeCurlText(text) : String(text || "").trim();
  if (!s || !/^curl\b/i.test(s)) return null;

  const tokens = hasHelpers ? _avExpandCurlTokens(_avTokenizeCurl(s)) : [s];

  let method = null, url = null, body = null;
  const headers = {};

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t) continue;
    if (i === 0 && /^curl$/i.test(t)) continue;

    if (t === "--url" && tokens[i + 1]) { url = tokens[i + 1]; i++; continue; }
    if (!url && /^https?:\/\//i.test(t)) { url = t; continue; }

    if ((t === "-X" || t === "--request") && tokens[i + 1]) {
      method = String(tokens[i + 1]).toUpperCase();
      i++;
      continue;
    }

    if ((t === "-H" || t === "--header") && tokens[i + 1]) {
      const h = tokens[i + 1] || "";
      const ci = h.indexOf(":");
      if (ci > 0) headers[h.slice(0, ci).trim()] = h.slice(ci + 1).trim();
      i++;
      continue;
    }

    if (["--data-raw","--data-binary","--data","-d","--data-urlencode","--json"].includes(t)) {
      body = tokens[i + 1] != null ? tokens[i + 1] : "";
      i++;
      continue;
    }
  }

  if (!url) return null;
  if (!method) method = body ? "POST" : "GET";

  let parsedBody = body;
  if (body && typeof body === "string") {
    try { parsedBody = JSON.parse(body); } catch (e) { /* keep raw */ }
  }
  return { method, url, headers, body: parsedBody };
}

// ── Start: Step 1 — extract & score params, let the user pick which to test ──
// Mirrors the CLI's "All Parameters Discovered" table + "Param Selection"
// prompt, just upfront via checkboxes instead of blocking on stdin.
async function lcShowStartModal() {
  lcSyncFromCapture();
  const selected = _lcEndpoints.filter(ep => ep.checked);
  if (!selected.length) {
    alert("Tick the checkbox next to one endpoint in the list to scan it.");
    return;
  }
  const target = selected[0];

  const btn = document.getElementById("lc-start-btn");
  const prevText = btn.textContent;
  btn.disabled = true; btn.textContent = "⏳ Extracting params...";
  try {
    const resp = await fetch(`${LC_BASE}/llmcmd/score-params`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoints: [{ url: target.url, method: target.method, headers: target.headers || {}, body: target.body }],
      }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Param scoring failed");

    _lcParamRows = data.params.map(p => ({ ...p, checked: p.testable }));
    _lcParamScope = new Set([lcBaseKey(target)]);
    lcRenderParamList();
    document.getElementById("lc-param-modal").style.display = "flex";
  } catch(e) {
    alert("Could not extract parameters — is the LLM/Command Injection backend running (port 8793)?");
  }
  btn.disabled = false; btn.textContent = prevText;
}
function lcCloseParamModal() {
  document.getElementById("lc-param-modal").style.display = "none";
}
function lcRenderParamList() {
  const wrap = document.getElementById("lc-param-list");
  if (!_lcParamRows.length) {
    wrap.innerHTML = `<div class="mt-empty-row" style="padding:24px;text-align:center">No parameters found on these endpoints.</div>`;
    return;
  }
  const TIER_COLOR = { 0: "#6e7681", 1: "#58a6ff", 2: "#d29922", 3: "#da3633" };
  wrap.innerHTML = _lcParamRows.map((p, i) => {
    const c = TIER_COLOR[p.tier] || "#6e7681";
    const tierLabel = p.tier > 0 ? `T${p.tier}` : "low";
    return `
      <label class="lc-param-row">
        <input type="checkbox" ${p.checked ? "checked" : ""} onchange="_lcParamRows[${i}].checked = this.checked">
        <span class="lc-param-loc">${lcEsc(p.location)}</span>
        <span class="lc-param-name" title="${lcEsc(p.name)}">${lcEsc(p.name)}</span>
        <span class="lc-param-tier" style="color:${c};border-color:${c}55;background:${c}22">${tierLabel}</span>
        <span class="lc-param-score">${p.score}</span>
        <span class="lc-param-url" title="${lcEsc(p.method)} ${lcEsc(p.url)}">${lcEsc(p.method)} ${lcEsc(p.url)}</span>
      </label>`;
  }).join("");
}
function lcParamSelectTestable() { _lcParamRows.forEach(p => p.checked = p.testable); lcRenderParamList(); }
function lcParamSelectAll()      { _lcParamRows.forEach(p => p.checked = true);       lcRenderParamList(); }
function lcParamDeselectAll()    { _lcParamRows.forEach(p => p.checked = false);      lcRenderParamList(); }
function lcConfirmParamSelection() {
  lcCloseParamModal();
  document.getElementById("lc-start-error").style.display = "none";
  // Reset OOB row each open (host field keeps last value for convenience)
  const oobCb = document.getElementById("lc-start-oob");
  if (oobCb) oobCb.checked = !!(_lcScanConfig.oob_host);
  const oobHostEl = document.getElementById("lc-start-oob-host");
  if (oobHostEl && _lcScanConfig.oob_host) oobHostEl.value = _lcScanConfig.oob_host;
  lcToggleOobHost();
  document.getElementById("lc-start-modal").style.display = "flex";
}

// ── Start: Step 2 — Extended Recon / LLM config, then go ────────────────────
function lcCloseStartModal() {
  document.getElementById("lc-start-modal").style.display = "none";
}
function lcToggleExtCats() {
  const on = document.getElementById("lc-start-extended").checked;
  document.getElementById("lc-start-ext-cats").style.display = on ? "flex" : "none";
}
function lcToggleLlmCats() {
  const on = document.getElementById("lc-start-llm").checked;
  document.getElementById("lc-start-llm-cats").style.display = on ? "flex" : "none";
}
function lcToggleOobHost() {
  const on = !!document.getElementById("lc-start-oob")?.checked;
  const row = document.getElementById("lc-start-oob-row");
  if (row) row.style.display = on ? "flex" : "none";
}
function lcConfirmStart() {
  const errEl = document.getElementById("lc-start-error");

  const target = _lcEndpoints.find(ep => ep.checked);
  if (!target) {
    errEl.textContent = "No endpoint selected — tick one in the Capture list first.";
    errEl.style.display = "block";
    return;
  }

  const runExtended = document.getElementById("lc-start-extended").checked;
  const extCats = runExtended
    ? LC_EXT_CATS.map(([c]) => c).filter(c => document.getElementById(`lc-extcat-${c}`)?.checked)
    : [];

  const runLlm = document.getElementById("lc-start-llm").checked;
  const llmCats = runLlm
    ? LC_LLM_CATS.map(([c]) => c).filter(c => document.getElementById(`lc-llmcat-${c}`)?.checked)
    : [];

  const oobOn = !!document.getElementById("lc-start-oob")?.checked;
  let oobHost = (document.getElementById("lc-start-oob-host")?.value || "").trim();
  // Normalize: strip scheme / path — backend wants host only
  oobHost = oobHost.replace(/^https?:\/\//i, "").split("/")[0].trim();
  if (oobOn && !oobHost) {
    errEl.textContent = "OOB enabled — paste a Collaborator / interactsh / oast host first.";
    errEl.style.display = "block";
    return;
  }

  _lcScanConfig = {
    run_extended       : runExtended,
    extended_categories: extCats,
    run_llm            : runLlm,
    llm_categories      : llmCats,
    oob_host            : oobOn ? oobHost : "",
    selected_params     : _lcParamRows.filter(p => p.checked)
      .map(p => ({ method: p.method, url: p.url, location: p.location, name: p.name })),
  };

  errEl.style.display = "none";
  lcCloseStartModal();

  // One explicit endpoint, one job — no continuous re-fetching of further
  // captured endpoints anymore; the user picks the next one manually.
  _lcScanRunning = true;
  _lcStartedOnce = true;
  lcSetStartButtonRunning(true);
  lcUpdateLiveCounts();

  _lcCurrentEp = target;
  target.status = "queued";
  lcRenderEndpointList();
  lcSwitchTab("scanning");
  lcSubmitAndPoll([target], lcOnScanDone);
}

// ── Endpoint list rendering ───────────────────────────────────────────────────
function lcRenderEndpointList() {
  const list  = document.getElementById("lc-endpoint-list");
  const empty = document.getElementById("lc-endpoint-empty");
  const filter = _lcFilterText.toLowerCase();

  if (!_lcEndpoints.length) {
    list.style.display = "none"; empty.style.display = "flex"; return;
  }
  list.style.display = "flex"; empty.style.display = "none";

  const filtered = filter
    ? _lcEndpoints.filter(ep => ep.url.toLowerCase().includes(filter))
    : _lcEndpoints;

  const MC = {GET:"#3fb950",POST:"#ffa657",PUT:"#d29922",PATCH:"#a5d6ff",DELETE:"#f85149"};
  const TAGS = {
    scanned:   `<span class="lc-ep-tag lc-ep-tag-scanned">✅ Scanned</span>`,
    duplicate: `<span class="lc-ep-tag lc-ep-tag-dup">⏭ Skipped</span>`,
    queued:    `<span class="lc-ep-tag lc-ep-tag-queued">⏳ Scanning</span>`,
  };

  list.innerHTML = filtered.map(ep => {
    const i = _lcEndpoints.indexOf(ep);
    const mc = MC[ep.method] || "#8b949e";
    const tag = TAGS[ep.status] || "";
    return `
      <div class="mt-ep-row ${ep.checked ? "mt-ep-checked" : ""}" onclick="lcToggleEpCheck(${i})">
        <input type="checkbox" class="mt-ep-cb" ${ep.checked ? "checked" : ""}
               onclick="event.stopPropagation(); lcToggleEpCheck(${i})">
        <span class="mt-ep-method" style="color:${mc};background:${mc}22;border:1px solid ${mc}55">${ep.method}</span>
        <span class="mt-ep-url" title="${lcEsc(ep.url)}">${lcEsc(ep.url)}</span>
        ${tag}
      </div>`;
  }).join("");
}

// Exclusive single-select — checking one unchecks every other endpoint, since
// a scan run always targets exactly one API at a time now.
function lcToggleEpCheck(idx) {
  const wasChecked = !!_lcEndpoints[idx]?.checked;
  _lcEndpoints.forEach(ep => { ep.checked = false; });
  if (!wasChecked && _lcEndpoints[idx]) _lcEndpoints[idx].checked = true;
  lcRenderEndpointList();
}

function lcFilterCapture() {
  _lcFilterText = document.getElementById("lc-url-filter-input").value;
  lcRenderEndpointList();
}

// ── Scanning / polling ────────────────────────────────────────────────────────
async function lcSubmitAndPoll(endpoints, onDone) {
  // Endpoints covered by the upfront param-selection step send exactly what
  // was checked there; anything outside that scope (e.g. arrived later via
  // live sync) falls back to the backend's own score-threshold auto-mode.
  const ep0 = endpoints[0];
  const inScope = ep0 && _lcParamScope.has(lcBaseKey(ep0));
  const selectedParams = inScope
    ? (_lcScanConfig.selected_params || []).filter(p => p.url === ep0.url && p.method === ep0.method)
    : null;

  try {
    const resp = await fetch(`${LC_BASE}/llmcmd/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoints: endpoints.map(ep => ({ url: ep.url, method: ep.method, headers: ep.headers || {}, body: ep.body })),
        run_extended       : _lcScanConfig.run_extended,
        extended_categories: _lcScanConfig.extended_categories,
        run_llm            : _lcScanConfig.run_llm,
        llm_categories     : _lcScanConfig.llm_categories,
        oob_host           : _lcScanConfig.oob_host || "",
        selected_params    : selectedParams,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Scan start failed");
    _lcJobId = data.job_id;

    document.getElementById("lc-scan-fill").style.width = "0%";
    document.getElementById("lc-scan-stats").textContent = `0 / ${data.total} requests`;
    const curUrl = document.getElementById("lc-scan-current-url");
    if (curUrl && endpoints[0]) curUrl.textContent = `Testing: ${endpoints[0].method} ${endpoints[0].url}`;
    document.getElementById("lc-abort-btn").style.display = "inline-block";
    document.getElementById("lc-abort-btn").disabled = false;
    _lcLogRendered = 0;

    // Snapshot of everything found by PRIOR jobs — this job's own findings
    // (from /progress) get re-merged against this same baseline on every
    // tick, since the backend reports this job's running total, not a delta.
    const baselineFindings = _lcAllFindings.slice();
    let lastConfirmedCount = 0;

    _lcPollTimer = setInterval(async () => {
      try {
        const r2 = await fetch(`${LC_BASE}/llmcmd/progress/${_lcJobId}`);
        const d2 = await r2.json();
        if (!r2.ok) { clearInterval(_lcPollTimer); return; }

        document.getElementById("lc-scan-fill").style.width = d2.progress + "%";
        document.getElementById("lc-scan-stats").textContent =
          `${d2.completed} / ${d2.total} requests · 🚨 ${d2.confirmed} confirmed · 🔒 ${d2.blocked} blocked · ${d2.elapsed}s`;
        lcAppendScanLogs(d2.logs);

        // Push newly-confirmed findings into the Results tab the moment
        // they show up, rather than waiting for the whole batch to finish.
        if (d2.findings && d2.findings.length !== lastConfirmedCount) {
          lastConfirmedCount = d2.findings.length;
          _lcAllFindings = lcSortFindings(baselineFindings.concat(d2.findings));
          lcShowResults();
        }

        if (d2.status === "done" || d2.status === "aborted") {
          clearInterval(_lcPollTimer);
          _lcJobId = null;
          document.getElementById("lc-abort-btn").style.display = "none";
          onDone(d2);
        }
      } catch(e) {}
    }, 800);
  } catch(e) {
    _lcJobId = null;
    onDone(null);
  }
}

function lcAppendScanLogs(logs) {
  if (!logs || logs.length <= _lcLogRendered) return;
  const list = document.getElementById("lc-scan-log-list");
  const newEntries = logs.slice(_lcLogRendered);
  const startIdx = _lcScanLogs.length;
  _lcScanLogs.push(...newEntries);

  const html = newEntries.map((l, i) => lcRenderLogRow(l, startIdx + i)).join("");
  list.insertAdjacentHTML("beforeend", html);
  _lcLogRendered = logs.length;
}

const LC_SEV_COLOR = { CRITICAL:"#da3633", HIGH:"#f85149", MEDIUM:"#d29922", LOW:"#58a6ff",
                        BLOCKED:"#6e7681", POTENTIAL_OOB:"#8957e5", SAFE:"#3fb950" };

function lcRenderLogRow(l, idx) {
  const statusColor = l.status === "TIMEOUT" || l.status === "ERROR" ? "#f85149"
    : (typeof l.status === "number" && l.status >= 200 && l.status < 400) ? "#3fb950" : "#d29922";
  const sevColor = LC_SEV_COLOR[l.severity] || "#8b949e";
  const confirmBadge = l.confirmed
    ? `<span class="lc-scan-log-confirmed" style="color:${sevColor}">🚨 ${lcEsc(l.severity)}</span>`
    : `<span class="lc-scan-log-confirmed" style="color:var(--text3)">—</span>`;
  return `<div class="lc-scan-log-entry">
    <div class="lc-scan-log-row" onclick="lcToggleLogDetail(${idx})">
      <span class="lc-scan-log-status" style="color:${statusColor}">${lcEsc(l.status)}</span>
      <span class="lc-scan-log-method">${lcEsc(l.method || "GET")}</span>
      <span class="lc-scan-log-param" title="${lcEsc(l.param_loc)}:${lcEsc(l.param_name)}">${lcEsc(l.param_loc)}:${lcEsc(l.param_name)}</span>
      <span class="lc-scan-log-payload" title="${lcEsc(l.payload)}">${lcEsc(l.category)} · ${lcEsc(l.payload)}</span>
      ${confirmBadge}
    </div>
    <div class="lc-scan-log-detail" id="lc-log-detail-${idx}" style="display:none"></div>
  </div>`;
}

function lcToggleLogDetail(idx) {
  const detail = document.getElementById(`lc-log-detail-${idx}`);
  if (!detail) return;
  if (detail.style.display !== "none") { detail.style.display = "none"; return; }
  const l = _lcScanLogs[idx];
  if (!l) return;
  detail.innerHTML = lcRenderLogDetailHtml(l, idx);
  detail.style.display = "block";
}

const _lcPreRaw = {};

// Wraps every occurrence of `payload` inside `text` in a highlight <mark> —
// lets the user spot exactly where the injected value landed inside a large
// request body at a glance, instead of hunting through it manually.
function lcHighlightPayload(text, payload) {
  const escaped = lcEsc(text);
  if (!payload) return escaped;
  const escPayload = lcEsc(payload).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!escPayload) return escaped;
  try {
    return escaped.replace(new RegExp(escPayload, "g"), m => `<mark class="lc-log-payload-hit">${m}</mark>`);
  } catch(e) { return escaped; }
}

function lcRenderLogDetailHtml(l, idx) {
  // Headers are mostly static auth/browser noise for CMDI review — what matters
  // is where the payload actually landed. body_json/body_form params show the
  // request body (which carries the payload); query params have no body at
  // all, so the full test URL (payload and all) is shown instead.
  const reqBody = l.req_body || l.url || "";
  const respColor = (typeof l.status === "number" && l.status >= 200 && l.status < 400) ? "#3fb950" : "#f85149";
  const respLabel = String(l.status);
  const respBody = l.resp_body || "(empty)";

  const reqBodyId = `lc-pre-reqb-${idx}`;
  const respId = `lc-pre-resp-${idx}`;
  _lcPreRaw[reqBodyId] = reqBody;
  _lcPreRaw[respId] = respBody;

  const tools = (panelId) => `
    <div class="lc-log-detail-tools">
      <input type="text" class="lc-log-detail-search" placeholder="🔍 Search" oninput="lcFilterDetailPanel('${panelId}', this.value)">
      <button type="button" class="lc-log-detail-copy" onclick="lcCopyDetailPanel('${panelId}', this)">📋 Copy</button>
    </div>`;

  return `
    <div class="lc-log-detail-meta">
      <span><b>Category:</b> ${lcEsc(l.category)}</span>
      <span><b>Tier:</b> T${lcEsc(l.tier)}</span>
      <span><b>Detection:</b> ${lcEsc(l.det_method)}</span>
      <span><b>Reason:</b> ${lcEsc(l.reason)}</span>
      ${l.evidence ? `<span><b>Evidence:</b> ${lcEsc(l.evidence)}</span>` : ""}
    </div>
    <div class="lc-log-detail-grid">
      <div class="lc-log-detail-panel" id="lc-req-panel-${idx}">
        <div class="lc-log-detail-head">
          <div class="lc-log-detail-label">📤 Request Body</div>
          ${tools(`lc-req-panel-${idx}`)}
        </div>
        <pre class="lc-log-detail-pre" id="${reqBodyId}">${lcHighlightPayload(reqBody, l.payload)}</pre>
      </div>
      <div class="lc-log-detail-panel" id="lc-resp-panel-${idx}">
        <div class="lc-log-detail-head">
          <div class="lc-log-detail-label" style="color:${respColor}">📥 Response · ${lcEsc(respLabel)}</div>
          ${tools(`lc-resp-panel-${idx}`)}
        </div>
        <pre class="lc-log-detail-pre" id="${respId}">${lcEsc(respBody)}</pre>
      </div>
    </div>`;
}

function lcFilterDetailPanel(panelId, query) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const q = query.trim();
  panel.querySelectorAll(".lc-log-detail-pre").forEach(pre => {
    const raw = _lcPreRaw[pre.id] != null ? _lcPreRaw[pre.id] : pre.textContent;
    if (!q) { pre.innerHTML = lcEsc(raw); return; }
    const escQ = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(escQ, "gi");
    pre.innerHTML = lcEsc(raw).replace(re, m => `<mark class="lc-log-search-hit">${m}</mark>`);
  });
  const firstHit = panel.querySelector(".lc-log-search-hit");
  if (firstHit) firstHit.scrollIntoView({ block: "center" });
}

async function lcCopyDetailPanel(panelId, btn) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const parts = [];
  panel.querySelectorAll(".lc-log-detail-pre").forEach(pre => {
    parts.push(_lcPreRaw[pre.id] != null ? _lcPreRaw[pre.id] : pre.textContent);
  });
  try {
    await navigator.clipboard.writeText(parts.join("\n\n"));
    const original = btn.textContent;
    btn.textContent = "✅ Copied";
    setTimeout(() => { btn.textContent = original; }, 1200);
  } catch (e) {}
}

// ── Abort ─────────────────────────────────────────────────────────────────────
async function lcAbortScan() {
  _lcScanRunning = false;

  if (!_lcJobId) {
    lcSetStartButtonRunning(false);
    return;
  }
  const btns = [document.getElementById("lc-abort-btn"), document.getElementById("lc-capture-abort-btn")]
    .filter(Boolean);
  btns.forEach(b => { b.disabled = true; b.textContent = "⏳ Aborting..."; });
  try {
    await fetch(`${LC_BASE}/llmcmd/abort/${_lcJobId}`, { method: "POST" });
  } catch(e) {}
  setTimeout(() => { btns.forEach(b => { b.disabled = false; b.textContent = "⏹ Abort"; }); }, 1500);
}

// ── Results ───────────────────────────────────────────────────────────────────
function lcShowResults() {
  document.getElementById("lc-results-wrap").style.display = "flex";
  document.getElementById("lc-results-empty").style.display = "none";
  lcApplyFilters();
}

function lcApplyFilters() {
  const q     = _lcTableFilterText.toLowerCase();
  const sev   = document.getElementById("lc-sev-filter").value;
  const phase = document.getElementById("lc-phase-filter").value;
  let rows = _lcAllFindings;
  if (sev)   rows = rows.filter(f => f.severity === sev);
  if (phase) rows = rows.filter(f => f.phase === phase);
  if (q) rows = rows.filter(f =>
    f.category.toLowerCase().includes(q) || f.payload.toLowerCase().includes(q) ||
    f.param_name.toLowerCase().includes(q) || f.url.toLowerCase().includes(q) ||
    f.reason.toLowerCase().includes(q));
  lcRenderTable(rows);
}
function lcFilterTable() {
  _lcTableFilterText = document.getElementById("lc-filter-input").value;
  lcApplyFilters();
}

function lcRenderTable(rows) {
  _lcVisibleRows = rows;
  const tbody = document.getElementById("lc-results-tbody");
  if (!rows.length) { tbody.innerHTML = `<tr><td colspan="8" class="mt-empty-row">No confirmed findings.</td></tr>`; return; }

  tbody.innerHTML = rows.map((f, i) => {
    const sevColor = LC_SEV_COLOR[f.severity] || "#8b949e";
    return `
      <tr class="lc-result-row" onclick="lcToggleResultDetail(${i})" oncontextmenu="lcShowCtxMenu(event, ${i}); return false;">
        <td><span class="lc-sev-badge" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}55">${f.severity}</span></td>
        <td class="lc-td-phase">${lcEsc(f.phase)}</td>
        <td><b style="color:#79c0ff">${lcEsc(f.method)}</b></td>
        <td class="lc-td-param">${lcEsc(f.param_loc)}:${lcEsc(f.param_name)}</td>
        <td class="lc-td-cat">${lcEsc(f.category)}</td>
        <td class="lc-td-payload" title="${lcEsc(f.payload)}">${lcEsc(f.payload)}</td>
        <td>${lcEsc(f.status)}</td>
        <td class="lc-td-reason" title="${lcEsc(f.evidence||"")}">${lcEsc(f.reason)}</td>
      </tr>
      <tr class="lc-result-detail-row" id="lc-result-detail-${i}" style="display:none">
        <td colspan="8" class="lc-result-detail-cell"></td>
      </tr>`;
  }).join("");
}

// Click a Results row to expand the same Request-body/Response-body view the
// Scanning tab uses — namespaced with a "res" prefix on the idx so element
// ids never collide with a simultaneously-expanded Scanning-tab row.
function lcToggleResultDetail(idx) {
  const row = document.getElementById(`lc-result-detail-${idx}`);
  if (!row) return;
  if (row.style.display !== "none") { row.style.display = "none"; return; }
  const f = _lcVisibleRows[idx];
  if (!f) return;
  row.querySelector("td").innerHTML = lcRenderLogDetailHtml(f, `res${idx}`);
  row.style.display = "table-row";
}

// ── Right-click context menu ──────────────────────────────────────────────────
function lcShowCtxMenu(e, idx) {
  _lcCtxFinding = _lcVisibleRows[idx];
  const menu = document.getElementById("lc-ctx-menu");
  if (!menu) return;
  menu.style.display = "block";
  const mw = menu.offsetWidth || 180, mh = menu.offsetHeight || 180;
  menu.style.left = Math.min(e.pageX, window.innerWidth  - mw - 8) + "px";
  menu.style.top  = Math.min(e.pageY, window.innerHeight - mh - 8) + "px";
}
function lcHideCtxMenu() {
  const menu = document.getElementById("lc-ctx-menu");
  if (menu) menu.style.display = "none";
}
document.addEventListener("click", lcHideCtxMenu);
document.addEventListener("scroll", lcHideCtxMenu, true);

function lcCopy(text) {
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
  };
  if (navigator.clipboard) navigator.clipboard.writeText(text).catch(fallback);
  else fallback();
}
function lcCtxCopyPayload() { if (_lcCtxFinding) lcCopy(_lcCtxFinding.payload); lcHideCtxMenu(); }
function lcCtxCopyUrl()     { if (_lcCtxFinding) lcCopy(_lcCtxFinding.url);     lcHideCtxMenu(); }
function lcCtxCopyRow() {
  if (!_lcCtxFinding) return;
  const f = _lcCtxFinding;
  lcCopy([f.severity, f.phase, f.method, `${f.param_loc}:${f.param_name}`, f.category, f.payload, f.status, f.reason, f.url].join("\t"));
  lcHideCtxMenu();
}
function lcCtxCopyCurl() {
  if (!_lcCtxFinding) return;
  const f = _lcCtxFinding;
  const parts = [`curl -X ${f.method} '${f.url}'`];
  Object.entries(f.req_headers || {}).forEach(([k, v]) => {
    parts.push(`  -H '${k}: ${String(v).replace(/'/g, "'\\''")}'`);
  });
  if (f.req_body) {
    parts.push(`  --data-raw '${String(f.req_body).replace(/'/g, "'\\''")}'`);
  }
  lcCopy(parts.join(" \\\n"));
  lcHideCtxMenu();
}

// ── Export HTML ───────────────────────────────────────────────────────────────
async function lcDownloadHtml() {
  if (!_lcLastJob) return;
  const html = lcGenerateHtml(_lcAllFindings);
  const ts = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
  if (window.pywebview?.api?.save_file) {
    await window.pywebview.api.save_file(html, `llm_cmdi_report_${ts}.html`);
  } else {
    const a = document.createElement("a");
    a.href = "data:text/html;charset=utf-8," + encodeURIComponent(html);
    a.download = `llm_cmdi_report_${ts}.html`; a.click();
  }
}

function lcGenerateHtml(findings) {
  const ts = new Date().toLocaleString();
  const sB = s => { const c = LC_SEV_COLOR[s] || "#8b949e"; return `<span style="background:${c};color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">${s}</span>`; };
  const crit = findings.filter(f => f.severity === "CRITICAL").length;
  const high = findings.filter(f => f.severity === "HIGH").length;
  const med  = findings.filter(f => f.severity === "MEDIUM").length;
  const rows = findings.map((f, i) => `<tr><td style="color:var(--text)">${i+1}</td><td>${sB(f.severity)}</td><td>${lcEsc(f.phase)}</td><td><b style="color:#79c0ff">${lcEsc(f.method)}</b></td><td style="font-size:10px;word-break:break-all">${lcEsc(f.url)}</td><td>${lcEsc(f.param_loc)}:${lcEsc(f.param_name)}</td><td>${lcEsc(f.category)}</td><td style="font-family:monospace;font-size:10px;color:#ff7b72;word-break:break-all">${lcEsc(f.payload)}</td><td>${lcEsc(f.status)}</td><td style="font-size:10px">${lcEsc(f.reason)}</td></tr>`).join("");
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>LLM/Command Injection Report</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,sans-serif;background:#080c10;color:#c9d1d9;padding:24px}h1{font-size:22px;font-weight:800;background:linear-gradient(135deg,#da3633,#f85149,#ffa657);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.meta{color:var(--text);font-size:10px;font-family:monospace;margin-top:4px}.cards{display:flex;gap:8px;margin:18px 0;flex-wrap:wrap}.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 16px;text-align:center}.card h3{font-size:22px;font-weight:800;margin-bottom:2px}.card.crit h3{color:#da3633}.card.high h3{color:#f85149}.card.med h3{color:#d29922}table{border-collapse:collapse;width:100%;background:#0d1117;border:1px solid #21262d;font-size:11px}th{background:#161b22;color:var(--text);padding:7px 9px;text-align:left;border-bottom:1px solid #30363d;font-size:9px;text-transform:uppercase;letter-spacing:.5px;font-weight:700}td{padding:6px 9px;border-bottom:1px solid #161b22;vertical-align:top}tr:hover td{background:#161b22}</style></head><body>
<h1>🛡️ LLM / Command Injection Report</h1>
<p class="meta">Generated: ${ts} | Confirmed findings: ${findings.length}</p>
<div class="cards"><div class="card crit"><h3>${crit}</h3><p>CRITICAL</p></div><div class="card high"><h3>${high}</h3><p>HIGH</p></div><div class="card med"><h3>${med}</h3><p>MEDIUM</p></div></div>
<table><tr><th>#</th><th>Severity</th><th>Phase</th><th>Method</th><th>URL</th><th>Param</th><th>Category</th><th>Payload</th><th>Status</th><th>Reason</th></tr>${rows}</table>
</body></html>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function lcEsc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function lcReset() {
  clearInterval(_lcPollTimer);
  if (_lcJobId) fetch(`${LC_BASE}/llmcmd/abort/${_lcJobId}`, { method: "POST" }).catch(() => {});
  _lcEndpoints.forEach(ep => { if (ep.id) _lcDismissedIds.add(ep.id); });
  _lcEndpoints = []; _lcChecked = {}; _lcJobId = null;
  _lcAllFindings = []; _lcVisibleRows = []; _lcLastJob = null;
  _lcFilterText = ""; _lcTableFilterText = ""; _lcLogRendered = 0; _lcScanLogs = [];
  _lcScanRunning = false; _lcStartedOnce = false;
  _lcScannedCount = 0; _lcCurrentEp = null;
  _lcScanConfig = { run_extended: false, extended_categories: [], run_llm: false, llm_categories: [], oob_host: "", selected_params: null };
  _lcParamRows = []; _lcParamScope.clear();

  const cc = document.getElementById("lc-capture-count"); if (cc) { cc.textContent = "0 endpoints"; cc.style.display = "inline"; }
  const lcc = document.getElementById("lc-scan-counts"); if (lcc) lcc.style.display = "none";
  const fi = document.getElementById("lc-url-filter-input"); if (fi) fi.value = "";
  const list = document.getElementById("lc-endpoint-list");
  if (list) { list.innerHTML = ""; list.style.display = "none"; }
  const empty = document.getElementById("lc-endpoint-empty"); if (empty) empty.style.display = "flex";
  const wrap = document.getElementById("lc-results-wrap"); if (wrap) wrap.style.display = "none";
  const re = document.getElementById("lc-results-empty"); if (re) re.style.display = "flex";
  const logList = document.getElementById("lc-scan-log-list"); if (logList) logList.innerHTML = "";
  const fill = document.getElementById("lc-scan-fill"); if (fill) fill.style.width = "0%";
  const stats = document.getElementById("lc-scan-stats"); if (stats) stats.textContent = "0 / 0 requests";
  const curUrl = document.getElementById("lc-scan-current-url"); if (curUrl) curUrl.textContent = "";
  const abortBtn = document.getElementById("lc-abort-btn"); if (abortBtn) abortBtn.style.display = "none";
  const tf = document.getElementById("lc-filter-input"); if (tf) tf.value = "";
  const sev = document.getElementById("lc-sev-filter"); if (sev) sev.value = "";
  const phase = document.getElementById("lc-phase-filter"); if (phase) phase.value = "";
  const ext = document.getElementById("lc-start-extended"); if (ext) ext.checked = false;
  const extCats = document.getElementById("lc-start-ext-cats"); if (extCats) extCats.style.display = "none";
  LC_EXT_CATS.forEach(([cat]) => { const cb = document.getElementById(`lc-extcat-${cat}`); if (cb) cb.checked = true; });
  const llm = document.getElementById("lc-start-llm"); if (llm) llm.checked = false;
  const llmCats = document.getElementById("lc-start-llm-cats"); if (llmCats) llmCats.style.display = "none";
  LC_LLM_CATS.forEach(([cat]) => { const cb = document.getElementById(`lc-llmcat-${cat}`); if (cb) cb.checked = true; });
  const paramModal = document.getElementById("lc-param-modal"); if (paramModal) paramModal.style.display = "none";
  const paramList = document.getElementById("lc-param-list"); if (paramList) paramList.innerHTML = "";
  lcSetStartButtonRunning(false);
  lcSwitchTab("capture");
}
window.lcReset = lcReset;

function lcRenderCatCheckboxes(containerId, prefix, cats) {
  const wrap = document.getElementById(containerId);
  if (!wrap) return;
  wrap.innerHTML = cats.map(([cat, label]) => `
    <label style="display:flex;align-items:center;gap:5px;cursor:pointer;font-size:11px;color:var(--text2)">
      <input type="checkbox" id="${prefix}-${cat}" checked>${lcEsc(label)}
    </label>`).join("");
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  lcSetupHarInput();
  lcRenderCatCheckboxes("lc-start-ext-cats", "lc-extcat", LC_EXT_CATS);
  lcRenderCatCheckboxes("lc-start-llm-cats", "lc-llmcat", LC_LLM_CATS);
  setInterval(() => {
    if (window._activeTool === "llmcmd") lcSyncFromCapture();
  }, 2000);
});
