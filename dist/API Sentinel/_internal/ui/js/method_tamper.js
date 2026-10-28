// ── Method Tampering ─────────────────────────────────────────────────────────
const MT_BASE = "http://127.0.0.1:8767";

let _mtEndpoints    = [];   // parsed endpoints
let _mtChecked      = {};   // {key: bool}
let _mtJobId        = null;
let _mtPollTimer    = null;
let _mtAllFindings  = [];
let _mtAllLogs      = [];
let _mtLastJob      = null;
let _mtFilterText   = "";
let _mtSource       = "har"; // 'har' | 'capture' | 'swagger'
let _mtSwaggerRaw   = null;  // original OpenAPI object for subset scan
let _mtBaseUrl      = "";
let _mtAborting     = false;

// ── Tab switch ────────────────────────────────────────────────────────────────
function mtSwitchTab(tab) {
  document.getElementById("mt-tab-capture").classList.toggle("active", tab === "capture");
  document.getElementById("mt-tab-results").classList.toggle("active", tab === "results");
  document.getElementById("mt-tab-capture-content").style.display = tab === "capture" ? "flex" : "none";
  document.getElementById("mt-tab-results-content").style.display = tab === "results"  ? "flex" : "none";
}

// ── Token / pending state ─────────────────────────────────────────────────────
let _mtPendingHar    = null;
let _mtPendingSource = null;  // 'har' | 'capture'
let _mtPendingReqs   = null;
let _mtPendingSwagger = null;

function mtEpKey(ep) {
  if (ep.source === "swagger" && ep.path_template) {
    return "SWAGGER::" + ep.path_template;
  }
  return (ep.method || "GET") + "::" + ep.url;
}

function mtSetupHarInput() {
  const inp = document.getElementById("mt-har-file-input");
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);

      // OpenAPI dropped on HAR button → route to swagger flow
      if (data && data.paths && !data.log) {
        _mtPendingSwagger = data;
        mtShowBaseUrlModal(data);
        inp.value = "";
        return;
      }

      let autoToken = "";
      for (const entry of (data?.log?.entries || [])) {
        for (const h of (entry?.request?.headers || [])) {
          if (h.name.toLowerCase() === "authorization") { autoToken = h.value; break; }
        }
        if (autoToken) break;
      }

      _mtPendingHar    = data;
      _mtPendingSource = "har";
      mtShowTokenModal(autoToken, `HAR loaded · replace token if expired`);
    } catch (e) {
      alert("HAR parse error: " + e.message);
    }
    inp.value = "";
  };
}

function mtSetupSwaggerInput() {
  const inp = document.getElementById("mt-swagger-file-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    try {
      const text = await file.text();
      // YAML not parsed client-side — ask for JSON
      if (/^\s*openapi\s*:/i.test(text) || /^\s*swagger\s*:/i.test(text)) {
        alert("Please import OpenAPI as JSON (not YAML).");
        inp.value = "";
        return;
      }
      const data = JSON.parse(text);
      if (!data.paths) {
        alert("Not a valid OpenAPI/Swagger file (missing 'paths').");
        inp.value = "";
        return;
      }
      _mtPendingSwagger = data;
      mtShowBaseUrlModal(data);
    } catch (e) {
      alert("OpenAPI parse error: " + e.message);
    }
    inp.value = "";
  };
}

function mtShowTokenModal(autoToken, subText) {
  const modal = document.getElementById("mt-token-modal");
  const inp   = document.getElementById("mt-token-modal-input");
  const sub   = document.getElementById("mt-token-modal-sub");
  inp.value   = autoToken || "";
  if (sub) sub.textContent = subText || "";
  modal.style.display = "flex";
  setTimeout(() => inp.focus(), 80);
}

function mtCancelTokenModal() {
  document.getElementById("mt-token-modal").style.display = "none";
  _mtPendingHar = null; _mtPendingSource = null; _mtPendingReqs = null;
}

function mtConfirmToken() {
  const token = document.getElementById("mt-token-modal-input").value.trim();
  document.getElementById("mt-token-modal").style.display = "none";
  const tf = document.getElementById("mt-token-input");
  if (tf) tf.value = token;

  if (_mtPendingSource === "har" && _mtPendingHar) {
    mtLoadFromHar(_mtPendingHar, token);
  } else if (_mtPendingSource === "capture" && _mtPendingReqs) {
    mtLoadReqsFromAV(_mtPendingReqs, token);
  }
  _mtPendingHar = null; _mtPendingSource = null; _mtPendingReqs = null;
}

function mtGuessBaseUrl(spec) {
  try {
    const servers = spec.servers;
    if (Array.isArray(servers) && servers[0]?.url) return String(servers[0].url).replace(/\/$/, "");
    const host = spec.host;
    if (host) {
      const scheme = (spec.schemes && spec.schemes[0]) || "https";
      const basePath = spec.basePath || "";
      return `${scheme}://${host}${basePath}`.replace(/\/$/, "");
    }
  } catch (_) {}
  return "";
}

function mtShowBaseUrlModal(spec) {
  const modal = document.getElementById("mt-baseurl-modal");
  const inp = document.getElementById("mt-baseurl-modal-input");
  if (inp) inp.value = mtGuessBaseUrl(spec) || "";
  modal.style.display = "flex";
  setTimeout(() => inp?.focus(), 80);
}

function mtCancelBaseUrlModal() {
  document.getElementById("mt-baseurl-modal").style.display = "none";
  _mtPendingSwagger = null;
}

async function mtConfirmBaseUrl() {
  const baseUrl = document.getElementById("mt-baseurl-modal-input").value.trim().replace(/\/$/, "");
  if (!baseUrl) { alert("Base URL is required."); return; }
  if (!_mtPendingSwagger) { mtCancelBaseUrlModal(); return; }

  const spec = _mtPendingSwagger;
  document.getElementById("mt-baseurl-modal").style.display = "none";

  try {
    const blob = new Blob([JSON.stringify(spec)], { type: "application/json" });
    const file = new File([blob], "openapi.json", { type: "application/json" });
    const fd = new FormData();
    fd.append("file", file);
    fd.append("base_url", baseUrl);
    fd.append("mode", "swagger");

    const resp = await fetch(`${MT_BASE}/mt/parse`, { method: "POST", body: fd });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Parse failed");
    if (data.needs_base_url) throw new Error("Base URL still required");

    _mtSwaggerRaw = spec;
    _mtBaseUrl = baseUrl;
    _mtSource = "swagger";
    _mtEndpoints = (data.endpoints || []).map(e => ({
      url: e.url,
      method: e.method || (e.allowed && e.allowed[0]) || "GET",
      allowed: e.allowed || [e.method || "GET"],
      path_template: e.path_template || "",
      headers: {},
      body: null,
      source: "swagger",
    }));
    _mtChecked = {};
    _mtEndpoints.forEach(ep => { _mtChecked[mtEpKey(ep)] = true; });

    document.getElementById("mt-capture-count").textContent =
      `${_mtEndpoints.length} endpoints (OpenAPI)`;
    mtRenderEndpointList();
  } catch (e) {
    alert("OpenAPI load failed: " + e.message);
  } finally {
    _mtPendingSwagger = null;
  }
}

function mtLoadFromHar(har, autoToken) {
  const entries = har?.log?.entries || [];
  const STATIC  = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp)(\?|$)/i;

  const seen = new Set();
  _mtEndpoints = [];
  _mtChecked   = {};
  _mtSource = "har";
  _mtSwaggerRaw = null;
  _mtBaseUrl = "";

  for (const entry of entries) {
    const rq  = entry.request || {};
    // Keep query string — required for query-gated APIs
    const url = rq.url || "";
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

    // Preserve postData body for POST/PUT/PATCH baselines
    let body = null;
    const postData = rq.postData;
    if (postData && postData.text && ["POST", "PUT", "PATCH"].includes(method)) {
      body = postData.text;
    }

    _mtEndpoints.push({ url, method, headers, body, source: "har", allowed: [method] });
    _mtChecked[key] = true;
  }

  if (autoToken) {
    const tf = document.getElementById("mt-token-input");
    if (tf && !tf.value.trim()) tf.value = autoToken;
  }

  document.getElementById("mt-capture-count").textContent =
    `${_mtEndpoints.length} endpoints (HAR)`;
  mtRenderEndpointList();
}

// ── Render endpoint list ──────────────────────────────────────────────────────
function mtRenderEndpointList() {
  const list  = document.getElementById("mt-endpoint-list");
  const empty = document.getElementById("mt-endpoint-empty");
  const filter= _mtFilterText.toLowerCase();

  if (!_mtEndpoints.length) {
    list.style.display = "none"; empty.style.display = "flex"; return;
  }
  list.style.display = "flex"; empty.style.display = "none";

  const filtered = filter
    ? _mtEndpoints.filter(ep => ep.url.toLowerCase().includes(filter) ||
        (ep.path_template || "").toLowerCase().includes(filter))
    : _mtEndpoints;

  const MC = {GET:"#3fb950",POST:"#ffa657",PUT:"#d29922",PATCH:"#a5d6ff",DELETE:"#f85149",OPTIONS:"#6e7681",HEAD:"#8b949e",TRACE:"#da3633"};

  list.innerHTML = filtered.map(ep => {
    const key = mtEpKey(ep);
    const checked = _mtChecked[key] !== false;
    const mc = MC[ep.method] || "#8b949e";
    const shortUrl = ep.url.length > 70 ? ep.url.substring(0,70)+"…" : ep.url;
    const allowed = (ep.allowed && ep.allowed.length > 1)
      ? `<span class="mt-ep-allowed">[${ep.allowed.join(", ")}]</span>`
      : "";
    return `
      <div class="mt-ep-row ${checked ? "mt-ep-checked" : ""}" data-ep-key="${escHtml(key)}" onclick="mtToggleEp(this.dataset.epKey, this)">
        <input type="checkbox" class="mt-ep-cb" ${checked ? "checked" : ""}
               onclick="event.stopPropagation(); mtToggleEp(this.closest('.mt-ep-row').dataset.epKey, this.closest('.mt-ep-row'))">
        <span class="mt-ep-method" style="color:${mc};background:${mc}22;border:1px solid ${mc}55">${ep.method}</span>
        <span class="mt-ep-url" title="${escHtml(ep.url)}">${escHtml(shortUrl)}</span>
        ${allowed}
      </div>`;
  }).join("");

  const sel = Object.values(_mtChecked).filter(Boolean).length;
  const btn = document.getElementById("mt-run-btn");
  if (btn) btn.textContent = `🚀 Run Method Tampering (${sel} selected)`;
}

function mtToggleEp(key, row) {
  _mtChecked[key] = !_mtChecked[key];
  row.classList.toggle("mt-ep-checked", _mtChecked[key]);
  const cb = row.querySelector(".mt-ep-cb");
  if (cb) cb.checked = _mtChecked[key];
  const sel = Object.values(_mtChecked).filter(Boolean).length;
  const btn = document.getElementById("mt-run-btn");
  if (btn) btn.textContent = `🚀 Run Method Tampering (${sel} selected)`;
}

function mtSelectAll() {
  const filter = _mtFilterText.toLowerCase();
  const targets = filter
    ? _mtEndpoints.filter(ep => ep.url.toLowerCase().includes(filter))
    : _mtEndpoints;
  targets.forEach(ep => { _mtChecked[mtEpKey(ep)] = true; });
  mtRenderEndpointList();
}

function mtDeselectAll() {
  const filter = _mtFilterText.toLowerCase();
  const targets = filter
    ? _mtEndpoints.filter(ep => ep.url.toLowerCase().includes(filter))
    : _mtEndpoints;
  targets.forEach(ep => { _mtChecked[mtEpKey(ep)] = false; });
  mtRenderEndpointList();
}
function mtFilterCapture() {
  _mtFilterText = document.getElementById("mt-url-filter-input").value;
  mtRenderEndpointList();
}

// ── Run scan ──────────────────────────────────────────────────────────────────
async function mtRunSelected() {
  const selected = _mtEndpoints.filter(ep => _mtChecked[mtEpKey(ep)]);
  if (!selected.length) { alert("Select at least one endpoint."); return; }

  const token = document.getElementById("mt-token-input").value.trim();
  const btn = document.getElementById("mt-run-btn");
  btn.disabled = true; btn.textContent = "⏳ Starting...";

  try {
    let resp, data;
    if (_mtSource === "swagger" && _mtSwaggerRaw) {
      // Build OpenAPI subset with only selected paths
      const paths = {};
      for (const ep of selected) {
        const tpl = ep.path_template;
        if (tpl && _mtSwaggerRaw.paths?.[tpl]) paths[tpl] = _mtSwaggerRaw.paths[tpl];
      }
      if (!Object.keys(paths).length) throw new Error("No matching OpenAPI paths for selection");
      const subset = { ..._mtSwaggerRaw, paths };
      const blob = new Blob([JSON.stringify(subset)], { type: "application/json" });
      const file = new File([blob], "selected_openapi.json", { type: "application/json" });
      const fd = new FormData();
      fd.append("file", file);
      fd.append("token", token);
      fd.append("mode", "swagger");
      fd.append("base_url", _mtBaseUrl);
      resp = await fetch(`${MT_BASE}/mt/scan`, { method: "POST", body: fd });
      data = await resp.json();
    } else {
      // Synthetic HAR — inject token + preserve body + query
      const entries = selected.map(ep => {
        const hdrs = { ...ep.headers };
        if (token && !Object.keys(hdrs).some(k => k.toLowerCase() === "authorization")) {
          hdrs["Authorization"] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
        } else if (token) {
          const key = Object.keys(hdrs).find(k => k.toLowerCase() === "authorization");
          if (key) hdrs[key] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
        }

        const entry = {
          request: {
            method:  ep.method,
            url:     ep.url,
            headers: Object.entries(hdrs).map(([name,value]) => ({name,value})),
          }
        };
        if (ep.body && ["POST","PUT","PATCH"].includes(ep.method)) {
          entry.request.postData = {
            mimeType: "application/json",
            text: typeof ep.body === "string" ? ep.body : JSON.stringify(ep.body),
          };
        }
        return entry;
      });
      const syntheticHar = { log: { entries } };
      const blob = new Blob([JSON.stringify(syntheticHar)], { type: "application/json" });
      const file = new File([blob], "selected.har", { type: "application/json" });
      const fd = new FormData();
      fd.append("file", file);
      fd.append("token", token);
      fd.append("mode", "har");
      resp = await fetch(`${MT_BASE}/mt/scan`, { method: "POST", body: fd });
      data = await resp.json();
    }

    if (!resp.ok) throw new Error(data.detail || "Scan start failed");
    _mtJobId = data.job_id;
    mtSwitchTab("results");
    mtStartScanning(data.total);
  } catch (e) {
    alert("Error: " + e.message);
    btn.disabled = false;
    btn.textContent = `🚀 Run Method Tampering (${selected.length} selected)`;
  }
}

// ── Scanning + Abort ──────────────────────────────────────────────────────────
async function mtAbortScan() {
  if (!_mtJobId || _mtAborting) return;
  _mtAborting = true;
  const abortBtn = document.getElementById("mt-btn-abort");
  if (abortBtn) {
    abortBtn.disabled = true;
    abortBtn.textContent = "Aborting…";
  }
  const title = document.getElementById("mt-scan-title");
  if (title) title.textContent = "⏹ Aborting…";
  try {
    await fetch(`${MT_BASE}/mt/abort/${_mtJobId}`, { method: "POST" });
  } catch (_) { /* poll will still finish */ }
}

function mtStartScanning(total) {
  const overlay = document.getElementById("mt-scanning-overlay");
  const resultsWrap = document.getElementById("mt-results-wrap");
  overlay.style.display = "flex";
  resultsWrap.style.display = "none";
  document.getElementById("mt-results-empty").style.display = "none";
  document.getElementById("mt-scan-fill").style.width = "0%";
  document.getElementById("mt-scan-stats").textContent = `0 / ${total} endpoints`;
  document.getElementById("mt-scan-live-findings").innerHTML = "";
  const title = document.getElementById("mt-scan-title");
  if (title) title.textContent = "🔀 Scanning endpoints...";
  const abortBtn = document.getElementById("mt-btn-abort");
  if (abortBtn) {
    abortBtn.disabled = false;
    abortBtn.textContent = "Abort";
  }
  _mtAborting = false;

  if (_mtPollTimer) clearInterval(_mtPollTimer);
  _mtPollTimer = setInterval(async () => {
    try {
      const resp = await fetch(`${MT_BASE}/mt/progress/${_mtJobId}`);
      const data = await resp.json();
      if (!resp.ok) {
        clearInterval(_mtPollTimer);
        overlay.style.display = "none";
        alert("Scan progress failed — backend may have stopped.");
        const btn = document.getElementById("mt-run-btn");
        const sel = Object.values(_mtChecked).filter(Boolean).length;
        if (btn) { btn.disabled = false; btn.textContent = `🚀 Run Method Tampering (${sel} selected)`; }
        return;
      }

      document.getElementById("mt-scan-fill").style.width = data.progress + "%";
      const abortNote = data.aborted ? " · aborting" : "";
      document.getElementById("mt-scan-stats").textContent =
        `${data.completed} / ${data.total} endpoints · ${data.findings.length} issue(s) · ${data.elapsed}s${abortNote}`;

      if (data.findings.length) {
        document.getElementById("mt-scan-live-findings").innerHTML =
          data.findings.slice(0, 6).map(f =>
            `<div class="mt-live-finding">${mtSevBadge(f.severity)} ${mtMethodBadge(f.method)}
             <span class="mt-live-url">${escHtml(f.url.substring(0, 70))}</span></div>`
          ).join("") + (data.findings.length > 6 ? `<div class="mt-live-more">+${data.findings.length - 6} more...</div>` : "");
      }

      if (data.status === "done") {
        clearInterval(_mtPollTimer);
        _mtAllFindings = data.findings;
        _mtAllLogs     = data.logs || [];
        _mtLastJob     = data;
        overlay.style.display = "none";
        mtShowResults(data);
        const btn = document.getElementById("mt-run-btn");
        const sel = Object.values(_mtChecked).filter(Boolean).length;
        if (btn) { btn.disabled = false; btn.textContent = `🚀 Run Method Tampering (${sel} selected)`; }
        _mtAborting = false;
      }
    } catch (e) {
      clearInterval(_mtPollTimer);
      overlay.style.display = "none";
      alert("Scan poll error: " + (e.message || e));
      const btn = document.getElementById("mt-run-btn");
      const sel = Object.values(_mtChecked).filter(Boolean).length;
      if (btn) { btn.disabled = false; btn.textContent = `🚀 Run Method Tampering (${sel} selected)`; }
      _mtAborting = false;
    }
  }, 800);
}

// ── Results ───────────────────────────────────────────────────────────────────
function mtShowResults(data) {
  document.getElementById("mt-results-wrap").style.display = "flex";
  const high  = data.findings.filter(f => f.severity === "HIGH").length;
  const med   = data.findings.filter(f => f.severity === "MEDIUM").length;
  const low   = data.findings.filter(f => f.severity === "LOW").length;
  const clean = _mtAllLogs.filter(l => !l.severity || l.severity === "").length;

  document.getElementById("mt-summary-cards").innerHTML = `
    <div class="mt-card mt-card-red"><div class="mt-card-num">${high}</div><div class="mt-card-lbl">HIGH</div></div>
    <div class="mt-card mt-card-orange"><div class="mt-card-num">${med}</div><div class="mt-card-lbl">MEDIUM</div></div>
    <div class="mt-card mt-card-blue"><div class="mt-card-num">${low}</div><div class="mt-card-lbl">LOW</div></div>
    <div class="mt-card mt-card-green"><div class="mt-card-num">${clean}</div><div class="mt-card-lbl">CLEAN</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${data.total}</div><div class="mt-card-lbl">ENDPOINTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${_mtAllLogs.length}</div><div class="mt-card-lbl">REQUESTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${data.elapsed}s</div><div class="mt-card-lbl">DURATION</div></div>
  `;

  document.getElementById("mt-filter-all").textContent    = `All (${_mtAllLogs.length})`;
  document.getElementById("mt-filter-HIGH").textContent   = `🔴 High (${high})`;
  document.getElementById("mt-filter-MEDIUM").textContent = `🟡 Medium (${med})`;
  document.getElementById("mt-filter-LOW").textContent    = `🔵 Low (${low})`;
  document.getElementById("mt-filter-clean").textContent  = `✅ Clean (${clean})`;

  document.querySelectorAll(".mt-filter-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("mt-filter-all").classList.add("active");
  mtRenderTable(_mtAllLogs);

  const existingWarn = document.getElementById("mt-token-expired-warn");
  if (existingWarn) existingWarn.remove();
  const existingAbort = document.getElementById("mt-aborted-warn");
  if (existingAbort) existingAbort.remove();

  if (data.aborted) {
    const warn = document.createElement("div");
    warn.id = "mt-aborted-warn";
    warn.style.cssText = "background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.35);border-radius:6px;color:#f85149;padding:10px 14px;font-size:12px;margin-bottom:12px;flex-shrink:0";
    const why = data.abort_reason === "auth_401"
      ? "Stopped early after 401 (token rejected)."
      : "Scan aborted — showing partial results.";
    warn.textContent = "⏹ " + why;
    const wrap = document.getElementById("mt-results-wrap");
    if (wrap) wrap.insertBefore(warn, wrap.firstChild);
  }

  const allUnauth = _mtAllLogs.length > 0 && _mtAllLogs.every(l => {
    const s = parseInt(l.original_status); return s === 401 || s === 403;
  });
  const emptyLogs = _mtAllLogs.length === 0 && data.total > 0;
  if (allUnauth || emptyLogs) {
    const warn = document.createElement("div");
    warn.id = "mt-token-expired-warn";
    warn.style.cssText = "background:rgba(210,153,34,.15);border:1px solid rgba(210,153,34,.4);border-radius:6px;color:#d29922;padding:10px 14px;font-size:12px;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-shrink:0";
    warn.innerHTML = allUnauth
      ? "⚠️ All requests returned 401/403 — <b style='margin-left:4px'>token is expired or invalid.</b>&nbsp; Update your token and retry."
      : "⚠️ No requests were tested — <b style='margin-left:4px'>token may be expired.</b>&nbsp; Update your token and retry.";
    const wrap = document.getElementById("mt-results-wrap");
    if (wrap) wrap.insertBefore(warn, wrap.firstChild);
  }
}

function mtFilterResults(sev) {
  document.querySelectorAll(".mt-filter-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("mt-filter-"+sev)?.classList.add("active");
  const rows = sev === "all"   ? _mtAllLogs
             : sev === "clean" ? _mtAllLogs.filter(l => !l.severity || l.severity === "")
             : _mtAllLogs.filter(l => l.severity === sev);
  mtRenderTable(rows);
}

function mtShellQuote(s) {
  return String(s).replace(/'/g, `'\\''`);
}

function mtBuildCurl(method, url, headers, body) {
  const m = (method || "GET").toUpperCase();
  let c = m === "GET" ? `curl '${mtShellQuote(url)}'` : `curl -X ${m} '${mtShellQuote(url)}'`;
  for (const [k, v] of Object.entries(headers || {})) {
    if (/^(content-length|host|connection|transfer-encoding)$/i.test(k)) continue;
    c += ` \\\n  -H '${mtShellQuote(k)}: ${mtShellQuote(v)}'`;
  }
  if (body && ["POST", "PUT", "PATCH"].includes(m)) {
    const bodyStr = typeof body === "object" ? JSON.stringify(body) : String(body);
    if (bodyStr && bodyStr !== "null") c += ` \\\n  --data-raw '${mtShellQuote(bodyStr)}'`;
  }
  return c;
}

/** Resolve headers/body for a log row — prefer backend fields, else Capture list. */
function mtResolveReqMeta(r, which) {
  // which: "tested" | "original"
  if (which === "original") {
    if (r.orig_req_headers) {
      return { headers: r.orig_req_headers, body: r.orig_req_body || "" };
    }
  } else if (r.req_headers) {
    return { headers: r.req_headers, body: r.req_body || "" };
  }

  // Fallback for older jobs / mid-session without req_* fields
  const ep = _mtEndpoints.find(e =>
    e.url === r.url ||
    (e.path_template && r.path_template && e.path_template === r.path_template)
  );
  const headers = { ...(ep?.headers || {}) };
  const token = (document.getElementById("mt-token-input")?.value || "").trim();
  if (token && !Object.keys(headers).some(k => k.toLowerCase() === "authorization")) {
    headers["Authorization"] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
  }
  const method = which === "original" ? r.original_method : r.tested_method;
  const body = ["POST", "PUT", "PATCH"].includes((method || "").toUpperCase())
    ? (ep?.body ?? "")
    : "";
  return { headers, body };
}

function mtCopyCurl(btn) {
  const encoded = btn?.getAttribute("data-curl") || "";
  let curl = "";
  try { curl = decodeURIComponent(encoded); } catch (_) { curl = encoded; }
  if (!curl) return;
  const orig = btn.textContent;
  const done = () => {
    btn.textContent = "✓ Copied!";
    setTimeout(() => { btn.textContent = orig; }, 1400);
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

function mtRenderTable(rows) {
  const tbody = document.getElementById("mt-results-tbody");
  if (!rows.length) { tbody.innerHTML = `<tr><td colspan="8" class="mt-empty-row">No results.</td></tr>`; return; }
  const stCls = n => isNaN(parseInt(n)) ? "mt-status-err" : (200<=n&&n<300)?"mt-status-2xx":(400<=n&&n<500)?"mt-status-4xx":"mt-status-5xx";
  tbody.innerHTML = rows.map((r,i) => {
    const isIssue = r.severity && r.severity !== "";
    const sevCell = isIssue ? mtSevBadge(r.severity) : `<span class="mt-clean-badge">✓ OK</span>`;
    const sc = parseInt(r.tested_status), oc = parseInt(r.original_status);
    const diffCell = r.body_diff==="CHANGED" ? `<span class="mt-diff-changed">CHANGED</span>` : `<span class="mt-diff-same">SAME</span>`;
    const shortUrl = r.url.length > 50 ? r.url.substring(0,50)+"…" : r.url;
    const uid = `mtrow-${i}`;

    const testedMeta = mtResolveReqMeta(r, "tested");
    const origMeta   = mtResolveReqMeta(r, "original");
    const testedCurl = encodeURIComponent(mtBuildCurl(r.tested_method, r.url, testedMeta.headers, testedMeta.body));
    const origCurl   = encodeURIComponent(mtBuildCurl(r.original_method, r.url, origMeta.headers, origMeta.body));

    return `
      <tr class="mt-result-row ${isIssue ? `mt-row-issue mt-row-${r.severity.toLowerCase()}` : "mt-row-clean"}"
          onclick="mtToggleExpand('${uid}')" style="cursor:pointer">
        <td class="mt-td-num">${i+1}</td>
        <td><span class="${stCls(oc)} mt-orig-method">${r.original_method}</span></td>
        <td>${mtMethodBadge(r.tested_method)}</td>
        <td class="mt-td-url" title="${escHtml(r.url)}">${escHtml(shortUrl)}</td>
        <td><span class="${stCls(oc)} mt-status-badge">${r.original_status}</span></td>
        <td><span class="${stCls(sc)} mt-status-badge">${r.tested_status}</span></td>
        <td>${sevCell}</td>
        <td class="mt-td-reason">${isIssue ? escHtml(r.reason) : diffCell}</td>
      </tr>
      <tr class="mt-expand-row" id="${uid}" style="display:none">
        <td colspan="8" class="mt-expand-cell">
          <div class="mt-response-grid">
            <div class="mt-resp-panel">
              <div class="mt-resp-label">
                <span>📥 Original <span class="mt-resp-method">${r.original_method} → ${r.original_status}</span> <span class="mt-resp-ms">${r.original_time_ms}ms</span></span>
                <button type="button" class="btn-sm as-rd-curl-btn mt-copy-curl-btn"
                        data-curl="${origCurl}" onclick="event.stopPropagation(); mtCopyCurl(this)" title="Copy original request as cURL">📋 Copy cURL</button>
              </div>
              <pre class="mt-resp-body">${escHtml((r.original_response||"(empty)").substring(0,2000))}</pre>
            </div>
            <div class="mt-resp-panel">
              <div class="mt-resp-label">
                <span>📤 Tested <span class="mt-resp-method">${r.tested_method} → ${r.tested_status}</span> <span class="mt-resp-ms">${r.tested_time_ms}ms</span></span>
                <button type="button" class="btn-sm as-rd-curl-btn mt-copy-curl-btn"
                        data-curl="${testedCurl}" onclick="event.stopPropagation(); mtCopyCurl(this)" title="Copy tested request as cURL (for manual validation)">📋 Copy cURL</button>
              </div>
              <pre class="mt-resp-body">${escHtml((r.tested_response||"(empty)").substring(0,2000))}</pre>
            </div>
          </div>
        </td>
      </tr>`;
  }).join("");
}

function mtToggleExpand(uid) {
  const row = document.getElementById(uid); if (!row) return;
  const isOpen = row.style.display !== "none";
  document.querySelectorAll(".mt-expand-row").forEach(r => r.style.display = "none");
  document.querySelectorAll(".mt-result-row").forEach(r => r.classList.remove("mt-row-selected"));
  if (!isOpen) { row.style.display = "table-row"; row.previousElementSibling?.classList.add("mt-row-selected"); }
}

// ── Export ────────────────────────────────────────────────────────────────────
async function mtDownloadCsv() {
  if (!_mtJobId) return;
  try {
    const resp = await fetch(`${MT_BASE}/mt/csv/${_mtJobId}`);
    const text = await resp.text();
    const ts = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
    if (window.pywebview?.api?.save_file) {
      await window.pywebview.api.save_file(text, `method_tampering_${ts}.csv`);
    } else {
      const a = document.createElement("a");
      a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(text);
      a.download = `method_tampering_${ts}.csv`; a.click();
    }
  } catch(e) { alert("CSV failed: " + e.message); }
}

async function mtDownloadHtml() {
  if (!_mtLastJob) return;
  const html = mtGenerateHtml(_mtLastJob, _mtAllLogs);
  const ts = new Date().toISOString().replace(/[:.]/g,"").substring(0,15);
  if (window.pywebview?.api?.save_file) {
    await window.pywebview.api.save_file(html, `method_tampering_${ts}.html`);
  } else {
    const a = document.createElement("a");
    a.href = "data:text/html;charset=utf-8," + encodeURIComponent(html);
    a.download = `method_tampering_${ts}.html`; a.click();
  }
}

function mtGenerateHtml(data, logs) {
  const findings = data.findings;
  const ts = new Date().toLocaleString();
  const SC={HIGH:"#f85149",MEDIUM:"#d29922",LOW:"#58a6ff"};
  const MC={GET:"#3fb950",POST:"#ffa657",PUT:"#d29922",PATCH:"#a5d6ff",DELETE:"#f85149",OPTIONS:"#6e7681",HEAD:"#8b949e",TRACE:"#da3633"};
  const sB=s=>{const c=SC[s]||"#8b949e";return`<span style="background:${c};color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">${s}</span>`;};
  const mB=m=>{const c=MC[m]||"#8b949e";return`<span style="background:${c}22;color:${c};border:1px solid ${c}55;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700">${m}</span>`;};
  const stB=c=>{const n=parseInt(c);const col=(200<=n&&n<300?"#3fb950":400<=n&&n<500?"#d29922":"#f85149");return`<span style="background:${col}22;color:${col};padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700">${c}</span>`;};
  const high=findings.filter(f=>f.severity==="HIGH"), medium=findings.filter(f=>f.severity==="MEDIUM"), low=findings.filter(f=>f.severity==="LOW");
  const fRows=items=>!items.length?`<tr><td colspan="7" style="color:#8b949e;padding:12px;font-style:italic">No findings.</td></tr>`:items.map((f,i)=>`<tr><td style="color:#8b949e">${i+1}</td><td>${mB(f.method)}</td><td><code style="font-size:10px;color:#79c0ff;word-break:break-all">${escHtml(f.url)}</code></td><td>${stB(f.status)}</td><td>${sB(f.severity)}</td><td style="font-size:11px;color:#e3b341">${escHtml(f.reason)}</td><td style="font-size:10px;color:${f.body_diff==="CHANGED"?"#f85149":"#6e7681"}">${f.body_diff}</td></tr>`).join("");
  const allRows=logs.map((r,i)=>{const isIssue=r.severity&&r.severity!=="";return`<tr><td style="color:#8b949e">${i+1}</td><td>${mB(r.original_method)}</td><td>${mB(r.tested_method)}</td><td><code style="font-size:10px;color:#79c0ff;word-break:break-all">${escHtml(r.url)}</code></td><td>${stB(r.original_status)}</td><td>${stB(r.tested_status)}</td><td>${isIssue?sB(r.severity):'<span style="color:#3fb950;font-size:10px;font-weight:700">✓ OK</span>'}</td><td style="font-size:10px;color:#e3b341">${escHtml(r.reason||"")}</td></tr>`;}).join("");
  return`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Method Tampering Report</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,sans-serif;background:#080c10;color:#c9d1d9;padding:24px}h1{font-size:22px;font-weight:800;background:linear-gradient(135deg,#f85149,#ffa657);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.meta{color:#8b949e;font-size:10px;font-family:monospace;margin-top:4px}.cards{display:flex;gap:8px;margin:18px 0;flex-wrap:wrap}.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 16px;text-align:center}.card h3{font-size:22px;font-weight:800;margin-bottom:2px}.card.red h3{color:#f85149}.card.orange h3{color:#d29922}.card.blue h3{color:#58a6ff}.card.grey h3{color:#8b949e}.card p{font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}.section{margin-bottom:24px}.sh{padding:7px 12px;border-radius:6px 6px 0 0;font-size:12px;font-weight:700;border-left:3px solid}.sh.high{background:#1a0808;border-color:#f85149;color:#f85149}.sh.medium{background:#1a1400;border-color:#d29922;color:#d29922}.sh.low{background:#0a1120;border-color:#58a6ff;color:#58a6ff}.sh.all{background:#161b22;border-color:#8b949e;color:#8b949e}table{border-collapse:collapse;width:100%;background:#0d1117;border:1px solid #21262d;border-top:none;font-size:11px}th{background:#161b22;color:#8b949e;padding:7px 9px;text-align:left;border-bottom:1px solid #30363d;font-size:9px;text-transform:uppercase;letter-spacing:.5px;font-weight:700}td{padding:6px 9px;border-bottom:1px solid #161b22;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#161b22}</style></head><body>
<h1>🔀 Method Tampering Report</h1>
<p class="meta">Generated: ${ts} | Endpoints: ${data.total} | Requests: ${logs.length} | Duration: ${data.elapsed}s${data.aborted ? " | ABORTED" : ""}</p>
<div class="cards"><div class="card red"><h3>${high.length}</h3><p>High</p></div><div class="card orange"><h3>${medium.length}</h3><p>Medium</p></div><div class="card blue"><h3>${low.length}</h3><p>Low</p></div><div class="card grey"><h3>${findings.length}</h3><p>Issues</p></div><div class="card grey"><h3>${data.total}</h3><p>Endpoints</p></div></div>
<div class="section"><div class="sh high">🚨 HIGH</div><table><tr><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Severity</th><th>Reason</th><th>Body Diff</th></tr>${fRows(high)}</table></div>
<div class="section"><div class="sh medium">⚠️ MEDIUM</div><table><tr><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Severity</th><th>Reason</th><th>Body Diff</th></tr>${fRows(medium)}</table></div>
<div class="section"><div class="sh low">ℹ️ LOW</div><table><tr><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Severity</th><th>Reason</th><th>Body Diff</th></tr>${fRows(low)}</table></div>
<div class="section"><div class="sh all">📋 All Requests (${logs.length})</div><table><tr><th>#</th><th>Original</th><th>Tested</th><th>URL</th><th>Orig Status</th><th>Test Status</th><th>Result</th><th>Reason</th></tr>${allRows}</table></div>
</body></html>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function mtSevBadge(s) {
  const c={HIGH:"#f85149",MEDIUM:"#d29922",LOW:"#58a6ff"}[s]||"#8b949e";
  return`<span class="mt-sev-badge" style="background:${c};color:#fff">${s}</span>`;
}
function mtMethodBadge(m) {
  const c={GET:"#3fb950",POST:"#ffa657",PUT:"#d29922",PATCH:"#a5d6ff",DELETE:"#f85149",OPTIONS:"#6e7681",HEAD:"#8b949e",TRACE:"#da3633"}[m]||"#8b949e";
  return`<span class="mt-method-badge" style="background:${c}22;color:${c};border:1px solid ${c}55">${m}</span>`;
}
function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  mtSetupHarInput();
  mtSetupSwaggerInput();
});

// ── Reset ─────────────────────────────────────────────────────────────────────
function mtReset() {
  clearInterval(_mtPollTimer);
  _mtEndpoints = []; _mtChecked = {}; _mtJobId = null;
  _mtAllFindings = []; _mtAllLogs = []; _mtLastJob = null; _mtFilterText = "";
  _mtSource = "har"; _mtSwaggerRaw = null; _mtBaseUrl = ""; _mtAborting = false;
  document.getElementById("mt-capture-count").textContent = "0 endpoints";
  document.getElementById("mt-url-filter-input").value = "";
  document.getElementById("mt-token-input").value = "";
  document.getElementById("mt-endpoint-list").innerHTML = "";
  document.getElementById("mt-endpoint-list").style.display = "none";
  document.getElementById("mt-endpoint-empty").style.display = "flex";
  document.getElementById("mt-results-wrap").style.display = "none";
  document.getElementById("mt-results-empty").style.display = "flex";
  document.getElementById("mt-scanning-overlay").style.display = "none";
  const btn = document.getElementById("mt-run-btn");
  if (btn) { btn.disabled = false; btn.textContent = "🚀 Run Method Tampering (0 selected)"; }
  mtSwitchTab("capture");
}
window.mtReset = mtReset;
window.mtAbortScan = mtAbortScan;
window.mtConfirmBaseUrl = mtConfirmBaseUrl;
window.mtCancelBaseUrlModal = mtCancelBaseUrlModal;

// ── Load from AV Captured requests ───────────────────────────────────────────
function mtLoadFromCapture() {
  const avState = window._avState;
  const reqs    = avState?.requests || [];
  if (!reqs.length) {
    alert("No requests in API Validator capture.\n\nImport cURL or capture requests in API Validator Pro tab first.");
    return;
  }

  let autoToken = "";
  for (const r of reqs) {
    const authH = Object.entries(r.headers||{}).find(([k]) => k.toLowerCase() === "authorization");
    if (authH) { autoToken = authH[1]; break; }
  }

  _mtPendingReqs   = reqs;
  _mtPendingSource = "capture";
  mtShowTokenModal(autoToken, `${reqs.length} requests from AV Capture · replace token if expired`);
}

function mtLoadReqsFromAV(reqs, token) {
  const STATIC = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp)(\?|$)/i;
  const seen = new Set();
  _mtEndpoints = []; _mtChecked = {};
  _mtSource = "capture";
  _mtSwaggerRaw = null;
  _mtBaseUrl = "";

  for (const r of reqs) {
    // Keep query string
    const url    = r.url || "";
    const method = (r.method || "GET").toUpperCase();
    if (!url.startsWith("http") || STATIC.test(url)) continue;
    const key = method + "::" + url;
    if (seen.has(key)) continue;
    seen.add(key);

    const hdrs = { ...(r.headers || {}) };
    if (token) {
      const authKey = Object.keys(hdrs).find(k => k.toLowerCase() === "authorization") || "Authorization";
      hdrs[authKey] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
    }

    let body = null;
    if (r.body && ["POST","PUT","PATCH"].includes(method)) {
      body = typeof r.body === "string" ? r.body : JSON.stringify(r.body);
    }

    _mtEndpoints.push({ url, method, headers: hdrs, body, source: "har", allowed: [method] });
    _mtChecked[key] = true;
  }

  document.getElementById("mt-capture-count").textContent = `${_mtEndpoints.length} endpoints (from AV)`;
  mtRenderEndpointList();
}
