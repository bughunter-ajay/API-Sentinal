// ════════════════════════════════════════════════════════════════════════
//  File Upload Security Tester — frontend  (backend: 127.0.0.1:8776)
//  Paste a multipart-upload cURL → replays it with malicious test files →
//  detects unrestricted upload / MIME-ext bypass / traversal / XSS / redirect.
// ════════════════════════════════════════════════════════════════════════

const UPLOAD_BASE = "http://127.0.0.1:8776";

let _upJobId   = null;
let _upPollTimer = null;
let _upFindings  = [];
let _upFilter    = "ALL";
let _upTarget    = "";
let _upSortKey   = null;   // "status" | "verdict" | null
let _upSortDir   = "asc";  // "asc" | "desc"

const _UP_VERDICT_ORDER = {
  ACCEPTED: 0,
  REJECTED_200: 1,
  SERVER_ERROR: 2,
  AUTH_ERROR: 3,
  REJECTED: 4,
  ERROR: 5,
};

function _upEsc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function uploadGoTab(tab) {
  document.getElementById("up-tab-capture").classList.toggle("active", tab === "capture");
  document.getElementById("up-tab-results").classList.toggle("active", tab === "results");
  document.getElementById("up-pane-capture").style.display = tab === "capture" ? "flex" : "none";
  document.getElementById("up-pane-results").style.display = tab === "results" ? "flex" : "none";
}

function uploadClearCurl() {
  document.getElementById("up-curl-input").value = "";
  const e = document.getElementById("up-parse-error");
  if (e) { e.style.display = "none"; e.textContent = ""; }
  const p = document.getElementById("up-parse-preview");
  if (p) p.style.display = "none";
}

// Pull the most recent multipart request from AV Capture as a cURL (best-effort)
async function uploadFromAV() {
  try {
    const r = await fetch("http://127.0.0.1:8765/capture/requests");
    const data = await r.json();
    const list = data.requests || data || [];
    // find a POST whose content-type is multipart/form-data
    const up = [...list].reverse().find(q => {
      const h = q.headers || {};
      const ct = (h["content-type"] || h["Content-Type"] || "").toLowerCase();
      return (q.method || "").toUpperCase() === "POST" && ct.includes("multipart/form-data");
    });
    if (!up) { _upParseError("No multipart upload request found in AV Capture."); return; }
    document.getElementById("up-curl-input").value = _upBuildCurl(up);
    uploadParse();
  } catch (e) {
    _upParseError("Could not reach AV Capture backend.");
  }
}

function _upBuildCurl(req) {
  let c = `curl '${req.url}'`;
  for (const [k, v] of Object.entries(req.headers || {})) c += ` \\\n  -H '${k}: ${v}'`;
  if (req.body) c += ` \\\n  --data-raw $'${req.body}'`;
  return c;
}

function _upParseError(msg) {
  const e = document.getElementById("up-parse-error");
  if (e) { e.textContent = "⚠ " + msg; e.style.display = "inline"; }
}

// Validate the cURL + show what file field was detected
async function uploadParse() {
  const curl = document.getElementById("up-curl-input").value.trim();
  const e = document.getElementById("up-parse-error");
  if (e) { e.style.display = "none"; e.textContent = ""; }
  if (!curl) { _upParseError("Paste a cURL command first."); return false; }
  try {
    const r = await fetch(`${UPLOAD_BASE}/upload/parse`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ curl }),
    });
    if (!r.ok) { _upParseError((await r.json()).detail || "Parse failed."); return false; }
    const d = await r.json();
    const prev = document.getElementById("up-parse-preview");
    const profile = d.profile || "generic";
    const profileColor = {
      excel: "#3fb950", docx: "#a371f7", pptx: "#db61a2", zip: "#d29922",
      image: "#58a6ff", pdf: "#ffa657", generic: "#8b949e",
    }[profile] || "#8b949e";
    const profileHint = {
      excel: "Excel/OOXML suite — baseline starts with valid.xlsx",
      docx:  "Word/DOCX suite — baseline starts with valid.docx",
      pptx:  "PowerPoint suite — baseline starts with valid.pptx",
      zip:   "Archive suite — baseline starts with valid.zip",
      image: "Image suite — JPEG/PNG/GIF baselines first",
      pdf:   "PDF suite — valid.pdf baseline first",
      generic: "Full union suite (family unknown)",
    }[profile] || "";
    const fileHints = (d.fields || [])
      .filter(f => f.is_file)
      .map(f => f.orig_name ? `${f.key}=${f.orig_name}` : f.key)
      .join(", ");
    const multi = (d.file_fields || []).length > 1
      ? `<br><span style="color:#ffa657">Multi-file form: probing <code>${_upEsc(d.file_param)}</code>; other file fields sent as benign companions</span>`
      : "";
    prev.style.display = "block";
    prev.innerHTML = `
      <div style="font-size:11px;color:var(--text2);line-height:1.8">
        <b style="color:var(--green)">✓ Parsed</b> &nbsp;
        <span style="color:var(--text3)">Target:</span>
        ${d.method ? `<code style="color:var(--purple, #bc8cff);font-weight:700">${_upEsc(d.method)}</code> ` : ""}<code style="color:var(--blue)">${_upEsc(d.url)}</code><br>
        <span style="color:var(--text3)">Primary file field:</span>
        <code style="color:#ffa657">${_upEsc(d.file_param)}</code> &nbsp;·&nbsp;
        <span style="color:var(--text3)">${d.fields.length} form field(s), ${d.header_count} header(s)</span>
        ${d.test_count ? ` &nbsp;·&nbsp; <span style="color:var(--text3)">${d.test_count} tests</span>` : ""}
        <br>
        <span style="color:var(--text3)">Detected profile:</span>
        <code style="color:${profileColor};font-weight:700">${_upEsc(profile)}</code>
        ${fileHints ? ` &nbsp;·&nbsp; <span style="color:var(--text3)">${_upEsc(fileHints)}</span>` : ""}
        ${profileHint ? `<br><span style="color:${profileColor}">${_upEsc(profileHint)}</span>` : ""}
        ${multi}
        <br>
        ${d.fields.map(f => `<span class="up-field-pill ${f.is_file ? "up-field-file" : ""}">${_upEsc(f.key)}${f.is_file ? (f.key === d.file_param ? " ★" : " 📎") : ""}</span>`).join(" ")}
      </div>`;
    return true;
  } catch (err) {
    _upParseError("Could not reach the File Upload backend (port 8776).");
    return false;
  }
}

async function uploadStartScan() {
  const curl = document.getElementById("up-curl-input").value.trim();
  if (!curl) { _upParseError("Paste a cURL command first."); return; }
  const ok = await uploadParse();
  if (!ok) return;

  // reset
  _upFindings = []; _upFilter = "ALL"; _upTarget = "";
  _upSortKey = null; _upSortDir = "asc";
  _uploadUpdateSortIndicators();
  document.getElementById("up-scanning-overlay").style.display = "flex";
  document.getElementById("up-scan-stat").textContent = "Starting scan…";
  document.getElementById("up-scan-bar").style.width = "0%";

  try {
    const r = await fetch(`${UPLOAD_BASE}/upload/scan`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ curl }),
    });
    if (!r.ok) {
      document.getElementById("up-scanning-overlay").style.display = "none";
      _upParseError((await r.json()).detail || "Scan failed to start.");
      return;
    }
    _upJobId = (await r.json()).job_id;
    uploadGoTab("results");
    _upPollTimer = setInterval(_uploadPoll, 700);
  } catch (e) {
    document.getElementById("up-scanning-overlay").style.display = "none";
    _upParseError("Could not reach the File Upload backend (port 8776).");
  }
}

function uploadStopScan() {
  if (_upJobId) fetch(`${UPLOAD_BASE}/upload/stop/${_upJobId}`, { method: "POST" });
}

function uploadReset() {
  // Stop any in-progress poll
  if (_upPollTimer) { clearInterval(_upPollTimer); _upPollTimer = null; }
  if (_upJobId) fetch(`${UPLOAD_BASE}/upload/stop/${_upJobId}`, { method: "POST" }).catch(() => {});

  // Reset state
  _upJobId    = null;
  _upFindings = [];
  _upFilter   = "ALL";
  _upTarget   = "";

  // Clear cURL input and parse feedback
  const inp = document.getElementById("up-curl-input");
  if (inp) inp.value = "";
  const e = document.getElementById("up-parse-error");
  if (e) { e.style.display = "none"; e.textContent = ""; }
  const p = document.getElementById("up-parse-preview");
  if (p) { p.style.display = "none"; p.innerHTML = ""; }

  // Hide scanning overlay
  const ov = document.getElementById("up-scanning-overlay");
  if (ov) ov.style.display = "none";
  const bar = document.getElementById("up-scan-bar");
  if (bar) bar.style.width = "0%";
  const stat = document.getElementById("up-scan-stat");
  if (stat) stat.textContent = "Starting…";
  const feed = document.getElementById("up-scan-feed");
  if (feed) feed.innerHTML = "";

  // Clear results pane
  const wrap = document.getElementById("up-results-wrap");
  if (wrap) wrap.style.display = "none";
  const cards = document.getElementById("up-summary-cards");
  if (cards) cards.innerHTML = "";
  const note = document.getElementById("up-accepted-note");
  if (note) note.innerHTML = "";
  const filters = document.getElementById("up-filters");
  if (filters) filters.innerHTML = "";
  const tbody = document.getElementById("up-results-tbody");
  if (tbody) tbody.innerHTML = "";
  const fstat = document.getElementById("up-footer-stat");
  if (fstat) fstat.textContent = "";

  // Return to capture tab
  uploadGoTab("capture");
}

window.uploadReset = uploadReset;

async function _uploadPoll() {
  if (!_upJobId) return;
  try {
    const r = await fetch(`${UPLOAD_BASE}/upload/progress/${_upJobId}`);
    const d = await r.json();

    if (d.error) {
      clearInterval(_upPollTimer);
      document.getElementById("up-scanning-overlay").style.display = "none";
      _upParseError(d.error);
      uploadGoTab("capture");
      return;
    }

    _upFindings = d.findings || [];
    _upTarget   = d.target || "";
    const pct = d.progress || 0;
    document.getElementById("up-scan-bar").style.width = pct + "%";
    document.getElementById("up-scan-stat").textContent =
      `${d.completed}/${d.total} files tested · ${(_upFindings.filter(f => f.verdict === "ACCEPTED").length)} accepted · ${d.elapsed}s`;

    _uploadRenderFeed(d.feed || []);
    _uploadRenderResults(d);

    if (d.status === "done" || d.status === "error") {
      clearInterval(_upPollTimer);
      document.getElementById("up-scanning-overlay").style.display = "none";
    }
  } catch (e) {
    clearInterval(_upPollTimer);
    document.getElementById("up-scanning-overlay").style.display = "none";
  }
}

// Live feed shown during scanning — newest file on top (column-reverse layout)
function _uploadRenderFeed(feed) {
  const el = document.getElementById("up-scan-feed");
  if (!el) return;
  const RC = { CRITICAL: "#f85149", HIGH: "#ffa657", MEDIUM: "#d29922", INFO: "#58a6ff", SAFE: "#6e7681" };
  el.innerHTML = feed.slice().reverse().map(f => {   // newest first, fills top→down
    const st = f.status;
    const stc = (typeof st === "number" && st >= 200 && st < 300) ? "#3fb950"
              : (typeof st === "number" && st >= 400 && st < 500) ? "#d29922" : "#f85149";
    const accepted = f.verdict === "ACCEPTED";
    const dot = accepted ? "🔴" : "🟢";
    const name = f.send_filename !== f.filename ? `${f.filename} → ${f.send_filename}` : f.filename;
    return `<div style="display:flex;align-items:center;gap:8px;padding:1px 0">
      <span>${dot}</span>
      <span style="color:${RC[f.risk] || '#8b949e'};min-width:64px">${_upEsc(f.risk)}</span>
      <span style="color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_upEsc(name)}</span>
      <span style="color:${stc};font-weight:700;min-width:34px;text-align:right">${_upEsc(st)}</span>
      <span style="color:${accepted ? '#f85149' : '#3fb950'};min-width:78px;text-align:right">${_upEsc(f.verdict)}</span>
    </div>`;
  }).join("");
}

function _uploadRenderResults(d) {
  const wrap = document.getElementById("up-results-wrap");
  if (wrap) wrap.style.display = "flex";

  const f = _upFindings;
  const count = lvl => f.filter(x => x.risk === lvl).length;
  const crit = count("CRITICAL"), high = count("HIGH"), med = count("MEDIUM");
  const safe = f.filter(x => x.verdict !== "ACCEPTED").length;
  const acc  = f.filter(x => x.verdict === "ACCEPTED").length;

  document.getElementById("up-summary-cards").innerHTML = `
    <div class="mt-card mt-card-red"><div class="mt-card-num">${crit}</div><div class="mt-card-lbl">CRITICAL</div></div>
    <div class="mt-card mt-card-orange"><div class="mt-card-num">${high}</div><div class="mt-card-lbl">HIGH</div></div>
    <div class="mt-card mt-card-yellow"><div class="mt-card-num">${med}</div><div class="mt-card-lbl">MEDIUM</div></div>
    <div class="mt-card mt-card-red"><div class="mt-card-num">${acc}</div><div class="mt-card-lbl">ACCEPTED</div></div>
    <div class="mt-card mt-card-green"><div class="mt-card-num">${safe}</div><div class="mt-card-lbl">BLOCKED</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${f.length}</div><div class="mt-card-lbl">TESTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${d.elapsed || 0}s</div><div class="mt-card-lbl">DURATION</div></div>`;

  // accepted-types note + detected profile
  const at = d.accepted_types || [];
  const note = document.getElementById("up-accepted-note");
  if (note) {
    const prof = d.profile ? `<span style="color:var(--text3)">Profile:</span> <code class="up-acc-pill">${_upEsc(d.profile)}</code> &nbsp;` : "";
    note.innerHTML = at.length
      ? `${prof}<b style="color:var(--blue)">Server accepts:</b> ${at.map(t => `<code class="up-acc-pill">${_upEsc(t)}</code>`).join(" ")}`
      : `${prof}<span style="color:var(--text3)">No baseline types accepted yet…</span>`;
  }

  const redir = f.filter(x => x.category === "redirect_content").length;
  const redirAcc = f.filter(x => x.category === "redirect_content" && x.verdict === "ACCEPTED").length;
  const filters = [
    ["ALL", "All", f.length],
    ["CRITICAL", "💀 Critical", crit],
    ["HIGH", "🚨 High", high],
    ["MEDIUM", "⚠️ Medium", med],
    ["ACCEPTED", "✓ Accepted", acc],
    ["REDIRECT", "🔀 Redirect", redir],
  ];
  document.getElementById("up-filters").innerHTML = filters.map(([k, lbl, n]) =>
    `<button class="mt-filter-btn ${_upFilter === k ? "active" : ""}" onclick="uploadFilter('${k}')">${lbl} (${n})</button>`
  ).join("");

  const fstat = document.getElementById("up-footer-stat");
  if (fstat) {
    fstat.textContent = _upTarget
      ? `${f.length} tests · ${acc} accepted · ${redir} redirect payload${redir === 1 ? "" : "s"}`
        + (redirAcc ? ` (${redirAcc} accepted ⚠)` : "")
      : "";
  }

  _uploadRenderTable();
}

function uploadFilter(k) {
  _upFilter = k;
  document.querySelectorAll("#tool-upload .mt-filter-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("onclick") === `uploadFilter('${k}')`);
  });
  _uploadRenderTable();
}

function uploadSortBy(key) {
  if (_upSortKey === key) {
    _upSortDir = _upSortDir === "asc" ? "desc" : "asc";
  } else {
    _upSortKey = key;
    // Status: low→high first; Verdict: ACCEPTED first (most interesting)
    _upSortDir = key === "verdict" ? "asc" : "asc";
  }
  _uploadUpdateSortIndicators();
  _uploadRenderTable();
}

function _uploadUpdateSortIndicators() {
  const statusEl = document.getElementById("up-sort-status");
  const verdictEl = document.getElementById("up-sort-verdict");
  if (statusEl) statusEl.textContent = _upSortKey === "status" ? (_upSortDir === "asc" ? "▲" : "▼") : "";
  if (verdictEl) verdictEl.textContent = _upSortKey === "verdict" ? (_upSortDir === "asc" ? "▲" : "▼") : "";
  document.querySelectorAll("#tool-upload .up-sort-th").forEach(th => {
    const active = th.getAttribute("data-up-sort") === _upSortKey;
    th.style.color = active ? "var(--blue)" : "var(--text3)";
  });
}

function _uploadStatusSortVal(st) {
  if (typeof st === "number" && !isNaN(st)) return st;
  const n = parseInt(st, 10);
  if (!isNaN(n)) return n;
  // ERROR / non-numeric → after HTTP codes
  return 9999;
}

function _uploadSortRows(rows) {
  if (!_upSortKey) return rows;
  const dir = _upSortDir === "asc" ? 1 : -1;
  return rows.slice().sort((a, b) => {
    let cmp = 0;
    if (_upSortKey === "status") {
      cmp = _uploadStatusSortVal(a.status) - _uploadStatusSortVal(b.status);
      if (cmp === 0) cmp = String(a.status).localeCompare(String(b.status));
    } else if (_upSortKey === "verdict") {
      const va = _UP_VERDICT_ORDER[a.verdict] ?? 50;
      const vb = _UP_VERDICT_ORDER[b.verdict] ?? 50;
      cmp = va - vb;
      if (cmp === 0) cmp = String(a.verdict || "").localeCompare(String(b.verdict || ""));
    }
    if (cmp === 0) cmp = String(a.filename || "").localeCompare(String(b.filename || ""));
    return cmp * dir;
  });
}

function _uploadRenderTable() {
  const tbody = document.getElementById("up-results-tbody");
  if (!tbody) return;
  let rows = _upFindings;
  if (_upFilter === "ACCEPTED") rows = rows.filter(r => r.verdict === "ACCEPTED");
  else if (_upFilter === "REDIRECT") rows = rows.filter(r => r.category === "redirect_content");
  else if (_upFilter !== "ALL") rows = rows.filter(r => r.risk === _upFilter);

  rows = _uploadSortRows(rows);
  _uploadUpdateSortIndicators();

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:24px">No findings for this filter.</td></tr>`;
    return;
  }

  const RC = { CRITICAL: "#da3633", HIGH: "#f85149", MEDIUM: "#d29922", INFO: "#58a6ff", SAFE: "#3fb950" };
  const VC = { ACCEPTED: "#f85149", REJECTED_200: "#d29922", REJECTED: "#3fb950", AUTH_ERROR: "#6e7681", SERVER_ERROR: "#ffa657" };

  tbody.innerHTML = rows.map((r, idx) => {
    const uid = "up-exp-" + idx;
    const rc = RC[r.risk] || "#8b949e";
    const vc = VC[r.verdict] || "#8b949e";
    const st = r.status;
    const stc = (typeof st === "number" && st >= 200 && st < 300) ? "#3fb950"
              : (typeof st === "number" && st >= 400 && st < 500) ? "#d29922" : "#f85149";
    const sentNote = r.send_filename !== r.filename
      ? `<br><span style="color:#ffa657;font-size:10px">↳ sends: ${_upEsc(r.send_filename)}</span>` : "";
    return `
      <tr class="mt-result-row" onclick="uploadToggleExpand('${uid}')" style="cursor:pointer">
        <td style="color:var(--text3);font-family:var(--mono);font-size:11px">${idx + 1}</td>
        <td><span style="background:${rc};color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">${r.risk}</span></td>
        <td><code style="font-size:11px;color:#79c0ff">${_upEsc(r.filename)}</code>${sentNote}</td>
        <td style="font-size:11px;color:var(--text2)">${_upEsc(r.description)}</td>
        <td><code style="font-size:10px;color:var(--text3)">${_upEsc(r.content_type)}</code></td>
        <td><span style="color:${stc};font-family:var(--mono);font-size:11px;font-weight:700">${_upEsc(st)}</span></td>
        <td><span style="background:${vc}22;color:${vc};border:1px solid ${vc}44;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">${r.verdict}</span></td>
      </tr>
      <tr class="mt-expand-row" id="${uid}" style="display:none">
        <td colspan="7" class="mt-expand-cell">
          <div class="mt-response-grid">
            <div class="mt-resp-panel">
              <div class="mt-resp-label">📤 REQUEST <span class="mt-resp-method">multipart</span></div>
              <pre class="mt-resp-body">${_upEsc(r.req_preview || "")}</pre>
            </div>
            <div class="mt-resp-panel">
              <div class="mt-resp-label">📥 RESPONSE <span class="mt-resp-method">${_upEsc(st)}</span>
                <span class="mt-resp-ms">${r.response_len}b · ${r.elapsed}s</span></div>
              <pre class="mt-resp-body">${_upEsc(r.response || "(empty)")}</pre>
            </div>
          </div>
        </td>
      </tr>`;
  }).join("");
}

function uploadToggleExpand(uid) {
  const row = document.getElementById(uid);
  if (!row) return;
  const open = row.style.display !== "none";
  document.querySelectorAll("#tool-upload .mt-expand-row").forEach(r => r.style.display = "none");
  row.style.display = open ? "none" : "table-row";
}

async function uploadExportCsv() {
  if (!_upJobId) return;
  try {
    const r = await fetch(`${UPLOAD_BASE}/upload/csv/${_upJobId}`);
    const d = await r.json();
    _upDownload(d.csv, d.filename || "upload_scan.csv", "text/csv");
  } catch (e) {}
}

async function uploadExportHtml() {
  if (!_upJobId) return;
  try {
    const r = await fetch(`${UPLOAD_BASE}/upload/html/${_upJobId}`);
    const d = await r.json();
    _upDownload(d.html, d.filename || "upload_scan.html", "text/html");
  } catch (e) {}
}

function _upDownload(content, filename, mime) {
  // Prefer the native save dialog (pywebview) if present
  if (window.pywebview && window.pywebview.api && window.pywebview.api.save_file) {
    window.pywebview.api.save_file(content, filename);
    return;
  }
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
