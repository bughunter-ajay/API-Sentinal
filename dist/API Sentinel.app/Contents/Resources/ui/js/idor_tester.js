// ── IDOR Tester Frontend ──────────────────────────────────────────────────────
const IDOR_BASE = "http://127.0.0.1:8773";

let _idorEntries      = [];   // raw {method, url, headers} entries
let _idorWeakRows     = [];   // detected weak endpoints (Capture tab)
let _idorScanWeakRows = [];   // weak endpoints tested in scan (from backend)
let _idorJobId        = null;
let _idorPollTimer  = null;
let _idorAllLogs    = [];
let _idorFindings   = [];
let _idorLastJob    = null;

let _idorPendingEntries = null;
let _idorPendingSrc     = null;
let _idorChecked        = {};   // {method+"::"+url: bool}
let _idorFilterText     = "";
let _idorTagFilter      = "ALL";
let _idorScanActive     = false; // true from scan-start until status:"done" (normal finish or stop)

// ── Tab switch ────────────────────────────────────────────────────────────────
function idorSwitchTab(tab) {
  document.getElementById("idor-tab-capture").classList.toggle("active", tab === "capture");
  document.getElementById("idor-tab-results").classList.toggle("active", tab === "results");
  document.getElementById("idor-tab-capture-content").style.display = tab === "capture" ? "flex" : "none";
  document.getElementById("idor-tab-results-content").style.display = tab === "results"  ? "flex" : "none";
  _idorSyncScanModalVisibility();
}

// The scanning popup only ever shows over the Capture tab — Results already
// has the live-growing table itself, so the popup would just be redundant
// (and in-the-way) there. Call this any time the tab or scan state changes.
function _idorSyncScanModalVisibility() {
  const modal = document.getElementById("idor-scanning-modal");
  if (!modal) return;
  const onCapture = document.getElementById("idor-tab-capture").classList.contains("active");
  modal.style.display = (_idorScanActive && onCapture) ? "flex" : "none";
}

// ── Two-token modal ───────────────────────────────────────────────────────────
function _idorShowTokenModal(token1, subText) {
  const modal = document.getElementById("idor-token-modal");
  const t1inp = document.getElementById("idor-token1-modal-input");
  const sub   = document.getElementById("idor-token-sub");
  if (t1inp) t1inp.value = token1 || "";
  document.getElementById("idor-token2-modal-input").value = "";
  if (sub) sub.textContent = subText || "";
  modal.style.display = "flex";
  setTimeout(() => t1inp?.focus(), 80);
}

function idorCancelToken() {
  document.getElementById("idor-token-modal").style.display = "none";
  _idorPendingEntries = null; _idorPendingSrc = null;
}

function idorConfirmToken() {
  const t1 = document.getElementById("idor-token1-modal-input").value.trim();
  const t2 = document.getElementById("idor-token2-modal-input").value.trim();
  document.getElementById("idor-token-modal").style.display = "none";
  // Push to footer fields
  const f1 = document.getElementById("idor-token1-input"); if (f1) f1.value = t1;
  const f2 = document.getElementById("idor-token2-input"); if (f2) f2.value = t2;
  if (_idorPendingEntries) {
    _idorLoadEntries(_idorPendingEntries, t1, t2);
  }
  _idorPendingEntries = null; _idorPendingSrc = null;
}

// ── HAR input setup ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const inp = document.getElementById("idor-har-input");
  if (!inp) return;
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    try {
      const text = await file.text();
      const har  = JSON.parse(text);
      // Auto-extract owner token from first Authorization header
      let autoToken = "";
      for (const entry of (har?.log?.entries || [])) {
        for (const h of (entry?.request?.headers || [])) {
          if (h.name.toLowerCase() === "authorization") { autoToken = h.value; break; }
        }
        if (autoToken) break;
      }
      const entries = (har?.log?.entries || []).map(e => ({
        method : (e.request?.method || "GET").toUpperCase(),
        url    : e.request?.url || "",
        headers: Object.fromEntries(
          (e.request?.headers || [])
            .filter(h => !h.name.startsWith(":") && h.name.toLowerCase() !== "content-length")
            .map(h => [h.name, h.value])
        ),
        body   : e.request?.postData?.text || null,
      })).filter(e => e.url.startsWith("http"));
      _idorPendingEntries = entries;
      _idorPendingSrc     = "har";
      _idorShowTokenModal(autoToken,
        `${entries.length} requests from HAR · Token 1 auto-extracted · Enter Token 2 (attacker)`);
    } catch(e) { alert("HAR parse error: " + e.message); }
    inp.value = "";
  };
});

// ── Load from AV Capture ──────────────────────────────────────────────────────
function idorLoadFromAV() {
  const reqs = window._avState?.requests || [];
  if (!reqs.length) {
    alert("No requests in API Validator capture.\n\nImport cURL or capture requests in API Validator Pro first.");
    return;
  }
  const STATIC = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp)(\?|$)/i;
  const entries = reqs.map(r => ({
    method : (r.method || "GET").toUpperCase(),
    url    : r.url || "",
    headers: r.headers || {},
    body   : r.body ? (typeof r.body === "string" ? r.body : JSON.stringify(r.body)) : null,
  })).filter(e => e.url.startsWith("http") && !STATIC.test(e.url));
  idorImportEntries(entries, "AV Capture");
}

/**
 * Shared import path (HAR / AV / API Scan handoff).
 * Prefills Token 1 from Authorization when present; opens Token 2 modal.
 */
function idorImportEntries(entries, srcLabel) {
  const list = (entries || []).filter(e => e && String(e.url || "").startsWith("http"));
  if (!list.length) {
    alert("No HTTP requests to import into IDOR Tester.");
    return;
  }
  let autoToken = "";
  for (const r of list) {
    const hdrs = r.headers || {};
    const k = Object.keys(hdrs).find(x => x.toLowerCase() === "authorization");
    if (k) { autoToken = hdrs[k]; break; }
  }
  _idorPendingEntries = list.map(e => ({
    method : (e.method || "GET").toUpperCase(),
    url    : e.url || "",
    headers: e.headers || {},
    body   : e.body == null ? null
            : (typeof e.body === "string" ? e.body : JSON.stringify(e.body)),
  }));
  _idorPendingSrc = srcLabel || "import";
  idorSwitchTab("capture");
  _idorShowTokenModal(
    autoToken,
    `${list.length} request${list.length !== 1 ? "s" : ""} from ${srcLabel || "import"} · ` +
    "Set Token 1 (owner) and Token 2 (attacker) to confirm BOLA"
  );
}
window.idorImportEntries = idorImportEntries;

// ── Load entries — detect weak points for preview ─────────────────────────────
function _idorLoadEntries(entries, t1, t2) {
  _idorEntries  = entries;
  const weak    = _idorDetectWeakJS(entries);
  _idorWeakRows = weak;
  // init checked state — all selected by default
  _idorChecked  = {};
  weak.forEach(ep => { _idorChecked[ep.method + "::" + ep.url] = true; });
  const count = document.getElementById("idor-ep-count");
  if (count) {
    count.textContent = weak.length > 0
      ? `${entries.length} requests loaded · ${weak.length} injectable endpoint(s) detected`
      : `${entries.length} requests loaded · No injectable endpoints detected`;
  }
  _idorUpdateTagFilterOptions(weak);
  _idorRenderWeakList(weak);
}

// RSQL/DSL identifier comparison: `<field>id <op> <number>`, value optionally
// quoted. Matches userId=='140723', customerId==1, accountId=eq=42, id:1042.
// Equality/in operators only (not range =ge=/=le=, which aren't IDOR signals).
const _IDOR_DSL_ID_RE = /[a-z0-9_]*id\s*(==|=eq=|=in=|:)\s*['"]?[1-9]\d{0,14}['"]?/i;

// Prefixed/zero-padded IDs like "H-0190", "EMP0190" — mirrors the backend's
// _parse_formatted_id so the preview count matches what the scan will find.
const _IDOR_FORMATTED_ID_RE = /^([A-Za-z]{1,12}-?)(\d{1,15})$/;
function _idorIsFormattedId(v) {
  const m = _IDOR_FORMATTED_ID_RE.exec(String(v || ""));
  return !!m && parseInt(m[2], 10) >= 1;
}
// String-formatted twin of an ID field (employeeIdStr → employeeid) — mirrors
// the backend's _match_id_keyword suffix stripping.
const _IDOR_KEY_STRIP_SUFFIXES = ["str", "text", "txt", "code", "val", "value"];
function _idorMatchIdKeyword(k, keySet) {
  const kl = String(k || "").toLowerCase();
  if (keySet.has(kl)) return true;
  for (const suf of _IDOR_KEY_STRIP_SUFFIXES) {
    if (kl.endsWith(suf) && kl.length > suf.length && keySet.has(kl.slice(0, -suf.length))) return true;
  }
  return false;
}

// HTTP header names conventionally use kebab-case with an optional X-
// prefix (X-User-Id, Customer-Id) — mirrors the backend's
// _match_header_id_keyword.
function _idorMatchHeaderIdKeyword(k, keySet) {
  const bare = String(k || "").toLowerCase().replace(/[-_\s]/g, "");
  if (_idorMatchIdKeyword(bare, keySet)) return true;
  if (bare.startsWith("x") && bare.length > 1) return _idorMatchIdKeyword(bare.slice(1), keySet);
  return false;
}

// Base64-encoded numeric/formatted ID, e.g. cursor=MTA0Mg== → "1042" —
// mirrors the backend's _try_base64_id (detection only; the preview never
// needs to re-encode, the backend does that at scan time).
function _idorIsBase64Id(v) {
  const s = String(v || "");
  if (s.length < 2 || !/^[A-Za-z0-9+/_=-]+$/.test(s)) return false;
  for (const urlsafe of [false, true]) {
    try {
      const norm = urlsafe ? s.replace(/-/g, "+").replace(/_/g, "/") : s;
      const decoded = atob(norm.replace(/=+$/, "").padEnd(Math.ceil(norm.length / 4) * 4, "="));
      if (/^\d{1,15}$/.test(decoded) && parseInt(decoded, 10) >= 1) return true;
      if (_idorIsFormattedId(decoded)) return true;
    } catch (e) { /* not valid base64 — skip */ }
  }
  return false;
}

// Decode a value, repeating while it still looks percent-encoded (handles
// single AND double encoding). Returns the original string on any error.
function _idorSafeDecode(s) {
  let out = String(s || "");
  try {
    for (let i = 0; i < 3 && /%[0-9a-fA-F]{2}/.test(out); i++) {
      const dec = decodeURIComponent(out);
      if (dec === out) break;
      out = dec;
    }
  } catch (e) { /* malformed — keep what we have */ }
  return out;
}

// ── Light JS detection (preview only — backend runs full detection at scan time) ─
function _idorDetectWeakJS(entries) {
  const STATIC_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|webp|zip)(\?|$)/i;
  const HIGH_KEYS = new Set([
    "id","ids","uid","uuid","caseid","case_id","customerid","customer_id","cust_id",
    "vendorid","vendor_id","companyid","company_id","chartofaccountsid","chart_of_accounts_id",
    "costcenterid","cost_center_id","profitcenterid","profit_center_id",
    "documentid","document_id","taskid","task_id","orderid","order_id",
    "ticketid","ticket_id","invoiceid","invoice_id","profileid","profile_id","accountid",
    "account_id","reportid","report_id","recordid","record_id","itemid","item_id",
    "requestid","request_id","employeeid","employee_id","fileid","file_id","assetid","asset_id",
    "transactionid","transaction_id","paymentid","payment_id","memberid","member_id",
    "projectid","project_id","formid","form_id","userid","user_id","entityid","entity_id",
    "claimid","claim_id","policyid","policy_id","roleid","role_id","tenantid","tenant_id",
  ]);
  const seen = new Set();
  const weak = [];

  for (const entry of entries) {
    const url = entry.url || "";
    if (!url.startsWith("http") || STATIC_RE.test(url)) continue;
    try {
      const urlObj  = new URL(url);
      const normKey = (entry.method || "GET") + "::" + urlObj.pathname.replace(/\/\d+/g, "/__ID__");
      if (seen.has(normKey)) continue;

      // Check numeric path segment — including a filename-style compound
      // segment like invoice_1042.pdf (3+ digits bounded by _/-/./edges).
      const _COMPOUND_SEG_RE = /(?:^|[_\-.])(\d{3,15})(?:[_\-.]|$)/;
      const hasPathId = urlObj.pathname.split("/").some(seg => {
        if (/^\d{1,15}$/.test(seg) && parseInt(seg) >= 1) return true;
        const m = _COMPOUND_SEG_RE.exec(seg);
        return !!m && parseInt(m[1], 10) >= 1;
      });
      // Check ID keyword + numeric query param (values are auto-decoded by
      // URLSearchParams; decode again defensively in case of double-encoding).
      let hasQueryId = false;
      for (const [k, v] of urlObj.searchParams) {
        const dv = _idorSafeDecode(v);
        if (!_idorMatchIdKeyword(k, HIGH_KEYS)) continue;
        if ((/^\d{1,15}$/.test(dv) && parseInt(dv) >= 1) || _idorIsFormattedId(dv) || _idorIsBase64Id(dv)) {
          hasQueryId = true; break;
        }
      }
      // Check DSL / RSQL filter values — the injectable ID is often nested
      // *inside* a filter expression and URL-encoded, e.g.
      //   filter=id%3Dge%3D0%3BuserId%3D%3D%27140723%27
      //   → decoded: id=ge=0;userId=='140723'
      // so we decode every query value and look for `<field>Id <op> <number>`,
      // allowing the value to be wrapped in single/double quotes.
      let hasDslId = false;
      for (const v of urlObj.searchParams.values()) {
        if (_IDOR_DSL_ID_RE.test(_idorSafeDecode(v))) { hasDslId = true; break; }
      }
      // Also scan the whole decoded query string as a fallback (covers odd
      // separators / params the URL parser split differently).
      if (!hasDslId && _IDOR_DSL_ID_RE.test(_idorSafeDecode(urlObj.search))) {
        hasDslId = true;
      }

      // Check JSON request-body fields — many report/search POST endpoints
      // carry the target ID in the body (e.g. {"companyId": 42}) instead of
      // the URL, which none of the checks above can see.
      let hasBodyId = false;
      if (entry.body) {
        try {
          const bobj = typeof entry.body === "string" ? JSON.parse(entry.body) : entry.body;
          if (bobj && typeof bobj === "object" && !Array.isArray(bobj)) {
            for (const [k, v] of Object.entries(bobj)) {
              if (!_idorMatchIdKeyword(k, HIGH_KEYS)) continue;
              if (typeof v === "number" && Number.isInteger(v) && v >= 1) { hasBodyId = true; break; }
              if (typeof v === "string" && (_idorIsFormattedId(v) || _idorIsBase64Id(v))) { hasBodyId = true; break; }
              if (Array.isArray(v) && v.length && Number.isInteger(v[0]) && v[0] >= 1) { hasBodyId = true; break; }
            }
          }
        } catch(e) { /* not JSON — skip */ }
      }

      // Check custom HEADERS — very common in multi-tenant APIs (customerid,
      // X-User-Id, ...) where tenant/user context rides in a header instead
      // of the URL or body, invisible to every check above.
      let hasHeaderId = false;
      if (entry.headers) {
        for (const [k, v] of Object.entries(entry.headers)) {
          if (!_idorMatchHeaderIdKeyword(k, HIGH_KEYS)) continue;
          const dv = String(v);
          if ((/^\d{1,15}$/.test(dv) && parseInt(dv) >= 1) || _idorIsFormattedId(dv) || _idorIsBase64Id(dv)) {
            hasHeaderId = true; break;
          }
        }
      }

      if (hasPathId || hasQueryId || hasDslId || hasBodyId || hasHeaderId) {
        seen.add(normKey);
        weak.push({
          method  : (entry.method || "GET").toUpperCase(),
          url     : url,
          priority: hasPathId ? "HIGH" : "MEDIUM",
          reason  : hasPathId ? "PATH_ID" : hasQueryId ? "QUERY_ID" : hasDslId ? "DSL_ID" : hasBodyId ? "BODY_ID" : "HEADER_ID",
        });
      }
    } catch(e) { /* invalid URL — skip */ }
  }
  return weak;
}

// Where the ID was found — shown as a small tag so it's obvious at a
// glance whether a row is testing a header, query param, path segment,
// body field, or DSL filter expression.
const _IDOR_LOC_META = {
  PATH_ID         : {label: "Path",   icon: "🛣️", color: "#58a6ff"},
  PATH_ID_COMPOUND: {label: "Path",   icon: "🛣️", color: "#58a6ff"},
  PATH_PARAM      : {label: "Path",   icon: "🛣️", color: "#58a6ff"},
  PATH_UUID       : {label: "Path",   icon: "🛣️", color: "#58a6ff"},
  QUERY_ID        : {label: "Query",  icon: "🔗", color: "#3fb950"},
  DSL_ID          : {label: "Filter", icon: "🧮", color: "#a5d6ff"},
  DSL_UUID        : {label: "Filter", icon: "🧮", color: "#a5d6ff"},
  BODY_ID         : {label: "Body",   icon: "📦", color: "#d29922"},
  BODY_ID_LIST    : {label: "Body",   icon: "📦", color: "#d29922"},
  HEADER_ID       : {label: "Header", icon: "🔑", color: "#f778ba"},
};

function _idorGetEpReason(ep) {
  if (!ep) return "";
  if (ep.reason) return ep.reason;
  if (Array.isArray(ep.weak_points) && ep.weak_points.length) return ep.weak_points[0];
  if (typeof ep.weak_points === "string" && ep.weak_points) return ep.weak_points;
  return "";
}

function _idorGetTagLabel(reasonOrEp) {
  if (!reasonOrEp) return "";
  const reason = typeof reasonOrEp === "object" ? _idorGetEpReason(reasonOrEp) : reasonOrEp;
  if (!reason) return "";
  const key = String(reason).split(":")[0];
  return (_IDOR_LOC_META[key] || _IDOR_LOC_META[reason])?.label || "";
}

function _idorGetFilteredWeakRows() {
  const urlFilter = (_idorFilterText || "").toLowerCase().trim();
  const tagFilter = (_idorTagFilter || "ALL").toUpperCase();

  return _idorWeakRows.filter(ep => {
    if (urlFilter && !ep.url.toLowerCase().includes(urlFilter)) {
      return false;
    }
    if (tagFilter !== "ALL") {
      const epTag = _idorGetTagLabel(ep).toUpperCase();
      if (epTag !== tagFilter) {
        return false;
      }
    }
    return true;
  });
}

function _idorUpdateTagFilterOptions(weak) {
  const sel = document.getElementById("idor-tag-filter-select");
  if (!sel) return;
  const currentVal = sel.value || _idorTagFilter || "ALL";

  const counts = {};
  for (const ep of (weak || [])) {
    const tag = _idorGetTagLabel(ep);
    if (tag) {
      counts[tag] = (counts[tag] || 0) + 1;
    }
  }

  const standardTags = [
    { value: "ALL",    label: "All Tags", icon: "" },
    { value: "Header", label: "Header",   icon: "🔑 " },
    { value: "Path",   label: "Path",     icon: "🛣️ " },
    { value: "Filter", label: "Filter",   icon: "🧮 " },
    { value: "Query",  label: "Query",    icon: "🔗 " },
    { value: "Body",   label: "Body",     icon: "📦 " },
  ];

  const knownVals = new Set(standardTags.map(t => t.value));
  for (const tag of Object.keys(counts)) {
    if (!knownVals.has(tag)) {
      standardTags.push({ value: tag, label: tag, icon: "🏷️ " });
    }
  }

  const hasItems = (weak && weak.length > 0);
  sel.innerHTML = standardTags.map(t => {
    let text = t.icon + t.label;
    if (hasItems) {
      const c = t.value === "ALL" ? weak.length : (counts[t.value] || 0);
      text += ` (${c})`;
    }
    return `<option value="${t.value}">${text}</option>`;
  }).join("");

  if (Array.from(sel.options).some(o => o.value === currentVal)) {
    sel.value = currentVal;
    _idorTagFilter = currentVal;
  } else {
    sel.value = "ALL";
    _idorTagFilter = "ALL";
  }
}

// `field` (e.g. "customerid") and `value` (the literal value actually
// sent) make the tag self-explanatory without needing to expand the row.
// Always leads with the type label (Header/Query/Path/...) — color alone
// isn't enough to tell rows apart at a glance.
function _idorLocationTagHtml(type, field, value) {
  if (!type) return "";
  const baseType = String(type).split(":")[0];
  const meta = _IDOR_LOC_META[type] || _IDOR_LOC_META[baseType];
  if (!meta) return "";
  const detail = field
    ? (value !== undefined && value !== null && value !== "" ? `: ${escHtml(String(value))}` : "")
    : "";
  const text = `${meta.label}${field ? ` · ${escHtml(field)}` : ""}${detail}`;
  return `<span title="Tested via ${meta.label.toLowerCase()}" style="background:${meta.color}22;color:${meta.color};
                border:1px solid ${meta.color}44;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;
                margin-right:5px;white-space:nowrap;font-family:var(--mono)">${meta.icon} ${text}</span>`;
}

function _idorRenderWeakList(weak) {
  const list  = document.getElementById("idor-endpoint-list");
  const empty = document.getElementById("idor-endpoint-empty");
  if (!weak.length) { list.style.display = "none"; empty.style.display = "flex"; return; }
  list.style.display = "flex"; empty.style.display = "none";

  const filtered = _idorGetFilteredWeakRows();

  const MC = {GET:"#3fb950",POST:"#ffa657",PUT:"#d29922",PATCH:"#a5d6ff",DELETE:"#f85149"};
  const PC = {HIGH:"#f85149",MEDIUM:"#d29922",LOW:"#58a6ff"};

  if (!filtered.length) {
    list.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px;color:var(--text3);gap:8px">
        <div style="font-size:24px">🔍</div>
        <div style="font-size:12px;font-weight:600;color:var(--text2)">No matching endpoints found</div>
        <div style="font-size:11px">Try adjusting your URL filter or tag selection</div>
      </div>`;
  } else {
    list.innerHTML = filtered.map(ep => {
      const key     = ep.method + "::" + ep.url;
      const checked = _idorChecked[key] !== false;
      const mc      = MC[ep.method] || "#8b949e";
      const pc      = PC[ep.priority] || "#8b949e";
      const safeKey = key.replace(/'/g, "\\'");
      const reason  = _idorGetEpReason(ep);
      return `
        <div class="mt-ep-row ${checked ? "mt-ep-checked" : ""}" onclick="idorToggleEp('${safeKey}', this)">
          <input type="checkbox" class="mt-ep-cb" ${checked ? "checked" : ""}
                 onclick="event.stopPropagation(); idorToggleEp('${safeKey}', this.closest('.mt-ep-row'))">
          <span class="mt-ep-method" style="color:${mc};background:${mc}22;border:1px solid ${mc}55">${ep.method}</span>
          ${_idorLocationTagHtml(reason)}
          <span class="mt-ep-url" title="${escHtml(ep.url)}">${escHtml(ep.url)}</span>
          <span style="font-size:10px;color:${pc};background:${pc}22;border:1px solid ${pc}44;
                padding:1px 6px;border-radius:3px;font-family:var(--mono);flex-shrink:0;margin-left:8px">
            ${ep.priority}
          </span>
        </div>`;
    }).join("");
  }

  const sel = Object.values(_idorChecked).filter(Boolean).length;
  const btn = document.getElementById("idor-run-btn");
  if (btn) btn.textContent = `🚀 Run IDOR Scan (${sel} selected)`;
}

function idorToggleEp(key, row) {
  _idorChecked[key] = !_idorChecked[key];
  row.classList.toggle("mt-ep-checked", _idorChecked[key]);
  const cb = row.querySelector(".mt-ep-cb");
  if (cb) cb.checked = _idorChecked[key];
  const sel = Object.values(_idorChecked).filter(Boolean).length;
  const btn = document.getElementById("idor-run-btn");
  if (btn) btn.textContent = `🚀 Run IDOR Scan (${sel} selected)`;
}

function idorSelectAll() {
  const targets = _idorGetFilteredWeakRows();
  targets.forEach(ep => { _idorChecked[ep.method + "::" + ep.url] = true; });
  _idorRenderWeakList(_idorWeakRows);
}

function idorDeselectAll() {
  const targets = _idorGetFilteredWeakRows();
  targets.forEach(ep => { _idorChecked[ep.method + "::" + ep.url] = false; });
  _idorRenderWeakList(_idorWeakRows);
}

function idorFilterCapture() {
  _idorFilterText = document.getElementById("idor-url-filter-input")?.value || "";
  _idorTagFilter  = document.getElementById("idor-tag-filter-select")?.value || "ALL";
  _idorRenderWeakList(_idorWeakRows);
}

function idorCopyUrls() {
  const visible = _idorGetFilteredWeakRows();
  const checked = visible.filter(ep => _idorChecked[ep.method + "::" + ep.url] !== false);
  const toCopy  = checked.length ? checked : _idorWeakRows.filter(ep => _idorChecked[ep.method + "::" + ep.url] !== false);
  if (!toCopy.length) { alert("No endpoints selected."); return; }
  const text = toCopy.map(ep => ep.url).join("\n");
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("idor-copy-url-btn");
    if (!btn) return;
    const original = btn.textContent;
    btn.textContent = "✓ Copied";
    btn.style.color = "var(--green)";
    btn.style.borderColor = "var(--green)";
    setTimeout(() => {
      btn.textContent = original;
      btn.style.color = "";
      btn.style.borderColor = "";
    }, 2000);
  }).catch(() => {
    // fallback for environments without clipboard API
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
    const btn = document.getElementById("idor-copy-url-btn");
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = "✓ Copied"; btn.style.color = "var(--green)";
      setTimeout(() => { btn.textContent = orig; btn.style.color = ""; }, 2000);
    }
  });
}

// ── Run scan ──────────────────────────────────────────────────────────────────
function idorRunScan() {
  if (_idorScanActive) {
    alert("A scan is already in progress. Stop it before starting a new one.");
    return;
  }
  if (!_idorEntries.length) {
    alert("Load requests first — Import HAR or From AV Capture.");
    return;
  }
  const selCount = Object.values(_idorChecked).filter(Boolean).length;
  if (!selCount) { alert("Select at least one endpoint to scan."); return; }
  const token1 = document.getElementById("idor-token1-input").value.trim();
  const token2 = document.getElementById("idor-token2-input").value.trim();
  if (!token1) { alert("Token 1 (Owner) is required."); return; }
  if (!token2) { alert("Token 2 (Attacker) is required."); return; }
  if (token1 === token2) {
    if (!confirm("⚠️ Token 1 and Token 2 are identical — this will give false positives.\nContinue anyway?")) return;
  }
  // Reset mode to Auto and show scan-mode selection modal
  idorToggleScanMode("auto");
  const rangeInput = document.getElementById("idor-manual-range-input");
  if (rangeInput) rangeInput.value = "";
  document.getElementById("idor-scan-modal").style.display = "flex";
}

function idorToggleScanMode(mode) {
  const autoOpt    = document.getElementById("idor-mode-auto");
  const manualOpt  = document.getElementById("idor-mode-manual");
  const manualWrap = document.getElementById("idor-manual-range-wrap");
  autoOpt.classList.toggle("selected",   mode === "auto");
  manualOpt.classList.toggle("selected", mode === "manual");
  manualWrap.style.display = mode === "manual" ? "block" : "none";
}

function idorCancelScanModal() {
  document.getElementById("idor-scan-modal").style.display = "none";
}

async function idorStartScan() {
  const isManual = document.getElementById("idor-mode-manual").classList.contains("selected");
  let manualIds = [];
  if (isManual) {
    const rangeStr = document.getElementById("idor-manual-range-input").value.trim();
    if (!rangeStr) { alert("Enter an ID range for manual mode (e.g. 300-310, 400-405)"); return; }
    manualIds = _idorParseRange(rangeStr);
    if (!manualIds.length) { alert("Invalid range format. Use: 300-310, 400-405, 999"); return; }
  }
  document.getElementById("idor-scan-modal").style.display = "none";

  // Only send entries that correspond to a checked weak endpoint
  const checkedKeys   = new Set(Object.entries(_idorChecked).filter(([,v]) => v).map(([k]) => k));
  const entriesToScan = _idorEntries.filter(e => checkedKeys.has(e.method + "::" + e.url));

  const token1 = document.getElementById("idor-token1-input").value.trim();
  const token2 = document.getElementById("idor-token2-input").value.trim();
  const includeHeaders = document.getElementById("idor-include-headers-cb")?.checked !== false;
  const includeBody    = document.getElementById("idor-include-body-cb")?.checked === true;
  const btn    = document.getElementById("idor-run-btn");
  btn.disabled = true; btn.textContent = "⏳ Starting...";

  try {
    const resp = await fetch(`${IDOR_BASE}/idor/scan`, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({ entries: entriesToScan, token1, token2, manual_ids: manualIds, include_headers: includeHeaders, include_body: includeBody }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Scan start failed");
    _idorJobId = data.job_id;
    _idorScanActive = true;
    _idorStartPolling();
  } catch(e) {
    alert("Error: " + e.message);
    btn.disabled = false; btn.textContent = "🚀 Run IDOR Scan";
  }
}

function _idorParseRange(str) {
  const ids = new Set();
  for (const part of str.split(",")) {
    const s = part.trim();
    if (!s) continue;
    if (s.includes("-")) {
      const [a, b] = s.split("-").map(x => parseInt(x.trim(), 10));
      if (!isNaN(a) && !isNaN(b) && b >= a && (b - a) <= 10000) {
        for (let i = a; i <= b; i++) ids.add(i);
      }
    } else {
      const n = parseInt(s, 10);
      if (!isNaN(n)) ids.add(n);
    }
  }
  return [...ids].sort((a, b) => a - b);
}

// ── Polling ───────────────────────────────────────────────────────────────────
function _idorStartPolling() {
  _idorSyncScanModalVisibility();
  document.getElementById("idor-scan-fill").style.width = "0%";
  document.getElementById("idor-scan-stats").textContent = "Detecting weak endpoints...";
  document.getElementById("idor-scan-current").textContent = "";

  const runBtn = document.getElementById("idor-run-btn");
  if (runBtn) { runBtn.disabled = true; runBtn.textContent = "⏳ Scan in progress..."; }

  // Results tab starts filling in immediately — switching there any time
  // during the scan shows live data growing, not "No results yet".
  document.getElementById("idor-results-empty").style.display = "none";
  document.getElementById("idor-results-wrap").style.display = "flex";
  document.getElementById("idor-results-tbody").innerHTML = "";
  _idorLiveRenderedCount = 0;
  document.querySelectorAll("#tool-idor .mt-filter-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("idor-filter-all").classList.add("active");
  const existingWarn = document.getElementById("idor-no-weak-warn");
  if (existingWarn) existingWarn.remove();

  const stopBtn = document.getElementById("idor-stop-btn");
  if (stopBtn) { stopBtn.disabled = false; stopBtn.textContent = "⏹ Stop Scan"; }

  _idorPollTimer = setInterval(async () => {
    try {
      const resp = await fetch(`${IDOR_BASE}/idor/progress/${_idorJobId}`);
      const data = await resp.json();
      if (!resp.ok) {
        clearInterval(_idorPollTimer);
        _idorScanActive = false;
        _idorSyncScanModalVisibility();
        const btn = document.getElementById("idor-run-btn");
        if (btn) { btn.disabled = false; btn.textContent = "🚀 Run IDOR Scan"; }
        return;
      }

      document.getElementById("idor-scan-fill").style.width = data.progress + "%";
      const total = data.total || "?";
      document.getElementById("idor-scan-stats").textContent =
        `${data.completed} / ${total} endpoint(s) · ${data.findings.length} finding(s) · ${data.elapsed}s`;

      // ── Popup's compact status line: current URL being hit ──────────────
      const logs  = data.logs || [];
      const curEl = document.getElementById("idor-scan-current");
      if (logs.length) {
        curEl.textContent = `🔄 ${logs[logs.length - 1].url}`;
      } else if (data.status !== "done") {
        curEl.textContent = "🔍 Detecting injectable endpoints...";
      }

      // ── Results tab: grows live, in place — never re-renders existing rows,
      //    so an already-expanded row stays expanded as new ones stream in.
      _idorAllLogs      = logs;
      _idorScanWeakRows = data.weak_rows || _idorScanWeakRows;
      _idorAppendLiveRows(logs);
      _idorRefreshSummary(data);

      if (data.status === "done") {
        clearInterval(_idorPollTimer);
        _idorFindings     = data.findings   || [];
        _idorScanWeakRows = data.weak_rows  || _idorScanWeakRows;
        _idorLastJob      = data;
        _idorScanActive   = false;
        _idorSyncScanModalVisibility();
        _idorRefreshSummary(data);
        const btn = document.getElementById("idor-run-btn");
        if (btn) { btn.disabled = false; btn.textContent = "🚀 Run IDOR Scan"; }
      }
    } catch(e) {}
  }, 800);
}

// ── Stop an in-progress scan ────────────────────────────────────────────────
async function idorStopScan() {
  if (!_idorJobId) return;
  const btn = document.getElementById("idor-stop-btn");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Stopping..."; }
  try {
    await fetch(`${IDOR_BASE}/idor/stop/${_idorJobId}`, { method: "POST" });
    // Backend finishes the in-flight request then exits its loop — the
    // existing poll loop above will pick up status:"done" with whatever
    // logs/findings were collected so far and render partial results.
  } catch(e) {
    alert("Error stopping scan: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⏹ Stop Scan"; }
  }
}

// ── Summary cards + filter counts ───────────────────────────────────────────
// Called on every poll tick (cheap DOM update, ticks up live) AND once more
// at completion. Deliberately does NOT touch the results table itself —
// _idorAppendLiveRows() owns that, so an expanded row is never disturbed.
function _idorRefreshSummary(data) {
  document.getElementById("idor-results-wrap").style.display = "flex";

  const confirmed    = _idorAllLogs.filter(l => l.result === "CONFIRMED_IDOR").length;
  const potential    = _idorAllLogs.filter(l => l.result === "POTENTIAL_IDOR").length;
  const safe         = _idorAllLogs.filter(l =>
    l.result === "SAFE" || l.result === "SAFE_NOT_FOUND" || l.result === "SAFE_PUBLIC").length;
  const naCount      = _idorAllLogs.filter(l => l.result === "NOT_APPLICABLE" || l.result === "EMPTY_RESPONSE").length;

  const weakRows = data.weak_rows || _idorScanWeakRows || _idorWeakRows;
  document.getElementById("idor-summary-cards").innerHTML = `
    <div class="mt-card mt-card-red"><div class="mt-card-num">${confirmed}</div><div class="mt-card-lbl">CONFIRMED</div></div>
    <div class="mt-card mt-card-orange"><div class="mt-card-num">${potential}</div><div class="mt-card-lbl">POTENTIAL</div></div>
    <div class="mt-card mt-card-green"><div class="mt-card-num">${safe}</div><div class="mt-card-lbl">SAFE</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${naCount}</div><div class="mt-card-lbl">N/A</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${data.total || weakRows.length}</div><div class="mt-card-lbl">ENDPOINTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${_idorAllLogs.length}</div><div class="mt-card-lbl">TESTS</div></div>
    <div class="mt-card mt-card-grey"><div class="mt-card-num">${data.elapsed}s</div><div class="mt-card-lbl">DURATION</div></div>
  `;

  document.getElementById("idor-filter-all").textContent       = `All (${_idorAllLogs.length})`;
  document.getElementById("idor-filter-confirmed").textContent = `🚨 Confirmed (${confirmed})`;
  document.getElementById("idor-filter-potential").textContent = `⚠️ Potential (${potential})`;
  document.getElementById("idor-filter-safe").textContent      = `✅ Safe (${safe})`;
  document.getElementById("idor-filter-na").textContent        = `⬛ N/A (${naCount})`;

  // Show warning only once the scan is actually done — an empty weak_rows
  // mid-scan just means Phase 1 detection hasn't finished yet, not "none found".
  const existingWarn = document.getElementById("idor-no-weak-warn");
  if (existingWarn) existingWarn.remove();
  if (data.status === "done" && weakRows.length === 0) {
    const warn = document.createElement("div");
    warn.id = "idor-no-weak-warn";
    warn.style.cssText = "background:rgba(110,118,129,.15);border:1px solid rgba(110,118,129,.3);border-radius:6px;color:var(--text);padding:10px 14px;font-size:12px;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-shrink:0";
    warn.innerHTML = "⬛ No IDOR-injectable endpoints detected. Need numeric IDs (e.g. <code style='color:var(--yellow)'>/api/users/1042</code>), UUIDs in path/query, or ID-named parameters.";
    const wrap = document.getElementById("idor-results-wrap");
    if (wrap) wrap.insertBefore(warn, wrap.firstChild);
  }
}

function idorFilterResults(type) {
  document.querySelectorAll("#tool-idor .mt-filter-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("idor-filter-" + type)?.classList.add("active");
  const rows =
    type === "all"       ? _idorAllLogs
    : type === "confirmed" ? _idorAllLogs.filter(l => l.result === "CONFIRMED_IDOR")
    : type === "potential" ? _idorAllLogs.filter(l => l.result === "POTENTIAL_IDOR")
    : type === "safe"      ? _idorAllLogs.filter(l =>
        l.result === "SAFE" || l.result === "SAFE_NOT_FOUND" || l.result === "SAFE_PUBLIC")
    :                        _idorAllLogs.filter(l =>
        l.result !== "CONFIRMED_IDOR" && l.result !== "POTENTIAL_IDOR" &&
        l.result !== "SAFE" && l.result !== "SAFE_NOT_FOUND" && l.result !== "SAFE_PUBLIC");
  _idorRenderTable(rows);
}

// ── Results table ─────────────────────────────────────────────────────────────
const _IDOR_RESULT_COLORS = {
  "CONFIRMED_IDOR"  : "#f85149",
  "POTENTIAL_IDOR"  : "#ffa657",
  "SAFE"            : "#3fb950",
  "SAFE_NOT_FOUND"  : "#3fb950",
  "SAFE_PUBLIC"     : "#3fb950",
  "NOT_APPLICABLE"  : "#6e7681",
  "EMPTY_RESPONSE"  : "#6e7681",
  "EMPTY_RESPONSE_U2": "#8b949e",
  "REQUEST_ERROR"   : "#da3633",
};
const _idorStatusCls = n => isNaN(parseInt(n)) ? "mt-status-err"
  : (200<=n&&n<300) ? "mt-status-2xx" : (400<=n&&n<500) ? "mt-status-4xx" : "mt-status-5xx";
const _IDOR_PRIORITY_COLORS = {HIGH:"#f85149",MEDIUM:"#d29922",LOW:"#58a6ff"};

// Shared by both the live (Capture-tab, growing during a scan) and the
// final (Results-tab, filterable) tables so row markup never drifts out
// of sync between the two views. `uid` must be unique across BOTH tables
// at once (they can coexist in the DOM) — callers namespace it.
function _idorRowHtml(r, displayNum, uid) {
  const isIssue = r.result === "CONFIRMED_IDOR" || r.result === "POTENTIAL_IDOR";
  const rColor  = _IDOR_RESULT_COLORS[r.result] || "#8b949e";
  const pc      = _IDOR_PRIORITY_COLORS[r.priority] || "#8b949e";
  const badge   = `<span style="background:${rColor};color:#fff;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;white-space:nowrap">
                     ${r.result.replace(/_/g, " ")}
                   </span>`;
  const simStr  = isIssue ? `${Math.round(r.similarity * 100)}%` : "—";
  const rowBg   = r.result === "CONFIRMED_IDOR" ? "background:#1a0808"
                : r.result === "POTENTIAL_IDOR"  ? "background:#1a1200" : "";
  // weak_points looks like ["HEADER_ID:customerid:HIGH"] — the part
  // before the first ":" tells us where this ID was actually tested.
  // tested_field/tested_value (from the backend) are the exact key name
  // and literal value that were sent — needed because a formatted ID
  // (H-0195) or base64-re-encoded value differs from the raw tested_id.
  const locType   = (r.weak_points && r.weak_points[0]) ? r.weak_points[0].split(":")[0] : "";
  const hasField  = r.tested_field !== undefined && r.tested_field !== null;
  const fieldName = hasField ? r.tested_field : (r.weak_points && r.weak_points[0] ? r.weak_points[0].split(":")[1] : "");
  const fieldVal  = hasField ? r.tested_value : r.tested_id;
  const locTag    = _idorLocationTagHtml(locType, fieldName, fieldVal);

  return `
    <tr class="mt-result-row ${isIssue ? "mt-row-issue" : "mt-row-clean"}"
        onclick="idorToggleExpand('${uid}')" style="cursor:pointer;${rowBg}">
      <td class="mt-td-num">${displayNum}</td>
      <td><span style="background:${pc}22;color:${pc};border:1px solid ${pc}44;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">${r.priority}</span></td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2)">${r.method}</td>
      <td>${locTag}</td>
      <td class="mt-td-url" title="${escHtml(r.url)}">${escHtml(r.url)}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--yellow);text-align:center">${r.tested_id}</td>
      <td><span class="${_idorStatusCls(r.u1_status)} mt-status-badge">${r.u1_status}</span></td>
      <td><span class="${_idorStatusCls(r.u2_status)} mt-status-badge">${r.u2_status}</span></td>
      <td>${badge}</td>
      <td style="color:${isIssue?"#ffa657":"#6e7681"};font-size:11px;text-align:center">${simStr}</td>
    </tr>
    <tr class="mt-expand-row" id="${uid}" style="display:none">
      <td colspan="10" class="mt-expand-cell">
        <div class="mt-response-grid">
          <div class="mt-resp-panel">
            <div class="mt-resp-label">
              👤 User 1 — Owner
              <span class="mt-resp-method">${r.u1_status}</span>
              <span class="mt-resp-ms">${r.u1_len}b</span>
            </div>
            <pre class="mt-resp-body">${escHtml(r.u1_resp || "(empty)")}</pre>
          </div>
          <div class="mt-resp-panel">
            <div class="mt-resp-label">
              🎯 User 2 — Attacker
              <span class="mt-resp-method" style="color:${isIssue?"#f85149":"inherit"}">${r.u2_status}</span>
              <span class="mt-resp-ms">${r.u2_len}b</span>
            </div>
            <pre class="mt-resp-body">${escHtml(r.u2_resp || "(empty)")}</pre>
          </div>
        </div>
        <div class="idor-meta-footer">
          <div class="idor-meta-url-line" title="${escHtml(r.url)}">
            🔗 Tested:&nbsp; ${escHtml(r.url)}
          </div>
          ${r.original_url && r.original_url !== r.url ? `<div class="idor-meta-url-line" title="${escHtml(r.original_url)}">
            📎 Original: ${escHtml(r.original_url)}
          </div>` : ""}
          <div style="margin-top:4px;display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            ${locTag}
            <span style="color:var(--text3)">Similarity: <span style="color:${isIssue?"#ffa657":"var(--text3)"}">${Math.round(r.similarity*100)}%</span></span>
          </div>
        </div>
      </td>
    </tr>`;
}

function _idorRenderTable(rows) {
  const tbody = document.getElementById("idor-results-tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="10" class="mt-empty-row">No results.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map((r, i) => _idorRowHtml(r, i + 1, `idorrow-${i}`)).join("");
}

// ── Live results table (Results tab, updates during a running scan) ────────
// Appends only the NEW rows since the last poll tick — never touches rows
// already in the DOM — so an expanded row stays expanded as more stream in.
let _idorLiveRenderedCount = 0;

function _idorAppendLiveRows(logs) {
  const tbody = document.getElementById("idor-results-tbody");
  if (!tbody || logs.length <= _idorLiveRenderedCount) return;
  const newRows = logs.slice(_idorLiveRenderedCount);
  const html = newRows.map((r, idx) => {
    const n = _idorLiveRenderedCount + idx;
    return _idorRowHtml(r, n + 1, `idorrow-${n}`);
  }).join("");
  tbody.insertAdjacentHTML("beforeend", html);
  _idorLiveRenderedCount = logs.length;

  // Auto-follow the stream only if the user is already near the bottom —
  // don't yank them away from a row they scrolled up to inspect.
  const wrap = document.getElementById("idor-results-table-wrap");
  if (wrap && wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 80) {
    wrap.scrollTop = wrap.scrollHeight;
  }
}

function idorToggleExpand(uid) {
  const row = document.getElementById(uid); if (!row) return;
  const scope = document.getElementById("idor-results-tbody");
  const isOpen = row.style.display !== "none";
  scope?.querySelectorAll(".mt-expand-row").forEach(r => r.style.display = "none");
  scope?.querySelectorAll(".mt-result-row").forEach(r => r.classList.remove("mt-row-selected"));
  if (!isOpen) {
    row.style.display = "table-row";
    row.previousElementSibling?.classList.add("mt-row-selected");
  }
}

// ── Export ────────────────────────────────────────────────────────────────────
async function idorDownloadCsv() {
  if (!_idorJobId) return;
  try {
    const resp = await fetch(`${IDOR_BASE}/idor/csv/${_idorJobId}`);
    const text = await resp.text();
    const ts   = new Date().toISOString().replace(/[:.]/g, "").substring(0, 15);
    if (window.pywebview?.api?.save_file) {
      await window.pywebview.api.save_file(text, `idor_report_${ts}.csv`);
    } else {
      const a = document.createElement("a");
      a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(text);
      a.download = `idor_report_${ts}.csv`; a.click();
    }
  } catch(e) { alert("CSV failed: " + e.message); }
}

async function idorDownloadHtml() {
  if (!_idorLastJob) return;
  const html = _idorGenHtml(_idorLastJob, _idorAllLogs, _idorScanWeakRows.length ? _idorScanWeakRows : _idorWeakRows);
  const ts   = new Date().toISOString().replace(/[:.]/g, "").substring(0, 15);
  if (window.pywebview?.api?.save_file) {
    await window.pywebview.api.save_file(html, `idor_report_${ts}.html`);
  } else {
    const a = document.createElement("a");
    a.href = "data:text/html;charset=utf-8," + encodeURIComponent(html);
    a.download = `idor_report_${ts}.html`; a.click();
  }
}

// ── HTML report generator ─────────────────────────────────────────────────────
function _idorGenHtml(data, logs, weakRows) {
  const ts = new Date().toLocaleString();
  const confirmed = logs.filter(l => l.result === "CONFIRMED_IDOR");
  const potential = logs.filter(l => l.result === "POTENTIAL_IDOR");
  const safe      = logs.filter(l => l.result === "SAFE" || l.result === "SAFE_NOT_FOUND");

  const RESULT_COLORS = {
    "CONFIRMED_IDOR":"#f85149","POTENTIAL_IDOR":"#ffa657",
    "SAFE":"#3fb950","SAFE_NOT_FOUND":"#3fb950","NOT_APPLICABLE":"#6e7681",
    "EMPTY_RESPONSE":"#6e7681","EMPTY_RESPONSE_U2":"#8b949e","REQUEST_ERROR":"#da3633",
  };
  const stC = n => {const c=parseInt(n);return isNaN(c)?'#6e7681':c<300?'#3fb950':c<400?'#58a6ff':c<500?'#d29922':'#f85149';};
  const PC  = {HIGH:"#f85149",MEDIUM:"#d29922",LOW:"#58a6ff"};

  const weakHtml = weakRows.map((r, i) => {
    const pc  = PC[r.priority] || "#8b949e";
    const wps = Array.isArray(r.weak_points) ? r.weak_points.join(", ") : (r.reason || "");
    return `<tr>
      <td style="color:var(--text)">${i+1}</td>
      <td><span style="background:${pc}22;color:${pc};padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700">${r.priority}</span></td>
      <td style="font-weight:700;color:#c9d1d9">${escHtml(r.method)}</td>
      <td style="font-size:10px;color:#79c0ff;font-family:monospace;word-break:break-all">${escHtml(r.url)}</td>
      <td style="font-size:10px;color:#e3b341;font-family:monospace">${escHtml(wps)}</td>
    </tr>`;
  }).join("");

  const logsHtml = logs.map((r, i) => {
    const isIssue = r.result === "CONFIRMED_IDOR" || r.result === "POTENTIAL_IDOR";
    const rc  = RESULT_COLORS[r.result] || "#8b949e";
    const pc  = PC[r.priority] || "#8b949e";
    const uid = `hr-${i}`;
    const hasR = r.u1_resp || r.u2_resp;
    return `<tr style="background:${r.result==="CONFIRMED_IDOR"?"#1a0808":r.result==="POTENTIAL_IDOR"?"#1a1200":"#0d1117"};cursor:${hasR?"pointer":"default"}" onclick="toggle('${uid}')">
      <td style="color:var(--text)">${i+1}</td>
      <td><span style="background:${pc}22;color:${pc};padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">${r.priority}</span></td>
      <td style="font-weight:700;color:#c9d1d9">${escHtml(r.method)}</td>
      <td style="font-size:10px;color:#79c0ff;font-family:monospace;word-break:break-all;max-width:280px">${escHtml(r.url)}</td>
      <td style="font-weight:700;color:#e3b341;text-align:center">${r.tested_id}</td>
      <td style="font-weight:700;color:${stC(r.u1_status)};text-align:center">${r.u1_status}</td>
      <td style="font-weight:700;color:${stC(r.u2_status)};text-align:center">${r.u2_status}</td>
      <td><span style="background:${rc};color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;white-space:nowrap">${r.result.replace(/_/g," ")}</span></td>
      <td style="color:${isIssue?"#ffa657":"#6e7681"};text-align:center">${isIssue?Math.round(r.similarity*100)+"%":"—"}</td>
    </tr>
    ${hasR ? `<tr id="${uid}" style="display:none;background:#0a0d14">
      <td colspan="10" style="padding:0">
        <div style="display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #21262d">
          <div style="padding:10px 12px;border-right:1px solid #21262d">
            <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:6px">👤 User 1 (Owner) — ${r.u1_status} (${r.u1_len}b)</div>
            <pre style="font-size:10px;color:#c9d1d9;background:#161b22;border:1px solid #30363d;border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin:0">${escHtml(r.u1_resp||"(empty)")}</pre>
          </div>
          <div style="padding:10px 12px">
            <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:6px">🎯 User 2 (Attacker) — <span style="color:${isIssue?"#f85149":stC(r.u2_status)}">${r.u2_status} (${r.u2_len}b)</span></div>
            <pre style="font-size:10px;color:#c9d1d9;background:#161b22;border:1px solid ${isIssue?"#f8514944":"#30363d"};border-radius:4px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin:0">${escHtml(r.u2_resp||"(empty)")}</pre>
          </div>
        </div>
      </td>
    </tr>` : ""}`;
  }).join("");

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IDOR Test Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#080c10;color:#c9d1d9;padding:24px;font-size:13px}
h1{font-size:22px;font-weight:800;background:linear-gradient(135deg,#f85149,#ffa657);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.meta{color:var(--text);font-size:10px;font-family:monospace;margin-top:4px;margin-bottom:18px}
.cards{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 18px;text-align:center;min-width:80px;position:relative;overflow:hidden}
.card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px}
.red::after{background:#f85149}.orange::after{background:#ffa657}.green::after{background:#3fb950}.grey::after{background:#6e7681}
.card h3{font-size:20px;font-weight:800;margin-bottom:2px}
.red h3{color:#f85149}.orange h3{color:#ffa657}.green h3{color:#3fb950}.grey h3{color:var(--text)}
.card p{font-size:9px;color:var(--text);text-transform:uppercase;letter-spacing:1px}
h2{background:#161b22;padding:7px 12px;border-left:3px solid #f85149;border-radius:0 5px 5px 0;font-size:13px;font-weight:700;margin:20px 0 10px}
table{border-collapse:collapse;width:100%;background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden;font-size:11px;margin-bottom:20px}
th{background:#161b22;color:var(--text);padding:7px 10px;text-align:left;border-bottom:1px solid #30363d;font-size:9px;text-transform:uppercase;letter-spacing:.5px;font-weight:700;position:sticky;top:0}
td{padding:6px 10px;border-bottom:1px solid #161b22;vertical-align:middle}
tr:hover td{background:#161b22}
.hint{font-size:9px;color:var(--text);margin-bottom:8px;font-style:italic}
</style>
<script>function toggle(id){var r=document.getElementById(id);if(r)r.style.display=r.style.display==='none'?'table-row':'none';}</script>
</head><body>
<h1>🔍 IDOR Vulnerability Report</h1>
<p class="meta">Generated: ${ts} &nbsp;|&nbsp; Weak Endpoints: ${weakRows.length} &nbsp;|&nbsp; Tests Run: ${logs.length} &nbsp;|&nbsp; Duration: ${data.elapsed}s</p>
<div class="cards">
  <div class="card red"><h3>${confirmed.length}</h3><p>Confirmed</p></div>
  <div class="card orange"><h3>${potential.length}</h3><p>Potential</p></div>
  <div class="card green"><h3>${safe.length}</h3><p>Safe</p></div>
  <div class="card grey"><h3>${weakRows.length}</h3><p>Endpoints</p></div>
  <div class="card grey"><h3>${logs.length}</h3><p>Tests</p></div>
</div>
<h2>🔎 Weak Endpoints Detected</h2>
<p class="hint">Endpoints with numeric IDs or ID keywords that were tested</p>
<table><thead><tr><th>#</th><th>Priority</th><th>Method</th><th>URL</th><th>Weak Points</th></tr></thead>
<tbody>${weakHtml}</tbody></table>
<h2>📋 All Test Results</h2>
<p class="hint">Click any row to expand User 1 vs User 2 responses side by side</p>
<table>
<thead><tr><th>#</th><th>Priority</th><th>Method</th><th>URL</th><th>Tested ID</th><th>U1 Status</th><th>U2 Status</th><th>Result</th><th>Similarity</th></tr></thead>
<tbody>${logsHtml}</tbody></table>
</body></html>`;
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function idorReset() {
  clearInterval(_idorPollTimer);
  _idorEntries = []; _idorWeakRows = []; _idorScanWeakRows = []; _idorJobId = null;
  _idorAllLogs = []; _idorFindings = []; _idorLastJob = null;
  _idorChecked = {}; _idorFilterText = ""; _idorTagFilter = "ALL"; _idorScanActive = false; _idorLiveRenderedCount = 0;
  const rt = document.getElementById("idor-results-tbody"); if (rt) rt.innerHTML = "";
  const fi = document.getElementById("idor-url-filter-input"); if (fi) fi.value = "";
  const ts = document.getElementById("idor-tag-filter-select"); if (ts) ts.value = "ALL";
  _idorUpdateTagFilterOptions([]);
  const ec = document.getElementById("idor-ep-count"); if (ec) ec.textContent = "0 endpoints";
  const list  = document.getElementById("idor-endpoint-list");
  if (list)  { list.innerHTML = ""; list.style.display = "none"; }
  const empty = document.getElementById("idor-endpoint-empty");
  if (empty) empty.style.display = "flex";
  const wrap = document.getElementById("idor-results-wrap"); if (wrap) wrap.style.display = "none";
  const re   = document.getElementById("idor-results-empty"); if (re) re.style.display = "flex";
  const ov   = document.getElementById("idor-scanning-modal"); if (ov) ov.style.display = "none";
  const btn  = document.getElementById("idor-run-btn");
  if (btn) { btn.disabled = false; btn.textContent = "🚀 Run IDOR Scan"; }
  const t1 = document.getElementById("idor-token1-input"); if (t1) t1.value = "";
  const t2 = document.getElementById("idor-token2-input"); if (t2) t2.value = "";
  idorSwitchTab("capture");
}
window.idorReset = idorReset;

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
