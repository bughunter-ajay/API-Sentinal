// ═══════════════════════════════════════════════════════════════
//  APISphere extras — OpenAPI import, Code gen, Compare, Secrets
//  Loaded after apisphere.js (uses asp* helpers). No prefix clash.
// ═══════════════════════════════════════════════════════════════

const ASP_HIST_BODY_MAX = 200000; // chars kept per history response for compare
const ASP_SECRET_HDR_RE = /^(authorization|proxy-authorization|x-api-key|api[-_]?key|x-auth-token|x-access-token|cookie|set-cookie)$/i;
let _aspCodeGenLang = "curl";
let _aspOaPending = null; // { spec, fileName }
let _aspHistCompareSel = new Set(); // history indices selected for compare

// ── Secret masking ────────────────────────────────────────────
function _aspIsSecretHeader(name) {
  return ASP_SECRET_HDR_RE.test(String(name || ""));
}
function _aspMaskValue(v) {
  if (v == null || v === "") return v;
  const s = String(v);
  if (s.length <= 8) return "********";
  return s.slice(0, 4) + "…" + "*".repeat(Math.min(12, s.length - 4));
}
function _aspMaskHeadersMap(headers) {
  const out = {};
  Object.entries(headers || {}).forEach(([k, v]) => {
    out[k] = _aspIsSecretHeader(k) ? _aspMaskValue(v) : v;
  });
  return out;
}
function _aspMaskAuthObj(auth) {
  if (!auth || typeof auth !== "object") return auth;
  const a = Object.assign({}, auth);
  if (a.token) a.token = _aspMaskValue(a.token);
  if (a.password) a.password = _aspMaskValue(a.password);
  return a;
}
/** Deep-clone payload / collection-ish objects and redact secrets. */
function _aspMaskSecretsDeep(input) {
  if (input == null || typeof input !== "object") return input;
  try {
    const o = JSON.parse(JSON.stringify(input));
    const walk = (node) => {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) {
        // header/param rows: { key, value }
        node.forEach(row => {
          if (row && typeof row === "object") {
            if (row.key != null && row.value != null && _aspIsSecretHeader(row.key)) {
              row.value = _aspMaskValue(row.value);
            }
            if (row.auth) row.auth = _aspMaskAuthObj(row.auth);
            if (row.headers && typeof row.headers === "object" && !Array.isArray(row.headers)) {
              row.headers = _aspMaskHeadersMap(row.headers);
            }
            if (Array.isArray(row.headers)) walk(row.headers);
            if (Array.isArray(row.items)) walk(row.items);
            if (Array.isArray(row.variables)) {
              row.variables.forEach(v => {
                if (v && v.key && /token|password|secret|api[_-]?key|authorization/i.test(v.key)) {
                  v.value = _aspMaskValue(v.value);
                }
              });
            }
            if (row.token) row.token = _aspMaskValue(row.token);
            if (row.password) row.password = _aspMaskValue(row.password);
          }
        });
        return;
      }
      if (node.headers && typeof node.headers === "object" && !Array.isArray(node.headers)) {
        node.headers = _aspMaskHeadersMap(node.headers);
      }
      if (Array.isArray(node.headers)) walk(node.headers);
      if (node.auth) node.auth = _aspMaskAuthObj(node.auth);
      if (Array.isArray(node.items)) walk(node.items);
      if (Array.isArray(node.variables)) {
        node.variables.forEach(v => {
          if (v && v.key && /token|password|secret|api[_-]?key|authorization/i.test(v.key)) {
            v.value = _aspMaskValue(v.value);
          }
        });
      }
      if (node.request && typeof node.request === "object") walk(node.request);
      if (node.item && Array.isArray(node.item)) walk(node.item);
      // Postman export auth shapes
      if (node.bearer && Array.isArray(node.bearer)) {
        node.bearer.forEach(b => { if (b && b.key === "token") b.value = _aspMaskValue(b.value); });
      }
      if (node.basic && Array.isArray(node.basic)) {
        node.basic.forEach(b => { if (b && b.key === "password") b.value = _aspMaskValue(b.value); });
      }
    };
    walk(o);
    return o;
  } catch (_) {
    return input;
  }
}
window._aspMaskSecretsDeep = _aspMaskSecretsDeep;
window._aspMaskHeadersMap = _aspMaskHeadersMap;

// ── Patch history save / render / export (after apisphere.js) ──
(function _aspPatchHistoryAndExport() {
  if (typeof _aspSaveHistory !== "function") return;
  const _origSave = _aspSaveHistory;
  _aspSaveHistory = function (req, resp) {
    let reqCopy = req;
    try {
      reqCopy = JSON.parse(JSON.stringify(req));
    } catch (_) { reqCopy = req; }
    // Strip multipart file bytes (same as original)
    if (reqCopy && reqCopy.body_type === "multipart" && Array.isArray(reqCopy.body)) {
      reqCopy.body = reqCopy.body.map(e => e && e.type === "file"
        ? { key: e.key, type: "file", filename: e.filename || "", contentType: e.contentType || "", data: "" }
        : e);
    }
    // Mask secrets in stored history (localStorage)
    reqCopy = _aspMaskSecretsDeep(reqCopy);

    const bodyStr = resp && resp.body != null ? String(resp.body) : "";
    const respSnap = {
      status_code: resp && resp.status_code,
      status_text: resp && resp.status_text,
      elapsed_ms: resp && resp.elapsed_ms,
      body_hint: resp && resp.body_hint,
      body: bodyStr.length > ASP_HIST_BODY_MAX
        ? bodyStr.slice(0, ASP_HIST_BODY_MAX) + "\n… [truncated for history]"
        : bodyStr,
      headers: _aspMaskHeadersMap((resp && resp.headers) || {}),
    };

    const hist = _aspGetHistory();
    hist.unshift({
      ts: Date.now(),
      method: req.method,
      url: req.url,
      status: resp && resp.status_code,
      ms: resp && resp.elapsed_ms,
      req: reqCopy,
      resp: respSnap,
    });
    if (hist.length > ASP_MAX_HISTORY) hist.length = ASP_MAX_HISTORY;
    try { localStorage.setItem(ASP_HISTORY_KEY, JSON.stringify(hist)); } catch (e) {
      // Quota: drop bodies and retry
      try {
        hist.forEach(h => { if (h.resp) h.resp.body = (h.resp.body || "").slice(0, 8000); });
        localStorage.setItem(ASP_HISTORY_KEY, JSON.stringify(hist));
      } catch (_) {}
    }
    _aspHistCompareSel.clear();
    _aspRenderHistory();
  };

  const _origRender = _aspRenderHistory;
  _aspRenderHistory = function () {
    const list = document.getElementById("asp-history-list");
    if (!list) return _origRender();
    const hist = _aspGetHistory();
    if (!hist.length) {
      list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px">No requests yet</div>`;
      _aspSyncHistCompareBtn();
      return;
    }
    list.innerHTML = hist.map((h, i) => {
      const mc = (_ASP_METHOD_COLORS && _ASP_METHOD_COLORS[h.method]) || "#8b949e";
      const sc = parseInt(h.status, 10);
      const scol = sc < 300 ? "#3fb950" : sc < 400 ? "#79c0ff" : sc < 500 ? "#d29922" : "#f85149";
      const short = (h.url || "").replace(/^https?:\/\//, "").slice(0, 48);
      const checked = _aspHistCompareSel.has(i) ? "checked" : "";
      const hasBody = !!(h.resp && h.resp.body != null);
      const dis = hasBody ? "" : "disabled";
      const tip = hasBody ? "" : " title=\"No saved response body — send again after update\"";
      return `<div class="asp-hist-item" title="${_aspEscAttr(h.url || "")}">
        <input type="checkbox" class="asp-hist-check" ${checked} ${dis}${tip}
          onclick="event.stopPropagation();aspToggleHistCompare(${i}, this.checked)">
        <span class="asp-hist-method" style="color:${mc};cursor:pointer" onclick="aspLoadHistory(${i})">${_aspEscHtml(h.method || "")}</span>
        <span class="asp-hist-url" style="cursor:pointer" onclick="aspLoadHistory(${i})">${_aspEscHtml(short)}</span>
        <span class="asp-hist-status" style="color:${scol}">${h.status != null ? h.status : ""}</span>
        <span class="asp-hist-ago">${_aspTimeAgo(h.ts)}</span>
      </div>`;
    }).join("");
    _aspSyncHistCompareBtn();
  };

  if (typeof aspClearHistory === "function") {
    const _origClear = aspClearHistory;
    aspClearHistory = function () {
      _aspHistCompareSel.clear();
      _origClear();
      _aspSyncHistCompareBtn();
    };
    window.aspClearHistory = aspClearHistory;
  }

  if (typeof aspCollCtxExport === "function") {
    const _origExport = aspCollCtxExport;
    aspCollCtxExport = function () {
      const colId = _aspCollCtxId;
      aspHideCollCtx();
      if (!colId) return;
      _aspFlushTab();
      const col = _aspGetColls().find(c => c.id === colId);
      if (!col) return;

      const items = (col.items || []).map(_aspExportPmTreeItem);
      const collection = {
        info: {
          name: col.name || "Collection",
          schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        item: items,
      };
      if (col.auth && col.auth.type && col.auth.type !== "none") {
        collection.auth = _aspExportPmAuth(col.auth);
      }
      const vars = (col.variables || []).filter(v => v.enabled !== false && v.key);
      if (vars.length) {
        collection.variable = vars.map(v => ({ key: v.key, value: v.value || "", type: "string" }));
      }

      const masked = _aspMaskSecretsDeep(collection);
      const json = JSON.stringify(masked, null, 2);
      const filename = (col.name || "collection").replace(/[\\/:*?"<>|]+/g, "_").trim() + ".json";
      if (window.pywebview && window.pywebview.api && window.pywebview.api.save_file) {
        window.pywebview.api.save_file(json, filename)
          .then(r => { if (r && r.ok) _aspAlert("Collection exported (secrets masked):\n" + r.path); })
          .catch(e => _aspAlert("Export failed: " + e.message));
      } else {
        // Browser fallback
        const a = document.createElement("a");
        a.href = URL.createObjectURL(new Blob([json], { type: "application/json" }));
        a.download = filename;
        a.click();
        _aspShowToast("Exported " + filename + " (secrets masked)");
      }
    };
    window.aspCollCtxExport = aspCollCtxExport;
  }

  window._aspSaveHistory = _aspSaveHistory;
  window._aspRenderHistory = _aspRenderHistory;
})();

function aspToggleHistCompare(idx, on) {
  if (on) {
    if (_aspHistCompareSel.size >= 2 && !_aspHistCompareSel.has(idx)) {
      // keep only latest + this
      const arr = Array.from(_aspHistCompareSel);
      _aspHistCompareSel.delete(arr[0]);
    }
    _aspHistCompareSel.add(idx);
  } else {
    _aspHistCompareSel.delete(idx);
  }
  _aspSyncHistCompareBtn();
  _aspRenderHistory();
}
function _aspSyncHistCompareBtn() {
  const btn = document.getElementById("asp-hist-compare-btn");
  if (!btn) return;
  const n = _aspHistCompareSel.size;
  btn.style.display = n > 0 ? "inline-flex" : "none";
  btn.textContent = n === 2 ? "Compare (2)" : `Compare (${n}/2)`;
  btn.disabled = n !== 2;
}
function aspOpenCompareFromHistory() {
  const idxs = Array.from(_aspHistCompareSel).sort((a, b) => a - b);
  if (idxs.length !== 2) {
    _aspShowToast("Select exactly 2 history items");
    return;
  }
  const hist = _aspGetHistory();
  const a = hist[idxs[0]];
  const b = hist[idxs[1]];
  if (!a || !b) return;
  aspShowCompare(a, b);
}
window.aspToggleHistCompare = aspToggleHistCompare;
window.aspOpenCompareFromHistory = aspOpenCompareFromHistory;

// ── Response compare ──────────────────────────────────────────
function aspShowCompare(ha, hb) {
  const modal = document.getElementById("asp-compare-modal");
  if (!modal) return;
  const fill = (metaId, bodyId, h, label) => {
    const meta = document.getElementById(metaId);
    const body = document.getElementById(bodyId);
    const r = h.resp || {};
    const st = r.status_code != null ? r.status_code : h.status;
    const ms = r.elapsed_ms != null ? r.elapsed_ms : h.ms;
    if (meta) {
      meta.innerHTML =
        `<div style="font-weight:700;color:var(--text);margin-bottom:4px">${_aspEscHtml(label)}</div>` +
        `<div>${_aspEscHtml(h.method || "")} ${_aspEscHtml(h.url || "")}</div>` +
        `<div style="margin-top:4px">Status <b style="color:${parseInt(st,10)<300?"#3fb950":"#f85149"}">${_aspEscHtml(String(st||""))} ${ _aspEscHtml(r.status_text||"")}</b>` +
        (ms != null ? ` · ${ms} ms` : "") +
        ` · ${_aspTimeAgo(h.ts)}</div>`;
    }
    if (body) {
      let text = r.body != null ? String(r.body) : "(no response body saved — send again after update)";
      if (r.body_hint === "json") {
        try { text = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
      }
      body.textContent = text;
    }
  };
  fill("asp-cmp-meta-a", "asp-cmp-body-a", ha, "A");
  fill("asp-cmp-meta-b", "asp-cmp-body-b", hb, "B");
  // Light line-diff highlight
  _aspApplyCompareDiff(
    document.getElementById("asp-cmp-body-a"),
    document.getElementById("asp-cmp-body-b")
  );
  modal.style.display = "flex";
}
function _aspApplyCompareDiff(preA, preB) {
  if (!preA || !preB) return;
  const linesA = preA.textContent.split("\n");
  const linesB = preB.textContent.split("\n");
  const setA = new Set(linesA);
  const setB = new Set(linesB);
  preA.innerHTML = linesA.map(l => {
    const cls = setB.has(l) ? "" : "asp-cmp-diff-del";
    return cls ? `<span class="${cls}">${_aspEscHtml(l)}</span>` : _aspEscHtml(l);
  }).join("\n");
  preB.innerHTML = linesB.map(l => {
    const cls = setA.has(l) ? "" : "asp-cmp-diff-add";
    return cls ? `<span class="${cls}">${_aspEscHtml(l)}</span>` : _aspEscHtml(l);
  }).join("\n");
}
function aspCloseCompare() {
  const modal = document.getElementById("asp-compare-modal");
  if (modal) modal.style.display = "none";
}
window.aspShowCompare = aspShowCompare;
window.aspCloseCompare = aspCloseCompare;

// ── Code gen ──────────────────────────────────────────────────
function aspShowCodeGen() {
  const modal = document.getElementById("asp-codegen-modal");
  if (!modal) return;
  modal.style.display = "flex";
  aspRefreshCodeGen();
}
function aspCloseCodeGen() {
  const modal = document.getElementById("asp-codegen-modal");
  if (modal) modal.style.display = "none";
}
function aspCodeGenLang(lang) {
  _aspCodeGenLang = lang;
  document.querySelectorAll(".asp-cg-lang").forEach(b => {
    b.classList.toggle("on", b.getAttribute("data-lang") === lang);
  });
  aspRefreshCodeGen();
}
async function aspRefreshCodeGen() {
  const out = document.getElementById("asp-codegen-out");
  if (!out) return;
  out.textContent = "Generating…";
  try {
    const snap = await _aspCodeGenSnapshot();
    const mask = !!(document.getElementById("asp-codegen-mask") || {}).checked;
    const data = mask ? _aspMaskSecretsDeep(snap) : snap;
    let code = "";
    switch (_aspCodeGenLang) {
      case "python": code = _aspGenPython(data); break;
      case "javascript": code = _aspGenJavascript(data); break;
      case "go": code = _aspGenGo(data); break;
      default: code = _aspGenCurl(data); break;
    }
    out.textContent = code;
  } catch (e) {
    out.textContent = "Error: " + (e.message || String(e));
  }
}
async function _aspCodeGenSnapshot() {
  // Prefer live form state (works before Send too)
  const method = (typeof _aspGetMethod === "function" ? _aspGetMethod() : "GET") || "GET";
  let url = (typeof _aspGetUrl === "function" ? _aspGetUrl() : "") || "";
  const params = {};
  if (typeof _aspGetRows === "function") {
    _aspGetRows("asp-params-table").filter(r => r.enabled && r.key)
      .forEach(r => { params[r.key] = r.value; });
  }
  const headers = {};
  if (typeof _aspGetRows === "function") {
    _aspGetRows("asp-headers-table").filter(r => r.enabled && r.key)
      .forEach(r => { headers[r.key] = r.value; });
  }
  let auth = typeof _aspGetAuth === "function"
    ? _aspGetAuth()
    : { type: "none", token: "", username: "", password: "" };
  try {
    const membership = typeof _aspGetActiveTabMembership === "function" ? _aspGetActiveTabMembership() : null;
    if (auth.type === "inherit" && typeof _aspResolveScopeAuth === "function") {
      auth = _aspResolveScopeAuth(membership && membership.col, membership && membership.folder);
    }
  } catch (_) {}
  if (auth.type === "bearer" && auth.token) {
    headers["Authorization"] = "Bearer " + auth.token;
  } else if (auth.type === "basic") {
    try {
      headers["Authorization"] = "Basic " + btoa((auth.username || "") + ":" + (auth.password || ""));
    } catch (_) {}
  }
  // Apply env/collection vars lightly on URL if helper exists
  try {
    const membership = typeof _aspGetActiveTabMembership === "function" ? _aspGetActiveTabMembership() : null;
    const vars = typeof _aspResolveActiveVars === "function"
      ? _aspResolveActiveVars(membership && membership.col, membership && membership.folder)
      : [];
    if (vars.length && typeof _aspApplyCollVars === "function") {
      url = _aspApplyCollVars(url, vars);
    }
  } catch (_) {}

  const bodyType = typeof _aspGetBodyType === "function" ? _aspGetBodyType() : "none";
  let bodyText = null;
  let isJson = false;
  if (bodyType === "raw" || bodyType === "json" || bodyType === "text") {
    bodyText = ((document.getElementById("asp-body-raw") || {}).value) || "";
    const lang = typeof _aspGetRawLang === "function" ? _aspGetRawLang() : "json";
    isJson = bodyType === "json" || lang === "json";
    if (isJson && typeof _aspStripJsonComments === "function") {
      bodyText = _aspStripJsonComments(bodyText);
    }
  } else if (bodyType === "form" && typeof _aspGetRows === "function") {
    const parts = _aspGetRows("asp-body-form-table").filter(r => r.enabled && r.key)
      .map(r => encodeURIComponent(r.key) + "=" + encodeURIComponent(r.value));
    bodyText = parts.join("&");
    if (!headers["Content-Type"] && !headers["content-type"]) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
    }
  } else if (bodyType === "graphql") {
    const query = ((document.getElementById("asp-gql-query") || {}).value || "").trim();
    const varsRaw = ((document.getElementById("asp-gql-vars") || {}).value || "").trim();
    let variables = {};
    if (varsRaw) { try { variables = JSON.parse(varsRaw); } catch (_) {} }
    bodyText = JSON.stringify({ query, variables });
    isJson = true;
    if (!headers["Content-Type"] && !headers["content-type"]) {
      headers["Content-Type"] = "application/json";
    }
  }

  // Build display URL from base + params table (URL bar may already include ?query).
  let fullUrl = url;
  if (typeof _aspSplitUrl === "function") {
    const split = _aspSplitUrl(url);
    const qs = Object.keys(params).map(k => encodeURIComponent(k) + "=" + encodeURIComponent(params[k])).join("&");
    fullUrl = qs ? `${split.base}?${qs}${split.hash || ""}` : `${split.base}${split.hash || ""}`;
  } else {
    const qs = Object.keys(params).map(k => encodeURIComponent(k) + "=" + encodeURIComponent(params[k])).join("&");
    if (qs) {
      const base = url.indexOf("?") >= 0 ? url.slice(0, url.indexOf("?")) : url;
      fullUrl = base + "?" + qs;
    }
  }

  return { method, url: fullUrl, headers, bodyText, isJson, params };
}
function _aspGenCurl(d) {
  const lines = [`curl -X ${d.method} '${String(d.url || "").replace(/'/g, "'\\''")}'`];
  Object.entries(d.headers || {}).forEach(([k, v]) => {
    lines.push(`  -H '${k}: ${String(v).replace(/'/g, "'\\''")}'`);
  });
  if (d.bodyText) {
    lines.push(`  --data-raw '${String(d.bodyText).replace(/'/g, "'\\''")}'`);
  }
  return lines.join(" \\\n");
}
function _aspGenPython(d) {
  const hdrs = JSON.stringify(d.headers || {}, null, 4);
  let bodyPart = "None";
  if (d.bodyText) {
    if (d.isJson) {
      try {
        bodyPart = "json=" + JSON.stringify(JSON.parse(d.bodyText), null, 4).replace(/\n/g, "\n    ");
      } catch (_) {
        bodyPart = "data=" + JSON.stringify(d.bodyText);
      }
    } else {
      bodyPart = "data=" + JSON.stringify(d.bodyText);
    }
  }
  const useJson = bodyPart.startsWith("json=");
  return [
    "import requests",
    "",
    `url = ${JSON.stringify(d.url)}`,
    `headers = ${hdrs}`,
    "",
    useJson
      ? `resp = requests.request(${JSON.stringify(d.method)}, url, headers=headers, ${bodyPart})`
      : (d.bodyText
        ? `resp = requests.request(${JSON.stringify(d.method)}, url, headers=headers, ${bodyPart})`
        : `resp = requests.request(${JSON.stringify(d.method)}, url, headers=headers)`),
    "print(resp.status_code)",
    "print(resp.text)",
  ].join("\n");
}
function _aspGenJavascript(d) {
  const hdrs = JSON.stringify(d.headers || {}, null, 2);
  const opts = {
    method: d.method,
    headers: d.headers || {},
  };
  let bodyLine = "";
  if (d.bodyText) {
    if (d.isJson) {
      try {
        bodyLine = `  body: JSON.stringify(${JSON.stringify(JSON.parse(d.bodyText), null, 2).split("\n").join("\n  ")}),`;
      } catch (_) {
        bodyLine = `  body: ${JSON.stringify(d.bodyText)},`;
      }
    } else {
      bodyLine = `  body: ${JSON.stringify(d.bodyText)},`;
    }
  }
  return [
    `fetch(${JSON.stringify(d.url)}, {`,
    `  method: ${JSON.stringify(d.method)},`,
    `  headers: ${hdrs.split("\n").join("\n  ")},`,
    bodyLine,
    "})",
    "  .then(r => r.text().then(t => ({ status: r.status, body: t })))",
    "  .then(console.log)",
    "  .catch(console.error);",
  ].filter(Boolean).join("\n");
}
function _aspGenGo(d) {
  const hdrLines = Object.entries(d.headers || {}).map(([k, v]) =>
    `\treq.Header.Set(${JSON.stringify(k)}, ${JSON.stringify(String(v))})`
  ).join("\n");
  const hasBody = !!(d.bodyText);
  return [
    "package main",
    "",
    "import (",
    '\t"fmt"',
    hasBody ? '\t"strings"' : "",
    '\t"io"',
    '\t"net/http"',
    ")",
    "",
    "func main() {",
    hasBody
      ? `\tbody := strings.NewReader(${JSON.stringify(d.bodyText)})\n\treq, err := http.NewRequest(${JSON.stringify(d.method)}, ${JSON.stringify(d.url)}, body)`
      : `\treq, err := http.NewRequest(${JSON.stringify(d.method)}, ${JSON.stringify(d.url)}, nil)`,
    "\tif err != nil { panic(err) }",
    hdrLines,
    "\tresp, err := http.DefaultClient.Do(req)",
    "\tif err != nil { panic(err) }",
    "\tdefer resp.Body.Close()",
    "\tb, _ := io.ReadAll(resp.Body)",
    '\tfmt.Println(resp.StatusCode)',
    "\tfmt.Println(string(b))",
    "}",
  ].filter(l => l !== "").join("\n");
}
function aspCopyCodeGen() {
  const out = document.getElementById("asp-codegen-out");
  const text = out ? out.textContent : "";
  if (!text) return;
  _aspClipboard(text, null, "Copy");
  _aspShowToast("Code copied");
}
window.aspShowCodeGen = aspShowCodeGen;
window.aspCloseCodeGen = aspCloseCodeGen;
window.aspCodeGenLang = aspCodeGenLang;
window.aspRefreshCodeGen = aspRefreshCodeGen;
window.aspCopyCodeGen = aspCopyCodeGen;

// ── OpenAPI / Swagger → Collection ────────────────────────────
function aspImportOpenApiFile(input) {
  const files = input.files;
  if (!files || !files.length) return;
  Array.from(files).forEach(file => {
    const reader = new FileReader();
    reader.onload = async e => {
      const text = e.target.result;
      let spec;
      try {
        spec = await _aspParseOpenApiText(text, file.name);
      } catch (err) {
        _aspAlert(`Failed to parse ${file.name}:\n${err.message || err}`);
        return;
      }
      if (!spec || !spec.paths || typeof spec.paths !== "object") {
        _aspAlert(`${file.name} is not a valid OpenAPI/Swagger document (missing paths).`);
        return;
      }
      _aspOaPending = { spec, fileName: file.name };
      const guess = _aspGuessOpenApiBaseUrl(spec);
      const count = _aspCountOpenApiOps(spec);
      const title = (spec.info && spec.info.title) || file.name.replace(/\.(json|ya?ml)$/i, "");
      const sum = document.getElementById("asp-oa-summary");
      if (sum) {
        sum.textContent = `"${title}" — ${count} operations found. Set the server base URL, then Import.`;
      }
      const inp = document.getElementById("asp-oa-baseurl");
      if (inp) inp.value = guess;
      const modal = document.getElementById("asp-oa-modal");
      if (modal) modal.style.display = "flex";
    };
    reader.onerror = () => _aspAlert(`Failed to read ${file.name}`);
    reader.readAsText(file);
  });
  input.value = "";
}
function aspCloseOpenApiModal() {
  const modal = document.getElementById("asp-oa-modal");
  if (modal) modal.style.display = "none";
  _aspOaPending = null;
}
function aspConfirmOpenApiImport() {
  if (!_aspOaPending) return;
  const base = ((document.getElementById("asp-oa-baseurl") || {}).value || "").trim().replace(/\/+$/, "");
  if (!base || !/^https?:\/\//i.test(base)) {
    _aspAlert("Enter a valid base URL starting with http:// or https://");
    return;
  }
  const { spec, fileName } = _aspOaPending;
  const col = _aspOpenApiToCollection(spec, base, fileName);
  const cols = _aspGetColls();
  cols.push(col);
  _aspSaveColls(cols);
  aspCloseOpenApiModal();
  if (!_aspCollOpen) aspToggleColl(); else _aspRenderCollPanel();
  _aspShowToast(`Imported OpenAPI → ${col.name} (${_aspCountOpenApiOps(spec)} ops)`);
}
async function _aspParseOpenApiText(text, fileName) {
  const t = String(text || "").trim();
  if (!t) throw new Error("Empty file");
  // JSON fast-path
  if (t[0] === "{" || t[0] === "[") {
    return JSON.parse(t);
  }
  // YAML / other → backend (PyYAML when available via app env)
  const base = (typeof ASP_BASE !== "undefined" ? ASP_BASE : "http://127.0.0.1:8791");
  try {
    const r = await fetch(base + "/parse-openapi", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: t, filename: fileName || "" }),
    });
    const d = await r.json();
    if (d && d.ok && d.spec) return d.spec;
    throw new Error((d && d.error) || "Parse failed");
  } catch (e) {
    throw new Error(
      (e && e.message) ||
      "Could not parse YAML. Convert to JSON (Swagger Editor → Convert and save as JSON) and retry."
    );
  }
}
function _aspGuessOpenApiBaseUrl(spec) {
  if (Array.isArray(spec.servers) && spec.servers[0] && spec.servers[0].url) {
    let u = String(spec.servers[0].url);
    // Resolve relative server URLs poorly — leave as-is if absolute
    if (/^https?:\/\//i.test(u)) return u.replace(/\/+$/, "");
  }
  if (spec.host) {
    const scheme = (Array.isArray(spec.schemes) && spec.schemes[0]) || "https";
    const basePath = spec.basePath || "";
    return (scheme + "://" + spec.host + basePath).replace(/\/+$/, "");
  }
  return "https://api.example.com";
}
function _aspCountOpenApiOps(spec) {
  let n = 0;
  Object.values(spec.paths || {}).forEach(pathItem => {
    if (!pathItem || typeof pathItem !== "object") return;
    ["get","post","put","patch","delete","head","options"].forEach(m => {
      if (pathItem[m]) n++;
    });
  });
  return n;
}
function _aspOpenApiParamExample(p) {
  if (!p) return "value";
  if (p.example != null) return String(p.example);
  const schema = p.schema || {};
  if (schema.example != null) return String(schema.example);
  if (schema.default != null) return String(schema.default);
  const t = p.type || schema.type || "string";
  if (t === "integer" || t === "number") return "0";
  if (t === "boolean") return "false";
  if (t === "array") return "item";
  return "string";
}
function _aspOpenApiToCollection(spec, baseUrl, fileName) {
  const title = (spec.info && spec.info.title) || (fileName || "OpenAPI").replace(/\.(json|ya?ml)$/i, "");
  const byTag = {}; // tag -> items
  const untagged = [];

  Object.keys(spec.paths || {}).forEach(pathKey => {
    const pathItem = spec.paths[pathKey];
    if (!pathItem || typeof pathItem !== "object") return;
    ["get","post","put","patch","delete","head","options"].forEach(method => {
      const op = pathItem[method];
      if (!op || typeof op !== "object") return;

      // Path params → replace {id} with example
      let path = pathKey;
      const allParams = []
        .concat(Array.isArray(pathItem.parameters) ? pathItem.parameters : [])
        .concat(Array.isArray(op.parameters) ? op.parameters : []);
      allParams.forEach(p => {
        if (!p || p.in !== "path") return;
        const ex = _aspOpenApiParamExample(p);
        path = path.replace(new RegExp("\\{" + p.name + "\\}", "g"), encodeURIComponent(ex));
        path = path.replace(new RegExp(":" + p.name + "\\b", "g"), encodeURIComponent(ex));
      });

      const queryParams = allParams
        .filter(p => p && p.in === "query")
        .map(p => ({
          enabled: !!p.required,
          key: p.name || "",
          value: _aspOpenApiParamExample(p),
        }))
        .filter(p => p.key);

      const headers = allParams
        .filter(p => p && p.in === "header" && !/^content-type$/i.test(p.name || ""))
        .map(p => ({
          enabled: true,
          key: p.name || "",
          value: _aspOpenApiParamExample(p),
        }))
        .filter(h => h.key);

      let bodyType = "none";
      let bodyRaw = "";
      let bodyRawLang = "json";
      // OAS3 requestBody
      const rb = op.requestBody;
      if (rb && rb.content) {
        if (rb.content["application/json"]) {
          bodyType = "raw";
          bodyRawLang = "json";
          const ex = rb.content["application/json"].example
            || (rb.content["application/json"].examples &&
                Object.values(rb.content["application/json"].examples)[0] &&
                Object.values(rb.content["application/json"].examples)[0].value)
            || rb.content["application/json"].schema;
          try {
            bodyRaw = typeof ex === "string" ? ex : JSON.stringify(_aspSchemaStub(ex), null, 2);
          } catch (_) { bodyRaw = "{\n  \n}"; }
        } else if (rb.content["application/x-www-form-urlencoded"]) {
          bodyType = "form";
        } else if (rb.content["multipart/form-data"]) {
          bodyType = "multipart";
        } else {
          const first = Object.keys(rb.content)[0];
          if (first) {
            bodyType = "raw";
            bodyRawLang = first.includes("json") ? "json" : "text";
            bodyRaw = "";
          }
        }
      }
      // Swagger2 body param
      const bodyParam = allParams.find(p => p && p.in === "body");
      if (bodyParam && bodyType === "none") {
        bodyType = "raw";
        bodyRawLang = "json";
        try {
          bodyRaw = JSON.stringify(
            bodyParam.schema ? _aspSchemaStub(bodyParam.schema) : (bodyParam.example || {}),
            null, 2
          );
        } catch (_) { bodyRaw = "{}"; }
      }

      const name = op.summary || op.operationId || `${method.toUpperCase()} ${pathKey}`;
      const item = {
        id: "oa_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        name,
        method: method.toUpperCase(),
        url: baseUrl.replace(/\/+$/, "") + (path.startsWith("/") ? path : "/" + path),
        params: queryParams,
        headers,
        auth: { type: "inherit", token: "", username: "", password: "" },
        bodyType,
        bodyRawLang,
        bodyRaw,
        bodyForm: [],
        bodyMultipart: [],
        bodyBinary: null,
        bodyGraphqlQuery: "",
        bodyGraphqlVars: "",
        preRequestScript: "",
        testScript: "",
        reqTab: "params",
        sourceTabId: null,
      };

      const tags = Array.isArray(op.tags) && op.tags.length ? op.tags : ["Default"];
      const tag = tags[0];
      if (!byTag[tag]) byTag[tag] = [];
      byTag[tag].push(item);
    });
  });

  const items = Object.keys(byTag).sort().map(tag => {
    const folder = (typeof _aspBlankFolder === "function")
      ? _aspBlankFolder(tag)
      : { type: "folder", id: "fld_" + Math.random().toString(36).slice(2, 8), name: tag, expanded: true, items: [], auth: { type: "inherit", token: "", username: "", password: "" }, variables: [] };
    folder.items = byTag[tag];
    folder.expanded = true;
    return folder;
  });

  // Collection variables from servers / security — skip secrets
  const variables = [];
  if (baseUrl) variables.push({ enabled: true, key: "baseUrl", value: baseUrl });

  return {
    id: typeof _aspMkCollId === "function" ? _aspMkCollId() : ("col_" + Date.now().toString(36)),
    name: title,
    expanded: true,
    items: items.length ? items : untagged,
    auth: { type: "none", token: "", username: "", password: "" },
    variables,
  };
}
function _aspSchemaStub(schema) {
  if (!schema || typeof schema !== "object") return {};
  if (schema.example != null) return schema.example;
  if (schema.default != null) return schema.default;
  if (schema.$ref) return { $ref: schema.$ref };
  const t = schema.type;
  if (t === "object" || schema.properties) {
    const o = {};
    Object.keys(schema.properties || {}).forEach(k => {
      o[k] = _aspSchemaStub(schema.properties[k]);
    });
    return o;
  }
  if (t === "array") return [ _aspSchemaStub(schema.items || {}) ];
  if (t === "integer" || t === "number") return 0;
  if (t === "boolean") return false;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  return "";
}
window.aspImportOpenApiFile = aspImportOpenApiFile;
window.aspCloseOpenApiModal = aspCloseOpenApiModal;
window.aspConfirmOpenApiImport = aspConfirmOpenApiImport;
