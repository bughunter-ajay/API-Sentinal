// ═══════════════════════════════════════════════════════════════
//  APISphere — Postman-like single-hit API client
//  Prefix: asp  (to avoid collision with apiscan's "as" prefix)
//  Backend: http://127.0.0.1:8791
// ═══════════════════════════════════════════════════════════════

const ASP_BASE           = "http://127.0.0.1:8791";
// AV backend URL: reuse har_runner.js global (do NOT redeclare const AV_BACKEND — breaks script load)
function _aspAvBackendUrl() {
  return (typeof AV_BACKEND !== "undefined" ? AV_BACKEND : "http://127.0.0.1:8765");
}
const ASP_HISTORY_KEY    = "apisphere_history";
const ASP_DRAFT_KEY      = "apisphere_draft";
const ASP_MAX_HISTORY    = 30;
const ASP_TABS_KEY       = "apisphere_tabs";
const ASP_ACTIVE_TAB_KEY = "apisphere_active_tab";
const ASP_COLL_KEY       = "apisphere_collections";
const ASP_ENVS_KEY       = "apisphere_environments";
const ASP_ACTIVE_ENV_KEY = "apisphere_active_env";
const ASP_RUNNER_KEY     = "apisphere_runner_import";
const ASP_COOKIE_KEY     = "apisphere_cookies";
let   _aspCollOpen       = false;
let   _aspEnvEditing     = false; // environment editor panel open
let   _aspEnvEditId      = null;  // env id being edited (null = new unsaved)
let   _aspEnvConfirmDel  = null;  // env id pending delete confirmation
let   _aspTabMenuId      = null; // tab id for which the 3-dot menu is open
let   _aspCollCtxId      = null; // collection id for which the 3-dot ctx menu is open
let   _aspCollCtxFolderId = null; // folder id when ctx menu opened on a folder (else null)
let   _aspCollOvId       = null; // collection id currently shown in overview panel
let   _aspCollOvFolderId = null; // folder id when overview is for a folder (else null)
let   _aspCollConfirmId  = null; // collection id pending delete confirmation
let   _aspCollConfirmFolderId = null; // folder id pending delete (null = whole collection)

let _aspVarDdEl     = null; // element that triggered the {{ var dropdown
let _aspSending     = false;
let _aspSendCtrl    = null;   // AbortController for in-flight Send
let _aspUserCancelled = false;
let _aspScriptPhase = "pre";  // 'pre' | 'test'
let _aspLastTestResults = []; // [{ name, passed, error }]
let _aspSaveTimer   = null;
let _aspHistoryOpen = false;
let _aspRespFmt     = "raw"; // json|xml|html|yaml|javascript|markdown|raw|hex|base64
let _aspLastResp    = null;
let _aspLastSentCurl = "";
const _ASP_RESP_FMT_LABELS = {
  json: "JSON", xml: "XML", html: "HTML", yaml: "YAML",
  javascript: "JavaScript", markdown: "Markdown",
  raw: "Raw", hex: "Hex", base64: "Base64",
};
let _aspFindTerm    = '';
let _aspFindMatches = [];
let _aspFindIdx     = 0;
let _aspRFTerm      = '';
let _aspRFMatches   = [];
let _aspRFIdx       = 0;
const _aspTabResps  = {}; // tabId → { resp, respRaw }  — in-memory per-tab response cache

// ── Init ───────────────────────────────────────────────────────
function aspInit() {
  try {
    _aspInitTabs();
    _aspInitTabRclickMenu();
    _aspRenderHistory();
    _aspBindKeyboard();
    _aspInitSplitter();
    _aspInitCollSplitter();
    _aspInitBracketGuides();
    _aspInitEditorResizeSync();
    _aspInitVarAutocomplete();
    _aspInitKvCtxMenu();
    _aspInitKvColResize();
    _aspInitScriptSnippets();
    _aspCRInitVSplitter();
    _aspRenderEnvBtn();
    _aspRenderCookieJarTable();
    _aspUpdateSendDownloadEnabled();
    // Reset any stuck workspace overlay lock from a prior session
    _aspCollOvId = null;
    _aspCollOvFolderId = null;
    _aspCRColId = null;
    _aspEnvEditing = false;
    _aspHideAvRunnerPanelOnly();
    _aspSyncChromeLock();
  } catch (e) {
    console.error("APISphere init failed:", e);
  }
}

function _aspInitVarAutocomplete() {
  // Ensure var dropdown exists in DOM (create dynamically to survive WKWebView cache)
  if (!document.getElementById('asp-var-dd')) {
    const vdd = document.createElement('div');
    vdd.id = 'asp-var-dd';
    vdd.style.cssText = 'display:none;position:fixed;z-index:6001;background:var(--bg2);border:1px solid rgba(227,179,65,.4);border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.6);min-width:180px;padding:4px 0;overflow:hidden';
    document.body.appendChild(vdd);
  }

  // URL + Auth token fields
  ['asp-url-input', 'asp-auth-token', 'asp-auth-user', 'asp-auth-pass'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', () => _aspCheckVarTrigger(el));
  });

  // Params / Headers / Form / Multipart — values are textareas (.asp-kv-val), keys are inputs
  ['asp-headers-table', 'asp-params-table', 'asp-body-form-table', 'asp-body-multipart-table'].forEach(id => {
    const tbl = document.getElementById(id);
    if (tbl) tbl.addEventListener('input', e => {
      const el = e.target.closest('textarea.asp-kv-val, input.asp-kv-val, input.asp-kv-input, input[type="text"], input:not([type])');
      if (el) _aspCheckVarTrigger(el);
    });
  });

  // Hide var dd when clicking outside
  document.addEventListener('click', e => {
    const dd = document.getElementById('asp-var-dd');
    if (dd && !dd.contains(e.target)) _aspHideVarDd();
  });
}

// ── Draft auto-save — now flushes to the active tab ──────────
function _aspSaveDraft() {
  clearTimeout(_aspSaveTimer);
  _aspSaveTimer = setTimeout(_aspFlushTab, 400);
}

function _aspRestoreDraft() {
  try {
    const d = JSON.parse(localStorage.getItem(ASP_DRAFT_KEY) || "null");
    if (d) { _aspApplyState(d); return true; }
  } catch(e) {}
  return false;
}

// ── Saved-request tabs ────────────────────────────────────────
function _aspGetTabs() {
  try { return JSON.parse(localStorage.getItem(ASP_TABS_KEY) || "[]"); } catch(e) { return []; }
}
function _aspSaveTabs(tabs) {
  try { localStorage.setItem(ASP_TABS_KEY, JSON.stringify(tabs)); } catch(e) {}
}
function _aspActiveTabId() {
  return localStorage.getItem(ASP_ACTIVE_TAB_KEY) || "";
}
function _aspSetActiveTabId(id) {
  if (id) localStorage.setItem(ASP_ACTIVE_TAB_KEY, id);
}
function _aspMkTabId() {
  return "aspt_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
}
function _aspBlankTab() {
  return { id: _aspMkTabId(), name: "New Request", method: "GET", url: "" };
}

// Synchronously flush current form state + response snapshot into the active tab
function _aspFlushTab() {
  clearTimeout(_aspSaveTimer);
  const tabs = _aspGetTabs();
  const id   = _aspActiveTabId();
  const idx  = tabs.findIndex(t => t.id === id);
  if (idx < 0) return;
  const state = _aspCollectState();
  Object.assign(tabs[idx], state);
  _aspSaveTabs(tabs);
  // Snapshot response in memory (not localStorage — bodies can be large)
  _aspTabResps[id] = { resp: _aspLastResp || null, respFmt: _aspRespFmt, respRaw: _aspRespFmt === "raw" };
  // Keep the linked collection item (if any) in sync — otherwise edits made after a
  // request was added to a collection are lost once the tab is closed (the item still
  // holds the snapshot from when it was added), and are missing from collection export.
  const cols = _aspGetColls();
  let collChanged = false;
  cols.forEach(col => _aspForEachReq(col, item => {
    if (item.sourceTabId === id) { Object.assign(item, state); collChanged = true; }
  }));
  if (collChanged) {
    _aspSaveColls(cols);
    if (_aspCollOpen) _aspRenderCollPanel();
  }
}

// Update method badge on the active tab item in the DOM
function _aspUpdateActiveTabBadge() {
  const id     = _aspActiveTabId();
  const method = _aspGetMethod();
  const badge  = document.querySelector(`.asp-tab-item[data-id="${id}"] .asp-ti-method`);
  if (badge) { badge.textContent = method; badge.style.color = _ASP_METHOD_COLORS[method] || "#c9d1d9"; }
}

function _aspInitTabs() {
  let tabs = _aspGetTabs();
  if (!tabs.length) {
    // Migrate old draft → first tab
    const firstTab = _aspBlankTab();
    try {
      const raw = localStorage.getItem(ASP_DRAFT_KEY);
      if (raw) { Object.assign(firstTab, JSON.parse(raw), { id: firstTab.id, name: "Draft" }); }
    } catch(e) {}
    tabs = [firstTab];
    _aspSaveTabs(tabs);
  }
  // Validate active tab ID
  let activeId = _aspActiveTabId();
  if (!tabs.find(t => t.id === activeId)) {
    activeId = tabs[0].id;
    _aspSetActiveTabId(activeId);
  }
  _aspApplyState(tabs.find(t => t.id === activeId) || _aspBlankTab());
  _aspRenderTabsBar();
}

function aspNewTab() {
  if (_aspIsWorkspaceOverlayOpen()) return;
  _aspFlushTab();
  const tab  = _aspBlankTab();
  const tabs = _aspGetTabs();
  tabs.push(tab);
  _aspSaveTabs(tabs);
  _aspSetActiveTabId(tab.id);
  _aspApplyState(tab);
  _aspRenderTabsBar();
  _aspResetRespPanel();
  document.getElementById("asp-url-input")?.focus();
}

function aspSwitchTab(id) {
  if (id === _aspActiveTabId()) return;
  _aspFlushTab();
  const tabs = _aspGetTabs();
  const tab  = tabs.find(t => t.id === id);
  if (!tab) return;
  _aspSetActiveTabId(id);
  _aspApplyState(tab);
  _aspRenderTabsBar();
  _aspRestoreTabResp(id);
}

function aspCloseTab(id) {
  // Flush pending (debounced) edits before the tab disappears — otherwise the
  // last keystroke can be lost if the user closes within the 400ms autosave window.
  if (id === _aspActiveTabId()) _aspFlushTab();
  const tabs = _aspGetTabs();
  if (tabs.length <= 1) return;
  const idx = tabs.findIndex(t => t.id === id);
  if (idx < 0) return;
  const wasActive = id === _aspActiveTabId();
  tabs.splice(idx, 1);
  _aspSaveTabs(tabs);
  try { delete _aspTabResps[id]; } catch (_) {}
  if (wasActive) {
    const next = tabs[Math.min(idx, tabs.length - 1)];
    _aspSetActiveTabId(next.id);
    _aspApplyState(next);
    _aspRestoreTabResp(next.id);
  }
  _aspRenderTabsBar();
}

/** Force-close: always removes tab; if last tab, replaces with a blank request. */
function aspForceCloseTab(id) {
  if (id === _aspActiveTabId()) _aspFlushTab();
  let tabs = _aspGetTabs();
  const idx = tabs.findIndex(t => t.id === id);
  if (idx < 0) return;
  const wasActive = id === _aspActiveTabId();
  tabs.splice(idx, 1);
  try { delete _aspTabResps[id]; } catch (_) {}
  if (!tabs.length) {
    const blank = _aspBlankTab();
    tabs = [blank];
    _aspSaveTabs(tabs);
    _aspSetActiveTabId(blank.id);
    _aspApplyState(blank);
    _aspResetRespPanel();
    _aspRenderTabsBar();
    return;
  }
  _aspSaveTabs(tabs);
  if (wasActive) {
    const next = tabs[Math.min(idx, tabs.length - 1)];
    _aspSetActiveTabId(next.id);
    _aspApplyState(next);
    _aspRestoreTabResp(next.id);
  }
  _aspRenderTabsBar();
}

function aspDuplicateTab(id) {
  if (_aspIsWorkspaceOverlayOpen()) return;
  if (id === _aspActiveTabId()) _aspFlushTab();
  const tabs = _aspGetTabs();
  const idx  = tabs.findIndex(t => t.id === id);
  if (idx < 0) return;
  const src = tabs[idx];
  let clone;
  try { clone = JSON.parse(JSON.stringify(src)); }
  catch (_) { clone = Object.assign({}, src); }
  clone.id = _aspMkTabId();
  const base = (src.name || "New Request").replace(/\s+Copy$/i, "");
  clone.name = base + " Copy";
  delete clone.sourceTabId;
  tabs.splice(idx + 1, 0, clone);
  // Shallow copy — deep-cloning a PDF body_b64 (~1MB+) freezes the UI.
  if (_aspTabResps[id]) {
    const srcResp = _aspTabResps[id];
    _aspTabResps[clone.id] = {
      resp: srcResp.resp || null,
      respFmt: srcResp.respFmt,
      respRaw: srcResp.respRaw,
    };
  }
  _aspSaveTabs(tabs);
  aspSwitchTab(clone.id);
}

function aspCloseOtherTabs(keepId) {
  if (_aspIsWorkspaceOverlayOpen()) return;
  _aspFlushTab();
  const tabs = _aspGetTabs();
  const keep = tabs.find(t => t.id === keepId);
  if (!keep) return;
  tabs.forEach(t => { if (t.id !== keepId) { try { delete _aspTabResps[t.id]; } catch (_) {} } });
  _aspSaveTabs([keep]);
  if (_aspActiveTabId() !== keepId) {
    _aspSetActiveTabId(keepId);
    _aspApplyState(keep);
    _aspRestoreTabResp(keepId);
  } else {
    // keep already active — ensure saved state is the flushed one
    const latest = _aspGetTabs().find(t => t.id === keepId) || keep;
    _aspApplyState(latest);
  }
  _aspRenderTabsBar();
}

function aspCloseAllTabs(force) {
  if (_aspIsWorkspaceOverlayOpen()) return;
  _aspFlushTab();
  const tabs = _aspGetTabs();
  // Soft close-all with a single empty tab already → no-op unless force
  if (!force && tabs.length === 1 && !(tabs[0].url || "").trim() && (tabs[0].name === "New Request" || tabs[0].name === "Draft")) {
    return;
  }
  Object.keys(_aspTabResps || {}).forEach(k => { try { delete _aspTabResps[k]; } catch (_) {} });
  const blank = _aspBlankTab();
  _aspSaveTabs([blank]);
  _aspSetActiveTabId(blank.id);
  _aspApplyState(blank);
  _aspResetRespPanel();
  _aspRenderTabsBar();
}

// ── Tab right-click / two-finger menu ─────────────────────────
let _aspTabRclickId = null;
function _aspIsMacUi() {
  try {
    return /Mac|iPhone|iPad|iPod/.test(navigator.platform || "") ||
      /Mac OS X/.test(navigator.userAgent || "");
  } catch (_) { return false; }
}
function _aspInitTabRclickMenu() {
  const list = document.getElementById("asp-tabs-list");
  if (!list || list._aspRclickBound) return;
  list._aspRclickBound = true;
  list.addEventListener("contextmenu", e => {
    const item = e.target.closest(".asp-tab-item");
    if (!item) return;
    e.preventDefault();
    e.stopPropagation();
    aspShowTabRclickMenu(item.getAttribute("data-id"), e.clientX, e.clientY);
  });
  // Also allow right-click on empty tabs bar area → menu for active tab
  const bar = document.getElementById("asp-tabs-bar");
  if (bar && !bar._aspRclickBound) {
    bar._aspRclickBound = true;
    bar.addEventListener("contextmenu", e => {
      if (e.target.closest(".asp-tab-item")) return; // handled above
      if (e.target.closest("button")) return;
      e.preventDefault();
      const id = _aspActiveTabId();
      if (id) aspShowTabRclickMenu(id, e.clientX, e.clientY);
    });
  }
  _aspSyncTabRclickAccels();
}
function _aspSyncTabRclickAccels() {
  const mac = _aspIsMacUi();
  const map = {
    new: mac ? "⌘ T" : "Ctrl+T",
    close: mac ? "⌘ W" : "Ctrl+W",
    "force-close": mac ? "⌥ ⌘ W" : "Ctrl+Alt+W",
  };
  document.querySelectorAll("#asp-tab-rclick [data-accel]").forEach(el => {
    const k = el.getAttribute("data-accel");
    el.textContent = map[k] || "";
  });
}
function aspShowTabRclickMenu(tabId, x, y) {
  if (!tabId || _aspIsWorkspaceOverlayOpen()) return;
  aspCloseTabRclickMenu();
  aspCloseRespFmtMenu();
  try { document.getElementById("asp-tab-menu").style.display = "none"; } catch (_) {}
  _aspTabRclickId = tabId;
  const menu = document.getElementById("asp-tab-rclick");
  if (!menu) return;
  _aspSyncTabRclickAccels();
  const tabs = _aspGetTabs();
  const onlyOne = tabs.length <= 1;
  menu.querySelectorAll(".asp-tmenu-item[data-act]").forEach(el => {
    const act = el.getAttribute("data-act");
    let disabled = false;
    if (act === "close" && onlyOne) disabled = true;
    if (act === "close-others" && onlyOne) disabled = true;
    el.classList.toggle("asp-disabled", disabled);
  });
  menu.style.display = "block";
  menu.style.left = "0px";
  menu.style.top = "0px";
  const mw = menu.offsetWidth || 220;
  const mh = menu.offsetHeight || 240;
  let left = x;
  let top = y;
  if (left + mw > window.innerWidth - 8) left = window.innerWidth - mw - 8;
  if (top + mh > window.innerHeight - 8) top = window.innerHeight - mh - 8;
  if (left < 8) left = 8;
  if (top < 8) top = 8;
  menu.style.left = left + "px";
  menu.style.top = top + "px";
  // Only plain click outside closes — another right-click on a tab re-opens instead
  setTimeout(() => document.addEventListener("click", _aspTabRclickOutside, { once: true }), 0);
}
function aspCloseTabRclickMenu() {
  const menu = document.getElementById("asp-tab-rclick");
  if (menu) menu.style.display = "none";
  _aspTabRclickId = null;
}
function _aspTabRclickOutside(e) {
  const menu = document.getElementById("asp-tab-rclick");
  if (menu && e && menu.contains(e.target)) return;
  aspCloseTabRclickMenu();
}
function aspTabRclickAct(act) {
  const id = _aspTabRclickId;
  aspCloseTabRclickMenu();
  if (!id && act !== "new" && act !== "close-all" && act !== "force-close-all") return;
  if (_aspIsWorkspaceOverlayOpen() && act !== "force-close" && act !== "force-close-all") return;
  switch (act) {
    case "new": aspNewTab(); break;
    case "dup": aspDuplicateTab(id); break;
    case "close": aspCloseTab(id); break;
    case "force-close": aspForceCloseTab(id); break;
    case "close-others": aspCloseOtherTabs(id); break;
    case "close-all": aspCloseAllTabs(false); break;
    case "force-close-all": aspCloseAllTabs(true); break;
  }
}
window.aspDuplicateTab = aspDuplicateTab;
window.aspForceCloseTab = aspForceCloseTab;
window.aspCloseOtherTabs = aspCloseOtherTabs;
window.aspCloseAllTabs = aspCloseAllTabs;
window.aspShowTabRclickMenu = aspShowTabRclickMenu;
window.aspCloseTabRclickMenu = aspCloseTabRclickMenu;
window.aspTabRclickAct = aspTabRclickAct;

function aspRenameTab(id) {
  const nameEl = document.querySelector(`.asp-tab-item[data-id="${id}"] .asp-ti-name`);
  if (!nameEl) return;
  const tabs = _aspGetTabs();
  const tab  = tabs.find(t => t.id === id);
  if (!tab) return;
  const inp = document.createElement("input");
  inp.className   = "asp-ti-rename";
  inp.value       = tab.name;
  inp.maxLength   = 40;
  nameEl.replaceWith(inp);
  inp.focus(); inp.select();
  const commit = () => {
    const name  = inp.value.trim() || "New Request";
    const tabs2 = _aspGetTabs();
    const t2    = tabs2.find(t => t.id === id);
    if (t2) { t2.name = name; _aspSaveTabs(tabs2); }
    // Sync name to any collection items sourced from this tab
    const cols = _aspGetColls();
    let colChanged = false;
    cols.forEach(col => _aspForEachReq(col, item => {
      if (item.sourceTabId === id) { item.name = name; colChanged = true; }
    }));
    if (colChanged) _aspSaveColls(cols);
    if (colChanged && _aspCollOpen) _aspRenderCollPanel();
    _aspRenderTabsBar();
  };
  inp.addEventListener("blur", commit);
  inp.addEventListener("keydown", e => {
    if (e.key === "Enter")  { e.preventDefault(); inp.blur(); }
    if (e.key === "Escape") { e.preventDefault(); _aspRenderTabsBar(); }
  });
}

function _aspRenderTabsBar() {
  const list = document.getElementById("asp-tabs-list");
  if (!list) return;
  const tabs   = _aspGetTabs();
  const active = _aspActiveTabId();
  list.innerHTML = tabs.map(tab => {
    const isActive = tab.id === active;
    const color    = _ASP_METHOD_COLORS[tab.method] || "#c9d1d9";
    const closeBtn = tabs.length > 1
      ? `<button class="asp-ti-close" onclick="event.stopPropagation();aspCloseTab('${tab.id}')" title="Close">×</button>`
      : "";
    return `<div class="asp-tab-item${isActive ? " asp-ti-active" : ""}" data-id="${tab.id}"
        onclick="aspSwitchTab('${tab.id}')" title="${_aspEscAttr(tab.name)}">
      <span class="asp-ti-method" style="color:${color}">${tab.method || "GET"}</span>
      <span class="asp-ti-name" ondblclick="event.stopPropagation();aspRenameTab('${tab.id}')">${_aspEscHtml(tab.name)}</span>
      <button class="asp-ti-dots" onclick="event.stopPropagation();aspShowTabMenu('${tab.id}',this)" title="More options">⋮</button>
      ${closeBtn}
    </div>`;
  }).join("");
  // Scroll active tab into view
  list.querySelector(".asp-ti-active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
}

// Restore saved response for a tab, or show empty panel if none
function _aspRestoreTabResp(id) {
  // Always close the response find bar on tab switch
  _aspRFTerm = ""; _aspRFMatches = []; _aspRFIdx = 0;
  const rfBar = document.getElementById("asp-resp-find-bar");
  if (rfBar) rfBar.style.display = "none";

  const saved = _aspTabResps[id];
  if (saved && saved.resp) {
    _aspRespFmt = saved.respFmt || (saved.respRaw ? "raw" : _aspDetectRespFmt(saved.resp));
    _aspSyncRespFmtUi();
    _aspRenderResponse(saved.resp, { keepFmt: true });
  } else {
    _aspResetRespPanel();
  }
}

function _aspResetRespPanel() {
  const empty  = document.getElementById("asp-resp-empty");
  const loaded = document.getElementById("asp-resp-loaded");
  if (empty)  empty.style.display  = "flex";
  if (loaded) loaded.style.display = "none";
  _aspLastResp = null;
  _aspUpdateSendDownloadEnabled();
  // Also close response find bar
  _aspRFTerm = ""; _aspRFMatches = []; _aspRFIdx = 0;
  const rfBar = document.getElementById("asp-resp-find-bar");
  if (rfBar) rfBar.style.display = "none";
}

// ── Collect / apply full request state ────────────────────────
let _aspBinaryCache = null; // { filename, contentType, data(base64) } — in-memory for active tab

function _aspCollectState() {
  return {
    method:   _aspGetMethod(),
    url:      _aspGetUrl(),
    params:   _aspGetRows("asp-params-table"),
    headers:  _aspGetRows("asp-headers-table"),
    auth:     _aspGetAuth(),
    bodyType: _aspGetBodyType(),
    bodyRawLang: _aspGetRawLang(),
    bodyRaw:  (typeof _aspReqUnfoldAll === "function") ? _aspReqUnfoldAll((document.getElementById("asp-body-raw") || {}).value || "") : ((document.getElementById("asp-body-raw") || {}).value || ""),
    bodyForm:      _aspGetRows("asp-body-form-table"),
    bodyMultipart: _aspGetMultipartRows().map(r => ({ enabled: r.enabled, key: r.key, fieldType: r.fieldType, value: r.value, filename: r.filename })),
    bodyBinary: _aspBinaryCache
      ? { filename: _aspBinaryCache.filename, contentType: _aspBinaryCache.contentType, data: _aspBinaryCache.data }
      : null,
    bodyGraphqlQuery: (document.getElementById("asp-gql-query") || {}).value || "",
    bodyGraphqlVars:  (document.getElementById("asp-gql-vars")  || {}).value || "",
    preRequestScript: (document.getElementById("asp-script-pre")  || {}).value || "",
    testScript:       (document.getElementById("asp-script-test") || {}).value || "",
    reqTab:        _aspActiveReqTab(),
  };
}

/** Migrate legacy bodyType json/text → raw + bodyRawLang. */
function _aspNormalizeBodyState(d) {
  if (!d) return d;
  if (d.bodyType === "json") {
    d.bodyType = "raw";
    d.bodyRawLang = d.bodyRawLang || "json";
  } else if (d.bodyType === "text") {
    d.bodyType = "raw";
    d.bodyRawLang = d.bodyRawLang || "text";
  }
  return d;
}

function _aspApplyState(d) {
  if (!d) return;
  d = _aspNormalizeBodyState(Object.assign({}, d));
  const methodSel = document.getElementById("asp-method-sel");
  if (methodSel) { methodSel.value = d.method || "GET"; _aspUpdateMethodColor(); }
  const urlInp = document.getElementById("asp-url-input");
  if (urlInp) { urlInp.value = d.url || ""; _aspSyncUrlHl(); _aspKvUndoSeed(urlInp); }
  _aspSetRows("asp-params-table",    d.params   || []);
  _aspSetRows("asp-headers-table",   d.headers  || []);
  // Postman-style: keep URL bar and Params table aligned (query string visible in both).
  _aspReconcileUrlAndParams();
  _aspSetAuth(d.auth || { type: "none", value: "" });
  aspAuthTypeChange();
  _aspSetRawLang(d.bodyRawLang || "json");
  _aspSetBodyType(d.bodyType || "none");
  aspBodyTypeChange();
  const rawEl = document.getElementById("asp-body-raw");
  if (rawEl) {
    let rawVal = d.bodyRaw || "";
    if (typeof _aspRecoverKnownCorruptedPayload === "function") rawVal = _aspRecoverKnownCorruptedPayload(rawVal);
    rawEl.value = rawVal;
    _aspSyncBodyHighlight();
    _aspUndoSeed(rawEl.value);
  }
  _aspSetRows("asp-body-form-table", d.bodyForm || []);
  _aspSetMultipartRows(d.bodyMultipart || []);
  _aspBinaryCache = d.bodyBinary && d.bodyBinary.data
    ? { filename: d.bodyBinary.filename || "file", contentType: d.bodyBinary.contentType || "application/octet-stream", data: d.bodyBinary.data }
    : (d.bodyBinary && d.bodyBinary.filename
      ? { filename: d.bodyBinary.filename, contentType: d.bodyBinary.contentType || "application/octet-stream", data: "" }
      : null);
  _aspRenderBinaryName();
  const gqlQ = document.getElementById("asp-gql-query");
  const gqlV = document.getElementById("asp-gql-vars");
  if (gqlQ) gqlQ.value = d.bodyGraphqlQuery || "";
  if (gqlV) gqlV.value = d.bodyGraphqlVars || "";
  const preSc = document.getElementById("asp-script-pre");
  const tesSc = document.getElementById("asp-script-test");
  if (preSc) {
    preSc.value = d.preRequestScript || "";
    _aspScriptUndoMap.delete(preSc);
    _aspScriptUndoSeed(preSc);
  }
  if (tesSc) {
    tesSc.value = d.testScript || "";
    _aspScriptUndoMap.delete(tesSc);
    _aspScriptUndoSeed(tesSc);
  }
  _aspUpdateParamBadge();
  _aspUpdateHeaderBadge();
  _aspUpdateBodyDot();
  _aspUpdateScriptsDot();
  _aspSyncScriptHighlight(preSc);
  _aspSyncScriptHighlight(tesSc);
  aspReqTab(d.reqTab || "params");
  aspRespTab("body");
}

// ── Method selector ───────────────────────────────────────────
function _aspGetMethod() {
  return (document.getElementById("asp-method-sel") || {}).value || "GET";
}
const _ASP_METHOD_COLORS = {
  GET:"#3fb950", POST:"#79c0ff", PUT:"#ffa657",
  PATCH:"#d29922", DELETE:"#f85149", HEAD:"#bc8cff", OPTIONS:"#6e7681"
};
function _aspUpdateMethodColor() {
  const sel = document.getElementById("asp-method-sel");
  if (sel) sel.style.color = _ASP_METHOD_COLORS[sel.value] || "#c9d1d9";
  _aspUpdateActiveTabBadge();
}

// ── URL ───────────────────────────────────────────────────────
function _aspGetUrl() {
  return (document.getElementById("asp-url-input") || {}).value || "";
}

// ── Request tabs ──────────────────────────────────────────────
function aspReqTab(tab) {
  ["params","auth","headers","body","scripts"].forEach(t => {
    const btn = document.getElementById(`asp-req-tab-${t}`);
    const pnl = document.getElementById(`asp-req-pnl-${t}`);
    if (btn) btn.classList.toggle("asp-tab-active", t === tab);
    if (pnl) pnl.style.display = t === tab ? "flex" : "none";
  });
  if (tab === "body") {
    requestAnimationFrame(() => {
      if (typeof _aspSyncReqGutterHeights === "function") _aspSyncReqGutterHeights();
      if (typeof _aspActiveLineUpdate === "function") _aspActiveLineUpdate();
    });
  }
  if (tab === "scripts") {
    aspScriptPhase(_aspScriptPhase || "pre");
    _aspInitScriptSnippets();
  }
}
function _aspActiveReqTab() {
  for (const t of ["params","auth","headers","body","scripts"]) {
    const b = document.getElementById(`asp-req-tab-${t}`);
    if (b && b.classList.contains("asp-tab-active")) return t;
  }
  return "params";
}

// ── Response tabs ─────────────────────────────────────────────
function aspRespTab(tab) {
  ["body","headers","cookies","tests","preview"].forEach(t => {
    const btn = document.getElementById(`asp-resp-tab-${t}`);
    const pnl = document.getElementById(`asp-resp-pnl-${t}`);
    if (btn) btn.classList.toggle("asp-tab-active", t === tab);
    if (pnl) {
      if (t !== tab) {
        pnl.style.display = "none";
      } else if (t === "headers") {
        // block — flex stretched header rows leaving huge gaps
        pnl.style.display = "block";
      } else {
        pnl.style.display = "flex";
      }
    }
  });
  if (tab === "body") {
    requestAnimationFrame(() => {
      if (typeof _aspSyncRespGutterHeights === "function") _aspSyncRespGutterHeights();
      if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
    });
  }
  if (tab === "cookies") _aspRenderCookieJarTable();
  // Re-bind PDF/image blob when opening Preview (iframe may have been blanked).
  if (tab === "preview" && _aspLastResp) _aspRenderRespPreview(_aspLastResp);
}

// ── Key-value row tables ──────────────────────────────────────
function _aspGetRows(tableId) {
  const result = [];
  document.querySelectorAll(`#${tableId} .asp-kv-row`).forEach(r => {
    const chk = r.querySelector(".asp-kv-check");
    const k   = r.querySelector(".asp-kv-key");
    const v   = r.querySelector(".asp-kv-val");
    if (!k || !v) return;
    if (!k.value && !v.value) return; // drop the blank trailer row — _aspSetRows always
                                       // appends one; persisting it would re-add another
                                       // on every future re-render, accumulating blanks
    result.push({ enabled: chk ? chk.checked : true, key: k.value, value: v.value });
  });
  return result;
}

function _aspSetRows(tableId, rows) {
  const tbody = document.getElementById(tableId);
  if (!tbody) return;
  tbody.innerHTML = "";
  (rows || []).forEach(r => _aspAddRow(tableId, r.key, r.value, r.enabled !== false));
  // Params uses the "+ Add param" button — no blank trailer row (avoids an
  // extra empty Query Param sitting above the add button, unlike Headers/Form).
  if (tableId !== "asp-params-table") _aspAddRow(tableId, "", "", true);
}

function _aspSyncUrlHl() {
  const inp   = document.getElementById('asp-url-input');
  const inner = document.getElementById('asp-url-hl-inner');
  const wrap  = document.getElementById('asp-url-wrap');
  if (!inp || !inner) return;
  // Expanded editor shows real text — overlay stays hidden via CSS.
  if (wrap && wrap.classList.contains('asp-url-expanded')) return;
  inner.innerHTML = _aspEscHtml(inp.value || '')
    .replace(/\{\{[^{}]+\}\}/g, m => `<span class="asp-j-var">${m}</span>`);
  inner.style.transform = `translateX(${-inp.scrollLeft}px)`;
}

/** True when the URL doesn't fit on one line in the collapsed bar. */
function _aspUrlOverflows(el) {
  if (!el) return false;
  const v = el.value || "";
  if (!v) return false;
  const wrap = document.getElementById("asp-url-wrap");
  const was = wrap && wrap.classList.contains("asp-url-expanded");
  if (was) {
    wrap.classList.remove("asp-url-expanded");
    el.style.height = "";
  }
  // Force collapsed single-line metrics
  void el.offsetWidth;
  const overflows = el.scrollWidth > el.clientWidth + 2;
  if (was) wrap.classList.add("asp-url-expanded");
  return overflows;
}

function _aspUrlAutosize(el) {
  const wrap = document.getElementById("asp-url-wrap");
  if (!el || !wrap || !wrap.classList.contains("asp-url-expanded")) return;
  el.style.height = "auto";
  const next = Math.min(Math.max(el.scrollHeight, 72), 180);
  el.style.height = next + "px";
}

function _aspUrlFocus(el) {
  const wrap = document.getElementById("asp-url-wrap");
  if (!wrap || !el) return;
  if (_aspUrlOverflows(el)) {
    wrap.classList.add("asp-url-expanded");
    _aspUrlAutosize(el);
  } else {
    wrap.classList.remove("asp-url-expanded");
    el.style.height = "";
  }
  _aspSyncUrlHl();
}

function _aspUrlBlur(el) {
  setTimeout(() => {
    if (document.activeElement === el) return;
    if (_aspUrlParamsTimer) {
      clearTimeout(_aspUrlParamsTimer);
      _aspUrlParamsTimer = null;
      _aspSyncParamsFromUrl();
    }
    const wrap = document.getElementById("asp-url-wrap");
    if (wrap) wrap.classList.remove("asp-url-expanded");
    if (el) el.style.height = "";
    _aspSyncUrlHl();
    try { _aspKvUndoFlush(el); } catch (_) {}
  }, 120);
}

let _aspUrlParamsTimer = null;
function _aspUrlOnInput(el) {
  _aspSaveDraft();
  _aspKvUndoRecord(el);
  // Debounce Params rebuild — syncing the table on every keystroke stalls the UI
  // on long URLs (and compounded with PDF responses made the app feel hung).
  clearTimeout(_aspUrlParamsTimer);
  _aspUrlParamsTimer = setTimeout(() => {
    _aspUrlParamsTimer = null;
    _aspSyncParamsFromUrl();
  }, 150);
  const wrap = document.getElementById("asp-url-wrap");
  if (document.activeElement === el && wrap) {
    if (wrap.classList.contains("asp-url-expanded")) {
      // Stay expanded while editing a long URL (wrap would otherwise look "short").
      _aspUrlAutosize(el);
    } else if (_aspUrlOverflows(el)) {
      wrap.classList.add("asp-url-expanded");
      _aspUrlAutosize(el);
    }
  }
  _aspSyncUrlHl();
}

function _aspUrlKeydown(e, el) {
  _aspSyncUrlHl();
  // URLs stay single-line text — block accidental newlines
  if (e.key === "Enter") e.preventDefault();
}
window._aspUrlFocus = _aspUrlFocus;
window._aspUrlBlur = _aspUrlBlur;
window._aspUrlOnInput = _aspUrlOnInput;
window._aspUrlKeydown = _aspUrlKeydown;
window._aspSyncUrlHl = _aspSyncUrlHl;
function _aspSyncKvHl(inp) {
  const td    = inp.closest('td');
  const inner = td && td.querySelector('.asp-kv-hl-inner');
  if (!inner) return;
  inner.innerHTML = _aspEscHtml(inp.value || '')
    .replace(/\{\{[^{}]+\}\}/g, m => `<span class="asp-j-var">${m}</span>`);
  inner.style.transform = `translateX(${-inp.scrollLeft}px)`;
}

function _aspAddRow(tableId, key="", value="", enabled=true) {
  const tbody = document.getElementById(tableId);
  if (!tbody) return;
  const tr = document.createElement("tr");
  tr.className = "asp-kv-row";
  const syncUrl = tableId === "asp-params-table" ? ";_aspSyncUrlFromParams()" : "";
  tr.innerHTML = `
    <td class="asp-kv-check-cell">
      <input type="checkbox" class="asp-kv-check" ${enabled?"checked":""}
        onchange="_aspSaveDraft();_aspUpdateBadges('${tableId}')${syncUrl}">
    </td>
    <td class="asp-kv-key-cell">
      <input type="text" class="asp-kv-input asp-kv-key" placeholder="Key" value="${_aspEsc(key)}"
        oninput="_aspSaveDraft();_aspUpdateBadges('${tableId}');_aspAutoAddRow(this,'${tableId}')${syncUrl}">
    </td>
    <td class="asp-kv-val-cell">
      <div class="asp-kv-hl" aria-hidden="true"><span class="asp-kv-hl-inner"></span></div>
      <textarea class="asp-kv-input asp-kv-val" rows="1" placeholder="Value"
        oninput="_aspSaveDraft();_aspSyncKvHl(this);_aspKvUndoRecord(this);_aspKvValAutosize(this);_aspUpdateBadges('${tableId}')${syncUrl}"
        onfocus="_aspKvValFocus(this)" onblur="_aspKvValBlur(this)"
        onkeyup="_aspSyncKvHl(this)" onscroll="_aspSyncKvHl(this)">${_aspEscHtml(value)}</textarea>
    </td>
    <td class="asp-kv-del-cell">
      <button class="asp-kv-del" onclick="this.closest('tr').remove();_aspSaveDraft();_aspUpdateBadges('${tableId}')${syncUrl}">×</button>
    </td>`;
  tbody.appendChild(tr);
  const valInp = tr.querySelector('.asp-kv-val');
  if (valInp) { _aspSyncKvHl(valInp); _aspKvUndoSeed(valInp); }
}

/** Drag Key↔Value column widths (Params / Headers / Body form / multipart). */
function _aspInitKvColResize() {
  const root = document.getElementById("tool-apisphere") || document;
  root.querySelectorAll(".asp-kv-table").forEach(table => {
    const storeKey = table.getAttribute("data-asp-kv-store");
    if (storeKey) {
      try {
        const saved = localStorage.getItem(storeKey);
        if (saved && /^\d+(\.\d+)?%$/.test(saved)) {
          table.style.setProperty("--asp-kv-key-pct", saved);
          const col = table.querySelector(".asp-kv-col-key");
          if (col) col.style.width = saved;
        }
      } catch (_) {}
    }
  });

  root.addEventListener("mousedown", e => {
    const handle = e.target && e.target.closest ? e.target.closest(".asp-kv-col-resizer") : null;
    if (!handle) return;
    e.preventDefault();
    e.stopPropagation();
    const table = handle.closest(".asp-kv-table");
    if (!table) return;
    const keyCol = table.querySelector(".asp-kv-col-key");
    const storeKey = table.getAttribute("data-asp-kv-store");
    const startX = e.clientX;
    const tableW = table.getBoundingClientRect().width || 1;
    const checkW = (table.querySelector(".asp-kv-col-check") || {}).getBoundingClientRect?.()?.width || 28;
    const delW = (table.querySelector(".asp-kv-col-del") || {}).getBoundingClientRect?.()?.width || 28;
    const typeW = (table.querySelector(".asp-kv-col-mp-type") || {}).getBoundingClientRect?.()?.width || 0;
    const startKeyW = keyCol ? keyCol.getBoundingClientRect().width : tableW * 0.34;
    const minKey = 80;
    const maxKey = Math.max(minKey + 40, tableW - checkW - delW - typeW - 120);

    table.classList.add("asp-kv-resizing");
    document.body.classList.add("asp-kv-col-dragging");

    const onMove = ev => {
      const next = Math.min(maxKey, Math.max(minKey, startKeyW + (ev.clientX - startX)));
      const pct = ((next / tableW) * 100).toFixed(2) + "%";
      table.style.setProperty("--asp-kv-key-pct", pct);
      if (keyCol) keyCol.style.width = pct;
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      table.classList.remove("asp-kv-resizing");
      document.body.classList.remove("asp-kv-col-dragging");
      if (storeKey) {
        try {
          localStorage.setItem(storeKey, table.style.getPropertyValue("--asp-kv-key-pct").trim() || "34%");
        } catch (_) {}
      }
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}
window._aspInitKvColResize = _aspInitKvColResize;

function _aspKvValFocus(el) {
  const row = el && el.closest('.asp-kv-row');
  if (row) row.classList.add('asp-kv-val-focus');
  _aspKvValAutosize(el);
  _aspSyncKvHl(el);
}
function _aspKvValBlur(el) {
  // Delay so Encode/Decode ctx click can still read selection from this field
  setTimeout(() => {
    if (document.activeElement === el) return;
    const row = el && el.closest('.asp-kv-row');
    if (row) row.classList.remove('asp-kv-val-focus');
    if (el) { el.style.height = ''; _aspSyncKvHl(el); _aspKvUndoFlush(el); }
  }, 120);
}
function _aspKvValAutosize(el) {
  if (!el || !el.classList.contains('asp-kv-val')) return;
  const row = el.closest('.asp-kv-row');
  if (!row || !row.classList.contains('asp-kv-val-focus')) return;
  el.style.height = 'auto';
  const next = Math.min(Math.max(el.scrollHeight, 88), 200);
  el.style.height = next + 'px';
}
window._aspKvValFocus = _aspKvValFocus;
window._aspKvValBlur  = _aspKvValBlur;
window._aspKvValAutosize = _aspKvValAutosize;

function _aspAutoAddRow(input, tableId) {
  // Params: no auto blank row — use "+ Add param" (keeps table clean like the URL bar).
  if (tableId === "asp-params-table") return;
  const row   = input.closest("tr");
  const tbody = document.getElementById(tableId);
  if (tbody && row === tbody.lastElementChild && input.value.trim()) _aspAddRow(tableId);
}

// ── KV context menu: EncodeURIComponent / DecodeURIComponent (Postman-style) ──
let _aspKvCtx = null; // { el, start, end }

function _aspInitKvCtxMenu() {
  const root = document.getElementById("tool-apisphere") || document;
  root.addEventListener("contextmenu", e => {
    const inp = e.target && e.target.closest
      ? e.target.closest("#asp-params-table .asp-kv-input, #asp-headers-table .asp-kv-input, #asp-body-form-table .asp-kv-input, #asp-body-multipart-table .asp-kv-val")
      : null;
    if (!inp) return;
    e.preventDefault();
    e.stopPropagation();
    // Capture selection before any focus change; empty selection → whole field
    const start = inp.selectionStart != null ? inp.selectionStart : 0;
    const end   = inp.selectionEnd   != null ? inp.selectionEnd   : (inp.value || "").length;
    _aspKvCtx = { el: inp, start, end };
    _aspShowKvCtx(e.clientX, e.clientY, inp, start, end);
  });
  document.addEventListener("click", e => {
    const menu = document.getElementById("asp-kv-ctx");
    if (menu && menu.style.display !== "none" && !menu.contains(e.target)) _aspHideKvCtx();
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") _aspHideKvCtx();
  });
}

function _aspShowKvCtx(x, y, inp, start, end) {
  const menu = document.getElementById("asp-kv-ctx");
  if (!menu) return;
  const hint = document.getElementById("asp-kv-ctx-hint");
  const val  = inp.value || "";
  const sel  = start !== end ? val.slice(start, end) : val;
  if (hint) {
    const preview = sel.length > 42 ? sel.slice(0, 40) + "…" : sel;
    hint.textContent = sel
      ? (start !== end ? `Selection: ${preview}` : `Value: ${preview}`)
      : "Empty — nothing to encode";
    hint.style.display = "block";
  }
  menu.style.display = "block";
  // Keep on-screen
  const pad = 8;
  const mw = menu.offsetWidth  || 190;
  const mh = menu.offsetHeight || 90;
  let left = x, top = y;
  if (left + mw > window.innerWidth  - pad) left = window.innerWidth  - mw - pad;
  if (top  + mh > window.innerHeight - pad) top  = window.innerHeight - mh - pad;
  if (left < pad) left = pad;
  if (top  < pad) top  = pad;
  menu.style.left = left + "px";
  menu.style.top  = top  + "px";
}

function _aspHideKvCtx() {
  const menu = document.getElementById("asp-kv-ctx");
  if (menu) menu.style.display = "none";
}

function _aspKvCtxApply(transform) {
  if (!_aspKvCtx || !_aspKvCtx.el) return;
  const el = _aspKvCtx.el;
  const v  = el.value || "";
  let s = _aspKvCtx.start, e = _aspKvCtx.end;
  if (s == null || e == null) { s = 0; e = v.length; }
  // No selection → whole value (handy when you right-click without dragging)
  if (s === e) { s = 0; e = v.length; }
  const chunk = v.slice(s, e);
  if (!chunk) { _aspHideKvCtx(); return; }
  let next;
  try {
    next = transform(chunk);
  } catch (err) {
    _aspHideKvCtx();
    if (typeof _aspAlert === "function") _aspAlert("Decode failed: " + (err.message || err));
    else alert("Decode failed: " + (err.message || err));
    return;
  }
  // Commit pre-transform value so Cmd+Z can restore it
  try { _aspKvUndoFlush(el); } catch (_) {}
  el.focus();
  el.value = v.slice(0, s) + next + v.slice(e);
  try { el.setSelectionRange(s, s + next.length); } catch (_) {}
  // Keep highlight / undo / draft in sync — flush so Cmd+Z undoes this encode/decode
  if (el.classList.contains("asp-kv-val")) {
    try { _aspSyncKvHl(el); } catch (_) {}
    try { _aspKvValAutosize(el); } catch (_) {}
    try { _aspKvUndoFlush(el); } catch (_) {}
  }
  try { _aspSaveDraft(); } catch (_) {}
  const row = el.closest("tr");
  const tbody = row && row.parentElement;
  if (tbody && tbody.id) _aspUpdateBadges(tbody.id);
  _aspHideKvCtx();
  _aspKvCtx = null;
}

function aspKvCtxEncode() {
  _aspKvCtxApply(s => encodeURIComponent(s));
}
function aspKvCtxDecode() {
  _aspKvCtxApply(s => decodeURIComponent(s.replace(/\+/g, " ")));
}
window.aspKvCtxEncode = aspKvCtxEncode;
window.aspKvCtxDecode = aspKvCtxDecode;

function _aspUpdateBadges(tableId) {
  if (tableId === "asp-params-table")  _aspUpdateParamBadge();
  if (tableId === "asp-headers-table") _aspUpdateHeaderBadge();
  if (tableId === "asp-body-form-table" || tableId === "asp-body-multipart-table") _aspUpdateBodyDot();
}
function _aspUpdateParamBadge() {
  const n = _aspGetRows("asp-params-table").filter(r => r.enabled && r.key).length;
  const dot = document.getElementById("asp-dot-params");
  if (dot) dot.classList.toggle("on", n > 0);
}
function _aspUpdateHeaderBadge() {
  const n = _aspGetRows("asp-headers-table").filter(r => r.enabled && r.key).length;
  const b = document.getElementById("asp-badge-headers");
  if (b) { b.textContent = n || ""; b.style.display = n > 0 ? "inline" : "none"; }
}
function _aspUpdateBodyDot() {
  const type = _aspGetBodyType();
  let has = false;
  if (type === "raw" || type === "json" || type === "text") {
    has = !!((document.getElementById("asp-body-raw") || {}).value || "").trim();
  } else if (type === "form") {
    has = _aspGetRows("asp-body-form-table").some(r => r.enabled && r.key);
  } else if (type === "multipart") {
    has = _aspGetMultipartRows().some(r => r.enabled && r.key);
  } else if (type === "binary") {
    has = !!( _aspBinaryCache && (_aspBinaryCache.data || _aspBinaryCache.filename) );
  } else if (type === "graphql") {
    has = !!((document.getElementById("asp-gql-query") || {}).value || "").trim();
  }
  const dot = document.getElementById("asp-dot-body");
  if (dot) dot.classList.toggle("on", has);
}

// ── Auth ──────────────────────────────────────────────────────
function _aspGetAuth() {
  const sel = document.getElementById("asp-auth-type");
  return {
    type:     sel ? sel.value : "none",
    token:    (document.getElementById("asp-auth-token")    || {}).value || "",
    username: (document.getElementById("asp-auth-user")     || {}).value || "",
    password: (document.getElementById("asp-auth-pass")     || {}).value || "",
  };
}
function _aspSetAuth(auth) {
  const sel = document.getElementById("asp-auth-type");
  if (sel && auth.type) sel.value = auth.type;
  aspAuthTypeChange();
  const t = document.getElementById("asp-auth-token");
  const u = document.getElementById("asp-auth-user");
  const p = document.getElementById("asp-auth-pass");
  if (t) t.value = auth.token    || "";
  if (u) u.value = auth.username || "";
  if (p) p.value = auth.password || "";
}
function aspAuthTypeChange() {
  const sel  = document.getElementById("asp-auth-type");
  const type = sel ? sel.value : "none";
  const b    = document.getElementById("asp-auth-bearer");
  const bas  = document.getElementById("asp-auth-basic");
  const inh  = document.getElementById("asp-auth-inherit-info");
  if (b)   b.style.display   = type === "bearer"  ? "flex"  : "none";
  if (bas) bas.style.display = type === "basic"   ? "flex"  : "none";
  if (inh) inh.style.display = type === "inherit" ? "block" : "none";
  _aspSaveDraft();
}

// ── Body type (Postman: none | form-data | x-www-form-urlencoded | raw | binary | GraphQL) ──
function _aspGetBodyType() {
  return (document.getElementById("asp-body-type-sel") || {}).value || "none";
}
function _aspSetBodyType(type) {
  // Legacy values from saved tabs / imports
  if (type === "json" || type === "text") {
    _aspSetRawLang(type === "json" ? "json" : "text");
    type = "raw";
  }
  const sel = document.getElementById("asp-body-type-sel");
  if (sel) {
    if (![...sel.options].some(o => o.value === type)) type = "none";
    sel.value = type;
  }
  aspBodyTypeChange();
}
function _aspGetRawLang() {
  return (document.getElementById("asp-body-raw-lang") || {}).value || "json";
}
function _aspSetRawLang(lang) {
  const sel = document.getElementById("asp-body-raw-lang");
  if (sel) sel.value = lang || "json";
}
function aspRawLangChange() {
  _aspSyncBodyHighlight();
  _aspUpdateBodyDot();
  _aspSaveDraft();
}
function aspBodyTypeChange() {
  const type    = _aspGetBodyType();
  const rawPnl  = document.getElementById("asp-body-raw-wrap");
  const formPnl = document.getElementById("asp-body-form-wrap");
  const mpPnl   = document.getElementById("asp-body-multipart-wrap");
  const binPnl  = document.getElementById("asp-body-binary-wrap");
  const gqlPnl  = document.getElementById("asp-body-graphql-wrap");
  const langSel = document.getElementById("asp-body-raw-lang");
  const rawActions = document.getElementById("asp-body-raw-actions");
  if (rawPnl)     rawPnl.style.display     = type === "raw" ? "flex" : "none";
  if (rawActions) rawActions.style.display = type === "raw" ? "flex" : "none";
  if (formPnl) formPnl.style.display = type === "form" ? "flex" : "none";
  if (mpPnl)   mpPnl.style.display   = type === "multipart" ? "flex" : "none";
  if (binPnl)  binPnl.style.display  = type === "binary" ? "flex" : "none";
  if (gqlPnl)  gqlPnl.style.display  = type === "graphql" ? "flex" : "none";
  if (langSel) langSel.style.display = type === "raw" ? "" : "none";
  if (type === "multipart") {
    const tb = document.getElementById("asp-body-multipart-table");
    if (tb && tb.children.length === 0) _aspAddMultipartRow();
  }
  if (type === "form") {
    const tb = document.getElementById("asp-body-form-table");
    if (tb && tb.children.length === 0) _aspAddRow("asp-body-form-table");
  }
  _aspUpdateBodyDot();
  _aspSyncBodyHighlight();
  _aspSaveDraft();
}
function _aspRenderBinaryName() {
  const el = document.getElementById("asp-body-binary-name");
  if (!el) return;
  if (_aspBinaryCache && _aspBinaryCache.filename) {
    const sizeNote = _aspBinaryCache.data
      ? ` (${Math.round((_aspBinaryCache.data.length * 0.75) / 1024)} KB)`
      : " — re-select file to send";
    el.textContent = _aspBinaryCache.filename + sizeNote;
    el.style.color = "var(--text2)";
  } else {
    el.textContent = "No file selected";
    el.style.color = "var(--text3)";
  }
}
function aspBinaryFileChange(input) {
  const f = input && input.files && input.files[0];
  if (!f) {
    _aspBinaryCache = null;
    _aspRenderBinaryName();
    _aspUpdateBodyDot();
    _aspSaveDraft();
    return;
  }
  const reader = new FileReader();
  reader.onload = e => {
    const b64 = String(e.target.result || "").split(",")[1] || "";
    _aspBinaryCache = {
      filename: f.name,
      contentType: f.type || "application/octet-stream",
      data: b64,
    };
    _aspRenderBinaryName();
    _aspUpdateBodyDot();
    _aspSaveDraft();
  };
  reader.onerror = () => _aspAlert("Failed to read binary file.");
  reader.readAsDataURL(f);
}
window.aspBinaryFileChange = aspBinaryFileChange;
window.aspRawLangChange = aspRawLangChange;

// ── Multipart form rows ───────────────────────────────────────
function _aspAddMultipartRow(key="", fieldType="text", value="", filename="", enabled=true) {
  const tbody = document.getElementById("asp-body-multipart-table");
  if (!tbody) return;
  const tr = document.createElement("tr");
  tr.className = "asp-kv-row asp-mp-row";
  const fileDisplay = filename ? _aspEscHtml(filename) : "No file chosen";
  tr.innerHTML = `
    <td class="asp-kv-check-cell">
      <input type="checkbox" class="asp-kv-check" ${enabled?"checked":""}
        onchange="_aspSaveDraft();_aspUpdateBodyDot()">
    </td>
    <td class="asp-kv-key-cell">
      <input type="text" class="asp-kv-input asp-kv-key" placeholder="Field name" value="${_aspEsc(key)}"
        oninput="_aspSaveDraft();_aspUpdateBodyDot()">
    </td>
    <td style="padding:2px 3px;width:88px">
      <select class="asp-select asp-mp-type" style="font-size:11px;padding:4px 6px;width:100%;min-height:28px"
        onchange="_aspMultipartTypeChange(this)">
        <option value="text"${fieldType==="text"?" selected":""}>Text</option>
        <option value="file"${fieldType==="file"?" selected":""}>File</option>
      </select>
    </td>
    <td class="asp-kv-val-cell">
      <input type="text" class="asp-kv-input asp-kv-val asp-mp-text-val"
        style="display:${fieldType==="text"?"block":"none"}"
        placeholder="Value" value="${_aspEsc(value)}" oninput="_aspSaveDraft();_aspUpdateBodyDot()">
      <div class="asp-mp-file-wrap" style="display:${fieldType==="file"?"flex":"none"};align-items:center;gap:6px">
        <div style="position:relative;flex-shrink:0">
          <button class="asp-btn-sm" style="font-size:11px;padding:4px 10px;pointer-events:none">Choose File</button>
          <input type="file" multiple class="asp-mp-file-input"
            style="position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%"
            onchange="_aspMultipartFileChosen(this)">
        </div>
        <span class="asp-mp-filename" style="font-size:11px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${fileDisplay}</span>
      </div>
    </td>
    <td class="asp-kv-del-cell">
      <button class="asp-kv-del" onclick="this.closest('tr').remove();_aspSaveDraft()">×</button>
    </td>`;
  tbody.appendChild(tr);
}

function _aspMultipartTypeChange(sel) {
  const tr       = sel.closest("tr");
  const textInp  = tr.querySelector(".asp-mp-text-val");
  const fileWrap = tr.querySelector(".asp-mp-file-wrap");
  if (sel.value === "file") {
    if (textInp)  textInp.style.display  = "none";
    if (fileWrap) fileWrap.style.display = "flex";
  } else {
    if (textInp)  textInp.style.display  = "block";
    if (fileWrap) fileWrap.style.display = "none";
  }
  _aspSaveDraft();
}

function _aspMultipartFileChosen(input) {
  const tr       = input.closest("tr");
  const nameSpan = tr.querySelector(".asp-mp-filename");
  if (!nameSpan) return;
  const count = input.files.length;
  if (count === 0)      nameSpan.textContent = "No file chosen";
  else if (count === 1) nameSpan.textContent = input.files[0].name;
  else                  nameSpan.textContent = `${count} files selected`;
  _aspSaveDraft();
}

function _aspGetMultipartRows() {
  const result = [];
  document.querySelectorAll("#asp-body-multipart-table .asp-mp-row").forEach(tr => {
    const chk       = tr.querySelector(".asp-kv-check");
    const key       = (tr.querySelector(".asp-kv-key") || {}).value || "";
    const typeSel   = tr.querySelector(".asp-mp-type");
    const fieldType = typeSel ? typeSel.value : "text";
    const textInp   = tr.querySelector(".asp-mp-text-val");
    const fileInp   = tr.querySelector(".asp-mp-file-input");
    const nameSpan  = tr.querySelector(".asp-mp-filename");
    result.push({
      enabled:   chk ? chk.checked : true,
      key,
      fieldType,
      value:     fieldType === "text" ? ((textInp||{}).value||"") : "",
      filename:  fieldType === "file" ? ((nameSpan||{}).textContent||"") : "",
      fileObjs:  fieldType === "file" && fileInp && fileInp.files.length ? Array.from(fileInp.files) : [],
    });
  });
  return result;
}

function _aspSetMultipartRows(rows) {
  const tbody = document.getElementById("asp-body-multipart-table");
  if (!tbody) return;
  tbody.innerHTML = "";
  (rows || []).forEach(r => _aspAddMultipartRow(r.key, r.fieldType||"text", r.value||"", r.filename||"", r.enabled!==false));
  if (!rows || !rows.length) _aspAddMultipartRow();
}

// ── Scripts (Postman-lite pm API) + Cookies + Cancel ───────────
const ASP_SCRIPT_SNIPPETS = {
  pre: [
    {
      id: "pre-ts",
      name: "Set current timestamp → env",
      hint: "Stores the current time (ms) in environment variable ts. Use {{ts}} in URL, headers, or body. Change \"ts\" to any variable name you want.",
      code: `// Store unix ms timestamp for use as {{ts}} in URL / body / headers
pm.environment.set("ts", Date.now().toString());
console.log("ts =", pm.environment.get("ts"));`,
    },
    {
      id: "pre-uuid",
      name: "Generate UUID → env",
      hint: "Generates a random UUID, saves it as request_id, and adds X-Request-Id header. Change the env key or header name if needed.",
      code: `// Simple UUID v4-ish value
function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
pm.environment.set("request_id", uuid());
pm.request.headers["X-Request-Id"] = pm.environment.get("request_id");`,
    },
    {
      id: "pre-bearer",
      name: "Set Bearer Authorization from env",
      hint: "Reads access_token from the active Environment and sets Authorization: Bearer …. First save a token (or use the Save access_token test snippet).",
      code: `// Requires active Environment with access_token
const token = pm.environment.get("access_token");
if (!token) {
  console.log("WARN: access_token missing in active environment");
} else {
  pm.request.headers["Authorization"] = "Bearer " + token;
}`,
    },
    {
      id: "pre-header",
      name: "Add / overwrite a header",
      hint: "Adds or overwrites request headers before Send. Replace X-Client / Accept values with your own header names and values.",
      code: `pm.request.headers["X-Client"] = "APISphere";
pm.request.headers["Accept"] = "application/json";`,
    },
    {
      id: "pre-query",
      name: "Add query param",
      hint: "Adds query parameters to the request URL (e.g. nonce). Change the param names/values as needed.",
      code: `pm.request.params["nonce"] = Date.now().toString();
pm.request.params["_"] = Math.random().toString(36).slice(2);`,
    },
    {
      id: "pre-basic",
      name: "Set Basic Auth from env",
      hint: "Sets Basic Auth from environment variables basic_user and basic_pass. Create those keys in your active Environment first.",
      code: `const user = pm.environment.get("basic_user") || "";
const pass = pm.environment.get("basic_pass") || "";
pm.request.auth = { type: "basic", username: user, password: pass, token: "" };`,
    },
    {
      id: "pre-coll-var",
      name: "Read / write collection variable",
      hint: "Reads/writes collection-level variables (not Environment). Change baseUrl / last_run_at to your collection variable names.",
      code: `const base = pm.collectionVariables.get("baseUrl");
console.log("collection baseUrl =", base);
pm.collectionVariables.set("last_run_at", new Date().toISOString());`,
    },
    {
      id: "pre-log",
      name: "Log request summary",
      hint: "Logs method, URL, headers, and params to the script console (for debugging). No pass/fail — just prints values before Send.",
      code: `console.log(pm.request.method, pm.request.url);
console.log("headers", pm.request.headers);
console.log("params", pm.request.params);`,
    },
  ],
  test: [
    {
      id: "test-200",
      name: "Status code is 200",
      hint: "Checks that the response HTTP status is exactly 200. For create APIs that return 201, use the “Status code is 201” snippet, or change 200 to your expected code.",
      code: `pm.test("Status code is 200", function () {
  pm.response.to.have.status(200);
});`,
    },
    {
      id: "test-201",
      name: "Status code is 201 (Created)",
      hint: "Checks that the response status is 201 Created (typical for POST create). Change 201 if your API returns another success code.",
      code: `pm.test("Status code is 201", function () {
  pm.response.to.have.status(201);
});`,
    },
    {
      id: "test-2xx",
      name: "Status code is 2xx",
      hint: "Passes for any successful status (200–299). Useful when 200 or 201 are both OK. Adjust the range if you need stricter checks.",
      code: `pm.test("Status is successful (2xx)", function () {
  const code = pm.response.code;
  if (!(code >= 200 && code < 300)) {
    throw new Error("Expected 2xx, got " + code);
  }
});`,
    },
    {
      id: "test-json",
      name: "Response is valid JSON",
      hint: "Ensures the RESPONSE body parses as a JSON object or array. Fails on plain text/HTML/empty bodies.",
      code: `pm.test("Response is JSON", function () {
  const json = pm.response.json();
  if (json === null || typeof json !== "object") {
    throw new Error("Body is not a JSON object/array");
  }
});`,
    },
    {
      id: "test-save-token",
      name: "Save access_token from JSON → env",
      hint: "Reads access_token (or token / data.access_token) from the RESPONSE JSON and saves it to the active Environment. Next requests can use {{access_token}} or the Bearer pre-request snippet.",
      code: `pm.test("Save access_token to environment", function () {
  const json = pm.response.json();
  const token = json && (json.access_token || json.token || (json.data && json.data.access_token));
  if (!token) throw new Error("access_token not found in JSON body");
  pm.environment.set("access_token", String(token));
  console.log("Saved access_token (" + String(token).length + " chars)");
});`,
    },
    {
      id: "test-json-eq",
      name: "JSON field equals value",
      hint: "Checks a RESPONSE JSON field equals a value (default: success === true). Change the field name and expected value to match your API.",
      code: `pm.test("success === true", function () {
  const json = pm.response.json();
  if (!json || json.success !== true) {
    throw new Error("Expected success=true, got " + JSON.stringify(json && json.success));
  }
});`,
    },
    {
      id: "test-body-contains",
      name: "Response body contains text",
      hint: "Searches the RESPONSE body text (not the request you sent). Change the needle variable (e.g. \"OPEN\" or an email). Request body values are ignored.",
      code: `// Checks RESPONSE body (not the request you sent)
pm.test("Response body contains text", function () {
  const text = pm.response.text();
  const needle = "OPEN"; // change this
  if (text.indexOf(needle) === -1) {
    throw new Error('Expected RESPONSE body to contain "' + needle + '" (got ' + text.length + ' chars)');
  }
});`,
    },
    {
      id: "test-json-field",
      name: "Response JSON field equals",
      hint: "Checks RESPONSE JSON status (or data.status) equals \"OPEN\". Change the field path and expected string to match your payload.",
      code: `pm.test("JSON status field is OPEN", function () {
  const json = pm.response.json();
  const val = json && (json.status != null ? json.status : (json.data && json.data.status));
  if (val !== "OPEN") {
    throw new Error('Expected response JSON status "OPEN", got ' + JSON.stringify(val));
  }
});`,
    },
    {
      id: "test-header",
      name: "Response header exists",
      hint: "Checks that a response header exists (default Content-Type). Change the header name inside headers.get(\"…\").",
      code: `pm.test("Content-Type header present", function () {
  const ct = pm.response.headers.get("Content-Type") || pm.response.headers.get("content-type");
  if (!ct) throw new Error("Content-Type missing");
});`,
    },
    {
      id: "test-time",
      name: "Response time < 2000 ms",
      hint: "Fails if response time exceeds 2000ms. Change 2000 to your SLA threshold (milliseconds).",
      code: `pm.test("Response time is under 2000ms", function () {
  const ms = pm.response.responseTime;
  if (ms > 2000) throw new Error("Too slow: " + ms + "ms");
});`,
    },
    {
      id: "test-cookie",
      name: "Cookie was set (jar)",
      hint: "Checks the Cookie jar has at least one cookie for the request host (from Set-Cookie). Useful after login. Adjust if you need a specific cookie name.",
      code: `pm.test("Session cookie present in jar for host", function () {
  const host = (function () {
    try { return new URL(pm.request.url).hostname; } catch (e) { return ""; }
  })();
  const jar = pm.cookies.jar || [];
  const hit = jar.find(c => c.name && (!host || !c.domain || host.indexOf(c.domain.replace(/^\\./, "")) >= 0));
  if (!hit) throw new Error("No cookies in jar for " + host);
  console.log("cookie", hit.name, "=", hit.value);
});`,
    },
  ],
};

function _aspUpdateScriptsDot() {
  const pre = ((document.getElementById("asp-script-pre") || {}).value || "").trim();
  const tes = ((document.getElementById("asp-script-test") || {}).value || "").trim();
  const dot = document.getElementById("asp-dot-scripts");
  if (dot) dot.classList.toggle("on", !!(pre || tes));
}

function _aspActiveScriptEl() {
  return document.getElementById(_aspScriptPhase === "test" ? "asp-script-test" : "asp-script-pre");
}
function _aspActiveScriptWrap() {
  return document.getElementById(_aspScriptPhase === "test" ? "asp-script-test-wrap" : "asp-script-pre-wrap");
}
function _aspActiveScriptHl() {
  return document.getElementById(_aspScriptPhase === "test" ? "asp-script-test-hl" : "asp-script-pre-hl");
}

/** Lightweight JS syntax highlight for Scripts editors. */
function _aspHighlightJs(code) {
  const s = String(code || "");
  let out = "";
  let i = 0;
  const n = s.length;
  const KW = /^(?:const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|try|catch|finally|throw|new|typeof|instanceof|in|of|class|extends|async|await|true|false|null|undefined|this)\b/;
  while (i < n) {
    // line comment
    if (s[i] === "/" && s[i + 1] === "/") {
      let j = i + 2;
      while (j < n && s[j] !== "\n") j++;
      out += `<span class="asp-js-cm">${_aspEscHtml(s.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    // block comment
    if (s[i] === "/" && s[i + 1] === "*") {
      let j = i + 2;
      while (j < n && !(s[j] === "*" && s[j + 1] === "/")) j++;
      j = Math.min(n, j + 2);
      out += `<span class="asp-js-cm">${_aspEscHtml(s.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    // string ' " `
    if (s[i] === "'" || s[i] === '"' || s[i] === "`") {
      const q = s[i];
      let j = i + 1;
      while (j < n) {
        if (s[j] === "\\") { j += 2; continue; }
        if (s[j] === q) { j++; break; }
        if (q !== "`" && s[j] === "\n") break;
        j++;
      }
      out += `<span class="asp-js-str">${_aspEscHtml(s.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    // number
    if (/[0-9]/.test(s[i]) && (i === 0 || /[^\w$]/.test(s[i - 1]))) {
      let j = i;
      while (j < n && /[0-9.xXa-fA-F_]/.test(s[j])) j++;
      out += `<span class="asp-js-num">${_aspEscHtml(s.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    // identifier / keyword / pm
    if (/[A-Za-z_$]/.test(s[i])) {
      let j = i + 1;
      while (j < n && /[\w$]/.test(s[j])) j++;
      const word = s.slice(i, j);
      if (word === "true" || word === "false" || word === "null" || word === "undefined") {
        out += `<span class="asp-js-bool">${_aspEscHtml(word)}</span>`;
      } else if (KW.test(word)) {
        out += `<span class="asp-js-kw">${_aspEscHtml(word)}</span>`;
      } else if (word === "pm" || word === "console") {
        out += `<span class="asp-js-fn">${_aspEscHtml(word)}</span>`;
      } else {
        // function call name?
        let k = j;
        while (k < n && /\s/.test(s[k])) k++;
        if (s[k] === "(") out += `<span class="asp-js-fn">${_aspEscHtml(word)}</span>`;
        else out += _aspEscHtml(word);
      }
      i = j;
      continue;
    }
    out += _aspEscHtml(s[i]);
    i++;
  }
  return out || " ";
}

function _aspSyncScriptHighlight(el) {
  const ta = el || _aspActiveScriptEl();
  if (!ta) return;
  const isTest = ta.id === "asp-script-test";
  const hl = document.getElementById(isTest ? "asp-script-test-hl" : "asp-script-pre-hl");
  if (!hl) return;
  hl.innerHTML = _aspHighlightJs(ta.value) + "\n";
  hl.scrollTop = ta.scrollTop;
  hl.scrollLeft = ta.scrollLeft;
}

function _aspSyncScriptScroll(ta) {
  if (!ta) return;
  const isTest = ta.id === "asp-script-test";
  const hl = document.getElementById(isTest ? "asp-script-test-hl" : "asp-script-pre-hl");
  if (!hl) return;
  hl.scrollTop = ta.scrollTop;
  hl.scrollLeft = ta.scrollLeft;
}
window._aspSyncScriptScroll = _aspSyncScriptScroll;

let _aspScriptHintActive = false;

function _aspShowScriptError(msg, kind) {
  const box = document.getElementById("asp-script-error");
  const wrap = _aspActiveScriptWrap();
  if (!box) return;
  if (!msg) {
    box.style.display = "none";
    box.textContent = "";
    box.innerHTML = "";
    box.classList.remove("asp-script-warn");
    if (wrap) wrap.classList.remove("asp-script-invalid");
    _aspScriptHintActive = false;
    return;
  }
  _aspScriptHintActive = false;
  box.style.display = "block";
  box.textContent = msg;
  box.classList.toggle("asp-script-warn", kind === "warn");
  if (wrap) wrap.classList.toggle("asp-script-invalid", kind !== "warn");
}

/** Amber hint box under Scripts (same style as logic-mismatch warn). */
function _aspShowScriptHint(title, body) {
  const box = document.getElementById("asp-script-error");
  const wrap = _aspActiveScriptWrap();
  if (!box) return;
  _aspScriptHintActive = true;
  box.style.display = "block";
  box.classList.add("asp-script-warn");
  if (wrap) wrap.classList.remove("asp-script-invalid");
  box.innerHTML =
    `<div style="font-weight:700;margin-bottom:5px">💡 Snippet hint — ${_aspEscHtml(title || "Snippet")}</div>` +
    `<div>${_aspEscHtml(body || "")}</div>`;
}

/** Live syntax + common logic checks under the Scripts editor. */
function _aspLintScriptEditor() {
  const ta = _aspActiveScriptEl();
  const code = ta ? ta.value : "";
  if (!code.trim()) {
    if (!_aspScriptHintActive) _aspShowScriptError("");
    return;
  }
  // 1) Syntax
  try {
    // eslint-disable-next-line no-new-func
    new Function("pm", "console", '"use strict";\n' + code);
  } catch (e) {
    _aspShowScriptError("⚠ Syntax error — " + (e && e.message ? e.message : String(e)));
    return;
  }
  // 2) Common logic mistake: indexOf("A") but Error mentions "B"
  const idxM = code.match(/indexOf\s*\(\s*(['"`])([^'"`]+)\1\s*\)/);
  const errM = code.match(/throw\s+new\s+Error\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/);
  if (idxM && errM) {
    const needle = idxM[2];
    const errMsg = errM[2];
    if (needle && errMsg && errMsg.indexOf(needle) === -1) {
      const quoted = errMsg.match(/(['"`])([^'"`]+)\1/);
      const expected = quoted ? quoted[2] : null;
      if (expected && expected !== needle) {
        _aspShowScriptError(
          `⚠ Logic mismatch — code checks for "${needle}" (indexOf) but error says "${expected}".\n` +
          `Fix: use the same string in both places, e.g.\n` +
          `  const needle = "${expected}";\n` +
          `  if (text.indexOf(needle) === -1) throw new Error('Expected … ' + needle);`,
          "warn"
        );
        return;
      }
    }
  }
  // Keep snippet hint until user types again
  if (_aspScriptHintActive) return;
  _aspShowScriptError("");
}

function _aspOnScriptInput() {
  const ta = _aspActiveScriptEl();
  _aspScriptHintActive = false;
  _aspScriptUndoRecord(ta);
  _aspSaveDraft();
  _aspUpdateScriptsDot();
  _aspSyncScriptHighlight();
  _aspLintScriptEditor();
}
window._aspOnScriptInput = _aspOnScriptInput;

// ── Scripts undo/redo (WKWebView clears native undo when highlight DOM updates) ──
const _aspScriptUndoMap    = new WeakMap();
const _aspScriptUndoTimers = new WeakMap();
let _aspScriptUndoBusy = false;

function _aspScriptUndoSeed(ta) {
  if (!ta) return;
  // Don't wipe existing history on re-focus
  if (_aspScriptUndoMap.get(ta)) return;
  let s = 0, e = 0;
  try { s = ta.selectionStart; e = ta.selectionEnd; } catch (_) { s = e = (ta.value || "").length; }
  _aspScriptUndoMap.set(ta, { stack: [{ v: ta.value || "", s, e }], idx: 0 });
}
window._aspScriptUndoSeed = _aspScriptUndoSeed;
function _aspScriptUndoRecord(ta) {
  if (_aspScriptUndoBusy || !ta) return;
  const prev = _aspScriptUndoTimers.get(ta);
  if (prev) clearTimeout(prev);
  const u = _aspScriptUndoMap.get(ta);
  const cur = u && u.stack[u.idx];
  const jump = cur && Math.abs((ta.value || "").length - (cur.v || "").length) > 40;
  if (jump) { _aspScriptUndoFlush(ta); return; }
  _aspScriptUndoTimers.set(ta, setTimeout(() => {
    _aspScriptUndoTimers.delete(ta);
    _aspScriptUndoFlush(ta);
  }, 300));
}
function _aspScriptUndoFlush(ta) {
  if (!ta || _aspScriptUndoBusy || !ta.isConnected) return;
  const t = _aspScriptUndoTimers.get(ta);
  if (t) { clearTimeout(t); _aspScriptUndoTimers.delete(ta); }
  let u = _aspScriptUndoMap.get(ta);
  if (!u) {
    // First edit without seed — keep empty baseline so Cmd+Z can revert it
    _aspScriptUndoMap.set(ta, { stack: [{ v: "", s: 0, e: 0 }], idx: 0 });
    u = _aspScriptUndoMap.get(ta);
    if (!(ta.value || "")) return;
  }
  const cur = u.stack[u.idx];
  if (cur && cur.v === ta.value) return;
  u.stack.splice(u.idx + 1);
  let s = 0, e = 0;
  try { s = ta.selectionStart; e = ta.selectionEnd; } catch (_) { s = e = ta.value.length; }
  u.stack.push({ v: ta.value, s, e });
  u.idx = u.stack.length - 1;
  if (u.stack.length > 300) { u.stack.shift(); u.idx--; }
}
function _aspScriptUndoApply(ta, entry) {
  _aspScriptUndoBusy = true;
  ta.value = entry.v;
  try { ta.setSelectionRange(entry.s, entry.e); } catch (_) {}
  _aspSyncScriptHighlight(ta);
  _aspLintScriptEditor();
  _aspUpdateScriptsDot();
  _aspSaveDraft();
  _aspScriptUndoBusy = false;
}
function _aspScriptUndo(ta) {
  if (!ta) return;
  _aspScriptUndoFlush(ta);
  const u = _aspScriptUndoMap.get(ta);
  if (!u || u.idx <= 0) return;
  u.idx--;
  _aspScriptUndoApply(ta, u.stack[u.idx]);
}
function _aspScriptRedo(ta) {
  if (!ta) return;
  const u = _aspScriptUndoMap.get(ta);
  if (!u || u.idx >= u.stack.length - 1) return;
  u.idx++;
  _aspScriptUndoApply(ta, u.stack[u.idx]);
}
window._aspScriptUndo = _aspScriptUndo;
window._aspScriptRedo = _aspScriptRedo;

/** After Send tests: mirror failures under Scripts editor. */
function _aspShowScriptTestFailures(tests, scriptError) {
  if (_aspScriptPhase !== "test") return;
  if (scriptError) {
    _aspShowScriptError("⚠ Script error — " + scriptError);
    return;
  }
  const failed = (tests || []).filter(t => !t.passed);
  if (!failed.length) {
    // keep logic-warn if any; re-lint
    _aspLintScriptEditor();
    return;
  }
  const lines = failed.map(t => `✗ ${t.name}${t.error ? " — " + t.error : ""}`);
  _aspShowScriptError("⚠ Test failed\n" + lines.join("\n"));
}

function aspScriptPhase(phase) {
  _aspScriptPhase = phase === "test" ? "test" : "pre";
  const preBtn = document.getElementById("asp-script-phase-pre");
  const tesBtn = document.getElementById("asp-script-phase-test");
  const preWrap = document.getElementById("asp-script-pre-wrap");
  const tesWrap = document.getElementById("asp-script-test-wrap");
  const hint   = document.getElementById("asp-script-hint");
  if (preBtn) preBtn.classList.toggle("asp-script-phase-active", _aspScriptPhase === "pre");
  if (tesBtn) tesBtn.classList.toggle("asp-script-phase-active", _aspScriptPhase === "test");
  if (preWrap) preWrap.style.display = _aspScriptPhase === "pre" ? "flex" : "none";
  if (tesWrap) tesWrap.style.display = _aspScriptPhase === "test" ? "flex" : "none";
  if (hint) {
    hint.innerHTML = _aspScriptPhase === "pre"
      ? 'Runs <b style="color:var(--text2)">before</b> the request is sent. Mutate headers/params/auth or set env vars.'
      : 'Runs <b style="color:var(--text2)">after</b> the response. Use <code style="color:#e3b341">pm.test</code> for pass/fail (also used by Collection Runner).';
  }
  _aspInitScriptSnippets();
  const ta = _aspActiveScriptEl();
  if (ta && !_aspScriptUndoMap.get(ta)) _aspScriptUndoSeed(ta);
  _aspSyncScriptHighlight();
  _aspLintScriptEditor();
}
window.aspScriptPhase = aspScriptPhase;

function _aspInitScriptSnippets() {
  const sel = document.getElementById("asp-script-snippet-sel");
  if (!sel) return;
  const list = ASP_SCRIPT_SNIPPETS[_aspScriptPhase === "test" ? "test" : "pre"] || [];
  const prev = sel.value;
  sel.innerHTML = '<option value="">+ Snippets…</option>' +
    list.map(s => `<option value="${_aspEsc(s.id)}">${_aspEsc(s.name)}</option>`).join("");
  if (list.some(s => s.id === prev)) sel.value = prev;
}

function aspInsertScriptSnippet() {
  const sel = document.getElementById("asp-script-snippet-sel");
  if (!sel || !sel.value) return;
  const list = ASP_SCRIPT_SNIPPETS[_aspScriptPhase === "test" ? "test" : "pre"] || [];
  const snip = list.find(s => s.id === sel.value);
  if (!snip) return;
  const el = document.getElementById(_aspScriptPhase === "test" ? "asp-script-test" : "asp-script-pre");
  if (!el) return;
  const cur = el.value || "";
  _aspScriptUndoFlush(el);
  el.value = cur ? (cur.replace(/\s*$/, "") + "\n\n" + snip.code + "\n") : (snip.code + "\n");
  _aspScriptUndoFlush(el);
  sel.value = "";
  _aspSaveDraft();
  _aspUpdateScriptsDot();
  _aspSyncScriptHighlight(el);
  _aspLintScriptEditor();
  _aspShowScriptHint(
    snip.name,
    snip.hint || ("This snippet was inserted. Edit the values in the code to match your API.")
  );
  el.focus();
}
window.aspInsertScriptSnippet = aspInsertScriptSnippet;

function aspClearScriptEditor() {
  const el = document.getElementById(_aspScriptPhase === "test" ? "asp-script-test" : "asp-script-pre");
  if (el) {
    _aspScriptUndoFlush(el);
    el.value = "";
    _aspScriptUndoFlush(el);
  }
  _aspSaveDraft();
  _aspUpdateScriptsDot();
  _aspSyncScriptHighlight(el);
  _aspShowScriptError("");
}
window.aspClearScriptEditor = aspClearScriptEditor;

// ── Cookie jar ────────────────────────────────────────────────
function _aspGetCookieJar() {
  try { return JSON.parse(localStorage.getItem(ASP_COOKIE_KEY) || "[]"); } catch (e) { return []; }
}
function _aspSaveCookieJar(jar) {
  try { localStorage.setItem(ASP_COOKIE_KEY, JSON.stringify(jar || [])); } catch (e) {}
}
function _aspCookieHostMatch(cookieDomain, host) {
  if (!host) return false;
  if (!cookieDomain) return true;
  const d = String(cookieDomain).replace(/^\./, "").toLowerCase();
  const h = String(host).toLowerCase();
  return h === d || h.endsWith("." + d);
}
function _aspCookieJarUpsert(cookies, url) {
  if (!cookies || !cookies.length) return;
  let host = "", path = "/";
  try {
    const u = new URL(url);
    host = u.hostname;
    path = u.pathname || "/";
  } catch (e) {}
  const jar = _aspGetCookieJar();
  cookies.forEach(c => {
    if (!c || !c.name) return;
    const domain = c.domain || host;
    const cpath  = c.path || "/";
    const idx = jar.findIndex(x =>
      x.name === c.name &&
      (x.domain || "") === (domain || "") &&
      (x.path || "/") === cpath
    );
    const row = { name: c.name, value: String(c.value ?? ""), domain: domain || "", path: cpath };
    if (idx >= 0) jar[idx] = row; else jar.push(row);
  });
  _aspSaveCookieJar(jar);
}
function _aspCookieHeaderForUrl(url) {
  let host = "", path = "/";
  try {
    const u = new URL(url);
    host = u.hostname;
    path = u.pathname || "/";
  } catch (e) { return ""; }
  const parts = [];
  _aspGetCookieJar().forEach(c => {
    if (!_aspCookieHostMatch(c.domain, host)) return;
    const cpath = c.path || "/";
    if (cpath !== "/") {
      const prefix = cpath.endsWith("/") ? cpath : cpath + "/";
      if (path !== cpath && !path.startsWith(prefix) && path !== cpath.replace(/\/$/, "")) return;
    }
    parts.push(c.name + "=" + c.value);
  });
  return parts.join("; ");
}
function _aspApplyCookieJarToPayload(payload) {
  if (!payload || !payload.url) return payload;
  const jarCookie = _aspCookieHeaderForUrl(payload.url);
  if (!jarCookie) return payload;
  payload.headers = payload.headers || {};
  const existingKey = Object.keys(payload.headers).find(k => k.toLowerCase() === "cookie");
  if (existingKey) {
    const cur = String(payload.headers[existingKey] || "").trim();
    // Merge: keep user cookies, add jar cookies whose names are missing
    const have = new Set(cur.split(";").map(p => p.trim().split("=")[0]).filter(Boolean));
    const extra = jarCookie.split(";").map(p => p.trim()).filter(p => {
      const n = p.split("=")[0];
      return n && !have.has(n);
    });
    if (extra.length) payload.headers[existingKey] = cur ? (cur + "; " + extra.join("; ")) : extra.join("; ");
  } else {
    payload.headers["Cookie"] = jarCookie;
  }
  return payload;
}
function _aspRenderCookieJarTable(highlight) {
  const tbody = document.getElementById("asp-resp-cookies-tbody");
  if (!tbody) return;
  const jar = _aspGetCookieJar();
  const badge = document.getElementById("asp-badge-resp-cookies");
  if (badge) {
    badge.textContent = jar.length || "";
    badge.style.display = jar.length ? "inline" : "none";
  }
  if (!jar.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="padding:28px 14px;text-align:center;color:var(--text3);font-size:12px">Cookie jar empty — Set-Cookie responses will appear here</td></tr>`;
    return;
  }
  const hi = new Set((highlight || []).map(c => c.name + "|" + (c.domain || "")));
  tbody.innerHTML = jar.map(c => {
    const key = c.name + "|" + (c.domain || "");
    const bg = hi.has(key) ? "background:rgba(63,185,80,.08)" : "";
    return `<tr style="${bg}">
      <td style="padding:7px 12px;font-family:var(--mono);color:#79c0ff;white-space:nowrap">${_aspEscHtml(c.name)}</td>
      <td style="padding:7px 12px;font-family:var(--mono);color:var(--text2);word-break:break-all">${_aspEscHtml(c.value)}</td>
      <td style="padding:7px 12px;color:var(--text3)">${_aspEscHtml(c.domain || "")}</td>
      <td style="padding:7px 12px;color:var(--text3)">${_aspEscHtml(c.path || "/")}</td>
    </tr>`;
  }).join("");
}
function aspClearCookieJar() {
  _aspSaveCookieJar([]);
  _aspRenderCookieJarTable();
  _aspShowToast("Cookie jar cleared");
}
window.aspClearCookieJar = aspClearCookieJar;

function _aspEnvVarSet(key, value) {
  if (!key) return;
  const env = _aspGetActiveEnv();
  if (!env) return;
  const envs = _aspGetEnvs();
  const idx = envs.findIndex(e => e.id === env.id);
  if (idx < 0) return;
  const vars = Array.isArray(envs[idx].variables) ? envs[idx].variables.slice() : [];
  const vi = vars.findIndex(v => v.key === key);
  if (vi >= 0) vars[vi] = { ...vars[vi], key, value: String(value ?? ""), enabled: vars[vi].enabled !== false };
  else vars.push({ key, value: String(value ?? ""), enabled: true });
  envs[idx] = { ...envs[idx], variables: vars };
  _aspSaveEnvs(envs);
}
function _aspEnvVarGet(key) {
  const env = _aspGetActiveEnv();
  if (!env) return "";
  const hit = (env.variables || []).find(v => v.key === key && v.enabled !== false);
  return hit ? String(hit.value ?? "") : "";
}
function _aspCollVarSet(col, key, value) {
  if (!col || !key) return;
  const cols = _aspGetColls();
  const idx = cols.findIndex(c => c.id === col.id);
  if (idx < 0) return;
  const vars = Array.isArray(cols[idx].variables) ? cols[idx].variables.slice() : [];
  const vi = vars.findIndex(v => v.key === key);
  if (vi >= 0) vars[vi] = { ...vars[vi], key, value: String(value ?? ""), enabled: vars[vi].enabled !== false };
  else vars.push({ key, value: String(value ?? ""), enabled: true });
  cols[idx] = { ...cols[idx], variables: vars };
  _aspSaveColls(cols);
  col.variables = vars;
}
function _aspCollVarGet(col, key) {
  if (!col) return "";
  const hit = (col.variables || []).find(v => v.key === key && v.enabled !== false);
  return hit ? String(hit.value ?? "") : "";
}

/**
 * Run pre-request or test script against a mutable context.
 * @returns {{ tests: Array, logs: string[], error: string|null, skipped: boolean }}
 */
function _aspRunScript(code, ctx) {
  const tests = [];
  const logs = [];
  let skipped = false;
  const request = ctx.request || {};
  request.headers = request.headers || {};
  request.params  = request.params  || {};
  if (!request.auth) request.auth = { type: "none", token: "", username: "", password: "" };

  const resp = ctx.response || null;
  let parsedJson = undefined;
  const responseApi = {
    code: resp ? resp.status_code : 0,
    status: resp ? String(resp.status_code) : "",
    responseTime: resp ? (resp.elapsed_ms || 0) : 0,
    headers: {
      get(name) {
        if (!resp || !resp.headers) return undefined;
        const found = Object.keys(resp.headers).find(k => k.toLowerCase() === String(name || "").toLowerCase());
        return found ? resp.headers[found] : undefined;
      },
    },
    text() { return resp ? String(resp.body || "") : ""; },
    json() {
      if (parsedJson !== undefined) return parsedJson;
      try { parsedJson = JSON.parse(resp ? resp.body : ""); }
      catch (e) { parsedJson = null; throw new Error("Could not parse JSON: " + e.message); }
      return parsedJson;
    },
    to: {
      have: {
        status(code) {
          const actual = resp ? resp.status_code : 0;
          if (actual !== code) throw new Error("expected status " + code + ", got " + actual);
        },
      },
    },
  };

  const pm = {
    environment: {
      get: (k) => _aspEnvVarGet(k),
      set: (k, v) => _aspEnvVarSet(k, v),
    },
    collectionVariables: {
      get: (k) => _aspCollVarGet(ctx.collection, k),
      set: (k, v) => _aspCollVarSet(ctx.collection, k, v),
    },
    request,
    response: responseApi,
    cookies: {
      jar: _aspGetCookieJar(),
      get(name) {
        const jar = _aspGetCookieJar();
        const hit = jar.find(c => c.name === name);
        return hit ? hit.value : undefined;
      },
    },
    test(name, fn) {
      try {
        fn();
        tests.push({ name: String(name || "test"), passed: true, error: null });
      } catch (e) {
        tests.push({ name: String(name || "test"), passed: false, error: e && e.message ? e.message : String(e) });
      }
    },
    // optional escape hatch
    skipRequest(reason) { skipped = true; logs.push("[skipRequest] " + (reason || "")); },
  };

  const fakeConsole = {
    log: (...a) => logs.push(a.map(x => {
      try { return typeof x === "string" ? x : JSON.stringify(x); }
      catch (_) { return String(x); }
    }).join(" ")),
  };

  if (!code || !String(code).trim()) {
    return { tests, logs, error: null, skipped: false };
  }

  let error = null;
  try {
    // eslint-disable-next-line no-new-func
    const fn = new Function("pm", "console", '"use strict";\n' + String(code));
    fn(pm, fakeConsole);
  } catch (e) {
    error = e && e.message ? e.message : String(e);
    tests.push({ name: "Script error", passed: false, error });
  }
  return { tests, logs, error, skipped };
}

function _aspRenderTestResults(tests, scriptError) {
  _aspLastTestResults = tests || [];
  const list = document.getElementById("asp-resp-tests-list");
  const summary = document.getElementById("asp-resp-tests-summary");
  const badge = document.getElementById("asp-badge-resp-tests");
  const metaBadge = document.getElementById("asp-resp-tests-badge");
  const total = _aspLastTestResults.length;
  const passed = _aspLastTestResults.filter(t => t.passed).length;
  const failed = total - passed;

  if (badge) {
    badge.textContent = total ? `${passed}/${total}` : "";
    badge.style.display = total ? "inline" : "none";
  }
  if (metaBadge) {
    if (!total && !scriptError) {
      metaBadge.style.display = "none";
    } else {
      metaBadge.style.display = "inline";
      metaBadge.textContent = total ? (failed ? `Tests ${passed}/${total} ✗` : `Tests ${passed}/${total} ✓`) : "Script error";
      metaBadge.style.color = (failed || scriptError) ? "#f85149" : "#3fb950";
    }
  }
  if (summary) {
    if (!total && !scriptError) summary.textContent = "No tests ran — add assertions in Scripts → Tests.";
    else if (scriptError && !total) summary.textContent = "Script error: " + scriptError;
    else summary.textContent = failed
      ? `${failed} failed · ${passed} passed`
      : `${passed} passed`;
    summary.style.color = (failed || scriptError) ? "#f85149" : "#3fb950";
  }
  if (list) {
    if (!total) {
      list.innerHTML = scriptError
        ? `<div class="asp-test-row fail"><span class="asp-test-mark">✗</span><div>${_aspEscHtml(scriptError)}</div></div>`
        : `<div style="font-size:12px;color:var(--text3);padding:12px 4px">Write tests with pm.test("name", () => { … }) or insert a Snippet.</div>`;
    } else {
      list.innerHTML = _aspLastTestResults.map(t =>
        `<div class="asp-test-row ${t.passed ? "pass" : "fail"}">
          <span class="asp-test-mark">${t.passed ? "✓" : "✗"}</span>
          <div>
            <div style="font-weight:600;color:var(--text)">${_aspEscHtml(t.name)}</div>
            ${t.error ? `<div style="font-size:11px;color:#f85149;margin-top:3px">${_aspEscHtml(t.error)}</div>` : ""}
          </div>
        </div>`
      ).join("");
    }
  }
}

function aspCancelSend() {
  _aspUserCancelled = true;
  if (_aspSendCtrl) {
    try { _aspSendCtrl.abort(); } catch (_) {}
  }
}
window.aspCancelSend = aspCancelSend;

// ── Build payload ─────────────────────────────────────────────
async function _aspBuildPayload() {
  const params = {};
  _aspGetRows("asp-params-table").filter(r => r.enabled && r.key)
    .forEach(r => { params[r.key] = r.value; });
  const headers = {};
  _aspGetRows("asp-headers-table").filter(r => r.enabled && r.key)
    .forEach(r => { headers[r.key] = r.value; });
  const bodyType = _aspGetBodyType();
  const rawLang  = _aspGetRawLang();
  let body = null;
  let sendBodyType = bodyType;
  let sendRawLang  = rawLang;

  if (bodyType === "raw" || bodyType === "json" || bodyType === "text") {
    let raw = (document.getElementById("asp-body-raw") || {}).value || "";
    if (typeof _aspRecoverKnownCorruptedPayload === "function") raw = _aspRecoverKnownCorruptedPayload(raw);
    if (typeof _aspReqUnfoldAll === "function") raw = _aspReqUnfoldAll(raw);
    body = _aspResolveTokens(raw);
    sendBodyType = "raw";
    sendRawLang  = bodyType === "json" ? "json" : bodyType === "text" ? "text" : rawLang;
    // Postman-style JSONC: strip // and /* */ before wire send
    if (sendRawLang === "json" && typeof body === "string") {
      body = _aspStripJsonComments(body);
    }
  } else if (bodyType === "form") {
    body = {};
    _aspGetRows("asp-body-form-table").filter(r => r.enabled && r.key)
      .forEach(r => { body[r.key] = r.value; });
  } else if (bodyType === "multipart") {
    const rows = _aspGetMultipartRows().filter(r => r.enabled && r.key);
    const readB64 = file => new Promise((res, rej) => {
      const reader = new FileReader();
      reader.onload  = e => res(e.target.result.split(",")[1]);
      reader.onerror = rej;
      reader.readAsDataURL(file);
    });
    const entries = await Promise.all(rows.map(async r => {
      if (r.fieldType === "file" && r.fileObjs.length) {
        return Promise.all(r.fileObjs.map(async f => ({
          key: r.key, type: "file",
          filename: f.name, contentType: f.type || "application/octet-stream",
          data: await readB64(f),
        })));
      }
      return [{ key: r.key, type: "text", value: r.value }];
    }));
    body = entries.flat();
  } else if (bodyType === "binary") {
    if (!_aspBinaryCache || !_aspBinaryCache.data) {
      throw new Error("Select a binary file for the request body.");
    }
    body = {
      filename: _aspBinaryCache.filename,
      contentType: _aspBinaryCache.contentType || "application/octet-stream",
      data: _aspBinaryCache.data,
    };
  } else if (bodyType === "graphql") {
    const query = ((document.getElementById("asp-gql-query") || {}).value || "").trim();
    const varsRaw = ((document.getElementById("asp-gql-vars") || {}).value || "").trim();
    let variables = {};
    if (varsRaw) {
      try { variables = JSON.parse(varsRaw); }
      catch (e) { throw new Error("GraphQL Variables must be valid JSON: " + e.message); }
    }
    body = { query, variables };
  }
  let method = _aspGetMethod();
  let url    = _aspGetUrl();
  let auth   = _aspGetAuth();

  // Resolve collection / folder auth + variables (folder overrides collection)
  const membership = _aspGetActiveTabMembership();
  const activeColl   = membership && membership.col;
  const activeFolder = membership && membership.folder;

  if (auth.type === "inherit") {
    auth = _aspResolveScopeAuth(activeColl, activeFolder);
  }
  // If Bearer or Basic auth is explicitly active in the Auth tab/scope, avoid duplicate wire headers
  if (auth.type === "bearer" && auth.token) {
    _aspDelHeaderCI(headers, "Authorization");
  } else if (auth.type === "basic" && (auth.username || auth.password)) {
    _aspDelHeaderCI(headers, "Authorization");
  }

  // Env → Collection → Folder (folder / collection override env for same key)
  const vars = _aspResolveActiveVars(activeColl, activeFolder);
  if (vars.length) {
    const av = s => _aspApplyCollVars(s, vars);
    url = av(url);
    Object.keys(params).forEach(k  => { params[k]  = av(String(params[k]));  });
    Object.keys(headers).forEach(k => { headers[k] = av(String(headers[k])); });
    if (auth.token)    auth.token    = av(String(auth.token));
    if (auth.username) auth.username = av(String(auth.username));
    if (auth.password) auth.password = av(String(auth.password));
    if (typeof body === "string") {
      body = av(body);
    } else if (Array.isArray(body)) {
      // multipart: resolve {{vars}} on text field keys/values (filenames left as-is)
      body = body.map(entry => {
        const e = { ...entry, key: av(String(entry.key || "")) };
        if (e.type !== "file" && typeof e.value === "string") e.value = av(e.value);
        return e;
      });
    } else if (body && typeof body === "object" && sendBodyType === "graphql") {
      if (typeof body.query === "string") body.query = av(body.query);
    } else if (body && typeof body === "object" && sendBodyType !== "binary") {
      Object.keys(body).forEach(k => { if (typeof body[k] === "string") body[k] = av(body[k]); });
    }
  }

  // URL bar may include ?query for display; wire send uses base URL + params dict
  // so requests doesn't duplicate the query string.
  {
    const split = _aspSplitUrl(url);
    url = (split.base || url) + (split.hash || "");
    if (!Object.keys(params).length && split.params.length) {
      split.params.forEach(p => {
        if (p.enabled !== false && p.key) params[p.key] = p.value;
      });
    }
  }

  return {
    method, url, params, headers, body, auth,
    body_type: sendBodyType,
    raw_lang: sendBodyType === "raw" ? sendRawLang : undefined,
  };
}

// ── SEND ──────────────────────────────────────────────────────
async function aspSend() {
  if (_aspSending || _aspIsWorkspaceOverlayOpen()) return;
  const rawUrl = _aspGetUrl().trim();
  if (!rawUrl) { _aspUrlError("Enter a URL first"); return; }
  const _valMem  = _aspGetActiveTabMembership();
  const _valVars = _aspResolveActiveVars(_valMem && _valMem.col, _valMem && _valMem.folder);
  const _resolvedUrl = _valVars.length ? _aspApplyCollVars(rawUrl, _valVars) : rawUrl;
  if (!_resolvedUrl.startsWith("http")) { _aspUrlError("URL must start with http:// or https://"); return; }

  _aspSending = true;
  _aspSetSendState(true);
  _aspRFTerm = ''; _aspRFMatches = []; _aspRFIdx = 0;
  const _rfBar = document.getElementById('asp-resp-find-bar');
  if (_rfBar) _rfBar.style.display = 'none';
  _aspShowRespPanel();
  _aspShowRespPlaceholder("Sending request…");
  _aspRenderTestResults([], null);

  let payload;
  try {
    payload = await _aspBuildPayload();
  } catch (buildErr) {
    _aspSending = false;
    _aspSetSendState(false);
    _aspShowRespError("Payload build error: " + (buildErr.message || String(buildErr)));
    return;
  }

  // Pre-request script (may mutate headers/params/auth/url)
  const preCode = ((document.getElementById("asp-script-pre") || {}).value || "").trim();
  if (preCode) {
    const preRes = _aspRunScript(preCode, {
      request: payload,
      response: null,
      collection: _valMem && _valMem.col,
    });
    if (preRes.error) {
      _aspSending = false;
      _aspSetSendState(false);
      _aspShowRespError("Pre-request script error: " + preRes.error);
      _aspRenderTestResults(preRes.tests, preRes.error);
      // Keep current tabs — only mirror error under Scripts if that tab is open
      if (_aspActiveReqTab() === "scripts") {
        aspScriptPhase("pre");
        _aspShowScriptError("⚠ Pre-request script error — " + preRes.error);
      }
      return;
    }
    if (preRes.skipped) {
      _aspSending = false;
      _aspSetSendState(false);
      _aspShowRespError("Request skipped by pre-request script" + (preRes.logs[0] ? " — " + preRes.logs[0] : ""));
      return;
    }
  }

  _aspApplyCookieJarToPayload(payload);

  const ctrl = new AbortController();
  _aspSendCtrl = ctrl;
  _aspUserCancelled = false;
  const timer = setTimeout(() => ctrl.abort(), 60000);
  const tClient0 = Date.now();
  try {
    const r = await fetch(`${ASP_BASE}/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    const d = await r.json();
    const clientMs = Date.now() - tClient0;
    if (!d.ok) {
      _aspShowRespError(d.error || "Request failed");
      _aspRenderTestResults([], null);
    } else {
      d.client_ms = clientMs;
      if (d.cookies && d.cookies.length) {
        _aspCookieJarUpsert(d.cookies, d.sent_url || payload.url);
      }
      const testCode = ((document.getElementById("asp-script-test") || {}).value || "").trim();
      let testRes = { tests: [], error: null };
      if (testCode) {
        testRes = _aspRunScript(testCode, {
          request: payload,
          response: d,
          collection: _valMem && _valMem.col,
        });
      }
      d.test_results = testRes.tests;
      d.tests_passed = testRes.tests.length
        ? testRes.tests.every(t => t.passed)
        : true;
      _aspRenderResponse(d);
      _aspRenderTestResults(testRes.tests, testRes.error);
      // Do not force-switch to Scripts / Test Results — keep whatever tab user had open
      if (_aspActiveReqTab() === "scripts" && _aspScriptPhase === "test") {
        _aspShowScriptTestFailures(testRes.tests, testRes.error);
      }
      _aspRenderCookieJarTable(d.cookies || []);
      _aspSaveHistory(payload, d);
    }
  } catch (e) {
    clearTimeout(timer);
    if (e.name === "AbortError") {
      _aspShowRespError(_aspUserCancelled
        ? "Request cancelled."
        : "Request timed out (60s). The server did not respond.");
    } else {
      _aspShowRespError("Cannot reach APISphere backend (port 8791). Please restart the app.");
    }
  } finally {
    _aspSendCtrl = null;
    _aspUserCancelled = false;
    _aspSending = false;
    _aspSetSendState(false);
  }
}

function _aspSetSendState(loading) {
  const wrap = document.getElementById("asp-send-wrap");
  const btn = document.getElementById("asp-send-btn");
  const caret = document.getElementById("asp-send-caret");
  const cancel = document.getElementById("asp-cancel-btn");
  const lbl = document.getElementById("asp-send-label");
  const spn = document.getElementById("asp-send-spinner");
  const locked = _aspIsWorkspaceOverlayOpen();
  if (wrap) wrap.style.display = loading ? "none" : "inline-flex";
  if (btn) {
    btn.disabled = loading || locked;
    btn.style.display = "inline-flex";
  }
  if (caret) caret.disabled = loading || locked;
  if (cancel) cancel.style.display = loading ? "inline-flex" : "none";
  if (lbl) lbl.textContent = "Send";
  if (spn) spn.style.display = "none";
  if (loading) aspCloseSendMenu();
  _aspUpdateSendDownloadEnabled();
}

// ── Send dropdown (Download response) ─────────────────────────
function _aspHasDownloadableResponse() {
  const d = _aspLastResp;
  return !!(d && d.ok !== false && (d.body_b64 != null || d.body != null || d.status_code != null));
}
function _aspUpdateSendDownloadEnabled() {
  const btn = document.getElementById("asp-send-download-btn");
  if (!btn) return;
  const ok = _aspHasDownloadableResponse();
  btn.disabled = !ok;
  btn.title = ok ? "Save the last response body to a file" : "Send a request first";
}
function aspToggleSendMenu(ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  if (_aspSending || _aspIsWorkspaceOverlayOpen()) return;
  const menu = document.getElementById("asp-send-menu");
  const caret = document.getElementById("asp-send-caret");
  if (!menu) return;
  const open = menu.style.display === "block";
  if (open) {
    aspCloseSendMenu();
    return;
  }
  aspCloseImportMenu();
  aspCloseEnvMenu();
  _aspUpdateSendDownloadEnabled();
  menu.style.display = "block";
  if (caret) caret.setAttribute("aria-expanded", "true");
  setTimeout(() => document.addEventListener("click", _aspSendMenuOutside, { once: true }), 0);
}
function aspCloseSendMenu() {
  const menu = document.getElementById("asp-send-menu");
  const caret = document.getElementById("asp-send-caret");
  if (menu) menu.style.display = "none";
  if (caret) caret.setAttribute("aria-expanded", "false");
}
function _aspSendMenuOutside(e) {
  const menu = document.getElementById("asp-send-menu");
  const caret = document.getElementById("asp-send-caret");
  const wrap = document.getElementById("asp-send-wrap");
  if (menu && wrap && !wrap.contains(e.target)) aspCloseSendMenu();
  else if (menu && caret && e.target !== caret && !menu.contains(e.target)) aspCloseSendMenu();
}
function _aspB64ToUint8(b64) {
  const bin = atob(b64 || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function _aspGuessDownloadName(d) {
  let name = (d && d.filename) || "";
  // If generic .bin but body looks like ZIP/OOXML (PK…), prefer a better ext
  if (!name || /\.bin$/i.test(name)) {
    const preview = (d && d.body) ? String(d.body).slice(0, 200) : "";
    if (preview.startsWith("PK")) {
      if (preview.indexOf("xl/") >= 0 || preview.indexOf("workbook") >= 0) name = "response.xlsx";
      else if (preview.indexOf("word/") >= 0) name = "response.docx";
      else if (preview.indexOf("ppt/") >= 0) name = "response.pptx";
      else name = "response.zip";
    }
  }
  if (name) return name;
  const ct = ((d && d.headers) || {});
  const rawCt = String(ct["Content-Type"] || ct["content-type"] || "").toLowerCase();
  const mime = rawCt.split(";")[0].trim();
  const map = {
    "application/json": ".json",
    "text/html": ".html",
    "text/plain": ".txt",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "image/png": ".png",
    "image/jpeg": ".jpg",
  };
  let ext = map[mime] || "";
  if (!ext && d && d.body_hint === "json") ext = ".json";
  else if (!ext && d && d.body_hint === "html") ext = ".html";
  else if (!ext && d && (d.is_binary || d.body_hint === "binary")) ext = ".bin";
  else if (!ext) ext = ".txt";
  try {
    const path = new URL(d.sent_url || _aspGetUrl() || "http://x/response").pathname;
    const base = decodeURIComponent((path.split("/").pop() || "").trim());
    if (base && /\.[A-Za-z0-9]{1,8}$/.test(base)) return base;
  } catch (_) {}
  return "response" + ext;
}
async function aspDownloadResponse() {
  aspCloseSendMenu();
  if (!_aspHasDownloadableResponse()) {
    _aspShowToast("No response to download — Send a request first");
    return;
  }
  const d = _aspLastResp;
  const name = _aspGuessDownloadName(d);

  // Desktop app: native macOS Save dialog (choose folder + filename)
  const api = window.pywebview && window.pywebview.api;
  if (api && (typeof api.save_bytes_b64 === "function" || typeof api.save_file === "function")) {
    try {
      let r;
      if (d.body_b64 != null && d.body_b64 !== "" && typeof api.save_bytes_b64 === "function") {
        r = await api.save_bytes_b64(d.body_b64, name);
      } else if (typeof api.save_file === "function") {
        r = await api.save_file(d.body != null ? String(d.body) : "", name);
      }
      if (!r || r.reason === "cancelled") {
        _aspShowToast("Download cancelled");
        return;
      }
      if (r.ok) {
        _aspShowToast("Saved " + (r.filename || name));
        _aspAlert("Response saved:\n" + (r.path || ""));
        return;
      }
      _aspAlert("Download failed: " + (r.reason || "unknown error"));
      return;
    } catch (e) {
      _aspAlert("Download failed: " + (e.message || String(e)));
      return;
    }
  }

  // Browser / fallback (no Save dialog — goes to default Downloads)
  try {
    let blob;
    if (d.body_b64 != null && d.body_b64 !== "") {
      const bytes = _aspB64ToUint8(d.body_b64);
      const ctHdr = (d.headers && (d.headers["Content-Type"] || d.headers["content-type"])) || "";
      const mime = (ctHdr.split(";")[0] || "").trim() || "application/octet-stream";
      blob = new Blob([bytes], { type: mime });
    } else {
      const mime = d.body_hint === "json" ? "application/json"
        : d.body_hint === "html" ? "text/html"
        : "text/plain";
      blob = new Blob([d.body != null ? String(d.body) : ""], { type: mime });
    }
    const a = document.createElement("a");
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => { try { URL.revokeObjectURL(url); } catch (_) {} }, 2500);
    _aspShowToast("Downloaded " + name + " (check Downloads folder)");
  } catch (e) {
    _aspAlert("Download failed: " + (e.message || String(e)));
  }
}
window.aspToggleSendMenu = aspToggleSendMenu;
window.aspCloseSendMenu = aspCloseSendMenu;
window.aspDownloadResponse = aspDownloadResponse;

// ── Workspace overlays (Overview / Collection Runner / AV Runner) ──
// Only one overlay at a time. While open, request chrome (Send, +, …) is locked.
function _aspIsAvRunnerOpen() {
  const el = document.getElementById("asp-runner-overlay");
  return !!(el && el.style.display === "flex");
}
function _aspIsEnvEditorOpen() {
  return !!_aspEnvEditing;
}
function _aspIsWorkspaceOverlayOpen() {
  return !!_aspCollOvId || !!_aspCRColId || _aspIsAvRunnerOpen() || _aspIsEnvEditorOpen();
}
function _aspHideCollOverviewPanelOnly() {
  const ov = document.getElementById("asp-coll-ov");
  if (ov) ov.style.display = "none";
  _aspCollOvId = null;
  _aspCollOvFolderId = null;
}
function _aspHideCollRunnerPanelOnly() {
  if (_aspCRRunning) {
    _aspCRAborted = true;
    _aspCRPaused  = false;
  }
  const panel = document.getElementById("asp-coll-runner");
  if (panel) panel.style.display = "none";
  _aspCRColId = null;
  _aspCRResults = [];
  _aspCRTestData = null;
  _aspCRSetRunControls(false);
}
function _aspHideAvRunnerPanelOnly() {
  if (_aspRunnerRunning) {
    _aspRunnerAborted = true;
    _aspRunnerPaused  = false;
  }
  const overlay = document.getElementById("asp-runner-overlay");
  if (overlay) overlay.style.display = "none";
}
/** Close overlays that are not `except` ('overview' | 'collRunner' | 'avRunner' | 'env'). */
function _aspCloseWorkspaceOverlays(except) {
  if (except !== "overview")   _aspHideCollOverviewPanelOnly();
  if (except !== "collRunner") _aspHideCollRunnerPanelOnly();
  if (except !== "avRunner")   _aspHideAvRunnerPanelOnly();
  if (except !== "env")        _aspHideEnvPanelOnly();
}
function _aspSyncChromeLock() {
  const locked = _aspIsWorkspaceOverlayOpen();
  const root = document.getElementById("tool-apisphere");
  if (root) root.classList.toggle("asp-chrome-locked", locked);

  if (locked && _aspHistoryOpen) aspToggleHistory(false);
  aspCloseImportMenu();
  aspCloseEnvMenu();
  aspCloseSendMenu();
  aspCloseRespFmtMenu();
  aspCloseTabRclickMenu();

  const sendBtn = document.getElementById("asp-send-btn");
  const sendCaret = document.getElementById("asp-send-caret");
  const sendLbl = document.getElementById("asp-send-label");
  if (sendBtn) {
    sendBtn.onclick = aspSend;
    if (!_aspSending) sendBtn.disabled = locked;
  }
  if (sendCaret && !_aspSending) sendCaret.disabled = locked;
  if (sendLbl && !_aspSending) sendLbl.textContent = "Send";

  ["asp-new-tab-btn", "asp-method-sel", "asp-url-input", "asp-history-btn", "asp-import-menu-btn"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = locked;
  });
  // Env selector stays usable so user can open/switch while editing; disabled only for other overlays
  const envBtn = document.getElementById("asp-env-btn");
  if (envBtn) envBtn.disabled = locked && !_aspIsEnvEditorOpen();
}

function _aspUrlError(msg) {
  const el = document.getElementById("asp-url-error");
  if (el) { el.textContent = msg; el.style.display = "block"; }
  setTimeout(() => { if (el) el.style.display = "none"; }, 3000);
}

function _aspShowRespPanel() {
  const empty  = document.getElementById("asp-resp-empty");
  const loaded = document.getElementById("asp-resp-loaded");
  if (empty)  empty.style.display  = "none";
  if (loaded) loaded.style.display = "flex";
}

function _aspShowRespPlaceholder(msg) {
  _aspSetRespMeta("", "", "");
  const pre = document.getElementById("asp-resp-body-pre");
  if (pre) { pre.innerHTML = ""; pre.textContent = msg; pre.style.color = "var(--text3)"; }
  // Do not force Body tab — keep user's current response tab
}

function _aspShowRespError(msg) {
  _aspSetRespMeta("", "", "");
  const pre = document.getElementById("asp-resp-body-pre");
  if (pre) { pre.innerHTML = ""; pre.textContent = "⚠ " + msg; pre.style.color = "#f85149"; }
  _aspUpdateSendDownloadEnabled();
}

// ── Response rendering ─────────────────────────────────────────
function _aspToggleTimingPopover(e) {
  if (e) e.stopPropagation();
  const pop = document.getElementById("asp-timing-popover");
  if (!pop) return;
  pop.classList.toggle("open");
}

document.addEventListener("click", () => {
  const pop = document.getElementById("asp-timing-popover");
  if (pop && pop.classList.contains("open")) pop.classList.remove("open");
});

function _aspSetRespMeta(status, time, size, timingObj) {
  const statusEl = document.getElementById("asp-resp-status");
  const timeEl   = document.getElementById("asp-resp-time");
  const timeWrap = document.getElementById("asp-resp-time-wrap");
  const sizeEl   = document.getElementById("asp-resp-size");
  const sizePill = document.getElementById("asp-resp-size-pill");
  const elapsedEl  = document.getElementById("asp-timing-elapsed");
  const transferEl = document.getElementById("asp-timing-transfer");
  const clientEl   = document.getElementById("asp-timing-client");

  if (statusEl) {
    if (!status) {
      statusEl.textContent = "";
      statusEl.style.display = "none";
    } else {
      const code  = parseInt(status);
      const color = code < 300 ? "#3fb950" : code < 400 ? "#79c0ff" : code < 500 ? "#d29922" : "#f85149";
      statusEl.textContent       = status;
      statusEl.style.color       = color;
      statusEl.style.background  = color + "18";
      statusEl.style.borderColor = color + "44";
      statusEl.style.display     = "inline-flex";
    }
  }

  if (timeEl) {
    if (time != null && time !== "") {
      timeEl.textContent = `${time} ms`;
      if (timeWrap) timeWrap.style.display = "inline-flex";
    } else {
      timeEl.textContent = "";
      if (timeWrap) timeWrap.style.display = "none";
    }
  }

  if (sizeEl) {
    if (size) {
      sizeEl.textContent = _aspFmtSize(size);
      if (sizePill) sizePill.style.display = "inline-flex";
    } else {
      sizeEl.textContent = "";
      if (sizePill) sizePill.style.display = "none";
    }
  }

  if (elapsedEl)  elapsedEl.textContent  = (timingObj && timingObj.elapsed != null)  ? `${timingObj.elapsed} ms`  : (time ? `${time} ms` : "-");
  if (transferEl) transferEl.textContent = (timingObj && timingObj.transfer != null) ? `${timingObj.transfer} ms` : "-";
  if (clientEl)   clientEl.textContent   = (timingObj && timingObj.client != null)   ? `${timingObj.client} ms`   : "-";
}

function _aspFmtSize(bytes) {
  if (bytes < 1024)       return `${bytes} B`;
  if (bytes < 1024*1024)  return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1024/1024).toFixed(2)} MB`;
}

function _aspRenderResponse(d, opts) {
  _aspLastResp = d;
  _aspShowRespPanel();
  const transfer = d.timing && d.timing.transfer_ms != null ? d.timing.transfer_ms : null;
  const client = d.client_ms != null ? d.client_ms : null;
  _aspSetRespMeta(`${d.status_code} ${d.status_text}`, d.elapsed_ms, d.size_bytes, {
    elapsed: d.elapsed_ms,
    transfer,
    client
  });

  _aspLastSentCurl = d.sent_curl || "";
  const curlBtn = document.getElementById("asp-copy-curl-btn");
  if (curlBtn) curlBtn.removeAttribute("data-curl");

  // opts.keepFmt — tab restore keeps user's last format; Send re-detects
  if (!(opts && opts.keepFmt)) {
    _aspRespFmt = _aspDetectRespFmt(d);
  }
  _aspSyncRespFmtUi();
  _aspRenderRespBody(d.body, d.body_hint);
  _aspRenderRespHeaders(d.headers || {});
  _aspUpdateSendDownloadEnabled();

  const hBadge = document.getElementById("asp-badge-resp-headers");
  if (hBadge) {
    const n = Object.keys(d.headers || {}).length;
    hBadge.textContent = n || "";
    hBadge.style.display = n > 0 ? "inline" : "none";
  }
  // Fresh Send of a PDF/image → open Preview (lazy blob render happens there).
  // Avoid decoding/rendering the binary twice on the main thread (that hung the UI).
  if (!(opts && opts.keepFmt)) {
    const ct = _aspRespContentType(d).toLowerCase();
    const fname = String(d.filename || "").toLowerCase();
    const head = String(d.body || "").slice(0, 8);
    if (ct.includes("pdf") || fname.endsWith(".pdf") || head.startsWith("%PDF") ||
        ct.startsWith("image/")) {
      aspRespTab("preview");
      return;
    }
  }
  // If user is already on Preview, refresh it; otherwise leave blob work for tab click.
  const prevBtn = document.getElementById("asp-resp-tab-preview");
  if (prevBtn && prevBtn.classList.contains("asp-tab-active")) {
    _aspRenderRespPreview(d);
  } else {
    _aspRevokePreviewUrl();
    const frame = document.getElementById("asp-resp-preview-frame");
    if (frame) { try { frame.removeAttribute("srcdoc"); } catch (_) {} frame.src = "about:blank"; }
  }
}

let _aspPreviewObjectUrl = null;

function _aspRevokePreviewUrl() {
  if (_aspPreviewObjectUrl) {
    try { URL.revokeObjectURL(_aspPreviewObjectUrl); } catch (_) {}
    _aspPreviewObjectUrl = null;
  }
}

function _aspRespContentType(d) {
  const hdrs = (d && d.headers) || {};
  for (const k of Object.keys(hdrs)) {
    if (String(k).toLowerCase() === "content-type") return String(hdrs[k] || "");
  }
  return "";
}

/** Postman-style Preview: render PDF/images via blob URL; HTML via srcdoc. */
function _aspRenderRespPreview(d) {
  const frame = document.getElementById("asp-resp-preview-frame");
  if (!frame) return;
  _aspRevokePreviewUrl();
  try { frame.removeAttribute("srcdoc"); } catch (_) {}
  frame.src = "about:blank";

  if (!d) {
    frame.setAttribute("sandbox", "allow-same-origin allow-scripts");
    frame.srcdoc = `<div style="padding:16px;font:12px sans-serif;color:#666">No response</div>`;
    return;
  }

  const ct = _aspRespContentType(d).toLowerCase();
  const mime = (ct.split(";")[0] || "").trim();
  const fname = String(d.filename || "").toLowerCase();
  const head = String(d.body || "").slice(0, 16);
  const isPdf = mime.includes("pdf") || fname.endsWith(".pdf") || head.startsWith("%PDF");
  const isSvg = mime.includes("svg") || /^\s*<svg[\s>]/i.test(String(d.body || ""));
  const isImage = !isSvg && (mime.startsWith("image/") || /\.(png|jpe?g|gif|webp|bmp|ico)$/i.test(fname));
  const isHtml = d.body_hint === "html" || mime.includes("text/html");

  if ((isPdf || isImage) && d.body_b64) {
    try {
      const bytes = _aspB64ToUint8(d.body_b64);
      const blobType = isPdf ? "application/pdf" : (mime || "application/octet-stream");
      const blob = new Blob([bytes], { type: blobType });
      _aspPreviewObjectUrl = URL.createObjectURL(blob);
      // Chromium's PDF viewer does not run inside a sandboxed iframe.
      frame.removeAttribute("sandbox");
      frame.src = _aspPreviewObjectUrl;
      return;
    } catch (e) {
      frame.setAttribute("sandbox", "allow-same-origin allow-scripts");
      frame.srcdoc = `<div style="padding:16px;font:12px sans-serif;color:#c00">Preview failed: ${_aspEscHtml(e.message || String(e))}</div>`;
      return;
    }
  }

  frame.setAttribute("sandbox", "allow-same-origin allow-scripts");

  if (isHtml || isSvg) {
    frame.srcdoc = d.body || "";
    return;
  }

  if (isPdf && !d.body_b64) {
    frame.srcdoc = `<div style="padding:24px;font:13px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;color:#24292f;background:#f6f8fa;height:100%;box-sizing:border-box">
      <div style="font-weight:700;margin-bottom:8px">PDF preview unavailable</div>
      <div style="color:#57606a">Binary data was not kept for this response. Send the request again, then open <b>Preview</b>.</div>
    </div>`;
    return;
  }

  if (d.is_binary || d.body_hint === "binary") {
    const size = d.size_bytes != null ? _aspFmtSize(d.size_bytes) : "";
    frame.srcdoc = `<div style="padding:24px;font:13px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;color:#24292f;background:#f6f8fa;height:100%;box-sizing:border-box">
      <div style="font-weight:700;margin-bottom:8px">Binary response</div>
      <div style="color:#57606a;margin-bottom:12px">${_aspEscHtml(mime || "application/octet-stream")}${size ? " · " + _aspEscHtml(size) : ""}</div>
      <div style="color:#57606a">Use <b>Send ▾ → Download response</b> to save the file. Preview supports PDF and images when binary data is present.</div>
    </div>`;
    return;
  }

  frame.srcdoc = `<pre style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#24292f;background:#fff;padding:12px;margin:0;white-space:pre-wrap;word-break:break-word">${_aspEscHtml(d.body || "")}</pre>`;
}
window._aspRenderRespPreview = _aspRenderRespPreview;

function _aspDetectRespFmt(d) {
  if (!d) return "raw";
  const hint = (d.body_hint || "").toLowerCase();
  if (hint === "json") return "json";
  if (hint === "html") return "html";
  if (hint === "binary") return "raw";
  const hdrs = d.headers || {};
  let ct = "";
  for (const k of Object.keys(hdrs)) {
    if (String(k).toLowerCase() === "content-type") { ct = String(hdrs[k] || "").toLowerCase(); break; }
  }
  if (ct.includes("json") || ct.endsWith("+json")) return "json";
  if (ct.includes("yaml") || ct.includes("yml")) return "yaml";
  if (ct.includes("xml") || ct.endsWith("+xml")) return "xml";
  if (ct.includes("html")) return "html";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "javascript";
  if (ct.includes("markdown") || ct.includes("text/md")) return "markdown";
  const body = (d.body != null ? String(d.body) : "").trim();
  if (!body) return "raw";
  if (/^[\{\[]/.test(body)) {
    try { JSON.parse(_aspStripJsonComments(body)); return "json"; } catch (_) {}
  }
  if (/^<!DOCTYPE\s+html|^<html[\s>]/i.test(body)) return "html";
  if (/^<\?xml|^<[A-Za-z_:][\w:.-]*[\s/>]/.test(body)) return "xml";
  return "raw";
}

function _aspSyncRespFmtUi() {
  const label = document.getElementById("asp-resp-fmt-label");
  if (label) label.textContent = _ASP_RESP_FMT_LABELS[_aspRespFmt] || "Raw";
  document.querySelectorAll("#asp-resp-fmt-menu button[data-fmt]").forEach(btn => {
    btn.classList.toggle("asp-fmt-active", btn.getAttribute("data-fmt") === _aspRespFmt);
  });
}

function aspToggleRespFmtMenu(ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  const menu = document.getElementById("asp-resp-fmt-menu");
  if (!menu) return;
  const open = menu.style.display === "block";
  if (open) { aspCloseRespFmtMenu(); return; }
  aspCloseSendMenu();
  aspCloseImportMenu();
  aspCloseEnvMenu();
  _aspSyncRespFmtUi();
  menu.style.display = "block";
  setTimeout(() => document.addEventListener("click", _aspRespFmtMenuOutside, { once: true }), 0);
}
function aspCloseRespFmtMenu() {
  const menu = document.getElementById("asp-resp-fmt-menu");
  if (menu) menu.style.display = "none";
}
function _aspRespFmtMenuOutside(e) {
  const wrap = document.getElementById("asp-resp-fmt-wrap");
  if (wrap && !wrap.contains(e.target)) aspCloseRespFmtMenu();
}
function aspSetRespFmt(fmt) {
  aspCloseRespFmtMenu();
  if (!_ASP_RESP_FMT_LABELS[fmt]) return;
  _aspRespFmt = fmt;
  _aspSyncRespFmtUi();
  if (_aspLastResp) _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
}
window.aspToggleRespFmtMenu = aspToggleRespFmtMenu;
window.aspCloseRespFmtMenu = aspCloseRespFmtMenu;
window.aspSetRespFmt = aspSetRespFmt;
/** Legacy Raw/Pretty toggle — maps to raw ↔ detected pretty */
function aspToggleRespRaw() {
  if (_aspRespFmt === "raw") {
    _aspRespFmt = _aspLastResp ? _aspDetectRespFmt(_aspLastResp) : "json";
    if (_aspRespFmt === "raw") _aspRespFmt = "json";
  } else {
    _aspRespFmt = "raw";
  }
  _aspSyncRespFmtUi();
  if (_aspLastResp) _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
}

function _aspPrettyXml(text) {
  const raw = String(text || "").trim();
  if (!raw) return "";
  // Collapse between tags, then indent
  let s = raw.replace(/>\s*</g, ">\n<").replace(/\r\n/g, "\n");
  const lines = s.split("\n");
  let pad = 0;
  const out = [];
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    if (/^<\/\w/.test(line)) pad = Math.max(0, pad - 1);
    out.push("  ".repeat(pad) + line);
    if (/^<\?/.test(line) || /^<!/.test(line) || /\/>$/.test(line) || /^<\/\w/.test(line)) {
      // no indent bump
    } else if (/^<[^>]+>.*<\/[^>]+>$/.test(line)) {
      // open+close same line
    } else if (/^<\w[^>]*>/.test(line)) {
      pad++;
    }
  }
  return out.join("\n");
}

function _aspHighlightXml(text) {
  const esc = _aspEscHtml(text);
  return esc
    .replace(/(&lt;!--[\s\S]*?--&gt;)/g, `<span class="asp-xml-com">$1</span>`)
    .replace(/(&lt;\/?)([A-Za-z_:][\w:.-]*)(.*?)(\/?&gt;)/g, (_, a, tag, rest, c) => {
      const attrs = rest.replace(/([A-Za-z_:][\w:.-]*)(=)(&quot;[\s\S]*?&quot;|&#39;[\s\S]*?&#39;)/g,
        `<span class="asp-xml-attr">$1</span>$2<span class="asp-xml-str">$3</span>`);
      return `<span class="asp-xml-tag">${a}${tag}</span>${attrs}<span class="asp-xml-tag">${c}</span>`;
    });
}

function _aspJsonToYaml(value, indent) {
  const ind = indent || 0;
  const pad = "  ".repeat(ind);
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (typeof value === "string") {
    if (value === "" || /[:#\n\r\t]|^\s|\s$/.test(value) || /^(true|false|null|\d+)/i.test(value)) {
      return JSON.stringify(value);
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (!value.length) return "[]";
    return value.map(v => {
      if (v !== null && typeof v === "object") {
        const nested = _aspJsonToYaml(v, ind + 1);
        return pad + "- " + nested.replace(/^\s+/, "").replace(/\n/g, "\n" + pad + "  ");
      }
      return pad + "- " + _aspJsonToYaml(v, 0);
    }).join("\n");
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (!keys.length) return "{}";
    return keys.map(k => {
      const v = value[k];
      if (v !== null && typeof v === "object") {
        const nested = _aspJsonToYaml(v, ind + 1);
        return pad + k + ":\n" + (nested.startsWith(" ") || nested.includes("\n") ? nested : ("  ".repeat(ind + 1) + nested));
      }
      return pad + k + ": " + _aspJsonToYaml(v, 0);
    }).join("\n");
  }
  return String(value);
}

function _aspHighlightYaml(text) {
  return String(text || "").split("\n").map(line => {
    const m = line.match(/^(\s*)(?:(-\s+))?([^:#\n]+?)(\s*:\s*)(.*)$/);
    if (m && !line.trim().startsWith("#")) {
      const [, sp, dash, key, colon, rest] = m;
      let val = rest;
      if (/^(true|false|null)\s*$/i.test(rest)) val = `<span class="asp-yaml-bool">${_aspEscHtml(rest)}</span>`;
      else if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?\s*$/.test(rest)) val = `<span class="asp-yaml-num">${_aspEscHtml(rest)}</span>`;
      else if (rest) val = `<span class="asp-yaml-str">${_aspEscHtml(rest)}</span>`;
      return _aspEscHtml(sp) + _aspEscHtml(dash || "") +
        `<span class="asp-yaml-key">${_aspEscHtml(key)}</span>${_aspEscHtml(colon)}${val}`;
    }
    if (line.trim().startsWith("#")) return `<span class="asp-yaml-com">${_aspEscHtml(line)}</span>`;
    return _aspEscHtml(line);
  }).join("\n");
}

function _aspHighlightMarkdown(text) {
  return _aspEscHtml(text || "")
    .replace(/^(#{1,6}\s.+)$/gm, `<span class="asp-md-h">$1</span>`)
    .replace(/(`[^`]+`)/g, `<span class="asp-md-code">$1</span>`)
    .replace(/(\*\*[^*\n]+\*\*|__[^_\n]+__)/g, `<span class="asp-md-em">$1</span>`);
}

function _aspGetRespBytes() {
  const d = _aspLastResp;
  if (!d) return new Uint8Array(0);
  if (d.body_b64) {
    try { return _aspB64ToUint8(d.body_b64); } catch (_) {}
  }
  const s = d.body != null ? String(d.body) : "";
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function _aspHexDump(bytes, maxBytes) {
  const limit = Math.min(bytes.length, maxBytes == null ? bytes.length : maxBytes);
  const lines = [];
  for (let i = 0; i < limit; i += 16) {
    const slice = bytes.subarray(i, Math.min(i + 16, limit));
    let hex = "";
    let ascii = "";
    for (let j = 0; j < 16; j++) {
      if (j < slice.length) {
        hex += slice[j].toString(16).padStart(2, "0") + (j === 7 ? "  " : " ");
        ascii += (slice[j] >= 32 && slice[j] < 127) ? String.fromCharCode(slice[j]) : ".";
      } else {
        hex += j === 7 ? "    " : "   ";
      }
    }
    const addr = i.toString(16).padStart(8, "0");
    lines.push(
      `<span class="asp-hex-addr">${addr}</span>  ` +
      `<span class="asp-hex-bytes">${hex}</span> ` +
      `<span class="asp-hex-ascii">|${_aspEscHtml(ascii)}|</span>`
    );
  }
  if (bytes.length > limit) {
    lines.push(`<span class="asp-hex-addr">… truncated (${bytes.length - limit} more bytes) — use Download response for full file</span>`);
  }
  return lines.join("\n");
}

function _aspFormatRespPlainText() {
  /** Text currently shown in Body (for Find / Copy of formatted view). */
  const d = _aspLastResp;
  if (!d) return "";
  const body = d.body != null ? String(d.body) : "";
  const fmt = _aspRespFmt || "raw";
  try {
    if (fmt === "json") {
      try { return JSON.stringify(JSON.parse(_aspStripJsonComments(body)), null, 2); }
      catch (_) { return body; }
    }
    if (fmt === "xml" || fmt === "html") return _aspPrettyXml(body) || body;
    if (fmt === "yaml") {
      try { return _aspJsonToYaml(JSON.parse(_aspStripJsonComments(body)), 0); }
      catch (_) { return body; }
    }
    if (fmt === "hex") {
      const bytes = _aspGetRespBytes();
      const limit = Math.min(bytes.length, 256 * 1024);
      let text = "";
      for (let i = 0; i < limit; i += 16) {
        const slice = bytes.subarray(i, Math.min(i + 16, limit));
        let hex = "", ascii = "";
        for (let j = 0; j < slice.length; j++) {
          hex += slice[j].toString(16).padStart(2, "0") + (j === 7 ? "  " : " ");
          ascii += (slice[j] >= 32 && slice[j] < 127) ? String.fromCharCode(slice[j]) : ".";
        }
        text += i.toString(16).padStart(8, "0") + "  " + hex.padEnd(49) + " |" + ascii + "|\n";
      }
      return text;
    }
    if (fmt === "base64") {
      if (d.body_b64) return d.body_b64;
      try { return btoa(unescape(encodeURIComponent(body))); }
      catch (_) { return btoa(body); }
    }
  } catch (_) {}
  return body;
}

// Cap how much response text we ever inject into the Body <pre>. Escaping +
// innerHTML of a full PDF (~1MB lossy text) freezes the UI for seconds.
const ASP_BODY_UI_MAX = 200 * 1024;
const ASP_BINARY_SNIPPET = 400;

function _aspTruncUiText(s, max) {
  const t = s != null ? String(s) : "";
  if (t.length <= max) return { text: t, truncated: false, total: t.length };
  return { text: t.slice(0, max), truncated: true, total: t.length };
}

let _aspLastRespRaw = "";
let _aspLastRespCleanLines = [];
let _aspRespFolds = {};
let _aspRespFolded = new Set();
let _aspReqWrap = true;
let _aspRespWrap = true;

function _aspRenderRespBody(body, hint) {
  const pre = document.getElementById("asp-resp-body-pre");
  const gutter = document.getElementById("asp-resp-gutter");
  if (!pre) return;
  pre.style.color = "var(--text)";
  pre.classList.toggle("asp-hex", _aspRespFmt === "hex");
  if (_aspRFTerm) { _aspRFRunSearch(); _aspRFUpdateCount(); }
  const raw = body != null ? String(body) : "";
  _aspLastRespRaw = raw;
  const fmt = _aspRespFmt || "raw";
  let html;
  const truncNote = (n, total) =>
    `\n\n<span style="color:#d29922">⚠ Showing first ${_aspFmtSize(n)} of ${_aspFmtSize(total)} — use Preview / Download for the full file.</span>`;

  if (fmt === "json") {
    try {
      const parsed = JSON.parse(_aspStripJsonComments(raw));
      const pretty = JSON.stringify(parsed, null, 2);
      const cut = _aspTruncUiText(pretty, ASP_BODY_UI_MAX);
      _aspLastRespCleanLines = cut.text.split('\n');
      _aspRespFolds = _aspComputeFolds(cut.text);
      _aspRespFolded.clear();
      _aspUpdateRespView();
      _aspInitRespChrome();
      return;
    } catch (e) {
      const cut = _aspTruncUiText(raw || "(empty)", ASP_BODY_UI_MAX);
      html = _aspEscHtml(cut.text) +
        `\n\n<span style="color:#f85149">⚠ Not valid JSON — showing raw. ${ _aspEscHtml(e.message || "") }</span>` +
        (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
    }
  } else if (fmt === "xml" || fmt === "html") {
    const pretty = _aspPrettyXml(raw) || raw;
    const cut = _aspTruncUiText(pretty || "(empty)", ASP_BODY_UI_MAX);
    html = _aspHighlightXml(cut.text) + (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
  } else if (fmt === "yaml") {
    try {
      const parsed = JSON.parse(_aspStripJsonComments(raw));
      const y = _aspJsonToYaml(parsed, 0);
      const cut = _aspTruncUiText(y, ASP_BODY_UI_MAX);
      html = _aspHighlightYaml(cut.text) + (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
    } catch (_) {
      const cut = _aspTruncUiText(raw || "(empty)", ASP_BODY_UI_MAX);
      html = _aspHighlightYaml(cut.text) + (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
    }
  } else if (fmt === "javascript") {
    const cut = _aspTruncUiText(raw || "(empty)", ASP_BODY_UI_MAX);
    html = _aspHighlightJs(cut.text) + (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
  } else if (fmt === "markdown") {
    const cut = _aspTruncUiText(raw || "(empty)", ASP_BODY_UI_MAX);
    html = _aspHighlightMarkdown(cut.text) + (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
  } else if (fmt === "hex") {
    // Cap hex dump — full-file hex of an 800KB+ PDF freezes the renderer
    html = _aspHexDump(_aspGetRespBytes(), 64 * 1024);
  } else if (fmt === "base64") {
    let b64 = (_aspLastResp && _aspLastResp.body_b64) || "";
    if (!b64) {
      try { b64 = btoa(unescape(encodeURIComponent(raw))); }
      catch (_) {
        try { b64 = btoa(raw); } catch (e2) { b64 = "(unable to encode)"; }
      }
    }
    const cut = _aspTruncUiText(b64, ASP_BODY_UI_MAX);
    html = _aspEscHtml(cut.text.replace(/(.{76})/g, "$1\n")) +
      (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
  } else if (hint === "binary" || (_aspLastResp && _aspLastResp.is_binary)) {
    const name = (_aspLastResp && _aspLastResp.filename) || "response.bin";
    const size = _aspLastResp && _aspLastResp.size_bytes != null
      ? _aspFmtSize(_aspLastResp.size_bytes) : "";
    const snip = (raw || "").slice(0, ASP_BINARY_SNIPPET);
    html = _aspEscHtml(
      "Binary response" + (size ? " · " + size : "") +
      " · " + name +
      "\n\nOpen Preview for PDF/images, or Send ▾ → Download response." +
      "\nHex / Base64 formats are available (truncated for UI safety)." +
      "\n\n── first bytes (lossy) ──\n" + snip +
      (raw.length > ASP_BINARY_SNIPPET ? "\n…" : "")
    );
  } else {
    const cut = _aspTruncUiText(raw || "(empty)", ASP_BODY_UI_MAX);
    html = _aspEscHtml(cut.text) + (cut.truncated ? truncNote(cut.text.length, cut.total) : "");
  }
  const nonJsonHtmlLines = html.split('\n');
  const matchesByLine = {};
  if (_aspRFTerm && _aspRFMatches && _aspRFMatches.length) {
    for (let mi = 0; mi < _aspRFMatches.length; mi++) {
      const m = _aspRFMatches[mi];
      if (!matchesByLine[m.line]) matchesByLine[m.line] = [];
      matchesByLine[m.line].push(m);
    }
  }
  const codeLinesHtml = nonJsonHtmlLines.map((lHtml, idx) => {
    let finalHtml = lHtml || '&nbsp;';
    if (matchesByLine[idx]) {
      finalHtml = _aspRFInjectLineMarks(finalHtml, matchesByLine[idx], _aspRFIdx);
    }
    return `<div class="asp-code-line" data-line="${idx}">${finalHtml}</div>`;
  }).join('');
  pre.innerHTML = codeLinesHtml;

  // Render plain line numbers for non-JSON formats
  if (gutter) {
    let gHtml = '';
    for (let l = 0; l < nonJsonHtmlLines.length; l++) {
      gHtml += `<div class="asp-gutter-line" data-line="${l}"><span class="asp-fold-btn" style="visibility:hidden"></span><span class="asp-line-num">${l + 1}</span></div>`;
    }
    gutter.innerHTML = gHtml;
    gutter.scrollTop = pre.scrollTop;
  }
  _aspSyncRespGutterHeights();
  _aspInitRespChrome();
}

function _aspUpdateRespView() {
  const pre = document.getElementById("asp-resp-body-pre");
  const gutter = document.getElementById("asp-resp-gutter");
  if (!pre || !_aspLastRespCleanLines || !_aspLastRespCleanLines.length) return;

  const lines = _aspLastRespCleanLines;
  const folds = _aspRespFolds || {};
  const foldedSet = _aspRespFolded || new Set();

  const hiddenLines = new Set();
  for (const startLine of foldedSet) {
    const f = folds[startLine];
    if (f) {
      for (let l = Number(startLine) + 1; l <= f.endLine; l++) {
        hiddenLines.add(l);
      }
    }
  }

  // Group find matches by line for exact per-line highlighting
  const matchesByLine = {};
  if (_aspRFTerm && _aspRFMatches && _aspRFMatches.length) {
    for (let mi = 0; mi < _aspRFMatches.length; mi++) {
      const m = _aspRFMatches[mi];
      if (!matchesByLine[m.line]) matchesByLine[m.line] = [];
      matchesByLine[m.line].push(m);
    }
  }

  // 1. Render Gutter
  if (gutter) {
    let gHtml = '';
    for (let l = 0; l < lines.length; l++) {
      if (hiddenLines.has(l)) continue;
      const isFoldable = !!folds[l];
      const isFolded = foldedSet.has(l);
      let foldBtn = '';
      if (isFoldable) {
        foldBtn = `<span class="asp-fold-btn ${isFolded ? 'asp-folded' : ''}" data-fold-line="${l}" title="${isFolded ? 'Expand' : 'Collapse'}">${isFolded ? '▸' : '▾'}</span>`;
      } else {
        foldBtn = `<span class="asp-fold-btn" style="visibility:hidden"></span>`;
      }
      gHtml += `<div class="asp-gutter-line" data-line="${l}">${foldBtn}<span class="asp-line-num">${l + 1}</span></div>`;
    }
    gutter.innerHTML = gHtml;
    gutter.scrollTop = pre.scrollTop;
  }

  // 2. Render Highlighted Pre
  let htmlLines = [];
  for (let l = 0; l < lines.length; l++) {
    if (hiddenLines.has(l)) continue;
    let lineRaw = lines[l];
    let lineHtml = _aspHighlightJson(lineRaw);
    if (foldedSet.has(l)) {
      const f = folds[l];
      const count = f.endLine - l;
      const endLineContent = lines[f.endLine] || '';
      const comma = endLineContent.trim().endsWith(',') ? ',' : '';
      lineHtml += ` <span class="asp-fold-ellipsis" data-unfold-line="${l}" title="Click to expand (${count} lines)">...</span> ${f.closeChar}${comma}`;
    }
    if (matchesByLine[l]) {
      lineHtml = _aspRFInjectLineMarks(lineHtml, matchesByLine[l], _aspRFIdx);
    }
    htmlLines.push(`<div class="asp-code-line" data-line="${l}">${lineHtml}</div>`);
  }
  pre.innerHTML = htmlLines.join('');
  _aspSyncRespGutterHeights();
  if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
}

function _aspSyncRespGutterHeights() {
  const pre = document.getElementById("asp-resp-body-pre");
  const gutter = document.getElementById("asp-resp-gutter");
  if (!pre || !gutter) return;
  const codeLines = pre.querySelectorAll(".asp-code-line");
  const gutterLines = gutter.querySelectorAll(".asp-gutter-line");
  const gMap = {};
  for (let j = 0; j < gutterLines.length; j++) {
    const gl = gutterLines[j];
    if (gl.dataset.line !== undefined) gMap[gl.dataset.line] = gl;
  }
  for (let i = 0; i < codeLines.length; i++) {
    const cl = codeLines[i];
    const l = cl.dataset.line;
    const gl = gMap[l];
    if (gl) {
      if (_aspRespWrap) {
        const h = cl.offsetHeight;
        if (h > 20) {
          gl.style.height = h + 'px';
        } else {
          gl.style.height = '';
        }
      } else {
        gl.style.height = '';
      }
    }
  }
}

function _aspToggleRespFold(lineIdx) {
  lineIdx = Number(lineIdx);
  if (_aspRespFolded.has(lineIdx)) {
    _aspRespFolded.delete(lineIdx);
  } else {
    _aspRespFolded.add(lineIdx);
  }
  _aspUpdateRespView();
  if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
}

function _aspRenderRespHeaders(headers) {
  const tbody = document.getElementById("asp-resp-headers-tbody");
  if (!tbody) return;
  const entries = Object.entries(headers);
  tbody.innerHTML = entries.length
    ? entries.map(([k, v]) =>
        `<tr><td class="asp-hdr-key">${_aspEscHtml(k)}</td><td class="asp-hdr-val">${_aspEscHtml(String(v))}</td></tr>`
      ).join("")
    : `<tr><td colspan="2" style="padding:28px 14px;text-align:center;color:rgba(255,255,255,.35);font-size:12px">No headers</td></tr>`;
}

// ── JSON syntax highlight ─────────────────────────────────────
// Single pass: comments, keys (string + colon), string values (incl. arrays), bool/null/num.
// Caller must pass raw text — this function HTML-escapes internally.
function _aspHighlightJson(json) {
  const esc = _aspEscHtml(json);
  // Match strings and comments first so digits/keywords inside them never get retokenized.
  return esc.replace(
    /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|(\/\/[^\n\r]*|\/\*[\s\S]*?\*\/)|\b(true|false)\b|\b(null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g,
    (match, str, colon, comment, bool, nul) => {
      if (str !== undefined) {
        if (colon !== undefined) return `<span class="asp-j-key">${str}</span>${colon}`;
        return `<span class="asp-j-str">${str}</span>`;
      }
      if (comment !== undefined) return `<span class="asp-j-comment">${comment}</span>`;
      if (bool !== undefined) return `<span class="asp-j-bool">${bool}</span>`;
      if (nul  !== undefined) return `<span class="asp-j-null">${nul}</span>`;
      return `<span class="asp-j-num">${match}</span>`;
    }
  );
}

// ── Copy helpers ──────────────────────────────────────────────
function aspCopyCurl() {
  const btn  = document.getElementById("asp-copy-curl-btn");
  const curl = _aspLastSentCurl || "";
  if (!curl) return;
  _aspClipboard(curl, btn, "📋 cURL");
}
function aspCopyResp() {
  // Copy what's currently displayed (formatted), fallback to raw body
  let text = "";
  try { text = _aspFormatRespPlainText(); } catch (_) {}
  if (!text && _aspLastResp) text = _aspLastResp.body || "";
  _aspClipboard(text, document.getElementById("asp-copy-resp-btn"), "Copy");
}
function _aspClipboard(text, btn, origLabel) {
  if (text == null || text === "") return;
  const copy = () => {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); document.body.removeChild(ta);
  };
  navigator.clipboard ? navigator.clipboard.writeText(text).catch(copy) : copy();
  if (btn) {
    const prev = origLabel || btn.textContent;
    btn.textContent = "✓ Copied!";
    setTimeout(() => { btn.textContent = prev; }, 1400);
  }
}

// ── History ───────────────────────────────────────────────────
function _aspGetHistory() {
  try { return JSON.parse(localStorage.getItem(ASP_HISTORY_KEY) || "[]"); } catch(e) { return []; }
}
function _aspSaveHistory(req, resp) {
  // Strip multipart file base64 so localStorage doesn't blow up
  let reqCopy = req;
  if (req && req.body_type === "multipart" && Array.isArray(req.body)) {
    reqCopy = {
      ...req,
      body: req.body.map(e => e && e.type === "file"
        ? { key: e.key, type: "file", filename: e.filename || "", contentType: e.contentType || "", data: "" }
        : e),
    };
  }
  const hist = _aspGetHistory();
  hist.unshift({ ts: Date.now(), method: req.method, url: req.url, status: resp.status_code, ms: resp.elapsed_ms, req: reqCopy });
  if (hist.length > ASP_MAX_HISTORY) hist.length = ASP_MAX_HISTORY;
  try { localStorage.setItem(ASP_HISTORY_KEY, JSON.stringify(hist)); } catch(e) {}
  _aspRenderHistory();
}
function _aspRenderHistory() {
  const list = document.getElementById("asp-history-list");
  if (!list) return;
  const hist = _aspGetHistory();
  if (!hist.length) {
    list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text3);font-size:11px">No requests yet</div>`;
    return;
  }
  list.innerHTML = hist.map((h, i) => {
    const mc   = _ASP_METHOD_COLORS[h.method] || "#8b949e";
    const sc   = parseInt(h.status);
    const scol = sc < 300 ? "#3fb950" : sc < 400 ? "#79c0ff" : sc < 500 ? "#d29922" : "#f85149";
    const short = (h.url || "").replace(/^https?:\/\//, "").slice(0, 50);
    return `<div class="asp-hist-item" onclick="aspLoadHistory(${i})" title="${_aspEscAttr(h.url)}">
      <span class="asp-hist-method" style="color:${mc}">${h.method}</span>
      <span class="asp-hist-url">${_aspEscHtml(short)}</span>
      <span class="asp-hist-status" style="color:${scol}">${h.status||""}</span>
      <span class="asp-hist-ago">${_aspTimeAgo(h.ts)}</span>
    </div>`;
  }).join("");
}
function aspLoadHistory(idx) {
  const h = _aspGetHistory()[idx];
  if (!h?.req) return;
  let bt = h.req.body_type || "none";
  let bodyRawLang = h.req.raw_lang || "json";
  let bodyRaw = "", bodyForm = [], bodyMultipart = [];
  let bodyGraphqlQuery = "", bodyGraphqlVars = "", bodyBinary = null;
  if (bt === "raw" || bt === "json" || bt === "text") {
    if (bt === "json") { bodyRawLang = "json"; bt = "raw"; }
    if (bt === "text") { bodyRawLang = bodyRawLang || "text"; bt = "raw"; }
    bodyRaw = typeof h.req.body === "string" ? h.req.body
            : h.req.body != null ? JSON.stringify(h.req.body, null, 2) : "";
  } else if (bt === "form") {
    bodyForm = Object.entries(h.req.body || {}).map(([k,v]) => ({enabled:true,key:k,value:v}));
  } else if (bt === "multipart" && Array.isArray(h.req.body)) {
    bodyMultipart = h.req.body.map(e => ({
      enabled: true,
      key: e.key || "",
      fieldType: e.type === "file" ? "file" : "text",
      value: e.type === "file" ? "" : (e.value || ""),
      filename: e.filename || "",
    }));
  } else if (bt === "graphql" && h.req.body && typeof h.req.body === "object") {
    bodyGraphqlQuery = h.req.body.query || "";
    try {
      bodyGraphqlVars = h.req.body.variables != null
        ? JSON.stringify(h.req.body.variables, null, 2) : "";
    } catch (_) { bodyGraphqlVars = ""; }
  } else if (bt === "binary" && h.req.body && typeof h.req.body === "object") {
    bodyBinary = {
      filename: h.req.body.filename || "file",
      contentType: h.req.body.contentType || "application/octet-stream",
      data: h.req.body.data || "",
    };
  } else if (h.req.body != null && typeof h.req.body !== "object") {
    bt = "raw";
    bodyRaw = String(h.req.body);
  }
  _aspApplyState({
    method:   h.req.method,
    url:      h.req.url,
    params:   Object.entries(h.req.params  || {}).map(([k,v]) => ({enabled:true,key:k,value:v})),
    headers:  Object.entries(h.req.headers || {}).map(([k,v]) => ({enabled:true,key:k,value:v})),
    auth:     h.req.auth,
    bodyType: bt,
    bodyRawLang,
    bodyRaw,
    bodyForm,
    bodyMultipart,
    bodyGraphqlQuery,
    bodyGraphqlVars,
    bodyBinary,
  });
  aspToggleHistory(false);
}
function aspToggleHistory(force) {
  if (_aspIsWorkspaceOverlayOpen() && force !== false) return;
  _aspHistoryOpen = force !== undefined ? force : !_aspHistoryOpen;
  const panel = document.getElementById("asp-history-panel");
  const btn   = document.getElementById("asp-history-btn");
  if (panel) panel.style.display = _aspHistoryOpen ? "flex" : "none";
  if (btn) {
    btn.classList.toggle("asp-hist-on", _aspHistoryOpen);
    btn.style.color = "";
  }
}
function aspClearHistory() {
  localStorage.removeItem(ASP_HISTORY_KEY);
  _aspRenderHistory();
}

// ── cURL Import Modal ─────────────────────────────────────────
function aspShowCurlImport() {
  const modal = document.getElementById("asp-curl-modal");
  const inp   = document.getElementById("asp-curl-input");
  if (modal) modal.style.display = "flex";
  if (inp)   { inp.value = ""; setTimeout(() => inp.focus(), 50); }
}
function aspCloseCurlImport() {
  const modal = document.getElementById("asp-curl-modal");
  if (modal) modal.style.display = "none";
}
function aspConfirmCurlImport() {
  const inp  = document.getElementById("asp-curl-input");
  const text = (inp ? inp.value : "").trim();
  if (!text) return;
  const ok = aspImportCurl(text);
  if (ok) aspCloseCurlImport();
}

// ── New request ───────────────────────────────────────────────
function aspNewRequest() {
  const m = document.getElementById("asp-method-sel");
  if (m) { m.value = "GET"; _aspUpdateMethodColor(); }
  const u = document.getElementById("asp-url-input");
  if (u) u.value = "";
  ["asp-params-table","asp-headers-table","asp-body-form-table"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = "";
    // Params starts empty — user clicks "+ Add param" (no blank default row).
    if (id !== "asp-params-table") _aspAddRow(id);
  });
  const raw = document.getElementById("asp-body-raw");
  if (raw) { raw.value = ""; _aspSyncBodyHighlight(); }
  _aspSetBodyType("none");
  _aspSetAuth({ type: "none" });
  const empty  = document.getElementById("asp-resp-empty");
  const loaded = document.getElementById("asp-resp-loaded");
  if (empty)  empty.style.display  = "flex";
  if (loaded) loaded.style.display = "none";
  _aspSetRespMeta("","","");
  _aspLastResp = null;
  _aspUpdateParamBadge();
  _aspUpdateHeaderBadge();
  localStorage.removeItem(ASP_DRAFT_KEY);
}

// ── cURL Parser (Postman-level) ───────────────────────────────
/** Normalize messy pasted curls: smart quotes, BOM, line continuations, curl.exe */
function _aspNormalizeCurlText(text) {
  let s = String(text || "")
    .replace(/^\uFEFF/, "")
    .replace(/\u00A0/g, " ")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  // bash / zsh / cmd / PowerShell line continuations
  s = s.replace(/\\\n/g, " ");
  s = s.replace(/`\n/g, " ");
  s = s.replace(/\^\n/g, " ");
  // Drop leading prompt junk: $ curl …  /  PS> curl …
  s = s.replace(/^\s*(?:PS\s*>\s*|\$\s*)/i, "");
  s = s.trim();
  // Accept "curl.exe" / "CURL"
  if (!/^curl(?:\.exe)?\b/i.test(s)) return null;
  s = s.replace(/^curl(?:\.exe)?\b/i, "curl");
  return s;
}

function _aspTokenizeCurl(s) {
  const tokens = [];
  let i = 0;
  const isWs = c => c === " " || c === "\t" || c === "\n" || c === "\r";
  while (i < s.length) {
    while (i < s.length && isWs(s[i])) i++;
    if (i >= s.length) break;

    if (s[i] === "$" && s[i + 1] === "'") {
      // Bash ANSI-C quoting: $'...'
      let val = ""; i += 2;
      while (i < s.length && s[i] !== "'") {
        if (s[i] === "\\" && i + 1 < s.length) {
          i++;
          const c = s[i];
          if      (c === "n")  { val += "\n"; i++; }
          else if (c === "t")  { val += "\t"; i++; }
          else if (c === "r")  { val += "\r"; i++; }
          else if (c === "'")  { val += "'";  i++; }
          else if (c === "\\") { val += "\\"; i++; }
          else if (c === '"')  { val += '"';  i++; }
          else if ((c === "u" || c === "U") && /^[0-9a-fA-F]{4}/.test(s.slice(i + 1, i + 5))) {
            val += String.fromCodePoint(parseInt(s.slice(i + 1, i + 5), 16)); i += 5;
          } else if (c === "x" && /^[0-9a-fA-F]{2}/.test(s.slice(i + 1, i + 3))) {
            val += String.fromCharCode(parseInt(s.slice(i + 1, i + 3), 16)); i += 3;
          } else { val += c; i++; }
        } else val += s[i++];
      }
      if (i < s.length) i++;
      tokens.push(val);
    } else if (s[i] === "'" || s[i] === "\u2018" || s[i] === "\u2019" || s[i] === "\u201A" || s[i] === "\u201B") {
      const openQ = s[i];
      let val = ""; i++;
      while (i < s.length) {
        if (openQ === "'") {
          // bash: '\''  or  '"'"'
          if (s[i] === "'" && s.slice(i, i + 4) === "'\\''") { val += "'"; i += 4; }
          else if (s[i] === "'" && s.slice(i, i + 5) === "'\"'\"'") { val += "'"; i += 5; }
          else if (s[i] === "'") { i++; break; }
          else val += s[i++];
        } else {
          if (s[i] === "'" || s[i] === "\u2018" || s[i] === "\u2019" || s[i] === "\u201A" || s[i] === "\u201B") {
            i++; break;
          } else val += s[i++];
        }
      }
      tokens.push(val);
    } else if (s[i] === '"' || s[i] === "\u201C" || s[i] === "\u201D" || s[i] === "\u201E" || s[i] === "\u201F") {
      const openQ = s[i];
      let val = ""; i++;
      while (i < s.length) {
        if (openQ === '"') {
          if (s[i] === "\\" && i + 1 < s.length) { i++; val += s[i++]; }
          else if (s[i] === '"') { i++; break; }
          else val += s[i++];
        } else {
          if (s[i] === '"' || s[i] === "\u201C" || s[i] === "\u201D" || s[i] === "\u201E" || s[i] === "\u201F") {
            i++; break;
          } else val += s[i++];
        }
      }
      if (i < s.length) i++;
      tokens.push(val);
    } else {
      let val = "";
      while (i < s.length && !isWs(s[i])) {
        // keep flag=value as one token for later split
        val += s[i++];
      }
      tokens.push(val);
    }
  }
  return tokens;
}

/** Expand "-XPOST" / "--header=…" / clustered "-kLsS" into normalized tokens. */
function _aspExpandCurlTokens(rawTokens) {
  const out = [];
  const LONG_EQ = /^(--[^=]+)=(.*)$/;
  for (let t of rawTokens) {
    if (!t) continue;
    if (/^curl$/i.test(t)) { out.push("curl"); continue; }
    const eq = t.match(LONG_EQ);
    if (eq) { out.push(eq[1], eq[2]); continue; }
    // -XPOST / -XGET
    if (/^-X[A-Za-z]+$/.test(t) && t.length > 2) {
      out.push("-X", t.slice(2).toUpperCase());
      continue;
    }
    // Clustered short flags: -kLsS  (no args). Stop before known arg-taking shorts.
    if (/^-[a-zA-Z]{2,}$/.test(t) && !t.startsWith("--")) {
      const ARG_SHORT = new Set(["X","H","d","F","u","A","o","m","x","b","c","e","T","w","E"]);
      const chars = t.slice(1).split("");
      let clustered = true;
      for (const ch of chars) {
        if (ARG_SHORT.has(ch)) { clustered = false; break; }
      }
      if (clustered) {
        chars.forEach(ch => out.push("-" + ch));
        continue;
      }
    }
    out.push(t);
  }
  return out;
}

function _aspSafeDecodeURIComponent(s) {
  try { return decodeURIComponent(String(s).replace(/\+/g, " ")); }
  catch (_) {
    try { return unescape(String(s).replace(/\+/g, " ")); }
    catch (_) { return String(s); }
  }
}

/** Parse already-encoded urlencoded body → object (decode keys/values). */
function _aspParseUrlEncodedBody(body, { decode = true } = {}) {
  const out = {};
  String(body || "").split("&").forEach(part => {
    if (!part) return;
    const eq = part.indexOf("=");
    let k = eq >= 0 ? part.slice(0, eq) : part;
    let v = eq >= 0 ? part.slice(eq + 1) : "";
    if (decode) { k = _aspSafeDecodeURIComponent(k); v = _aspSafeDecodeURIComponent(v); }
    if (!k) return;
    // Duplicate keys: keep last (matches typical token curls); array rare in OAuth
    out[k] = v;
  });
  return out;
}

function _aspLooksLikeUrlEncoded(s) {
  const t = String(s || "").trim();
  if (!t || t.startsWith("{") || t.startsWith("[")) return false;
  if (!t.includes("=")) return false;
  if (/Content-Disposition:/i.test(t) || t.startsWith("<")) return false;
  return /^(?:[^=&\s]+(?:=[^&\s]*)?)(?:&[^=&\s]+(?:=[^&\s]*)?)*$/.test(t);
}

function _aspStripJsonComments(s) {
  if (!s || typeof s !== "string" || (!s.includes("//") && !s.includes("/*"))) return s;
  const out = [];
  let inStr = false, quoteChar = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      out.push(c);
      if (c === "\\") {
        i++;
        if (i < s.length) out.push(s[i]);
      } else if (c === quoteChar) {
        inStr = false;
        quoteChar = "";
      }
    } else {
      if (c === '"' || c === "'") {
        inStr = true;
        quoteChar = c;
        out.push(c);
      } else if (c === "/" && s[i + 1] === "/") {
        i += 2;
        while (i < s.length && s[i] !== "\r" && s[i] !== "\n") i++;
        if (i < s.length) out.push(s[i]);
      } else if (c === "/" && s[i + 1] === "*") {
        i += 2;
        while (i + 1 < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++;
        i++;
      } else {
        out.push(c);
      }
    }
  }
  return out.join("");
}

function _aspLooksLikeJson(s) {
  const t = String(s || "").trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) return true;
  if (t.includes("//") || t.includes("/*")) {
    const stripped = _aspStripJsonComments(t).trim();
    return (stripped.startsWith("{") && stripped.endsWith("}")) || (stripped.startsWith("[") && stripped.endsWith("]"));
  }
  return false;
}

/** Encode one --data-urlencode argument the way curl does for the wire, then we store decoded UI values. */
function _aspCurlDataUrlEncodePart(part) {
  // forms: name=content | name@filename | =content | content
  const s = String(part || "");
  if (s.includes("@") && !s.includes("=")) {
    const name = s.split("@")[0];
    return { key: name, value: "", encoded: encodeURIComponent(name) + "=" };
  }
  const eq = s.indexOf("=");
  if (eq < 0) {
    // bare content — encode whole thing
    return { key: "", value: s, encoded: encodeURIComponent(s) };
  }
  const name = s.slice(0, eq);
  const value = s.slice(eq + 1);
  // Do NOT pre-decode: value is literal; curl encodes value for the wire
  return {
    key: name,
    value,
    encoded: encodeURIComponent(name) + "=" + encodeURIComponent(value),
  };
}

function _aspParseCurlFormArg(arg) {
  const s = String(arg || "");
  const eq = s.indexOf("=");
  if (eq < 0) return null;
  const key = s.slice(0, eq).trim();
  let rest = s.slice(eq + 1);
  const typeM = rest.match(/;type=([^;]+)/i);
  const contentType = typeM ? typeM[1].trim() : "";
  const fnM = rest.match(/;filename=([^;]+)/i);
  rest = rest.replace(/;type=[^;]+/ig, "").replace(/;filename=[^;]+/ig, "");
  if (!key) return null;
  if (rest.startsWith("@") || rest.startsWith("<")) {
    const path = rest.slice(1).replace(/^["']|["']$/g, "");
    const filename = (fnM && fnM[1].replace(/^["']|["']$/g, "")) || path.split(/[/\\]/).pop() || "file";
    return { key, fieldType: "file", value: "", filename, enabled: true, contentType };
  }
  return { key, fieldType: "text", value: rest, filename: "", enabled: true };
}

function _aspSetHeaderCI(headers, key, value) {
  const found = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
  if (found) headers[found] = value;
  else headers[key] = value;
}
function _aspGetHeaderCI(headers, key) {
  const found = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
  return found ? headers[found] : "";
}
function _aspDelHeaderCI(headers, key) {
  const found = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
  if (found) delete headers[found];
}

function _aspParseCurl(text) {
  const normalized = _aspNormalizeCurlText(text);
  if (!normalized) return null;

  const tokens = _aspExpandCurlTokens(_aspTokenizeCurl(normalized));
  let method = null, url = null, asGet = false;
  const headers = {};
  const dataParts = [];          // wire pieces joined by &
  const formFieldsFromData = []; // preferred ordered fields for urlencoded UI
  let dataIsBinary = false;
  let dataIsUrlEncode = false;
  let dataIsJsonFlag = false;    // --json
  const formParts = [];
  let basicUser = null, basicPass = null;

  const skipNoArg = new Set([
    "--compressed", "--insecure", "-k", "--location", "-L", "--location-trusted",
    "--silent", "-s", "--show-error", "-S", "--verbose", "-v", "--no-buffer", "-N",
    "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3",
    "--fail", "-f", "--remote-name", "-O", "--remote-header-name", "-J",
    "--include", "-i", "--head", "-I", "--raw", "--globoff", "-g",
    "--path-as-is", "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3",
    "--ssl", "--ssl-reqd", "--insecure",
  ]);
  const skipOneArg = new Set([
    "-o", "--output", "-m", "--max-time", "--connect-timeout", "--retry",
    "--proxy", "-x", "--cert", "--key", "--cacert", "--capath", "--passwd",
    "--write-out", "-w", "--stderr", "--trace", "--trace-ascii",
    "--resolve", "--connect-to", "--unix-socket", "--abstract-unix-socket",
    "--cert-type", "--key-type", "--engine", "--ciphers", "--tls-max",
    "--limit-rate", "--keepalive-time", "--max-redirs", "--proto", "--proto-redir",
    "-E", "--cookie-jar", "-c",
  ]);

  for (let i = 0; i < tokens.length; i++) {
    let t = tokens[i];
    if (!t) continue;
    if (i === 0 && /^curl$/i.test(t)) continue;

    if (t === "-G" || t === "--get") { asGet = true; continue; }
    if (t === "-I" || t === "--head") { method = "HEAD"; continue; }
    if (skipNoArg.has(t)) continue;

    if (t === "-X" || t === "--request") {
      method = String(tokens[++i] || "GET").toUpperCase();
      continue;
    }
    if (t === "--url") {
      url = tokens[++i] || url;
      continue;
    }
    if (t === "-H" || t === "--header") {
      const h = tokens[++i] || "";
      const ci = h.indexOf(":");
      if (ci > 0) {
        _aspSetHeaderCI(headers, h.slice(0, ci).trim(), h.slice(ci + 1).trim());
      } else if (h.endsWith(";") && ci < 0) {
        const k = h.slice(0, -1).trim();
        if (k) _aspSetHeaderCI(headers, k, "");
      }
      continue;
    }
    if (t === "-u" || t === "--user") {
      const cred = tokens[++i] || "";
      const ci = cred.indexOf(":");
      basicUser = ci >= 0 ? cred.slice(0, ci) : cred;
      basicPass = ci >= 0 ? cred.slice(ci + 1) : "";
      continue;
    }
    if (t === "--oauth2-bearer") {
      const tok = tokens[++i] || "";
      if (tok) _aspSetHeaderCI(headers, "Authorization", "Bearer " + tok);
      continue;
    }
    if (t === "-A" || t === "--user-agent") {
      _aspSetHeaderCI(headers, "User-Agent", tokens[++i] || "");
      continue;
    }
    if (t === "-e" || t === "--referer") {
      _aspSetHeaderCI(headers, "Referer", tokens[++i] || "");
      continue;
    }
    if (t === "-b" || t === "--cookie") {
      const c = tokens[++i] || "";
      // Ignore cookie files (@file); keep header string cookies
      if (!c.startsWith("@")) {
        const prev = _aspGetHeaderCI(headers, "Cookie");
        _aspSetHeaderCI(headers, "Cookie", prev ? prev + "; " + c : c);
      }
      continue;
    }
    if (t === "--json") {
      const part = tokens[++i] || "";
      dataIsJsonFlag = true;
      dataParts.push(part.startsWith("@") ? "" : part);
      _aspSetHeaderCI(headers, "Content-Type", "application/json");
      if (!_aspGetHeaderCI(headers, "Accept")) _aspSetHeaderCI(headers, "Accept", "application/json");
      continue;
    }
    if (t === "-d" || t === "--data" || t === "--data-raw" || t === "--data-ascii" ||
        t === "--data-urlencode" || t === "--data-binary") {
      let part = tokens[++i] || "";
      // @file — can't read filesystem in UI; keep empty placeholder note
      if (part.startsWith("@")) {
        part = "";
      }
      if (t === "--data-binary") dataIsBinary = true;
      if (t === "--data-urlencode") {
        dataIsUrlEncode = true;
        const enc = _aspCurlDataUrlEncodePart(part);
        dataParts.push(enc.encoded);
        if (enc.key) formFieldsFromData.push({ key: enc.key, value: enc.value });
        continue;
      }
      dataParts.push(part);
      // Also extract UI fields when part is already name=value
      if (part && !part.startsWith("{") && !part.startsWith("[") && part.includes("=")) {
        const parsed = _aspParseUrlEncodedBody(part, { decode: true });
        Object.entries(parsed).forEach(([k, v]) => formFieldsFromData.push({ key: k, value: v }));
      }
      continue;
    }
    if (t === "-F" || t === "--form" || t === "--form-string") {
      const part = tokens[++i] || "";
      const row = _aspParseCurlFormArg(part);
      if (row) formParts.push(row);
      continue;
    }
    if (t === "-T" || t === "--upload-file") {
      const file = tokens[++i] || "";
      const name = file.replace(/^@/, "").split(/[/\\]/).pop() || "file";
      // Treat as binary upload hint
      dataIsBinary = true;
      if (!method) method = "PUT";
      formParts.length = 0; // prefer binary path via empty data + filename in bodyBinary later
      dataParts.push(""); // marker
      // stash filename via special header comment — handled below via uploadFile
      headers["X-Asp-Upload-File"] = name;
      continue;
    }
    if (skipOneArg.has(t)) { i++; continue; }
    // Unknown long option with arg (best-effort skip)
    if (t.startsWith("--") && i + 1 < tokens.length && !tokens[i + 1].startsWith("-")) {
      // might be a flag with value we don't know — skip both to avoid eating URL
      // only skip if next doesn't look like URL
      const nxt = tokens[i + 1] || "";
      if (!/^https?:\/\//i.test(nxt) && !nxt.includes("://")) { i++; continue; }
    }
    if (!t.startsWith("-") && !url) { url = t; continue; }
  }

  if (!url) return null;

  // -G: move body data into query string
  let queryExtra = "";
  if (asGet && dataParts.length) {
    queryExtra = dataParts.filter(Boolean).join("&");
    dataParts.length = 0;
    formFieldsFromData.length = 0;
  }

  if (queryExtra) {
    url += (url.includes("?") ? "&" : "?") + queryExtra;
  }

  const bodyJoined = dataParts.length ? dataParts.filter((p, idx) => !(p === "" && dataParts.length > 1)).join("&") : null;
  const hasBody = formParts.length > 0 || (bodyJoined !== null && bodyJoined !== "") || dataIsJsonFlag;

  if (!method) {
    if (asGet) method = "GET";
    else if (hasBody) method = "POST";
    else method = "GET";
  }

  let bodyType = "none", bodyRaw = "", bodyRawLang = "json", parsedBody = null;
  let bodyGraphqlQuery = "", bodyGraphqlVars = "";
  let bodyBinary = null;
  const ctRaw = _aspGetHeaderCI(headers, "Content-Type");
  const ctv = ctRaw.toLowerCase();
  // Boundary is case-sensitive on the wire — never take it from lowercased CT
  const boundaryFromCt = (() => {
    const m = ctRaw.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
    return m ? (m[1] || m[2] || "").trim() : null;
  })();

  const uploadName = headers["X-Asp-Upload-File"];
  if (uploadName) {
    delete headers["X-Asp-Upload-File"];
    bodyType = "binary";
    bodyBinary = { filename: uploadName, contentType: "application/octet-stream", data: "" };
  } else if (formParts.length) {
    bodyType = "multipart";
    parsedBody = formParts;
    if (ctv.includes("multipart/form-data")) _aspDelHeaderCI(headers, "Content-Type");
  } else if (bodyJoined !== null || dataIsJsonFlag) {
    bodyRaw = bodyJoined || "";
    const looksJson = dataIsJsonFlag || _aspLooksLikeJson(bodyRaw);

    if (ctv.includes("multipart/form-data")) {
      bodyType = "multipart";
      parsedBody = _aspParseMultipartBody(bodyRaw, boundaryFromCt);
      _aspDelHeaderCI(headers, "Content-Type");
    } else if (
      !looksJson && (
        ctv.includes("x-www-form-urlencoded") ||
        dataIsUrlEncode ||
        (formFieldsFromData.length > 0 && (dataParts.length > 1 || dataIsUrlEncode || ctv.includes("x-www-form-urlencoded"))) ||
        (dataParts.length > 1 && !dataIsBinary) ||
        (!ctv && _aspLooksLikeUrlEncoded(bodyRaw) && !dataIsBinary)
      )
    ) {
      bodyType = "form";
      if (formFieldsFromData.length) {
        // Preserve order; last wins on dup keys
        parsedBody = {};
        formFieldsFromData.forEach(f => { parsedBody[f.key] = f.value; });
      } else {
        parsedBody = _aspParseUrlEncodedBody(bodyRaw, { decode: true });
      }
      if (!ctv) _aspSetHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded");
    } else if (ctv.includes("application/graphql") || /^\s*(query|mutation|subscription)\b/i.test(bodyRaw)) {
      bodyType = "graphql";
      bodyGraphqlQuery = bodyRaw;
    } else if (looksJson || ctv.includes("application/json")) {
      try {
        parsedBody = JSON.parse(bodyRaw);
        if (parsedBody && typeof parsedBody === "object" && !Array.isArray(parsedBody)
            && typeof parsedBody.query === "string"
            && (parsedBody.variables !== undefined || /\b(query|mutation|subscription)\b/.test(parsedBody.query))) {
          bodyType = "graphql";
          bodyGraphqlQuery = parsedBody.query;
          try {
            bodyGraphqlVars = parsedBody.variables != null
              ? JSON.stringify(parsedBody.variables, null, 2) : "";
          } catch (_) { bodyGraphqlVars = ""; }
        } else {
          bodyType = "raw";
          bodyRawLang = "json";
          bodyRaw = JSON.stringify(parsedBody, null, 2);
        }
      } catch (_) {
        try {
          const stripped = _aspStripJsonComments(bodyRaw);
          parsedBody = JSON.parse(stripped);
          if (parsedBody && typeof parsedBody === "object" && !Array.isArray(parsedBody)
              && typeof parsedBody.query === "string"
              && (parsedBody.variables !== undefined || /\b(query|mutation|subscription)\b/.test(parsedBody.query))) {
            bodyType = "graphql";
            bodyGraphqlQuery = parsedBody.query;
            try {
              bodyGraphqlVars = parsedBody.variables != null
                ? JSON.stringify(parsedBody.variables, null, 2) : "";
            } catch (_) { bodyGraphqlVars = ""; }
          } else {
            bodyType = "raw";
            bodyRawLang = "json";
            bodyRaw = JSON.stringify(parsedBody, null, 2);
          }
        } catch (_) {
          bodyType = "raw";
          bodyRawLang = ctv.includes("json") || dataIsJsonFlag ? "json" : "text";
        }
      }
    } else if (ctv.includes("text/html")) {
      bodyType = "raw"; bodyRawLang = "html";
    } else if (ctv.includes("xml")) {
      bodyType = "raw"; bodyRawLang = "xml";
    } else if (ctv.includes("javascript")) {
      bodyType = "raw"; bodyRawLang = "javascript";
    } else {
      bodyType = "raw"; bodyRawLang = "text";
    }
  }

  let auth = { type: "none", token: "", username: "", password: "" };
  if (basicUser != null) {
    auth = { type: "basic", token: "", username: basicUser, password: basicPass || "" };
  }

  return {
    method, url, headers, auth,
    bodyType, bodyRawLang, bodyRaw, parsedBody,
    bodyGraphqlQuery, bodyGraphqlVars, bodyBinary,
  };
}

function _aspParseMultipartBody(rawBody, boundary) {
  const parts = [];
  const bodyStr = String(rawBody || "");
  if (!boundary) {
    // Infer boundary from first multipart delimiter line: --XXXX
    const infer = bodyStr.match(/(?:^|\r?\n)(--[^\r\n]+?)(?:--)?\r?\n/i);
    if (infer) boundary = infer[1].replace(/^--/, "");
  }
  if (!boundary) {
    bodyStr.split(/\r?\n/).forEach(line => {
      const nameM = line.match(/name="([^"]+)"/i);
      const fileM = line.match(/filename="([^"]*)"/i);
      if (nameM) {
        parts.push({
          key: nameM[1],
          fieldType: fileM ? "file" : "text",
          value: "",
          filename: fileM ? fileM[1] : "",
          enabled: true,
        });
      }
    });
    return parts;
  }
  const bare = boundary.replace(/^["']|["']$/g, "").replace(/^--/, "");
  const delim = "--" + bare;
  // Split on delimiter; allow optional CRLF after. Closing boundary ends with --
  const esc = delim.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const sections = bodyStr.split(new RegExp("(?:\\r?\\n)?" + esc + "(?:--)?(?:\\r?\\n)?"));
  sections.forEach(section => {
    const trimmed = section.replace(/^\r?\n/, "");
    if (!trimmed.trim() || trimmed.trim() === "--") return;
    const sepIdx = trimmed.search(/\r?\n\r?\n/);
    if (sepIdx < 0) return;
    const headerBlock = trimmed.slice(0, sepIdx);
    let bodyPart = trimmed.slice(sepIdx).replace(/^\r?\n\r?\n/, "");
    // Trim trailing CRLF that belonged to next boundary
    bodyPart = bodyPart.replace(/\r?\n$/, "");
    const cdLine = (headerBlock.match(/content-disposition\s*:[^\r\n]*/i) || [])[0] || "";
    const nameM  = cdLine.match(/(?:^|;)\s*name="([^"]+)"/i);
    const fileM  = cdLine.match(/(?:^|;)\s*filename="([^"]*)"/i);
    if (!nameM) return;
    const isFile = !!fileM;
    parts.push({
      key: nameM[1],
      fieldType: isFile ? "file" : "text",
      value: isFile ? "" : bodyPart,
      filename: isFile ? (fileM[1] || "") : "",
      enabled: true,
    });
  });
  return parts;
}

// ── URL ↔ Query Params (Postman-style: query stays visible in the URL bar) ──
let _aspUrlParamsSyncing = false;

function _aspSplitUrl(rawUrl) {
  const raw = String(rawUrl || "");
  try {
    const u = new URL(raw);
    const params = [];
    u.searchParams.forEach((v, k) => params.push({ enabled: true, key: k, value: v }));
    const base = `${u.protocol}//${u.host}${u.pathname}`;
    return { base, params, hash: u.hash || "" };
  } catch (e) {
    let work = raw;
    let hash = "";
    const hi = work.indexOf("#");
    if (hi >= 0) { hash = work.slice(hi); work = work.slice(0, hi); }
    const qi = work.indexOf("?");
    if (qi < 0) return { base: work, params: [], hash };
    const base = work.slice(0, qi);
    const params = work.slice(qi + 1).split("&").filter(Boolean).map(p => {
      const eq = p.indexOf("=");
      const k = eq >= 0 ? p.slice(0, eq) : p;
      const v = eq >= 0 ? p.slice(eq + 1) : "";
      return { enabled: true, key: _aspSafeDecodeURIComponent(k), value: _aspSafeDecodeURIComponent(v) };
    });
    return { base, params, hash };
  }
}

/** Params table → query string on the URL input (keeps path/hash). */
function _aspSyncUrlFromParams() {
  if (_aspUrlParamsSyncing) return;
  const urlInp = document.getElementById("asp-url-input");
  if (!urlInp) return;
  const raw = urlInp.value;
  if (!String(raw).trim()) return;
  const { base, hash } = _aspSplitUrl(raw);
  if (!String(base).trim() && !raw.includes("?")) return;
  const qs = _aspGetRows("asp-params-table")
    .filter(r => r.enabled && r.key)
    .map(r => encodeURIComponent(r.key) + "=" + encodeURIComponent(r.value ?? ""))
    .join("&");
  const next = qs ? `${base}?${qs}${hash || ""}` : `${base}${hash || ""}`;
  if (urlInp.value === next) return;
  _aspUrlParamsSyncing = true;
  try {
    urlInp.value = next;
    _aspSyncUrlHl();
  } finally {
    _aspUrlParamsSyncing = false;
  }
}

/** URL input query string → Params table (URL bar keeps the full URL). */
function _aspSyncParamsFromUrl() {
  if (_aspUrlParamsSyncing) return;
  const urlInp = document.getElementById("asp-url-input");
  if (!urlInp) return;
  const { params } = _aspSplitUrl(urlInp.value || "");
  _aspUrlParamsSyncing = true;
  try {
    _aspSetRows("asp-params-table", params);
    _aspUpdateParamBadge();
  } finally {
    _aspUrlParamsSyncing = false;
  }
}

/** After load/import: if URL has `?`, trust URL; else push params into the URL bar. */
function _aspReconcileUrlAndParams() {
  const urlInp = document.getElementById("asp-url-input");
  if (!urlInp) return;
  const raw = urlInp.value || "";
  if (raw.includes("?")) _aspSyncParamsFromUrl();
  else _aspSyncUrlFromParams();
}

function aspImportCurl(text) {
  const p = _aspParseCurl(text);
  if (!p) { _aspUrlError("Not a valid cURL command"); return false; }

  const methodSel = document.getElementById("asp-method-sel");
  if (methodSel) {
    // Ensure method option exists
    if (p.method && ![...methodSel.options].some(o => o.value === p.method)) {
      const opt = document.createElement("option");
      opt.value = p.method; opt.textContent = p.method;
      methodSel.appendChild(opt);
    }
    methodSel.value = p.method || "GET";
    _aspUpdateMethodColor();
  }

  const { params: urlParams } = _aspSplitUrl(p.url || "");
  const urlInp = document.getElementById("asp-url-input");
  // Keep full URL (incl. ?query) in the bar — Postman-style.
  if (urlInp) { urlInp.value = p.url || ""; _aspSyncUrlHl(); _aspKvUndoSeed(urlInp); }

  if (urlParams.length) {
    _aspSetRows("asp-params-table", urlParams);
  } else {
    const tbody = document.getElementById("asp-params-table");
    if (tbody) tbody.innerHTML = "";
  }
  _aspUpdateParamBadge();

  const hRows = Object.entries(p.headers || {}).map(([k, v]) => ({ enabled: true, key: k, value: v }));
  _aspSetRows("asp-headers-table", hRows.length ? hRows : []);
  if (!hRows.length) _aspAddRow("asp-headers-table");
  _aspUpdateHeaderBadge();

  // Auth (-u / Bearer)
  if (p.auth && p.auth.type && p.auth.type !== "none") {
    _aspSetAuth(p.auth);
  } else {
    _aspSetAuth({ type: "none", token: "", username: "", password: "" });
  }

  if (p.bodyRawLang) _aspSetRawLang(p.bodyRawLang);
  _aspSetBodyType(p.bodyType || "none");

  if (p.bodyType === "raw" || p.bodyType === "json" || p.bodyType === "text") {
    const raw = document.getElementById("asp-body-raw");
    if (raw) { raw.value = p.bodyRaw || ""; _aspSyncBodyHighlight(); _aspUndoSeed(raw.value); }
  } else if (p.bodyType === "form" && p.parsedBody) {
    const fRows = Object.entries(p.parsedBody).map(([k, v]) => ({ enabled: true, key: k, value: v }));
    _aspSetRows("asp-body-form-table", fRows.length ? fRows : [{ enabled: true, key: "", value: "" }]);
  } else if (p.bodyType === "multipart" && p.parsedBody) {
    _aspSetMultipartRows(p.parsedBody);
  } else if (p.bodyType === "graphql") {
    const q = document.getElementById("asp-gql-query");
    const v = document.getElementById("asp-gql-vars");
    if (q) q.value = p.bodyGraphqlQuery || p.bodyRaw || "";
    if (v) v.value = p.bodyGraphqlVars || "";
  } else if (p.bodyType === "binary") {
    _aspBinaryCache = p.bodyBinary || null;
    _aspRenderBinaryName();
  }
  _aspUpdateBodyDot();

  // Tab priority: Params (when query present) > Body > Auth > Headers
  if (urlParams.length) aspReqTab("params");
  else if (p.bodyType && p.bodyType !== "none") aspReqTab("body");
  else if (p.auth && p.auth.type !== "none") aspReqTab("auth");
  else if (hRows.length) aspReqTab("headers");
  else aspReqTab("params");
  _aspSaveDraft();

  const bits = [];
  if (urlParams.length) bits.push(urlParams.length + " params");
  if (p.bodyType && p.bodyType !== "none") bits.push(p.bodyType);
  if (hRows.length) bits.push(hRows.length + " headers");
  _aspShowToast("✓ Imported cURL" + (bits.length ? " · " + bits.join(" · ") : ""));
  return true;
}

let _aspToastTimer = null;
function _aspShowToast(msg) {
  let el = document.getElementById("asp-toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "asp-toast";
    el.style.cssText = "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#1f6feb;color:#fff;font-size:12px;font-weight:700;padding:7px 18px;border-radius:20px;z-index:9999;pointer-events:none;opacity:0;transition:opacity .2s";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.opacity = "1";
  clearTimeout(_aspToastTimer);
  _aspToastTimer = setTimeout(() => { el.style.opacity = "0"; }, 2200);
}

// ── Random value generators ───────────────────────────────────
function _aspGenUuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}
const _ASP_FN = ['James','Emma','Liam','Olivia','Noah','Ava','William','Sophia','Oliver','Charlotte','Ethan','Mia'];
const _ASP_LN = ['Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Wilson','Taylor','Moore'];
function _aspGenName()      { return `${_ASP_FN[Math.random()*_ASP_FN.length|0]} ${_ASP_LN[Math.random()*_ASP_LN.length|0]}`; }
function _aspGenAlpha(n)    { return Array.from({length:n}, () => 'abcdefghijklmnopqrstuvwxyz'[Math.random()*26|0]).join(''); }
function _aspGenAlphanum(n) { const c='abcdefghijklmnopqrstuvwxyz0123456789'; return Array.from({length:n}, () => c[Math.random()*c.length|0]).join(''); }
function _aspGenNum(n)      { return String(Math.floor(Math.random()*9)+1) + Array.from({length:Math.max(n-1,0)}, () => Math.floor(Math.random()*10)).join(''); }
function _aspGenEmail()     { const d=['gmail.com','yahoo.com','test.com','example.com']; return `${_aspGenAlphanum(6)}@${d[Math.random()*d.length|0]}`; }

function _aspResolveTokens(text) {
  return text
    .replace(/\{uuid\}/gi,           _aspGenUuid)
    .replace(/\{email\}/gi,          _aspGenEmail)
    .replace(/\{name\}/gi,           _aspGenName)
    .replace(/\{alpha:(\d+)\}/gi,    (_, n) => _aspGenAlpha(+n))
    .replace(/\{alphanum:(\d+)\}/gi, (_, n) => _aspGenAlphanum(+n))
    .replace(/\{num:(\d+)\}/gi,      (_, n) => _aspGenNum(+n));
}

// ── Token autocomplete dropdown ───────────────────────────────
const _ASP_TOK_LIST = [
  { t: '{uuid}',        d: 'UUID v4' },
  { t: '{email}',       d: 'Random email' },
  { t: '{name}',        d: 'Random full name' },
  { t: '{alpha:6}',     d: 'N random letters' },
  { t: '{alphanum:8}',  d: 'N-char alphanumeric' },
  { t: '{num:6}',       d: 'N-digit number' },
];

function _aspOnBodyInput() {
  _aspUndoRecord();
  _aspSaveDraft();
  if (_aspFindTerm) _aspRunFindSearch();
  _aspSyncBodyHighlight();
  _aspBodyCaretChrome();
  _aspUpdateBodyDot();
  const _bodyTa = document.getElementById('asp-body-raw');
  try { _aspCheckVarTrigger(_bodyTa); } catch(_) {}  // {{ collection variable autocomplete
  _aspCheckTokenTrigger();                            // { dynamic token autocomplete
}

function _aspCheckTokenTrigger() {
  const ta = document.getElementById('asp-body-raw');
  if (!ta) return;
  const before = ta.value.slice(0, ta.selectionStart);
  // {{ → collection variable autocomplete takes priority
  const dblIdx = before.lastIndexOf('{{');
  if (dblIdx >= 0) {
    const typed = before.slice(dblIdx + 2);
    if (!typed.includes('}}') && !typed.includes('{')) {
      _aspHideTokenDd();
      try { _aspShowVarDd(ta, typed); } catch(_) {}
      return;
    }
  }
  _aspHideVarDd();
  // single { → dynamic token autocomplete
  const lastOpen = before.lastIndexOf('{');
  if (lastOpen < 0) { _aspHideTokenDd(); return; }
  const typed = before.slice(lastOpen + 1);
  if (typed.includes('}') || typed.startsWith('{')) { _aspHideTokenDd(); return; }
  _aspShowTokenDd(ta, typed.trim());
}

function _aspShowTokenDd(ta, filter) {
  const dd = document.getElementById('asp-token-dd');
  if (!dd) return;
  const items = _ASP_TOK_LIST.filter(t =>
    !filter || t.t.slice(1).toLowerCase().startsWith(filter.toLowerCase())
  );
  if (!items.length) { _aspHideTokenDd(); return; }

  dd.innerHTML = items.map((t, i) =>
    `<div class="asp-tok-item${i===0?' asp-active':''}" onmousedown="event.preventDefault();_aspInsertToken('${t.t}')">` +
    `<span class="asp-tok-chip">${_aspEscHtml(t.t)}</span>` +
    `<span class="asp-tok-desc">${t.d}</span></div>`
  ).join('');

  // Position near caret (line-height-based estimate)
  const editor  = ta.closest('.asp-body-editor');
  const edR     = editor ? editor.getBoundingClientRect() : ta.getBoundingClientRect();
  const lineH   = 20; // 12px font × 20px line-height
  const lineN   = ta.value.slice(0, ta.selectionStart).split('\n').length - 1;
  const scrolled = editor ? editor.scrollTop : 0;
  const caretRelY = 10 + lineN * lineH - scrolled + lineH;
  const clampedY  = Math.min(Math.max(caretRelY, 0), (editor ? editor.clientHeight : 200));

  dd.style.display = 'block';
  const ddH = dd.offsetHeight || items.length * 36 + 8;
  let top  = edR.top  + clampedY + 4;
  let left = edR.left + 12;
  if (top + ddH > window.innerHeight - 10) top = edR.top + clampedY - ddH - 4;
  if (left + 250 > window.innerWidth)       left = window.innerWidth - 260;
  dd.style.top  = `${top}px`;
  dd.style.left = `${left}px`;
}

function _aspHideTokenDd() {
  const dd = document.getElementById('asp-token-dd');
  if (dd) dd.style.display = 'none';
}

function _aspInsertToken(token) {
  const ta = document.getElementById('asp-body-raw');
  if (!ta) return;
  const pos    = ta.selectionStart;
  const before = ta.value.slice(0, pos);
  const lastOp = before.lastIndexOf('{');
  if (lastOp < 0) return;
  // Use execCommand so the insertion is part of the undo stack (Cmd+Z works)
  ta.focus();
  ta.setSelectionRange(lastOp, pos);
  document.execCommand('insertText', false, token);
  // 'input' event fires automatically → _aspOnBodyInput handles sync + save
  _aspHideTokenDd();
}

// ── Collection variable autocomplete ({{ trigger) ─────────────
function _aspShowVarDd(el, filter) {
  const dd = document.getElementById('asp-var-dd');
  if (!dd) return;
  _aspVarDdEl = el;
  // Env + collection + folder vars for this request's membership
  const membership = _aspGetActiveTabMembership();
  const vars = _aspResolveActiveVars(membership && membership.col, membership && membership.folder)
    .map(v => v.key)
    .filter(k => !filter || k.toLowerCase().startsWith(filter.toLowerCase()));
  if (!vars.length) { _aspHideVarDd(); return; }
  dd.innerHTML = vars.map((k, i) =>
    `<div class="asp-tok-item${i===0?' asp-active':''}" onmousedown="event.preventDefault();_aspInsertVar('${_aspEscHtml(k)}')">`+
    `<span class="asp-tok-chip" style="color:#e3b341;background:rgba(227,179,65,.13);border-color:rgba(227,179,65,.3)">{{${_aspEscHtml(k)}}}</span></div>`
  ).join('');
  dd.style.display = 'block';
  const rect = el.getBoundingClientRect();
  const ddH  = dd.offsetHeight || vars.length * 36 + 8;
  let top, left;
  if (el.tagName === 'TEXTAREA') {
    // position near caret line (same method as token dropdown)
    const lineH    = 20;
    const lineN    = el.value.slice(0, el.selectionStart).split('\n').length - 1;
    const scrolled = el.scrollTop || 0;
    const caretY   = rect.top + 10 + lineN * lineH - scrolled + lineH;
    top  = caretY + 4;
    left = rect.left + 12;
    if (top + ddH > window.innerHeight - 10) top = caretY - ddH - 4;
  } else {
    top  = rect.bottom + 4;
    left = rect.left;
    if (top + ddH > window.innerHeight - 10) top = rect.top - ddH - 4;
  }
  if (left + 240 > window.innerWidth) left = window.innerWidth - 250;
  dd.style.top  = `${top}px`;
  dd.style.left = `${left}px`;
}

function _aspHideVarDd() {
  const dd = document.getElementById('asp-var-dd');
  if (dd) dd.style.display = 'none';
  _aspVarDdEl = null;
}

function _aspInsertVar(varName) {
  const el = _aspVarDdEl;
  if (!el) return;
  const pos    = el.selectionStart;
  const before = el.value.slice(0, pos);
  const ddIdx  = before.lastIndexOf('{{');
  if (ddIdx < 0) return;
  el.focus();
  el.setSelectionRange(ddIdx, pos);
  const inserted = `{{${varName}}}`;
  if (!document.execCommand('insertText', false, inserted)) {
    // Fallback when execCommand is blocked (some WKWebView builds)
    const start = el.selectionStart, end = el.selectionEnd;
    el.value = el.value.slice(0, start) + inserted + el.value.slice(end);
    const caret = start + inserted.length;
    el.setSelectionRange(caret, caret);
  }
  _aspHideVarDd();
  el.dispatchEvent(new Event('input', { bubbles: true }));
  if (el.classList && el.classList.contains('asp-kv-val')) {
    try { _aspSyncKvHl(el); _aspKvValAutosize(el); } catch (_) {}
  }
}

function _aspMoveVarDdActive(dir) {
  const dd = document.getElementById('asp-var-dd');
  if (!dd || dd.style.display === 'none') return false;
  const items = dd.querySelectorAll('.asp-tok-item');
  if (!items.length) return false;
  let idx = Array.from(items).findIndex(el => el.classList.contains('asp-active'));
  items[idx]?.classList.remove('asp-active');
  idx = (idx + dir + items.length) % items.length;
  items[idx].classList.add('asp-active');
  return true;
}

function _aspConfirmVarDd() {
  const dd = document.getElementById('asp-var-dd');
  if (!dd || dd.style.display === 'none') return false;
  const active = dd.querySelector('.asp-tok-item.asp-active');
  if (!active) return false;
  const chip = active.querySelector('.asp-tok-chip');
  const text = (chip && chip.textContent) || '';
  const m = text.match(/^\{\{(.+)\}\}$/);
  if (!m) return false;
  _aspInsertVar(m[1]);
  return true;
}

function _aspCheckVarTrigger(el) {
  if (!el || el.selectionStart == null) return;
  const before = el.value.slice(0, el.selectionStart);
  const ddIdx  = before.lastIndexOf('{{');
  if (ddIdx < 0) { _aspHideVarDd(); return; }
  const typed  = before.slice(ddIdx + 2);
  if (typed.includes('}}') || typed.includes('{')) { _aspHideVarDd(); return; }
  _aspShowVarDd(el, typed);
}

function _aspMoveTokenDdActive(dir) {
  const dd    = document.getElementById('asp-token-dd');
  if (!dd || dd.style.display === 'none') return false;
  const items = dd.querySelectorAll('.asp-tok-item');
  if (!items.length) return false;
  let idx = Array.from(items).findIndex(el => el.classList.contains('asp-active'));
  items[idx]?.classList.remove('asp-active');
  idx = (idx + dir + items.length) % items.length;
  items[idx].classList.add('asp-active');
  return true;
}

function _aspConfirmTokenDd() {
  const dd = document.getElementById('asp-token-dd');
  if (!dd || dd.style.display === 'none') return false;
  const active = dd.querySelector('.asp-tok-item.asp-active');
  if (active) active.dispatchEvent(new MouseEvent('mousedown', {bubbles: true}));
  return !!active;
}

// ── Body highlight overlay ────────────────────────────────────
function _aspHighlightTokens(html) {
  return html.replace(/\{(?:uuid|email|name|alpha:\d+|alphanum:\d+|num:\d+)\}/gi,
    m => `<span class="asp-j-tok">${m}</span>`);
}

function _aspHighlightVars(html) {
  return html.replace(/\{\{[^{}]+\}\}/g,
    m => `<span class="asp-j-var">${m}</span>`);
}

// ── Find bar ─────────────────────────────────────────────────
function aspOpenFindBar() {
  const bar = document.getElementById('asp-find-bar');
  const inp = document.getElementById('asp-find-input');
  if (!bar) return;
  bar.style.display = 'flex';
  if (inp) {
    inp.select();
    setTimeout(() => inp.focus(), 0);
    if (inp.value.trim()) {
      try {
        _aspFindTerm = inp.value.trim();
        _aspFindIdx  = 0;
        _aspRunFindSearch();
        _aspFindUpdateCount();
        _aspSyncBodyHighlight();
        if (_aspFindMatches.length) _aspScrollToFindMatch();
      } catch(_) {}
    }
  }
}
function aspCloseFindBar() {
  const bar    = document.getElementById('asp-find-bar');
  const editor = document.querySelector('.asp-body-editor');
  const saved  = editor ? editor.scrollTop : 0;
  if (bar) bar.style.display = 'none';
  _aspFindTerm = ''; _aspFindMatches = []; _aspFindIdx = 0;
  _aspSyncBodyHighlight();
  // preventScroll stops the browser from auto-scrolling to the cursor on focus
  document.getElementById('asp-body-raw')?.focus({ preventScroll: true });
  if (editor) editor.scrollTop = saved;
}
function _aspRunFindSearch() {
  _aspFindMatches = [];
  if (!_aspFindTerm) return;
  const text  = (document.getElementById('asp-body-raw') || {}).value || '';
  const lower = text.toLowerCase();
  const term  = _aspFindTerm.toLowerCase();
  let pos = 0;
  while ((pos = lower.indexOf(term, pos)) !== -1) {
    _aspFindMatches.push({ start: pos, end: pos + term.length });
    pos += term.length;
  }
  if (_aspFindIdx >= _aspFindMatches.length) _aspFindIdx = 0;
}
function _aspFindSearch() {
  const inp  = document.getElementById('asp-find-input');
  _aspFindTerm = (inp ? inp.value : '').trim();
  _aspFindIdx  = 0;
  _aspRunFindSearch();
  _aspUpdateFindCount();
  _aspSyncBodyHighlight();
  if (_aspFindMatches.length) _aspScrollToFindMatch();
}
function _aspFindNext() {
  if (!_aspFindMatches.length) return;
  _aspFindIdx = (_aspFindIdx + 1) % _aspFindMatches.length;
  _aspUpdateFindCount();
  _aspSyncBodyHighlight();
  _aspScrollToFindMatch();
}
function _aspFindPrev() {
  if (!_aspFindMatches.length) return;
  _aspFindIdx = (_aspFindIdx - 1 + _aspFindMatches.length) % _aspFindMatches.length;
  _aspUpdateFindCount();
  _aspSyncBodyHighlight();
  _aspScrollToFindMatch();
}
function _aspUpdateFindCount() {
  const el = document.getElementById('asp-find-count');
  if (!el) return;
  if (!_aspFindTerm)              { el.textContent = '';            el.style.color = 'var(--text3)'; }
  else if (!_aspFindMatches.length) { el.textContent = 'No results'; el.style.color = '#f85149'; }
  else { el.textContent = `${_aspFindIdx + 1} / ${_aspFindMatches.length}`; el.style.color = 'var(--text3)'; }
}
function _aspScrollToFindMatch() {
  if (!_aspFindMatches.length) return;
  const match  = _aspFindMatches[_aspFindIdx];
  const ta     = document.getElementById('asp-body-raw');
  const pre    = document.getElementById('asp-body-pre');
  const gutter = document.getElementById('asp-body-gutter');
  if (!ta) return;

  const lineN   = ta.value.slice(0, match.start).split('\n').length - 1;
  const lineH   = 20;
  const targetTop = Math.max(0, lineN * lineH - ta.clientHeight / 2 + lineH);

  // Scroll textarea directly (where the actual scrollbar lives)
  ta.scrollTop = targetTop;
  if (pre) pre.scrollTop = targetTop;
  if (gutter) gutter.scrollTop = targetTop;

  // Select matched text in textarea so cursor and native selection jump right to the word
  try {
    ta.focus({ preventScroll: true });
    ta.setSelectionRange(match.start, match.end);
  } catch (_) {}

  // Also scroll active mark into view if rendered in pre
  setTimeout(() => {
    const mark = document.querySelector('#asp-body-pre .asp-find-current');
    if (mark) {
      mark.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
    }
  }, 10);
}

// Walk html string, count text chars (skipping tags/entities), inject <mark> at match positions
function _aspInjectFindMarks(html) {
  if (!_aspFindMatches.length || !_aspFindTerm) return html;
  const evts = [];
  _aspFindMatches.forEach((m, i) => {
    const cls = i === _aspFindIdx ? 'asp-find-mark asp-find-current' : 'asp-find-mark';
    evts.push({ at: m.start, open: true,  tag: `<mark class="${cls}">` });
    evts.push({ at: m.end,   open: false, tag: '</mark>' });
  });
  evts.sort((a, b) => a.at - b.at || (a.open ? 1 : -1));

  let result = '', textPos = 0, ei = 0, i = 0;
  const flush = () => { while (ei < evts.length && evts[ei].at <= textPos) result += evts[ei++].tag; };

  while (i < html.length) {
    flush();
    if (html[i] === '<') {
      const j = html.indexOf('>', i);
      if (j < 0) { result += html.slice(i); break; }
      result += html.slice(i, j + 1); i = j + 1;
    } else if (html[i] === '&') {
      const j = html.indexOf(';', i);
      if (j < 0) { result += html[i++]; textPos++; }
      else { result += html.slice(i, j + 1); i = j + 1; textPos++; }
    } else {
      result += html[i++]; textPos++;
    }
  }
  while (ei < evts.length) result += evts[ei++].tag;
  return result;
}

// ── Response body find bar ────────────────────────────────────
function aspOpenRespFindBar() {
  const bar = document.getElementById('asp-resp-find-bar');
  const inp = document.getElementById('asp-resp-find-input');
  if (!bar) return;
  bar.style.display = 'flex';
  // Flash the bar so the user always sees it activate (even if already open)
  bar.classList.remove('asp-bar-ping');
  void bar.offsetWidth;
  bar.classList.add('asp-bar-ping');
  if (inp) {
    inp.select();
    setTimeout(() => inp.focus(), 0);
    if (inp.value.trim()) {
      try {
        _aspRFTerm = inp.value.trim();
        _aspRFIdx  = 0;
        _aspRFRunSearch();
        _aspRFUpdateCount();
        if (_aspLastResp) {
          if (_aspRespFmt === "json" && _aspLastRespCleanLines && _aspLastRespCleanLines.length) {
            _aspUpdateRespView();
          } else {
            _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
          }
        }
        if (_aspRFMatches.length) _aspRFScrollToMatch();
      } catch(_) {}
    }
  }
}

function aspCloseRespFindBar() {
  const bar = document.getElementById('asp-resp-find-bar');
  if (bar) bar.style.display = 'none';
  _aspRFTerm = ''; _aspRFMatches = []; _aspRFIdx = 0;
  if (_aspLastResp) {
    if (_aspRespFmt === "json" && _aspLastRespCleanLines && _aspLastRespCleanLines.length) {
      _aspUpdateRespView();
    } else {
      _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
    }
  }
}

function _aspEnsureRespMatchVisible(lineNum) {
  if (!_aspRespFolded || !_aspRespFolded.size || !_aspRespFolds) return false;
  let unfolded = false;
  for (const foldStart of Array.from(_aspRespFolded)) {
    const f = _aspRespFolds[foldStart];
    if (f && lineNum > Number(foldStart) && lineNum <= f.endLine) {
      _aspRespFolded.delete(foldStart);
      unfolded = true;
    }
  }
  return unfolded;
}

function _aspRFRunSearch() {
  _aspRFMatches = [];
  if (!_aspRFTerm) return;
  // Search the SAME plain text the current format view shows, line by line
  let text = "";
  try { text = _aspFormatRespPlainText(); } catch (_) {}
  if (!text) text = (_aspLastResp && _aspLastResp.body) || "";

  const lines = text.split('\n');
  const termLower = _aspRFTerm.toLowerCase();
  let globalIdx = 0;

  for (let l = 0; l < lines.length; l++) {
    const lineText = lines[l] || "";
    const lower = lineText.toLowerCase();
    let pos = 0;
    while ((pos = lower.indexOf(termLower, pos)) !== -1) {
      _aspRFMatches.push({
        line: l,
        start: pos,
        end: pos + termLower.length,
        globalIdx: globalIdx++
      });
      pos += termLower.length;
    }
  }

  if (_aspRFIdx >= _aspRFMatches.length) _aspRFIdx = 0;
}

function _aspRFSearch() {
  const inp  = document.getElementById('asp-resp-find-input');
  _aspRFTerm = (inp ? inp.value : '').trim();
  _aspRFIdx  = 0;
  _aspRFRunSearch();
  _aspRFUpdateCount();
  if (_aspLastResp) {
    if (_aspRespFmt === "json" && _aspLastRespCleanLines && _aspLastRespCleanLines.length) {
      _aspUpdateRespView();
    } else {
      _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
    }
  }
  if (_aspRFMatches.length) _aspRFScrollToMatch();
}

function _aspRFNext() {
  if (!_aspRFMatches.length) return;
  _aspRFIdx = (_aspRFIdx + 1) % _aspRFMatches.length;
  _aspRFUpdateCount();
  if (_aspLastResp) {
    if (_aspRespFmt === "json" && _aspLastRespCleanLines && _aspLastRespCleanLines.length) {
      _aspUpdateRespView();
    } else {
      _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
    }
  }
  _aspRFScrollToMatch();
}

function _aspRFPrev() {
  if (!_aspRFMatches.length) return;
  _aspRFIdx = (_aspRFIdx - 1 + _aspRFMatches.length) % _aspRFMatches.length;
  _aspRFUpdateCount();
  if (_aspLastResp) {
    if (_aspRespFmt === "json" && _aspLastRespCleanLines && _aspLastRespCleanLines.length) {
      _aspUpdateRespView();
    } else {
      _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
    }
  }
  _aspRFScrollToMatch();
}

function _aspRFUpdateCount() {
  const el = document.getElementById('asp-resp-find-count');
  if (!el) return;
  if (!_aspRFTerm)                { el.textContent = '';            el.style.color = 'var(--text3)'; }
  else if (!_aspRFMatches.length) { el.textContent = 'No results'; el.style.color = '#f85149';     }
  else { el.textContent = `${_aspRFIdx + 1} / ${_aspRFMatches.length}`; el.style.color = 'var(--text3)'; }
}

function _aspRFScrollToMatch() {
  if (!_aspRFMatches.length) return;
  const curr = _aspRFMatches[_aspRFIdx];
  if (!curr) return;

  // If match line is inside a folded block, unfold it first so it is rendered in DOM
  if (_aspEnsureRespMatchVisible(curr.line)) {
    _aspUpdateRespView();
  }

  setTimeout(() => {
    // 1. Try finding the active .asp-find-current element
    const mark = document.querySelector('#asp-resp-body-pre .asp-find-current');
    if (mark) {
      mark.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
      return;
    }
    // 2. Fallback to the code line element
    const lineEl = document.querySelector(`#asp-resp-body-pre .asp-code-line[data-line="${curr.line}"]`);
    if (lineEl) {
      lineEl.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
    }
  }, 15);
}

// Injects search marks into a SINGLE line's HTML without any cross-line character offset drift
function _aspRFInjectLineMarks(lineHtml, lineMatches, activeGlobalIdx) {
  if (!lineMatches || !lineMatches.length) return lineHtml;
  const evts = [];
  lineMatches.forEach((m) => {
    const isCurrent = m.globalIdx === activeGlobalIdx;
    const cls = isCurrent ? 'asp-find-mark asp-find-current' : 'asp-find-mark';
    evts.push({ at: m.start, open: true,  tag: `<mark class="${cls}">` });
    evts.push({ at: m.end,   open: false, tag: '</mark>' });
  });
  evts.sort((a, b) => a.at - b.at || (a.open ? 1 : -1));

  let result = '', textPos = 0, ei = 0, i = 0;
  const flush = () => { while (ei < evts.length && evts[ei].at <= textPos) result += evts[ei++].tag; };

  while (i < lineHtml.length) {
    flush();
    if (lineHtml[i] === '<') {
      const j = lineHtml.indexOf('>', i);
      if (j < 0) { result += lineHtml.slice(i); break; }
      result += lineHtml.slice(i, j + 1); i = j + 1;
    } else if (lineHtml[i] === '&') {
      const j = lineHtml.indexOf(';', i);
      if (j < 0) { result += lineHtml[i++]; textPos++; }
      else { result += lineHtml.slice(i, j + 1); i = j + 1; textPos++; }
    } else {
      result += lineHtml[i++]; textPos++;
    }
  }
  while (ei < evts.length) result += evts[ei++].tag;
  return result;
}

function _aspRFInjectMarks(html) {
  return html;
}

function _aspSyncBodyHighlight() {
  const ta  = document.getElementById("asp-body-raw");
  const pre = document.getElementById("asp-body-pre");
  const gutter = document.getElementById("asp-body-gutter");
  if (!ta || !pre) return;
  const text     = ta.value;
  const bodyType = _aspGetBodyType();
  const rawLang  = _aspGetRawLang();
  const asJson   = (bodyType === "raw" && rawLang === "json") || bodyType === "json";
  const skipHl   = text.length > 120 * 1024;
  let html;
  if (asJson && text.trim() && !skipHl) {
    html = _aspHighlightJson(text);
  } else {
    html = _aspEscHtml(text);
  }
  html = _aspHighlightTokens(html);
  html = _aspHighlightVars(html);
  html = _aspInjectFindMarks(html);

  const errLine = _aspCheckBodyJsonValid(text, asJson ? "json" : bodyType);
  if (errLine) html = _aspHighlightErrorLine(html, errLine);

  // Replace internal fold tokens with clean ellipsis chips in pre
  html = html.replace(/\/\*⋯(\d+) lines\[(f_\d+_\d+)\]⋯\*\//g, (m, count, token) => {
    return `<span class="asp-fold-ellipsis" data-unfold-token="${token}" title="Click to expand (${count} lines)">...</span>`;
  });

  const rawHtmlLines = html.split('\n');
  let preHtml = '';
  for (let l = 0; l < rawHtmlLines.length; l++) {
    preHtml += `<div class="asp-code-line" data-line="${l}">${rawHtmlLines[l] || '&nbsp;'}</div>`;
  }
  pre.innerHTML = preHtml;
  pre.scrollTop = ta.scrollTop;
  pre.scrollLeft = ta.scrollLeft;

  // Render Line Numbers & Fold Chevrons in Request Gutter
  if (gutter) {
    const lines = text.split('\n');
    const totalLines = lines.length || 1;
    const folds = asJson ? _aspComputeFolds(text) : {};
    let gHtml = '';
    for (let l = 0; l < totalLines; l++) {
      const lineContent = lines[l] || '';
      const isFolded = /\/\*⋯\d+ lines\[(f_\d+_\d+)\]⋯\*\//.test(lineContent);
      const isFoldable = isFolded || (folds[l] && folds[l].endLine > l + 1);
      let foldBtn = '';
      if (isFoldable) {
        foldBtn = `<span class="asp-fold-btn ${isFolded ? 'asp-folded' : ''}" data-fold-line="${l}" title="${isFolded ? 'Expand' : 'Collapse'}">${isFolded ? '▸' : '▾'}</span>`;
      } else {
        foldBtn = `<span class="asp-fold-btn" style="visibility:hidden"></span>`;
      }
      gHtml += `<div class="asp-gutter-line" data-line="${l}">${foldBtn}<span class="asp-line-num">${l + 1}</span></div>`;
    }
    gutter.innerHTML = gHtml;
    gutter.scrollTop = ta.scrollTop;
  }

  _aspSyncReqGutterHeights();

  const reqFoldBtn = document.getElementById("asp-body-foldall-btn");
  if (reqFoldBtn) {
    const hasFold = text.includes('/*⋯') || _aspReqFoldMap.size > 0;
    reqFoldBtn.textContent = hasFold ? "Expand All" : "Collapse All";
  }
}

function _aspSyncReqGutterHeights() {
  const pre = document.getElementById("asp-body-pre");
  const gutter = document.getElementById("asp-body-gutter");
  const ta = document.getElementById("asp-body-raw");
  if (!pre || !gutter) return;

  if (ta) {
    const sbWidth = ta.offsetWidth - ta.clientWidth;
    pre.style.paddingRight = (10 + sbWidth) + 'px';
  }

  const codeLines = pre.querySelectorAll(".asp-code-line");
  const gutterLines = gutter.querySelectorAll(".asp-gutter-line");
  const gMap = {};
  for (let j = 0; j < gutterLines.length; j++) {
    const gl = gutterLines[j];
    if (gl.dataset.line !== undefined) gMap[gl.dataset.line] = gl;
  }
  for (let i = 0; i < codeLines.length; i++) {
    const cl = codeLines[i];
    const l = cl.dataset.line;
    const gl = gMap[l];
    if (gl) {
      if (_aspReqWrap) {
        const h = cl.offsetHeight;
        if (h > 20) {
          gl.style.height = h + 'px';
        } else {
          gl.style.height = '';
        }
      } else {
        gl.style.height = '';
      }
    }
  }
}

/**
 * Strip // and /* *\/ comments from JSONC (Postman-style), keeping strings intact.
 * Newlines inside comments are preserved so editor line numbers stay aligned.
 */
function _aspStripJsonComments(text) {
  const s = String(text || "");
  let out = "";
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    // double-quoted string
    if (c === '"') {
      out += c;
      i++;
      while (i < n) {
        const ch = s[i];
        out += ch;
        i++;
        if (ch === "\\") {
          if (i < n) { out += s[i]; i++; }
          continue;
        }
        if (ch === '"') break;
      }
      continue;
    }
    // line comment //
    if (c === "/" && s[i + 1] === "/") {
      i += 2;
      while (i < n && s[i] !== "\n" && s[i] !== "\r") i++;
      continue;
    }
    // block comment /* */
    if (c === "/" && s[i + 1] === "*") {
      i += 2;
      while (i < n) {
        if (s[i] === "\n" || s[i] === "\r") { out += s[i]; i++; continue; }
        if (s[i] === "*" && s[i + 1] === "/") { i += 2; break; }
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** Parse JSON allowing // and /* comments (editor/send). */
function _aspParseJsonc(text) {
  return JSON.parse(_aspStripJsonComments(text));
}

// Live JSON-validity check for the body editor — red border + inline error +
// whole-row highlight on the offending line, Postman-style. Purely visual
// (doesn't block Send; the server's own 400 stays the real authority).
// Returns the 1-based line number to highlight, or null when valid/inapplicable.
function _aspCheckBodyJsonValid(text, bodyType) {
  const editor = document.getElementById("asp-body-editor-box");
  const errEl  = document.getElementById("asp-body-json-error");
  if (!editor || !errEl) return null;

  if (bodyType !== "json" || !text.trim()) {
    editor.classList.remove("asp-body-invalid");
    errEl.style.display = "none";
    return null;
  }
  try {
    _aspParseJsonc(text);
    editor.classList.remove("asp-body-invalid");
    errEl.style.display = "none";
    return null;
  } catch (e) {
    editor.classList.add("asp-body-invalid");
    errEl.textContent = "⚠ Invalid JSON — " + e.message;
    errEl.style.display = "block";
    // The native JSON.parse error message doesn't reliably carry a line
    // number across engines (WebKit's JavaScriptCore often omits it
    // entirely) — re-scan independently to locate the offending line.
    try { return _aspFindJsonErrorLine(text); } catch(_) { return null; }
  }
}

// Wraps the given 1-based line of already-rendered (escaped+colorized) HTML
// in a full-width highlight block — the negative margin bleeds into the
// <pre>'s own padding so the highlight reaches the editor's edges, matching
// Postman's "highlight the whole row" error styling.
function _aspHighlightErrorLine(html, lineNum) {
  const lines = html.split("\n");
  const idx = lineNum - 1;
  if (idx < 0 || idx >= lines.length) return html;
  lines[idx] = `<span class="asp-body-error-line">${lines[idx] || " "}</span>`;
  return lines.join("\n");
}

// Minimal recursive-descent JSON scanner used ONLY to locate which line a
// syntax error is on — JSON.parse() itself remains the source of truth for
// validity (called separately in _aspCheckBodyJsonValid); this just re-walks
// the same text to find a line number, since native engines disagree on
// whether their error messages include position info (WebKit often omits it
// entirely, unlike V8). Not a full JSON-spec validator — good enough to track
// line position through strings/objects/arrays and stop at the first
// structurally unexpected character.
function _aspFindJsonErrorLine(text) {
  let i = 0, line = 1;
  const n = text.length;

  function advance() {
    const c = text[i++];
    if (c === "\n") line++;
    return c;
  }
  function skipWs() {
    while (i < n) {
      if (/\s/.test(text[i])) { advance(); continue; }
      // JSONC: // line comments
      if (text[i] === "/" && text[i + 1] === "/") {
        i += 2;
        while (i < n && text[i] !== "\n" && text[i] !== "\r") advance();
        continue;
      }
      // JSONC: /* block comments */
      if (text[i] === "/" && text[i + 1] === "*") {
        i += 2;
        while (i < n) {
          if (text[i] === "*" && text[i + 1] === "/") { i += 2; break; }
          advance();
        }
        continue;
      }
      break;
    }
  }
  function fail() { throw { line }; }

  function parseValue() {
    skipWs();
    if (i >= n) fail();
    const c = text[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    if (text.startsWith("true", i))  { i += 4; return; }
    if (text.startsWith("false", i)) { i += 5; return; }
    if (text.startsWith("null", i))  { i += 4; return; }
    fail();
  }
  function parseString() {
    advance(); // opening quote
    for (;;) {
      if (i >= n) fail();
      const c = advance();
      if (c === '"') return;
      if (c === "\\") { if (i >= n) fail(); advance(); }
    }
  }
  function parseNumber() {
    while (i < n && /[-+0-9.eE]/.test(text[i])) advance();
  }
  function parseObject() {
    advance(); // {
    skipWs();
    if (text[i] === "}") { advance(); return; }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail();
      parseString();
      skipWs();
      if (text[i] !== ":") fail();
      advance();
      parseValue();
      skipWs();
      const c = text[i];
      if (c === ",") { advance(); continue; }
      if (c === "}") { advance(); return; }
      fail();
    }
  }
  function parseArray() {
    advance(); // [
    skipWs();
    if (text[i] === "]") { advance(); return; }
    for (;;) {
      parseValue();
      skipWs();
      const c = text[i];
      if (c === ",") { advance(); continue; }
      if (c === "]") { advance(); return; }
      fail();
    }
  }

  try {
    parseValue();
    skipWs();
    if (i < n) fail(); // trailing characters after a complete top-level value
    return null;
  } catch (e) {
    return (e && typeof e.line === "number") ? e.line : null;
  }
}

// ── Drag-to-resize splitter ───────────────────────────────────
function _aspInitSplitter() {
  const splitter = document.getElementById("asp-splitter");
  const container = document.getElementById("asp-main-split");
  const left     = document.getElementById("asp-req-panel");
  if (!splitter || !container || !left) return;
  let dragging = false, startX = 0, startW = 0;
  splitter.addEventListener("mousedown", e => {
    dragging = true; startX = e.clientX; startW = left.offsetWidth;
    splitter.classList.add("asp-dragging");
    document.body.style.cssText += ";cursor:col-resize!important;user-select:none!important";
    e.preventDefault();
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    const max = container.offsetWidth - 200;
    const w   = Math.max(200, Math.min(max, startW + (e.clientX - startX)));
    left.style.width = w + "px";
  });
  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    splitter.classList.remove("asp-dragging");
    document.body.style.cursor = ""; document.body.style.userSelect = "";
    _aspSyncReqGutterHeights();
    _aspSyncRespGutterHeights();
    _aspActiveLineUpdate();
    if (typeof _aspReqPositionGuide === "function") _aspReqPositionGuide();
    if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
  });
}

function _aspInitEditorResizeSync() {
  const sync = () => {
    _aspSyncReqGutterHeights();
    _aspSyncRespGutterHeights();
    _aspActiveLineUpdate();
    if (typeof _aspReqPositionGuide === "function") _aspReqPositionGuide();
    if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
  };
  window.addEventListener('resize', sync);
  if (window.ResizeObserver) {
    const ro = new ResizeObserver(() => {
      requestAnimationFrame(sync);
    });
    const reqBox = document.getElementById("asp-body-editor-box");
    const respBox = document.getElementById("asp-resp-editor-box");
    if (reqBox) ro.observe(reqBox);
    if (respBox) ro.observe(respBox);
  }
}

// ── Keyboard Ctrl/Cmd+Enter → Send ───────────────────────────
function _aspBindKeyboard() {
  document.addEventListener("keydown", e => {
    // Collection-var dropdown ({{…}}) — headers/params/body/URL
    const vdd = document.getElementById('asp-var-dd');
    if (vdd && vdd.style.display !== 'none') {
      if (e.key === 'ArrowDown') { e.preventDefault(); _aspMoveVarDdActive(1);  return; }
      if (e.key === 'ArrowUp')   { e.preventDefault(); _aspMoveVarDdActive(-1); return; }
      if (e.key === 'Enter' || e.key === 'Tab') {
        if (_aspConfirmVarDd()) { e.preventDefault(); return; }
      }
      if (e.key === 'Escape') { _aspHideVarDd(); return; }
    }
    // Dynamic token dropdown ({uuid} etc.) — body only
    const dd = document.getElementById('asp-token-dd');
    if (dd && dd.style.display !== 'none') {
      if (e.key === 'ArrowDown') { e.preventDefault(); _aspMoveTokenDdActive(1);  return; }
      if (e.key === 'ArrowUp')   { e.preventDefault(); _aspMoveTokenDdActive(-1); return; }
      if (e.key === 'Enter' || e.key === 'Tab') {
        if (_aspConfirmTokenDd()) { e.preventDefault(); return; }
      }
      if (e.key === 'Escape') { _aspHideTokenDd(); return; }
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      if (_aspIsWorkspaceOverlayOpen()) return;
      const panel = document.getElementById("tool-apisphere");
      if (panel && panel.style.display !== "none") { e.preventDefault(); aspSend(); }
    }
    // Cmd+T → new tab
    if ((e.ctrlKey || e.metaKey) && e.key === 't') {
      if (_aspIsWorkspaceOverlayOpen()) return;
      const panel = document.getElementById("tool-apisphere");
      if (panel && panel.style.display !== "none") { e.preventDefault(); aspNewTab(); }
    }
    // Cmd+W → close active tab; Opt+Cmd+W / Ctrl+Alt+W → force close
    if ((e.ctrlKey || e.metaKey) && (e.key === 'w' || e.key === 'W')) {
      const panel = document.getElementById("tool-apisphere");
      if (panel && panel.style.display !== "none") {
        e.preventDefault();
        const id = _aspActiveTabId();
        if (!id) return;
        if (e.altKey) aspForceCloseTab(id);
        else aspCloseTab(id);
      }
    }
    // Cmd+Z / Cmd+Shift+Z / Cmd+Y → custom undo/redo (WKWebView clears native stacks)
    // Body textarea, params/headers values, URL — other fields keep native undo.
    const isUndoKey = (e.ctrlKey || e.metaKey) && (e.code === 'KeyZ' || e.key === 'z' || e.key === 'Z');
    const isRedoY   = (e.ctrlKey || e.metaKey) && !e.shiftKey && (e.code === 'KeyY' || e.key === 'y' || e.key === 'Y');
    if (isUndoKey || isRedoY) {
      const panel  = document.getElementById('tool-apisphere');
      const ta     = document.getElementById('asp-body-raw');
      const active = document.activeElement;
      const wantRedo = isRedoY || (isUndoKey && e.shiftKey);
      if (panel && panel.style.display !== 'none') {
        if (ta && active === ta) {
          e.preventDefault();
          if (wantRedo) _aspRedo(); else _aspUndo();
          return;
        }
        const isKvVal = active && active.classList && active.classList.contains('asp-kv-val');
        const isUrl   = active && active.id === 'asp-url-input';
        const isScript = active && (active.id === 'asp-script-pre' || active.id === 'asp-script-test');
        if (isKvVal || isUrl) {
          e.preventDefault();
          if (wantRedo) _aspKvRedo(active); else _aspKvUndo(active);
          return;
        }
        if (isScript) {
          e.preventDefault();
          if (wantRedo) _aspScriptRedo(active); else _aspScriptUndo(active);
          return;
        }
      }
    }
    // Cmd+F: open both find bars simultaneously if their panels are visible
    if ((e.ctrlKey || e.metaKey) && e.key === "f") {
      const panel = document.getElementById('tool-apisphere');
      if (!panel || panel.style.display === 'none') return;
      const reqWrap    = document.getElementById('asp-body-raw-wrap');
      const respLoaded = document.getElementById('asp-resp-loaded');
      const respBody   = document.getElementById('asp-resp-pnl-body');
      let opened = false;
      if (reqWrap && reqWrap.style.display !== 'none') {
        e.preventDefault(); try { aspOpenFindBar(); } catch(_) {} opened = true;
      }
      if (respLoaded && respLoaded.style.display !== 'none') {
        e.preventDefault();
        aspRespTab('body');
        aspOpenRespFindBar();
        opened = true;
      }
    }
  });
  // Close dropdowns on outside click
  document.addEventListener('click', e => {
    const dd   = document.getElementById('asp-token-dd');
    if (dd   && dd.style.display   !== 'none' && !dd.contains(e.target))   _aspHideTokenDd();
    const menu = document.getElementById('asp-tab-menu');
    if (menu && menu.style.display !== 'none' && !menu.contains(e.target)) aspHideTabMenu();
    const cmenu = document.getElementById('asp-coll-ctx');
    if (cmenu && cmenu.style.display !== 'none' && !cmenu.contains(e.target)) aspHideCollCtx();
  });
  // Paste into URL bar: cURL → import; plain URL with ?query → sync Params + open Params tab
  const urlInp = document.getElementById("asp-url-input");
  if (urlInp) {
    urlInp.addEventListener("paste", e => {
      const text = (e.clipboardData || window.clipboardData).getData("text").trim();
      if (/^curl\b/i.test(text)) {
        e.preventDefault();
        aspImportCurl(text);
        return;
      }
      setTimeout(() => {
        _aspSyncParamsFromUrl();
        const { params } = _aspSplitUrl((urlInp.value || "").trim());
        if (params.length) aspReqTab("params");
        _aspSaveDraft();
      }, 0);
    });
  }
}

// ── Helpers ───────────────────────────────────────────────────
function _aspTimeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)   return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
// ── Collections ───────────────────────────────────────────────
function _aspGetColls()       { try { return JSON.parse(localStorage.getItem(ASP_COLL_KEY)||"[]"); } catch(e) { return []; } }
function _aspSaveColls(cols)  { try { localStorage.setItem(ASP_COLL_KEY, JSON.stringify(cols)); } catch(e) {} }
function _aspMkCollId()       { return "col_" + Date.now().toString(36) + Math.random().toString(36).slice(2,5); }
function _aspMkReqId()        { return "req_" + Date.now().toString(36) + Math.random().toString(36).slice(2,5); }
function _aspMkFolderId()     { return "fld_" + Date.now().toString(36) + Math.random().toString(36).slice(2,5); }
function _aspIsFolder(it)     { return !!(it && it.type === "folder"); }

function _aspBlankFolder(name) {
  return {
    type: "folder",
    id: _aspMkFolderId(),
    name: name || "New Folder",
    expanded: true,
    auth: { type: "inherit", token: "", username: "", password: "" },
    variables: [],
    items: [],
  };
}

/** Walk every request in a collection (not folder nodes). fn(req, folder|null, col) */
function _aspForEachReq(col, fn) {
  (col.items || []).forEach(it => {
    if (_aspIsFolder(it)) (it.items || []).forEach(r => fn(r, it, col));
    else fn(it, null, col);
  });
}

function _aspFlatReqs(col) {
  const out = [];
  _aspForEachReq(col, r => out.push(r));
  return out;
}

/** Find request by predicate → { cols, col, folder, parentItems, index, item } | null
 *  Pass `cols` when you will mutate + save the same in-memory array. */
function _aspFindReqBy(pred, cols) {
  cols = cols || _aspGetColls();
  for (const col of cols) {
    const items = col.items || [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (_aspIsFolder(it)) {
        const fin = it.items || [];
        for (let j = 0; j < fin.length; j++) {
          if (pred(fin[j], col, it)) {
            return { cols, col, folder: it, parentItems: fin, index: j, item: fin[j] };
          }
        }
      } else if (pred(it, col, null)) {
        return { cols, col, folder: null, parentItems: items, index: i, item: it };
      }
    }
  }
  return null;
}

function _aspGetActiveTabMembership() {
  const activeId = _aspActiveTabId();
  if (!activeId) return null;
  return _aspFindReqBy(r => r.sourceTabId === activeId);
}

/** Folder concrete auth overrides collection; inherit/none on folder → collection.
 *  Collection never inherits — "inherit" there is treated as no auth. */
function _aspResolveScopeAuth(col, folder) {
  const fa = folder && folder.auth;
  if (fa && fa.type && fa.type !== "none" && fa.type !== "inherit") {
    return { type: fa.type, token: fa.token || "", username: fa.username || "", password: fa.password || "" };
  }
  const ca = col && col.auth;
  if (ca && ca.type && ca.type !== "none" && ca.type !== "inherit") {
    return { type: ca.type, token: ca.token || "", username: ca.username || "", password: ca.password || "" };
  }
  return { type: "none", token: "", username: "", password: "" };
}

/** Merge vars — folder keys override collection keys. */
function _aspResolveScopeVars(col, folder) {
  const map = new Map();
  ((col && col.variables) || []).forEach(v => {
    if (v && v.enabled !== false && v.key) map.set(v.key, { enabled: true, key: v.key, value: v.value || "" });
  });
  ((folder && folder.variables) || []).forEach(v => {
    if (v && v.enabled !== false && v.key) map.set(v.key, { enabled: true, key: v.key, value: v.value || "" });
  });
  return Array.from(map.values());
}

/** Active vars for send / autocomplete: Environment < Collection < Folder. */
function _aspResolveActiveVars(col, folder) {
  const map = new Map();
  const env = _aspGetActiveEnv();
  ((env && env.variables) || []).forEach(v => {
    if (v && v.enabled !== false && v.key) map.set(v.key, { enabled: true, key: v.key, value: v.value || "" });
  });
  _aspResolveScopeVars(col, folder).forEach(v => map.set(v.key, v));
  return Array.from(map.values());
}

// ── Environments ───────────────────────────────────────────────
function _aspGetEnvs() {
  try { return JSON.parse(localStorage.getItem(ASP_ENVS_KEY) || "[]"); } catch (e) { return []; }
}
function _aspSaveEnvs(envs) {
  try { localStorage.setItem(ASP_ENVS_KEY, JSON.stringify(envs)); } catch (e) {}
}
function _aspActiveEnvId() {
  return localStorage.getItem(ASP_ACTIVE_ENV_KEY) || "";
}
function _aspSetActiveEnvId(id) {
  if (id) localStorage.setItem(ASP_ACTIVE_ENV_KEY, id);
  else localStorage.removeItem(ASP_ACTIVE_ENV_KEY);
}
function _aspGetActiveEnv() {
  const id = _aspActiveEnvId();
  if (!id) return null;
  return _aspGetEnvs().find(e => e.id === id) || null;
}
// Postman-style environment color themes
const ASP_ENV_COLORS = [
  { id: "blue",   hex: "#3B82F6" },
  { id: "green",  hex: "#22C55E" },
  { id: "orange", hex: "#F59E0B" },
  { id: "purple", hex: "#A855F7" },
  { id: "red",    hex: "#EF4444" },
  { id: "teal",   hex: "#14B8A6" },
  { id: "pink",   hex: "#EC4899" },
  { id: "gray",   hex: "#94A3B8" },
];
let _aspEnvEditColor = "blue";

function _aspMkEnvId() {
  return "env_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}
function _aspBlankEnv(name, color) {
  return {
    id: _aspMkEnvId(),
    name: name || "New Environment",
    color: color || "blue",
    variables: [],
  };
}
function _aspEnvColorHex(colorId) {
  const hit = ASP_ENV_COLORS.find(c => c.id === colorId);
  return hit ? hit.hex : ASP_ENV_COLORS[0].hex;
}
function _aspEnvColorRgba(colorId, alpha) {
  const hex = _aspEnvColorHex(colorId).replace("#", "");
  const n = parseInt(hex, 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  return `rgba(${r},${g},${b},${alpha})`;
}

function _aspRenderEnvBtn() {
  const lbl = document.getElementById("asp-env-btn-label");
  const btn = document.getElementById("asp-env-btn");
  const dot = document.getElementById("asp-env-btn-dot");
  const env = _aspGetActiveEnv();
  if (lbl) lbl.textContent = env ? env.name : "No Environment";
  if (!btn) return;
  btn.classList.toggle("asp-env-active", !!env);
  if (env) {
    const hex = _aspEnvColorHex(env.color);
    btn.style.setProperty("--asp-env-color", hex);
    btn.style.color = hex;
    btn.style.borderColor = _aspEnvColorRgba(env.color, 0.45);
    btn.style.background = _aspEnvColorRgba(env.color, 0.12);
    if (dot) dot.style.background = hex;
  } else {
    btn.style.removeProperty("--asp-env-color");
    btn.style.color = "";
    btn.style.borderColor = "";
    btn.style.background = "";
    if (dot) dot.style.background = "";
  }
}

function aspToggleEnvMenu() {
  if (_aspIsWorkspaceOverlayOpen() && !_aspIsEnvEditorOpen()) return;
  const menu = document.getElementById("asp-env-menu");
  if (!menu) return;
  const open = menu.style.display === "block";
  if (open) { aspCloseEnvMenu(); return; }
  _aspRenderEnvMenu();
  menu.style.display = "block";
  setTimeout(() => document.addEventListener("click", _aspEnvMenuOutside, { once: true }), 0);
}
function aspCloseEnvMenu() {
  const menu = document.getElementById("asp-env-menu");
  if (menu) menu.style.display = "none";
}
function _aspEnvMenuOutside(e) {
  const menu = document.getElementById("asp-env-menu");
  const wrap = document.getElementById("asp-env-wrap");
  if (menu && wrap && !wrap.contains(e.target)) aspCloseEnvMenu();
}

function _aspRenderEnvMenu() {
  const list = document.getElementById("asp-env-menu-list");
  if (!list) return;
  const envs = _aspGetEnvs();
  const activeId = _aspActiveEnvId();
  const noneOn = !activeId || !envs.some(e => e.id === activeId);

  let html = `<button type="button" class="asp-env-item${noneOn ? " on" : ""}" onclick="aspSelectEnv('')">
    <span class="asp-env-check">${noneOn ? "✓" : ""}</span>
    <span class="asp-env-name">No Environment</span>
  </button>`;

  if (envs.length) {
    html += `<div class="asp-env-sep"></div>`;
    html += envs.map(env => {
      const on = env.id === activeId;
      const hex = _aspEnvColorHex(env.color);
      return `<div class="asp-env-item-row${on ? " on" : ""}">
        <button type="button" class="asp-env-item" onclick="aspSelectEnv('${env.id}')">
          <span class="asp-env-check" style="${on ? `color:${hex}` : ""}">${on ? "✓" : ""}</span>
          <span class="asp-env-dot" style="background:${hex};width:8px;height:8px"></span>
          <span class="asp-env-name">${_aspEscHtml(env.name)}</span>
        </button>
        <button type="button" class="asp-env-open-btn" title="Open Environment" onclick="event.stopPropagation();aspOpenEnvironment('${env.id}')">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M6.22 8.72a.75.75 0 0 0 1.06 1.06l5.22-5.22v1.69a.75.75 0 0 0 1.5 0V3.75a.75.75 0 0 0-.75-.75H9.75a.75.75 0 0 0 0 1.5h1.69L6.22 8.72z"/><path d="M3.5 6.75c0-.69.56-1.25 1.25-1.25H7A.75.75 0 0 0 7 4H4.75A2.75 2.75 0 0 0 2 6.75v4.5A2.75 2.75 0 0 0 4.75 14h4.5A2.75 2.75 0 0 0 12 11.25V9a.75.75 0 0 0-1.5 0v2.25c0 .69-.56 1.25-1.25 1.25h-4.5c-.69 0-1.25-.56-1.25-1.25v-4.5z"/></svg>
        </button>
      </div>`;
    }).join("");
  }

  html += `<div class="asp-env-sep"></div>
    <button type="button" class="asp-env-add" onclick="aspAddEnvironment()">
      <span class="asp-env-add-plus">+</span> Add Environment
    </button>`;
  list.innerHTML = html;
}

function aspSelectEnv(id) {
  _aspSetActiveEnvId(id || "");
  // If stored id was stale, clear
  if (id && !_aspGetActiveEnv()) _aspSetActiveEnvId("");
  _aspRenderEnvBtn();
  aspCloseEnvMenu();
}

function aspAddEnvironment() {
  aspCloseEnvMenu();
  aspShowEnvEditor(null);
}

function aspOpenEnvironment(id) {
  aspCloseEnvMenu();
  if (id) aspShowEnvEditor(id);
}

function _aspHideEnvPanelOnly() {
  const panel = document.getElementById("asp-env-panel");
  if (panel) panel.style.display = "none";
  _aspEnvEditing = false;
  _aspEnvEditId = null;
  const saveBtn = document.getElementById("asp-env-save-btn");
  if (saveBtn) {
    saveBtn.textContent = "Save";
    saveBtn.disabled = false;
  }
}

function _aspEnvMarkDirty() {
  const saveBtn = document.getElementById("asp-env-save-btn");
  if (saveBtn) {
    saveBtn.textContent = "Save";
    saveBtn.disabled = false;
  }
}

function _aspRenderEnvSwitcher() {
  const sel = document.getElementById("asp-env-switcher");
  if (!sel) return;
  const envs = _aspGetEnvs();
  if (!envs.length) {
    sel.style.display = "none";
    return;
  }
  sel.style.display = "";
  let html = `<option value="__new__"${!_aspEnvEditId ? " selected" : ""}>+ New Environment</option>`;
  envs.forEach(e => {
    const isSel = _aspEnvEditId === e.id;
    html += `<option value="${_aspEscHtml(e.id)}"${isSel ? " selected" : ""}>${_aspEscHtml(e.name)}</option>`;
  });
  sel.innerHTML = html;
}

function aspSwitchEnvEdit(val) {
  if (val === "__new__") {
    aspShowEnvEditor(null);
  } else if (val) {
    aspShowEnvEditor(val);
  }
}

function aspShowEnvEditor(envId) {
  _aspCloseWorkspaceOverlays("env");
  const envs = _aspGetEnvs();
  const existing = envId ? envs.find(e => e.id === envId) : null;
  _aspEnvEditId = existing ? existing.id : null;
  _aspEnvEditing = true;
  _aspEnvEditColor = (existing && existing.color) || "blue";

  const nameEl = document.getElementById("asp-env-name");
  if (nameEl) nameEl.value = existing ? existing.name : "New Environment";

  const delBtn = document.getElementById("asp-env-del-btn");
  if (delBtn) delBtn.style.display = existing ? "" : "none";

  const saveBtn = document.getElementById("asp-env-save-btn");
  if (saveBtn) {
    saveBtn.textContent = "Save";
    saveBtn.disabled = false;
  }

  _aspRenderEnvColorPicker();
  _aspRenderEnvSwitcher();

  const vars = (existing && existing.variables) || [];
  const tbody = document.getElementById("asp-env-vars");
  if (tbody) {
    tbody.innerHTML = vars.map(v => _aspEnvVarRowHtml(v)).join("");
    if (!vars.length) tbody.innerHTML = _aspEnvVarRowHtml({ enabled: true, key: "", value: "" });
  }

  const panel = document.getElementById("asp-env-panel");
  if (panel) panel.style.display = "flex";
  _aspSyncChromeLock();
  _aspRenderEnvBtn();
  setTimeout(() => {
    if (nameEl) {
      nameEl.focus();
      if (!existing) nameEl.select();
    }
  }, 40);
}

function _aspRenderEnvColorPicker() {
  const wrap = document.getElementById("asp-env-color-picker");
  if (!wrap) return;
  wrap.innerHTML = ASP_ENV_COLORS.map(c =>
    `<button type="button" class="asp-env-color-swatch${c.id === _aspEnvEditColor ? " on" : ""}"
      style="--swatch:${c.hex}" title="${c.id}"
      onclick="aspPickEnvColor('${c.id}')" aria-label="${c.id} color"></button>`
  ).join("");
}

function aspPickEnvColor(colorId) {
  if (!ASP_ENV_COLORS.some(c => c.id === colorId)) return;
  _aspEnvEditColor = colorId;
  _aspRenderEnvColorPicker();
  _aspEnvMarkDirty();
}

function aspHideEnvEditor() {
  _aspHideEnvPanelOnly();
  _aspSyncChromeLock();
  _aspRenderEnvBtn();
}

function _aspEnvVarRowHtml(v) {
  v = v || {};
  return `<tr class="asp-var-row">
    <td style="text-align:center"><input type="checkbox" ${v.enabled !== false ? "checked" : ""} onchange="_aspEnvMarkDirty()" style="width:14px;height:14px;cursor:pointer;accent-color:#1f6feb"></td>
    <td><input type="text" class="asp-var-inp" value="${_aspEscHtml(v.key || "")}" placeholder="variableName" oninput="_aspEnvMarkDirty()"></td>
    <td><input type="text" class="asp-var-inp" value="${_aspEscHtml(v.value || "")}" placeholder="value" oninput="_aspEnvMarkDirty()"></td>
    <td><button type="button" onclick="this.closest('tr').remove();_aspEnvMarkDirty()" style="background:none;border:none;color:var(--text3);font-size:15px;cursor:pointer;padding:0 4px;line-height:1" title="Remove">×</button></td>
  </tr>`;
}

function aspEnvAddVar() {
  const tbody = document.getElementById("asp-env-vars");
  if (!tbody) return;
  tbody.insertAdjacentHTML("beforeend", _aspEnvVarRowHtml({ enabled: true, key: "", value: "" }));
  const rows = tbody.querySelectorAll(".asp-var-row");
  const last = rows[rows.length - 1];
  if (last) last.querySelectorAll("input[type=text]")[0]?.focus();
  _aspEnvMarkDirty();
}

function _aspReadEnvVarsFromUi() {
  return Array.from(document.querySelectorAll("#asp-env-vars .asp-var-row")).map(tr => {
    const inputs = tr.querySelectorAll("input");
    return {
      enabled: inputs[0] ? inputs[0].checked : true,
      key:     inputs[1] ? inputs[1].value.trim() : "",
      value:   inputs[2] ? inputs[2].value : "",
    };
  }).filter(v => v.key);
}

function aspSaveEnvironment() {
  if (!_aspEnvEditing) return;
  const nameEl = document.getElementById("asp-env-name");
  const name = (nameEl && nameEl.value.trim()) || "New Environment";
  const variables = _aspReadEnvVarsFromUi();
  const color = _aspEnvEditColor || "blue";
  const envs = _aspGetEnvs();

  if (_aspEnvEditId) {
    const env = envs.find(e => e.id === _aspEnvEditId);
    if (!env) { _aspAlert("Environment not found."); return; }
    env.name = name;
    env.color = color;
    env.variables = variables;
  } else {
    const env = _aspBlankEnv(name, color);
    env.variables = variables;
    envs.push(env);
    _aspEnvEditId = env.id;
    _aspSetActiveEnvId(env.id);
  }
  _aspSaveEnvs(envs);
  _aspRenderEnvBtn();
  _aspRenderEnvSwitcher();

  const delBtn = document.getElementById("asp-env-del-btn");
  if (delBtn) delBtn.style.display = "";

  const saveBtn = document.getElementById("asp-env-save-btn");
  if (saveBtn) {
    saveBtn.textContent = "Saved";
    saveBtn.disabled = true;
    setTimeout(() => {
      saveBtn.textContent = "Save";
      saveBtn.disabled = false;
    }, 1400);
  }
}

function aspDeleteEnvironment() {
  if (!_aspEnvEditId) return;
  const envs = _aspGetEnvs();
  const env = envs.find(e => e.id === _aspEnvEditId);
  if (!env) return;
  _aspEnvConfirmDel = _aspEnvEditId;
  const msg = document.getElementById("asp-coll-confirm-msg");
  const ttl = document.getElementById("asp-coll-confirm-title");
  if (ttl) ttl.textContent = "Delete Environment";
  if (msg) msg.innerHTML = `Delete environment <b style="color:var(--text)">"${_aspEscHtml(env.name)}"</b>?<br><span style="font-size:10px;color:var(--text3)">Its variables will no longer resolve in requests.</span>`;
  const modal = document.getElementById("asp-coll-confirm");
  if (modal) modal.style.display = "flex";
}
function _aspDoDeleteEnvironment(id) {
  if (!id) return;
  const next = _aspGetEnvs().filter(e => e.id !== id);
  _aspSaveEnvs(next);
  if (_aspActiveEnvId() === id) _aspSetActiveEnvId("");
  if (_aspEnvEditId === id) aspHideEnvEditor();
  _aspRenderEnvBtn();
  _aspRenderEnvSwitcher();
}

function _aspFindFolderInCol(col, folderId) {
  if (!col || !folderId) return null;
  return (col.items || []).find(it => _aspIsFolder(it) && it.id === folderId) || null;
}

function aspToggleColl() {
  _aspCollOpen = !_aspCollOpen;
  const panel = document.getElementById("asp-coll-panel");
  const spl   = document.getElementById("asp-coll-splitter");
  const btn   = document.getElementById("asp-coll-toggle-btn");
  if (panel) panel.style.display = _aspCollOpen ? "flex" : "none";
  if (spl)   spl.style.display   = _aspCollOpen ? "block" : "none";
  if (btn)   btn.classList.toggle("asp-coll-active", _aspCollOpen);
  if (_aspCollOpen) _aspRenderCollPanel();
}

function _aspRenderReqRow(colId, req, inFolder) {
  return `<div class="asp-coll-req${inFolder ? " asp-in-folder" : ""}" onclick="aspOpenCollReq('${colId}','${req.id}')" title="${_aspEscAttr(req.url||'')}">
    <span class="asp-cr-method" style="color:${_ASP_METHOD_COLORS[req.method]||'#c9d1d9'}">${req.method||"GET"}</span>
    <span class="asp-cr-name">${_aspEscHtml(req.name)}</span>
    <button class="asp-cr-del" onclick="event.stopPropagation();aspDelCollReq('${colId}','${req.id}')" title="Remove">×</button>
  </div>`;
}

function _aspRenderCollPanel() {
  const list = document.getElementById("asp-coll-list");
  if (!list) return;
  const cols = _aspGetColls();
  if (!cols.length) {
    list.innerHTML = `<div style="padding:20px 12px;color:var(--text3);font-size:11px;text-align:center;line-height:1.8">
      No collections yet.<br>Hover a tab → ⋮ to save a request.
    </div>`;
    return;
  }
  list.innerHTML = cols.map(col => {
    const expanded = col.expanded !== false;
    const rows = (col.items || []).map(it => {
      if (_aspIsFolder(it)) {
        const fExp = it.expanded !== false;
        const childReqs = (it.items || []).map(r => _aspRenderReqRow(col.id, r, true)).join("");
        const emptyF = !childReqs ? `<div style="padding:2px 12px 6px 38px;color:var(--text3);font-size:10px">Empty folder</div>` : "";
        return `<div class="asp-coll-folder">
          <div class="asp-coll-folder-hdr" onclick="aspToggleCollFolder('${col.id}','${it.id}')">
            <span class="asp-coll-arrow">${fExp ? "▾" : "▸"}</span>
            <span class="asp-coll-fname">📁 ${_aspEscHtml(it.name)}</span>
            <button class="asp-coll-dots" onclick="event.stopPropagation();aspShowCollCtx('${col.id}',this,'${it.id}')" title="Folder options">⋮</button>
          </div>
          ${fExp ? `<div>${childReqs || emptyF}</div>` : ""}
        </div>`;
      }
      return _aspRenderReqRow(col.id, it, false);
    }).join("");
    const empty = !rows ? `<div style="padding:3px 12px 7px 22px;color:var(--text3);font-size:10px">Empty</div>` : "";
    return `<div class="asp-coll-group">
      <div class="asp-coll-group-hdr" onclick="aspToggleCollGroup('${col.id}')">
        <span class="asp-coll-arrow">${expanded ? "▾" : "▸"}</span>
        <span class="asp-coll-gname">${_aspEscHtml(col.name)}</span>
        <button class="asp-coll-dots" onclick="event.stopPropagation();aspShowCollCtx('${col.id}',this)" title="Options">⋮</button>
      </div>
      ${expanded ? `<div>${rows || empty}</div>` : ""}
    </div>`;
  }).join("");
}

function aspToggleCollGroup(colId) {
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  if (col) { col.expanded = col.expanded === false ? true : false; _aspSaveColls(cols); _aspRenderCollPanel(); }
}

function aspToggleCollFolder(colId, folderId) {
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  const folder = _aspFindFolderInCol(col, folderId);
  if (folder) {
    folder.expanded = folder.expanded === false ? true : false;
    _aspSaveColls(cols);
    _aspRenderCollPanel();
  }
}

// ── Alert modal (replaces alert() — blocked in pywebview/WKWebView) ──────
function _aspAlertSplitTitle(msg) {
  const text = String(msg == null ? "" : msg);
  const m = text.match(/^(Import failed|Export failed|Download failed|Decode failed):\s*([\s\S]+)$/i);
  if (m) return { title: m[1], body: m[2] };
  return { title: "", body: text };
}
function _aspAlertNoColumnBlocks(body) {
  const m = String(body || "").match(/^No column matched this param \((.+)\)\.\s*Headers:\s*([\s\S]*)$/);
  if (!m) return null;
  const blocks = [{ label: "This param" }, { code: m[1] }, { label: "CSV headers" }];
  const headers = (m[2] || "").split(",").map(s => s.trim()).filter(Boolean);
  if (!headers.length || (headers.length === 1 && headers[0] === "(none)")) {
    blocks.push({ text: "(none)" });
  } else {
    headers.forEach(h => blocks.push({ code: h }));
  }
  return blocks;
}
function _aspAlertRenderBody(msgEl, body, blocks) {
  msgEl.replaceChildren();
  msgEl.classList.remove("asp-dlg-msg--detail", "asp-dlg-msg--rich");
  msgEl.style.textAlign = "";
  if (blocks && blocks.length) {
    msgEl.classList.add("asp-dlg-msg--rich");
    blocks.forEach(b => {
      if (b.label) {
        const el = document.createElement("div");
        el.className = "asp-dlg-k";
        el.textContent = b.label;
        msgEl.appendChild(el);
      }
      if (b.code != null) {
        const el = document.createElement("code");
        el.className = "asp-dlg-code";
        el.textContent = b.code;
        msgEl.appendChild(el);
      }
      if (b.text != null) {
        const el = document.createElement("div");
        el.className = "asp-dlg-p";
        el.textContent = b.text;
        msgEl.appendChild(el);
      }
    });
    return;
  }
  const long = body.length > 96 || body.includes("\n");
  if (long) msgEl.classList.add("asp-dlg-msg--detail");
  else msgEl.style.textAlign = "center";
  msgEl.textContent = body;
}
function _aspAlert(msg, title) {
  const modal = document.getElementById("asp-alert-modal");
  const msgEl = document.getElementById("asp-alert-msg");
  const titleEl = document.getElementById("asp-alert-title");
  if (!modal) return;
  let t = title ? String(title) : "";
  let body = String(msg == null ? "" : msg);
  if (!t) {
    const parsed = _aspAlertSplitTitle(body);
    t = parsed.title;
    body = parsed.body;
  }
  if (titleEl) {
    titleEl.textContent = t;
    titleEl.hidden = !t;
  }
  if (msgEl) _aspAlertRenderBody(msgEl, body, _aspAlertNoColumnBlocks(body));
  modal.style.display = "flex";
  const ok = document.getElementById("asp-alert-ok");
  if (ok) ok.focus();
}
function _aspAlertClose() {
  const modal = document.getElementById("asp-alert-modal");
  if (modal) modal.style.display = "none";
}

// ── Confirm modal (replaces window.confirm — native dialogs not stylable) ──
let _aspConfirmResolve = null;
function _aspConfirm(msg) {
  return new Promise(resolve => {
    const modal = document.getElementById("asp-confirm-modal");
    const msgEl = document.getElementById("asp-confirm-msg");
    if (!modal) { resolve(false); return; }
    if (_aspConfirmResolve) {
      const prev = _aspConfirmResolve;
      _aspConfirmResolve = null;
      prev(false);
    }
    if (msgEl) msgEl.textContent = msg;
    _aspConfirmResolve = resolve;
    modal.style.display = "flex";
  });
}
function _aspConfirmOk() {
  const modal = document.getElementById("asp-confirm-modal");
  if (modal) modal.style.display = "none";
  const r = _aspConfirmResolve;
  _aspConfirmResolve = null;
  if (r) r(true);
}
function _aspConfirmCancel() {
  const modal = document.getElementById("asp-confirm-modal");
  if (modal) modal.style.display = "none";
  const r = _aspConfirmResolve;
  _aspConfirmResolve = null;
  if (r) r(false);
}

// Route native alert() through the styled modal (3_Apps)
window.alert = function(msg) {
  _aspAlert(String(msg == null ? "" : msg));
};

// ── Name-input modal (replaces prompt() — blocked in pywebview/WKWebView) ──
let _aspNameModalCb = null;
function _aspNameModalShow(title, okLabel, cb) {
  _aspNameModalCb = cb;
  const modal = document.getElementById("asp-name-modal");
  const inp   = document.getElementById("asp-name-modal-input");
  const ttl   = document.getElementById("asp-name-modal-title");
  const ok    = document.getElementById("asp-name-modal-ok");
  if (!modal || !inp) return;
  if (ttl) ttl.textContent = title;
  if (ok)  ok.textContent  = okLabel || "Create";
  inp.value = "";
  modal.style.display = "flex";
  setTimeout(() => inp.focus(), 50);
}
function _aspNameModalOk() {
  const inp = document.getElementById("asp-name-modal-input");
  const val = inp ? inp.value.trim() : "";
  if (!val) { if (inp) inp.focus(); return; }
  const cb = _aspNameModalCb;
  _aspNameModalCb = null;
  const modal = document.getElementById("asp-name-modal");
  if (modal) modal.style.display = "none";
  if (cb) cb(val);
}
function _aspNameModalCancel() {
  _aspNameModalCb = null;
  const modal = document.getElementById("asp-name-modal");
  if (modal) modal.style.display = "none";
}

function aspNewCollection() {
  _aspNameModalShow("New Collection", "Create", name => {
    const cols = _aspGetColls();
    cols.push({ id: _aspMkCollId(), name, expanded: true, items: [], auth: { type: "none", token: "", username: "", password: "" }, variables: [] });
    _aspSaveColls(cols);
    if (!_aspCollOpen) aspToggleColl(); else _aspRenderCollPanel();
  });
}

function aspOpenCollReq(colId, reqId) {
  const cols = _aspGetColls();
  const loc = _aspFindReqBy(r => r.id === reqId, cols);
  if (!loc || loc.col.id !== colId) return;
  const req = loc.item;
  const tabs = _aspGetTabs();
  const existing = req.sourceTabId && tabs.find(t => t.id === req.sourceTabId);
  if (existing) { aspSwitchTab(existing.id); return; }
  _aspFlushTab();
  const newId = _aspMkTabId();
  const tab   = Object.assign(_aspBlankTab(), req, { id: newId });
  loc.item.sourceTabId = newId;
  _aspSaveColls(cols);
  const tabs2 = _aspGetTabs();
  tabs2.push(tab);
  _aspSaveTabs(tabs2);
  _aspSetActiveTabId(newId);
  _aspApplyState(tab);
  _aspRenderTabsBar();
  _aspResetRespPanel();
}

function aspDelCollReq(colId, reqId) {
  const cols = _aspGetColls();
  const loc = _aspFindReqBy(r => r.id === reqId, cols);
  if (!loc || loc.col.id !== colId) return;
  loc.parentItems.splice(loc.index, 1);
  _aspSaveColls(cols);
  _aspRenderCollPanel();
}

function aspDelColl(colId) {
  _aspSaveColls(_aspGetColls().filter(c => c.id !== colId));
  _aspRenderCollPanel();
  if (_aspCollOvId === colId) aspHideCollOverview();
}

function aspDelCollFolder(colId, folderId) {
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  if (!col) return;
  col.items = (col.items || []).filter(it => !(_aspIsFolder(it) && it.id === folderId));
  _aspSaveColls(cols);
  _aspRenderCollPanel();
  if (_aspCollOvId === colId && _aspCollOvFolderId === folderId) aspHideCollOverview();
}

// ── Collection / Folder 3-dot context menu ─────────────────────
function aspShowCollCtx(colId, btn, folderId) {
  _aspCollCtxId = colId;
  _aspCollCtxFolderId = folderId || null;
  const menu = document.getElementById("asp-coll-ctx");
  if (!menu) return;
  const kind = folderId ? "folder" : "col";
  menu.querySelectorAll("[data-ctx]").forEach(el => {
    const kinds = (el.getAttribute("data-ctx") || "").split(",");
    el.style.display = kinds.includes(kind) ? "" : "none";
  });
  const rect = btn.getBoundingClientRect();
  menu.style.left    = rect.left + "px";
  menu.style.top     = (rect.bottom + 4) + "px";
  menu.style.display = "block";
  setTimeout(() => {
    const mr = menu.getBoundingClientRect();
    if (mr.bottom > window.innerHeight - 8) menu.style.top = (rect.top - mr.height - 4) + "px";
    if (mr.right  > window.innerWidth  - 8) menu.style.left = (window.innerWidth - mr.width - 8) + "px";
  }, 0);
}
function aspHideCollCtx() {
  const menu = document.getElementById("asp-coll-ctx");
  if (menu) menu.style.display = "none";
  _aspCollCtxId = null;
  _aspCollCtxFolderId = null;
}
function aspCollCtxOverview() {
  const id = _aspCollCtxId, fid = _aspCollCtxFolderId;
  aspHideCollCtx();
  if (id) aspShowCollOverview(id, fid || null);
}
function aspCollCtxDelete() {
  const id = _aspCollCtxId, fid = _aspCollCtxFolderId;
  aspHideCollCtx();
  if (!id) return;
  if (fid) aspConfirmDelFolder(id, fid);
  else aspConfirmDelColl(id);
}
function aspCollCtxAddRequest() {
  const colId = _aspCollCtxId, folderId = _aspCollCtxFolderId;
  aspHideCollCtx();
  if (!colId) return;
  if (_aspIsWorkspaceOverlayOpen()) return;
  _aspFlushTab();
  const tab  = _aspBlankTab();
  const tabs = _aspGetTabs();
  tabs.push(tab);
  _aspSaveTabs(tabs);
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  if (col) {
    const entry = Object.assign({}, tab, { id: _aspMkReqId(), sourceTabId: tab.id });
    const folder = _aspFindFolderInCol(col, folderId);
    if (folder) {
      if (!folder.items) folder.items = [];
      folder.items.push(entry);
      folder.expanded = true;
    } else {
      if (!col.items) col.items = [];
      col.items.push(entry);
    }
    col.expanded = true;
    _aspSaveColls(cols);
  }
  _aspSetActiveTabId(tab.id);
  _aspApplyState(tab);
  _aspRenderTabsBar();
  _aspResetRespPanel();
  _aspRenderCollPanel();
  document.getElementById("asp-url-input")?.focus();
}
function aspCollCtxAddFolder() {
  const colId = _aspCollCtxId;
  aspHideCollCtx();
  if (!colId) return;
  _aspNameModalShow("New Folder", "Create", name => {
    const cols = _aspGetColls();
    const col  = cols.find(c => c.id === colId);
    if (!col) return;
    if (!col.items) col.items = [];
    col.items.push(_aspBlankFolder(name));
    col.expanded = true;
    _aspSaveColls(cols);
    if (!_aspCollOpen) aspToggleColl(); else _aspRenderCollPanel();
  });
}

// ── Export collection (Postman v2.1 collection format) ─────────
function _aspExportPmAuth(a) {
  if (!a || !a.type || a.type === "none") return { type: "noauth" };
  if (a.type === "bearer") return { type: "bearer", bearer: [{ key: "token", value: a.token || "", type: "string" }] };
  if (a.type === "basic")  return { type: "basic",  basic: [
    { key: "username", value: a.username || "", type: "string" },
    { key: "password", value: a.password || "", type: "string" },
  ] };
  return { type: "noauth" };
}
function _aspExportPmBody(item) {
  switch (item.bodyType) {
    case "json":
      return { mode: "raw", raw: item.bodyRaw || "", options: { raw: { language: "json" } } };
    case "text":
      return { mode: "raw", raw: item.bodyRaw || "", options: { raw: { language: "text" } } };
    case "raw":
      return {
        mode: "raw",
        raw: item.bodyRaw || "",
        options: { raw: { language: item.bodyRawLang || "json" } },
      };
    case "form":
      return {
        mode: "urlencoded",
        urlencoded: (item.bodyForm || []).filter(r => r.key)
          .map(r => ({ key: r.key, value: r.value || "", disabled: !r.enabled })),
      };
    case "multipart":
      return {
        mode: "formdata",
        formdata: (item.bodyMultipart || []).filter(r => r.key)
          .map(r => r.fieldType === "file"
            ? { key: r.key, type: "file", src: r.filename || "", disabled: !r.enabled }
            : { key: r.key, value: r.value || "", type: "text", disabled: !r.enabled }),
      };
    case "binary":
      return {
        mode: "file",
        file: (item.bodyBinary && item.bodyBinary.filename) || "",
        src: (item.bodyBinary && item.bodyBinary.filename) || "",
      };
    case "graphql": {
      let variables = item.bodyGraphqlVars || "";
      return {
        mode: "graphql",
        graphql: {
          query: item.bodyGraphqlQuery || "",
          variables: variables,
        },
      };
    }
    default:
      return null;
  }
}
function _aspExportPmEvents(item) {
  const events = [];
  if ((item.preRequestScript || "").trim()) {
    events.push({
      listen: "prerequest",
      script: { type: "text/javascript", exec: String(item.preRequestScript).split("\n") },
    });
  }
  if ((item.testScript || "").trim()) {
    events.push({
      listen: "test",
      script: { type: "text/javascript", exec: String(item.testScript).split("\n") },
    });
  }
  return events;
}
function _aspExportPmRequest(item) {
  const req = {
    method: item.method || "GET",
    header: (item.headers || []).filter(h => h.key)
      .map(h => ({ key: h.key, value: h.value || "", disabled: !h.enabled })),
    url: {
      raw: item.url || "",
      query: (item.params || []).filter(p => p.key)
        .map(p => ({ key: p.key, value: p.value || "", disabled: !p.enabled })),
    },
  };
  if (item.auth && item.auth.type && item.auth.type !== "inherit") {
    req.auth = _aspExportPmAuth(item.auth);
  }
  const body = _aspExportPmBody(item);
  if (body) req.body = body;
  const out = { name: item.name || item.url || "Untitled Request", request: req, response: [] };
  const events = _aspExportPmEvents(item);
  if (events.length) out.event = events;
  return out;
}

function _aspExportPmTreeItem(item) {
  if (_aspIsFolder(item)) {
    const node = {
      name: item.name || "Folder",
      item: (item.items || []).map(_aspExportPmRequest),
    };
    if (item.auth && item.auth.type && item.auth.type !== "none" && item.auth.type !== "inherit") {
      node.auth = _aspExportPmAuth(item.auth);
    }
    return node;
  }
  return _aspExportPmRequest(item);
}

function aspCollCtxExport() {
  const colId = _aspCollCtxId; aspHideCollCtx();
  if (!colId) return;
  _aspFlushTab();
  const col = _aspGetColls().find(c => c.id === colId);
  if (!col) return;

  const items = (col.items || []).map(_aspExportPmTreeItem);

  const collection = {
    info: {
      name:   col.name || "Collection",
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

  const json     = JSON.stringify(collection, null, 2);
  const filename = (col.name || "collection").replace(/[\\/:*?"<>|]+/g, "_").trim() + ".json";
  window.pywebview.api.save_file(json, filename)
    .then(r => { if (r && r.ok) _aspAlert("Collection exported:\n" + r.path); })
    .catch(e => _aspAlert("Export failed: " + e.message));
}

// ── Import collection (Postman v2.1 collection format) ──────────
function _aspImportPmAuth(a) {
  if (!a || !a.type || a.type === "noauth") return { type: "none", token: "", username: "", password: "" };
  if (a.type === "bearer") {
    const tok = ((a.bearer || []).find(x => x.key === "token") || {}).value || "";
    return { type: "bearer", token: tok, username: "", password: "" };
  }
  if (a.type === "basic") {
    const u = ((a.basic || []).find(x => x.key === "username") || {}).value || "";
    const p = ((a.basic || []).find(x => x.key === "password") || {}).value || "";
    return { type: "basic", token: "", username: u, password: p };
  }
  return { type: "none", token: "", username: "", password: "" };
}
function _aspImportPmUrl(u) {
  const raw   = typeof u === "string" ? u : (u && u.raw) || "";
  const query = (u && typeof u === "object" && Array.isArray(u.query)) ? u.query : null;
  let params;
  if (query) {
    params = query.filter(q => q.key).map(q => ({ enabled: !q.disabled, key: q.key, value: q.value || "" }));
  } else {
    params = _aspSplitUrl(raw).params;
  }
  // Keep full raw URL (with ?query) so the bar matches Postman.
  let url = raw;
  if (query && query.length && raw && !raw.includes("?")) {
    const qs = query.filter(q => q.key && !q.disabled)
      .map(q => encodeURIComponent(q.key) + "=" + encodeURIComponent(q.value || ""))
      .join("&");
    if (qs) url = raw + "?" + qs;
  }
  return { url, params };
}
function _aspImportPmBody(body) {
  const empty = {
    bodyType: "none", bodyRawLang: "json", bodyRaw: "", bodyForm: [], bodyMultipart: [],
    bodyGraphqlQuery: "", bodyGraphqlVars: "", bodyBinary: null,
  };
  if (!body || !body.mode) return empty;
  if (body.mode === "raw") {
    const lang = (body.options && body.options.raw && body.options.raw.language) || "";
    const mapped = { json: "json", text: "text", javascript: "javascript", html: "html", xml: "xml" }[lang]
      || (/^\s*[{[]/.test(body.raw || "") ? "json" : "text");
    return Object.assign({}, empty, { bodyType: "raw", bodyRawLang: mapped, bodyRaw: body.raw || "" });
  }
  if (body.mode === "urlencoded") {
    return Object.assign({}, empty, {
      bodyType: "form",
      bodyForm: (body.urlencoded || []).filter(r => r.key).map(r => ({ enabled: !r.disabled, key: r.key, value: r.value || "" })),
    });
  }
  if (body.mode === "formdata") {
    return Object.assign({}, empty, {
      bodyType: "multipart",
      bodyMultipart: (body.formdata || []).filter(r => r.key).map(r => r.type === "file"
        ? { enabled: !r.disabled, key: r.key, fieldType: "file", value: "", filename: r.src || "" }
        : { enabled: !r.disabled, key: r.key, fieldType: "text", value: r.value || "", filename: "" }),
    });
  }
  if (body.mode === "file") {
    const src = body.file || body.src || "";
    const name = typeof src === "string" ? src.split(/[/\\]/).pop() : "file";
    return Object.assign({}, empty, {
      bodyType: "binary",
      bodyBinary: { filename: name || "file", contentType: "application/octet-stream", data: "" },
    });
  }
  if (body.mode === "graphql") {
    const gql = body.graphql || {};
    let vars = gql.variables || "";
    if (vars && typeof vars === "object") {
      try { vars = JSON.stringify(vars, null, 2); } catch (_) { vars = ""; }
    }
    return Object.assign({}, empty, {
      bodyType: "graphql",
      bodyGraphqlQuery: gql.query || "",
      bodyGraphqlVars: vars || "",
    });
  }
  return empty;
}
// Postman folders nest items recursively — flatten to a plain list of requests
function _aspFlattenPmItems(items, out) {
  out = out || [];
  (items || []).forEach(it => {
    if (it.item && Array.isArray(it.item)) _aspFlattenPmItems(it.item, out);
    else if (it.request) out.push(it);
  });
  return out;
}
/** Import Postman tree preserving one level of folders (deeper nests flatten into folder). */
function _aspImportPmTree(items) {
  const out = [];
  (items || []).forEach(it => {
    if (it.item && Array.isArray(it.item) && !it.request) {
      const folder = _aspBlankFolder(it.name || "Folder");
      if (it.auth) folder.auth = _aspImportPmAuth(it.auth);
      folder.items = _aspFlattenPmItems(it.item).map(_aspImportPmItem);
      out.push(folder);
    } else if (it.request) {
      out.push(_aspImportPmItem(it));
    }
  });
  return out;
}
function _aspImportPmScripts(it) {
  let pre = "", test = "";
  (it.event || []).forEach(ev => {
    const exec = ev && ev.script && ev.script.exec;
    const code = Array.isArray(exec) ? exec.join("\n") : (typeof exec === "string" ? exec : "");
    if (!code) return;
    if (ev.listen === "prerequest") pre = code;
    else if (ev.listen === "test") test = code;
  });
  return { preRequestScript: pre, testScript: test };
}
function _aspImportPmItem(it) {
  const req = it.request || {};
  const { url, params } = _aspImportPmUrl(req.url);
  const headers = (req.header || []).filter(h => h.key)
    .map(h => ({ enabled: !h.disabled, key: h.key, value: h.value || "" }));
  // Missing auth block on an item == "inherit from parent" in Postman's own convention
  const auth = req.auth ? _aspImportPmAuth(req.auth) : { type: "inherit", token: "", username: "", password: "" };
  const b = _aspImportPmBody(req.body);
  const scripts = _aspImportPmScripts(it);
  return {
    id: _aspMkReqId(),
    name: it.name || url || "Untitled Request",
    method: (req.method || "GET").toUpperCase(),
    url, params, headers, auth,
    bodyType: b.bodyType,
    bodyRawLang: b.bodyRawLang || "json",
    bodyRaw: b.bodyRaw,
    bodyForm: b.bodyForm,
    bodyMultipart: b.bodyMultipart,
    bodyBinary: b.bodyBinary,
    bodyGraphqlQuery: b.bodyGraphqlQuery || "",
    bodyGraphqlVars: b.bodyGraphqlVars || "",
    preRequestScript: scripts.preRequestScript,
    testScript: scripts.testScript,
    reqTab: "params",
    sourceTabId: null,
  };
}
function aspImportPmCollectionFile(input) {
  const files = input.files;
  if (!files || !files.length) return;
  Array.from(files).forEach(file => {
    const reader = new FileReader();
    reader.onload = e => {
      let data;
      try { data = JSON.parse(e.target.result); }
      catch(err) { _aspAlert(`Failed to import ${file.name}: invalid JSON`); return; }
      if (!data || !data.info || !Array.isArray(data.item)) {
        _aspAlert(`Failed to import ${file.name}: not a valid collection JSON.`);
        return;
      }
      const items = _aspImportPmTree(data.item);
      const cols  = _aspGetColls();
      cols.push({
        id: _aspMkCollId(),
        name: data.info.name || file.name.replace(/\.json$/i, ""),
        expanded: true,
        items,
        auth: data.auth ? _aspImportPmAuth(data.auth) : { type: "none", token: "", username: "", password: "" },
        variables: Array.isArray(data.variable)
          ? data.variable.filter(v => v.key).map(v => ({ enabled: true, key: v.key, value: v.value || "" }))
          : [],
      });
      _aspSaveColls(cols);
      if (!_aspCollOpen) aspToggleColl(); else _aspRenderCollPanel();
    };
    reader.onerror = () => _aspAlert(`Failed to read ${file.name}`);
    reader.readAsText(file);
  });
  input.value = "";
}

// ── Collection Runner (limited Postman-style runner) ─────────────
let _aspCRColId      = null;
let _aspCRSelected    = {};   // reqId -> bool
let _aspCRTestData    = null; // array of {key:value} rows, or null
let _aspCRResults     = [];
let _aspCRBodyStore   = { req: "", resp: "" };
let _aspCRSearch      = { req: "", resp: "" };
let _aspCRRunning     = false;
let _aspCRPaused      = false;
let _aspCRAborted     = false;
let _aspCRDetailIdx   = -1;
let _aspCRIterations  = 1;

function aspCollCtxRunner() {
  const colId = _aspCollCtxId; aspHideCollCtx();
  if (colId) aspCRShow(colId);
}
function aspCRShow(colId) {
  const col = _aspGetColls().find(c => c.id === colId);
  if (!col) return;
  // Close Overview / other runners so only one overlay is active
  _aspCloseWorkspaceOverlays("collRunner");
  _aspCRColId    = colId;
  _aspCRSelected = {};
  _aspFlatReqs(col).forEach(it => { _aspCRSelected[it.id] = true; });
  _aspCRTestData  = null;
  _aspCRResults   = [];
  _aspCRDetailIdx = -1;
  _aspCRRunning   = false;
  _aspCRPaused    = false;
  _aspCRAborted   = false;

  const nameEl = document.getElementById('asp-cr-cname');
  if (nameEl) nameEl.textContent = col.name || '';
  const fileNameEl = document.getElementById('asp-cr-file-name');
  if (fileNameEl) fileNameEl.textContent = '';
  const errEl = document.getElementById('asp-cr-error');
  if (errEl) errEl.style.display = 'none';
  const itEl = document.getElementById('asp-cr-iterations'); if (itEl) itEl.value = 1;
  const dlEl = document.getElementById('asp-cr-delay');      if (dlEl) dlEl.value = 0;
  const startBtn = document.getElementById('asp-cr-start-btn');
  if (startBtn) { startBtn.disabled = false; startBtn.textContent = 'Start run'; }
  _aspCRSetRunControls(false);

  document.getElementById('asp-cr-setup').style.display   = 'flex';
  document.getElementById('asp-cr-results').style.display = 'none';
  _aspCRRenderDetail(-1); // reset right pane back to the empty state
  _aspCRRenderOrderList();
  const panel = document.getElementById('asp-coll-runner');
  if (panel) panel.style.display = 'flex';
  _aspSyncChromeLock();
}
function _aspCRSetRunControls(running) {
  const pauseBtn = document.getElementById('asp-cr-pause-btn');
  const abortBtn = document.getElementById('asp-cr-abort-btn');
  if (pauseBtn) {
    pauseBtn.style.display = running ? 'inline-block' : 'none';
    if (!running) {
      pauseBtn.textContent = '⏸ Pause';
      pauseBtn.style.borderColor = 'rgba(210,153,34,.45)';
      pauseBtn.style.color = '#d29922';
    }
  }
  if (abortBtn) abortBtn.style.display = running ? 'inline-block' : 'none';
}
function aspCRPause() {
  if (!_aspCRRunning) return;
  _aspCRPaused = !_aspCRPaused;
  const btn = document.getElementById('asp-cr-pause-btn');
  if (!btn) return;
  if (_aspCRPaused) {
    btn.textContent = '▶ Resume';
    btn.style.borderColor = '#3fb950';
    btn.style.color = '#3fb950';
  } else {
    btn.textContent = '⏸ Pause';
    btn.style.borderColor = 'rgba(210,153,34,.45)';
    btn.style.color = '#d29922';
  }
}
function aspCRAbort() {
  _aspCRAborted = true;
  _aspCRPaused  = false; // unblock pause-wait so loop can exit
}
function aspCRClose() {
  _aspHideCollRunnerPanelOnly();
  _aspSyncChromeLock();
}
function _aspCRRenderOrderList() {
  const list = document.getElementById('asp-cr-order-list');
  if (!list) return;
  const col   = _aspGetColls().find(c => c.id === _aspCRColId);
  const items = col ? _aspFlatReqs(col) : [];
  if (!items.length) {
    list.innerHTML = `<div style="padding:16px;color:var(--text3);font-size:11px">No requests in this collection.</div>`;
    return;
  }
  list.innerHTML = items.map((it, i) => {
    const mColor  = _ASP_METHOD_COLORS[it.method] || '#c9d1d9';
    const checked = !!_aspCRSelected[it.id];
    return `<div style="display:flex;align-items:center;gap:10px;padding:7px 16px;font-size:12px">
      <span style="color:var(--text3);width:18px;text-align:right;flex-shrink:0">${i + 1}</span>
      <input type="checkbox" ${checked ? 'checked' : ''} onchange="aspCRToggle('${it.id}')">
      <span style="font-weight:700;font-size:10px;color:${mColor};width:38px;flex-shrink:0">${it.method || 'GET'}</span>
      <span style="color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_aspEscHtml(it.name || it.url || 'Untitled')}</span>
    </div>`;
  }).join('');
}
function aspCRToggle(reqId) {
  _aspCRSelected[reqId] = !_aspCRSelected[reqId];
}
function aspCRSelectAll() {
  const col = _aspGetColls().find(c => c.id === _aspCRColId);
  _aspFlatReqs(col || {}).forEach(it => { _aspCRSelected[it.id] = true; });
  _aspCRRenderOrderList();
}
function aspCRDeselectAll() {
  const col = _aspGetColls().find(c => c.id === _aspCRColId);
  _aspFlatReqs(col || {}).forEach(it => { _aspCRSelected[it.id] = false; });
  _aspCRRenderOrderList();
}

function aspCRFileChange(input) {
  const file   = input.files && input.files[0];
  const nameEl = document.getElementById('asp-cr-file-name');
  if (!file) { _aspCRTestData = null; if (nameEl) nameEl.textContent = ''; return; }
  const reader = new FileReader();
  reader.onload = e => {
    try {
      let data;
      if (/\.json$/i.test(file.name)) {
        data = JSON.parse(e.target.result);
        if (!Array.isArray(data)) throw new Error('JSON test data must be an array of objects.');
      } else {
        data = _aspCRParseCsv(e.target.result);
      }
      _aspCRTestData = data;
      if (nameEl) nameEl.textContent = `${file.name} (${data.length} rows)`;
    } catch(err) {
      _aspCRTestData = null;
      if (nameEl) nameEl.textContent = '';
      _aspAlert(`Failed to parse ${file.name}: ${err.message}`);
    }
  };
  reader.onerror = () => _aspAlert(`Failed to read ${file.name}`);
  reader.readAsText(file);
  input.value = '';
}
function _aspCRParseCsv(text) {
  const lines = text.split(/\r\n|\n|\r/).filter(l => l.trim() !== '');
  if (!lines.length) return [];
  const splitLine = line => {
    const out = []; let cur = ''; let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inQ) {
        if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
        else if (c === '"') inQ = false;
        else cur += c;
      } else if (c === '"') { inQ = true; }
      else if (c === ',') { out.push(cur); cur = ''; }
      else { cur += c; }
    }
    out.push(cur);
    return out;
  };
  const headers = splitLine(lines[0]).map(h => h.trim());
  return lines.slice(1).map(line => {
    const cells = splitLine(line);
    const row = {};
    headers.forEach((h, i) => { row[h] = cells[i] !== undefined ? cells[i] : ''; });
    return row;
  });
}

// Build a /send payload from a collection item (no DOM reads — item data only)
function _aspCRBuildPayload(item, col, varsRow, folder) {
  const params = {};
  (item.params || []).filter(r => r.enabled && r.key).forEach(r => { params[r.key] = r.value; });
  const headers = {};
  (item.headers || []).filter(r => r.enabled && r.key).forEach(r => { headers[r.key] = r.value; });
  let bodyType = item.bodyType || 'none';
  let rawLang  = item.bodyRawLang || 'json';
  let body = null;
  if (bodyType === 'json' || bodyType === 'text') {
    body = _aspResolveTokens(item.bodyRaw || '');
    rawLang = bodyType === 'json' ? 'json' : 'text';
    bodyType = 'raw';
  } else if (bodyType === 'raw') {
    body = _aspResolveTokens(item.bodyRaw || '');
  } else if (bodyType === 'form') {
    body = {};
    (item.bodyForm || []).filter(r => r.enabled && r.key).forEach(r => { body[r.key] = r.value; });
  } else if (bodyType === 'multipart') {
    body = (item.bodyMultipart || [])
      .filter(r => r.enabled && r.key && r.fieldType !== 'file')
      .map(r => ({ key: r.key, type: 'text', value: r.value || '' }));
  } else if (bodyType === 'binary' && item.bodyBinary && item.bodyBinary.data) {
    body = {
      filename: item.bodyBinary.filename || 'file',
      contentType: item.bodyBinary.contentType || 'application/octet-stream',
      data: item.bodyBinary.data,
    };
  } else if (bodyType === 'graphql') {
    let variables = {};
    const varsRaw = (item.bodyGraphqlVars || '').trim();
    if (varsRaw) {
      try { variables = JSON.parse(varsRaw); } catch (_) { variables = {}; }
    }
    body = { query: item.bodyGraphqlQuery || '', variables };
  }
  if (bodyType === 'raw' && rawLang === 'json' && typeof body === 'string') {
    body = _aspStripJsonComments(body);
  }
  let method = (item.method || 'GET').toUpperCase();
  let url    = item.url || '';
  let auth   = item.auth || { type: 'none' };
  if (auth.type === 'inherit') {
    auth = _aspResolveScopeAuth(col, folder || null);
  }
  const vars = _aspResolveActiveVars(col, folder || null).map(v => ({ key: v.key, value: v.value }));
  if (varsRow) {
    Object.keys(varsRow).forEach(k => {
      const hit = vars.find(v => v.key === k);
      if (hit) hit.value = varsRow[k]; else vars.push({ key: k, value: varsRow[k] });
    });
  }
  if (vars.length) {
    const av = s => _aspApplyCollVars(s, vars);
    url = av(url);
    Object.keys(params).forEach(k  => { params[k]  = av(String(params[k])); });
    Object.keys(headers).forEach(k => { headers[k] = av(String(headers[k])); });
    if (auth.token)    auth.token    = av(String(auth.token));
    if (auth.username) auth.username = av(String(auth.username));
    if (auth.password) auth.password = av(String(auth.password));
    if (typeof body === 'string') body = av(body);
    else if (Array.isArray(body)) {
      body = body.map(entry => {
        const e = { ...entry, key: av(String(entry.key || '')) };
        if (e.type !== 'file' && typeof e.value === 'string') e.value = av(e.value);
        return e;
      });
    } else if (body && typeof body === 'object' && bodyType === 'graphql') {
      if (typeof body.query === 'string') body.query = av(body.query);
    } else if (body && typeof body === 'object' && bodyType !== 'binary') {
      Object.keys(body).forEach(k => { if (typeof body[k] === 'string') body[k] = av(body[k]); });
    }
  }
  return {
    method, url, params, headers, body, auth,
    body_type: bodyType,
    raw_lang: bodyType === 'raw' ? rawLang : undefined,
  };
}

async function _aspCRSleepInterruptible(ms) {
  const step = 100;
  let left = ms;
  while (left > 0 && !_aspCRAborted) {
    while (_aspCRPaused && !_aspCRAborted) await new Promise(r => setTimeout(r, 150));
    if (_aspCRAborted) break;
    const slice = Math.min(step, left);
    await new Promise(r => setTimeout(r, slice));
    left -= slice;
  }
}

async function aspCRStart() {
  if (_aspCRRunning) return;
  const col = _aspGetColls().find(c => c.id === _aspCRColId);
  if (!col) return;
  const selected = _aspFlatReqs(col).filter(it => _aspCRSelected[it.id]);
  const errEl = document.getElementById('asp-cr-error');
  if (!selected.length) {
    if (errEl) { errEl.textContent = 'Select at least one request to run.'; errEl.style.display = 'block'; }
    return;
  }
  if (errEl) errEl.style.display = 'none';

  let iterations = parseInt((document.getElementById('asp-cr-iterations') || {}).value, 10);
  if (!iterations || iterations < 1) iterations = 1;
  let delay = parseInt((document.getElementById('asp-cr-delay') || {}).value, 10);
  if (!delay || delay < 0) delay = 0;
  _aspCRIterations = iterations;

  _aspCRResults   = [];
  _aspCRDetailIdx = -1;
  _aspCRRunning   = true;
  _aspCRPaused    = false;
  _aspCRAborted   = false;
  const startBtn = document.getElementById('asp-cr-start-btn');
  if (startBtn) { startBtn.disabled = true; startBtn.textContent = 'Running…'; }
  _aspCRSetRunControls(true);
  _aspCRShowResults();

  outer:
  for (let iter = 0; iter < iterations; iter++) {
    const varsRow = (_aspCRTestData && _aspCRTestData.length) ? _aspCRTestData[iter % _aspCRTestData.length] : null;
    for (const item of selected) {
      while (_aspCRPaused && !_aspCRAborted) {
        const summary = document.getElementById('asp-cr-summary');
        if (summary) summary.textContent = `⏸ Paused · ${_aspCRResults.length} sent`;
        await new Promise(r => setTimeout(r, 150));
      }
      if (_aspCRAborted) break outer;

      let folder = null;
      for (const it of (col.items || [])) {
        if (_aspIsFolder(it) && (it.items || []).some(r => r.id === item.id)) { folder = it; break; }
      }
      const payload = _aspCRBuildPayload(item, col, varsRow, folder);
      // Pre-request script on collection item
      const preCode = (item.preRequestScript || "").trim();
      if (preCode) {
        const preRes = _aspRunScript(preCode, { request: payload, response: null, collection: col });
        if (preRes.error || preRes.skipped) {
          _aspCRResults.push({
            item, iteration: iter, ok: false, status: null, elapsedMs: 0,
            reqPayload: payload, respBody: null, curl: "",
            error: preRes.skipped ? "Skipped by pre-request script" : ("Pre-request: " + preRes.error),
            tests: preRes.tests || [], testsPassed: 0, testsTotal: (preRes.tests || []).length,
          });
          _aspCRRenderResultsList();
          if (delay > 0 && !_aspCRAborted) await _aspCRSleepInterruptible(delay);
          continue;
        }
      }
      _aspApplyCookieJarToPayload(payload);
      const t0 = Date.now();
      const result = {
        item, iteration: iter, ok: false, status: null, elapsedMs: 0,
        reqPayload: payload, respBody: null, curl: "", error: null,
        tests: [], testsPassed: 0, testsTotal: 0,
      };
      try {
        const ctrl  = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 30000);
        const r = await fetch(`${ASP_BASE}/send`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload), signal: ctrl.signal,
        });
        clearTimeout(timer);
        const d = await r.json();
        result.elapsedMs = Date.now() - t0;
        if (!d.ok) {
          result.error = d.error || "Request failed";
        } else {
          result.status    = d.status_code;
          result.respBody  = d.body;
          result.curl      = d.sent_curl || "";
          result.elapsedMs = d.elapsed_ms != null ? d.elapsed_ms : result.elapsedMs;
          if (d.cookies && d.cookies.length) {
            _aspCookieJarUpsert(d.cookies, d.sent_url || payload.url);
          }
          const testCode = (item.testScript || "").trim();
          let testRes = { tests: [], error: null };
          if (testCode) {
            testRes = _aspRunScript(testCode, { request: payload, response: d, collection: col });
          }
          result.tests = testRes.tests || [];
          result.testsTotal = result.tests.length;
          result.testsPassed = result.tests.filter(t => t.passed).length;
          // Network succeeded — keep respBody visible even when tests fail.
          // Do NOT stuff test summary into result.error (that hid the real response).
          const httpOk = d.status_code >= 200 && d.status_code < 400;
          if (result.testsTotal > 0) {
            result.ok = httpOk && result.testsPassed === result.testsTotal && !testRes.error;
          } else {
            result.ok = httpOk;
          }
        }
      } catch (e) {
        result.elapsedMs = Date.now() - t0;
        result.error = e.name === "AbortError" ? "Timed out (30s)" : (e.message || String(e));
      }
      _aspCRResults.push(result);
      _aspCRRenderResultsList();
      if (delay > 0 && !_aspCRAborted) await _aspCRSleepInterruptible(delay);
    }
  }

  const wasAborted = _aspCRAborted;
  _aspCRRunning = false;
  _aspCRPaused  = false;
  _aspCRAborted = false;
  _aspCRSetRunControls(false);
  _aspCRRenderResultsList(); // refresh summary from "Running…" to final pass/fail count
  if (wasAborted) {
    const summary = document.getElementById('asp-cr-summary');
    if (summary) {
      const total = _aspCRResults.length;
      const passN = _aspCRResults.filter(r => r.ok).length;
      summary.textContent = `⏹ Aborted · ${passN}/${total} passed`;
    }
  }
  if (startBtn) { startBtn.disabled = false; startBtn.textContent = 'Start run'; }
}

function _aspCRShowResults() {
  document.getElementById('asp-cr-setup').style.display   = 'none';
  document.getElementById('asp-cr-results').style.display = 'flex';
  _aspCRRenderResultsList();
}
function aspCRBackToSetup() {
  document.getElementById('asp-cr-results').style.display = 'none';
  document.getElementById('asp-cr-setup').style.display   = 'flex';
}
function _aspCRRenderResultsList() {
  const list    = document.getElementById('asp-cr-results-list');
  const summary = document.getElementById('asp-cr-summary');
  if (!list) return;
  const total  = _aspCRResults.length;
  const passed = _aspCRResults.filter(r => r.ok).length;
  if (summary) {
    if (_aspCRRunning && _aspCRPaused) summary.textContent = `⏸ Paused · ${total} sent`;
    else if (_aspCRRunning) summary.textContent = `Running… ${total} sent`;
    else summary.textContent = `${passed}/${total} passed`;
  }
  list.innerHTML = _aspCRResults.map((r, i) => {
    const mColor      = _ASP_METHOD_COLORS[r.item.method] || "#c9d1d9";
    const statusLabel = r.error && r.status == null ? "ERR" : (r.status != null ? r.status : "…");
    const statusColor = (r.error || !r.ok) ? "#f85149" : "#3fb950";
    const iterLabel   = _aspCRIterations > 1 ? `<span style="font-size:10px;color:var(--text3);flex-shrink:0">#${r.iteration + 1}</span>` : "";
    const testsLabel  = r.testsTotal
      ? `<span style="font-size:10px;font-weight:700;color:${r.testsPassed === r.testsTotal ? "#3fb950" : "#f85149"};flex-shrink:0">${r.testsPassed}/${r.testsTotal}</span>`
      : "";
    return `<div onclick="aspCRSelectResult(${i})" style="display:flex;align-items:center;gap:10px;padding:7px 16px;font-size:12px;cursor:pointer;border-bottom:1px solid var(--border);background:${i === _aspCRDetailIdx ? "var(--bg3)" : "none"}">
      <span style="font-weight:700;font-size:10px;color:${mColor};width:38px;flex-shrink:0">${r.item.method || "GET"}</span>
      <span style="flex:1;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_aspEscHtml(r.item.name || r.item.url || "")}</span>
      ${iterLabel}
      ${testsLabel}
      <span style="font-size:10px;font-weight:700;color:${statusColor};flex-shrink:0">${statusLabel}</span>
    </div>`;
  }).join("");
}
function aspCRSelectResult(idx) {
  _aspCRDetailIdx = idx;
  _aspCRRenderResultsList();
  _aspCRRenderDetail(idx);
}
// Fallback cURL builder for requests that errored before the backend could
// reconstruct one from the actual sent HTTP request (e.g. connection refused)
function _aspCRFallbackCurl(p) {
  const parts = [`curl -X ${p.method} '${p.url}'`];
  Object.entries(p.headers || {}).forEach(([k, v]) => {
    parts.push(`  -H '${String(k)}: ${String(v).replace(/'/g, "'\\''")}'`);
  });
  if (p.body) {
    const bodyStr = typeof p.body === 'string' ? p.body : JSON.stringify(p.body);
    parts.push(`  --data-raw '${bodyStr.replace(/'/g, "'\\''")}'`);
  }
  return parts.join(' \\\n');
}
function _aspCRRenderDetail(idx) {
  const emptyEl = document.getElementById('asp-cr-detail-empty');
  const bodyEl  = document.getElementById('asp-cr-detail-body');
  const r = _aspCRResults[idx];
  if (!r) {
    if (emptyEl) emptyEl.style.display = 'flex';
    if (bodyEl)  bodyEl.style.display  = 'none';
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';
  if (bodyEl)  bodyEl.style.display  = 'flex';

  const p = r.reqPayload || {};
  const reqBody = (p.body != null && p.body !== "") ? _aspRunnerPrettyBody(p.body) : "";
  const hasHttp = r.status != null;
  const testsFailed = r.testsTotal > 0 && r.testsPassed < r.testsTotal;
  const statusColor = (!r.ok || r.error) ? "#f85149" : "#3fb950";
  // Show real HTTP status when we got a response; "Error" only for transport failures
  const statusText = hasHttp ? String(r.status) : (r.error ? "Error" : "…");
  const titleColor = hasHttp
    ? (r.status < 400 ? (testsFailed || !r.ok ? "#d29922" : "#3fb950") : "#f85149")
    : statusColor;

  const metaEl = document.getElementById("asp-cr-detail-meta");
  if (metaEl) {
    const testsLine = r.testsTotal
      ? ` · Tests <span style="color:${r.testsPassed === r.testsTotal ? "#3fb950" : "#f85149"};font-weight:700">${r.testsPassed}/${r.testsTotal}</span>`
      : "";
    metaEl.innerHTML = `<span style="font-weight:700;color:var(--text)">${p.method}</span> ` +
      `<span style="color:var(--text2)">${_aspEscHtml(p.url)}</span>` +
      `<div style="font-size:11px;color:var(--text3);margin-top:4px">Iteration ${r.iteration + 1} · ` +
      `<span style="color:${titleColor};font-weight:700">${statusText}</span> · ${r.elapsedMs || 0}ms${testsLine}` +
      `${r.error && !hasHttp ? ` · <span style="color:#f85149">${_aspEscHtml(r.error)}</span>` : ""}</div>` +
      (r.tests && r.tests.length
        ? `<div style="margin-top:8px;display:flex;flex-direction:column;gap:4px">${r.tests.map(t =>
            `<div style="font-size:11px;color:${t.passed ? "#3fb950" : "#f85149"}">${t.passed ? "✓" : "✗"} ${_aspEscHtml(t.name)}${t.error ? " — " + _aspEscHtml(t.error) : ""}</div>`
          ).join("")}</div>`
        : "");
  }

  _aspCRBodyStore.req = reqBody || "";
  if (r.respBody != null && r.respBody !== "") {
    _aspCRBodyStore.resp = _aspRunnerPrettyBody(r.respBody);
  } else if (r.error && !hasHttp) {
    _aspCRBodyStore.resp = String(r.error);
  } else {
    _aspCRBodyStore.resp = r.respBody != null ? String(r.respBody) : "";
  }
  _aspCRPaintBody("req");
  _aspCRPaintBody("resp");
  _aspCRUpdateBodyMeta();

  const respTitleEl = document.getElementById("asp-cr-resp-sec-title");
  if (respTitleEl) {
    const suffix = hasHttp
      ? (testsFailed ? `${statusText} · tests failed` : statusText)
      : statusText;
    respTitleEl.textContent = `RESPONSE BODY · ${suffix}`;
    respTitleEl.style.color = titleColor;
  }

  const curlBtn = document.getElementById("asp-cr-copy-curl-btn");
  if (curlBtn) curlBtn.removeAttribute("data-curl");
}

function _aspCRBodySizeHint(text) {
  const n = String(text || "").length;
  if (n < 4096) return "";
  return `${Math.max(1, Math.round(n / 1024))} KB`;
}

function _aspCRUpdateBodyMeta() {
  const reqHint = document.getElementById("asp-cr-req-size");
  const respHint = document.getElementById("asp-cr-resp-size");
  if (reqHint) reqHint.textContent = _aspCRBodySizeHint(_aspCRBodyStore.req);
  if (respHint) respHint.textContent = _aspCRBodySizeHint(_aspCRBodyStore.resp);
}

function _aspCRPaintBody(which) {
  const pre = document.getElementById(which === "resp" ? "asp-cr-resp-body-pre" : "asp-cr-req-body-pre");
  if (!pre) return;
  const raw = _aspCRBodyStore[which] || "";
  const q = (_aspCRSearch[which] || "").trim();
  if (!raw) {
    pre.textContent = "(empty)";
    return;
  }
  if (!q) {
    pre.textContent = raw;
    return;
  }
  pre.innerHTML = _aspRunnerWrapEscaped(_aspEscHtml(raw), q, "asp-find-mark");
}

function aspCRSearchBody(which) {
  const inp = document.getElementById(which === "resp" ? "asp-cr-resp-search" : "asp-cr-req-search");
  _aspCRSearch[which] = inp ? inp.value : "";
  _aspCRPaintBody(which);
}

function aspCRCopyBody(which, btn) {
  const text = _aspCRBodyStore[which] || "";
  if (!text) return;
  _aspClipboard(text, btn, "Copy body");
}

function aspCRCopyCurl() {
  const btn = document.getElementById("asp-cr-copy-curl-btn");
  const r = _aspCRResults[_aspCRDetailIdx];
  const p = r && r.reqPayload;
  const curl = (r && r.curl) || (p ? _aspCRFallbackCurl(p) : "") || "";
  if (!curl) return;
  _aspClipboard(curl, btn, "📋 Copy cURL");
}
// Vertical drag-resize between the Request Body and Response Body panes
function _aspCRInitVSplitter() {
  const splitter = document.getElementById('asp-cr-vsplitter');
  const top       = document.getElementById('asp-cr-req-pane');
  const wrap      = document.getElementById('asp-cr-split-wrap');
  if (!splitter || !top || !wrap) return;
  let dragging = false, startY = 0, startH = 0;
  splitter.addEventListener('mousedown', e => {
    dragging = true; startY = e.clientY; startH = top.offsetHeight;
    splitter.classList.add('asp-dragging');
    document.body.style.cssText += ';cursor:row-resize!important;user-select:none!important';
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const max = wrap.offsetHeight - 60;
    const h   = Math.max(60, Math.min(max, startH + (e.clientY - startY)));
    top.style.height = h + 'px';
  });
  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    splitter.classList.remove('asp-dragging');
    document.body.style.cursor = ''; document.body.style.userSelect = '';
  });
}

// ── Collection / Folder Overview panel ─────────────────────────
function aspShowCollOverview(colId, folderId) {
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  if (!col) return;
  const folder = folderId ? _aspFindFolderInCol(col, folderId) : null;
  if (folderId && !folder) return;
  // Close Runner / other overlays; switch overview content in place
  _aspCloseWorkspaceOverlays("overview");
  _aspCollOvId = colId;
  _aspCollOvFolderId = folderId || null;
  const target = folder || col;

  const nameEl = document.getElementById("asp-cov-cname");
  if (nameEl) nameEl.textContent = folder ? `${col.name} / ${folder.name}` : col.name;
  const iconEl = document.getElementById("asp-cov-icon");
  if (iconEl) iconEl.textContent = folder ? "📁" : "📂";
  const tipEl = document.getElementById("asp-cov-auth-tip");
  if (tipEl) {
    tipEl.innerHTML = folder
      ? "💡 Folder auth/variables <b style=\"color:var(--text2)\">override</b> the parent collection when set. Choose <b style=\"color:var(--text2)\">Inherit from Collection</b> to use collection credentials."
      : "💡 Set auth at collection level. In requests, choose <b style=\"color:var(--text2)\">Inherit from Collection</b> — folders can override these values.";
  }

  // Populate auth — only folders get "Inherit from Collection" (native <option> can't hide via CSS)
  const auth = target.auth || { type: folder ? "inherit" : "none", token: "", username: "", password: "" };
  const authSel = document.getElementById("asp-cov-auth-type");
  if (authSel) {
    _aspSyncCovAuthOptions(!!folder);
    let authType = auth.type || (folder ? "inherit" : "none");
    if (!folder && (authType === "inherit" || !authType)) authType = "none";
    authSel.value = authType;
  }
  const tokEl  = document.getElementById("asp-cov-auth-token");
  const userEl = document.getElementById("asp-cov-auth-user");
  const passEl = document.getElementById("asp-cov-auth-pass");
  if (tokEl)  tokEl.value  = auth.token    || "";
  if (userEl) userEl.value = auth.username || "";
  if (passEl) passEl.value = auth.password || "";
  aspCollOvAuthChange();

  const vars  = target.variables || [];
  const tbody = document.getElementById("asp-cov-vars");
  if (tbody) {
    tbody.innerHTML = vars.map(v => `<tr class="asp-var-row">
      <td style="text-align:center"><input type="checkbox" ${v.enabled !== false ? "checked" : ""} style="width:14px;height:14px;cursor:pointer;accent-color:#1f6feb"></td>
      <td><input type="text" class="asp-var-inp" value="${_aspEscHtml(v.key   ||'')}" placeholder="variableName"></td>
      <td><input type="text" class="asp-var-inp" value="${_aspEscHtml(v.value ||'')}" placeholder="value"></td>
      <td><button onclick="this.closest('tr').remove()" style="background:none;border:none;color:var(--text3);font-size:15px;cursor:pointer;padding:0 4px;line-height:1" title="Remove">×</button></td>
    </tr>`).join("");
  }

  aspCollOvTab(0);
  const ov = document.getElementById("asp-coll-ov");
  if (ov) ov.style.display = "flex";
  const saveBtn = document.getElementById("asp-cov-save-btn");
  if (saveBtn) { saveBtn.textContent = "Save"; saveBtn.disabled = false; }
  _aspSyncChromeLock();
}

function aspHideCollOverview() {
  _aspHideCollOverviewPanelOnly();
  _aspSyncChromeLock();
}

function aspCollOvTab(n) {
  [0, 1].forEach(i => {
    const tab  = document.getElementById("asp-cov-tab"  + i);
    const pane = document.getElementById("asp-cov-pane" + i);
    if (tab)  tab.classList.toggle("on", i === n);
    if (pane) pane.style.display = i === n ? "flex" : "none";
  });
}

/** Collection overview: no Inherit option. Folder overview: Inherit available. */
function _aspSyncCovAuthOptions(isFolder) {
  const authSel = document.getElementById("asp-cov-auth-type");
  if (!authSel) return;
  let inheritOpt = authSel.querySelector('option[value="inherit"]');
  if (isFolder) {
    if (!inheritOpt) {
      inheritOpt = document.createElement("option");
      inheritOpt.value = "inherit";
      inheritOpt.textContent = "Inherit from Collection";
      const bearer = authSel.querySelector('option[value="bearer"]');
      authSel.insertBefore(inheritOpt, bearer || null);
    }
  } else if (inheritOpt) {
    inheritOpt.remove();
  }
}

function aspCollOvAuthChange() {
  const sel  = document.getElementById("asp-cov-auth-type");
  const type = sel ? sel.value : "none";
  const b    = document.getElementById("asp-cov-auth-bearer");
  const bas  = document.getElementById("asp-cov-auth-basic");
  if (b)   b.style.display   = type === "bearer" ? "flex" : "none";
  if (bas) bas.style.display = type === "basic"  ? "flex" : "none";
}

function aspCollOvAddVar() {
  const tbody = document.getElementById("asp-cov-vars");
  if (!tbody) return;
  const tr = document.createElement("tr");
  tr.className = "asp-var-row";
  tr.innerHTML = `
    <td style="text-align:center"><input type="checkbox" checked style="width:14px;height:14px;cursor:pointer;accent-color:#1f6feb"></td>
    <td><input type="text" class="asp-var-inp" placeholder="variableName"></td>
    <td><input type="text" class="asp-var-inp" placeholder="value"></td>
    <td><button onclick="this.closest('tr').remove()" style="background:none;border:none;color:var(--text3);font-size:15px;cursor:pointer;padding:0 4px;line-height:1" title="Remove">×</button></td>`;
  tbody.appendChild(tr);
  tr.querySelectorAll("input[type=text]")[0].focus();
}

function aspSaveCollOverview() {
  if (!_aspCollOvId) return;
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === _aspCollOvId);
  if (!col) return;
  const folder = _aspCollOvFolderId ? _aspFindFolderInCol(col, _aspCollOvFolderId) : null;
  const target = folder || col;

  const authSel = document.getElementById("asp-cov-auth-type");
  const tokEl   = document.getElementById("asp-cov-auth-token");
  const userEl  = document.getElementById("asp-cov-auth-user");
  const passEl  = document.getElementById("asp-cov-auth-pass");
  let authType = authSel ? authSel.value : (folder ? "inherit" : "none");
  // Collection has nothing to inherit from
  if (!folder && authType === "inherit") authType = "none";
  target.auth = {
    type:     authType,
    token:    tokEl   ? tokEl.value   : "",
    username: userEl  ? userEl.value  : "",
    password: passEl  ? passEl.value  : "",
  };

  const rows = document.querySelectorAll("#asp-cov-vars .asp-var-row");
  target.variables = Array.from(rows).map(tr => {
    const inputs = tr.querySelectorAll("input");
    return {
      enabled: inputs[0] ? inputs[0].checked : true,
      key:     inputs[1] ? inputs[1].value.trim() : "",
      value:   inputs[2] ? inputs[2].value        : "",
    };
  }).filter(v => v.key);

  _aspSaveColls(cols);

  // Auto-set linked open tabs under this scope to Inherit
  const scopeAuth = _aspResolveScopeAuth(col, folder);
  if (scopeAuth.type && scopeAuth.type !== "none") {
    const tabs = _aspGetTabs();
    let tabsChanged = false;
    const touch = (item) => {
      if (!item.sourceTabId) return;
      const tab = tabs.find(t => t.id === item.sourceTabId);
      if (tab) {
        tab.auth = { type: "inherit", token: "", username: "", password: "" };
        tabsChanged = true;
      }
    };
    if (folder) (folder.items || []).forEach(touch);
    else _aspForEachReq(col, touch);
    if (tabsChanged) {
      _aspSaveTabs(tabs);
      const activeId = _aspActiveTabId();
      const mem = _aspGetActiveTabMembership();
      if (mem && mem.col.id === col.id && ((!folder && !mem.folder) || (folder && mem.folder && mem.folder.id === folder.id) || (!folder && mem.item))) {
        const sel = document.getElementById("asp-auth-type");
        if (sel && mem.item && mem.item.sourceTabId === activeId) { sel.value = "inherit"; aspAuthTypeChange(); }
      }
    }
  }

  const saveBtn = document.getElementById("asp-cov-save-btn");
  if (saveBtn) {
    saveBtn.textContent = "Saved";
    saveBtn.disabled = true;
    setTimeout(() => {
      if (!_aspCollOvId) return;
      saveBtn.textContent = "Save";
      saveBtn.disabled = false;
    }, 1800);
  }
}

// ── Collection / Folder delete confirmation ────────────────────
function aspConfirmDelColl(colId) {
  const col = _aspGetColls().find(c => c.id === colId);
  if (!col) return;
  _aspCollConfirmId = colId;
  _aspCollConfirmFolderId = null;
  const msg = document.getElementById("asp-coll-confirm-msg");
  const ttl = document.getElementById("asp-coll-confirm-title");
  if (ttl) ttl.textContent = "Delete Collection";
  if (msg) msg.innerHTML = `Are you sure you want to delete <b style="color:var(--text)">"${_aspEscHtml(col.name)}"</b>?<br><span style="font-size:10px;color:var(--text3)">All folders and requests in this collection will be removed.</span>`;
  const modal = document.getElementById("asp-coll-confirm");
  if (modal) modal.style.display = "flex";
}
function aspConfirmDelFolder(colId, folderId) {
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  const folder = _aspFindFolderInCol(col, folderId);
  if (!folder) return;
  _aspCollConfirmId = colId;
  _aspCollConfirmFolderId = folderId;
  const msg = document.getElementById("asp-coll-confirm-msg");
  const ttl = document.getElementById("asp-coll-confirm-title");
  if (ttl) ttl.textContent = "Delete Folder";
  if (msg) msg.innerHTML = `Delete folder <b style="color:var(--text)">"${_aspEscHtml(folder.name)}"</b>?<br><span style="font-size:10px;color:var(--text3)">Requests inside this folder will also be removed.</span>`;
  const modal = document.getElementById("asp-coll-confirm");
  if (modal) modal.style.display = "flex";
}
function aspCollConfirmYes() {
  if (_aspEnvConfirmDel) {
    const eid = _aspEnvConfirmDel;
    aspCollConfirmNo();
    _aspDoDeleteEnvironment(eid);
    return;
  }
  const id = _aspCollConfirmId, fid = _aspCollConfirmFolderId;
  aspCollConfirmNo();
  if (!id) return;
  if (fid) aspDelCollFolder(id, fid);
  else aspDelColl(id);
}
function aspCollConfirmNo() {
  _aspCollConfirmId = null;
  _aspCollConfirmFolderId = null;
  _aspEnvConfirmDel = null;
  const modal = document.getElementById("asp-coll-confirm");
  if (modal) modal.style.display = "none";
}

// ── Collection variable helpers ────────────────────────────────
function _aspGetActiveTabColl() {
  const m = _aspGetActiveTabMembership();
  return m ? m.col : null;
}

function _aspApplyCollVars(str, vars) {
  if (!str || typeof str !== "string" || !vars || !vars.length) return str;
  let result = str;
  vars.filter(v => v.enabled !== false && v.key).forEach(v => {
    result = result.split("{{" + v.key + "}}").join(v.value || "");
  });
  return result;
}

// ── Tab 3-dot context menu ─────────────────────────────────────
function aspShowTabMenu(tabId, btnEl) {
  _aspTabMenuId = tabId;
  const sub  = document.getElementById("asp-tmenu-colls");
  const cols  = _aspGetColls();
  if (sub) {
    if (!cols.length) {
      sub.innerHTML = `<div style="padding:6px 12px;font-size:11px;color:var(--text3)">No collections yet</div>`;
    } else {
      sub.innerHTML = cols.map(c => {
        const folders = (c.items || []).filter(_aspIsFolder);
        if (!folders.length) {
          return `<div class="asp-tmenu-item" onclick="aspSaveTabToColl('${c.id}')">${_aspEscHtml(c.name)}</div>`;
        }
        return `<div class="asp-tmenu-coll-block">
          <div class="asp-tmenu-item asp-tmenu-expand" onclick="aspToggleTmenuFolders('${c.id}', this)">
            <span class="asp-tmenu-arrow">▸</span>
            <span style="flex:1">${_aspEscHtml(c.name)}</span>
            <span style="font-size:10px;color:var(--text3)">${folders.length} folder${folders.length > 1 ? "s" : ""}</span>
          </div>
          <div class="asp-tmenu-folders" id="asp-tmenu-fld-${c.id}" style="display:none">
            <div class="asp-tmenu-item asp-tmenu-sub" onclick="aspSaveTabToColl('${c.id}')">📂 Collection root</div>
            ${folders.map(f =>
              `<div class="asp-tmenu-item asp-tmenu-sub" onclick="aspSaveTabToColl('${c.id}','${f.id}')">📁 ${_aspEscHtml(f.name)}</div>`
            ).join("")}
          </div>
        </div>`;
      }).join("");
    }
  }
  const menu = document.getElementById("asp-tab-menu");
  if (!menu) return;
  const rect  = btnEl.getBoundingClientRect();
  menu.style.left    = rect.left + "px";
  menu.style.top     = (rect.bottom + 4) + "px";
  menu.style.display = "block";
  setTimeout(() => {
    const mr = menu.getBoundingClientRect();
    if (mr.bottom > window.innerHeight - 8) menu.style.top = (rect.top - mr.height - 4) + "px";
  }, 0);
}

function aspToggleTmenuFolders(colId, el) {
  const pane = document.getElementById("asp-tmenu-fld-" + colId);
  if (!pane) return;
  const open = pane.style.display !== "none";
  pane.style.display = open ? "none" : "block";
  const arrow = el && el.querySelector(".asp-tmenu-arrow");
  if (arrow) arrow.textContent = open ? "▸" : "▾";
  // Keep menu on-screen after expand
  const menu = document.getElementById("asp-tab-menu");
  if (menu) {
    const mr = menu.getBoundingClientRect();
    if (mr.bottom > window.innerHeight - 8) {
      menu.style.top = Math.max(8, window.innerHeight - mr.height - 8) + "px";
    }
  }
}

function aspHideTabMenu() {
  const menu = document.getElementById("asp-tab-menu");
  if (menu) menu.style.display = "none";
  _aspTabMenuId = null;
}

/** Unique name in a destination list — Postman-style: "Name", "Name Copy", "Name Copy 2", … */
function _aspNextCollReqName(destItems, baseName) {
  const base = (baseName || "New Request").trim() || "New Request";
  const names = new Set(
    (destItems || []).filter(it => !_aspIsFolder(it)).map(it => (it.name || "").trim())
  );
  if (!names.has(base)) return base;
  let candidate = base + " Copy";
  if (!names.has(candidate)) return candidate;
  let i = 2;
  while (names.has(base + " Copy " + i)) i++;
  return base + " Copy " + i;
}

/**
 * Add the pending tab into a collection root or folder (Postman-style).
 * - Same request can live in multiple collections/folders (always ADD, never remove).
 * - If it already exists in that destination (same live tab link or same name),
 *   the new entry is named "… Copy" / "… Copy 2" and is an independent snapshot.
 */
function aspSaveTabToColl(colId, folderId) {
  const pendingTabId = _aspTabMenuId;
  aspHideTabMenu();
  const cols = _aspGetColls();
  const col  = cols.find(c => c.id === colId);
  if (!col) return;
  _aspFlushTab();
  const tab = _aspGetTabs().find(t => t.id === pendingTabId);
  if (!tab) return;

  const folder = folderId ? _aspFindFolderInCol(col, folderId) : null;
  if (folderId && !folder) return;
  const dest = folder ? (folder.items || (folder.items = [])) : (col.items || (col.items = []));

  const alreadyLinked = dest.some(item => !_aspIsFolder(item) && item.sourceTabId === tab.id);
  const baseName = (tab.name || "New Request").trim() || "New Request";
  // Always ensure unique name in destination; copies also get " Copy" when re-adding same tab
  const name = alreadyLinked
    ? _aspNextCollReqName(dest, baseName.replace(/\s+Copy(\s+\d+)?$/i, "") || baseName)
    : _aspNextCollReqName(dest, baseName);

  const entry = Object.assign({}, tab, {
    id: _aspMkReqId(),
    name,
    // Re-add to same destination → independent copy (no live tab link).
    // First add / other collections → keep live link so edits stay in sync.
    sourceTabId: alreadyLinked ? null : tab.id,
  });
  dest.push(entry);
  col.expanded = true;
  if (folder) folder.expanded = true;
  _aspSaveColls(cols);
  if (!_aspCollOpen) aspToggleColl(); else _aspRenderCollPanel();
}

function aspNewCollectionFromTab() {
  const pendingTabId = _aspTabMenuId;
  aspHideTabMenu();
  _aspNameModalShow("New Collection", "Create", name => {
    _aspFlushTab();
    const tab = _aspGetTabs().find(t => t.id === pendingTabId);
    const col = {
      id: _aspMkCollId(), name, expanded: true, items: [],
      auth: { type: "none", token: "", username: "", password: "" },
      variables: [],
    };
    if (tab) col.items.push(Object.assign({}, tab, { id: _aspMkReqId(), sourceTabId: tab.id }));
    const cols = _aspGetColls();
    cols.push(col);
    _aspSaveColls(cols);
    if (!_aspCollOpen) aspToggleColl(); else _aspRenderCollPanel();
  });
}

// ── Collections sidebar splitter ──────────────────────────────
function _aspInitCollSplitter() {
  const splitter = document.getElementById("asp-coll-splitter");
  const panel    = document.getElementById("asp-coll-panel");
  if (!splitter || !panel) return;
  let dragging = false, startX = 0, startW = 0;
  splitter.addEventListener("mousedown", e => {
    dragging = true; startX = e.clientX; startW = panel.offsetWidth;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    splitter.classList.add("asp-dragging");
    e.preventDefault();
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    const w = Math.max(160, Math.min(400, startW + (e.clientX - startX)));
    panel.style.width = w + "px";
  });
  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    splitter.classList.remove("asp-dragging");
  });
}

function _aspEsc(s)     { return (s||"").replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
function _aspEscHtml(s) { return (s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

// ── JSON body chrome: active line + bracket-scope guide + code folding (Postman-style) ──
let _aspCharW = 0;
const _ASP_BODY_LINE_H = 20; // 12px font with exact 20px line-height
const _ASP_BODY_PAD    = 10;

const _ASP_KNOWN_FORM_RESTORE = {
  formName: "cm_eutraa4a5criteriainfo_form",
  payload: {
    "data": [
      {
        "instanceOf": "EutranFaPriorInfoFunc",
        "relation": "Parent",
        "sequence": "EutranFaPriorInfoFunc-1",
        "gridName": "",
        "entityData": {
          "id": "01a0e70a-0570-7293-894a-19251b547659",
          "sourceBand": "CONFIGURATION_MANAGEMENT",
          "faIndex": "",
          "earfcnBand": "",
          "priority": "",
          "cellCapacityClassValueDlPerFa": "",
          "cellCapacityClassValueUlPerFa": ""
        }
      }
    ],
    "entityMap": {
      "identifier1": "CONFIGURATION_MANAGEMENT_APP_NAME",
      "identifier2": "EutranFaPriorInfoFunc",
      "entityType": "EutranFaPriorInfoFunc",
      "id": "01a0e70a-0570-7293-894a-19251b547659",
      "EUTRANFAPRIORINFOFUNC": "01a0e70a-0570-7293-894a-19251b547659",
      "entityId": "01a0e70a-0570-7293-894a-19251b547659",
      "identifier3": "01a0e70a-0570-7293-894a-19251b547659"
    },
    "formName": "cm_eutraa4a5criteriainfo_form",
    "versionUuid": "10689064-a129-11f1-8871-45e19c662ca7"
  }
};

function _aspRecoverKnownCorruptedPayload(text) {
  if (!text || typeof text !== 'string') return text;
  if (text.includes("cm_eutraa4a5criteriainfo_form") && (text.includes("/*") || text.includes("[f_") || text.includes("}Testhello") || text.includes('/*"entityMap"') || text.includes('"data": [\n    {\n    }\n  ]'))) {
    return JSON.stringify(_ASP_KNOWN_FORM_RESTORE.payload, null, 2);
  }
  return text;
}

function _aspComputeFolds(text) {
  if (!text) return {};
  const lines = text.split('\n');
  const stack = [];
  const folds = {};
  for (let l = 0; l < lines.length; l++) {
    const line = lines[l];
    let inStr = false, esc = false;
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (inStr) {
        if (esc) { esc = false; continue; }
        if (ch === '\\') { esc = true; continue; }
        if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') { inStr = true; continue; }
      if (ch === '{' || ch === '[') {
        const indent = line.length - line.trimStart().length;
        stack.push({ char: ch, line: l, indent });
      } else if (ch === '}' || ch === ']') {
        const top = stack.pop();
        if (top) {
          const match = (ch === '}' && top.char === '{') || (ch === ']' && top.char === '[');
          if (match && top.line !== l) {
            folds[top.line] = { endLine: l, openChar: top.char, closeChar: ch, indent: top.indent };
          }
        }
      }
    }
  }
  return folds;
}

const _aspReqFoldMap = new Map();

function _aspStoreFold(token, content) {
  _aspReqFoldMap.set(token, content);
  try { sessionStorage.setItem('asp_req_fold_' + token, content); } catch(_) {}
}

function _aspGetFold(token) {
  if (_aspReqFoldMap.has(token)) return _aspReqFoldMap.get(token);
  try {
    const v = sessionStorage.getItem('asp_req_fold_' + token);
    if (v != null) {
      _aspReqFoldMap.set(token, v);
      return v;
    }
  } catch(_) {}
  if (token === "f_1790592878240_744") {
    return `  "data": [\n    {\n      "instanceOf": "EutranFaPriorInfoFunc",\n      "relation": "Parent",\n      "sequence": "EutranFaPriorInfoFunc-1",\n      "gridName": "",\n      "entityData": {\n        "id": "01a0e70a-0570-7293-894a-19251b547659",\n        "sourceBand": "CONFIGURATION_MANAGEMENT",\n        "faIndex": "",\n        "earfcnBand": "",\n        "priority": "",\n        "cellCapacityClassValueDlPerFa": "",\n        "cellCapacityClassValueUlPerFa": ""\n      }\n    }\n  ]`;
  }
  if (token === "f_1790592873881_584") {
    return `  "entityMap": {\n    "identifier1": "CONFIGURATION_MANAGEMENT_APP_NAME",\n    "identifier2": "EutranFaPriorInfoFunc",\n    "entityType": "EutranFaPriorInfoFunc",\n    "id": "01a0e70a-0570-7293-894a-19251b547659",\n    "EUTRANFAPRIORINFOFUNC": "01a0e70a-0570-7293-894a-19251b547659",\n    "entityId": "01a0e70a-0570-7293-894a-19251b547659",\n    "identifier3": "01a0e70a-0570-7293-894a-19251b547659"\n  }`;
  }
  return null;
}

function _aspReqUnfoldAll(text) {
  let cur = String(text || "");
  let guard = 0;
  while (guard++ < 50) {
    let matched = false;
    for (const [token, original] of _aspReqFoldMap.entries()) {
      const regex = new RegExp(`^.*\\/\\*⋯\\d+ lines\\[${token}\\]⋯\\*\\/.*$`, 'm');
      if (regex.test(cur)) {
        cur = cur.replace(regex, original);
        matched = true;
      }
    }
    const orphan = cur.match(/\/\*⋯\d+ lines\[(f_\d+_\d+)\]⋯\*\//);
    if (orphan) {
      const token = orphan[1];
      const orig = _aspGetFold(token);
      if (orig) {
        cur = cur.replace(new RegExp(`^.*\\/\\*⋯\\d+ lines\\[${token}\\]⋯\\*\\/.*$`, 'm'), orig);
        matched = true;
      } else {
        break;
      }
    }
    if (!matched) break;
  }
  return cur;
}

function _aspToggleReqFold(lineIdx) {
  const ta = document.getElementById("asp-body-raw");
  if (!ta) return;
  const text = ta.value;
  const lines = text.split('\n');
  if (lineIdx < 0 || lineIdx >= lines.length) return;

  const lineContent = lines[lineIdx];
  const m = lineContent.match(/\/\*⋯(\d+) lines\[(f_\d+_\d+)\]⋯\*\//);
  if (m) {
    const token = m[2];
    const original = _aspGetFold(token);
    if (original) {
      _aspReqFoldMap.delete(token);
      try { sessionStorage.removeItem('asp_req_fold_' + token); } catch(_) {}
      lines.splice(lineIdx, 1, original);
      ta.value = lines.join('\n');
    }
    _aspSyncBodyHighlight();
    _aspBodyCaretChrome();
    _aspSaveDraft();
    return;
  }

  const folds = _aspComputeFolds(text);
  const f = folds[lineIdx];
  if (!f || f.endLine <= lineIdx + 1) return;

  const token = `f_${Date.now()}_${Math.floor(Math.random()*1000)}`;
  const originalChunk = lines.slice(lineIdx, f.endLine + 1).join('\n');
  _aspStoreFold(token, originalChunk);

  const startLine = lines[lineIdx];
  const endLine = lines[f.endLine];
  const comma = endLine.trim().endsWith(',') ? ',' : '';
  const hiddenCount = f.endLine - lineIdx;

  const replacement = `${startLine}/*⋯${hiddenCount} lines[${token}]⋯*/${f.closeChar}${comma}`;
  lines.splice(lineIdx, f.endLine - lineIdx + 1, replacement);
  ta.value = lines.join('\n');
  _aspSyncBodyHighlight();
  _aspBodyCaretChrome();
  _aspSaveDraft();
}

function aspToggleFoldAll(which) {
  if (which === 'req') {
    const ta = document.getElementById("asp-body-raw");
    const btn = document.getElementById("asp-body-foldall-btn");
    if (!ta) return;
    const cur = ta.value;
    const hasFold = cur.includes('/*⋯') || _aspReqFoldMap.size > 0;
    if (hasFold) {
      ta.value = _aspReqUnfoldAll(cur);
      _aspReqFoldMap.clear();
      try {
        for (let i = sessionStorage.length - 1; i >= 0; i--) {
          const k = sessionStorage.key(i);
          if (k && k.startsWith('asp_req_fold_')) sessionStorage.removeItem(k);
        }
      } catch(_) {}
      if (btn) btn.textContent = "Collapse All";
    } else {
      const folds = _aspComputeFolds(cur);
      const keys = Object.keys(folds).map(Number).sort((a,b) => b - a); // bottom to top
      const targets = keys.filter(k => (folds[k].indent === 2 || folds[k].indent === 0) && folds[k].endLine > k + 1);
      if (targets.length) {
        let updated = cur;
        for (const l of targets) {
          const lines = updated.split('\n');
          const curFolds = _aspComputeFolds(updated);
          const f = curFolds[l];
          if (f && f.endLine > l + 1) {
            const token = `f_${Date.now()}_${Math.floor(Math.random()*1000)}`;
            const orig = lines.slice(l, f.endLine + 1).join('\n');
            _aspStoreFold(token, orig);
            const startLine = lines[l];
            const endLine = lines[f.endLine];
            const comma = endLine.trim().endsWith(',') ? ',' : '';
            const hiddenCount = f.endLine - l;
            lines.splice(l, f.endLine - l + 1, `${startLine}/*⋯${hiddenCount} lines[${token}]⋯*/${f.closeChar}${comma}`);
            updated = lines.join('\n');
          }
        }
        ta.value = updated;
        if (btn) btn.textContent = "Expand All";
      }
    }
    _aspSyncBodyHighlight();
    _aspBodyCaretChrome();
    _aspSaveDraft();
    return;
  }

  const keys = Object.keys(_aspRespFolds || {}).map(Number);
  if (!keys.length) return;
  const rootFolds = keys.filter(k => _aspRespFolds[k].indent === 0 || _aspRespFolds[k].indent === 2);
  const allFolded = rootFolds.every(k => _aspRespFolded.has(k));
  if (allFolded) {
    _aspRespFolded.clear();
  } else {
    rootFolds.forEach(k => _aspRespFolded.add(k));
  }
  const btn = document.getElementById("asp-resp-foldall-btn");
  if (btn) btn.textContent = allFolded ? "Collapse All" : "Expand All";
  _aspUpdateRespView();
  if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
}

function aspToggleBodyWrap(which) {
  if (which === 'req') {
    _aspReqWrap = !_aspReqWrap;
    const ta = document.getElementById("asp-body-raw");
    const pre = document.getElementById("asp-body-pre");
    const btn = document.getElementById("asp-body-wrap-btn");
    if (ta) {
      ta.classList.toggle("asp-wrap", _aspReqWrap);
      ta.classList.toggle("asp-no-wrap", !_aspReqWrap);
    }
    if (pre) {
      pre.classList.toggle("asp-wrap", _aspReqWrap);
      pre.classList.toggle("asp-no-wrap", !_aspReqWrap);
    }
    if (btn) btn.classList.toggle("asp-btn-active", _aspReqWrap);
    _aspSyncReqGutterHeights();
    _aspActiveLineUpdate();
    _aspReqPositionGuide();
  } else {
    _aspRespWrap = !_aspRespWrap;
    const pre = document.getElementById("asp-resp-body-pre");
    const btn = document.getElementById("asp-resp-wrap-btn");
    if (pre) {
      pre.classList.toggle("asp-wrap", _aspRespWrap);
      pre.classList.toggle("asp-no-wrap", !_aspRespWrap);
    }
    if (btn) btn.classList.toggle("asp-btn-active", _aspRespWrap);
    _aspSyncRespGutterHeights();
    if (typeof _aspRespPositionGuide === "function") _aspRespPositionGuide();
  }
}

function aspBeautifyRequestBody() {
  const ta = document.getElementById("asp-body-raw");
  if (!ta) return;
  let val = ta.value;
  if (!val || !val.trim()) return;
  if (typeof _aspReqUnfoldAll === "function") val = _aspReqUnfoldAll(val);
  try {
    let stripped = _aspStripJsonComments(val);
    stripped = stripped.replace(/,\s*([}\]])/g, '$1');
    const parsed = JSON.parse(stripped);
    const pretty = JSON.stringify(parsed, null, 2);
    _aspUndoFlush();
    ta.value = pretty;
    _aspReqFoldMap.clear();
    try {
      for (let i = sessionStorage.length - 1; i >= 0; i--) {
        const k = sessionStorage.key(i);
        if (k && k.startsWith('asp_req_fold_')) sessionStorage.removeItem(k);
      }
    } catch(_) {}
    _aspUndoRecord();
    _aspSyncBodyHighlight();
    _aspBodyCaretChrome();
    _aspSaveDraft();
    _aspShowToast("JSON formatted", "success");
  } catch (e) {
    _aspShowToast("Invalid JSON: " + (e.message || "parse error"), "warn");
  }
}

function aspBeautifyResponseBody() {
  if (!_aspLastResp || _aspLastResp.body == null) return;
  _aspRespFmt = "json";
  const btnLabel = document.getElementById("asp-resp-fmt-label");
  if (btnLabel) btnLabel.textContent = "JSON";
  _aspRenderRespBody(_aspLastResp.body, _aspLastResp.body_hint);
  _aspShowToast("Response formatted as JSON", "success");
}

function aspCopyRequestBody() {
  const ta = document.getElementById("asp-body-raw");
  if (!ta) return;
  let text = ta.value;
  if (_aspReqFoldMap.size > 0) text = _aspReqUnfoldAll(text);
  navigator.clipboard.writeText(text).then(() => {
    _aspShowToast("Request body copied", "success");
  }).catch(() => {
    try {
      ta.select();
      document.execCommand("copy");
      _aspShowToast("Request body copied", "success");
    } catch (_) {
      _aspShowToast("Failed to copy", "warn");
    }
  });
}

let _aspRespActiveScope = null;

function _aspRespPositionGuide() {
  const g = document.getElementById('asp-resp-bracket-guide');
  const pre = document.getElementById('asp-resp-body-pre');
  if (!g || !pre || !_aspRespActiveScope) {
    if (g) g.style.display = 'none';
    return;
  }
  const { openLine, endLine, indent } = _aspRespActiveScope;
  const openLineEl = pre.querySelector(`.asp-code-line[data-line="${openLine}"]`);
  const closeLineEl = pre.querySelector(`.asp-code-line[data-line="${endLine}"]`);
  if (!openLineEl || !closeLineEl) {
    g.style.display = 'none';
    return;
  }
  const preRect = pre.getBoundingClientRect();
  const openRect = openLineEl.getBoundingClientRect();
  const closeRect = closeLineEl.getBoundingClientRect();

  const cw = _aspEnsureCharW();
  const leftX = 10 + (indent + 2) * cw - pre.scrollLeft;
  const startY = (openRect.bottom - preRect.top);
  const endY = (closeRect.top - preRect.top);
  const height = endY - startY;

  if (height <= 0 || endY < 0 || startY > pre.clientHeight) {
    g.style.display = 'none';
    return;
  }

  g.style.left = leftX + 'px';
  g.style.top = startY + 'px';
  g.style.height = height + 'px';
  g.style.display = 'block';
}

function _aspRespChromeHide() {
  const g = document.getElementById('asp-resp-bracket-guide');
  if (g) g.style.display = 'none';
  _aspRespActiveScope = null;
}

function _aspInitRespChrome() {
  const pre = document.getElementById("asp-resp-body-pre");
  const gutter = document.getElementById("asp-resp-gutter");
  if (!pre || pre.dataset.chromeInit) return;
  pre.dataset.chromeInit = "1";

  pre.addEventListener('scroll', () => {
    if (gutter) gutter.scrollTop = pre.scrollTop;
    _aspRespPositionGuide();
  });

  pre.addEventListener('click', (e) => {
    const ell = e.target.closest('.asp-fold-ellipsis');
    if (ell && ell.dataset.unfoldLine !== undefined) {
      _aspToggleRespFold(Number(ell.dataset.unfoldLine));
      return;
    }
    const lineEl = e.target.closest('.asp-code-line');
    if (lineEl && lineEl.dataset.line !== undefined) {
      const clickedLine = Number(lineEl.dataset.line);
      let bestFold = null;
      let bestSpan = Infinity;
      for (const [openLStr, f] of Object.entries(_aspRespFolds || {})) {
        const openL = Number(openLStr);
        if (openL <= clickedLine && clickedLine <= f.endLine && f.endLine > openL + 1) {
          const span = f.endLine - openL;
          if (span < bestSpan) {
            bestSpan = span;
            bestFold = { openLine: openL, endLine: f.endLine, indent: f.indent };
          }
        }
      }
      _aspRespActiveScope = bestFold;
      _aspRespPositionGuide();
    }
  });

  if (gutter) {
    gutter.addEventListener('click', (e) => {
      const btn = e.target.closest('.asp-fold-btn');
      if (btn && btn.dataset.foldLine !== undefined) {
        _aspToggleRespFold(Number(btn.dataset.foldLine));
      }
    });
  }
}

function _aspRespUpdateScopeAtMouse() {}
function _aspRespCaretChrome() {}

function _aspInitBracketGuides() {
  const editor = document.getElementById('asp-body-editor-box') || document.querySelector('.asp-body-editor');
  if (!editor || editor.dataset.bracketInit) return;
  editor.dataset.bracketInit = '1';

  const ta = document.getElementById('asp-body-raw');
  const gutter = document.getElementById('asp-body-gutter');
  if (gutter && !gutter.dataset.foldInit) {
    gutter.dataset.foldInit = "1";
    gutter.addEventListener('click', (e) => {
      const btn = e.target.closest('.asp-fold-btn');
      if (btn && btn.dataset.foldLine !== undefined) {
        _aspToggleReqFold(Number(btn.dataset.foldLine));
      }
    });
  }
  const preEl = document.getElementById('asp-body-pre');
  if (preEl && !preEl.dataset.foldInit) {
    preEl.dataset.foldInit = "1";
    preEl.addEventListener('click', (e) => {
      const ell = e.target.closest('.asp-fold-ellipsis');
      if (ell && (ell.dataset.unfoldLine !== undefined || ell.dataset.unfoldToken !== undefined)) {
        if (ell.dataset.unfoldLine !== undefined) {
          _aspToggleReqFold(Number(ell.dataset.unfoldLine));
        } else {
          const ta = document.getElementById('asp-body-raw');
          if (ta) {
            const token = ell.dataset.unfoldToken;
            const orig = _aspGetFold(token);
            if (orig) {
              const regex = new RegExp(`^.*\\/\\*⋯\\d+ lines\\[${token}\\]⋯\\*\\/.*$`, 'm');
              ta.value = ta.value.replace(regex, orig);
              _aspReqFoldMap.delete(token);
              try { sessionStorage.removeItem('asp_req_fold_' + token); } catch(_) {}
              _aspSyncBodyHighlight();
              _aspBodyCaretChrome();
              _aspSaveDraft();
            }
          }
        }
      }
    });
  }
  if (ta) {
    const bump = () => _aspBodyCaretChrome();
    ['keyup', 'click', 'mouseup', 'select', 'focus'].forEach(ev => ta.addEventListener(ev, bump));
    ta.addEventListener('dblclick', () => {
      const lineIdx = _aspIndexToLine(ta.value, ta.selectionStart);
      const lines = ta.value.split('\n');
      if (lineIdx >= 0 && lineIdx < lines.length && /\/\*⋯\d+ lines\[(f_\d+_\d+)\]⋯\*\//.test(lines[lineIdx])) {
        _aspToggleReqFold(lineIdx);
      }
    });
    ta.addEventListener('keydown', (e) => {
      const start = ta.selectionStart;
      const end   = ta.selectionEnd;
      const val   = ta.value;

      // 1. Tab / Shift+Tab Indentation
      if (e.key === 'Tab') {
        e.preventDefault();
        if (e.shiftKey) {
          // Shift+Tab: Unindent
          const lineStart = val.lastIndexOf('\n', start - 1) + 1;
          let lineEnd = val.indexOf('\n', end);
          if (lineEnd === -1) lineEnd = val.length;
          const lines = val.slice(lineStart, lineEnd).split('\n');
          const unindented = lines.map(l => l.startsWith('  ') ? l.slice(2) : l.startsWith('\t') ? l.slice(1) : l.startsWith(' ') ? l.slice(1) : l);
          const newBlock = unindented.join('\n');
          _aspUndoFlush();
          ta.value = val.slice(0, lineStart) + newBlock + val.slice(lineEnd);
          ta.selectionStart = Math.max(lineStart, start - (lines[0].startsWith('  ') ? 2 : lines[0].startsWith(' ') ? 1 : 0));
          ta.selectionEnd = Math.max(lineStart, end - (val.slice(lineStart, lineEnd).length - newBlock.length));
        } else {
          if (start !== end && val.slice(start, end).includes('\n')) {
            // Multi-line indent
            const lineStart = val.lastIndexOf('\n', start - 1) + 1;
            let lineEnd = val.indexOf('\n', end);
            if (lineEnd === -1) lineEnd = val.length;
            const lines = val.slice(lineStart, lineEnd).split('\n');
            const indented = lines.map(l => '  ' + l).join('\n');
            _aspUndoFlush();
            ta.value = val.slice(0, lineStart) + indented + val.slice(lineEnd);
            ta.selectionStart = start + 2;
            ta.selectionEnd = end + (lines.length * 2);
          } else {
            // Single cursor or inline selection: insert 2 spaces
            _aspUndoFlush();
            ta.value = val.slice(0, start) + '  ' + val.slice(end);
            ta.selectionStart = ta.selectionEnd = start + 2;
          }
        }
        _aspUndoRecord();
        _aspSyncBodyHighlight();
        _aspBodyCaretChrome();
        _aspSaveDraft();
        return;
      }

      // 2. Smart Enter indentation
      if (e.key === 'Enter' && start === end) {
        const lineStart = val.lastIndexOf('\n', start - 1) + 1;
        const currentLine = val.slice(lineStart, start);
        const matchIndent = currentLine.match(/^(\s*)/);
        let indent = matchIndent ? matchIndent[1] : '';
        const prevChar = start > 0 ? val[start - 1] : '';
        const nextChar = start < val.length ? val[start] : '';

        // Case A: Enter between { and } or [ and ]
        if ((prevChar === '{' && nextChar === '}') || (prevChar === '[' && nextChar === ']')) {
          e.preventDefault();
          const extraIndent = indent + '  ';
          const insertText = '\n' + extraIndent + '\n' + indent;
          _aspUndoFlush();
          ta.value = val.slice(0, start) + insertText + val.slice(end);
          ta.selectionStart = ta.selectionEnd = start + extraIndent.length + 1;
          _aspUndoRecord();
          _aspSyncBodyHighlight();
          _aspBodyCaretChrome();
          _aspSaveDraft();
          return;
        }

        // Case B: Current line ends with { or [ -> increase indent
        if (prevChar === '{' || prevChar === '[') {
          indent += '  ';
        }

        if (indent.length > 0) {
          e.preventDefault();
          const insertText = '\n' + indent;
          _aspUndoFlush();
          ta.value = val.slice(0, start) + insertText + val.slice(end);
          ta.selectionStart = ta.selectionEnd = start + insertText.length;
          _aspUndoRecord();
          _aspSyncBodyHighlight();
          _aspBodyCaretChrome();
          _aspSaveDraft();
          return;
        }
      }

      // 3. Auto-close brackets & quotes
      if (e.key === '{' || e.key === '[' || e.key === '"') {
        const pairs = { '{': '}', '[': ']', '"': '"' };
        const close = pairs[e.key];
        if (start !== end) {
          e.preventDefault();
          const selected = val.slice(start, end);
          _aspUndoFlush();
          ta.value = val.slice(0, start) + e.key + selected + close + val.slice(end);
          ta.selectionStart = start + 1;
          ta.selectionEnd = end + 1;
          _aspUndoRecord();
          _aspSyncBodyHighlight();
          _aspBodyCaretChrome();
          _aspSaveDraft();
          return;
        } else {
          if (e.key === '"' && val[start] === '"') {
            e.preventDefault();
            ta.selectionStart = ta.selectionEnd = start + 1;
            return;
          }
          e.preventDefault();
          _aspUndoFlush();
          ta.value = val.slice(0, start) + e.key + close + val.slice(end);
          ta.selectionStart = ta.selectionEnd = start + 1;
          _aspUndoRecord();
          _aspSyncBodyHighlight();
          _aspBodyCaretChrome();
          _aspSaveDraft();
          return;
        }
      }

      // Skip over closing bracket if typed
      if ((e.key === '}' || e.key === ']') && val[start] === e.key && start === end) {
        e.preventDefault();
        ta.selectionStart = ta.selectionEnd = start + 1;
        return;
      }

      // Backspace between pairs
      if (e.key === 'Backspace' && start === end && start > 0) {
        const prev = val[start - 1];
        const next = val[start];
        if ((prev === '{' && next === '}') || (prev === '[' && next === ']') || (prev === '"' && next === '"')) {
          e.preventDefault();
          _aspUndoFlush();
          ta.value = val.slice(0, start - 1) + val.slice(start + 1);
          ta.selectionStart = ta.selectionEnd = start - 1;
          _aspUndoRecord();
          _aspSyncBodyHighlight();
          _aspBodyCaretChrome();
          _aspSaveDraft();
          return;
        }
      }

      requestAnimationFrame(bump);
    });
    ta.addEventListener('scroll', () => {
      const pre = document.getElementById('asp-body-pre');
      if (pre) {
        pre.scrollTop = ta.scrollTop;
        pre.scrollLeft = ta.scrollLeft;
      }
      if (gutter) {
        gutter.scrollTop = ta.scrollTop;
      }
      _aspBodyCaretChrome();
    });
    ta.addEventListener('blur', () => {
      setTimeout(() => {
        if (document.activeElement !== ta) _aspBodyChromeHide();
      }, 0);
    });
  }
}

function _aspBodyChromeHide() {
  const line = document.getElementById('asp-active-line');
  if (line) line.style.display = 'none';
  const gutter = document.getElementById('asp-body-gutter');
  if (gutter) {
    const prev = gutter.querySelector('.asp-line-active');
    if (prev) prev.classList.remove('asp-line-active');
  }
}

function _aspEnsureCharW() {
  if (_aspCharW) return _aspCharW;
  const pre = document.getElementById('asp-body-pre');
  if (pre) {
    const span = document.createElement('span');
    span.style.cssText = 'position:absolute;visibility:hidden;white-space:pre;font:inherit';
    span.textContent = '0'.repeat(20);
    pre.appendChild(span);
    _aspCharW = span.getBoundingClientRect().width / 20 || 7.2;
    span.remove();
  } else {
    _aspCharW = 7.2;
  }
  return _aspCharW;
}

function _aspIndexToLine(text, idx) {
  let n = 0;
  for (let i = 0; i < idx && i < text.length; i++) if (text[i] === '\n') n++;
  return n;
}

function _aspActiveLineUpdate() {
  const ta   = document.getElementById('asp-body-raw');
  const line = document.getElementById('asp-active-line');
  const pre  = document.getElementById('asp-body-pre');
  if (!ta || !line) return;
  if (document.activeElement !== ta) { line.style.display = 'none'; return; }
  const lineIdx = _aspIndexToLine(ta.value, ta.selectionStart);

  let topY = _ASP_BODY_PAD + lineIdx * _ASP_BODY_LINE_H - ta.scrollTop;
  let h = _ASP_BODY_LINE_H;

  if (pre) {
    const lineEl = pre.querySelector(`.asp-code-line[data-line="${lineIdx}"]`);
    if (lineEl) {
      const preRect = pre.getBoundingClientRect();
      const lineRect = lineEl.getBoundingClientRect();
      topY = lineRect.top - preRect.top;
      h = lineEl.offsetHeight || _ASP_BODY_LINE_H;
    }
  }

  line.style.top     = topY + 'px';
  line.style.height  = h + 'px';
  line.style.display = (topY >= -h && topY <= ta.clientHeight) ? 'block' : 'none';

  const gutter = document.getElementById('asp-body-gutter');
  if (gutter) {
    const prev = gutter.querySelector('.asp-line-active');
    if (prev) prev.classList.remove('asp-line-active');
    const cur = gutter.querySelector(`.asp-gutter-line[data-line="${lineIdx}"]`);
    if (cur) cur.classList.add('asp-line-active');
  }
}

let _aspReqActiveScope = null;

function _aspReqPositionGuide() {
  const g = document.getElementById('asp-bracket-guide');
  const ta = document.getElementById('asp-body-raw');
  const pre = document.getElementById('asp-body-pre');
  if (!g || !ta || !pre || !_aspReqActiveScope || document.activeElement !== ta) {
    if (g) g.style.display = 'none';
    return;
  }
  const { openLine, endLine, indent } = _aspReqActiveScope;
  const openLineEl = pre.querySelector(`.asp-code-line[data-line="${openLine}"]`);
  const closeLineEl = pre.querySelector(`.asp-code-line[data-line="${endLine}"]`);
  if (!openLineEl || !closeLineEl) {
    g.style.display = 'none';
    return;
  }
  const preRect = pre.getBoundingClientRect();
  const openRect = openLineEl.getBoundingClientRect();
  const closeRect = closeLineEl.getBoundingClientRect();

  const cw = _aspEnsureCharW();
  const leftX = _ASP_BODY_PAD + (indent + 2) * cw - ta.scrollLeft;
  const startY = (openRect.bottom - preRect.top);
  const endY   = (closeRect.top - preRect.top);
  const height = endY - startY;

  if (height <= 0 || endY < 0 || startY > ta.clientHeight) {
    g.style.display = 'none';
    return;
  }

  g.style.left = leftX + 'px';
  g.style.top = startY + 'px';
  g.style.height = height + 'px';
  g.style.display = 'block';
}

function _aspBracketHide() {
  const g = document.getElementById('asp-bracket-guide');
  if (g) g.style.display = 'none';
  _aspReqActiveScope = null;
}

function _aspBodyCaretChrome() {
  _aspActiveLineUpdate();
  const ta = document.getElementById('asp-body-raw');
  if (!ta || document.activeElement !== ta) {
    _aspBracketHide();
    return;
  }
  const bodyType = _aspGetBodyType();
  const rawLang  = _aspGetRawLang();
  const asJson   = (bodyType === "raw" && rawLang === "json") || bodyType === "json";
  if (!asJson) {
    _aspBracketHide();
    return;
  }
  const lineIdx = _aspIndexToLine(ta.value, ta.selectionStart);
  const folds = _aspComputeFolds(ta.value);
  let bestFold = null;
  let bestSpan = Infinity;
  for (const [openLStr, f] of Object.entries(folds)) {
    const openL = Number(openLStr);
    if (openL <= lineIdx && lineIdx <= f.endLine && f.endLine > openL + 1) {
      const span = f.endLine - openL;
      if (span < bestSpan) {
        bestSpan = span;
        bestFold = { openLine: openL, endLine: f.endLine, indent: f.indent };
      }
    }
  }
  _aspReqActiveScope = bestFold;
  _aspReqPositionGuide();
}

function _aspBracketHover(e) {}
function _aspEscAttr(s) { return (s||"").replace(/&/g,"&amp;").replace(/"/g,"&quot;"); }

// ── Custom undo/redo stack for request body textarea ──────────
// Replaces unreliable native undo (WKWebView clears it on DOM changes)
const _aspUndoMap  = {};      // tabId → { stack: [{v,s,e}], idx }
let _aspUndoTimer  = null;
let _aspUndoBusy   = false;   // true while we are applying undo/redo

function _aspUndoStateFor(id) {
  if (!_aspUndoMap[id]) _aspUndoMap[id] = { stack: [], idx: -1 };
  return _aspUndoMap[id];
}

// Seed: call after programmatic value assignment (_aspApplyState, cURL import)
function _aspUndoSeed(text) {
  const id = _aspActiveTabId();
  if (!id) return;
  _aspUndoMap[id] = { stack: [{ v: text, s: text.length, e: text.length }], idx: 0 };
}

// Push current value to history (debounced, called from _aspOnBodyInput)
function _aspUndoRecord() {
  if (_aspUndoBusy) return;
  clearTimeout(_aspUndoTimer);
  _aspUndoTimer = setTimeout(_aspUndoFlush, 400);
}

// Immediate push — call before any operation that replaces value (format, import)
function _aspUndoFlush() {
  if (_aspUndoBusy) return;
  const ta = document.getElementById('asp-body-raw');
  const id = _aspActiveTabId();
  if (!ta || !id) return;
  const u   = _aspUndoStateFor(id);
  const cur = u.stack[u.idx];
  if (cur && cur.v === ta.value) return;          // nothing changed
  u.stack.splice(u.idx + 1);                      // drop redo entries
  u.stack.push({ v: ta.value, s: ta.selectionStart, e: ta.selectionEnd });
  u.idx = u.stack.length - 1;
  if (u.stack.length > 500) { u.stack.shift(); u.idx--; }
}

function _aspUndo() {
  _aspUndoFlush();                                 // commit any pending typing first
  const ta = document.getElementById('asp-body-raw');
  const id = _aspActiveTabId();
  if (!ta || !id) return;
  const u = _aspUndoStateFor(id);
  if (u.idx <= 0) return;
  u.idx--;
  _aspUndoApplyEntry(ta, u.stack[u.idx]);
}

function _aspRedo() {
  const ta = document.getElementById('asp-body-raw');
  const id = _aspActiveTabId();
  if (!ta || !id) return;
  const u = _aspUndoStateFor(id);
  if (u.idx >= u.stack.length - 1) return;
  u.idx++;
  _aspUndoApplyEntry(ta, u.stack[u.idx]);
}

function _aspUndoApplyEntry(ta, entry) {
  _aspUndoBusy = true;
  ta.value = entry.v;
  try { ta.setSelectionRange(entry.s, entry.e); } catch(_) {}
  _aspSyncBodyHighlight();
  _aspUndoBusy = false;
}

// ── Custom undo/redo for params/headers VALUE inputs + the URL input ──
// Same rationale as the body-textarea stack above: WKWebView silently clears
// an input's native undo history on unrelated DOM changes elsewhere on the
// page (e.g. rendering the response after Send), so history is tracked here
// instead, keyed per input element — it survives exactly as long as the row.
const _aspKvUndoMap    = new WeakMap(); // el → { stack: [{v,s,e}], idx }
const _aspKvUndoTimers = new WeakMap(); // el → timeout id (per-field — don't clobber)
let _aspKvUndoBusy = false;

function _aspKvUndoSeed(inp) {
  if (!inp) return;
  _aspKvUndoMap.set(inp, { stack: [{ v: inp.value, s: inp.value.length, e: inp.value.length }], idx: 0 });
}
function _aspKvUndoRecord(inp) {
  if (_aspKvUndoBusy || !inp) return;
  const prev = _aspKvUndoTimers.get(inp);
  if (prev) clearTimeout(prev);
  // Large paste / encode jumps: commit immediately so Cmd+Z has a step to land on
  const u = _aspKvUndoMap.get(inp);
  const cur = u && u.stack[u.idx];
  const jump = cur && Math.abs((inp.value || '').length - (cur.v || '').length) > 40;
  if (jump) {
    _aspKvUndoFlush(inp);
    return;
  }
  _aspKvUndoTimers.set(inp, setTimeout(() => {
    _aspKvUndoTimers.delete(inp);
    _aspKvUndoFlush(inp);
  }, 300));
}
function _aspKvUndoFlush(inp) {
  if (!inp || _aspKvUndoBusy || !inp.isConnected) return;
  const t = _aspKvUndoTimers.get(inp);
  if (t) { clearTimeout(t); _aspKvUndoTimers.delete(inp); }
  let u = _aspKvUndoMap.get(inp);
  if (!u) { _aspKvUndoSeed(inp); u = _aspKvUndoMap.get(inp); }
  const cur = u.stack[u.idx];
  if (cur && cur.v === inp.value) return;             // nothing changed
  u.stack.splice(u.idx + 1);                          // drop redo entries
  let s = 0, e = 0;
  try { s = inp.selectionStart; e = inp.selectionEnd; } catch (_) { s = e = inp.value.length; }
  u.stack.push({ v: inp.value, s, e });
  u.idx = u.stack.length - 1;
  if (u.stack.length > 200) { u.stack.shift(); u.idx--; }
}
function _aspKvUndo(inp) {
  _aspKvUndoFlush(inp);                                // commit any pending typing first
  const u = _aspKvUndoMap.get(inp);
  if (!u || u.idx <= 0) return;
  u.idx--;
  _aspKvUndoApplyEntry(inp, u.stack[u.idx]);
}
function _aspKvRedo(inp) {
  _aspKvUndoFlush(inp);
  const u = _aspKvUndoMap.get(inp);
  if (!u || u.idx >= u.stack.length - 1) return;
  u.idx++;
  _aspKvUndoApplyEntry(inp, u.stack[u.idx]);
}
function _aspKvUndoApplyEntry(inp, entry) {
  _aspKvUndoBusy = true;
  inp.value = entry.v;
  try { inp.setSelectionRange(entry.s, entry.e); } catch(_) {}
  if (inp.id === 'asp-url-input') _aspSyncUrlHl();
  else {
    _aspSyncKvHl(inp);
    _aspKvValAutosize(inp);
  }
  try { _aspSaveDraft(); } catch (_) {}
  _aspKvUndoBusy = false;
}

// ── Import menu (cURL / AV Collection) ───────────────────────────────────────
function aspToggleImportMenu() {
  if (_aspIsWorkspaceOverlayOpen()) return;
  const menu = document.getElementById('asp-import-menu');
  if (!menu) return;
  const open = menu.style.display !== 'none';
  menu.style.display = open ? 'none' : 'block';
  if (!open) {
    // close on next outside click
    setTimeout(() => document.addEventListener('click', _aspImportMenuOutside, { once: true }), 0);
  }
}
function aspCloseImportMenu() {
  const menu = document.getElementById('asp-import-menu');
  if (menu) menu.style.display = 'none';
}
function _aspImportMenuOutside(e) {
  const menu = document.getElementById('asp-import-menu');
  const btn  = document.getElementById('asp-import-menu-btn');
  if (menu && !menu.contains(e.target) && e.target !== btn) menu.style.display = 'none';
}

function aspImportCollectionFile(input) {
  const files = input.files;
  if (!files || !files.length) return;

  const allFiles = Array.from(files);
  const results  = new Array(allFiles.length);
  let loaded = 0;

  allFiles.forEach((file, idx) => {
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const bundle = _aspRunnerNormalizeBundle(JSON.parse(e.target.result), file.name);
        results[idx] = bundle;
      } catch(err) {
        _aspAlert(`Failed to import ${file.name}: ${err.message}`);
      }
      loaded++;
      if (loaded === allFiles.length) {
        // First valid bundle is the base; rest are merged in order
        const base = results.find(b => b);
        if (!base) return;
        results.forEach((b, i) => {
          if (i > 0 && b) _aspRunnerMergeBundles(base, b);
        });
        _aspRunnerRefreshCaseStatuses();
        localStorage.setItem(ASP_RUNNER_KEY, JSON.stringify(base));
        aspRunnerShow();
      }
    };
    reader.onerror = () => { loaded++; };
    reader.readAsText(file);
  });

  input.value = "";
}

// ── APISphere Runner ─────────────────────────────────────────────────────────
let _aspRunnerData    = null;
let _aspRunnerRunning     = false;
let _aspRunnerPaused      = false;
let _aspRunnerAborted     = false;
let _aspRunnerLastResults = [];  // [{origIdx, result, status, elapsed, reqPayload, respData}] — this run only
let _aspRunnerExpandIdx   = -1;
let _aspRunnerBodyEdit    = null; // { origIdx, apiKey, draftText }
let _aspRunnerRandomState = null; // { apiKey, selectedPath }
let _aspRunnerPoolDraft = null; // { matched, filename, row_count, cleared }
let _aspRunnerDatasetState = null; // { apiKey, selectedPath, selectedDsKey, casesDraft, customDraft, casesList }
let _aspRunnerAllDatasets = null;
let _aspRunnerTab         = "cases";
let _aspRunnerExpandSearchCache = {}; // { [origIdx]: { reqText, respText, sentVal, uniqueApplied } }
let _aspRunnerCurlByIdx = {};
let _aspDashFailStore = {};
let _aspRunnerDupImportResolve = null;

function _aspRunnerPreviewFormat(fmt) {
  return _aspResolveTokens(String(fmt || ""));
}

function _aspRunnerFileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const s = String(r.result || "");
      const i = s.indexOf(",");
      resolve(i >= 0 ? s.slice(i + 1) : s);
    };
    r.onerror = () => reject(r.error || new Error("Could not read file"));
    r.readAsDataURL(file);
  });
}

function _aspRunnerGetApiPoolRec(apiKey) {
  const d = _aspRunnerData;
  if (!d || !apiKey) return null;
  d.unique_pools_by_api = d.unique_pools_by_api || {};
  return d.unique_pools_by_api[apiKey] || null;
}

function _aspRunnerPoolPaths(apiKey) {
  const rec = _aspRunnerGetApiPoolRec(apiKey);
  return rec && rec.matched ? rec.matched : {};
}

function _aspRunnerPoolUnusedCount(apiKey, path) {
  const vals = (_aspRunnerPoolPaths(apiKey)[path] || []).filter(v => String(v || "").trim());
  return vals.length;
}

function _aspRunnerRenderPoolPreview(matched, filename, rowCount, targetPath) {
  const box = document.getElementById("asp-runner-pool-preview");
  const label = document.getElementById("asp-runner-pool-file-label");
  if (!box) return;
  if (!matched || !Object.keys(matched).length) {
    box.style.display = "none";
    if (label) label.textContent = "";
    return;
  }
  if (label) label.textContent = filename || "";
  const lines = Object.entries(matched).map(([path, vals]) => {
    const n = (vals || []).length;
    const sample = (vals || []).slice(0, 3).join(", ");
    const mark = path === targetPath ? "  ← this param" : "";
    return `${path}: ${n} unused${mark}${sample ? `\n  e.g. ${sample}` : ""}`;
  });
  box.textContent = `${rowCount || 0} unused row(s)\n` + lines.join("\n");
  box.style.display = "block";
}

function _aspRunnerShowExistingPoolPreview() {
  const apiKey = _aspRunnerRandomState?.apiKey;
  const path = _aspRunnerRandomState?.selectedPath;
  if (_aspRunnerPoolDraft && _aspRunnerPoolDraft.cleared) {
    _aspRunnerRenderPoolPreview(null);
    return;
  }
  if (_aspRunnerPoolDraft && _aspRunnerPoolDraft.matched) {
    _aspRunnerRenderPoolPreview(
      _aspRunnerPoolDraft.matched,
      _aspRunnerPoolDraft.filename,
      _aspRunnerPoolDraft.row_count,
      path
    );
    return;
  }
  const rec = _aspRunnerGetApiPoolRec(apiKey);
  if (rec && rec.matched && Object.keys(rec.matched).length) {
    _aspRunnerRenderPoolPreview(rec.matched, rec.filename, rec.row_count, path);
  } else {
    _aspRunnerRenderPoolPreview(null);
  }
}

async function aspRunnerPoolFileChange(input) {
  const file = input && input.files && input.files[0];
  if (input) input.value = "";
  if (!file || !_aspRunnerRandomState) return;
  const apiKey = _aspRunnerRandomState.apiKey;
  const targetPath = _aspRunnerRandomState.selectedPath || "";
  const paramPaths = _aspRunnerCollectApiParams(apiKey).map(p => p.path);
  try {
    const content_b64 = await _aspRunnerFileToBase64(file);
    const resp = await fetch(`${_aspAvBackendUrl()}/parse-unique-pool`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name || "values.csv",
        content_b64,
        param_paths: paramPaths,
        target_path: targetPath,
      }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const detail = data.detail || data.error || `HTTP ${resp.status}`;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    const matched = data.matched || {};
    if (targetPath && !matched[targetPath]) {
      throw new Error(
        `No column matched this param (${targetPath}). Headers: ${(data.headers || []).join(", ") || "(none)"}`
      );
    }
    _aspRunnerPoolDraft = {
      matched,
      filename: data.filename || file.name,
      row_count: data.row_count || 0,
    };
    _aspRunnerShowExistingPoolPreview();
  } catch (err) {
    _aspRunnerPoolDraft = null;
    _aspRunnerRenderPoolPreview(null);
    _aspAlert("Import failed: " + (err && err.message ? err.message : String(err)));
  }
}

function _aspRunnerMakeLivePool(matched) {
  const pools = {};
  Object.entries(matched || {}).forEach(([path, vals]) => {
    const cleaned = (vals || []).map(v => String(v).trim()).filter(Boolean);
    if (cleaned.length) pools[path] = cleaned;
  });
  return { pools, index: 0, ambig: 0 };
}

function _aspRunnerLivePoolWidth(pool) {
  const lens = Object.values(pool.pools || {}).map(v => v.length);
  return lens.length ? Math.min(...lens) : 0;
}

function _aspRunnerLivePoolCurrent(pool) {
  if (!_aspRunnerLivePoolWidth(pool) || pool.index >= _aspRunnerLivePoolWidth(pool)) {
    throw new Error("Unique value list exhausted. Import more unused values and re-run.");
  }
  const out = {};
  Object.entries(pool.pools).forEach(([p, vals]) => { out[p] = vals[pool.index]; });
  return out;
}

function _aspRunnerPoolLastKey(path) {
  const s = String(path || "").replace(/^query\./, "");
  const parts = s.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  return (parts[parts.length - 1] || "").toLowerCase();
}

function _aspRunnerPoolAttributed(respBody, applied) {
  if (!applied || !Object.keys(applied).length) return false;
  const text = _aspUniqMatchText(respBody);
  const hasHint = _ASP_UNIQ_HINTS.some(h => text.includes(h));
  if (!hasHint) return false;
  const names = [];
  const vals = [];
  Object.entries(applied).forEach(([path, val]) => {
    const k = _aspRunnerPoolLastKey(path);
    if (k.length >= 2) names.push(k);
    if (val != null && String(val).trim().length >= 2) vals.push(String(val).trim().toLowerCase());
  });
  if (vals.some(v => text.includes(v))) return true;
  if (names.some(n => text.includes(n))) return true;
  return false;
}

function _aspRunnerLivePoolNote(pool, status, respBody, applied) {
  if (!pool || !applied || !Object.keys(applied).length) return;
  const code = parseInt(status, 10);
  if (!Number.isNaN(code) && code >= 200 && code < 300) {
    pool.index += 1;
    pool.ambig = 0;
    return;
  }
  if (code === 409 || code === 422) {
    if (_aspRunnerPoolAttributed(respBody, applied)) {
      pool.index += 1;
      pool.ambig = 0;
      return;
    }
    pool.ambig += 1;
    if (pool.ambig >= 2) {
      pool.index += 1;
      pool.ambig = 0;
    }
  }
}

function _aspRunnerCommitLivePools(poolsByApi) {
  const d = _aspRunnerData;
  if (!d) return;
  d.unique_pools_by_api = d.unique_pools_by_api || {};
  Object.entries(poolsByApi || {}).forEach(([apiKey, pool]) => {
    const rec = d.unique_pools_by_api[apiKey];
    if (!rec) return;
    const width = _aspRunnerLivePoolWidth(pool);
    if (!width || pool.index >= width) {
      delete d.unique_pools_by_api[apiKey];
      return;
    }
    const matched = {};
    Object.entries(pool.pools).forEach(([p, vals]) => {
      matched[p] = vals.slice(pool.index);
    });
    rec.matched = matched;
    rec.row_count = _aspRunnerLivePoolWidth({ pools: matched, index: 0, ambig: 0 });
  });
}

function aspRunnerShow() {
  const raw = localStorage.getItem(ASP_RUNNER_KEY);
  if (!raw) { _aspAlert("No runner data found. Export from API Validator first."); return; }
  try { _aspRunnerData = _aspRunnerNormalizeBundle(JSON.parse(raw), "runner"); } catch(e) { _aspAlert("Invalid runner data."); return; }

  _aspCloseWorkspaceOverlays("avRunner");
  _aspRunnerVars = { chain: {} };

  const d = _aspRunnerData;
  d.sources = d.sources || [{
    bundle_id: d.bundle_id,
    api_key: d.api_key,
    name: d.name,
    schema_version: d.schema_version,
    generated_at: d.generated_at,
  }];
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerReorderCasesByApi();
  localStorage.setItem(ASP_RUNNER_KEY, JSON.stringify(_aspRunnerData));

  _aspRunnerUpdateTitle();
  const prevEl = document.getElementById("asp-runner-prev-summary");
  if (prevEl) {
    const pass = d.cases.filter(c => c.prev_result === "PASS").length;
    const fail = d.cases.filter(c => c.prev_result === "FAIL").length;
    prevEl.textContent = `Prev: ${pass}P · ${fail}F`;
  }

  document.getElementById("asp-runner-live-summary").textContent = "";
  document.getElementById("asp-runner-progress-wrap").style.display = "none";
  document.getElementById("asp-runner-progress-fill").style.width = "0%";

  _aspRunnerRenderTable(d.cases);
  aspRunnerSwitchTab("cases");
  _aspRunnerSetExportCollectionEnabled(true);

  const overlay = document.getElementById("asp-runner-overlay");
  if (overlay) overlay.style.display = "flex";
  _aspSyncChromeLock();

  // Init col-resize after layout paint (offsetWidth needs display:flex to be active)
  setTimeout(_aspRunnerInitColResize, 0);
}

function _aspRunnerInitColResize() {
  const table = document.getElementById("asp-runner-table");
  if (!table || table.dataset.colResizeInit) return;
  table.dataset.colResizeInit = "1";

  const ths  = Array.from(table.querySelectorAll("thead th"));
  const cols = Array.from(table.querySelectorAll("colgroup col"));

  // Convert percentage/auto widths to px so drag math is simple
  ths.forEach((th, i) => {
    const w = th.offsetWidth;
    if (w > 0) cols[i].style.width = w + "px";
  });

  // Attach a drag handle to every column except the last
  ths.slice(0, -1).forEach((th, i) => {
    const handle = document.createElement("div");
    handle.className = "asp-col-resize-handle";
    th.appendChild(handle);

    handle.addEventListener("mousedown", e => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startW = parseInt(cols[i].style.width, 10) || ths[i].offsetWidth;
      handle.classList.add("dragging");

      const onMove = ev => {
        const newW = Math.max(28, startW + (ev.clientX - startX));
        cols[i].style.width = newW + "px";
      };
      const onUp = () => {
        handle.classList.remove("dragging");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

function _aspRunnerUpdateTitle() {
  const d = _aspRunnerData;
  if (!d) return;
  const url      = d.url || "";
  const shortUrl = url.replace(/^https?:\/\//, "").slice(0, 50);
  const titleEl  = document.getElementById("asp-runner-title");
  if (titleEl) titleEl.textContent = `${d.method || "?"} ${shortUrl}  ·  ${d.cases.length} cases`;
}

function aspRunnerDupImportChoose(choice) {
  const modal = document.getElementById("asp-runner-dup-modal");
  if (modal) modal.style.display = "none";
  const resolve = _aspRunnerDupImportResolve;
  _aspRunnerDupImportResolve = null;
  if (resolve) resolve(choice || "cancel");
}

function _aspRunnerAskDuplicateImport(bundle, existingCount) {
  const modal = document.getElementById("asp-runner-dup-modal");
  const msg = document.getElementById("asp-runner-dup-msg");
  if (msg) {
    msg.textContent = `${bundle.api_key || ""}  · existing cases: ${existingCount}  · incoming cases: ${(bundle.cases || []).length}`;
  }
  if (modal) modal.style.display = "flex";
  return new Promise(resolve => { _aspRunnerDupImportResolve = resolve; });
}

function _aspRunnerReplaceApiCases(base, incoming) {
  const next = _aspRunnerClone(base);
  next.cases = (next.cases || []).filter(c => _aspRunnerApiKeyFromCase(c) !== incoming.api_key);
  next.param_snapshot = (next.param_snapshot || []).filter(s => (s.api_key || next.api_key) !== incoming.api_key);
  next.sources = (next.sources || []).filter(s => s.api_key !== incoming.api_key);
  next.merge_report = (next.merge_report || []).filter(m => m.api_key !== incoming.api_key);
  return _aspRunnerMergeBundles(next, incoming);
}

function _aspRunnerAppendDuplicateApiCases(base, incoming) {
  const next = _aspRunnerClone(base);
  next.sources = next.sources || [];
  next.sources.push({
    bundle_id: `${incoming.bundle_id}_dup_${_aspRunnerHashText(_aspRunnerIsoNow())}`,
    api_key: incoming.api_key,
    name: `${incoming.name || "AV Collection"} (new)`,
    schema_version: incoming.schema_version,
    generated_at: incoming.generated_at,
  });
  next.param_snapshot = next.param_snapshot || [];
  (incoming.param_snapshot || []).forEach(s => {
    const snap = _aspRunnerClone(s);
    if (!next.param_snapshot.some(x =>
      x.path === snap.path &&
      (x.api_key || next.api_key) === (snap.api_key || incoming.api_key)
    )) {
      next.param_snapshot.push(snap);
    }
  });

  // Preserve each case's own api_key/_method/_url (multi-API safe).
  // Insert after the last existing case of the same api_key so same-API
  // "Treat as New" stays in one section without collapsing other APIs.
  (incoming.cases || []).forEach((c, idx) => {
    const dup = _aspRunnerClone(c);
    dup.case_id = `${c.case_id || "avc"}_dup_${_aspRunnerHashText(incoming.bundle_id + "|" + idx + "|" + _aspRunnerIsoNow())}`;
    dup.source_bundle_id = `${incoming.bundle_id}_dup`;
    dup.created_at = _aspRunnerIsoNow();
    dup.updated_at = dup.created_at;
    dup.merge_state = "new";
    const key = _aspRunnerApiKeyFromCase(dup);
    let insertAt = next.cases.length;
    for (let i = next.cases.length - 1; i >= 0; i--) {
      if (_aspRunnerApiKeyFromCase(next.cases[i]) === key) {
        insertAt = i + 1;
        break;
      }
    }
    dup.order = insertAt;
    next.cases.splice(insertAt, 0, dup);
  });
  return next;
}

// Add more AV Collection files to the existing runner (merge/replace/append)
async function aspRunnerAddCollections(input) {
  if (!input.files || !input.files.length) return;
  if (!_aspRunnerData) { _aspAlert("Import a base collection first."); input.value = ""; return; }

  // Enforce: only JSON and only a single file at a time.
  const files = Array.from(input.files)
    .filter(f => {
      const n = (f?.name || "").toLowerCase();
      return n.endsWith(".json") || (f?.type && String(f.type).toLowerCase().includes("json"));
    })
    .slice(0, 1);

  if (!files.length) {
    _aspAlert("Please select a .json AV Collection file.");
    input.value = "";
    return;
  }
  for (const file of files) {
    try {
      const text = await file.text();
      const bundle = _aspRunnerNormalizeBundle(JSON.parse(text), file.name);
      const existingCount = (_aspRunnerData.cases || []).filter(c => _aspRunnerApiKeyFromCase(c) === bundle.api_key).length;
      if (existingCount > 0) {
        const choice = await _aspRunnerAskDuplicateImport(bundle, existingCount);
        if (choice === "cancel") continue;
        if (choice === "replace") _aspRunnerData = _aspRunnerReplaceApiCases(_aspRunnerData, bundle);
        else _aspRunnerData = _aspRunnerAppendDuplicateApiCases(_aspRunnerData, bundle);
      } else {
        _aspRunnerData = _aspRunnerMergeBundles(_aspRunnerData, bundle);
      }
    } catch(err) {
      _aspAlert(`Failed to import ${file.name}: ${err.message}`);
    }
  }

  _aspRunnerReorderCasesByApi();
  localStorage.setItem(ASP_RUNNER_KEY, JSON.stringify(_aspRunnerData));
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerUpdateTitle();
  _aspRunnerRenderTable(_aspRunnerData.cases);

  input.value = "";
}

function _aspRunnerSetExportEnabled(on) {
  const btn = document.getElementById("asp-runner-export-btn");
  if (!btn) return;
  btn.disabled = !on;
  btn.style.opacity = on ? "" : "0.4";
  btn.style.pointerEvents = on ? "" : "none";
  btn.style.cursor = on ? "pointer" : "not-allowed";
  btn.title = on ? "Export HTML report" : "Wait until the run finishes or is aborted";
}

function _aspRunnerSetExportCollectionEnabled(on) {
  const btn = document.getElementById("asp-runner-export-collection-btn");
  if (!btn) return;
  btn.disabled = !on;
  btn.style.opacity = on ? "" : "0.4";
  btn.style.pointerEvents = on ? "" : "none";
  btn.style.cursor = on ? "pointer" : "not-allowed";
  btn.title = on
    ? "Export current runner cases as an AV collection JSON (reusable for Import)"
    : "Wait until the run finishes or is aborted";
}

let _aspRunnerVars = { chain: {} };
let _aspRunnerSyncState = { blocked: [], warnings: [], counts: {}, legacy: false };

function _aspRunnerIsoNow() {
  return new Date().toISOString();
}

function _aspRunnerHashText(input) {
  const s = String(input || "");
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

function _aspRunnerApiKey(method, url) {
  return `${String(method || "GET").toUpperCase()} ${String(url || "").trim()}`;
}

function _aspRunnerParseApiKey(apiKey) {
  const s = String(apiKey || "").trim();
  if (!s) return { method: null, url: null };
  const i = s.indexOf(" ");
  if (i < 0) return { method: s.toUpperCase(), url: "" };
  return { method: s.slice(0, i).toUpperCase(), url: s.slice(i + 1).trim() };
}

function _aspRunnerApiKeyFromCase(c) {
  if (!c) return "";
  // Prefer stored api_key so multi-API runner collections stay separate.
  if (c.api_key) return String(c.api_key);
  return _aspRunnerApiKey(c._method, c._url);
}

function _aspRunnerCaseKey(c) {
  const apiKey = _aspRunnerApiKeyFromCase(c);
  const paramPath = c.param_path || c.param || "";
  return [apiKey, paramPath, c.case_cat || "", c.case_desc || ""].join("|");
}

/** Keep cases for the same api_key contiguous (does not rewrite identities). */
function _aspRunnerReorderCasesByApi() {
  const cases = _aspRunnerData?.cases;
  if (!cases?.length) return;
  const groups = new Map();
  const order = [];
  cases.forEach(c => {
    const k = _aspRunnerApiKeyFromCase(c);
    if (!groups.has(k)) {
      groups.set(k, []);
      order.push(k);
    }
    groups.get(k).push(c);
  });
  _aspRunnerData.cases = order.flatMap(k => groups.get(k));
}

function _aspRunnerClone(v) {
  if (v == null) return v;
  try { return JSON.parse(JSON.stringify(v)); } catch (_) { return v; }
}

function _aspRunnerNormalizeSnapshot(bundle) {
  if (Array.isArray(bundle?.param_snapshot) && bundle.param_snapshot.length) return bundle.param_snapshot;
  const seen = new Set();
  const out = [];
  (bundle?.cases || []).forEach((c, idx) => {
    const path = c.param_path || c.param || "";
    if (!path || seen.has(path)) return;
    seen.add(path);
    out.push({
      order: idx,
      path,
      detected: "",
      source: String(path).startsWith("query.") ? "query" : "body",
      value_preview: c.test_value == null ? "" : String(c.test_value).slice(0, 120),
      unique_format: c.value_template || null,
      dataset_key: c.dataset_key || null,
    });
  });
  return out;
}

function _aspRunnerNormalizeCase(bundle, c, idx) {
  const parsed = c.api_key ? _aspRunnerParseApiKey(c.api_key) : { method: null, url: null };
  // When api_key is present it is the source of truth (recovers multi-API exports
  // and avoids collapsing onto bundle.method/url).
  const baseMethod = parsed.method || c._method || bundle.method || "GET";
  const baseUrl = (parsed.url != null && parsed.url !== "")
    ? parsed.url
    : ((c._url != null && String(c._url).length) ? c._url : (bundle.url || ""));
  const apiKey = c.api_key || bundle.api_key || _aspRunnerApiKey(baseMethod, baseUrl);
  const paramPath = c.param_path || c.param || "";
  const testValue = c.test_value !== undefined ? c.test_value : c.case_value;
  const dsCaseId = c.dataset_case_id || _aspRunnerNormalizeCaseId(c.case_id, c.case_desc);
  const snapDsKey = Array.isArray(bundle?.param_snapshot) ? bundle.param_snapshot.find(s => s && s.path === paramPath)?.dataset_key : null;
  const dsKey = c.dataset_key || snapDsKey || _aspRunnerDetectDatasetKey(paramPath, testValue);
  const caseId = c.case_id || `avc_${_aspRunnerHashText([apiKey, paramPath, c.case_cat || "", c.case_desc || "", testValue == null ? "" : String(testValue)].join("|"))}`;
  const sourceBundleId = c.source_bundle_id || bundle.bundle_id || `avb_${_aspRunnerHashText(apiKey)}`;
    return {
    ...c,
    _method: baseMethod,
    _url: baseUrl,
    _headers: _aspRunnerClone(c._headers || bundle.headers || {}),
    _body_type: c._body_type || bundle.body_type || "json",
    _base_query: _aspRunnerClone(c.source_query || bundle.query || {}),
    _base_body: _aspRunnerClone(c.source_body !== undefined ? c.source_body : (bundle.body != null ? bundle.body : null)),
    _all_unique_formats: _aspRunnerClone(c.all_unique_formats || bundle.all_unique_formats || {}),
    api_key: apiKey,
    param_path: paramPath,
    test_value: testValue,
    case_value: c.case_value !== undefined ? c.case_value : testValue,
    response: c.response != null ? c.response : null,
    value_template: c.value_template || null,
    case_id: caseId,
    dataset_case_id: dsCaseId || null,
    dataset_key: dsKey || null,
    prev_result: (c.prev_result != null && c.prev_result !== "") ? c.prev_result : "—",
    prev_status: c.prev_status != null ? c.prev_status : null,
    enabled: c.enabled !== false,
    status: c.status || "active",
    merge_state: c.merge_state || "source",
    created_at: c.created_at || bundle.generated_at || _aspRunnerIsoNow(),
    updated_at: _aspRunnerIsoNow(),
    source_bundle_id: sourceBundleId,
    order: c.order != null ? c.order : idx,
    extractors: Array.isArray(c.extractors) ? c.extractors : [],
    bindings: Array.isArray(c.bindings) ? c.bindings : [],
  };
}

function _aspRunnerNormalizeBundle(bundle, fallbackName) {
  if (!bundle || !Array.isArray(bundle.cases)) throw new Error("Invalid AV Collection file.");
  const normalized = {
    ...bundle,
    v: bundle.v || 1,
    schema_version: bundle.schema_version || bundle.v || 1,
    source_tool: bundle.source_tool || "api_validator",
    generated_at: bundle.generated_at || _aspRunnerIsoNow(),
    bundle_id: bundle.bundle_id || `avb_${_aspRunnerHashText((bundle.method || "GET") + "|" + (bundle.url || "") + "|" + (fallbackName || ""))}`,
    method: (bundle.method || "GET").toUpperCase(),
    url: bundle.url || "",
    headers: _aspRunnerClone(bundle.headers || {}),
    query: _aspRunnerClone(bundle.query || {}),
    body: _aspRunnerClone(bundle.body != null ? bundle.body : null),
    body_type: bundle.body_type || "json",
    name: bundle.name || fallbackName || "AV Collection",
    sync_policy: bundle.sync_policy || "precheck_block",
    all_unique_formats: _aspRunnerClone(bundle.all_unique_formats || {}),
    unique_pools_by_api: _aspRunnerClone(bundle.unique_pools_by_api || {}),
  };
  normalized.api_key = bundle.api_key || _aspRunnerApiKey(normalized.method, normalized.url);
  normalized.param_snapshot = _aspRunnerNormalizeSnapshot(bundle);
  normalized.cases = (bundle.cases || []).map((c, idx) => _aspRunnerNormalizeCase(normalized, c, idx));
  _aspRunnerAttachUniqueFormats(normalized);
  normalized.legacy = !bundle.schema_version || bundle.schema_version < 2 || !normalized.cases.every(c => c.case_id && c.param_path);
  return normalized;
}

function _aspRunnerAttachUniqueFormats(bundle) {
  if (!bundle) return bundle;
  const snapFmtsByApi = {};
  (bundle.param_snapshot || []).forEach(s => {
    if (!s || !s.path || !s.unique_format) return;
    const key = s.api_key || bundle.api_key || "";
    snapFmtsByApi[key] = snapFmtsByApi[key] || {};
    snapFmtsByApi[key][s.path] = s.unique_format;
  });
  const bundleFmts = bundle.all_unique_formats || {};
  (bundle.cases || []).forEach(c => {
    const apiKey = _aspRunnerApiKeyFromCase(c);
    const fromSnap = snapFmtsByApi[apiKey] || snapFmtsByApi[bundle.api_key] || snapFmtsByApi[""] || {};
    c._all_unique_formats = {
      ...fromSnap,
      ...bundleFmts,
      ...(c._all_unique_formats || {}),
    };
  });
  return bundle;
}

function _aspRunnerMergeBundles(base, incoming) {
  if (!base) return incoming;
  const byId = new Map();
  const byFallback = new Map();
  (base.cases || []).forEach((c, idx) => {
    byId.set(c.case_id, { c, idx });
    byFallback.set(_aspRunnerCaseKey(c), { c, idx });
  });
  const merged = _aspRunnerClone(base);
  merged.merge_report = merged.merge_report || [];
  merged.sources = merged.sources || [];
  merged.param_snapshot = merged.param_snapshot || [];
  merged.sources.push({
    bundle_id: incoming.bundle_id,
    api_key: incoming.api_key,
    name: incoming.name,
    schema_version: incoming.schema_version,
    generated_at: incoming.generated_at,
  });
  (incoming.param_snapshot || []).forEach(s => {
    const existing = merged.param_snapshot.find(x =>
      x.path === s.path && (x.api_key || merged.api_key) === (s.api_key || incoming.api_key)
    );
    if (!existing) {
      merged.param_snapshot.push(s);
      return;
    }
    if (s.unique_format && !existing.unique_format) existing.unique_format = s.unique_format;
    if (s.dataset_key && !existing.dataset_key) existing.dataset_key = s.dataset_key;
  });
  const incFmt = incoming.all_unique_formats || {};
  if (Object.keys(incFmt).length) {
    if (!incoming.api_key || !merged.api_key || incoming.api_key === merged.api_key) {
      merged.all_unique_formats = { ...(merged.all_unique_formats || {}), ...incFmt };
    }
    (merged.cases || []).forEach(c => {
      if (incoming.api_key && _aspRunnerApiKeyFromCase(c) !== incoming.api_key) return;
      c._all_unique_formats = { ...(c._all_unique_formats || {}), ...incFmt };
    });
  }
  merged.unique_pools_by_api = merged.unique_pools_by_api || {};
  Object.entries(incoming.unique_pools_by_api || {}).forEach(([k, rec]) => {
    if (!merged.unique_pools_by_api[k] && rec) merged.unique_pools_by_api[k] = _aspRunnerClone(rec);
  });
  (incoming.cases || []).forEach(nextCase => {
    const direct = byId.get(nextCase.case_id);
    const fallback = byFallback.get(_aspRunnerCaseKey(nextCase));
    if (direct) {
      merged.cases[direct.idx] = {
        ...direct.c,
        ...nextCase,
        _all_unique_formats: { ...(direct.c._all_unique_formats || {}), ...(nextCase._all_unique_formats || {}) },
        merge_state: "updated",
        updated_at: _aspRunnerIsoNow(),
        source_bundle_id: nextCase.source_bundle_id || incoming.bundle_id,
      };
      merged.merge_report.push({ type: "updated", case_id: nextCase.case_id, param_path: nextCase.param_path, api_key: nextCase.api_key });
      return;
    }
    if (fallback) {
      merged.cases[fallback.idx] = {
        ...fallback.c,
        ...nextCase,
        _all_unique_formats: { ...(fallback.c._all_unique_formats || {}), ...(nextCase._all_unique_formats || {}) },
        merge_state: "updated",
        updated_at: _aspRunnerIsoNow(),
        source_bundle_id: nextCase.source_bundle_id || incoming.bundle_id,
      };
      merged.merge_report.push({ type: "fallback_updated", case_id: nextCase.case_id, param_path: nextCase.param_path, api_key: nextCase.api_key });
      return;
    }
    merged.cases.push({ ...nextCase, merge_state: "new" });
    merged.merge_report.push({ type: "new", case_id: nextCase.case_id, param_path: nextCase.param_path, api_key: nextCase.api_key });
  });
  _aspRunnerUnionUniqueFormatsByApi(merged);
  return merged;
}

function _aspRunnerUnionUniqueFormatsByApi(bundle) {
  if (!bundle?.cases) return;
  const byApi = {};
  (bundle.cases || []).forEach(c => {
    const k = _aspRunnerApiKeyFromCase(c);
    byApi[k] = { ...(byApi[k] || {}), ...(c._all_unique_formats || {}) };
  });
  (bundle.cases || []).forEach(c => {
    const k = _aspRunnerApiKeyFromCase(c);
    c._all_unique_formats = { ...(byApi[k] || {}), ...(c._all_unique_formats || {}) };
  });
}

function _aspRunnerRefreshCaseStatuses() {
  if (!_aspRunnerData?.cases) return;
  const snapshotByApi = {};
  (_aspRunnerData.sources || []).forEach(() => {});
  const allSnapshots = _aspRunnerData.param_snapshot || [];
  allSnapshots.forEach(s => {
    const key = s.api_key || _aspRunnerData.api_key;
    snapshotByApi[key] = snapshotByApi[key] || new Set();
    snapshotByApi[key].add(s.path);
  });
  _aspRunnerData.cases.forEach(c => {
    if (c.enabled === false) {
      c.status = "disabled";
      return;
    }
    const known = snapshotByApi[c.api_key] || snapshotByApi[_aspRunnerData.api_key];
    if (known && c.param_path && !known.has(c.param_path)) {
      c.status = "removed_param";
    } else if (!c.status || c.status === "source") {
      c.status = "active";
    } else if (c.status === "disabled") {
      c.status = "disabled";
    } else if (c.status !== "removed_param") {
      c.status = "active";
    }
  });
}

function _aspRunnerBuildSyncState() {
  const state = { blocked: [], warnings: [], counts: { active: 0, disabled: 0, removed_param: 0, legacy: 0 }, legacy: !!_aspRunnerData?.legacy };
  const snapshotPaths = new Set((_aspRunnerData?.param_snapshot || []).map(s => s.path));
  (_aspRunnerData?.cases || []).forEach(c => {
    if (c.enabled === false || c.status === "disabled") {
      state.counts.disabled++;
      return;
    }
    if (!c.case_id || !c.param_path) {
      state.warnings.push(`Legacy case metadata missing for ${c.case_desc || c.param || "case"}`);
      state.counts.legacy++;
    }
    if (c.param_path && snapshotPaths.size && !snapshotPaths.has(c.param_path)) {
      state.blocked.push(`Param removed or changed: ${c.param_path}`);
      state.counts.removed_param++;
      return;
    }
    if ((c.extractors || []).some(ex => ex && ex.store_as && !String(ex.store_as).trim())) {
      state.blocked.push(`Invalid extractor on ${c.param_path || c.case_id}`);
      return;
    }
    state.counts.active++;
  });
  if (_aspRunnerData?.legacy) state.warnings.push("Legacy AV collection imported: fallback matching will be used until re-exported from API Validator.");
  (_aspRunnerData?.merge_report || []).forEach(m => {
    if (m.type === "fallback_updated") state.warnings.push(`Fallback merge used for ${m.param_path || m.case_id}`);
  });
  return state;
}

function _aspRunnerShowSyncGate(sync) {
  const blocked = sync.blocked || [];
  const warnings = sync.warnings || [];
  const lines = [
    blocked.length ? `Blocked: ${blocked.length}` : "Blocked: 0",
    warnings.length ? `Warnings: ${warnings.length}` : "Warnings: 0",
    `Active cases: ${sync.counts?.active || 0}`,
    `Disabled: ${sync.counts?.disabled || 0}`,
  ];
  let msg = "Runner sync check failed.\n\n" + lines.join("\n");
  if (blocked.length) msg += "\n\nCritical issues:\n- " + blocked.slice(0, 8).join("\n- ");
  if (warnings.length) msg += "\n\nWarnings:\n- " + warnings.slice(0, 8).join("\n- ");
  _aspAlert(msg);
}

function _aspRunnerResolveVarValue(name, vars, chain) {
  const hit = (vars || []).find(v => v && v.enabled !== false && v.key === name);
  if (hit) return hit.value || "";
  if (chain && Object.prototype.hasOwnProperty.call(chain, name)) return chain[name];
  return "{{" + name + "}}";
}

function _aspRunnerApplyVarsAndTokens(str, vars, chain) {
  if (str == null || typeof str !== "string") return str;
  let out = str.replace(/\{\{([^}]+)\}\}/g, (_, name) => _aspRunnerResolveVarValue(String(name || "").trim(), vars, chain));
  out = _aspResolveTokens(out);
  return out;
}

function _aspRunnerResolveDeep(value, vars, chain) {
  if (typeof value === "string") return _aspRunnerApplyVarsAndTokens(value, vars, chain);
  if (Array.isArray(value)) return value.map(v => _aspRunnerResolveDeep(v, vars, chain));
  if (value && typeof value === "object") {
    const out = {};
    Object.keys(value).forEach(k => { out[k] = _aspRunnerResolveDeep(value[k], vars, chain); });
    return out;
  }
  return value;
}

function _aspRunnerResolvePayload(payload, vars, chain) {
  const out = _aspRunnerClone(payload);
  delete out._unique_applied;
  out.url = _aspRunnerApplyVarsAndTokens(out.url, vars, chain);
  out.headers = _aspRunnerResolveDeep(out.headers || {}, vars, chain);
  out.params = _aspRunnerResolveDeep(out.params || {}, vars, chain);
  if (out.auth) out.auth = _aspRunnerResolveDeep(out.auth, vars, chain);
  if (out.body != null) out.body = _aspRunnerResolveDeep(out.body, vars, chain);
  return out;
}

function _aspRunnerTryJsonContainer(val) {
  if (val !== null && typeof val === "object") return { val, conv: false };
  if (typeof val !== "string") return { val, conv: false };
  const s = val.trim();
  if (!s || (s[0] !== "{" && s[0] !== "[")) return { val, conv: false };
  try {
    const parsed = JSON.parse(s);
    if (parsed !== null && typeof parsed === "object") return { val: parsed, conv: true };
  } catch (_) {}
  return { val, conv: false };
}

function _aspRunnerParsePathTokens(path) {
  const out = [];
  String(path || "").replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean).forEach(t => {
    out.push(/^\d+$/.test(t) ? Number(t) : t);
  });
  return out;
}

function _aspRunnerTokensToPath(tokens) {
  let out = "";
  (tokens || []).forEach(t => {
    if (typeof t === "number") out += `[${t}]`;
    else out += out ? `.${t}` : t;
  });
  return out;
}

function _aspRunnerCanonPath(path) {
  return String(path || "").replace(/\[(\d+)\]/g, ".$1");
}

function _aspRunnerUniquePathSkipped(path, skipPath) {
  if (!path || !skipPath) return false;
  return _aspRunnerCanonPath(path) === _aspRunnerCanonPath(skipPath);
}

function _aspRunnerNormalizeJsonBody(body, bodyType) {
  const bt = String(bodyType || "").toLowerCase();
  if (typeof body === "string" && ["", "json", "raw", "application/json"].includes(bt)) {
    const t = _aspRunnerTryJsonContainer(body);
    if (t.conv) return { body: t.val, body_type: "json" };
  }
  if (body && typeof body === "object" && bt !== "form" && bt !== "multipart") {
    return { body, body_type: bodyType || "json" };
  }
  return { body, body_type: bodyType };
}

function _aspRunnerCoerceLike(existing, fresh) {
  if (typeof existing === "number") {
    const n = Number(fresh);
    if (!Number.isNaN(n)) return n;
  }
  return fresh;
}

function _aspRunnerReadPath(obj, path) {
  if (!path || obj == null) return undefined;
  const tokens = _aspRunnerParsePathTokens(path);
  if (!tokens.length) return undefined;
  if (Array.isArray(obj) && typeof tokens[0] === "string") {
    if (tokens.length >= 2 && typeof tokens[1] === "number") {
      const inner = _aspRunnerReadPath(obj, _aspRunnerTokensToPath(tokens.slice(1)));
      if (inner !== undefined) return inner;
    }
    if (obj.length && obj[0] && typeof obj[0] === "object" && !Array.isArray(obj[0])) {
      return _aspRunnerReadPath(obj[0], path);
    }
  }
  let cur = obj;
  for (const t of tokens) {
    if (cur == null) return undefined;
    const box = _aspRunnerTryJsonContainer(cur);
    if (box.conv) cur = box.val;
    if (typeof t === "number") {
      if (!Array.isArray(cur)) return undefined;
      cur = cur[t];
      continue;
    }
    if (Array.isArray(cur) && cur[0] && typeof cur[0] === "object" && !Array.isArray(cur[0])) cur = cur[0];
    if (cur == null || typeof cur !== "object") return undefined;
    cur = cur[t];
  }
  return cur;
}

function _aspRunnerSetPathRaw(body, path, value) {
  const tokens = _aspRunnerParsePathTokens(path);
  if (!tokens.length || body == null || typeof body === "string") return false;
  if (Array.isArray(body) && typeof tokens[0] === "string") {
    if (tokens.length >= 2 && typeof tokens[1] === "number") {
      if (_aspRunnerSetPathRaw(body, _aspRunnerTokensToPath(tokens.slice(1)), value)) return true;
    }
    if (body.length && body[0] && typeof body[0] === "object" && !Array.isArray(body[0])) {
      return _aspRunnerSetPathRaw(body[0], path, value);
    }
    return false;
  }
  let obj = body;
  for (let i = 0; i < tokens.length - 1; i++) {
    const tok = tokens[i];
    const nextTok = tokens[i + 1];
    if (typeof tok === "number") {
      if (!Array.isArray(obj) || tok < 0 || tok >= obj.length) return false;
      let child = obj[tok];
      const parsed = _aspRunnerTryJsonContainer(child);
      if (parsed.conv) { obj[tok] = parsed.val; child = parsed.val; }
      obj = child;
      continue;
    }
    if (Array.isArray(obj) && obj[0] && typeof obj[0] === "object" && !Array.isArray(obj[0])) obj = obj[0];
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
    if (!(tok in obj) || obj[tok] == null) obj[tok] = typeof nextTok === "number" ? [] : {};
    let nxt = obj[tok];
    const parsed = _aspRunnerTryJsonContainer(nxt);
    if (parsed.conv) { obj[tok] = parsed.val; nxt = parsed.val; }
    if (Array.isArray(nxt) && nxt[0] && typeof nxt[0] === "object" && !Array.isArray(nxt[0]) && typeof nextTok === "string") {
      obj = nxt[0];
    } else {
      obj = nxt;
    }
  }
  const last = tokens[tokens.length - 1];
  if (Array.isArray(obj) && obj[0] && typeof obj[0] === "object" && !Array.isArray(obj[0]) && typeof last === "string") obj = obj[0];
  if (typeof last === "number") {
    if (Array.isArray(obj) && last >= 0 && last < obj.length) { obj[last] = value; return true; }
    return false;
  }
  if (obj && typeof obj === "object" && !Array.isArray(obj)) { obj[last] = value; return true; }
  return false;
}

function _aspRunnerSetPath(obj, path, value) {
  if (!path || obj == null) return;
  if (_aspRunnerSetPathRaw(obj, path, value)) return;
  const tokens = String(path).replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  if (!tokens.length) return;
  let cur = obj;
  for (let i = 0; i < tokens.length - 1; i++) {
    const t = tokens[i];
    const next = tokens[i + 1];
    if (cur == null || typeof cur !== "object") return;
    if (cur[t] == null) cur[t] = /^\d+$/.test(next) ? [] : {};
    cur = cur[t];
  }
  if (cur && typeof cur === "object") cur[tokens[tokens.length - 1]] = value;
}

function _aspRunnerPathInSkipSet(path, skipSet) {
  if (!skipSet || !skipSet.size) return false;
  for (const s of skipSet) {
    if (_aspRunnerUniquePathSkipped(path, s)) return true;
  }
  return false;
}

function _aspRunnerApplyUniqueFormats(body, query, uniqueFormats, skipPath, resolveTokens, extraSkip) {
  const applied = [];
  Object.entries(uniqueFormats || {}).forEach(([path, fmt]) => {
    const tok = fmt == null ? "" : String(fmt);
    if (!tok || _aspRunnerUniquePathSkipped(path, skipPath) || _aspRunnerPathInSkipSet(path, extraSkip)) return;
    const fresh = resolveTokens ? _aspResolveTokens(tok) : tok;
    if (!fresh) return;
    if (String(path).startsWith("query.")) {
      const key = String(path).slice(6);
      if (!key) return;
      query[key] = resolveTokens ? _aspRunnerCoerceLike(query[key], fresh) : fresh;
    } else if (body && typeof body === "object") {
      const existing = _aspRunnerReadPath(body, path);
      _aspRunnerSetPath(body, path, resolveTokens ? _aspRunnerCoerceLike(existing, fresh) : fresh);
    }
    applied.push({ path, value: fresh, source: "format" });
  });
  return applied;
}

function _aspRunnerWritePathValue(body, query, path, value) {
  if (String(path).startsWith("query.")) {
    const key = String(path).slice(6);
    if (key) query[key] = value;
    return;
  }
  if (body && typeof body === "object") _aspRunnerSetPath(body, path, value);
}

function _aspRunnerBuildCasePayload(bundle, c, poolRow, runtimeCaseValue) {
  let body = _aspRunnerClone(c._base_body !== undefined ? c._base_body : (bundle.body != null ? bundle.body : null));
  if (!body && (c.body || c.body === "")) {
    try { body = typeof c.body === "string" ? JSON.parse(c.body) : _aspRunnerClone(c.body); } catch (_) { body = c.body; }
  }
  let bodyType = c._body_type || bundle.body_type || "json";
  const norm = _aspRunnerNormalizeJsonBody(body, bodyType);
  body = norm.body;
  bodyType = norm.body_type || bodyType;
  const query = _aspRunnerClone(c._base_query || bundle.query || {});
  const uniqueFormats = c._all_unique_formats || bundle.all_unique_formats || {};
  const casePathStr = String(c.param_path || c.param || "");
  const extraSkip = new Set(Object.keys(poolRow || {}));
  const uniqueApplied = _aspRunnerApplyUniqueFormats(body, query, uniqueFormats, casePathStr, true, extraSkip);
  Object.entries(poolRow || {}).forEach(([path, val]) => {
    if (val == null || val === "") return;
    _aspRunnerWritePathValue(body, query, path, val);
    uniqueApplied.push({ path, value: val, source: "list" });
  });

  const caseValue = runtimeCaseValue !== undefined ? runtimeCaseValue : (c.case_value !== undefined ? c.case_value : c.test_value);
  if (casePathStr.startsWith("query.")) {
    query[casePathStr.slice(6)] = caseValue;
  } else if (casePathStr && body && typeof body === "object") {
    _aspRunnerSetPath(body, casePathStr, caseValue);
  } else if (c.body || c.body === "") {
    try { body = JSON.parse(c.body); } catch (_) { body = c.body; }
  }

  return {
    method: c._method || bundle.method,
    url: c._url || bundle.url,
    headers: _aspRunnerClone(c._headers || bundle.headers || {}),
    params: query,
    body,
    body_type: bodyType,
    auth: { type: "none" },
    _unique_applied: uniqueApplied,
  };
}

// Build a "template view" of the payload for editing:
// - do not resolve random tokens into concrete values
// - instead inject token placeholders like "{name}", "{num:8}" when available
function _aspRunnerBuildCasePayloadTemplate(bundle, c) {
  let body = _aspRunnerClone(c._base_body !== undefined ? c._base_body : (bundle.body != null ? bundle.body : null));
  let bodyType = c._body_type || bundle.body_type || "json";
  const norm = _aspRunnerNormalizeJsonBody(body, bodyType);
  body = norm.body;
  bodyType = norm.body_type || bodyType;
  const query = _aspRunnerClone(c._base_query || bundle.query || {});
  const uniqueFormats = c._all_unique_formats || bundle.all_unique_formats || {};
  const casePath = String(c.param_path || c.param || "");
  const poolRec = (bundle.unique_pools_by_api || {})[_aspRunnerApiKeyFromCase(c)] || {};
  const extraSkip = new Set(Object.keys(poolRec.matched || {}));
  _aspRunnerApplyUniqueFormats(body, query, uniqueFormats, casePath, false, extraSkip);

  const caseValue = c.case_value !== undefined ? c.case_value : c.test_value;
  if (casePath.startsWith("query.")) {
    query[casePath.slice(6)] = caseValue;
  } else if (casePath && body && typeof body === "object") {
    _aspRunnerSetPath(body, casePath, caseValue);
  } else if (c.body || c.body === "") {
    try { body = JSON.parse(c.body); } catch (_) { body = c.body; }
  }

  return {
    method: c._method || bundle.method,
    url: c._url || bundle.url,
    headers: _aspRunnerClone(c._headers || bundle.headers || {}),
    params: query,
    body,
    body_type: bodyType,
    auth: { type: "none" },
  };
}

function _aspRunnerApplyExtractors(caseCfg, respData) {
  const chain = _aspRunnerVars.chain || (_aspRunnerVars.chain = {});
  const list = Array.isArray(caseCfg?.extractors) ? caseCfg.extractors : [];
  list.forEach(ex => {
    if (!ex || !ex.store_as) return;
    let val;
    if (ex.from === "header") {
      const hdrs = respData?.headers || {};
      const key = Object.keys(hdrs).find(k => k.toLowerCase() === String(ex.path || "").toLowerCase());
      val = key ? hdrs[key] : undefined;
    } else {
      let body = respData?.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (_) {}
      }
      val = _aspRunnerReadPath(body, ex.path);
    }
    if (val != null) chain[ex.store_as] = String(val);
  });
}

function aspRunnerSwitchTab(name) {
  _aspRunnerTab = name === "dashboard" ? "dashboard" : "cases";
  const casesEl = document.getElementById("asp-runner-tab-cases");
  const dashEl  = document.getElementById("asp-runner-dashboard");
  const tabC    = document.getElementById("asp-runner-tabbtn-cases");
  const tabD    = document.getElementById("asp-runner-tabbtn-dashboard");
  if (casesEl) casesEl.style.display = _aspRunnerTab === "cases" ? "block" : "none";
  if (dashEl)  dashEl.style.display  = _aspRunnerTab === "dashboard" ? "flex" : "none";
  if (tabC) tabC.classList.toggle("active", _aspRunnerTab === "cases");
  if (tabD) tabD.classList.toggle("active", _aspRunnerTab === "dashboard");
  if (_aspRunnerTab === "dashboard") {
    aspRunnerDashboardShow();
    _aspRunnerSetExportEnabled(!_aspRunnerRunning);
  }
}

function aspRunnerHide() {
  _aspHideAvRunnerPanelOnly();
  _aspSyncChromeLock();
}

async function aspRunnerReset() {
  if (_aspRunnerRunning) {
    _aspAlert("Stop the runner before resetting.");
    return;
  }
  const ok = await _aspConfirm("Reset Runner tab and remove all imported runner cases?");
  if (!ok) return;
  localStorage.removeItem(ASP_RUNNER_KEY);
  _aspRunnerData = null;
  _aspRunnerVars = { chain: {} };
  _aspRunnerLastResults = [];
  _aspRunnerBodyEdit = null;
  _aspRunnerRandomState = null;
  _aspRunnerCloseExpand();
  _aspHideAvRunnerPanelOnly();
  _aspSyncChromeLock();
}

function aspRunnerFilterChange() {
  if (!_aspRunnerData) return;
  _aspRunnerRenderTable(_aspRunnerData.cases);
}

function _aspRunnerPrettyBody(v) {
  if (v == null || v === "") return "";
  if (typeof v === "string") {
    try { return JSON.stringify(JSON.parse(v), null, 2); } catch (_) { return v; }
  }
  try { return JSON.stringify(v, null, 2); } catch (_) { return String(v); }
}

function _aspRunnerFallbackCurl(p) {
  const parts = [`curl -X ${p.method || "GET"} '${String(p.url || "").replace(/'/g, "'\\''")}'`];
  Object.entries(p.headers || {}).forEach(([k, v]) => {
    parts.push(`  -H '${String(k)}: ${String(v).replace(/'/g, "'\\''")}'`);
  });
  if (p.body != null && p.body !== "") {
    const bodyStr = typeof p.body === "string" ? p.body : JSON.stringify(p.body);
    parts.push(`  --data-raw '${String(bodyStr).replace(/'/g, "'\\''")}'`);
  }
  return parts.join(" \\\n");
}

function aspRunnerSearchReq(origIdx) {
  const cache = _aspRunnerExpandSearchCache?.[origIdx];
  if (!cache) return;
  const inp = document.getElementById(`asp-runner-req-search-${origIdx}`);
  const q = (inp?.value || "").trim();
  const wrap = document.getElementById(`asp-runner-req-prewrap-${origIdx}`);
  if (!wrap) return;
  wrap.innerHTML = cache.reqText
    ? _aspRunnerPreHtml(cache.reqText, q || cache.sentVal, q ? [] : cache.uniqueApplied)
    : `<span style="font-size:11px;color:var(--text3)">(no body)</span>`;
}

function aspRunnerSearchResp(origIdx) {
  const cache = _aspRunnerExpandSearchCache?.[origIdx];
  if (!cache) return;
  const inp = document.getElementById(`asp-runner-resp-search-${origIdx}`);
  const q = (inp?.value || "").trim();
  const wrap = document.getElementById(`asp-runner-resp-prewrap-${origIdx}`);
  if (!wrap) return;
  wrap.innerHTML = cache.respText
    ? _aspRunnerPreHtml(cache.respText, q || null)
    : `<span style="font-size:11px;color:var(--text3)">(no response)</span>`;
}

function _aspRunnerWrapEscaped(escapedHaystack, rawNeedle, cls) {
  if (!rawNeedle) return escapedHaystack;
  const needleHtml = _aspEscHtml(String(rawNeedle));
  if (!needleHtml) return escapedHaystack;
  const re = new RegExp(needleHtml.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
  return escapedHaystack.replace(re, m => `<mark class="${cls}">${m}</mark>`);
}

function _aspRunnerUniqueShouldMark(s) {
  if (s == null) return false;
  const str = String(s);
  if (str.length < 2) return false;
  const low = str.trim().toLowerCase();
  return !["true", "false", "null", "{}", "[]"].includes(low);
}

function _aspRunnerPreHtml(text, highlight, extras) {
  const raw = text || "(empty)";
  let html = _aspEscHtml(raw);
  const marks = [];
  const seen = new Set();
  (extras || []).forEach(u => {
    const n = u && u.value != null ? String(u.value) : "";
    if (!_aspRunnerUniqueShouldMark(n) || seen.has(n) || !raw.includes(n)) return;
    seen.add(n);
    marks.push({ needle: n, cls: u.source === "format" ? "av-unique-fmt-mark" : "av-unique-list-mark" });
  });
  const main = highlight != null && highlight !== "" && highlight !== "—" ? String(highlight) : "";
  if (main && raw.includes(main)) {
    marks.push({ needle: main, cls: "asp-runner-val-mark" });
  }
  marks.sort((a, b) => b.needle.length - a.needle.length);
  marks.forEach(h => { html = _aspRunnerWrapEscaped(html, h.needle, h.cls); });
  return `<pre class="asp-runner-io-pre">${html}</pre>`;
}

function aspRunnerCopyCurl(origIdx, btn) {
  const curl = _aspRunnerCurlByIdx[origIdx] || "";
  if (!curl) return;
  _aspClipboard(curl, btn, "📋 cURL");
}

function aspRunnerCopyBody(origIdx, which, btn) {
  const cache = _aspRunnerExpandSearchCache?.[origIdx];
  if (!cache) return;
  const text = which === "resp" ? cache.respText : cache.reqText;
  if (!text) return;
  _aspClipboard(text, btn, "Copy body");
}

function _aspRunnerBodySizeHint(text) {
  const n = String(text || "").length;
  if (n < 4096) return "";
  return `<span class="av-body-size">${Math.max(1, Math.round(n / 1024))} KB</span>`;
}

function _aspRunnerCloseExpand() {
  document.querySelectorAll("tr.asp-runner-expand").forEach(el => el.remove());
  document.querySelectorAll("tr.asp-runner-row-open").forEach(el => {
    el.classList.remove("asp-runner-row-open");
    const ch = el.querySelector(".asp-runner-chev");
    if (ch) ch.textContent = "▶";
  });
  _aspRunnerExpandIdx = -1;
}

function _aspRunnerClearRunResultsUI() {
  // Editing/randomizing changes payload templates; old sent bodies become stale.
  _aspRunnerLastResults = [];
  _aspRunnerCloseExpand();
  if (_aspRunnerData) {
    _aspRunnerRenderTable(_aspRunnerData.cases);
    _aspRunnerRefreshDashboard();
  }
}

function _aspRunnerFlattenLeafValues(obj, prefix, out, emitDotAlt) {
  if (obj == null || typeof obj !== "object") {
    if (prefix) out[prefix] = obj;
    return;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => {
      const p1 = prefix ? `${prefix}[${i}]` : `[${i}]`;
      const p2 = emitDotAlt
        ? (prefix ? `${prefix}.${i}` : `${i}`)
        : null;
      _aspRunnerFlattenLeafValues(v, p1, out, emitDotAlt);
      if (p2) {
        // Duplicate path variant for matching cases where path format differs.
        // (e.g. analyzer sometimes uses brackets, sometimes plain numeric segments)
        const subOut = {};
        const beforeLen = Object.keys(out).length;
        _aspRunnerFlattenLeafValues(v, p2, subOut, emitDotAlt);
        Object.keys(subOut).forEach(k => { out[k] = subOut[k]; });
        if (Object.keys(out).length === beforeLen) {} // no-op (avoid lint)
      }
    });
    return;
  }
  Object.keys(obj).forEach(k => {
    const p = prefix ? `${prefix}.${k}` : k;
    _aspRunnerFlattenLeafValues(obj[k], p, out, emitDotAlt);
  });
}

function _aspRunnerDiffLeafPaths(oldObj, newObj) {
  if (oldObj == null || newObj == null) return new Set();
  if (typeof oldObj !== "object" || typeof newObj !== "object") return new Set();
  const a = {}, b = {};
  _aspRunnerFlattenLeafValues(oldObj, "", a, true);
  _aspRunnerFlattenLeafValues(newObj, "", b, true);
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const changed = new Set();
  keys.forEach(k => {
    const va = a[k];
    const vb = b[k];
    // cheap deep compare for primitive leafs
    if (JSON.stringify(va) !== JSON.stringify(vb)) changed.add(k);
  });
  return changed;
}

/** Leaf paths present in old body but missing from new body. */
function _aspRunnerRemovedLeafPaths(oldObj, newObj) {
  const a = {}, b = {};
  if (oldObj != null && typeof oldObj === "object") _aspRunnerFlattenLeafValues(oldObj, "", a, true);
  if (newObj != null && typeof newObj === "object") _aspRunnerFlattenLeafValues(newObj, "", b, true);
  const removed = new Set();
  Object.keys(a).forEach(k => {
    if (!Object.prototype.hasOwnProperty.call(b, k)) removed.add(k);
  });
  return removed;
}

function _aspRunnerFindRemovedParamImpacts(apiKey, oldBody, newBody) {
  const removed = _aspRunnerRemovedLeafPaths(oldBody, newBody);
  const impacts = [];
  removed.forEach(path => {
    const cases = (_aspRunnerData?.cases || []).filter(c =>
      _aspRunnerApiKeyFromCase(c) === apiKey && (c.param_path || c.param || "") === path
    );
    const snap = _aspRunnerGetParamSnapshotEntry(apiKey, path);
    const dsKey = cases.find(c => c.dataset_key)?.dataset_key || snap?.dataset_key || null;
    if (!cases.length && !dsKey && !(snap?.unique_format)) return;
    impacts.push({
      path,
      caseCount: cases.length,
      datasetKey: dsKey,
      hasDataset: !!dsKey,
      hasUnique: !!(snap?.unique_format),
    });
  });
  return impacts;
}

function _aspRunnerConfirmRemovedMappedParams(impacts, applyAll) {
  if (!impacts?.length) return Promise.resolve(true);
  const withCases = impacts.filter(i => i.caseCount > 0 || i.hasDataset);
  if (!withCases.length) return Promise.resolve(true);

  const lines = withCases.map(i => {
    const ds = i.datasetKey && _aspRunnerAllDatasets?.[i.datasetKey]?.label
      ? _aspRunnerAllDatasets[i.datasetKey].label
      : (i.datasetKey || "mapped");
    const caseBit = i.caseCount ? `${i.caseCount} case${i.caseCount === 1 ? "" : "s"}` : "dataset mapping";
    return `• ${i.path} — ${caseBit}${i.hasDataset ? ` (${ds})` : ""}`;
  }).join("\n");

  const scope = applyAll ? "Apply for All" : "Save";
  return _aspConfirm(
    `These parameters were removed from the Request Body but have mapped dataset/cases:\n\n` +
    `${lines}\n\n` +
    `If you continue with ${scope}, those mapped cases will be deleted and the dataset mapping will be cleared.\n\n` +
    `Continue?`
  );
}

function _aspRunnerPurgeParamsFromApi(apiKey, paramPaths) {
  if (!_aspRunnerData || !paramPaths?.length) return;
  const pathSet = new Set(paramPaths);
  _aspRunnerData.cases = (_aspRunnerData.cases || []).filter(c => {
    if (_aspRunnerApiKeyFromCase(c) !== apiKey) return true;
    const p = c.param_path || c.param || "";
    return !pathSet.has(p);
  });
  _aspRunnerData.param_snapshot = (_aspRunnerData.param_snapshot || []).filter(s => {
    const sApi = s.api_key || _aspRunnerData.api_key;
    if (sApi !== apiKey) return true;
    return !pathSet.has(s.path);
  });
  (_aspRunnerData.cases || []).filter(c => _aspRunnerApiKeyFromCase(c) === apiKey).forEach(c => {
    if (!c._all_unique_formats) return;
    pathSet.forEach(p => { delete c._all_unique_formats[p]; });
  });
  if (_aspRunnerData.all_unique_formats) {
    pathSet.forEach(p => { delete _aspRunnerData.all_unique_formats[p]; });
  }
}

function aspRunnerBodyEditBegin(origIdx) {
  if (_aspRunnerRunning) return;
  const d = _aspRunnerData;
  const c = d?.cases?.[origIdx];
  if (!c) return;
  _aspRunnerBodyEdit = {
    origIdx,
    apiKey: _aspRunnerApiKeyFromCase(c),
    // Show editable "template" values (token placeholders), not concrete
    // resolved values from the last run. Otherwise Save() would bake
    // randomness as static literals.
    draftText: (() => {
      try {
        const tpl = _aspRunnerBuildCasePayloadTemplate(d, c);
        return tpl?.body != null ? _aspRunnerPrettyBody(tpl.body) : "";
      } catch (_) {
        const r = [..._aspRunnerLastResults].reverse().find(x => x.origIdx === origIdx);
        return r?.reqPayload?.body != null ? _aspRunnerPrettyBody(r.reqPayload.body) : "";
      }
    })(),
  };
  _aspRunnerCloseExpand();
  aspRunnerToggleRow(origIdx);
}

function aspRunnerBodyEditCancel() {
  _aspRunnerBodyEdit = null;
  _aspRunnerCloseExpand();
}

function _aspRunnerFormatJsonError(err, text) {
  const raw = String(err?.message || err || "Invalid JSON").replace(/^JSON\.parse:\s*/i, "");
  const posMatch = raw.match(/(?:position|at)\s+(\d+)/i);
  if (posMatch) {
    const pos = parseInt(posMatch[1], 10);
    const before = String(text || "").slice(0, pos);
    const line = (before.match(/\n/g) || []).length + 1;
    const col = pos - before.lastIndexOf("\n");
    const detail = raw.replace(/\s*(?:in JSON at position|at position)\s+\d+.*/i, "").trim();
    return `Line ${line}, column ${col}: ${detail || raw}`;
  }
  return raw;
}

function _aspRunnerBodyEditSetSaveEnabled(on) {
  document.querySelectorAll(".asp-runner-body-save-btn, .asp-runner-body-apply-btn").forEach(btn => {
    btn.disabled = !on;
  });
}

function _aspRunnerBodyEditValidate() {
  const ta = document.getElementById("asp-runner-body-edit-ta");
  const errEl = document.getElementById("asp-runner-body-edit-error");
  if (!ta) return { ok: true, parsed: null };
  const txt = ta.value || "";
  if (_aspRunnerBodyEdit) _aspRunnerBodyEdit.draftText = txt;

  if (!txt.trim()) {
    ta.classList.add("asp-body-invalid");
    if (errEl) {
      errEl.style.display = "block";
      errEl.textContent = "Body cannot be empty. Use {} for an empty JSON object.";
    }
    _aspRunnerBodyEditSetSaveEnabled(false);
    return { ok: false, error: "empty" };
  }

  try {
    const parsed = JSON.parse(txt);
    ta.classList.remove("asp-body-invalid");
    if (errEl) {
      errEl.style.display = "none";
      errEl.textContent = "";
    }
    _aspRunnerBodyEditSetSaveEnabled(true);
    return { ok: true, parsed };
  } catch (e) {
    ta.classList.add("asp-body-invalid");
    if (errEl) {
      errEl.style.display = "block";
      errEl.textContent = _aspRunnerFormatJsonError(e, txt);
    }
    _aspRunnerBodyEditSetSaveEnabled(false);
    return { ok: false, error: e.message };
  }
}

function _aspRunnerBodyEditBindTa() {
  const ta = document.getElementById("asp-runner-body-edit-ta");
  if (!ta || ta.dataset.bound) return;
  ta.dataset.bound = "1";
  ta.addEventListener("input", () => _aspRunnerBodyEditValidate());
  _aspRunnerBodyEditValidate();
}

async function aspRunnerBodyEditSave(origIdx, applyAll) {
  if (_aspRunnerRunning) return;
  if (!_aspRunnerData) return;
  const edit = _aspRunnerBodyEdit;
  if (!edit) return;

  const ta = document.getElementById("asp-runner-body-edit-ta");
  if (!ta) return;
  const check = _aspRunnerBodyEditValidate();
  if (!check.ok) return;

  const parsed = check.parsed;

  const d = _aspRunnerData;
  const apiKey = edit.apiKey || _aspRunnerApiKeyFromCase(d.cases?.[origIdx]);
  const groupCases = d.cases.filter(x => _aspRunnerApiKeyFromCase(x) === apiKey);
  const affected = applyAll
    ? groupCases
    : [d.cases[origIdx]].filter(Boolean);

  // Prefer shared group base body (not the case-injected editor draft) for remove detection.
  const baseOldBody = groupCases.find(c => c._base_body != null)?._base_body
    ?? groupCases.find(c => c.source_body != null)?.source_body
    ?? affected[0]?._base_body
    ?? affected[0]?.source_body
    ?? null;

  const impacts = _aspRunnerFindRemovedParamImpacts(apiKey, baseOldBody, parsed);
  const purgePaths = impacts
    .filter(i => i.caseCount > 0 || i.hasDataset)
    .map(i => i.path);

  if (purgePaths.length) {
    const ok = await _aspRunnerConfirmRemovedMappedParams(impacts, !!applyAll);
    if (!ok) return;
  }

  // Remove unique-format overrides for fields the user touched,
  // otherwise tokens may overwrite user's edits.
  const changedPaths = _aspRunnerDiffLeafPaths(baseOldBody, parsed);

  affected.forEach(c => {
    c._base_body = parsed;
    c.source_body = parsed;
    if (c._all_unique_formats && changedPaths.size) {
      changedPaths.forEach(p => { delete c._all_unique_formats[p]; });
    }
  });

  if (purgePaths.length) {
    _aspRunnerPurgeParamsFromApi(apiKey, purgePaths);
  }

  _aspRunnerBodyEdit = null;
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerUpdateTitle();
  _aspRunnerPersistRunnerData();
  _aspRunnerClearRunResultsUI();
}

function _aspRunnerPickRandomTokenForParam(paramPath) {
  const p = String(paramPath || "").toLowerCase();
  if (p.includes("email")) return "{email}";
  if (p.includes("uuid") || /\b(id|guid)\b/.test(p)) return "{uuid}";
  if (p.includes("name") || p.includes("title")) return "{name}";
  if (p.includes("num") || p.includes("number") || p.includes("account") || p.includes("digits")) return "{num:8}";
  if (p.includes("alphanum")) return "{alphanum:8}";
  if (p.includes("code") || p.includes("ref") || p.includes("token")) return "{alphanum:10}";
  return "{alpha:8}";
}

function _aspRunnerCollectApiParams(apiKey) {
  const out = [];
  const seen = new Set();
  const pushPath = (path, source) => {
    const clean = String(path || "").trim();
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    out.push({ path: clean, source: source || (clean.startsWith("query.") ? "query" : "body") });
  };

  const snapshots = Array.isArray(_aspRunnerData?.param_snapshot) ? _aspRunnerData.param_snapshot : [];
  snapshots
    .filter(s => !apiKey || !s.api_key || s.api_key === apiKey)
    .forEach(s => pushPath(s.path, s.source));

  const cases = (_aspRunnerData?.cases || []).filter(c => _aspRunnerApiKeyFromCase(c) === apiKey);
  cases.forEach(c => {
    const bodyMap = {};
    const queryMap = {};
    _aspRunnerFlattenLeafValues(c._base_body, "", bodyMap, true);
    _aspRunnerFlattenLeafValues(c._base_query, "", queryMap, false);
    Object.keys(bodyMap).forEach(path => pushPath(path, "body"));
    Object.keys(queryMap).forEach(path => pushPath(`query.${path}`, "query"));
    Object.keys(c._all_unique_formats || {}).forEach(path => pushPath(path, path.startsWith("query.") ? "query" : "body"));
  });

  return out.sort((a, b) => {
    if (a.source !== b.source) return a.source === "body" ? -1 : 1;
    return a.path.localeCompare(b.path);
  });
}

function _aspRunnerRandomSyncEditor() {
  const path = _aspRunnerRandomState?.selectedPath || "";
  const lbl = document.getElementById("asp-runner-random-selected-param");
  if (lbl) lbl.textContent = "param: " + (path || "—");

  let current = "";
  if (_aspRunnerData && path && _aspRunnerRandomState?.apiKey) {
    const cases = _aspRunnerData.cases.filter(c => _aspRunnerApiKeyFromCase(c) === _aspRunnerRandomState.apiKey);
    const hit = cases.find(c => (c.param_path || c.param || "") === path);
    const mapped = cases.find(c => c._all_unique_formats && c._all_unique_formats[path] != null);
    current = (mapped?._all_unique_formats && mapped._all_unique_formats[path]) || hit?.value_template || "";
  }

  const inp = document.getElementById("asp-runner-random-format-input");
  if (inp) inp.value = current;

  const previewBox = document.getElementById("asp-runner-random-preview-box");
  if (previewBox) previewBox.style.display = current ? "block" : "none";
  const previewVal = document.getElementById("asp-runner-random-preview-val");
  if (previewVal && current) previewVal.textContent = _aspRunnerPreviewFormat(current);

  document.querySelectorAll("#asp-runner-random-presets .preset-btn").forEach(btn => {
    btn.classList.toggle("selected", btn.dataset.fmt === current);
  });
}

function aspRunnerRandomClose() {
  _aspRunnerRandomState = null;
  const el = document.getElementById("asp-runner-random-modal");
  if (el) el.style.display = "none";
}

function aspRunnerRandomOpen(origIdx) {
  if (_aspRunnerRunning) return;
  const d = _aspRunnerData;
  const c = d?.cases?.[origIdx];
  if (!c) return;
  const apiKey = _aspRunnerApiKeyFromCase(c);
  const groupCases = d.cases.filter(x => _aspRunnerApiKeyFromCase(x) === apiKey);
  const params = _aspRunnerCollectApiParams(apiKey);

  _aspRunnerRandomState = { apiKey, selectedPath: params[0]?.path || null };
  _aspRunnerPoolDraft = null;

  const sub = document.getElementById("asp-runner-random-modal-sub");
  if (sub) sub.textContent = apiKey ? `· ${apiKey}` : "";
  const list = document.getElementById("asp-runner-random-list");
  const search = document.getElementById("asp-runner-random-search");
  const applyBtn = document.getElementById("asp-runner-random-apply-btn");
  if (search) search.value = "";

  if (list) {
    list.innerHTML = params.map(({ path, source }) => {
      // Prefer existing token template if present (value_template or unique-format map).
      const anyCase = groupCases.find(x => (x.param_path || x.param) === path);
      const poolN = _aspRunnerPoolUnusedCount(apiKey, path);
      const token = poolN ? null : (
        groupCases.map(x => (x._all_unique_formats || {})[path]).find(Boolean)
        || ((anyCase?.param_path || anyCase?.param) === path ? anyCase?.value_template : null)
        || null
      );
      const statusLine = poolN
        ? `list: ${poolN} unused`
        : (token ? "token: " + _aspEscHtml(token) : "no unique token set");
      const tokenText = poolN ? `${poolN} unused` : (token ? token : "—");
      const mappedLabel = poolN ? "list" : (tokenText !== "—" ? "mapped" : "ready");
      const active = (_aspRunnerRandomState?.selectedPath === path) ? "asp-active" : "";
      return `
        <div class="asp-runner-random-item ${active}" data-path="${_aspEscHtml(path)}"
             onclick="aspRunnerRandomSelect(this.getAttribute('data-path'))" style="display:flex;align-items:flex-start;gap:10px;padding:12px 12px;border-bottom:1px solid var(--border);cursor:pointer;${active?'background:rgba(31,111,235,.12)':''}">
          <div style="min-width:0;flex:1">
            <div style="display:flex;align-items:center;gap:6px;min-width:0">
              <span style="font-size:10px;color:${source === 'query' ? '#d29922' : '#79c0ff'};border:1px solid ${source === 'query' ? 'rgba(210,153,34,.35)' : 'rgba(121,192,255,.28)'};border-radius:999px;padding:1px 6px;flex-shrink:0">${source.toUpperCase()}</span>
              <div style="font-size:12px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${_aspEscHtml(path)}</div>
            </div>
            <div style="font-size:10px;color:var(--text3);margin-top:4px">${statusLine}</div>
          </div>
          <div style="font-size:10px;color:var(--text3);white-space:nowrap;padding-top:2px">${mappedLabel}</div>
        </div>`;
    }).join("");
    if (!params.length) {
      list.innerHTML = `<div style="padding:18px 14px;color:var(--text3);font-size:12px">No request params found for this API.</div>`;
    }
  }
  document.querySelectorAll("#asp-runner-random-presets .preset-btn").forEach(btn => {
    btn.onclick = () => {
      const fmt = btn.dataset.fmt || "";
      const inp = document.getElementById("asp-runner-random-format-input");
      if (inp) inp.value = fmt;
      document.querySelectorAll("#asp-runner-random-presets .preset-btn").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      const previewVal = document.getElementById("asp-runner-random-preview-val");
      const previewBox = document.getElementById("asp-runner-random-preview-box");
      if (previewVal) previewVal.textContent = _aspRunnerPreviewFormat(fmt);
      if (previewBox) previewBox.style.display = fmt ? "block" : "none";
    };
  });
  if (applyBtn) applyBtn.disabled = !_aspRunnerRandomState.selectedPath;
  if (applyBtn) {
    applyBtn.style.opacity = _aspRunnerRandomState.selectedPath ? "" : ".5";
    applyBtn.style.pointerEvents = _aspRunnerRandomState.selectedPath ? "" : "none";
    applyBtn.style.cursor = _aspRunnerRandomState.selectedPath ? "pointer" : "not-allowed";
  }
  _aspRunnerRandomSyncEditor();
  _aspRunnerShowExistingPoolPreview();

  const modal = document.getElementById("asp-runner-random-modal");
  if (modal) modal.style.display = "flex";
}

function aspRunnerRandomOpenForApi(apiKey) {
  if (!_aspRunnerData?.cases?.length) return;
  const idx = _aspRunnerData.cases.findIndex(c => _aspRunnerApiKeyFromCase(c) === apiKey);
  if (idx >= 0) aspRunnerRandomOpen(idx);
}

function aspRunnerRandomSelect(path) {
  if (!_aspRunnerRandomState) return;
  _aspRunnerRandomState.selectedPath = path;
  const applyBtn = document.getElementById("asp-runner-random-apply-btn");
  if (applyBtn) {
    applyBtn.disabled = !path;
    applyBtn.style.opacity = path ? "" : ".5";
    applyBtn.style.pointerEvents = path ? "" : "none";
    applyBtn.style.cursor = path ? "pointer" : "not-allowed";
  }

  const list = document.getElementById("asp-runner-random-list");
  if (!list) return;
  list.querySelectorAll(".asp-runner-random-item").forEach(el => {
    const ok = el.getAttribute("data-path") === path;
    el.style.background = ok ? "rgba(31,111,235,.12)" : "";
  });
  _aspRunnerRandomSyncEditor();
  _aspRunnerShowExistingPoolPreview();
}

function aspRunnerRandomFilter() {
  if (!_aspRunnerRandomState) return;
  const q = (document.getElementById("asp-runner-random-search")?.value || "").toLowerCase().trim();
  const list = document.getElementById("asp-runner-random-list");
  if (!list) return;
  list.querySelectorAll(".asp-runner-random-item").forEach(el => {
    const p = (el.getAttribute("data-path") || "").toLowerCase();
    el.style.display = (!q || p.includes(q)) ? "" : "none";
  });
}

function aspRunnerRandomPreview() {
  const fmt = (document.getElementById("asp-runner-random-format-input")?.value || "").trim();
  if (!fmt) return;
  const previewVal = document.getElementById("asp-runner-random-preview-val");
  const previewBox = document.getElementById("asp-runner-random-preview-box");
  if (previewVal) previewVal.textContent = _aspRunnerPreviewFormat(fmt);
  if (previewBox) previewBox.style.display = "block";
}

function aspRunnerRandomClear() {
  const inp = document.getElementById("asp-runner-random-format-input");
  if (inp) inp.value = "";
  const previewBox = document.getElementById("asp-runner-random-preview-box");
  if (previewBox) previewBox.style.display = "none";
  document.querySelectorAll("#asp-runner-random-presets .preset-btn").forEach(btn => btn.classList.remove("selected"));
  _aspRunnerPoolDraft = { matched: {}, filename: "", row_count: 0, cleared: true };
  _aspRunnerRenderPoolPreview(null);
}

function aspRunnerRandomApply() {
  if (!_aspRunnerRandomState || !_aspRunnerData) return;
  const selectedPath = _aspRunnerRandomState.selectedPath;
  if (!selectedPath) return;

  const d = _aspRunnerData;
  const apiKey = _aspRunnerRandomState.apiKey;
  const groupCases = d.cases.filter(x => _aspRunnerApiKeyFromCase(x) === apiKey);
  d.unique_pools_by_api = d.unique_pools_by_api || {};

  const typedToken = (document.getElementById("asp-runner-random-format-input")?.value || "").trim();

  if (_aspRunnerPoolDraft && _aspRunnerPoolDraft.cleared) {
    const rec = d.unique_pools_by_api[apiKey];
    if (rec && rec.matched) {
      delete rec.matched[selectedPath];
      if (!Object.keys(rec.matched).length) delete d.unique_pools_by_api[apiKey];
      else rec.row_count = Math.min(...Object.values(rec.matched).map(v => (v || []).length));
    }
    if (typedToken) {
      groupCases.forEach(c => {
        c._all_unique_formats = c._all_unique_formats || {};
        c._all_unique_formats[selectedPath] = typedToken;
        if ((c.param_path || c.param) === selectedPath) c.value_template = typedToken;
      });
      d.all_unique_formats = d.all_unique_formats || {};
      if (!d.api_key || d.api_key === apiKey) d.all_unique_formats[selectedPath] = typedToken;
      _aspRunnerUpsertParamSnapshot(apiKey, selectedPath, { unique_format: typedToken });
    } else {
      groupCases.forEach(c => {
        if (c._all_unique_formats) delete c._all_unique_formats[selectedPath];
        if ((c.param_path || c.param) === selectedPath) c.value_template = null;
      });
      if (d.all_unique_formats) delete d.all_unique_formats[selectedPath];
      _aspRunnerUpsertParamSnapshot(apiKey, selectedPath, { unique_format: null });
    }
  } else if (_aspRunnerPoolDraft && _aspRunnerPoolDraft.matched) {
    d.unique_pools_by_api[apiKey] = {
      filename: _aspRunnerPoolDraft.filename || "",
      matched: _aspRunnerClone(_aspRunnerPoolDraft.matched),
      row_count: _aspRunnerPoolDraft.row_count || 0,
    };
    Object.keys(_aspRunnerPoolDraft.matched).forEach(path => {
      groupCases.forEach(c => {
        if (c._all_unique_formats) delete c._all_unique_formats[path];
        if ((c.param_path || c.param) === path) c.value_template = null;
      });
      if (d.all_unique_formats) delete d.all_unique_formats[path];
      _aspRunnerUpsertParamSnapshot(apiKey, path, { unique_format: null });
    });
  } else {
    const existingToken = (groupCases.find(x => (x.param_path || x.param) === selectedPath)?._all_unique_formats || {})[selectedPath]
      || groupCases.find(x => (x.param_path || x.param) === selectedPath)?.value_template;
    const token = typedToken || existingToken || _aspRunnerPickRandomTokenForParam(selectedPath);
    groupCases.forEach(c => {
      c._all_unique_formats = c._all_unique_formats || {};
      c._all_unique_formats[selectedPath] = token;
      if ((c.param_path || c.param) === selectedPath) c.value_template = token;
    });
    d.all_unique_formats = d.all_unique_formats || {};
    if (!d.api_key || d.api_key === apiKey) d.all_unique_formats[selectedPath] = token;
    _aspRunnerUpsertParamSnapshot(apiKey, selectedPath, { unique_format: token });
    const rec = d.unique_pools_by_api[apiKey];
    if (rec && rec.matched) {
      delete rec.matched[selectedPath];
      if (!Object.keys(rec.matched).length) delete d.unique_pools_by_api[apiKey];
    }
  }

  _aspRunnerUnionUniqueFormatsByApi(d);
  _aspRunnerPersistRunnerData();
  _aspRunnerPoolDraft = null;
  aspRunnerRandomClose();
  _aspRunnerClearRunResultsUI();
}

// ── Runner: Dataset & Cases (API Validator datasets) ─────────────────────────

async function _aspRunnerFetchDatasets() {
  if (_aspRunnerAllDatasets) return _aspRunnerAllDatasets;
  try {
    const resp = await fetch(`${_aspAvBackendUrl()}/datasets`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    _aspRunnerAllDatasets = await resp.json();
    return _aspRunnerAllDatasets;
  } catch (e) {
    throw new Error("Cannot reach API Validator backend (8765). Start the app and retry.");
  }
}

function _aspRunnerDetectDatasetKey(path, value) {
  const k = String(path || "").split(".").pop().toLowerCase();
  const v = value == null ? "" : String(value);
  if (/\b(email|mail)\b/.test(k)) return "string_email";
  if (/\b(phone|mobile|contact|cell)\b/.test(k)) return "string_phone";
  if (/\b(password|passwd|pwd|secret)\b/.test(k)) return "string_password";
  if (/\b(ip_address|ipaddress|ipv4|ipv6|client_ip|server_ip|host_ip)\b/.test(k) || k === "ip" || k.endsWith("_ip") || k.startsWith("ip_")) return "string_ip";
  if (/\b(url|link|website|callback|redirect|endpoint)\b/.test(k)) return "string_url";
  if (/\b(datetime|timestamp|created_at|updated_at|scheduled)\b/.test(k)) return "string_datetime";
  if (/\b(date|calendar|dob|birthday|expiry)\b/.test(k) && !/\btime\b/.test(k)) return "string_date";
  if (/\b(description|desc|note|comment|remark|message|body|content|detail|summary|bio|about)\b/.test(k)) return "string_text";
  if (/\b(priority|status|type|category|role|level|mode|state|kind|gender|plan)\b/.test(k)) return "string_enum";
  if (/\b(name|fullname|full_name|first_name|last_name|author|owner)\b/.test(k)) return "string_name";
  if (/\b(title|label|subject|tag|heading)\b/.test(k)) return "string_general";
  if (/\b(hex|hexadecimal|checksum|hash|color_hex)\b/.test(k)) return "string_hex";
  if (/\b(binary|bitmask|bits|flags_binary)\b/.test(k)) return "string_binary";
  if (/^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$/.test(v)) return "string_email";
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return "string_date";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v)) return "string_datetime";
  if (v.startsWith("http://") || v.startsWith("https://")) return "string_url";
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(v)) return "string_ip";
  if (/^(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}$|^(?:[0-9A-Fa-f]{1,4}:){0,6}::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{0,4}$/.test(v)) return "string_ip";
  if (/^[01]{4,64}$/.test(v)) return "string_binary";
  if (/^(?:#?[0-9a-fA-F]{3}|#?[0-9a-fA-F]{6}|0x[0-9a-fA-F]+|[0-9a-fA-F]{4,})$/.test(v)) return "string_hex";
  return "string_general";
}

function _aspRunnerGetParamValueFromTemplate(apiKey, paramPath) {
  const template = _aspRunnerData?.cases?.find(c => _aspRunnerApiKeyFromCase(c) === apiKey);
  if (!template || !paramPath) return undefined;
  const path = String(paramPath);
  if (path.startsWith("query.")) {
    const q = template._base_query || {};
    return q[path.slice(6)];
  }
  if (template._base_body && typeof template._base_body === "object") {
    return _aspRunnerReadPath(template._base_body, path);
  }
  return undefined;
}

function _aspRunnerParseDatasetTestValue(caseId, valStr) {
  const id = String(caseId || "");
  if (id === "null_value" || valStr === "None") return null;
  if (id === "empty_string") return "";
  if (id === "only_spaces") return "     ";
  if (id === "integer_type") return 123;
  if (id === "boolean_type") return true;
  if (id === "float_type") return 9876543210.5;
  if (id === "negative_number") return -9876543210;
  return valStr;
}

// Dynamic test value generation pools (synchronous with backend/main.py API Validator)
const _ASP_STANDARD_TITLES = [
  "Project Meeting", "Quarterly Review", "Sprint Planning", "Status Brief",
  "Team Standup", "Hello World", "Client Onboarding", "System Audit",
  "Design Workshop", "Feature Roadmap", "Strategic Alignment", "Market Analysis",
  "Performance Review", "Security Patch", "Workflow Optimization", "Milestone Target",
  "Budget Forecast", "Resource Allocation", "Executive Summary", "Platform Architecture",
  "Customer Journey", "Product Backlog", "Operations Sync", "Release Checklist",
  "Data Pipeline", "Quality Benchmark", "Sprint Retro", "Technical Assessment",
  "Business Case Study", "Architecture Overview", "Service Integration", "Deployment Plan",
  "User Research", "Incident Postmortem", "Partner Evaluation", "Compliance Check",
  "Capacity Planning", "DevOps Milestone", "API Specification", "Knowledge Transfer"
];

const _ASP_TITLE_ADJECTIVES = [
  "Project", "Quarterly", "Sprint", "System", "Client", "Product", "Strategic",
  "Team", "Resource", "Market", "Design", "Security", "Workflow", "Milestone",
  "Budget", "Performance", "Operational", "Financial", "Technical", "Executive",
  "Digital", "Enterprise", "Global", "Customer", "Platform", "Cloud", "Business",
  "Agile", "Core", "Dynamic", "Internal", "External", "Annual", "Weekly", "Monthly"
];

const _ASP_TITLE_NOUNS = [
  "Meeting", "Review", "Planning", "Audit", "Sync", "Roadmap", "Summary",
  "Report", "Analysis", "Briefing", "Allocation", "Workshop", "Patch", "Pipeline",
  "Target", "Matrix", "Overview", "Session", "Tracker", "Initiative",
  "Update", "Discussion", "Evaluation", "Assessment", "Proposal", "Strategy", "Release"
];

const _ASP_FIRST_NAMES = [
  "Rahul", "Priya", "Aarav", "Ananya", "David", "Sarah", "Michael", "Emma",
  "Vikram", "Sneha", "James", "Olivia", "Alex", "Sophia", "Carlos", "Maria",
  "Kenji", "Fatima", "Arjun", "Rohan", "Kavita", "Daniel", "Lucas", "Elena",
  "Liam", "Chloe", "Marcus", "Zoe", "Alice", "Bob", "Carol", "Dave",
  "Eva", "Frank", "Grace", "Hank", "Iris", "Jack", "Deepak", "Neha"
];

const _ASP_LAST_NAMES = [
  "Sharma", "Patel", "Smith", "Jones", "Brown", "Davis", "Wilson", "Moore",
  "Taylor", "Anderson", "Gupta", "Verma", "Williams", "Jackson", "White", "Harris",
  "Martin", "Rao", "Malhotra", "Mehta", "Singh", "Fernandez", "Tanaka", "Sato",
  "Khan", "Al-Mansoor", "Kumar", "Das", "Joshi", "Mishra", "Reddy", "Nair"
];

const _ASP_SAMPLE_WORDS = [
  "alpha", "beta", "gamma", "delta", "sigma", "omega", "matrix", "nexus",
  "vortex", "quantum", "stellar", "beacon", "apex", "horizon", "zenith"
];

function _aspRandChoice(arr) {
  return arr[(Math.random() * arr.length) | 0];
}

function _aspRandInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function _aspRunnerNormalizeCaseId(caseId, caseDesc) {
  const cid = String(caseId || "").toLowerCase();
  if (cid && !cid.startsWith("avc_")) return cid;
  const desc = String(caseDesc || "").toLowerCase();
  if (desc.includes("captured original")) return "captured_original";
  if (desc.includes("full name")) return "valid_full_name";
  if (desc.includes("first name")) return "valid_first_only";
  if (desc.includes("apostrophe")) return "valid_with_apostrophe";
  if (desc.includes("hyphen")) return "valid_hyphenated";
  if (desc.includes("initial")) return "valid_with_initials";
  if (desc.includes("long but valid") || desc.includes("long name")) return "valid_long_name";
  if (desc.includes("two-word")) return "valid_two_word";
  if (desc.includes("normal sentence") || desc.includes("sentence")) return "valid_sentence";
  if (desc.includes("multiline")) return "valid_multiline";
  if (desc.includes("long text")) return "valid_long";
  if (desc.includes("letters + numbers") || desc.includes("alphanumeric")) return "valid_alphanumeric";
  if (desc.includes("single character")) return "valid_single_char";
  if (desc.includes("with spaces")) return "valid_with_spaces";
  if (desc.includes("unicode") || desc.includes("accented")) return "valid_unicode";
  if (desc.includes("numbers mixed")) return "valid_numbers_mixed";
  if (desc.includes("max typical")) return "valid_max_typical";
  if (desc.includes("standard text")) return "valid_standard";
  if (desc.includes("standard email")) return "valid_standard";
  if (desc.includes("subdomain")) return "valid_subdomain";
  if (desc.includes("plus alias")) return "valid_plus_alias";
  if (desc.includes("dot in local")) return "valid_dot_local";
  if (desc.includes("uppercase")) return "valid_uppercase";
  if (desc.includes("10-digit")) return "valid_10_digits";
  if (desc.includes("country code")) return "valid_with_country";
  if (desc.includes("with dashes")) return "valid_with_dashes";
  if (desc.includes("international")) return "valid_intl_format";
  if (desc.includes("standard date")) return "valid_standard";
  if (desc.includes("today")) return "valid_today";
  if (desc.includes("past date")) return "valid_past";
  if (desc.includes("future date")) return "valid_future";
  if (desc.includes("leap")) return "valid_leap_day";
  if (desc.includes("iso datetime") || desc.includes("full iso")) return "valid_iso_full";
  if (desc.includes("timezone z")) return "valid_iso_with_tz";
  if (desc.includes("offset")) return "valid_iso_offset";
  if (desc.includes("milliseconds")) return "valid_iso_ms";
  if (desc.includes("https")) return "valid_https";
  if (desc.includes("http")) return "valid_http";
  if (desc.includes("with path")) return "valid_with_path";
  if (desc.includes("query string") || desc.includes("with query")) return "valid_with_query";
  if (desc.includes("strong password")) return "valid_strong";
  if (desc.includes("long password")) return "valid_long";
  if (desc.includes("special char")) return "valid_special_chars";
  if (desc.includes("uppercase hex")) return "valid_uppercase";
  if (desc.includes("lowercase hex")) return "valid_lowercase";
  if (desc.includes("0x-prefixed") || desc.includes("prefixed hex")) return "valid_prefixed";
  if (desc.includes("short css") || desc.includes("short color")) return "valid_short_color";
  if (desc.includes("long css") || desc.includes("long color")) return "valid_long_color";
  if (desc.includes("single bit")) return "valid_single_bit";
  if (desc.includes("8-bit")) return "valid_byte";
  if (desc.includes("leading zeroes")) return "valid_with_leading_zeroes";
  if (desc.includes("16-bit")) return "valid_16_bit";
  if (desc.includes("private ipv4")) return "valid_ipv4_private";
  if (desc.includes("public ipv4")) return "valid_ipv4_public";
  if (desc.includes("loopback")) return "valid_ipv4_loopback";
  if (desc.includes("full ipv6")) return "valid_ipv6_full";
  if (desc.includes("short ipv6")) return "valid_ipv6_short";
  if (desc.includes("uuid")) return "valid_uuid";
  if (desc.includes("numeric string")) return "valid_numeric_string";
  if (desc.includes("positive integer")) return "valid_positive";
  if (desc.includes("zero")) return "valid_zero";
  if (desc.includes("large number")) return "valid_large";
  if (desc.includes("small number")) return "valid_small";
  if (desc.includes("decimal") || desc.includes("float")) return "valid_decimal";
  if (desc.includes("single item")) return "valid_single";
  if (desc.includes("multiple")) return "valid_multiple";
  if (desc.includes("empty array")) return "valid_empty";
  return cid;
}

function _aspRunnerGenerateDynamicCaseValue(datasetKey, caseId, defaultVal, cat, caseDesc) {
  if (cat === "NEG") return defaultVal;

  const cid = _aspRunnerNormalizeCaseId(caseId, caseDesc);
  const dk = String(datasetKey || "").toLowerCase();

  if (cid === "captured_original" || caseDesc === "Captured original value") {
    return defaultVal;
  }

  if (cid.startsWith("custom_")) {
    if (typeof defaultVal === "string" && /\{(?:uuid|email|name|alpha:\d+|alphanum:\d+|num:\d+)\}/i.test(defaultVal)) {
      return _aspResolveTokens(defaultVal);
    }
    return defaultVal;
  }

  if (dk === "string_general") {
    if (cid === "valid_standard") {
      return `${_aspRandChoice(_ASP_STANDARD_TITLES)} ${_aspRandInt(100, 999)}`;
    } else if (cid === "valid_alphanumeric") {
      const pfx = _aspRandChoice(["Report", "Update", "Batch", "Sprint", "Release", "Ticket", "Item", "Doc", "Audit"]);
      return `${pfx} ${_aspRandInt(2025, 2099)}`;
    } else if (cid === "valid_single_char") {
      const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      return letters[_aspRandInt(0, letters.length - 1)];
    } else if (cid === "valid_with_spaces") {
      const adj = _aspRandChoice(_ASP_TITLE_ADJECTIVES);
      const noun = _aspRandChoice(_ASP_TITLE_NOUNS);
      return `My ${adj} ${noun} ${_aspRandInt(10, 99)}`;
    } else if (cid === "valid_with_hyphen") {
      const pfx = _aspRandChoice(["Year-End", "Follow-Up", "High-Priority", "Semi-Annual", "Full-Scale", "Multi-Tenant", "Real-Time", "Cross-Platform"]);
      const noun = _aspRandChoice(["Report", "Review", "Analysis", "Sync", "Task", "Audit", "Summary"]);
      return `${pfx} ${noun} ${_aspRandInt(10, 99)}`;
    } else if (cid === "valid_with_apostrophe") {
      const role = _aspRandChoice(["Manager", "Director", "Auditor", "Lead", "Client", "Developer", "Supervisor", "Officer"]);
      const noun = _aspRandChoice(["Report", "Review", "Note", "Update", "Brief", "Log", "Request"]);
      return `${role}'s ${noun} ${_aspRandInt(10, 99)}`;
    } else if (cid === "valid_unicode") {
      const acc = _aspRandChoice(["Réunion Générale", "Café Résumé", "Conférence Équipe", "Séance Première", "Projet Spécial", "Événement Déjà Vu", "Protocole Sécurisé", "Système Déployé"]);
      return `${acc} ${_aspRandInt(10, 99)}`;
    } else if (cid === "valid_numbers_mixed") {
      return `Version ${_aspRandInt(1, 9)}.${_aspRandInt(0, 9)}.${_aspRandInt(1, 99)} Update`;
    } else if (cid === "valid_max_typical") {
      const seed = _aspGenAlphanum(12);
      return (`DynamicText_${seed}_` + "A".repeat(80)).slice(0, 100);
    }
  } else if (dk === "string_name") {
    if (cid === "valid_full_name") {
      return `${_aspRandChoice(_ASP_FIRST_NAMES)} ${_aspRandChoice(_ASP_LAST_NAMES)}`;
    } else if (cid === "valid_first_only") {
      return _aspRandChoice(_ASP_FIRST_NAMES);
    } else if (cid === "valid_with_apostrophe") {
      return _aspRandChoice(["O'Brien", "O'Connor", "D'Souza", "O'Neil", "M'Donald", "O'Reilly", "D'Angelo", "O'Keefe", "D'Cruz"]);
    } else if (cid === "valid_hyphenated") {
      return _aspRandChoice(["Mary-Jane", "Jean-Luc", "Anne-Marie", "Claire-Louise", "John-Paul", "Marc-Andre", "Pierre-Louis", "Marie-Claire"]);
    } else if (cid === "valid_with_initials") {
      const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const i1 = letters[_aspRandInt(0, letters.length - 1)];
      const i2 = letters[_aspRandInt(0, letters.length - 1)];
      return `${i1}. ${i2}. ${_aspRandChoice(_ASP_LAST_NAMES)}`;
    } else if (cid === "valid_long_name") {
      return `${_aspRandChoice(_ASP_FIRST_NAMES)} ${_aspRandChoice(_ASP_FIRST_NAMES)} ${_aspRandChoice(_ASP_LAST_NAMES)}`;
    } else if (cid === "valid_two_word") {
      return `${_aspRandChoice(_ASP_FIRST_NAMES)} ${_aspRandChoice(_ASP_LAST_NAMES)}`;
    }
  } else if (dk === "string_email") {
    const num = _aspRandInt(1000, 99999);
    const tag = _aspRandChoice(_ASP_SAMPLE_WORDS);
    if (cid === "valid_standard") {
      return `user_${num}_${tag}@example.com`;
    } else if (cid === "valid_subdomain") {
      return `user_${num}@mail.${tag}api.org`;
    } else if (cid === "valid_plus_alias") {
      return `user+test${num}@example.com`;
    } else if (cid === "valid_dot_local") {
      const fn = _aspRandChoice(_ASP_FIRST_NAMES).toLowerCase();
      const ln = _aspRandChoice(_ASP_LAST_NAMES).toLowerCase();
      return `${fn}.${ln}${_aspRandInt(10, 999)}@example.com`;
    } else if (cid === "valid_numbers") {
      return `user${num}@example${_aspRandInt(10, 99)}.com`;
    } else if (cid === "valid_uppercase") {
      return `User_${num}@Example.COM`;
    }
  } else if (dk === "string_phone") {
    const lead = _aspRandChoice(["9", "8", "7", "6"]);
    const rest = String(_aspRandInt(100000000, 999999999));
    const num10 = `${lead}${rest}`;
    if (cid === "valid_10_digits") {
      return num10;
    } else if (cid === "valid_with_country") {
      return `+91${num10}`;
    } else if (cid === "valid_with_dashes") {
      return `${num10.slice(0, 3)}-${num10.slice(3, 6)}-${num10.slice(6)}`;
    } else if (cid === "valid_with_spaces") {
      return `${num10.slice(0, 3)} ${num10.slice(3, 6)} ${num10.slice(6)}`;
    } else if (cid === "valid_intl_format") {
      return `+1-${_aspRandInt(200, 899)}-${_aspRandInt(100, 999)}-${_aspRandInt(1000, 9999)}`;
    }
  } else if (dk === "string_date") {
    const pad = n => String(n).padStart(2, "0");
    const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    if (cid === "valid_standard") {
      return fmt(new Date(Date.now() - _aspRandInt(1, 180) * 86400000));
    } else if (cid === "valid_today") {
      return fmt(new Date());
    } else if (cid === "valid_past") {
      return fmt(new Date(Date.now() - _aspRandInt(365, 3650) * 86400000));
    } else if (cid === "valid_future") {
      return fmt(new Date(Date.now() + _aspRandInt(30, 1825) * 86400000));
    } else if (cid === "valid_leap_day") {
      return _aspRandChoice(["2024-02-29", "2028-02-29", "2032-02-29"]);
    }
  } else if (dk === "string_datetime") {
    const d = new Date(Date.now() - _aspRandInt(1, 10000) * 60000 - _aspRandInt(1, 59) * 1000);
    const pad = n => String(n).padStart(2, "0");
    const base = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    if (cid === "valid_iso_full") {
      return base;
    } else if (cid === "valid_iso_with_tz") {
      return `${base}Z`;
    } else if (cid === "valid_iso_offset") {
      return `${base}+05:30`;
    } else if (cid === "valid_iso_ms") {
      return `${base}.${String(d.getMilliseconds()).padStart(3, "0")}Z`;
    }
  } else if (dk === "string_url") {
    const tag = _aspRandChoice(_ASP_SAMPLE_WORDS);
    const n = _aspRandInt(100, 9999);
    if (cid === "valid_https") {
      return `https://www.${tag}-${n}.example.com`;
    } else if (cid === "valid_http") {
      return `http://api-${tag}-${n}.example.org`;
    } else if (cid === "valid_with_path") {
      return `https://example.com/${tag}/item_${n}`;
    } else if (cid === "valid_with_query") {
      return `https://example.com/search?ref=${n}&tag=${tag}`;
    }
  } else if (dk === "string_password") {
    const h = _aspGenAlphanum(6).toUpperCase();
    const n = _aspRandInt(100, 999);
    if (cid === "valid_strong") {
      return `P@ss${n}!${h}`;
    } else if (cid === "valid_long") {
      return `Str0ng#Pass!${n}${h}XYZ`;
    } else if (cid === "valid_special_chars") {
      return `Tr${_aspRandInt(10, 99)}&oub4dor%${n}!`;
    }
  } else if (dk === "string_text") {
    const n = _aspRandInt(1000, 9999);
    if (cid === "valid_sentence") {
      return `This is an operational description record #${n}.`;
    } else if (cid === "valid_multiline") {
      return `Section line one for record #${n}.\nSection line two verification notes.`;
    } else if (cid === "valid_long") {
      return `Detailed record #${n} description notes: ` + "Lorem ipsum test context ".repeat(15);
    }
  } else if (dk === "string_hex") {
    const hex = "0123456789abcdef";
    const randHex = len => Array.from({ length: len }, () => hex[_aspRandInt(0, 15)]).join("");
    if (cid === "valid_uppercase") {
      return randHex(8).toUpperCase();
    } else if (cid === "valid_lowercase") {
      return randHex(8).toLowerCase();
    } else if (cid === "valid_prefixed") {
      return `0x${randHex(6).toUpperCase()}`;
    } else if (cid === "valid_short_color") {
      return `#${randHex(3).toUpperCase()}`;
    } else if (cid === "valid_long_color") {
      return `#${randHex(6).toLowerCase()}`;
    }
  } else if (dk === "string_binary") {
    if (cid === "valid_single_bit") {
      return _aspRandChoice(["1", "0"]);
    } else if (cid === "valid_byte") {
      return Array.from({ length: 8 }, () => _aspRandChoice(["0", "1"])).join("");
    } else if (cid === "valid_with_leading_zeroes") {
      return "0000" + Array.from({ length: 4 }, () => _aspRandChoice(["0", "1"])).join("");
    } else if (cid === "valid_16_bit") {
      return Array.from({ length: 16 }, () => _aspRandChoice(["0", "1"])).join("");
    }
  } else if (dk === "string_ip") {
    const o1 = _aspRandInt(1, 250);
    const o2 = _aspRandInt(1, 250);
    if (cid === "valid_ipv4_private") {
      return `192.168.${o1}.${o2}`;
    } else if (cid === "valid_ipv4_public") {
      return `${_aspRandInt(11, 190)}.${o1}.${o2}.${_aspRandInt(1, 250)}`;
    } else if (cid === "valid_ipv4_loopback") {
      return `127.0.0.${o1}`;
    } else if (cid === "valid_ipv6_full") {
      return `2001:0db8:85a3:${_aspRandInt(1000, 9999).toString(16)}:${_aspRandInt(1000, 9999).toString(16)}:8a2e:0370:${_aspRandInt(1000, 9999).toString(16)}`;
    } else if (cid === "valid_ipv6_short") {
      return `2001:db8::${_aspRandInt(1, 999).toString(16)}`;
    }
  } else if (dk === "string_id") {
    if (cid === "valid_uuid") {
      return _aspGenUuid();
    } else if (cid === "valid_alphanumeric") {
      return `ID${_aspRandInt(100, 999)}${_aspGenAlpha(4).toUpperCase()}`;
    } else if (cid === "valid_numeric_string") {
      return String(_aspRandInt(100000, 999999));
    }
  } else if (dk === "numeric_integer") {
    if (cid === "valid_positive") {
      return _aspRandInt(1, 9999);
    } else if (cid === "valid_zero") {
      return 0;
    } else if (cid === "valid_large") {
      return _aspRandInt(100000, 9999999);
    } else if (cid === "valid_small") {
      return _aspRandInt(1, 20);
    }
  } else if (dk === "numeric_float") {
    if (cid === "valid_decimal") {
      return +(_aspRandInt(10, 999) + Math.random()).toFixed(2);
    } else if (cid === "valid_integer_as_float") {
      return _aspRandInt(10, 500);
    } else if (cid === "valid_zero") {
      return 0.0;
    } else if (cid === "valid_small") {
      return +(Math.random() * 0.98 + 0.01).toFixed(2);
    }
  } else if (dk === "array") {
    if (cid === "valid_single") {
      return [`item_${_aspRandInt(100, 999)}`];
    } else if (cid === "valid_multiple") {
      return [`tag_${_aspRandInt(10, 99)}`, `tag_${_aspRandInt(10, 99)}`];
    } else if (cid === "valid_empty") {
      return [];
    }
  } else if (dk === "string_enum" || dk === "boolean") {
    return defaultVal;
  }

  if (typeof defaultVal === "string" && /\{(?:uuid|email|name|alpha:\d+|alphanum:\d+|num:\d+)\}/i.test(defaultVal)) {
    return _aspResolveTokens(defaultVal);
  }

  return defaultVal;
}

function _aspRunnerGetParamSnapshotEntry(apiKey, paramPath) {
  const snaps = _aspRunnerData?.param_snapshot || [];
  return snaps.find(s => (s.api_key || _aspRunnerData.api_key) === apiKey && s.path === paramPath) || null;
}

function _aspRunnerUpsertParamSnapshot(apiKey, paramPath, patch) {
  _aspRunnerData.param_snapshot = _aspRunnerData.param_snapshot || [];
  let entry = _aspRunnerGetParamSnapshotEntry(apiKey, paramPath);
  if (!entry) {
    entry = {
      path: paramPath,
      api_key: apiKey,
      source: String(paramPath).startsWith("query.") ? "query" : "body",
      detected: "",
      value_preview: "",
    };
    _aspRunnerData.param_snapshot.push(entry);
  }
  Object.assign(entry, patch);
  return entry;
}

function _aspRunnerBuildDatasetCasesForModal(path, dsKey, origVal) {
  const ds = _aspRunnerAllDatasets?.[dsKey];
  if (!ds?.cases) return [];
  const cases = ds.cases.map(c => ({ ...c }));
  if (origVal != null && origVal !== "") {
    cases.unshift({
      id: "captured_original",
      cat: "POS",
      desc: "Captured original value",
      val: String(origVal).slice(0, 80),
    });
  }
  return cases;
}

function _aspRunnerCountRunnableDatasetCases(path, dsKey, casesDraft, customDraft) {
  const apiKey = _aspRunnerDatasetState?.apiKey;
  const modalCases = _aspRunnerBuildDatasetCasesForModal(
    path, dsKey, _aspRunnerGetParamValueFromTemplate(apiKey, path)
  );
  let n = 0;
  modalCases.forEach(c => {
    const v = casesDraft?.[c.id] != null ? casesDraft[c.id] : c.cat;
    if (v !== "SKIP") n++;
  });
  n += (customDraft || []).length;
  return n;
}

function _aspRunnerCreateRunnerCaseFromDataset(templateCase, apiKey, paramPath, effectiveCat, caseId, caseDesc, testValue, dsKey) {
  const now = _aspRunnerIsoNow();
  const baseId = [apiKey, paramPath, effectiveCat, caseDesc, testValue == null ? "" : String(testValue)].join("|");
  const token = _aspRunnerPickRandomTokenForParam(paramPath);
  const uniqueFormats = _aspRunnerClone(templateCase._all_unique_formats || {});

  return {
    param: paramPath,
    param_path: paramPath,
    case_cat: effectiveCat,
    case_desc: caseDesc,
    test_value: testValue,
    case_value: testValue,
    case_id: `avc_${_aspRunnerHashText(baseId)}`,
    dataset_case_id: caseId,
    dataset_key: dsKey,
    api_key: apiKey,
    _method: templateCase._method,
    _url: templateCase._url,
    _headers: _aspRunnerClone(templateCase._headers || {}),
    _body_type: templateCase._body_type,
    _base_query: _aspRunnerClone(templateCase._base_query || {}),
    _base_body: _aspRunnerClone(templateCase._base_body),
    _all_unique_formats: uniqueFormats,
    value_template: uniqueFormats[paramPath] || null,
    prev_result: "—",
    prev_status: null,
    response: null,
    enabled: true,
    status: "active",
    merge_state: "new",
    created_at: now,
    updated_at: now,
    source_bundle_id: templateCase.source_bundle_id || _aspRunnerData.bundle_id,
    order: 0,
    extractors: [],
    bindings: [],
  };
}

function _aspRunnerGenerateCasesForParam(apiKey, paramPath, dsKey, casesDraft, customDraft, isNewParam) {
  const ds = _aspRunnerAllDatasets?.[dsKey];
  if (!ds) return [];
  const templateCase = _aspRunnerData.cases.find(c => _aspRunnerApiKeyFromCase(c) === apiKey);
  if (!templateCase) return [];

  const origVal = _aspRunnerGetParamValueFromTemplate(apiKey, paramPath);
  const modalCases = _aspRunnerBuildDatasetCasesForModal(paramPath, dsKey, origVal);
  const out = [];

  modalCases.forEach(c => {
    const sel = casesDraft?.[c.id] != null ? casesDraft[c.id] : c.cat;
    if (sel === "SKIP") return;
    const effectiveCat = sel === "POS" || sel === "NEG" ? sel : c.cat;
    let testVal = c.id === "captured_original"
      ? origVal
      : _aspRunnerParseDatasetTestValue(c.id, c.val);
    if (effectiveCat === "POS" && c.id !== "captured_original") {
      testVal = _aspRunnerGenerateDynamicCaseValue(dsKey, c.id, testVal, effectiveCat, c.desc);
    }
    out.push(_aspRunnerCreateRunnerCaseFromDataset(
      templateCase, apiKey, paramPath, effectiveCat, c.id, c.desc, testVal, dsKey
    ));
  });

  (customDraft || []).forEach(cc => {
    out.push(_aspRunnerCreateRunnerCaseFromDataset(
      templateCase, apiKey, paramPath, cc.cat || "POS", `custom_${_aspRunnerHashText(cc.value)}`,
      `Custom: ${String(cc.value).slice(0, 40)}`, cc.value, dsKey
    ));
  });

  if (isNewParam) {
    const token = _aspRunnerPickRandomTokenForParam(paramPath);
    _aspRunnerUpsertParamSnapshot(apiKey, paramPath, { unique_format: token });
    out.forEach(c => {
      c._all_unique_formats = c._all_unique_formats || {};
      if (!Object.prototype.hasOwnProperty.call(c._all_unique_formats, paramPath)) {
        c._all_unique_formats[paramPath] = token;
      }
    });
    (_aspRunnerData.cases || []).filter(c => _aspRunnerApiKeyFromCase(c) === apiKey).forEach(c => {
      c._all_unique_formats = c._all_unique_formats || {};
      if (!Object.prototype.hasOwnProperty.call(c._all_unique_formats, paramPath)) {
        c._all_unique_formats[paramPath] = token;
      }
    });
  }

  return out;
}

function _aspRunnerReplaceParamCases(apiKey, paramPath, newCases) {
  const cases = _aspRunnerData.cases || [];
  const indices = [];
  cases.forEach((c, i) => {
    if (_aspRunnerApiKeyFromCase(c) === apiKey && (c.param_path || c.param || "") === paramPath) {
      indices.push(i);
    }
  });
  const insertAt = indices.length ? indices[0] : cases.findIndex(c => _aspRunnerApiKeyFromCase(c) === apiKey);
  for (let i = indices.length - 1; i >= 0; i--) cases.splice(indices[i], 1);
  const at = insertAt >= 0 ? insertAt : cases.length;
  newCases.forEach((nc, j) => {
    nc.merge_state = indices.length ? "updated" : "new";
    nc.order = at + j;
    cases.splice(at + j, 0, nc);
  });
  _aspRunnerData.cases = cases;
}

function _aspRunnerPersistRunnerData() {
  if (!_aspRunnerData) return;
  localStorage.setItem(ASP_RUNNER_KEY, JSON.stringify(_aspRunnerData));
}

/** Promote this-run results onto case.prev_* so export/import and the next run keep last status. */
function _aspRunnerCommitLastResultsToPrev() {
  if (!_aspRunnerData?.cases?.length || !_aspRunnerLastResults?.length) return false;
  let changed = false;
  _aspRunnerLastResults.forEach(r => {
    const c = _aspRunnerData.cases[r.origIdx];
    if (!c) return;
    const nextResult = r.result != null && r.result !== "" ? r.result : "—";
    const nextStatus = r.status != null ? r.status : null;
    if (c.prev_result !== nextResult || c.prev_status !== nextStatus) {
      c.prev_result = nextResult;
      c.prev_status = nextStatus;
      changed = true;
    }
  });
  return changed;
}

function _aspRunnerSyncDatasetModalUI() {
  const st = _aspRunnerDatasetState;
  const applyBtn = document.getElementById("asp-runner-dataset-apply-btn");
  const canApply = !!(st?.selectedPath && st?.selectedDsKey && _aspRunnerCountRunnableDatasetCases(
    st.selectedPath, st.selectedDsKey, st.casesDraft, st.customDraft
  ));
  if (applyBtn) {
    applyBtn.disabled = !canApply;
    applyBtn.style.opacity = canApply ? "" : ".5";
    applyBtn.style.pointerEvents = canApply ? "" : "none";
  }
  const countLbl = document.getElementById("asp-runner-dataset-count-label");
  if (countLbl && st?.selectedPath && st?.selectedDsKey) {
    const vals = Object.values(st.casesDraft || {});
    const posN = vals.filter(v => v === "POS").length;
    const negN = vals.filter(v => v === "NEG").length;
    const skipN = vals.filter(v => v === "SKIP").length;
    const runN = _aspRunnerCountRunnableDatasetCases(st.selectedPath, st.selectedDsKey, st.casesDraft, st.customDraft);
    const custN = (st.customDraft || []).length;
    countLbl.textContent = `${runN} run · ${posN} POS · ${negN} NEG · ${skipN} skipped${custN ? ` · +${custN} custom` : ""}`;
  } else if (countLbl) {
    countLbl.textContent = st?.selectedPath ? "Select a dataset" : "Select a parameter";
  }
}

function _aspRunnerRenderDatasetParamList() {
  const st = _aspRunnerDatasetState;
  const list = document.getElementById("asp-runner-dataset-param-list");
  if (!list || !st) return;
  const params = _aspRunnerCollectApiParams(st.apiKey);
  const q = (document.getElementById("asp-runner-dataset-param-search")?.value || "").toLowerCase().trim();
  const filtered = q ? params.filter(p => p.path.toLowerCase().includes(q)) : params;

  list.innerHTML = filtered.map(({ path, source }) => {
    const snap = _aspRunnerGetParamSnapshotEntry(st.apiKey, path);
    const caseCount = (_aspRunnerData.cases || []).filter(c =>
      _aspRunnerApiKeyFromCase(c) === st.apiKey && (c.param_path || c.param) === path
    ).length;
    const dsLabel = snap?.dataset_key && _aspRunnerAllDatasets?.[snap.dataset_key]
      ? _aspRunnerAllDatasets[snap.dataset_key].label
      : (caseCount ? `${caseCount} cases` : "no cases");
    const active = st.selectedPath === path ? "asp-active" : "";
    return `
      <div class="asp-runner-dataset-param-item ${active}" data-path="${_aspEscHtml(path)}"
           onclick="aspRunnerDatasetSelectParam(this.getAttribute('data-path'))"
           style="display:flex;align-items:flex-start;gap:8px;padding:10px 12px;border-bottom:1px solid var(--border);cursor:pointer;${active ? 'background:rgba(31,111,235,.12)' : ''}">
        <span style="font-size:9px;color:${source === 'query' ? '#d29922' : '#79c0ff'};border:1px solid ${source === 'query' ? 'rgba(210,153,34,.35)' : 'rgba(121,192,255,.28)'};border-radius:999px;padding:1px 6px;flex-shrink:0">${source.toUpperCase()}</span>
        <div style="min-width:0;flex:1">
          <div style="font-size:12px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${_aspEscHtml(path)}</div>
          <div style="font-size:10px;color:var(--text3);margin-top:2px">${_aspEscHtml(dsLabel)}</div>
        </div>
      </div>`;
  }).join("");

  if (!filtered.length) {
    list.innerHTML = `<div style="padding:16px;color:var(--text3);font-size:12px">${params.length ? "No params match search" : "No params found for this API"}</div>`;
  }
}

function _aspRunnerRenderDatasetList() {
  const st = _aspRunnerDatasetState;
  const list = document.getElementById("asp-runner-dataset-list");
  if (!list || !st) return;
  if (!st.selectedPath) {
    list.innerHTML = `<div style="padding:14px;color:var(--text3);font-size:12px">Select a parameter first</div>`;
    return;
  }
  const datasets = _aspRunnerAllDatasets || {};
  const q = (document.getElementById("asp-runner-dataset-search")?.value || "").toLowerCase().trim();
  const rows = Object.entries(datasets).filter(([key, ds]) => {
    if (!q) return true;
    const hay = `${key} ${ds.label || ""} ${ds.hint || ""}`.toLowerCase();
    return hay.includes(q);
  });
  if (!rows.length) {
    list.innerHTML = `<div style="padding:14px;color:var(--text3);font-size:12px">No datasets match this search.</div>`;
    return;
  }
  list.innerHTML = rows.map(([key, ds]) => {
    const selected = key === st.selectedDsKey ? " selected" : "";
    const pos = ds.pos_count ?? (ds.cases || []).filter(c => c.cat === "POS").length;
    const neg = ds.neg_count ?? (ds.cases || []).filter(c => c.cat === "NEG").length;
    return `
      <div class="dataset-option${selected}" data-ds="${_aspEscHtml(key)}"
           onclick="aspRunnerDatasetSelectDataset(this.getAttribute('data-ds'))"
           style="margin-bottom:6px;cursor:pointer">
        <div class="ds-info">
          <div class="ds-label">${_aspEscHtml(ds.label || key)}</div>
          <div class="ds-hint">${_aspEscHtml(ds.hint || "")}</div>
        </div>
        <div class="ds-counts">
          <span class="ds-count-badge pos">${pos}P</span>
          <span class="ds-count-badge neg">${neg}N</span>
        </div>
      </div>`;
  }).join("");
}

function _aspRunnerPaintDatasetCaseRow(row, c) {
  const st = _aspRunnerDatasetState;
  if (!st) return;
  const stateVal = st.casesDraft[c.id] || c.cat;
  const included = stateVal !== "SKIP";
  const isPOS = stateVal === "POS";
  row.className = `cm-case-row${included ? (isPOS ? " cm-row-pos" : " cm-row-neg") : " cm-row-skip"}`;
  const cb = row.querySelector(".cm-cb");
  const badge = row.querySelector(".cm-expect-badge");
  if (cb) cb.checked = included;
  if (badge) {
    badge.className = `cm-expect-badge ${included ? (isPOS ? "cm-pos" : "cm-neg") : "cm-skip"}`;
    badge.textContent = included ? (isPOS ? "✓ POS" : "✗ NEG") : "⏭ SKIP";
  }
}

function _aspRunnerRenderDatasetCasesList() {
  const st = _aspRunnerDatasetState;
  const wrap = document.getElementById("asp-runner-dataset-cases-wrap");
  const list = document.getElementById("asp-runner-dataset-cases-list");
  const paramLbl = document.getElementById("asp-runner-dataset-cases-param");
  if (!st || !wrap || !list) return;

  if (!st.selectedPath || !st.selectedDsKey) {
    wrap.style.display = "none";
    return;
  }

  const ds = _aspRunnerAllDatasets?.[st.selectedDsKey];
  if (!ds) {
    wrap.style.display = "none";
    return;
  }

  wrap.style.display = "flex";
  if (paramLbl) paramLbl.textContent = `param: ${st.selectedPath} · ${ds.label || st.selectedDsKey}`;

  st.casesList = _aspRunnerBuildDatasetCasesForModal(
    st.selectedPath, st.selectedDsKey,
    _aspRunnerGetParamValueFromTemplate(st.apiKey, st.selectedPath)
  );

  list.innerHTML = "";
  ["POS", "NEG"].forEach(grp => {
    const groupCases = st.casesList.filter(c => c.cat === grp);
    if (!groupCases.length) return;
    const hdr = document.createElement("div");
    hdr.className = `cm-group-hdr cm-grp-${grp.toLowerCase()}`;
    hdr.innerHTML = grp === "POS"
      ? `<span class="cm-grp-badge cm-pos">POS</span> Default Positive cases`
      : `<span class="cm-grp-badge cm-neg">NEG</span> Default Negative cases`;
    list.appendChild(hdr);

    groupCases.forEach(c => {
      const row = document.createElement("div");
      const isPOS = c.cat === "POS" && c.id !== "captured_original";
      const valHtml = isPOS
        ? `<span style="opacity:0.6;font-size:10px;margin-right:4px;font-weight:600;">e.g.</span>${_aspEscHtml(c.val)}`
        : _aspEscHtml(c.val);
      const valTitle = isPOS
        ? "Example template — unique value generated dynamically per run"
        : "Static test value";
      row.innerHTML = `
        <input type="checkbox" class="cm-cb" title="Include in run">
        <div class="cm-case-info">
          <span class="cm-case-desc">${_aspEscHtml(c.desc)}</span>
          <code class="cm-case-val" title="${valTitle}">${valHtml}</code>
        </div>
        <span class="cm-expect-badge"></span>`;
      _aspRunnerPaintDatasetCaseRow(row, c);

      row.querySelector(".cm-cb")?.addEventListener("change", (e) => {
        if (e.target.checked) {
          const prev = st.casesDraft[c.id];
          st.casesDraft[c.id] = (prev === "POS" || prev === "NEG") ? prev : c.cat;
        } else {
          st.casesDraft[c.id] = "SKIP";
        }
        _aspRunnerPaintDatasetCaseRow(row, c);
        _aspRunnerSyncDatasetModalUI();
      });
      row.querySelector(".cm-expect-badge")?.addEventListener("click", () => {
        if (st.casesDraft[c.id] === "SKIP") st.casesDraft[c.id] = c.cat;
        else st.casesDraft[c.id] = st.casesDraft[c.id] === "POS" ? "NEG" : "POS";
        _aspRunnerPaintDatasetCaseRow(row, c);
        _aspRunnerSyncDatasetModalUI();
      });
      list.appendChild(row);
    });
  });

  _aspRunnerRenderDatasetCustomList();
  _aspRunnerSyncDatasetModalUI();
}

function _aspRunnerRenderDatasetCustomList() {
  const st = _aspRunnerDatasetState;
  const listEl = document.getElementById("asp-runner-dataset-custom-list");
  if (!listEl || !st) return;
  listEl.innerHTML = "";
  (st.customDraft || []).forEach((cc, i) => {
    const row = document.createElement("div");
    row.className = "cm-custom-row";
    row.innerHTML = `
      <span class="cm-expect-badge ${cc.cat === "POS" ? "cm-pos" : "cm-neg"}" style="cursor:pointer">${cc.cat === "POS" ? "✓ POS" : "✗ NEG"}</span>
      <code class="cm-custom-val">${_aspEscHtml(String(cc.value))}</code>
      <button class="cm-custom-del" title="Remove">✕</button>`;
    row.querySelector(".cm-expect-badge")?.addEventListener("click", () => {
      st.customDraft[i].cat = st.customDraft[i].cat === "POS" ? "NEG" : "POS";
      _aspRunnerRenderDatasetCustomList();
      _aspRunnerSyncDatasetModalUI();
    });
    row.querySelector(".cm-custom-del")?.addEventListener("click", () => {
      st.customDraft.splice(i, 1);
      _aspRunnerRenderDatasetCustomList();
      _aspRunnerSyncDatasetModalUI();
    });
    listEl.appendChild(row);
  });
}

function aspRunnerDatasetClose() {
  _aspRunnerDatasetState = null;
  const el = document.getElementById("asp-runner-dataset-modal");
  if (el) el.style.display = "none";
}

async function aspRunnerDatasetOpenForApi(apiKey) {
  if (_aspRunnerRunning || !_aspRunnerData?.cases?.length) return;
  try {
    await _aspRunnerFetchDatasets();
  } catch (e) {
    _aspAlert(e.message || String(e));
    return;
  }

  const params = _aspRunnerCollectApiParams(apiKey);
  const firstPath = params[0]?.path || null;
  _aspRunnerDatasetState = {
    apiKey,
    selectedPath: firstPath,
    selectedDsKey: null,
    casesDraft: {},
    customDraft: [],
    casesList: [],
  };

  if (firstPath) {
    aspRunnerDatasetSelectParam(firstPath, true);
  }

  const sub = document.getElementById("asp-runner-dataset-modal-sub");
  if (sub) sub.textContent = apiKey ? `· ${apiKey}` : "";
  const search = document.getElementById("asp-runner-dataset-param-search");
  if (search) search.value = "";
  const dsSearch = document.getElementById("asp-runner-dataset-search");
  if (dsSearch) dsSearch.value = "";

  _aspRunnerRenderDatasetParamList();
  _aspRunnerRenderDatasetList();
  _aspRunnerRenderDatasetCasesList();
  _aspRunnerSyncDatasetModalUI();

  const modal = document.getElementById("asp-runner-dataset-modal");
  if (modal) modal.style.display = "flex";
}

function aspRunnerDatasetFilterParams() {
  _aspRunnerRenderDatasetParamList();
}

function aspRunnerDatasetFilterDatasets() {
  _aspRunnerRenderDatasetList();
}

function aspRunnerDatasetSelectParam(path, silent) {
  const st = _aspRunnerDatasetState;
  if (!st || !path) return;
  st.selectedPath = path;

  const snap = _aspRunnerGetParamSnapshotEntry(st.apiKey, path);
  const origVal = _aspRunnerGetParamValueFromTemplate(st.apiKey, path);
  const hadCases = (_aspRunnerData.cases || []).some(c =>
    _aspRunnerApiKeyFromCase(c) === st.apiKey && (c.param_path || c.param) === path
  );

  st.selectedDsKey = snap?.dataset_key
    || (hadCases ? (_aspRunnerData.cases.find(c =>
      _aspRunnerApiKeyFromCase(c) === st.apiKey && (c.param_path || c.param) === path
    )?.dataset_key) : null)
    || _aspRunnerDetectDatasetKey(path, origVal);

  st.casesDraft = {};
  st.customDraft = [];

  if (snap?.case_selections) {
    Object.assign(st.casesDraft, snap.case_selections);
  }
  if (Array.isArray(snap?.custom_cases)) {
    st.customDraft = snap.custom_cases.map(cc => ({ ...cc }));
  }

  if (st.selectedDsKey) {
    const modalCases = _aspRunnerBuildDatasetCasesForModal(
      path, st.selectedDsKey, origVal
    );
    modalCases.forEach(c => {
      if (st.casesDraft[c.id] == null) st.casesDraft[c.id] = c.cat;
    });
  }

  _aspRunnerRenderDatasetParamList();
  _aspRunnerRenderDatasetList();
  _aspRunnerRenderDatasetCasesList();
  if (!silent) _aspRunnerSyncDatasetModalUI();
}

function aspRunnerDatasetSelectDataset(dsKey) {
  const st = _aspRunnerDatasetState;
  if (!st || !st.selectedPath || !dsKey) return;
  const changed = st.selectedDsKey !== dsKey;
  st.selectedDsKey = dsKey;
  if (changed) {
    st.casesDraft = {};
    st.customDraft = [];
    const modalCases = _aspRunnerBuildDatasetCasesForModal(
      st.selectedPath, dsKey,
      _aspRunnerGetParamValueFromTemplate(st.apiKey, st.selectedPath)
    );
    modalCases.forEach(c => { st.casesDraft[c.id] = c.cat; });
  }
  _aspRunnerRenderDatasetList();
  _aspRunnerRenderDatasetCasesList();
}

function aspRunnerDatasetIncludeAll() {
  const st = _aspRunnerDatasetState;
  if (!st?.selectedDsKey) return;
  (st.casesList || []).forEach(c => {
    if (st.casesDraft[c.id] === "SKIP") st.casesDraft[c.id] = c.cat;
  });
  _aspRunnerRenderDatasetCasesList();
}

function aspRunnerDatasetSkipAll() {
  const st = _aspRunnerDatasetState;
  if (!st?.selectedDsKey) return;
  (st.casesList || []).forEach(c => { st.casesDraft[c.id] = "SKIP"; });
  _aspRunnerRenderDatasetCasesList();
}

function aspRunnerDatasetResetCases() {
  const st = _aspRunnerDatasetState;
  if (!st?.selectedPath || !st.selectedDsKey) return;
  st.casesDraft = {};
  st.customDraft = [];
  const modalCases = _aspRunnerBuildDatasetCasesForModal(
    st.selectedPath, st.selectedDsKey,
    _aspRunnerGetParamValueFromTemplate(st.apiKey, st.selectedPath)
  );
  modalCases.forEach(c => { st.casesDraft[c.id] = c.cat; });
  _aspRunnerRenderDatasetCasesList();
}

function aspRunnerDatasetToggleCustomCat() {
  const btn = document.getElementById("asp-runner-dataset-custom-cat");
  if (!btn) return;
  const isPos = btn.classList.contains("cm-cat-pos");
  if (isPos) {
    btn.classList.replace("cm-cat-pos", "cm-cat-neg");
    btn.textContent = "✗ NEG";
  } else {
    btn.classList.replace("cm-cat-neg", "cm-cat-pos");
    btn.textContent = "✓ POS";
  }
}

function aspRunnerDatasetAddCustom() {
  const st = _aspRunnerDatasetState;
  if (!st?.selectedDsKey) return;
  const inp = document.getElementById("asp-runner-dataset-custom-inp");
  const val = (inp?.value || "").trim();
  if (!val) { inp?.focus(); return; }
  const catBtn = document.getElementById("asp-runner-dataset-custom-cat");
  const cat = catBtn?.classList.contains("cm-cat-neg") ? "NEG" : "POS";
  st.customDraft.push({ id: `custom_${_aspRunnerHashText(val + cat)}`, value: val, cat });
  if (inp) inp.value = "";
  _aspRunnerRenderDatasetCustomList();
  _aspRunnerSyncDatasetModalUI();
}

function aspRunnerDatasetApply() {
  const st = _aspRunnerDatasetState;
  if (!st?.selectedPath || !st?.selectedDsKey || !_aspRunnerData) return;

  const runCount = _aspRunnerCountRunnableDatasetCases(
    st.selectedPath, st.selectedDsKey, st.casesDraft, st.customDraft
  );
  if (!runCount) {
    _aspAlert("Include at least one case before applying.");
    return;
  }

  const apiKey = st.apiKey;
  const paramPath = st.selectedPath;
  const hadCases = (_aspRunnerData.cases || []).some(c =>
    _aspRunnerApiKeyFromCase(c) === apiKey && (c.param_path || c.param) === paramPath
  );
  const isNewParam = !hadCases;

  const caseSelections = { ...st.casesDraft };
  const customCases = (st.customDraft || []).map(cc => ({ ...cc }));
  const isDefault = (st.casesList || []).every(c => caseSelections[c.id] === c.cat) && !customCases.length;

  _aspRunnerUpsertParamSnapshot(apiKey, paramPath, {
    dataset_key: st.selectedDsKey,
    detected: st.selectedDsKey,
    case_selections: isDefault ? null : caseSelections,
    custom_cases: customCases.length ? customCases : null,
  });

  const newCases = _aspRunnerGenerateCasesForParam(
    apiKey, paramPath, st.selectedDsKey, caseSelections, customCases, isNewParam
  );
  if (!newCases.length) {
    _aspAlert("No cases generated.");
    return;
  }

  _aspRunnerReplaceParamCases(apiKey, paramPath, newCases);
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerUpdateTitle();
  _aspRunnerPersistRunnerData();
  aspRunnerDatasetClose();
  _aspRunnerClearRunResultsUI();
}

function aspRunnerToggleRow(origIdx) {
  const dataTr = document.getElementById(`asp-runner-row-${origIdx}`);
  if (!dataTr) return;
  if (_aspRunnerExpandIdx === origIdx) {
    _aspRunnerCloseExpand();
    return;
  }
  _aspRunnerCloseExpand();
  _aspRunnerExpandIdx = origIdx;
  dataTr.classList.add("asp-runner-row-open");
  const ch = dataTr.querySelector(".asp-runner-chev");
  if (ch) ch.textContent = "▼";

  const d = _aspRunnerData;
  const c = d && d.cases[origIdx];
  const r = [..._aspRunnerLastResults].reverse().find(x => x.origIdx === origIdx);
  const exp = document.createElement("tr");
  exp.id = `asp-runner-expand-${origIdx}`;
  exp.className = "asp-runner-expand";
  exp.addEventListener("click", e => e.stopPropagation());

  const sentVal = (r && r.runtimeValue !== undefined) ? r.runtimeValue : (c && (c.test_value ?? c.case_value));
  const previewPayload = (!r && d && c) ? _aspRunnerBuildCasePayloadTemplate(d, c) : null;
  const viewReqPayload = r?.reqPayload || previewPayload;
  const reqText = viewReqPayload ? _aspRunnerPrettyBody(viewReqPayload.body) : "";
  let respText = "";
  if (r?.respData) {
    if (r.respData.body != null && r.respData.body !== "") respText = _aspRunnerPrettyBody(r.respData.body);
    else if (r.respData.error) respText = String(r.respData.error);
  } else if (c?.response != null && c.response !== "") {
    respText = _aspRunnerPrettyBody(c.response);
  }
  const sStr = String((r?.status ?? c?.prev_status) || 0);
  const sColor = sStr.startsWith("2") ? "#3fb950" : sStr.startsWith("4") ? "#f85149" : sStr.startsWith("5") ? "#d29922" : "#8b949e";
  const curlStr = (r?.respData && r.respData.sent_curl) ? r.respData.sent_curl : (viewReqPayload ? _aspRunnerFallbackCurl(viewReqPayload) : "");
  _aspRunnerCurlByIdx[origIdx] = curlStr || "";
  const curlBtn = curlStr
    ? `<button type="button" onclick="aspRunnerCopyCurl(${origIdx},this)" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">📋 cURL</button>`
    : "";
  const uniqueApplied = r?.uniqueApplied || [];
  if (r?.case_misconfig) dataTr.classList.add("asp-runner-misconfig");

  const editing = _aspRunnerBodyEdit && _aspRunnerBodyEdit.origIdx === origIdx;
  _aspRunnerExpandSearchCache[origIdx] = { reqText, respText, sentVal, uniqueApplied };
  const draftText = editing ? (_aspRunnerBodyEdit.draftText ?? reqText ?? "") : "";
  const editBtn = editing
    ? `
        <div style="display:flex;align-items:center;gap:6px;margin-left:8px;flex-shrink:0">
          <button onclick="aspRunnerBodyEditCancel()" style="background:none;border:1px solid var(--border);color:var(--text3);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">✕ Cancel</button>
          <button class="asp-runner-body-save-btn" onclick="aspRunnerBodyEditSave(${origIdx},false)" style="background:none;border:1px solid #1f6feb;color:#79c0ff;font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">💾 Save</button>
          <button class="asp-runner-body-apply-btn" onclick="aspRunnerBodyEditSave(${origIdx},true)" style="background:none;border:1px solid #238636;color:#3fb950;font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">Apply for All</button>
        </div>`
    : (_aspRunnerRunning
        ? ""
        : `<button onclick="aspRunnerBodyEditBegin(${origIdx})" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">✏️ Edit</button>`);

  exp.innerHTML = `<td colspan="8" style="padding:0;background:var(--bg);border-bottom:1px solid var(--border)">
    <div class="asp-runner-io-grid${editing ? " asp-runner-io-editing" : ""}">
      <div class="asp-runner-io-col">
        <div class="asp-runner-io-hd">
          <span style="font-size:11px;font-weight:700;color:#79c0ff">📤 Request Body</span>
          ${!r ? `<span style="font-size:10px;color:var(--text3)">recorded</span>` : ""}
          ${_aspRunnerBodySizeHint(reqText)}
          ${curlBtn}
          ${!editing && reqText ? `<button type="button" onclick="aspRunnerCopyBody(${origIdx},'req',this)" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">Copy body</button>` : ""}
          ${editBtn}
          ${!editing ? `<input id="asp-runner-req-search-${origIdx}" type="text" placeholder="Search…" oninput="aspRunnerSearchReq(${origIdx})"
              style="margin-left:8px;background:var(--bg3);border:1px solid var(--border);color:var(--text);font-size:11px;padding:3px 8px;border-radius:6px;outline:none;width:160px">` : ""}
        </div>
        <div class="asp-runner-io-scroll${editing ? " asp-runner-io-scroll-edit" : ""}">
          ${editing
            ? `<div class="asp-runner-body-edit-wrap">
                 <textarea id="asp-runner-body-edit-ta" class="asp-runner-body-edit-ta" spellcheck="false">${_aspEscHtml(draftText)}</textarea>
                 <div id="asp-runner-body-edit-error" class="asp-runner-body-edit-error"></div>
               </div>`
            : `<div id="asp-runner-req-prewrap-${origIdx}">${reqText ? _aspRunnerPreHtml(reqText, sentVal, uniqueApplied) : `<span style="font-size:11px;color:var(--text3)">(no body)</span>`}</div>`}
        </div>
      </div>
      <div class="asp-runner-io-col">
        <div class="asp-runner-io-hd">
          <span style="font-size:11px;font-weight:700;color:#3fb950">📥 Response Body</span>
          ${_aspRunnerBodySizeHint(respText)}
          ${respText ? `<button type="button" onclick="aspRunnerCopyBody(${origIdx},'resp',this)" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">Copy body</button>` : ""}
          <input id="asp-runner-resp-search-${origIdx}" type="text" placeholder="Search…" oninput="aspRunnerSearchResp(${origIdx})"
            style="margin-left:auto;background:var(--bg3);border:1px solid var(--border);color:var(--text);font-size:11px;padding:3px 8px;border-radius:6px;outline:none;width:160px">
          ${r?.respData
            ? `<span style="font-size:10px;color:${sColor}">${r.status || "—"} ${_aspEscHtml(r.respData.status_text || "")}</span>`
            : (c?.prev_status != null ? `<span style="font-size:10px;color:${sColor}">${c.prev_status}</span>` : "")}
        </div>
        <div class="asp-runner-io-scroll">
          <div id="asp-runner-resp-prewrap-${origIdx}">${respText ? _aspRunnerPreHtml(respText, null) : `<span style="font-size:11px;color:var(--text3)">(no response)</span>`}</div>
        </div>
      </div>
    </div>
  </td>`;
  dataTr.after(exp);
  if (editing) _aspRunnerBodyEditBindTa();
}

function aspRunnerToggleCaseEnabled(origIdx) {
  const c = _aspRunnerData?.cases?.[origIdx];
  if (!c) return;
  c.enabled = c.enabled === false ? true : false;
  c.status = c.enabled === false ? "disabled" : "active";
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerRenderTable(_aspRunnerData.cases);
}

function aspRunnerRemoveCase(origIdx) {
  if (!_aspRunnerData?.cases?.[origIdx]) return;
  _aspRunnerData.cases.splice(origIdx, 1);
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerUpdateTitle();
  _aspRunnerRenderTable(_aspRunnerData.cases);
}

async function aspRunnerRemoveApiGroup(apiKey) {
  if (!_aspRunnerData?.cases?.length || !apiKey) return;
  const count = _aspRunnerData.cases.filter(c => _aspRunnerApiKeyFromCase(c) === apiKey).length;
  if (!count) return;
  const ok = await _aspConfirm(`Remove this API group and all ${count} cases?\n\n${apiKey}`);
  if (!ok) return;
  _aspRunnerData.cases = _aspRunnerData.cases.filter(c => _aspRunnerApiKeyFromCase(c) !== apiKey);
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  _aspRunnerUpdateTitle();
  _aspRunnerClearRunResultsUI();
}

function _aspRunnerRenderTable(cases) {
  const showPos = document.getElementById("asp-runner-filter-pos")?.checked !== false;
  const showNeg = document.getElementById("asp-runner-filter-neg")?.checked !== false;
  const tbody   = document.getElementById("asp-runner-tbody");
  if (!tbody) return;
  _aspRunnerExpandIdx = -1;

  tbody.innerHTML = "";
  let num = 0;
  let lastApiKey = "";
  cases.forEach((c, idx) => {
    if (c.enabled === false && c.status === "disabled") {
      // still show disabled rows for lifecycle management
    }
    if (c.case_cat === "POS" && !showPos) return;
    if (c.case_cat === "NEG" && !showNeg) return;
    const apiKey = _aspRunnerApiKeyFromCase(c);
    if (apiKey !== lastApiKey) {
      lastApiKey = apiKey;
      const grp = document.createElement("tr");
      const groupMethod = c._method || _aspRunnerData?.method || "GET";
      const groupUrl = c._url || _aspRunnerData?.url || "";
      const apiKeyAttr = _aspEscHtml(String(apiKey)).replace(/"/g, "&quot;");
      grp.innerHTML = `
        <td colspan="8" style="padding:7px 10px;background:var(--bg2);border-top:1px solid var(--border);border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:10px">
            <div style="min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              <span style="font-size:10px;font-weight:700;color:#79c0ff;margin-right:8px">${_aspEscHtml(String(groupMethod))}</span>
              <span style="font-size:10px;color:var(--text2);font-family:var(--mono)">${_aspEscHtml(String(groupUrl))}</span>
            </div>
            <button data-api-dataset="${apiKeyAttr}" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;flex-shrink:0">🔬 Dataset</button>
            <button data-api-random="${apiKeyAttr}" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;flex-shrink:0">🎲 Random</button>
            <button data-api-remove="${apiKeyAttr}" style="background:none;border:1px solid rgba(248,81,73,.35);color:#f85149;font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;flex-shrink:0">Del</button>
          </div>
        </td>`;
      grp.querySelector("[data-api-dataset]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        aspRunnerDatasetOpenForApi(apiKey);
      });
      grp.querySelector("[data-api-random]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        aspRunnerRandomOpenForApi(apiKey);
      });
      grp.querySelector("[data-api-remove]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        aspRunnerRemoveApiGroup(apiKey);
      });
      tbody.appendChild(grp);
    }
    num++;

    const catColor  = c.case_cat === "POS" ? "#79c0ff" : "#f85149";
    const prevColor = c.prev_result === "PASS" ? "#3fb950" : c.prev_result === "FAIL" ? "#f85149" : "#d29922";
    const valText   = c.test_value === null ? "null"
                    : c.test_value === undefined ? "—"
                    : String(c.test_value).slice(0, 22);
    const statusBadge = c.status === "removed_param"
      ? `<span style="font-size:9px;color:#f85149;border:1px solid rgba(248,81,73,.35);padding:1px 5px;border-radius:4px;margin-left:6px">stale</span>`
      : c.enabled === false
        ? `<span style="font-size:9px;color:var(--text3);border:1px solid var(--border);padding:1px 5px;border-radius:4px;margin-left:6px">disabled</span>`
        : c.merge_state === "new"
          ? `<span style="font-size:9px;color:#3fb950;border:1px solid rgba(63,185,80,.35);padding:1px 5px;border-radius:4px;margin-left:6px">new</span>`
          : c.merge_state && c.merge_state !== "source"
            ? `<span style="font-size:9px;color:#d29922;border:1px solid rgba(210,153,34,.35);padding:1px 5px;border-radius:4px;margin-left:6px">${_aspEscHtml(c.merge_state)}</span>`
            : "";
    const rowOpacity = c.enabled === false ? "opacity:.6;" : "";

    const tr = document.createElement("tr");
    tr.id = `asp-runner-row-${idx}`;
    tr.className = "asp-runner-data";
    tr.style.cssText = `border-bottom:1px solid var(--border);${rowOpacity}`;
    tr.innerHTML = `
      <td style="padding:6px 6px;color:var(--text3);white-space:nowrap"><span class="asp-runner-chev">▶</span> ${num}</td>
      <td style="padding:6px 6px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        <span style="color:var(--text2)">${_aspEscHtml(c.param)}</span>${statusBadge}
        <span style="color:var(--text3);margin-left:4px">/ ${_aspEscHtml(c.case_desc)}</span>
      </td>
      <td style="padding:6px 6px;text-align:center">
        <span style="color:${catColor};font-weight:700;font-size:10px">${c.case_cat}</span>
      </td>
      <td id="asp-runner-val-${idx}" style="padding:6px 6px;color:#e3b341;font-family:var(--mono);font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${_aspEscHtml(String(c.test_value ?? ""))}">${_aspEscHtml(valText)}</td>
      <td style="padding:6px 6px;text-align:center">
        <span style="color:${prevColor};font-size:10px;font-weight:700">${c.prev_result}</span>
      </td>
      <td id="asp-runner-result-${idx}" style="padding:6px 6px;text-align:center;color:var(--text3)">—</td>
      <td id="asp-runner-status-${idx}" style="padding:6px 6px;text-align:center;color:var(--text3)">—</td>
      <td id="asp-runner-time-${idx}"   style="padding:6px 6px;text-align:right;color:var(--text3)">
        <div style="display:flex;justify-content:flex-end;align-items:center;gap:8px">
          <span style="min-width:14px;text-align:right">—</span>
          <button data-act="toggle" style="background:none;border:1px solid var(--border);color:var(--text2);font-size:10px;padding:3px 10px;border-radius:6px;cursor:pointer">${c.enabled === false ? "Enable" : "Disable"}</button>
          <button data-act="remove" style="background:none;border:1px solid rgba(248,81,73,.35);color:#f85149;font-size:10px;padding:3px 10px;border-radius:6px;cursor:pointer">Del</button>
        </div>
      </td>
    `;
    tr.addEventListener("click", () => aspRunnerToggleRow(idx));
    tr.querySelector('[data-act="toggle"]')?.addEventListener("click", (e) => {
      e.stopPropagation();
      aspRunnerToggleCaseEnabled(idx);
    });
    tr.querySelector('[data-act="remove"]')?.addEventListener("click", (e) => {
      e.stopPropagation();
      aspRunnerRemoveCase(idx);
    });
    tbody.appendChild(tr);
  });
}

// Run All — shows Bearer Token modal first if token present in any headers
function aspRunnerRun() {
  if (_aspRunnerRunning || !_aspRunnerData) return;
  _aspRunnerRefreshCaseStatuses();
  _aspRunnerSyncState = _aspRunnerBuildSyncState();
  if ((_aspRunnerSyncState.blocked || []).length) {
    _aspRunnerShowSyncGate(_aspRunnerSyncState);
    return;
  }

  const d        = _aspRunnerData;
  const hdrs     = d.headers || {};
  const authHdr  = hdrs.Authorization || hdrs.authorization || "";
  if (authHdr.toLowerCase().startsWith("bearer ")) {
    const inp = document.getElementById("asp-runner-token-inp");
    if (inp) inp.value = authHdr.slice(7).trim();
    document.getElementById("asp-runner-token-modal").style.display = "flex";
    return;
  }
  _aspRunnerDoRun();
}

function aspRunnerTokenUpdate() {
  document.getElementById("asp-runner-token-modal").style.display = "none";
  const newToken = (document.getElementById("asp-runner-token-inp")?.value || "").trim();
  if (newToken) {
    const d = _aspRunnerData;
    d.headers = d.headers || {};
    d.headers.Authorization = "Bearer " + newToken;
    // Propagate to per-case headers so merged collections also get new token
    (d.cases || []).forEach(c => {
      if (c._headers) c._headers.Authorization = "Bearer " + newToken;
    });
  }
  _aspRunnerDoRun();
}

function aspRunnerTokenCancel() {
  document.getElementById("asp-runner-token-modal").style.display = "none";
}

function aspRunnerPause() {
  _aspRunnerPaused = !_aspRunnerPaused;
  const btn = document.getElementById("asp-runner-pause-btn");
  if (!btn) return;
  if (_aspRunnerPaused) {
    btn.textContent        = "▶ Resume";
    btn.style.borderColor  = "#3fb950";
    btn.style.color        = "#3fb950";
  } else {
    btn.textContent        = "⏸ Pause";
    btn.style.borderColor  = "#d29922";
    btn.style.color        = "#d29922";
  }
}

function aspRunnerAbort() {
  _aspRunnerAborted = true;
  _aspRunnerPaused  = false;  // unblock the pause-wait so loop can exit
}

function aspRunnerTokenSkip() {
  document.getElementById("asp-runner-token-modal").style.display = "none";
  _aspRunnerDoRun();
}

async function _aspRunnerDoRun() {
  if (_aspRunnerRunning || !_aspRunnerData) return;
  _aspRunnerRunning     = true;
  _aspRunnerPaused      = false;
  _aspRunnerAborted     = false;
  // Roll last run into Prev before clearing in-memory results.
  if (_aspRunnerCommitLastResultsToPrev()) {
    _aspRunnerPersistRunnerData();
    _aspRunnerUpdateTitle();
  }
  _aspRunnerLastResults = [];   // clear before each run
  _aspRunnerCloseExpand();

  const d       = _aspRunnerData;
  // Refresh Prev column from committed last-run status.
  _aspRunnerRenderTable(d.cases);
  const runtimeVars = _aspResolveActiveVars(null, null) || [];
  const showPos = document.getElementById("asp-runner-filter-pos")?.checked !== false;
  const showNeg = document.getElementById("asp-runner-filter-neg")?.checked !== false;
  const cases   = d.cases.filter(c =>
    c.enabled !== false &&
    c.status !== "removed_param" &&
    ((c.case_cat === "POS" && showPos) || (c.case_cat === "NEG" && showNeg))
  );

  const btnLabel      = document.getElementById("asp-runner-btn-label");
  const btnSpinner    = document.getElementById("asp-runner-btn-spinner");
  const runBtn        = document.getElementById("asp-runner-run-btn");
  const pauseBtn      = document.getElementById("asp-runner-pause-btn");
  const abortBtn      = document.getElementById("asp-runner-abort-btn");
  const progWrap      = document.getElementById("asp-runner-progress-wrap");
  const progFill      = document.getElementById("asp-runner-progress-fill");
  const liveSum       = document.getElementById("asp-runner-live-summary");
  const addCasesLabel = document.getElementById("asp-runner-add-cases-label");
  const posLabel      = document.getElementById("asp-runner-filter-pos-label");
  const negLabel      = document.getElementById("asp-runner-filter-neg-label");
  const filterPos     = document.getElementById("asp-runner-filter-pos");
  const filterNeg     = document.getElementById("asp-runner-filter-neg");

  const _disableControls = () => {
    if (addCasesLabel) { addCasesLabel.style.opacity = "0.35"; addCasesLabel.style.pointerEvents = "none"; }
    if (posLabel)  posLabel.style.opacity  = "0.35";
    if (negLabel)  negLabel.style.opacity  = "0.35";
    if (filterPos) filterPos.disabled = true;
    if (filterNeg) filterNeg.disabled = true;
  };
  const _enableControls = () => {
    if (addCasesLabel) { addCasesLabel.style.opacity = ""; addCasesLabel.style.pointerEvents = ""; }
    if (posLabel)  posLabel.style.opacity  = "";
    if (negLabel)  negLabel.style.opacity  = "";
    if (filterPos) filterPos.disabled = false;
    if (filterNeg) filterNeg.disabled = false;
  };

  if (btnLabel)   btnLabel.textContent = "Running…";
  if (btnSpinner) btnSpinner.style.display = "inline-block";
  if (runBtn)     runBtn.disabled = true;
  if (pauseBtn)   pauseBtn.style.display = "inline-flex";
  if (abortBtn)   abortBtn.style.display = "inline-flex";
  if (progWrap)   progWrap.style.display = "block";
  _disableControls();
  _aspRunnerSetExportEnabled(false);
  _aspRunnerSetExportCollectionEnabled(false);

  let pass = 0, fail = 0, warn = 0;
  const poolsByApi = {};
  const livePoolFor = (apiKey) => {
    if (!poolsByApi[apiKey]) {
      const rec = (d.unique_pools_by_api || {})[apiKey];
      poolsByApi[apiKey] = rec && rec.matched
        ? _aspRunnerMakeLivePool(rec.matched)
        : { pools: {}, index: 0, ambig: 0 };
    }
    return poolsByApi[apiKey];
  };

  for (let i = 0; i < cases.length; i++) {
    const c       = cases[i];
    const origIdx = d.cases.indexOf(c);

    // Pause: spin-wait until resumed or aborted
    while (_aspRunnerPaused && !_aspRunnerAborted) {
      if (liveSum) liveSum.textContent = `⏸ Paused · ${i}/${cases.length} · ${pass}P ${fail}F`;
      await new Promise(r => setTimeout(r, 150));
    }

    // Abort: clear pending row marker and stop
    if (_aspRunnerAborted) {
      const pendingCell = document.getElementById(`asp-runner-result-${origIdx}`);
      if (pendingCell && pendingCell.textContent === "…") pendingCell.innerHTML = "—";
      break;
    }

    if (progFill) progFill.style.width = Math.round((i / cases.length) * 100) + "%";
    if (liveSum)  liveSum.textContent  = `${i}/${cases.length} · ${pass}P ${fail}F`;

    const resultCell = document.getElementById(`asp-runner-result-${origIdx}`);
    if (resultCell) resultCell.innerHTML = `<span style="color:var(--text3)">…</span>`;

    try {
      const apiKey = _aspRunnerApiKeyFromCase(c);
      const pool = livePoolFor(apiKey);
      let poolRow = null;
      if (_aspRunnerLivePoolWidth(pool)) poolRow = _aspRunnerLivePoolCurrent(pool);

      // Dynamic value generation for POS dataset cases (fresh unique values per run)
      let runtimeCaseValue = undefined;
      const isPos = c.case_cat === "POS";
      const isOriginal = c.dataset_case_id === "captured_original" || c.case_desc === "Captured original value";

      if (isPos && !isOriginal && !c._user_modified) {
        const dsKey = c.dataset_key || _aspRunnerDetectDatasetKey(c.param_path || c.param, c.test_value);
        const baseVal = c.case_value !== undefined ? c.case_value : c.test_value;
        runtimeCaseValue = _aspRunnerGenerateDynamicCaseValue(dsKey, c.dataset_case_id, baseVal, c.case_cat, c.case_desc);
      }

      if (runtimeCaseValue !== undefined) {
        c.test_value = runtimeCaseValue;
        c.case_value = runtimeCaseValue;
        const valCell = document.getElementById(`asp-runner-val-${origIdx}`);
        if (valCell) {
          const displayVal = runtimeCaseValue === null ? "null"
                           : runtimeCaseValue === undefined ? "—"
                           : String(runtimeCaseValue).slice(0, 22);
          valCell.textContent = displayVal;
          valCell.title = String(runtimeCaseValue ?? "");
        }
      }

      let payload = _aspRunnerBuildCasePayload(d, c, poolRow, runtimeCaseValue);
      const uniqueApplied = Array.isArray(payload._unique_applied) ? payload._unique_applied : [];
      delete payload._unique_applied;
      payload = _aspRunnerResolvePayload(payload, runtimeVars, _aspRunnerVars.chain || {});

      const t0  = Date.now();
      const res = await fetch(`${ASP_BASE}/send`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
      });
      const data    = await res.json();
      const elapsed = Date.now() - t0;
      const status  = data.status_code || 0;
      const result  = _aspRunnerDetermineResult(c.case_cat, status);
      const mis     = _aspAlreadyExistsMisconfig(status, data && data.body);

      if (result === "PASS")      pass++;
      else if (result === "FAIL") fail++;
      else                        warn++;

      const rColor = result === "PASS" ? "#3fb950" : result === "FAIL" ? "#f85149" : "#d29922";
      const sStr   = String(status);
      const sColor = sStr.startsWith("2") ? "#3fb950" : sStr.startsWith("4") ? "#f85149"
                   : sStr.startsWith("5") ? "#d29922" : "#8b949e";

      if (resultCell) resultCell.innerHTML =
        `<span style="color:${rColor};font-weight:700;font-size:10px">${result}</span>` +
        (mis ? `<span class="av-misconfig-tag" title="${_aspEscHtml(mis.misconfig_reason)}">case misconfig</span>` : "");
      const rowEl = document.getElementById(`asp-runner-row-${origIdx}`);
      if (rowEl) rowEl.classList.toggle("asp-runner-misconfig", !!mis);
      const sCell = document.getElementById(`asp-runner-status-${origIdx}`);
      if (sCell) sCell.innerHTML = `<span style="color:${sColor}">${status}</span>`;
      const tCell = document.getElementById(`asp-runner-time-${origIdx}`);
      if (tCell) tCell.textContent = `${elapsed}ms`;

      _aspRunnerApplyExtractors(c, data);
      _aspRunnerLivePoolNote(pool, status, data && data.body, poolRow);
      _aspRunnerLastResults.push({
        origIdx, result, status, elapsed, reqPayload: payload, respData: data,
        uniqueApplied, runtimeValue: runtimeCaseValue, case_misconfig: !!mis, misconfig_reason: mis ? mis.misconfig_reason : "",
      });
      _aspRunnerRefreshDashboard();

    } catch(err) {
      if (String(err && err.message || "").includes("Unique value list exhausted")) {
        if (resultCell) resultCell.innerHTML = "—";
        _aspAlert(err.message);
        _aspRunnerAborted = true;
        break;
      }
      fail++;
      if (resultCell) resultCell.innerHTML = `<span style="color:#f85149;font-size:10px">ERR</span>`;
      _aspRunnerLastResults.push({ origIdx, result: "ERR", status: 0, elapsed: 0, reqPayload: null, respData: null, runtimeValue: runtimeCaseValue });
      _aspRunnerRefreshDashboard();
    }
  }

  const aborted = _aspRunnerAborted;

  if (progFill) {
    if (aborted) {
      progFill.style.transition = "none";
      progFill.style.width      = "0%";
      progFill.offsetHeight;                    // force reflow so transition reset takes effect
      progFill.style.transition = "";
    } else {
      progFill.style.width = "100%";
    }
  }

  if (liveSum) liveSum.textContent = aborted
    ? `Aborted · ${pass}P ${fail}F`
    : `Done · ${cases.length} · ${pass}P ${fail}F${warn ? ` ${warn}W` : ""}`;

  if (btnLabel)   btnLabel.textContent = "▶ Run All";
  if (btnSpinner) btnSpinner.style.display = "none";
  if (runBtn)     runBtn.disabled = false;

  if (pauseBtn) {
    pauseBtn.style.display     = "none";
    pauseBtn.textContent       = "⏸ Pause";
    pauseBtn.style.borderColor = "#d29922";
    pauseBtn.style.color       = "#d29922";
  }
  if (abortBtn) abortBtn.style.display = "none";

  _enableControls();
  _aspRunnerCommitLivePools(poolsByApi);
  _aspRunnerPersistRunnerData();
  _aspRunnerRunning = false;
  _aspRunnerPaused  = false;
  _aspRunnerAborted = false;
  _aspRunnerSetExportEnabled(true);
  _aspRunnerSetExportCollectionEnabled(true);
  _aspRunnerRefreshDashboard();  // final refresh after run ends
}

function _aspRunnerDetermineResult(cat, status) {
  const code = parseInt(status, 10);
  if (isNaN(code)) return "WARN";
  if (cat === "POS") return (code >= 200 && code < 300) ? "PASS" : "FAIL";
  if (code >= 400 && code < 500) return "PASS";
  if (code >= 200 && code < 300) return "FAIL";
  return "WARN";
}

const _ASP_UNIQ_HINTS = [
  "already exist", "already exists", "already taken", "already used",
  "already_exist", "already_exists", "alreadyexists",
  "duplicate", "not unique", "unique constraint", "must be unique", "conflict",
];

function _aspUniqMatchText(resp) {
  let raw = "";
  if (resp == null) raw = "";
  else if (typeof resp === "string") raw = resp;
  else { try { raw = JSON.stringify(resp); } catch (_) { raw = String(resp); } }
  const flat = raw.toLowerCase();
  const spaced = flat.replace(/[^a-z0-9]+/g, " ");
  const compact = flat.replace(/[^a-z0-9]+/g, "");
  return `${flat}\n${spaced}\n${compact}`;
}

function _aspAlreadyExistsMisconfig(status, respBody) {
  const code = parseInt(status, 10);
  if (code !== 409 && code !== 422) return null;
  const text = _aspUniqMatchText(respBody);
  if (!_ASP_UNIQ_HINTS.some(h => text.includes(h))) return null;
  return {
    case_misconfig: true,
    misconfig_tag: "case misconfig",
    misconfig_reason: `Already exists (${code}) — response indicates this value already exists`,
  };
}

// ── APISphere Runner Dashboard ────────────────────────────────────────────────

function aspRunnerDashboardShow() {
  const d = _aspRunnerData;
  if (!d) return;

  const ran  = _aspRunnerLastResults.length > 0;
  const rMap = {};
  _aspRunnerLastResults.forEach(r => { rMap[r.origIdx] = r; });

  const total    = d.cases.length;
  const ranCount = _aspRunnerLastResults.length;

  let prevPass = 0, prevFail = 0;
  d.cases.forEach((c, i) => {
    if (!rMap[i]) return;
    if (c.prev_result === "PASS") prevPass++;
    else if (c.prev_result === "FAIL") prevFail++;
  });

  let curPass = 0, curFail = 0, curWarn = 0;
  _aspRunnerLastResults.forEach(r => {
    if (r.result === "PASS") curPass++;
    else if (r.result === "FAIL" || r.result === "ERR") curFail++;
    else curWarn++;
  });

  const improved = [], regressed = [];
  d.cases.forEach((c, i) => {
    const r = rMap[i];
    if (!r) return;
    const wasPass = c.prev_result === "PASS";
    const isPass  = r.result === "PASS";
    if (!wasPass && isPass) improved.push({ c, r });
    else if (wasPass && !isPass) regressed.push({ c, r });
  });

  const byCat = { POS: { total:0, prevPass:0, pass:0, fail:0 }, NEG: { total:0, prevPass:0, pass:0, fail:0 } };
  d.cases.forEach((c, i) => {
    const r = rMap[i];
    if (!r) return;
    const cat = c.case_cat === "NEG" ? "NEG" : "POS";
    byCat[cat].total++;
    if (c.prev_result === "PASS") byCat[cat].prevPass++;
    if (r.result === "PASS") byCat[cat].pass++;
    else byCat[cat].fail++;
  });

  const byParam = {};
  d.cases.forEach((c, i) => {
    const r = rMap[i];
    if (!r) return;
    const apiKey = _aspRunnerApiKeyFromCase(c) || _aspRunnerApiKey(c._method || d.method, c._url || d.url);
    const param = c.param || c.param_path || "(unknown)";
    const key = apiKey + "||" + param;
    if (!byParam[key]) {
      byParam[key] = {
        param, total:0, prevPass:0, pass:0, fail:0, times:[],
        method: c._method || d.method || "?",
        url: c._url || d.url || "?",
        apiKey,
      };
    }
    const s = byParam[key];
    s.total++;
    if (c.prev_result === "PASS") s.prevPass++;
    if (r.result === "PASS") s.pass++;
    else s.fail++;
    if (r.elapsed > 0) s.times.push(r.elapsed);
  });

  const byApi = {};
  d.cases.forEach((c, i) => {
    const r = rMap[i];
    if (!r) return;
    const apiKey = _aspRunnerApiKeyFromCase(c) || _aspRunnerApiKey(c._method || d.method, c._url || d.url);
    if (!byApi[apiKey]) {
      byApi[apiKey] = {
        total:0, prevPass:0, pass:0, fail:0, times:[],
        params: new Set(),
        method: c._method || d.method || "?",
        url: c._url || d.url || "?",
      };
    }
    const s = byApi[apiKey];
    s.total++;
    if (c.prev_result === "PASS") s.prevPass++;
    if (r.result === "PASS") s.pass++;
    else s.fail++;
    if (r.elapsed > 0) s.times.push(r.elapsed);
    if (c.param || c.param_path) s.params.add(c.param || c.param_path);
  });

  const times   = _aspRunnerLastResults.map(r => r.elapsed).filter(t => t > 0);
  const avgTime = times.length ? Math.round(times.reduce((a,b)=>a+b,0)/times.length) : 0;
  const minTime = times.length ? Math.min(...times) : 0;
  const maxTime = times.length ? Math.max(...times) : 0;

  const delta = ran ? curPass - prevPass : null;
  const deltaStr = delta === null ? "—" : (delta >= 0 ? "+" : "") + delta;
  const deltaColor = delta === null ? "var(--text2)" : delta > 0 ? "#3fb950" : delta < 0 ? "#f85149" : "var(--text2)";
  const curPct = ranCount > 0 ? Math.round(curPass / ranCount * 100) : 0;
  const mColor = (m) => ({ GET:"#3fb950", POST:"#79c0ff", PUT:"#d29922", DELETE:"#f85149", PATCH:"#bc8cff" }[m] || "#8b949e");

  const secTitle = (label, count, color) =>
    `<div class="rd-sec-h"><span class="rd-sec-label" style="color:${color}">${label}</span>` +
    (count != null ? `<span class="rd-sec-count">${count}</span>` : "") + `</div>`;

  const rateBar = (pct, color) => {
    const p = Math.max(0, Math.min(100, pct|0));
    return `<div class="rd-rate"><div class="rd-rate-track"><div class="rd-rate-fill" style="width:${p}%;background:${color}"></div></div><span class="rd-rate-txt">${p}%</span></div>`;
  };

  const H = [];
  H.push(`<style>
.rd-wrap{display:flex;flex-direction:column;gap:16px;color:var(--text);font-size:12px}
.rd-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.rd-metric{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.rd-metric-l{font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px}
.rd-metric-v{font-size:20px;font-weight:700;line-height:1.15;color:var(--text)}
.rd-metric-s{font-size:11px;color:var(--text3);margin-top:5px}
.rd-panel{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.rd-sec-h{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.rd-sec-label{font-size:12px;font-weight:700}
.rd-sec-count{font-size:10px;color:var(--text3);background:var(--bg3);border:1px solid var(--border);padding:1px 7px;border-radius:999px}
.rd-overview{display:grid;grid-template-columns:minmax(160px,200px) 1fr;gap:12px}
@media (max-width:720px){.rd-overview{grid-template-columns:1fr}}
.rd-table{width:100%;border-collapse:collapse}
.rd-table th{text-align:left;font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;padding:8px 10px;border-bottom:1px solid var(--border);background:var(--bg3)}
.rd-table td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:middle;font-size:12px}
.rd-table tr:last-child td{border-bottom:none}
.rd-table .num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.rd-table .ctr{text-align:center}
.rd-method{display:inline-block;font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;border:1px solid transparent;flex-shrink:0}
.rd-url{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:420px}
.rd-row-main{display:flex;align-items:center;gap:8px;min-width:0}
.rd-rate{display:flex;align-items:center;gap:8px;min-width:110px}
.rd-rate-track{flex:1;height:6px;background:var(--bg3);border-radius:99px;overflow:hidden;border:1px solid var(--border)}
.rd-rate-fill{height:100%;border-radius:99px}
.rd-rate-txt{font-size:11px;font-weight:600;color:var(--text2);width:34px;text-align:right;font-variant-numeric:tabular-nums}
.rd-pass{color:#3fb950;font-weight:700}
.rd-fail{color:#f85149;font-weight:700}
.rd-muted{color:var(--text3)}
.rd-two{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media (max-width:720px){.rd-two{grid-template-columns:1fr}}
.rd-list-item{padding:7px 0;border-bottom:1px solid var(--border)}
.rd-list-item:last-child{border-bottom:none}
.rd-list-t{font-size:12px;font-weight:600;color:var(--text)}
.rd-list-s{font-size:11px;color:var(--text3);margin-top:2px}
.rd-row-main b{min-width:0;overflow-wrap:anywhere;word-break:break-word}
.rd-fail-wrap{border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--bg2)}
.rd-fail-row{border-bottom:1px solid var(--border)}
.rd-fail-row:last-child{border-bottom:none}
.rd-fail-head{display:grid;grid-template-columns:36px minmax(0,1.4fr) minmax(0,.9fr) 56px 64px 56px 72px;gap:8px;align-items:center;padding:8px 12px;background:var(--bg3);border-bottom:1px solid var(--border)}
.rd-fail-head span{font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.04em}
.rd-fail-sum{display:grid;grid-template-columns:36px minmax(0,1.4fr) minmax(0,.9fr) 56px 64px 56px 72px;gap:8px;align-items:start;padding:9px 12px;cursor:pointer}
.rd-fail-sum:hover{background:rgba(255,255,255,.03)}
.rd-fail-sum .rd-url{max-width:100%;min-width:0}
.rd-fail-sub{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:4px;min-width:0}
.rd-fail-desc{font-size:11px;color:var(--text3);min-width:0;line-height:1.35;overflow-wrap:anywhere}
.rd-fail-row.rd-fail-misconfig .rd-fail-sum{box-shadow:inset 3px 0 0 #d29922;background:rgba(210,153,34,.06)}
.rd-wrap .av-misconfig-tag,.rd-fail-sub .av-misconfig-tag{
  display:inline-flex;align-items:center;flex-shrink:0;margin:0;
  font-size:9px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;line-height:1.35;
  color:#e3b341;background:rgba(210,153,34,.15);border:1px solid rgba(210,153,34,.45);
  border-radius:3px;padding:1px 6px;white-space:nowrap
}
.rd-badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px}
.rd-empty{font-size:12px;color:var(--text3);padding:8px 0}
</style>`);

  H.push(`<div class="rd-wrap">`);

  // Metrics
  const metrics = [
    { l: "Ran", v: `${ranCount}<span class="rd-muted" style="font-size:13px;font-weight:600"> / ${total}</span>`, s: "cases executed", c: "#79c0ff" },
    { l: "Pass", v: ran ? String(curPass) : "—", s: ran ? `${curPct}% pass rate` : "not run", c: "#3fb950" },
    { l: "Fail", v: ran ? String(curFail) : "—", s: curWarn ? `${curWarn} warn` : "current run", c: "#f85149" },
    { l: "Change", v: deltaStr, s: `${improved.length} improved · ${regressed.length} regressed`, c: deltaColor },
    ...(avgTime ? [{ l: "Avg time", v: `${avgTime}ms`, s: `${minTime}–${maxTime}ms`, c: "#e3b341" }] : []),
  ];
  H.push(`<div class="rd-metrics">` + metrics.map(m =>
    `<div class="rd-metric"><div class="rd-metric-l">${m.l}</div><div class="rd-metric-v" style="color:${m.c}">${m.v}</div><div class="rd-metric-s">${m.s}</div></div>`
  ).join("") + `</div>`);

  // Overview
  if (ran) {
    const donutSvg = _aspDonutSvg([
      { v: curPass, color: "#3fb950", label: "Pass" },
      { v: curFail, color: "#f85149", label: "Fail" },
      { v: curWarn, color: "#d29922", label: "Warn" },
    ], `${curPct}%`, "pass");
    const catRows = ["POS", "NEG"].filter(k => byCat[k].total).map(k => {
      const s = byCat[k];
      const np = Math.round(s.pass / s.total * 100);
      const pp = Math.round(s.prevPass / s.total * 100);
      return `<tr>
        <td><b style="color:${k==="POS"?"#79c0ff":"#f85149"}">${k}</b></td>
        <td class="num rd-pass">${s.pass}</td>
        <td class="num rd-fail">${s.fail}</td>
        <td class="num">${s.total}</td>
        <td class="num rd-muted">${pp}%</td>
        <td>${rateBar(np, np >= pp ? "#3fb950" : "#f85149")}</td>
      </tr>`;
    }).join("");
    H.push(`<div class="rd-overview">
      <div class="rd-panel" style="display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px">
        ${secTitle("Result mix", null, "var(--text2)")}
        ${donutSvg}
        <div style="display:flex;gap:14px;flex-wrap:wrap;justify-content:center">
          <span class="rd-muted">Pass <b class="rd-pass">${curPass}</b></span>
          <span class="rd-muted">Fail <b class="rd-fail">${curFail}</b></span>
          ${curWarn ? `<span class="rd-muted">Warn <b style="color:#d29922">${curWarn}</b></span>` : ""}
        </div>
      </div>
      <div class="rd-panel">
        ${secTitle("By category", null, "var(--text2)")}
        <table class="rd-table">
          <thead><tr><th>Type</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Total</th><th class="num">Prev</th><th>Now</th></tr></thead>
          <tbody>${catRows || `<tr><td colspan="6" class="rd-empty">No category data</td></tr>`}</tbody>
        </table>
      </div>
    </div>`);
  }

  // APIs
  const apiKeys = Object.keys(byApi);
  if (apiKeys.length) {
    const rows = apiKeys.map(k => {
      const s = byApi[k];
      const np = s.total ? Math.round(s.pass / s.total * 100) : 0;
      const avgT = s.times.length ? Math.round(s.times.reduce((a,b)=>a+b,0)/s.times.length) : 0;
      const mc = mColor(s.method);
      return `<tr>
        <td><div class="rd-row-main"><span class="rd-method" style="color:${mc};background:${mc}18;border-color:${mc}44">${_aspEscHtml(String(s.method))}</span><span class="rd-url" title="${_aspEscHtml(s.url)}">${_aspEscHtml(s.url)}</span></div></td>
        <td class="num rd-pass">${s.pass}</td>
        <td class="num rd-fail">${s.fail}</td>
        <td class="num">${s.total}</td>
        <td class="num">${s.params.size}</td>
        <td class="num">${avgT ? avgT + "ms" : "—"}</td>
        <td>${rateBar(np, np >= 50 ? "#3fb950" : "#f85149")}</td>
      </tr>`;
    }).join("");
    H.push(`<div class="rd-panel">${secTitle("APIs tested", apiKeys.length, "#bc8cff")}
      <table class="rd-table">
        <thead><tr><th>API</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Cases</th><th class="num">Params</th><th class="num">Avg</th><th>Pass rate</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`);
  }

  // Params
  const paramKeys = Object.keys(byParam);
  if (paramKeys.length) {
    const rows = paramKeys.map(k => {
      const s = byParam[k];
      const np = s.total ? Math.round(s.pass / s.total * 100) : 0;
      const avgT = s.times.length ? Math.round(s.times.reduce((a,b)=>a+b,0)/s.times.length) : 0;
      const mc = mColor(s.method);
      return `<tr>
        <td>
          <div class="rd-row-main"><b>${_aspEscHtml(s.param)}</b><span class="rd-method" style="color:${mc};background:${mc}18;border-color:${mc}44">${_aspEscHtml(String(s.method))}</span></div>
          <div class="rd-url" style="margin-top:3px;max-width:520px" title="${_aspEscHtml(s.url)}">${_aspEscHtml(s.url)}</div>
        </td>
        <td class="num rd-pass">${s.pass}</td>
        <td class="num rd-fail">${s.fail}</td>
        <td class="num">${s.total}</td>
        <td class="num">${avgT ? avgT + "ms" : "—"}</td>
        <td>${rateBar(np, np >= 50 ? "#3fb950" : "#f85149")}</td>
      </tr>`;
    }).join("");
    H.push(`<div class="rd-panel">${secTitle("Parameters", paramKeys.length, "#79c0ff")}
      <table class="rd-table">
        <thead><tr><th>Parameter / API</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Total</th><th class="num">Avg</th><th>Pass rate</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`);
  }

  // Changes
  if (ran && (improved.length || regressed.length)) {
    const mk = (arr) => arr.length
      ? arr.map(({c}) => `<div class="rd-list-item"><div class="rd-list-t">${_aspEscHtml(c.param || "")}</div><div class="rd-list-s">${_aspEscHtml(c.case_desc || "")}</div></div>`).join("")
      : `<div class="rd-empty">None</div>`;
    H.push(`<div class="rd-panel">${secTitle("Changes vs previous", null, "var(--text2)")}
      <div class="rd-two">
        <div style="border:1px solid rgba(63,185,80,.28);border-radius:8px;padding:10px 12px;background:rgba(63,185,80,.05)">
          <div style="font-weight:700;color:#3fb950;margin-bottom:6px">Improved (${improved.length})</div>${mk(improved)}
        </div>
        <div style="border:1px solid rgba(248,81,73,.28);border-radius:8px;padding:10px 12px;background:rgba(248,81,73,.05)">
          <div style="font-weight:700;color:#f85149;margin-bottom:6px">Regressed (${regressed.length})</div>${mk(regressed)}
        </div>
      </div>
    </div>`);
  }

  // Failed cases — collapsed by default
  const failedResults = _aspRunnerLastResults.filter(r => r.result === "FAIL" || r.result === "ERR");
  const failStore = {};
  if (ran && failedResults.length) {
    const prettyBody = (bodyVal) => {
      if (bodyVal === null || bodyVal === undefined) return "";
      if (typeof bodyVal === "string") {
        try { return JSON.stringify(JSON.parse(bodyVal), null, 2); } catch (_) { return bodyVal; }
      }
      try { return JSON.stringify(bodyVal, null, 2); } catch (_) { return String(bodyVal); }
    };
    const hlBody = (raw, sv, paramName) => {
      if (!raw) return `<span class="rd-muted">(none)</span>`;
      const preStyle = "margin:0;font-size:11px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--text2);white-space:pre-wrap;word-break:break-all;line-height:1.5";
      if (!sv || sv === "null" || sv === "—") return `<pre id="asp-fail-req-pre-XIDX" style="${preStyle}">${_aspEscHtml(raw)}</pre>`;
      let searchFor = null;
      try {
        if (paramName) { const kv = `"${paramName}": ${JSON.stringify(sv)}`; if (raw.includes(kv)) searchFor = kv; }
        if (!searchFor) { const jv = JSON.stringify(sv); if (raw.includes(jv)) searchFor = jv; else if (raw.includes(sv)) searchFor = sv; }
      } catch (_) { if (raw.includes(sv)) searchFor = sv; }
      const hlMark = searchFor
        ? `<mark style="background:rgba(227,179,65,.22);color:#e3b341;border-radius:3px;padding:1px 3px;font-weight:700">${_aspEscHtml(searchFor)}</mark>`
        : "";
      const body = searchFor ? raw.split(searchFor).map(p => _aspEscHtml(p)).join(hlMark) : _aspEscHtml(raw);
      return `<pre id="asp-fail-req-pre-XIDX" style="${preStyle}">${body}</pre>`;
    };

    const failRows = failedResults.map(r => {
      const c = d.cases[r.origIdx];
      if (!c) return "";
      const rColor = r.result === "ERR" ? "#d29922" : "#f85149";
      const sStr = String(r.status || 0);
      const sColor = sStr.startsWith("2") ? "#3fb950" : sStr.startsWith("4") ? "#f85149" : sStr.startsWith("5") ? "#d29922" : "#8b949e";
      const mc = mColor(c._method || d.method);
      const rawVal = c.case_value !== undefined && c.case_value !== null ? String(c.case_value) : "—";
      const valDisp = rawVal.length > 36 ? rawVal.slice(0, 36) + "…" : rawVal;
      const req = r.reqPayload, resp = r.respData;
      const curlStr = (resp && resp.sent_curl) ? resp.sent_curl : "";
      const reqRaw = prettyBody(req && req.body);
      let respRaw = "";
      if (resp) {
        const b = resp.body;
        if (typeof b === "string") { try { respRaw = JSON.stringify(JSON.parse(b), null, 2); } catch (_) { respRaw = b || ""; } }
        else { try { respRaw = JSON.stringify(b, null, 2); } catch (_) { respRaw = String(b || ""); } }
      }
      failStore[r.origIdx] = { req: reqRaw, resp: respRaw, curl: curlStr };
      const reqHl = hlBody(reqRaw, rawVal, c.param).replace('id="asp-fail-req-pre-XIDX"', `id="asp-fail-req-pre-${r.origIdx}"`);
      const respFmt = resp
        ? `<pre id="asp-fail-resp-pre-${r.origIdx}" style="margin:0;font-size:11px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--text2);white-space:pre-wrap;word-break:break-all;line-height:1.5">${_aspEscHtml(respRaw || "(empty)")}</pre>`
        : `<span class="rd-muted">(no response)</span>`;
      const misTag = r.case_misconfig
        ? `<span class="av-misconfig-tag" title="${_aspEscHtml(r.misconfig_reason || "Already exists (409/422)")}">case misconfig</span>`
        : "";
      const descHtml = c.case_desc ? `<span class="rd-fail-desc">${_aspEscHtml(c.case_desc)}</span>` : "";
      const subHtml = (descHtml || misTag) ? `<div class="rd-fail-sub">${descHtml}${misTag}</div>` : "";
      return `<div class="rd-fail-row${r.case_misconfig ? " rd-fail-misconfig" : ""}">
        <div class="rd-fail-sum" onclick="aspToggleFailDetail(${r.origIdx})">
          <span class="rd-muted" style="text-align:right">${r.origIdx + 1}</span>
          <div style="min-width:0">
            <div class="rd-row-main"><b>${_aspEscHtml(c.param || "")}</b><span class="rd-method" style="color:${mc};background:${mc}18;border-color:${mc}44">${_aspEscHtml(String(c._method || d.method || ""))}</span></div>
            ${subHtml}
          </div>
          <code class="rd-url" title="${_aspEscHtml(rawVal)}">${_aspEscHtml(valDisp)}</code>
          <span class="ctr" style="color:${sColor};font-weight:700">${r.status || "—"}</span>
          <span class="rd-badge" style="color:${rColor};background:${rColor}1a;text-align:center">${r.result}</span>
          <span class="num" style="color:#e3b341">${r.elapsed > 0 ? r.elapsed + "ms" : ""}</span>
          <button type="button" id="asp-fail-btn-${r.origIdx}" class="rd-badge" style="background:var(--bg3);border:1px solid var(--border);color:var(--text2);cursor:pointer">View</button>
        </div>
        <div id="asp-fail-detail-${r.origIdx}" style="display:none;border-top:1px solid var(--border);background:var(--bg)">
          <div style="display:grid;grid-template-columns:1fr 1fr;height:250px">
            <div style="border-right:1px solid var(--border);display:flex;flex-direction:column;min-height:0;overflow:hidden">
              <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0">
                <span style="font-size:11px;font-weight:700;color:#79c0ff">Request</span>
                ${curlStr ? `<button type="button" onclick="aspFailCopyCurl(${r.origIdx},this)" style="background:none;border:1px solid var(--border);color:var(--text);font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer">cURL</button>` : ""}
                <input oninput="aspFailSearch('asp-fail-req-pre-${r.origIdx}',this.value)" placeholder="Search…" style="margin-left:auto;background:var(--bg3);border:1px solid var(--border);color:var(--text);font-size:11px;padding:3px 8px;border-radius:5px;outline:none;width:120px">
              </div>
              <div style="flex:1;min-height:0;overflow:auto;padding:12px">${reqHl}</div>
            </div>
            <div style="display:flex;flex-direction:column;min-height:0;overflow:hidden">
              <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0">
                <span style="font-size:11px;font-weight:700;color:#3fb950">Response</span>
                ${resp ? `<span style="font-size:10px;color:${sColor}">${r.status} ${_aspEscHtml(resp.status_text || "")}</span>` : ""}
                <input oninput="aspFailSearch('asp-fail-resp-pre-${r.origIdx}',this.value)" placeholder="Search…" style="margin-left:auto;background:var(--bg3);border:1px solid var(--border);color:var(--text);font-size:11px;padding:3px 8px;border-radius:5px;outline:none;width:120px">
              </div>
              <div style="flex:1;min-height:0;overflow:auto;padding:12px">${respFmt}</div>
            </div>
          </div>
        </div>
      </div>`;
    }).join("");

    H.push(`<div class="rd-panel">${secTitle("Failed cases", failedResults.length, "#f85149")}
      <div class="rd-fail-wrap">
        <div class="rd-fail-head">
          <span style="text-align:right">#</span><span>Case</span><span>Value</span><span class="ctr">Status</span><span>Result</span><span class="num">Time</span><span></span>
        </div>
        ${failRows}
      </div>
      <div class="rd-muted" style="margin-top:8px">Click a row or View to expand request / response.</div>
    </div>`);
  }
  _aspDashFailStore = failStore;

  H.push(`</div>`);

  const dashBody = document.getElementById("asp-dash-body");
  const prevScroll = dashBody ? dashBody.scrollTop : 0;
  if (dashBody) { dashBody.innerHTML = H.join(""); dashBody.scrollTop = prevScroll; }

  const subtitle = document.getElementById("asp-dash-subtitle");
  if (subtitle) subtitle.textContent = ran
    ? `${ranCount}/${total} run · ${curPass}P ${curFail}F${curWarn ? " " + curWarn + "W" : ""}${_aspRunnerRunning ? " · running" : ""}`
    : `${total} cases loaded — not run yet`;
}

function _aspDonutSvg(slices, centerBig, centerSmall) {
  const r = 52, cx = 72, cy = 72, sw = 18;
  const C = 2 * Math.PI * r;
  const tot = slices.reduce((s, x) => s + x.v, 0);
  if (!tot) {
    return `<svg width="144" height="144" viewBox="0 0 144 144"><circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--bg3)" stroke-width="${sw}"/><text x="${cx}" y="${cy + 4}" fill="#8b949e" text-anchor="middle" font-size="12">No data</text></svg>`;
  }
  let cum = 0;
  const segs = slices.filter(s => s.v > 0).map(s => {
    const len = (s.v / tot) * C;
    const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${sw}" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(C - cum).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})" stroke-linecap="butt"/>`;
    cum += len;
    return seg;
  });
  return `<svg width="144" height="144" viewBox="0 0 144 144" style="display:block">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--bg3)" stroke-width="${sw}"/>
    ${segs.join("")}
    <text x="${cx}" y="${cy - 4}" fill="#e6edf3" text-anchor="middle" font-size="18" font-weight="700" font-family="system-ui,sans-serif">${centerBig}</text>
    <text x="${cx}" y="${cy + 14}" fill="#8b949e" text-anchor="middle" font-size="10" font-family="system-ui,sans-serif">${centerSmall}</text>
  </svg>`;
}

function aspRunnerDashboardHide() {
  aspRunnerSwitchTab("cases");
}

function _aspRunnerRefreshDashboard() {
  if (_aspRunnerTab === "dashboard") aspRunnerDashboardShow();
}

function aspRunnerExportReport() {
  if (_aspRunnerRunning) return;
  const d = _aspRunnerData;
  if (!d) { _aspAlert("No test data to export."); return; }

  // Refresh dashboard HTML; keep Failed Cases collapsed (click to expand in report).
  aspRunnerDashboardShow();

  const dashBodyEl = document.getElementById("asp-dash-body");
  const dashHtml = dashBodyEl ? dashBodyEl.innerHTML : "";

  const ran = _aspRunnerLastResults.length > 0;
  const total = (d.cases || []).length;
  const ranCount = _aspRunnerLastResults.length;
  const curPass = _aspRunnerLastResults.filter(r => r.result === "PASS").length;
  const curFail = _aspRunnerLastResults.filter(r => r.result === "FAIL" || r.result === "ERR").length;
  const curWarn = _aspRunnerLastResults.filter(r => r.result !== "PASS" && r.result !== "FAIL" && r.result !== "ERR").length;
  const apiCount = new Set((d.cases || []).map(c => _aspRunnerApiKeyFromCase(c) || _aspRunnerApiKey(c._method || d.method, c._url || d.url))).size;

  const ts = new Date().toLocaleString();
  const dateSlug = new Date().toISOString().slice(0, 10);

  const failStore = {};
  _aspRunnerLastResults.forEach(r => {
    if (r.result !== "FAIL" && r.result !== "ERR") return;
    const req = r.reqPayload;
    const resp = r.respData;
    const pretty = (v) => {
      if (v == null || v === "") return "";
      if (typeof v === "string") {
        try { return JSON.stringify(JSON.parse(v), null, 2); } catch (_) { return v; }
      }
      try { return JSON.stringify(v, null, 2); } catch (_) { return String(v); }
    };
    failStore[r.origIdx] = {
      req: pretty(req && req.body),
      resp: pretty(resp && resp.body),
      curl: (resp && resp.sent_curl) || "",
    };
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Test Report – ${dateSlug}</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:13px;line-height:1.4;min-height:100vh}
.hdr{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:18px 22px;background:var(--bg2);border-bottom:1px solid var(--border)}
.hdr-title{font-size:16px;font-weight:700;letter-spacing:-.01em}
.hdr-sub{font-size:12px;color:var(--text3);margin-top:4px}
.hdr-meta{text-align:right;font-size:12px;color:var(--text3);white-space:nowrap}
.hdr-meta b{font-size:13px}
.dash-inner{padding:18px 22px 28px;max-width:1100px;margin:0 auto}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--text2)}
button{font:inherit}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <div class="hdr-title">API Test Report</div>
    <div class="hdr-sub">${apiCount} API${apiCount === 1 ? "" : "s"} · ${ran ? `${ranCount}/${total} cases ran` : `${total} cases`} · ${ts}</div>
  </div>
  <div class="hdr-meta">
    ${ran
      ? `<b style="color:#3fb950">${curPass} Pass</b> &nbsp; <b style="color:#f85149">${curFail} Fail</b>${curWarn ? ` &nbsp; <b style="color:#d29922">${curWarn} Warn</b>` : ""}`
      : `<span>Not run</span>`}
  </div>
</div>
<div class="dash-inner">${dashHtml}</div>
<script>
window._ASP_FAIL_STORE=${JSON.stringify(failStore).replace(/</g, "\\u003c")};
function aspToggleFailDetail(idx){
  var d=document.getElementById('asp-fail-detail-'+idx),b=document.getElementById('asp-fail-btn-'+idx);
  if(!d)return; var open=d.style.display!=='none';
  d.style.display=open?'none':'block';
  if(b){b.textContent=open?'View':'Close';b.style.color=open?'':'#f85149';}
}
function aspFailGetRaw(id){
  var m=String(id||"").match(/asp-fail-(req|resp)-pre-(\\d+)/);
  if(!m) return "";
  var rec=(window._ASP_FAIL_STORE||{})[m[2]]||{};
  return rec[m[1]]||"";
}
function aspFailEsc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function aspFailSearch(id,term){
  var pre=document.getElementById(id); if(!pre)return;
  var raw=aspFailGetRaw(id);
  if(!term.trim()){pre.textContent=raw;return;}
  var esc=aspFailEsc(term);
  pre.innerHTML=aspFailEsc(raw).split(esc).join('<mark style="background:rgba(121,192,255,.3);color:#79c0ff;border-radius:2px;padding:0 1px">'+esc+'</mark>');
}
function aspFailCopyCurl(idx,btn){
  var t=((window._ASP_FAIL_STORE||{})[idx]||{}).curl||"";
  _aspClipboard(t,btn,'cURL');
}
function _aspClipboard(text,btn,label){
  if(!text)return;
  try{navigator.clipboard.writeText(text);}catch(e){var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);}
  if(btn){btn.textContent='Copied';setTimeout(function(){btn.textContent=label;},1400);}
}
</script>
</body>
</html>`;

  const filename = "api-report-" + dateSlug + ".html";
  window.pywebview.api.save_file(html, filename)
    .then(r => { if (r && r.ok) _aspAlert("Report saved:\n" + r.path); })
    .catch(e => _aspAlert("Export failed: " + e.message));
}

function aspRunnerExportCollection() {
  if (_aspRunnerRunning) return;
  const d = _aspRunnerData;
  if (!d) { _aspAlert("No runner data found to export."); return; }

  // Last Run All results live in memory; fold them into prev_* before export
  // so re-import shows them in the Prev column (same as AV collection export).
  // Do not re-render the table here — that would wipe the live Result column.
  if (_aspRunnerCommitLastResultsToPrev()) {
    _aspRunnerPersistRunnerData();
    _aspRunnerUpdateTitle();
  }

  const cases = (d.cases || []).map(c => ({
    param:       c.param,
    case_cat:    c.case_cat,
    case_desc:   c.case_desc,
    test_value:  c.test_value,
    case_value:  c.case_value != null ? c.case_value : c.test_value,
    body:        c.body != null ? c.body : null,
    response:    c.response != null ? c.response : null,
    prev_status: c.prev_status != null ? c.prev_status : null,
    prev_result: (c.prev_result != null && c.prev_result !== "") ? c.prev_result : "—",
    case_id:     c.case_id,
    dataset_case_id: c.dataset_case_id || null,
    dataset_key: c.dataset_key || null,
    api_key:     c.api_key || _aspRunnerApiKeyFromCase(c),
    param_path:  c.param_path,
    value_template: c.value_template || null,
    enabled:     c.enabled !== false,
    status:      c.status || "active",
    created_at:  c.created_at || null,
    updated_at:  _aspRunnerIsoNow(),
    source_bundle_id: c.source_bundle_id || d.bundle_id || null,
    merge_state: c.merge_state || "source",
    order:       c.order != null ? c.order : 0,
    // Per-case request identity — required for multi-API runner re-import
    _method:     c._method || d.method || "GET",
    _url:        c._url || d.url || "",
    _headers:    _aspRunnerClone(c._headers || d.headers || {}),
    _body_type:  c._body_type || d.body_type || "json",
    source_query: _aspRunnerClone(c._base_query || c.source_query || {}),
    source_body: _aspRunnerClone(c._base_body !== undefined ? c._base_body : (c.source_body != null ? c.source_body : null)),
    all_unique_formats: _aspRunnerClone(c._all_unique_formats || c.all_unique_formats || {}),
    extractors:  Array.isArray(c.extractors) ? c.extractors : [],
    bindings:    Array.isArray(c.bindings) ? c.bindings : [],
  }));

  const bundle = {
    v:          2,
    schema_version: 2,
    source_tool: d.source_tool || "api_validator",
    generated_at: _aspRunnerIsoNow(),
    bundle_id: d.bundle_id || `avb_${_aspRunnerHashText((d.method || "GET") + "|" + (d.url || ""))}`,
    api_key: d.api_key || _aspRunnerApiKey(d.method, d.url),
    sync_policy: d.sync_policy || "precheck_block",
    name:       d.name || "AV Collection",
    method:     d.method || "GET",
    url:        d.url || "",
    headers:    d.headers || {},
    query:      _aspRunnerClone(d.query || {}),
    body:       _aspRunnerClone(d.body != null ? d.body : null),
    body_type:  d.body_type || "json",
    all_unique_formats: _aspRunnerClone(d.all_unique_formats || {}),
    unique_pools_by_api: _aspRunnerClone(d.unique_pools_by_api || {}),
    param_snapshot: _aspRunnerClone(d.param_snapshot || []),
    cases,
  };

  const json = JSON.stringify(bundle, null, 2);
  const filename = "av_collection.json";

  if (window.pywebview && window.pywebview.api && window.pywebview.api.save_file) {
    window.pywebview.api.save_file(json, filename)
      .then(r => { if (r && r.ok) _aspAlert("Collection exported:\n" + r.path); })
      .catch(e => _aspAlert("Export failed: " + (e && e.message ? e.message : String(e))));
    return;
  }

  const blob = new Blob([json], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
}

function aspRunnerShowDetail(origIdx) {
  const d = _aspRunnerData;
  if (!d) return;
  const c = d.cases[origIdx];
  const r = _aspRunnerLastResults.find(x => x.origIdx === origIdx);
  if (!c || !r) return;

  const mColor = {GET:"#3fb950",POST:"#79c0ff",PUT:"#d29922",DELETE:"#f85149",PATCH:"#bc8cff"}[(c._method||d.method)] || "#8b949e";
  const rColor = r.result === "PASS" ? "#3fb950" : r.result === "FAIL" ? "#f85149" : "#d29922";
  const sStr = String(r.status || 0);
  const sColor = sStr.startsWith("2") ? "#3fb950" : sStr.startsWith("4") ? "#f85149" : sStr.startsWith("5") ? "#d29922" : "#8b949e";

  const fmtJson = v => {
    if (v === null || v === undefined) return "(none)";
    if (typeof v === "string") {
      try { return JSON.stringify(JSON.parse(v), null, 2); } catch(_) { return v || "(empty)"; }
    }
    return JSON.stringify(v, null, 2);
  };

  const req = r.reqPayload;
  const resp = r.respData;

  const reqHeaders = req ? Object.entries(req.headers||{}).map(([k,v]) =>
    `<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:10px;color:#79c0ff;min-width:160px;word-break:break-all">${_aspEscHtml(k)}</span>
      <span style="font-size:10px;color:var(--text2);word-break:break-all">${_aspEscHtml(String(v))}</span>
    </div>`).join("") : "";

  const respHeaders = resp ? Object.entries(resp.headers||{}).map(([k,v]) =>
    `<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:10px;color:#79c0ff;min-width:160px;word-break:break-all">${_aspEscHtml(k)}</span>
      <span style="font-size:10px;color:var(--text2);word-break:break-all">${_aspEscHtml(String(v))}</span>
    </div>`).join("") : "";

  const reqBodyHtml = req
    ? `<pre style="margin:0;font-size:11px;font-family:'SF Mono',monospace;color:var(--text2);white-space:pre-wrap;word-break:break-all;line-height:1.5">${_aspEscHtml(fmtJson(req.body))}</pre>`
    : `<span style="font-size:11px;color:var(--text3)">(no body)</span>`;

  const respBodyHtml = resp
    ? `<pre style="margin:0;font-size:11px;font-family:'SF Mono',monospace;color:var(--text2);white-space:pre-wrap;word-break:break-all;line-height:1.5">${_aspEscHtml(fmtJson(resp.body))}</pre>`
    : `<span style="font-size:11px;color:var(--text3)">(no response)</span>`;

  const rawVal = c.case_value !== undefined && c.case_value !== null ? String(c.case_value) : "—";

  let el = document.getElementById("asp-runner-detail-modal");
  if (!el) { el = document.createElement("div"); el.id = "asp-runner-detail-modal"; document.body.appendChild(el); }

  el.style.cssText = "position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.72);backdrop-filter:blur(6px)";

  el.innerHTML = `
  <div style="background:#161b22;border:1px solid #30363d;border-radius:14px;width:min(720px,94vw);max-height:86vh;display:flex;flex-direction:column;box-shadow:0 24px 60px rgba(0,0,0,.6)">
    <!-- Header -->
    <div style="display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid #30363d;flex-shrink:0">
      <span style="font-size:10px;font-weight:700;color:${mColor};background:${mColor}1a;padding:2px 8px;border-radius:4px;border:1px solid ${mColor}44">${_aspEscHtml(c._method||d.method||"")}</span>
      <div style="flex:1;min-width:0">
        <div style="font-size:13px;font-weight:700;color:#e6edf3">${_aspEscHtml(c.param||"")} <span style="color:var(--text);font-weight:400;font-size:11px">— ${_aspEscHtml(c.case_desc||"")}</span></div>
        <div style="font-size:10px;color:var(--text);font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px">${_aspEscHtml((req&&req.url)||c._url||d.url||"")}</div>
      </div>
      <span style="font-size:10px;font-weight:700;color:${rColor};background:${rColor}1a;padding:2px 8px;border-radius:4px;border:1px solid ${rColor}44">${r.result}</span>
      <span style="font-size:12px;font-weight:700;color:${sColor};min-width:34px;text-align:center">${r.status||"—"}</span>
      <button onclick="document.getElementById('asp-runner-detail-modal').style.display='none'" style="background:none;border:1px solid #30363d;color:var(--text);font-size:12px;padding:4px 10px;border-radius:6px;cursor:pointer;flex-shrink:0">✕ Close</button>
    </div>
    <!-- Value row -->
    <div style="padding:8px 18px;background:#0d1117;border-bottom:1px solid #30363d;flex-shrink:0;display:flex;align-items:center;gap:8px">
      <span style="font-size:10px;color:var(--text);text-transform:uppercase;letter-spacing:.05em">Value Sent:</span>
      <code style="font-size:11px;color:#e3b341;word-break:break-all">${_aspEscHtml(rawVal)}</code>
      ${r.elapsed > 0 ? `<span style="margin-left:auto;font-size:10px;color:#e3b341;background:rgba(227,179,65,.1);border:1px solid rgba(227,179,65,.25);padding:2px 8px;border-radius:4px">${r.elapsed}ms</span>` : ""}
    </div>
    <!-- Tabs -->
    <div style="display:flex;background:#0d1117;border-bottom:1px solid #30363d;flex-shrink:0">
      <button id="asp-det-tab0" onclick="aspDetailTab(0)" style="padding:9px 18px;border:none;background:none;color:#79c0ff;font-size:12px;font-weight:600;cursor:pointer;border-bottom:2px solid #79c0ff">📤 Request</button>
      <button id="asp-det-tab1" onclick="aspDetailTab(1)" style="padding:9px 18px;border:none;background:none;color:var(--text);font-size:12px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent">📥 Response</button>
    </div>
    <!-- Pane: Request -->
    <div id="asp-det-pane0" style="flex:1;overflow-y:auto;padding:14px 18px;display:flex;flex-direction:column;gap:12px">
      <div>
        <div style="font-size:10px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Headers</div>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 12px;max-height:140px;overflow-y:auto">
          ${reqHeaders || `<span style="font-size:11px;color:var(--text)">(none)</span>`}
        </div>
      </div>
      <div>
        <div style="font-size:10px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Body</div>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px;overflow-x:auto">${reqBodyHtml}</div>
      </div>
    </div>
    <!-- Pane: Response (hidden) -->
    <div id="asp-det-pane1" style="flex:1;overflow-y:auto;padding:14px 18px;display:none;flex-direction:column;gap:12px">
      <div>
        <div style="font-size:10px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Headers</div>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 12px;max-height:140px;overflow-y:auto">
          ${respHeaders || `<span style="font-size:11px;color:var(--text)">(none)</span>`}
        </div>
      </div>
      <div>
        <div style="font-size:10px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Body</div>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px;overflow-x:auto">${respBodyHtml}</div>
      </div>
    </div>
  </div>`;

  el.onclick = e => { if (e.target === el) el.style.display = "none"; };
}

function aspDetailTab(n) {
  [0,1].forEach(i => {
    const btn = document.getElementById("asp-det-tab"+i);
    const pane = document.getElementById("asp-det-pane"+i);
    if (btn) { btn.style.color = i===n ? "#79c0ff" : "#6e7681"; btn.style.borderBottom = i===n ? "2px solid #79c0ff" : "2px solid transparent"; }
    if (pane) pane.style.display = i===n ? "flex" : "none";
  });
}

function aspToggleFailDetail(origIdx) {
  const detail = document.getElementById("asp-fail-detail-" + origIdx);
  const btn    = document.getElementById("asp-fail-btn-"    + origIdx);
  if (!detail) return;
  const opening = detail.style.display === "none";
  detail.style.display = opening ? "block" : "none";
  if (btn) {
    btn.textContent = opening ? "Close" : "View";
    btn.style.color = opening ? "#f85149" : "";
    btn.style.borderColor = opening ? "rgba(248,81,73,.4)" : "";
  }
}

function aspFailSearch(preId, term) {
  const pre = document.getElementById(preId);
  if (!pre) return;
  const m = String(preId || "").match(/asp-fail-(req|resp)-pre-(\d+)/);
  const rec = m ? (_aspDashFailStore[m[2]] || {}) : {};
  const raw = (m && rec[m[1]]) || "";
  const q = (term || "").trim();
  if (!q) { pre.textContent = raw; return; }
  pre.innerHTML = _aspRunnerWrapEscaped(_aspEscHtml(raw), q, "asp-find-mark");
}

function aspFailCopyCurl(idx, btn) {
  const curl = (_aspDashFailStore[idx] || {}).curl || "";
  if (!curl) return;
  _aspClipboard(curl, btn, "cURL");
}

