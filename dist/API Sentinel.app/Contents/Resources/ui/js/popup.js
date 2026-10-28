// popup.js — API Validator Pro
// Main UI controller

const BACKEND = "http://127.0.0.1:8765";

// Ids hidden by this tool's own Reset button. The capture buffer itself is
// shared with Auth Validator Pro (same backend), so Reset can't delete these
// requests there — it just stops showing them in THIS tool going forward.
let _avDismissedIds = new Set();

// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  capturing: false,
  requests: [],
  filteredRequests: null,  // null = no filter; [] = filter with 0 results
  selectedRequest: null,
  analyzedData: null,
  currentParams: [],
  paramDatasets: {},
  paramUnique: {},
  paramUniquePool: {},  // path → { values, filename, header }
  paramChecked: {},
  caseSelections: {},       // {paramPath: {case_id:"POS"|"NEG"}} — user business overrides
  customCases: {},          // {paramPath: [{id,value,cat}]} — extra user-defined test values
  allDatasets: {},
  testResults: null,
  activeFilter: "ALL",
  paramsSearchQuery: "",    // Patch 3: params search
  savedApiConfigs: {},      // Persisted parameters & business cases per API
  selectedRequestIds: new Set(), // Multi-select captured APIs for bulk run
};

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  try {
    localStorage.removeItem("av_saved_api_configs_v1");
  } catch(e) {}
  state.savedApiConfigs = {};
  await checkBackend();
  await loadRequests();
  await loadDatasets();
  // Wrap each setup in try-catch so one error doesn't kill rest
  [
    setupTabs, setupCaptureControls, setupFilters, setupActions,
    setupModal, setupImport, setupDetailsEdit, setupQueryEdit, setupParamsSearch, setupAvMessageModal, setupBulkRunModal
  ].forEach(fn => { try { fn(); } catch(e) { console.error(fn.name, e); } });
  // Mac App: Always poll for new requests (user may switch from HAR Runner which captured requests)
  setInterval(async () => {
    await loadRequests();
  }, 2000);

  // Expose showExportToast globally so HAR runner can also use it
  window.showExportToast = showExportToast;

  // Window close button — pywebview compatible
  const closeBtn = $("btn-close-panel");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      try {
        if (window.pywebview && window.pywebview.api) {
          // pywebview JS API
          window.pywebview.api.close_window && window.pywebview.api.close_window();
        } else {
          window.close();
        }
      } catch(e) { window.close(); }
    });
  }
});

// ── Configuration Persistence & Helpers ──────────────────────────────────────
function showAvMessage(title, text) {
  const modal = $("av-msg-modal");
  if (!modal) {
    alert((title ? title + "\n\n" : "") + (text || ""));
    return;
  }
  const t = $("av-msg-modal-title");
  const b = $("av-msg-modal-text");
  if (t) t.textContent = title || "Notice";
  if (b) {
    b.style.whiteSpace = "pre-line";
    b.textContent = text || "";
  }
  modal.style.display = "block";
}

function extractPoolMetadata(pool) {
  if (!pool || typeof pool !== "object") return null;
  const meta = {};
  Object.entries(pool).forEach(([p, rec]) => {
    if (!rec) return;
    const filename = rec.filename || (typeof rec === "string" ? rec : "");
    const header = rec.header || p;
    const hasData = (Array.isArray(rec.all_values) && rec.all_values.length > 0) ||
                    (Array.isArray(rec.values) && rec.values.length > 0) ||
                    rec.requires_file;
    if (filename || hasData) {
      meta[p] = {
        filename: filename,
        header: header,
        requires_file: true,
      };
    }
  });
  return Object.keys(meta).length > 0 ? meta : null;
}

function sanitizeExportPool(pool) {
  const result = {};
  Object.entries(pool || {}).forEach(([p, rec]) => {
    if (!rec) return;
    if (Array.isArray(rec)) {
      result[p] = {
        all_values: rec.slice(),
        values: rec.slice(),
        filename: "",
        header: p,
      };
    } else {
      const allVals = Array.isArray(rec.all_values) && rec.all_values.length > 0
        ? rec.all_values.slice()
        : (Array.isArray(rec.values) ? rec.values.slice() : []);
      const curVals = Array.isArray(rec.values) && rec.values.length > 0
        ? rec.values.slice()
        : allVals.slice();
      result[p] = {
        all_values: allVals,
        values: curVals,
        filename: rec.filename || "",
        header: rec.header || p,
        requires_file: !!rec.requires_file,
      };
    }
  });
  return result;
}

function _hashString(s) {
  if (!s) return "0";
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = (((h << 5) + h) + s.charCodeAt(i)) & 0xFFFFFFFF;
  }
  return (h >>> 0).toString(16);
}

function _normalizeUrl(rawUrl) {
  if (!rawUrl) return "";
  try {
    const withoutQuery = rawUrl.split("?")[0].split("#")[0].trim();
    const parsed = new URL(withoutQuery);
    if (parsed.protocol && parsed.host) {
      const p = parsed.pathname.replace(/\/+$/, "") || "/";
      return `${parsed.protocol}//${parsed.host.toLowerCase()}${p}`;
    }
    return withoutQuery.replace(/\/+$/, "");
  } catch (e) {
    const withoutQuery = rawUrl.split("?")[0].split("#")[0].trim();
    return withoutQuery.replace(/\/+$/, "");
  }
}

function _extractQueryKeys(req) {
  const keys = new Set();
  if (req && req.queryParams && typeof req.queryParams === "object" && !Array.isArray(req.queryParams)) {
    Object.keys(req.queryParams).forEach(k => {
      if (k && typeof k === "string") keys.add(k.trim());
    });
  }
  const rawUrl = req?.url || "";
  if (rawUrl.includes("?")) {
    try {
      const search = rawUrl.split("?")[1]?.split("#")[0] || "";
      const sp = new URLSearchParams(search);
      sp.forEach((_, k) => {
        if (k) keys.add(k.trim());
      });
    } catch (e) {}
  }
  return Array.from(keys).filter(Boolean).sort();
}

function _extractBodyPaths(body, prefix = "", depth = 0) {
  if (depth > 12 || body == null) return [];
  if (typeof body === "string") {
    const trimmed = body.trim();
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        body = JSON.parse(trimmed);
      } catch (e) {
        return [prefix || "_raw"];
      }
    } else if (trimmed.includes("=") && !trimmed.includes("\n") && !trimmed.startsWith("<")) {
      try {
        const sp = new URLSearchParams(trimmed);
        const keys = [];
        sp.forEach((_, k) => {
          if (k) keys.push(prefix ? `${prefix}.${k}` : k);
        });
        if (keys.length > 0) return keys;
      } catch (e) {}
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
    if (body.length === 0) {
      if (prefix) paths.push(prefix);
    } else {
      body.forEach((item, idx) => {
        const subPrefix = prefix ? `${prefix}[${idx}]` : `[${idx}]`;
        if (item && typeof item === "object") {
          paths.push(..._extractBodyPaths(item, subPrefix, depth + 1));
        } else {
          paths.push(subPrefix);
        }
      });
    }
  } else {
    const keys = Object.keys(body);
    if (keys.length === 0) {
      if (prefix) paths.push(prefix);
    } else {
      keys.forEach(k => {
        const subPrefix = prefix ? `${prefix}.${k}` : String(k);
        const v = body[k];
        if (v && typeof v === "object") {
          paths.push(..._extractBodyPaths(v, subPrefix, depth + 1));
        } else {
          paths.push(subPrefix);
        }
      });
    }
  }
  return paths;
}

function _findDiscriminator(body) {
  if (!body) return "";
  let obj = body;
  if (typeof obj === "string") {
    const trimmed = obj.trim();
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        obj = JSON.parse(trimmed);
      } catch (e) {
        return "";
      }
    } else {
      return "";
    }
  }
  if (!obj || typeof obj !== "object") return "";

  if (Array.isArray(obj)) {
    if (obj.length > 0 && typeof obj[0] === "object" && obj[0] !== null) {
      obj = obj[0];
    } else {
      return "";
    }
  }

  const discKeys = [
    "formName", "form_name", "entityType", "entity_type",
    "action", "operationName", "command", "cmd", "type"
  ];

  for (const k of discKeys) {
    if (k in obj && obj[k] !== null && typeof obj[k] !== "object") {
      const val = String(obj[k]).trim();
      if (val) return `${k}=${val}`;
    }
  }

  const entityMap = obj.entityMap;
  if (entityMap && typeof entityMap === "object" && !Array.isArray(entityMap)) {
    for (const k of ["identifier2", "entityType", "identifier1", "identifier3"]) {
      if (k in entityMap && entityMap[k] !== null && typeof entityMap[k] !== "object") {
        const val = String(entityMap[k]).trim();
        if (val) return `entityMap.${k}=${val}`;
      }
    }
  }
  return "";
}

function getApiSignature(req) {
  if (!req) return "";
  const m = (req.method || "GET").toUpperCase().trim();
  const rawUrl = (req.url || "").trim();
  if (!rawUrl) return "";

  const u = _normalizeUrl(rawUrl);
  const qKeys = _extractQueryKeys(req);
  const qSig = qKeys.length > 0 ? `?${qKeys.join("&")}` : "";

  let paths = [];
  const cfg = req.config;
  if (cfg && Array.isArray(cfg.currentParams) && cfg.currentParams.length > 0) {
    paths = cfg.currentParams.map(p => p?.path).filter(Boolean);
  } else if (Array.isArray(req.currentParams) && req.currentParams.length > 0) {
    paths = req.currentParams.map(p => p?.path).filter(Boolean);
  } else if (req.body !== undefined && req.body !== null) {
    paths = _extractBodyPaths(req.body);
  } else if (req.payload !== undefined && req.payload !== null) {
    paths = _extractBodyPaths(req.payload);
  }

  const uniqueSortedPaths = Array.from(new Set(paths.filter(Boolean))).sort();
  const pathsCount = uniqueSortedPaths.length;
  const pathsHash = pathsCount > 0 ? _hashString(uniqueSortedPaths.join(",")) : "";

  const b = req.body !== undefined && req.body !== null ? req.body : req.payload;
  const disc = _findDiscriminator(b);

  if (!qSig && pathsCount === 0 && !disc) {
    return `${m} ${u}`;
  }

  const parts = [`${m} ${u}${qSig}`];
  if (pathsCount > 0) {
    parts.push(`params:${pathsCount}:${pathsHash}`);
  }
  if (disc) {
    parts.push(`disc:${disc}`);
  }
  return parts.join("|");
}

function getApiDifferentiatorLabel(req) {
  if (!req) return "";
  const b = req.body !== undefined && req.body !== null ? req.body : req.payload;
  let obj = b;
  if (typeof obj === "string") {
    const trimmed = obj.trim();
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try { obj = JSON.parse(trimmed); } catch (e) {}
    }
  }
  if (Array.isArray(obj) && obj.length > 0 && typeof obj[0] === "object") {
    obj = obj[0];
  }

  if (obj && typeof obj === "object") {
    if (obj.entityMap && typeof obj.entityMap === "object") {
      const em = obj.entityMap;
      if (em.identifier2) return String(em.identifier2).trim();
      if (em.entityType) return String(em.entityType).trim();
      if (em.identifier1) return String(em.identifier1).trim();
    }
    if (obj.entityType && typeof obj.entityType !== "object") return String(obj.entityType).trim();
    if (obj.entity_type && typeof obj.entity_type !== "object") return String(obj.entity_type).trim();
    if (obj.action && typeof obj.action !== "object") return String(obj.action).trim();
    if (obj.operationName && typeof obj.operationName !== "object") return String(obj.operationName).trim();
    if (obj.operation && typeof obj.operation !== "object") return String(obj.operation).trim();
    if (obj.formName && typeof obj.formName !== "object") {
      const fn = String(obj.formName).trim();
      return fn.length > 12 ? `form: ${fn.slice(0, 8)}…` : `form: ${fn}`;
    }
    if (obj.form_name && typeof obj.form_name !== "object") {
      const fn = String(obj.form_name).trim();
      return fn.length > 12 ? `form: ${fn.slice(0, 8)}…` : `form: ${fn}`;
    }
  }

  let paths = [];
  if (Array.isArray(req.currentParams) && req.currentParams.length > 0) {
    paths = req.currentParams;
  } else if (b) {
    paths = _extractBodyPaths(b);
  }
  if (paths.length > 0) {
    return `${paths.length} params`;
  }
  return "";
}

function getApiConfigKey(req) {
  if (!req) return "";
  return getApiSignature(req);
}

function getSavedApiConfig(req) {
  if (!req) return null;
  const key1 = req.id;
  if (key1 && state.savedApiConfigs[key1]) {
    return state.savedApiConfigs[key1];
  }
  const key2 = getApiSignature(req);
  if (key2 && state.savedApiConfigs[key2]) {
    return state.savedApiConfigs[key2];
  }
  return null;
}

function isConfiguredParamRunnable(cfg, path) {
  if (!cfg) return false;
  const paramChecked = cfg.paramChecked || {};
  const hasExplicitChecked = Object.keys(paramChecked).length > 0;

  if (hasExplicitChecked) {
    return paramChecked[path] === true;
  }

  // Fallback only when paramChecked was never defined/saved
  const caseSelections = cfg.caseSelections || {};
  const customCases = cfg.customCases || {};
  const sel = caseSelections[path];
  if (sel && typeof sel === "object" && Object.values(sel).some(v => v === "POS" || v === "NEG")) return true;
  if (Array.isArray(customCases[path]) && customCases[path].length > 0) return true;
  return false;
}

function hasSavedApiConfig(req) {
  const cfg = getSavedApiConfig(req);
  if (!cfg) return false;
  const paramChecked = cfg.paramChecked || {};
  const hasExplicitChecked = Object.keys(paramChecked).length > 0;
  if (hasExplicitChecked) {
    return Object.values(paramChecked).some(Boolean);
  }
  const hasCases = Object.keys(cfg.caseSelections || {}).length > 0;
  const hasCustom = Object.keys(cfg.customCases || {}).length > 0;
  const hasChecked = Object.values(cfg.paramChecked || {}).some(Boolean);
  const hasUnique = Object.values(cfg.paramUnique || {}).some(Boolean);
  const hasPool = Object.values(cfg.paramUniquePool || {}).some(rec => {
    if (!rec) return false;
    if (rec.requires_file) return true;
    if (Array.isArray(rec)) return rec.length > 0;
    return (Array.isArray(rec.all_values) && rec.all_values.length > 0) || (Array.isArray(rec.values) && rec.values.length > 0);
  });
  return hasCases || hasCustom || hasChecked || hasUnique || hasPool;
}

function reqNeedsTestData(req) {
  if (!req) return false;
  const cfg = getSavedApiConfig(req);
  if (!cfg) return false;
  const pool = (state.selectedRequest && (state.selectedRequest.id === req.id || getApiSignature(state.selectedRequest) === getApiSignature(req)))
    ? (state.paramUniquePool || cfg.paramUniquePool)
    : cfg.paramUniquePool;

  if (!pool || typeof pool !== "object") return false;
  return Object.values(pool).some(rec => {
    if (!rec) return false;
    if (rec.requires_file) return true;
    const hasVals = (Array.isArray(rec.values) && rec.values.length > 0) ||
                    (Array.isArray(rec.all_values) && rec.all_values.length > 0);
    return !hasVals;
  });
}

function countConfiguredCasesForReq(cfg) {
  if (!cfg) return 0;
  let cnt = 0;
  Object.entries(cfg.caseSelections || {}).forEach(([path, selMap]) => {
    if (!isConfiguredParamRunnable(cfg, path)) return;
    cnt += Object.values(selMap || {}).filter(v => v === "POS" || v === "NEG").length;
  });
  Object.entries(cfg.customCases || {}).forEach(([path, cList]) => {
    if (!isConfiguredParamRunnable(cfg, path)) return;
    cnt += (cList || []).length;
  });
  if (cnt === 0 && Object.values(cfg.paramChecked || {}).some(Boolean)) {
    cnt = Object.values(cfg.paramChecked || {}).filter(Boolean).length;
  }
  return cnt;
}

function saveCurrentApiConfig(showToast = false) {
  const req = state.selectedRequest;
  if (!req) return;

  const key1 = req.id;
  const key2 = getApiConfigKey(req);

  const cfg = {
    id: req.id,
    method: req.method,
    url: req.url,
    paramChecked: { ...(state.paramChecked || {}) },
    paramDatasets: { ...(state.paramDatasets || {}) },
    paramUnique: { ...(state.paramUnique || {}) },
    paramUniquePool: JSON.parse(JSON.stringify(state.paramUniquePool || {})),
    caseSelections: { ...(state.caseSelections || {}) },
    customCases: { ...(state.customCases || {}) },
    currentParams: (state.currentParams || []).map(p => ({ ...p })),
    analyzedData: state.analyzedData ? { ...state.analyzedData } : null,
    updatedAt: new Date().toISOString()
  };

  if (key1) state.savedApiConfigs[key1] = cfg;
  if (key2) state.savedApiConfigs[key2] = cfg;

  // Update request list item to show configured badge
  renderRequestList();

  if (showToast) {
    const totalCases = countConfiguredCasesForReq(cfg);
    showConfigToast(`✓ Saved configuration for ${req.method} ${truncate(req.url, 35)} (${totalCases} cases)`);
  }
}

function autoSaveCurrentApiConfig() {
  if (state.selectedRequest && state.currentParams && state.currentParams.length > 0) {
    const hasCases = Object.values(state.caseSelections || {}).some(sel => sel && typeof sel === "object" && Object.values(sel).some(v => v === "POS" || v === "NEG"));
    const hasCustom = Object.values(state.customCases || {}).some(c => Array.isArray(c) && c.length > 0);
    const hasChecked = Object.values(state.paramChecked || {}).some(Boolean);
    const hasUnique = Object.values(state.paramUnique || {}).some(fmt => Boolean(fmt && fmt.trim()));
    const hasPool = Object.values(state.paramUniquePool || {}).some(rec => {
      if (!rec) return false;
      if (rec.requires_file) return true;
      if (Array.isArray(rec)) return rec.length > 0;
      return (Array.isArray(rec.all_values) && rec.all_values.length > 0) || (Array.isArray(rec.values) && rec.values.length > 0);
    });
    const hasAnyConfig = hasCases || hasCustom || hasChecked || hasUnique || hasPool;
    if (hasAnyConfig) {
      saveCurrentApiConfig(false);
    }
  }
}

function loadApiConfigIntoState(req) {
  if (!req) return;
  state.analyzedData  = null;
  state.currentParams = [];
  state.paramDatasets = {};
  state.paramUnique   = {};
  state.paramUniquePool = {};
  state.paramChecked  = {};
  state.caseSelections = {};
  state.customCases    = {};

  const saved = getSavedApiConfig(req);
  if (saved) {
    state.paramChecked = { ...(saved.paramChecked || {}) };
    state.paramDatasets = { ...(saved.paramDatasets || {}) };
    state.paramUnique = { ...(saved.paramUnique || {}) };
    state.paramUniquePool = JSON.parse(JSON.stringify(saved.paramUniquePool || {}));
    state.caseSelections = { ...(saved.caseSelections || {}) };
    state.customCases = { ...(saved.customCases || {}) };
    if (saved.analyzedData && saved.currentParams?.length) {
      state.analyzedData = saved.analyzedData;
      state.currentParams = saved.currentParams;
    }
  }
}

function syncSingleSelection() {
  if (state.selectedRequestIds && state.selectedRequestIds.size === 1) {
    const singleId = Array.from(state.selectedRequestIds)[0];
    const targetReq = (state.requests || []).find(r => r.id === singleId);
    if (targetReq && state.selectedRequest?.id !== targetReq.id) {
      state.selectedRequest = targetReq;
      loadApiConfigIntoState(targetReq);
    }
  } else if (!state.selectedRequestIds || state.selectedRequestIds.size === 0) {
    state.selectedRequest = null;
  }
}

function showAvConfirm(title, message, confirmBtnText = "Confirm", isDanger = false) {
  return new Promise((resolve) => {
    const modal = $("av-confirm-modal");
    if (!modal) {
      const ok = window.confirm(`${title}\n\n${message}`);
      resolve(ok);
      return;
    }
    const titleEl = $("av-confirm-modal-title");
    const textEl = $("av-confirm-modal-text");
    const confirmBtn = $("av-confirm-modal-confirm");
    const cancelBtn = $("av-confirm-modal-cancel");
    const overlay = $("av-confirm-modal-overlay");

    if (titleEl) titleEl.textContent = title || "Confirm Action";
    if (textEl) textEl.textContent = message || "Are you sure?";
    if (confirmBtn) {
      confirmBtn.textContent = confirmBtnText || "Confirm";
      confirmBtn.className = isDanger ? "btn-sm btn-danger" : "btn-sm btn-save";
    }

    modal.style.display = "block";

    function cleanup(result) {
      modal.style.display = "none";
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      overlay.removeEventListener("click", onCancel);
      resolve(result);
    }

    function onConfirm(e) {
      e.preventDefault();
      e.stopPropagation();
      cleanup(true);
    }
    function onCancel(e) {
      e.preventDefault();
      e.stopPropagation();
      cleanup(false);
    }

    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    overlay.addEventListener("click", onCancel);
  });
}

async function resetCurrentApiConfig() {
  const req = state.selectedRequest;
  if (!req) return;

  const urlDisplay = truncate(req.url, 45);
  const ok = await showAvConfirm(
    "Reset API Configuration",
    `Are you sure you want to reset all configured cases and parameter selections for this API?\n\n${req.method} ${urlDisplay}`,
    "Yes, Reset",
    true
  );

  if (!ok) return;

  const key1 = req.id;
  const key2 = getApiConfigKey(req);
  if (key1) delete state.savedApiConfigs[key1];
  if (key2) delete state.savedApiConfigs[key2];

  state.caseSelections = {};
  state.customCases = {};
  state.paramUnique = {};
  state.paramUniquePool = {};
  state.paramChecked = {};
  state.paramDatasets = {};

  (state.currentParams || []).forEach(p => {
    state.paramDatasets[p.path] = p.detected;
    state.paramUnique[p.path] = "";
    state.paramChecked[p.path] = false;
  });

  renderParamsTable();
  updateTestCount();
  renderRequestList();

  showConfigToast(`🔄 Reset configuration for ${req.method} ${urlDisplay}`);
}

async function deleteCapturedRequest(req) {
  if (!req) return;

  const urlDisplay = truncate(req.url, 45);
  const ok = await showAvConfirm(
    "Delete API Request",
    `Are you sure you want to delete this API from the list?\n\n${req.method} ${urlDisplay}`,
    "Yes, Delete",
    true
  );

  if (!ok) return;

  _avDismissedIds.add(req.id);
  state.requests = (state.requests || []).filter(r => r.id !== req.id);
  if (state.filteredRequests) {
    state.filteredRequests = state.filteredRequests.filter(r => r.id !== req.id);
  }

  // Delete any saved configuration for this API
  const key1 = req.id;
  const key2 = getApiConfigKey(req);
  if (key1) delete state.savedApiConfigs[key1];
  if (key2) delete state.savedApiConfigs[key2];

  // If the deleted request was active, clear details and params
  if (state.selectedRequest?.id === req.id) {
    state.selectedRequest = null;
    state.analyzedData = null;
    state.currentParams = [];
    state.paramDatasets = {};
    state.paramUnique = {};
    state.paramUniquePool = {};
    state.paramChecked = {};
    state.caseSelections = {};
    state.customCases = {};

    const detContent = $("details-content");
    const detEmpty = $("details-empty");
    if (detContent) detContent.style.display = "none";
    if (detEmpty) detEmpty.style.display = "flex";

    showParamsEmpty("Select a captured request first", false);
  }

  // Sync delete with backend
  fetch(`${BACKEND}/capture/delete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: req.id })
  }).catch(() => {});

  renderRequestList();
  updateAnalyzeBtn();
  showConfigToast(`🗑️ Deleted ${req.method} ${urlDisplay}`);
}

function showConfigToast(msg) {
  let toast = $("cfg-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "cfg-toast";
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #064e3b;
      color: #34d399;
      border: 1px solid #059669;
      padding: 10px 16px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 9999;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: opacity 0.3s, transform 0.3s;
      opacity: 0;
      transform: translateY(10px);
      pointer-events: none;
    `;
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.opacity = "1";
  toast.style.transform = "translateY(0)";
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
  }, 3200);
}

async function exportConfiguredApis() {
  const reqs = state.requests || [];
  if (!reqs.length) {
    alert("No APIs to export. Capture or import requests first.");
    return;
  }

  autoSaveCurrentApiConfig();

  const exportData = {
    version: "1.0",
    source: "API Sentinel - API Validator Pro",
    exported_at: new Date().toISOString(),
    total_apis: reqs.length,
    apis: reqs.map(r => {
      const cfg = getSavedApiConfig(r);
      return {
        id: r.id,
        method: r.method,
        url: r.url,
        headers: r.headers || {},
        queryParams: r.queryParams || {},
        body: r.body,
        body_type: r.body_type,
        status: r.status,
        statusText: r.statusText,
        config: cfg ? {
          paramChecked: cfg.paramChecked || {},
          paramDatasets: cfg.paramDatasets || {},
          paramUnique: cfg.paramUnique || {},
          paramUniquePool: extractPoolMetadata(cfg.paramUniquePool || {}),
          caseSelections: cfg.caseSelections || {},
          customCases: cfg.customCases || {},
          currentParams: (cfg.currentParams || []).map(p => ({ ...p })),
        } : null,
      };
    }),
  };

  const jsonStr = JSON.stringify(exportData, null, 2);
  const filename = `api_sentinel_apis_${new Date().toISOString().slice(0, 10)}.json`;

  // 1. pywebview desktop app: use native OS Save File dialog (allows user to select folder and filename)
  if (window.pywebview && window.pywebview.api && typeof window.pywebview.api.save_file === "function") {
    try {
      const result = await window.pywebview.api.save_file(jsonStr, filename);
      if (result && result.ok) {
        showConfigToast(`✓ Saved: ${result.filename || filename}`);
      } else if (result && result.reason && result.reason !== "cancelled") {
        alert("Save failed: " + result.reason);
      }
      return;
    } catch (err) {
      console.warn("pywebview save_file error:", err);
    }
  }

  // 2. Modern browser: native File System Save As dialog
  if (typeof window.showSaveFilePicker === "function") {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: filename,
        types: [{
          description: "JSON Files (*.json)",
          accept: { "application/json": [".json"] }
        }]
      });
      const writable = await handle.createWritable();
      await writable.write(jsonStr);
      await writable.close();
      showConfigToast(`✓ Saved: ${handle.name || filename}`);
      return;
    } catch (err) {
      if (err.name === "AbortError") return; // User cancelled
      console.warn("showSaveFilePicker error:", err);
    }
  }

  // 3. Fallback for browsers without native save dialogs
  try {
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 500);
    showConfigToast(`✓ Exported ${reqs.length} APIs with configured cases!`);
  } catch (e) {
    alert("Export failed: " + e.message);
  }
}

async function importConfiguredApis(file) {
  if (!file) return;
  try {
    const text = await file.text();
    const fileNameLower = (file.name || "").toLowerCase();

    // Guard 1: Excel or ZIP/binary file (magic bytes "PK")
    if (fileNameLower.endsWith(".xlsx") || fileNameLower.endsWith(".xls") || text.startsWith("PK\x03\x04") || text.startsWith("PK")) {
      showAvMessage(
        "Excel File Detected",
        `Aapne "${file.name}" select kiya hai jo ki ek Excel (.xlsx) file hai.\n\n` +
        `• 'Import AV Json' sirf exported API configuration JSON files ke liye hai.\n\n` +
        `• Agar aapko Test Data (CSV / Excel) use ya update karna hai:\n` +
        `  1. Capture tab me se us API ko select karke 'Params' tab me jayein.\n` +
        `  2. Jis parameter ke liye test data use karna hai, uske Unique Format (📋 / ⊕) button par click karein.\n` +
        `  3. 'Import CSV / XLSX' par click karke apni updated Excel file select karein.`
      );
      return;
    }

    // Guard 2: CSV file
    if (fileNameLower.endsWith(".csv") || (!text.trim().startsWith("{") && !text.trim().startsWith("[") && text.includes(","))) {
      if (!text.trim().startsWith("{") && !text.trim().startsWith("[")) {
        showAvMessage(
          "CSV File Detected",
          `Aapne "${file.name}" select kiya hai jo ki ek CSV test data file hai.\n\n` +
          `• 'Import AV Json' sirf API configuration JSON files ke liye hai.\n\n` +
          `• CSV Test Data add karne ke liye: Params tab me jakar Parameter ke 'Unique Format' (📋 / ⊕) modal se 'Import CSV / XLSX' karein.`
        );
        return;
      }
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch (parseErr) {
      showAvMessage(
        "Invalid JSON File",
        `File ko parse karne me syntax error aayi:\n${parseErr.message}\n\nKripya ek valid exported API Sentinel (.json) file select karein.`
      );
      return;
    }

    let rawList = [];
    if (Array.isArray(data)) {
      rawList = data;
    } else if (data && Array.isArray(data.apis)) {
      rawList = data.apis;
    } else if (data && Array.isArray(data.requests)) {
      rawList = data.requests;
    } else {
      showAvMessage("Invalid Format", "Expected JSON file with an 'apis' or 'requests' array.");
      return;
    }

    if (!rawList.length) {
      showAvMessage("No APIs", "No APIs found in the imported file.");
      return;
    }

    // Query backend store first to identify any matching requests in store that were dismissed
    let backendReqs = [];
    try {
      const bResp = await fetch(`${BACKEND}/capture/requests`).then(r => r.json());
      backendReqs = bResp.requests || [];
    } catch(e) {}

    let addedCount = 0;
    let duplicateCount = 0;
    const newItemsToBackend = [];
    const apisNeedingData = [];

    rawList.forEach(item => {
      const m = (item.method || "GET").toUpperCase().trim();
      const u = (item.url || "").trim();
      if (!u) return;

      // Always un-dismiss item.id so polling never hides this imported API!
      if (item.id) {
        _avDismissedIds.delete(item.id);
      }

      const itemSig = getApiSignature(item);

      // If backend has this request (by id or signature) in store, also un-dismiss that backend ID!
      const backendMatch = backendReqs.find(r => 
        (r.id && item.id && r.id === item.id) ||
        getApiSignature(r) === itemSig
      );
      if (backendMatch && backendMatch.id) {
        _avDismissedIds.delete(backendMatch.id);
      }

      const existing = state.requests.find(r => 
        (r.id && item.id && r.id === item.id) ||
        getApiSignature(r) === itemSig
      );

      const reqId = item.id || (backendMatch ? backendMatch.id : `req_imp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`);
      const targetId = existing ? existing.id : reqId;

      _avDismissedIds.delete(reqId);
      _avDismissedIds.delete(targetId);

      const rawPool = (item.config && (item.config.paramUniquePool || item.config.paramUniquePoolMeta)) || {};
      const hasActualConfig = item.config && (
        Object.keys(item.config.caseSelections || {}).length > 0 ||
        Object.keys(item.config.customCases || {}).length > 0 ||
        Object.values(item.config.paramChecked || {}).some(Boolean) ||
        Object.values(item.config.paramUnique || {}).some(Boolean) ||
        Object.keys(rawPool).length > 0
      );

      if (hasActualConfig) {
        const pool = {};
        const pendingForThisApi = [];

        Object.entries(rawPool).forEach(([p, rec]) => {
          if (!rec) return;
          const fname = rec.filename || (typeof rec === "string" ? rec : "");
          const hasExistingValues = (Array.isArray(rec.all_values) && rec.all_values.length > 0) ||
                                    (Array.isArray(rec.values) && rec.values.length > 0) ||
                                    (Array.isArray(rec) && rec.length > 0);

          if (!hasExistingValues || rec.requires_file) {
            pool[p] = {
              filename: fname,
              header: rec.header || p,
              requires_file: true,
              values: [],
              all_values: [],
            };
            pendingForThisApi.push({ path: p, filename: fname });
          } else {
            const allVals = Array.isArray(rec.all_values) && rec.all_values.length > 0
              ? rec.all_values.slice()
              : (Array.isArray(rec.values) ? rec.values.slice() : (Array.isArray(rec) ? rec.slice() : []));
            pool[p] = {
              filename: fname,
              header: rec.header || p,
              requires_file: false,
              values: allVals.slice(),
              all_values: allVals.slice(),
            };
          }
        });

        if (pendingForThisApi.length > 0) {
          apisNeedingData.push({
            method: m,
            url: u,
            params: pendingForThisApi
          });
        }

        const cfg = {
          id: targetId,
          method: m,
          url: u,
          paramChecked: item.config.paramChecked || {},
          paramDatasets: item.config.paramDatasets || {},
          paramUnique: item.config.paramUnique || {},
          paramUniquePool: pool,
          caseSelections: item.config.caseSelections || {},
          customCases: item.config.customCases || {},
          currentParams: item.config.currentParams || [],
          updatedAt: new Date().toISOString()
        };
        state.savedApiConfigs[targetId] = cfg;
        state.savedApiConfigs[itemSig] = cfg;
        if (state.selectedRequest && (state.selectedRequest.id === targetId || getApiSignature(state.selectedRequest) === itemSig)) {
          state.paramUniquePool = JSON.parse(JSON.stringify(pool));
        }
      } else {
        // Explicitly clear any previous config for this API if imported item has none
        delete state.savedApiConfigs[targetId];
        delete state.savedApiConfigs[itemSig];
        if (item.id) delete state.savedApiConfigs[item.id];
      }

      if (existing) {
        duplicateCount++;
      } else {
        const newReq = {
          id: reqId,
          method: m,
          url: u,
          headers: item.headers || {},
          queryParams: item.queryParams || {},
          body: item.body,
          body_type: item.body_type,
          status: item.status || 200,
          statusText: item.statusText || "OK"
        };
        state.requests.unshift(newReq);
        newItemsToBackend.push(newReq);
        addedCount++;
      }
    });

    if (newItemsToBackend.length > 0) {
      try {
        await fetch(`${BACKEND}/capture/import`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(newItemsToBackend)
        });
      } catch(e) {
        console.warn("Backend import sync failed:", e);
      }
    }

    renderRequestList();
    updateAnalyzeBtn();

    let msg = `✅ Import Complete! • ${addedCount} new API(s) imported`;
    if (duplicateCount > 0) {
      msg += `\n• ${duplicateCount} duplicate API(s) skipped/merged configuration`;
    }

    if (apisNeedingData.length > 0) {
      msg += `\n⚠️ Note: New Test data required`;
    }
    showAvMessage("Import Complete", msg);
  } catch(err) {
    showAvMessage("Import Failed", "Failed to import file: " + (err.message || "Invalid file"));
  }
}

// ── Backend check ─────────────────────────────────────────────────────────────
async function checkBackend() {
  const dot = $("backend-dot");
  const label = $("backend-label");
  try {
    const resp = await fetchBackend("/");
    dot.className = "status-dot online";
    label.textContent = "Online";
  } catch(e) {
    dot.className = "status-dot offline";
    label.textContent = "Offline";
  }
}

// ── Load initial requests ─────────────────────────────────────────────────────
async function loadRequests() {
  try {
    const resp = await fetch(`${BACKEND}/capture/requests`).then(r => r.json());
    const prevSelectedId = state.selectedRequest?.id || null;

    const backendFiltered = (resp.requests || []).filter(r => !_avDismissedIds.has(r.id));
    const backendIds = new Set(backendFiltered.map(r => r.id));
    const localPending = (state.requests || []).filter(r => !_avDismissedIds.has(r.id) && !backendIds.has(r.id));
    state.requests = [...localPending, ...backendFiltered];
    // Re-bind selection to fresh object by id (edits live on backend store)
    state.selectedRequest = prevSelectedId
      ? (state.requests.find(r => r.id === prevSelectedId) || null)
      : null;
    state.capturing = resp.capturing || false;
    updateCaptureUI();
    renderRequestList();
    updateAnalyzeBtn();
  } catch(e) { console.error("loadRequests error:", e); }
}

async function loadDatasets() {
  try {
    const data = await fetchBackend("/datasets");
    state.allDatasets = data;
  } catch(e) { console.error("Dataset load failed:", e); }
}

// ── Tab management ────────────────────────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const name = tab.dataset.tab;
      try {
        autoSaveCurrentApiConfig();
      } catch(e) {
        console.warn("autoSaveCurrentApiConfig failed during tab switch:", e);
      }
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(`tab-${name}`)?.classList.add("active");

      if (name === "details") {
        if (state.selectedRequest) {
          showDetails(state.selectedRequest, false);
        } else {
          const empty = $("details-empty");
          const content = $("details-content");
          if (empty) empty.style.display = "flex";
          if (content) content.style.display = "none";
        }
      } else if (name === "params") {
        if (state.selectedRequest && !state.analyzedData) {
          triggerParamsAnalyze();
        } else if (!state.selectedRequest) {
          showParamsEmpty("Select a captured request first", false);
        } else if (state.selectedRequest && state.analyzedData) {
          renderParamsTab();
        }
      }
    });
  });

  // Manual analyze button inside params-empty
  const btnPA = document.getElementById("btn-params-analyze");
  if (btnPA) {
    btnPA.addEventListener("click", () => {
      if (state.selectedRequest) triggerParamsAnalyze();
    });
  }
}

function showParamsEmpty(msg, showBtn) {
  const icon = document.getElementById("params-empty-icon");
  const msgEl = document.getElementById("params-empty-msg");
  const btn   = document.getElementById("btn-params-analyze");
  if (icon)  icon.textContent = showBtn ? "⚙️" : "⚙️";
  if (msgEl) msgEl.textContent = msg;
  if (btn)   btn.style.display = showBtn ? "inline-block" : "none";
  const empty   = document.getElementById("params-empty");
  const content = document.getElementById("params-content");
  if (empty)   empty.style.display = "flex";
  if (content) content.style.display = "none";
}

async function triggerParamsAnalyze() {
  // Show loading state immediately
  showParamsEmpty("⏳ Analyzing API...", false);
  const req = buildEffectiveRequest(state.selectedRequest);
  try {
    await analyzeRequest(req);
  } catch(e) {
    showParamsEmpty("❌ Analyze failed — " + (e.message || "unknown error"), true);
  }
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => {
    t.classList.toggle("active", t.dataset.tab === name);
  });
  document.querySelectorAll(".tab-content").forEach(c => {
    c.classList.toggle("active", c.id === `tab-${name}`);
  });
}

// ── Capture controls ──────────────────────────────────────────────────────────
function setupCaptureControls() {
  const btnCapture = $("btn-capture");
  if (btnCapture && !btnCapture._bound) {
    btnCapture._bound = true;
    btnCapture.addEventListener("click", toggleCapture);
  }
  const btnClear = $("btn-clear");
  if (btnClear && !btnClear._bound) {
    btnClear._bound = true;
    btnClear.addEventListener("click", clearAll);
  }
  const btnAnalyze = $("btn-analyze");
  if (btnAnalyze && !btnAnalyze._bound) {
    btnAnalyze._bound = true;
    btnAnalyze.addEventListener("click", analyzeSelected);
  }

  // Multi-selection bar controls
  const chkAll = $("chk-select-all-reqs");
  if (chkAll && !chkAll._bound) {
    chkAll._bound = true;
    chkAll.addEventListener("change", () => {
      const visibleReqs = (state.filteredRequests !== null ? state.filteredRequests : state.requests)
        .filter(r => !isJsAsset(r));
      if (chkAll.checked) {
        visibleReqs.forEach(r => state.selectedRequestIds.add(r.id));
      } else {
        visibleReqs.forEach(r => state.selectedRequestIds.delete(r.id));
      }
      renderRequestList();
    });
  }

  const btnSelCfg = $("btn-select-configured");
  if (btnSelCfg && !btnSelCfg._bound) {
    btnSelCfg._bound = true;
    btnSelCfg.addEventListener("click", () => {
      state.selectedRequestIds.clear();
      const visibleReqs = (state.filteredRequests !== null ? state.filteredRequests : state.requests)
        .filter(r => !isJsAsset(r));
      visibleReqs.filter(r => hasSavedApiConfig(r)).forEach(r => state.selectedRequestIds.add(r.id));
      renderRequestList();
    });
  }

  const btnClearSel = $("btn-clear-selection");
  if (btnClearSel && !btnClearSel._bound) {
    btnClearSel._bound = true;
    btnClearSel.addEventListener("click", () => {
      state.selectedRequestIds.clear();
      renderRequestList();
    });
  }

  const btnBulkRun = $("btn-bulk-run");
  if (btnBulkRun && !btnBulkRun._bound) {
    btnBulkRun._bound = true;
    btnBulkRun.addEventListener("click", openBulkRunModal);
  }

  const btnBulkRunFooter = $("btn-bulk-run-footer");
  if (btnBulkRunFooter && !btnBulkRunFooter._bound) {
    btnBulkRunFooter._bound = true;
    btnBulkRunFooter.addEventListener("click", openBulkRunModal);
  }
}

// Global exposure
window.toggleCapture = toggleCapture;
window.clearAll = clearAll;
window.getCaptureState = () => state.capturing;

async function toggleCapture() {
  const endpoint = state.capturing ? "/capture/stop" : "/capture/start";
  try {
    await fetch(`${BACKEND}${endpoint}`, { method: "POST" });
    state.capturing = !state.capturing;
    updateCaptureUI();
    // Show proxy port in header badge when capturing
    const badge = document.getElementById("proxy-port-badge");
    if (badge) {
      if (state.capturing) {
        fetch("http://127.0.0.1:8765/capture/proxy-port").then(r=>r.json())
          .then(d => { badge.textContent = "🔀 :"+d.port; badge.style.display="inline"; })
          .catch(()=>{ badge.textContent = "🔀 :8767"; badge.style.display="inline"; });
      } else {
        badge.style.display = "none";
      }
    }
  } catch(e) { console.error("toggleCapture error:", e); }
}

function updateCaptureUI() {
  const btn = $("btn-capture");
  const icon = $("capture-icon");
  const status = $("capture-status-text");
  if (state.capturing) {
    if (btn) {
      btn.classList.add("capturing");
      btn.title = "Live traffic capturing active — Click to Stop";
    }
    if (icon) icon.textContent = "⏸";
    if (status) {
      status.textContent = "Stop Capture";
    }
  } else {
    if (btn) {
      btn.classList.remove("capturing");
      btn.title = "Click to Start Live Capture";
    }
    if (icon) icon.textContent = "▶";
    if (status) {
      status.textContent = "Start Capture";
    }
  }
  const harStatus = $("har-capture-status-text");
  if (harStatus) {
    harStatus.textContent = state.capturing ? "🔴 Capturing..." : "⏸ Capture paused";
    harStatus.style.color = state.capturing ? "var(--red)" : "var(--text2)";
  }
}

async function clearAll() {
  // If the active tool is API Scan, delegate to its own reset
  if (window._activeTool === 'apiscan') {
    if (typeof window.asReset === 'function') window.asReset();
    return;
  }

  try {
    await fetch(`${BACKEND}/capture/clear`, { method: "POST" });
  } catch(e) { console.error("capture/clear error:", e); }

  // ── Reset ALL API Validator state ─────────────────────────────────────────
  state.requests          = [];
  state.filteredRequests  = null;
  state.selectedRequest   = null;
  state.analyzedData      = null;
  state.testResults       = null;
  state.currentParams     = [];
  state.paramDatasets     = {};
  state.paramUnique       = {};
  state.paramUniquePool   = {};
  state.paramChecked      = {};
  state.caseSelections    = {};
  state.customCases       = {};
  state.paramsSearchQuery = "";

  // ── Reset UI back to Capture tab ─────────────────────────────────────────
  switchTab("capture");
  renderRequestList();
  updateAnalyzeBtn();

  // Reset Details tab
  const detContent = $("details-content");
  const detEmpty   = $("details-empty");
  if (detContent) detContent.style.display = "none";
  if (detEmpty)   detEmpty.style.display   = "flex";

  // Reset Params tab
  const prmsContent = $("params-content");
  const prmsEmpty   = $("params-empty");
  if (prmsContent) prmsContent.style.display = "none";
  if (prmsEmpty)   prmsEmpty.style.display   = "flex";
  const psearch = $("params-search");
  if (psearch) psearch.value = "";

  // Reset Results tab
  const resContent = $("results-content");
  const resEmpty   = $("results-empty");
  if (resContent) resContent.style.display = "none";
  if (resEmpty)   resEmpty.style.display   = "flex";

  // ── Clear Auth Validator state too ────────────────────────────────────────
  if (window.harClearAll) window.harClearAll();

  // ── Clear Method Tampering state too ──────────────────────────────────────
  if (typeof mtReset === "function") mtReset();

  // ── Clear Soft Delete state too ───────────────────────────────────────────
  if (typeof sdReset === "function") sdReset();

  // ── Clear IDOR Tester state too ───────────────────────────────────────────
  if (typeof idorReset === "function") idorReset();

  // ── Clear File Upload state too ───────────────────────────────────────────
  if (typeof uploadReset === "function") uploadReset();

  // ── Clear XSS Tester state too ────────────────────────────────────────────
  if (typeof xssReset === "function") xssReset();

  // ── Clear JS Analyser state too ───────────────────────────────────────────
  if (typeof jsaReset === "function") jsaReset();
}

// Scoped Reset button — clears this tool's own captured list, results,
// selections and config. Never calls /capture/clear: the backend buffer is
// shared with Auth Validator Pro, so wiping it there would also empty that
// tool's view. Instead the currently-shown requests are just hidden from
// THIS tool going forward (_avDismissedIds) — Auth Validator keeps seeing
// them untouched, and the shared buffer itself is never modified.
function avReset() {
  state.requests.forEach(r => _avDismissedIds.add(r.id));
  state.requests          = [];
  state.filteredRequests  = null;
  state.selectedRequest   = null;
  state.analyzedData      = null;
  state.testResults       = null;
  state.currentParams     = [];
  state.paramDatasets     = {};
  state.paramUnique       = {};
  state.paramUniquePool   = {};
  state.paramChecked      = {};
  state.caseSelections    = {};
  state.customCases       = {};
  state.paramsSearchQuery = "";
  state.savedApiConfigs   = {};
  state.selectedRequestIds = new Set();
  try {
    localStorage.removeItem("av_saved_api_configs_v1");
  } catch(e) {}

  switchTab("capture");
  renderRequestList();
  updateAnalyzeBtn();

  const detContent = $("details-content");
  const detEmpty   = $("details-empty");
  if (detContent) detContent.style.display = "none";
  if (detEmpty)   detEmpty.style.display   = "flex";

  const prmsContent = $("params-content");
  const prmsEmpty   = $("params-empty");
  if (prmsContent) prmsContent.style.display = "none";
  if (prmsEmpty)   prmsEmpty.style.display   = "flex";
  const psearch = $("params-search");
  if (psearch) psearch.value = "";

  const resContent = $("results-content");
  const resEmpty   = $("results-empty");
  if (resContent) resContent.style.display = "none";
  if (resEmpty)   resEmpty.style.display   = "flex";
}
window.avReset = avReset;

// ── Request list rendering ────────────────────────────────────────────────────
function setupFilters() {
  $("search-input").addEventListener("input", filterRequests);
  $("method-filter").addEventListener("change", filterRequests);
}

function filterRequests() {
  const q = ($("search-input")?.value || "").toLowerCase().trim();
  const m = $("method-filter")?.value || "";
  // Always filter — if no query/method, show all
  if (!q && !m) {
    state.filteredRequests = null; // null = "no active filter = show all"
  } else {
    state.filteredRequests = state.requests.filter(req => {
      const matchUrl = !q || req.url.toLowerCase().includes(q);
      const matchMethod = !m || req.method === m;
      return matchUrl && matchMethod;
    });
  }
  renderRequestList();
}

// .js files are captured (for JS Analyser's use, via window._avState) but
// hidden from API Validator's own list/selection — filtered out at the UI
// layer only; state.requests itself stays complete so other tools (and
// window._avState consumers) still see everything that was captured.
function isJsAsset(r) {
  return (r.url || "").split("?")[0].toLowerCase().endsWith(".js");
}

function renderRequestList() {
  const list = $("request-list");
  const empty = $("empty-state");
  const countEl = $("request-count");
  const badge = $("tab-badge");

  if (!state.selectedRequestIds) state.selectedRequestIds = new Set();
  const validIds = new Set(state.requests.map(r => r.id));
  for (const id of state.selectedRequestIds) {
    if (!validIds.has(id)) state.selectedRequestIds.delete(id);
  }

  const visibleAll = state.requests.filter(r => !isJsAsset(r));

  // null = no filter active; [] = filter active but no matches
  const reqs = (state.filteredRequests !== null ? state.filteredRequests : state.requests)
    .filter(r => !isJsAsset(r));
  countEl.textContent = `${visibleAll.length} requests`;
  badge.textContent = visibleAll.length;

  if (!reqs.length) {
    empty.style.display = "flex";
    list.style.display = "none";
    list.innerHTML = "";
    updateCaptureSelectionUi();
    return;
  }

  empty.style.display = "none";
  list.style.display = "flex";
  list.innerHTML = "";

  reqs.forEach((req) => {
    const isSelected = state.selectedRequest?.id === req.id;
    const hasConfig = hasSavedApiConfig(req);
    const isChecked = state.selectedRequestIds.has(req.id);

    const item = document.createElement("div");
    item.className = `request-item${isSelected ? " selected" : ""}${hasConfig ? " has-config" : ""}`;

    const methodClass = getMethodClass(req.method);
    const statusClass = getStatusClass(req.status);
    const statusText = req.status || "---";

    // Full URL on one line — CSS ellipsis only if it overflows available row width
    let displayUrl = esc(req.url || "");
    try {
      const u = new URL(req.url);
      displayUrl =
        `<span class="url-host">${esc(u.host)}</span>` +
        `<span class="url-path">${esc(u.pathname)}</span>` +
        (u.search ? `<span class="url-query">${esc(u.search)}</span>` : "");
    } catch (e) {}

    const discLabel = getApiDifferentiatorLabel(req);
    const discTag = discLabel
      ? `<span class="req-disc-badge" title="API Discriminator: ${esc(discLabel)}">${esc(discLabel)}</span>`
      : "";

    const cfgTag = hasConfig
      ? `<span class="req-configured-badge" title="Parameters & cases configured for this API">⚡ Configured</span>`
      : "";
    const warnTag = (hasConfig && reqNeedsTestData(req))
      ? `<span class="req-warn-badge" title="Note: New Test data required">⚠️</span>`
      : "";

    item.innerHTML = `
      <input type="checkbox" class="req-checkbox" data-req-id="${req.id}" ${isChecked ? "checked" : ""} title="Select for bulk run">
      <span class="method-badge method-${methodClass}">${req.method}</span>
      <span class="req-url" title="${esc(req.url || "")}">${displayUrl}</span>
      ${discTag}${cfgTag}${warnTag}
      <span class="status-pill ${statusClass}">${statusText}</span>
      <button class="btn-delete-req" title="Delete API from list" aria-label="Delete API">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
          <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
          <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
        </svg>
      </button>
    `;

    const chk = item.querySelector(".req-checkbox");
    if (chk) {
      chk.addEventListener("click", (e) => {
        e.stopPropagation();
      });
      chk.addEventListener("change", (e) => {
        e.stopPropagation();
        if (chk.checked) {
          state.selectedRequestIds.add(req.id);
        } else {
          state.selectedRequestIds.delete(req.id);
        }
        syncSingleSelection();
        renderRequestList();
        updateCaptureSelectionUi();
        updateAnalyzeBtn();
      });
    }

    const delBtn = item.querySelector(".btn-delete-req");
    if (delBtn) {
      delBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteCapturedRequest(req);
      });
    }

    // Row click: selects this API's checkbox, does NOT open details tab directly
    item.addEventListener("click", (e) => {
      if (e.target.closest(".btn-delete-req") || e.target.closest(".req-checkbox")) return;
      if (state.selectedRequestIds.has(req.id) && state.selectedRequestIds.size === 1) {
        state.selectedRequestIds.delete(req.id);
      } else {
        state.selectedRequestIds.clear();
        state.selectedRequestIds.add(req.id);
      }
      syncSingleSelection();
      renderRequestList();
      updateCaptureSelectionUi();
      updateAnalyzeBtn();
    });

    list.appendChild(item);
  });

  updateCaptureSelectionUi();
}

function updateCaptureSelectionUi() {
  if (!state.selectedRequestIds) state.selectedRequestIds = new Set();
  const visibleReqs = (state.filteredRequests !== null ? state.filteredRequests : state.requests)
    .filter(r => !isJsAsset(r));
  const configuredAll = state.requests.filter(r => !isJsAsset(r) && hasSavedApiConfig(r));

  const chkAll = $("chk-select-all-reqs");
  if (chkAll) {
    if (visibleReqs.length === 0) {
      chkAll.checked = false;
      chkAll.indeterminate = false;
    } else {
      const selectedVisible = visibleReqs.filter(r => state.selectedRequestIds.has(r.id)).length;
      chkAll.checked = selectedVisible === visibleReqs.length;
      chkAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleReqs.length;
    }
  }

  const countConfiguredEl = $("count-configured-apis");
  if (countConfiguredEl) {
    countConfiguredEl.textContent = configuredAll.length;
  }

  const selectedCountEl = $("selected-apis-count");
  if (selectedCountEl) {
    const selTotal = state.selectedRequestIds.size;
    selectedCountEl.textContent = `${selTotal} selected`;
    selectedCountEl.classList.toggle("has-selected", selTotal > 0);
  }

  const selTotal = state.selectedRequestIds.size;

  const runCountSpan = $("run-selected-count");
  if (runCountSpan) runCountSpan.textContent = selTotal;

  const runCountFooterSpan = $("run-selected-count-footer");
  if (runCountFooterSpan) runCountFooterSpan.textContent = selTotal;

  const btnBulkRun = $("btn-bulk-run");
  if (btnBulkRun) {
    btnBulkRun.disabled = selTotal === 0;
  }

  const btnBulkRunFooter = $("btn-bulk-run-footer");
  if (btnBulkRunFooter) {
    btnBulkRunFooter.disabled = selTotal === 0;
  }

  updateAnalyzeBtn();
}

function getMethodClass(method) {
  return ["GET","POST","PUT","PATCH","DELETE"].includes(method) ? method : "OTHER";
}

function getStatusClass(status) {
  if (status == null || status === "" || status === "null") return "status-err";
  const code = parseInt(status);
  if (isNaN(code)) return "status-err";
  if (code < 300) return "status-2xx";
  if (code < 400) return "status-3xx";
  if (code < 500) return "status-4xx";
  return "status-5xx";
}

function updateAnalyzeBtn() {
  const btn = $("btn-analyze");
  if (!btn) return;

  const selCount = state.selectedRequestIds ? state.selectedRequestIds.size : 0;

  if (selCount === 1) {
    const singleId = Array.from(state.selectedRequestIds)[0];
    const targetReq = (state.requests || []).find(r => r.id === singleId);
    if (targetReq) {
      state.selectedRequest = targetReq;
    }
    btn.disabled = false;
    btn.title = "Analyze selected API";
  } else if (selCount > 1) {
    btn.disabled = true;
    btn.title = `Analysis only supports 1 API at a time (${selCount} APIs selected). Use 'Run Selected' for multi-API testing.`;
  } else {
    btn.disabled = true;
    btn.title = "Select 1 API to analyze";
  }
}

// ── Details tab ───────────────────────────────────────────────────────────────
let _avDetailsEdit = { hdr: false, body: false, query: false, req: false };

function avBodyText(req) {
  if (!req?.body && req?.body !== 0) return "";
  return typeof req.body === "object"
    ? JSON.stringify(req.body, null, 2)
    : String(req.body);
}

function avKvViewHtml(k, v, maxLen) {
  const s = String(v ?? "");
  const shown = maxLen ? truncate(s, maxLen) : s;
  return `<div class="kv-row"><div class="kv-key">${esc(k)}</div><div class="kv-val" title="${esc(s)}">${esc(shown)}</div></div>`;
}

function avKvEditHtml(k, v) {
  const s = String(v ?? "");
  const field = s.length > 80
    ? `<textarea class="av-kv-edit" rows="2" spellcheck="false">${esc(s)}</textarea>`
    : `<input type="text" class="av-kv-edit" spellcheck="false" value="${esc(s)}">`;
  return `<div class="kv-row"><div class="kv-key">${esc(k)}</div><div class="kv-val av-kv-val-edit">${field}</div></div>`;
}

function avReadKvEdits(tableEl) {
  const out = {};
  if (!tableEl) return out;
  tableEl.querySelectorAll(".kv-row").forEach(row => {
    const k = row.querySelector(".kv-key")?.textContent?.trim();
    const field = row.querySelector(".av-kv-edit");
    if (k) out[k] = field ? field.value : "";
  });
  return out;
}

function avRenderKvTable(tableId, obj, maxLen) {
  const el = $(tableId);
  if (!el) return;
  const entries = Object.entries(obj || {});
  el.innerHTML = entries.map(([k, v]) => avKvViewHtml(k, v, maxLen)).join("");
}

function avQueryFromUrl(url) {
  try {
    const u = new URL(url);
    const q = {};
    u.searchParams.forEach((v, k) => { q[k] = v; });
    return q;
  } catch (e) {
    return null;
  }
}

function avFillReqView(req) {
  if (!req) return;
  const methodEl = $("det-method");
  if (methodEl) {
    const m = (req.method || "GET").toUpperCase();
    methodEl.textContent = m;
    methodEl.className = `method-badge method-${getMethodClass(m)}`;
  }
  const urlEl = $("det-url");
  if (urlEl) {
    const disc = getApiDifferentiatorLabel(req);
    urlEl.textContent = disc ? `${req.url || ""}  [${disc}]` : (req.url || "");
    urlEl.title = req.url || "";
  }
}

function avShowReqView() {
  const view = $("det-req-view");
  const edit = $("det-req-edit");
  if (view) view.style.display = "";
  if (edit) {
    edit.hidden = true;
    edit.classList.remove("is-open");
  }
}

function avShowReqEdit() {
  const view = $("det-req-view");
  const edit = $("det-req-edit");
  if (view) view.style.display = "none";
  if (edit) {
    edit.hidden = false;
    edit.classList.add("is-open");
  }
}

function avExitReqEdit() {
  _avDetailsEdit.req = false;
  const btnER = $("btn-edit-req");
  if (btnER) { btnER.textContent = "✏️ Edit"; btnER.style.color = ""; }
  const reqAct = $("req-edit-actions");
  if (reqAct) reqAct.style.display = "none";
  avShowReqView();
}

function avEnsureMethodOption(method) {
  const sel = $("det-method-edit");
  if (!sel || !method) return;
  const m = String(method).toUpperCase();
  const exists = [...sel.options].some(o => (o.value || o.textContent).toUpperCase() === m);
  if (!exists) {
    const opt = document.createElement("option");
    opt.value = m;
    opt.textContent = m;
    sel.appendChild(opt);
  }
  sel.value = m;
}

function avRefreshQuerySection(req) {
  const query = req?.queryParams || {};
  const queryBlock = $("query-block");
  if (!queryBlock) return;
  if (Object.keys(query).length > 0) {
    queryBlock.style.display = "block";
    const qc = $("query-count");
    if (qc) qc.textContent = Object.keys(query).length;
    avRenderKvTable("query-table", query, 80);
  } else {
    queryBlock.style.display = "none";
  }
}

function avResetDetailsEditUi() {
  _avDetailsEdit = { hdr: false, body: false, query: false, req: false };
  const btnEH = $("btn-edit-headers");
  if (btnEH) { btnEH.textContent = "✏️ Edit"; btnEH.style.color = ""; }
  const btnEB = $("btn-edit-body");
  if (btnEB) { btnEB.textContent = "✏️ Edit"; btnEB.style.color = ""; }
  const btnEQ = $("btn-edit-query");
  if (btnEQ) { btnEQ.textContent = "✏️ Edit"; btnEQ.style.color = ""; }
  const btnER = $("btn-edit-req");
  if (btnER) { btnER.textContent = "✏️ Edit"; btnER.style.color = ""; }
  const hdrAct = $("hdr-edit-actions");
  if (hdrAct) hdrAct.style.display = "none";
  const bodyAct = $("body-edit-actions");
  if (bodyAct) bodyAct.style.display = "none";
  const qAct = $("query-edit-actions");
  if (qAct) qAct.style.display = "none";
  const reqAct = $("req-edit-actions");
  if (reqAct) reqAct.style.display = "none";
  avShowReqView();
  const ta = $("body-editor");
  const pre = $("body-preview");
  if (ta) {
    ta.style.display = "none";
    ta.hidden = true;
    ta.value = "";
  }
  if (pre) {
    pre.style.display = "";
    pre.contentEditable = "false";
    pre.classList.remove("kv-val-editing");
    pre.classList.remove("is-expanded");
  }
  const expBtn = $("btn-expand-body");
  if (expBtn) expBtn.textContent = "↕ Full";
}

function showDetails(req, shouldSwitchTab = true) {
  if (!req) return;
  const empty = $("details-empty");
  const content = $("details-content");
  if (empty) empty.style.display = "none";
  if (content) content.style.display = "flex";
  avResetDetailsEditUi();
  avFillReqView(req);

  // Headers
  const hdrs = req.headers || {};
  if ($("hdr-count")) $("hdr-count").textContent = Object.keys(hdrs).length;
  avRenderKvTable("headers-table", hdrs, 60);

  avRefreshQuerySection(req);

  // Body
  const bodyBlock = $("body-block");
  if (bodyBlock) {
    if (req.body) {
      bodyBlock.style.display = "block";
      const bodyStr = avBodyText(req);
      const keys = typeof req.body === "object" ? Object.keys(req.body).length : 1;
      if ($("body-count")) $("body-count").textContent = `${keys} fields`;
      if ($("body-type-badge")) $("body-type-badge").textContent = req.body_type || "json";
      if ($("body-preview")) $("body-preview").textContent = bodyStr;
    } else {
      bodyBlock.style.display = "none";
    }
  }

  if ($("details-edit-hint")) $("details-edit-hint").style.display = "none";

  // Switch to details tab
  if (shouldSwitchTab) {
    switchTab("details");
  }
}

$("btn-go-params").addEventListener("click", () => {
  if (state.selectedRequest) {
    state.analyzedData  = null;
    state.currentParams = [];
    triggerParamsAnalyze();
  }
});

// Clone request for analyze/run — each API keeps its own headers/body/query
function buildEffectiveRequest(req) {
  if (!req) return req;
  let body = req.body;
  if (body && typeof body === "object") {
    try { body = JSON.parse(JSON.stringify(body)); }
    catch (e) { body = body; }
  }
  return {
    ...req,
    headers: { ...(req.headers || {}) },
    queryParams: { ...(req.queryParams || {}) },
    body,
    body_type: req.body_type,
  };
}

/** Persist a patch to ONE captured request (by id) — local state + backend store */
function avApplyRequestPatch(target, patch) {
  if (!target || !patch) return;
  if (patch.method) target.method = patch.method;
  if (patch.url) target.url = patch.url;
  if ("status" in patch) target.status = patch.status;
  if ("statusText" in patch) target.statusText = patch.statusText;
  if (patch.headers) target.headers = { ...patch.headers };
  if (patch.queryParams) target.queryParams = { ...patch.queryParams };
  if ("body" in patch) {
    target.body = patch.body;
    target.body_type = patch.body_type;
    if ("payload" in patch) target.payload = patch.payload;
  }
}

async function persistRequestPatch(req, patch) {
  if (!req?.id) return;
  avApplyRequestPatch(req, patch);
  const inList = state.requests.find(r => r.id === req.id);
  if (inList && inList !== req) avApplyRequestPatch(inList, patch);
  try {
    await fetch(`${BACKEND}/capture/update`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: req.id, ...patch }),
    });
  } catch (e) {
    console.warn("capture/update failed:", e);
  }
  // Keep Params/Run in sync with Details edits (no stale frozen request)
  syncAnalyzedRequestAfterEdit(patch);
}

/** After Details edit: refresh Run payload; re-analyze if body/query shape changed. */
function syncAnalyzedRequestAfterEdit(patch) {
  if (!state.selectedRequest) return;
  const shapeChanged = ("body" in patch) || ("queryParams" in patch) || ("url" in patch);

  if (shapeChanged) {
    state.analyzedData = null;
    state.currentParams = [];
    const activeTab = document.querySelector("#tabs .tab.active")?.dataset?.tab;
    if (activeTab === "params") {
      triggerParamsAnalyze();
    }
    return;
  }

  // Headers/method/status: keep param list, refresh frozen request for Run
  if (state.analyzedData) {
    state.analyzedData._req = buildEffectiveRequest(state.selectedRequest);
  }
}

/** Always prefer live selectedRequest so Details edits are used on Run. */
function getLiveRequest() {
  if (state.selectedRequest) {
    return buildEffectiveRequest(state.selectedRequest);
  }
  if (state.analyzedData?._req) {
    return buildEffectiveRequest(state.analyzedData._req);
  }
  return null;
}

/** Count runnable cases for a param (excludes SKIP; includes backend captured_original seed). */
function countRunnableCases(path, dsKey) {
  const ds = state.allDatasets[dsKey];
  const sel = state.caseSelections[path];
  let n = 0;
  if (ds?.cases) {
    ds.cases.forEach(c => {
      const v = sel && sel[c.id] != null ? sel[c.id] : c.cat;
      if (v !== "SKIP") n++;
    });
  }
  // Backend prepends POS "captured_original" when the param has a non-empty value
  const p = state.currentParams.find(x => x.path === path);
  if (p && p.value != null && p.value !== "") {
    const seedSel = sel && sel.captured_original != null ? sel.captured_original : "POS";
    if (seedSel !== "SKIP") n += 1;
  }
  n += (state.customCases[path] || []).length;
  return n;
}

// ── Analyze selected APIs ─────────────────────────────────────────────────────
async function analyzeSelected() {
  const selCount = state.selectedRequestIds ? state.selectedRequestIds.size : 0;
  if (selCount > 1) {
    alert(`Analysis only supports 1 API at a time (${selCount} APIs selected). Please select only 1 API to analyze, or use 'Run Selected' for multi-API testing.`);
    return;
  }
  if (selCount === 0) {
    alert("Please select 1 API to analyze.");
    return;
  }
  const singleId = Array.from(state.selectedRequestIds)[0];
  const targetReq = (state.requests || []).find(r => r.id === singleId);
  if (!targetReq) return;

  state.selectedRequest = targetReq;
  loadApiConfigIntoState(targetReq);
  showDetails(targetReq, true);
}

// Strip HTTP/2 pseudo-headers and browser-internal headers that backend cannot use
function stripBadHeaders(hdrs) {
  const result = {};
  for (const [k, v] of Object.entries(hdrs || {})) {
    const kl = k.toLowerCase().trim();
    // Skip HTTP/2 pseudo-headers (:authority, :method, :path, :scheme)
    if (kl.startsWith(":")) continue;
    // Skip hop-by-hop and browser-managed headers
    if (["host","content-length","transfer-encoding","connection",
         "upgrade","keep-alive","proxy-connection"].includes(kl)) continue;
    result[k] = v;
  }
  return result;
}

async function analyzeRequest(req) {
  const resp = await fetchBackend("/analyze", "POST", {
    url:       req.url,
    method:    req.method,
    headers:   stripBadHeaders(req.headers),
    query:     req.queryParams || {},
    body:      req.body || null,
    body_type: req.body_type || null,
  });

  state.analyzedData = { ...resp, _req: req };

  // Include query params as testable params (important for GET APIs)
  const queryParamEntries = (resp.query_params || []).map(qp => ({
    path:            "query." + qp.path,
    value:           qp.value,
    detected:        qp.detected,
    detected_label:  qp.detected_label,
    datasets:        qp.datasets || [],
    is_query_param:  true,
  }));
  state.currentParams = [...(resp.params || []), ...queryParamEntries];

  const saved = getSavedApiConfig(req);

  state.paramDatasets = {};
  state.paramUnique   = {};
  state.paramUniquePool = saved?.paramUniquePool ? JSON.parse(JSON.stringify(saved.paramUniquePool)) : {};
  state.paramChecked  = {};
  state.caseSelections = saved?.caseSelections ? { ...saved.caseSelections } : {};
  state.customCases    = saved?.customCases ? { ...saved.customCases } : {};

  state.currentParams.forEach(p => {
    state.paramDatasets[p.path] = (saved?.paramDatasets && saved.paramDatasets[p.path]) || p.detected;
    state.paramUnique[p.path]   = (saved?.paramUnique && saved.paramUnique[p.path]) || "";
    state.paramChecked[p.path]  = (saved?.paramChecked && saved.paramChecked[p.path] != null) ? saved.paramChecked[p.path] : false;
  });

  if (!state.currentParams.length) {
    showParamsEmpty("No testable params found in this request", false);
    switchTab("params");
    return;
  }

  renderParamsTab();
  switchTab("params");
}

// ── Params tab ────────────────────────────────────────────────────────────────
function renderParamsTab() {
  if (!state.currentParams.length) return;

  const data = state.analyzedData;
  const req = data._req;

  $("params-empty").style.display = "none";
  $("params-content").style.display = "flex";

  // Header info
  const m = $("prm-method");
  m.textContent = req.method;
  m.className = `method-badge method-${getMethodClass(req.method)}`;
  $("prm-url").textContent = req.url;
  $("prm-url").title = req.url;

  renderParamsTable();
  updateTestCount();
}

function renderParamsTable() {
  const tbody = $("params-tbody");
  tbody.innerHTML = "";

  // Patch 3: search filter
  const q = (state.paramsSearchQuery || "").toLowerCase();
  const paramsToShow = q
    ? state.currentParams.filter(p =>
        p.path.toLowerCase().includes(q) ||
        String(p.value ?? "").toLowerCase().includes(q)
      )
    : state.currentParams;

  // Group: body params first, then query params (with separator)
  const bodyParams  = paramsToShow.filter(p => !p.is_query_param);
  const queryParams = paramsToShow.filter(p =>  p.is_query_param);

  // Render body params
  bodyParams.forEach(p => { renderParamRow(p, tbody); });

  // If query params exist, add a separator row + render them
  if (queryParams.length) {
    const sepRow = document.createElement("tr");
    sepRow.innerHTML = `<td colspan="5" style="padding:6px 8px;background:var(--bg3);color:var(--text3);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;border-top:1px solid var(--border)">🔗 Query Parameters</td>`;
    tbody.appendChild(sepRow);
    queryParams.forEach(p => { renderParamRow(p, tbody); });
  }
}

function renderParamRow(p, tbody) {
  {
    const checked    = state.paramChecked[p.path] || false;
    const dsKey      = state.paramDatasets[p.path] || p.detected;
    const dsInfo     = state.allDatasets[dsKey];
    const dsLabel    = dsInfo?.label || dsKey;
    const poolRec    = (state.paramUniquePool || {})[p.path];
    const needsFile  = poolRec && (poolRec.requires_file || ((!poolRec.values || poolRec.values.length === 0) && (!poolRec.all_values || poolRec.all_values.length === 0) && poolRec.filename));
    const poolTotal  = poolRec && Array.isArray(poolRec.all_values) ? poolRec.all_values.length : (poolRec && Array.isArray(poolRec.values) ? poolRec.values.length : 0);
    const poolN      = poolRec && Array.isArray(poolRec.values) ? poolRec.values.length : poolTotal;
    const poolNext   = poolN ? poolRec.values[0] : (poolTotal ? poolRec.all_values[0] : null);
    const hasPool    = poolTotal > 0 || needsFile;
    const uniqueVal  = hasPool ? "" : (state.paramUnique[p.path] || "");
    const uniqueTitle = needsFile
      ? esc(`Test data required: previous file was ${poolRec.filename || "Excel"}. Click to upload fresh CSV/XLSX file.`)
      : hasPool
        ? esc((poolRec.filename || "list") + " · " + poolN + "/" + poolTotal + " available (auto-resets when exhausted)")
        : (checked && uniqueVal)
          ? esc(uniqueVal + " — dataset cases when this param is tested; this format when other params are tested")
          : esc(uniqueVal || "Click to set unique format");
    const customSel  = state.caseSelections[p.path];
    const hasCustom  = !!customSel;
    const customPos  = hasCustom ? Object.values(customSel).filter(v => v === "POS").length : 0;
    const customNeg  = hasCustom ? Object.values(customSel).filter(v => v === "NEG").length : 0;
    const customSkip = hasCustom ? Object.values(customSel).filter(v => v === "SKIP").length : 0;
    const runCount   = countRunnableCases(p.path, dsKey);

    let chipClass = "unique-chip";
    let chipIcon = "⊕";
    let chipLabel = "Set format";

    if (needsFile) {
      chipClass += " has-list needs-file";
      chipIcon = "⚠️";
      chipLabel = poolRec.filename ? truncate(poolRec.filename.replace(/\.[^.]+$/, ""), 10) + " (Upload)" : "Upload Data";
    } else if (poolTotal > 0) {
      chipClass += " has-list";
      chipIcon = "📋";
      chipLabel = (poolRec.filename ? truncate(poolRec.filename.replace(/\.[^.]+$/, ""), 10) : "list") + " · " + (poolN || poolTotal);
    } else if (uniqueVal) {
      chipClass += " has-value";
      chipIcon = "🔀";
      chipLabel = truncate(uniqueVal, 16);
    }

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>
        <input type="checkbox" class="param-check" ${checked ? "checked" : ""}>
      </td>
      <td class="param-name">${esc(p.path)}${p.encoding === "b64_json" ? `<span class="av-b64-badge" title="Sent as base64 JSON in ${esc(p.b64_field || p.path.split(".")[0] || "")}">b64</span>` : ""}</td>
      <td class="param-value" title="${esc(needsFile ? "Fresh Excel/CSV file required" : hasPool ? (`Next list value (${poolN}/${poolTotal} available): ` + String(poolNext ?? "")) : String(p.value ?? ""))}">${esc(needsFile ? "⚠️ Needs file" : truncate(String(hasPool ? (poolNext ?? p.value) : (p.value ?? "null")), 20))}</td>
      <td>
        <div class="dataset-selector">
          <span class="dataset-label" title="Click to change dataset">
            ${esc(truncate(dsLabel, 22))}
            ${dsInfo ? `<span style="color:var(--text3);font-size:9px"> (${runCount} run)</span>` : ""}
          </span>
          <button class="cases-btn${hasCustom ? ' cases-btn-custom' : ''}"
                  title="${hasCustom ? `Custom: ${customPos} POS · ${customNeg} NEG · ${customSkip} SKIP — click to edit` : 'Include/skip cases and set POS/NEG expectations'}">
            🔬${hasCustom ? ` ${customPos}✓ ${customNeg}✗${customSkip ? ` ${customSkip}⏭` : ""}` : ' Cases'}
          </button>
        </div>
      </td>
      <td>
        <span class="${chipClass}" title="${uniqueTitle}">
          <span class="unique-chip-icon">${chipIcon}</span>
          <span>${esc(chipLabel)}</span>
        </span>
      </td>
    `;

    // Checkbox
    const cb = tr.querySelector(".param-check");
    cb.addEventListener("change", (e) => {
      state.paramChecked[p.path] = e.target.checked;
      updateTestCount();
      autoSaveCurrentApiConfig();
    });

    // Dataset selector
    const dsLabel_el = tr.querySelector(".dataset-label");
    dsLabel_el.addEventListener("click", () => openDatasetModal(p.path, dsKey));

    // Cases button — opens business cases modal
    const casesBtn = tr.querySelector(".cases-btn");
    casesBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      openCasesModal(p.path, dsKey);
    });

    // Unique format chip — opens popup
    const chip = tr.querySelector(".unique-chip");
    chip.addEventListener("click", () => openUniqueModal(p.path));

    tbody.appendChild(tr);
  }
}

function updateTestCount() {
  const selectedParams = state.currentParams.filter(p => state.paramChecked[p.path]);
  const hasUniqueFormats = state.currentParams.some(p =>
    state.paramUnique[p.path] || ((state.paramUniquePool[p.path] || {}).values || []).length
  );

  let total = 0;
  selectedParams.forEach(p => {
    const dsKey = state.paramDatasets[p.path] || p.detected;
    total += countRunnableCases(p.path, dsKey);
  });

  const runBtn = $("btn-run-test");
  // Always enabled — button changes label based on mode
  runBtn.disabled = false;

  if (selectedParams.length === 0) {
    if (hasUniqueFormats) {
      $("total-test-count").textContent = "1 single hit (with unique values)";
      runBtn.textContent = "▶ Single Hit";
      runBtn.style.background = "linear-gradient(135deg,#1f6feb,#58a6ff)";
    } else {
      $("total-test-count").textContent = "1 single static hit (Postman-like)";
      runBtn.textContent = "▶ Single Hit";
      runBtn.style.background = "linear-gradient(135deg,#1f6feb,#58a6ff)";
    }
  } else {
    $("total-test-count").textContent = `${total} test cases`;
    runBtn.textContent = "🚀 Run Tests";
    runBtn.style.background = "linear-gradient(135deg,var(--green2),var(--green))";
  }
}

$("btn-select-all-params").addEventListener("click", () => {
  state.currentParams.forEach(p => { state.paramChecked[p.path] = true; });
  renderParamsTable();
  updateTestCount();
  autoSaveCurrentApiConfig();
});

$("btn-deselect-all-params").addEventListener("click", () => {
  state.currentParams.forEach(p => { state.paramChecked[p.path] = false; });
  renderParamsTable();
  updateTestCount();
  autoSaveCurrentApiConfig();
});

// ── Dataset Modal ─────────────────────────────────────────────────────────────
let _modalTargetPath = null;
let _modalCurrentDs = null;
let _modalDatasetQuery = "";

function setupModal() {
  $("modal-close").addEventListener("click", closeModal);
  $("modal-overlay").addEventListener("click", closeModal);
  $("dataset-search")?.addEventListener("input", (e) => {
    _modalDatasetQuery = (e.target.value || "").trim().toLowerCase();
    renderDatasetList();
  });
  setupUniqueModal();
  _setupCasesModal();
}

function openDatasetModal(path, currentDs) {
  _modalTargetPath = path;
  _modalCurrentDs = currentDs;
  _modalDatasetQuery = "";
  $("modal-title").textContent = `Dataset for: ${path}`;
  if ($("dataset-search")) $("dataset-search").value = "";
  $("dataset-modal").style.display = "block";
  renderDatasetList();
}

function renderDatasetList() {
  const list = $("dataset-list");
  list.innerHTML = "";
  const query = _modalDatasetQuery;
  const rows = Object.entries(state.allDatasets).filter(([key, ds]) => {
    if (!query) return true;
    const hay = `${key} ${ds.label || ""} ${ds.hint || ""}`.toLowerCase();
    return hay.includes(query);
  });
  if (!rows.length) {
    list.innerHTML = `<div style="padding:14px;color:var(--text3);font-size:12px">No datasets match this search.</div>`;
    return;
  }
  rows.forEach(([key, ds]) => {
    const opt = document.createElement("div");
    opt.className = `dataset-option${key === _modalCurrentDs ? " selected" : ""}`;
    opt.innerHTML = `
      <div class="ds-info">
        <div class="ds-label">${esc(ds.label)}</div>
        <div class="ds-hint">${esc(ds.hint || "")}</div>
      </div>
      <div class="ds-counts">
        <span class="ds-count-badge pos">${ds.pos_count}P</span>
        <span class="ds-count-badge neg">${ds.neg_count}N</span>
      </div>
    `;
    opt.addEventListener("click", () => {
      state.paramDatasets[_modalTargetPath] = key;
      // Dataset changed → old case-selections no longer valid
      delete state.caseSelections[_modalTargetPath];
      closeModal();
      renderParamsTable();
      updateTestCount();
      autoSaveCurrentApiConfig();
    });
    list.appendChild(opt);
  });
}

function closeModal() {
  $("dataset-modal").style.display = "none";
  _modalTargetPath = null;
  _modalCurrentDs = null;
  _modalDatasetQuery = "";
}

// ── Business Cases Modal ──────────────────────────────────────────────────────
let _casesMPath   = null;   // param path currently being edited
let _casesMDsKey  = null;   // dataset key
let _casesMCases  = [];     // cases list for modal (may include captured_original seed)
let _casesDraft   = {};     // {case_id: "POS"|"NEG"|"SKIP"} — working copy while modal open
let _customDraft  = [];     // [{id,value,cat}] — custom cases working copy

function _buildCasesForModal(path, dsKey) {
  const ds = state.allDatasets[dsKey];
  if (!ds?.cases) return [];
  const cases = ds.cases.map(c => ({ ...c }));
  const p = state.currentParams.find(x => x.path === path);
  if (p && p.value != null && p.value !== "") {
    cases.unshift({
      id: "captured_original",
      cat: "POS",
      desc: "Captured original value",
      val: String(p.value).slice(0, 80),
    });
  }
  return cases;
}

function openCasesModal(path, dsKey) {
  const ds = state.allDatasets[dsKey];
  if (!ds || !ds.cases) return;

  _casesMPath  = path;
  _casesMDsKey = dsKey;
  _casesMCases = _buildCasesForModal(path, dsKey);

  // Initialise draft from saved selections or dataset defaults
  const saved = state.caseSelections[path];
  _casesDraft  = {};
  _casesMCases.forEach(c => {
    _casesDraft[c.id] = saved && saved[c.id] != null ? saved[c.id] : c.cat;
  });

  // Initialise custom cases draft
  _customDraft = (state.customCases[path] || []).map(cc => ({ ...cc }));

  $("cases-modal-param").textContent = `param: ${path}  ·  ${ds.label}`;
  renderCasesModal({ ...ds, cases: _casesMCases });
  _renderCustomList();
  $("cases-modal").style.display = "flex";   // flex for centering
}

function _paintCaseRow(row, c) {
  const stateVal = _casesDraft[c.id] || c.cat;
  const included = stateVal !== "SKIP";
  const isPOS = stateVal === "POS";
  row.className = `cm-case-row${included ? (isPOS ? " cm-row-pos" : " cm-row-neg") : " cm-row-skip"}`;
  const cb = row.querySelector(".cm-cb");
  const badge = row.querySelector(".cm-expect-badge");
  if (cb) cb.checked = included;
  if (badge) {
    if (!included) {
      badge.className = "cm-expect-badge cm-skip";
      badge.textContent = "⏭ SKIP";
      badge.title = "Skipped — click to include as default category";
    } else {
      badge.className = `cm-expect-badge ${isPOS ? "cm-pos" : "cm-neg"}`;
      badge.textContent = isPOS ? "✓ POS" : "✗ NEG";
      badge.title = "Click to flip POS ↔ NEG";
    }
  }
}

function renderCasesModal(ds) {
  const list = $("cases-list");
  list.innerHTML = "";

  // Group: POS first, NEG below (with section headers)
  ["POS", "NEG"].forEach(grp => {
    const groupCases = ds.cases.filter(c => c.cat === grp);
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
        ? `<span style="opacity:0.6;font-size:10px;margin-right:4px;font-weight:600;">e.g.</span>${esc(c.val)}`
        : esc(c.val);
      const valTitle = isPOS
        ? "Example template — unique value generated dynamically per run"
        : "Static test value";
      row.innerHTML = `
        <input type="checkbox" class="cm-cb" data-id="${esc(c.id)}" title="Include in run">
        <div class="cm-case-info">
          <span class="cm-case-desc">${esc(c.desc)}</span>
          <code class="cm-case-val" title="${valTitle}">${valHtml}</code>
        </div>
        <span class="cm-expect-badge"></span>
      `;
      _paintCaseRow(row, c);

      const cb = row.querySelector(".cm-cb");
      const badge = row.querySelector(".cm-expect-badge");

      // Checkbox = include / SKIP
      cb.addEventListener("change", () => {
        if (cb.checked) {
          // Restore last POS/NEG or dataset default
          const prev = _casesDraft[c.id];
          _casesDraft[c.id] = (prev === "POS" || prev === "NEG") ? prev : c.cat;
        } else {
          _casesDraft[c.id] = "SKIP";
        }
        _paintCaseRow(row, c);
        _updateCasesCount();
      });

      // Badge = flip POS/NEG when included; re-include when skipped
      badge.addEventListener("click", (e) => {
        e.stopPropagation();
        if (_casesDraft[c.id] === "SKIP") {
          _casesDraft[c.id] = c.cat;
        } else {
          _casesDraft[c.id] = _casesDraft[c.id] === "POS" ? "NEG" : "POS";
        }
        _paintCaseRow(row, c);
        _updateCasesCount();
      });

      list.appendChild(row);
    });
  });

  _updateCasesCount();
}

function _updateCasesCount() {
  const vals    = Object.values(_casesDraft);
  const posN    = vals.filter(v => v === "POS").length;
  const negN    = vals.filter(v => v === "NEG").length;
  const skipN   = vals.filter(v => v === "SKIP").length;
  const runN    = posN + negN;
  const custN   = _customDraft.length;
  const custPos = _customDraft.filter(c => c.cat === "POS").length;
  const custNeg = _customDraft.filter(c => c.cat === "NEG").length;
  const customPart = custN ? `  ·  +${custPos} custom POS  +${custNeg} custom NEG` : "";
  $("cases-count-label").textContent =
    `${runN} run · ${posN} POS · ${negN} NEG · ${skipN} skipped${customPart}`;
}

function _renderCustomList() {
  const listEl = $("cm-custom-list");
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!_customDraft.length) return;

  _customDraft.forEach((cc, i) => {
    const row = document.createElement("div");
    row.className = "cm-custom-row";
    row.innerHTML = `
      <span class="cm-expect-badge ${cc.cat === "POS" ? "cm-pos" : "cm-neg"}" style="cursor:pointer"
            title="Click to toggle POS/NEG">${cc.cat === "POS" ? "✓ POS" : "✗ NEG"}</span>
      <code class="cm-custom-val">${esc(String(cc.value))}</code>
      <button class="cm-custom-del" data-idx="${i}" title="Remove">✕</button>
    `;
    // Toggle cat
    row.querySelector(".cm-expect-badge").addEventListener("click", () => {
      _customDraft[i].cat = _customDraft[i].cat === "POS" ? "NEG" : "POS";
      _renderCustomList();
      _updateCasesCount();
    });
    // Delete
    row.querySelector(".cm-custom-del").addEventListener("click", () => {
      _customDraft.splice(i, 1);
      _renderCustomList();
      _updateCasesCount();
    });
    listEl.appendChild(row);
  });
}

function _setupCasesModal() {
  $("cases-modal-overlay").addEventListener("click", _closeCasesModal);
  $("cases-modal-close").addEventListener("click", _closeCasesModal);
  $("cases-cancel-btn").addEventListener("click", _closeCasesModal);

  // ── Custom case: POS/NEG toggle button ──────────────────────────────────
  $("cm-custom-cat-btn").addEventListener("click", () => {
    const btn = $("cm-custom-cat-btn");
    const isPos = btn.classList.contains("cm-cat-pos");
    if (isPos) {
      btn.classList.replace("cm-cat-pos", "cm-cat-neg");
      btn.textContent = "✗ NEG";
    } else {
      btn.classList.replace("cm-cat-neg", "cm-cat-pos");
      btn.textContent = "✓ POS";
    }
  });

  // ── Custom case: Add button + Enter key ──────────────────────────────────
  const _addCustomCase = () => {
    const inp = $("cm-custom-input");
    const val = inp.value.trim();
    if (!val) { inp.focus(); return; }
    const catBtn = $("cm-custom-cat-btn");
    const cat    = catBtn.classList.contains("cm-cat-pos") ? "POS" : "NEG";
    _customDraft.push({ id: Date.now() + Math.random(), value: val, cat });
    inp.value = "";
    inp.focus();
    _renderCustomList();
    _updateCasesCount();
  };
  $("cm-custom-add-btn").addEventListener("click", _addCustomCase);
  $("cm-custom-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); _addCustomCase(); }
  });

  // ── Include all / Skip all ────────────────────────────────────────────────
  const includeAllBtn = $("cases-include-all-btn");
  if (includeAllBtn) {
    includeAllBtn.addEventListener("click", () => {
      const ds = state.allDatasets[_casesMDsKey];
      if (!ds) return;
      _casesMCases.forEach(c => {
        if (_casesDraft[c.id] === "SKIP") _casesDraft[c.id] = c.cat;
      });
      renderCasesModal({ ...ds, cases: _casesMCases });
    });
  }
  const skipAllBtn = $("cases-skip-all-btn");
  if (skipAllBtn) {
    skipAllBtn.addEventListener("click", () => {
      const ds = state.allDatasets[_casesMDsKey];
      if (!ds) return;
      _casesMCases.forEach(c => { _casesDraft[c.id] = "SKIP"; });
      renderCasesModal({ ...ds, cases: _casesMCases });
    });
  }

  // ── Reset ─────────────────────────────────────────────────────────────────
  $("cases-reset-btn").addEventListener("click", () => {
    const ds = state.allDatasets[_casesMDsKey];
    if (!ds) return;
    _casesMCases = _buildCasesForModal(_casesMPath, _casesMDsKey);
    _casesMCases.forEach(c => { _casesDraft[c.id] = c.cat; });
    _customDraft = [];
    renderCasesModal({ ...ds, cases: _casesMCases });
    _renderCustomList();
  });

  // ── Save ──────────────────────────────────────────────────────────────────
  $("cases-save-btn").addEventListener("click", () => {
    if (!_casesMPath) return;

    // Case selections (POS/NEG/SKIP); omit store when all match defaults
    const isDefault = _casesMCases.every(c => _casesDraft[c.id] === c.cat);
    if (isDefault) {
      delete state.caseSelections[_casesMPath];
    } else {
      state.caseSelections[_casesMPath] = { ..._casesDraft };
    }

    // Custom cases
    if (_customDraft.length) {
      state.customCases[_casesMPath] = _customDraft.map(cc => ({ ...cc }));
    } else {
      delete state.customCases[_casesMPath];
    }

    _closeCasesModal();
    renderParamsTable();
    updateTestCount();
    autoSaveCurrentApiConfig();
  });
}

function _closeCasesModal() {
  $("cases-modal").style.display = "none";
  _casesMPath  = null;
  _casesMDsKey = null;
  _casesMCases = [];
  _casesDraft  = {};
  _customDraft = [];
  // Reset cat toggle back to POS
  const catBtn = $("cm-custom-cat-btn");
  if (catBtn) {
    catBtn.className = "cm-cat-toggle cm-cat-pos";
    catBtn.textContent = "✓ POS";
  }
  const inp = $("cm-custom-input");
  if (inp) inp.value = "";
}

// ── Unique Format Modal ───────────────────────────────────────────────────────
let _uniqueTargetPath = null;
let _uniquePoolDraft = null; // { matched, filename, row_count }

function avCollectUniquePools() {
  const pools = {};
  Object.entries(state.paramUniquePool || {}).forEach(([path, rec]) => {
    if (!rec) return;
    let vals = Array.isArray(rec.values)
      ? rec.values.map(v => String(v).trim()).filter(Boolean)
      : [];
    // Auto-reset if working values were exhausted from earlier run
    if (!vals.length && Array.isArray(rec.all_values) && rec.all_values.length > 0) {
      rec.values = rec.all_values.slice();
      vals = rec.values.map(v => String(v).trim()).filter(Boolean);
    }
    if (vals.length) pools[path] = vals;
  });
  return pools;
}

function avTrimUniquePools(idx) {
  if (idx == null || Number.isNaN(Number(idx)) || Number(idx) < 0) return;
  const n = Number(idx);
  Object.keys(state.paramUniquePool || {}).forEach(path => {
    const rec = state.paramUniquePool[path];
    if (!rec || !Array.isArray(rec.values)) return;
    rec.values = rec.values.slice(n);
    // Note: We DO NOT delete state.paramUniquePool[path]!
    // Keeping it preserves rec.all_values, rec.filename, and rec.header so it auto-resets on next run.
  });
}

function setupAvMessageModal() {
  const close = () => {
    const m = $("av-msg-modal");
    if (m) m.style.display = "none";
  };
  $("av-msg-modal-ok")?.addEventListener("click", close);
  $("av-msg-modal-overlay")?.addEventListener("click", close);
}

function avRenderPoolPreview(matched, filename, rowCount, targetPath, totalCount) {
  const box = $("um-pool-preview");
  const label = $("um-pool-file-label");
  const resetBtn = $("um-pool-reset-btn");
  if (!box) return;
  if (!matched || !Object.keys(matched).length) {
    box.style.display = "none";
    if (label) label.textContent = "";
    if (resetBtn) resetBtn.style.display = "none";
    return;
  }
  if (label) label.textContent = filename || "";
  if (resetBtn) {
    const hasUsed = totalCount != null && rowCount != null && totalCount > rowCount;
    resetBtn.style.display = hasUsed ? "inline-block" : "none";
  }
  const lines = Object.entries(matched).map(([path, vals]) => {
    const n = (vals || []).length;
    const sample = (vals || []).slice(0, 3).join(", ");
    const mark = path === targetPath ? "  ← this param" : "";
    return `${path}: ${n} available${mark}${sample ? `\n  e.g. ${sample}` : ""}`;
  });
  const countHeader = totalCount != null && totalCount !== rowCount
    ? `${rowCount} remaining of ${totalCount} original row(s) (auto-resets when exhausted)`
    : `${rowCount} row(s) available (auto-resets when exhausted)`;
  box.textContent = `${countHeader}\n` + lines.join("\n");
  box.style.display = "block";
}

function avFileToBase64(file) {
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

function avCommitPoolDraft(draft, clearFormatPaths) {
  if (!draft || !draft.matched) return;
  Object.entries(draft.matched).forEach(([path, vals]) => {
    const values = (vals || []).map(v => String(v).trim()).filter(Boolean);
    if (!values.length) return;
    state.paramUniquePool[path] = {
      all_values: values.slice(),
      values: values.slice(),
      filename: draft.filename || "",
      header: path,
    };
    if (clearFormatPaths) state.paramUnique[path] = "";
  });
}

async function avImportUniquePoolFile(file) {
  if (!file) return;
  const paramPaths = (state.currentParams || []).map(p => p.path);
  const content_b64 = await avFileToBase64(file);
  const data = await fetchBackend("/parse-unique-pool", "POST", {
    filename: file.name || "values.csv",
    content_b64,
    param_paths: paramPaths,
    target_path: _uniqueTargetPath || "",
  });
  const matched = data.matched || {};
  if (_uniqueTargetPath && !matched[_uniqueTargetPath]) {
    throw new Error(
      `No column matched this param (${_uniqueTargetPath}). Headers: ${(data.headers || []).join(", ") || "(none)"}`
    );
  }
  _uniquePoolDraft = {
    matched,
    filename: data.filename || file.name,
    row_count: data.row_count || 0,
  };
  avRenderPoolPreview(matched, _uniquePoolDraft.filename, _uniquePoolDraft.row_count, _uniqueTargetPath, _uniquePoolDraft.row_count);
}

function setupUniqueModal() {
  $("unique-modal-overlay").addEventListener("click", closeUniqueModal);
  $("unique-modal-close").addEventListener("click", closeUniqueModal);
  $("um-cancel-btn").addEventListener("click", closeUniqueModal);

  $("um-clear-btn").addEventListener("click", () => {
    $("unique-format-input").value = "";
    $("um-preview-box").style.display = "none";
    document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("selected"));
    _uniquePoolDraft = { matched: {}, filename: "", row_count: 0, cleared: true };
    avRenderPoolPreview(null);
  });

  $("um-preview-btn").addEventListener("click", () => {
    const fmt = $("unique-format-input").value.trim();
    if (!fmt) return;
    const preview = previewFormat(fmt);
    $("um-preview-val").textContent = preview;
    $("um-preview-box").style.display = "flex";
  });

  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const fmt = btn.dataset.fmt;
      $("unique-format-input").value = fmt;
      document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      const preview = previewFormat(fmt);
      $("um-preview-val").textContent = preview;
      $("um-preview-box").style.display = "flex";
    });
  });

  $("um-pool-import-btn")?.addEventListener("click", () => $("um-pool-file")?.click());
  $("um-pool-file")?.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    try {
      await avImportUniquePoolFile(file);
    } catch (err) {
      _uniquePoolDraft = null;
      avRenderPoolPreview(null);
      let msg = err.message || String(err);
      const brace = msg.indexOf("{");
      if (brace >= 0) {
        try {
          const j = JSON.parse(msg.slice(brace));
          if (j.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
        } catch (_) {}
      }
      showAvMessage("Import failed", msg);
    }
  });

  $("um-pool-reset-btn")?.addEventListener("click", () => {
    if (_uniqueTargetPath && state.paramUniquePool[_uniqueTargetPath]) {
      const rec = state.paramUniquePool[_uniqueTargetPath];
      if (Array.isArray(rec.all_values)) {
        rec.values = rec.all_values.slice();
        const existing = {};
        Object.entries(state.paramUniquePool || {}).forEach(([p, r]) => {
          if (r && r.values && r.values.length) existing[p] = r.values;
        });
        avRenderPoolPreview(existing, rec.filename, rec.values.length, _uniqueTargetPath, rec.all_values.length);
        renderParamsTable();
        showConfigToast("✓ Test data pool reset to all rows");
      }
    }
  });

  $("um-ok-btn").addEventListener("click", () => {
    const fmt = $("unique-format-input").value.trim();
    if (_uniqueTargetPath !== null) {
      if (_uniquePoolDraft && _uniquePoolDraft.cleared) {
        delete state.paramUniquePool[_uniqueTargetPath];
        state.paramUnique[_uniqueTargetPath] = fmt;
      } else if (_uniquePoolDraft && _uniquePoolDraft.matched) {
        avCommitPoolDraft(_uniquePoolDraft, true);
      } else {
        state.paramUnique[_uniqueTargetPath] = fmt;
        if (fmt) delete state.paramUniquePool[_uniqueTargetPath];
      }
    }
    closeUniqueModal();
    renderParamsTable();
    updateTestCount();
    autoSaveCurrentApiConfig();
  });
}

function openUniqueModal(path) {
  _uniqueTargetPath = path;
  _uniquePoolDraft = null;
  $("unique-modal-param").textContent = "param: " + path;
  const current = state.paramUnique[path] || "";
  $("unique-format-input").value = current;
  $("um-preview-box").style.display = "none";
  document.querySelectorAll(".preset-btn").forEach(b => {
    b.classList.toggle("selected", b.dataset.fmt === current);
  });
  if (current) {
    $("um-preview-val").textContent = previewFormat(current);
    $("um-preview-box").style.display = "flex";
  }

  const rec = (state.paramUniquePool || {})[path];
  const totalCount = rec && Array.isArray(rec.all_values) ? rec.all_values.length : (rec && Array.isArray(rec.values) ? rec.values.length : 0);
  const remainingCount = rec && Array.isArray(rec.values) ? rec.values.length : totalCount;

  const existing = {};
  Object.entries(state.paramUniquePool || {}).forEach(([p, r]) => {
    const vals = (r && Array.isArray(r.values) && r.values.length > 0)
      ? r.values
      : (r && Array.isArray(r.all_values) ? r.all_values : []);
    if (vals.length) existing[p] = vals;
  });
  const fname = (state.paramUniquePool[path] || {}).filename
    || (Object.values(state.paramUniquePool || {})[0] || {}).filename
    || "";
  if (totalCount > 0) {
    avRenderPoolPreview(existing, fname, remainingCount, path, totalCount);
  } else if (rec && rec.requires_file && fname) {
    const label = $("um-pool-file-label");
    if (label) label.textContent = `Previous: ${fname} (Upload fresh file)`;
    avRenderPoolPreview(null);
  } else {
    avRenderPoolPreview(null);
  }
  $("unique-modal").style.display = "block";
}

function closeUniqueModal() {
  $("unique-modal").style.display = "none";
  _uniqueTargetPath = null;
  _uniquePoolDraft = null;
}

// Client-side preview generator (matches backend logic)
function previewFormat(fmt) {
  if (!fmt) return "";
  const chars = "abcdefghijklmnopqrstuvwxyz";
  const anum  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const nums  = "0123456789";
  const names = ["Alice Smith","Bob Jones","Carol Brown","Dave Wilson","Eva Moore"];

  return fmt.replace(/\{([^}]+)\}/g, (_, token) => {
    token = token.toLowerCase().trim();
    if (token === "uuid") {
      return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
        const r = Math.random()*16|0;
        return (c==="x"?r:(r&0x3|0x8)).toString(16);
      });
    }
    if (token === "email") {
      const u = Array.from({length:8},()=>anum[Math.random()*anum.length|0]).join("");
      return u + "@testapi.com";
    }
    if (token === "name") return names[Math.random()*names.length|0];
    const parts = token.split(":");
    const kind = parts[0]; const n = parseInt(parts[1]) || 8;
    if (kind === "alpha")    return Array.from({length:n},()=>chars[Math.random()*chars.length|0]).join("");
    if (kind === "alphanum") return Array.from({length:n},()=>anum[Math.random()*anum.length|0]).join("");
    if (kind === "num")      return Array.from({length:n},()=>nums[Math.random()*nums.length|0]).join("");
    return `{${token}}`;
  });
}

// ── Single Hit ────────────────────────────────────────────────────────────────
async function runSingleHit(req) {
  const overlay = $("running-overlay");
  overlay.style.display = "flex";
  switchTab("results");
  $("results-empty").style.display = "none";
  $("results-content").style.display = "none";
  resetRunningOverlay("Single Hit...");
  const abortBtn = $("btn-abort-run");
  if (abortBtn) abortBtn.classList.add("is-hidden");
  updateRunProgress(30, 0, 1, "Firing single request...");

  const uniqueFormats = {};
  const uniquePools = avCollectUniquePools();
  state.currentParams.forEach(p => {
    if (uniquePools[p.path]) return;
    if (state.paramUnique[p.path]) uniqueFormats[p.path] = state.paramUnique[p.path];
  });

  const effectiveReq = buildEffectiveRequest(req);
  const payload = {
    url:            effectiveReq.url,
    method:         effectiveReq.method,
    headers:        stripBadHeaders(effectiveReq.headers || {}),
    query:          effectiveReq.queryParams || {},
    body:           effectiveReq.body || null,
    body_type:      effectiveReq.body_type || null,
    unique_formats: uniqueFormats,
    unique_pools:   uniquePools,
  };

  try {
    const data = await fetchBackend("/run-single", "POST", payload);
    avTrimUniquePools(data.pool_index);
    renderParamsTable();
    if (data.pool_exhausted) {
      showAvMessage(
        "Unique list exhausted",
        data.message || "No unused values left in the imported list. Import more and re-run."
      );
    }
    updateRunProgress(100, 1, 1, "✅ Done");
    await new Promise(r => setTimeout(r, 280));
    state.testResults = avStampRequestMeta(data, effectiveReq);
    renderResults(state.testResults);
  } catch(e) {
    alert("Run failed: " + e.message);
    $("results-empty").style.display = "flex";
  } finally {
    overlay.style.display = "none";
    $("results-content").style.display = "flex";
  }
}

// ── Run Tests ─────────────────────────────────────────────────────────────────
let _runAbortController = null;
let _runUserAborted = false;

function setupActions() {
  $("btn-run-test").addEventListener("click", runTests);
  $("btn-export-csv").addEventListener("click", exportCsv);
  $("btn-export-html").addEventListener("click", exportHtml);
  $("btn-export-runner").addEventListener("click", exportToApisphereRunner);
  $("btn-back-to-params").addEventListener("click", () => switchTab("params"));
  const btnSaveParams = $("btn-save-params");
  if (btnSaveParams) {
    btnSaveParams.addEventListener("click", () => saveCurrentApiConfig(true));
  }
  const btnResetParams = $("btn-reset-params");
  if (btnResetParams) {
    btnResetParams.addEventListener("click", () => resetCurrentApiConfig());
  }
  const abortBtn = $("btn-abort-run");
  if (abortBtn) {
    abortBtn.addEventListener("click", () => {
      _runUserAborted = true;
      abortBtn.disabled = true;
      abortBtn.textContent = "Aborting…";
      appendRunFeed("info", "Abort requested — stopping after current case…");
      if ($("running-title")) $("running-title").textContent = "Aborting…";
      if (_runAbortController) _runAbortController.abort();
    });
  }
}

function resetRunningOverlay(title) {
  if ($("running-title")) $("running-title").textContent = title || "Running Tests...";
  if ($("running-pct")) $("running-pct").textContent = "0%";
  if ($("running-progress-fill")) $("running-progress-fill").style.width = "0%";
  if ($("running-progress-label")) $("running-progress-label").textContent = "Preparing...";
  const feed = $("running-live-feed");
  if (feed) {
    feed.innerHTML = "";
    feed.classList.remove("has-lines");
  }
  const abortBtn = $("btn-abort-run");
  if (abortBtn) {
    abortBtn.disabled = false;
    abortBtn.textContent = "Abort";
    abortBtn.classList.remove("is-hidden");
  }
}

function updateRunProgress(pct, done, total, label) {
  const safePct = Math.max(0, Math.min(100, pct));
  if ($("running-pct")) $("running-pct").textContent = safePct + "%";
  if ($("running-progress-fill")) $("running-progress-fill").style.width = safePct + "%";
  if ($("running-progress-label")) {
    $("running-progress-label").textContent = label || (
      safePct < 100
        ? `Testing ${done} / ${total} cases...`
        : `✅ ${total} tests complete`
    );
  }
}

function appendRunFeed(kind, text) {
  const feed = $("running-live-feed");
  if (!feed) return;
  feed.classList.add("has-lines");
  const line = document.createElement("div");
  line.className = "feed-line feed-" + (kind || "info");
  line.textContent = text;
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
}

function feedKindForResult(result) {
  if (result === "PASS") return "pass";
  if (result === "FAIL") return "fail";
  if (result === "WARN") return "warn";
  if (result === "ERROR") return "fail";
  return "info";
}

function truncateFeedVal(v, n) {
  const s = v === null || v === undefined ? "null" : String(v);
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function summarizePartialResults(results) {
  const s = {
    total: results.length, passed: 0, failed: 0, warned: 0,
    pos_pass: 0, pos_fail: 0, neg_pass: 0, neg_fail: 0, health_pct: 0,
  };
  results.forEach(r => {
    if (r.result === "PASS") s.passed++;
    else if (r.result === "FAIL") s.failed++;
    else if (r.result === "WARN") s.warned++;
    if (r.case_cat === "POS") {
      if (r.result === "PASS") s.pos_pass++;
      else if (r.result === "FAIL") s.pos_fail++;
    } else {
      if (r.result === "PASS") s.neg_pass++;
      else if (r.result === "FAIL") s.neg_fail++;
    }
  });
  s.health_pct = s.total ? Math.round((s.passed / s.total) * 100) : 0;
  return s;
}

async function consumeRunTestsStream(payload, totalExpected, signal) {
  let results = [];
  let summary = null;
  let expected = totalExpected;
  let aborted = false;
  let finalPayload = null;

  const packPartial = (wasAborted) => ({
    aborted: !!wasAborted,
    results,
    summary: summary || summarizePartialResults(results),
  });

  const handleEvent = (ev) => {
    if (!ev || !ev.type) return;
    if (ev.type === "start") {
      expected = ev.total_expected || expected;
      const skipped = String(ev.baseline_status || "").toLowerCase() === "skipped";
      const baseOk = ev.baseline_ok !== false && !ev.auth_expired;
      appendRunFeed(
        ev.auth_expired ? "fail" : "info",
        ev.auth_expired
          ? `Baseline ${ev.baseline_status} · AUTH FAILED — stopping`
          : skipped
            ? `No extra baseline (write API) · first case is the first request · ${expected} cases queued`
            : `Baseline ${ev.baseline_status}${baseOk ? "" : " (not 2xx)"} · ${expected} cases queued`
      );
      updateRunProgress(0, 0, expected);
      return;
    }
    if (ev.type === "case") {
      const row = ev.result;
      results.push(row);
      summary = ev.summary || summary;
      expected = ev.total_expected || expected;
      const done = ev.done || results.length;
      const pct = expected ? Math.round((done / expected) * 100) : 0;
      updateRunProgress(pct, done, expected);
      const reasonBit = row.fail_reason ? ` · ${truncateFeedVal(row.fail_reason, 48)}` : "";
      appendRunFeed(
        feedKindForResult(row.result),
        `${row.result}  ${row.param}  ${row.case_id}  → ${row.status_code}  (${truncateFeedVal(row.test_value, 28)})${reasonBit}`
      );
      return;
    }
    if (ev.type === "done") {
      aborted = !!ev.aborted;
      results = Array.isArray(ev.results) ? ev.results : results;
      summary = ev.summary || summary;
      finalPayload = {
        summary,
        results,
        aborted,
        auth_expired: !!(ev.auth_expired || summary?.auth_expired),
        pool_exhausted: !!ev.pool_exhausted,
        pool_index: ev.pool_index,
        message: ev.message || "",
      };
      return;
    }
    if (ev.type === "error") {
      throw new Error(ev.message || "Stream error");
    }
  };

  try {
    const resp = await fetch(`${BACKEND}/run-tests-stream`, {
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
    // User abort / disconnect: return whatever cases we already received
    if (e.name === "AbortError" || _runUserAborted) {
      return packPartial(true);
    }
    throw e;
  }

  return finalPayload || packPartial(_runUserAborted || aborted);
}

async function runTests() {
  const req = getLiveRequest();
  if (!req) {
    alert("Select an API and open Params first.");
    return;
  }
  // Keep analyzed freeze in sync so exports also see latest headers/body
  if (state.analyzedData) {
    state.analyzedData._req = req;
  }

  const selectedParams = state.currentParams
    .filter(p => state.paramChecked[p.path])
    .map(p => ({
      path:            p.path,
      dataset_key:     state.paramDatasets[p.path] || p.detected,
      unique_format:   state.paramUnique[p.path] || null,
      case_selections: state.caseSelections[p.path] || null,
      custom_cases:    (state.customCases[p.path] || []).map(cc => ({value: cc.value, cat: cc.cat})),
    }));

  // No checkboxes selected → single hit mode (static or with unique values)
  if (!selectedParams.length) {
    await runSingleHit(req);
    return;
  }

  const overlay = $("running-overlay");
  overlay.style.display = "flex";
  switchTab("results");
  $("results-empty").style.display = "none";
  $("results-content").style.display = "none";
  resetRunningOverlay("Running Tests...");
  _runUserAborted = false;
  _runAbortController = new AbortController();

  let totalExpected = 0;
  selectedParams.forEach(sp => {
    totalExpected += countRunnableCases(sp.path, sp.dataset_key);
  });
  if (totalExpected === 0) {
    overlay.style.display = "none";
    alert("All cases are skipped for the selected params. Include at least one case in 🔬 Cases.");
    return;
  }
  updateRunProgress(0, 0, totalExpected, "Connecting…");

  try {
    const allUniqueFormats = {};
    const uniquePools = avCollectUniquePools();
    state.currentParams.forEach(p => {
      if (uniquePools[p.path]) return;
      if (state.paramUnique[p.path]) {
        allUniqueFormats[p.path] = state.paramUnique[p.path];
      }
    });

    const effectiveReq = req;
    const bodySelectedParams  = selectedParams.filter(p => !p.path.startsWith("query."));
    const querySelectedParams = selectedParams
      .filter(p => p.path.startsWith("query."))
      .map(p => ({ ...p, path: p.path.replace(/^query\./, "") }));

    const payload = {
      url:            effectiveReq.url,
      method:         effectiveReq.method,
      headers:        stripBadHeaders(effectiveReq.headers || {}),
      query:          effectiveReq.queryParams || {},
      body:           effectiveReq.body || null,
      body_type:      effectiveReq.body_type || null,
      selected_params: bodySelectedParams,
      query_selected_params: querySelectedParams,
      all_unique_formats: allUniqueFormats,
      unique_pools: uniquePools,
      delay_ms: Math.max(0, parseInt($("bulk-delay-ms")?.value, 10) || 0),
    };

    const data = await consumeRunTestsStream(
      payload, totalExpected, _runAbortController.signal
    );

    const total = data.summary?.total || data.results?.length || 0;
    const aborted = !!(data.aborted || _runUserAborted);
    const authExpired = !!(data.auth_expired || data.summary?.auth_expired);
    const poolExhausted = !!data.pool_exhausted;
    avTrimUniquePools(data.pool_index);
    updateRunProgress(
      100,
      total,
      total,
      authExpired
        ? `⛔ Auth expired — ${total} result(s)`
        : poolExhausted
          ? `⏹ Unique list exhausted — ${total} result(s)`
        : aborted
          ? `⏹ Aborted — ${total} result(s)`
          : `✅ ${total} tests complete`
    );
    if ($("running-title")) {
      $("running-title").textContent = authExpired
        ? "Stopped — auth expired"
        : poolExhausted
          ? "Stopped — unique list exhausted"
        : aborted
          ? "Scan aborted"
          : "Running Tests...";
    }
    if (authExpired) {
      appendRunFeed("fail", "Auth expired (401) — update token in Details and re-run");
    } else if (poolExhausted) {
      appendRunFeed("warn", data.message || "Unique value list exhausted — scan stopped");
    } else if (aborted) {
      appendRunFeed("warn", `Stopped early · showing ${total} completed case(s)`);
    }
    await new Promise(r => setTimeout(r, aborted || poolExhausted ? 450 : 280));

    if (!data.results || !data.results.length) {
      $("results-empty").style.display = "flex";
      $("results-content").style.display = "none";
      state.testResults = null;
    } else {
      state.testResults = avStampRequestMeta(
        { summary: data.summary, results: data.results },
        effectiveReq
      );
      renderResults(state.testResults);
    }
    if (poolExhausted) {
      showAvMessage(
        "Unique list exhausted",
        data.message || "Imported unique values ran out. Scan stopped. Import more unused values and re-run."
      );
    }
  } catch (e) {
    alert("Test run failed: " + e.message);
    $("results-empty").style.display = "flex";
  } finally {
    _runAbortController = null;
    overlay.style.display = "none";
    const abortBtn = $("btn-abort-run");
    if (abortBtn) {
      abortBtn.disabled = false;
      abortBtn.textContent = "Abort";
    }
  }
}

// ── Multi-API Sequential Runner & Bulk Modal ─────────────────────────────────

function extractValueByPath(path, bodyObj, queryObj) {
  if (!path) return null;
  if (path.startsWith("query.")) {
    const qKey = path.slice(6);
    return queryObj?.[qKey] ?? null;
  }
  let bPath = path.startsWith("body.") ? path.slice(5) : path;
  if (!bodyObj || typeof bodyObj !== "object") return null;
  const parts = bPath.split(".");
  let cur = bodyObj;
  for (const part of parts) {
    if (cur == null || typeof cur !== "object") return null;
    cur = cur[part];
  }
  return cur !== undefined ? cur : null;
}

function getEffectiveParamsForConfig(cfg, req) {
  if (!cfg) return [];
  const existingParams = Array.isArray(cfg.currentParams) ? cfg.currentParams : [];

  const configuredPaths = new Set();
  if (cfg.paramChecked) {
    Object.entries(cfg.paramChecked).forEach(([p, checked]) => {
      if (checked) configuredPaths.add(p);
    });
  }
  if (cfg.caseSelections) {
    Object.entries(cfg.caseSelections).forEach(([p, selMap]) => {
      if (selMap && typeof selMap === "object" && Object.values(selMap).some(v => v === "POS" || v === "NEG")) {
        configuredPaths.add(p);
      }
    });
  }
  if (cfg.customCases) {
    Object.entries(cfg.customCases).forEach(([p, cases]) => {
      if (Array.isArray(cases) && cases.length > 0) {
        configuredPaths.add(p);
      }
    });
  }
  if (cfg.paramDatasets) {
    Object.keys(cfg.paramDatasets).forEach(p => configuredPaths.add(p));
  }
  if (cfg.paramUnique) {
    Object.entries(cfg.paramUnique).forEach(([p, fmt]) => {
      if (fmt) configuredPaths.add(p);
    });
  }
  if (cfg.paramUniquePool) {
    Object.entries(cfg.paramUniquePool).forEach(([p, rec]) => {
      let len = 0;
      if (Array.isArray(rec)) len = rec.length;
      else if (rec && Array.isArray(rec.all_values)) len = rec.all_values.length;
      else if (rec && Array.isArray(rec.values)) len = rec.values.length;
      if (len > 0) configuredPaths.add(p);
    });
  }

  const existingPathMap = new Map();
  existingParams.forEach(p => {
    if (p && p.path) existingPathMap.set(p.path, p);
  });

  let parsedBody = null;
  if (req?.body) {
    if (typeof req.body === "object") parsedBody = req.body;
    else if (typeof req.body === "string") {
      try { parsedBody = JSON.parse(req.body); } catch (e) {}
    }
  }
  let parsedQuery = { ...(req?.queryParams || {}) };
  if (req?.url) {
    try {
      const u = new URL(req.url);
      u.searchParams.forEach((v, k) => {
        if (parsedQuery[k] === undefined) parsedQuery[k] = v;
      });
    } catch (e) {}
  }

  const result = [...existingParams];

  configuredPaths.forEach(path => {
    if (!existingPathMap.has(path)) {
      const isQuery = path.startsWith("query.");
      const dsKey = cfg.paramDatasets?.[path] || "string";
      const val = extractValueByPath(path, parsedBody, parsedQuery);
      const newParam = {
        path: path,
        detected: dsKey,
        detected_label: dsKey,
        is_query_param: isQuery,
        location: isQuery ? "query" : "body",
        value: val,
        datasets: [dsKey],
      };
      result.push(newParam);
      existingPathMap.set(path, newParam);
    }
  });

  return result;
}

function countRunnableCasesForConfig(cfg, path, dsKey) {
  if (!cfg) return 0;
  const ds = state.allDatasets?.[dsKey];
  const sel = (cfg.caseSelections || {})[path];
  let n = 0;
  if (ds?.cases) {
    ds.cases.forEach(c => {
      const v = sel && sel[c.id] != null ? sel[c.id] : c.cat;
      if (v !== "SKIP") n++;
    });
  } else if (sel && typeof sel === "object") {
    const activeSel = Object.values(sel).filter(v => v === "POS" || v === "NEG").length;
    if (activeSel > 0) {
      n += activeSel;
    }
  }
  const p = (cfg.currentParams || []).find(x => x.path === path);
  if (p && p.value != null && p.value !== "") {
    const seedSel = sel && sel.captured_original != null ? sel.captured_original : "POS";
    if (seedSel !== "SKIP") n += 1;
  }
  n += ((cfg.customCases || {})[path] || []).length;
  return n;
}

function countExpectedCasesForConfig(cfg, req) {
  if (!cfg) return 0;
  const currentParams = getEffectiveParamsForConfig(cfg, req);
  const paramDatasets = cfg.paramDatasets || {};

  let total = 0;
  currentParams.forEach(p => {
    if (isConfiguredParamRunnable(cfg, p.path)) {
      const dsKey = paramDatasets[p.path] || p.detected || "string";
      total += countRunnableCasesForConfig(cfg, p.path, dsKey);
    }
  });
  return total;
}

function buildRunPayloadForConfig(req, cfg, delayMs) {
  if (!cfg) cfg = {};
  const currentParams = getEffectiveParamsForConfig(cfg, req);
  const paramDatasets = cfg.paramDatasets || {};
  const paramUnique = cfg.paramUnique || {};
  const caseSelections = cfg.caseSelections || {};
  const customCases = cfg.customCases || {};

  const selectedParams = currentParams
    .filter(p => isConfiguredParamRunnable(cfg, p.path))
    .map(p => ({
      path: p.path,
      dataset_key: paramDatasets[p.path] || p.detected || "string",
      unique_format: paramUnique[p.path] || null,
      case_selections: caseSelections[p.path] || null,
      custom_cases: (customCases[p.path] || []).map(cc => ({ value: cc.value, cat: cc.cat })),
    }));

  const allUniqueFormats = {};
  const uniquePools = {};
  if (cfg.paramUniquePool) {
    Object.entries(cfg.paramUniquePool).forEach(([path, rec]) => {
      let vals = [];
      if (Array.isArray(rec)) {
        vals = rec;
      } else if (rec && Array.isArray(rec.values) && rec.values.length > 0) {
        vals = rec.values;
      } else if (rec && Array.isArray(rec.all_values) && rec.all_values.length > 0) {
        vals = rec.all_values;
      }
      vals = vals.map(v => String(v).trim()).filter(Boolean);
      if (vals.length > 0) {
        uniquePools[path] = vals;
      }
    });
  }
  currentParams.forEach(p => {
    if (uniquePools[p.path]) return;
    if (paramUnique[p.path]) {
      allUniqueFormats[p.path] = paramUnique[p.path];
    }
  });

  const bodySelectedParams = selectedParams.filter(p => !p.path.startsWith("query."));
  const querySelectedParams = selectedParams
    .filter(p => p.path.startsWith("query."))
    .map(p => ({ ...p, path: p.path.replace(/^query\./, "") }));

  return {
    url: req.url,
    method: req.method,
    headers: stripBadHeaders(req.headers || {}),
    query: req.queryParams || {},
    body: req.body || null,
    body_type: req.body_type || null,
    selected_params: bodySelectedParams,
    query_selected_params: querySelectedParams,
    all_unique_formats: allUniqueFormats,
    unique_pools: uniquePools,
    delay_ms: delayMs || 0,
  };
}

function setupBulkRunModal() {
  const closeBtn = $("bulk-run-modal-close");
  if (closeBtn && !closeBtn._bound) {
    closeBtn._bound = true;
    closeBtn.addEventListener("click", closeBulkRunModal);
  }

  const cancelBtn = $("btn-bulk-cancel");
  if (cancelBtn && !cancelBtn._bound) {
    cancelBtn._bound = true;
    cancelBtn.addEventListener("click", closeBulkRunModal);
  }

  const overlay = $("bulk-run-modal-overlay");
  if (overlay && !overlay._bound) {
    overlay._bound = true;
    overlay.addEventListener("click", closeBulkRunModal);
  }

  const pasteBtn = $("btn-paste-bulk-token");
  if (pasteBtn && !pasteBtn._bound) {
    pasteBtn._bound = true;
    pasteBtn.addEventListener("click", async () => {
      try {
        const txt = await navigator.clipboard.readText();
        if (txt) {
          $("bulk-bearer-token").value = txt.trim();
        }
      } catch (e) {
        console.warn("Clipboard paste error:", e);
      }
    });
  }

  const skipBtn = $("btn-bulk-skip-run");
  if (skipBtn && !skipBtn._bound) {
    skipBtn._bound = true;
    skipBtn.addEventListener("click", () => handleBulkRunSubmit(false));
  }

  const updateBtn = $("btn-bulk-update-run");
  if (updateBtn && !updateBtn._bound) {
    updateBtn._bound = true;
    updateBtn.addEventListener("click", () => handleBulkRunSubmit(true));
  }
}

function openBulkRunModal() {
  autoSaveCurrentApiConfig();

  if (!state.selectedRequestIds || state.selectedRequestIds.size === 0) {
    alert("Please select at least one API from the list using checkboxes.");
    return;
  }

  const selectedReqs = state.requests.filter(r => state.selectedRequestIds.has(r.id));
  if (!selectedReqs.length) return;

  const configuredReqs = selectedReqs.filter(r => hasSavedApiConfig(r));
  const unconfiguredReqs = selectedReqs.filter(r => !hasSavedApiConfig(r));

  const modal = $("bulk-run-modal");
  if (!modal) return;

  let totalCases = 0;
  configuredReqs.forEach(r => {
    const cfg = getSavedApiConfig(r);
    totalCases += countExpectedCasesForConfig(cfg, r) || countConfiguredCasesForReq(cfg) || 1;
  });
  totalCases += unconfiguredReqs.length; // Each unconfigured API will run 1 baseline check

  const apiCountEl = $("bulk-modal-api-count");
  if (apiCountEl) {
    if (configuredReqs.length > 0 && unconfiguredReqs.length > 0) {
      apiCountEl.textContent = `${selectedReqs.length} APIs (${configuredReqs.length} configured · ${unconfiguredReqs.length} baseline check)`;
    } else if (configuredReqs.length > 0) {
      apiCountEl.textContent = `${configuredReqs.length} ${configuredReqs.length === 1 ? "API" : "APIs"}`;
    } else {
      apiCountEl.textContent = `${unconfiguredReqs.length} ${unconfiguredReqs.length === 1 ? "API" : "APIs"} (Baseline Connectivity & Auth Check)`;
    }
  }

  const caseCountEl = $("bulk-modal-case-count");
  if (caseCountEl) {
    if (configuredReqs.length > 0 && unconfiguredReqs.length > 0) {
      caseCountEl.textContent = `${totalCases} test hits (${totalCases - unconfiguredReqs.length} cases + ${unconfiguredReqs.length} baseline)`;
    } else if (configuredReqs.length === 0) {
      caseCountEl.textContent = `${unconfiguredReqs.length} baseline check${unconfiguredReqs.length > 1 ? "s" : ""}`;
    } else {
      caseCountEl.textContent = `${totalCases} test cases`;
    }
  }

  // Pre-fill existing Bearer token from selected requests if present
  let existingToken = "";
  for (const r of selectedReqs) {
    const authEntry = Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === "authorization");
    if (authEntry && authEntry[1]) {
      existingToken = authEntry[1];
      break;
    }
  }
  const tokenInp = $("bulk-bearer-token");
  if (tokenInp) {
    tokenInp.value = existingToken || "";
  }

  // Populate preview list
  const previewList = $("bulk-apis-preview-list");
  if (previewList) {
    previewList.innerHTML = "";
    selectedReqs.forEach(r => {
      const cfg = getSavedApiConfig(r);
      const isConfigured = hasSavedApiConfig(r);
      const cCount = isConfigured ? (countExpectedCasesForConfig(cfg, r) || countConfiguredCasesForReq(cfg) || 1) : 0;
      const mClass = getMethodClass(r.method);
      const authEntry = Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === "authorization");
      let authLabel = "No token";
      if (authEntry && authEntry[1]) {
        const val = String(authEntry[1]).trim();
        authLabel = val.toLowerCase().startsWith("bearer ") ? "Bearer …" + val.slice(-6) : "Custom Auth";
      }

      let shortUrl = r.url;
      try {
        const u = new URL(r.url);
        shortUrl = u.pathname + (u.search || "");
      } catch(e) {}

      const row = document.createElement("div");
      row.className = "bulk-api-preview-row";
      const caseBadge = isConfigured
        ? `<span class="bulk-api-cases">${cCount} cases</span>`
        : `<span class="bulk-api-cases unconfigured">⚡ Baseline check</span>`;
      const warnBadge = (isConfigured && reqNeedsTestData(r))
        ? `<span class="req-warn-badge" title="Note: New Test data required">⚠️</span>`
        : "";

      row.innerHTML = `
        <span class="method-badge method-${mClass}">${r.method}</span>
        <span class="bulk-api-url" title="${esc(r.url)}">${esc(shortUrl)}</span>
        ${caseBadge}${warnBadge}
        <span class="bulk-api-auth-tag">${esc(authLabel)}</span>
      `;
      previewList.appendChild(row);
    });
  }

  modal.style.display = "block";
}

function closeBulkRunModal() {
  const modal = $("bulk-run-modal");
  if (modal) modal.style.display = "none";
}

async function handleBulkRunSubmit(shouldUpdateToken) {
  const selectedReqs = state.requests.filter(r => state.selectedRequestIds.has(r.id));
  if (!selectedReqs.length) return;

  const rawToken = ($("bulk-bearer-token")?.value || "").trim();
  const delayMs = Math.max(0, parseInt($("bulk-delay-ms")?.value, 10) || 0);

  closeBulkRunModal();

  if (shouldUpdateToken && rawToken) {
    const formattedToken = rawToken.toLowerCase().startsWith("bearer ") ? rawToken : `Bearer ${rawToken}`;
    for (const req of selectedReqs) {
      if (!req.headers) req.headers = {};
      Object.keys(req.headers).forEach(k => {
        if (k.toLowerCase() === "authorization") delete req.headers[k];
      });
      req.headers["Authorization"] = formattedToken;
      await persistRequestPatch(req, { headers: req.headers });
    }
    if (state.selectedRequest && selectedReqs.some(r => r.id === state.selectedRequest.id)) {
      showDetails(state.selectedRequest);
    }
  }

  await runMultipleApis(selectedReqs, delayMs);
}

async function runMultipleApis(apiList, delayMs) {
  if (!apiList || !apiList.length) return;

  const overlay = $("running-overlay");
  overlay.style.display = "flex";
  switchTab("results");
  $("results-empty").style.display = "none";
  $("results-content").style.display = "none";
  resetRunningOverlay("Running Multi-API Tests...");
  _runUserAborted = false;
  _runAbortController = new AbortController();

  let grandExpected = 0;
  apiList.forEach(req => {
    const cfg = getSavedApiConfig(req);
    const isConfigured = hasSavedApiConfig(req);
    if (isConfigured && cfg) {
      grandExpected += countExpectedCasesForConfig(cfg, req) || countConfiguredCasesForReq(cfg) || 1;
    } else {
      grandExpected += 1;
    }
  });

  updateRunProgress(0, 0, grandExpected, `Preparing ${apiList.length} APIs…`);
  appendRunFeed("info", `🚀 Starting Multi-API Test Run: ${apiList.length} APIs queued · ${grandExpected} hits · pacing: ${delayMs}ms`);

  let allResults = [];
  let aggSummary = {
    total: 0, passed: 0, failed: 0, warned: 0,
    pos_pass: 0, pos_fail: 0, neg_pass: 0, neg_fail: 0, health_pct: 0,
    auth_expired: false,
  };
  let completedCount = 0;

  try {
    for (let i = 0; i < apiList.length; i++) {
      if (_runUserAborted || (_runAbortController && _runAbortController.signal.aborted)) {
        appendRunFeed("warn", `Multi-API run stopped by user at API ${i + 1}/${apiList.length}`);
        break;
      }

      const req = apiList[i];
      const cfg = getSavedApiConfig(req);
      const isConfigured = hasSavedApiConfig(req);

      let shortUrl = req.url;
      try {
        const u = new URL(req.url);
        let s = u.search || "";
        if (s.length > 55) {
          s = s.slice(0, 52) + "…";
        }
        shortUrl = u.pathname + s;
      } catch(e) {
        if (shortUrl.length > 80) shortUrl = shortUrl.slice(0, 77) + "…";
      }

      let payload = null;
      if (isConfigured && cfg) {
        payload = buildRunPayloadForConfig(req, cfg, delayMs);
      }

      const hasParams = payload && (
        (payload.selected_params && payload.selected_params.length > 0) ||
        (payload.query_selected_params && payload.query_selected_params.length > 0)
      );

      if ($("running-title")) {
        $("running-title").textContent = `Running API (${i + 1}/${apiList.length}): ${req.method} ${shortUrl}`;
        $("running-title").title = `${req.method} ${req.url}`;
      }

      if (hasParams) {
        const apiExpected = countExpectedCasesForConfig(cfg, req) || countConfiguredCasesForReq(cfg) || payload.selected_params.length || 1;
        appendRunFeed("info", `── [API ${i + 1}/${apiList.length}] ${req.method} ${req.url} (${apiExpected} cases) ──`);

        const data = await consumeRunTestsStream(payload, apiExpected, _runAbortController.signal);

        const apiLabel = getApiDifferentiatorLabel(req);
        const apiSig = getApiSignature(req);
        const apiId = req.id || `api_${i + 1}`;
        const apiKey = apiSig ? `${apiSig}::${apiId}` : `${req.method} ${req.url}::${apiId}`;

        const apiResults = (data.results || []).map(r => ({
          ...r,
          tested_url: r.tested_url || req.url,
          api_url: req.url,
          api_method: req.method,
          method: req.method,
          endpoint: r.tested_url || req.url,
          api_id: apiId,
          api_label: apiLabel,
          api_signature: apiSig,
          api_key: apiKey,
          api_index: i + 1,
          request_body: r.request_body !== undefined ? r.request_body : req.body,
        }));
        allResults.push(...apiResults);

        if (data.summary) {
          aggSummary.total += (data.summary.total || 0);
          aggSummary.passed += (data.summary.passed || 0);
          aggSummary.failed += (data.summary.failed || 0);
          aggSummary.warned += (data.summary.warned || 0);
          aggSummary.pos_pass += (data.summary.pos_pass || 0);
          aggSummary.pos_fail += (data.summary.pos_fail || 0);
          aggSummary.neg_pass += (data.summary.neg_pass || 0);
          aggSummary.neg_fail += (data.summary.neg_fail || 0);
          if (data.summary.auth_expired || data.auth_expired) {
            aggSummary.auth_expired = true;
          }
        }

        if (data.auth_expired || (data.summary && data.summary.auth_expired)) {
          appendRunFeed("fail", `⛔ Auth expired on ${req.method} ${shortUrl} — stopping remaining APIs.`);
          break;
        }
      } else {
        appendRunFeed("info", `── [API ${i + 1}/${apiList.length}] ${req.method} ${req.url} (Baseline Check) ──`);

        const singlePayload = {
          url: req.url,
          method: req.method,
          headers: stripBadHeaders(req.headers || {}),
          query: req.queryParams || {},
          body: req.body || null,
          body_type: req.body_type || null,
          unique_formats: {},
          unique_pools: {},
        };

        const resp = await fetch(`${BACKEND}/run-single`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(singlePayload),
          signal: _runAbortController?.signal,
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}));
          throw new Error(errData.detail || `Baseline check failed (HTTP ${resp.status})`);
        }

        const singleData = await resp.json();
        const row = (singleData.results && singleData.results[0]) || {
          param: "—",
          dataset: "Baseline Check",
          case_cat: "POS",
          case_id: "baseline_check",
          case_desc: "Baseline Connectivity & Auth Check",
          status_code: resp.status,
          result: resp.status >= 200 && resp.status < 300 ? "PASS" : "FAIL",
          elapsed_ms: 0,
        };

        const apiLabel = getApiDifferentiatorLabel(req);
        const apiSig = getApiSignature(req);
        const apiId = req.id || `api_${i + 1}`;
        const apiKey = apiSig ? `${apiSig}::${apiId}` : `${req.method} ${req.url}::${apiId}`;

        row.dataset = "Baseline Check";
        row.case_desc = "Baseline Connectivity & Auth Check (Unconfigured API)";
        row.tested_url = req.url;
        row.api_url = req.url;
        row.api_method = req.method;
        row.method = req.method;
        row.endpoint = req.url;
        row.api_id = apiId;
        row.api_label = apiLabel;
        row.api_signature = apiSig;
        row.api_key = apiKey;
        row.api_index = i + 1;
        row.request_body = row.request_body !== undefined ? row.request_body : req.body;

        allResults.push(row);

        const isPass = row.result === "PASS";
        aggSummary.total += 1;
        if (isPass) {
          aggSummary.passed += 1;
          aggSummary.pos_pass += 1;
        } else {
          aggSummary.failed += 1;
          aggSummary.pos_fail += 1;
        }

        const scCode = String(row.status_code || "");
        if (scCode === "401") {
          aggSummary.auth_expired = true;
          appendRunFeed("fail", `⛔ Auth expired (401) on ${req.method} ${shortUrl}`);
          break;
        } else {
          appendRunFeed(isPass ? "pass" : "fail", `Baseline Check → ${row.status_code} (${row.elapsed_ms || 0}ms)`);
        }
      }

      completedCount++;
      const currentDone = allResults.length;
      const pct = grandExpected ? Math.min(100, Math.round((currentDone / grandExpected) * 100)) : 0;
      updateRunProgress(pct, currentDone, grandExpected, `Completed ${completedCount}/${apiList.length} APIs (${currentDone}/${grandExpected} hits)`);

      if (_runUserAborted) break;

      if (i < apiList.length - 1 && delayMs > 0 && !_runUserAborted) {
        appendRunFeed("info", `⏳ Pacing delay ${delayMs}ms before next API...`);
        await new Promise(r => setTimeout(r, delayMs));
      }
    }

    aggSummary.health_pct = aggSummary.total ? Math.round((aggSummary.passed / aggSummary.total) * 100) : 0;
    updateRunProgress(100, allResults.length, allResults.length, `✅ Multi-API run finished: ${completedCount}/${apiList.length} APIs tested (${allResults.length} cases)`);
    await new Promise(r => setTimeout(r, 350));

    if (!allResults.length) {
      $("results-empty").style.display = "flex";
      $("results-content").style.display = "none";
      state.testResults = null;
    } else {
      state.testResults = {
        summary: aggSummary,
        results: allResults,
        url: `Multiple APIs (${completedCount}/${apiList.length} completed)`,
        method: "BULK",
        isBulk: true,
      };
      renderResults(state.testResults);
    }
  } catch (e) {
    console.error("Multi-API run failed:", e);
    alert("Multi-API test run error: " + e.message);
  } finally {
    _runAbortController = null;
    overlay.style.display = "none";
    const abortBtn = $("btn-abort-run");
    if (abortBtn) {
      abortBtn.disabled = false;
      abortBtn.textContent = "Abort";
    }
  }
}

// ── Results rendering ─────────────────────────────────────────────────────────
function avStampRequestMeta(data, req) {
  if (!data) return data;
  const src = req || getLiveRequest();
  if (!src) return data;
  data.url = src.url || data.url || "";
  data.method = src.method || data.method || "";
  data.headers = stripBadHeaders(src.headers || data.headers || {});
  data.query = src.queryParams || data.query || {};
  data.body_type = src.body_type || data.body_type || null;

  // Stamp each result row with target API's metadata for single API runs (prevents GET mutated queries splitting into separate APIs)
  if (!data.isBulk && Array.isArray(data.results)) {
    const m = (data.method || "GET").toUpperCase();
    const targetUrl = data.url || "";
    const sig = typeof getApiSignature === "function" ? getApiSignature(src) : "";
    const singleApiKey = sig ? `${sig}::api_1` : `${m} ${targetUrl}`;
    data.results.forEach(r => {
      if (!r.api_url) r.api_url = targetUrl;
      if (!r.api_method) r.api_method = m;
      if (!r.api_key) r.api_key = singleApiKey;
      if (r.api_index === undefined) r.api_index = 1;
    });
  }
  return data;
}

function avCurlArg(s) {
  // POSIX single-quote. Never turn real newlines into \n inside double quotes —
  // bash/Postman then send literal backslash-n and JSON parse fails.
  return "'" + String(s ?? "").replace(/'/g, `'\\''`) + "'";
}

function avCurlPayload(body) {
  if (body == null) return "";
  let s = typeof body === "string" ? body : JSON.stringify(body);
  if (!s || s === "(no body)" || s === "null") return "";
  const trimmed = s.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try { s = JSON.stringify(JSON.parse(s)); } catch (e) { /* keep original */ }
  }
  return s;
}

function avComposeUrl(baseUrl, queryObj) {
  try {
    const u = new URL(baseUrl);
    if (queryObj && typeof queryObj === "object") {
      u.search = "";
      Object.entries(queryObj).forEach(([k, v]) => {
        if (v == null) return;
        u.searchParams.append(k, String(v));
      });
    }
    return u.toString();
  } catch (e) {
    return baseUrl || "";
  }
}

function avBuildResultCurl(r) {
  const meta = state.testResults || {};
  const live = getLiveRequest() || {};
  const method = String(meta.method || live.method || "GET").toUpperCase();
  const headers = meta.headers || live.headers || {};
  const query = { ...(meta.query || live.queryParams || {}) };
  let url = r.tested_url || meta.url || live.url || "";
  const param = String(r.param || "");
  if (!r.tested_url) {
    if (param.startsWith("query.")) {
      const key = param.slice(6);
      if (key) query[key] = r.test_value;
    }
    if (Object.keys(query).length) url = avComposeUrl(url, query);
  }
  const skipName = /^(content-length|host|connection|transfer-encoding|accept-encoding|content-encoding|keep-alive|proxy-connection|te|trailer|upgrade|http2-settings|upgrade-insecure-requests)$/i;
  const skipPrefix = /^(sec-ch-|sec-fetch-|sec-gpc)/i;
  const lines = [`curl --http1.1 -X ${method} ${avCurlArg(url)}`];
  const seen = new Set();
  Object.entries(headers).forEach(([k, v]) => {
    if (!k || k.startsWith(":") || skipName.test(k) || skipPrefix.test(k)) return;
    const lk = k.toLowerCase();
    if (seen.has(lk)) return;
    seen.add(lk);
    lines.push(`  -H ${avCurlArg(k + ": " + v)}`);
  });
  const bodyStr = avCurlPayload(r.request_body);
  if (bodyStr) {
    if (!seen.has("content-type") && /^\s*[\[{]/.test(bodyStr)) {
      lines.push(`  -H ${avCurlArg("Content-Type: application/json")}`);
    }
    lines.push(`  --data-raw ${avCurlArg(bodyStr)}`);
  }
  return lines.join(" \\\n");
}

function avPickHighlightNeedle(raw, val) {
  if (val == null || val === "") return "";
  const text = raw == null ? "" : String(raw);
  const s = String(val);
  if (s && text.includes(s)) return s;
  try {
    if (typeof val === "string") {
      const inner = JSON.stringify(val).slice(1, -1);
      if (inner && text.includes(inner)) return inner;
    } else {
      const j = JSON.stringify(val);
      if (j && text.includes(j)) return j;
    }
  } catch (e) { /* ignore */ }
  return s || "";
}

function avWrapEscaped(escapedHaystack, rawNeedle, cls, ignoreCase) {
  if (!rawNeedle) return escapedHaystack;
  const needleHtml = esc(rawNeedle);
  if (!needleHtml) return escapedHaystack;
  const re = new RegExp(needleHtml.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), ignoreCase ? "gi" : "g");
  return escapedHaystack.replace(re, m => `<mark class="${cls}">${m}</mark>`);
}

const _avDetailStore = new WeakMap();

function avPrettyBody(text) {
  if (text == null) return "(no body)";
  const s = String(text);
  if (!s || s === "(no body)") return s;
  const t = s.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return s;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch (_) {
    return s;
  }
}

function avBodySizeHint(text) {
  const n = String(text || "").length;
  if (n < 4096) return "";
  return `<span class="av-body-size">${Math.max(1, Math.round(n / 1024))} KB</span>`;
}

function avDetailGetRaw(pre) {
  if (!pre) return "";
  const rec = _avDetailStore.get(pre);
  if (rec && rec.raw != null) return rec.raw;
  return pre.getAttribute("data-raw") || pre.textContent || "";
}

function avPaintDetailPre(pre, searchQuery) {
  if (!pre) return;
  const rec = _avDetailStore.get(pre) || {};
  const raw = rec.raw != null ? rec.raw : (pre.getAttribute("data-raw") || "");
  const q = (searchQuery || "").trim();
  let html = esc(raw);
  if (q) {
    html = avWrapEscaped(html, q, "detail-search-mark", true);
  } else {
    const unique = rec.unique || (() => {
      try { return JSON.parse(pre.getAttribute("data-unique") || "[]"); } catch (_) { return []; }
    })();
    unique.forEach(u => {
      if (!u || !u.needle) return;
      const cls = u.source === "format" ? "av-unique-fmt-mark" : "av-unique-list-mark";
      html = avWrapEscaped(html, u.needle, cls);
    });
    const val = rec.val != null ? rec.val : (pre.getAttribute("data-val") || "");
    if (val) html = avWrapEscaped(html, val, "av-val-mark");
  }
  pre.innerHTML = html;
}

function avUniqueShouldMark(s) {
  if (!s || String(s).length < 2) return false;
  const low = String(s).trim().toLowerCase();
  return !["true", "false", "null", "{}", "[]"].includes(low);
}

function avFillDetailPre(pre, text, testVal, uniqueApplied) {
  if (!pre) return;
  const raw = text == null ? "" : String(text);
  // Keep large bodies in JS, not data-* attributes (WKWebView can clip attrs).
  pre.removeAttribute("data-raw");
  pre.removeAttribute("data-val");
  pre.removeAttribute("data-unique");
  const needle = avPickHighlightNeedle(raw, testVal);
  const extras = [];
  const seen = new Set(needle ? [needle] : []);
  (uniqueApplied || []).forEach(u => {
    const n = avPickHighlightNeedle(raw, u && u.value);
    if (!n || !avUniqueShouldMark(n) || seen.has(n) || n === needle) return;
    seen.add(n);
    extras.push({ needle: n, source: (u && u.source) || "list" });
  });
  _avDetailStore.set(pre, { raw, val: needle || "", unique: extras });
  avPaintDetailPre(pre, "");
}

function avUniqueLegendHtml(uniqueApplied) {
  const src = new Set((uniqueApplied || []).map(u => u && u.source).filter(Boolean));
  if (!src.size) return "";
  const bits = ['<mark class="av-val-mark">tested</mark>'];
  if (src.has("list")) bits.push('<mark class="av-unique-list-mark">list</mark>');
  if (src.has("format")) bits.push('<mark class="av-unique-fmt-mark">format</mark>');
  return `<span class="av-hl-legend">${bits.join(" ")}</span>`;
}

function avCopyText(text, btn) {
  if (!text) return;
  const orig = btn ? btn.textContent : "";
  const done = () => {
    if (btn) {
      btn.textContent = "✓ Copied!";
      setTimeout(() => { btn.textContent = orig; }, 1400);
    }
  };
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  };
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => { fallback(); done(); });
  } else {
    fallback();
    done();
  }
}

function avToggleResultDetail(detailTr, btn) {
  if (!detailTr) return;
  const isOpen = detailTr.style.display !== "none";
  detailTr.style.display = isOpen ? "none" : "table-row";
  if (btn) {
    btn.textContent = isOpen ? "▼ Detail" : "▲ Close";
    btn.classList.toggle("btn-detail-open", !isOpen);
  }
}

function updateResultsSummaryForFilter() {
  const all = state.allResultsCache || state.testResults?.results || [];
  const apiFilter = state.activeApiFilter || "ALL";
  const subset = apiFilter === "ALL"
    ? all
    : all.filter(r => {
        if (r.api_key && r.api_key === apiFilter) return true;
        const m = (r.api_method || r.method || "").toUpperCase();
        const u = r.api_url || (!state.testResults?.isBulk && state.testResults?.url ? state.testResults.url : (r.tested_url || ""));
        return `${m} ${u}` === apiFilter;
      });

  const total = subset.length;
  const passed = subset.filter(r => r.result === "PASS").length;
  const failed = subset.filter(r => r.result === "FAIL").length;
  const warned = subset.filter(r => r.result === "WARN").length;
  const pct = total ? Math.round((passed / total) * 100) : 0;

  $("sc-total").textContent = total;
  $("sc-pass").textContent  = passed;
  $("sc-fail").textContent  = failed;
  $("sc-warn").textContent  = warned;
  $("health-pct").textContent = `${pct}%`;
  $("health-bar-fill").style.width = `${pct}%`;
}

function renderResults(data) {
  const { summary, results } = data;
  state.allResultsCache = results || [];
  state.activeApiFilter = "ALL";

  $("results-content").style.display = "flex";
  $("results-empty").style.display = "none";

  const urlBar = $("av-tested-url-bar");
  const urlEl = $("av-tested-url");
  const live = getLiveRequest() || {};
  const testedUrl = data.url || live.url || "";
  const testedMethod = (data.method || live.method || "").toUpperCase();
  if (urlBar && urlEl) {
    if (testedUrl) {
      urlEl.textContent = testedMethod ? `${testedMethod} ${testedUrl}` : testedUrl;
      urlEl.title = urlEl.textContent;
      urlBar.classList.add("is-visible");
    } else {
      urlEl.textContent = "";
      urlBar.classList.remove("is-visible");
    }
  }

  // Summary cards
  $("sc-total").textContent = summary.total || 0;
  $("sc-pass").textContent  = summary.passed || 0;
  $("sc-fail").textContent  = summary.failed || 0;
  $("sc-warn").textContent  = summary.warned || 0;

  const pct = summary.health_pct || 0;
  $("health-pct").textContent = `${pct}%`;
  $("health-bar-fill").style.width = `${pct}%`;

  const authBanner = $("auth-expired-banner");
  if (authBanner) {
    if (summary.auth_expired) {
      authBanner.style.display = "block";
      authBanner.textContent =
        "⛔ Auth expired (401) — run stopped so NEG cases are not marked PASS. Update Bearer token in Details and re-run.";
    } else {
      authBanner.style.display = "none";
      authBanner.textContent = "";
    }
  }

  state.activeFilter = "ALL";
  document.querySelectorAll(".filter-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.filter === "ALL");
  });

  // Multi-API Dropdown and Tested APIs Tab Setup
  const uniqueApis = [];
  const seenApiKeys = new Set();
  (results || []).forEach(r => {
    const m = (r.api_method || r.method || data.method || "API").toUpperCase();
    const targetApiUrl = r.api_url || (!data.isBulk && data.url ? data.url : "");
    const u = targetApiUrl || r.tested_url || data.url || "";

    let label = r.api_label || "";
    if (!label && r.request_body) {
      label = getApiDifferentiatorLabel({ body: r.request_body, method: m, url: u });
      if (label) r.api_label = label;
    }

    let key = r.api_key;
    if (!key) {
      if (!data.isBulk && (targetApiUrl || data.url)) {
        key = `${m} ${targetApiUrl || data.url}`;
      } else if (r.api_signature && r.api_id) {
        key = `${r.api_signature}::${r.api_id}`;
      } else if (r.api_signature) {
        key = r.api_signature;
      } else if (r.api_id) {
        key = `${m} ${u}::${r.api_id}`;
      } else if (label) {
        key = `${m} ${u} [${label}]`;
      } else {
        key = `${m} ${u}`;
      }
      r.api_key = key;
    }

    if (u && !seenApiKeys.has(key)) {
      seenApiKeys.add(key);
      let shortUrl = u;
      try {
        const parsed = new URL(u);
        shortUrl = parsed.pathname + (parsed.search || "");
      } catch (e) {}

      const apiResults = (results || []).filter(x => {
        const xKey = x.api_key || (x.api_signature ? (x.api_id ? `${x.api_signature}::${x.api_id}` : x.api_signature) : `${(x.api_method || x.method || data.method || "API").toUpperCase()} ${x.api_url || (!data.isBulk && data.url ? data.url : (x.tested_url || data.url || ""))}`);
        return xKey === key;
      });
      const count = apiResults.length;
      const passed = apiResults.filter(x => x.result === "PASS").length;
      const failed = apiResults.filter(x => x.result === "FAIL").length;
      const warned = apiResults.filter(x => x.result === "WARN").length;
      const passRate = count ? Math.round((passed / count) * 100) : 0;
      const totalTime = apiResults.reduce((acc, x) => acc + (Number(x.elapsed_ms) || 0), 0);
      const avgTime = count ? Math.round(totalTime / count) : 0;

      uniqueApis.push({
        method: m,
        url: u,
        shortUrl,
        key,
        label: label || r.api_label || "",
        apiIndex: r.api_index || (uniqueApis.length + 1),
        count,
        passed,
        failed,
        warned,
        passRate,
        avgTime
      });
    }
  });

  state.uniqueApisCache = uniqueApis;

  const btnFilterApis = $("btn-filter-apis");
  const apiFilterWrap = $("results-api-filter-wrap");
  const apiSelect = $("results-api-select");
  const isMulti = uniqueApis.length > 1 || (data.isBulk && uniqueApis.length > 0);

  if (isMulti) {
    if (btnFilterApis) {
      btnFilterApis.style.display = "inline-flex";
      btnFilterApis.innerHTML = `🌐 Tested APIs <span style="margin-left:5px;padding:0 5px;background:rgba(56,139,253,.25);color:#58a6ff;border-radius:10px;font-size:10px">${uniqueApis.length}</span>`;
    }
    if (apiFilterWrap && apiSelect) {
      apiFilterWrap.style.display = "flex";
      apiSelect.innerHTML = "";
      const optAll = document.createElement("option");
      optAll.value = "ALL";
      optAll.textContent = `All APIs (${uniqueApis.length} APIs · ${results.length} cases)`;
      apiSelect.appendChild(optAll);

      uniqueApis.forEach((api, idx) => {
        const opt = document.createElement("option");
        opt.value = api.key;
        const discText = api.label ? ` [${api.label}]` : (uniqueApis.filter(a => a.shortUrl === api.shortUrl).length > 1 ? ` (API ${idx + 1})` : "");
        opt.textContent = `[${api.method}] ${api.shortUrl}${discText} (${api.count} cases)`;
        apiSelect.appendChild(opt);
      });

      apiSelect.value = state.activeApiFilter || "ALL";
      apiSelect.onchange = () => {
        state.activeApiFilter = apiSelect.value;
        if (state.activeFilter === "APIS") {
          state.activeFilter = "ALL";
          document.querySelectorAll(".filter-btn").forEach(b => {
            b.classList.toggle("active", b.dataset.filter === "ALL");
          });
          if ($("results-apis-listing-wrap")) $("results-apis-listing-wrap").style.display = "none";
          if ($("results-table-wrap")) $("results-table-wrap").style.display = "block";
        }
        updateResultsSummaryForFilter();
        renderResultsTable();
      };
    }
  } else {
    if (btnFilterApis) btnFilterApis.style.display = "none";
    if (apiFilterWrap) apiFilterWrap.style.display = "none";
    if ($("results-apis-listing-wrap")) $("results-apis-listing-wrap").style.display = "none";
    if ($("results-table-wrap")) $("results-table-wrap").style.display = "block";
  }

  // Helper to view cases from Tested APIs listing
  window.viewCasesForApi = function(apiKey) {
    state.activeApiFilter = apiKey;
    if (apiSelect) apiSelect.value = apiKey;
    state.activeFilter = "ALL";
    document.querySelectorAll(".filter-btn").forEach(b => {
      b.classList.toggle("active", b.dataset.filter === "ALL");
    });
    if ($("results-apis-listing-wrap")) $("results-apis-listing-wrap").style.display = "none";
    if ($("results-table-wrap")) $("results-table-wrap").style.display = "block";
    updateResultsSummaryForFilter();
    renderResultsTable();
  };

  renderResultsTable();

  // Filter buttons click handler
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.onclick = () => {
      state.activeFilter = btn.dataset.filter;
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const isApisTab = state.activeFilter === "APIS";
      const apisWrap = $("results-apis-listing-wrap");
      const casesWrap = $("results-table-wrap");

      if (isApisTab) {
        if (casesWrap) casesWrap.style.display = "none";
        if (apisWrap) {
          apisWrap.style.display = "flex";
          apisWrap.style.flexDirection = "column";
          renderApisListingTable(state.uniqueApisCache || uniqueApis);
        }
      } else {
        if (apisWrap) apisWrap.style.display = "none";
        if (casesWrap) casesWrap.style.display = "block";
        renderResultsTable();
      }
    };
  });
}

function renderApisListingTable(apis) {
  const tbody = $("results-apis-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  (apis || []).forEach((a, i) => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid var(--border)";
    tr.style.cursor = "default";
    tr.className = "av-api-listing-row";

    const rateColor = a.passRate >= 80 ? "var(--green)" : a.passRate >= 50 ? "var(--yellow)" : "var(--red)";

    tr.innerHTML = `
      <td style="padding:10px;color:var(--text3);font-size:11px">${i + 1}</td>
      <td style="padding:10px">
        <span class="method-badge method-${a.method}">${esc(a.method)}</span>
      </td>
      <td style="padding:10px">
        <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px">
          <span style="font-weight:600;color:#e6edf3;font-family:var(--mono);font-size:11px;word-break:break-all">${esc(a.url)}</span>
          ${a.label ? `<span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600;background:rgba(56,139,253,.2);color:#58a6ff;border:1px solid rgba(56,139,253,.35)">${esc(a.label)}</span>` : ""}
        </div>
      </td>
      <td style="padding:10px;text-align:center;font-weight:700;font-family:var(--mono);color:#58a6ff">${a.count}</td>
      <td style="padding:10px;text-align:center;font-weight:700;color:var(--green)">${a.passed}</td>
      <td style="padding:10px;text-align:center;font-weight:700;color:var(--red)">${a.failed}</td>
      <td style="padding:10px;text-align:center;font-weight:700;color:var(--yellow)">${a.warned}</td>
      <td style="padding:10px;text-align:center">
        <span style="font-weight:700;font-size:11.5px;color:${rateColor}">${a.passRate}%</span>
      </td>
      <td style="padding:10px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:11px">${a.avgTime}ms</td>
      <td style="padding:10px;text-align:center">
        <button type="button" class="btn-sm" style="font-size:11px;padding:3px 10px;border-color:var(--blue);color:var(--blue);background:rgba(31,111,235,.12);border-radius:4px;cursor:pointer;white-space:nowrap" onclick="window.viewCasesForApi('${esc(a.key)}')">🔍 View Cases</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderResultsTable(results) {
  const tbody = $("results-tbody");
  const filter = state.activeFilter || "ALL";
  const apiFilter = state.activeApiFilter || "ALL";
  const allList = results || state.allResultsCache || state.testResults?.results || [];

  const uniqueUrls = new Set(allList.map(r => r.api_url || (!state.testResults?.isBulk && state.testResults?.url ? state.testResults.url : r.tested_url)).filter(Boolean));
  const isMultiApi = (state.testResults?.isBulk && uniqueUrls.size > 0) || (state.uniqueApisCache && state.uniqueApisCache.length > 1);

  const filtered = allList.filter(r => {
    if (apiFilter !== "ALL") {
      if (r.api_key) {
        if (r.api_key !== apiFilter) return false;
      } else {
        const m = (r.api_method || r.method || "").toUpperCase();
        const u = r.api_url || (!state.testResults?.isBulk && state.testResults?.url ? state.testResults.url : (r.tested_url || ""));
        if (`${m} ${u}` !== apiFilter) return false;
      }
    }
    if (filter === "ALL") return true;
    if (filter === "PASS" || filter === "FAIL" || filter === "WARN" || filter === "ERROR") {
      return r.result === filter;
    }
    if (filter === "POS" || filter === "NEG") return r.case_cat === filter;
    return true;
  });

  tbody.innerHTML = "";

  filtered.forEach((r, idx) => {
    const catColor   = r.case_cat === "POS" ? "var(--blue)" : "var(--red2)";
    const isOverride = r.case_cat_default && r.case_cat !== r.case_cat_default;
    const catBadge   = isOverride
      ? `<span style="color:${catColor};font-weight:700;font-size:10px">${r.case_cat}</span>
         <span style="font-size:8px;color:#a371f7;background:rgba(163,113,247,.15);border:1px solid rgba(163,113,247,.3);border-radius:3px;padding:0 4px;margin-left:3px" title="You overrode the default (${r.case_cat_default})">custom</span>`
      : `<span style="color:${catColor};font-weight:700;font-size:10px">${r.case_cat}</span>`;
    const scCode = String(r.status_code);
    const scClass = scCode.startsWith("2") ? "sc-2xx" : scCode.startsWith("4") ? "sc-4xx" : scCode.startsWith("5") ? "sc-5xx" : "sc-err";
    const detailRowId = `detail-row-${idx}`;

    // Value sent display
    const valSent = r.test_value === null ? '<span style="color:var(--text3);font-style:italic">null</span>'
                  : r.test_value === undefined ? ''
                  : `<span style="font-family:var(--mono);font-size:10px;color:var(--yellow)">${esc(truncate(String(r.test_value), 18))}</span>`;

    const rowUrl = r.api_url || r.tested_url || "";
    const rowMethod = (r.api_method || r.method || "GET").toUpperCase();
    const mClass = getMethodClass(rowMethod);

    // Main row
    const tr = document.createElement("tr");
    tr.className = "av-result-row" + (r.case_misconfig ? " av-misconfig-row" : "");
    const reasonHint = r.fail_reason
      ? `<div style="font-size:9px;color:var(--text3);margin-top:2px" title="${esc(r.fail_reason)}">${esc(truncate(r.fail_reason, 42))}</div>`
      : "";
    const misTag = r.case_misconfig
      ? `<span class="av-misconfig-tag" title="${esc(r.misconfig_reason || "Already exists (409/422)")}">case misconfig</span>`
      : "";

    tr.innerHTML = `
      <td class="param-name" title="${esc(r.param)}">
        <div class="param-name-text">${esc(r.param)}</div>
      </td>
      <td style="font-size:10px;color:var(--text3)">${esc(truncate(r.dataset, 18))}</td>
      <td>${catBadge}</td>
      <td style="color:var(--text2)">${esc(r.case_desc)}${reasonHint}</td>
      <td>${valSent}</td>
      <td class="status-code ${scClass}">${esc(String(r.status_code))}</td>
      <td><span class="result-badge result-${r.result}">${r.result}</span>${misTag}</td>
      <td class="elapsed-ms">${r.elapsed_ms}ms</td>
      <td><button class="btn-detail" data-target="${detailRowId}">▼ Detail</button></td>
    `;
    tbody.appendChild(tr);

    // Detail row (hidden by default)
    const detailTr = document.createElement("tr");
    detailTr.id = detailRowId;
    detailTr.style.display = "none";
    detailTr.className = "detail-row";

    const reqBody = avPrettyBody(r.request_body);
    const respBody = avPrettyBody(r.response == null || r.response === "" ? "(no response)" : r.response);

    const reqSearchId  = `req-search-${idx}`;
    const respSearchId = `resp-search-${idx}`;
    const reqPreId     = `req-pre-${idx}`;
    const respPreId    = `resp-pre-${idx}`;

    const apiInfoBar = rowUrl ? `
      <div class="detail-api-info-bar">
        <span class="method-badge method-${mClass}">${esc(rowMethod)}</span>
        <span class="detail-api-url" title="${esc(rowUrl)}">${esc(rowUrl)}</span>
      </div>
    ` : "";

    detailTr.innerHTML = `
      <td colspan="9" class="detail-cell">
        ${apiInfoBar}
        <div class="detail-grid">
          <div class="detail-panel">
            <div class="detail-panel-title">
              <span>📤 Request Body Sent</span>
              ${avBodySizeHint(reqBody)}
              ${avUniqueLegendHtml(r.unique_applied)}
              <button type="button" class="btn-sm av-copy-body-btn" title="Copy full request body">Copy body</button>
              <button type="button" class="btn-sm av-detail-expand-btn" title="Show the full body">↕ Full</button>
              <button type="button" class="btn-sm as-rd-curl-btn av-copy-curl-btn" title="Copy this request as cURL">📋 Copy cURL</button>
              <input type="text" class="detail-search-input" id="${reqSearchId}" placeholder="🔍 Search..." oninput="detailSearch('${reqPreId}',this.value)">
            </div>
            <div class="detail-pre-scroll"><pre class="detail-pre" id="${reqPreId}"></pre></div>
          </div>
          <div class="detail-panel">
            <div class="detail-panel-title">
              <span>📥 Response Body</span>
              ${avBodySizeHint(respBody)}
              <button type="button" class="btn-sm av-copy-body-btn" title="Copy full response body">Copy body</button>
              <button type="button" class="btn-sm av-detail-expand-btn" title="Show the full body">↕ Full</button>
              <button type="button" class="btn-sm as-rd-curl-btn av-copy-curl-btn" title="Copy this request as cURL">📋 Copy cURL</button>
              <input type="text" class="detail-search-input" id="${respSearchId}" placeholder="🔍 Search..." oninput="detailSearch('${respPreId}',this.value)">
            </div>
            <div class="detail-pre-scroll"><pre class="detail-pre" id="${respPreId}"></pre></div>
          </div>
        </div>
      </td>
    `;
    tbody.appendChild(detailTr);

    avFillDetailPre(document.getElementById(reqPreId), reqBody, r.test_value, r.unique_applied);
    avFillDetailPre(document.getElementById(respPreId), respBody, r.test_value, r.unique_applied);

    const toggle = () => avToggleResultDetail(detailTr, tr.querySelector(".btn-detail"));
    tr.addEventListener("click", toggle);
    tr.querySelector(".btn-detail").addEventListener("click", (e) => {
      e.stopPropagation();
      toggle();
    });
    detailTr.querySelectorAll(".av-copy-curl-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        avCopyText(avBuildResultCurl(r), e.currentTarget);
      });
    });
    detailTr.querySelectorAll(".av-copy-body-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const preEl = btn.closest(".detail-panel")?.querySelector(".detail-pre");
        avCopyText(avDetailGetRaw(preEl), e.currentTarget);
      });
    });
    detailTr.querySelectorAll(".av-detail-expand-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const panel = btn.closest(".detail-panel");
        const open = panel.classList.toggle("is-expanded");
        btn.textContent = open ? "Collapse" : "↕ Full";
      });
    });
    detailTr.querySelectorAll(".detail-search-input").forEach(inp => {
      inp.addEventListener("click", (e) => e.stopPropagation());
    });
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:20px">No results match filter</td></tr>`;
  }
}

// ── Export ─────────────────────────────────────────────────────────────────────
// ── Shared pywebview-compatible download helper ───────────────────────────────
async function pyDownload(backendPath, payload, filename) {
  try {
    const resp = await fetch(`${BACKEND}${backendPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();

    // pywebview: use JSApi — js_api is now passed at window creation, so this always works
    if (window.pywebview && window.pywebview.api) {
      const result = await window.pywebview.api.save_file(text, filename);
      if (result && result.ok) {
        showExportToast(result.filename || filename);
      } else if (result && result.reason && result.reason !== "cancelled") {
        alert("Save failed: " + result.reason);
      }
      // "cancelled" = user closed dialog = silent
      return;
    }
    // Not in pywebview (running in plain browser) — standard download
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
  } catch(e) {
    alert("Export failed: " + e.message);
  }
}

function showExportToast(filename) {
  let toast = document.getElementById("export-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "export-toast";
    toast.style.cssText = `position:fixed;bottom:60px;left:50%;transform:translateX(-50%);
      background:var(--green2);color:white;padding:8px 16px;border-radius:20px;
      font-size:12px;font-weight:600;z-index:9999;opacity:0;transition:opacity .3s;
      box-shadow:0 4px 12px rgba(0,0,0,.4);pointer-events:none;white-space:nowrap`;
    document.body.appendChild(toast);
  }
  toast.textContent = "✅ Saved: " + filename + " (Downloads)";
  toast.style.opacity = "1";
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.style.opacity = "0"; }, 3000);
}

async function exportCsv() {
  if (!state.testResults) return;
  const isBulk = Boolean(state.testResults.isBulk);
  const baseTargetUrl = state.testResults.url || "";
  const payload = {
    ...state.testResults,
    results: (state.testResults.results || []).map(r => ({
      ...r,
      method: r.api_method || r.method || state.testResults.method || "",
      endpoint: r.api_url || (!isBulk && baseTargetUrl ? baseTargetUrl : (r.tested_url || r.endpoint || baseTargetUrl)),
      api_url: r.api_url || (!isBulk && baseTargetUrl ? baseTargetUrl : (r.endpoint || baseTargetUrl)),
      api_method: r.api_method || r.method || state.testResults.method || "",
      tested_url: r.tested_url || r.api_url || r.endpoint || baseTargetUrl,
      request_body: r.request_body !== undefined ? r.request_body : "",
      response: r.response !== undefined ? r.response : (r.response_body !== undefined ? r.response_body : ""),
    })),
  };
  await pyDownload("/export/csv", payload, "api_validation_report.csv");
}

async function exportHtml() {
  if (!state.testResults) return;
  const isBulk = Boolean(state.testResults.isBulk);
  const baseTargetUrl = state.testResults.url || "";
  const payload = {
    ...state.testResults,
    isBulk: isBulk,
    results: (state.testResults.results || []).map(r => ({
      ...r,
      method: r.api_method || r.method || state.testResults.method || "",
      endpoint: r.api_url || (!isBulk && baseTargetUrl ? baseTargetUrl : (r.tested_url || r.endpoint || baseTargetUrl)),
      api_url: r.api_url || (!isBulk && baseTargetUrl ? baseTargetUrl : (r.endpoint || baseTargetUrl)),
      api_method: r.api_method || r.method || state.testResults.method || "",
      tested_url: r.tested_url || r.api_url || r.endpoint || baseTargetUrl,
      api_id: r.api_id || "",
      api_label: r.api_label || "",
      api_signature: r.api_signature || "",
      api_key: r.api_key || "",
      api_index: r.api_index || 0,
      request_body: r.request_body !== undefined ? r.request_body : "",
      response: r.response !== undefined ? r.response : (r.response_body !== undefined ? r.response_body : ""),
    })),
  };
  await pyDownload("/export/html", payload, "api_validation_report.html");
}

function avIsoNow() {
  return new Date().toISOString();
}

function avHashText(input) {
  const s = String(input || "");
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

function avNormalizeApiKey(method, url) {
  return `${String(method || "GET").toUpperCase()} ${String(url || "").trim()}`;
}

function avBundleApiKey(req) {
  return avNormalizeApiKey(req?.method, req?.url);
}

function avCurrentParamSnapshot() {
  const req = getLiveRequest() || (state.analyzedData?._req ? buildEffectiveRequest(state.analyzedData._req) : null);
  const apiKey = avBundleApiKey(req || {});
  return (state.currentParams || []).map((p, idx) => ({
    order: idx,
    path: p.path,
    api_key: apiKey,
    detected: p.detected || "",
    source: p.path.startsWith("query.") ? "query" : "body",
    value_preview: p.value == null ? "" : String(p.value).slice(0, 120),
    unique_format: state.paramUnique[p.path] || null,
    dataset_key: state.paramDatasets[p.path] || p.detected || null,
  }));
}

function avBuildCaseMeta(req, r, idx) {
  const paramPath = r.param || "";
  const apiKey = avBundleApiKey(req);
  const baseId = [
    apiKey,
    paramPath,
    r.case_cat || "",
    r.case_desc || "",
    r.test_value == null ? "" : String(r.test_value),
  ].join("|");
  const now = avIsoNow();
  return {
    case_id: `avc_${avHashText(baseId)}`,
    api_key: apiKey,
    param_path: paramPath,
    value_template: state.paramUnique[paramPath] || null,
    enabled: true,
    status: "active",
    created_at: now,
    updated_at: now,
    source_bundle_id: `avb_${avHashText(apiKey + "|" + now)}`,
    order: idx,
    merge_state: "source",
    extractors: [],
    bindings: [],
  };
}

async function exportToApisphereRunner() {
  if (!state.testResults || !state.testResults.results) {
    alert("No test results to export. Run tests first.");
    return;
  }

  const req   = getLiveRequest() || (state.analyzedData?._req ? buildEffectiveRequest(state.analyzedData._req) : null);
  if (!req) {
    alert("No request selected.");
    return;
  }
  const generatedAt = avIsoNow();
  const bundleId = `avb_${avHashText(avBundleApiKey(req) + "|" + generatedAt)}`;
  const paramSnapshot = avCurrentParamSnapshot();
  const allUniqueFormats = {};
  (state.currentParams || []).forEach(p => {
    if (state.paramUnique[p.path]) allUniqueFormats[p.path] = state.paramUnique[p.path];
  });
  const cases = state.testResults.results.map((r, idx) => {
    const meta = avBuildCaseMeta(req, r, idx);
    meta.source_bundle_id = bundleId;
    return {
      param:       r.param,
      case_cat:    r.case_cat,
      case_desc:   r.case_desc,
      test_value:  r.test_value,
      case_value:  r.test_value,
      body:        r.request_body || null,
      response:    r.response || null,
      prev_status: r.status_code,
      prev_result: r.result,
      source_query: req.queryParams || {},
      source_body: req.body || null,
      all_unique_formats: allUniqueFormats,
      dataset_case_id: r.case_id || null,
      dataset_key: state.paramDatasets[r.param] || null,
      ...meta,
    };
  });

  const bundle = {
    v:         2,
    schema_version: 2,
    source_tool: "api_validator",
    generated_at: generatedAt,
    bundle_id: bundleId,
    api_key: avBundleApiKey(req),
    sync_policy: "precheck_block",
    name:      `${req.method} ${(req.url || "").replace(/^https?:\/\//, "").slice(0, 60)}`,
    method:    req.method,
    url:       req.url,
    headers:   req.headers || {},
    query:     req.queryParams || {},
    body:      req.body || null,
    body_type: req.body_type || "json",
    all_unique_formats: allUniqueFormats,
    param_snapshot: paramSnapshot,
    cases,
  };

  const text     = JSON.stringify(bundle, null, 2);
  const filename = "av_collection.json";

  // pywebview: use native save dialog
  if (window.pywebview && window.pywebview.api) {
    const result = await window.pywebview.api.save_file(text, filename);
    if (result && result.ok) showExportToast(result.filename || filename);
    else if (result && result.reason && result.reason !== "cancelled")
      alert("Save failed: " + result.reason);
    return;
  }

  // Browser fallback
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
}

// ── Background messages ───────────────────────────────────────────────────────
function onBackgroundMessage(msg) {
  if (msg.type === "REQUEST_ADDED") {
    state.requests = [msg.request, ...state.requests.filter(r => r.id !== msg.request.id)];
    filterRequests();
    $("tab-badge").textContent = state.requests.length;
  }
}

// ── PATCH 1: HAR + cURL Import ───────────────────────────────────────────────

/**
 * Parse HAR request headers without losing auth.
 * - Empty values never overwrite a non-empty Authorization/Cookie
 * - Rebuild Cookie from request.cookies[] when Cookie header is missing
 *   (common when Chrome exports sanitized HARs that still keep the cookies array)
 */
function parseHarRequestHeaders(rq) {
  const headers = {};
  const setHeader = (name, value) => {
    if (!name) return;
    const val = value == null ? "" : String(value);
    const existing = Object.keys(headers).find(k => k.toLowerCase() === String(name).toLowerCase());
    if (existing) {
      // Prefer non-empty — don't let a blank/redacted duplicate wipe the real token
      if (val.trim()) headers[existing] = val;
      return;
    }
    headers[name] = val;
  };

  (rq.headers || []).forEach(h => setHeader(h.name, h.value));

  const hasCookie = Object.keys(headers).some(
    k => k.toLowerCase() === "cookie" && String(headers[k] || "").trim()
  );
  if (!hasCookie && Array.isArray(rq.cookies) && rq.cookies.length) {
    const cookieStr = rq.cookies
      .filter(c => c && c.name)
      .map(c => `${c.name}=${c.value == null ? "" : c.value}`)
      .join("; ");
    if (cookieStr) headers["Cookie"] = cookieStr;
  }

  return headers;
}

function setupImport() {
  const btnExportApis = $("btn-export-apis");
  if (btnExportApis) {
    btnExportApis.addEventListener("click", exportConfiguredApis);
  }

  const btnImportApis = $("btn-import-apis");
  const cfgFileInput = $("cfg-file-input");
  if (btnImportApis && cfgFileInput) {
    btnImportApis.addEventListener("click", () => {
      cfgFileInput.value = "";
      cfgFileInput.click();
    });
    cfgFileInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) importConfiguredApis(file);
    });
  }

  $("btn-import-har").addEventListener("click", () => {
    $("har-file-input").value = "";
    $("har-file-input").click();
  });

  $("har-file-input").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const har = JSON.parse(ev.target.result);
        const entries = har?.log?.entries || [];
        const imported = [];
        entries.forEach((entry, idx) => {
          const rq = entry.request || {};
          const method = (rq.method || "GET").toUpperCase();
          const url    = rq.url || "";
          if (!url) return;

          // Keep HAR Authorization / Cookie exactly as recorded
          const headers = parseHarRequestHeaders(rq);

          // Query params
          const queryParams = {};
          (rq.queryString || []).forEach(q => { queryParams[q.name] = q.value; });

          // Body
          let body = null, body_type = null, payload = null;
          const postData = rq.postData;
          if (postData && postData.text) {
            payload = postData.text;
            try { body = JSON.parse(postData.text); body_type = "json"; }
            catch(e) { body = postData.text; body_type = "raw"; }
          }

          const status = entry.response?.status || null;
          imported.push({
            id: `har-${Date.now()}-${idx}`,
            method, url, headers, queryParams,
            body, body_type, payload,
            status, statusText: String(status || ""),
            timestamp: Date.now() - idx * 10,
            source: "har",
          });
        });

        if (!imported.length) {
          alert("No API entries found in HAR file");
          return;
        }

        // Token is mandatory — same Bearer applied to every imported API (no Skip / mixed auth)
        openImportTokenModal(`${imported.length} APIs from HAR`, (token) => {
          imported.forEach(r => {
            r.headers = { ...(r.headers || {}) };
            // Normalize casing: drop any existing Authorization*, then set one clean header
            Object.keys(r.headers).forEach(k => {
              if (k.toLowerCase() === "authorization") delete r.headers[k];
            });
            r.headers["Authorization"] = `Bearer ${token}`;
          });
          addImportedRequests(imported);
        });
      } catch(err) {
        alert("Invalid HAR file: " + err.message);
      }
    };
    reader.readAsText(file);
  });

  $("btn-import-curl").addEventListener("click", () => {
    openCurlModal();
  });

  initImportModals();
}

async function addImportedRequests(reqs) {
  // Un-dismiss any imported requests so polling never hides them
  reqs.forEach(r => {
    if (r.id) _avDismissedIds.delete(r.id);
  });
  // Persist to backend so polling doesn't wipe them
  try {
    await fetch(`${BACKEND}/capture/import`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reqs),
    });
  } catch(e) { console.warn("capture/import failed:", e); }
  // Also update local state (polling will confirm from backend)
  reqs.forEach(r => {
    if (!state.requests.find(x => x.id === r.id))
      state.requests.unshift(r);
  });
  filterRequests();
  $("tab-badge").textContent = state.requests.length;
}

// ── Import Token Modal ─────────────────────────────────────────────────────────
let _importTokenCallback = null;

function openImportTokenModal(label, callback) {
  _importTokenCallback = callback;
  const modal = $("import-token-modal");
  $("import-token-label").textContent = label;
  $("import-token-input").value = "";
  const errEl = $("import-token-error");
  if (errEl) errEl.style.display = "none";
  modal.style.display = "block";
  setTimeout(() => $("import-token-input").focus(), 50);
}

function initImportModals() {
  // Token modal — token required; ✕ / overlay cancels import (no requests added)
  const cancelTokenModal = () => {
    $("import-token-modal").style.display = "none";
    _importTokenCallback = null;
    const errEl = $("import-token-error");
    if (errEl) errEl.style.display = "none";
  };

  $("import-token-save").addEventListener("click", () => {
    const raw = $("import-token-input").value.trim();
    const token = raw.replace(/^Bearer\s+/i, "");
    const errEl = $("import-token-error");
    if (!token) {
      if (errEl) errEl.style.display = "block";
      $("import-token-input").focus();
      return;
    }
    if (errEl) errEl.style.display = "none";
    $("import-token-modal").style.display = "none";
    const cb = _importTokenCallback;
    _importTokenCallback = null;
    if (cb) cb(token);
  });

  $("import-token-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      $("import-token-save").click();
    }
  });

  $("import-token-close").addEventListener("click", cancelTokenModal);
  $("import-token-overlay").addEventListener("click", cancelTokenModal);

  // cURL modal
  $("curl-modal-close").addEventListener("click",   () => { $("curl-modal").style.display = "none"; });
  $("curl-modal-cancel").addEventListener("click",  () => { $("curl-modal").style.display = "none"; });
  $("curl-modal-overlay").addEventListener("click", () => { $("curl-modal").style.display = "none"; });

  $("curl-modal-import").addEventListener("click", () => {
    const raw = $("curl-textarea").value.trim();
    if (!raw) return;
    const errEl = $("curl-parse-error");
    try {
      // Split on multiple curl commands
      const parts = raw.split(/(?=^(?:\$\s*)?curl(?:\.exe)?\s)/im)
        .map(s => s.replace(/^\$\s*/m, "").trim())
        .filter(s => /^curl(?:\.exe)?\b/i.test(s));
      const imported = parts.length ? parts.map(p => parseCurl(p)) : [parseCurl(raw)];
      const valid = imported.filter(r => r.url);
      if (!valid.length) { errEl.textContent = "No valid URL found in cURL command"; errEl.style.display="block"; return; }
      errEl.style.display = "none";
      $("curl-modal").style.display = "none";
      addImportedRequests(valid);
      alert(`✅ ${valid.length} API(s) imported from cURL`);
    } catch(e) {
      errEl.textContent = "Parse error: " + e.message;
      errEl.style.display = "block";
    }
  });
}

// ── cURL Modal ─────────────────────────────────────────────────────────────────
function openCurlModal() {
  $("curl-modal").style.display = "block";
  $("curl-textarea").value = "";
  setTimeout(() => $("curl-textarea").focus(), 50);
}

function _avNormalizeCurlText(text) {
  let s = String(text || "")
    .replace(/^\uFEFF/, "")
    .replace(/\u00A0/g, " ")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  s = s.replace(/\\\n/g, " ");
  s = s.replace(/`\n/g, " ");
  s = s.replace(/\^\n/g, " ");
  // Drop shell prompts: $ curl … / PS> curl …
  s = s.replace(/^\s*(?:PS\s*>\s*|\$\s*)/i, "");
  s = s.trim();
  if (!/^curl(?:\.exe)?\b/i.test(s)) return null;
  return s.replace(/^curl(?:\.exe)?\b/i, "curl");
}

function _avTokenizeCurl(s) {
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
      tokens.push(val);
    } else {
      let val = "";
      while (i < s.length && !isWs(s[i])) val += s[i++];
      tokens.push(val);
    }
  }
  return tokens;
}

function _avExpandCurlTokens(rawTokens) {
  const out = [];
  const LONG_EQ = /^(--[^=]+)=(.*)$/;
  const ARG_SHORT = new Set(["X","H","d","F","u","A","o","m","x","b","c","e","T","w","E"]);
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
    // Clustered short flags without args: -kLsS
    if (/^-[a-zA-Z]{2,}$/.test(t) && !t.startsWith("--")) {
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

function _avSafeDecodeURIComponent(s) {
  try { return decodeURIComponent(String(s).replace(/\+/g, " ")); }
  catch (_) {
    try { return unescape(String(s).replace(/\+/g, " ")); }
    catch (_) { return String(s); }
  }
}

function _avParseUrlEncodedBody(body) {
  const out = {};
  String(body || "").split("&").forEach(part => {
    if (!part) return;
    const eq = part.indexOf("=");
    let k = eq >= 0 ? part.slice(0, eq) : part;
    let v = eq >= 0 ? part.slice(eq + 1) : "";
    k = _avSafeDecodeURIComponent(k);
    v = _avSafeDecodeURIComponent(v);
    if (!k) return;
    out[k] = v;
  });
  return out;
}

function _avLooksLikeUrlEncoded(s) {
  const t = String(s || "").trim();
  if (!t || t.startsWith("{") || t.startsWith("[")) return false;
  if (!t.includes("=")) return false;
  if (/Content-Disposition:/i.test(t) || t.startsWith("<")) return false;
  return /^(?:[^=&\s]+(?:=[^&\s]*)?)(?:&[^=&\s]+(?:=[^&\s]*)?)*$/.test(t);
}

function _avStripJsonComments(s) {
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

function _avLooksLikeJson(s) {
  const t = String(s || "").trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) return true;
  if (t.includes("//") || t.includes("/*")) {
    const stripped = _avStripJsonComments(t).trim();
    return (stripped.startsWith("{") && stripped.endsWith("}")) || (stripped.startsWith("[") && stripped.endsWith("]"));
  }
  return false;
}

function _avCurlDataUrlEncodePart(part) {
  const s = String(part || "");
  if (s.includes("@") && !s.includes("=")) {
    const name = s.split("@")[0];
    return { key: name, value: "", encoded: encodeURIComponent(name) + "=" };
  }
  const eq = s.indexOf("=");
  if (eq < 0) return { key: "", value: s, encoded: encodeURIComponent(s) };
  const name = s.slice(0, eq);
  const value = s.slice(eq + 1);
  return {
    key: name,
    value,
    encoded: encodeURIComponent(name) + "=" + encodeURIComponent(value),
  };
}

function _avParseCurlFormArg(arg) {
  const s = String(arg || "");
  const eq = s.indexOf("=");
  if (eq < 0) return null;
  const key = s.slice(0, eq).trim();
  let rest = s.slice(eq + 1);
  rest = rest.replace(/;type=[^;]+/ig, "").replace(/;filename=[^;]+/ig, "");
  if (!key) return null;
  // File fields: keep key with filename placeholder (no filesystem read in AV)
  if (rest.startsWith("@") || rest.startsWith("<")) {
    const path = rest.slice(1).replace(/^["']|["']$/g, "");
    const filename = path.split(/[/\\]/).pop() || "file";
    return { key, value: filename, isFile: true };
  }
  return { key, value: rest, isFile: false };
}

function _avSetHeaderCI(headers, key, value) {
  const found = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
  if (found) headers[found] = value;
  else headers[key] = value;
}
function _avGetHeaderCI(headers, key) {
  const found = Object.keys(headers).find(k => k.toLowerCase() === key.toLowerCase());
  return found ? headers[found] : "";
}

function parseCurl(curlStr) {
  curlStr = _avNormalizeCurlText(curlStr);
  if (!curlStr) throw new Error("Invalid cURL");
  const tokens = _avExpandCurlTokens(_avTokenizeCurl(curlStr));

  let method = null, url = "", asGet = false;
  const headers = {};
  const dataParts = [];
  const formFieldsFromData = [];
  let dataIsUrlEncode = false;
  let dataIsJsonFlag = false;
  let dataIsBinary = false;
  const formParts = [];
  let basicUser = null, basicPass = null;

  const skipNoArg = new Set([
    "--compressed", "--insecure", "-k", "--location", "-L", "--location-trusted",
    "--silent", "-s", "--show-error", "-S", "--verbose", "-v", "--no-buffer", "-N",
    "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3",
    "--fail", "-f", "--remote-name", "-O", "--remote-header-name", "-J",
    "--include", "-i", "--head", "-I", "--raw", "--globoff", "-g",
    "--path-as-is", "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3",
    "--ssl", "--ssl-reqd",
  ]);
  const skipOneArg = new Set([
    "-o", "--output", "-m", "--max-time", "--connect-timeout", "--retry",
    "--proxy", "-x", "--cert", "--key", "--cacert", "--capath", "--passwd",
    "--write-out", "-w", "--stderr", "--trace", "--trace-ascii",
    "--resolve", "--connect-to", "--unix-socket", "--abstract-unix-socket",
    "--cert-type", "--key-type", "--engine", "--ciphers", "--tls-max",
    "--limit-rate", "--keepalive-time", "--max-redirs", "--proto", "--proto-redir",
    "-E", "--cookie-jar", "-c",
    // Upload file not supported in AV — skip arg so URL/body stay intact
    "-T", "--upload-file",
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
        _avSetHeaderCI(headers, h.slice(0, ci).trim(), h.slice(ci + 1).trim());
      } else if (h.endsWith(";") && ci < 0) {
        const k = h.slice(0, -1).trim();
        if (k) _avSetHeaderCI(headers, k, "");
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
    if (t === "-A" || t === "--user-agent") {
      _avSetHeaderCI(headers, "User-Agent", tokens[++i] || "");
      continue;
    }
    if (t === "-e" || t === "--referer") {
      _avSetHeaderCI(headers, "Referer", tokens[++i] || "");
      continue;
    }
    if (t === "-b" || t === "--cookie") {
      const c = tokens[++i] || "";
      if (!c.startsWith("@")) {
        const prev = _avGetHeaderCI(headers, "Cookie");
        _avSetHeaderCI(headers, "Cookie", prev ? prev + "; " + c : c);
      }
      continue;
    }
    if (t === "--json") {
      const part = tokens[++i] || "";
      dataIsJsonFlag = true;
      dataParts.push(part.startsWith("@") ? "" : part);
      _avSetHeaderCI(headers, "Content-Type", "application/json");
      if (!_avGetHeaderCI(headers, "Accept")) _avSetHeaderCI(headers, "Accept", "application/json");
      continue;
    }
    if (t === "-d" || t === "--data" || t === "--data-raw" || t === "--data-ascii" ||
        t === "--data-urlencode" || t === "--data-binary") {
      let part = tokens[++i] || "";
      if (part.startsWith("@")) part = "";
      if (t === "--data-binary") dataIsBinary = true;
      if (t === "--data-urlencode") {
        dataIsUrlEncode = true;
        const enc = _avCurlDataUrlEncodePart(part);
        dataParts.push(enc.encoded);
        if (enc.key) formFieldsFromData.push({ key: enc.key, value: enc.value });
        continue;
      }
      dataParts.push(part);
      if (part && !part.startsWith("{") && !part.startsWith("[") && part.includes("=")) {
        const parsed = _avParseUrlEncodedBody(part);
        Object.entries(parsed).forEach(([k, v]) => formFieldsFromData.push({ key: k, value: v }));
      }
      continue;
    }
    if (t === "-F" || t === "--form" || t === "--form-string") {
      const part = tokens[++i] || "";
      const row = _avParseCurlFormArg(part);
      if (row) formParts.push(row);
      continue;
    }
    if (skipOneArg.has(t)) { i++; continue; }
    if (t.startsWith("--") && i + 1 < tokens.length && !tokens[i + 1].startsWith("-")) {
      const nxt = tokens[i + 1] || "";
      if (!/^https?:\/\//i.test(nxt) && !nxt.includes("://")) { i++; continue; }
    }
    // URL token (scheme optional — scheme-less host/path still accepted)
    if (!t.startsWith("-") && !url) { url = t; continue; }
  }

  if (!url) throw new Error("No valid URL found in cURL command");

  // -G: move body into query string
  let queryExtra = "";
  if (asGet && dataParts.length) {
    queryExtra = dataParts.filter(Boolean).join("&");
    dataParts.length = 0;
    formFieldsFromData.length = 0;
  }
  if (queryExtra) url += (url.includes("?") ? "&" : "?") + queryExtra;

  // Basic auth → Authorization header (AV has no separate auth tab)
  if (basicUser != null) {
    try {
      const token = btoa(unescape(encodeURIComponent(basicUser + ":" + (basicPass || ""))));
      _avSetHeaderCI(headers, "Authorization", "Basic " + token);
    } catch (_) {
      _avSetHeaderCI(headers, "Authorization", "Basic " + basicUser + ":" + (basicPass || ""));
    }
  }

  const bodyJoined = dataParts.length
    ? dataParts.filter((p, idx) => !(p === "" && dataParts.length > 1)).join("&")
    : null;
  const hasBody = formParts.length > 0 || (bodyJoined !== null && bodyJoined !== "") || dataIsJsonFlag;

  if (!method) {
    if (asGet) method = "GET";
    else if (hasBody) method = "POST";
    else method = "GET";
  }

  let body = null, body_type = null, payload = null;
  const ct = _avGetHeaderCI(headers, "Content-Type").toLowerCase();

  if (formParts.length) {
    // Multipart / -F: AV has no file upload — keep text (+ filename placeholders) as form object
    const formObj = {};
    formParts.forEach(f => { formObj[f.key] = f.value; });
    body = formObj;
    body_type = "form";
    payload = Object.entries(formObj).map(([k, v]) =>
      encodeURIComponent(k) + "=" + encodeURIComponent(v == null ? "" : String(v))
    ).join("&");
    if (!ct) _avSetHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded");
  } else if (bodyJoined !== null || dataIsJsonFlag) {
    payload = bodyJoined || "";
    const looksJson = dataIsJsonFlag || _avLooksLikeJson(payload);

    if (
      !looksJson && (
        ct.includes("x-www-form-urlencoded") ||
        dataIsUrlEncode ||
        (formFieldsFromData.length > 0 && (dataParts.length > 1 || dataIsUrlEncode || ct.includes("x-www-form-urlencoded"))) ||
        (dataParts.length > 1 && !dataIsBinary) ||
        (!ct && _avLooksLikeUrlEncoded(payload) && !dataIsBinary)
      )
    ) {
      body_type = "form";
      if (formFieldsFromData.length) {
        body = {};
        formFieldsFromData.forEach(f => { body[f.key] = f.value; });
      } else {
        body = _avParseUrlEncodedBody(payload);
      }
      if (!ct) _avSetHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded");
    } else if (looksJson || ct.includes("application/json") || ct.includes("application/graphql")) {
      try {
        body = JSON.parse(payload);
        body_type = "json";
        // Pretty payload for UI when valid JSON (incl. GraphQL JSON envelopes)
        try { payload = JSON.stringify(body); } catch (_) {}
      } catch (_) {
        try {
          const stripped = _avStripJsonComments(payload);
          body = JSON.parse(stripped);
          body_type = "json";
          try { payload = JSON.stringify(body); } catch (_) {}
        } catch (_) {
          try {
            body = JSON.parse(payload.replace(/\\"/g, '"'));
            body_type = "json";
          } catch (_) {
            body = payload;
            body_type = "raw";
          }
        }
      }
    } else {
      body = payload;
      body_type = "raw";
    }
  }

  const queryParams = {};
  try {
    // Absolute URL preferred; relative / scheme-less still best-effort via URL with base
    let u;
    try { u = new URL(url); }
    catch (_) { u = new URL(url, "http://placeholder.local"); }
    u.searchParams.forEach((v, k) => { queryParams[k] = v; });
  } catch (_) {}

  return {
    method, url, headers, queryParams, body, body_type, payload,
    id: "curl-" + Date.now() + "-" + Math.random().toString(36).slice(2, 7),
    status: null, statusText: "", timestamp: Date.now(), source: "curl",
  };
}

function setupDetailsEdit() {
  const btnER = $("btn-edit-req");
  if (btnER) {
    btnER.addEventListener("click", () => {
      if (_avDetailsEdit.req) return;
      const req = state.selectedRequest;
      if (!req) return;
      _avDetailsEdit.req = true;
      btnER.textContent = "✏️ Editing";
      btnER.style.color = "var(--yellow)";
      const act = $("req-edit-actions");
      if (act) act.style.display = "flex";
      avEnsureMethodOption(req.method || "GET");
      const urlInp = $("det-url-edit");
      if (urlInp) urlInp.value = req.url || "";
      avShowReqEdit();
      requestAnimationFrame(() => urlInp?.focus());
    });
  }

  $("btn-req-cancel")?.addEventListener("click", () => {
    avExitReqEdit();
    avFillReqView(state.selectedRequest);
  });

  $("btn-req-save")?.addEventListener("click", async () => {
    const req = state.selectedRequest;
    if (!req) return;
    const method = ($("det-method-edit")?.value || "GET").trim().toUpperCase();
    const url = ($("det-url-edit")?.value || "").trim();
    if (!url) {
      $("det-url-edit")?.focus();
      return;
    }
    const patch = { method, url };
    const q = avQueryFromUrl(url);
    if (q) patch.queryParams = q;
    await persistRequestPatch(req, patch);
    avExitReqEdit();
    avFillReqView(req);
    if (q) {
      _avDetailsEdit.query = false;
      const btnEQ = $("btn-edit-query");
      if (btnEQ) { btnEQ.textContent = "✏️ Edit"; btnEQ.style.color = ""; }
      const qAct = $("query-edit-actions");
      if (qAct) qAct.style.display = "none";
      avRefreshQuerySection(req);
    }
    renderRequestList();
    showEditHint();
  });

  $("det-url-edit")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("btn-req-save")?.click(); }
    if (e.key === "Escape") { e.preventDefault(); $("btn-req-cancel")?.click(); }
  });

  const btnEH = $("btn-edit-headers");
  if (btnEH) {
    btnEH.addEventListener("click", () => {
      if (_avDetailsEdit.hdr) return;
      _avDetailsEdit.hdr = true;
      btnEH.textContent = "✏️ Editing";
      btnEH.style.color = "var(--yellow)";
      $("hdr-edit-actions").style.display = "flex";
      const hdrs = state.selectedRequest?.headers || {};
      $("headers-table").innerHTML = Object.entries(hdrs).map(([k, v]) => avKvEditHtml(k, v)).join("");
    });
  }

  $("btn-headers-cancel")?.addEventListener("click", () => {
    _avDetailsEdit.hdr = false;
    btnEH.textContent = "✏️ Edit";
    btnEH.style.color = "";
    $("hdr-edit-actions").style.display = "none";
    const hdrs = state.selectedRequest?.headers || {};
    $("hdr-count").textContent = Object.keys(hdrs).length;
    avRenderKvTable("headers-table", hdrs, 60);
  });

  $("btn-headers-save")?.addEventListener("click", async () => {
    const req = state.selectedRequest;
    if (!req) return;
    const newHdrs = avReadKvEdits($("headers-table"));
    await persistRequestPatch(req, { headers: newHdrs });
    _avDetailsEdit.hdr = false;
    btnEH.textContent = "✏️ Edit";
    btnEH.style.color = "";
    $("hdr-edit-actions").style.display = "none";
    $("hdr-count").textContent = Object.keys(newHdrs).length;
    avRenderKvTable("headers-table", newHdrs, 60);
    showEditHint();
  });

  const bodyEditBtn = $("btn-edit-body");
  const pre = $("body-preview");
  const ta = $("body-editor");
  $("btn-expand-body")?.addEventListener("click", () => {
    if (!pre) return;
    const open = pre.classList.toggle("is-expanded");
    const btn = $("btn-expand-body");
    if (btn) btn.textContent = open ? "Collapse" : "↕ Full";
  });
  if (bodyEditBtn && pre && ta) {
    bodyEditBtn.addEventListener("click", () => {
      if (_avDetailsEdit.body) return;
      _avDetailsEdit.body = true;
      bodyEditBtn.textContent = "✏️ Editing";
      bodyEditBtn.style.color = "var(--yellow)";
      $("body-edit-actions").style.display = "flex";
      ta.value = avBodyText(state.selectedRequest);
      ta.hidden = false;
      ta.style.display = "block";
      pre.style.display = "none";
      requestAnimationFrame(() => ta.focus());
    });

    $("btn-body-cancel")?.addEventListener("click", () => {
      _avDetailsEdit.body = false;
      bodyEditBtn.textContent = "✏️ Edit";
      bodyEditBtn.style.color = "";
      $("body-edit-actions").style.display = "none";
      ta.style.display = "none";
      ta.hidden = true;
      ta.value = "";
      pre.style.display = "";
      pre.textContent = avBodyText(state.selectedRequest);
    });

    $("btn-body-save")?.addEventListener("click", async () => {
      const req = state.selectedRequest;
      if (!req) return;
      const raw = ta.value.trim();
      let parsed, type;
      try { parsed = JSON.parse(raw); type = "json"; }
      catch (e) { parsed = raw; type = "raw"; }
      await persistRequestPatch(req, { body: parsed, body_type: type, payload: raw });
      const keys = typeof parsed === "object" && parsed ? Object.keys(parsed).length : 1;
      $("body-count").textContent = `${keys} fields`;
      $("body-type-badge").textContent = type;
      _avDetailsEdit.body = false;
      bodyEditBtn.textContent = "✏️ Edit";
      bodyEditBtn.style.color = "";
      $("body-edit-actions").style.display = "none";
      ta.style.display = "none";
      ta.hidden = true;
      ta.value = "";
      pre.style.display = "";
      pre.textContent = avBodyText(req);
      showEditHint();
    });
  }
}

function showEditHint() {
  const hint = $("details-edit-hint");
  if (!hint) return;
  hint.style.display = "inline";
  setTimeout(() => { hint.style.display = "none"; }, 2500);
}

// ── Query Params inline edit ─────────────────────────────────────────────────
function setupQueryEdit() {
  const btnEQ = $("btn-edit-query");
  if (!btnEQ) return;

  btnEQ.addEventListener("click", () => {
    if (_avDetailsEdit.query) return;
    _avDetailsEdit.query = true;
    btnEQ.textContent = "✏️ Editing";
    btnEQ.style.color = "var(--yellow)";
    $("query-edit-actions").style.display = "flex";
    const q = state.selectedRequest?.queryParams || {};
    $("query-table").innerHTML = Object.entries(q).map(([k, v]) => avKvEditHtml(k, v)).join("");
  });

  $("btn-query-cancel")?.addEventListener("click", () => {
    _avDetailsEdit.query = false;
    btnEQ.textContent = "✏️ Edit";
    btnEQ.style.color = "";
    $("query-edit-actions").style.display = "none";
    const q = state.selectedRequest?.queryParams || {};
    $("query-count").textContent = Object.keys(q).length;
    avRenderKvTable("query-table", q, 80);
  });

  $("btn-query-save")?.addEventListener("click", async () => {
    const req = state.selectedRequest;
    if (!req) return;
    const newQ = avReadKvEdits($("query-table"));
    await persistRequestPatch(req, { queryParams: newQ });
    _avDetailsEdit.query = false;
    btnEQ.textContent = "✏️ Edit";
    btnEQ.style.color = "";
    $("query-edit-actions").style.display = "none";
    $("query-count").textContent = Object.keys(newQ).length;
    avRenderKvTable("query-table", newQ, 80);
    showEditHint();
  });
}

// ── PATCH 3: Params Search ─────────────────────────────────────────────────────
function setupParamsSearch() {
  const inp = $("params-search");
  if (!inp) return;
  inp.addEventListener("input", (e) => {
    state.paramsSearchQuery = e.target.value;
    renderParamsTable();
  });
}

// ── Detail Search (Patch 5) ───────────────────────────────────────────────────
function detailSearch(preId, query) {
  const pre = document.getElementById(preId);
  if (!pre) return;
  avPaintDetailPre(pre, query);
  if ((query || "").trim()) {
    const first = pre.querySelector("mark");
    if (first) first.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str || "")
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;");
}

function truncate(str, n) {
  str = String(str || "");
  return str.length > n ? str.substring(0, n) + "…" : str;
}

async function fetchBackend(path, method = "GET", body = null) {
  const opts = {
    method,
    headers: { "Content-Type": "application/json" },
  };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`${BACKEND}${path}`, opts);
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${txt}`);
  }
  return resp.json();
}

// Expose state globally for other modules (e.g. Method Tampering)
window._avState = state;
