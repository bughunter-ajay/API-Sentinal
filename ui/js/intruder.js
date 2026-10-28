// ── Intruder (Burp-style: Sniper / Battering ram / Pitchfork / Cluster bomb) ──
"use strict";

const INTR_BASE = "http://127.0.0.1:8794";

let _intrJobId = null;
let _intrPoll = null;
let _intrResults = [];
let _intrSince = 0;
let _intrSort = { key: "id", dir: 1 };
let _intrFilter = { text: "", status: "" };
let _intrDashboard = null;
let _intrSel = { start: 0, end: 0 };
let _intrCtx = null; // { start, end }
let _intrSelectedId = null;
let _intrRespTab = "pretty";
let _intrSelectedRow = null;
let _intrPayloads = ["admin", "test", "1", "true", "{uuid}"];
/** Per-position payload lists (Sniper / Pitchfork / Cluster). Index 0 = Position 1. */
let _intrPayloadSets = [["admin", "test", "1", "true", "{uuid}"]];
/** Which position's list is currently shown in Payload configuration (0-based). */
let _intrEditSetIdx = 0;
/** Per-position Unique format ("" = attack variable with a payload list). */
let _intrUniqueFormats = [""];
/** Last non-unique payload type (simple|numbers|null). */
let _intrListPayType = "simple";
let _intrUniqueModalIdx = -1;
let _intrProcRules = [];
let _intrProcSeq = 0;

function intrEl(id) { return document.getElementById(id); }

function intrAlert(msg) {
  if (typeof _aspAlert === "function") {
    try { _aspAlert(String(msg)); return; } catch (_) {}
  }
  try { window.alert(String(msg)); } catch (_) { console.warn(msg); }
}

function intrSwitchTab(tab) {
  ["attack", "scanning", "dashboard"].forEach((t) => {
    const btn = intrEl("intr-tab-" + t);
    const pane = intrEl("intr-tab-" + t + "-content");
    if (btn) btn.classList.toggle("active", t === tab);
    if (pane) {
      pane.classList.toggle("active", t === tab);
      pane.style.display = t === tab ? "flex" : "none";
    }
  });
  if (tab === "dashboard") intrRenderDashboard();
}

function intrReset() {
  if (_intrJobId) {
    fetch(`${INTR_BASE}/intruder/stop/${_intrJobId}`, { method: "POST" }).catch(() => {});
  }
  _intrJobId = null;
  _intrResults = [];
  _intrSince = 0;
  _intrDashboard = null;
  _intrSel = { start: 0, end: 0 };
  _intrSelectedId = null;
  _intrSelectedRow = null;
  _intrRespTab = "pretty";
  if (_intrPoll) { clearInterval(_intrPoll); _intrPoll = null; }
  const tpl = intrEl("intr-template");
  if (tpl) tpl.value = "";
  _intrPayloads = [];
  _intrPayloadSets = [[]];
  _intrUniqueFormats = [""];
  _intrEditSetIdx = 0;
  _intrListPayType = "simple";
  _intrProcRules = [];
  const add = intrEl("intr-pay-add");
  if (add) add.value = "";
  const enc = intrEl("intr-url-encode");
  if (enc) enc.checked = true;
  const chars = intrEl("intr-url-chars");
  if (chars) chars.value = ".\\=<>?+&*':;\"()|^`#";
  const threads = intrEl("intr-threads");
  if (threads) threads.value = "1";
  const delay = intrEl("intr-delay-ms");
  if (delay) delay.value = "0";
  const pxy = intrEl("intr-proxy-url");
  if (pxy) pxy.value = "";
  const plist = intrEl("intr-proxy-list");
  if (plist) plist.value = "";
  const prot = intrEl("intr-proxy-rotate");
  if (prot) prot.checked = false;
  const gmInp = intrEl("intr-grep-match-input");
  if (gmInp) gmInp.value = "";
  const geInp = intrEl("intr-grep-extract-input");
  if (geInp) geInp.value = "";
  intrSyncProxyBtn();
  const atype = intrEl("intr-attack-type");
  if (atype) atype.value = "sniper";
  const ptype = intrEl("intr-pay-type");
  if (ptype) ptype.value = "simple";
  intrOnPayloadTypeChange();
  intrOnAttackTypeChange();
  intrRenderPayloadList();
  intrRenderProcRules();
  intrUpdatePosCount();
  intrRenderScanList();
  intrShowDetailEmpty();
  intrRenderDashboard();
  const fill = intrEl("intr-scan-fill");
  const stats = intrEl("intr-scan-stats");
  const title = intrEl("intr-scan-title");
  if (fill) fill.style.width = "0%";
  if (stats) stats.textContent = "0 / 0";
  if (title) title.textContent = "No attack running";
  intrSetStopBtn("idle");
  intrSwitchTab("attack");
}

// ── Selection memory (Mark button steals focus otherwise) ────────────────────

function intrRememberSel() {
  const ta = intrEl("intr-template");
  if (!ta) return;
  _intrSel = {
    start: ta.selectionStart || 0,
    end: ta.selectionEnd || 0,
  };
}

function intrGetMarkRange() {
  const ta = intrEl("intr-template");
  if (!ta) return { start: 0, end: 0 };
  let start = ta.selectionStart || 0;
  let end = ta.selectionEnd || 0;
  if (start === end && _intrSel && _intrSel.start !== _intrSel.end) {
    start = _intrSel.start;
    end = _intrSel.end;
  }
  return { start, end };
}

// ── Import cURL ──────────────────────────────────────────────────────────────

function intrShowCurlImport() {
  const m = intrEl("intr-curl-modal");
  const inp = intrEl("intr-curl-modal-input");
  const err = intrEl("intr-curl-modal-error");
  if (inp) inp.value = "";
  if (err) { err.style.display = "none"; err.textContent = ""; }
  if (m) m.style.display = "flex";
  setTimeout(() => { if (inp) inp.focus(); }, 60);
}

function intrCloseCurlModal() {
  const m = intrEl("intr-curl-modal");
  if (m) m.style.display = "none";
}

async function intrImportCurl() {
  const inp = intrEl("intr-curl-modal-input");
  const errEl = intrEl("intr-curl-modal-error");
  const curl = (inp ? inp.value : "").trim();
  if (!curl) {
    if (errEl) {
      errEl.textContent = "Paste a cURL command first.";
      errEl.style.display = "block";
    }
    return;
  }
  try {
    const httpTpl = await intrCurlToHttpTemplate(curl);
    const ta = intrEl("intr-template");
    if (ta) ta.value = httpTpl;
    intrUpdatePosCount();
    if (errEl) errEl.style.display = "none";
    intrCloseCurlModal();
    if (ta) { ta.focus(); ta.setSelectionRange(0, 0); }
  } catch (e) {
    if (errEl) {
      errEl.textContent = "cURL parse error: " + e.message;
      errEl.style.display = "block";
    }
  }
}

/** True if text still looks like a shell cURL (not Burp raw HTTP). */
function intrLooksLikeCurl(text) {
  const t = String(text || "").trim();
  if (!t) return false;
  if (/^curl(?:\.exe)?\b/i.test(t)) return true;
  // Multi-line curl paste without leading curl on first non-empty? rare
  return /\n\s*-H\s+['"]/.test(t) && /\n\s*-X\s+['"]/.test(t);
}

/**
 * Parse cURL → Burp-style raw HTTP template.
 * Always builds from method/url/headers/body — never leaves -H / -X shell flags in the editor.
 */
async function intrCurlToHttpTemplate(curl) {
  const r = await fetch(`${INTR_BASE}/intruder/parse_curl`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ curl }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const detail = data.detail;
    const msg = typeof detail === "string" ? detail
      : (Array.isArray(detail) ? detail.map((d) => d.msg || d).join("; ") : null);
    throw new Error(msg || data.message || "Parse failed");
  }
  let tpl = data.template && String(data.template).trim()
    ? String(data.template)
    : "";
  // Never keep shell curl in the editor — rebuild if needed
  if (!tpl || intrLooksLikeCurl(tpl)) {
    tpl = intrBuildHttpTemplate(data);
  }
  if (!tpl.trim() || intrLooksLikeCurl(tpl)) {
    throw new Error("Could not build HTTP template from cURL");
  }
  return tpl;
}

/** If the request editor still has raw cURL, convert it in place (paste / leftover). */
async function intrEnsureHttpTemplate(opts) {
  const silent = !!(opts && opts.silent);
  const ta = intrEl("intr-template");
  if (!ta) return false;
  const raw = ta.value || "";
  if (!intrLooksLikeCurl(raw)) return false;
  try {
    const httpTpl = await intrCurlToHttpTemplate(raw.trim());
    ta.value = httpTpl;
    intrUpdatePosCount();
    return true;
  } catch (e) {
    if (!silent) {
      intrAlert("cURL → HTTP convert failed: " + (e && e.message ? e.message : e));
    }
    return false;
  }
}

async function intrOnTemplatePaste(e) {
  // Let the paste land, then convert if it's cURL
  setTimeout(() => { intrEnsureHttpTemplate({ silent: true }); }, 0);
}

/** Build METHOD/URL + headers + blank line + body (same shape as backend). */
function intrBuildHttpTemplate(parsed) {
  const method = (parsed && parsed.method) || "GET";
  const url = (parsed && parsed.url) || "";
  const lines = [`${method} ${url}`];
  const hdrs = (parsed && parsed.headers) || {};
  Object.keys(hdrs).forEach((k) => {
    lines.push(`${k}: ${hdrs[k]}`);
  });
  lines.push("");
  lines.push((parsed && parsed.body) != null ? String(parsed.body) : "");
  return lines.join("\n");
}

function intrMarkSelection() {
  const ta = intrEl("intr-template");
  if (!ta) return;
  if (intrLooksLikeCurl(ta.value)) {
    intrEnsureHttpTemplate({ silent: false }).then((ok) => {
      if (ok) intrAlert("Converted cURL → raw HTTP. Select text again, then Mark § §.");
    });
    return;
  }
  const { start, end } = intrGetMarkRange();
  if (start === end) {
    intrAlert("Select text in the request, then click Mark § §.");
    return;
  }
  const val = ta.value;
  const selected = val.slice(start, end);
  const wrapped = selected.startsWith("§") && selected.endsWith("§")
    ? selected
    : ("§" + selected + "§");
  ta.value = val.slice(0, start) + wrapped + val.slice(end);
  ta.focus();
  const ns = start;
  const ne = start + wrapped.length;
  ta.setSelectionRange(ns, ne);
  _intrSel = { start: ns, end: ne };
  intrUpdatePosCount();
}

function intrClearMarks() {
  const ta = intrEl("intr-template");
  if (!ta) return;
  ta.value = ta.value.replace(/§/g, "");
  _intrSel = { start: 0, end: 0 };
  intrUpdatePosCount();
}

function intrToggleAcc(btn) {
  const acc = btn && btn.parentElement;
  if (acc) acc.classList.toggle("open");
}

function intrGetAttackType() {
  return ((intrEl("intr-attack-type") && intrEl("intr-attack-type").value) || "sniper").toLowerCase();
}

function intrIsMultiSetAttack() {
  const t = intrGetAttackType();
  return t === "pitchfork" || t === "cluster_bomb";
}

/** Sniper + Pitchfork + Cluster: each §position§ has its own payload list. */
function intrUsesPerPositionSets() {
  return intrGetAttackType() !== "battering_ram";
}

function intrCountPositions() {
  const tpl = (intrEl("intr-template") && intrEl("intr-template").value) || "";
  const bases = [];
  const re = /§(.*?)§/g;
  let m;
  while ((m = re.exec(tpl))) bases.push(m[1]);
  return bases;
}

function intrSaveCurrentSet() {
  if (!_intrPayloadSets.length) _intrPayloadSets.push([]);
  const idx = Math.min(Math.max(0, _intrEditSetIdx), _intrPayloadSets.length - 1);
  _intrPayloadSets[idx] = _intrPayloads.slice();
}

function intrLoadEditSet(idx) {
  intrSaveCurrentSet();
  const n = Math.max(1, intrCountPositions().length || 1);
  while (_intrPayloadSets.length < n) _intrPayloadSets.push([]);
  _intrEditSetIdx = Math.max(0, Math.min(idx, n - 1));
  _intrPayloads = (_intrPayloadSets[_intrEditSetIdx] || []).slice();
  intrRenderPayloadList();
}

function intrSyncSetsToPositionCount() {
  const n = Math.max(intrCountPositions().length, 1);
  while (_intrPayloadSets.length < n) {
    _intrPayloadSets.push([]);
  }
  if (_intrPayloadSets.length > n) _intrPayloadSets.length = n;
  while (_intrUniqueFormats.length < n) _intrUniqueFormats.push("");
  if (_intrUniqueFormats.length > n) _intrUniqueFormats.length = n;
  if (_intrEditSetIdx >= n) _intrEditSetIdx = Math.max(0, n - 1);
  if (!intrUsesPerPositionSets()) {
    _intrPayloadSets[0] = _intrPayloads.slice();
    _intrEditSetIdx = 0;
  } else {
    _intrPayloads = (_intrPayloadSets[_intrEditSetIdx] || []).slice();
  }
}

function intrIsUniquePos(idx) {
  return idx >= 0 && !!((_intrUniqueFormats[idx] || "").trim());
}

function intrCurrentPosIdx() {
  const posSel = intrEl("intr-pay-position");
  const val = (posSel && posSel.value) || "all";
  if (val === "all") return -1;
  return Math.max(0, (parseInt(val, 10) || 1) - 1);
}

function intrAttackPositionIndices(nPos) {
  const n = Math.max(nPos || 0, 0);
  const out = [];
  for (let i = 0; i < n; i++) {
    if (!intrIsUniquePos(i)) out.push(i);
  }
  return out;
}

function intrShowAttackInfo() {
  const m = intrEl("intr-attack-info-modal");
  if (m) m.style.display = "flex";
}
function intrCloseAttackInfo() {
  const m = intrEl("intr-attack-info-modal");
  if (m) m.style.display = "none";
}

function intrProxyListLines() {
  const ta = intrEl("intr-proxy-list");
  const raw = (ta && ta.value) || "";
  return raw.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && s.charAt(0) !== "#");
}
function intrCollectProxyCfg() {
  return {
    proxy: ((intrEl("intr-proxy-url") && intrEl("intr-proxy-url").value) || "").trim(),
    proxy_list: intrProxyListLines(),
    proxy_rotate: !!(intrEl("intr-proxy-rotate") && intrEl("intr-proxy-rotate").checked),
  };
}
function intrSyncProxyBtn() {
  const btn = intrEl("intr-proxy-list-btn");
  if (!btn) return;
  const n = intrProxyListLines().length;
  const rot = !!(intrEl("intr-proxy-rotate") && intrEl("intr-proxy-rotate").checked);
  btn.classList.toggle("has-list", n > 0 || rot);
  if (rot && n) btn.textContent = "List ↻ " + n;
  else if (rot) btn.textContent = "List ↻";
  else if (n) btn.textContent = "List (" + n + ")";
  else btn.textContent = "List";
}
function intrOpenProxyModal() {
  const m = intrEl("intr-proxy-modal");
  if (m) m.style.display = "flex";
}
function intrCloseProxyModal() {
  const m = intrEl("intr-proxy-modal");
  if (m) m.style.display = "none";
  intrSyncProxyBtn();
}

function intrOnAttackTypeChange() {
  intrSaveCurrentSet();
  intrSyncSetsToPositionCount();
  const perPos = intrUsesPerPositionSets();
  const label = intrEl("intr-pos-label");
  if (label) {
    const first = label.childNodes[0];
    if (first && first.nodeType === 3) {
      first.textContent = perPos ? "Payload position  " : "Payloads (all positions)  ";
    }
  }
  const hint = intrEl("intr-attack-hint");
  const t = intrGetAttackType();
  if (hint) {
    const tips = {
      sniper: "Sniper: each list position has its own payloads. Unique-format positions are skipped by the attack and get a fresh value on every hit.",
      battering_ram: "Battering ram: one list goes into every payload-list §position§ at once. Unique-format positions still get a fresh value each hit.",
      pitchfork: "Pitchfork: pair line i across payload-list positions. Unique-format positions are not paired — they refresh every request.",
      cluster_bomb: "Cluster bomb: all combinations of payload-list positions. Unique-format positions refresh every request.",
    };
    hint.textContent = tips[t] || "";
  }
  const btn = intrEl("intr-btn-sniper");
  if (btn) {
    const names = {
      sniper: "▶ Start Sniper",
      battering_ram: "▶ Start Battering ram",
      pitchfork: "▶ Start Pitchfork",
      cluster_bomb: "▶ Start Cluster bomb",
    };
    btn.textContent = names[t] || "▶ Start attack";
  }
  intrUpdatePosCount();
}

function intrOnPositionSelectChange() {
  const posSel = intrEl("intr-pay-position");
  const val = (posSel && posSel.value) || "all";
  if (!intrUsesPerPositionSets()) {
    intrSaveCurrentSet();
    if (val !== "all") {
      const idx = Math.max(0, (parseInt(val, 10) || 1) - 1);
      _intrEditSetIdx = idx;
    }
    intrUpdatePosCount();
    intrSyncPayloadTypeUi(false);
    return;
  }
  if (val === "all") {
    intrSaveCurrentSet();
    intrRenderPayloadList();
    intrSyncPayloadTypeUi(false);
    return;
  }
  const idx = Math.max(0, (parseInt(val, 10) || 1) - 1);
  intrLoadEditSet(idx);
  intrSyncPayloadTypeUi(false);
}

function intrCalcRequestCount(nPos, payloadsLen) {
  const t = intrGetAttackType();
  const posSel = intrEl("intr-pay-position");
  const posVal = (posSel && posSel.value) || "all";
  const attackIdx = intrAttackPositionIndices(nPos);
  if (t === "battering_ram") return payloadsLen;
  if (t === "pitchfork") {
    if (!attackIdx.length) return 0;
    const sets = attackIdx.map((i) => _intrPayloadSets[i] || []);
    if (sets.some((s) => !s.length)) return 0;
    return Math.min(...sets.map((s) => s.length));
  }
  if (t === "cluster_bomb") {
    if (!attackIdx.length) return 0;
    const sets = attackIdx.map((i) => _intrPayloadSets[i] || []);
    if (sets.some((s) => !s.length)) return 0;
    return sets.reduce((a, s) => a * s.length, 1);
  }
  // sniper
  if (posVal !== "all") {
    const i = Math.max(0, (parseInt(posVal, 10) || 1) - 1);
    if (intrIsUniquePos(i)) return 0;
    return (_intrPayloadSets[i] || []).length;
  }
  let sum = 0;
  attackIdx.forEach((i) => { sum += (_intrPayloadSets[i] || []).length; });
  return sum;
}

function intrUpdatePosCount() {
  const bases = intrCountPositions();
  const n = bases.length;
  intrSaveCurrentSet();
  intrSyncSetsToPositionCount();

  const el = intrEl("intr-pos-count");
  if (el) el.textContent = n + " position" + (n === 1 ? "" : "s");

  const perPos = intrUsesPerPositionSets();
  const multi = intrIsMultiSetAttack();
  const posSel = intrEl("intr-pay-position");
  if (posSel) {
    const cur = posSel.value;
    const posOpts = bases.map((b, i) => {
      const label = (b || "").slice(0, 24);
      const uniq = (_intrUniqueFormats[i] || "").trim();
      const name = multi ? `Set ${i + 1}` : `Position ${i + 1}`;
      if (uniq) {
        const short = uniq.length > 22 ? uniq.slice(0, 20) + "…" : uniq;
        return `<option value="${i + 1}">${name} (UNIQUE · ${intrEsc(short)})${label ? " — " + intrEsc(label) : ""}</option>`;
      }
      const cnt = (_intrPayloadSets[i] || []).length;
      return `<option value="${i + 1}">${name} (${cnt})${label ? " — " + intrEsc(label) : ""}</option>`;
    }).join("");
    if (perPos && !multi) {
      posSel.disabled = false;
      posSel.innerHTML = '<option value="all">All positions (own lists)</option>' + posOpts;
      if (cur === "all") posSel.value = "all";
      else if ([].some.call(posSel.options, (o) => o.value === cur)) posSel.value = cur;
      else posSel.value = String(_intrEditSetIdx + 1);
    } else if (multi) {
      posSel.disabled = false;
      posSel.innerHTML = posOpts || '<option value="1">Set 1</option>';
      const prefer = String(_intrEditSetIdx + 1);
      if ([].some.call(posSel.options, (o) => o.value === prefer)) posSel.value = prefer;
      else if ([].some.call(posSel.options, (o) => o.value === cur)) posSel.value = cur;
    } else {
      posSel.innerHTML = '<option value="all">All payload positions</option>' + posOpts;
      posSel.disabled = false;
      if (cur === "all" || !cur) posSel.value = "all";
      else if ([].some.call(posSel.options, (o) => o.value === cur)) posSel.value = cur;
    }
  }

  if (perPos) {
    _intrPayloadSets[_intrEditSetIdx] = _intrPayloads.slice();
  } else {
    _intrPayloadSets[0] = _intrPayloads.slice();
  }

  const payloads = intrGetPayloads();
  const pc = intrEl("intr-payload-count");
  if (pc) {
    if (perPos) {
      const total = _intrPayloadSets.slice(0, Math.max(n, 1)).reduce((a, s) => a + (s || []).length, 0);
      const allSel = posSel && posSel.value === "all";
      const viewIdx = allSel ? _intrEditSetIdx : Math.max(0, (parseInt(posSel.value, 10) || 1) - 1);
      if (intrIsUniquePos(viewIdx) && !allSel) {
        pc.textContent = "UNIQUE";
      } else if (allSel) {
        const uN = _intrUniqueFormats.slice(0, n).filter((s) => (s || "").trim()).length;
        pc.textContent = uN ? `${total} list · ${uN} unique` : String(total);
      } else {
        pc.textContent = String(payloads.length);
      }
    } else {
      pc.textContent = String(payloads.length);
    }
  }
  const rc = intrEl("intr-req-count");
  if (rc) {
    const reqs = intrCalcRequestCount(n, payloads.length);
    rc.textContent = String(reqs);
    rc.title = reqs > 25000 ? "Too many requests — shrink lists" : "";
    rc.style.color = reqs > 25000 ? "#f85149" : "";
  }
  const hidden = intrEl("intr-payloads");
  if (hidden) hidden.value = payloads.join("\n");
  intrRefreshTemplateHighlight();
}

function intrSyncListToSelect(selId, items) {
  const sel = intrEl(selId);
  if (!sel) return;
  const picked = [].map.call(sel.selectedOptions || [], (o) => o.value);
  sel.innerHTML = (items || []).map((p, i) => {
    const vis = p === "" ? "(empty)" : String(p);
    return `<option value="${i}">${intrEsc(vis)}</option>`;
  }).join("");
  [].forEach.call(sel.options, (o) => {
    if (picked.indexOf(o.value) >= 0) o.selected = true;
  });
}

function intrRenderPayloadList() {
  const box = intrEl("intr-pay-list");
  if (box) {
    const picked = new Set();
    box.querySelectorAll(".intr-pay-row.selected").forEach((r) => {
      const i = parseInt(r.getAttribute("data-i"), 10);
      if (!isNaN(i)) picked.add(i);
    });
    const items = _intrPayloads || [];
    if (!items.length) {
      box.innerHTML = '<div class="intr-pay-empty">No payloads — Add, Paste, or Load</div>';
    } else {
      box.innerHTML = items.map((p, i) => {
        const vis = p === "" ? "(empty)" : String(p);
        const sel = picked.has(i) ? " selected" : "";
        return `<div class="intr-pay-row${sel}" data-i="${i}" role="option" aria-selected="${picked.has(i) ? "true" : "false"}">${intrEsc(vis)}</div>`;
      }).join("");
    }
  }
  intrUpdatePosCount();
}

function intrBindPayList() {
  const box = intrEl("intr-pay-list");
  if (!box || box._intrBound) return;
  box._intrBound = true;
  box.addEventListener("click", (e) => {
    const row = e.target.closest(".intr-pay-row");
    if (!row || !box.contains(row)) return;
    const rows = [].slice.call(box.querySelectorAll(".intr-pay-row"));
    if (e.metaKey || e.ctrlKey) {
      row.classList.toggle("selected");
    } else {
      rows.forEach((r) => r.classList.remove("selected"));
      row.classList.add("selected");
    }
    rows.forEach((r) => r.setAttribute("aria-selected", r.classList.contains("selected") ? "true" : "false"));
  });
}

function intrOnPayloadTypeChange() {
  const ptype = intrEl("intr-pay-type");
  const t = (ptype && ptype.value) || "simple";
  if (t === "unique") {
    const idx = intrCurrentPosIdx();
    if (idx < 0) {
      intrAlert("Pick a specific Payload position first, then set Unique format.\n\n“All positions” cannot be Unique — Unique is per variable.");
      if (ptype) ptype.value = _intrListPayType || "simple";
      intrShowListPayloadPanels(_intrListPayType || "simple");
      return;
    }
    if (!intrIsUniquePos(idx)) {
      intrOpenUniqueModal();
      return;
    }
    intrShowListPayloadPanels("unique");
    intrUpdatePosCount();
    return;
  }
  const idx = intrCurrentPosIdx();
  if (idx >= 0 && intrIsUniquePos(idx)) {
    _intrUniqueFormats[idx] = "";
  }
  _intrListPayType = t;
  intrShowListPayloadPanels(t);
  if (t === "numbers") intrPreviewNumbers();
  if (t === "null") intrPreviewNulls();
  intrUpdatePosCount();
}

function intrShowListPayloadPanels(t) {
  const simple = intrEl("intr-cfg-simple");
  const nums = intrEl("intr-cfg-numbers");
  const nul = intrEl("intr-cfg-null");
  const uniq = intrEl("intr-cfg-unique");
  if (simple) simple.style.display = t === "simple" ? "" : "none";
  if (nums) nums.style.display = t === "numbers" ? "" : "none";
  if (nul) nul.style.display = t === "null" ? "" : "none";
  if (uniq) uniq.style.display = t === "unique" ? "" : "none";
  const view = intrEl("intr-unique-fmt-view");
  const idx = _intrEditSetIdx;
  if (view) view.textContent = (_intrUniqueFormats[idx] || "").trim() || "—";
}

function intrSyncPayloadTypeUi(openModalIfEmpty) {
  const idx = intrCurrentPosIdx() >= 0 ? intrCurrentPosIdx() : _intrEditSetIdx;
  const ptype = intrEl("intr-pay-type");
  if (intrIsUniquePos(idx)) {
    if (ptype) ptype.value = "unique";
    _intrEditSetIdx = idx;
    intrShowListPayloadPanels("unique");
  } else {
    if (ptype) ptype.value = _intrListPayType || "simple";
    intrShowListPayloadPanels(_intrListPayType || "simple");
  }
  if (openModalIfEmpty && ptype && ptype.value === "unique" && !intrIsUniquePos(idx)) {
    intrOpenUniqueModal();
  }
}

function intrPreviewNumbers() {
  const from = parseInt((intrEl("intr-num-from") && intrEl("intr-num-from").value) || "1", 10);
  const to = parseInt((intrEl("intr-num-to") && intrEl("intr-num-to").value) || "100", 10);
  let step = parseInt((intrEl("intr-num-step") && intrEl("intr-num-step").value) || "1", 10);
  if (!step) step = 1;
  const out = [];
  if (step > 0) {
    for (let n = from; n <= to && out.length < 5000; n += step) out.push(String(n));
  } else {
    for (let n = from; n >= to && out.length < 5000; n += step) out.push(String(n));
  }
  _intrPayloads = out;
  intrSyncListToSelect("intr-num-preview", out);
  intrUpdatePosCount();
}

function intrPreviewNulls() {
  const count = Math.max(1, Math.min(500, parseInt((intrEl("intr-null-count") && intrEl("intr-null-count").value) || "20", 10)));
  const ch = ((intrEl("intr-null-char") && intrEl("intr-null-char").value) || "A").slice(0, 1) || "A";
  const out = [""];
  for (let i = 1; i < count; i++) out.push(ch.repeat(i));
  _intrPayloads = out;
  intrUpdatePosCount();
}

function intrPayloadAdd() {
  const inp = intrEl("intr-pay-add");
  const v = inp ? inp.value : "";
  _intrPayloads.push(v);
  if (inp) { inp.value = ""; inp.focus(); }
  intrRenderPayloadList();
}

function _intrSplitLines(text) {
  return String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function _intrAppendPayloads(lines) {
  (lines || []).forEach((l) => { _intrPayloads.push(l); });
  if (_intrPayloads.length > 5000) _intrPayloads = _intrPayloads.slice(0, 5000);
  intrRenderPayloadList();
}

async function intrPayloadPaste() {
  try {
    if (navigator.clipboard && navigator.clipboard.readText) {
      const t = await navigator.clipboard.readText();
      if (t) { _intrAppendPayloads(_intrSplitLines(t)); return; }
    }
  } catch (_) {}
  const m = intrEl("intr-paste-modal");
  const inp = intrEl("intr-paste-input");
  if (inp) inp.value = "";
  if (m) m.style.display = "flex";
  setTimeout(() => { if (inp) inp.focus(); }, 40);
}

function intrClosePasteModal() {
  const m = intrEl("intr-paste-modal");
  if (m) m.style.display = "none";
}

function intrConfirmPaste() {
  const inp = intrEl("intr-paste-input");
  _intrAppendPayloads(_intrSplitLines(inp ? inp.value : ""));
  intrClosePasteModal();
}

function intrPayloadLoad() {
  const f = intrEl("intr-pay-file");
  if (f) { f.value = ""; f.click(); }
}

function intrPayloadFilePicked(ev) {
  const file = ev && ev.target && ev.target.files && ev.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    _intrAppendPayloads(_intrSplitLines(String(reader.result || "")));
  };
  reader.onerror = () => intrAlert("Could not read file.");
  reader.readAsText(file);
}

function intrPayloadRemove() {
  const box = intrEl("intr-pay-list");
  if (!box) return;
  const idx = [].map.call(box.querySelectorAll(".intr-pay-row.selected"), (r) => parseInt(r.getAttribute("data-i"), 10))
    .filter((n) => !isNaN(n))
    .sort((a, b) => b - a);
  if (!idx.length) { intrAlert("Select one or more payloads to remove."); return; }
  idx.forEach((i) => _intrPayloads.splice(i, 1));
  intrRenderPayloadList();
}

function intrPayloadClear() {
  _intrPayloads = [];
  intrRenderPayloadList();
}

function intrPayloadDedup() {
  const seen = Object.create(null);
  const out = [];
  _intrPayloads.forEach((p) => {
    if (seen[p] == null) { seen[p] = 1; out.push(p); }
  });
  _intrPayloads = out;
  intrRenderPayloadList();
}

const INTR_WORDLISTS = {
  bool: ["true", "false"],
};

function intrValueLists() {
  const raw = window.INTR_VALUE_LISTS;
  return Array.isArray(raw) ? raw : [];
}

function intrFillValueListDropdown() {
  const sel = intrEl("intr-pay-from-list");
  if (!sel) return;
  const packs = intrValueLists();
  const groups = [];
  const seen = Object.create(null);
  packs.forEach((p) => {
    const g = p.group || "Other";
    if (!seen[g]) { seen[g] = 1; groups.push(g); }
  });
  let html = '<option value="">Add from list…</option>';
  groups.forEach((g) => {
    html += `<optgroup label="${intrEsc(g)}">`;
    packs.filter((p) => (p.group || "Other") === g).forEach((p) => {
      const n = (p.payloads || []).length;
      const label = n ? `${p.label} (${n})` : p.label;
      html += `<option value="${intrEsc(p.id)}">${intrEsc(label)}</option>`;
    });
    html += "</optgroup>";
  });
  sel.innerHTML = html;
}

async function intrPayloadFromList(kind) {
  const sel = intrEl("intr-pay-from-list");
  if (sel) sel.value = "";
  if (!kind) return;
  const pack = intrValueLists().find((p) => p.id === kind);
  if (pack && Array.isArray(pack.payloads) && pack.payloads.length) {
    _intrAppendPayloads(pack.payloads);
    return;
  }
  if (INTR_WORDLISTS[kind]) {
    _intrAppendPayloads(INTR_WORDLISTS[kind]);
    return;
  }
  const gen = (pack && pack.generate) || kind;
  try {
    const r = await fetch(`${INTR_BASE}/intruder/generate_payloads`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: gen, count: 50 }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Generate failed");
    _intrAppendPayloads(data.payloads || []);
  } catch (e) {
    intrAlert("Generate error: " + e.message);
  }
}

function intrEndpointPacks() {
  const base = Array.isArray(window.INTR_ENDPOINT_PACKS) ? window.INTR_ENDPOINT_PACKS : [];
  const services = Array.isArray(window.SERVICES_ENDPOINT_PACKS) ? window.SERVICES_ENDPOINT_PACKS : [];
  return [...base, ...services];
}

function intrFillEndpointDropdown() {
  const sel = intrEl("intr-pay-endpoints");
  if (!sel) return;
  const packs = intrEndpointPacks();
  const groups = [];
  const seen = Object.create(null);
  packs.forEach((p) => {
    const g = p.group || "Other";
    if (!seen[g]) { seen[g] = 1; groups.push(g); }
  });
  let html = '<option value="">Load endpoints…</option>';
  groups.forEach((g) => {
    html += `<optgroup label="${intrEsc(g)}">`;
    packs.filter((p) => (p.group || "Other") === g).forEach((p) => {
      const n = (p.paths || []).length;
      html += `<option value="${intrEsc(p.id)}">${intrEsc(p.label)} (${n})</option>`;
    });
    html += "</optgroup>";
  });
  sel.innerHTML = html;
}

async function intrLoadEndpointPack(packId) {
  const sel = intrEl("intr-pay-endpoints");
  if (sel) sel.value = "";
  if (!packId) return;
  const idx = intrCurrentPosIdx() >= 0 ? intrCurrentPosIdx() : _intrEditSetIdx;
  if (intrIsUniquePos(idx)) {
    intrAlert("This position is Unique format. Clear Unique first, then load an endpoint list.");
    return;
  }
  const pack = intrEndpointPacks().find((p) => p.id === packId);
  const paths = pack && Array.isArray(pack.paths) ? pack.paths.slice() : [];
  if (!paths.length) {
    intrAlert("That endpoint pack is empty.");
    return;
  }
  if (_intrPayloads.length) {
    let ok = true;
    if (typeof _aspConfirm === "function") {
      ok = await _aspConfirm(
        "Load “" + (pack.label || packId) + "” and replace this position’s " +
        _intrPayloads.length + " payload(s)?\n\nAdd from list is unchanged — this only replaces the current list."
      );
    }
    if (!ok) return;
  }
  _intrPayloads = paths.slice();
  if (_intrPayloads.length > 5000) _intrPayloads = _intrPayloads.slice(0, 5000);
  intrRenderPayloadList();
}

function intrProcAdd() {
  const type = (intrEl("intr-proc-add-type") && intrEl("intr-proc-add-type").value) || "prefix";
  _intrProcSeq += 1;
  const rule = { id: _intrProcSeq, type, a: "", b: "" };
  if (type === "hash") rule.a = "md5";
  _intrProcRules.push(rule);
  intrRenderProcRules();
}

function intrProcRemove(id) {
  _intrProcRules = _intrProcRules.filter((r) => r.id !== id);
  intrRenderProcRules();
}

function intrProcSet(id, field, val) {
  const r = _intrProcRules.find((x) => x.id === id);
  if (r) r[field] = val;
}

function intrRenderProcRules() {
  const wrap = intrEl("intr-proc-list");
  if (!wrap) return;
  if (!_intrProcRules.length) {
    wrap.innerHTML = "<div class='intr-cfg-desc'>No rules — payloads are used as-is (plus encoding below).</div>";
    return;
  }
  wrap.innerHTML = _intrProcRules.map((r) => {
    let fields = "";
    if (r.type === "prefix") fields = `<input value="${intrEsc(r.a)}" placeholder="prefix" oninput="intrProcSet(${r.id},'a',this.value)">`;
    else if (r.type === "suffix") fields = `<input value="${intrEsc(r.a)}" placeholder="suffix" oninput="intrProcSet(${r.id},'a',this.value)">`;
    else if (r.type === "match") fields = `<input value="${intrEsc(r.a)}" placeholder="match" oninput="intrProcSet(${r.id},'a',this.value)"><input value="${intrEsc(r.b)}" placeholder="replace" oninput="intrProcSet(${r.id},'b',this.value)">`;
    else if (r.type === "regex_replace") fields = `<input value="${intrEsc(r.a)}" placeholder="regex pattern" oninput="intrProcSet(${r.id},'a',this.value)"><input value="${intrEsc(r.b)}" placeholder="replace with" oninput="intrProcSet(${r.id},'b',this.value)">`;
    else if (r.type === "hash") fields = `<select onchange="intrProcSet(${r.id},'a',this.value)">
      <option value="md5"${r.a === "md5" ? " selected" : ""}>MD5</option>
      <option value="sha1"${r.a === "sha1" ? " selected" : ""}>SHA1</option>
      <option value="sha256"${r.a === "sha256" ? " selected" : ""}>SHA256</option>
      <option value="sha512"${r.a === "sha512" ? " selected" : ""}>SHA512</option>
    </select>`;
    else if (r.type === "skip") fields = `<input value="${intrEsc(r.a)}" placeholder="regex" oninput="intrProcSet(${r.id},'a',this.value)">`;
    const labels = {
      prefix: "Prefix",
      suffix: "Suffix",
      match: "Replace",
      regex_replace: "Regex Replace",
      hash: "Hash",
      base64: "Base64",
      urlencode_all: "URL-encode",
      urldecode: "URL-decode",
      upper: "Uppercase",
      lower: "Lowercase",
      hex: "Hex encode",
      skip: "Skip"
    };
    return `<div class="intr-proc-rule"><span class="t">${labels[r.type] || r.type}</span>${fields}
      <button type="button" class="btn-sm" onclick="intrProcRemove(${r.id})">Remove</button></div>`;
  }).join("");
}

function intrGetPayloads() {
  const t = (intrEl("intr-pay-type") && intrEl("intr-pay-type").value) || "simple";
  if (t === "numbers" || t === "null") return _intrPayloads.slice();
  return _intrPayloads.slice();
}

function intrGetProcessors() {
  return _intrProcRules.map((r) => ({ type: r.type, a: r.a || "", b: r.b || "" }));
}

function intrGetGrepConfig() {
  const matchRaw = (intrEl("intr-grep-match-input") && intrEl("intr-grep-match-input").value) || "";
  const extractRaw = (intrEl("intr-grep-extract-input") && intrEl("intr-grep-extract-input").value) || "";
  const grepMatch = matchRaw.split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
  const grepExtract = extractRaw.split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
  return { grep_match: grepMatch, grep_extract: grepExtract };
}

function intrPreviewFormat(fmt) {
  const f = String(fmt || "");
  const chars = "abcdefghijklmnopqrstuvwxyz";
  const anum = chars + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const nums = "0123456789";
  const names = ["Alex Kumar", "Sam Patel", "Jordan Lee", "Riley Shah"];
  return f.replace(/\{([^}]+)\}/g, (_, token) => {
    const t = String(token || "").toLowerCase().trim();
    if (t === "uuid") {
      const hex = "0123456789abcdef";
      const g = (n) => Array.from({ length: n }, () => hex[Math.random() * 16 | 0]).join("");
      return `${g(8)}-${g(4)}-4${g(3)}-${g(4)}-${g(12)}`;
    }
    if (t === "email") {
      const u = Array.from({ length: 8 }, () => anum[Math.random() * 36 | 0]).join("");
      return u + "@testapi.com";
    }
    if (t === "name") return names[Math.random() * names.length | 0];
    const parts = t.split(":");
    const kind = parts[0];
    const n = parseInt(parts[1], 10) || 8;
    if (kind === "alpha") return Array.from({ length: n }, () => chars[Math.random() * 26 | 0]).join("");
    if (kind === "alphanum") return Array.from({ length: n }, () => anum[Math.random() * anum.length | 0]).join("");
    if (kind === "num") return Array.from({ length: n }, () => nums[Math.random() * 10 | 0]).join("");
    return `{${token}}`;
  });
}

function intrOpenUniqueModal() {
  let idx = intrCurrentPosIdx();
  if (idx < 0) idx = _intrEditSetIdx;
  if (idx < 0) {
    intrAlert("Pick a specific Payload position first, then set Unique format.");
    return;
  }
  _intrUniqueModalIdx = idx;
  const bases = intrCountPositions();
  const param = intrEl("intr-um-param");
  if (param) param.textContent = `position ${idx + 1}` + (bases[idx] ? `: ${bases[idx]}` : "");
  const current = (_intrUniqueFormats[idx] || "").trim();
  const inp = intrEl("intr-um-input");
  if (inp) inp.value = current;
  const box = intrEl("intr-um-preview-box");
  const val = intrEl("intr-um-preview-val");
  document.querySelectorAll("#intr-unique-modal .preset-btn").forEach((b) => {
    b.classList.toggle("selected", b.getAttribute("data-fmt") === current);
  });
  if (current && box && val) {
    val.textContent = intrPreviewFormat(current);
    box.style.display = "flex";
  } else if (box) box.style.display = "none";
  const m = intrEl("intr-unique-modal");
  if (m) m.style.display = "flex";
}

function intrCloseUniqueModal(revertType) {
  const m = intrEl("intr-unique-modal");
  if (m) m.style.display = "none";
  if (revertType && _intrUniqueModalIdx >= 0 && !intrIsUniquePos(_intrUniqueModalIdx)) {
    const ptype = intrEl("intr-pay-type");
    if (ptype) ptype.value = _intrListPayType || "simple";
    intrShowListPayloadPanels(_intrListPayType || "simple");
  }
  _intrUniqueModalIdx = -1;
}

function intrUniquePreview() {
  const fmt = ((intrEl("intr-um-input") && intrEl("intr-um-input").value) || "").trim();
  if (!fmt) return;
  const val = intrEl("intr-um-preview-val");
  const box = intrEl("intr-um-preview-box");
  if (val) val.textContent = intrPreviewFormat(fmt);
  if (box) box.style.display = "flex";
}

function intrUniqueApplyPreset(btn) {
  const fmt = btn && btn.getAttribute("data-fmt");
  const inp = intrEl("intr-um-input");
  if (inp && fmt) inp.value = fmt;
  document.querySelectorAll("#intr-unique-modal .preset-btn").forEach((b) => {
    b.classList.toggle("selected", b === btn);
  });
  if (fmt) {
    const val = intrEl("intr-um-preview-val");
    const box = intrEl("intr-um-preview-box");
    if (val) val.textContent = intrPreviewFormat(fmt);
    if (box) box.style.display = "flex";
  }
}

function intrUniqueOk() {
  const idx = _intrUniqueModalIdx;
  const fmt = ((intrEl("intr-um-input") && intrEl("intr-um-input").value) || "").trim();
  if (idx < 0) { intrCloseUniqueModal(true); return; }
  while (_intrUniqueFormats.length <= idx) _intrUniqueFormats.push("");
  _intrUniqueFormats[idx] = fmt;
  _intrEditSetIdx = idx;
  const posSel = intrEl("intr-pay-position");
  if (posSel) posSel.value = String(idx + 1);
  const ptype = intrEl("intr-pay-type");
  if (fmt) {
    if (ptype) ptype.value = "unique";
    intrShowListPayloadPanels("unique");
  } else {
    if (ptype) ptype.value = _intrListPayType || "simple";
    intrShowListPayloadPanels(_intrListPayType || "simple");
  }
  _intrUniqueModalIdx = -1;
  const m = intrEl("intr-unique-modal");
  if (m) m.style.display = "none";
  intrUpdatePosCount();
}

function intrClearUnique() {
  const idx = intrCurrentPosIdx() >= 0 ? intrCurrentPosIdx() : _intrEditSetIdx;
  if (idx < 0) return;
  _intrUniqueFormats[idx] = "";
  const ptype = intrEl("intr-pay-type");
  if (ptype) ptype.value = _intrListPayType || "simple";
  intrShowListPayloadPanels(_intrListPayType || "simple");
  intrUpdatePosCount();
}

async function intrStartAttack() {
  // If user pasted raw cURL into the editor, convert to Burp HTTP first
  await intrEnsureHttpTemplate({ silent: true });

  const template = (intrEl("intr-template") && intrEl("intr-template").value) || "";
  if (!template.trim()) {
    intrAlert("Import a cURL first.");
    return;
  }
  if (intrLooksLikeCurl(template)) {
    intrAlert("Request still looks like shell cURL.\n\nUse Import cURL (or paste again) so it becomes:\nMETHOD url\\nHeader: value\\n\\nbody");
    return;
  }
  if (template.indexOf("§") < 0) {
    intrAlert("Mark at least one payload position: select text → Mark § §");
    return;
  }

  const attackType = intrGetAttackType();
  const perPos = intrUsesPerPositionSets();
  const multi = intrIsMultiSetAttack();
  intrSaveCurrentSet();
  intrSyncSetsToPositionCount();

  const nPos = intrCountPositions().length;
  const payloadSets = _intrPayloadSets.slice(0, nPos).map((s) => (s || []).slice());
  const uniqueFormats = _intrUniqueFormats.slice(0, nPos).map((s) => String(s || "").trim());
  const attackIdx = [];
  for (let i = 0; i < nPos; i++) if (!uniqueFormats[i]) attackIdx.push(i);
  const payloads = attackType === "battering_ram"
    ? (payloadSets[0] || []).slice()
    : perPos
      ? (payloadSets[attackIdx.indexOf(_intrEditSetIdx) >= 0 ? _intrEditSetIdx : (attackIdx[0] || 0)] || []).slice()
      : intrGetPayloads();

  if (!attackIdx.length) {
    intrAlert("Every marked position is Unique format.\n\nKeep at least one position as a payload list so Sniper / Pitchfork / Cluster can iterate.");
    return;
  }

  if (multi) {
    if (attackIdx.some((i) => !(payloadSets[i] && payloadSets[i].length))) {
      intrAlert("Pitchfork / Cluster bomb: each payload-list position needs its own non-empty set.\n\nUnique-format positions are skipped automatically.");
      return;
    }
  } else if (attackType === "sniper") {
    const posSel0 = intrEl("intr-pay-position");
    const posVal0 = (posSel0 && posSel0.value) || "all";
    if (posVal0 !== "all") {
      const i = Math.max(0, (parseInt(posVal0, 10) || 1) - 1);
      if (uniqueFormats[i]) {
        intrAlert("This position is Unique format — it is not an attack variable.\n\nPick a payload-list position, or All positions.");
        return;
      }
      if (!(payloadSets[i] && payloadSets[i].length)) {
        intrAlert("This position has no payloads. Select it in the dropdown and Add / Paste / Load a list.");
        return;
      }
    } else if (!attackIdx.some((i) => payloadSets[i] && payloadSets[i].length)) {
      intrAlert("Add payloads on at least one non-Unique position.");
      return;
    }
  } else if (!payloads.length) {
    intrAlert("Add payloads with Add, Paste, Load, or Add from list.");
    return;
  }

  const reqs = intrCalcRequestCount(nPos, payloads.length);
  if (reqs > 25000) {
    intrAlert(`Too many requests (${reqs}). Max 25000 — shrink payload sets.`);
    return;
  }
  if (reqs <= 0) {
    intrAlert("Request count is 0 — check positions and payload sets.");
    return;
  }

  let method = "GET";
  const m = template.trim().match(/^([A-Z]+)\s+/);
  if (m && !/^curl/i.test(template.trim())) method = m[1];

  const posSel = intrEl("intr-pay-position");
  const posVal = (posSel && posSel.value) || "all";
  const position = (perPos && posVal !== "all") ? (parseInt(posVal, 10) || 0) : 0;
  const urlEncode = !!(intrEl("intr-url-encode") && intrEl("intr-url-encode").checked);
  const urlChars = (intrEl("intr-url-chars") && intrEl("intr-url-chars").value) || "";
  let threads = parseInt((intrEl("intr-threads") && intrEl("intr-threads").value) || "1", 10);
  if (isNaN(threads) || threads < 1) threads = 1;
  if (threads > 20) threads = 20;
  let delayMs = parseFloat((intrEl("intr-delay-ms") && intrEl("intr-delay-ms").value) || "0");
  if (isNaN(delayMs) || delayMs < 0) delayMs = 0;
  if (delayMs > 60000) delayMs = 60000;

  const btn = intrEl("intr-btn-sniper");
  const single = intrEl("intr-btn-single");
  if (btn) btn.disabled = true;
  if (single) single.disabled = true;
  try {
    const r = await fetch(`${INTR_BASE}/intruder/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        template,
        method,
        headers: {},
        payloads: payloads,
        payload_sets: payloadSets,
        unique_formats: uniqueFormats,
        attack_type: attackType,
        timeout: 15,
        position,
        url_encode: urlEncode,
        url_encode_chars: urlChars,
        processors: intrGetProcessors(),
        threads,
        delay_ms: delayMs,
        ...intrCollectProxyCfg(),
        ...intrGetGrepConfig(),
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
    _intrJobId = data.job_id;
    _intrResults = [];
    _intrSince = 0;
    _intrDashboard = null;
    _intrSelectedId = null;
    _intrSelectedRow = null;
    intrShowDetailEmpty();
    intrRenderScanList();
    intrSwitchTab("scanning");
    const title = intrEl("intr-scan-title");
    const nice = {
      sniper: "Sniper",
      battering_ram: "Battering ram",
      pitchfork: "Pitchfork",
      cluster_bomb: "Cluster bomb",
    };
    if (title) title.textContent = `${nice[attackType] || "Attack"} running… (${data.total || reqs} requests)`;
    intrSetStopBtn("running");
    if (_intrPoll) clearInterval(_intrPoll);
    _intrPoll = setInterval(intrPollStatus, 500);
    await intrPollStatus();
  } catch (e) {
    intrAlert("Start failed: " + e.message);
  } finally {
    if (btn) btn.disabled = false;
    const single = intrEl("intr-btn-single");
    if (single) single.disabled = false;
  }
}

/** @deprecated use intrStartAttack */
async function intrStartSniper() {
  return intrStartAttack();
}

async function intrSingleHit() {
  await intrEnsureHttpTemplate({ silent: true });
  const template = (intrEl("intr-template") && intrEl("intr-template").value) || "";
  if (!template.trim()) {
    intrAlert("Import or paste a request first.");
    return;
  }
  if (intrLooksLikeCurl(template)) {
    intrAlert("Request still looks like shell cURL.\n\nUse Import cURL (or paste again) so it becomes:\nMETHOD url\\nHeader: value\\n\\nbody");
    return;
  }
  if (_intrJobId && _intrPoll) {
    intrAlert("An attack is running. Stop it first, then Send.");
    return;
  }

  let method = "GET";
  const m = template.trim().match(/^([A-Z]+)\s+/);
  if (m && !/^curl/i.test(template.trim())) method = m[1];

  const nPos = intrCountPositions().length;
  const uniqueFormats = _intrUniqueFormats.slice(0, nPos).map((s) => String(s || "").trim());
  const urlEncode = !!(intrEl("intr-url-encode") && intrEl("intr-url-encode").checked);
  const urlChars = (intrEl("intr-url-chars") && intrEl("intr-url-chars").value) || "";

  const btn = intrEl("intr-btn-single");
  const start = intrEl("intr-btn-sniper");
  if (btn) { btn.disabled = true; btn.textContent = "Sending…"; }
  if (start) start.disabled = true;
  try {
    const r = await fetch(`${INTR_BASE}/intruder/single`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        template,
        method,
        headers: {},
        unique_formats: uniqueFormats,
        timeout: 15,
        url_encode: urlEncode,
        url_encode_chars: urlChars,
        ...intrCollectProxyCfg(),
        ...intrGetGrepConfig(),
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
    const nextId = _intrResults.reduce((mx, row) => Math.max(mx, Number(row.id) || 0), 0) + 1;
    const row = Object.assign({}, data, { id: nextId, payload: data.payload || "single" });
    _intrResults.push(row);
    _intrSelectedId = nextId;
    _intrSelectedRow = row;
    _intrDashboard = null;
    intrSwitchTab("scanning");
    const title = intrEl("intr-scan-title");
    if (title) title.textContent = "Single hit";
    const stats = intrEl("intr-scan-stats");
    if (stats) stats.textContent = String(_intrResults.length);
    const fill = intrEl("intr-scan-fill");
    if (fill) fill.style.width = "100%";
    intrRenderScanList();
    intrSelectResult(nextId);
  } catch (e) {
    intrAlert("Single hit failed: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Send"; }
    if (start) start.disabled = false;
  }
}

async function intrStop() {
  if (!_intrJobId) return;
  try {
    await fetch(`${INTR_BASE}/intruder/stop/${_intrJobId}`, { method: "POST" });
    const btn = intrEl("intr-stop-btn");
    if (btn) { btn.disabled = true; btn.textContent = "⏹ Stopping…"; }
  } catch (_) {}
}

async function intrPollStatus() {
  if (!_intrJobId) return;
  try {
    const r = await fetch(`${INTR_BASE}/intruder/status/${_intrJobId}?since=${_intrSince}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "status error");
    const neu = data.new_results || [];
    if (neu.length) {
      _intrResults = _intrResults.concat(neu);
      _intrSince = data.result_count || _intrResults.length;
      intrRenderScanList();
    }
    const prog = data.progress || {};
    const fill = intrEl("intr-scan-fill");
    const stats = intrEl("intr-scan-stats");
    if (fill) fill.style.width = (prog.pct || 0) + "%";
    if (stats) stats.textContent = `${prog.done || 0} / ${prog.total || 0}`;
    const title = intrEl("intr-scan-title");
    if (data.dashboard && Object.keys(data.dashboard).length) {
      _intrDashboard = data.dashboard;
    }
    if (data.status === "done" || data.status === "stopped" || data.status === "error") {
      if (_intrPoll) { clearInterval(_intrPoll); _intrPoll = null; }
      if (title) {
        title.textContent = data.status === "error"
          ? ("Error: " + (data.error || "failed"))
          : (data.status === "stopped" ? "Attack stopped" : "Attack complete");
      }
      intrSetStopBtn(data.status === "error" ? "error" : (data.status === "stopped" ? "stopped" : "done"));
      try {
        const rr = await fetch(`${INTR_BASE}/intruder/results/${_intrJobId}`);
        const full = await rr.json();
        _intrResults = full.results || _intrResults;
        _intrDashboard = full.dashboard || _intrDashboard;
        _intrSince = _intrResults.length;
        intrRenderScanList();
        intrRenderDashboard();
      } catch (_) {}
    }
  } catch (e) {
    console.warn("intruder poll", e);
  }
}

function intrStatusClass(st) {
  const n = parseInt(st, 10) || 0;
  if (n >= 200 && n < 300) return "intr-st-2xx";
  if (n >= 300 && n < 400) return "intr-st-3xx";
  if (n >= 400 && n < 500) return "intr-st-4xx";
  if (n >= 500) return "intr-st-5xx";
  return "intr-st-0";
}

function intrProxyPageKind(row) {
  const ct = String((row && row.content_type) || "").toLowerCase();
  const raw = String((row && row.response_preview) || "");
  const t = raw.toLowerCase();
  const stripped = raw.replace(/^\s+/, "");
  // Real API JSON/405 must never show the interceptor warning — even via Burp.
  if (ct.indexOf("json") >= 0 || stripped.charAt(0) === "{" || stripped.charAt(0) === "[") {
    return "";
  }
  const html = ct.indexOf("html") >= 0 || /<html|<head|<title|<body/i.test(raw);
  if (!html) return "";
  if (/burp suite|portswigger/.test(t)) return "burp";
  if (t.indexOf("mitmproxy") >= 0) return "mitmproxy";
  if (t.indexOf("charles proxy") >= 0) return "charles";
  if (t.indexOf("fiddler") >= 0) return "fiddler";
  if (/owasp zap|zaproxy/.test(t)) return "zap";
  return "";
}

function intrProxyPageLabel(kind) {
  const m = {
    burp: "Burp",
    mitmproxy: "mitmproxy",
    charles: "Charles",
    fiddler: "Fiddler",
    zap: "ZAP",
  };
  return m[kind] || kind;
}

function intrFilteredSorted() {
  let rows = _intrResults.slice();
  const q = (_intrFilter.text || "").toLowerCase();
  const stf = _intrFilter.status;
  if (q) {
    rows = rows.filter((r) => {
      const gm = (r.grep_match || []).join(" ");
      const ge = (r.grep_extract || []).join(" ");
      const blob = [r.payload, r.url, r.method, String(r.status), r.error, r.response_preview, r.proxy, gm, ge]
        .join(" ").toLowerCase();
      return blob.indexOf(q) >= 0;
    });
  }
  if (stf === "2xx") rows = rows.filter((r) => r.status >= 200 && r.status < 300);
  else if (stf === "3xx") rows = rows.filter((r) => r.status >= 300 && r.status < 400);
  else if (stf === "4xx") rows = rows.filter((r) => r.status >= 400 && r.status < 500);
  else if (stf === "5xx") rows = rows.filter((r) => r.status >= 500);
  else if (stf === "err") rows = rows.filter((r) => r.error || !r.status);
  else if (stf === "match") rows = rows.filter((r) => Array.isArray(r.grep_match) && r.grep_match.length > 0);
  else if (stf === "extract") rows = rows.filter((r) => Array.isArray(r.grep_extract) && r.grep_extract.length > 0);

  const k = _intrSort.key;
  const d = _intrSort.dir;
  rows.sort((a, b) => {
    let va = a[k], vb = b[k];
    if (k === "grep") {
      va = ((a.grep_match || []).join(" ") + " " + (a.grep_extract || []).join(" ")).trim();
      vb = ((b.grep_match || []).join(" ") + " " + (b.grep_extract || []).join(" ")).trim();
      return va < vb ? -d : va > vb ? d : 0;
    }
    if (k === "payload" || k === "url" || k === "method") {
      va = String(va || ""); vb = String(vb || "");
      return va < vb ? -d : va > vb ? d : 0;
    }
    va = Number(va) || 0; vb = Number(vb) || 0;
    return (va - vb) * d;
  });
  return rows;
}

function intrSetSort(key) {
  if (_intrSort.key === key) _intrSort.dir *= -1;
  else { _intrSort.key = key; _intrSort.dir = 1; }
  intrPaintSortHeaders();
  intrRenderScanList();
}

function intrPaintSortHeaders() {
  const head = document.getElementById("intr-col-head") || document.querySelector(".intr-col-head");
  if (!head) return;
  [].forEach.call(head.querySelectorAll("[data-sort]"), (el) => {
    const key = el.getAttribute("data-sort");
    const active = key === _intrSort.key;
    el.classList.toggle("sorted", active);
    let ico = el.querySelector(".intr-sort-ico");
    if (!ico) {
      ico = document.createElement("span");
      ico.className = "intr-sort-ico";
      el.appendChild(ico);
    }
    ico.textContent = active ? (_intrSort.dir > 0 ? "▲" : "▼") : "⇅";
  });
}

function intrApplyFilters() {
  _intrFilter.text = (intrEl("intr-filter-text") && intrEl("intr-filter-text").value) || "";
  _intrFilter.status = (intrEl("intr-filter-status") && intrEl("intr-filter-status").value) || "";
  intrRenderScanList();
}

function intrEsc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Colorize a non-§ chunk (already HTML-escaped). APISphere soft palette. */
function intrColorizeEscaped(h) {
  // HTTP methods at line starts
  h = h.replace(/(^|\n)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\b/g,
    '$1<span class="intr-tok-method">$2</span>');
  // Header names at line start: Name:
  h = h.replace(/(^|\n)([A-Za-z][\w\-]*)(:)/g, '$1<span class="intr-tok-hk">$2</span>$3');
  // URLs
  h = h.replace(/(https?:\/\/[^\s"'\\]+)/g, '<span class="intr-tok-url">$1</span>');
  // Single-quoted strings
  h = h.replace(/('[^'\\]*(?:\\.[^'\\]*)*')/g, '<span class="intr-tok-str">$1</span>');
  // Double-quoted / JSON strings (&quot;…&quot;)
  h = h.replace(/(&quot;[^&]*(?:&(?!quot;)[^&]*)*&quot;)/g, '<span class="intr-tok-str">$1</span>');
  // JSON keys: "key":
  h = h.replace(/(<span class="intr-tok-str">&quot;[^&]+&quot;<\/span>)(\s*:)/g,
    (m, a, b) => a.replace('intr-tok-str', 'intr-tok-key') + b);
  // Bools / null
  h = h.replace(/\b(true|false)\b/g, '<span class="intr-tok-bool">$1</span>');
  h = h.replace(/\b(null)\b/g, '<span class="intr-tok-null">$1</span>');
  // Numbers
  h = h.replace(/\b(-?\d+(?:\.\d+)?)\b/g, '<span class="intr-tok-num">$1</span>');
  // Leftover curl (should rarely appear after convert)
  h = h.replace(/\b(curl(?:\.exe)?)\b/gi, '<span class="intr-tok-curl">$1</span>');
  h = h.replace(/(^|[\s\\])(--?[A-Za-z][\w-]*)/g, '$1<span class="intr-tok-flag">$2</span>');
  return h;
}

function intrBuildHighlightHtml(text, opts) {
  const hideDelimiters = !!(opts && opts.hideDelimiters);
  const raw = String(text || "");
  if (!raw) return "";
  let out = "";
  const re = /§([\s\S]*?)§/g;
  let last = 0;
  let m;
  while ((m = re.exec(raw))) {
    if (m.index > last) {
      out += intrColorizeEscaped(intrEsc(raw.slice(last, m.index)));
    }
    const shown = hideDelimiters ? m[1] : m[0];
    out += `<mark class="intr-mark">${intrEsc(shown)}</mark>`;
    last = m.index + m[0].length;
  }
  if (last < raw.length) out += intrColorizeEscaped(intrEsc(raw.slice(last)));
  return out;
}

function intrRowInsertedPayloads(row) {
  if (!row) return [];
  if (Array.isArray(row.inserted_payloads) && row.inserted_payloads.length) {
    return row.inserted_payloads.map((x) => String(x == null ? "" : x)).filter((s) => s !== "");
  }
  const p = row.payload == null ? "" : String(row.payload);
  if (!p) return [];
  if (p.indexOf(" | ") >= 0) return p.split(" | ").map((s) => s.trim()).filter(Boolean);
  return [p];
}

/** Highlight payload values in already-sent request text (no § delimiters). */
function intrHighlightPayloadsHtml(raw, payloads) {
  const text = String(raw || "");
  const needles = [];
  const seen = {};
  (payloads || []).forEach((p) => {
    const s = p == null ? "" : String(p);
    if (!s || seen[s]) return;
    seen[s] = true;
    needles.push(s);
  });
  needles.sort((a, b) => b.length - a.length);
  if (!needles.length) return intrColorizeEscaped(intrEsc(text));

  const ranges = [];
  needles.forEach((n) => {
    let from = 0;
    while (from <= text.length - n.length) {
      const i = text.indexOf(n, from);
      if (i < 0) break;
      const end = i + n.length;
      const overlap = ranges.some((r) => i < r.end && end > r.start);
      if (!overlap) ranges.push({ start: i, end, value: n });
      from = i + Math.max(n.length, 1);
    }
  });
  ranges.sort((a, b) => a.start - b.start);
  if (!ranges.length) return intrColorizeEscaped(intrEsc(text));

  let out = "";
  let last = 0;
  ranges.forEach((r) => {
    if (r.start > last) out += intrColorizeEscaped(intrEsc(text.slice(last, r.start)));
    out += `<mark class="intr-mark">${intrEsc(r.value)}</mark>`;
    last = r.end;
  });
  if (last < text.length) out += intrColorizeEscaped(intrEsc(text.slice(last)));
  return out;
}

function intrScanRequestHtml(row) {
  const marked = row && row.request_display ? String(row.request_display) : "";
  if (marked && marked.indexOf("§") >= 0) {
    return intrBuildHighlightHtml(marked, { hideDelimiters: true });
  }
  const raw = intrBuildRequestRaw(row);
  return intrHighlightPayloadsHtml(raw, intrRowInsertedPayloads(row));
}

function intrRefreshTemplateHighlight() {
  const ta = intrEl("intr-template");
  const hl = intrEl("intr-template-hl");
  if (!ta || !hl) return;
  // Trailing newline in pre is collapsed unless followed by space; keep height exactly 1:1 with textarea
  hl.innerHTML = intrBuildHighlightHtml(text) + (text.endsWith("\n") ? " " : "");
  intrSyncTemplateScroll();
}

function intrSyncTemplateScroll() {
  const ta = intrEl("intr-template");
  const hl = intrEl("intr-template-hl");
  if (!ta || !hl) return;
  hl.scrollTop = ta.scrollTop;
  hl.scrollLeft = ta.scrollLeft;
}

function intrSetStopBtn(state) {
  // state: running | done | stopped | error | idle
  const btn = intrEl("intr-stop-btn");
  if (!btn) return;
  if (state === "running") {
    btn.disabled = false;
    btn.textContent = "⏹ Stop";
    btn.style.opacity = "1";
    btn.onclick = () => intrStop();
    return;
  }
  if (state === "done") {
    btn.disabled = true;
    btn.textContent = "✓ Done";
    btn.style.opacity = "0.85";
    return;
  }
  if (state === "stopped") {
    btn.disabled = true;
    btn.textContent = "⏹ Stopped";
    btn.style.opacity = "0.85";
    return;
  }
  if (state === "error") {
    btn.disabled = true;
    btn.textContent = "⚠ Error";
    btn.style.opacity = "0.85";
    return;
  }
  btn.disabled = true;
  btn.textContent = "⏹ Stop";
  btn.style.opacity = "0.55";
}

function intrBuildRequestRaw(r) {
  if (!r) return "";
  const lines = [];
  lines.push(`${r.method || "GET"} ${r.url || ""}`);
  const hdrs = r.request_headers || {};
  Object.keys(hdrs).forEach((k) => {
    lines.push(`${k}: ${hdrs[k]}`);
  });
  lines.push("");
  if (r.request_body) lines.push(r.request_body);
  if (r.error) {
    lines.push("");
    lines.push(`# Error: ${r.error}`);
  }
  return lines.join("\n");
}

/** Escape HTML then wrap every occurrence of the sent payload value. */
function intrHighlightPayloadHtml(raw, payload) {
  const esc = intrEsc(raw || "");
  const p = payload == null ? "" : String(payload);
  if (!p) return esc;
  const needle = intrEsc(p);
  if (!needle) return esc;
  const parts = esc.split(needle);
  if (parts.length < 2) return esc;
  return parts.join('<mark class="intr-hl">' + needle + "</mark>");
}

function intrPrettyBody(text) {
  const raw = text == null ? "" : String(text);
  const t = raw.trim();
  if (!t) return "(empty)";
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) {}
  }
  return raw;
}

function intrHeadersText(r) {
  const hdrs = (r && r.response_headers) || {};
  const keys = Object.keys(hdrs);
  if (!keys.length) return "(no response headers)";
  return keys.map((k) => `${k}: ${hdrs[k]}`).join("\n");
}

function intrShowDetailEmpty() {
  const empty = intrEl("intr-detail-empty");
  const panels = intrEl("intr-detail-panels");
  if (empty) empty.style.display = "flex";
  if (panels) panels.style.display = "none";
  _intrSelectedRow = null;
  const warn = intrEl("intr-proxy-page-warn");
  if (warn) warn.style.display = "none";
  const frame = intrEl("intr-resp-render");
  if (frame) {
    try { frame.srcdoc = ""; } catch (_) {}
    frame.style.display = "none";
  }
}

function intrSelectResult(id) {
  _intrSelectedId = id;
  const row = _intrResults.find((r) => r.id === id) || null;
  _intrSelectedRow = row;
  document.querySelectorAll("#intr-req-list .intr-req-row").forEach((el) => {
    el.classList.toggle("selected", String(el.getAttribute("data-id")) === String(id));
  });
  if (!row) {
    intrShowDetailEmpty();
    return;
  }
  const empty = intrEl("intr-detail-empty");
  const panels = intrEl("intr-detail-panels");
  if (empty) empty.style.display = "none";
  if (panels) panels.style.display = "flex";

  const reqBody = intrEl("intr-req-body");
  const reqMeta = intrEl("intr-req-meta");
  if (reqBody) reqBody.innerHTML = intrScanRequestHtml(row) || "(empty)";
  if (reqMeta) {
    const posLabel = row.position ? `P${row.position}` : "All";
    const px = (row.proxy || "").trim();
    const base = `${posLabel} · ${row.payload || ""}`;
    reqMeta.textContent = (px ? `${base} · ${px}` : base).slice(0, 180);
  }
  const respMeta = intrEl("intr-resp-meta");
  if (respMeta) {
    const st = row.status || "ERR";
    let metaTxt = `${st} · ${row.length || 0} B · ${row.time_ms || 0} ms`;
    if (Array.isArray(row.grep_match) && row.grep_match.length) {
      metaTxt += ` · 🎯 Matched: ${row.grep_match.join(", ")}`;
    }
    if (Array.isArray(row.grep_extract) && row.grep_extract.length) {
      metaTxt += ` · 🔍 Extracted: ${row.grep_extract.join(", ")}`;
    }
    respMeta.textContent = metaTxt;
  }
  const warn = intrEl("intr-proxy-page-warn");
  if (warn) {
    const page = intrProxyPageKind(row);
    if (page) {
      warn.style.display = "block";
      warn.textContent =
        `This ${row.status || ""} body is from ${intrProxyPageLabel(page)} (proxy UI), not the target API. ` +
        "Intruder Proxy URL must match the listener (e.g. http://127.0.0.1:8080). " +
        "Intercept off. Uncheck Support HTTP/2 on that listener — Python uses HTTP/1.1. " +
        "JSON 405 from the API will not show this warning.";
    } else {
      warn.style.display = "none";
      warn.textContent = "";
    }
  }
  intrApplyRespTab();
  const el = document.querySelector(`#intr-req-list .intr-req-row[data-id="${id}"]`);
  if (el && typeof el.scrollIntoView === "function") {
    el.scrollIntoView({ block: "nearest", inline: "nearest" });
  }
}

function intrScanTabActive() {
  const tool = intrEl("tool-intruder");
  const pane = intrEl("intr-tab-scanning-content");
  if (!tool || !pane) return false;
  if (tool.style.display === "none") return false;
  if (pane.style.display === "none") return false;
  return pane.classList.contains("active") || pane.style.display === "flex";
}

function intrMoveSelection(delta) {
  const rows = intrFilteredSorted();
  if (!rows.length) return;
  let idx = rows.findIndex((r) => r.id === _intrSelectedId);
  if (idx < 0) idx = delta > 0 ? -1 : rows.length;
  let next = idx + delta;
  if (next < 0) next = 0;
  if (next >= rows.length) next = rows.length - 1;
  const row = rows[next];
  if (row) intrSelectResult(row.id);
}

function intrOnScanKey(e) {
  if (!e) return;
  if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
  if (!intrScanTabActive()) return;
  const t = e.target;
  const tag = (t && t.tagName) ? t.tagName.toLowerCase() : "";
  if (tag === "input" || tag === "textarea" || tag === "select" || (t && t.isContentEditable)) return;
  if (t && t.closest && t.closest("#intr-req-body, #intr-resp-body, #intr-resp-render, #intr-curl-modal, #intr-paste-modal, #intr-ctx-menu")) return;
  e.preventDefault();
  e.stopPropagation();
  intrMoveSelection(e.key === "ArrowDown" ? 1 : -1);
}

function intrSetRespTab(tab) {
  _intrRespTab = tab || "pretty";
  document.querySelectorAll(".intr-rtab").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-rtab") === _intrRespTab);
  });
  intrApplyRespTab();
}

function intrApplyRespTab() {
  const row = _intrSelectedRow;
  const pre = intrEl("intr-resp-body");
  const frame = intrEl("intr-resp-render");
  if (!pre) return;
  if (!row) {
    pre.style.display = "block";
    pre.textContent = "";
    if (frame) frame.style.display = "none";
    return;
  }
  const raw = row.response_preview || "";
  if (_intrRespTab === "render") {
    pre.style.display = "none";
    if (frame) {
      frame.style.display = "block";
      const ct = String(row.content_type || "").toLowerCase();
      const looksHtml = /html/i.test(ct) || /^\s*</.test(raw);
      if (looksHtml && raw.trim()) {
        frame.srcdoc = raw;
      } else if (raw.trim()) {
        const pretty = intrEsc(intrPrettyBody(raw));
        frame.srcdoc = `<!doctype html><meta charset="utf-8"><body style="margin:12px;font:12px/1.45 ui-monospace,Menlo,monospace;white-space:pre-wrap;background:#111;color:#ddd">${pretty}</body>`;
      } else {
        frame.srcdoc = `<!doctype html><body style="margin:16px;font:13px system-ui;color:#666">No response body to render</body>`;
      }
    }
    return;
  }
  if (frame) {
    frame.style.display = "none";
    try { frame.srcdoc = ""; } catch (_) {}
  }
  pre.style.display = "block";
  if (row.error && !raw) {
    pre.textContent = "Connection error:\n" + String(row.error);
    return;
  }
  if (_intrRespTab === "headers") pre.textContent = intrHeadersText(row);
  else if (_intrRespTab === "raw") pre.textContent = raw || "(empty)";
  else pre.textContent = raw ? intrPrettyBody(raw) : "(empty)";
}

function intrCopySelectedCurl() {
  const row = _intrSelectedRow;
  if (!row) { intrAlert("Select a request first."); return; }
  const hdrs = row.request_headers || {};
  let curl = `curl -X ${row.method || "GET"} '${String(row.url || "").replace(/'/g, "'\\''")}'`;
  Object.keys(hdrs).forEach((k) => {
    const v = String(hdrs[k]).replace(/'/g, "'\\''");
    curl += ` \\\n  -H '${k}: ${v}'`;
  });
  if (row.request_body) {
    const b = String(row.request_body).replace(/'/g, "'\\''");
    curl += ` \\\n  --data-raw '${b}'`;
  }
  const done = () => intrAlert("cURL copied.");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(curl).then(done).catch(() => {
      try {
        const ta = document.createElement("textarea");
        ta.value = curl; document.body.appendChild(ta); ta.select();
        document.execCommand("copy"); document.body.removeChild(ta); done();
      } catch (_) { intrAlert(curl); }
    });
  } else {
    intrAlert(curl);
  }
}

function intrRenderScanList() {
  const list = intrEl("intr-req-list");
  const empty = intrEl("intr-empty-scan");
  if (!list) return;
  intrPaintSortHeaders();
  const rows = intrFilteredSorted();
  if (!_intrResults.length) {
    list.innerHTML = "";
    if (empty) empty.style.display = "flex";
    intrShowDetailEmpty();
    return;
  }
  if (empty) empty.style.display = "none";
  list.innerHTML = rows.map((r) => {
    const page = intrProxyPageKind(r);
    const stc = page ? "intr-st-proxy" : intrStatusClass(r.status);
    const sel = _intrSelectedId === r.id ? " selected" : "";
    const px = (r.proxy || "").trim();
    const pxHtml = px
      ? `<span class="intr-req-proxy" title="${intrEsc(px)}">${intrEsc(px)}</span>`
      : "";
    const stLabel = page
      ? `${r.status || "ERR"} ${intrEsc(intrProxyPageLabel(page))}`
      : String(r.status || "ERR");

    const gm = Array.isArray(r.grep_match) ? r.grep_match : [];
    const ge = Array.isArray(r.grep_extract) ? r.grep_extract : [];
    let grepBadgesHtml = "";
    if (gm.length || ge.length) {
      const mBadges = gm.map((m) => `<span class="intr-grep-badge" title="Match: ${intrEsc(m)}">🎯 ${intrEsc(m)}</span>`).join("");
      const eBadges = ge.map((e) => `<span class="intr-extract-badge" title="Extract: ${intrEsc(e)}">🔍 ${intrEsc(e)}</span>`).join("");
      grepBadgesHtml = `<span class="intr-grep-cell">${mBadges}${eBadges}</span>`;
    } else {
      grepBadgesHtml = `<span class="intr-grep-empty">—</span>`;
    }

    return `<div class="intr-req-row${sel}" data-id="${r.id}" onclick="intrSelectResult(${r.id})">
      <div class="intr-req-main">
        <span>#${r.id}</span>
        <span>${r.position ? ("P" + r.position) : "—"}</span>
        <span class="${stc}" title="${page ? "Interceptor page — not the target API" : ""}">${stLabel}</span>
        <span>${intrEsc(r.method)}</span>
        <span>${r.length}</span>
        <span>${r.time_ms}ms</span>
        <span class="intr-req-payload-cell">
          <span class="intr-req-payload" title="${intrEsc(r.payload)}">${intrEsc(r.payload)}</span>
          ${pxHtml}
        </span>
        ${grepBadgesHtml}
      </div>
    </div>`;
  }).join("");

  if (_intrSelectedId != null) {
    const still = _intrResults.some((r) => r.id === _intrSelectedId);
    if (still) intrSelectResult(_intrSelectedId);
    else intrShowDetailEmpty();
  }
}

function intrToggleRow(el) {
  // backwards-compat — prefer select + bottom panel
  if (!el) return;
  const id = parseInt(el.getAttribute("data-id"), 10);
  if (!isNaN(id)) intrSelectResult(id);
}

function intrRenderDashboard() {
  const wrap = intrEl("intr-dash");
  const empty = intrEl("intr-empty-dash");
  if (!wrap) return;
  const dash = _intrDashboard;
  if (!dash || !dash.total) {
    wrap.style.display = "none";
    if (empty) empty.style.display = "flex";
    return;
  }
  if (empty) empty.style.display = "none";
  wrap.style.display = "flex";

  const by = dash.by_status || {};
  const maxSt = Math.max(1, ...Object.values(by).map(Number));
  const bars = Object.keys(by).sort((a, b) => Number(a) - Number(b)).map((st) => {
    const n = by[st];
    const pct = Math.round(100 * n / maxSt);
    return `<div class="intr-bar-row"><span>${intrEsc(st)}</span>
      <div class="intr-bar-track"><div class="intr-bar-fill" style="width:${pct}%"></div></div>
      <span>${n}</span></div>`;
  }).join("");

  const t = dash.time_ms || {};
  const L = dash.length || {};
  wrap.innerHTML = `
    <div class="intr-dash-cards">
      <div class="intr-dash-card"><div class="v">${dash.total}</div><div class="l">Requests</div></div>
      <div class="intr-dash-card"><div class="v">${dash.errors || 0}</div><div class="l">Errors</div></div>
      <div class="intr-dash-card"><div class="v">${t.avg || 0}<span style="font-size:12px">ms</span></div><div class="l">Avg time (p95 ${t.p95 || 0})</div></div>
      <div class="intr-dash-card"><div class="v">${L.avg || 0}</div><div class="l">Avg length (max ${L.max || 0})</div></div>
    </div>
    <div class="intr-bar-block">
      <h4>Status code distribution</h4>
      ${bars || "<div style='color:var(--text3);font-size:11px'>No data</div>"}
    </div>
    <div class="intr-bar-block">
      <h4>Timing</h4>
      <div style="font-size:11px;font-family:var(--mono);color:var(--text2);line-height:1.7">
        min ${t.min || 0} ms · avg ${t.avg || 0} ms · p95 ${t.p95 || 0} ms · max ${t.max || 0} ms
      </div>
    </div>`;
}

// ── Right-click encode / decode ──────────────────────────────────────────────

function intrHideCtx() {
  const menu = intrEl("intr-ctx-menu");
  if (menu) menu.style.display = "none";
  _intrCtx = null;
}

function intrShowCtx(e) {
  const ta = intrEl("intr-template");
  if (!ta || e.target !== ta) return;
  e.preventDefault();
  intrRememberSel();
  let start = ta.selectionStart || 0;
  let end = ta.selectionEnd || 0;
  if (start === end && _intrSel.start !== _intrSel.end) {
    start = _intrSel.start;
    end = _intrSel.end;
  }
  _intrCtx = { start, end };
  const menu = intrEl("intr-ctx-menu");
  const hint = intrEl("intr-ctx-hint");
  if (!menu) return;
  const val = ta.value || "";
  const sel = start !== end ? val.slice(start, end) : "";
  if (hint) {
    const preview = sel.length > 42 ? sel.slice(0, 40) + "…" : sel;
    hint.textContent = sel ? ("Selection: " + preview) : "Select text first to encode/decode";
  }
  menu.style.display = "block";
  const pad = 8;
  const mw = menu.offsetWidth || 200;
  const mh = menu.offsetHeight || 120;
  let left = e.clientX, top = e.clientY;
  if (left + mw > window.innerWidth - pad) left = window.innerWidth - mw - pad;
  if (top + mh > window.innerHeight - pad) top = window.innerHeight - mh - pad;
  if (left < pad) left = pad;
  if (top < pad) top = pad;
  menu.style.left = left + "px";
  menu.style.top = top + "px";
}

function intrCtxApply(transform) {
  const ta = intrEl("intr-template");
  if (!ta || !_intrCtx) { intrHideCtx(); return; }
  let s = _intrCtx.start, e = _intrCtx.end;
  if (s === e) {
    intrAlert("Select text first, then right-click → Encode/Decode.");
    intrHideCtx();
    return;
  }
  const v = ta.value || "";
  const chunk = v.slice(s, e);
  let next;
  try {
    next = transform(chunk);
  } catch (err) {
    intrAlert("Transform failed: " + (err && err.message ? err.message : err));
    intrHideCtx();
    return;
  }
  ta.value = v.slice(0, s) + next + v.slice(e);
  ta.focus();
  ta.setSelectionRange(s, s + next.length);
  _intrSel = { start: s, end: s + next.length };
  intrUpdatePosCount();
  intrHideCtx();
}

function intrCtxEncode() {
  intrCtxApply((s) => encodeURIComponent(s));
}

function intrCtxDecode() {
  intrCtxApply((s) => decodeURIComponent(String(s).replace(/\+/g, " ")));
}

function intrCtxMark() {
  if (_intrCtx) _intrSel = { start: _intrCtx.start, end: _intrCtx.end };
  intrHideCtx();
  intrMarkSelection();
}

// ── Resize ───────────────────────────────────────────────────────────────────

function intrBindColResize(handleId, leftId, rightId, splitId) {
  const handle = intrEl(handleId);
  const left = intrEl(leftId);
  const right = intrEl(rightId);
  const split = intrEl(splitId);
  if (!handle || !left || !right || !split || handle._intrBound) return;
  handle._intrBound = true;
  let dragging = false;
  let startX = 0;
  let startLeft = 0;
  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragging = true;
    handle.classList.add("as-dragging", "intr-dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    startX = e.clientX;
    startLeft = left.getBoundingClientRect().width;
  });
  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const total = split.getBoundingClientRect().width;
    const handleW = handle.getBoundingClientRect().width || 5;
    let nl = startLeft + (e.clientX - startX);
    nl = Math.max(160, Math.min(total - handleW - 160, nl));
    left.style.flex = "none";
    right.style.flex = "1 1 0";
    left.style.width = ((nl / total) * 100) + "%";
  });
  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("as-dragging", "intr-dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  });
}

function intrBindRowResize(handleId, topId, botId, splitId) {
  const handle = intrEl(handleId);
  const top = intrEl(topId);
  const bot = intrEl(botId);
  const split = intrEl(splitId);
  if (!handle || !top || !bot || !split || handle._intrBound) return;
  handle._intrBound = true;
  let dragging = false;
  let startY = 0;
  let startTop = 0;
  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragging = true;
    handle.classList.add("as-dragging", "intr-dragging");
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    startY = e.clientY;
    startTop = top.getBoundingClientRect().height;
  });
  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const total = split.getBoundingClientRect().height;
    const handleH = handle.getBoundingClientRect().height || 5;
    let nt = startTop + (e.clientY - startY);
    nt = Math.max(100, Math.min(total - handleH - 120, nt));
    top.style.flex = "none";
    bot.style.flex = "1 1 0";
    top.style.height = nt + "px";
  });
  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("as-dragging", "intr-dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  });
}

function intrInitResize() {
  // 50-50 fixed split layout: horizontal resizer removed per user request
  // intrBindColResize("intr-hresize", "intr-pane-request", "intr-pane-payloads", "intr-attack-split");
  intrBindColResize("intr-detail-hresize", "intr-req-panel", "intr-resp-panel", "intr-detail-panels");
  intrBindRowResize("intr-vresize", "intr-scan-list-wrap", "intr-scan-detail", "intr-scan-body");
}

function intrInit() {
  const tpl = intrEl("intr-template");
  if (tpl && !tpl._intrBound) {
    tpl.addEventListener("input", intrUpdatePosCount);
    tpl.addEventListener("scroll", intrSyncTemplateScroll);
    tpl.addEventListener("paste", intrOnTemplatePaste);
    tpl.addEventListener("select", intrRememberSel);
    tpl.addEventListener("keyup", intrRememberSel);
    tpl.addEventListener("mouseup", intrRememberSel);
    tpl.addEventListener("contextmenu", intrShowCtx);
    tpl._intrBound = true;
  }
  const edWrap = document.querySelector("#tool-intruder .intr-editor-wrap");
  if (edWrap && !edWrap._intrRo && typeof ResizeObserver !== "undefined") {
    edWrap._intrRo = new ResizeObserver(() => intrSyncTemplateScroll());
    edWrap._intrRo.observe(edWrap);
  }
  if (!document._intrCtxDoc) {
    document.addEventListener("click", (e) => {
      const menu = intrEl("intr-ctx-menu");
      if (menu && menu.style.display !== "none" && !menu.contains(e.target)) intrHideCtx();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        intrHideCtx();
        intrClosePasteModal();
        intrCloseAttackInfo();
        intrCloseUniqueModal(false);
        intrCloseProxyModal();
      }
      intrOnScanKey(e);
    });
    document._intrCtxDoc = true;
  }
  if (!document._intrThemeHl) {
    try {
      const mo = new MutationObserver(() => intrRefreshTemplateHighlight());
      mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
      document._intrThemeHl = true;
    } catch (_) { /* ignore */ }
  }
  intrInitResize();
  intrBindPayList();
  intrFillEndpointDropdown();
  intrFillValueListDropdown();
  intrRenderPayloadList();
  intrRenderProcRules();
  intrShowListPayloadPanels(_intrListPayType || "simple");
  intrOnAttackTypeChange();
  intrUpdatePosCount();
  intrSyncPayloadTypeUi(false);
  intrRefreshTemplateHighlight();
  intrPaintSortHeaders();
  intrSyncProxyBtn();
}

window.intrSwitchTab = intrSwitchTab;
window.intrReset = intrReset;
window.intrShowCurlImport = intrShowCurlImport;
window.intrCloseCurlModal = intrCloseCurlModal;
window.intrImportCurl = intrImportCurl;
window.intrMarkSelection = intrMarkSelection;
window.intrClearMarks = intrClearMarks;
window.intrStartAttack = intrStartAttack;
window.intrStartSniper = intrStartSniper;
window.intrSingleHit = intrSingleHit;
window.intrShowAttackInfo = intrShowAttackInfo;
window.intrCloseAttackInfo = intrCloseAttackInfo;
window.intrOpenProxyModal = intrOpenProxyModal;
window.intrCloseProxyModal = intrCloseProxyModal;
window.intrSyncProxyBtn = intrSyncProxyBtn;
window.intrOnAttackTypeChange = intrOnAttackTypeChange;
window.intrOnPositionSelectChange = intrOnPositionSelectChange;
window.intrStop = intrStop;
window.intrSetSort = intrSetSort;
window.intrApplyFilters = intrApplyFilters;
window.intrToggleRow = intrToggleRow;
window.intrSelectResult = intrSelectResult;
window.intrSetRespTab = intrSetRespTab;
window.intrCopySelectedCurl = intrCopySelectedCurl;
window.intrInit = intrInit;
window.intrRememberSel = intrRememberSel;
window.intrCtxEncode = intrCtxEncode;
window.intrCtxDecode = intrCtxDecode;
window.intrCtxMark = intrCtxMark;
window.intrHideCtx = intrHideCtx;
window.intrToggleAcc = intrToggleAcc;
window.intrOnPayloadTypeChange = intrOnPayloadTypeChange;
window.intrOpenUniqueModal = intrOpenUniqueModal;
window.intrCloseUniqueModal = intrCloseUniqueModal;
window.intrUniquePreview = intrUniquePreview;
window.intrUniqueApplyPreset = intrUniqueApplyPreset;
window.intrUniqueOk = intrUniqueOk;
window.intrClearUnique = intrClearUnique;
window.intrPreviewNumbers = intrPreviewNumbers;
window.intrPreviewNulls = intrPreviewNulls;
window.intrPayloadAdd = intrPayloadAdd;
window.intrPayloadPaste = intrPayloadPaste;
window.intrClosePasteModal = intrClosePasteModal;
window.intrConfirmPaste = intrConfirmPaste;
window.intrPayloadLoad = intrPayloadLoad;
window.intrPayloadFilePicked = intrPayloadFilePicked;
window.intrPayloadRemove = intrPayloadRemove;
window.intrPayloadClear = intrPayloadClear;
window.intrPayloadDedup = intrPayloadDedup;
window.intrPayloadFromList = intrPayloadFromList;
window.intrLoadEndpointPack = intrLoadEndpointPack;
window.intrProcAdd = intrProcAdd;
window.intrProcRemove = intrProcRemove;
window.intrProcSet = intrProcSet;
window.intrGetGrepConfig = intrGetGrepConfig;
