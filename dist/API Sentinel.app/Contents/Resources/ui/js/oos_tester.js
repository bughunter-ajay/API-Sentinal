/* ── Swagger Scan — OpenAPI Audit Tool ─────────────────────────────────────── */
"use strict";

const OOS_BACKEND = "http://127.0.0.1:8771";

let _oosFile    = null;   // selected File object
let _oosJobId   = null;   // last scan job id
let _oosAudit   = null;   // last audit result
let _oosView    = "upload"; // "upload" | "scanning" | "results"
let _oosFilterSev = "all";

// ── Helpers ──────────────────────────────────────────────────────────────────
function $o(id) { return document.getElementById("oos-" + id); }

function oosEsc(s) {
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── View switching ────────────────────────────────────────────────────────────
function oosShowView(view) {
  _oosView = view;
  ["upload","scanning","results"].forEach(v => {
    const el = $o(v);
    if (el) el.style.display = (v === view) ? "" : "none";
  });
}

// ── Init ─────────────────────────────────────────────────────────────────────
function oosInit() {
  oosShowView("upload");

  // File input change
  const fileInput = $o("file-input");
  if (fileInput) {
    fileInput.addEventListener("change", e => {
      const f = e.target.files[0];
      if (f) oosSetFile(f);
    });
  }

  // Drag & drop on upload zone
  const zone = $o("upload-zone");
  if (zone) {
    zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", e => {
      e.preventDefault();
      zone.classList.remove("drag-over");
      const f = e.dataTransfer.files[0];
      if (f) oosSetFile(f);
    });
    zone.addEventListener("click", () => fileInput && fileInput.click());
  }

  // Start scan button
  const scanBtn = $o("btn-scan");
  if (scanBtn) scanBtn.addEventListener("click", oosStartScan);

  // New scan (from results)
  const newBtn = $o("btn-new-scan");
  if (newBtn) newBtn.addEventListener("click", oosReset);

  // Export buttons
  const csvBtn  = $o("btn-export-csv");
  const htmlBtn = $o("btn-export-html");
  if (csvBtn)  csvBtn.addEventListener("click",  () => oosExport("csv"));
  if (htmlBtn) htmlBtn.addEventListener("click", () => oosExport("html"));

  // Hide lint noise (multi-method / dupes / noresp / noid)
  const lintCb = document.getElementById("oos-opt-hide-lint");
  if (lintCb) lintCb.addEventListener("change", () => {
    oosApplyLintHide();
    oosApplyResultsFilter();
  });

  // Results search + severity chips
  const qEl = document.getElementById("oos-filter-q");
  if (qEl) qEl.addEventListener("input", oosApplyResultsFilter);
  document.querySelectorAll("#oos-sev-filters .oos-sev-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      _oosFilterSev = chip.getAttribute("data-sev") || "all";
      document.querySelectorAll("#oos-sev-filters .oos-sev-chip").forEach((c) => {
        c.classList.toggle("active", c === chip);
      });
      oosApplyResultsFilter();
    });
  });
}

// ── File selection ────────────────────────────────────────────────────────────
function oosSetFile(file) {
  const ext = file.name.split(".").pop().toLowerCase();
  if (!["json","yaml","yml"].includes(ext)) {
    oosShowError("Unsupported file type. Please upload .json / .yaml / .yml");
    return;
  }
  _oosFile = file;

  const nameEl = $o("file-name");
  if (nameEl) nameEl.textContent = file.name;

  const sizeEl = $o("file-size");
  if (sizeEl) {
    const kb = (file.size / 1024).toFixed(1);
    sizeEl.textContent = kb < 1000 ? `${kb} KB` : `${(kb/1024).toFixed(2)} MB`;
  }

  const infoEl = $o("file-info");
  if (infoEl) infoEl.style.display = "flex";

  const scanBtn = $o("btn-scan");
  if (scanBtn) scanBtn.disabled = false;

  oosHideError();
}

// ── Start scan ────────────────────────────────────────────────────────────────
async function oosStartScan() {
  if (!_oosFile) return;

  oosShowView("scanning");
  _oosJobId = null;
  _oosAudit = null;

  // Animate steps
  const steps = [
    { id: "step-load",      label: "Loading spec file…"             },
    { id: "step-parse",     label: "Parsing OpenAPI structure…"     },
    { id: "step-sec",       label: "Checking security config…"      },
    { id: "step-dangerous", label: "Scanning for dangerous endpoints…" },
    { id: "step-dup",       label: "Detecting duplicates…"          },
    { id: "step-ref",       label: "Validating \$refs…"             },
    { id: "step-score",     label: "Computing health score…"        },
  ];

  // Reset all steps
  steps.forEach(s => {
    const el = $o(s.id);
    if (el) { el.className = "oos-step"; el.querySelector(".oos-step-icon").textContent = "⏳"; }
  });

  // Kick off fetch in parallel with animation
  const formData = new FormData();
  formData.append("file", _oosFile);
  const strictEl = $o("opt-strict-unsecured");
  formData.append("strict_unsecured", strictEl && strictEl.checked ? "true" : "false");
  const probeEl = $o("opt-live-probe");
  const liveProbe = !!(probeEl && probeEl.checked);
  formData.append("live_probe", liveProbe ? "true" : "false");
  formData.append("base_url", ($o("base-url")?.value || "").trim());
  formData.append("auth_header", ($o("auth-header")?.value || "").trim());
  if (liveProbe && !($o("base-url")?.value || "").trim()) {
    oosShowView("upload");
    oosShowError("Live probe is on — enter a Base URL first.");
    return;
  }

  const fetchPromise = fetch(`${OOS_BACKEND}/scan`, { method: "POST", body: formData });

  // Animate first 3 steps (fake progress while waiting)
  for (let i = 0; i < 3; i++) {
    await _oosDelay(260);
    _oosStepDone(steps[i].id);
  }

  let result;
  try {
    const resp = await fetchPromise;
    result = await resp.json();
    if (!resp.ok) throw new Error(result.detail || "Scan failed");
  } catch (e) {
    oosShowView("upload");
    oosShowError("Scan error: " + e.message);
    return;
  }

  // Animate remaining steps
  for (let i = 3; i < steps.length; i++) {
    await _oosDelay(200);
    _oosStepDone(steps[i].id);
  }

  await _oosDelay(300);

  _oosJobId = result.job_id;
  _oosAudit = result;
  oosRenderResults(result);
  oosShowView("results");
}

function _oosStepDone(id) {
  const el = $o(id);
  if (el) {
    el.classList.add("done");
    el.querySelector(".oos-step-icon").textContent = "✅";
  }
}

function _oosDelay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Render results ────────────────────────────────────────────────────────────
function oosRenderResults(audit) {
  // ── Health score card (uniform card design)
  const score = audit.health_score;
  const colorClass = score >= 80 ? "oos-sum-green" : score >= 50 ? "oos-sum-yellow" : "oos-sum-red";

  const scoreCard = $o("score-card");
  if (scoreCard) scoreCard.className = "oos-sum-card " + colorClass;

  const scoreEl = $o("score-value");
  if (scoreEl) scoreEl.textContent = score + "%";

  const barEl = $o("score-bar");
  if (barEl) {
    barEl.style.width = score + "%";
    barEl.style.background = score >= 80 ? "var(--green)" : score >= 50 ? "var(--yellow)" : "var(--red)";
  }

  const scoreLabel = $o("score-label");
  if (scoreLabel) {
    scoreLabel.textContent = score >= 80 ? "Good" : score >= 50 ? "Fair" : "Poor";
  }

  // ── Summary cards
  const total = audit.unique_apis.length;
  _oosSet("sum-dangerous", (audit.dangerous_endpoints || []).length);
  _oosSet("sum-secrets",   (audit.leaked_secrets || []).length);
  _oosSet("sum-total",    total);
  _oosSet("sum-unsec",    audit.unsecured.length);
  _oosSet("sum-dup",      audit.duplicates.length);
  _oosSet("sum-refs",     audit.undefined_refs.length);
  _oosSet("sum-noresp",   audit.missing_responses.length);
  _oosSet("sum-noid",     audit.no_operation_id.length);

  // ── Spec info
  _oosSet("spec-title",   audit.spec_title);
  _oosSet("spec-version", audit.spec_version || "-");
  _oosSet("spec-file",    audit.filename);
  _oosSet("spec-time",    audit.scanned_at);
  // Soft hint for OAS2 normalization
  const fileEl = $o("spec-file");
  if (fileEl && audit.spec_format === "swagger2") {
    fileEl.title = "Normalized from OpenAPI 2.0 (swagger: 2.0)";
  }

  // ── Security schemes
  const schemesEl = $o("schemes");
  if (schemesEl) {
    if (audit.security_schemes.length) {
      schemesEl.innerHTML = audit.security_schemes.map(s =>
        `<span class="oos-scheme-pill">${oosEsc(s)}</span>`
      ).join("");
    } else {
      schemesEl.innerHTML = '<span class="oos-no-scheme">None defined</span>';
    }
  }

  const globalEl = $o("global-security");
  if (globalEl) {
    globalEl.innerHTML = audit.global_security
      ? '<span class="oos-sec-ok">✅ Global security policy present</span>'
      : '<span class="oos-sec-warn">⚠️ No global security policy set</span>';
  }

  // ── Section tables
  const sections = [
    { id: "sec-dangerous",   items: audit.dangerous_endpoints || [],       sev: "critical", emptyMsg: "No dangerous-by-design endpoints detected ✅", dangerous: true },
    { id: "sec-sensitive",   items: audit.sensitive_data_exposure || [],   sev: "high",     emptyMsg: "No high-signal sensitive fields in 2xx response schemas ✅", fields: true, fieldLabel: "fields" },
    { id: "sec-massassign",  items: audit.mass_assignment_risk || [],      sev: "high",     emptyMsg: "No high-signal privilege fields / open additionalProperties in request bodies ✅", fields: true, fieldLabel: "fields" },
    { id: "sec-secrets",     items: audit.leaked_secrets || [],            sev: "critical", emptyMsg: "No hardcoded secrets found in spec examples ✅", secrets: true },
    { id: "sec-insecuresrv", items: audit.insecure_servers || [],          sev: "high",     emptyMsg: "No plaintext HTTP servers found ✅" },
    { id: "sec-weakkey",     items: audit.weak_apikey_schemes || [],       sev: "medium",   emptyMsg: "No weak apiKey placements found ✅" },
    { id: "sec-getbody",     items: audit.get_with_body || [],             sev: "medium",   emptyMsg: "No GET-with-body endpoints found ✅" },
    { id: "sec-deprecated",  items: audit.deprecated_endpoints || [],      sev: "low",      emptyMsg: "No deprecated-but-live endpoints found ✅" },
    { id: "sec-unsecured",  items: audit.unsecured || [],         sev: "critical", emptyMsg: "All endpoints are secured (or only expected-public) ✅" },
    { id: "sec-public",     items: audit.public_expected || [],   sev: "info",     emptyMsg: "No allowlisted public endpoints ✅" },
    { id: "sec-probes",     items: audit.live_probes || [],       sev: "info",     emptyMsg: "No live probes run (enable on upload + Base URL)", probes: true },
    { id: "sec-dupes",      items: audit.duplicates,         sev: "warning",  emptyMsg: "No duplicate endpoints found ✅" },
    { id: "sec-multi",      items: audit.multi_methods,      sev: "info",     emptyMsg: "No multi-method paths ✅", custom: true },
    { id: "sec-refs",       items: audit.undefined_refs || [],  sev: "high",  emptyMsg: "All local $refs resolve ✅" },
    { id: "sec-extrefs",    items: audit.external_refs || [],   sev: "info",  emptyMsg: "No external $refs ✅" },
    { id: "sec-noresp",     items: audit.missing_responses,  sev: "medium",   emptyMsg: "All endpoints have response definitions ✅" },
    { id: "sec-noid",       items: audit.no_operation_id,    sev: "low",      emptyMsg: "All endpoints have operationId ✅" },
    { id: "sec-all",        items: audit.unique_apis,        sev: "info",     emptyMsg: "No endpoints found." },
  ];

  sections.forEach(({ id, items, sev, emptyMsg, custom, dangerous, fields, fieldLabel, secrets, probes }) => {
    const tbody   = $o(id + "-body");
    const countEl = $o(id + "-count");
    if (countEl) countEl.textContent = items.length;
    if (!tbody) return;

    if (!items.length) {
      const colspan = dangerous ? 8 : (fields ? 4 : (secrets ? 5 : (probes ? 5 : 3)));
      tbody.innerHTML = `<tr><td colspan="${colspan}" class="oos-empty">${emptyMsg}</td></tr>`;
      return;
    }

    // ── Dangerous endpoints: expandable row with full write-up ──
    if (dangerous) {
      tbody.innerHTML = items.map((item, i) => {
        const authHtml = item.unauthenticated
          ? '<span style="color:var(--red);font-weight:700">NO AUTH REQUIRED</span>'
          : '<span style="color:var(--text3)">Secured</span>';
        const uid = `oos-dz-${i}`;
        return `<tr class="oos-row-clickable" onclick="oosToggleDetail('${uid}')">
          <td class="oos-num">${i + 1}</td>
          <td class="oos-detail"><code>${oosEsc(item.endpoint)}</code></td>
          <td style="font-size:11px">${oosEsc(item.category)}</td>
          <td style="font-size:11px;color:#7dd3fc">${oosEsc(item.matched_keywords.join(", "))}</td>
          <td>${authHtml}</td>
          <td>${_oosSevBadge(item.severity.toLowerCase())}</td>
          <td style="font-family:var(--mono);font-size:11px;color:#f0abfc">${oosEsc(item.cvss_score)}</td>
          <td class="oos-expand-arrow">▾</td>
        </tr>
        <tr class="oos-detail-row" id="${uid}" style="display:none">
          <td colspan="8">
            <div class="oos-detail-box">
              <p><strong>Spec description:</strong> <em>${item.summary ? oosEsc(item.summary) : "(none provided in spec)"}</em></p>
              <p><strong>Impact:</strong> ${oosEsc(item.impact)}</p>
              <p><strong>Recommendation:</strong> ${oosEsc(item.recommendation)}</p>
              <p><strong>CWE:</strong> ${oosEsc(item.cwe)} &nbsp;|&nbsp; <strong>OWASP:</strong> ${oosEsc(item.owasp)}</p>
              <p><strong>Suggested CVSS 3.1:</strong> ${oosEsc(item.cvss_score)} — <code>${oosEsc(item.cvss_vector)}</code>
                <span class="oos-cvss-note">(template default for this category — verify against actual business impact)</span></p>
              <p><strong>Exploitation note:</strong> ${oosEsc(item.exploitation_note)}</p>
            </div>
          </td>
        </tr>`;
      }).join("");
      return;
    }

    // ── Sensitive-data / mass-assignment: {endpoint, fields:[...]} rows ──
    if (fields) {
      tbody.innerHTML = items.map((item, i) => `<tr>
        <td class="oos-num">${i + 1}</td>
        <td class="oos-detail"><code>${oosEsc(item.endpoint)}</code></td>
        <td style="font-size:11px;color:#f0abfc">${oosEsc(item.fields.join(", "))}</td>
        <td>${_oosSevBadge(sev)}</td>
      </tr>`).join("");
      return;
    }

    // ── Leaked secrets: {type, location, value} rows ──
    if (secrets) {
      tbody.innerHTML = items.map((item, i) => `<tr>
        <td class="oos-num">${i + 1}</td>
        <td style="font-size:11px">${oosEsc(item.type)}</td>
        <td class="oos-detail"><code>${oosEsc(item.location)}</code></td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--red)">${oosEsc(item.value)}</td>
        <td>${_oosSevBadge("critical")}</td>
      </tr>`).join("");
      return;
    }

    // ── Live probes ──
    if (probes) {
      const verdictColor = {
        open_ok: "var(--red)", auth_required: "var(--green)",
        not_found: "var(--text3)", unreachable: "var(--yellow)",
        server_error: "#f97316", other: "var(--text2)",
      };
      tbody.innerHTML = items.map((item, i) => `<tr>
        <td class="oos-num">${i + 1}</td>
        <td class="oos-detail"><code>${oosEsc(item.endpoint)}</code></td>
        <td style="font-family:var(--mono);font-size:11px">${oosEsc(item.probe_method || "-")}</td>
        <td style="font-family:var(--mono);font-size:11px">${item.status != null ? oosEsc(item.status) : "—"}</td>
        <td style="font-size:11px;font-weight:600;color:${verdictColor[item.verdict] || "var(--text2)"}" title="${oosEsc(item.error || item.url || "")}">${oosEsc(item.verdict || "-")}</td>
      </tr>`).join("");
      return;
    }

    // ── Multi-method: custom row with clickable cURL badges ──
    if (custom) {
      tbody.innerHTML = items.map((item, i) => {
        const arrowIdx   = item.indexOf("  →  ");
        const path       = arrowIdx >= 0 ? item.substring(0, arrowIdx).trim() : item;
        const methodsStr = arrowIdx >= 0 ? item.substring(arrowIdx + 5).trim() : "";
        const methods    = methodsStr ? methodsStr.split(", ").map(m => m.trim()) : [];
        const safeP      = path.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
        const badges     = methods.map(m =>
          `<span class="oos-method-curl oos-mc-${m.toLowerCase()}"
                onclick="oosCopyCurl(this,'${m}','${safeP}')"
                title="Click to copy cURL — ${m} ${path}">${m}</span>`
        ).join("");
        return `<tr>
          <td class="oos-num">${i + 1}</td>
          <td class="oos-detail">
            <div class="oos-multi-row">
              <code class="oos-path">${oosEsc(path)}</code>
              <div class="oos-badges-row">${badges}</div>
            </div>
          </td>
          <td>${_oosSevBadge(sev)}</td>
        </tr>`;
      }).join("");
      return;
    }

    // ── Default rendering ──
    tbody.innerHTML = items.map((item, i) =>
      `<tr>
        <td class="oos-num">${i + 1}</td>
        <td class="oos-detail"><code>${oosEsc(item)}</code></td>
        <td>${_oosSevBadge(sev)}</td>
      </tr>`
    ).join("");
  });

  // Auto-open real findings with hits; keep lint + inventory collapsed
  document.querySelectorAll("#tool-oos .oos-section").forEach((sec) => {
    const body = sec.querySelector(".oos-section-body");
    const arr  = sec.querySelector(".oos-section-arrow");
    if (!body) return;
    const isLint = sec.getAttribute("data-lint") === "1";
    const countEl = sec.querySelector(".oos-section-count");
    const count = countEl ? parseInt(countEl.textContent || "0", 10) : 0;
    const inventory = !!(sec.querySelector("#oos-hdr-all") || sec.querySelector("#oos-hdr-public"));
    const open = count > 0 && !isLint && !inventory;
    body.style.display = open ? "" : "none";
    if (arr) arr.textContent = open ? "▾" : "▸";
  });
  oosApplyLintHide();
  oosApplyResultsFilter();
}

/** Hide/show style-lint sections (multi-method, dupes, noresp, noid). */
function oosApplyLintHide() {
  const cb = document.getElementById("oos-opt-hide-lint");
  const hide = !cb || cb.checked;
  document.querySelectorAll("#tool-oos .oos-section[data-lint='1']").forEach((sec) => {
    sec.classList.toggle("oos-lint-hidden", hide);
    if (hide) {
      const body = sec.querySelector(".oos-section-body");
      const arr = sec.querySelector(".oos-section-arrow");
      if (body) body.style.display = "none";
      if (arr) arr.textContent = "▸";
    }
  });
}

function _oosNormSev(s) {
  s = String(s || "").trim().toLowerCase();
  if (s === "warning" || s === "warn") return "medium";
  return s;
}

/** Filter visible sections/rows by search text + severity chip. */
function oosApplyResultsFilter() {
  const q = (document.getElementById("oos-filter-q")?.value || "").trim().toLowerCase();
  const sev = _oosNormSev(_oosFilterSev || "all");
  const filtering = !!(q || sev !== "all");
  let visibleRows = 0;
  let visibleSecs = 0;

  document.querySelectorAll("#tool-oos .oos-section").forEach((sec) => {
    const lintHidden = sec.classList.contains("oos-lint-hidden");
    const sectionSev = _oosNormSev(sec.getAttribute("data-sev") || "info");
    let rowHits = 0;

    const dataRows = [];
    sec.querySelectorAll("tbody tr").forEach((tr) => {
      if (tr.classList.contains("oos-detail-row")) return;
      if (tr.querySelector(".oos-empty")) {
        tr.style.display = filtering ? "none" : "";
        return;
      }
      dataRows.push(tr);
    });

    dataRows.forEach((tr) => {
      const text = (tr.textContent || "").toLowerCase();
      const badge = tr.querySelector(".oos-sev");
      const rowSev = badge
        ? _oosNormSev(badge.textContent)
        : sectionSev;
      const sevOk = sev === "all" || rowSev === sev;
      const textOk = !q || text.includes(q);
      const show = sevOk && textOk;
      tr.style.display = show ? "" : "none";
      const detail = tr.nextElementSibling;
      if (detail && detail.classList.contains("oos-detail-row") && !show) {
        detail.style.display = "none";
      }
      if (show) rowHits++;
    });

    const showSec = !lintHidden && (!filtering || rowHits > 0);
    sec.classList.toggle("oos-filter-hidden", !showSec && filtering);
    if (!filtering) sec.classList.remove("oos-filter-hidden");

    if (showSec && filtering && rowHits > 0) {
      const body = sec.querySelector(".oos-section-body");
      const arr = sec.querySelector(".oos-section-arrow");
      if (body) body.style.display = "";
      if (arr) arr.textContent = "▾";
    }

    if (showSec) {
      visibleSecs++;
      visibleRows += rowHits;
    }
  });

  const meta = document.getElementById("oos-filter-meta");
  if (meta) {
    meta.textContent = filtering
      ? `${visibleRows} row${visibleRows === 1 ? "" : "s"} in ${visibleSecs} section${visibleSecs === 1 ? "" : "s"}`
      : "";
  }
}

function _oosSet(id, val) {
  const el = $o(id);
  if (el) el.textContent = val ?? "-";
}

function _oosSevBadge(sev) {
  const cfg = {
    critical: ["#fef2f2","#ef4444","#7f1d1d"],
    high:     ["#fff7ed","#f97316","#7c2d12"],
    warning:  ["#fefce8","#eab308","#713f12"],
    medium:   ["rgba(34,197,94,.12)","#22c55e","#14532d"],
    low:      ["rgba(148,163,184,.1)","#64748b","#94a3b8"],
    info:     ["rgba(59,130,246,.1)","#3b82f6","#bfdbfe"],
  };
  const [bg, border, text] = cfg[sev] || cfg.info;
  return `<span class="oos-sev" style="background:${bg};border-color:${border};color:${text}">${sev.toUpperCase()}</span>`;
}

// ── Copy cURL ─────────────────────────────────────────────────────────────────
function oosCopyCurl(badgeEl, method, path) {
  const needsBody = ["POST","PUT","PATCH"].includes(method.toUpperCase());
  let curl = `curl -X ${method} "{{BASE_URL}}${path}"`;
  curl    += `\n  -H "Authorization: Bearer {{TOKEN}}"`;
  if (needsBody) {
    curl  += `\n  -H "Content-Type: application/json"`;
    curl  += `\n  -d '{}'`;
  }

  // Copy to clipboard
  try {
    navigator.clipboard.writeText(curl).catch(() => _oosFallbackCopy(curl));
  } catch(e) {
    _oosFallbackCopy(curl);
  }

  // Visual feedback: badge → "✓ Copied" for 1.5s
  const orig = badgeEl.textContent;
  badgeEl.textContent = "✓ Copied";
  badgeEl.classList.add("oos-mc-copied");
  setTimeout(() => {
    badgeEl.textContent = orig;
    badgeEl.classList.remove("oos-mc-copied");
  }, 1500);
}

function _oosFallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.cssText = "position:fixed;opacity:0;top:0;left:0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); } catch(e) {}
  document.body.removeChild(ta);
}

// ── Section toggle ────────────────────────────────────────────────────────────
function oosToggleSection(headerId) {
  const header = document.getElementById(headerId);
  if (!header) return;
  const body = header.nextElementSibling;
  const arr  = header.querySelector(".oos-section-arrow");
  if (!body) return;
  const open = body.style.display !== "none";
  body.style.display = open ? "none" : "";
  if (arr) arr.textContent = open ? "▸" : "▾";
}

// ── Dangerous-endpoint row expand/collapse (full write-up) ────────────────────
function oosToggleDetail(rowId) {
  const row = document.getElementById(rowId);
  if (!row) return;
  const open = row.style.display !== "none";
  row.style.display = open ? "none" : "table-row";
  const trigger = row.previousElementSibling;
  const arrow = trigger && trigger.querySelector(".oos-expand-arrow");
  if (arrow) arrow.textContent = open ? "▾" : "▴";
}

// ── Export ────────────────────────────────────────────────────────────────────
async function oosExport(format) {
  if (!_oosJobId) return;
  const url = `${OOS_BACKEND}/export/${format}?job_id=${_oosJobId}`;

  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("Export failed");
    const blob = await resp.blob();
    const text = await blob.text();
    const ext  = format === "csv" ? "csv" : "html";
    const filename = (_oosAudit?.filename || "spec").replace(/\.[^.]+$/, "") + `.${ext}`;
    const mimeType = format === "csv" ? "text/csv" : "text/html";
    _oosSaveFile(text, filename, mimeType);
  } catch(e) {
    alert("Export error: " + e.message);
  }
}

function _oosSaveFile(content, filename, mimeType) {
  // Try pywebview native save dialog first
  if (window.pywebview && window.pywebview.api && window.pywebview.api.save_file) {
    window.pywebview.api.save_file(content, filename)
      .then(result => {
        if (result && result.ok) {
          _oosFlashExport(`✅ Saved: ${result.filename}`);
        }
      })
      .catch(() => _oosBlobDownload(content, filename, mimeType));
    return;
  }
  _oosBlobDownload(content, filename, mimeType);
}

function _oosBlobDownload(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  _oosFlashExport(`✅ Downloaded: ${filename}`);
}

function _oosFlashExport(msg) {
  const el = $o("export-msg");
  if (!el) return;
  el.textContent = msg;
  el.style.opacity = "1";
  setTimeout(() => { el.style.opacity = "0"; }, 3000);
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function oosReset() {
  _oosFile   = null;
  _oosJobId  = null;
  _oosAudit  = null;
  _oosFilterSev = "all";

  const fileInput = $o("file-input");
  if (fileInput) fileInput.value = "";

  const infoEl = $o("file-info");
  if (infoEl) infoEl.style.display = "none";

  const scanBtn = $o("btn-scan");
  if (scanBtn) scanBtn.disabled = true;

  const qEl = document.getElementById("oos-filter-q");
  if (qEl) qEl.value = "";
  document.querySelectorAll("#oos-sev-filters .oos-sev-chip").forEach((c) => {
    c.classList.toggle("active", (c.getAttribute("data-sev") || "") === "all");
  });
  const meta = document.getElementById("oos-filter-meta");
  if (meta) meta.textContent = "";

  oosHideError();
  oosShowView("upload");
}

// ── Error handling ────────────────────────────────────────────────────────────
function oosShowError(msg) {
  const el = $o("error");
  if (el) { el.textContent = msg; el.style.display = ""; }
}
function oosHideError() {
  const el = $o("error");
  if (el) el.style.display = "none";
}
