/**
 * ══════════════════════════════════════════════════════════════════════════════
 * JWT TOOL (JWT Sentinel) - CLIENT CONTROLLER
 * Port 8798 · Token Inspection, Attack Suite & Automated Vulnerability Probing
 * ══════════════════════════════════════════════════════════════════════════════
 */

const JWT_BASE = "http://127.0.0.1:8798";

let _jwtCurrentParsed = null;
let _jwtScanResults = [];
let _jwtSelectedResultIdx = null;

// Initialize on load
document.addEventListener("DOMContentLoaded", () => {
  const tokenInp = document.getElementById("jwt-token-input");
  if (tokenInp) {
    tokenInp.addEventListener("input", () => jwtOnTokenInput());
  }

  // Real-time JSON syntax error feedback in Forger tab + auto-forge listeners
  const forgerHdrTa = document.getElementById("jwt-forger-header");
  const forgerPayTa = document.getElementById("jwt-forger-payload");
  const forgerAlgSel = document.getElementById("jwt-forger-alg");
  const forgerSecInp = document.getElementById("jwt-forger-secret");

  if (forgerHdrTa) {
    const handleHdrChange = () => {
      const errEl = document.getElementById("jwt-forger-header-err");
      try {
        const cleanH = jwtCleanJsonString(forgerHdrTa.value.trim() || "{}");
        const parsed = JSON.parse(cleanH);
        if (errEl) errEl.style.display = "none";
        
        // If user typed a recognized algorithm in JSON, sync dropdown without touching textarea
        if (parsed && parsed.alg && forgerAlgSel) {
          const matchedOpt = Array.from(forgerAlgSel.options).find(o => o.value.toLowerCase() === String(parsed.alg).toLowerCase());
          if (matchedOpt && forgerAlgSel.value !== matchedOpt.value) {
            forgerAlgSel.value = matchedOpt.value;
          }
        }
        jwtAutoUpdateForgedToken();
      } catch (_) {
        if (errEl) errEl.style.display = "inline";
      }
    };
    forgerHdrTa.addEventListener("input", handleHdrChange);
    forgerHdrTa.addEventListener("blur", () => jwtNormalizeSmartQuotesInTextarea(forgerHdrTa));
    forgerHdrTa.addEventListener("paste", () => setTimeout(() => {
      jwtNormalizeSmartQuotesInTextarea(forgerHdrTa);
      handleHdrChange();
    }, 20));
    forgerHdrTa.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "z" || e.key === "Z" || e.key === "y" || e.key === "Y")) {
        setTimeout(handleHdrChange, 30);
      }
    });
  }
  if (forgerPayTa) {
    const handlePayChange = () => {
      const errEl = document.getElementById("jwt-forger-payload-err");
      try {
        const cleanP = jwtCleanJsonString(forgerPayTa.value.trim() || "{}");
        JSON.parse(cleanP);
        if (errEl) errEl.style.display = "none";
        jwtAutoUpdateForgedToken();
      } catch (_) {
        if (errEl) errEl.style.display = "inline";
      }
    };
    forgerPayTa.addEventListener("input", handlePayChange);
    forgerPayTa.addEventListener("blur", () => jwtNormalizeSmartQuotesInTextarea(forgerPayTa));
    forgerPayTa.addEventListener("paste", () => setTimeout(() => {
      jwtNormalizeSmartQuotesInTextarea(forgerPayTa);
      handlePayChange();
    }, 20));
    forgerPayTa.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "z" || e.key === "Z" || e.key === "y" || e.key === "Y")) {
        setTimeout(handlePayChange, 30);
      }
    });
  }
  if (forgerAlgSel) {
    forgerAlgSel.addEventListener("change", () => {
      const headerTa = document.getElementById("jwt-forger-header");
      if (headerTa) {
        try {
          const hObj = JSON.parse(jwtCleanJsonString(headerTa.value.trim() || "{}"));
          hObj.alg = forgerAlgSel.value;
          headerTa.value = JSON.stringify(hObj, null, 2);
        } catch (_) {}
      }
      jwtExecuteForgeAuto();
    });
  }
  if (forgerSecInp) {
    forgerSecInp.addEventListener("input", () => {
      jwtAutoUpdateForgedToken();
    });
  }

  jwtCheckEngineHealth();
  jwtInitPocResizer();
});

async function jwtCheckEngineHealth() {
  const statusPill = document.getElementById("jwt-status-pill");
  try {
    const res = await fetch(`${JWT_BASE}/jwt/health`, { method: "GET" });
    if (res.ok) {
      if (statusPill) {
        statusPill.innerHTML = "● Online";
        statusPill.style.color = "var(--green, #3fb950)";
        statusPill.style.background = "rgba(63, 185, 80, 0.12)";
      }
    } else {
      throw new Error("HTTP " + res.status);
    }
  } catch (_) {
    if (statusPill) {
      statusPill.innerHTML = "○ Offline";
      statusPill.style.color = "var(--red, #f85149)";
      statusPill.style.background = "rgba(248, 81, 73, 0.12)";
    }
  }
}

let _jwtInspCurrentTab = "payload";

function jwtSwitchInspectorTab(tab) {
  _jwtInspCurrentTab = tab;
  document.querySelectorAll(".jwt-insp-tab").forEach(b => b.classList.remove("active"));
  const btn = document.getElementById(`jwt-insp-tab-${tab}`);
  if (btn) btn.classList.add("active");

  const boxH = document.getElementById("jwt-box-header");
  const boxP = document.getElementById("jwt-box-payload");
  const boxS = document.getElementById("jwt-box-sig");
  const boxA = document.getElementById("jwt-box-audit");

  if (boxH) boxH.style.display = tab === "header" ? "flex" : "none";
  if (boxP) boxP.style.display = tab === "payload" ? "flex" : "none";
  if (boxS) boxS.style.display = tab === "sig" ? "flex" : "none";
  if (boxA) boxA.style.display = tab === "audit" ? "flex" : "none";
}

function jwtCopyDecoded(btn) {
  let targetId = "jwt-pre-payload";
  if (_jwtInspCurrentTab === "header") targetId = "jwt-pre-header";
  else if (_jwtInspCurrentTab === "sig") targetId = "jwt-pre-sig";
  else if (_jwtInspCurrentTab === "audit") {
    const el = document.getElementById("jwt-audit-content");
    if (el) jwtCopyToClipboard(el.innerText || el.textContent, btn, "Copied!");
    return;
  }
  const el = document.getElementById(targetId);
  if (el) {
    jwtCopyToClipboard(el.innerText || el.textContent, btn, "Copied!");
  }
}

function jwtSelectAllAttacks(val) {
  document.querySelectorAll(".jwt-atk-cb").forEach(cb => {
    cb.checked = !!val;
  });
  jwtUpdateAttackCount();
}

function jwtUpdateAttackCount() {
  const total = document.querySelectorAll(".jwt-atk-cb").length || 19;
  const count = document.querySelectorAll(".jwt-atk-cb:checked").length;
  const pill = document.getElementById("jwt-attacks-count-pill");
  if (pill) pill.textContent = `${count}/${total} Active`;
}

function jwtInitPocResizer() {
  const handle = document.getElementById("jwt-poc-vresize");
  const panel = document.getElementById("jwt-poc-panel");
  if (!handle || !panel || handle._jwtBound) return;
  handle._jwtBound = true;

  // Restore saved height if any
  const savedH = localStorage.getItem("jwt_poc_height");
  if (savedH) {
    const h = parseInt(savedH, 10);
    if (!isNaN(h) && h >= 65 && h <= 700) {
      panel.style.height = h + "px";
    }
  }

  let dragging = false;
  let startY = 0;
  let startH = 0;

  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragging = true;
    handle.classList.add("dragging");
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    startY = e.clientY;
    startH = panel.getBoundingClientRect().height;
  });

  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    // Dragging UP (smaller clientY) increases the bottom panel height
    const delta = startY - e.clientY;
    const minH = 65;
    const maxH = Math.max(250, window.innerHeight - 240);
    const newH = Math.max(minH, Math.min(maxH, startH + delta));
    panel.style.height = newH + "px";
  });

  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    const currentH = panel.getBoundingClientRect().height;
    localStorage.setItem("jwt_poc_height", Math.round(currentH));
  });

  // Double click on handle to toggle between compact (180px) and expanded (360px)
  handle.addEventListener("dblclick", () => {
    const cur = panel.getBoundingClientRect().height;
    const targetH = cur > 220 ? 180 : 360;
    panel.style.height = targetH + "px";
    localStorage.setItem("jwt_poc_height", targetH);
  });
}

let _jwtCurrentMainTab = "setup";
let _jwtConsoleLogs = [];
let _jwtUnreadConsoleCount = 0;

function jwtSwitchMainTab(tab) {
  _jwtCurrentMainTab = tab;
  document.querySelectorAll(".jwt-nav-tab-btn").forEach(b => b.classList.remove("active"));
  const btn = document.getElementById(`jwt-nav-btn-${tab}`);
  if (btn) btn.classList.add("active");

  const vSetup = document.getElementById("jwt-view-setup");
  const vScanner = document.getElementById("jwt-view-scanner");
  const vConsole = document.getElementById("jwt-view-console");
  const vCracker = document.getElementById("jwt-view-cracker");
  const vForger = document.getElementById("jwt-view-forger");

  if (vSetup) vSetup.style.display = tab === "setup" ? "flex" : "none";
  if (vScanner) vScanner.style.display = tab === "scanner" ? "flex" : "none";
  if (vConsole) vConsole.style.display = tab === "console" ? "flex" : "none";
  if (vCracker) vCracker.style.display = tab === "cracker" ? "flex" : "none";
  if (vForger) {
    vForger.style.display = tab === "forger" ? "flex" : "none";
    if (tab === "forger") {
      const curTok = (document.getElementById("jwt-token-input")?.value || "").trim();
      if (!curTok || curTok !== _jwtForgerLoadedToken || !document.getElementById("jwt-forger-payload")?.value.trim()) {
        jwtSyncForgerFromSetup();
      }
    }
  }

  if (tab === "scanner") {
    jwtInitPocResizer();
  } else if (tab === "console") {
    const badge = document.getElementById("jwt-badge-console");
    if (badge) {
      badge.style.display = "none";
      _jwtUnreadConsoleCount = 0;
    }
    jwtScrollConsole();
  } else if (tab === "cracker") {
    jwtUpdateCrackerAlgDisplay();
  }
}

function jwtSwitchEpTab(tab) {
  document.querySelectorAll(".jwt-ep-tab").forEach(b => b.classList.remove("active"));
  const btn = document.getElementById(`jwt-ep-tab-${tab}`);
  if (btn) btn.classList.add("active");

  const pHdrs = document.getElementById("jwt-ep-pane-headers");
  const pBody = document.getElementById("jwt-ep-pane-body");
  const pAdv = document.getElementById("jwt-ep-pane-advanced");

  if (pHdrs) pHdrs.style.display = tab === "headers" ? "flex" : "none";
  if (pBody) pBody.style.display = tab === "body" ? "flex" : "none";
  if (pAdv) pAdv.style.display = tab === "advanced" ? "flex" : "none";
}

function jwtProceedToScanner() {
  const token = (document.getElementById("jwt-token-input")?.value || "").trim();
  const url = (document.getElementById("jwt-target-url")?.value || "").trim();
  const pubKey = (document.getElementById("jwt-target-pubkey")?.value || "").trim();

  jwtSwitchMainTab("scanner");

  // If token is present, no URL is set, and attacks are not yet loaded, auto-generate offline!
  if (token && !url && (!_jwtScanResults || _jwtScanResults.length === 0)) {
    jwtRunOfflineGeneration(token, pubKey);
  }
}

async function jwtRunOfflineGeneration(token, pubKey = null, selected = []) {
  jwtSwitchMainTab("scanner");

  const runBtn = document.getElementById("jwt-run-scan-btn");
  const summaryBar = document.getElementById("jwt-summary-bar");
  const consoleStatus = document.getElementById("jwt-console-status-text");

  if (runBtn) {
    runBtn.disabled = true;
    runBtn.innerHTML = "⏳ Generating Vectors…";
  }
  if (summaryBar) {
    summaryBar.innerHTML = "⚡ <strong>Offline Mode:</strong> Generating 22+ tampered attack tokens (No Target URL configured)...";
    summaryBar.style.color = "var(--blue, #58a6ff)";
  }
  if (consoleStatus) consoleStatus.textContent = "Offline Generated";

  jwtLogConsole("══════════════════════════════════════════════════════════════════", "dim");
  jwtLogConsole("⚡ [OFFLINE MODE] Generating tampered attack tokens for inspection...", "info");
  jwtLogConsole("   ↳ Target URL not set: Offline PoC Generation active. Attacks will not be sent over network.", "dim");

  try {
    const res = await fetch(`${JWT_BASE}/jwt/generate-attacks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token,
        public_key: pubKey || null
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to generate attack vectors");

    const allAttacks = data.attacks || [];
    const attacksToRun = (selected && selected.length > 0)
      ? allAttacks.filter(a => selected.includes(a.id) || a.id === "baseline_original")
      : allAttacks;

    const results = attacksToRun.map(a => {
      const authHdr = `Authorization: Bearer ${a.token}`;
      const curlPoc = `curl -i -s -k -X GET "https://api.example.com/target-endpoint" \\\n  -H "${authHdr}"`;
      const pyPoc = `# Standalone PoC Script for ${a.name}\nimport requests\n\nurl = "https://api.example.com/target-endpoint"\nheaders = {\n    "Authorization": "Bearer ${a.token}"\n}\nresp = requests.get(url, headers=headers, verify=False)\nprint("HTTP", resp.status_code)\nprint(resp.text[:500])\n`;

      return {
        attack_id: a.id,
        name: a.name,
        category: a.category,
        description: a.description,
        severity: a.severity,
        tampered_aspect: a.tampered_aspect,
        attack_token: a.token,
        status_code: null,
        reason: "Offline Generated",
        elapsed_seconds: 0,
        content_length: 0,
        response_snippet: "(Offline Mode: Target API URL was not configured. Use 'Copy Token' or configure URL above and click 'Re-check' to probe live.)",
        verdict: "GENERATED",
        vulnerable: false,
        notes: `Offline attack vector ready: ${a.tampered_aspect}. Copy token or configure URL to probe.`,
        curl_poc: curlPoc,
        python_poc: pyPoc
      };
    });

    _jwtScanResults = results;
    jwtRenderScanTable(results);

    const resultsBadge = document.getElementById("jwt-badge-results");
    if (resultsBadge) {
      resultsBadge.textContent = results.length;
      resultsBadge.style.display = "inline-block";
    }

    if (summaryBar) {
      summaryBar.innerHTML = `⚡ <strong>Offline Mode:</strong> ${results.length} Attack Vectors Generated &amp; Ready! Select any vector below to inspect Diff, Decoder, or Copy Token.`;
      summaryBar.style.color = "#58a6ff";
    }

    jwtLogConsole(`✅ [OFFLINE READY] ${results.length} vectors generated. Select any row to inspect tampered claims or copy token.`, "success");
  } catch (err) {
    jwtLogConsole(`[-] Vector generation error: ${err.message}`, "danger");
    if (summaryBar) {
      summaryBar.innerHTML = "❌ Error generating vectors: " + err.message;
      summaryBar.style.color = "#f85149";
    }
    alert("Error generating vectors: " + err.message);
  } finally {
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerHTML = "🚀 Run JWT Attacks";
    }
  }
}

let _jwtAttacksGridExpanded = true;
function jwtToggleAttacksGrid() {
  const el = document.getElementById("jwt-attacks-collapsible");
  const btn = document.getElementById("jwt-toggle-attacks-btn");
  if (!el) return;
  _jwtAttacksGridExpanded = !_jwtAttacksGridExpanded;
  el.style.display = _jwtAttacksGridExpanded ? "block" : "none";
  const pill = document.getElementById("jwt-attacks-count-pill")?.textContent || "";
  if (btn) {
    btn.innerHTML = `⚔️ Vectors (${pill}) ${_jwtAttacksGridExpanded ? "▾" : "▸"}`;
  }
}

function jwtSelectAttackPreset(preset) {
  const allCbs = document.querySelectorAll(".jwt-atk-cb");
  const owaspIds = ["alg_none_lower", "sig_stripped", "sig_tampered", "key_confusion_rs256_hs256", "role_escalation_none", "jwk_embedded_key"];
  const headerIds = ["jwk_embedded_key", "jku_remote_spoof", "x5u_remote_spoof", "kid_path_traversal", "kid_path_win", "kid_null_byte", "kid_sqli", "kid_sqli_or", "kid_cmd_injection", "kid_cmd_pipe"];

  allCbs.forEach(cb => {
    if (preset === "all") cb.checked = true;
    else if (preset === "none") cb.checked = false;
    else if (preset === "owasp") cb.checked = owaspIds.includes(cb.value);
    else if (preset === "header") cb.checked = headerIds.includes(cb.value);
  });
  jwtUpdateAttackCount();
}

function jwtLogConsole(msg, type = "info") {
  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0]; // "HH:MM:SS"
  const entry = { time: timeStr, msg, type };
  _jwtConsoleLogs.push(entry);

  const out = document.getElementById("jwt-console-output");
  if (out) {
    const line = document.createElement("div");
    line.className = `jwt-log-line jwt-log-${type}`;
    line.innerHTML = `<span class="jwt-log-time">[${timeStr}]</span> ${msg}`;
    out.appendChild(line);
    jwtScrollConsole();
  }

  // Update badge if user is on another tab
  if (_jwtCurrentMainTab !== "console") {
    _jwtUnreadConsoleCount++;
    const badge = document.getElementById("jwt-badge-console");
    if (badge) {
      badge.textContent = _jwtUnreadConsoleCount;
      badge.style.display = "inline-block";
    }
  }
}

function jwtScrollConsole() {
  const out = document.getElementById("jwt-console-output");
  const auto = document.getElementById("jwt-console-autoscroll");
  if (out && (!auto || auto.checked)) {
    out.scrollTop = out.scrollHeight;
  }
}

function jwtClearConsoleLogs() {
  _jwtConsoleLogs = [];
  _jwtUnreadConsoleCount = 0;
  const out = document.getElementById("jwt-console-output");
  if (out) out.innerHTML = `<div class="jwt-log-line jwt-log-dim">[*] Console cleared. Ready for next scan session.</div>`;
  const badge = document.getElementById("jwt-badge-console");
  if (badge) badge.style.display = "none";
}

function jwtCopyConsoleLogs(btn) {
  if (!_jwtConsoleLogs.length) return;
  const text = _jwtConsoleLogs.map(l => `[${l.time}] ${l.msg}`).join("\n");
  jwtCopyToClipboard(text, btn, "Logs Copied!");
}

function jwtUpdateCrackerAlgDisplay() {
  const badge = document.getElementById("jwt-crack-alg-badge");
  const subtext = document.getElementById("jwt-crack-subtext");
  if (!badge) return;

  const alg = (_jwtCurrentParsed?.header?.alg || "").toUpperCase();
  if (!alg) {
    badge.textContent = "Alg: (No Token)";
    badge.style.color = "var(--text2)";
    badge.style.background = "var(--bg3)";
    if (subtext) subtext.textContent = "";
    return;
  }

  if (alg.startsWith("HS")) {
    badge.textContent = `Alg: ${alg} (Symmetric HMAC)`;
    badge.style.color = "#3fb950";
    badge.style.background = "rgba(63, 185, 80, 0.15)";
    if (subtext) subtext.textContent = "Ready to brute-force shared secret.";
  } else {
    badge.textContent = `Alg: ${alg} (Asymmetric / Non-HMAC)`;
    badge.style.color = "#d29922";
    badge.style.background = "rgba(210, 153, 34, 0.15)";
    if (subtext) subtext.textContent = `Notice: ${alg} uses RSA/EC keys, not a symmetric HMAC secret.`;
  }
}

function jwtRenderSecurityAudit(audit) {
  const container = document.getElementById("jwt-audit-content");
  if (!container) return;

  if (!audit || !audit.valid) {
    container.innerHTML = `<span style="color:var(--text3);font-size:12px">No audit findings available for this token.</span>`;
    return;
  }

  const grade = audit.grade || "C";
  const gradeClass = `jwt-grade-${grade.toLowerCase()}`;
  const findings = audit.findings || [];

  let html = `
    <div class="jwt-audit-summary-card">
      <div>
        <div style="font-size:12px;font-weight:700;color:var(--text)">${jwtEsc(audit.summary || "Security Analysis")}</div>
        <div style="font-size:10.5px;color:var(--text3);margin-top:2px">Score: ${audit.score || 0}/100 • Algorithm: ${jwtEsc(audit.algorithm || "unknown")}</div>
      </div>
      <div class="jwt-audit-grade-pill ${gradeClass}">Grade ${grade}</div>
    </div>
  `;

  if (findings.length === 0) {
    html += `<div style="text-align:center;padding:16px;color:#3fb950;font-size:12px;font-weight:600">✅ No passive security issues discovered! Token structure adheres to standard RFC guidelines.</div>`;
  } else {
    findings.forEach(f => {
      const sev = (f.severity || "Low").toLowerCase();
      const badgeClass = `jwt-audit-badge-${sev}`;
      html += `
        <div class="jwt-audit-card">
          <div class="jwt-audit-card-head">
            <span style="font-size:11.5px;font-weight:700;color:var(--text)">${jwtEsc(f.title)}</span>
            <span class="${badgeClass}">${jwtEsc(f.severity.toUpperCase())}</span>
          </div>
          <div style="font-size:11px;color:var(--text2);line-height:1.4">${jwtEsc(f.description)}</div>
          ${f.remediation ? `<div style="font-size:10.5px;color:var(--blue,#58a6ff);margin-top:2px"><strong style="color:var(--text3)">Fix:</strong> ${jwtEsc(f.remediation)}</div>` : ""}
        </div>
      `;
    });
  }

  container.innerHTML = html;
}

/**
 * Triggered on token typing/paste in left pane textarea
 */
async function jwtOnTokenInput() {
  const raw = (document.getElementById("jwt-token-input")?.value || "").trim();
  const banner = document.getElementById("jwt-exp-banner");
  const headPre = document.getElementById("jwt-pre-header");
  const payPre = document.getElementById("jwt-pre-payload");
  const sigPre = document.getElementById("jwt-pre-sig");
  const auditContent = document.getElementById("jwt-audit-content");

  if (!raw) {
    if (headPre) headPre.textContent = "// Header (paste JWT above)";
    if (payPre) payPre.textContent = "// Payload";
    if (sigPre) sigPre.textContent = "// Signature";
    if (banner) banner.style.display = "none";
    if (auditContent) auditContent.innerHTML = '<span style="color:var(--text3);font-size:12px">Paste a token to inspect passive security vulnerabilities.</span>';
    _jwtCurrentParsed = null;
    jwtUpdateCrackerAlgDisplay();
    return;
  }

  // ── INTELLIGENT AUTO-CURL DETECTION ON DIRECT PASTE ──
  if (/^\s*curl\s+/i.test(raw)) {
    jwtLogConsole("[cURL DETECTED] Auto-parsing pasted cURL command into target and token fields...", "info");
    const summaryBar = document.getElementById("jwt-summary-bar");
    if (summaryBar) {
      summaryBar.innerHTML = "⏳ <strong>Auto-detecting cURL…</strong> Parsing endpoint, headers, and token...";
      summaryBar.style.color = "#58a6ff";
    }

    let extracted = null;
    try {
      const res = await fetch(`${JWT_BASE}/jwt/parse-curl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ curl: raw })
      });
      if (res.ok) extracted = await res.json();
    } catch (_) {}

    if (!extracted || !extracted.success) {
      extracted = jwtParseCurlClientSide(raw);
    }

    if (extracted && (extracted.url || extracted.token)) {
      // 1. Populate Target URL
      if (extracted.url) {
        const urlInp = document.getElementById("jwt-target-url");
        if (urlInp) urlInp.value = extracted.url;
      }
      // 2. Populate Method
      if (extracted.method) {
        const methodSel = document.getElementById("jwt-target-method");
        if (methodSel) methodSel.value = extracted.method.toUpperCase();
      }
      // 3. Populate Headers
      const hdrsInp = document.getElementById("jwt-target-headers");
      if (hdrsInp && extracted.headers_text !== undefined) {
        hdrsInp.value = extracted.headers_text;
      }
      // 4. Populate Body
      const bodyInp = document.getElementById("jwt-target-body");
      if (bodyInp && extracted.body !== undefined) {
        bodyInp.value = extracted.body;
      }

      // 5. Populate Token field
      const tokenInp = document.getElementById("jwt-token-input");
      if (extracted.token) {
        if (tokenInp) tokenInp.value = extracted.token;
        if (summaryBar) {
          summaryBar.innerHTML = "⚡ <strong>cURL Auto-Imported!</strong> Endpoint, headers, and Bearer token populated.";
          summaryBar.style.color = "#3fb950";
        }
        jwtLogConsole(`[cURL IMPORT] Target: ${extracted.method} ${extracted.url} | Token extracted: ${extracted.token.slice(0, 16)}...`, "success");
        // Re-run decoding with clean extracted JWT
        return jwtOnTokenInput();
      } else {
        if (tokenInp) tokenInp.value = "";
        if (summaryBar) {
          summaryBar.innerHTML = "ℹ️ <strong>cURL Endpoint Loaded!</strong> Target URL &amp; headers configured, but no Bearer token was found in this cURL. Please paste your token above.";
          summaryBar.style.color = "#d29922";
        }
        if (headPre) headPre.textContent = "// Target URL & headers loaded from cURL.\n// No Bearer token found in cURL. Please paste JWT token above.";
        if (payPre) payPre.textContent = "// (paste JWT token above)";
        if (sigPre) sigPre.textContent = "// (none)";
        if (banner) banner.style.display = "none";
        if (auditContent) auditContent.innerHTML = '<span style="color:var(--text3);font-size:12px">cURL imported without token. Paste a token to run passive security audit.</span>';
        _jwtCurrentParsed = null;
        jwtUpdateCrackerAlgDisplay();
        return;
      }
    }
  }

  try {
    const res = await fetch(`${JWT_BASE}/jwt/decode`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: raw })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Invalid JWT format");

    _jwtCurrentParsed = data;
    jwtUpdateCrackerAlgDisplay();

    if (headPre) headPre.textContent = JSON.stringify(data.header, null, 2);
    if (payPre) payPre.textContent = JSON.stringify(data.payload, null, 2);
    if (sigPre) sigPre.textContent = data.sig_b64 || "(empty signature)";

    // Render security audit checklist
    if (data.audit) {
      jwtRenderSecurityAudit(data.audit);
    }

    // Update Expiry display
    if (banner && data.expiry) {
      banner.style.display = "flex";
      if (!data.expiry.has_exp) {
        banner.className = "jwt-exp-banner jwt-exp-active";
        banner.innerHTML = "<span>⏳ Expiration</span><span>No 'exp' claim (Permanent)</span>";
      } else if (data.expiry.expired) {
        banner.className = "jwt-exp-banner jwt-exp-expired";
        banner.innerHTML = `<span>⚠️ Token Expired</span><span>${data.expiry.exp_formatted || "Expired"}</span>`;
      } else {
        banner.className = "jwt-exp-banner jwt-exp-active";
        const mins = Math.round(data.expiry.remaining_seconds / 60);
        banner.innerHTML = `<span>✅ Active Session</span><span>Valid for ~${mins} mins (${data.expiry.exp_formatted})</span>`;
      }
    }
  } catch (err) {
    if (headPre) headPre.textContent = "Error: " + err.message;
    if (payPre) payPre.textContent = "";
    if (sigPre) sigPre.textContent = "";
    if (banner) banner.style.display = "none";
    if (auditContent) auditContent.innerHTML = `<span style="color:var(--text3);font-size:12px">Invalid token format (${jwtEsc(err.message)}). Paste a valid JWT token to run security audit.</span>`;
    _jwtCurrentParsed = null;
    jwtUpdateCrackerAlgDisplay();
  }
}

/**
 * Execute live scanning against target API endpoint with all selected attacks
 */
async function jwtRunLiveScan() {
  const token = (document.getElementById("jwt-token-input")?.value || "").trim();
  const url = (document.getElementById("jwt-target-url")?.value || "").trim();
  const method = (document.getElementById("jwt-target-method")?.value || "GET").trim();
  const hdrsRaw = (document.getElementById("jwt-target-headers")?.value || "").trim();
  const bodyRaw = (document.getElementById("jwt-target-body")?.value || "").trim();
  const pubKey = (document.getElementById("jwt-target-pubkey")?.value || "").trim();
  const successStr = (document.getElementById("jwt-target-success-str")?.value || "").trim();
  const timeoutVal = parseInt(document.getElementById("jwt-target-timeout")?.value, 10) || 20;

  if (!token) {
    alert("Please provide a JWT token in the 'Target & Token Setup' tab first.");
    jwtSwitchMainTab("setup");
    return;
  }

  // Gather selected attacks
  const selected = [];
  document.querySelectorAll(".jwt-atk-cb:checked").forEach(cb => selected.push(cb.value));

  // ── DUAL MODE: IF NO TARGET URL, RUN OFFLINE GENERATION SMOOTHLY (NO VALIDATION ALERT!) ──
  if (!url) {
    return jwtRunOfflineGeneration(token, pubKey, selected);
  }

  // Parse headers
  const headers = {};
  if (hdrsRaw) {
    hdrsRaw.split("\n").forEach(line => {
      const ci = line.indexOf(":");
      if (ci > 0) headers[line.slice(0, ci).trim()] = line.slice(ci + 1).trim();
    });
  }

  // Automatically switch to Scanner view
  jwtSwitchMainTab("scanner");

  const runBtn = document.getElementById("jwt-run-scan-btn");
  const summaryBar = document.getElementById("jwt-summary-bar");
  const consoleStatus = document.getElementById("jwt-console-status-text");

  if (runBtn) {
    runBtn.disabled = true;
    runBtn.innerHTML = "⏳ Scanning Vectors…";
  }
  if (summaryBar) {
    summaryBar.innerHTML = "⏳ Fuzzing target with tampered JWT attack vectors…";
    summaryBar.style.color = "var(--blue, #58a6ff)";
  }
  if (consoleStatus) consoleStatus.textContent = "Scanning...";

  jwtLogConsole("══════════════════════════════════════════════════════════════════", "dim");
  jwtLogConsole(`🚀 JWT ATTACK SCAN LAUNCHED against: ${url}`, "info");
  jwtLogConsole(`Method: ${method.toUpperCase()} | Timeout: ${timeoutVal}s | Vectors: ${selected.length ? selected.length : 20} Active | Headers: ${Object.keys(headers).length}`, "dim");
  if (successStr) jwtLogConsole(`False Positive Filter Active: Expected Success String = "${successStr}"`, "info");
  if (pubKey) jwtLogConsole(`Public Key Supplied: Testing RS256 -> HS256 Key Confusion with Server PEM`, "info");

  try {
    const res = await fetch(`${JWT_BASE}/jwt/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        method,
        token,
        headers,
        body: bodyRaw || null,
        timeout: timeoutVal,
        selected_attacks: selected.length ? selected : null,
        public_key: pubKey || null,
        expected_success_string: successStr || null
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Scan failed");

    _jwtScanResults = data.results || [];
    jwtRenderScanTable(_jwtScanResults);

    // Stream logs to console for each result
    _jwtScanResults.forEach((r, idx) => {
      const icon = r.verdict === "VULNERABLE" ? "🚨" : r.verdict === "BASELINE" ? "●" : r.verdict === "SECURE" ? "🛡️" : "⚠️";
      const logType = r.verdict === "VULNERABLE" ? "danger" : r.verdict === "SECURE" ? "success" : r.verdict === "BASELINE" ? "info" : "warn";
      
      jwtLogConsole(`${icon} [${r.verdict}] #${idx+1} ${r.name} (${r.tampered_aspect}) -> HTTP ${r.status_code || "ERR"} (${r.elapsed_seconds}s)`, logType);
      
      if (r.verdict === "VULNERABLE") {
        jwtLogConsole(`   ↳ ⚠️ VULNERABILITY ALERT: Server accepted tampered token with HTTP ${r.status_code}!`, "danger");
        jwtLogConsole(`   ↳ 💡 Gateway Caching Diagnostic: If this 200 response intermittently changes to 401 across runs, it indicates WSO2 API Gateway Redis Token Caching with TTL expiration. Use "Re-Check (Cache Buster)" to verify.`, "warn");
      } else if (r.verdict === "SECURE") {
        jwtLogConsole(`   ↳ Server rejected tampered vector (${r.reason || "Unauthorized"}).`, "dim");
      }
    });

    const badge = document.getElementById("jwt-badge-results");
    if (badge) {
      badge.style.display = "inline-block";
      badge.textContent = data.vulnerable_count > 0 ? `${data.vulnerable_count} Vuln` : `${data.total_tested} Done`;
      badge.style.color = data.vulnerable_count > 0 ? "#f85149" : "#3fb950";
    }

    if (summaryBar) {
      if (data.vulnerable_count > 0) {
        summaryBar.innerHTML = `🚨 <strong>${data.vulnerable_count} VULNERABILITIES FOUND!</strong> Server accepted tampered/unsigned JWTs! Check results below.`;
        summaryBar.style.color = "#f85149";
      } else {
        summaryBar.innerHTML = `🛡️ <strong>All ${data.total_tested} Attacks Blocked!</strong> Server securely validated and rejected all forged tokens.`;
        summaryBar.style.color = "#3fb950";
      }
    }

    jwtLogConsole(`══════════════════════════════════════════════════════════════════`, "dim");
    jwtLogConsole(`✅ SCAN COMPLETED: ${data.total_tested} vectors tested | ${data.vulnerable_count} vulnerabilities discovered.`, data.vulnerable_count > 0 ? "warn" : "success");
    if (consoleStatus) consoleStatus.textContent = "Idle (Completed)";

  } catch (err) {
    jwtLogConsole(`[-] SCAN ERROR: ${err.message}`, "danger");
    alert("Scan Error: " + err.message);
    if (summaryBar) {
      summaryBar.innerHTML = "❌ Error: " + err.message;
      summaryBar.style.color = "#f85149";
    }
    if (consoleStatus) consoleStatus.textContent = "Error";
  } finally {
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerHTML = "🚀 Run JWT Attacks";
    }
  }
}

const JWT_ATTACK_EXPLANATIONS = {
  baseline_original: {
    concept: "Original Active Token Benchmark",
    why: "Transmits the unmodified original session token to establish a baseline HTTP response benchmark (expected 200 OK).",
    impact: "Baseline Verification: Confirms target endpoint is live and the active user session is valid."
  },
  alg_none_lower: {
    concept: "alg: none (Lowercase with Trailing Dot)",
    why: "Sets header alg='none' and removes the signature ('header.payload.'). Tests RFC 7519 unsecured token acceptance.",
    impact: "Critical Authentication Bypass: Attacker can forge tokens for any user or admin without knowing any private/secret key."
  },
  alg_none_title: {
    concept: "alg: None (Titlecase Case-Sensitivity Bypass)",
    why: "Injects Titlecase alg='None' with signature stripped to bypass case-sensitive blacklist regex filters (e.g. if alg == 'none').",
    impact: "Authentication Bypass: Server fails to reject insecure tokens due to strict case matching."
  },
  alg_none_upper: {
    concept: "alg: NONE (Uppercase Filter Bypass)",
    why: "Changes header to uppercase alg='NONE' without signature to bypass uppercase-only blacklist filters.",
    impact: "Full Authentication & Signature Bypass."
  },
  alg_none_nodot: {
    concept: "alg: none (No Trailing Dot)",
    why: "Removes the trailing dot completely ('header.payload'), providing a 2-part token to bypass boundary length checks (parts.length == 3).",
    impact: "Signature verification bypass via token structure boundary confusion."
  },
  sig_stripped: {
    concept: "Signature Stripping (Alg Kept, Signature Removed)",
    why: "Preserves the original algorithm (e.g. RS256) but completely drops the signature ('header.payload.').",
    impact: "Authentication Bypass: Server validates algorithm type but fails to verify whether a cryptographic signature is actually present."
  },
  sig_tampered: {
    concept: "Signature Bit-Flipping / Mathematical Corruption",
    why: "Corrupts characters in the middle of the signature while keeping byte length intact, testing whether cryptographic signature verification is actually executed.",
    impact: "Signature Verification Test: If accepted, server blindly trusts claims without validating cryptographic signature math."
  },
  sig_appended: {
    concept: "Signature Trailing Chars Appended (+A)",
    why: "Appends extra trailing characters (+A) to the signature (increasing length from 256 to 257 bytes) to test byte-length and boundary validation.",
    impact: "Tests whether backend strictly validates signature length or leniently truncates/ignores trailing garbage."
  },
  empty_secret_hs256: {
    concept: "Empty HMAC Secret (HS256 with '')",
    why: "Changes algorithm to HS256 and signs using an empty string '' as secret key (common default when environment variables are missing).",
    impact: "Trivial Token Forgery: Attacker can sign valid tokens using an empty string."
  },
  common_secret_hs256: {
    concept: "Default Secret ('secret')",
    why: "Changes algorithm to HS256 and signs with common default dictionary secret 'secret' (widely used in templates and development).",
    impact: "Full Token Forgery: Attacker can sign arbitrary tokens using known default secret."
  },
  key_confusion_rs256_hs256: {
    concept: "Key Confusion Attack (RS256 → HS256 with Public Key)",
    why: "CVE-2016-5431: Changes algorithm from asymmetric RS256 to symmetric HS256 and signs using the server's public RSA key as the HMAC secret.",
    impact: "Critical Signature Bypass: Server verifies HMAC using its own public key, allowing arbitrary token generation."
  },
  jwk_embedded_key: {
    concept: "JWK Header Injection (Embedded Key)",
    why: "Embeds an attacker-controlled symmetric key inside header 'jwk' parameter and signs with it, testing if the server trusts the embedded key instead of its own keystore.",
    impact: "Arbitrary Signature Bypass or Gateway Parser Crash (HTTP 500 Unhandled Exception)."
  },
  jku_remote_spoof: {
    concept: "JKU Header Spoofing (Remote Attacker URL)",
    why: "Injects a remote 'jku' parameter pointing to an external attacker JWKS URL (https://api-sentinel.local/...).",
    impact: "Server-Side Request Forgery (SSRF) and arbitrary signature verification bypass."
  },
  role_escalation_none: {
    concept: "Privilege Escalation (Role & Scope Tampering)",
    why: "Injects elevated permissions (role: 'admin', isAdmin: true, scope: 'admin all') with alg:none.",
    impact: "Vertical Privilege Escalation: Unprivileged user gains full administrator rights."
  },
  exp_removed_none: {
    concept: "Expiry Bypass (exp Claim Removed)",
    why: "Removes the 'exp' expiration timestamp claim completely from the payload.",
    impact: "Immortal Session Tokens: Tokens never expire, bypassing session lifetime security policies."
  },
  exp_future_none: {
    concept: "Expiry Bypass (Set to Year 2038+)",
    why: "Extends the 'exp' timestamp 10+ years into the future.",
    impact: "Session Lifetime Policy Bypass: Extends token validity indefinitely."
  },
  kid_path_traversal: {
    concept: "Key ID (kid) Path Traversal (/dev/null)",
    why: "Injects directory traversal in 'kid' parameter pointing to /dev/null signed with an empty secret key ''.",
    impact: "Arbitrary File Key Lookup: Forces backend to read an empty file as the secret key."
  },
  kid_path_win: {
    concept: "Key ID (kid) Windows Traversal (win.ini)",
    why: "Injects Windows path traversal '..\\windows\\win.ini' signed with an empty secret.",
    impact: "Arbitrary File Key Lookup on Windows hosts."
  },
  kid_null_byte: {
    concept: "Key ID (kid) Null-Byte Truncation (%00)",
    why: "Injects null byte %00 truncation in kid ('/dev/null%00.key') to bypass file extension whitelisting.",
    impact: "Path traversal filter bypass via null-byte truncation."
  },
  kid_sqli: {
    concept: "Key ID (kid) SQL Injection (UNION SELECT)",
    why: "Injects 'key1' UNION SELECT 'secret'--' in kid to force database-backed key stores to return 'secret'.",
    impact: "Database Key Lookup Bypass: Allows attacker to sign tokens with predictable key."
  },
  kid_sqli_or: {
    concept: "Key ID (kid) SQL Injection (' OR '1'='1)",
    why: "Injects SQL tautology in kid parameter to retrieve the first available key in the database.",
    impact: "Database Key Enumeration and Authentication Bypass."
  },
  kid_cmd_injection: {
    concept: "Key ID (kid) Command Injection",
    why: "Injects shell command sequence '; echo secret |' in kid to test for dynamic shell evaluation.",
    impact: "Remote Code Execution (RCE) / Arbitrary Command Execution on server."
  },
  exp_past_none: {
    concept: "Expiry Bypass (Expired -1 Year)",
    why: "Sets 'exp' timestamp to 1 year in the past to test if the server actually verifies expiration times.",
    impact: "Broken Authentication: Expired sessions and revoked tokens can be replayed indefinitely."
  },
  nbf_future_none: {
    concept: "Premature Token (nbf: +1 Day Future)",
    why: "Sets 'nbf' (Not Before) claim 1 day into the future to verify if the server rejects tokens before activation.",
    impact: "Premature Session Access: Tokens used before their authorized start window are improperly honored."
  },
  epoch_overflow: {
    concept: "Epoch Overflow (exp: 9999999999)",
    why: "Sets 'exp' to 9999999999 (Year 2286) to test 32-bit / 64-bit integer overflow handling in timestamp parsers.",
    impact: "Denial of Service (DoS) or integer wrap-around vulnerability allowing token reuse."
  },
  kid_cmd_pipe: {
    concept: "kid Pipe Command Injection (| cat /etc/passwd)",
    why: "Injects pipe shell command in kid parameter ('key1 | cat /etc/passwd') to verify if backend executes shell commands for key lookup.",
    impact: "Remote Code Execution (RCE) / Arbitrary Command Execution on server."
  },
  x5u_remote_spoof: {
    concept: "x5u Certificate Spoofing (Remote URL)",
    why: "Injects untrusted remote X.509 certificate URL in header['x5u'] pointing to attacker certificate.",
    impact: "Server-Side Request Forgery (SSRF) and complete cryptographic authentication bypass."
  }
};

function jwtB64UrlDecode(str) {
  if (!str) return "";
  try {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    const decoded = atob(base64);
    try {
      return decodeURIComponent(decoded.split("").map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join(""));
    } catch (_) {
      return decoded;
    }
  } catch (e) {
    return "";
  }
}

function jwtCleanJsonString(str) {
  if (!str) return "{}";
  return String(str)
    .replace(/[\u201C\u201D\u201E\u201F\u2033\u2036]/g, '"')
    .replace(/[\u2018\u2019\u201A\u201B\u2032\u2035]/g, "'");
}

function jwtNormalizeSmartQuotesInTextarea(ta) {
  if (!ta) return;
  const val = ta.value;
  if (/[\u201C\u201D\u201E\u201F\u2033\u2036\u2018\u2019\u201A\u201B\u2032\u2035]/.test(val)) {
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    ta.value = jwtCleanJsonString(val);
    try { ta.setSelectionRange(start, end); } catch (_) {}
  }
}

function jwtSafeJsonParse(str) {
  if (!str) return null;
  try {
    return JSON.parse(jwtCleanJsonString(str));
  } catch (_) {
    return null;
  }
}

function jwtFormatHighlightedCurl(curlCmd, attackToken) {
  if (!curlCmd || !attackToken) return jwtEsc(curlCmd || "");
  const parts = attackToken.split(".");
  const h = parts[0] || "";
  const p = parts[1] || "";
  const s = parts[2] || "";

  const highlightedToken = `<span class="jwt-part-header" style="color:var(--jwt-hdr-color,#ffa198)">${jwtEsc(h)}</span>.<span class="jwt-part-payload" style="color:var(--jwt-pay-color,#e2c5ff)">${jwtEsc(p)}</span>.<span class="jwt-part-sig" style="color:var(--jwt-sig-color,#a5d6ff)">${jwtEsc(s)}</span>`;
  const escapedCmd = jwtEsc(curlCmd);
  const tokenEsc = jwtEsc(attackToken);
  if (escapedCmd.includes(tokenEsc)) {
    return escapedCmd.replace(tokenEsc, highlightedToken);
  }
  return escapedCmd;
}

function jwtRenderAttackDiff(r) {
  const diffBox = document.getElementById("jwt-poc-diff");
  if (!diffBox) return;

  const expl = JWT_ATTACK_EXPLANATIONS[r.attack_id] || {
    concept: r.name,
    why: r.description || "Tests backend JWT validation resilience.",
    impact: "Security bypass."
  };

  // Original Token info
  const origHeader = (_jwtCurrentParsed && _jwtCurrentParsed.header) || {};
  const origPayload = (_jwtCurrentParsed && _jwtCurrentParsed.payload) || {};
  const origSig = (_jwtCurrentParsed && _jwtCurrentParsed.sig_b64) || "";

  // Tampered Token info
  const parts = (r.attack_token || "").split(".");
  const tampHeaderStr = jwtB64UrlDecode(parts[0]);
  const tampPayloadStr = jwtB64UrlDecode(parts[1]);
  const tampHeader = jwtSafeJsonParse(tampHeaderStr) || {};
  const tampPayload = jwtSafeJsonParse(tampPayloadStr) || {};
  const tampSig = parts[2] || "";

  // 1. Analyze Header Differences
  let headerChanged = false;
  let headerDiffHtml = "";
  if (JSON.stringify(origHeader) !== JSON.stringify(tampHeader)) {
    headerChanged = true;
    const origKeys = Object.keys(origHeader);
    const tampKeys = Object.keys(tampHeader);
    const diffs = [];
    tampKeys.forEach(k => {
      if (origHeader[k] === undefined) {
        diffs.push(`<span class="jwt-highlight-tamper">+ "${jwtEsc(k)}": ${jwtEsc(JSON.stringify(tampHeader[k]))}</span>`);
      } else if (JSON.stringify(origHeader[k]) !== JSON.stringify(tampHeader[k])) {
        diffs.push(`"${jwtEsc(k)}": <span style="text-decoration:line-through;opacity:0.6">${jwtEsc(JSON.stringify(origHeader[k]))}</span> ➔ <span class="jwt-highlight-tamper">${jwtEsc(JSON.stringify(tampHeader[k]))}</span>`);
      }
    });
    origKeys.forEach(k => {
      if (tampHeader[k] === undefined) {
        diffs.push(`<span style="color:#f85149;text-decoration:line-through">- "${jwtEsc(k)}": ${jwtEsc(JSON.stringify(origHeader[k]))}</span>`);
      }
    });
    headerDiffHtml = diffs.join(", ") || jwtEsc(JSON.stringify(tampHeader));
  }

  // 2. Analyze Payload Differences
  let payloadChanged = false;
  let payloadDiffHtml = "";
  if (JSON.stringify(origPayload) !== JSON.stringify(tampPayload)) {
    payloadChanged = true;
    const origKeys = Object.keys(origPayload);
    const tampKeys = Object.keys(tampPayload);
    const diffs = [];
    tampKeys.forEach(k => {
      if (origPayload[k] === undefined) {
        diffs.push(`<span class="jwt-highlight-tamper">+ "${jwtEsc(k)}": ${jwtEsc(JSON.stringify(tampPayload[k]))}</span>`);
      } else if (JSON.stringify(origPayload[k]) !== JSON.stringify(tampPayload[k])) {
        diffs.push(`"${jwtEsc(k)}": <span style="text-decoration:line-through;opacity:0.6">${jwtEsc(JSON.stringify(origPayload[k]))}</span> ➔ <span class="jwt-highlight-tamper">${jwtEsc(JSON.stringify(tampPayload[k]))}</span>`);
      }
    });
    origKeys.forEach(k => {
      if (tampPayload[k] === undefined) {
        diffs.push(`<span style="color:#f85149;text-decoration:line-through">- "${jwtEsc(k)}" (Removed)</span>`);
      }
    });
    payloadDiffHtml = diffs.join(", ") || jwtEsc(JSON.stringify(tampPayload));
  }

  // 3. Analyze Signature Differences
  let sigStatusTag = "safe";
  let sigStatusText = "UNCHANGED";
  let sigOrigText = origSig ? `${origSig.slice(0, 10)}...${origSig.slice(-6)} (Valid Signature)` : "(none)";
  let sigTampText = "<span style=\"color:#8b949e\">(unchanged)</span>";

  if (!tampSig) {
    sigStatusTag = "changed";
    sigStatusText = "STRIPPED";
    sigTampText = `<span style="color:#ffa198;font-weight:700">❌ (Empty / Signature completely removed)</span>`;
  } else if (r.attack_id === "sig_tampered") {
    sigStatusTag = "changed";
    sigStatusText = "BIT-FLIPPED";
    sigTampText = `<span class="jwt-highlight-tamper">⚠️ Corrupted in Middle (${jwtEsc(tampSig.slice(0, 8))}...<strong style="color:#ff7b72">${jwtEsc(tampSig.slice(Math.floor(tampSig.length/2)-2, Math.floor(tampSig.length/2)+3))}</strong>...${jwtEsc(tampSig.slice(-6))})</span>`;
  } else if (r.attack_id === "sig_appended") {
    sigStatusTag = "changed";
    sigStatusText = "CHARS APPENDED";
    sigTampText = `<span class="jwt-highlight-tamper">⚠️ Trailing '+A' Added (...${jwtEsc(origSig.slice(-6))} ➔ ...${jwtEsc(tampSig.slice(-7))})</span>`;
  } else if (tampSig !== origSig) {
    sigStatusTag = "injected";
    sigStatusText = "FORGED / RE-SIGNED";
    sigTampText = `<span class="jwt-highlight-tamper">🔑 Re-signed: ${jwtEsc(r.tampered_aspect || tampSig.slice(0, 16) + '...')}</span>`;
  }

  diffBox.innerHTML = `
    <!-- Top Concept Card -->
    <div class="jwt-diff-concept-card">
      <div class="jwt-diff-concept-title">
        <span>💡 Attack Concept: ${jwtEsc(expl.concept)}</span>
        <span class="jwt-badge" style="background:rgba(88,166,255,0.15);color:#58a6ff;border:1px solid rgba(88,166,255,0.3);">${jwtEsc(r.category)}</span>
      </div>
      <div class="jwt-diff-explanation-text">
        <strong>Mechanism Tested:</strong> ${jwtEsc(expl.why)}
      </div>
      <div style="font-size:10px;color:var(--text3);margin-top:2px;">
        <strong>Security Risk:</strong> ${jwtEsc(expl.impact)}
      </div>
    </div>

    <!-- Side-by-Side Old vs New Comparison Grid -->
    <div class="jwt-diff-grid">
      <!-- Header -->
      <div class="jwt-diff-item">
        <div class="jwt-diff-label">
          <span>1. Header Mutation</span>
          <span class="jwt-diff-tag ${headerChanged ? 'changed' : 'safe'}">${headerChanged ? 'TAMPERED / INJECTED' : 'UNCHANGED'}</span>
        </div>
        <div class="jwt-diff-compare">
          <div class="jwt-diff-before" title="Original Header"><span class="jwt-diff-tag-sub">Original Header:</span><code class="jwt-diff-code">${jwtEsc(JSON.stringify(origHeader))}</code></div>
          <div class="jwt-diff-arrow">➔</div>
          <div class="jwt-diff-after" title="Injected/Tampered Header"><span class="jwt-diff-tag-sub">Injected Header:</span><code class="jwt-diff-code">${headerChanged ? headerDiffHtml : '<span style="color:#8b949e">(Unchanged)</span>'}</code></div>
        </div>
      </div>

      <!-- Payload -->
      <div class="jwt-diff-item">
        <div class="jwt-diff-label">
          <span>2. Payload Claims Mutation</span>
          <span class="jwt-diff-tag ${payloadChanged ? 'changed' : 'safe'}">${payloadChanged ? 'CLAIMS MODIFIED' : 'UNCHANGED'}</span>
        </div>
        <div class="jwt-diff-compare">
          <div class="jwt-diff-before" title="Original Claims"><span class="jwt-diff-tag-sub">Original Claims:</span><code class="jwt-diff-code">${jwtEsc(JSON.stringify(origPayload))}</code></div>
          <div class="jwt-diff-arrow">➔</div>
          <div class="jwt-diff-after" title="Injected/Tampered Claims"><span class="jwt-diff-tag-sub">Injected Claims:</span><code class="jwt-diff-code">${payloadChanged ? payloadDiffHtml : '<span style="color:#8b949e">(Unchanged - identical to original claims)</span>'}</code></div>
        </div>
      </div>

      <!-- Signature -->
      <div class="jwt-diff-item">
        <div class="jwt-diff-label">
          <span>3. Cryptographic Signature Treatment</span>
          <span class="jwt-diff-tag ${sigStatusTag}">${sigStatusText}</span>
        </div>
        <div class="jwt-diff-compare">
          <div class="jwt-diff-before" title="Original Signature"><span class="jwt-diff-tag-sub">Original Signature:</span><code class="jwt-diff-code">${jwtEsc(sigOrigText)}</code></div>
          <div class="jwt-diff-arrow">➔</div>
          <div class="jwt-diff-after" title="Injected/Tampered Signature"><span class="jwt-diff-tag-sub">Tampered Signature:</span><code class="jwt-diff-code">${sigTampText}</code></div>
        </div>
      </div>
    </div>
  `;
}

function jwtClearPocDetails() {
  const pocPre = document.getElementById("jwt-poc-curl");
  const pyPre = document.getElementById("jwt-poc-python");
  const diffBox = document.getElementById("jwt-poc-diff");
  const respPre = document.getElementById("jwt-poc-resp");
  const notesEl = document.getElementById("jwt-poc-notes");
  const flappingBadge = document.getElementById("jwt-flapping-badge");
  const cacheHint = document.getElementById("jwt-poc-cache-hint");

  const decHeaderPre = document.getElementById("jwt-dec-header-pre");
  const decPayloadPre = document.getElementById("jwt-dec-payload-pre");
  const decSigPre = document.getElementById("jwt-dec-sig-pre");
  const decAlgBadge = document.getElementById("jwt-dec-alg-badge");
  const decClaimsCount = document.getElementById("jwt-dec-claims-count");
  const decSigBadge = document.getElementById("jwt-dec-sig-badge");

  if (flappingBadge) flappingBadge.style.display = "none";
  if (cacheHint) cacheHint.textContent = "";

  if (notesEl) notesEl.textContent = "Attack Details & PoC";
  if (diffBox) diffBox.innerHTML = '<div style="color:var(--text3);padding:20px;text-align:center;">Select any attack vector row from the table above to view what was changed, the attack concept, and the security risk.</div>';
  if (pocPre) pocPre.textContent = "(select an attack row above)";
  if (pyPre) pyPre.textContent = "(select an attack row above)";
  if (respPre) respPre.textContent = "(response snippet)";

  if (decHeaderPre) decHeaderPre.textContent = "(select an attack row above)";
  if (decPayloadPre) decPayloadPre.textContent = "(select an attack row above)";
  if (decSigPre) decSigPre.textContent = "(select an attack row above)";
  if (decAlgBadge) decAlgBadge.textContent = "alg: --";
  if (decClaimsCount) decClaimsCount.textContent = "0 claims";
  if (decSigBadge) {
    decSigBadge.textContent = "Signature";
    decSigBadge.style.color = "#a5d6ff";
    decSigBadge.style.background = "rgba(165,214,255,0.15)";
  }

  const posPill = document.getElementById("jwt-nav-pos-pill");
  const prevBtn = document.getElementById("jwt-nav-prev-btn");
  const nextBtn = document.getElementById("jwt-nav-next-btn");
  if (posPill) posPill.textContent = "—";
  if (prevBtn) prevBtn.disabled = true;
  if (nextBtn) nextBtn.disabled = true;
}

/**
 * Render Results Table
 */
function jwtRenderScanTable(results) {
  const tbody = document.getElementById("jwt-results-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (!results.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text2);padding:24px;">No attack results yet. Configure target and run attack scan.</td></tr>`;
    jwtClearPocDetails();
    return;
  }

  results.forEach((r, idx) => {
    const tr = document.createElement("tr");
    tr.id = `jwt-row-${idx}`;
    tr.onclick = () => jwtSelectResult(idx);

    let badgeClass = "jwt-badge-secure";
    let badgeText = "SECURE";
    if (r.verdict === "VULNERABLE") {
      badgeClass = "jwt-badge-vuln";
      badgeText = "🚨 VULNERABLE";
    } else if (r.verdict === "BASELINE") {
      badgeClass = "jwt-badge-baseline";
      badgeText = "BASELINE";
    } else if (r.verdict === "GENERATED" || r.verdict === "OFFLINE") {
      badgeClass = "jwt-badge-baseline";
      badgeText = "GENERATED";
    } else if (r.verdict === "SOFT_FAIL" || r.verdict === "FALSE_POSITIVE") {
      badgeClass = "jwt-badge-warn";
      badgeText = "SOFT FAIL";
    } else if (r.verdict === "SUSPICIOUS") {
      badgeClass = "jwt-badge-suspicious";
      badgeText = "SUSPICIOUS";
    } else if (r.verdict === "ERROR") {
      badgeClass = "jwt-badge-suspicious";
      badgeText = (r.reason === "Timed Out" || (r.notes && r.notes.includes("TIMED OUT"))) ? "TIMEOUT" : "ERROR";
    }

    const isOffline = (r.verdict === "GENERATED" || r.verdict === "OFFLINE");
    const isTimeout = (r.reason === "Timed Out" || (r.notes && r.notes.includes("TIMED OUT")));
    let statusText = isOffline ? "OFFLINE" : (r.status_code || (isTimeout ? "TIMEOUT" : "ERR"));
    const statusColor = isOffline ? "#8b949e" : (r.status_code >= 200 && r.status_code < 400) ? "#3fb950" : (r.status_code >= 400 && r.status_code < 500) ? "#d29922" : "#f85149";
    const elapsedText = isOffline ? "—" : `${r.elapsed_seconds || 0}s`;

    const expl = JWT_ATTACK_EXPLANATIONS[r.attack_id] || { concept: r.name, why: r.description || "" };
    const tooltipText = jwtEsc(`${expl.concept}\n\nConcept: ${expl.why}\nRisk: ${expl.impact || ''}`);

    tr.innerHTML = `
      <td style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:11px;font-weight:600;">${idx + 1}</td>
      <td style="font-weight:700;">
        ${jwtEsc(r.name)}
        <span class="jwt-info-icon" title="${tooltipText}">ℹ️</span>
      </td>
      <td><span style="font-size:11px;color:var(--text2);">${jwtEsc(r.category)}</span></td>
      <td><code style="font-size:11px;color:var(--blue,#58a6ff);">${jwtEsc(r.tampered_aspect)}</code></td>
      <td><span style="font-family:var(--mono);font-weight:700;color:${statusColor};font-size:11px;">${jwtEsc(String(statusText))}</span></td>
      <td><span class="${badgeClass}">${badgeText}</span></td>
      <td style="font-size:11px;color:var(--text2);">${elapsedText}</td>
    `;
    tbody.appendChild(tr);
  });

  // Auto-select first vulnerable or first row
  const firstVuln = results.findIndex(r => r.vulnerable);
  jwtSelectResult(firstVuln >= 0 ? firstVuln : 0);
}

function jwtSelectResult(idx) {
  _jwtSelectedResultIdx = idx;
  document.querySelectorAll("#jwt-results-tbody tr").forEach(tr => tr.classList.remove("selected"));
  const row = document.getElementById(`jwt-row-${idx}`);
  if (row) row.classList.add("selected");

  const r = _jwtScanResults[idx];
  if (!r) return;

  const pocPre = document.getElementById("jwt-poc-curl");
  const pyPre = document.getElementById("jwt-poc-python");
  const respPre = document.getElementById("jwt-poc-resp");
  const notesEl = document.getElementById("jwt-poc-notes");
  const flappingBadge = document.getElementById("jwt-flapping-badge");
  const cacheHint = document.getElementById("jwt-poc-cache-hint");

  const decHeaderPre = document.getElementById("jwt-dec-header-pre");
  const decPayloadPre = document.getElementById("jwt-dec-payload-pre");
  const decSigPre = document.getElementById("jwt-dec-sig-pre");
  const decAlgBadge = document.getElementById("jwt-dec-alg-badge");
  const decClaimsCount = document.getElementById("jwt-dec-claims-count");
  const decSigBadge = document.getElementById("jwt-dec-sig-badge");

  if (flappingBadge) flappingBadge.style.display = "none";
  if (cacheHint) cacheHint.textContent = "";

  // 1. Render Educational Attack Diff & Concept
  jwtRenderAttackDiff(r);

  // 2. Render Decoded Attack Token in JWT Decoder Tab
  if (r.attack_token) {
    const parts = (r.attack_token || "").split(".");
    const hStr = jwtB64UrlDecode(parts[0]);
    const pStr = jwtB64UrlDecode(parts[1]);
    const hObj = jwtSafeJsonParse(hStr);
    const pObj = jwtSafeJsonParse(pStr);
    const sigPart = parts[2] || "";

    if (decHeaderPre) {
      decHeaderPre.textContent = hObj ? JSON.stringify(hObj, null, 2) : (hStr || "(raw: " + (parts[0] || "") + ")");
    }
    if (decPayloadPre) {
      decPayloadPre.textContent = pObj ? JSON.stringify(pObj, null, 2) : (pStr || "(raw: " + (parts[1] || "") + ")");
    }
    if (decSigPre) {
      decSigPre.textContent = sigPart ? sigPart : "(No Signature - Stripped/Empty)";
    }
    if (decAlgBadge) {
      const alg = (hObj && hObj.alg !== undefined) ? hObj.alg : "none";
      decAlgBadge.textContent = `alg: ${alg}`;
    }
    if (decClaimsCount) {
      const cnt = pObj ? Object.keys(pObj).length : 0;
      decClaimsCount.textContent = `${cnt} claim${cnt === 1 ? '' : 's'}`;
    }
    if (decSigBadge) {
      if (!sigPart) {
        decSigBadge.textContent = "Stripped / None";
        decSigBadge.style.color = "var(--jwt-hdr-color, #ffa198)";
        decSigBadge.style.background = "var(--jwt-badge-hdr-bg, rgba(255,161,152,0.15))";
      } else {
        decSigBadge.textContent = `${sigPart.length} chars`;
        decSigBadge.style.color = "var(--jwt-sig-color, #a5d6ff)";
        decSigBadge.style.background = "var(--jwt-badge-sig-bg, rgba(165,214,255,0.15))";
      }
    }
  } else {
    if (decHeaderPre) decHeaderPre.textContent = "(no token)";
    if (decPayloadPre) decPayloadPre.textContent = "(no token)";
    if (decSigPre) decSigPre.textContent = "(no signature)";
    if (decAlgBadge) decAlgBadge.textContent = "alg: --";
    if (decClaimsCount) decClaimsCount.textContent = "0 claims";
  }

  // 3. Render Highlighted cURL
  if (pocPre) {
    pocPre.innerHTML = jwtFormatHighlightedCurl(r.curl_poc, r.attack_token);
  }

  // 4. Render Python PoC
  if (pyPre) pyPre.textContent = r.python_poc || "(none)";

  // 5. Render Response Preview
  if (respPre) {
    if (r.status_code === 0) {
      if (r.reason === "Timed Out" || (r.notes && r.notes.includes("TIMED OUT"))) {
        const timeoutLimit = document.getElementById("jwt-target-timeout")?.value || 20;
        respPre.textContent = `⏱️ Request Timed Out!\n\nTarget server did not respond within ${r.elapsed_seconds || timeoutLimit}s (Timeout limit was set to ${timeoutLimit}s).\n\nTip: If your target API is slow, you can increase the 'Timeout (sec)' in Tab 1 (Target & Token Setup -> Advanced) and run again.`;
      } else {
        respPre.textContent = `⚠️ Network Error / Connection Failed:\n\n${r.notes || r.reason || "Connection failed"}`;
      }
    } else {
      respPre.textContent = r.response_snippet || `HTTP ${r.status_code} (${r.reason})`;
    }
  }

  // 6. Notes Header
  if (notesEl) notesEl.textContent = `${r.name}: ${r.notes}`;

  // 7. Update Row Navigation Controls
  const posPill = document.getElementById("jwt-nav-pos-pill");
  const prevBtn = document.getElementById("jwt-nav-prev-btn");
  const nextBtn = document.getElementById("jwt-nav-next-btn");
  if (posPill) posPill.textContent = `${idx + 1} / ${_jwtScanResults.length}`;
  if (prevBtn) prevBtn.disabled = (idx <= 0);
  if (nextBtn) nextBtn.disabled = (idx >= _jwtScanResults.length - 1);
}

/**
 * Navigate to Next / Previous Attack Row (via Buttons or Arrow Keys)
 */
function jwtNavigateResult(direction) {
  if (!_jwtScanResults || !_jwtScanResults.length) return;
  let cur = (_jwtSelectedResultIdx === null || _jwtSelectedResultIdx === undefined) ? 0 : _jwtSelectedResultIdx;
  let targetIdx = cur + direction;
  if (targetIdx < 0) targetIdx = 0;
  if (targetIdx >= _jwtScanResults.length) targetIdx = _jwtScanResults.length - 1;
  jwtSelectResult(targetIdx);
  const row = document.getElementById(`jwt-row-${targetIdx}`);
  if (row) {
    row.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

async function jwtRecheckCurrentVector(btn) {
  if (_jwtSelectedResultIdx === null || !_jwtScanResults[_jwtSelectedResultIdx]) {
    alert("Please select a result row from the table first.");
    return;
  }
  const r = _jwtScanResults[_jwtSelectedResultIdx];
  const url = (document.getElementById("jwt-target-url")?.value || "").trim();
  if (!url) {
    alert("Target API URL is required to probe this vector live against a server.\nPlease enter the target URL in Tab 1 (Target & Token Setup).");
    jwtSwitchMainTab("setup");
    return;
  }
  const method = (document.getElementById("jwt-target-method")?.value || "GET").trim();
  const hdrsRaw = (document.getElementById("jwt-target-headers")?.value || "").trim();
  const bodyRaw = (document.getElementById("jwt-target-body")?.value || "").trim();
  const successStr = (document.getElementById("jwt-target-success-str")?.value || "").trim();
  const timeoutVal = parseInt(document.getElementById("jwt-target-timeout")?.value, 10) || 20;

  const headers = {};
  if (hdrsRaw) {
    hdrsRaw.split("\n").forEach(line => {
      const ci = line.indexOf(":");
      if (ci > 0) headers[line.slice(0, ci).trim()] = line.slice(ci + 1).trim();
    });
  }

  const originalHtml = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = "⏳ Probing…";
  }

  jwtLogConsole(`[RE-CHECK] Re-probing vector: ${r.name}...`, "info");

  try {
    const res = await fetch(`${JWT_BASE}/jwt/probe-single`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        method,
        attack_token: r.attack_token,
        headers,
        body: bodyRaw || null,
        timeout: timeoutVal,
        expected_success_string: successStr || null
      })
    });

    const probe = await res.json();
    if (!res.ok) throw new Error(probe.detail || "Probe failed");

    const prevStatus = r.status_code;
    const newStatus = probe.status_code;
    const flappingBadge = document.getElementById("jwt-flapping-badge");
    const cacheHint = document.getElementById("jwt-poc-cache-hint");

    jwtLogConsole(`[RE-CHECK RESULT] Initial HTTP: ${prevStatus} | Current HTTP: ${newStatus} (${probe.reason}) in ${probe.elapsed_seconds}s`, newStatus === prevStatus ? "info" : "warn");

    if (prevStatus !== newStatus) {
      if (flappingBadge) {
        flappingBadge.style.display = "inline-block";
        flappingBadge.textContent = `⚠️ Gateway Flapping! (${prevStatus} vs ${newStatus})`;
      }
      if (cacheHint) {
        cacheHint.textContent = `⚠️ Gateway cache inconsistency: Initial HTTP ${prevStatus}, Current HTTP ${newStatus}.`;
        cacheHint.style.color = "#d29922";
      }
      jwtLogConsole(`🚨 [FLAPPING DETECTED] Server response changed from HTTP ${prevStatus} to HTTP ${newStatus}!`, "danger");
      jwtLogConsole(`   ↳ Reason: WSO2 Gateway Token Caching. A valid token context was previously cached (giving 200), and on cache TTL expiry or load-balancer node rotation, full signature validation failed (giving ${newStatus}).`, "warn");
    } else {
      if (flappingBadge) flappingBadge.style.display = "none";
      if (cacheHint) {
        cacheHint.textContent = `Consistent response: HTTP ${newStatus}`;
        cacheHint.style.color = "#3fb950";
      }
      jwtLogConsole(`✅ [CONSISTENT] Server returned identical HTTP ${newStatus} on re-check.`, "success");
    }

    // Update response preview
    const respPre = document.getElementById("jwt-poc-resp");
    if (respPre && probe.response_snippet) {
      respPre.textContent = probe.response_snippet;
    }

    if (btn) {
      btn.innerHTML = prevStatus !== newStatus ? `⚠️ Flapped (${newStatus})` : `✅ Consistent (${newStatus})`;
      setTimeout(() => { if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; } }, 2500);
    }
  } catch (err) {
    jwtLogConsole(`[-] Re-check error: ${err.message}`, "danger");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

let _jwtPocCurrentMode = "diff";

function jwtSwitchPocCodeTab(mode) {
  _jwtPocCurrentMode = mode;
  const tabDiff = document.getElementById("jwt-poc-tab-diff");
  const tabDecoder = document.getElementById("jwt-poc-tab-decoder");
  const tabCurl = document.getElementById("jwt-poc-tab-curl");
  const tabPy = document.getElementById("jwt-poc-tab-python");

  const paneDiff = document.getElementById("jwt-poc-diff");
  const wrapDecoder = document.getElementById("jwt-poc-decoder-wrap");
  const wrapCurl = document.getElementById("jwt-poc-curl-wrap");
  const wrapPy = document.getElementById("jwt-poc-python-wrap");

  if (tabDiff) tabDiff.classList.toggle("active", mode === "diff");
  if (tabDecoder) tabDecoder.classList.toggle("active", mode === "decoder");
  if (tabCurl) tabCurl.classList.toggle("active", mode === "curl");
  if (tabPy) tabPy.classList.toggle("active", mode === "python");

  if (paneDiff) paneDiff.style.display = mode === "diff" ? "flex" : "none";
  if (wrapDecoder) wrapDecoder.style.display = mode === "decoder" ? "flex" : "none";
  if (wrapCurl) wrapCurl.style.display = mode === "curl" ? "flex" : "none";
  if (wrapPy) wrapPy.style.display = mode === "python" ? "flex" : "none";
}

function jwtCopyCurrentAttackToken(btn) {
  if (_jwtSelectedResultIdx === null || !_jwtScanResults[_jwtSelectedResultIdx]) {
    alert("Please select an attack vector row from the table first.");
    return;
  }
  const tok = _jwtScanResults[_jwtSelectedResultIdx].attack_token || "";
  if (!tok) {
    alert("No attack token available for this row.");
    return;
  }
  jwtCopyToClipboard(tok, btn, "Token Copied!");
}

function jwtCopyToClipboard(text, btn, successLabel = "Copied!") {
  if (!text) return;
  const originalHtml = btn ? btn.innerHTML : "";
  const setCopied = () => {
    if (btn) {
      btn.innerHTML = `✅ ${successLabel}`;
      setTimeout(() => { btn.innerHTML = originalHtml; }, 1600);
    }
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(setCopied).catch(() => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        setCopied();
      } catch (_) {}
    });
  } else {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied();
    } catch (_) {}
  }
}

function jwtCopySelectedCurl(btn) {
  const r = _jwtScanResults[_jwtSelectedResultIdx];
  if (!r || !r.curl_poc) return;
  jwtCopyToClipboard(r.curl_poc, btn, "cURL Copied!");
}

function jwtCopySelectedPython(btn) {
  const r = _jwtScanResults[_jwtSelectedResultIdx];
  if (!r || !r.python_poc) return;
  jwtCopyToClipboard(r.python_poc, btn, "Python Copied!");
}

function jwtCopyAttackToken(btn) {
  const r = _jwtScanResults[_jwtSelectedResultIdx];
  if (!r || !r.attack_token) return;
  jwtCopyToClipboard(r.attack_token, btn, "Token Copied!");
}

/**
 * Offline HMAC Secret Cracker
 */
async function jwtRunSecretCrack() {
  const token = (document.getElementById("jwt-token-input")?.value || "").trim();
  const alertEl = document.getElementById("jwt-crack-alert");
  const btn = document.getElementById("jwt-crack-btn");

  if (!token) {
    alert("Please provide a JWT token in the left panel first.");
    return;
  }

  // Pre-check algorithm to give instant and friendly explanation if RS256/asymmetric
  const alg = (_jwtCurrentParsed?.header?.alg || "").toUpperCase();
  if (alg && !alg.startsWith("HS")) {
    if (alertEl) {
      alertEl.style.display = "block";
      alertEl.style.background = "rgba(210, 153, 34, 0.15)";
      alertEl.style.color = "#d29922";
      alertEl.innerHTML = `⚠️ <strong>Algorithm Mismatch (${jwtEsc(alg)}):</strong><br>` +
        `Current token uses <strong>${jwtEsc(alg)}</strong> (Asymmetric RSA Public/Private Key).<br>` +
        `<span style="font-size:11.5px;color:var(--text2);display:inline-block;margin-top:6px;line-height:1.4">HMAC Secret Cracker is designed for symmetric algorithms (<strong>HS256, HS384, HS512</strong>) which use a shared secret password.<br>` +
        `RS256 tokens are signed with an RSA private key and verified with a public key — they cannot be brute-forced via dictionary passwords.</span>`;
    }
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = "⏳ Brute-Forcing…";
  }
  if (alertEl) {
    alertEl.style.display = "block";
    alertEl.style.background = "rgba(88, 166, 255, 0.15)";
    alertEl.style.color = "#58a6ff";
    alertEl.textContent = "⏳ Running HMAC dictionary brute-force attack…";
  }

  try {
    const res = await fetch(`${JWT_BASE}/jwt/crack-secret`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Cracking error");

    if (!data.success) {
      alertEl.style.background = "rgba(210, 153, 34, 0.15)";
      alertEl.style.color = "#d29922";
      alertEl.innerHTML = `⚠️ <strong>Notice:</strong> ${jwtEsc(data.error || "Unable to crack token.")}`;
      return;
    }

    if (data.cracked) {
      window._jwtCrackedSecret = data.secret;
      alertEl.style.background = "rgba(248, 81, 73, 0.18)";
      alertEl.style.color = "#f85149";
      alertEl.innerHTML = `🎉 <strong>SECRET CRACKED IN ${data.elapsed_seconds}s!</strong><br>HMAC Secret Key: <code style="font-size:14px;background:rgba(0,0,0,0.3);padding:2px 8px;border-radius:4px;">${jwtEsc(data.secret)}</code>
      <div style="margin-top:8px;">
        <button type="button" class="jwt-btn-primary" onclick="jwtUseCrackedInForger('${jwtEsc(data.secret)}')" style="font-size:11px;padding:4px 10px;">🛠️ Open in Token Forger</button>
      </div>`;
    } else {
      alertEl.style.background = "rgba(63, 185, 80, 0.12)";
      alertEl.style.color = "#3fb950";
      alertEl.textContent = `🛡️ Strong Secret: Not found in ${data.tested_count || 0} common dictionary passwords (${data.elapsed_seconds || 0}s).`;
    }
  } catch (err) {
    if (alertEl) {
      alertEl.style.background = "rgba(248, 81, 73, 0.15)";
      alertEl.style.color = "#f85149";
      alertEl.textContent = "Cracking Error: " + err.message;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = "🚀 Start HMAC Brute-Force";
    }
  }
}

function jwtEsc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── cURL Import & Reset Functions ──────────────────────────────────────────

function jwtOpenCurlModal() {
  const modal = document.getElementById("jwt-curl-modal");
  const input = document.getElementById("jwt-curl-input");
  const errEl = document.getElementById("jwt-curl-error");
  if (errEl) errEl.style.display = "none";
  if (modal) modal.style.display = "flex";
  if (input) {
    input.value = "";
    setTimeout(() => input.focus(), 50);
  }
}

function jwtCloseCurlModal() {
  const modal = document.getElementById("jwt-curl-modal");
  if (modal) modal.style.display = "none";
}

async function jwtProcessCurlImport() {
  const input = document.getElementById("jwt-curl-input");
  const errEl = document.getElementById("jwt-curl-error");
  const btn = document.getElementById("jwt-btn-do-import");
  const curl = (input?.value || "").trim();

  if (!curl) {
    if (errEl) {
      errEl.textContent = "Please paste a cURL command.";
      errEl.style.display = "block";
    }
    return;
  }

  if (errEl) errEl.style.display = "none";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = "⏳ Parsing…";
  }

  let extracted = null;

  // 1. Try backend robust parser first
  try {
    const res = await fetch(`${JWT_BASE}/jwt/parse-curl`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ curl })
    });
    if (res.ok) {
      extracted = await res.json();
    }
  } catch (_) {
    // Backend offline or error, use fallback
  }

  // 2. Client-side fallback if backend was unavailable
  if (!extracted || !extracted.success) {
    extracted = jwtParseCurlClientSide(curl);
  }

  if (btn) {
    btn.disabled = false;
    btn.innerHTML = "⚡ Import &amp; Populate All";
  }

  if (!extracted || (!extracted.url && !extracted.token)) {
    if (errEl) {
      errEl.textContent = "Could not parse a valid URL or token from this cURL. Please check format.";
      errEl.style.display = "block";
    }
    return;
  }

  // Populate UI inputs
  if (extracted.token) {
    const tokenInp = document.getElementById("jwt-token-input");
    if (tokenInp) tokenInp.value = extracted.token;
    jwtOnTokenInput(); // triggers jwt.io inspector decoding
  }

  if (extracted.url) {
    const urlInp = document.getElementById("jwt-target-url");
    if (urlInp) urlInp.value = extracted.url;
  }

  if (extracted.method) {
    const methodSel = document.getElementById("jwt-target-method");
    if (methodSel) methodSel.value = extracted.method.toUpperCase();
  }

  const hdrsInp = document.getElementById("jwt-target-headers");
  if (hdrsInp && extracted.headers_text !== undefined) {
    hdrsInp.value = extracted.headers_text;
  }

  const bodyInp = document.getElementById("jwt-target-body");
  if (bodyInp && extracted.body !== undefined) {
    bodyInp.value = extracted.body;
  }

  jwtCloseCurlModal();
  jwtSyncForgerFromSetup(true);

  const summaryBar = document.getElementById("jwt-summary-bar");
  if (summaryBar) {
    if (extracted.token) {
      summaryBar.innerHTML = "✅ <strong>cURL Imported!</strong> Token, target URL, and headers loaded. Ready to run.";
      summaryBar.style.color = "#3fb950";
    } else {
      summaryBar.innerHTML = "ℹ️ <strong>cURL Imported!</strong> Target URL loaded, but no Bearer token found. Please paste token.";
      summaryBar.style.color = "#d29922";
    }
  }
}

/**
 * Fallback regex-based client-side cURL parser
 */
function jwtParseCurlClientSide(curl) {
  let s = curl.replace(/\\\r?\n/g, " ").trim();

  // Extract URL
  let url = "";
  const urlMatch = s.match(/(?:--url\s+['"]?|curl\s+(?:-[^\s]+\s+)*['"]?)(https?:\/\/[^\s'"]+)/i) ||
                   s.match(/['"](https?:\/\/[^'"]+)['"]/i) ||
                   s.match(/\b(https?:\/\/[^\s]+)/i);
  if (urlMatch) url = urlMatch[1];

  // Extract Method
  let method = "GET";
  const methodMatch = s.match(/(?:-X|--request)\s+['"]?([A-Za-z]+)['"]?/i);
  if (methodMatch) {
    method = methodMatch[1].toUpperCase();
  } else if (/--data|-d\s|--data-raw/i.test(s)) {
    method = "POST";
  }

  // Extract Headers and Token
  let token = "";
  const headersList = [];
  const headerRegex = /(?:-H|--header)\s+['"]([^'"]+)['"]/gi;
  let hm;
  while ((hm = headerRegex.exec(s)) !== null) {
    const line = hm[1].trim();
    const ci = line.indexOf(":");
    if (ci > 0) {
      const k = line.slice(0, ci).trim();
      const v = line.slice(ci + 1).trim();
      if (k.toLowerCase() === "authorization") {
        if (/^bearer\s+/i.test(v)) {
          token = v.replace(/^bearer\s+/i, "").trim();
        } else {
          token = v;
        }
      } else {
        headersList.push(`${k}: ${v}`);
      }
    }
  }

  // Fallback 1: check if any other header has a JWT (starts with eyJ and has at least 2 dots)
  if (!token) {
    for (let i = 0; i < headersList.length; i++) {
      const h = headersList[i];
      const ci = h.indexOf(":");
      if (ci > 0) {
        const val = h.slice(ci + 1).trim();
        if (/^bearer\s+eyJ/i.test(val)) {
          token = val.replace(/^bearer\s+/i, "").trim();
          headersList.splice(i, 1);
          break;
        } else if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(val)) {
          token = val;
          headersList.splice(i, 1);
          break;
        }
      }
    }
  }

  // Fallback 2: regex search for any JWT pattern anywhere in the cURL
  if (!token) {
    const jwtMatch = s.match(/\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/);
    if (jwtMatch) {
      token = jwtMatch[1];
    }
  }

  // Extract Body
  let body = "";
  const bodyMatch = s.match(/(?:--data|--data-raw|-d)\s+['"]([^'"]*)['"]/i) ||
                    s.match(/(?:--data|--data-raw|-d)\s+(\$?'[^']*')/i);
  if (bodyMatch) {
    body = bodyMatch[1].replace(/^\$?'|'$/g, "");
  }

  return {
    success: true,
    token,
    url,
    method,
    headers_text: headersList.join("\n"),
    body
  };
}

function jwtClearScanResults() {
  _jwtScanResults = [];
  _jwtSelectedResultIdx = null;
  jwtRenderScanTable([]);
  jwtClearPocDetails();

  const resultsBadge = document.getElementById("jwt-badge-results");
  if (resultsBadge) {
    resultsBadge.textContent = "0";
    resultsBadge.style.display = "none";
  }

  const summaryBar = document.getElementById("jwt-summary-bar");
  if (summaryBar) {
    summaryBar.innerHTML = "Ready to probe. Select attacks and click \"Run JWT Attacks\".";
    summaryBar.style.color = "var(--text2)";
  }
}

function jwtClearAllInputs() {
  const tokenInp = document.getElementById("jwt-token-input");
  const urlInp = document.getElementById("jwt-target-url");
  const hdrsInp = document.getElementById("jwt-target-headers");
  const bodyInp = document.getElementById("jwt-target-body");
  const methodSel = document.getElementById("jwt-target-method");
  const pubkeyInp = document.getElementById("jwt-target-pubkey");
  const successStrInp = document.getElementById("jwt-target-success-str");
  const timeoutInp = document.getElementById("jwt-target-timeout");

  if (tokenInp) tokenInp.value = "";
  if (urlInp) urlInp.value = "";
  if (hdrsInp) hdrsInp.value = "";
  if (bodyInp) bodyInp.value = "";
  if (pubkeyInp) pubkeyInp.value = "";
  if (successStrInp) successStrInp.value = "";
  if (timeoutInp) timeoutInp.value = "20";
  if (methodSel) methodSel.value = "GET";

  jwtClearScanResults();

  jwtOnTokenInput();
  jwtSwitchInspectorTab("payload");
  jwtSelectAllAttacks(true);
}

// Global Keyboard Navigation: Up/Down arrow moves to previous/next vector in attack results table
window.addEventListener("keydown", (e) => {
  if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;

  const scannerView = document.getElementById("jwt-view-scanner");
  if (!scannerView || scannerView.style.display === "none") return;
  if (!_jwtScanResults || !_jwtScanResults.length) return;

  const tag = (document.activeElement && document.activeElement.tagName) || "";
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

  e.preventDefault();
  jwtNavigateResult(e.key === "ArrowDown" ? 1 : -1);
});

// Keyboard Shortcut: Cmd+Enter (Mac) / Ctrl+Enter (Win/Linux) triggers Send Probe in Tab 5
window.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
    const forgerView = document.getElementById("jwt-view-forger");
    if (forgerView && forgerView.style.display !== "none") {
      e.preventDefault();
      const probeBtn = document.getElementById("jwt-forger-probe-btn");
      if (probeBtn && !probeBtn.disabled) {
        jwtProbeForgedTokenLive(probeBtn);
      }
    }
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── SUB-TAB 5: INTERACTIVE TOKEN FORGER & CLAIM EDITOR CONTROLLER ─────────────
// ══════════════════════════════════════════════════════════════════════════════

let _jwtLastForgedToken = "";
let _jwtForgerLoadedToken = "";
let _jwtOriginalToken = "";
let _jwtOriginalHObj = null;
let _jwtOriginalPObj = null;

function jwtDeepEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;

  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!jwtDeepEqual(a[i], b[i])) return false;
    }
    return true;
  }

  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;

  for (const k of keysA) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    if (!jwtDeepEqual(a[k], b[k])) return false;
  }
  return true;
}

function jwtSyncForgerFromSetup(force = false) {
  const token = (document.getElementById("jwt-token-input")?.value || "").trim();
  const url = (document.getElementById("jwt-target-url")?.value || "").trim();
  const method = (document.getElementById("jwt-target-method")?.value || "GET").trim();

  const probeUrlInp = document.getElementById("jwt-forger-probe-url");
  const probeMethodSel = document.getElementById("jwt-forger-probe-method");
  if (probeUrlInp && url) probeUrlInp.value = url;
  if (probeMethodSel && method) probeMethodSel.value = method;

  const headerTa = document.getElementById("jwt-forger-header");
  const payloadTa = document.getElementById("jwt-forger-payload");
  const secretInp = document.getElementById("jwt-forger-secret");
  const algSel = document.getElementById("jwt-forger-alg");
  const displayBox = document.getElementById("jwt-forger-token-display");
  const metaEl = document.getElementById("jwt-forger-token-meta");
  const lenEl = document.getElementById("jwt-forger-token-len");

  if (!token) {
    if (force || !headerTa?.value.trim()) {
      if (headerTa) headerTa.value = JSON.stringify({ alg: "HS256", typ: "JWT" }, null, 2);
    }
    if (force || !payloadTa?.value.trim()) {
      if (payloadTa) payloadTa.value = JSON.stringify({ sub: "user_101", name: "Alice", role: "user" }, null, 2);
    }
    _jwtForgerLoadedToken = "";
    return;
  }

  const parts = token.split(".");
  if (parts.length >= 2) {
    try {
      const hStr = jwtB64UrlDecode(parts[0]);
      const pStr = jwtB64UrlDecode(parts[1]);
      const hObj = jwtSafeJsonParse(hStr) || { alg: "HS256", typ: "JWT" };
      const pObj = jwtSafeJsonParse(pStr) || {};

      _jwtOriginalToken = token;
      _jwtOriginalHObj = JSON.parse(JSON.stringify(hObj));
      _jwtOriginalPObj = JSON.parse(JSON.stringify(pObj));

      if (headerTa && (force || token !== _jwtForgerLoadedToken || !headerTa.value.trim())) {
        headerTa.value = JSON.stringify(hObj, null, 2);
      }
      if (payloadTa && (force || token !== _jwtForgerLoadedToken || !payloadTa.value.trim())) {
        payloadTa.value = JSON.stringify(pObj, null, 2);
      }

      if (algSel && hObj.alg) {
        const matchingOpt = Array.from(algSel.options).find(o => o.value.toLowerCase() === String(hObj.alg).toLowerCase());
        if (matchingOpt) algSel.value = matchingOpt.value;
      }

      // If no token was forged yet or new token imported, initialize display box with baseline token
      if (force || !_jwtLastForgedToken || token !== _jwtForgerLoadedToken) {
        _jwtLastForgedToken = token;
        _jwtLastForgedH = headerTa?.value.trim() || "";
        _jwtLastForgedP = payloadTa?.value.trim() || "";
        _jwtLastForgedAlg = algSel?.value || "";
        _jwtLastForgedSecret = secretInp?.value || "";

        const tParts = token.split(".");
        const hColored = `<span class="jwt-part-header" style="color:var(--jwt-hdr-color,#ffa198);">${tParts[0] || ""}</span>`;
        const pColored = `<span class="jwt-part-payload" style="color:var(--jwt-pay-color,#e2c5ff);">${tParts[1] || ""}</span>`;
        const sColored = `<span class="jwt-part-sig" style="color:var(--jwt-sig-color,#a5d6ff);">${tParts[2] || ""}</span>`;
        if (displayBox) displayBox.innerHTML = `${hColored}.${pColored}.${sColored}`;
        if (metaEl) {
          metaEl.textContent = "Baseline Token Loaded (Ready to probe or forge)";
          metaEl.style.color = "var(--blue, #58a6ff)";
        }
        if (lenEl) lenEl.textContent = `${token.length} chars`;
      }

      _jwtForgerLoadedToken = token;
    } catch (e) {
      console.warn("Could not decode token for forger:", e);
    }
  }

  if (secretInp && window._jwtCrackedSecret) {
    secretInp.value = window._jwtCrackedSecret;
  }
}

function jwtFormatForgerJson() {
  const headerTa = document.getElementById("jwt-forger-header");
  const payloadTa = document.getElementById("jwt-forger-payload");
  const headerErr = document.getElementById("jwt-forger-header-err");
  const payloadErr = document.getElementById("jwt-forger-payload-err");

  if (headerTa) {
    try {
      const cleanH = jwtCleanJsonString(headerTa.value.trim() || "{}");
      const hObj = JSON.parse(cleanH);
      headerTa.value = JSON.stringify(hObj, null, 2);
      if (headerErr) headerErr.style.display = "none";
    } catch (e) {
      if (headerErr) {
        headerErr.style.display = "inline";
        headerErr.textContent = "Invalid JSON";
      }
    }
  }

  if (payloadTa) {
    try {
      const cleanP = jwtCleanJsonString(payloadTa.value.trim() || "{}");
      const pObj = JSON.parse(cleanP);
      payloadTa.value = JSON.stringify(pObj, null, 2);
      if (payloadErr) payloadErr.style.display = "none";
    } catch (e) {
      if (payloadErr) {
        payloadErr.style.display = "inline";
        payloadErr.textContent = "Invalid JSON";
      }
    }
  }
  jwtAutoUpdateForgedToken();
}

function jwtApplyForgerPreset(presetKey) {
  const payloadTa = document.getElementById("jwt-forger-payload");
  const payloadErr = document.getElementById("jwt-forger-payload-err");
  if (!payloadTa) return;

  let pObj = {};
  try {
    const cleanP = jwtCleanJsonString(payloadTa.value.trim() || "{}");
    pObj = JSON.parse(cleanP);
    if (payloadErr) payloadErr.style.display = "none";
  } catch (e) {
    alert("Please fix invalid Payload JSON first: " + e.message);
    if (payloadErr) {
      payloadErr.style.display = "inline";
      payloadErr.textContent = "Invalid JSON";
    }
    return;
  }

  const nowSec = Math.floor(Date.now() / 1000);

  if (presetKey === "admin_role") {
    pObj.role = "admin";
    pObj.isAdmin = true;
    pObj.admin = true;
  } else if (presetKey === "id_one") {
    if ("user_id" in pObj) pObj.user_id = 1;
    else if ("userId" in pObj) pObj.userId = 1;
    else if ("sub" in pObj && !isNaN(Number(pObj.sub))) pObj.sub = 1;
    else pObj.id = 1;
  } else if (presetKey === "future_exp") {
    pObj.exp = nowSec + (10 * 365 * 86400); // +10 years
  } else if (presetKey === "remove_exp") {
    delete pObj.exp;
  } else if (presetKey === "sub_admin") {
    pObj.sub = "admin";
  } else if (presetKey === "scope_all") {
    pObj.scope = "* admin write read all";
    pObj.authorities = ["ROLE_ADMIN", "ADMIN", "SUPERADMIN"];
  }

  payloadTa.value = JSON.stringify(pObj, null, 2);

  // Auto-forge immediately upon preset application
  jwtExecuteForgeAuto();
}

function jwtUseCrackedSecretForger() {
  const secretInp = document.getElementById("jwt-forger-secret");
  if (!secretInp) return;
  if (window._jwtCrackedSecret) {
    secretInp.value = window._jwtCrackedSecret;
    alert(`Applied cracked secret: "${window._jwtCrackedSecret}"`);
    jwtExecuteForgeAuto();
  } else {
    secretInp.value = "secret";
    alert("No secret cracked yet in Tab 4. Set to common default: 'secret'");
    jwtExecuteForgeAuto();
  }
}

function jwtUseCrackedInForger(sec) {
  window._jwtCrackedSecret = sec;
  jwtSwitchMainTab("forger");
  const secretInp = document.getElementById("jwt-forger-secret");
  if (secretInp) secretInp.value = sec;
  jwtExecuteForgeAuto();
}

let _jwtLastForgedH = "";
let _jwtLastForgedP = "";
let _jwtLastForgedAlg = "";
let _jwtLastForgedSecret = "";
let _jwtForgerDebounceTimer = null;

function jwtAutoUpdateForgedToken() {
  clearTimeout(_jwtForgerDebounceTimer);
  _jwtForgerDebounceTimer = setTimeout(() => {
    jwtExecuteForgeAuto();
  }, 250);
}

async function jwtExecuteForgeAuto() {
  const headerTa = document.getElementById("jwt-forger-header");
  const payloadTa = document.getElementById("jwt-forger-payload");
  const algSel = document.getElementById("jwt-forger-alg");
  const secretInp = document.getElementById("jwt-forger-secret");

  if (!headerTa || !payloadTa) return;

  let hObj = null, pObj = null;
  try {
    hObj = JSON.parse(jwtCleanJsonString(headerTa.value.trim() || "{}"));
    pObj = JSON.parse(jwtCleanJsonString(payloadTa.value.trim() || "{}"));
  } catch (_) {
    // Incomplete JSON while typing - do not auto-forge
    return;
  }

  const hAlg = hObj && hObj.alg ? String(hObj.alg).toLowerCase() : "";
  const selAlg = (algSel?.value || "none").toLowerCase();
  const secret = (secretInp?.value || "").trim();

  let mode = "keep_sig";
  if (hAlg === "none") {
    mode = "none";
  } else if (hAlg.startsWith("hs") && secret) {
    mode = "sign";
  } else if (secret) {
    mode = "sign";
  } else if (selAlg === "none" && !hAlg) {
    mode = "none";
  } else {
    mode = "keep_sig";
  }
  await jwtExecuteForge(mode, true);
}

async function jwtEnsureTokenForged() {
  const headerTa = document.getElementById("jwt-forger-header");
  const payloadTa = document.getElementById("jwt-forger-payload");
  if (!headerTa || !payloadTa) return;

  const currentH = headerTa.value.trim();
  const currentP = payloadTa.value.trim();

  // If already matches what we forged, we are good
  if (_jwtLastForgedH === currentH && _jwtLastForgedP === currentP && _jwtLastForgedToken) {
    return;
  }

  // Otherwise, automatically forge from current inputs
  await jwtExecuteForgeAuto();
}

async function jwtExecuteForge(mode, silent = false) {
  const headerTa = document.getElementById("jwt-forger-header");
  const payloadTa = document.getElementById("jwt-forger-payload");
  const algSel = document.getElementById("jwt-forger-alg");
  const secretInp = document.getElementById("jwt-forger-secret");
  const displayBox = document.getElementById("jwt-forger-token-display");
  const metaEl = document.getElementById("jwt-forger-token-meta");
  const lenEl = document.getElementById("jwt-forger-token-len");

  let hObj = {};
  let pObj = {};

  try {
    const cleanH = jwtCleanJsonString(headerTa?.value.trim() || '{"alg":"HS256","typ":"JWT"}');
    hObj = JSON.parse(cleanH);
  } catch (e) {
    if (!silent) alert("Invalid Header JSON: " + e.message);
    return;
  }

  try {
    const cleanP = jwtCleanJsonString(payloadTa?.value.trim() || '{}');
    pObj = JSON.parse(cleanP);
  } catch (e) {
    if (!silent) alert("Invalid Payload Claims JSON: " + e.message);
    return;
  }

  // CASE 2 REVERSION CHECK:
  // If claims in editor match the baseline original token from Setup, restore original token directly!
  const isOriginalClaims = _jwtOriginalToken && _jwtOriginalHObj && _jwtOriginalPObj &&
                           jwtDeepEqual(hObj, _jwtOriginalHObj) && jwtDeepEqual(pObj, _jwtOriginalPObj);

  if (isOriginalClaims && (mode === "keep_sig" || mode === "auto" || !mode || (hObj.alg && hObj.alg === _jwtOriginalHObj.alg))) {
    if (algSel && _jwtOriginalHObj.alg) {
      const match = Array.from(algSel.options).find(o => o.value.toLowerCase() === _jwtOriginalHObj.alg.toLowerCase());
      if (match) algSel.value = match.value;
    }
    _jwtLastForgedToken = _jwtOriginalToken;
    _jwtLastForgedH = headerTa?.value.trim() || "";
    _jwtLastForgedP = payloadTa?.value.trim() || "";
    _jwtLastForgedAlg = _jwtOriginalHObj.alg || "RS256";
    _jwtLastForgedSecret = "";

    const tParts = _jwtOriginalToken.split(".");
    const hColored = `<span class="jwt-part-header" style="color:var(--jwt-hdr-color,#ffa198);">${tParts[0] || ""}</span>`;
    const pColored = `<span class="jwt-part-payload" style="color:var(--jwt-pay-color,#e2c5ff);">${tParts[1] || ""}</span>`;
    const sColored = `<span class="jwt-part-sig" style="color:var(--jwt-sig-color,#a5d6ff);">${tParts[2] || ""}</span>`;
    if (displayBox) displayBox.innerHTML = `${hColored}.${pColored}.${sColored}`;
    if (metaEl) {
      metaEl.textContent = "Baseline Token Restored (Original Server Signature)";
      metaEl.style.color = "var(--blue, #58a6ff)";
    }
    if (lenEl) lenEl.textContent = `${_jwtOriginalToken.length} chars`;
    return;
  }

  let alg = (algSel?.value || "HS256").toUpperCase();
  let secret = (secretInp?.value || "").trim();
  let customSig = null;

  if (mode === "none") {
    alg = "none";
    hObj.alg = "none";
    if (headerTa && !silent && document.activeElement !== headerTa) {
      headerTa.value = JSON.stringify(hObj, null, 2);
    }
    if (algSel && algSel.value !== "none") algSel.value = "none";
  } else if (mode === "keep_sig") {
    // Keep signature from original active token in setup
    const originalToken = (document.getElementById("jwt-token-input")?.value || "").trim();
    const parts = originalToken.split(".");
    customSig = parts[2] || "AAAA";
    if (algSel && algSel.value === "none" && hObj.alg && hObj.alg !== "none") {
      const match = Array.from(algSel.options).find(o => o.value.toLowerCase() === String(hObj.alg).toLowerCase());
      if (match) algSel.value = match.value;
    }
  } else if (mode === "sign") {
    if (algSel && algSel.value === "none") {
      algSel.value = "HS256";
      alg = "HS256";
    }
    hObj.alg = alg;
    if (headerTa && !silent && document.activeElement !== headerTa) {
      headerTa.value = JSON.stringify(hObj, null, 2);
    }
  }

  try {
    const res = await fetch(`${JWT_BASE}/jwt/forge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        header: hObj,
        payload: pObj,
        secret: secret,
        alg: alg,
        custom_signature: customSig
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Forge failed");

    _jwtLastForgedToken = data.token || "";
    _jwtLastForgedH = headerTa?.value.trim() || "";
    _jwtLastForgedP = payloadTa?.value.trim() || "";
    _jwtLastForgedAlg = alg;
    _jwtLastForgedSecret = secret;

    // Format display with colored parts
    const tParts = _jwtLastForgedToken.split(".");
    const hColored = `<span class="jwt-part-header" style="color:var(--jwt-hdr-color,#ffa198);">${tParts[0] || ""}</span>`;
    const pColored = `<span class="jwt-part-payload" style="color:var(--jwt-pay-color,#e2c5ff);">${tParts[1] || ""}</span>`;
    const sColored = `<span class="jwt-part-sig" style="color:var(--jwt-sig-color,#a5d6ff);">${tParts[2] || ""}</span>`;

    if (displayBox) {
      displayBox.innerHTML = `${hColored}.${pColored}.${sColored}`;
    }
    if (metaEl) {
      if (mode === "none") {
        metaEl.textContent = "⚡ Forged with alg:none (Unsigned)";
        metaEl.style.color = "var(--jwt-hdr-color, #ffa198)";
      } else if (mode === "keep_sig") {
        metaEl.textContent = "🎭 Forged (Original Signature Preserved)";
        metaEl.style.color = "var(--yellow, #d29922)";
      } else {
        metaEl.textContent = `🔑 Signed with ${alg} (Key: ${secret || "none"})`;
        metaEl.style.color = "var(--green, #3fb950)";
      }
    }
    if (lenEl) lenEl.textContent = `${_jwtLastForgedToken.length} chars`;

  } catch (err) {
    if (!silent) alert("Forging error: " + err.message);
  }
}

async function jwtCopyForgedToken(btn) {
  await jwtEnsureTokenForged();
  if (!_jwtLastForgedToken) {
    alert("Please forge a token first by clicking one of the Forge buttons.");
    return;
  }
  jwtCopyToClipboard(_jwtLastForgedToken, btn, "Copied!");
}

function jwtSendForgedToSetup() {
  if (!_jwtLastForgedToken) {
    alert("Please forge a token first.");
    return;
  }
  const tokenInp = document.getElementById("jwt-token-input");
  if (tokenInp) {
    tokenInp.value = _jwtLastForgedToken;
    jwtOnTokenInput();
  }
  jwtSwitchMainTab("setup");
}

async function jwtProbeForgedTokenLive(btn) {
  await jwtEnsureTokenForged();
  if (!_jwtLastForgedToken) {
    alert("Please forge a token first before sending probe.");
    return;
  }

  const url = (document.getElementById("jwt-forger-probe-url")?.value || "").trim();
  const method = (document.getElementById("jwt-forger-probe-method")?.value || "GET").trim();
  const hdrsRaw = (document.getElementById("jwt-target-headers")?.value || "").trim();
  const bodyRaw = (document.getElementById("jwt-target-body")?.value || "").trim();
  const timeoutVal = parseInt(document.getElementById("jwt-target-timeout")?.value, 10) || 20;

  if (!url) {
    alert("Please enter a Target Endpoint URL to probe.");
    return;
  }

  const headers = {};
  if (hdrsRaw) {
    hdrsRaw.split("\n").forEach(line => {
      const ci = line.indexOf(":");
      if (ci > 0) headers[line.slice(0, ci).trim()] = line.slice(ci + 1).trim();
    });
  }

  const originalHtml = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = "⏳ Probing…";
  }

  const badgeEl = document.getElementById("jwt-forger-resp-badge");
  const snippetEl = document.getElementById("jwt-forger-resp-snippet");
  if (snippetEl) snippetEl.textContent = `Probing ${method} ${url}...`;

  try {
    const res = await fetch(`${JWT_BASE}/jwt/probe-single`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        method,
        attack_token: _jwtLastForgedToken,
        headers,
        body: bodyRaw || null,
        timeout: timeoutVal
      })
    });

    const probe = await res.json();
    if (!res.ok) throw new Error(probe.detail || "Probe failed");

    if (badgeEl) {
      badgeEl.style.display = "inline-block";
      const sc = probe.status_code;
      badgeEl.textContent = `HTTP ${sc} (${probe.reason}) in ${probe.elapsed_seconds}s`;
      badgeEl.className = (sc >= 200 && sc < 400) ? "jwt-badge-vuln" : (sc >= 400 && sc < 500) ? "jwt-badge-secure" : "jwt-badge-warn";
    }

    if (snippetEl) {
      let rawSnippet = probe.response_snippet || `Status: HTTP ${probe.status_code} (${probe.reason})\n(Empty response body)`;
      try {
        const parsed = JSON.parse(rawSnippet);
        rawSnippet = JSON.stringify(parsed, null, 2);
      } catch (_) {}
      snippetEl.textContent = rawSnippet;
    }
  } catch (err) {
    if (badgeEl) {
      badgeEl.style.display = "inline-block";
      badgeEl.textContent = "ERR (Failed)";
      badgeEl.className = "jwt-badge-warn";
    }
    if (snippetEl) {
      snippetEl.textContent = "Request Error: " + err.message;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// STANDALONE EXECUTIVE HTML REPORT EXPORTER (MARKET-READY)
// ══════════════════════════════════════════════════════════════════════════════

function _jwtToast(msg, type = "info") {
  if (typeof showToast === "function") {
    showToast(msg, type);
  } else if (typeof _asShowToast === "function") {
    _asShowToast(msg);
  } else if (typeof fuzzToast === "function") {
    fuzzToast(msg);
  } else {
    console.log(`[JWT Tool] ${msg}`);
  }
}

function _jwtEscAttr(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function _jwtFormatTokenPartsHtml(rawToken) {
  if (!rawToken || typeof rawToken !== "string") return '<span style="color:#6e7681">(No Token Provided)</span>';
  const parts = rawToken.trim().split(".");
  const h = jwtEsc(parts[0] || "");
  const p = jwtEsc(parts[1] || "");
  const s = jwtEsc(parts[2] || "");
  let out = `<span style="color:#ff7b72;word-break:break-all;">${h}</span>`;
  if (parts.length > 1) {
    out += `<span style="color:#8b949e;">.</span><span style="color:#d2a8ff;word-break:break-all;">${p}</span>`;
  }
  if (parts.length > 2) {
    out += `<span style="color:#8b949e;">.</span><span style="color:#79c0ff;word-break:break-all;">${s}</span>`;
  }
  return out;
}

function _jwtBuildCurlFallback(url, method, token, headers, body) {
  let cmd = `curl -i -X ${method || "POST"} "${url || "https://target-api.com/endpoint"}"`;
  cmd += ` \\\n  -H "Authorization: Bearer ${token || ""}"`;
  if (headers) {
    headers.split("\n").forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.toLowerCase().startsWith("authorization:")) {
        cmd += ` \\\n  -H "${trimmed.replace(/"/g, '\\"')}"`;
      }
    });
  }
  if (body) {
    cmd += ` \\\n  --data '${body.replace(/'/g, "'\\''")}'`;
  }
  return cmd;
}

function _jwtBuildPythonFallback(url, method, token) {
  return `import requests\n\nurl = "${url || "https://target-api.com/endpoint"}"\nheaders = {\n    "Authorization": "Bearer ${token || ""}"\n}\n\nresponse = requests.request("${(method || "POST").toUpperCase()}", url, headers=headers, verify=False)\nprint(f"Status Code: {response.status_code}")\nprint("Response Headers:", response.headers)\nprint("Response Body:\\n", response.text)\n`;
}

async function jwtDownloadHtmlReport() {
  const hasResults = _jwtScanResults && _jwtScanResults.length > 0;
  const hasParsed = !!_jwtCurrentParsed;
  const rawToken = (document.getElementById("jwt-token-input")?.value || "").trim();

  if (!hasResults && !hasParsed && !rawToken) {
    _jwtToast("⚠️ No JWT scan results or decoded tokens to export. Decode a token or run attacks first!", "warn");
    return;
  }

  const targetUrl = (document.getElementById("jwt-target-url")?.value || "").trim();
  const targetMethod = (document.getElementById("jwt-target-method")?.value || "POST").toUpperCase();
  const targetHeaders = (document.getElementById("jwt-target-headers")?.value || "").trim();
  const targetBody = (document.getElementById("jwt-target-body")?.value || "").trim();

  const meta = {
    targetUrl,
    targetMethod,
    targetHeaders,
    targetBody,
    rawToken
  };

  const html = _jwtGenHtmlReport(_jwtScanResults || [], _jwtCurrentParsed, meta);

  // Generate safe filename
  let hostStr = "jwt_audit";
  if (targetUrl) {
    try {
      const u = new URL(targetUrl.startsWith("http") ? targetUrl : "http://" + targetUrl);
      hostStr = u.hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
    } catch (_) {
      hostStr = "target";
    }
  }
  const ts = new Date().toISOString().replace(/[:.]/g, "").substring(0, 15);
  const filename = `jwt_security_report_${hostStr}_${ts}.html`;

  // PyWebView native file save API
  if (window.pywebview?.api?.save_file) {
    try {
      await window.pywebview.api.save_file(html, filename);
      _jwtToast(`📄 HTML report saved: ${filename}`, "success");
      return;
    } catch (_) {}
  }

  // Browser download fallback
  try {
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      a.remove();
      URL.revokeObjectURL(url);
    }, 1000);
    _jwtToast(`⬇ HTML report exported: ${filename}`, "success");
  } catch (err) {
    _jwtToast("Failed to download HTML report: " + err.message, "error");
  }
}
window.jwtDownloadHtmlReport = jwtDownloadHtmlReport;

function _jwtGenHtmlReport(results, parsedToken, meta) {
  const now = new Date().toLocaleString();
  const totalTested = results.length;
  const vulnList = results.filter(r => r.verdict === "VULNERABLE" || r.vulnerable);
  const vulnCount = vulnList.length;
  const secureList = results.filter(r => r.verdict === "SECURE" || (!r.vulnerable && r.verdict !== "BASELINE"));
  const secureCount = secureList.length;
  const baselineCount = results.filter(r => r.verdict === "BASELINE").length;

  const audit = parsedToken?.audit || {};
  const grade = audit.grade || (vulnCount > 0 ? "F" : totalTested > 0 ? "A" : "B");
  const score = audit.score !== undefined ? audit.score : (vulnCount > 0 ? 30 : 95);
  const findings = audit.findings || [];
  const expiry = parsedToken?.expiry;

  let expText = "Permanent (No exp claim)";
  if (expiry) {
    if (expiry.expired) {
      expText = `Expired (${expiry.exp_formatted || ""})`;
    } else if (expiry.has_exp) {
      const mins = Math.round(expiry.remaining_seconds / 60);
      expText = `Valid (~${mins}m remaining)`;
    }
  }

  const headerObj = parsedToken?.header || {};
  const payloadObj = parsedToken?.payload || {};
  const alg = headerObj.alg || (results[0]?.attack_token ? "Analyzed" : "N/A");

  // Executive Risk Verdict
  let verdictClass = "verdict-warn";
  let verdictTitle = "ℹ️ TOKEN STRUCTURE & PASSIVE SECURITY AUDIT";
  let verdictDesc = "Passive analysis and structural validation performed on the provided JSON Web Token.";
  let verdictBg = "rgba(88, 166, 255, 0.12)";
  let verdictBorder = "rgba(88, 166, 255, 0.35)";
  let verdictColor = "#58a6ff";

  if (vulnCount > 0) {
    verdictClass = "verdict-vuln";
    verdictTitle = `🚨 CRITICAL VULNERABILITIES IDENTIFIED (${vulnCount} Attack Vector${vulnCount > 1 ? "s" : ""} Accepted)`;
    verdictDesc = "CRITICAL RISK: Target server accepted unauthorized, unsigned, or tampered JWT tokens without proper signature verification. Immediate remediation required.";
    verdictBg = "rgba(248, 81, 73, 0.12)";
    verdictBorder = "rgba(248, 81, 73, 0.4)";
    verdictColor = "#f85149";
  } else if (totalTested > 0) {
    verdictClass = "verdict-secure";
    verdictTitle = `🛡️ ALL ATTACK VECTORS BLOCKED (${totalTested} Tests Passed)`;
    verdictDesc = "HARDENED POSTURE: Target server strictly verified cryptographic signatures and rejected all tested token manipulation variants.";
    verdictBg = "rgba(63, 185, 80, 0.12)";
    verdictBorder = "rgba(63, 185, 80, 0.4)";
    verdictColor = "#3fb950";
  }

  // Generate Table Rows
  const rowsHtml = totalTested === 0 
    ? `<tr><td colspan="7" style="text-align:center;padding:28px;color:#8b949e;">No active attack scans were executed. This report reflects passive token structure inspection and RFC security compliance.</td></tr>`
    : results.map((r, i) => {
        const isVuln = r.verdict === "VULNERABLE" || r.vulnerable;
        const isBase = r.verdict === "BASELINE";
        const cat = isVuln ? "vuln" : isBase ? "baseline" : "secure";
        const verdictBadge = isVuln
          ? `<span class="badge badge-vuln">🚨 VULNERABLE</span>`
          : isBase
          ? `<span class="badge badge-baseline">● BASELINE</span>`
          : `<span class="badge badge-secure">🛡️ SECURE</span>`;

        const sc = r.status_code;
        let scColor = "#8b949e";
        if (sc >= 200 && sc < 300) scColor = isVuln ? "#f85149" : "#3fb950";
        else if (sc >= 300 && sc < 400) scColor = "#58a6ff";
        else if (sc >= 400 && sc < 500) scColor = "#e3b341";
        else if (sc >= 500) scColor = "#f85149";

        const elapsed = r.elapsed_seconds !== undefined ? `${Number(r.elapsed_seconds).toFixed(3)}s` : "—";

        return `<tr class="result-row" data-category="${cat}">
          <td style="text-align:center;font-weight:700;color:#8b949e;">${i + 1}</td>
          <td>
            <div style="font-weight:600;color:#fff;">${jwtEsc(r.name || r.attack_id || "Attack")}</div>
            <div style="font-size:11px;color:#8b949e;margin-top:2px;">${jwtEsc(r.reason || "")}</div>
          </td>
          <td><code style="color:#d2a8ff;font-size:11px;">${jwtEsc(r.tampered_aspect || "Signature/Claims")}</code></td>
          <td><span class="status-pill" style="color:${scColor};border-color:${scColor}44;background:${scColor}18;">${sc || "ERR"}</span></td>
          <td>${verdictBadge}</td>
          <td style="color:#8b949e;font-size:11px;">${elapsed}</td>
          <td style="text-align:center;">
            <button type="button" class="btn-action" onclick="togglePoc(${i})">🔍 View Evidence</button>
          </td>
        </tr>`;
      }).join("");

  // Generate Technical Evidence Cards
  const evidenceCardsHtml = results.map((r, i) => {
    const isVuln = r.verdict === "VULNERABLE" || r.vulnerable;
    const isBase = r.verdict === "BASELINE";
    const info = (typeof JWT_ATTACK_EXPLANATIONS !== "undefined" && JWT_ATTACK_EXPLANATIONS[r.attack_id]) ? JWT_ATTACK_EXPLANATIONS[r.attack_id] : {
      concept: r.name || "JWT Security Verification Test",
      why: r.reason || "Automated signature verification test.",
      impact: isVuln ? "Critical Authentication Bypass: Attacker can forge valid API requests." : "Security Validation: Server rejects manipulated tokens."
    };

    const cardBorder = isVuln ? "border-left: 4px solid #f85149;" : isBase ? "border-left: 4px solid #58a6ff;" : "border-left: 4px solid #3fb950;";
    const curlCmd = r.curl_poc || _jwtBuildCurlFallback(meta.targetUrl, meta.targetMethod, r.attack_token, meta.targetHeaders, meta.targetBody);
    const pyScript = r.python_poc || _jwtBuildPythonFallback(meta.targetUrl, meta.targetMethod, r.attack_token);

    const formattedTokenHtml = _jwtFormatTokenPartsHtml(r.attack_token || "");

    return `<div class="evidence-card" id="poc-card-${i}" style="${cardBorder}">
      <div class="evidence-header">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <span style="font-size:14px;font-weight:700;color:#fff;">#${i + 1} ${jwtEsc(r.name || r.attack_id)}</span>
          ${isVuln ? '<span class="badge badge-vuln">🚨 VULNERABLE</span>' : isBase ? '<span class="badge badge-baseline">● BASELINE</span>' : '<span class="badge badge-secure">🛡️ SECURE</span>'}
          <span class="status-pill" style="font-size:11px;">HTTP ${r.status_code || "ERR"}</span>
          <span style="font-size:11px;color:#8b949e;">${r.elapsed_seconds ? r.elapsed_seconds + "s" : ""}</span>
        </div>
        <button type="button" class="btn-action" onclick="togglePoc(${i})" style="font-size:11px;">✕ Close</button>
      </div>

      <div class="evidence-meta-grid">
        <div>
          <div class="meta-label">Attack Concept & Technique:</div>
          <div class="meta-val">${jwtEsc(info.concept)} — ${jwtEsc(info.why)}</div>
        </div>
        <div>
          <div class="meta-label">Technical Risk & Security Impact:</div>
          <div class="meta-val" style="color:${isVuln ? '#ff7b72' : '#8b949e'};">${jwtEsc(info.impact)}</div>
        </div>
      </div>

      ${r.is_flapping ? `
        <div class="alert-box alert-warn" style="margin-top:10px;">
          ⚠️ <strong>Intermittent Gateway Response (Flapping) Detected:</strong> Response codes varied between runs. This strongly indicates WSO2 / Redis edge token caching with TTL expiration.
        </div>
      ` : ""}

      <div style="margin-top:12px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <span class="meta-label">Injected Attack Token:</span>
          <button type="button" class="btn-copy" onclick="copyText('${_jwtEscAttr(r.attack_token || "")}', this)">📋 Copy Token</button>
        </div>
        <div class="code-box" style="font-size:11px;word-break:break-all;">${formattedTokenHtml}</div>
      </div>

      <div style="margin-top:12px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <span class="meta-label">cURL Reproduction Proof of Concept (PoC):</span>
          <button type="button" class="btn-copy" onclick="copyText('${_jwtEscAttr(curlCmd)}', this)">📋 Copy cURL</button>
        </div>
        <pre class="code-box"><code>${jwtEsc(curlCmd)}</code></pre>
      </div>

      <div style="margin-top:12px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <span class="meta-label">Python Requests Exploit Script:</span>
          <button type="button" class="btn-copy" onclick="copyText('${_jwtEscAttr(pyScript)}', this)">📋 Copy Python</button>
        </div>
        <pre class="code-box"><code>${jwtEsc(pyScript)}</code></pre>
      </div>

      <div style="margin-top:12px;">
        <span class="meta-label">Server Response Evidence:</span>
        <pre class="code-box" style="max-height:160px;overflow-y:auto;color:#79c0ff;"><code>${jwtEsc(r.response_body || "(Empty response body or no content)")}</code></pre>
      </div>
    </div>`;
  }).join("");

  // Passive Audit Findings HTML
  const auditFindingsHtml = findings.length === 0
    ? `<div style="padding:14px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#3fb950;font-weight:600;text-align:center;">
        ✅ No passive structural flaws found in the token. Signature algorithm and claim formatting follow RFC standard best practices.
       </div>`
    : findings.map(f => {
        const sev = (f.severity || "Low").toLowerCase();
        const sevColor = sev === "critical" ? "#f85149" : (sev === "high" ? "#ff7b72" : sev === "medium" ? "#e3b341" : "#58a6ff");
        return `<div class="audit-item" style="border-left:3px solid ${sevColor};">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
            <span style="font-weight:700;color:#fff;font-size:13px;">${jwtEsc(f.title)}</span>
            <span class="badge" style="background:${sevColor}22;color:${sevColor};">${jwtEsc(f.severity.toUpperCase())}</span>
          </div>
          <div style="font-size:12px;color:#c9d1d9;line-height:1.4;">${jwtEsc(f.description)}</div>
          ${f.remediation ? `<div style="font-size:11.5px;color:#58a6ff;margin-top:4px;"><strong style="color:#8b949e;">Remediation:</strong> ${jwtEsc(f.remediation)}</div>` : ""}
        </div>`;
      }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Sentinel — JWT Security Audit & Vulnerability Assessment Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --bg2: #161b22;
      --bg3: #21262d;
      --border: #30363d;
      --text: #c9d1d9;
      --text2: #8b949e;
      --text3: #6e7681;
      --blue: #58a6ff;
      --red: #f85149;
      --green: #3fb950;
      --yellow: #e3b341;
      --purple: #d2a8ff;
      --mono: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 13px;
      line-height: 1.5;
      padding: 24px 32px;
    }
    .header-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 18px;
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand-title {
      font-size: 20px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .brand-title span.sub {
      font-size: 13px;
      font-weight: 500;
      color: var(--text2);
    }
    .target-box {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }
    .method-pill {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      background: rgba(88, 166, 255, 0.15);
      color: var(--blue);
      border: 1px solid rgba(88, 166, 255, 0.3);
      font-family: var(--mono);
    }
    .verdict-banner {
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 28px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .verdict-title {
      font-size: 16px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .verdict-desc {
      font-size: 12.5px;
      opacity: 0.92;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }
    .stat-val {
      font-size: 24px;
      font-weight: 700;
      font-family: var(--mono);
      color: #fff;
    }
    .stat-lbl {
      font-size: 11.5px;
      color: var(--text2);
      margin-top: 4px;
    }
    .section-title {
      font-size: 15px;
      font-weight: 600;
      color: #fff;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
    }
    .code-box {
      background: #00000044;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: var(--mono);
      font-size: 11.5px;
      color: var(--text);
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }
    th {
      background: var(--bg3);
      color: var(--text2);
      font-weight: 600;
      padding: 9px 12px;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    td {
      padding: 8px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    tr:last-child td { border-bottom: none; }
    .badge {
      font-size: 10.5px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      white-space: nowrap;
    }
    .badge-vuln { background: rgba(248, 81, 73, 0.15); color: var(--red); border: 1px solid rgba(248, 81, 73, 0.3); }
    .badge-secure { background: rgba(63, 185, 80, 0.15); color: var(--green); border: 1px solid rgba(63, 185, 80, 0.3); }
    .badge-baseline { background: rgba(88, 166, 255, 0.15); color: var(--blue); border: 1px solid rgba(88, 166, 255, 0.3); }
    .status-pill {
      font-size: 10.5px;
      font-weight: 700;
      padding: 1px 6px;
      border-radius: 4px;
      font-family: var(--mono);
      border: 1px solid transparent;
    }
    .btn-action {
      background: var(--bg3);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-action:hover {
      background: var(--blue);
      color: #fff;
      border-color: var(--blue);
    }
    .btn-copy {
      background: var(--bg3);
      border: 1px solid var(--border);
      color: var(--text2);
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-copy:hover {
      color: #fff;
      background: rgba(88, 166, 255, 0.2);
      border-color: var(--blue);
    }
    .filter-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 12px;
    }
    .filter-pills {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }
    .filter-pill {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text2);
      font-size: 11.5px;
      padding: 4px 10px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-pill:hover {
      background: var(--bg3);
      color: #fff;
    }
    .filter-pill.active {
      background: var(--blue);
      color: #fff;
      border-color: var(--blue);
      font-weight: 600;
    }
    .search-inp {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: #fff;
      font-size: 12px;
      padding: 5px 12px;
      width: 250px;
      outline: none;
    }
    .search-inp:focus {
      border-color: var(--blue);
    }
    .evidence-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
      display: none;
    }
    .evidence-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    .evidence-meta-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      background: var(--bg3);
      padding: 10px 14px;
      border-radius: 6px;
      margin-bottom: 12px;
    }
    .meta-label {
      font-size: 11px;
      color: var(--text3);
      font-weight: 600;
      margin-bottom: 2px;
    }
    .meta-val {
      font-size: 12px;
      color: var(--text);
    }
    .audit-item {
      background: var(--bg3);
      border-radius: 6px;
      padding: 10px 14px;
      margin-bottom: 10px;
    }
    .alert-box {
      border-radius: 6px;
      padding: 10px 14px;
      font-size: 12px;
      line-height: 1.4;
    }
    .alert-warn {
      background: rgba(227, 179, 65, 0.12);
      border: 1px solid rgba(227, 179, 65, 0.3);
      color: #e3b341;
    }
    .rem-step {
      display: flex;
      gap: 12px;
      margin-bottom: 14px;
    }
    .rem-num {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: rgba(88, 166, 255, 0.15);
      color: var(--blue);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 12px;
      flex-shrink: 0;
    }
    @media print {
      body {
        background: #fff !important;
        color: #000 !important;
        padding: 0 !important;
      }
      .filter-bar, .btn-action, .btn-copy, .btn-print {
        display: none !important;
      }
      .evidence-card {
        display: block !important;
        page-break-inside: avoid;
        border: 1px solid #ccc !important;
        background: #fafafa !important;
      }
      .card, .stat-card, .target-box, .verdict-banner {
        border: 1px solid #ddd !important;
        background: #fff !important;
      }
      .code-box, pre {
        background: #eee !important;
        color: #000 !important;
      }
    }
  </style>
</head>
<body>

  <!-- Top Brand & Header -->
  <div class="header-bar">
    <div>
      <div class="brand-title">
        🛡️ API SENTINEL <span class="sub">— JWT Security Audit Suite</span>
      </div>
      <div style="font-size:12px;color:var(--text2);margin-top:3px;">
        OWASP API Security Top 10 (API1: BOLA, API2: Broken Authentication)
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:10px;">
      <span class="badge" style="background:rgba(210,168,255,0.15);color:var(--purple);border:1px solid rgba(210,168,255,0.3);font-size:11px;">OWASP Compliant</span>
      <button type="button" class="btn-action btn-print" onclick="window.print()" style="font-weight:600;display:inline-flex;align-items:center;gap:5px;">
        🖨️ Print / Save PDF
      </button>
    </div>
  </div>

  <!-- Target Endpoint Info -->
  <div class="target-box">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <span class="method-pill">${jwtEsc(meta.targetMethod)}</span>
      <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:#fff;">${jwtEsc(meta.targetUrl || "No Target URL specified (Offline Analysis)")}</span>
    </div>
    <div style="font-size:11.5px;color:var(--text2);">
      Generated: <strong>${now}</strong>
    </div>
  </div>

  <!-- Executive Risk Posture Verdict -->
  <div class="verdict-banner" style="background:${verdictBg};border:1px solid ${verdictBorder};color:${verdictColor};">
    <div class="verdict-title">${verdictTitle}</div>
    <div class="verdict-desc">${verdictDesc}</div>
  </div>

  <!-- KPI Metrics Grid -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val">${totalTested}</div>
      <div class="stat-lbl">Total Attacks Tested</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:${vulnCount > 0 ? '#f85149' : '#3fb950'};">${vulnCount}</div>
      <div class="stat-lbl">Vulnerabilities Detected</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#3fb950;">${secureCount}</div>
      <div class="stat-lbl">Hardened / Blocked</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#58a6ff;">Grade ${grade} <span style="font-size:13px;color:var(--text2);">(${score}/100)</span></div>
      <div class="stat-lbl">Passive Audit Score</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="font-size:15px;color:#ffa657;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${expText}</div>
      <div class="stat-lbl">Session Lifespan</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="font-size:18px;color:#d2a8ff;">${jwtEsc(alg)}</div>
      <div class="stat-lbl">Algorithm Specified</div>
    </div>
  </div>

  <!-- SECTION 1: Token Architecture & Inspection -->
  <div class="section-title">🔑 Target Token Architecture &amp; Structure</div>
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
      <div style="font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px;">
        Raw JWT Structure (🔴 Header · 🟣 Payload · 🔵 Signature):
      </div>
      <button type="button" class="btn-copy" onclick="copyText('${_jwtEscAttr(meta.rawToken || "")}', this)">📋 Copy Token</button>
    </div>
    <div class="code-box" style="margin-bottom:16px;">${_jwtFormatTokenPartsHtml(meta.rawToken || "")}</div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div>
        <div style="font-size:11px;font-weight:700;color:#ff7b72;margin-bottom:4px;">🔴 Decoded Header:</div>
        <pre class="code-box" style="max-height:180px;color:#ff7b72;"><code>${jwtEsc(JSON.stringify(headerObj, null, 2))}</code></pre>
      </div>
      <div>
        <div style="font-size:11px;font-weight:700;color:#d2a8ff;margin-bottom:4px;">🟣 Decoded Payload Claims:</div>
        <pre class="code-box" style="max-height:180px;color:#d2a8ff;"><code>${jwtEsc(JSON.stringify(payloadObj, null, 2))}</code></pre>
      </div>
    </div>
  </div>

  <!-- SECTION 2: Passive Security Audit Findings -->
  <div class="section-title">📋 Passive RFC Compliance Audit Findings</div>
  <div class="card">
    ${auditFindingsHtml}
  </div>

  <!-- SECTION 3: Active Attack Scanner Matrix -->
  <div class="section-title">⚔️ Active Attack Scanner &amp; Vulnerability Matrix</div>
  <div class="card" style="padding:0;overflow:hidden;">
    <div style="padding:14px 16px;border-bottom:1px solid var(--border);">
      <div class="filter-bar">
        <div class="filter-pills">
          <button type="button" class="filter-pill active" onclick="setFilter('all', this)">All (${totalTested})</button>
          <button type="button" class="filter-pill" onclick="setFilter('vuln', this)" style="color:#ff7b72;">🚨 Vulnerable (${vulnCount})</button>
          <button type="button" class="filter-pill" onclick="setFilter('secure', this)" style="color:#3fb950;">🛡️ Secure (${secureCount})</button>
          <button type="button" class="filter-pill" onclick="setFilter('baseline', this)" style="color:#58a6ff;">● Baseline (${baselineCount})</button>
        </div>
        <input type="text" class="search-inp" id="search-input" oninput="applyFilters()" placeholder="🔍 Quick search attacks, status...">
      </div>
    </div>

    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th style="width:40px;text-align:center;">#</th>
            <th>Attack Scenario &amp; Vector</th>
            <th>Tampered Aspect</th>
            <th>HTTP Status</th>
            <th>Verdict</th>
            <th>Latency</th>
            <th style="text-align:center;">Action</th>
          </tr>
        </thead>
        <tbody id="results-tbody">
          ${rowsHtml}
          <tr id="no-match-row" style="display:none;">
            <td colspan="7" style="text-align:center;padding:24px;color:#8b949e;">No attacks match your filter criteria.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- SECTION 4: Technical Evidence & PoCs -->
  ${totalTested > 0 ? `
    <div class="section-title">🔬 Technical Evidence &amp; Proof of Concept (PoCs)</div>
    <div style="margin-bottom:24px;">
      ${evidenceCardsHtml}
    </div>
  ` : ""}

  <!-- SECTION 5: Executive Remediation Roadmap -->
  <div class="section-title">🛡️ Remediation &amp; Hardening Framework (OWASP Recommendations)</div>
  <div class="card">
    <div class="rem-step">
      <div class="rem-num">1</div>
      <div>
        <div style="font-weight:700;color:#fff;">Strict Algorithm Allowlisting</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px;">
          Explicitly reject <code style="color:#ff7b72">alg: none</code>, <code style="color:#ff7b72">None</code>, and case variations in the verification engine. Restrict accepted algorithms to a strict allowlist (e.g. only <code style="color:#58a6ff">RS256</code> or <code style="color:#58a6ff">ES256</code>).
        </div>
      </div>
    </div>

    <div class="rem-step">
      <div class="rem-num">2</div>
      <div>
        <div style="font-weight:700;color:#fff;">Mandatory Cryptographic Signature Verification</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px;">
          Never trust, decode, or extract payload claims without first mathematically validating the token's cryptographic signature against the verified public key or private secret.
        </div>
      </div>
    </div>

    <div class="rem-step">
      <div class="rem-num">3</div>
      <div>
        <div style="font-weight:700;color:#fff;">Prevent Algorithm Confusion Attacks (Key Confusion)</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px;">
          Ensure that public RSA/EC verification keys cannot be repurposed as symmetric HMAC secret keys (<code style="color:#e3b341">RS256 → HS256</code>). Strictly isolate key stores by cryptographic type.
        </div>
      </div>
    </div>

    <div class="rem-step">
      <div class="rem-num">4</div>
      <div>
        <div style="font-weight:700;color:#fff;">Sanitize Header Parameters (<code style="color:#d2a8ff">kid</code>, <code style="color:#d2a8ff">jku</code>, <code style="color:#d2a8ff">x5u</code>)</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px;">
          Never allow client-controlled <code style="color:#d2a8ff">kid</code> values to be passed directly to file systems or SQL queries. Validate <code style="color:#d2a8ff">kid</code> against a static dictionary of allowed key IDs. Ignore untrusted remote JWKS URLs.
        </div>
      </div>
    </div>

    <div class="rem-step">
      <div class="rem-num">5</div>
      <div>
        <div style="font-weight:700;color:#fff;">Enforce Token Expiry (<code style="color:#d2a8ff">exp</code>) &amp; Clock Skew Bounds</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px;">
          Mandate short-lived session lifetimes (15-60 minutes) and reject any token lacking an <code style="color:#d2a8ff">exp</code> claim. Verify <code style="color:#d2a8ff">iss</code> (Issuer) and <code style="color:#d2a8ff">aud</code> (Audience) to prevent cross-service token reuse.
        </div>
      </div>
    </div>

    <div class="rem-step" style="margin-bottom:0;">
      <div class="rem-num">6</div>
      <div>
        <div style="font-weight:700;color:#fff;">Edge Gateway Token Revocation Management</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px;">
          If using API Gateways (WSO2, Kong, Apigee) with Redis caching, implement immediate cache invalidation webhooks on logout or revocation to prevent cached HTTP 200 authorization bypasses.
        </div>
      </div>
    </div>
  </div>

  <div style="text-align:center;color:var(--text3);font-size:11px;margin-top:24px;padding-top:16px;border-top:1px solid var(--border);">
    API Sentinel Security Lab · Automated JWT Penetration Testing &amp; Vulnerability Suite · Confirmed Against RFC 7519 Standards
  </div>

  <script>
    let activeFilter = 'all';

    function setFilter(filter, btn) {
      activeFilter = filter;
      document.querySelectorAll('.filter-pill').forEach(function(b) {
        b.classList.remove('active');
      });
      if (btn) btn.classList.add('active');
      applyFilters();
    }

    function applyFilters() {
      const search = (document.getElementById('search-input') ? document.getElementById('search-input').value : '').toLowerCase().trim();
      const rows = document.querySelectorAll('#results-tbody tr.result-row');
      let visibleCount = 0;

      rows.forEach(function(row) {
        const cat = row.getAttribute('data-category') || '';
        const text = row.textContent.toLowerCase();

        const matchCat = (activeFilter === 'all') || (cat === activeFilter);
        const matchSearch = !search || text.indexOf(search) !== -1;

        if (matchCat && matchSearch) {
          row.style.display = '';
          visibleCount++;
        } else {
          row.style.display = 'none';
        }
      });

      const noRowsEl = document.getElementById('no-match-row');
      if (noRowsEl) {
        noRowsEl.style.display = (visibleCount === 0) ? '' : 'none';
      }
    }

    function togglePoc(id) {
      const el = document.getElementById('poc-card-' + id);
      if (!el) return;
      if (el.style.display === 'none' || !el.style.display) {
        el.style.display = 'block';
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } else {
        el.style.display = 'none';
      }
    }

    function copyText(text, btn) {
      if (!navigator.clipboard) {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      } else {
        navigator.clipboard.writeText(text);
      }
      if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = '✓ Copied!';
        btn.style.borderColor = '#3fb950';
        btn.style.color = '#3fb950';
        setTimeout(function() {
          btn.innerHTML = orig;
          btn.style.borderColor = '';
          btn.style.color = '';
        }, 1500);
      }
    }
  </script>
</body>
</html>`;
}



