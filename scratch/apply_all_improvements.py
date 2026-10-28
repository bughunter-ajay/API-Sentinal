import re

# ==========================================
# 1. Patch backend/main.py (Report template + StartDalfoxScanReq)
# ==========================================
with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    main_code = f.read()

# Update StartDalfoxScanReq
old_start_req = '''class StartDalfoxScanReq(BaseModel):
    endpoints: List[Dict[str, Any]]
    workers: int = 10
    rate_limit: int = 15
    waf_bypass: str = "auto"
    scan_mode: str = "standard"
    deep_scan: bool = False
    skip_ast_analysis: bool = False
    follow_redirects: bool = True
    debug: bool = False
    blind_url: Optional[str] = None
    proxy: Optional[str] = None'''

new_start_req = '''class StartDalfoxScanReq(BaseModel):
    endpoints: List[Dict[str, Any]]
    workers: int = 10
    rate_limit: int = 15
    waf_bypass: str = "auto"
    waf_evasion: bool = False
    remote_payloads: bool = False
    scan_mode: str = "standard"
    deep_scan: bool = False
    skip_ast_analysis: bool = False
    follow_redirects: bool = True
    debug: bool = False
    blind_url: Optional[str] = None
    proxy: Optional[str] = None'''

if old_start_req in main_code:
    main_code = main_code.replace(old_start_req, new_start_req)

# Replace finding cards in generate_dalfox_standalone_report
old_cards = '''            <div class="code-box">
                <div class="code-header">
                    <span>🎯 Injected XSS Payload</span>
                    <button class="copy-btn" onclick="copySnippet(this, 'payload-{idx}')">📋 Copy Payload</button>
                </div>
                <pre id="payload-{idx}">{f_payload}</pre>
            </div>
            <div class="code-box" style="margin-top:10px;">
                <div class="code-header">
                    <span>🚀 Reproduce PoC cURL</span>
                    <button class="copy-btn" onclick="copySnippet(this, 'curl-{idx}')">📋 Copy cURL</button>
                </div>
                <pre id="curl-{idx}">{f_curl}</pre>
            </div>'''

new_cards = '''            <details class="collapsible-box" open>
                <summary class="collapsible-header">
                    <span class="box-title">🎯 Injected XSS Payload</span>
                    <div class="header-actions">
                        <button class="copy-btn" onclick="copySnippet(this, 'payload-{idx}', event)">📋 Copy Payload</button>
                        <span class="chevron">▾</span>
                    </div>
                </summary>
                <div class="box-content">
                    <pre id="payload-{idx}">{f_payload}</pre>
                </div>
            </details>
            <details class="collapsible-box" open style="margin-top:10px;">
                <summary class="collapsible-header">
                    <span class="box-title">🚀 Reproduce PoC cURL</span>
                    <div class="header-actions">
                        <button class="copy-btn" onclick="copySnippet(this, 'curl-{idx}', event)">📋 Copy cURL</button>
                        <span class="chevron">▾</span>
                    </div>
                </summary>
                <div class="box-content">
                    <pre id="curl-{idx}">{f_curl}</pre>
                </div>
            </details>'''

if old_cards in main_code:
    main_code = main_code.replace(old_cards, new_cards)

# Replace copySnippet function in template
old_copy = '''    <script>
        function copySnippet(btn, id) {{
            const el = document.getElementById(id);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText || el.textContent).then(() => {{
                const orig = btn.innerText;
                btn.innerText = "✔ Copied!";
                setTimeout(() => {{ btn.innerText = orig; }}, 2000);
            }});
        }}
    </script>'''

new_copy = '''    <script>
        function copySnippet(btn, id, event) {{
            if (event) {{
                event.stopPropagation();
                event.preventDefault();
            }}
            const el = document.getElementById(id);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText || el.textContent).then(() => {{
                const orig = btn.innerText;
                btn.innerText = "✔ Copied!";
                setTimeout(() => {{ btn.innerText = orig; }}, 2000);
            }});
        }}
    </script>'''

if old_copy in main_code:
    main_code = main_code.replace(old_copy, new_copy)

# Replace CSS for code-box with collapsible-box
old_css_box = '''.code-box {
            background: var(--bg-code);
            border: 1px solid #14202e;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
        }
        .code-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; color: var(--text-dim); font-size: 11px; }'''

new_css_box = '''.collapsible-box {
            background: var(--bg-code);
            border: 1px solid #14202e;
            border-radius: 6px;
            font-family: monospace;
            font-size: 12px;
            transition: all 0.2s ease;
        }
        .collapsible-box:hover {
            border-color: #24364a;
        }
        .collapsible-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 14px;
            cursor: pointer;
            user-select: none;
            outline: none;
            list-style: none;
            background: rgba(13, 21, 32, 0.6);
            border-radius: 6px;
        }
        .collapsible-header::-webkit-details-marker {
            display: none;
        }
        .box-title {
            color: var(--text-dim);
            font-size: 11px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .collapsible-header:hover .box-title {
            color: var(--text-main);
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .chevron {
            color: var(--accent);
            font-size: 13px;
            transition: transform 0.2s ease;
            display: inline-block;
        }
        details[open] .chevron {
            transform: rotate(180deg);
        }
        .box-content {
            padding: 12px 14px;
            border-top: 1px solid #14202e;
            background: #020508;
            border-bottom-left-radius: 6px;
            border-bottom-right-radius: 6px;
        }
        .box-content pre {
            white-space: pre-wrap;
            word-break: break-all;
            overflow-wrap: anywhere;
            color: #7ee787;
            font-family: inherit;
            font-size: 11.5px;
            line-height: 1.5;
            margin: 0;
        }'''

if old_css_box in main_code:
    main_code = main_code.replace(old_css_box, new_css_box)

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(main_code)
print("main.py updated successfully!")


# ==========================================
# 2. Patch backend/dalfox_engine.py (CLI flags)
# ==========================================
with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    eng_code = f.read()

old_cfg_read = '''            blind_url = str(config.get("blind_url") or "").strip()
            proxy = str(config.get("proxy") or "").strip()
            debug_mode = bool(config.get("debug", False))'''

new_cfg_read = '''            blind_url = str(config.get("blind_url") or "").strip()
            proxy = str(config.get("proxy") or "").strip()
            debug_mode = bool(config.get("debug", False))
            waf_evasion = bool(config.get("waf_evasion", False))
            remote_payloads = bool(config.get("remote_payloads", False))'''

if old_cfg_read in eng_code:
    eng_code = eng_code.replace(old_cfg_read, new_cfg_read)

old_waf_bypass = '''                # WAF Bypass
                if waf_bypass in ["auto", "force", "off"]:
                    cmd.extend(["--waf-bypass", waf_bypass])'''

new_waf_bypass = '''                # WAF Bypass & Evasion
                if waf_bypass in ["auto", "force", "off"]:
                    cmd.extend(["--waf-bypass", waf_bypass])
                if waf_evasion:
                    cmd.append("--waf-evasion")
                if remote_payloads:
                    cmd.extend(["--remote-payloads", "portswigger,payloadbox"])'''

if old_waf_bypass in eng_code:
    eng_code = eng_code.replace(old_waf_bypass, new_waf_bypass)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(eng_code)
print("dalfox_engine.py updated successfully!")


# ==========================================
# 3. Patch ui/index.html (Add Checkboxes)
# ==========================================
with open("UltronScan/ui/index.html", "r", encoding="utf-8") as f:
    html_code = f.read()

debug_block = '''              <!-- Debug Verbose -->
              <div class="config-item">
                <span class="config-label" style="visibility: hidden;">Debug</span>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-family: var(--font-mono); font-size: 11px; height: 27px; padding: 0 4px; box-sizing: border-box; white-space: nowrap;" title="Enable deep verbose debug logs (--debug)">
                  <input type="checkbox" id="dalfox-cfg-debug" style="accent-color: #ff9900; cursor: pointer;" />
                  <span>Debug Logs</span>
                </label>
              </div>'''

new_checkboxes = debug_block + '''

              <!-- WAF Evasion -->
              <div class="config-item">
                <span class="config-label" style="visibility: hidden;">Evasion</span>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-family: var(--font-mono); font-size: 11px; height: 27px; padding: 0 4px; box-sizing: border-box; white-space: nowrap;" title="Enable adaptive jitter & timing evasion to avoid WAF rate-limiting/IP ban (--waf-evasion)">
                  <input type="checkbox" id="dalfox-cfg-waf-evasion" style="accent-color: #ff9900; cursor: pointer;" />
                  <span>WAF Evasion</span>
                </label>
              </div>

              <!-- Remote Payloads -->
              <div class="config-item">
                <span class="config-label" style="visibility: hidden;">Remote</span>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-family: var(--font-mono); font-size: 11px; height: 27px; padding: 0 4px; box-sizing: border-box; white-space: nowrap;" title="Fetch latest online XSS payloads from PortSwigger & PayloadBox (--remote-payloads portswigger,payloadbox)">
                  <input type="checkbox" id="dalfox-cfg-remote-payloads" style="accent-color: #ff9900; cursor: pointer;" />
                  <span>Remote Payloads</span>
                </label>
              </div>'''

if debug_block in html_code and "dalfox-cfg-waf-evasion" not in html_code:
    html_code = html_code.replace(debug_block, new_checkboxes)

with open("UltronScan/ui/index.html", "w", encoding="utf-8") as f:
    f.write(html_code)
print("index.html updated successfully!")


# ==========================================
# 4. Patch ui/js/dalfox.js (Variables, Preview, Payload, Modal hooks)
# ==========================================
with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    dfx_code = f.read()

# Add element references in initElements
old_init_cfg = '''    cfgFollowRedirects = document.getElementById("dalfox-cfg-follow-redirects");
    cfgDebug = document.getElementById("dalfox-cfg-debug");
    cfgBlind = document.getElementById("dalfox-cfg-blind");'''

new_init_cfg = '''    cfgFollowRedirects = document.getElementById("dalfox-cfg-follow-redirects");
    cfgDebug = document.getElementById("dalfox-cfg-debug");
    cfgBlind = document.getElementById("dalfox-cfg-blind");
    cfgWafEvasion = document.getElementById("dalfox-cfg-waf-evasion");
    cfgRemotePayloads = document.getElementById("dalfox-cfg-remote-payloads");'''

if old_init_cfg in dfx_code:
    dfx_code = dfx_code.replace(old_init_cfg, new_init_cfg)

# Add listeners in setupEvents
old_listeners = '[cfgRateLimit, cfgWorkers, cfgWaf, cfgMode, cfgFollowRedirects, cfgBlind].forEach(ctrl => {'
new_listeners = '[cfgRateLimit, cfgWorkers, cfgWaf, cfgWafEvasion, cfgRemotePayloads, cfgMode, cfgFollowRedirects, cfgDebug, cfgBlind].forEach(ctrl => {'

if old_listeners in dfx_code:
    dfx_code = dfx_code.replace(old_listeners, new_listeners)

# Update preview in updateCmdPreview
old_cmd_build = '''    if (cfgDebug && cfgDebug.checked) cmd += " --debug";
    if (bld) cmd += ` -b "${bld}"`;'''

new_cmd_build = '''    if (cfgWafEvasion && cfgWafEvasion.checked) cmd += " --waf-evasion";
    if (cfgRemotePayloads && cfgRemotePayloads.checked) cmd += " --remote-payloads portswigger,payloadbox";
    if (cfgDebug && cfgDebug.checked) cmd += " --debug";
    if (bld) cmd += ` -b "${bld}"`;'''

if old_cmd_build in dfx_code:
    dfx_code = dfx_code.replace(old_cmd_build, new_cmd_build)

# Update startScan payload
old_start_payload = '''        waf_bypass: cfgWaf?.value || "auto",
        scan_mode: cfgMode?.value || "standard",
        deep_scan: cfgMode?.value === "deep",
        skip_ast_analysis: cfgMode?.value === "fast",
        follow_redirects: cfgFollowRedirects ? cfgFollowRedirects.checked : true,
        debug: !!(cfgDebug && cfgDebug.checked),
        blind_url: (cfgBlind?.value || "").trim()'''

new_start_payload = '''        waf_bypass: cfgWaf?.value || "auto",
        waf_evasion: !!(cfgWafEvasion && cfgWafEvasion.checked),
        remote_payloads: !!(cfgRemotePayloads && cfgRemotePayloads.checked),
        scan_mode: cfgMode?.value || "standard",
        deep_scan: cfgMode?.value === "deep",
        skip_ast_analysis: cfgMode?.value === "fast",
        follow_redirects: cfgFollowRedirects ? cfgFollowRedirects.checked : true,
        debug: !!(cfgDebug && cfgDebug.checked),
        blind_url: (cfgBlind?.value || "").trim()'''

if old_start_payload in dfx_code:
    dfx_code = dfx_code.replace(old_start_payload, new_start_payload)

# Replace exportReport with openReportModal & add report modal handlers
old_export_fn = '''  async function exportReport() {
    if (state.findings.length === 0 && state.endpoints.length === 0) {
      window.showToast("No scan data available to generate report.", "warning");
      return;
    }

    try {
      window.showToast("Generating Standalone Dalfox HTML Report...", "info");
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: state.endpoints[0]?.url || "Target Web APIs",
          findings: state.findings,
          stats: {
            scanned_endpoints: state.endpoints.filter(e => e.status !== "Pending").length,
            total_findings: state.findings.length,
            verified_xss: state.findings.filter(f => f.type.includes("Verified")).length,
            dom_xss: state.findings.filter(f => f.type.includes("DOM")).length,
            stored_xss: state.findings.filter(f => f.type.includes("Stored")).length,
            reflected_xss: state.findings.filter(f => !f.type.includes("DOM") && !f.type.includes("Stored")).length,
          },
          open_in_browser: true,
          reveal_in_finder: true
        })
      });
      const data = await res.json();
      if (data.success) {
        window.showToast(`Report saved & opened: ${data.filename}`, "success");
      } else {
        window.showToast(data.error || "Failed to save report.", "error");
      }
    } catch (err) {
      window.showToast(`Report generation error: ${err.message}`, "error");
    }
  }'''

new_report_modal_fns = '''  function openReportModal() {
    if (state.findings.length === 0 && state.endpoints.length === 0) {
      window.showToast("No scan data available to generate report.", "warning");
      return;
    }

    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const targetUrl = state.endpoints[0]?.url || "Target Web APIs";
      const scannedCount = state.endpoints.filter(e => e.status !== "Pending").length;
      const vulnCount = state.findings.length;
      const verifiedCount = state.findings.filter(f => (f.type || "").includes("Verified")).length;
      summaryEl.innerHTML = `
        <div style="color:var(--text-main); margin-bottom:4px;"><strong>Target:</strong> ${window.escapeHtml(targetUrl)}</div>
        <div style="margin-bottom:4px;"><strong>Endpoints Scanned:</strong> ${scannedCount}</div>
        <div style="color:${vulnCount > 0 ? 'var(--neon-red)' : 'var(--neon-green)'};">
          <strong>Identified Vulnerabilities:</strong> ${vulnCount} ${vulnCount > 0 ? `🚨 (${verifiedCount} Verified XSS)` : '✅ (Target Safe)'}
        </div>
      `;
    }

    if (window.setReportPresetPath) {
      window.setReportPresetPath("downloads");
    }
    window.openModal("report-save-modal");
  }

  window.saveDalfoxReportToSelectedPath = async function(revealInFinder = true) {
    const pathInput = document.getElementById("report-custom-path");
    const chosenPath = pathInput?.value?.trim() || "~/Downloads";

    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: state.endpoints[0]?.url || "Target Web APIs",
          findings: state.findings,
          stats: {
            scanned_endpoints: state.endpoints.filter(e => e.status !== "Pending").length,
            total_findings: state.findings.length,
            verified_xss: state.findings.filter(f => (f.type || "").includes("Verified")).length,
            dom_xss: state.findings.filter(f => (f.type || "").includes("DOM")).length,
            stored_xss: state.findings.filter(f => (f.type || "").includes("Stored")).length,
            reflected_xss: state.findings.filter(f => !(f.type || "").includes("DOM") && !(f.type || "").includes("Stored")).length,
          },
          custom_path: chosenPath,
          reveal_in_finder: !!revealInFinder
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to save report");

      window.closeModal("report-save-modal");
      window.showToast(`✅ ${data.message || 'Report saved successfully!'} (Revealed in Finder)`, "success");
    } catch (err) {
      window.showToast(err.message, "error");
    }
  };

  window.openDalfoxReportInBrowser = async function() {
    const pathInput = document.getElementById("report-custom-path");
    const chosenPath = pathInput?.value?.trim() || "~/Downloads";

    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: state.endpoints[0]?.url || "Target Web APIs",
          findings: state.findings,
          stats: {
            scanned_endpoints: state.endpoints.filter(e => e.status !== "Pending").length,
            total_findings: state.findings.length,
            verified_xss: state.findings.filter(f => (f.type || "").includes("Verified")).length,
            dom_xss: state.findings.filter(f => (f.type || "").includes("DOM")).length,
            stored_xss: state.findings.filter(f => (f.type || "").includes("Stored")).length,
            reflected_xss: state.findings.filter(f => !(f.type || "").includes("DOM") && !(f.type || "").includes("Stored")).length,
          },
          custom_path: chosenPath,
          open_in_browser: true
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to open report");

      window.closeModal("report-save-modal");
      window.showToast(`🌐 Report opened in default browser!`, "success");
    } catch (err) {
      window.showToast(err.message, "error");
    }
  };'''

if old_export_fn in dfx_code:
    dfx_code = dfx_code.replace(old_export_fn, new_report_modal_fns)

# Wire btnSaveReport to openReportModal instead of exportReport
old_btn_save = 'if (btnSaveReport) btnSaveReport.addEventListener("click", exportReport);'
new_btn_save = 'if (btnSaveReport) btnSaveReport.addEventListener("click", openReportModal);'
if old_btn_save in dfx_code:
    dfx_code = dfx_code.replace(old_btn_save, new_btn_save)

# Variable declaration at top
if "cfgWafEvasion" not in dfx_code:
    dfx_code = dfx_code.replace(
        "cfgBlind,",
        "cfgBlind, cfgWafEvasion, cfgRemotePayloads,"
    )

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(dfx_code)
print("dalfox.js updated successfully!")

