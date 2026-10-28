import re

# ========================================================
# 1. Patch sqlmap.js for Dalfox Report Modal Hooks
# ========================================================
with open("UltronScan/ui/js/sqlmap.js", "r", encoding="utf-8") as f:
    sqlmap_js = f.read()

# Update toolPrefix in setReportPresetPath
old_preset = 'const toolPrefix = (active === "commix") ? "commix" : (active === "arjun" ? "arjun" : "sqlmap");'
new_preset = 'const toolPrefix = (active === "commix") ? "commix" : (active === "arjun" ? "arjun" : (active === "dalfox" ? "dalfox" : "sqlmap"));'
assert old_preset in sqlmap_js, "Could not find old_preset in sqlmap.js"
sqlmap_js = sqlmap_js.replace(old_preset, new_preset)

# Update saveReportToSelectedPath
old_save_hook = '''  window.saveReportToSelectedPath = async function(revealInFinder = true) {
    if (window.appState && window.appState.activeTool === "commix" && window.saveCommixReportToSelectedPath) {
      return window.saveCommixReportToSelectedPath(revealInFinder);
    }
    if (window.appState && window.appState.activeTool === "arjun" && window.saveArjunReportToSelectedPath) {
      return window.saveArjunReportToSelectedPath(revealInFinder);
    }'''

new_save_hook = '''  window.saveReportToSelectedPath = async function(revealInFinder = true) {
    if (window.appState && window.appState.activeTool === "commix" && window.saveCommixReportToSelectedPath) {
      return window.saveCommixReportToSelectedPath(revealInFinder);
    }
    if (window.appState && window.appState.activeTool === "arjun" && window.saveArjunReportToSelectedPath) {
      return window.saveArjunReportToSelectedPath(revealInFinder);
    }
    if (window.appState && window.appState.activeTool === "dalfox" && window.saveDalfoxReportToSelectedPath) {
      return window.saveDalfoxReportToSelectedPath(revealInFinder);
    }'''
assert old_save_hook in sqlmap_js, "Could not find old_save_hook in sqlmap.js"
sqlmap_js = sqlmap_js.replace(old_save_hook, new_save_hook)

# Update openReportInBrowser
old_open_hook = '''  window.openReportInBrowser = async function() {
    if (window.appState && window.appState.activeTool === "commix" && window.openCommixReportInBrowser) {
      return window.openCommixReportInBrowser();
    }
    if (window.appState && window.appState.activeTool === "arjun" && window.openArjunReportInBrowser) {
      return window.openArjunReportInBrowser();
    }'''

new_open_hook = '''  window.openReportInBrowser = async function() {
    if (window.appState && window.appState.activeTool === "commix" && window.openCommixReportInBrowser) {
      return window.openCommixReportInBrowser();
    }
    if (window.appState && window.appState.activeTool === "arjun" && window.openArjunReportInBrowser) {
      return window.openArjunReportInBrowser();
    }
    if (window.appState && window.appState.activeTool === "dalfox" && window.openDalfoxReportInBrowser) {
      return window.openDalfoxReportInBrowser();
    }'''
assert old_open_hook in sqlmap_js, "Could not find old_open_hook in sqlmap.js"
sqlmap_js = sqlmap_js.replace(old_open_hook, new_open_hook)

with open("UltronScan/ui/js/sqlmap.js", "w", encoding="utf-8") as f:
    f.write(sqlmap_js)
print("sqlmap.js patched successfully!")


# ========================================================
# 2. Patch backend/main.py (Collapsible Report + Evasion/Remote Payloads Req)
# ========================================================
with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    main_py = f.read()

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

assert old_start_req in main_py, "Could not find old_start_req in main.py"
main_py = main_py.replace(old_start_req, new_start_req)

# Overhaul generate_dalfox_standalone_report
old_report_cards = '''            <div class="code-box">
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

new_report_cards = '''            <details class="collapsible-box" open>
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

assert old_report_cards in main_py, "Could not find old_report_cards in main.py"
main_py = main_py.replace(old_report_cards, new_report_cards)

# Update copySnippet script function
old_copy_func = '''    <script>
        function copySnippet(btn, id) {
            const el = document.getElementById(id);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText || el.textContent).then(() => {
                const orig = btn.innerText;
                btn.innerText = "✔ Copied!";
                setTimeout(() => { btn.innerText = orig; }, 2000);
            });
        }
    </script>'''

new_copy_func = '''    <script>
        function copySnippet(btn, id, event) {
            if (event) {
                event.stopPropagation();
                event.preventDefault();
            }
            const el = document.getElementById(id);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText || el.textContent).then(() => {
                const orig = btn.innerText;
                btn.innerText = "✔ Copied!";
                setTimeout(() => { btn.innerText = orig; }, 2000);
            });
        }
    </script>'''

assert old_copy_func in main_py, "Could not find old_copy_func in main.py"
main_py = main_py.replace(old_copy_func, new_copy_func)

# Add CSS for .collapsible-box and text wrap
old_css_code_box = '''.code-box {
            background: var(--bg-code);
            border: 1px solid #14202e;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
        }
        .code-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; color: var(--text-dim); font-size: 11px; }'''

new_css_code_box = '''.collapsible-box {
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

assert old_css_code_box in main_py, "Could not find old_css_code_box in main.py"
main_py = main_py.replace(old_css_code_box, new_css_code_box)

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(main_py)
print("main.py patched successfully!")

# ========================================================
# 3. Patch backend/dalfox_engine.py (CLI flags for WAF Evasion & Remote Payloads)
# ========================================================
with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    engine_py = f.read()

old_cfg_read = '''            blind_url = str(config.get("blind_url") or "").strip()
            proxy = str(config.get("proxy") or "").strip()
            debug_mode = bool(config.get("debug", False))'''

new_cfg_read = '''            blind_url = str(config.get("blind_url") or "").strip()
            proxy = str(config.get("proxy") or "").strip()
            debug_mode = bool(config.get("debug", False))
            waf_evasion = bool(config.get("waf_evasion", False))
            remote_payloads = bool(config.get("remote_payloads", False))'''

assert old_cfg_read in engine_py, "Could not find old_cfg_read in dalfox_engine.py"
engine_py = engine_py.replace(old_cfg_read, new_cfg_read)

old_waf_bypass_cmd = '''                # WAF Bypass
                if waf_bypass in ["auto", "force", "off"]:
                    cmd.extend(["--waf-bypass", waf_bypass])'''

new_waf_bypass_cmd = '''                # WAF Bypass & Evasion
                if waf_bypass in ["auto", "force", "off"]:
                    cmd.extend(["--waf-bypass", waf_bypass])
                if waf_evasion:
                    cmd.append("--waf-evasion")
                if remote_payloads:
                    cmd.extend(["--remote-payloads", "portswigger,payloadbox"])'''

assert old_waf_bypass_cmd in engine_py, "Could not find old_waf_bypass_cmd in dalfox_engine.py"
engine_py = engine_py.replace(old_waf_bypass_cmd, new_waf_bypass_cmd)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(engine_py)
print("dalfox_engine.py patched successfully!")

