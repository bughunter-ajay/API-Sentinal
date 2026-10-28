# 1. Patch app.js
with open("UltronScan/ui/js/app.js", "r", encoding="utf-8") as f:
    app_code = f.read()

old_open_modal = '''// Modal helpers
window.openModal = function(modalId) {
  if (modalId === "curl-modal" && window.isUltronScanning && window.isUltronScanning()) {
    window.showToast("Cannot import cURL while scan is in progress! Please stop the scan first.", "error");
    return;
  }
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add("open");
};'''

new_open_modal = '''// Modal helpers
window.openModal = function(modalId) {
  if (modalId === "curl-modal") {
    const curTool = window.appState?.activeTool || "sqlmap";
    let isCurrentToolScanning = false;
    if (curTool === "sqlmap" && window.isSqlmapScanning) isCurrentToolScanning = window.isSqlmapScanning();
    else if (curTool === "commix" && window.isCommixScanning) isCurrentToolScanning = window.isCommixScanning();
    else if (curTool === "arjun" && window.isArjunScanning) isCurrentToolScanning = window.isArjunScanning();
    else if (curTool === "dalfox" && window.isDalfoxScanning) isCurrentToolScanning = window.isDalfoxScanning();

    if (isCurrentToolScanning) {
      window.showToast(`Cannot import cURL while ${curTool.toUpperCase()} scan is in progress! Please stop the scan first.`, "error");
      return;
    }
  }
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add("open");
};'''

assert old_open_modal in app_code, "Could not find old_open_modal in app.js"
app_code = app_code.replace(old_open_modal, new_open_modal)

with open("UltronScan/ui/js/app.js", "w", encoding="utf-8") as f:
    f.write(app_code)
print("app.js patched successfully!")

# 2. Patch dalfox.js
with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    dfx_code = f.read()

old_update_scroll_ui = '''  function updateAutoScrollUI() {
    if (!btnAutoScroll) return;
    if (state.autoScroll) {
      btnAutoScroll.textContent = "Scroll: ON";
      btnAutoScroll.style.color = "var(--neon-green)";
      btnAutoScroll.style.borderColor = "var(--neon-green)";
    } else {
      btnAutoScroll.textContent = "Scroll: OFF";
      btnAutoScroll.style.color = "var(--text-muted)";
      btnAutoScroll.style.borderColor = "var(--border-dim)";
    }
  }'''

new_update_scroll_ui = '''  function updateAutoScrollUI() {
    if (!btnAutoScroll) return;
    btnAutoScroll.textContent = "Scroll";
    if (state.autoScroll) {
      btnAutoScroll.style.color = "var(--neon-green)";
      btnAutoScroll.style.borderColor = "rgba(0, 255, 170, 0.45)";
      btnAutoScroll.style.background = "rgba(0, 255, 170, 0.08)";
    } else {
      btnAutoScroll.style.color = "var(--text-muted)";
      btnAutoScroll.style.borderColor = "var(--border-dim)";
      btnAutoScroll.style.background = "transparent";
    }
  }'''

assert old_update_scroll_ui in dfx_code, "Could not find old_update_scroll_ui in dalfox.js"
dfx_code = dfx_code.replace(old_update_scroll_ui, new_update_scroll_ui)

# Update progress pill to only show time
old_pill_line = 'scanProgressBadge.textContent = `${s.scanned_endpoints}/${s.total_endpoints} · ${formatScanTime(s.elapsed_seconds)}`;'
new_pill_line = 'scanProgressBadge.textContent = formatScanTime(s.elapsed_seconds);'

assert old_pill_line in dfx_code, "Could not find old_pill_line in dalfox.js"
dfx_code = dfx_code.replace(old_pill_line, new_pill_line)

# Add window.isDalfoxScanning
if "window.isDalfoxScanning" not in dfx_code:
    dfx_code = dfx_code.replace(
        "  // Hook into global scanning check",
        "  window.isDalfoxScanning = () => !!state.isScanning;\n\n  // Hook into global scanning check"
    )

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(dfx_code)
print("dalfox.js patched successfully!")

# 3. Patch index.html
with open("UltronScan/ui/index.html", "r", encoding="utf-8") as f:
    html_code = f.read()

old_scroll_btn = '''                  <button class="cyber-btn secondary" id="btn-dalfox-auto-scroll" style="color:var(--neon-green);" title="Toggle Auto-Scroll">
                    Scroll: ON
                  </button>'''

new_scroll_btn = '''                  <button class="cyber-btn secondary" id="btn-dalfox-auto-scroll" style="color:var(--neon-green); background:rgba(0,255,170,0.08); border-color:rgba(0,255,170,0.45);" title="Toggle Auto-Scroll">
                    Scroll
                  </button>'''

assert old_scroll_btn in html_code, "Could not find old_scroll_btn in index.html"
html_code = html_code.replace(old_scroll_btn, new_scroll_btn)

with open("UltronScan/ui/index.html", "w", encoding="utf-8") as f:
    f.write(html_code)
print("index.html patched successfully!")

