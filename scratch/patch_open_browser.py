# 1. Patch main.py
with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    main_code = f.read()

open_url_endpoint = '''class OpenUrlReq(BaseModel):
    url: str

@app.post("/api/system/open-url")
def open_url_in_default_browser(req: OpenUrlReq):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty URL")
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", url])
        elif sys.platform == "win32":
            os.startfile(url)
        else:
            subprocess.Popen(["xdg-open", url])
        return {"success": True, "url": url}
    except Exception as e:
        return {"success": False, "error": str(e)}

'''

if "/api/system/open-url" not in main_code:
    main_code = main_code.replace(
        "# Mount UI directory",
        open_url_endpoint + "# Mount UI directory"
    )

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(main_code)
print("main.py patched with /api/system/open-url!")

# 2. Patch app.js
with open("UltronScan/ui/js/app.js", "r", encoding="utf-8") as f:
    app_code = f.read()

open_external_helper = '''window.openExternalUrl = async function(url) {
  if (!url) return;
  try {
    await navigator.clipboard.writeText(url);
  } catch (e) {}

  try {
    const res = await fetch(`${API_BASE}/api/system/open-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    const data = await res.json();
    if (data.success) {
      window.showToast("🌐 Opened exploit URL in default browser!", "success");
      return;
    }
  } catch (err) {}

  window.showToast("📋 Exploit URL copied to clipboard! (Paste in browser)", "info");
};
'''

if "window.openExternalUrl" not in app_code:
    app_code += "\n" + open_external_helper

with open("UltronScan/ui/js/app.js", "w", encoding="utf-8") as f:
    f.write(app_code)
print("app.js patched with window.openExternalUrl!")

# 3. Patch dalfox.js
with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    dfx_code = f.read()

old_findings_render = '''    let html = "";
    state.findings.forEach((f) => {
      const sevClass = (f.severity || "HIGH").toLowerCase();
      html += `
        <div class="vuln-card" style="margin-bottom:12px;">
          <div class="vuln-card-head">
            <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <span class="badge-num badge-${sevClass}">${f.severity || "HIGH"}</span>
              <span style="color:#bf5af2; font-weight:700; font-size:11px;">⚡ ${window.escapeHtml(f.type)}</span>
              <span style="color:#9bbcd9; font-size:11px; font-family:var(--font-mono);">Param: <code>${window.escapeHtml(f.param)}</code></span>
              <span class="method-badge ${f.method}">${f.method}</span>
            </div>
            <span style="font-size:11px; color:var(--text-muted);">${f.timestamp}</span>
          </div>

          <div style="font-family:var(--font-mono); font-size:12px; margin-bottom:8px; word-break:break-all;">
            <a href="${window.escapeHtml(f.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--neon-cyan); text-decoration:none;">${window.escapeHtml(f.url)} ↗</a>
          </div>

          ${f.evidence ? `<div style="background:rgba(0,0,0,0.3); border-left:3px solid var(--neon-cyan); padding:6px 10px; font-family:var(--font-mono); font-size:11.5px; border-radius:3px; margin-bottom:8px;"><strong>Evidence:</strong> <code>${window.escapeHtml(f.evidence)}</code></div>` : ""}

          <div style="background:#04080e; border:1px solid var(--border-dim); border-radius:4px; padding:8px 10px; margin-bottom:8px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; color:var(--text-muted); font-size:10.5px;">
              <span>🎯 Injected Payload</span>
              <button class="cyber-btn secondary" style="font-size:10px; padding:1px 6px;" onclick="window.copyDalfoxSnippet('${window.escapeHtml(f.payload)}', this)">📋 Copy</button>
            </div>
            <code style="color:#00ff66; font-family:var(--font-mono); font-size:11.5px; word-break:break-all;">${window.escapeHtml(f.payload)}</code>
          </div>

          <div style="display:flex; gap:8px;">
            <button class="cyber-btn secondary" style="font-size:11px; padding:3px 10px;" onclick="window.copyDalfoxSnippet('${window.escapeHtml(f.poc_curl)}', this)">
              📋 Copy PoC cURL
            </button>
            <button class="cyber-btn secondary" style="font-size:11px; padding:3px 10px;" onclick="window.open('${window.escapeHtml(f.url)}', '_blank')">
              🌐 Open in Browser ↗
            </button>
          </div>
        </div>
      `;
    });'''

new_findings_render = '''    let html = "";
    state.findings.forEach((f) => {
      const sevClass = (f.severity || "HIGH").toLowerCase();
      const exploitUrl = (f.payload && f.payload.startsWith("http")) ? f.payload : f.url;
      html += `
        <div class="vuln-card" style="margin-bottom:12px;">
          <div class="vuln-card-head">
            <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <span class="badge-num badge-${sevClass}">${f.severity || "HIGH"}</span>
              <span style="color:#bf5af2; font-weight:700; font-size:11px;">⚡ ${window.escapeHtml(f.type)}</span>
              <span style="color:#9bbcd9; font-size:11px; font-family:var(--font-mono);">Param: <code>${window.escapeHtml(f.param)}</code></span>
              <span class="method-badge ${f.method}">${f.method}</span>
            </div>
            <span style="font-size:11px; color:var(--text-muted);">${f.timestamp}</span>
          </div>

          <div style="font-family:var(--font-mono); font-size:12px; margin-bottom:8px; word-break:break-all;">
            <a href="javascript:void(0)" onclick="window.openExternalUrl('${window.escapeHtml(exploitUrl)}')" style="color:var(--neon-cyan); text-decoration:none;">${window.escapeHtml(f.url)} ↗</a>
          </div>

          ${f.evidence ? `<div style="background:rgba(0,0,0,0.3); border-left:3px solid var(--neon-cyan); padding:6px 10px; font-family:var(--font-mono); font-size:11.5px; border-radius:3px; margin-bottom:8px;"><strong>Evidence:</strong> <code>${window.escapeHtml(f.evidence)}</code></div>` : ""}

          <div style="background:#04080e; border:1px solid var(--border-dim); border-radius:4px; padding:8px 10px; margin-bottom:8px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; color:var(--text-muted); font-size:10.5px;">
              <span>🎯 Injected Payload</span>
              <button class="cyber-btn secondary" style="font-size:10px; padding:1px 6px;" onclick="window.copyDalfoxSnippet('${window.escapeHtml(f.payload)}', this)">📋 Copy</button>
            </div>
            <code style="color:#00ff66; font-family:var(--font-mono); font-size:11.5px; word-break:break-all;">${window.escapeHtml(f.payload)}</code>
          </div>

          <div style="display:flex; gap:8px;">
            <button class="cyber-btn secondary" style="font-size:11px; padding:3px 10px;" onclick="window.copyDalfoxSnippet('${window.escapeHtml(f.poc_curl)}', this)">
              📋 Copy PoC cURL
            </button>
            <button class="cyber-btn secondary" style="font-size:11px; padding:3px 10px;" onclick="window.openExternalUrl('${window.escapeHtml(exploitUrl)}')">
              🌐 Open in Browser ↗
            </button>
          </div>
        </div>
      `;
    });'''

assert old_findings_render in dfx_code, "Could not find old_findings_render in dalfox.js"
dfx_code = dfx_code.replace(old_findings_render, new_findings_render)

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(dfx_code)
print("dalfox.js patched with openExternalUrl!")

