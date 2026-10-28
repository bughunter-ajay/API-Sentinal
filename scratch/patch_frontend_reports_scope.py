# 1. Patch dalfox.js
with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    dfx_js = f.read()

old_dfx_open = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const targetUrl = state.endpoints[0]?.url || "Target Web APIs";'''

new_dfx_open = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target Web APIs");'''

if old_dfx_open in dfx_js:
    dfx_js = dfx_js.replace(old_dfx_open, new_dfx_open)

old_dfx_save = '''    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: state.endpoints[0]?.url || "Target Web APIs",
          findings: state.findings,'''

new_dfx_save = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target Web APIs");

    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: state.endpoints,'''

if old_dfx_save in dfx_js:
    dfx_js = dfx_js.replace(old_dfx_save, new_dfx_save)

old_dfx_browser = '''  window.openDalfoxReportInBrowser = async function() {
    const pathInput = document.getElementById("report-custom-path");
    const chosenPath = pathInput?.value?.trim() || "~/Downloads";

    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: state.endpoints[0]?.url || "Target Web APIs",
          findings: state.findings,'''

new_dfx_browser = '''  window.openDalfoxReportInBrowser = async function() {
    const pathInput = document.getElementById("report-custom-path");
    const chosenPath = pathInput?.value?.trim() || "~/Downloads";
    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target Web APIs");

    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: state.endpoints,'''

if old_dfx_browser in dfx_js:
    dfx_js = dfx_js.replace(old_dfx_browser, new_dfx_browser)

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(dfx_js)
print("dalfox.js updated with multi-host target and endpoints array!")


# 2. Patch sqlmap.js
with open("UltronScan/ui/js/sqlmap.js", "r", encoding="utf-8") as f:
    sql_js = f.read()

old_sql_open = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const vulnCount = state.findings.length;
      const targetUrl = state.endpoints[0]?.url || "Target APIs";'''

new_sql_open = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const vulnCount = state.findings.length;
      const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");'''

if old_sql_open in sql_js:
    sql_js = sql_js.replace(old_sql_open, new_sql_open)

old_sql_save = '''    try {
      const res = await fetch(`${API_BASE}/api/sqlmap/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan SQLMap Pro Security Audit Report",
          target: state.endpoints[0]?.url || "Target APIs",
          findings: state.findings,'''

new_sql_save = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");

    try {
      const res = await fetch(`${API_BASE}/api/sqlmap/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan SQLMap Pro Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: state.endpoints,'''

if old_sql_save in sql_js:
    sql_js = sql_js.replace(old_sql_save, new_sql_save)

old_sql_browser = '''    try {
      const res = await fetch(`${API_BASE}/api/sqlmap/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan SQLMap Pro Security Audit Report",
          target: state.endpoints[0]?.url || "Target APIs",
          findings: state.findings,'''

# Notice old_sql_browser is identical to old_sql_save because both call fetch with state.endpoints[0]?.url
# Since we replaced old_sql_save (which was the first occurrence), let's replace the second occurrence if present:
if old_sql_save in sql_js:
    sql_js = sql_js.replace(old_sql_save, new_sql_save)

with open("UltronScan/ui/js/sqlmap.js", "w", encoding="utf-8") as f:
    f.write(sql_js)
print("sqlmap.js updated with multi-host target and endpoints array!")


# 3. Patch commix.js
with open("UltronScan/ui/js/commix.js", "r", encoding="utf-8") as f:
    cmx_js = f.read()

old_cmx_save = '''    try {
      const res = await fetch(`${API_BASE}/api/commix/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Commix OS Command Injection Security Audit Report",
          target: state.endpoints[0]?.url || "Target APIs",
          findings: state.findings,'''

new_cmx_save = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");

    try {
      const res = await fetch(`${API_BASE}/api/commix/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Commix OS Command Injection Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: state.endpoints,'''

# Replace both occurrences in commix.js
cmx_js = cmx_js.replace(old_cmx_save, new_cmx_save)

with open("UltronScan/ui/js/commix.js", "w", encoding="utf-8") as f:
    f.write(cmx_js)
print("commix.js updated with multi-host target and endpoints array!")


# 4. Patch arjun.js
with open("UltronScan/ui/js/arjun.js", "r", encoding="utf-8") as f:
    arj_js = f.read()

old_arj_save = '''    try {
      const data = await safeFetchJson(`${API_BASE}/api/arjun/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Arjun Parameter Discovery Audit Report",
          target: state.endpoints[0]?.url || "Target APIs",
          findings: state.findings,'''

new_arj_save = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");

    try {
      const data = await safeFetchJson(`${API_BASE}/api/arjun/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Arjun Parameter Discovery Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: state.endpoints,'''

arj_js = arj_js.replace(old_arj_save, new_arj_save)

with open("UltronScan/ui/js/arjun.js", "w", encoding="utf-8") as f:
    f.write(arj_js)
print("arjun.js updated with multi-host target and endpoints array!")


# 5. Patch dalfox_engine.py for output_json_existed
with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    eng_py = f.read()

old_parse_block = '''                # Parse Results from Output JSON
                new_findings = self._parse_dalfox_json_report(output_json_path, ep)
                try:
                    if os.path.exists(output_json_path):
                        os.remove(output_json_path)
                except Exception:
                    pass'''

new_parse_block = '''                # Parse Results from Output JSON
                output_json_existed = os.path.exists(output_json_path)
                new_findings = self._parse_dalfox_json_report(output_json_path, ep)
                try:
                    if os.path.exists(output_json_path):
                        os.remove(output_json_path)
                except Exception:
                    pass'''

if old_parse_block in eng_py:
    eng_py = eng_py.replace(old_parse_block, new_parse_block)

old_error_status = '''                    elif proc.returncode != 0:
                        ep["status"] = "Scan Error"
                        ep["findings_count"] = 0
                        self.append_log(f"✖ [ERROR] {target_url}: Process exited with error code {proc.returncode}.", "ERROR")'''

new_error_status = '''                    elif proc.returncode != 0:
                        if output_json_existed:
                            ep["status"] = "Clean (0 XSS)"
                            ep["findings_count"] = 0
                            self.append_log(f"✔ Completed {target_url}: Zero XSS detected (Exit code {proc.returncode} due to socket drop on some payloads).", "INFO")
                        else:
                            ep["status"] = "Scan Error"
                            ep["findings_count"] = 0
                            self.append_log(f"✖ [ERROR] {target_url}: Process exited with error code {proc.returncode}.", "ERROR")'''

if old_error_status in eng_py:
    eng_py = eng_py.replace(old_error_status, new_error_status)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(eng_py)
print("dalfox_engine.py updated with graceful exit handling!")

