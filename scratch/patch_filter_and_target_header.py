import re

# ==============================================================
# 1. Update backend/main.py build_report_scope_html
# ==============================================================
with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    main_code = f.read()

old_scope_helper_body = '''    if not endpoints:
        return target, ""

    # 1. Compute multi-host Target Surface label
    hosts = []
    for ep in endpoints:
        u = ep.get("url") or ""
        if u:
            try:
                h = urllib.parse.urlsplit(u).netloc
                if h and h not in hosts:
                    hosts.append(h)
            except Exception:
                pass

    if len(hosts) > 1:
        display_target = f"{len(hosts)} Target Hosts ({', '.join(hosts)}) • {len(endpoints)} Endpoints"
    elif len(hosts) == 1:
        display_target = f"{hosts[0]} • {len(endpoints)} Endpoint{'s' if len(endpoints) > 1 else ''}"
    else:
        display_target = target

    # 2. Build rows for each audited endpoint
    scope_rows = ""
    for idx, ep in enumerate(endpoints, 1):'''

new_scope_helper_body = '''    if not endpoints:
        return target, ""

    # Filter out unchecked / pending endpoints that were never scanned
    audited_endpoints = []
    for ep in (endpoints or []):
        st = str(ep.get("status", "")).strip().lower()
        sel = ep.get("selected", True)
        if st in ("pending", "wait", "skipped"):
            continue
        if not sel and (not st or st == "pending"):
            continue
        audited_endpoints.append(ep)

    # Fallback to selected endpoints if scan status is not set yet
    if not audited_endpoints:
        audited_endpoints = [ep for ep in (endpoints or []) if ep.get("selected", True)]
    if not audited_endpoints:
        audited_endpoints = endpoints or []

    # 1. Compute Target Surface label (just "N Target Hosts", no parenthesized listing)
    hosts = []
    for ep in audited_endpoints:
        u = ep.get("url") or ""
        if u:
            try:
                h = urllib.parse.urlsplit(u).netloc
                if h and h not in hosts:
                    hosts.append(h)
            except Exception:
                pass

    if len(hosts) > 1:
        display_target = f"{len(hosts)} Target Hosts"
    elif len(hosts) == 1:
        display_target = hosts[0]
    else:
        display_target = target

    # 2. Build rows for each actually audited endpoint
    scope_rows = ""
    for idx, ep in enumerate(audited_endpoints, 1):'''

assert old_scope_helper_body in main_code, "Could not find old_scope_helper_body in main.py"
main_code = main_code.replace(old_scope_helper_body, new_scope_helper_body)

# Also update the card title count to use audited_endpoints
old_badge_count = '<span class="scope-count-badge">{len(endpoints)} Target APIs</span>'
new_badge_count = '<span class="scope-count-badge">{len(audited_endpoints)} Target APIs</span>'
assert old_badge_count in main_code, "Could not find old_badge_count in main.py"
main_code = main_code.replace(old_badge_count, new_badge_count)

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(main_code)
print("main.py build_report_scope_html updated successfully!")


# ==============================================================
# 2. Update dalfox.js
# ==============================================================
with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    dfx_js = f.read()

# openReportModal
old_dfx_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target Web APIs");'''

new_dfx_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedEps = state.endpoints.filter(e => e.selected && e.status && e.status !== "Pending");
      const auditedList = scannedEps.length > 0 ? scannedEps : state.endpoints.filter(e => e.selected);
      const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target Web APIs");'''

if old_dfx_modal in dfx_js:
    dfx_js = dfx_js.replace(old_dfx_modal, new_dfx_modal)

# saveDalfoxReportToSelectedPath & openDalfoxReportInBrowser
old_dfx_dispatch = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
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

new_dfx_dispatch = '''    const scannedEps = state.endpoints.filter(e => e.selected && e.status && e.status !== "Pending");
    const auditedList = scannedEps.length > 0 ? scannedEps : state.endpoints.filter(e => e.selected);
    const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target Web APIs");

    try {
      const res = await fetch(`${API_BASE}/api/dalfox/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Dalfox XSS Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: auditedList,'''

dfx_js = dfx_js.replace(old_dfx_dispatch, new_dfx_dispatch)

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(dfx_js)
print("dalfox.js updated!")


# ==============================================================
# 3. Update sqlmap.js
# ==============================================================
with open("UltronScan/ui/js/sqlmap.js", "r", encoding="utf-8") as f:
    sql_js = f.read()

old_sql_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const vulnCount = state.findings.length;
      const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Hosts (${hosts.join(", ")})` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");'''

new_sql_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const vulnCount = state.findings.length;
      const auditedList = state.endpoints.filter(e => e.selected && e.status !== "skipped");
      const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");'''

if old_sql_modal in sql_js:
    sql_js = sql_js.replace(old_sql_modal, new_sql_modal)

old_sql_dispatch = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
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

new_sql_dispatch = '''    const auditedList = state.endpoints.filter(e => e.selected && e.status !== "skipped");
    const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");

    try {
      const res = await fetch(`${API_BASE}/api/sqlmap/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan SQLMap Pro Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: auditedList,'''

sql_js = sql_js.replace(old_sql_dispatch, new_sql_dispatch)

with open("UltronScan/ui/js/sqlmap.js", "w", encoding="utf-8") as f:
    f.write(sql_js)
print("sqlmap.js updated!")


# ==============================================================
# 4. Update commix.js
# ==============================================================
with open("UltronScan/ui/js/commix.js", "r", encoding="utf-8") as f:
    cmx_js = f.read()

old_cmx_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const vulnCount = state.findings.length;
      const targetUrl = state.endpoints[0]?.url || "Target APIs";'''

new_cmx_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const auditedList = state.endpoints.filter(e => e.selected);
      const scannedCount = auditedList.length;
      const vulnCount = state.findings.length;
      const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");'''

if old_cmx_modal in cmx_js:
    cmx_js = cmx_js.replace(old_cmx_modal, new_cmx_modal)

old_cmx_dispatch = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
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

new_cmx_dispatch = '''    const auditedList = state.endpoints.filter(e => e.selected);
    const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");

    try {
      const res = await fetch(`${API_BASE}/api/commix/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Commix OS Command Injection Security Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: auditedList,'''

cmx_js = cmx_js.replace(old_cmx_dispatch, new_cmx_dispatch)

with open("UltronScan/ui/js/commix.js", "w", encoding="utf-8") as f:
    f.write(cmx_js)
print("commix.js updated!")


# ==============================================================
# 5. Update arjun.js
# ==============================================================
with open("UltronScan/ui/js/arjun.js", "r", encoding="utf-8") as f:
    arj_js = f.read()

old_arj_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const scannedCount = state.endpoints.filter(e => e.selected).length;
      const discoveredCount = state.findings.reduce((acc, f) => acc + (f.discovered_params?.length || 0), 0);
      const targetUrl = state.endpoints[0]?.url || "Target APIs";'''

new_arj_modal = '''    const summaryEl = document.getElementById("report-modal-summary");
    if (summaryEl) {
      const auditedList = state.endpoints.filter(e => e.selected);
      const scannedCount = auditedList.length;
      const discoveredCount = state.findings.reduce((acc, f) => acc + (f.discovered_params?.length || 0), 0);
      const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
      const targetUrl = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");'''

if old_arj_modal in arj_js:
    arj_js = arj_js.replace(old_arj_modal, new_arj_modal)

old_arj_dispatch = '''    const hosts = [...new Set(state.endpoints.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
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

new_arj_dispatch = '''    const auditedList = state.endpoints.filter(e => e.selected);
    const hosts = [...new Set(auditedList.map(e => { try { return new URL(e.url).host; } catch(err){ return e.url; } }))];
    const targetLabel = hosts.length > 1 ? `${hosts.length} Target Hosts` : (hosts[0] || state.endpoints[0]?.url || "Target APIs");

    try {
      const data = await safeFetchJson(`${API_BASE}/api/arjun/save-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "UltronScan Arjun Parameter Discovery Audit Report",
          target: targetLabel,
          findings: state.findings,
          endpoints: auditedList,'''

arj_js = arj_js.replace(old_arj_dispatch, new_arj_dispatch)

with open("UltronScan/ui/js/arjun.js", "w", encoding="utf-8") as f:
    f.write(arj_js)
print("arjun.js updated!")

