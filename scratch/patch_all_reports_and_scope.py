import re

# ==============================================================
# 1. Update UltronScan/backend/main.py
# ==============================================================
with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    main_py = f.read()

# Add endpoints to Pydantic models
main_py = main_py.replace(
    'class SaveReportReq(BaseModel):\n    title: str = "UltronScan SQLMap Security Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False',
    'class SaveReportReq(BaseModel):\n    title: str = "UltronScan SQLMap Security Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    endpoints: Optional[List[Dict[str, Any]]] = None\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False'
)

main_py = main_py.replace(
    'class SaveCommixReportReq(BaseModel):\n    title: str = "UltronScan Commix OS Command Injection Security Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False',
    'class SaveCommixReportReq(BaseModel):\n    title: str = "UltronScan Commix OS Command Injection Security Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    endpoints: Optional[List[Dict[str, Any]]] = None\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False'
)

main_py = main_py.replace(
    'class SaveArjunReportReq(BaseModel):\n    title: str = "UltronScan Arjun Hidden Parameter Discovery Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False',
    'class SaveArjunReportReq(BaseModel):\n    title: str = "UltronScan Arjun Hidden Parameter Discovery Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    endpoints: Optional[List[Dict[str, Any]]] = None\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False'
)

main_py = main_py.replace(
    'class SaveDalfoxReportReq(BaseModel):\n    title: str = "UltronScan Dalfox XSS Security Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False',
    'class SaveDalfoxReportReq(BaseModel):\n    title: str = "UltronScan Dalfox XSS Security Audit Report"\n    target: str = "Target APIs"\n    findings: List[Dict[str, Any]]\n    stats: Dict[str, Any]\n    endpoints: Optional[List[Dict[str, Any]]] = None\n    custom_path: Optional[str] = None\n    reveal_in_finder: bool = False\n    open_in_browser: bool = False'
)

# Route handlers passing req.endpoints
main_py = main_py.replace(
    "html = generate_standalone_report(req.title, req.target, req.findings, req.stats)",
    "html = generate_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
)
main_py = main_py.replace(
    "html = generate_commix_standalone_report(req.title, req.target, req.findings, req.stats)",
    "html = generate_commix_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
)
main_py = main_py.replace(
    "html_content = generate_arjun_standalone_report(req.title, req.target, req.findings, req.stats)",
    "html_content = generate_arjun_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
)
main_py = main_py.replace(
    "html_content = generate_dalfox_standalone_report(req.title, req.target, req.findings, req.stats)",
    "html_content = generate_dalfox_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
)

# Helper function build_report_scope_html
scope_helper_code = '''
# ----------------- Shared Report Scope Helper -----------------
def build_report_scope_html(endpoints: Optional[List[Dict[str, Any]]], findings: List[Dict[str, Any]], target: str, tool_name: str = "generic") -> Tuple[str, str]:
    """
    Computes a comprehensive target surface string (listing all unique hosts/domains)
    and constructs the '📋 Audited Endpoints & Scope Summary' HTML table.
    """
    if not endpoints:
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
    for idx, ep in enumerate(endpoints, 1):
        method = html.escape((ep.get("method") or "GET").upper())
        ep_url = ep.get("url") or ""
        ep_url_esc = html.escape(ep_url)
        
        # Determine params display
        p_names = ep.get("param_names") or []
        if not p_names and ep.get("params"):
            p_names = [p.get("name") if isinstance(p, dict) else str(p) for p in ep.get("params")]
        
        if p_names:
            clean_names = [str(p) for p in p_names if str(p).strip()]
            if clean_names:
                p_snippet = ", ".join(clean_names[:4])
                if len(clean_names) > 4:
                    p_snippet += f" +{len(clean_names) - 4}"
                params_display = f'<span class="scope-params" title="{html.escape(", ".join(clean_names))}">⚡ {html.escape(p_snippet)}</span>'
            else:
                params_display = '<span style="color:var(--text-dim);">&mdash;</span>'
        else:
            params_display = '<span style="color:var(--text-dim);">&mdash;</span>'

        # Check vulnerability status
        ep_findings = []
        for f in findings:
            f_url = f.get("url") or ""
            f_epid = f.get("endpoint_id") or ""
            if (f_url and f_url == ep_url) or (f_epid and f_epid == ep.get("id")):
                ep_findings.append(f)

        if ep_findings:
            if tool_name == "arjun":
                p_cnt = sum(len(f.get("discovered_params", [])) for f in ep_findings)
                status_html = f'<span class="scope-pill vuln">⚡ {p_cnt} Hidden Params Discovered</span>'
            else:
                status_html = f'<span class="scope-pill vuln">🚨 Vulnerable ({len(ep_findings)} Finding{"s" if len(ep_findings) > 1 else ""})</span>'
        elif "ERROR" in str(ep.get("status", "")).upper():
            status_html = f'<span class="scope-pill warn">⚠️ {html.escape(str(ep.get("status")))}</span>'
        else:
            status_html = '<span class="scope-pill clean">✔ Passed Clean (0 Vulns)</span>'

        scope_rows += f"""
        <tr>
            <td style="width:70px;"><span class="scope-method {method}">{method}</span></td>
            <td><a href="{ep_url_esc}" target="_blank" rel="noopener noreferrer" class="scope-url">{ep_url_esc}</a></td>
            <td>{params_display}</td>
            <td style="text-align:right;">{status_html}</td>
        </tr>
        """

    scope_section = f"""
    <details class="scope-details-card" open>
        <summary class="scope-summary-head">
            <span class="scope-title">
                📋 Audited Endpoints & Scope Surface
                <span class="scope-count-badge">{len(endpoints)} Target APIs</span>
            </span>
            <span class="chevron" style="color:var(--accent); font-size:13px;">▾</span>
        </summary>
        <div class="scope-table-wrap">
            <table class="scope-table">
                <thead>
                    <tr>
                        <th style="width:70px;">Method</th>
                        <th>Target Endpoint URL</th>
                        <th style="width:250px;">Audited Parameters</th>
                        <th style="width:200px; text-align:right;">Security Status</th>
                    </tr>
                </thead>
                <tbody>
                    {scope_rows}
                </tbody>
            </table>
        </div>
    </details>
    """
    return display_target, scope_section
'''

if "def build_report_scope_html" not in main_py:
    # Insert before generate_standalone_report
    pos = main_py.find("def generate_standalone_report")
    main_py = main_py[:pos] + scope_helper_code + "\n" + main_py[pos:]
    print("Inserted build_report_scope_html helper function.")

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(main_py)
print("main.py updated!")
