with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    code = f.read()

scope_css = '''
        .scope-details-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .scope-summary-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            cursor: pointer;
            user-select: none;
            background: rgba(13, 21, 32, 0.8);
            border-bottom: 1px solid var(--border);
            list-style: none;
        }
        .scope-summary-head::-webkit-details-marker { display: none; }
        .scope-title {
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .scope-count-badge {
            background: rgba(0, 229, 255, 0.15);
            color: var(--accent);
            border: 1px solid var(--accent);
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 12px;
        }
        .scope-table-wrap {
            padding: 10px 16px;
            overflow-x: auto;
        }
        .scope-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            font-family: monospace;
        }
        .scope-table th {
            text-align: left;
            padding: 8px 10px;
            color: var(--text-dim);
            border-bottom: 1px solid var(--border);
            font-size: 10.5px;
            text-transform: uppercase;
        }
        .scope-table td {
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            vertical-align: middle;
        }
        .scope-table tr:hover td {
            background: rgba(255,255,255,0.02);
        }
        .scope-method {
            font-weight: 800;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
            display: inline-block;
        }
        .scope-method.GET { background: #002b36; color: #00e5ff; }
        .scope-method.POST { background: #2b1f00; color: #ff9900; }
        .scope-method.PUT { background: #1a0033; color: #bf5af2; }
        .scope-method.PATCH { background: #1f2b00; color: #a6e22e; }
        .scope-method.DELETE { background: #330010; color: #ff3366; }
        .scope-url {
            color: var(--accent);
            text-decoration: none;
            word-break: break-all;
        }
        .scope-url:hover { text-decoration: underline; }
        .scope-params {
            color: #9bbcd9;
            font-size: 11px;
        }
        .scope-pill {
            font-size: 10.5px;
            font-weight: 700;
            padding: 2px 7px;
            border-radius: 4px;
            white-space: nowrap;
            display: inline-block;
        }
        .scope-pill.vuln {
            background: rgba(255, 51, 102, 0.2);
            color: var(--red);
            border: 1px solid var(--red);
        }
        .scope-pill.clean {
            background: rgba(0, 255, 102, 0.15);
            color: var(--green);
            border: 1px solid var(--green);
        }
        .scope-pill.warn {
            background: rgba(255, 153, 0, 0.2);
            color: var(--orange);
            border: 1px solid var(--orange);
        }
'''

# Escape curly braces for f-strings: {{ and }}
scope_css_fstring = scope_css.replace("{", "{{").replace("}", "}}")

# 1. Update generate_dalfox_standalone_report
old_dfx_sig = "def generate_dalfox_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:"
new_dfx_sig = "def generate_dalfox_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any], endpoints: Optional[List[Dict[str, Any]]] = None) -> str:"
if old_dfx_sig in code:
    code = code.replace(old_dfx_sig, new_dfx_sig)

old_dfx_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    total_findings = len(findings)'''

new_dfx_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    total_findings = len(findings)
    display_target, scope_section = build_report_scope_html(endpoints, findings, target, "dalfox")'''

if old_dfx_start in code:
    code = code.replace(old_dfx_start, new_dfx_start)

# Update dalfox header target and inject scope_section
code = code.replace(
    'Target Surface: <b>{html.escape(target)}</b>',
    'Target Surface: <b>{html.escape(display_target)}</b>'
)
code = code.replace(
    '''        <h2 style="font-size:16px; margin-bottom:14px; color:#fff;">🎯 Discovered Vulnerabilities & Verified PoCs</h2>''',
    '''        {scope_section}\n        <h2 style="font-size:16px; margin-bottom:14px; color:#fff;">🎯 Discovered Vulnerabilities & Verified PoCs</h2>'''
)

# 2. Update generate_standalone_report (SQLMap)
old_sql_sig = "def generate_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:"
new_sql_sig = "def generate_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any], endpoints: Optional[List[Dict[str, Any]]] = None) -> str:"
if old_sql_sig in code:
    code = code.replace(old_sql_sig, new_sql_sig)

old_sql_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_count = len(findings)'''

new_sql_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_count = len(findings)
    display_target, scope_section = build_report_scope_html(endpoints, findings, target, "sqlmap")'''

if old_sql_start in code:
    code = code.replace(old_sql_start, new_sql_start)

code = code.replace(
    'Target: {html.escape(target)}',
    'Target: {html.escape(display_target)}'
)
code = code.replace(
    '''        <h2>🔍 AUDIT FINDINGS &amp; VULNERABILITIES ({findings_count})</h2>''',
    '''        {scope_section}\n        <h2>🔍 AUDIT FINDINGS &amp; VULNERABILITIES ({findings_count})</h2>'''
)

# 3. Update generate_commix_standalone_report (Commix)
old_cmx_sig = "def generate_commix_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:"
new_cmx_sig = "def generate_commix_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any], endpoints: Optional[List[Dict[str, Any]]] = None) -> str:"
if old_cmx_sig in code:
    code = code.replace(old_cmx_sig, new_cmx_sig)

old_cmx_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_count = len(findings)'''

new_cmx_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_count = len(findings)
    display_target, scope_section = build_report_scope_html(endpoints, findings, target, "commix")'''

if old_cmx_start in code:
    code = code.replace(old_cmx_start, new_cmx_start)

code = code.replace(
    '''        <h2>⚡ COMMAND INJECTION FINDINGS ({findings_count})</h2>''',
    '''        {scope_section}\n        <h2>⚡ COMMAND INJECTION FINDINGS ({findings_count})</h2>'''
)

# 4. Update generate_arjun_standalone_report (Arjun)
old_arj_sig = "def generate_arjun_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:"
new_arj_sig = "def generate_arjun_standalone_report(title: str, target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any], endpoints: Optional[List[Dict[str, Any]]] = None) -> str:"
if old_arj_sig in code:
    code = code.replace(old_arj_sig, new_arj_sig)

old_arj_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_count = len(findings)'''

new_arj_start = '''    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_count = len(findings)
    display_target, scope_section = build_report_scope_html(endpoints, findings, target, "arjun")'''

if old_arj_start in code:
    code = code.replace(old_arj_start, new_arj_start)

code = code.replace(
    '''        <h2>🔍 PARAMETER DISCOVERY FINDINGS ({findings_count})</h2>''',
    '''        {scope_section}\n        <h2>🔍 PARAMETER DISCOVERY FINDINGS ({findings_count})</h2>'''
)

# Inject scope_css_fstring into CSS of all 4 templates
# In SQLMap CSS:
code = code.replace(
    """.empty-state {{ text-align: center; padding: 40px; color: var(--text-dim); border: 1px dashed var(--border); border-radius: 8px; }}""",
    """.empty-state {{ text-align: center; padding: 40px; color: var(--text-dim); border: 1px dashed var(--border); border-radius: 8px; }}""" + scope_css_fstring
)
# In Commix CSS:
code = code.replace(
    """.empty-box {{ text-align: center; padding: 40px; color: var(--text-dim); border: 1px dashed var(--border); border-radius: 8px; }}""",
    """.empty-box {{ text-align: center; padding: 40px; color: var(--text-dim); border: 1px dashed var(--border); border-radius: 8px; }}""" + scope_css_fstring
)
# In Arjun CSS:
code = code.replace(
    """.empty-box {{ text-align:center; padding:50px 20px; color:var(--text-muted); font-size:14px; border:1px dashed var(--border-dim); border-radius:8px; }}""",
    """.empty-box {{ text-align:center; padding:50px 20px; color:var(--text-muted); font-size:14px; border:1px dashed var(--border-dim); border-radius:8px; }}""" + scope_css_fstring
)
# In Dalfox CSS:
code = code.replace(
    """.empty-state {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            text-align: center;
            padding: 50px 20px;
            border-radius: 8px;
        }}""",
    """.empty-state {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            text-align: center;
            padding: 50px 20px;
            border-radius: 8px;
        }}""" + scope_css_fstring
)

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(code)

print("All 4 report generators patched with Scope section and multi-host Target Surface!")
