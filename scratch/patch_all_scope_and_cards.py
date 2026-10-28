import re

with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update build_report_scope_html summary chevron
old_chevron = '<span class="chevron" style="color:var(--accent); font-size:13px;">▾</span>'
new_chevron = '<span class="scope-chevron">▾</span>'
if old_chevron in content:
    content = content.replace(old_chevron, new_chevron, 1)
    print("Replaced chevron in build_report_scope_html")
else:
    print("Chevron already updated or not found")

# Scope CSS to inject
scope_css = """
        /* Audited Endpoints & Scope Section */
        .scope-details-card {
            background: #0d1520;
            border: 1px solid #1a2634;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
        }
        .scope-summary-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 16px;
            cursor: pointer;
            user-select: none;
            background: rgba(13, 21, 32, 0.9);
            border-bottom: 1px solid #1a2634;
            list-style: none;
            outline: none;
        }
        .scope-summary-head::-webkit-details-marker { display: none !important; }
        .scope-summary-head::marker { display: none !important; }
        .scope-title {
            font-size: 13px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--font-mono, monospace);
        }
        .scope-count-badge {
            background: rgba(0, 229, 255, 0.12);
            color: #00e5ff;
            border: 1px solid rgba(0, 229, 255, 0.35);
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
        }
        .scope-chevron {
            color: #00e5ff;
            font-size: 13px;
            transition: transform 0.2s ease;
            display: inline-block;
        }
        details[open] .scope-chevron {
            transform: rotate(180deg);
        }
        .scope-table-wrap {
            padding: 10px 16px 14px 16px;
            overflow-x: auto;
            background: #080d14;
        }
        .scope-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            font-family: var(--font-mono, monospace);
        }
        .scope-table th {
            text-align: left;
            padding: 8px 10px;
            color: #8b949e;
            border-bottom: 1px solid #1a2634;
            font-size: 10.5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 700;
        }
        .scope-table td {
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            vertical-align: middle;
            color: #d1d7e0;
        }
        .scope-table tr:last-child td {
            border-bottom: none;
        }
        .scope-table tr:hover td {
            background: rgba(0, 229, 255, 0.02);
        }
        .scope-method {
            font-weight: 800;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
            display: inline-block;
            font-family: var(--font-mono, monospace);
        }
        .scope-method.GET { background: #002b36; color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.3); }
        .scope-method.POST { background: #2b1f00; color: #ff9900; border: 1px solid rgba(255, 153, 0, 0.3); }
        .scope-method.PUT { background: #1a0033; color: #bf5af2; border: 1px solid rgba(191, 90, 242, 0.3); }
        .scope-method.PATCH { background: #1f2b00; color: #a6e22e; border: 1px solid rgba(166, 226, 46, 0.3); }
        .scope-method.DELETE { background: #330010; color: #ff3366; border: 1px solid rgba(255, 51, 102, 0.3); }
        .scope-url {
            color: #00e5ff;
            text-decoration: none;
            word-break: break-all;
            font-size: 12px;
        }
        .scope-url:hover { text-decoration: underline; color: #33ecff; }
        .scope-params {
            color: #9bbcd9;
            font-size: 11px;
        }
        .scope-pill {
            font-size: 10.5px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
            white-space: nowrap;
            display: inline-block;
        }
        .scope-pill.vuln {
            background: rgba(255, 51, 102, 0.15);
            color: #ff3366;
            border: 1px solid rgba(255, 51, 102, 0.4);
        }
        .scope-pill.clean {
            background: rgba(0, 255, 102, 0.12);
            color: #00ff66;
            border: 1px solid rgba(0, 255, 102, 0.35);
        }
        .scope-pill.warn {
            background: rgba(255, 153, 0, 0.15);
            color: #ff9900;
            border: 1px solid rgba(255, 153, 0, 0.35);
        }
""".replace("{", "{{").replace("}", "}}")

# We will patch each generator function individually
def patch_function(func_name, content, tool_name, stat_val_color="critical"):
    start = content.find(f"def {func_name}")
    if start == -1:
        print(f"ERROR: {func_name} not found")
        return content
    
    # Find next function or end
    next_def = content.find("\ndef ", start + 10)
    if next_def == -1:
        fn_body = content[start:]
    else:
        fn_body = content[start:next_def]

    # 1. Clean redundant build_report_scope_html calls
    pattern_redundant = (
        r'display_target, scope_section = build_report_scope_html\(endpoints, findings, target, "[^"]+"\)\s*'
        r'display_target, scope_section = build_report_scope_html\(endpoints, findings, target, "[^"]+"\)\s*'
        r'display_target, scope_section = build_report_scope_html\(endpoints, findings, target, "[^"]+"\)'
    )
    correct_call = f'display_target, scope_section = build_report_scope_html(endpoints, findings, target, "{tool_name}")'
    fn_body = re.sub(pattern_redundant, correct_call, fn_body)

    # 2. Update .risk-banner to compact
    old_rb_pattern = re.compile(
        r'\.risk-banner\s*\{\{.*?padding:\s*16px\s*20px;.*?margin-bottom:\s*25px;.*?\}\}',
        re.DOTALL
    )
    new_rb = """        .risk-banner {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 16px;
            border-radius: 6px;
            margin-bottom: 18px;
            border: 1px solid transparent;
        }}"""
    fn_body = old_rb_pattern.sub(new_rb, fn_body, count=1)

    # Update risk-icon, risk-title, risk-desc, cvss-tag
    fn_body = fn_body.replace(".risk-icon {{ font-size: 28px; line-height: 1; }}", ".risk-icon {{ font-size: 20px; line-height: 1; }}")
    fn_body = fn_body.replace(
        ".risk-title {{\n            font-family: var(--font-mono);\n            font-weight: 800;\n            font-size: 14px;\n            letter-spacing: 0.5px;\n            margin-bottom: 4px;\n        }}",
        ".risk-title {{\n            font-family: var(--font-mono);\n            font-weight: 800;\n            font-size: 13px;\n            letter-spacing: 0.5px;\n            margin-bottom: 2px;\n        }}"
    )
    fn_body = fn_body.replace("font-size: 12px;\n            color: var(--text-main);\n            line-height: 1.4;", "font-size: 11.5px;\n            color: var(--text-main);\n            line-height: 1.35;")
    fn_body = fn_body.replace("padding: 6px 12px;\n            border-radius: 4px;", "font-size: 10px;\n            font-weight: 800;\n            padding: 4px 10px;\n            border-radius: 4px;")

    # 3. Update .stats-grid & .stat-card to compact
    old_sg_pattern = re.compile(
        r'\.stats-grid\s*\{\{.*?grid-template-columns:\s*repeat\(auto-fit,\s*minmax\(180px,\s*1fr\)\);.*?gap:\s*15px;.*?margin-bottom:\s*25px;.*?\}\}',
        re.DOTALL
    )
    new_sg = """        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }}"""
    fn_body = old_sg_pattern.sub(new_sg, fn_body, count=1)

    old_sc_pattern = re.compile(
        r'\.stat-card\s*\{\{.*?padding:\s*16px\s*20px;.*?\}\}',
        re.DOTALL
    )
    new_sc = """        .stat-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 10px 14px;
            text-align: center;
        }}"""
    fn_body = old_sc_pattern.sub(new_sc, fn_body, count=1)

    # Update stat-val & stat-lbl
    fn_body = fn_body.replace(
        ".stat-val {{\n            font-family: var(--font-mono);\n            font-size: 28px;\n            font-weight: 800;\n            color: var(--text-main);\n        }}",
        ".stat-val {{\n            font-family: var(--font-mono);\n            font-size: 20px;\n            font-weight: 800;\n            line-height: 1.2;\n            color: var(--text-main);\n        }}"
    )
    fn_body = fn_body.replace(
        ".stat-lbl {{\n            font-size: 11px;\n            color: var(--text-muted);\n            text-transform: uppercase;\n            letter-spacing: 1px;\n            margin-top: 4px;\n        }}",
        ".stat-lbl {{\n            font-size: 10px;\n            color: var(--text-muted);\n            text-transform: uppercase;\n            letter-spacing: 0.6px;\n            margin-top: 3px;\n        }}"
    )

    # 4. Inject scope_css before </style> if not already present
    if ".scope-details-card" not in fn_body:
        style_close_idx = fn_body.find("    </style>")
        if style_close_idx != -1:
            fn_body = fn_body[:style_close_idx] + scope_css + "\n" + fn_body[style_close_idx:]
            print(f"Injected scope_css into {func_name}")
        else:
            print(f"WARNING: </style> not found in {func_name}")
    else:
        print(f".scope-details-card already in {func_name}")

    if next_def == -1:
        return content[:start] + fn_body
    else:
        return content[:start] + fn_body + content[next_def:]

content = patch_function("generate_standalone_report", content, "sqlmap")
content = patch_function("generate_commix_standalone_report", content, "commix")
content = patch_function("generate_arjun_standalone_report", content, "arjun", stat_val_color="cyan")

# Also update Dalfox stats grid to be equally compact
df_start = content.find("def generate_dalfox_standalone_report")
if df_start != -1:
    df_part = content[df_start:]
    df_part = df_part.replace(
        ".stats-grid {{\n            display: grid;\n            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));\n            gap: 12px;\n            margin-bottom: 28px;\n        }}",
        ".stats-grid {{\n            display: grid;\n            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));\n            gap: 10px;\n            margin-bottom: 20px;\n        }}"
    )
    df_part = df_part.replace(
        ".stat-card {{\n            background: var(--bg-card);\n            border: 1px solid var(--border);\n            border-radius: 6px;\n            padding: 16px;\n            text-align: center;\n        }}\n        .stat-card .val {{ font-size: 26px; font-weight: 800; line-height: 1.2; }}\n        .stat-card .lbl {{ font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 600; margin-top: 4px; }}",
        ".stat-card {{\n            background: var(--bg-card);\n            border: 1px solid var(--border);\n            border-radius: 6px;\n            padding: 10px 14px;\n            text-align: center;\n        }}\n        .stat-card .val {{ font-size: 20px; font-weight: 800; line-height: 1.2; }}\n        .stat-card .lbl {{ font-size: 10px; text-transform: uppercase; color: var(--text-dim); font-weight: 600; margin-top: 3px; }}"
    )
    # Ensure Dalfox has .scope-chevron
    if ".scope-chevron" not in df_part:
        df_part = df_part.replace(
            ".scope-count-badge {{",
            ".scope-chevron {{\n            color: #00e5ff;\n            font-size: 13px;\n            transition: transform 0.2s ease;\n            display: inline-block;\n        }}\n        details[open] .scope-chevron {{\n            transform: rotate(180deg);\n        }}\n        .scope-count-badge {{"
        )
    content = content[:df_start] + df_part

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Patching complete!")
