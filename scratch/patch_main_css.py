with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    main_code = f.read()

old_css = '''        .code-box {{
            background: var(--bg-code);
            border: 1px solid #14202e;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
        }}
        .code-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; color: var(--text-dim); font-size: 11px; }}'''

new_css = '''        .collapsible-box {{
            background: var(--bg-code);
            border: 1px solid #14202e;
            border-radius: 6px;
            font-family: monospace;
            font-size: 12px;
            transition: all 0.2s ease;
        }}
        .collapsible-box:hover {{
            border-color: #24364a;
        }}
        .collapsible-header {{
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
        }}
        .collapsible-header::-webkit-details-marker {{
            display: none;
        }}
        .box-title {{
            color: var(--text-dim);
            font-size: 11px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .collapsible-header:hover .box-title {{
            color: var(--text-main);
        }}
        .header-actions {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .chevron {{
            color: var(--accent);
            font-size: 13px;
            transition: transform 0.2s ease;
            display: inline-block;
        }}
        details[open] .chevron {{
            transform: rotate(180deg);
        }}
        .box-content {{
            padding: 12px 14px;
            border-top: 1px solid #14202e;
            background: #020508;
            border-bottom-left-radius: 6px;
            border-bottom-right-radius: 6px;
        }}
        .box-content pre {{
            white-space: pre-wrap;
            word-break: break-all;
            overflow-wrap: anywhere;
            color: #7ee787;
            font-family: inherit;
            font-size: 11.5px;
            line-height: 1.5;
            margin: 0;
        }}'''

assert old_css in main_code, "Could not find old_css with double braces in main.py"
main_code = main_code.replace(old_css, new_css)

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(main_code)

print("main.py CSS successfully replaced!")
