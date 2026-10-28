with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    c = f.read()

# 1. SQLMap
old_sql_tb = '''    <div class="toolbar">
        <div class="section-title">🔍 AUDIT FINDINGS &amp; SQL INJECTION PROOFS ({findings_count})</div>'''
new_sql_tb = '''    {scope_section}

    <div class="toolbar">
        <div class="section-title">🔍 AUDIT FINDINGS &amp; SQL INJECTION PROOFS ({findings_count})</div>'''
assert old_sql_tb in c, "Could not find old_sql_tb in main.py"
c = c.replace(old_sql_tb, new_sql_tb)

# 2. Commix
old_cmx_tb = '''    <div class="toolbar">
        <div class="section-title">🔍 AUDIT FINDINGS &amp; RCE VECTORS ({findings_count})</div>'''
new_cmx_tb = '''    {scope_section}

    <div class="toolbar">
        <div class="section-title">🔍 AUDIT FINDINGS &amp; RCE VECTORS ({findings_count})</div>'''
assert old_cmx_tb in c, "Could not find old_cmx_tb in main.py"
c = c.replace(old_cmx_tb, new_cmx_tb)

# 3. Arjun
old_arj_tb = '''    <div class="toolbar">
        <div class="section-title">🎯 DISCOVERY FINDINGS &amp; PARAMETER PROOFS ({findings_count})</div>'''
new_arj_tb = '''    {scope_section}

    <div class="toolbar">
        <div class="section-title">🎯 DISCOVERY FINDINGS &amp; PARAMETER PROOFS ({findings_count})</div>'''
assert old_arj_tb in c, "Could not find old_arj_tb in main.py"
c = c.replace(old_arj_tb, new_arj_tb)

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(c)

print("Successfully injected {scope_section} into SQLMap, Commix, and Arjun!")
