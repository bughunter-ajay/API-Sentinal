import re

with open("UltronScan/backend/main.py", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Update the 4 Pydantic models to accept endpoints
models_to_update = [
    ("class SaveReportReq(BaseModel):", "SaveReportReq"),
    ("class SaveCommixReportReq(BaseModel):", "SaveCommixReportReq"),
    ("class SaveArjunReportReq(BaseModel):", "SaveArjunReportReq"),
    ("class SaveDalfoxReportReq(BaseModel):", "SaveDalfoxReportReq")
]

for class_def, name in models_to_update:
    pattern = rf"({class_def}.*?open_in_browser:\s*bool\s*=\s*False)"
    m = re.search(pattern, code, re.DOTALL)
    assert m, f"Could not find model {name}"
    orig_block = m.group(1)
    if "endpoints:" not in orig_block:
        new_block = orig_block + "\n    endpoints: Optional[List[Dict[str, Any]]] = None"
        code = code.replace(orig_block, new_block)

print("Updated Pydantic models with endpoints field.")

# 2. Update the 4 /save-report route handlers to pass req.endpoints to generator functions
old_save_sqlmap = "html = generate_standalone_report(req.title, req.target, req.findings, req.stats)"
new_save_sqlmap = "html = generate_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
if old_save_sqlmap in code:
    code = code.replace(old_save_sqlmap, new_save_sqlmap)

old_save_commix = "html = generate_commix_standalone_report(req.title, req.target, req.findings, req.stats)"
new_save_commix = "html = generate_commix_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
if old_save_commix in code:
    code = code.replace(old_save_commix, new_save_commix)

old_save_arjun = "html_content = generate_arjun_standalone_report(req.title, req.target, req.findings, req.stats)"
new_save_arjun = "html_content = generate_arjun_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
if old_save_arjun in code:
    code = code.replace(old_save_arjun, new_save_arjun)

old_save_dalfox = "html_content = generate_dalfox_standalone_report(req.title, req.target, req.findings, req.stats)"
new_save_dalfox = "html_content = generate_dalfox_standalone_report(req.title, req.target, req.findings, req.stats, req.endpoints)"
if old_save_dalfox in code:
    code = code.replace(old_save_dalfox, new_save_dalfox)

print("Updated route handlers to pass req.endpoints.")

with open("UltronScan/backend/main.py", "w", encoding="utf-8") as f:
    f.write(code)

