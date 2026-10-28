# 1. Patch dalfox_engine.py
with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    code = f.read()

old_loop_init = '''                session_lost = False
                try:'''

new_loop_init = '''                session_lost = False
                is_unreachable = False
                try:'''

assert old_loop_init in code, "Could not find old_loop_init in dalfox_engine.py"
code = code.replace(old_loop_init, new_loop_init)

old_check = '''                            if "SESSION LOST" in clean_l.upper() or "UNAUTHENTICATED" in clean_l.upper():
                                session_lost = True'''

new_check = '''                            if "SESSION LOST" in clean_l.upper() or "UNAUTHENTICATED" in clean_l.upper():
                                session_lost = True
                            if "UNREACHABLE" in clean_l.upper() or "DNS RESOLUTION FAILED" in clean_l.upper() or "PREFLIGHT UNREACHABLE" in clean_l.upper():
                                is_unreachable = True'''

assert old_check in code, "Could not find old_check in dalfox_engine.py"
code = code.replace(old_check, new_check)

old_status_eval = '''                        ep["status"] = f"Vulnerable ({len(new_findings)} XSS)"
                        ep["findings_count"] = len(new_findings)
                        self.append_log(f"🔥 [VULNERABILITY] Found {len(new_findings)} XSS vulnerability in {target_url}!", "SUCCESS")
                    elif session_lost:
                        ep["status"] = "Auth Failed (401)"
                        ep["findings_count"] = 0
                        self.append_log(f"⚠️ {target_url}: Skipped due to expired/invalid credentials (HTTP 401). Moving to next API in queue...", "WARN")
                    else:'''

new_status_eval = '''                        ep["status"] = f"Vulnerable ({len(new_findings)} XSS)"
                        ep["findings_count"] = len(new_findings)
                        self.append_log(f"🔥 [VULNERABILITY] Found {len(new_findings)} XSS vulnerability in {target_url}!", "SUCCESS")
                    elif is_unreachable:
                        ep["status"] = "Unreachable"
                        ep["findings_count"] = 0
                        self.append_log(f"✖ [UNREACHABLE] {target_url} failed: DNS resolution failed or server is down.", "ERROR")
                    elif session_lost:
                        ep["status"] = "Auth Failed (401)"
                        ep["findings_count"] = 0
                        self.append_log(f"⚠️ {target_url}: Skipped due to expired/invalid credentials (HTTP 401). Moving to next API in queue...", "WARN")
                    else:'''

assert old_status_eval in code, "Could not find old_status_eval in dalfox_engine.py"
code = code.replace(old_status_eval, new_status_eval)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(code)
print("dalfox_engine.py patched with unreachable host detection!")

# 2. Patch dalfox.js
with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    js_code = f.read()

old_status_js = '''      if (statusText === "Scanning") statusClass = "running";
      else if (statusText.includes("Vulnerable")) statusClass = "vuln";
      else if (statusText.includes("Clean")) statusClass = "success";
      else if (statusText.includes("Auth") || statusText.includes("401")) statusClass = "stopped";'''

new_status_js = '''      if (statusText === "Scanning") statusClass = "running";
      else if (statusText.includes("Vulnerable")) statusClass = "vuln";
      else if (statusText.includes("Clean")) statusClass = "success";
      else if (statusText.includes("Auth") || statusText.includes("401")) statusClass = "stopped";
      else if (statusText.includes("Unreachable") || statusText.includes("Error")) statusClass = "vuln";'''

assert old_status_js in js_code, "Could not find old_status_js in dalfox.js"
js_code = js_code.replace(old_status_js, new_status_js)

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(js_code)
print("dalfox.js patched with unreachable badge class!")

