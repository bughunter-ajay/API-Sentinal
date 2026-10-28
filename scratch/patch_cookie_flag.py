with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    code = f.read()

old_cookie_flag = '''                if cookie_headers:
                    cmd.extend(["-C", "; ".join(cookie_headers)])'''

new_cookie_flag = '''                if cookie_headers:
                    cmd.extend(["--cookies", "; ".join(cookie_headers)])'''

assert old_cookie_flag in code, "Could not find old_cookie_flag in dalfox_engine.py"
code = code.replace(old_cookie_flag, new_cookie_flag)

old_error_status = '''                    elif session_lost:
                        ep["status"] = "Auth Failed (401)"
                        ep["findings_count"] = 0
                        self.append_log(f"⚠️ {target_url}: Skipped due to expired/invalid credentials (HTTP 401). Moving to next API in queue...", "WARN")
                    else:
                        ep["status"] = "Clean (0 XSS)"
                        ep["findings_count"] = 0
                        self.append_log(f"✔ Completed {target_url}: Zero XSS detected.", "INFO")'''

new_error_status = '''                    elif session_lost:
                        ep["status"] = "Auth Failed (401)"
                        ep["findings_count"] = 0
                        self.append_log(f"⚠️ {target_url}: Skipped due to expired/invalid credentials (HTTP 401). Moving to next API in queue...", "WARN")
                    elif proc.returncode != 0:
                        ep["status"] = "Scan Error"
                        ep["findings_count"] = 0
                        self.append_log(f"✖ [ERROR] {target_url}: Process exited with error code {proc.returncode}.", "ERROR")
                    else:
                        ep["status"] = "Clean (0 XSS)"
                        ep["findings_count"] = 0
                        self.append_log(f"✔ Completed {target_url}: Zero XSS detected.", "INFO")'''

assert old_error_status in code, "Could not find old_error_status in dalfox_engine.py"
code = code.replace(old_error_status, new_error_status)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(code)

print("dalfox_engine.py patched: -C replaced with --cookies and error status handled!")
