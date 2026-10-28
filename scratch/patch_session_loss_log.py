with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    code = f.read()

old_log_filter = '''                            # High-level events stream to Console tab
                            if any(k in clean_l.upper() for k in ["[POC]", "VULN", "XSS", "FOUND", "ERROR", "CRITICAL", "WARN", "TRIGGER", "SUCCESS", "INITIALIZE"]):
                                self.append_log(clean_l)
                            elif clean_l.startswith("➔") or clean_l.startswith("⚡") or clean_l.startswith("✔") or clean_l.startswith("🏁") or "Results written to" in clean_l:
                                self.append_log(clean_l)'''

new_log_filter = '''                            # High-level events stream to Console tab
                            if any(k in clean_l.upper() for k in ["[POC]", "VULN", "XSS", "FOUND", "ERROR", "CRITICAL", "WARN", "TRIGGER", "SUCCESS", "INITIALIZE", "SESSION LOST", "UNAUTHENTICATED", "ABORT"]):
                                if "SESSION LOST" in clean_l.upper() or "UNAUTHENTICATED" in clean_l.upper():
                                    self.append_log(f"⚠️ [AUTH EXPIRED / 401] {clean_l}", "WARN")
                                else:
                                    self.append_log(clean_l)
                            elif clean_l.startswith("➔") or clean_l.startswith("⚡") or clean_l.startswith("✔") or clean_l.startswith("🏁") or "Results written to" in clean_l:
                                self.append_log(clean_l)'''

assert old_log_filter in code, "Could not find old_log_filter in dalfox_engine.py"
code = code.replace(old_log_filter, new_log_filter)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(code)

print("dalfox_engine.py updated with session loss alert!")
