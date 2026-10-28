with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    code = f.read()

old_block = '''                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        preexec_fn=os.setsid
                    )
                    with self.lock:
                        self.active_process = proc

                    if proc.stdout:
                        for line in iter(proc.stdout.readline, ""):
                            if self.stop_requested:
                                break
                            clean_l = clean_ansi(line).rstrip()
                            if not clean_l:
                                continue'''

new_block = '''                session_lost = False
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        preexec_fn=os.setsid
                    )
                    with self.lock:
                        self.active_process = proc

                    if proc.stdout:
                        for line in iter(proc.stdout.readline, ""):
                            if self.stop_requested:
                                break
                            clean_l = clean_ansi(line).rstrip()
                            if not clean_l:
                                continue
                            if "SESSION LOST" in clean_l.upper() or "UNAUTHENTICATED" in clean_l.upper():
                                session_lost = True'''

assert old_block in code, "Could not find old_block in dalfox_engine.py"
code = code.replace(old_block, new_block)

old_status_block = '''                        ep["status"] = f"Vulnerable ({len(new_findings)} XSS)"
                        ep["findings_count"] = len(new_findings)
                        self.append_log(f"🔥 [VULNERABILITY] Found {len(new_findings)} XSS vulnerability in {target_url}!", "SUCCESS")
                    else:
                        ep["status"] = "Clean (0 XSS)"
                        ep["findings_count"] = 0
                        self.append_log(f"✔ Completed {target_url}: Zero XSS detected.", "INFO")'''

new_status_block = '''                        ep["status"] = f"Vulnerable ({len(new_findings)} XSS)"
                        ep["findings_count"] = len(new_findings)
                        self.append_log(f"🔥 [VULNERABILITY] Found {len(new_findings)} XSS vulnerability in {target_url}!", "SUCCESS")
                    elif session_lost:
                        ep["status"] = "Auth Failed (401)"
                        ep["findings_count"] = 0
                        self.append_log(f"⚠️ {target_url}: Skipped due to expired/invalid credentials (HTTP 401). Moving to next API in queue...", "WARN")
                    else:
                        ep["status"] = "Clean (0 XSS)"
                        ep["findings_count"] = 0
                        self.append_log(f"✔ Completed {target_url}: Zero XSS detected.", "INFO")'''

assert old_status_block in code, "Could not find old_status_block in dalfox_engine.py"
code = code.replace(old_status_block, new_status_block)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(code)

print("dalfox_engine.py patched with session_lost status handling!")
