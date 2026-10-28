import re

# 1. Patch dalfox_engine.py
with open("UltronScan/backend/dalfox_engine.py", "r", encoding="utf-8") as f:
    engine_code = f.read()

# Replace append_verbose definition
old_append_verbose = '''    def append_verbose(self, tag: str, action: str, target: str = "", detail: str = ""):
        """Appends a real-time probe line to the verbose stream."""
        with self.lock:
            self.verbose_counter += 1
            entry = {
                "id": self.verbose_counter,
                "time": datetime.now().strftime("%H:%M:%S"),
                "tag": tag,
                "action": action,
                "target": target,
                "detail": detail
            }
            self.verbose_logs.append(entry)
            if len(self.verbose_logs) > 600:
                self.verbose_logs.pop(0)'''

new_append_verbose = '''    def append_verbose(self, tag: str, action: str, target: str = "", detail: str = "", param: str = "", payload: str = ""):
        """Appends a real-time probe line to the verbose stream."""
        with self.lock:
            self.verbose_counter += 1
            entry = {
                "id": self.verbose_counter,
                "time": datetime.now().strftime("%H:%M:%S"),
                "tag": tag,
                "action": action,
                "target": target,
                "detail": detail,
                "param": param,
                "payload": payload
            }
            self.verbose_logs.append(entry)
            if len(self.verbose_logs) > 1000:
                self.verbose_logs.pop(0)'''

assert old_append_verbose in engine_code, "Could not find old_append_verbose in dalfox_engine.py"
engine_code = engine_code.replace(old_append_verbose, new_append_verbose)

# Replace line classification in _scan_worker
old_classify = '''                            # Classify line for Verbose Stream
                            tag = "PROBE"
                            action = clean_l
                            detail = ""

                            m = re.match(r"^\[([A-Za-z0-9_\-\+]+)\]\s*(.*)", clean_l)
                            if m:
                                tag = m.group(1).upper()
                                action = m.group(2)
                            elif "VERIFIED" in clean_l.upper() or "POC" in clean_l.upper():
                                tag = "VULN"
                            elif "DOM" in clean_l.upper():
                                tag = "DOM"
                            elif "WAF" in clean_l.upper():
                                tag = "WAF"
                            elif "PARAM" in clean_l.upper():
                                tag = "PARAM"

                            self.append_verbose(tag=tag, action=action, target=target_url, detail=detail)'''

new_classify = '''                            # Classify line for Verbose Stream
                            clean_msg = re.sub(r'^\d{1,2}:\d{2}(?:AM|PM)\s+DBG\s+', '', clean_l)
                            param_match = re.search(r'param=([a-zA-Z0-9_\-\.]+)', clean_msg)
                            param_name = param_match.group(1) if param_match else ""

                            payload_match = re.search(r'payload=([^\s,)]+)', clean_msg) or re.search(r'payload\s*[:=]\s*["\']?([^"\']+)["\']?', clean_msg)
                            payload_str = payload_match.group(1) if payload_match else ""

                            tag = "PROBE"
                            m = re.match(r"^\[([A-Za-z0-9_\-\+]+)\]\s*(.*)", clean_l)
                            if m:
                                tag = m.group(1).upper()
                                action = m.group(2)
                            else:
                                action = clean_msg
                                if param_name:
                                    tag = f"PARAM: {param_name}"
                                elif "CONTENT-SECURITY-POLICY" in clean_msg.upper() or "CSP" in clean_msg.upper():
                                    tag = "CSP"
                                elif "VERIFIED" in clean_msg.upper() or "POC" in clean_msg.upper() or "VULN" in clean_msg.upper():
                                    tag = "VULN"
                                elif "DOM" in clean_msg.upper() or "AST" in clean_msg.upper():
                                    tag = "DOM"
                                elif "WAF" in clean_msg.upper():
                                    tag = "WAF"

                            self.append_verbose(tag=tag, action=action, target=target_url, detail="", param=param_name, payload=payload_str)'''

assert old_classify in engine_code, "Could not find old_classify in dalfox_engine.py"
engine_code = engine_code.replace(old_classify, new_classify)

with open("UltronScan/backend/dalfox_engine.py", "w", encoding="utf-8") as f:
    f.write(engine_code)
print("dalfox_engine.py patched successfully!")

# 2. Patch sqlmap.css
with open("UltronScan/ui/css/sqlmap.css", "r", encoding="utf-8") as f:
    css_code = f.read()

# Update .output-tabs-bar and .tab-buttons and .scan-progress-pill
old_css_block = '''.output-tabs-bar {
  padding: 8px 14px;
  background: var(--bg-card);
  border-bottom: 1px solid var(--border-dim);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}

.tab-buttons {
  display: flex;
  gap: 6px;
}

.out-tab-btn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 5px 12px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.15s ease;
  display: flex;
  align-items: center;
  gap: 6px;
}
.out-tab-btn:hover {
  color: var(--text-main);
}
.out-tab-btn.active {
  background: var(--neon-green-dim);
  border-color: var(--neon-green);
  color: var(--neon-green);
}

.findings-count-pill {
  background: var(--neon-red);
  color: #fff;
  font-size: 9px;
  font-weight: 800;
  padding: 1px 5px;
  border-radius: 10px;
}

.scan-progress-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono, monospace);
  font-size: 11px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 4px;
  background: rgba(0, 255, 170, 0.12);
  border: 1px solid rgba(0, 255, 170, 0.45);
  color: var(--neon-green, #00ffaa);
  letter-spacing: 0.5px;
  user-select: none;
  white-space: nowrap;
  flex-shrink: 0;
  line-height: 1.2;
  transition: all 0.2s ease;
}'''

new_css_block = '''.output-tabs-bar {
  padding: 8px 12px;
  background: var(--bg-card);
  border-bottom: 1px solid var(--border-dim);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  min-width: 0;
  gap: 8px;
}

.tab-buttons {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.out-tab-btn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 5px 10px;
  height: 28px;
  box-sizing: border-box;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.15s ease;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  flex-shrink: 0;
}
.out-tab-btn:hover {
  color: var(--text-main);
}
.out-tab-btn.active {
  background: var(--neon-green-dim);
  border-color: var(--neon-green);
  color: var(--neon-green);
}

.findings-count-pill {
  background: var(--neon-red);
  color: #fff;
  font-size: 9px;
  font-weight: 800;
  padding: 1px 5px;
  border-radius: 10px;
}

.scan-progress-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono, monospace);
  font-size: 11px;
  font-weight: 700;
  height: 28px;
  padding: 0 8px;
  box-sizing: border-box;
  border-radius: 4px;
  background: rgba(0, 255, 170, 0.12);
  border: 1px solid rgba(0, 255, 170, 0.45);
  color: var(--neon-green, #00ffaa);
  letter-spacing: 0.5px;
  user-select: none;
  white-space: nowrap;
  flex-shrink: 0;
  line-height: 1;
  font-variant-numeric: tabular-nums;
  transition: all 0.2s ease;
}'''

assert old_css_block in css_code, "Could not find old_css_block in sqlmap.css"
css_code = css_code.replace(old_css_block, new_css_block)

# Add badge styles for verbose if not already there
badge_styles = '''
.v-badge.param {
  color: #ffaa00;
  background: rgba(255, 170, 0, 0.12);
  border: 1px solid rgba(255, 170, 0, 0.35);
  font-weight: 700;
}
.v-badge.vuln {
  color: var(--neon-red, #ff3366);
  background: rgba(255, 51, 102, 0.15);
  border: 1px solid rgba(255, 51, 102, 0.4);
  font-weight: 700;
}
.v-badge.testing {
  color: var(--neon-cyan, #00e5ff);
  background: rgba(0, 229, 255, 0.12);
  border: 1px solid rgba(0, 229, 255, 0.3);
}
.v-badge.csp {
  color: #c678dd;
  background: rgba(198, 120, 221, 0.12);
  border: 1px solid rgba(198, 120, 221, 0.3);
}
'''
if ".v-badge.param" not in css_code:
    css_code = css_code.replace(".v-badge {", badge_styles + "\n.v-badge {")

with open("UltronScan/ui/css/sqlmap.css", "w", encoding="utf-8") as f:
    f.write(css_code)
print("sqlmap.css patched successfully!")

# 3. Patch index.html
with open("UltronScan/ui/index.html", "r", encoding="utf-8") as f:
    html_code = f.read()

old_dalfox_scroll = '''                <div style="display:flex; align-items:center; gap:6px;">
                  <button class="cyber-btn secondary" id="btn-dalfox-auto-scroll" style="color:var(--neon-green);" title="Toggle Auto-Scroll">
                    Scroll
                  </button>'''

new_dalfox_scroll = '''                <div style="display:flex; align-items:center; gap:6px; flex-shrink:0;">
                  <button class="cyber-btn secondary" id="btn-dalfox-auto-scroll" style="color:var(--neon-green);" title="Toggle Auto-Scroll">
                    Scroll: ON
                  </button>'''

assert old_dalfox_scroll in html_code, "Could not find old_dalfox_scroll in index.html"
html_code = html_code.replace(old_dalfox_scroll, new_dalfox_scroll)

with open("UltronScan/ui/index.html", "w", encoding="utf-8") as f:
    f.write(html_code)
print("index.html patched successfully!")

