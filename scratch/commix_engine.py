"""
Commix Engine for UltronScan
Asynchronous Process Coordinator, Queue Manager, Live Log Streamer, and OS Command Injection Exploitation Engine.
Features:
- Guaranteed non-blocking subprocess with stdin=PIPE for interactive replies & shell sessions
- Process group isolation (os.setsid) and instant SIGKILL on stop
- SIGSTOP / SIGCONT smart rate-limit auto-pause and cooldown (60s/120s retries)
- Two-Tier Auto-Fallback Scan (Pass 1 standard, Pass 2 custom injection marker * for params)
- 1-Click exploitation (--os-cmd, --current-user, --file-read, --os-shell)
- Automatic --force-ssl for HTTPS endpoints
"""

import os
import sys
import time
import json
import re
import signal
import shutil
import threading
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_DIR = os.path.join(BASE_DIR, "workspace")
REQUESTS_DIR = os.path.join(WORKSPACE_DIR, "requests")
REPORTS_DIR = os.path.join(WORKSPACE_DIR, "reports")

os.makedirs(REQUESTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Rate limit regexes
RE_HTTP_429 = re.compile(
    r"(?:\bHTTP\s*(?:/\d\.\d\s*)?429\b|\(HTTP\s*429\)|\b429\b.*(?:rate[- ]limit|throttl)|(?:rate[- ]limit|throttl).*\b429\b|\b429\s*[:(-]?\s*Too Many Requests|\bToo Many Requests\b)",
    re.I
)
RE_RATE_LIMIT = re.compile(
    r"\b(?:rate[- ]limit(?:ed|ing)?|backing off and throttling|target kept rate[- ]limiting)\b",
    re.I
)


def get_commix_command_base() -> List[str]:
    """
    Returns the command prefix to run Commix.
    Prefers virtual environment executable, then Homebrew or system PATH.
    """
    venv_bin = os.path.join(BASE_DIR, "venv", "bin", "commix")
    if os.path.exists(venv_bin) and os.access(venv_bin, os.X_OK):
        return [venv_bin]

    hb_bin = "/opt/homebrew/bin/commix"
    if os.path.exists(hb_bin):
        return [hb_bin]

    which_bin = shutil.which("commix")
    if which_bin:
        return [which_bin]

    return ["commix"]


class CommixEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.active_process: Optional[subprocess.Popen] = None
        self.is_running = False
        self.stop_requested = False
        self.is_paused = False

        # Cooldown & Rate Limit State
        self.cooldown_until: Optional[float] = None
        self.cooldown_count = 0
        self.ep_cooldown_attempts = 0
        self.cooldown_target = ""

        # Scan State
        self.current_job_id = ""
        self.status = "idle"  # idle | running | cooldown | paused | stopped | completed | error
        self.config: Dict[str, Any] = {}

        # Queue & Progress
        self.queue: List[Dict[str, Any]] = []
        self.current_index = -1
        self.total_endpoints = 0
        self.scanned_count = 0
        self.vulnerable_count = 0
        self.current_ep_progress = 0.0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Logs & Findings
        self.logs: List[Dict[str, Any]] = []
        self.log_counter = 0
        self.findings: List[Dict[str, Any]] = []
        self.current_endpoint_log: List[str] = []
        self.verbose_logs: List[Dict[str, Any]] = []
        self.verbose_counter = 0

    def get_binary_info(self) -> Dict[str, Any]:
        """Check if Commix is detected and return its version."""
        cmd_base = get_commix_command_base()
        try:
            res = subprocess.run(cmd_base + ["--version"], capture_output=True, text=True, timeout=5)
            version_str = res.stdout.strip() or res.stderr.strip()
            return {"installed": True, "path": " ".join(cmd_base), "version": version_str}
        except Exception as e:
            return {"installed": False, "path": " ".join(cmd_base), "error": str(e)}

    def append_verbose(self, tag: str, action: str, target: str, detail: str = ""):
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
                self.verbose_logs.pop(0)

    def append_log(self, text: str, level: str = "INFO"):
        with self.lock:
            self.log_counter += 1
            entry = {
                "id": self.log_counter,
                "time": datetime.now().strftime("%H:%M:%S"),
                "level": level,
                "text": text
            }
            self.logs.append(entry)
            if len(self.logs) > 8000:
                self.logs.pop(0)
            self.current_endpoint_log.append(text)

    def parse_log_line(self, line: str) -> str:
        """Categorize Commix stdout log lines for visual styling."""
        line_clean = line.strip()
        if not line_clean:
            return "INFO"

        l_upper = line_clean.upper()
        if "[CRITICAL]" in l_upper or "VULNERABLE" in l_upper or "INJECTION POINT" in l_upper or "IS VULNERABLE" in l_upper:
            return "CRITICAL"
        elif "[WARNING]" in l_upper or "WAF" in l_upper or "RATE LIMIT" in l_upper or "HEURISTIC" in l_upper:
            return "WARNING"
        elif "[PAYLOAD]" in l_upper or "PAYLOAD:" in l_upper:
            return "PAYLOAD"
        elif "HOST OS:" in l_upper or "TARGET URL:" in l_upper or "[SUCCESS]" in l_upper or "CURRENT USER:" in l_upper:
            return "SUCCESS"
        elif "[ERROR]" in l_upper or "EXCEPTION OCCURRED" in l_upper:
            return "ERROR"
        return "INFO"

    def classify_rate_limit(self, line: str) -> Optional[str]:
        clean = line.strip()
        clean_lower = clean.lower()
        if ("[payload]" in clean_lower or "payload:" in clean_lower) and not (
            "rate-limit" in clean_lower or "backing off" in clean_lower or "too many requests" in clean_lower
        ):
            return None
        if RE_HTTP_429.search(clean):
            return "http429"
        if RE_RATE_LIMIT.search(clean):
            return "rate_limit"
        return None

    def trigger_rate_limit_cooldown(self, rate_type: str, evidence: str, ep_url: str) -> bool:
        with self.lock:
            if self.stop_requested or not self.active_process or self.active_process.poll() is not None:
                return False

            self.ep_cooldown_attempts += 1
            attempt = self.ep_cooldown_attempts

            if attempt > 2:
                self.is_paused = False
                self.status = "running"
                self.cooldown_until = None
                return True

            cooldown_secs = 60 if attempt == 1 else 120
            self.cooldown_until = time.time() + cooldown_secs
            self.is_paused = True
            self.status = "cooldown"
            self.cooldown_target = ep_url
            proc = self.active_process

        paused = False
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGSTOP)
            paused = True
        except Exception:
            try:
                os.kill(proc.pid, signal.SIGSTOP)
                paused = True
            except Exception:
                pass

        reason_str = "HTTP 429 (Too Many Requests)" if rate_type == "http429" else "Rate-limiting detected"
        retry_tag = f"Retry {attempt}/2"
        self.append_log(f"⚠️ [RATE LIMIT DETECTED] {reason_str}! Evidence: {evidence[:100]}", "WARNING")
        if paused:
            self.append_log(f"⏳ Process paused via SIGSTOP. Cooling down for {cooldown_secs}s before {retry_tag}...", "WARNING")
            self.append_verbose("Rate-Limit", f"SIGSTOP Cooldown ({cooldown_secs}s) | {retry_tag}", ep_url, evidence[:100])
        else:
            self.append_log(f"⏳ Cooling down for {cooldown_secs}s before {retry_tag}...", "WARNING")

        end_time = time.time() + cooldown_secs
        while time.time() < end_time:
            if self.stop_requested:
                break
            time.sleep(0.5)

        if not self.stop_requested and proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
            except Exception:
                try:
                    os.kill(proc.pid, signal.SIGCONT)
                except Exception:
                    pass

        with self.lock:
            self.is_paused = False
            self.status = "running"
            self.cooldown_until = None

        self.append_log(f"▶️ [COOLDOWN COMPLETE] {cooldown_secs}s elapsed. Resumed Commix ({retry_tag}) via SIGCONT.", "SUCCESS")
        self.append_verbose("Rate-Limit", f"SIGCONT Resumed ({retry_tag})", ep_url, "Continuing testing")

        return False

    def send_reply(self, text: str) -> Dict[str, Any]:
        with self.lock:
            if not self.active_process or self.active_process.poll() is not None:
                return {"success": False, "error": "No active Commix process to receive input."}
            try:
                if self.active_process.stdin:
                    self.active_process.stdin.write(text + "\n")
                    self.active_process.stdin.flush()
                    self.append_log(f"❯ [USER INPUT] {text}", "INFO")
                    return {"success": True, "message": f"Sent input: {text}"}
                return {"success": False, "error": "Process stdin is unavailable."}
            except Exception as e:
                return {"success": False, "error": str(e)}

    def pause_scan(self) -> Dict[str, Any]:
        with self.lock:
            if not self.is_running or not self.active_process or self.active_process.poll() is not None:
                return {"success": False, "error": "No Commix scan is currently running."}
            if self.is_paused:
                return {"success": False, "error": "Scan is already paused."}
            try:
                os.killpg(os.getpgid(self.active_process.pid), signal.SIGSTOP)
                self.is_paused = True
                self.status = "paused"
                self.append_log("⏸️ Commix Scan PAUSED by user via SIGSTOP.", "WARNING")
                return {"success": True, "status": "paused"}
            except Exception as e:
                return {"success": False, "error": str(e)}

    def resume_scan(self) -> Dict[str, Any]:
        with self.lock:
            if not self.is_running or not self.active_process or self.active_process.poll() is not None:
                return {"success": False, "error": "No Commix scan is currently active."}
            if not self.is_paused:
                return {"success": False, "error": "Scan is not paused."}
            try:
                os.killpg(os.getpgid(self.active_process.pid), signal.SIGCONT)
                self.is_paused = False
                self.status = "running"
                self.cooldown_until = None
                self.append_log("▶️ Commix Scan RESUMED by user via SIGCONT.", "SUCCESS")
                return {"success": True, "status": "running"}
            except Exception as e:
                return {"success": False, "error": str(e)}

    def reset_session(self) -> Dict[str, Any]:
        with self.lock:
            if self.is_running:
                return {"success": False, "error": "Cannot reset while Commix is running. Stop it first."}
            self.logs = []
            self.log_counter = 0
            self.verbose_logs = []
            self.verbose_counter = 0
            self.findings = []
            self.queue = []
            self.current_index = -1
            self.total_endpoints = 0
            self.scanned_count = 0
            self.vulnerable_count = 0
            self.current_ep_progress = 0.0
            self.status = "idle"
            self.is_paused = False
            self.cooldown_until = None
            self.cooldown_count = 0
            self.ep_cooldown_attempts = 0
            self.current_job_id = ""
            self.current_endpoint_log = []
            return {"success": True, "message": "Commix session and logs reset successfully."}

    def start_scan(self, config: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            if self.is_running:
                return {"success": False, "error": "A Commix scan is already running. Stop it first."}

            self.stop_requested = False
            self.is_running = True
            self.is_paused = False
            self.status = "running"
            self.cooldown_until = None
            self.cooldown_count = 0
            self.start_time = time.time()
            self.end_time = None
            self.current_job_id = f"cmx_job_{int(time.time())}"
            self.config = config

            endpoints = config.get("endpoints", [])
            self.queue = [ep for ep in endpoints if ep.get("selected", True)]
            self.total_endpoints = len(self.queue)
            self.scanned_count = 0
            self.vulnerable_count = 0
            self.current_ep_progress = 0.0
            self.current_index = -1
            self.logs = []
            self.log_counter = 0
            self.findings = []
            self.verbose_logs = []
            self.verbose_counter = 0

        self.append_log(f"⚡ [COMMIX] Initializing Command Injection Audit Session '{self.current_job_id}'...", "SUCCESS")
        self.append_log(f"⚡ Target Queue: {self.total_endpoints} endpoints loaded.", "INFO")
        flags_str = f"Delay={config.get('delay', 1.0)}s, Level={config.get('level', 1)}"
        if config.get("technique"):
            flags_str += f", Technique={config.get('technique')}"
        if config.get("tamper"):
            flags_str += f", Tamper={config.get('tamper')}"
        self.append_log(f"⚡ Flags Configured: {flags_str}", "INFO")

        t = threading.Thread(target=self._scan_worker, daemon=True)
        t.start()

        return {
            "success": True,
            "job_id": self.current_job_id,
            "total_endpoints": self.total_endpoints,
            "status": "running"
        }

    def stop_scan(self) -> Dict[str, Any]:
        with self.lock:
            self.stop_requested = True
            self.status = "stopped"
            self.is_running = False
            self.is_paused = False
            self.cooldown_until = None

            if self.active_process and self.active_process.poll() is None:
                try:
                    os.killpg(os.getpgid(self.active_process.pid), signal.SIGKILL)
                except Exception:
                    try:
                        self.active_process.kill()
                    except Exception:
                        pass

        self.append_log("🛑 Commix scan STOPPED by user. Active process killed.", "WARNING")
        return {"success": True, "message": "Commix scan stopped successfully."}

    def run_exploitation(self, finding_id: str, action: str, cmd_payload: str = "") -> Dict[str, Any]:
        with self.lock:
            if self.is_running:
                return {"success": False, "error": "A scan is already active. Please stop it first."}

            target_finding = next((f for f in self.findings if f.get("id") == finding_id), None)
            if not target_finding:
                return {"success": False, "error": f"Finding '{finding_id}' not found."}

            self.stop_requested = False
            self.is_running = True
            self.status = "running"

        action_flags = []
        action_name = "Exploitation"
        if action == "current-user":
            action_flags = ["--current-user"]
            action_name = "Current User Retrieval"
        elif action == "file-read":
            file_target = cmd_payload.strip() or "/etc/passwd"
            action_flags = [f"--file-read={file_target}"]
            action_name = f"File Read ({file_target})"
        elif action == "os-cmd":
            cmd_exec = cmd_payload.strip() or "id"
            action_flags = [f"--os-cmd={cmd_exec}"]
            action_name = f"Command Execution ('{cmd_exec}')"
        else:
            action_flags = ["--current-user"]

        t = threading.Thread(target=self._exploitation_worker, args=(target_finding, action_flags, action_name), daemon=True)
        t.start()

        return {"success": True, "message": f"Started {action_name} for finding {finding_id}."}

    def _exploitation_worker(self, finding: Dict[str, Any], flags: List[str], action_name: str):
        cmd_base = get_commix_command_base()
        ep_url = finding.get("url", "")
        req_file = os.path.join(REQUESTS_DIR, f"cmx_exploit_{int(time.time())}.txt")

        raw_req = finding.get("raw_request") or ""
        if not raw_req:
            method = finding.get("method", "GET")
            raw_req = f"{method} {ep_url} HTTP/1.1\r\nHost: target\r\n\r\n"
        with open(req_file, "w", encoding="utf-8") as f:
            f.write(raw_req)

        cmd = cmd_base + [
            "-r", req_file,
            "--batch",
            "-v", "1",
            f"--timeout={self.config.get('timeout', 15)}",
            f"--retries={self.config.get('retries', 1)}"
        ] + flags

        if ep_url.lower().startswith("https://") or "https://" in raw_req.lower():
            if "--force-ssl" not in cmd:
                cmd.append("--force-ssl")

        if self.config.get("proxy"):
            cmd.append(f"--proxy={self.config['proxy']}")
        if self.config.get("random_agent", True):
            cmd.append("--random-agent")

        self.append_log(f"─────────────────────────────────────────────────────────────", "INFO")
        self.append_log(f"💥 [COMMIX EXPLOITATION] Launching {action_name} on {ep_url}", "CRITICAL")
        self.append_log(f"💥 Command: {' '.join(cmd)}", "INFO")

        try:
            self.active_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid
            )

            for raw_line in iter(self.active_process.stdout.readline, ''):
                if self.stop_requested:
                    try:
                        os.killpg(os.getpgid(self.active_process.pid), signal.SIGKILL)
                    except Exception:
                        pass
                    break

                clean_line = raw_line.rstrip()
                if not clean_line:
                    continue

                level = self.parse_log_line(clean_line)
                self.append_log(clean_line, level)

                if "current user" in clean_line.lower() or "[*]" in clean_line:
                    self.append_verbose("Exploit", "Command output received", ep_url, clean_line)

            self.active_process.wait()
        except Exception as e:
            self.append_log(f"❌ Exploitation error: {str(e)}", "ERROR")
        finally:
            with self.lock:
                self.is_running = False
                self.status = "completed"
            self.append_log(f"🏁 [COMMIX EXPLOITATION] {action_name} complete.", "SUCCESS")
            try:
                if os.path.exists(req_file):
                    os.remove(req_file)
            except Exception:
                pass

    def _generate_fallback_raw_request(self, raw_req: str) -> Optional[str]:
        if not raw_req or "*" in raw_req:
            return None

        parts = raw_req.split("\r\n\r\n", 1)
        if len(parts) == 1:
            parts = raw_req.split("\n\n", 1)
            newline = "\n"
        else:
            newline = "\r\n"

        header_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ""

        header_lines = header_part.split(newline)
        if not header_lines:
            return None

        first_line = header_lines[0]
        first_line_parts = first_line.split(" ")
        if len(first_line_parts) < 2:
            return None

        method = first_line_parts[0]
        url_path = first_line_parts[1]
        proto = " ".join(first_line_parts[2:]) if len(first_line_parts) > 2 else "HTTP/1.1"

        changed = False

        # 1. Modify Query parameters
        if "?" in url_path:
            base_path, qs = url_path.split("?", 1)
            pairs = qs.split("&")
            new_pairs = []
            for p in pairs:
                if "=" in p:
                    k, v = p.split("=", 1)
                    new_pairs.append(f"{k}=*")
                    changed = True
                else:
                    new_pairs.append(p)
            url_path = f"{base_path}?{'&'.join(new_pairs)}"
            header_lines[0] = f"{method} {url_path} {proto}"

        # 2. Modify Body parameters (JSON or form-urlencoded)
        new_body = body_part
        if body_part:
            body_stripped = body_part.strip()
            if (body_stripped.startswith("{") and body_stripped.endswith("}")) or (body_stripped.startswith("[") and body_stripped.endswith("]")):
                try:
                    data = json.loads(body_stripped)
                    def replace_leaf(obj):
                        nonlocal changed
                        if isinstance(obj, dict):
                            return {k: replace_leaf(v) for k, v in obj.items()}
                        elif isinstance(obj, list):
                            return [replace_leaf(x) for x in obj]
                        else:
                            changed = True
                            return "*"
                    new_data = replace_leaf(data)
                    new_body = json.dumps(new_data)
                except Exception:
                    pass
            elif "=" in body_part:
                pairs = body_part.split("&")
                new_pairs = []
                for p in pairs:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        new_pairs.append(f"{k}=*")
                        changed = True
                    else:
                        new_pairs.append(p)
                new_body = "&".join(new_pairs)

        if not changed:
            return None

        if new_body:
            return newline.join(header_lines) + newline + newline + new_body
        else:
            return newline.join(header_lines) + newline + newline

    def _run_commix_pass(
        self,
        ep: Dict[str, Any],
        req_file_path: str,
        raw_req_content: str,
        job_dir: str,
        pass_label: str,
        progress_base: float,
        progress_span: float
    ) -> Tuple[bool, bool, str, List[Dict[str, Any]], float, List[str]]:
        cmd_base = get_commix_command_base()
        cmd = cmd_base + [
            "-r", req_file_path,
            "--batch",
            "-v", "1",
            f"--delay={self.config.get('delay', 1.0)}",
            f"--timeout={self.config.get('timeout', 15)}",
            f"--retries={self.config.get('retries', 1)}",
            f"--level={self.config.get('level', 1)}",
            f"--output-dir={job_dir}"
        ]

        ep_url = ep.get("url", "")
        ep_method = ep.get("method", "GET")

        # Force SSL/HTTPS for HTTPS targets
        if ep_url.lower().startswith("https://") or "https://" in raw_req_content.lower():
            if "--force-ssl" not in cmd:
                cmd.append("--force-ssl")

        if self.config.get("random_agent", True):
            cmd.append("--random-agent")

        if self.config.get("proxy"):
            cmd.append(f"--proxy={self.config['proxy']}")

        if self.config.get("tamper"):
            cmd.append(f"--tamper={self.config['tamper']}")

        if self.config.get("technique"):
            cmd.append(f"--technique={self.config['technique']}")

        start_time = time.time()
        is_vuln = False
        ep_skipped = False
        detected_os = ""
        vulnerable_params: List[Dict[str, Any]] = []
        current_param_info: Dict[str, Any] = {}
        local_ep_pct = 5.0

        with self.lock:
            self.current_ep_progress = progress_base + (local_ep_pct * (progress_span / 100.0))

        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            self.active_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                preexec_fn=os.setsid
            )

            for raw_line in iter(self.active_process.stdout.readline, ''):
                if self.stop_requested:
                    try:
                        os.killpg(os.getpgid(self.active_process.pid), signal.SIGKILL)
                    except Exception:
                        pass
                    break

                clean_line = raw_line.rstrip()
                if not clean_line:
                    continue

                level = self.parse_log_line(clean_line)
                self.append_log(clean_line, level)

                # Rate-limit auto-pause
                rate_limit_type = self.classify_rate_limit(clean_line)
                if rate_limit_type and not self.is_paused and not self.stop_requested:
                    should_skip = self.trigger_rate_limit_cooldown(rate_limit_type, clean_line, ep_url)
                    if should_skip:
                        ep_skipped = True
                        self.append_log("🛑 [RATE LIMIT PERSISTED] Target returned HTTP 429 after 60s & 120s cooldown retries.", "CRITICAL")
                        self.append_log(f"⏭️ Skipping {ep_method} {ep_url} to protect IP reputation...", "WARNING")
                        self.append_verbose("Rate-Limit", "Skipped Endpoint (429 Persisted)", ep_url, "Exhausted retries")
                        try:
                            os.killpg(os.getpgid(self.active_process.pid), signal.SIGKILL)
                        except Exception:
                            pass
                        break

                clean_lower = clean_line.lower()

                # Live Verbose Stream Capture
                if "[payload]" in clean_lower or "payload:" in clean_lower:
                    p_val = clean_line.split("Payload:", 1)[-1].strip() if "Payload:" in clean_line else clean_line.split("[PAYLOAD]", 1)[-1].strip()
                    self.append_verbose("RCE-Payload", "Injected command probe to", ep_url, p_val)
                elif "testing" in clean_lower and ("technique" in clean_lower or "injection" in clean_lower):
                    self.append_verbose("Attack-Vector", f"[{pass_label}] Testing injection technique", ep_url, clean_line)
                elif "heuristics" in clean_lower or "waf" in clean_lower:
                    self.append_verbose("WAF-Bypass", "WAF/Filter detected", ep_url, "Testing evasion tampers")
                elif "testing connection" in clean_lower or "checking connection" in clean_lower:
                    self.append_verbose("HTTP-Probe", "Testing connection to", ep_url, "Reachability check")

                # Progress estimate within current endpoint
                if "testing connection" in clean_lower or "checking" in clean_lower:
                    local_ep_pct = max(local_ep_pct, 15.0)
                elif "classic" in clean_lower or "results-based" in clean_lower:
                    local_ep_pct = max(local_ep_pct, 40.0)
                elif "blind" in clean_lower or "time-based" in clean_lower:
                    local_ep_pct = max(local_ep_pct, 70.0)
                elif "file-based" in clean_lower or "eval-based" in clean_lower:
                    local_ep_pct = max(local_ep_pct, 90.0)
                elif "[payload]" in clean_lower or "payload:" in clean_lower:
                    local_ep_pct = min(96.0, local_ep_pct + 2.0)

                with self.lock:
                    self.current_ep_progress = progress_base + (local_ep_pct * (progress_span / 100.0))

                # Live Extraction of findings
                m_param1 = re.search(r"(?:The\s+'([^']+)'\s+parameter\s+is\s+vulnerable|parameter\s+'([^']+)'\s+seems\s+to\s+be\s+injectable)", clean_line, re.I)
                m_param2 = re.search(r"Parameter:\s+([^\s]+)\s*(?:\(([^)]+)\))?", clean_line, re.I)

                if m_param1 or m_param2:
                    is_vuln = True
                    param_name = (m_param1.group(1) or m_param1.group(2)) if m_param1 else m_param2.group(1)
                    loc = m_param2.group(2) if (m_param2 and m_param2.group(2)) else ("QUERY" if "?" in ep_url else "BODY")
                    current_param_info = {
                        "param": param_name,
                        "location": loc,
                        "techniques": []
                    }
                    if not any(p["param"] == param_name for p in vulnerable_params):
                        vulnerable_params.append(current_param_info)

                m_type = re.search(r"(?:Type|Technique):\s+([^\r\n]+)", clean_line, re.I)
                if m_type and current_param_info:
                    current_param_info["techniques"].append({"type": m_type.group(1).strip()})

                m_payload = re.search(r"Payload:\s+([^\r\n]+)", clean_line, re.I)
                if m_payload and current_param_info and current_param_info.get("techniques"):
                    current_param_info["techniques"][-1]["payload"] = m_payload.group(1).strip()

                m_os = re.search(r"(?:Host OS|target OS|operating system):\s+([^\r\n]+)", clean_line, re.I)
                if m_os:
                    detected_os = m_os.group(1).strip()

            self.active_process.wait()
        except Exception as e:
            self.append_log(f"❌ Subprocess error in {pass_label} for {ep_url}: {str(e)}", "ERROR")
        finally:
            try:
                if os.path.exists(req_file_path):
                    os.remove(req_file_path)
            except Exception:
                pass

        duration = round(time.time() - start_time, 2)
        return is_vuln, ep_skipped, detected_os, vulnerable_params, duration, cmd

    def _scan_worker(self):
        job_dir = os.path.join(WORKSPACE_DIR, "output", self.current_job_id)
        os.makedirs(job_dir, exist_ok=True)

        for idx, ep in enumerate(self.queue):
            if self.stop_requested:
                break

            with self.lock:
                self.current_index = idx
                self.current_endpoint_log = []
                self.ep_cooldown_attempts = 0
                self.current_ep_progress = 0.0

            ep_skipped = False
            ep_url = ep.get("url", "")
            ep_method = ep.get("method", "GET")
            self.append_log(f"─────────────────────────────────────────────────────────────", "INFO")
            self.append_log(f"🔍 [{idx + 1}/{self.total_endpoints}] Testing {ep_method} {ep_url} for OS Command Injection", "SUCCESS")

            raw_req = ep.get("raw_request", "")
            if not raw_req:
                raw_req = f"{ep_method} {ep_url} HTTP/1.1\r\nHost: target\r\n\r\n"

            fallback_raw = self._generate_fallback_raw_request(raw_req)
            has_fallback = bool(fallback_raw)

            # Pass 1: Standard Scan
            req_file_1 = os.path.join(REQUESTS_DIR, f"{self.current_job_id}_{idx}_t1.txt")
            with open(req_file_1, "w", encoding="utf-8") as rf:
                rf.write(raw_req)

            span_1 = 50.0 if has_fallback else 100.0
            is_vuln, ep_skipped, detected_os, vuln_params, dur_1, cmd_1 = self._run_commix_pass(
                ep=ep,
                req_file_path=req_file_1,
                raw_req_content=raw_req,
                job_dir=job_dir,
                pass_label="Tier-1",
                progress_base=0.0,
                progress_span=span_1
            )
            total_dur = dur_1
            used_tier2 = False
            final_cmd = cmd_1

            # Pass 2: Tier-2 Auto-Fallback
            if not is_vuln and not ep_skipped and not self.stop_requested and has_fallback:
                self.append_log("⚡ [TIER-2 AUTO-FALLBACK] Pass 1 clean. Testing direct parameter injection (*)...", "WARNING")
                self.append_verbose("Auto-Fallback", "Testing direct injection (*)", ep_url, "Pass 2 with custom injection marker")

                req_file_2 = os.path.join(REQUESTS_DIR, f"{self.current_job_id}_{idx}_t2.txt")
                with open(req_file_2, "w", encoding="utf-8") as rf:
                    rf.write(fallback_raw)

                is_vuln_2, ep_skipped_2, detected_os_2, vuln_params_2, dur_2, cmd_2 = self._run_commix_pass(
                    ep=ep,
                    req_file_path=req_file_2,
                    raw_req_content=fallback_raw,
                    job_dir=job_dir,
                    pass_label="Tier-2 Fallback",
                    progress_base=50.0,
                    progress_span=50.0
                )
                total_dur += dur_2
                if ep_skipped_2:
                    ep_skipped = True
                if is_vuln_2:
                    is_vuln = True
                    used_tier2 = True
                    detected_os = detected_os_2 or detected_os
                    vuln_params = vuln_params_2
                    final_cmd = cmd_2

            with self.lock:
                self.current_ep_progress = 100.0
            total_dur = round(total_dur, 2)

            with self.lock:
                if ep_skipped:
                    ep["status"] = "skipped"
                    self.scanned_count += 1
                    if idx + 1 >= len(self.queue):
                        self.stop_requested = True
                        self.append_log("🛑 Single/last endpoint rate-limited. Stopping scan session.", "WARNING")
                        break
                    else:
                        self.append_log(f"⏭️ Moving to next endpoint in queue ({idx + 2}/{self.total_endpoints})...", "INFO")
                        continue
                elif not self.stop_requested:
                    self.scanned_count += 1
                    if is_vuln:
                        ep["status"] = "vulnerable"
                        self.vulnerable_count += 1
                        note_str = " (Tier-2 Auto-Fallback)" if used_tier2 else ""
                        c_cmd = ep.get("curl_command", "")
                        if not c_cmd:
                            c_cmd = f"curl -i -s -k -X {ep_method} '{ep_url}'"

                        finding = {
                            "id": f"cmx-vuln-{len(self.findings) + 1}",
                            "endpoint_id": ep.get("id"),
                            "url": ep_url,
                            "method": ep_method,
                            "os": (detected_os or "Linux/Unix (Generic)") + note_str,
                            "vulnerable_params": vuln_params,
                            "duration": total_dur,
                            "full_log": list(self.current_endpoint_log),
                            "raw_request": fallback_raw if used_tier2 else raw_req,
                            "curl_command": c_cmd,
                            "commix_command": " ".join(final_cmd)
                        }
                        self.findings.append(finding)
                        self.append_log(f"🚨 [VULNERABILITY CONFIRMED] OS Command Injection found in {ep_url}{note_str} (OS: {detected_os or 'Detected'})", "CRITICAL")
                    else:
                        clean_tier_note = " (Tier-1 & Tier-2 Auto-Fallback complete)" if has_fallback else ""
                        self.append_log(f"✅ Clean: No Command Injection detected for {ep_url}{clean_tier_note} ({total_dur}s)", "SUCCESS")

        with self.lock:
            self.is_running = False
            self.is_paused = False
            self.cooldown_until = None
            self.status = "stopped" if self.stop_requested else "completed"
            self.end_time = time.time()
            total_duration = round(self.end_time - self.start_time, 1) if self.start_time else 0

        self.append_log(f"═════════════════════════════════════════════════════════════", "INFO")
        self.append_log(f"🏁 Commix Scan {self.status.upper()} in {total_duration}s | Total Scanned: {self.scanned_count} | Vulnerable: {self.vulnerable_count}", "SUCCESS")

    def get_status(self, since_log_id: int = 0, since_verbose_id: int = 0) -> Dict[str, Any]:
        with self.lock:
            new_logs = [l for l in self.logs if l["id"] > since_log_id]
            new_verbose = [v for v in self.verbose_logs if v["id"] > since_verbose_id]
            current_ep = self.queue[self.current_index] if (0 <= self.current_index < len(self.queue)) else None

            rem_cd = 0.0
            if self.cooldown_until:
                rem_cd = max(0.0, round(self.cooldown_until - time.time(), 1))

            total_eps = max(1, self.total_endpoints)
            if self.status == "completed":
                progress_pct = 100
            elif self.status == "idle" and not self.is_running:
                progress_pct = 0
            elif self.status == "stopped" and not self.is_running:
                progress_pct = int(min(100, (self.scanned_count / total_eps) * 100))
            else:
                ep_frac = max(0.0, min(100.0, getattr(self, "current_ep_progress", 0.0))) / 100.0
                calculated = ((self.scanned_count + ep_frac) / total_eps) * 100.0
                progress_pct = min(99, max(0, int(calculated)))

            return {
                "status": self.status,
                "is_running": self.is_running,
                "is_paused": self.is_paused,
                "cooldown_until": self.cooldown_until,
                "cooldown_remaining": rem_cd,
                "cooldown_target": self.cooldown_target,
                "job_id": self.current_job_id,
                "total_endpoints": self.total_endpoints,
                "current_index": self.current_index,
                "scanned_count": self.scanned_count,
                "vulnerable_count": self.vulnerable_count,
                "progress_percent": progress_pct,
                "current_endpoint": {
                    "method": current_ep.get("method"),
                    "url": current_ep.get("url")
                } if current_ep else None,
                "queue": [
                    {"id": q.get("id"), "status": q.get("status", "wait")}
                    for q in self.queue
                ],
                "findings": self.findings,
                "logs": new_logs,
                "last_log_id": self.log_counter,
                "verbose_logs": new_verbose,
                "last_verbose_id": self.verbose_counter
            }


commix_engine = CommixEngine()
