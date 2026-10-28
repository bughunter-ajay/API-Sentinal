#!/usr/bin/env python3
"""
==============================================================================
🚀 Unified Vulnerability Assessment (Nuclei Engine & Nikto Web Scanner)
==============================================================================
Features:
  1. Auto-checks installation & updates for both Nuclei and Nikto CLI engines.
  2. Parallel multi-host scanning via thread worker pool (--concurrency N).
  3. Automatic HTTPS scheme resolution & target normalization.
  4. Silent scanner execution: console spam suppressed with capture_output=True.
  5. Live Terminal Progress Bar with real-time percentage (%) and active tasks.
  6. Nuclei Rate Limit: 15 req/s (Balanced & WAF-safe).
  7. Nikto Tuning: All categories enabled (-Tuning 12345890abde).
  8. Extended execution timeout: 7200s (2 Hours) per tool.
  9. Standalone Interactive HTML Report with dark-mode aesthetic, KPI cards,
     search/filter, and full embedded Console Proof logs (no standalone log files).
  10. Colorized console summary dashboard with severity breakdown.
==============================================================================
"""

from __future__ import annotations

import argparse
import datetime
import html
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ==============================================================================
# 🎯 TARGET HOSTS CONFIGURATION SECTION
# Paste or list all your target hosts here.
# (If no scheme is present, 'https://' will be applied automatically)
# ==============================================================================
DEFAULT_TARGET_HOSTS: List[str] = [
    "apps.visionwaves.com",
    "eyops.visionwaves.com",
    "talent.visionwaves.com",
    "demo.visionwaves.com",
    "platform.visionwaves.com",
    "dev.visionwaves.com",
    "one-sit.visionwaves.com",
    "one-demo.visionwaves.com",
]
# ==============================================================================

# ANSI color code cleaner for raw CLI output
ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def clean_ansi(text: str) -> str:
    """Remove ANSI escape codes for clean readable HTML logging."""
    return ANSI_REGEX.sub("", text)


# Terminal Colors
class Colors:
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def log_banner(title: str):
    width = 75
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * width}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD} {title.center(width - 2)}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * width}{Colors.RESET}\n")


def log_step(step: str, detail: str = ""):
    dt = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.DIM}[{dt}]{Colors.RESET} {Colors.BOLD}{Colors.BLUE}➔ {step}{Colors.RESET} {detail}")


def log_success(msg: str):
    print(f"  {Colors.GREEN}✔ {msg}{Colors.RESET}")


def log_warn(msg: str):
    print(f"  {Colors.YELLOW}⚠ {msg}{Colors.RESET}")


def log_error(msg: str):
    print(f"  {Colors.RED}✖ {msg}{Colors.RESET}")


# ------------------------------------------------------------------------------
# 📊 LIVE TERMINAL PROGRESS TRACKER
# ------------------------------------------------------------------------------

class PipelineProgress:
    """Thread-safe live visual progress bar with percentage, timer, and 2-line active host display."""
    def __init__(self, total_steps: int):
        self.total_steps = max(1, total_steps)
        self.completed_steps = 0
        self.active_tasks: Dict[str, str] = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.rendered_lines = 0
        self.is_tty = sys.stdout.isatty()
        self.done_event = threading.Event()
        if self.is_tty:
            self.ticker = threading.Thread(target=self._ticker, daemon=True)
            self.ticker.start()

    def _ticker(self):
        while not self.done_event.is_set():
            time.sleep(1)
            with self.lock:
                if self.active_tasks and self.is_tty:
                    self._render()

    def start_step(self, host: str, tool: str):
        with self.lock:
            self.active_tasks[host] = tool
            if self.is_tty:
                self._render()
            else:
                elapsed = int(time.time() - self.start_time)
                mins, secs = divmod(elapsed, 60)
                hrs, mins = divmod(mins, 60)
                time_str = f"{hrs:02d}h {mins:02d}m {secs:02d}s"
                sys.stdout.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ➔ [{tool}] Starting scan on {host} (Elapsed: {time_str})\n")
                sys.stdout.flush()

    def finish_step(self, host: str, tool: str, log_msg: str = ""):
        with self.lock:
            if host in self.active_tasks:
                del self.active_tasks[host]
            self.completed_steps += 1
            pct = int((self.completed_steps / self.total_steps) * 100)
            elapsed = int(time.time() - self.start_time)
            mins, secs = divmod(elapsed, 60)
            hrs, mins = divmod(mins, 60)
            time_str = f"{hrs:02d}h {mins:02d}m {secs:02d}s"

            if self.is_tty:
                if log_msg:
                    if self.rendered_lines > 0:
                        sys.stdout.write("\r\x1b[2K\x1b[A\r\x1b[2K")
                        self.rendered_lines = 0
                    sys.stdout.write(log_msg + "\n")
                self._render()
            else:
                if log_msg:
                    sys.stdout.write(log_msg + "\n")
                sys.stdout.write(f"[PROGRESS {pct:>3}%] Completed {self.completed_steps}/{self.total_steps} tasks | Elapsed: {time_str}\n")
                sys.stdout.flush()

    def close(self):
        self.done_event.set()
        with self.lock:
            if self.is_tty and self.rendered_lines > 0:
                sys.stdout.write("\r\x1b[2K\x1b[A\r\x1b[2K\n")
            sys.stdout.flush()

    def _render(self):
        pct = int((self.completed_steps / self.total_steps) * 100)
        pct = min(100, pct)
        bar_width = 25
        filled = int((pct / 100) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        hrs, mins = divmod(mins, 60)
        time_str = f"{hrs:02d}h {mins:02d}m {secs:02d}s"

        # Show all active targets in full without slicing/cropping!
        active_items = [f"{h} ({t})" for h, t in list(self.active_tasks.items())]
        active_str = " | ".join(active_items) if active_items else "Finalizing..."

        line1 = (
            f"{Colors.BOLD}{Colors.CYAN}[PROGRESS {pct:>3}%]{Colors.RESET} "
            f"{Colors.BLUE}[{bar}]{Colors.RESET} "
            f"({self.completed_steps}/{self.total_steps} tasks) | "
            f"{Colors.YELLOW}⏱ {time_str}{Colors.RESET}\x1b[K"
        )
        line2 = f"  {Colors.DIM}➔ Active: {active_str}{Colors.RESET}\x1b[K"

        if self.rendered_lines == 0:
            sys.stdout.write(f"\r\x1b[2K{line1}\n\x1b[2K{line2}")
            self.rendered_lines = 2
        else:
            sys.stdout.write(f"\r\x1b[A\r\x1b[2K{line1}\n\x1b[2K{line2}")
        sys.stdout.flush()


def find_nuclei_binary() -> Optional[str]:
    """Locate Nuclei binary from PATH or standard Homebrew/Linux locations."""
    p = shutil.which("nuclei")
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return os.path.abspath(p)

    candidates = [
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        "/opt/homebrew/bin/nuclei",
        "/home/linuxbrew/.linuxbrew/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/.local/bin/nuclei"),
        os.path.expanduser("~/bin/nuclei"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None



def _auto_install_nuclei_linux() -> Optional[str]:
    """Downloads official static Nuclei release binary for Linux (amd64/arm64) with custom User-Agent to prevent 403 Forbidden."""
    import platform, urllib.request, zipfile
    arch = "amd64"
    mach = platform.machine().lower()
    if mach in ("aarch64", "arm64"):
        arch = "arm64"

    # Pinned stable release - direct asset URL (no GitHub API rate limit)
    version = "3.3.7"
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_{arch}.zip"

    # Determine writable target directory
    target_dir = None
    for d in ["/usr/local/bin", os.path.expanduser("~/.local/bin"), os.path.expanduser("~/bin")]:
        try:
            os.makedirs(d, exist_ok=True)
            test_f = os.path.join(d, ".write_test")
            with open(test_f, "w") as tf: tf.write("1")
            os.remove(test_f)
            target_dir = d
            break
        except Exception:
            continue

    if not target_dir:
        return None

    log_step(f"Downloading pre-compiled Nuclei v{version} (linux/{arch}) directly...")
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False).name
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NiktoNucleiScanner/1.0 (Linux)"})
        with urllib.request.urlopen(req, timeout=45) as resp, open(tmp_zip, "wb") as out_f:
            shutil.copyfileobj(resp, out_f)

        with zipfile.ZipFile(tmp_zip, "r") as zf:
            for member in zf.namelist():
                if member == "nuclei" or member.endswith("/nuclei"):
                    extracted = zf.extract(member, path=tempfile.gettempdir())
                    dest = os.path.join(target_dir, "nuclei")
                    shutil.move(extracted, dest)
                    os.chmod(dest, 0o755)
                    log_success(f"Nuclei installed successfully to: {dest}")
                    return dest
    except Exception as e:
        log_warn(f"Direct download note: {e}")
    finally:
        if os.path.exists(tmp_zip):
            try: os.remove(tmp_zip)
            except Exception: pass
    return None

def prepare_nuclei(auto_install: bool = True, auto_update: bool = True) -> Tuple[bool, Optional[str], str]:
    """Check if Nuclei is installed; auto-install & update templates if needed."""
    log_step("Checking Nuclei Engine...")
    nuclei_bin = find_nuclei_binary()

    # 1. Install if missing
    if not nuclei_bin:
        log_warn("Nuclei binary not found on system PATH.")
        if auto_install:
            # A. Try Homebrew (macOS / Linuxbrew)
            brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
            if os.path.isfile(brew_bin):
                log_step("Attempting auto-installation via Homebrew (`brew install nuclei`)...")
                try:
                    res = subprocess.run([brew_bin, "install", "nuclei"], check=False, capture_output=True, text=True)
                    if res.returncode == 0:
                        log_success("Nuclei installed successfully via Homebrew!")
                        nuclei_bin = find_nuclei_binary()
                except Exception as e:
                    log_warn(f"Homebrew install error: {e}")

            # B. Try Linux Direct Download (Ubuntu / Debian / Docker)
            if not nuclei_bin and sys.platform.startswith("linux"):
                nuclei_bin = _auto_install_nuclei_linux()

            # C. Try Go install if go toolchain exists
            if not nuclei_bin and shutil.which("go"):
                log_step("Attempting auto-installation via Go (`go install nuclei@latest`)...")
                try:
                    res = subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], check=False, capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        nuclei_bin = find_nuclei_binary()
                except Exception as e:
                    log_warn(f"Go install error: {e}")

        if not nuclei_bin:
            return False, None, "Nuclei not installed. Install via: 'apt-get install -y nuclei' or 'brew install nuclei' or 'docker run projectdiscovery/nuclei'"

    # 2. Get version
    version_str = "Installed"
    try:
        vres = subprocess.run([nuclei_bin, "-version"], capture_output=True, text=True, check=False, timeout=10)
        out = (vres.stdout or vres.stderr).strip()
        m = re.search(r"Nuclei Engine Version:\s*([^\s\n]+)", out, re.IGNORECASE) or re.search(r"v\d+\.\d+\.\d+", out)
        if m:
            version_str = m.group(0) if "v" in m.group(0) else f"v{m.group(1)}"
    except Exception:
        pass

    log_success(f"Nuclei found: {nuclei_bin} ({version_str})")

    # 3. Update templates
    if auto_update:
        log_step("Checking and updating Nuclei templates (`nuclei -update-templates`)...")
        try:
            up_res = subprocess.run([nuclei_bin, "-update-templates"], capture_output=True, text=True, check=False, timeout=60)
            if up_res.returncode == 0:
                log_success("Nuclei templates are up to date!")
            else:
                log_warn(f"Template update notice: {up_res.stderr.strip()[:150] or up_res.stdout.strip()[:150]}")
        except Exception as e:
            log_warn(f"Template update check skipped/timed out: {e}")

    return True, nuclei_bin, version_str


def find_nikto_components() -> Tuple[Optional[str], Optional[str]]:
    """Locate Perl binary and Nikto script / binary."""
    perl_bin = shutil.which("perl") or "/usr/bin/perl"
    if not (os.path.isfile(perl_bin) and os.access(perl_bin, os.X_OK)):
        perl_bin = None

    # Check bundled Nikto in repository first
    here = os.path.dirname(os.path.abspath(__file__))
    bundled_candidates = [
        os.path.join(here, "API Sentinel", "API Sentinel_ALL", "nikto_backend", "nikto", "program", "nikto.pl"),
        os.path.join(here, "nikto_backend", "nikto", "program", "nikto.pl"),
        os.path.join(here, "nikto_backend", "nikto", "nikto.pl"),
    ]
    for bc in bundled_candidates:
        if os.path.isfile(bc):
            return perl_bin, os.path.abspath(bc)

    # Check system executable
    nikto_sys = shutil.which("nikto")
    if nikto_sys and os.path.isfile(nikto_sys) and os.access(nikto_sys, os.X_OK):
        return perl_bin, os.path.abspath(nikto_sys)

    standard_candidates = [
        "/opt/homebrew/bin/nikto",
        "/usr/local/bin/nikto",
        "/usr/bin/nikto",
    ]
    for sc in standard_candidates:
        if os.path.isfile(sc):
            return perl_bin, os.path.abspath(sc)

    return perl_bin, None


def prepare_nikto(auto_install: bool = True, auto_update: bool = True) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Check if Perl & Nikto are installed; auto-install/update if possible."""
    log_step("Checking Nikto Engine...")
    perl_bin, nikto_script = find_nikto_components()

    if not perl_bin:
        return False, None, None, "Perl is not installed. Please install Perl to run Nikto."

    if not nikto_script:
        log_warn("Nikto executable / script not found.")
        if auto_install:
            # A. Try Homebrew (macOS)
            brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
            if os.path.isfile(brew_bin):
                log_step("Attempting auto-installation via Homebrew (`brew install nikto`)...")
                try:
                    res = subprocess.run([brew_bin, "install", "nikto"], check=False, capture_output=True, text=True)
                    if res.returncode == 0:
                        log_success("Nikto installed successfully via Homebrew!")
                        perl_bin, nikto_script = find_nikto_components()
                except Exception as e:
                    log_warn(f"Homebrew install error: {e}")

            # B. Try apt-get (Ubuntu / Debian / Docker)
            if not nikto_script and sys.platform.startswith("linux") and shutil.which("apt-get"):
                log_step("Attempting auto-installation via APT (`apt-get install -y nikto`)...")
                try:
                    res = subprocess.run(["apt-get", "update", "-qq"], check=False, capture_output=True, text=True, timeout=60)
                    res2 = subprocess.run(["apt-get", "install", "-y", "-qq", "nikto", "perl"], check=False, capture_output=True, text=True, timeout=120)
                    if res2.returncode == 0:
                        log_success("Nikto installed successfully via APT!")
                        perl_bin, nikto_script = find_nikto_components()
                except Exception as e:
                    log_warn(f"APT install note: {e}")

        if not nikto_script:
            return False, None, None, "Nikto not found. Install via 'apt-get install -y nikto' or 'brew install nikto'."

    # Get version
    version_str = "Nikto (Active)"
    try:
        cmd = [perl_bin, nikto_script, "-Version"] if nikto_script.endswith(".pl") else [nikto_script, "-Version"]
        vres = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        out = (vres.stdout or vres.stderr).strip()
        m = re.search(r"Nikto\s+[0-9.]+", out, re.IGNORECASE)
        if m:
            version_str = m.group(0)
    except Exception:
        pass

    log_success(f"Nikto found: {nikto_script} ({version_str})")

    # Update database
    if auto_update:
        log_step("Checking Nikto plugin/database updates (`nikto -update`)...")
        try:
            cmd = [perl_bin, nikto_script, "-update"] if nikto_script.endswith(".pl") else [nikto_script, "-update"]
            up_res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            if up_res.returncode == 0:
                log_success("Nikto plugins/database are up to date!")
            else:
                log_warn(f"Nikto update check note: {up_res.stdout.strip()[:100] or 'Complete'}")
        except Exception as e:
            log_warn(f"Nikto update check skipped: {e}")

    return True, perl_bin, nikto_script, version_str


# ------------------------------------------------------------------------------
# 🎯 SCAN EXECUTION ENGINES
# ------------------------------------------------------------------------------

def normalize_target_url(target: str) -> Tuple[str, str]:
    """Ensures target has https:// scheme and extracts pure hostname."""
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"https://{target}"

    parsed = urlparse(target)
    hostname = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0]
    return target, hostname


def classify_nikto_severity(msg: str) -> str:
    """Classify Nikto message severity."""
    m = msg.lower()
    if any(k in m for k in [
        "remote code execution", "rce", "command injection", "sql injection",
        "arbitrary file upload", "unauthenticated remote", "backdoor", "remote shell"
    ]):
        return "CRITICAL"
    if any(k in m for k in [
        "directory traversal", "path traversal", "authentication bypass",
        "auth bypass", "credential leak", "private key", "/etc/passwd", ".env"
    ]):
        return "HIGH"
    if any(k in m for k in [
        "misconfiguration", "default file", "interesting file", "directory indexing",
        "backup file", ".git", "actuator", "swagger", "graphql", "cors"
    ]):
        return "MEDIUM"
    if any(k in m for k in [
        "x-frame-options", "content-security-policy", "x-content-type-options",
        "strict-transport-security", "cookie without", "httponly", "insecure cookie"
    ]):
        return "LOW"
    return "INFO"


def run_nuclei_scan(
    nuclei_bin: str,
    target_url: str,
    hostname: str,
    rate_limit: int = 15,
    timeout: int = 7200,
) -> Dict[str, Any]:
    """Execute Nuclei CLI scan quietly (capture_output=True) with balanced rate limit and 2hr timeout."""
    temp_jsonl = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    temp_jsonl_path = temp_jsonl.name
    temp_jsonl.close()

    start_t = time.time()
    cmd = [
        nuclei_bin,
        "-u", target_url,
        "-jsonl",
        "-o", temp_jsonl_path,
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-stats",
    ]

    findings_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
    }
    findings_list = []
    captured_log = ""

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        raw_output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        captured_log = clean_ansi(raw_output)
    except subprocess.TimeoutExpired as e:
        captured_log = f"Scan timed out after {timeout}s: {e}"
    except Exception as e:
        captured_log = f"Scan error: {e}"

    # Parse findings from temporary JSONL
    if os.path.isfile(temp_jsonl_path):
        try:
            with open(temp_jsonl_path, "r", encoding="utf-8", errors="ignore") as rf:
                for line in rf:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        findings_list.append(item)
                        sev = str(item.get("info", {}).get("severity", "info")).lower()
                        if sev in findings_summary:
                            findings_summary[sev] += 1
                        findings_summary["total"] += 1
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            try:
                os.remove(temp_jsonl_path)
            except Exception:
                pass

    elapsed = round(time.time() - start_t, 2)
    return {
        "engine": "Nuclei",
        "target": target_url,
        "hostname": hostname,
        "elapsed_seconds": elapsed,
        "log_text": captured_log,
        "summary": findings_summary,
        "findings": findings_list,
        "findings_count": findings_summary["total"],
    }


def run_nikto_scan(
    perl_bin: str,
    nikto_script: str,
    target_url: str,
    hostname: str,
    timeout: int = 7200,
) -> Dict[str, Any]:
    """Execute Nikto CLI scan quietly across ALL categories (-Tuning 12345890abde) with 2hr timeout."""
    temp_json = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    temp_json_path = temp_json.name
    temp_json.close()

    start_t = time.time()
    cmd = []
    if nikto_script.endswith(".pl"):
        cmd.extend([perl_bin, nikto_script])
    else:
        cmd.append(nikto_script)

    cmd.extend([
        "-h", target_url,
        "-Format", "json",
        "-o", temp_json_path,
        "-timeout", "10",
        "-Tuning", "12345890abde",  # ALL Nikto Categories Included!
    ])

    findings_items = []
    findings_count = 0
    captured_log = ""

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        raw_output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        captured_log = clean_ansi(raw_output)
    except subprocess.TimeoutExpired as e:
        captured_log = f"Nikto scan timed out after {timeout}s: {e}"
    except Exception as e:
        captured_log = f"Nikto execution error: {e}"

    # Parse JSON report
    if os.path.isfile(temp_json_path):
        try:
            with open(temp_json_path, "r", encoding="utf-8", errors="ignore") as rf:
                data = json.load(rf)
                if isinstance(data, dict):
                    vulns = data.get("vulnerabilities", [])
                    findings_items = vulns
                    findings_count = len(vulns)
                elif isinstance(data, list):
                    for h in data:
                        vulns = h.get("vulnerabilities", [])
                        findings_items.extend(vulns)
                    findings_count = len(findings_items)
        except Exception:
            pass
        finally:
            try:
                os.remove(temp_json_path)
            except Exception:
                pass

    elapsed = round(time.time() - start_t, 2)
    return {
        "engine": "Nikto",
        "target": target_url,
        "hostname": hostname,
        "elapsed_seconds": elapsed,
        "log_text": captured_log,
        "findings": findings_items,
        "findings_count": findings_count,
    }


# ------------------------------------------------------------------------------
# 📄 HTML REPORT GENERATION ENGINE (STANDALONE WITH AUDIT TRAIL)
# ------------------------------------------------------------------------------

def generate_pipeline_html_report(summary_data: Dict[str, Any], output_path: str):
    """Generate modern, interactive dark-themed standalone HTML report with console proof logs."""
    results = summary_data.get("results", [])
    total_targets = summary_data.get("total_targets", len(results))
    elapsed_total = summary_data.get("total_elapsed_seconds", 0)
    timestamp = summary_data.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Compute global stats
    total_findings = 0
    kpi_crit = 0
    kpi_high = 0
    kpi_med = 0
    kpi_low = 0
    kpi_info = 0

    target_rows_html = []
    findings_cards_html = []
    console_audit_html = []

    for idx, r in enumerate(results, 1):
        target_url = r.get("url", "")
        hostname = r.get("hostname", "")

        n_data = r.get("nuclei") or {}
        n_sum = n_data.get("summary") or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        n_findings = n_data.get("findings") or []
        n_elapsed = n_data.get("elapsed_seconds", 0)
        n_log = n_data.get("log_text") or "No Nuclei console output recorded."

        k_data = r.get("nikto") or {}
        k_count = k_data.get("findings_count", 0)
        k_findings = k_data.get("findings") or []
        k_elapsed = k_data.get("elapsed_seconds", 0)
        k_log = k_data.get("log_text") or "No Nikto console output recorded."

        # Accumulate KPIs
        kpi_crit += n_sum.get("critical", 0)
        kpi_high += n_sum.get("high", 0)
        kpi_med += n_sum.get("medium", 0)
        kpi_low += n_sum.get("low", 0)
        kpi_info += n_sum.get("info", 0)
        total_findings += n_sum.get("total", 0) + k_count

        host_total = n_sum.get("total", 0) + k_count

        # Target Table Row
        target_rows_html.append(f"""
        <tr>
            <td style="font-weight:600;color:#58a6ff;">
                <a href="{html.escape(target_url)}" target="_blank" rel="noopener noreferrer" style="color:#58a6ff;text-decoration:none;">
                    {html.escape(hostname)} ↗
                </a>
                <div style="font-size:11px;color:#8b949e;margin-top:2px;">{html.escape(target_url)}</div>
            </td>
            <td>
                <span class="badge-num badge-crit">{n_sum.get('critical', 0)} C</span>
                <span class="badge-num badge-high">{n_sum.get('high', 0)} H</span>
                <span class="badge-num badge-med">{n_sum.get('medium', 0)} M</span>
                <span class="badge-num badge-low">{n_sum.get('low', 0)} L</span>
                <span class="badge-num badge-info">{n_sum.get('info', 0)} I</span>
                <div style="font-size:11px;color:#8b949e;margin-top:2px;">{n_elapsed}s elapsed</div>
            </td>
            <td>
                <span class="badge-num badge-nikto">{k_count} Items</span>
                <div style="font-size:11px;color:#8b949e;margin-top:2px;">{k_elapsed}s elapsed</div>
            </td>
            <td style="font-weight:bold;color:#f0f6fc;">
                {host_total}
            </td>
            <td>
                <span class="status-pill status-ok">✔ COMPLETED</span>
                <a href="#audit-{idx}" class="log-jump-btn">📜 View Logs</a>
            </td>
        </tr>
        """)

        # Process Nuclei Findings for Cards
        for f in n_findings:
            info = f.get("info", {})
            name = info.get("name") or f.get("template-id") or "Nuclei Finding"
            sev = str(info.get("severity", "info")).upper()
            matched_at = f.get("matched-at") or f.get("url") or target_url
            template_id = f.get("template-id", "")
            desc = info.get("description", "")
            cwe_raw = info.get("classification", {}).get("cwe-id") if isinstance(info.get("classification"), dict) else ""
            cwe = ", ".join(str(x) for x in cwe_raw if x) if isinstance(cwe_raw, list) else (str(cwe_raw) if cwe_raw else "")
            cve_raw = info.get("classification", {}).get("cve-id") if isinstance(info.get("classification"), dict) else ""
            cve = ", ".join(str(x) for x in cve_raw if x) if isinstance(cve_raw, list) else (str(cve_raw) if cve_raw else "")

            sev_class = f"badge-{sev.lower()}"
            findings_cards_html.append(f"""
            <div class="finding-card" data-severity="{sev}" data-tool="nuclei" data-host="{html.escape(hostname)}">
                <div class="finding-header">
                    <span class="sev-badge {sev_class}">{sev}</span>
                    <span class="tool-badge tool-nuclei">Nuclei</span>
                    <span class="host-pill">{html.escape(hostname)}</span>
                    <span class="finding-title">{html.escape(name)}</span>
                </div>
                <div class="finding-url">
                    <span style="color:#8b949e;">Target:</span>
                    <a href="{html.escape(matched_at)}" target="_blank" rel="noopener noreferrer" style="color:#58a6ff;text-decoration:none;">{html.escape(matched_at)}</a>
                </div>
                {f'<div class="finding-desc">{html.escape(desc)}</div>' if desc else ''}
                <div class="finding-meta">
                    {f'<span class="meta-tag">ID: {html.escape(template_id)}</span>' if template_id else ''}
                    {f'<span class="meta-tag">CVE: {html.escape(cve)}</span>' if cve else ''}
                    {f'<span class="meta-tag">CWE: {html.escape(cwe)}</span>' if cwe else ''}
                </div>
            </div>
            """)

        # Process Nikto Findings for Cards
        for k in k_findings:
            msg = k.get("msg") or k.get("description") or "Nikto Finding"
            url_path = k.get("url") or ""
            full_url = target_url.rstrip("/") + ("/" + url_path.lstrip("/") if url_path else "")
            k_sev = classify_nikto_severity(msg)
            sev_class = f"badge-{k_sev.lower()}"

            if k_sev == "CRITICAL":
                kpi_crit += 1
            elif k_sev == "HIGH":
                kpi_high += 1
            elif k_sev == "MEDIUM":
                kpi_med += 1
            elif k_sev == "LOW":
                kpi_low += 1
            else:
                kpi_info += 1

            findings_cards_html.append(f"""
            <div class="finding-card" data-severity="{k_sev}" data-tool="nikto" data-host="{html.escape(hostname)}">
                <div class="finding-header">
                    <span class="sev-badge {sev_class}">{k_sev}</span>
                    <span class="tool-badge tool-nikto">Nikto</span>
                    <span class="host-pill">{html.escape(hostname)}</span>
                    <span class="finding-title">{html.escape(msg[:120])}</span>
                </div>
                <div class="finding-url">
                    <span style="color:#8b949e;">Endpoint:</span>
                    <a href="{html.escape(full_url)}" target="_blank" rel="noopener noreferrer" style="color:#58a6ff;text-decoration:none;">{html.escape(full_url)}</a>
                </div>
                <div class="finding-desc">{html.escape(msg)}</div>
                <div class="finding-meta">
                    <span class="meta-tag">HTTP Method: {html.escape(k.get('method', 'GET'))}</span>
                    {f"<span class='meta-tag'>OSVDB: {html.escape(str(k.get('osvdb', '')))}</span>" if k.get('osvdb') else ""}
                </div>
            </div>
            """)

        # Section 3: Expandable Console Logs Accordion per Host
        console_audit_html.append(f"""
        <details class="log-accordion" id="audit-{idx}">
            <summary class="log-summary">
                <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-weight:700;color:#f0f6fc;">Host [{idx}/{len(results)}]: {html.escape(hostname)}</span>
                    <span style="font-size:12px;color:#8b949e;">({html.escape(target_url)})</span>
                </div>
                <div style="font-size:12px;color:#8b949e;">
                    Duration: <b>{round(n_elapsed + k_elapsed, 1)}s</b> | Total Findings: <b>{host_total}</b> ▼
                </div>
            </summary>
            <div class="log-body">
                <!-- Nuclei Console Log -->
                <div class="log-block-header">
                    <span style="font-weight:700;color:#60a5fa;">🛡️ Nuclei CLI Console Output Log ({n_elapsed}s)</span>
                    <button type="button" class="copy-btn" onclick="copyLogContent('nlog-{idx}', this)">📋 Copy Nuclei Log</button>
                </div>
                <pre class="console-box" id="nlog-{idx}">{html.escape(n_log.strip() if n_log else "No output.")}</pre>

                <!-- Nikto Console Log -->
                <div class="log-block-header" style="margin-top:18px;">
                    <span style="font-weight:700;color:#fbbf24;">🔍 Nikto CLI Console Output Log ({k_elapsed}s)</span>
                    <button type="button" class="copy-btn" onclick="copyLogContent('klog-{idx}', this)">📋 Copy Nikto Log</button>
                </div>
                <pre class="console-box" id="klog-{idx}">{html.escape(k_log.strip() if k_log else "No output.")}</pre>
            </div>
        </details>
        """)

    # Assemble Full HTML Template with Updated Title
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Vulnerability Assessment (Nuclei Engine &amp; Nikto Web Scanner)</title>
    <style>
        :root {{
            --bg-dark: #090d16;
            --bg-card: #0f172a;
            --bg-hover: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --accent: #38bdf8;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --blue: #3b82f6;
            --purple: #a855f7;
            --green: #22c55e;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-dark);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Helvetica, sans-serif;
            padding: 28px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1350px;
            margin: 0 auto;
        }}
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .logo-title {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-icon {{
            font-size: 28px;
            background: rgba(56, 189, 248, 0.15);
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid var(--accent);
        }}
        .header h1 {{
            font-size: 22px;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.3px;
        }}
        .meta-badges {{
            display: flex;
            gap: 10px;
        }}
        .meta-pill {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12px;
            color: var(--text-dim);
        }}
        .meta-pill b {{ color: #fff; }}

        /* Stat Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 14px;
            margin-bottom: 28px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
            transition: transform 0.15s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent);
        }}
        .stat-card .val {{
            font-size: 28px;
            font-weight: 800;
            line-height: 1.2;
            margin-bottom: 4px;
        }}
        .stat-card .lbl {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-dim);
            font-weight: 600;
        }}

        /* Table */
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 6px;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .section-subtitle {{
            font-size: 12.5px;
            color: var(--text-dim);
            margin-bottom: 14px;
        }}
        .table-wrap {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow-x: auto;
            margin-bottom: 32px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: #1e293b;
            color: #cbd5e1;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            color: #e2e8f0;
        }}
        tr:hover td {{
            background: var(--bg-hover);
        }}

        /* Badges */
        .badge-num {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            margin-right: 4px;
        }}
        .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--orange); border: 1px solid var(--orange); }}
        .badge-med {{ background: rgba(234, 179, 8, 0.2); color: var(--yellow); border: 1px solid var(--yellow); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--blue); border: 1px solid var(--blue); }}
        .badge-info {{ background: rgba(168, 85, 247, 0.2); color: var(--purple); border: 1px solid var(--purple); }}
        .badge-nikto {{ background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid var(--accent); }}

        .status-pill {{
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
        }}
        .status-ok {{
            background: rgba(34, 197, 94, 0.15);
            color: var(--green);
            border: 1px solid var(--green);
        }}
        .log-jump-btn {{
            font-size: 11px;
            color: var(--accent);
            text-decoration: none;
            margin-left: 8px;
            padding: 2px 6px;
            border: 1px solid rgba(56, 189, 248, 0.4);
            border-radius: 4px;
            transition: all 0.15s ease;
        }}
        .log-jump-btn:hover {{
            background: rgba(56, 189, 248, 0.2);
            color: #fff;
        }}

        /* Filter Controls */
        .filter-bar {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 9px 14px;
            color: #fff;
            font-size: 13px;
            outline: none;
        }}
        .search-box:focus {{
            border-color: var(--accent);
        }}
        .filter-btn {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-dim);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent);
            color: #090d16;
            border-color: var(--accent);
        }}

        /* Finding Cards */
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
            transition: border-color 0.15s ease;
        }}
        .finding-card:hover {{
            border-color: #64748b;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            flex-wrap: wrap;
        }}
        .sev-badge {{
            font-size: 11px;
            font-weight: 800;
            padding: 2px 8px;
            border-radius: 4px;
            letter-spacing: 0.5px;
        }}
        .tool-badge {{
            font-size: 11px;
            font-weight: 700;
            padding: 2px 7px;
            border-radius: 4px;
            background: #334155;
            color: #cbd5e1;
        }}
        .tool-nuclei {{ background: rgba(59, 130, 246, 0.25); color: #60a5fa; border: 1px solid #3b82f6; }}
        .tool-nikto {{ background: rgba(245, 158, 11, 0.25); color: #fbbf24; border: 1px solid #f59e0b; }}
        .host-pill {{
            font-size: 11px;
            font-family: monospace;
            background: #1e293b;
            color: #94a3b8;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .finding-title {{
            font-weight: 700;
            font-size: 14px;
            color: #f1f5f9;
        }}
        .finding-url {{
            font-size: 12px;
            font-family: monospace;
            margin-bottom: 8px;
            word-break: break-all;
        }}
        .finding-desc {{
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 10px;
            background: rgba(0, 0, 0, 0.2);
            padding: 8px 12px;
            border-radius: 4px;
        }}
        .finding-meta {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .meta-tag {{
            font-size: 11px;
            background: #1e293b;
            color: #94a3b8;
            padding: 2px 7px;
            border-radius: 3px;
            border: 1px solid #334155;
        }}
        .empty-state {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            text-align: center;
            padding: 36px 20px;
            color: #94a3b8;
            font-size: 14px;
            margin-bottom: 24px;
        }}

        /* Log Accordions & Proof Console */
        .log-accordion {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 14px;
            overflow: hidden;
            transition: border-color 0.15s ease;
        }}
        .log-accordion[open] {{
            border-color: #64748b;
        }}
        .log-summary {{
            padding: 14px 18px;
            background: #1e293b;
            cursor: pointer;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
            outline: none;
        }}
        .log-summary::-webkit-details-marker {{
            display: none;
        }}
        .log-body {{
            padding: 18px;
            background: var(--bg-card);
        }}
        .log-block-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .copy-btn {{
            background: #1e293b;
            border: 1px solid var(--border);
            color: var(--text-dim);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .copy-btn:hover {{
            background: var(--accent);
            color: #090d16;
            border-color: var(--accent);
        }}
        .console-box {{
            background: #030712;
            border: 1px solid #1f2937;
            color: #e5e7eb;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 11.5px;
            line-height: 1.45;
            padding: 14px;
            border-radius: 6px;
            max-height: 380px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo-title">
                <div class="logo-icon">🛡️</div>
                <div>
                    <h1>Unified Vulnerability Assessment (Nuclei Engine &amp; Nikto Web Scanner)</h1>
                </div>
            </div>
            <div class="meta-badges">
                <div class="meta-pill">Generated: <b>{html.escape(str(timestamp))}</b></div>
                <div class="meta-pill">Duration: <b>{elapsed_total}s</b></div>
            </div>
        </div>

        <!-- KPI Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="val" style="color:var(--accent);">{total_targets}</div>
                <div class="lbl">Hosts Scanned</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color:#fff;">{total_findings}</div>
                <div class="lbl">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color:var(--red);">{kpi_crit}</div>
                <div class="lbl">Critical</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color:var(--orange);">{kpi_high}</div>
                <div class="lbl">High</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color:var(--yellow);">{kpi_med}</div>
                <div class="lbl">Medium</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color:var(--blue);">{kpi_low}</div>
                <div class="lbl">Low</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color:var(--purple);">{kpi_info}</div>
                <div class="lbl">Info</div>
            </div>
        </div>

        <!-- Section 1: Targets Overview -->
        <div class="section-title">🎯 Scanned Targets & Security Posture Overview</div>
        <div class="section-subtitle">High-level summary breakdown across all evaluated hosts.</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Target Host</th>
                        <th>Nuclei Findings (C / H / M / L / I)</th>
                        <th>Nikto Findings</th>
                        <th>Total Vulnerabilities</th>
                        <th>Execution Status</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(target_rows_html)}
                </tbody>
            </table>
        </div>

        <!-- Section 2: Interactive Finding Explorer -->
        <div class="section-title">🔍 Detailed Findings Explorer</div>
        <div class="section-subtitle">Search, inspect and filter findings by severity level or scanning tool.</div>
        <div class="filter-bar">
            <input type="text" class="search-box" id="search-input" placeholder="Search findings by CVE, CWE, path, host, or keyword..." onkeyup="filterFindings()">
            <button type="button" class="filter-btn active" onclick="setFilter('ALL', this)">All</button>
            <button type="button" class="filter-btn" onclick="setFilter('CRITICAL', this)">Critical</button>
            <button type="button" class="filter-btn" onclick="setFilter('HIGH', this)">High</button>
            <button type="button" class="filter-btn" onclick="setFilter('MEDIUM', this)">Medium</button>
            <button type="button" class="filter-btn" onclick="setFilter('LOW', this)">Low</button>
            <button type="button" class="filter-btn" onclick="setFilter('INFO', this)">Info</button>
            <button type="button" class="filter-btn" onclick="setToolFilter('nuclei', this)">Nuclei Only</button>
            <button type="button" class="filter-btn" onclick="setToolFilter('nikto', this)">Nikto Only</button>
        </div>

        <div id="findings-container">
            {''.join(findings_cards_html) if findings_cards_html else '<div class="empty-state"><b style="color:#22c55e;">✔ Clean Bill of Health!</b><br>Zero security vulnerabilities or misconfigurations discovered across the scanned target hosts. Check the execution audit logs below for full verification proof.</div>'}
        </div>

        <!-- Section 3: Execution Proof & Raw Console Logs -->
        <div style="margin-top:36px;">
            <div class="section-title">📜 Execution Proof & Raw Console Logs (Audit Trail)</div>
            <div class="section-subtitle">
                Complete CLI console execution logs captured for both Nuclei and Nikto engines. Use these transcripts to verify tests evaluated, request counts, SSL handshakes, and server responses even when zero issues are detected.
            </div>
            <div>
                {''.join(console_audit_html)}
            </div>
        </div>
    </div>

    <script>
        let currentSevFilter = 'ALL';
        let currentToolFilter = 'ALL';

        function setFilter(sev, btn) {{
            currentSevFilter = sev;
            currentToolFilter = 'ALL';
            updateActiveButtons(btn);
            filterFindings();
        }}

        function setToolFilter(tool, btn) {{
            currentToolFilter = tool;
            currentSevFilter = 'ALL';
            updateActiveButtons(btn);
            filterFindings();
        }}

        function updateActiveButtons(activeBtn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            if (activeBtn) activeBtn.classList.add('active');
        }}

        function filterFindings() {{
            const search = (document.getElementById('search-input').value || '').toLowerCase().trim();
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;

            cards.forEach(c => {{
                const sev = c.getAttribute('data-severity') || '';
                const tool = c.getAttribute('data-tool') || '';
                const text = c.textContent.toLowerCase();

                const matchSev = (currentSevFilter === 'ALL' || sev === currentSevFilter);
                const matchTool = (currentToolFilter === 'ALL' || tool === currentToolFilter);
                const matchSearch = (!search || text.includes(search));

                if (matchSev && matchTool && matchSearch) {{
                    c.style.display = 'block';
                    visibleCount++;
                }} else {{
                    c.style.display = 'none';
                }}
            }});
        }}

        function copyLogContent(elemId, btn) {{
            const el = document.getElementById(elemId);
            if (!el) return;
            const text = el.innerText || el.textContent;
            navigator.clipboard.writeText(text).then(() => {{
                const orig = btn.innerText;
                btn.innerText = "✔ Copied!";
                btn.style.borderColor = "var(--green)";
                btn.style.color = "var(--green)";
                setTimeout(() => {{
                    btn.innerText = orig;
                    btn.style.borderColor = "";
                    btn.style.color = "";
                }}, 2000);
            }}).catch(() => {{
                alert("Failed to copy log content to clipboard.");
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as hf:
        hf.write(html_content)


# ------------------------------------------------------------------------------
# 🎯 SINGLE HOST SCAN WORKER (FOR THREADPOOL)
# ------------------------------------------------------------------------------

def scan_host_worker(
    raw_host: str,
    idx: int,
    total_hosts: int,
    nuclei_bin: Optional[str],
    perl_bin: Optional[str],
    nikto_script: Optional[str],
    skip_nuclei: bool,
    skip_nikto: bool,
    rate_limit: int,
    timeout: int,
    progress: PipelineProgress,
) -> Dict[str, Any]:
    """Scans a single target host with Nuclei and Nikto, updating the visual progress bar."""
    target_url, hostname = normalize_target_url(raw_host)

    target_record: Dict[str, Any] = {
        "host": raw_host,
        "url": target_url,
        "hostname": hostname,
        "nuclei": None,
        "nikto": None,
    }

    # 1. Run Nuclei Scan
    if not skip_nuclei and nuclei_bin:
        progress.start_step(hostname, "Nuclei")
        n_res = run_nuclei_scan(nuclei_bin, target_url, hostname, rate_limit=rate_limit, timeout=timeout)
        target_record["nuclei"] = n_res
        s = n_res.get("summary", {})
        log_msg = (
            f"  {Colors.GREEN}✔ [Nuclei]{Colors.RESET} Completed {Colors.BOLD}{hostname}{Colors.RESET} in {n_res['elapsed_seconds']}s: "
            f"{Colors.RED}{s.get('critical', 0)} C{Colors.RESET}, {Colors.YELLOW}{s.get('high', 0)} H{Colors.RESET}, "
            f"{s.get('medium', 0)} M, {s.get('low', 0)} L, {s.get('info', 0)} I"
        )
        progress.finish_step(hostname, "Nuclei", log_msg=log_msg)

    # 2. Run Nikto Scan
    if not skip_nikto and perl_bin and nikto_script:
        progress.start_step(hostname, "Nikto")
        k_res = run_nikto_scan(perl_bin, nikto_script, target_url, hostname, timeout=timeout)
        target_record["nikto"] = k_res
        log_msg = (
            f"  {Colors.GREEN}✔ [Nikto]{Colors.RESET} Completed {Colors.BOLD}{hostname}{Colors.RESET} in {k_res['elapsed_seconds']}s: "
            f"{k_res['findings_count']} findings discovered."
        )
        progress.finish_step(hostname, "Nikto", log_msg=log_msg)

    return target_record


# ------------------------------------------------------------------------------
# 📊 PIPELINE RUNNER & DASHBOARD
# ------------------------------------------------------------------------------

def run_pipeline(
    hosts: List[str],
    skip_nuclei: bool = False,
    skip_nikto: bool = False,
    check_only: bool = False,
    rate_limit: int = 15,
    concurrency: int = 2,
    timeout: int = 7200,
    output_dir: str = "reports",
):
    log_banner("UNIFIED VULNERABILITY ASSESSMENT (NUCLEI & NIKTO)")

    print(f"{Colors.BOLD}Configured Hosts ({len(hosts)} Targets | Parallel Workers: {concurrency}):{Colors.RESET}")
    for idx, h in enumerate(hosts, 1):
        print(f"  {idx}. {h}")
    print()

    # Step 1: Binary checks & updates
    nuclei_ok, nuclei_bin, nuclei_ver = False, None, "N/A"
    if not skip_nuclei:
        nuclei_ok, nuclei_bin, nuclei_ver = prepare_nuclei(auto_install=True, auto_update=True)

    nikto_ok, perl_bin, nikto_script, nikto_ver = False, None, None, "N/A"
    if not skip_nikto:
        nikto_ok, perl_bin, nikto_script, nikto_ver = prepare_nikto(auto_install=True, auto_update=True)

    if check_only:
        log_banner("DEPENDENCY CHECK FINISHED (--check-only flag provided)")
        print(f"• Nuclei Engine: {'READY' if nuclei_ok else 'FAILED'} ({nuclei_ver})")
        print(f"• Nikto Engine:  {'READY' if nikto_ok else 'FAILED'} ({nikto_ver})")
        return

    # Check feasibility
    if not skip_nuclei and not nuclei_ok:
        log_error("Nuclei is not ready. Aborting Nuclei scans.")
    if not skip_nikto and not nikto_ok:
        log_error("Nikto is not ready. Aborting Nikto scans.")

    # Create run output directory for HTML report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.abspath(os.path.join(output_dir, f"pipeline_{timestamp}"))
    os.makedirs(out_dir, exist_ok=True)
    log_step(f"Pipeline output directory created: {out_dir}")
    log_step(f"Execution Timeout: {timeout}s (2 Hours) | Rate Limit: {rate_limit} req/s | Parallel Workers: {concurrency}\n")

    # Step 2: Initialize Progress Tracker
    steps_per_host = (1 if not skip_nuclei and nuclei_ok else 0) + (1 if not skip_nikto and nikto_ok else 0)
    total_steps = max(1, len(hosts) * steps_per_host)
    progress = PipelineProgress(total_steps=total_steps)

    pipeline_results: List[Dict[str, Any]] = []
    total_start = time.time()

    # Step 3: Run Multi-Host Scans in Parallel via ThreadPoolExecutor
    workers_count = min(concurrency, len(hosts))
    with ThreadPoolExecutor(max_workers=workers_count) as executor:
        futures = {
            executor.submit(
                scan_host_worker,
                raw_host,
                idx,
                len(hosts),
                nuclei_bin if nuclei_ok else None,
                perl_bin if nikto_ok else None,
                nikto_script if nikto_ok else None,
                skip_nuclei,
                skip_nikto,
                rate_limit,
                timeout,
                progress,
            ): raw_host
            for idx, raw_host in enumerate(hosts, 1)
        }

        for future in as_completed(futures):
            res = future.result()
            pipeline_results.append(res)

    progress.close()
    total_elapsed = round(time.time() - total_start, 2)

    # Sort results to match original host ordering
    host_index_map = {h: i for i, h in enumerate(hosts)}
    pipeline_results.sort(key=lambda r: host_index_map.get(r["host"], 999))

    # Step 4: Prepare Summary Data for HTML Report
    summary_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "total_targets": len(hosts),
        "total_elapsed_seconds": total_elapsed,
        "nuclei_version": nuclei_ver,
        "nikto_version": nikto_ver,
        "results": pipeline_results,
    }

    # Step 5: Generate ONLY the Standalone Interactive HTML Report (No extra log files)
    html_report_file = os.path.join(out_dir, "pipeline_report.html")
    latest_html_file = os.path.abspath(os.path.join(output_dir, "latest_pipeline_report.html"))
    try:
        os.makedirs(os.path.dirname(latest_html_file), exist_ok=True)
        generate_pipeline_html_report(summary_data, html_report_file)
        shutil.copyfile(html_report_file, latest_html_file)
        log_success(f"Interactive HTML Report generated successfully: {html_report_file}")
    except Exception as e:
        log_error(f"Failed to generate HTML report: {e}")

    # Step 6: Render Console Summary Dashboard
    log_banner("SECURITY ASSESSMENT EXECUTION SUMMARY")
    header = f"{'Target Host':<28} | {'Nuclei (Crit/High/Med/Low)':<30} | {'Nikto Findings':<16} | {'Status'}"
    print(header)
    print("-" * len(header))

    for item in pipeline_results:
        host_str = item["hostname"][:28]
        n_info = item.get("nuclei")
        if n_info:
            s = n_info["summary"]
            nuclei_str = f"C:{s['critical']} H:{s['high']} M:{s['medium']} L:{s['low']}"
        else:
            nuclei_str = "Skipped / N/A"

        k_info = item.get("nikto")
        if k_info:
            nikto_str = f"{k_info['findings_count']} items"
        else:
            nikto_str = "Skipped / N/A"

        status_str = f"{Colors.GREEN}DONE{Colors.RESET}"
        print(f"{host_str:<28} | {nuclei_str:<30} | {nikto_str:<16} | {status_str}")

    print("-" * len(header))
    print(f"\n{Colors.BOLD}Total Time Elapsed:{Colors.RESET}   {total_elapsed}s")
    print(f"{Colors.BOLD}HTML Report File:{Colors.RESET}     file://{html_report_file}")
    print(f"{Colors.BOLD}Latest HTML Link:{Colors.RESET}     file://{latest_html_file}\n")


# ------------------------------------------------------------------------------
# 🏁 MAIN ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified Vulnerability Assessment (Nuclei & Nikto Pipeline)")
    parser.add_argument(
        "--hosts",
        type=str,
        default="",
        help="Comma-separated target hosts list (overrides default script hosts)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="Number of target hosts to scan concurrently in parallel (default: 2)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=15,
        help="Nuclei rate limit in req/s per target (default: 15)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=7200,
        help="Max execution timeout per tool in seconds (default: 7200 / 2 hours)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=os.environ.get("OUTPUT_DIR", "reports"),
        help="Directory to store HTML reports (default: reports or $OUTPUT_DIR)",
    )
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scans")
    parser.add_argument("--skip-nikto", action="store_true", help="Skip Nikto scans")
    parser.add_argument("--check-only", action="store_true", help="Only check and update tool installations")

    args = parser.parse_args()

    # Determine hosts (CLI --hosts > env TARGET_HOSTS > DEFAULT_TARGET_HOSTS)
    if args.hosts.strip():
        targets = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        env_hosts = os.environ.get("TARGET_HOSTS", "").strip()
        if env_hosts:
            targets = [h.strip() for h in env_hosts.replace("\n", ",").split(",") if h.strip()]
        else:
            targets = DEFAULT_TARGET_HOSTS

    # Precedence: CLI argument (if explicitly passed in sys.argv) > Environment Variable > Default
    concurrency = args.concurrency if any(arg.startswith("--concurrency") for arg in sys.argv) else (
        int(os.environ["CONCURRENCY"]) if os.environ.get("CONCURRENCY", "").isdigit() else args.concurrency
    )
    rate_limit = args.rate_limit if any(arg.startswith("--rate-limit") for arg in sys.argv) else (
        int(os.environ["RATE_LIMIT"]) if os.environ.get("RATE_LIMIT", "").isdigit() else args.rate_limit
    )
    timeout = args.timeout if any(arg.startswith("--timeout") for arg in sys.argv) else (
        int(os.environ["TIMEOUT"]) if os.environ.get("TIMEOUT", "").isdigit() else args.timeout
    )
    skip_nuclei = args.skip_nuclei or os.environ.get("SKIP_NUCLEI", "").lower() in ("true", "1", "yes")
    skip_nikto = args.skip_nikto or os.environ.get("SKIP_NIKTO", "").lower() in ("true", "1", "yes")

    run_pipeline(
        hosts=targets,
        skip_nuclei=skip_nuclei,
        skip_nikto=skip_nikto,
        check_only=args.check_only,
        rate_limit=rate_limit,
        concurrency=concurrency,
        timeout=timeout,
        output_dir=args.output_dir,
    )
