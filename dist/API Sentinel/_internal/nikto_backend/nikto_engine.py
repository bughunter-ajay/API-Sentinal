"""
Nikto Scanner Execution Engine
Runs Nikto CLI via subprocess, streams live console output, parses structured JSON
and real-time item discoveries, classifies severity, and provides report generation.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from nikto_backend.binary_helper import find_nikto_script, find_perl_binary

logger = logging.getLogger("nikto_engine")


def classify_nikto_severity(msg: str) -> str:
    """Intelligently map Nikto finding text to industry-standard severity levels."""
    m = msg.lower()
    # 1. Critical
    if any(k in m for k in [
        "remote code execution", "rce", "command injection", "sql injection",
        "arbitrary file upload", "unauthenticated remote", "buffer overflow",
        "backdoor", "remote shell", "eval("
    ]):
        return "CRITICAL"

    # 2. High
    if any(k in m for k in [
        "directory traversal", "path traversal", "authentication bypass",
        "auth bypass", "default password", "admin bypass", "credential leak",
        "private key", "/etc/passwd", "wp-config", "configuration disclosure",
        "database leak", "shell script found"
    ]):
        return "HIGH"

    # 3. Medium
    if any(k in m for k in [
        "misconfiguration", "default file", "interesting file", "directory indexing",
        "backup file", ".git", ".env", "phpinfo", "source code", "cors",
        "actuator", "swagger", "graphql", "server-status", "admin panel"
    ]):
        return "MEDIUM"

    # 4. Low
    if any(k in m for k in [
        "anti-clickjacking", "x-frame-options", "content-security-policy",
        "x-content-type-options", "strict-transport-security", "cookie without",
        "httponly", "insecure cookie", "http methods", "options method",
        "trace method", "public methods"
    ]):
        return "LOW"

    # 5. Info default
    return "INFO"


class NiktoScanJob:
    def __init__(self):
        self.lock = threading.RLock()
        self.status = "idle"  # idle, running, completed, stopped, error
        self.target = ""
        self.base_url = ""
        self.port = 80
        self.ssl = False
        self.tuning = ""
        self.pause = 0
        self.evasion = ""
        self.maxtime = "30m"
        self.proc: Optional[subprocess.Popen] = None
        self.start_time: float = 0
        self.end_time: float = 0
        self.server_banner = "Unknown"
        self.ip_address = ""
        self.hostname = ""
        self.logs: List[str] = []
        self.findings: List[Dict[str, Any]] = []
        self.temp_dir: Optional[str] = None
        self.output_json_file: Optional[str] = None
        self.error_message: Optional[str] = None

    def reset(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
            self.status = "idle"
            self.target = ""
            self.base_url = ""
            self.port = 80
            self.ssl = False
            self.tuning = ""
            self.pause = 0
            self.evasion = ""
            self.proc = None
            self.start_time = 0
            self.end_time = 0
            self.server_banner = "Unknown"
            self.ip_address = ""
            self.hostname = ""
            self.logs = []
            self.findings = []
            self.error_message = None

    def add_log(self, line: str):
        with self.lock:
            self.logs.append(line)
            # Retain maximum 5000 lines
            if len(self.logs) > 5000:
                self.logs = self.logs[-4000:]

    def add_finding(self, f: Dict[str, Any]):
        with self.lock:
            def _clean_title(txt: str) -> str:
                t = re.sub(r"\s*see:\s*https?://\S+", "", txt or "", flags=re.IGNORECASE)
                return t.strip().lower()

            t_norm = _clean_title(f.get("title") or f.get("description") or "")
            u_norm = (f.get("url") or "").strip().lower()

            for x in self.findings:
                xu = (x.get("url") or "").strip().lower()
                xt = _clean_title(x.get("title") or x.get("description") or "")
                if xu == u_norm:
                    if t_norm == xt or (t_norm and xt and (t_norm in xt or xt in t_norm)):
                        if f.get("references") and not x.get("references"):
                            x["references"] = f.get("references")
                        if f.get("osvdb") and not x.get("osvdb"):
                            x["osvdb"] = f.get("osvdb")
                        return

            self.findings.append(f)

    def get_stats(self) -> Dict[str, int]:
        with self.lock:
            total = len(self.findings)
            crit = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
            high = sum(1 for f in self.findings if f.get("severity") == "HIGH")
            med = sum(1 for f in self.findings if f.get("severity") == "MEDIUM")
            low = sum(1 for f in self.findings if f.get("severity") == "LOW")
            info = sum(1 for f in self.findings if f.get("severity") == "INFO")
            return {
                "total": total,
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "info": info,
            }

    def get_status_dict(self) -> Dict[str, Any]:
        with self.lock:
            elapsed = int(time.time() - self.start_time) if self.start_time > 0 and self.status == "running" else (
                int(self.end_time - self.start_time) if self.end_time > 0 else 0
            )
            return {
                "status": self.status,
                "target": self.target,
                "base_url": self.base_url,
                "hostname": self.hostname,
                "ip_address": self.ip_address,
                "port": self.port,
                "ssl": self.ssl,
                "server_banner": self.server_banner,
                "elapsed_seconds": elapsed,
                "stats": self.get_stats(),
                "total_logs": len(self.logs),
                "total_findings": len(self.findings),
                "error_message": self.error_message,
            }

    def get_logs_slice(self, offset: int = 0) -> Dict[str, Any]:
        with self.lock:
            safe_offset = max(0, min(offset, len(self.logs)))
            return {
                "status": self.status,
                "offset": safe_offset,
                "total": len(self.logs),
                "lines": list(self.logs[safe_offset:]),
            }

    def get_results_dict(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "target": self.target,
                "base_url": self.base_url,
                "server_banner": self.server_banner,
                "ip_address": self.ip_address,
                "stats": self.get_stats(),
                "findings": list(self.findings),
            }


_current_job = NiktoScanJob()


def get_current_job() -> NiktoScanJob:
    return _current_job


def start_nikto_scan(
    target_url: str,
    port: Optional[int] = None,
    ssl_mode: Optional[bool] = None,
    tuning: Optional[str] = None,
    pause_sec: int = 0,
    evasion: Optional[str] = None,
    maxtime: str = "30m",
    user_agent: Optional[str] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    job = get_current_job()
    with job.lock:
        if job.status == "running":
            return {"success": False, "error": "A scan is already actively running. Stop it first."}

    # Normalize target URL
    clean_target = target_url.strip()
    if not clean_target:
        return {"success": False, "error": "Target URL or host cannot be empty."}

    if not clean_target.startswith("http://") and not clean_target.startswith("https://"):
        if port == 443 or ssl_mode is True:
            clean_target = "https://" + clean_target
        else:
            clean_target = "http://" + clean_target

    parsed = urlparse(clean_target)
    hostname = parsed.hostname or clean_target
    detected_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    final_port = port if (port and port > 0) else detected_port
    final_ssl = (parsed.scheme == "https") if ssl_mode is None else ssl_mode

    perl_bin = find_perl_binary()
    nikto_bin = find_nikto_script()
    if not perl_bin or not nikto_bin:
        return {
            "success": False,
            "error": "Perl or Nikto binary was not found. Please install Perl or Nikto.",
        }

    job.reset()
    job.status = "running"
    job.target = clean_target
    job.base_url = f"{'https' if final_ssl else 'http'}://{hostname}:{final_port}" if (final_port not in (80, 443)) else f"{'https' if final_ssl else 'http'}://{hostname}"
    job.hostname = hostname
    job.port = final_port
    job.ssl = final_ssl
    job.tuning = tuning or ""
    job.pause = pause_sec
    job.evasion = evasion or ""
    job.maxtime = maxtime or "30m"
    job.start_time = time.time()

    temp_dir = tempfile.mkdtemp(prefix="sentinel_nikto_")
    out_json = os.path.join(temp_dir, "nikto_output.json")
    job.temp_dir = temp_dir
    job.output_json_file = out_json

    # Build command
    cmd: List[str] = []
    if nikto_bin.endswith(".pl"):
        cmd = [perl_bin, nikto_bin]
    else:
        cmd = [nikto_bin]

    cmd += ["-host", hostname, "-port", str(final_port)]
    if final_ssl:
        cmd.append("-ssl")

    if tuning:
        cmd += ["-Tuning", str(tuning)]
    if pause_sec and pause_sec > 0:
        cmd += ["-Pause", str(pause_sec)]
    if evasion:
        cmd += ["-evasion", str(evasion)]
    if maxtime:
        cmd += ["-maxtime", str(maxtime)]
    if user_agent:
        cmd += ["-useragent", str(user_agent)]

    display_flags = "3PV" if verbose else "P"
    cmd += [
        "-Format", "json",
        "-output", out_json,
        "-Display", display_flags,
        "-nointeractive",
    ]

    working_dir = os.path.dirname(nikto_bin) if nikto_bin.endswith(".pl") else None

    # Spawn thread
    t = threading.Thread(target=_run_scan_worker, args=(job, cmd, working_dir), daemon=True)
    t.start()

    return {
        "success": True,
        "status": "running",
        "target": job.target,
        "port": job.port,
        "ssl": job.ssl,
        "command": " ".join(cmd),
    }


def stop_nikto_scan() -> Dict[str, Any]:
    job = get_current_job()
    with job.lock:
        if job.status != "running":
            return {"success": False, "message": "No scan is currently running."}

        if job.proc and job.proc.poll() is None:
            try:
                job.proc.terminate()
                time.sleep(0.5)
                if job.proc.poll() is None:
                    job.proc.kill()
            except Exception as e:
                logger.warning(f"Error terminating Nikto process: {e}")

        job.status = "stopped"
        job.end_time = time.time()
        job.add_log(f"\n[!] Scan manually aborted by user at {time.strftime('%H:%M:%S')}")

    return {"success": True, "status": "stopped"}


def _run_scan_worker(job: NiktoScanJob, cmd: List[str], cwd: Optional[str]):
    job.add_log(f"[*] Starting Nikto Server Audit: {job.target} (Port: {job.port}, SSL: {job.ssl})")
    job.add_log(f"[*] Command: {' '.join(cmd)}\n")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        job.proc = proc

        # Stream output line-by-line
        for raw_line in iter(proc.stdout.readline, ""):
            line = raw_line.rstrip()
            if not line:
                continue

            job.add_log(line)
            _parse_realtime_line(job, line)

        proc.wait()
        job.end_time = time.time()

        if job.status == "running":
            job.status = "completed"

    except Exception as e:
        logger.error(f"Nikto execution failed: {e}")
        job.status = "error"
        job.error_message = str(e)
        job.add_log(f"[!] Nikto execution error: {e}")
    finally:
        # Check if output JSON exists and parse details
        _parse_nikto_json(job)
        job.add_log(f"\n[*] Scan finished in {int(time.time() - job.start_time)}s. Found {len(job.findings)} items.")


def _parse_realtime_line(job: NiktoScanJob, line: str):
    """Parse key information on-the-fly from live stdout."""
    clean = line.strip()

    # Server Banner
    if "+ Server:" in clean:
        parts = clean.split("+ Server:", 1)
        if len(parts) > 1:
            val = parts[1].strip()
            if val and val.lower() != "no banner retrieved":
                job.server_banner = val

    # Target IP
    if "+ Target IP:" in clean:
        parts = clean.split("+ Target IP:", 1)
        if len(parts) > 1:
            job.ip_address = parts[1].strip()

    # Target Hostname
    if "+ Target Hostname:" in clean:
        parts = clean.split("+ Target Hostname:", 1)
        if len(parts) > 1:
            job.hostname = parts[1].strip()

    # Vulnerability / Finding Line (+ /path/file: Msg or + Msg)
    if clean.startswith("+ ") and not any(clean.startswith(p) for p in [
        "+ Target IP:", "+ Target Hostname:", "+ Target Port:", "+ Start Time:",
        "+ End Time:", "+ Server:", "+ OSVDB-0:", "+ No CGI Directories",
        "+ 0 host(s) tested", "+ 1 host(s) tested", "+ Nikto v", "+ SSL Info:",
        "+ Root:", "+ Platform:"
    ]):
        msg_body = clean[2:].strip()
        if not msg_body or "requests:" in msg_body or "items reported on" in msg_body or "execution time" in msg_body or "Scan terminated" in msg_body:
            return

        rule_id = f"NIKTO-{len(job.findings) + 1:04d}"
        path_part = "/"
        title = msg_body

        # Case 1: [999100] /admin.cgi: Uncommon header(s)...
        m_code = re.match(r"^\[([0-9a-zA-Z_-]+)\]\s*([^:]+):\s*(.*)$", msg_body)
        if m_code:
            rule_id = f"NIKTO-{m_code.group(1)}"
            path_part = m_code.group(2).strip()
            title = m_code.group(3).strip()
        # Case 2: OSVDB-3092: /test.php: A test script was found.
        elif "osvdb-" in msg_body.lower():
            m_osvdb = re.search(r"OSVDB-(\d+):\s*([^:]+):\s*(.*)", msg_body, re.IGNORECASE)
            if m_osvdb:
                rule_id = f"OSVDB-{m_osvdb.group(1)}"
                path_part = m_osvdb.group(2).strip()
                title = m_osvdb.group(3).strip()
        # Case 3: /path: Title
        elif msg_body.startswith("/"):
            tokens = msg_body.split(":", 1)
            path_part = tokens[0].strip()
            if len(tokens) > 1:
                title = tokens[1].strip()

        # Check for reference URL in msg_body or title (e.g. See: https://...)
        ref_url = None
        m_ref = re.search(r"(?:See|Reference):\s*(https?://\S+)", msg_body, re.IGNORECASE)
        if m_ref:
            ref_url = m_ref.group(1).rstrip(".,;)")
            title = re.sub(r"\.?\s*(?:See|Reference):\s*https?://\S+", "", title, flags=re.IGNORECASE).strip()
            if title and not title.endswith(".") and not title.endswith(":"):
                title += "."

        matched_url = f"{job.base_url.rstrip('/')}{path_part if path_part.startswith('/') else '/' + path_part}"
        sev = classify_nikto_severity(msg_body)

        finding = {
            "id": rule_id,
            "osvdb": rule_id if "OSVDB" in rule_id else None,
            "severity": sev,
            "title": title,
            "url": matched_url,
            "method": "GET",
            "description": msg_body,
            "references": [ref_url] if ref_url else [],
            "reference_url": ref_url,
            "evidence": line,
            "curl_command": f"curl -i -k '{matched_url}'",
        }
        job.add_finding(finding)


def _parse_nikto_json(job: NiktoScanJob):
    """Parse JSON report generated by Nikto to enrich findings."""
    if not job.output_json_file or not os.path.isfile(job.output_json_file):
        return

    try:
        with open(job.output_json_file, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        # Structure can vary between Nikto versions (dict or list)
        items = []
        if isinstance(data, dict):
            # Banner
            if "banner" in data and data["banner"]:
                job.server_banner = data["banner"]
            if "ip" in data and data["ip"]:
                job.ip_address = data["ip"]

            items = data.get("vulnerabilities", []) or data.get("items", [])
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    if "banner" in entry:
                        job.server_banner = entry["banner"]
                    items.extend(entry.get("vulnerabilities", []))

        for it in items:
            if not isinstance(it, dict):
                continue
            msg = it.get("msg") or it.get("message") or it.get("description") or ""
            if not msg:
                continue

            path = it.get("url") or it.get("uri") or ""
            full_url = f"{job.base_url.rstrip('/')}{path}" if path else job.base_url
            method = it.get("method") or "GET"
            osvdb = it.get("OSVDB") or it.get("osvdb")
            id_val = f"OSVDB-{osvdb}" if osvdb and str(osvdb) != "0" else f"NIKTO-{len(job.findings) + 1:04d}"

            sev = classify_nikto_severity(msg)

            ref_url = None
            m_ref = re.search(r"(?:See|Reference):\s*(https?://\S+)", msg, re.IGNORECASE)
            clean_title = msg
            if m_ref:
                ref_url = m_ref.group(1).rstrip(".,;)")
                clean_title = re.sub(r"\.?\s*(?:See|Reference):\s*https?://\S+", "", msg, flags=re.IGNORECASE).strip()
                if clean_title and not clean_title.endswith(".") and not clean_title.endswith(":"):
                    clean_title += "."

            finding = {
                "id": id_val,
                "osvdb": f"OSVDB-{osvdb}" if osvdb else None,
                "severity": sev,
                "title": clean_title,
                "url": full_url,
                "method": method,
                "description": msg,
                "references": [ref_url] if ref_url else [],
                "reference_url": ref_url,
                "evidence": json.dumps(it, indent=2),
                "curl_command": f"curl -i -k -X {method} '{full_url}'",
            }
            job.add_finding(finding)

    except Exception as e:
        logger.warning(f"Could not parse Nikto output JSON: {e}")


def get_nikto_knowledge(f: Dict[str, Any]) -> Dict[str, str]:
    """Provide intelligence mapping for Nikto findings (Category, OWASP, CWE, Impact, Remediation)."""
    combined = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')} {f.get('id', '')}".lower()

    if "x-frame-options" in combined or "anti-clickjacking" in combined or "clickjacking" in combined:
        return {
            "category": "Missing Security Header",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-1021",
            "impact": "The application is vulnerable to Clickjacking (UI Redressing). Attackers can frame this application inside an invisible <iframe> on an attacker-controlled site to trick authenticated users into clicking sensitive buttons or triggering unintended transactions.",
            "recommended": "DENY or SAMEORIGIN",
            "nginx": 'add_header X-Frame-Options "SAMEORIGIN" always;',
            "apache": 'Header always set X-Frame-Options "SAMEORIGIN"',
        }

    if "x-content-type-options" in combined or "mime type" in combined or "mime sniffing" in combined or "nosniff" in combined:
        return {
            "category": "MIME Sniffing Vulnerability",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-79 / CWE-16",
            "impact": "Without nosniff, browsers may inspect (sniff) content and treat non-executable files (like user-uploaded images or text) as executable HTML/JavaScript, leading to Cross-Site Scripting (XSS).",
            "recommended": "nosniff",
            "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
            "apache": 'Header always set X-Content-Type-Options "nosniff"',
        }

    if "strict-transport-security" in combined or "hsts" in combined or ("ssl" in combined and "transport-security" in combined):
        return {
            "category": "Insecure Transport / Missing HSTS",
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-319",
            "impact": "Enables SSL-stripping and man-in-the-middle (MITM) attacks. Without HSTS, initial HTTP requests or unencrypted links can be intercepted and redirected to eavesdropping proxies on local Wi-Fi or networks.",
            "recommended": "max-age=31536000; includeSubDomains; preload",
            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        }

    if "referrer-policy" in combined or "referer-policy" in combined:
        return {
            "category": "Referrer Information Leakage",
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-200",
            "impact": "Sensitive parameters (tokens, session IDs, private query parameters, or internal URLs) may leak to external third-party sites via the HTTP Referer request header during user navigation.",
            "recommended": "strict-origin-when-cross-origin or no-referrer",
            "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        }

    if "content-security-policy" in combined or "csp" in combined:
        return {
            "category": "Missing Content Security Policy (CSP)",
            "owasp": "A03:2021 - Injection / XSS",
            "cwe": "CWE-79",
            "impact": "Lack of a restrictive Content Security Policy permits unauthorized inline scripts, external malicious script loading, and unauthorized data exfiltration, drastically increasing XSS risk.",
            "recommended": "default-src 'self'; frame-ancestors 'self'; script-src 'self';",
            "nginx": 'add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\';" always;',
            "apache": 'Header always set Content-Security-Policy "default-src \'self\'; frame-ancestors \'self\';"',
        }

    if "permissions-policy" in combined or "feature-policy" in combined:
        return {
            "category": "Browser Feature Permissions",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-16",
            "impact": "Allows embedded third-party iframes to access hardware and sensitive browser APIs (camera, microphone, geolocation, payment, usb) without explicit restrictions.",
            "recommended": "camera=(), microphone=(), geolocation=()",
            "nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
            "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
        }

    if "wildcard" in combined and ("certificate" in combined or "ssl" in combined or "cert" in combined):
        return {
            "category": "TLS / Certificate Policy",
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-295",
            "impact": "Wildcard certificates (*.domain.com) share a single private key across all subdomains. A compromise on any staging or legacy server using this key compromises the security of all subdomains.",
            "recommended": "Use separate SSL/TLS certificates per subdomain using automated ACME / Let's Encrypt tooling.",
            "nginx": "# Configure discrete SSL certificate per virtual host:\nssl_certificate /etc/ssl/certs/subdomain.crt;\nssl_certificate_key /etc/ssl/private/subdomain.key;",
            "apache": "# VirtualHost discrete certificate:\nSSLCertificateFile /etc/ssl/certs/subdomain.crt\nSSLCertificateKeyFile /etc/ssl/private/subdomain.key",
        }

    if "cookie" in combined and ("httponly" in combined or "secure" in combined or "samesite" in combined):
        return {
            "category": "Insecure Cookie Flags",
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-614 / CWE-1004",
            "impact": "Cookies missing Secure can be intercepted over plaintext HTTP. Cookies missing HttpOnly can be accessed and stolen via client-side JavaScript (XSS attacks).",
            "recommended": "Secure; HttpOnly; SameSite=Lax (or Strict)",
            "nginx": 'proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";',
            "apache": 'Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"',
        }

    if "cors" in combined or "access-control-allow-origin" in combined or "cross-domain" in combined:
        return {
            "category": "Permissive CORS Policy",
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-942",
            "impact": "Wildcard or misconfigured Access-Control-Allow-Origin headers allow malicious websites to issue authenticated cross-origin requests and read sensitive API response payloads.",
            "recommended": "Explicit origin whitelist instead of '*' or echoing request origin.",
            "nginx": 'add_header Access-Control-Allow-Origin "https://yourdomain.com" always;',
            "apache": 'Header always set Access-Control-Allow-Origin "https://yourdomain.com"',
        }

    if "directory indexing" in combined or "directory listing" in combined or "index of /" in combined:
        return {
            "category": "Directory Listing Enabled",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-548",
            "impact": "Automatic directory listings expose all files and folders in directory paths, allowing attackers to discover unlinked source files, backups, and logs.",
            "recommended": "Disable automatic directory indexing (autoindex off / Options -Indexes).",
            "nginx": "autoindex off;",
            "apache": "Options -Indexes",
        }

    if "trace method" in combined or "http method" in combined or "dangerous method" in combined:
        return {
            "category": "Dangerous HTTP Methods",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-650",
            "impact": "Insecure HTTP methods such as TRACE enable Cross-Site Tracing (XST) to steal HTTP-only credentials; uncontrolled PUT/DELETE allow unauthorized file manipulation.",
            "recommended": "Limit allowed methods to GET, POST, HEAD, OPTIONS.",
            "nginx": "if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$ ) {\n    return 405;\n}",
            "apache": "<LimitExcept GET POST HEAD OPTIONS>\n    Require all denied\n</LimitExcept>",
        }

    if "uncommon header" in combined or "x-powered-by" in combined or "server banner" in combined or "reveals" in combined or "version" in combined:
        return {
            "category": "Information Disclosure",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-200",
            "impact": "Exposes server software, exact version numbers, and framework details, giving attackers precise intelligence to lookup known CVEs and exploit version-specific vulnerabilities.",
            "recommended": "Suppress server tokens, banner strings, and framework disclosure headers.",
            "nginx": "server_tokens off;\nproxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;",
            "apache": "ServerSignature Off\nServerTokens Prod\nHeader unset X-Powered-By",
        }

    if ".git" in combined or ".env" in combined or "backup" in combined or "dump" in combined or "archive" in combined or ".sql" in combined or ".tar" in combined or ".zip" in combined:
        return {
            "category": "Sensitive File & Source Code Exposure",
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-538",
            "impact": "Direct access to version control repositories, environment files, or backups allows attackers to download source code, database dumps, passwords, and private API keys.",
            "recommended": "Block direct web access to dotfiles (.git, .env) and backup extensions immediately.",
            "nginx": "location ~ /\\.(?!well-known).* {\n    deny all;\n    return 404;\n}",
            "apache": '<FilesMatch "^\\.(?!well-known)">\n    Require all denied\n</FilesMatch>',
        }

    return {
        "category": "Server Configuration & Hygiene",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-16",
        "impact": "Exposes server configuration anomalies or potentially unhardened endpoint behavior that may assist attackers in reconnaissance and exploitation.",
        "recommended": "Inspect the identified resource, review access control policies, and verify against server security baseline.",
        "nginx": "# Review endpoint configuration:\nlocation /path {\n    # Restrict permissions or deny public access\n}",
        "apache": '# Review endpoint directives:\n<Directory "/path">\n    # Restrict permissions or require authentication\n</Directory>',
    }


def export_html_report(target: str, findings: List[Dict[str, Any]], stats: Dict[str, Any], banner: str) -> str:
    """Generate high-quality, fully interactive standalone HTML report for Nikto results with live filters and remediation."""
    date_str = time.strftime("%Y-%m-%d %H:%M:%S")

    sev_color = {
        "CRITICAL": "#f85149",
        "HIGH": "#f97316",
        "MEDIUM": "#d29922",
        "LOW": "#58a6ff",
        "INFO": "#8b949e",
    }

    rows_html = ""
    for idx, f in enumerate(findings, 1):
        sev = (f.get("severity") or "INFO").upper()
        col = sev_color.get(sev, "#8b949e")

        raw_title = f.get("title") or f.get("id") or ""
        clean_title = re.sub(r"\.?\s*(?:See|Reference):\s*https?://\S+", "", raw_title, flags=re.IGNORECASE).strip()
        if clean_title and not clean_title.endswith((".", ":", ";")):
            clean_title += "."

        raw_desc = f.get("description") or f.get("title") or "No description provided."
        clean_desc = re.sub(r"\.?\s*(?:See|Reference):\s*https?://\S+", "", raw_desc, flags=re.IGNORECASE).strip()
        if clean_desc and not clean_desc.endswith((".", ":", ";")):
            clean_desc += "."

        target_url = f.get("url") or target
        method = f.get("method") or "GET"
        evidence = f.get("evidence") or "No raw evidence captured."
        curl = f.get("curl_command") or f"curl -i -k '{target_url}'"

        ref_url = f.get("reference_url")
        if not ref_url:
            refs = f.get("references")
            if isinstance(refs, list) and refs and refs[0]:
                ref_url = str(refs[0]).strip()
        if not ref_url:
            m = re.search(r"(?:See|Reference):\s*(https?://[^\s\"',]+)", f"{raw_title} {raw_desc} {evidence}", re.IGNORECASE)
            if m:
                ref_url = re.sub(r"[.,;)]+$", "", m.group(1)).strip()

        fid = f.get("osvdb") or f.get("id") or ""
        kb = get_nikto_knowledge(f)

        searchable_text = html.escape(f"{sev} {clean_title} {clean_desc} {target_url} {fid} {kb['category']} {kb['owasp']} {kb['cwe']} {evidence}").lower()

        rows_html += f"""
        <!-- Finding Row #{idx} -->
        <tr class="finding-row" data-sev="{sev}" data-idx="{idx}" data-search="{searchable_text}">
            <td style="padding:10px;text-align:center;font-weight:700;color:#8b949e;font-size:11px;">{idx}</td>
            <td style="padding:10px;font-weight:700;">
                <span class="badge badge-{sev.lower()}">{sev}</span>
            </td>
            <td style="padding:10px;">
                <div style="font-weight:700;color:#ffffff;font-size:12.5px;line-height:1.4;">{html.escape(clean_title)}</div>
                <div class="tags-row" style="margin-top:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                    {f'<span class="id-badge">{html.escape(fid)}</span>' if fid else ''}
                    <span class="tag-pill tag-cat">🏷️ {html.escape(kb['category'])}</span>
                    <span class="tag-pill tag-owasp">🛡️ {html.escape(kb['owasp'])}</span>
                    <span class="tag-pill tag-cwe">🎯 {html.escape(kb['cwe'])}</span>
                </div>
            </td>
            <td style="padding:10px;">
                <div style="display:inline-flex;align-items:center;gap:6px;background:#0d1117;padding:4px 8px;border-radius:4px;border:1px solid #30363d;max-width:100%;box-sizing:border-box;">
                    <span class="method-badge">{html.escape(method)}</span>
                    <a href="{html.escape(target_url)}" target="_blank" rel="noopener noreferrer" style="font-family:monospace;font-size:11.5px;color:#58a6ff;text-decoration:none;word-break:break-all;" title="Open target endpoint">{html.escape(target_url)}</a>
                </div>
            </td>
            <td style="padding:10px;text-align:center;">
                <button class="btn-toggle" id="btn-toggle-{idx}" onclick="toggleDetail({idx})">▼ Details &amp; Fix</button>
            </td>
        </tr>

        <!-- Expanded Details Row #{idx} -->
        <tr class="detail-row" id="detail-row-{idx}" data-sev="{sev}" data-search="{searchable_text}">
            <td colspan="5" style="padding:12px 14px;background:#131822;border-bottom:2px solid #30363d;">
                <div class="split-detail-grid">
                    <!-- Left: Problem & Evidence -->
                    <div class="detail-col">
                        <div class="card-box">
                            <div class="card-title">📝 SCANNER OBSERVATION &amp; DETAILS</div>
                            <div class="desc-card">{html.escape(clean_desc)}</div>
                        </div>

                        <div class="card-box" style="border-left:3px solid #f97316;">
                            <div class="card-title" style="color:#f97316;">⚠️ SECURITY THREAT &amp; RISK IMPACT</div>
                            <div class="impact-card">{html.escape(kb['impact'])}</div>
                        </div>

                        <div class="card-box">
                            <div class="card-title" style="display:flex;justify-content:space-between;align-items:center;">
                                <span>📑 RAW SCANNER EVIDENCE</span>
                                <button class="btn-copy" onclick="copyFromId('evid-{idx}', this)">📋 Copy Evidence</button>
                            </div>
                            <pre class="code-block" id="evid-{idx}">{html.escape(evidence)}</pre>
                        </div>
                    </div>

                    <!-- Right: Remediation & Server Code -->
                    <div class="detail-col">
                        <div class="card-box" style="border-left:3px solid #38bdf8;">
                            <div class="card-title" style="color:#38bdf8;display:flex;justify-content:space-between;align-items:center;">
                                <span>🛠️ SMART REMEDIATION &amp; SERVER HARDENING</span>
                                <button class="btn-copy" onclick="copyFromId('recom-{idx}', this)">📋 Copy Directive</button>
                            </div>
                            <div style="font-size:11px;color:#8b949e;margin-bottom:4px;">Recommended value:</div>
                            <div class="recom-card" id="recom-{idx}">{html.escape(kb['recommended'])}</div>

                            <!-- Nginx Snippet -->
                            <div class="snippet-wrap">
                                <div class="snippet-head">
                                    <span>🟢 <b>Nginx</b> Configuration (<code>nginx.conf</code>)</span>
                                    <button class="btn-copy" onclick="copyFromId('snip-nginx-{idx}', this)">📋 Copy</button>
                                </div>
                                <pre class="snippet-code" id="snip-nginx-{idx}">{html.escape(kb['nginx'])}</pre>
                            </div>

                            <!-- Apache Snippet -->
                            <div class="snippet-wrap">
                                <div class="snippet-head">
                                    <span>🔴 <b>Apache</b> Configuration (<code>.htaccess / httpd.conf</code>)</span>
                                    <button class="btn-copy" onclick="copyFromId('snip-apache-{idx}', this)">📋 Copy</button>
                                </div>
                                <pre class="snippet-code" id="snip-apache-{idx}">{html.escape(kb['apache'])}</pre>
                            </div>
                        </div>

                        {f'''
                        <div class="card-box" style="border-left:3px solid #3fb950;background:rgba(35,134,54,0.08);">
                            <div class="card-title" style="color:#3fb950;display:flex;justify-content:space-between;align-items:center;">
                                <span>📖 OFFICIAL ADVISORY &amp; RFC GUIDANCE</span>
                                <button class="btn-copy" onclick="copyFromId('ref-{idx}', this)">📋 Copy Link</button>
                            </div>
                            <div style="margin-top:4px;">
                                <a href="{html.escape(ref_url)}" target="_blank" rel="noopener noreferrer" class="ref-link" id="ref-{idx}">
                                    <span>🔗 {html.escape(ref_url)} ↗</span>
                                </a>
                            </div>
                        </div>
                        ''' if ref_url else ''}

                        <div class="card-box">
                            <div class="card-title" style="display:flex;justify-content:space-between;align-items:center;">
                                <span>⚡ REPRODUCTION CURL COMMAND</span>
                                <button class="btn-copy" onclick="copyFromId('curl-{idx}', this)">📋 Copy cURL</button>
                            </div>
                            <pre class="code-block" style="color:#58a6ff;cursor:pointer;" id="curl-{idx}" onclick="copyFromId('curl-{idx}', this)" title="Click to copy cURL">{html.escape(curl)}</pre>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
        """

    tot = stats.get('total', len(findings))
    crit = stats.get('critical', 0)
    high = stats.get('high', 0)
    med = stats.get('medium', 0)
    low = stats.get('low', 0)
    info = stats.get('info', 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nikto Web Server Security Audit - {html.escape(target)}</title>
<style>
  :root {{
    --bg: #0d1117;
    --bg2: #161b22;
    --bg3: #21262d;
    --border: #30363d;
    --text: #ffffff;
    --text2: #c9d1d9;
    --text3: #8b949e;
    --blue: #58a6ff;
    --green: #3fb950;
    --yellow: #d29922;
    --orange: #f97316;
    --red: #f85149;
    --purple: #a371f7;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text2);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1400px; margin: auto; }}
  
  /* Header Card */
  .header {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  }}
  .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }}
  .header h1 {{ margin: 0 0 6px 0; font-size: 21px; color: var(--text); font-weight: 800; display: flex; align-items: center; gap: 8px; }}
  .header-sub {{ font-size: 13px; color: var(--text3); }}
  .header-sub b {{ color: var(--blue); }}
  
  /* Stat Cards Deck (Clickable Filters) */
  .badge-deck {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 10px;
    margin-top: 18px;
  }}
  .stat-card {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    text-align: center;
    cursor: pointer;
    transition: all 0.18s ease;
    user-select: none;
  }}
  .stat-card:hover {{
    transform: translateY(-2px);
    border-color: var(--blue);
    background: #28303b;
  }}
  .stat-card.active {{
    border-color: var(--blue);
    background: rgba(88, 166, 255, 0.12);
    box-shadow: 0 0 0 1px var(--blue);
  }}
  .stat-card b {{ font-size: 22px; display: block; font-weight: 800; line-height: 1.2; }}
  .stat-card span {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; color: var(--text3); margin-top: 2px; display: block; }}
  
  /* Toolbar (Filters & Search) */
  .toolbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 12px;
    flex-wrap: wrap;
  }}
  .filter-pills {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }}
  .filter-pill {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text2);
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11.5px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.15s ease;
  }}
  .filter-pill:hover {{ border-color: var(--blue); color: var(--text); }}
  .filter-pill.active {{
    background: var(--blue);
    color: #ffffff;
    border-color: var(--blue);
  }}
  .search-wrap {{ flex: 1 1 260px; max-width: 420px; }}
  .search-input {{
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    padding: 6px 12px;
    font-size: 12px;
    outline: none;
    transition: border-color 0.15s ease;
  }}
  .search-input:focus {{ border-color: var(--blue); }}
  .toolbar-actions {{ display: flex; align-items: center; gap: 8px; }}
  .btn-action {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text2);
    padding: 5px 10px;
    border-radius: 4px;
    font-size: 11.5px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
  }}
  .btn-action:hover {{ border-color: var(--blue); color: var(--text); }}
  
  /* Table Layout */
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 4px 12px rgba(0,0,0,0.25);
  }}
  th {{
    background: var(--bg3);
    padding: 10px 12px;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text3);
    border-bottom: 1px solid var(--border);
    letter-spacing: 0.5px;
  }}
  tr.finding-row {{ border-bottom: 1px solid var(--border); transition: background 0.12s ease; }}
  tr.finding-row:hover {{ background: rgba(88, 166, 255, 0.04); }}
  
  /* Badges & Tags */
  .badge {{
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 10.5px;
    font-weight: 800;
    display: inline-block;
    letter-spacing: 0.5px;
  }}
  .badge-critical {{ background: rgba(248, 81, 73, 0.18); color: var(--red); border: 1px solid var(--red); }}
  .badge-high     {{ background: rgba(249, 115, 22, 0.18); color: var(--orange); border: 1px solid var(--orange); }}
  .badge-medium   {{ background: rgba(210, 153, 34, 0.18); color: var(--yellow); border: 1px solid var(--yellow); }}
  .badge-low      {{ background: rgba(88, 166, 255, 0.18); color: var(--blue); border: 1px solid var(--blue); }}
  .badge-info     {{ background: rgba(139, 148, 158, 0.18); color: var(--text3); border: 1px solid var(--text3); }}
  
  .id-badge {{
    font-size: 9.5px;
    padding: 1px 6px;
    border-radius: 3px;
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text3);
    font-family: var(--mono);
    font-weight: 600;
  }}
  .tag-pill {{
    font-size: 9.5px;
    font-weight: 600;
    font-family: var(--mono);
    padding: 1px 7px;
    border-radius: 12px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    white-space: nowrap;
  }}
  .tag-cat   {{ background: rgba(88, 166, 255, 0.12); border: 1px solid rgba(88, 166, 255, 0.35); color: #79c0ff; }}
  .tag-owasp {{ background: rgba(249, 115, 22, 0.12); border: 1px solid rgba(249, 115, 22, 0.35); color: #fb923c; }}
  .tag-cwe   {{ background: rgba(163, 113, 247, 0.12); border: 1px solid rgba(163, 113, 247, 0.35); color: #d2a8ff; }}
  
  .method-badge {{
    background: rgba(88, 166, 255, 0.15);
    border: 1px solid var(--blue);
    color: var(--blue);
    font-size: 9.5px;
    font-weight: 800;
    font-family: var(--mono);
    padding: 1px 5px;
    border-radius: 3px;
    letter-spacing: 0.5px;
  }}
  
  .btn-toggle {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text2);
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
    white-space: nowrap;
  }}
  .btn-toggle:hover {{
    border-color: var(--blue);
    color: var(--blue);
    background: rgba(88, 166, 255, 0.08);
  }}
  
  .btn-copy {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text2);
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.12s ease;
  }}
  .btn-copy:hover {{ border-color: var(--blue); color: #ffffff; }}
  
  /* Collapsible Details Panel */
  tr.detail-row {{ display: none; }}
  tr.detail-row.expanded {{ display: table-row; }}
  
  .split-detail-grid {{
    display: grid;
    grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr);
    gap: 12px;
    align-items: start;
  }}
  @media (max-width: 1024px) {{
    .split-detail-grid {{ grid-template-columns: 1fr; }}
  }}
  .detail-col {{ display: flex; flex-direction: column; gap: 10px; min-width: 0; }}
  
  .card-box {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 8px 12px;
    box-sizing: border-box;
  }}
  .card-title {{
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    color: var(--text3);
    margin-bottom: 4px;
    letter-spacing: 0.5px;
  }}
  .desc-card {{
    line-height: 1.5;
    font-size: 11.5px;
    color: var(--text2);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 7px 10px;
    word-break: break-word;
  }}
  .impact-card {{
    line-height: 1.5;
    font-size: 11.5px;
    color: #fbd38d;
    background: rgba(249, 115, 22, 0.07);
    border: 1px solid rgba(249, 115, 22, 0.3);
    border-radius: 4px;
    padding: 7px 10px;
    word-break: break-word;
  }}
  .recom-card {{
    line-height: 1.5;
    font-size: 11px;
    font-family: var(--mono);
    font-weight: 600;
    color: #7ee787;
    background: rgba(56, 189, 248, 0.08);
    border: 1px solid rgba(56, 189, 248, 0.28);
    border-radius: 4px;
    padding: 6px 9px;
    word-break: break-word;
  }}
  .code-block {{
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-all;
    margin: 4px 0 0 0;
    background: var(--bg);
    padding: 6px 8px;
    border-radius: 4px;
    border: 1px solid var(--border);
  }}
  .snippet-wrap {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-top: 6px;
    overflow: hidden;
  }}
  .snippet-head {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg3);
    padding: 4px 8px;
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text2);
    border-bottom: 1px solid var(--border);
  }}
  .snippet-code {{
    margin: 0;
    padding: 6px 9px;
    font-family: var(--mono);
    font-size: 10.5px;
    line-height: 1.4;
    color: var(--blue);
    background: #090d13;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .ref-link {{
    color: var(--blue);
    font-family: var(--mono);
    font-size: 11px;
    text-decoration: none;
    display: inline-block;
    word-break: break-all;
  }}
  .ref-link:hover {{ text-decoration: underline; color: #79c0ff; }}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="header-top">
      <div>
        <h1>🌐 Nikto Web Server Security Audit Report</h1>
        <div class="header-sub">
          Target: <a href="{html.escape(target)}" target="_blank" rel="noopener noreferrer" style="color:var(--blue);text-decoration:none;"><b>{html.escape(target)}</b></a>
          &nbsp;|&nbsp; Server Banner: <b>{html.escape(banner)}</b>
          &nbsp;|&nbsp; Generated: <b>{date_str}</b>
        </div>
      </div>
    </div>

    <!-- Clickable Interactive Stat Cards -->
    <div class="badge-deck">
      <div class="stat-card active" id="card-all" onclick="filterSev('ALL')">
        <b>{tot}</b>
        <span>Total Findings</span>
      </div>
      <div class="stat-card" id="card-critical" onclick="filterSev('CRITICAL')">
        <b style="color:var(--red);">{crit}</b>
        <span>Critical</span>
      </div>
      <div class="stat-card" id="card-high" onclick="filterSev('HIGH')">
        <b style="color:var(--orange);">{high}</b>
        <span>High</span>
      </div>
      <div class="stat-card" id="card-medium" onclick="filterSev('MEDIUM')">
        <b style="color:var(--yellow);">{med}</b>
        <span>Medium</span>
      </div>
      <div class="stat-card" id="card-low" onclick="filterSev('LOW')">
        <b style="color:var(--blue);">{low}</b>
        <span>Low</span>
      </div>
      <div class="stat-card" id="card-info" onclick="filterSev('INFO')">
        <b style="color:var(--text3);">{info}</b>
        <span>Info</span>
      </div>
    </div>
  </div>

  <!-- Interactive Controls Toolbar -->
  <div class="toolbar">
    <div class="filter-pills">
      <span style="font-size:11px;font-weight:700;color:var(--text3);margin-right:4px;">FILTER:</span>
      <button class="filter-pill active" id="pill-all" onclick="filterSev('ALL')">All ({tot})</button>
      <button class="filter-pill" id="pill-critical" onclick="filterSev('CRITICAL')">Critical ({crit})</button>
      <button class="filter-pill" id="pill-high" onclick="filterSev('HIGH')">High ({high})</button>
      <button class="filter-pill" id="pill-medium" onclick="filterSev('MEDIUM')">Medium ({med})</button>
      <button class="filter-pill" id="pill-low" onclick="filterSev('LOW')">Low ({low})</button>
      <button class="filter-pill" id="pill-info" onclick="filterSev('INFO')">Info ({info})</button>
    </div>

    <div class="search-wrap">
      <input type="text" id="report-search-input" class="search-input" placeholder="🔍 Search findings, URLs, OWASP, CWE, keywords..." oninput="handleSearch(this.value)">
    </div>

    <div class="toolbar-actions">
      <button class="btn-action" onclick="toggleAllDetails()">↕ Expand / Collapse All</button>
    </div>
  </div>

  <div id="filter-counter-text" style="font-size:11.5px;color:var(--text3);margin-bottom:10px;font-weight:600;">
    Showing <b>{tot}</b> of <b>{tot}</b> findings
  </div>

  <!-- Findings Table -->
  <table>
    <thead>
      <tr>
        <th style="width:40px;text-align:center;">#</th>
        <th style="width:85px;">Severity</th>
        <th>Vulnerability &amp; Classification</th>
        <th style="width:340px;">Matched Target Endpoint</th>
        <th style="width:120px;text-align:center;">Action</th>
      </tr>
    </thead>
    <tbody id="report-findings-body">
      {rows_html if rows_html else '<tr><td colspan="5" style="text-align:center;padding:36px;color:var(--text3);">No vulnerabilities or misconfigurations discovered.</td></tr>'}
    </tbody>
  </table>
</div>

<script>
  let activeSev = 'ALL';
  let searchQuery = '';
  let allExpanded = false;

  function filterSev(sev) {{
    activeSev = sev;

    // Update active class on stat cards
    const cards = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    cards.forEach(s => {{
      const c = document.getElementById('card-' + s.toLowerCase());
      if (c) c.classList.toggle('active', s === sev);
      const p = document.getElementById('pill-' + s.toLowerCase());
      if (p) p.classList.toggle('active', s === sev);
    }});

    applyFilters();
  }}

  function handleSearch(q) {{
    searchQuery = (q || '').trim().toLowerCase();
    applyFilters();
  }}

  function applyFilters() {{
    const rows = document.querySelectorAll('tr.finding-row');
    let visibleCount = 0;

    rows.forEach(row => {{
      const idx = row.getAttribute('data-idx');
      const sev = row.getAttribute('data-sev') || '';
      const text = row.getAttribute('data-search') || '';
      const detailRow = document.getElementById('detail-row-' + idx);

      const matchesSev = (activeSev === 'ALL' || sev === activeSev);
      const matchesSearch = (!searchQuery || text.includes(searchQuery));

      if (matchesSev && matchesSearch) {{
        row.style.display = '';
        visibleCount++;
      }} else {{
        row.style.display = 'none';
        if (detailRow) detailRow.classList.remove('expanded');
      }}
    }});

    const counter = document.getElementById('filter-counter-text');
    if (counter) {{
      counter.innerHTML = 'Showing <b>' + visibleCount + '</b> of <b>{tot}</b> findings' + (activeSev !== 'ALL' ? ' (Filter: ' + activeSev + ')' : '');
    }}
  }}

  function toggleDetail(idx) {{
    const row = document.getElementById('detail-row-' + idx);
    const btn = document.getElementById('btn-toggle-' + idx);
    if (!row) return;

    const isExpanded = row.classList.contains('expanded');
    if (isExpanded) {{
      row.classList.remove('expanded');
      if (btn) btn.innerHTML = '▼ Details &amp; Fix';
    }} else {{
      row.classList.add('expanded');
      if (btn) btn.innerHTML = '▲ Hide Details';
    }}
  }}

  function toggleAllDetails() {{
    allExpanded = !allExpanded;
    const detailRows = document.querySelectorAll('tr.detail-row');
    detailRows.forEach(d => {{
      const idx = d.id.replace('detail-row-', '');
      const parentRow = document.querySelector('tr.finding-row[data-idx="' + idx + '"]');
      if (parentRow && parentRow.style.display !== 'none') {{
        d.classList.toggle('expanded', allExpanded);
        const btn = document.getElementById('btn-toggle-' + idx);
        if (btn) btn.innerHTML = allExpanded ? '▲ Hide Details' : '▼ Details &amp; Fix';
      }}
    }});
  }}

  function copyFromId(id, btn) {{
    const el = document.getElementById(id);
    if (!el) return;
    const text = el.innerText || el.textContent || '';
    copyText(text, btn);
  }}

  function copyText(text, btn) {{
    if (!text) return;
    const originalText = btn ? btn.textContent : '';

    function flash() {{
      if (btn) {{
        btn.textContent = '✓ Copied!';
        setTimeout(() => {{ btn.textContent = originalText; }}, 1400);
      }}
    }}

    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(flash).catch(fallback);
    }} else {{
      fallback();
    }}

    function fallback() {{
      try {{
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        flash();
      }} catch (e) {{
        alert('Could not copy to clipboard.');
      }}
    }}
  }}
</script>
</body>
</html>"""

