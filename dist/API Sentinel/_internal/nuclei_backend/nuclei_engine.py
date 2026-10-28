"""
Nuclei Scanning & Execution Engine
Dual-mode engine:
  Mode 1: Executes real `nuclei` CLI subprocess with `-jsonl` stream if binary is present.
  Mode 2: Native Python API Security Baseline Engine if binary is not yet installed.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from nuclei_backend.binary_helper import find_nuclei_binary

logger = logging.getLogger("nuclei_engine")

# ANSI color code cleaner for raw CLI output
ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def clean_ansi(text: str) -> str:
    return ANSI_REGEX.sub("", text)


class ScanJob:
    def __init__(
        self,
        job_id: str,
        target_type: str,
        base_url: str,
        targets: List[str],
        headers: Dict[str, str],
        tags: List[str],
        rate_limit: int = 50,
        timeout: int = 10,
    ):
        self.job_id = job_id
        self.target_type = target_type
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.targets = targets
        self.headers = headers
        self.tags = tags
        self.rate_limit = rate_limit
        self.timeout = timeout

        self.status = "queued"  # queued | running | completed | stopped | failed
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None

        self.stats = {
            "total_targets": len(targets),
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self.findings: List[Dict[str, Any]] = []
        self.logs: List[str] = []

        self._process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()
        self._subscribers: List[collections.deque] = []
        self._lock = threading.Lock()

    def add_log(self, msg: str):
        cleaned = clean_ansi(msg.strip())
        if not cleaned:
            return
        with self._lock:
            self.logs.append(cleaned)
            # Notify subscribers
            self._broadcast({"type": "log", "message": cleaned})

    def add_verbose(self, msg: str):
        cleaned = clean_ansi(msg.strip())
        if not cleaned:
            return
        with self._lock:
            self._broadcast({"type": "verbose", "message": cleaned})

    def add_stats_tick(self, msg_or_data: Any):
        progress_data = {"message": "", "percent": 0, "current": 0, "total": 0, "rps": 0, "hosts": 0}
        cleaned = ""

        if isinstance(msg_or_data, dict):
            sdata = msg_or_data
            cur_req = int(sdata.get("requests") or 0)
            tot_req = int(sdata.get("total") or 0)
            pct = int(sdata.get("percent") or 0)
            rps = int(sdata.get("rps") or 0)
            hosts = int(sdata.get("hosts") or 0)
            duration = str(sdata.get("duration") or "")
            cleaned = f"[{duration}] | Requests: {cur_req}/{tot_req} ({pct}%) | RPS: {rps} | Hosts: {hosts}"
            progress_data = {
                "message": cleaned,
                "percent": pct,
                "current": cur_req,
                "total": tot_req,
                "rps": rps,
                "hosts": hosts,
            }
        elif isinstance(msg_or_data, str):
            cleaned = clean_ansi(msg_or_data.strip())
            if not cleaned:
                return
            if cleaned.startswith("{") and ("requests" in cleaned or "duration" in cleaned):
                try:
                    sdata = json.loads(cleaned)
                    cur_req = int(sdata.get("requests") or 0)
                    tot_req = int(sdata.get("total") or 0)
                    pct = int(sdata.get("percent") or 0)
                    rps = int(sdata.get("rps") or 0)
                    hosts = int(sdata.get("hosts") or 0)
                    duration = str(sdata.get("duration") or "")
                    formatted = f"[{duration}] | Requests: {cur_req}/{tot_req} ({pct}%) | RPS: {rps} | Hosts: {hosts}"
                    progress_data = {
                        "message": formatted,
                        "percent": pct,
                        "current": cur_req,
                        "total": tot_req,
                        "rps": rps,
                        "hosts": hosts,
                    }
                    cleaned = formatted
                except Exception:
                    pass

            if not progress_data["current"]:
                req_match = re.search(r"Requests:\s*(\d+)/(\d+)\s*\((\d+)%\)", cleaned)
                if req_match:
                    progress_data["current"] = int(req_match.group(1))
                    progress_data["total"] = int(req_match.group(2))
                    progress_data["percent"] = int(req_match.group(3))
                rps_match = re.search(r"RPS:\s*(\d+)", cleaned)
                if rps_match:
                    progress_data["rps"] = int(rps_match.group(1))
                hosts_match = re.search(r"Hosts:\s*(\d+)", cleaned)
                if hosts_match:
                    progress_data["hosts"] = int(hosts_match.group(1))
                progress_data["message"] = cleaned

        with self._lock:
            if progress_data.get("percent", 0) > 0:
                self.stats["progress_percent"] = progress_data["percent"]
            if progress_data.get("current", 0) > 0:
                self.stats["requests_probed"] = progress_data["current"]
            if progress_data.get("total", 0) > 0:
                self.stats["requests_total"] = progress_data["total"]
            if progress_data.get("rps", 0) > 0:
                self.stats["rps"] = progress_data["rps"]
            self._broadcast({"type": "stats_tick", "message": cleaned, "progress": progress_data})

    def add_finding(self, finding: Dict[str, Any]):
        sev = str(finding.get("severity") or "info").upper()
        with self._lock:
            self.findings.append(finding)
            self.stats["findings"] += 1
            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                self.stats[sev.lower()] += 1
            else:
                self.stats["info"] += 1

            self._broadcast({"type": "finding", "data": finding, "stats": dict(self.stats)})

    def subscribe(self) -> collections.deque:
        with self._lock:
            q = collections.deque()
            self._subscribers.append(q)
            # Replay existing findings and recent logs to newly connected subscriber
            for f in self.findings:
                q.append({"type": "finding", "data": f, "stats": dict(self.stats)})
            for l in self.logs[-40:]:
                q.append({"type": "log", "message": l})
            if self.status in ("completed", "stopped", "failed"):
                q.append({"type": "done", "status": self.status, "stats": dict(self.stats)})
            return q

    def unsubscribe(self, q: collections.deque):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast(self, item: Dict[str, Any]):
        for q in self._subscribers:
            q.append(item)

    def stop(self):
        self._stop_event.set()
        self.status = "stopped"
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=2)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
        self.finished_at = time.time()
        self.add_log("🛑 Scan was manually stopped by user.")
        self._broadcast({"type": "done", "status": "stopped", "stats": dict(self.stats)})


# In-memory jobs store
_JOBS: Dict[str, ScanJob] = {}
_JOBS_LOCK = threading.Lock()


def get_job(job_id: str) -> Optional[ScanJob]:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def create_job(
    target_type: str,
    base_url: str,
    targets: List[str],
    headers: Dict[str, str],
    tags: List[str],
    rate_limit: int = 50,
    timeout: int = 10,
) -> ScanJob:
    jid = f"nuc_{uuid.uuid4().hex[:10]}"
    job = ScanJob(
        job_id=jid,
        target_type=target_type,
        base_url=base_url,
        targets=targets,
        headers=headers,
        tags=tags,
        rate_limit=rate_limit,
        timeout=timeout,
    )
    with _JOBS_LOCK:
        _JOBS[jid] = job
    return job


def run_scan_job(job: ScanJob):
    """Worker thread that executes either Nuclei CLI or native fallback baseline."""
    job.started_at = time.time()
    job.status = "running"
    bin_path = find_nuclei_binary()

    if bin_path:
        _run_nuclei_cli(job, bin_path)
    else:
        _run_native_baseline(job)

    if job.status == "running":
        job.status = "completed"
        job.finished_at = time.time()
        elapsed = round(job.finished_at - job.started_at, 1)
        tot_req = job.stats.get("requests_total") or len(job.targets)
        job.add_log(f"🏁 Scan completed in {elapsed}s. Findings: {job.stats['findings']}")
        job._broadcast({
            "type": "done",
            "status": "completed",
            "stats": dict(job.stats),
            "progress": {
                "percent": 100,
                "status": "completed",
                "current": tot_req,
                "total": tot_req,
            }
        })


# ── Mode 1: Real Nuclei CLI Execution ──────────────────────────────────────────

def _run_nuclei_cli(job: ScanJob, bin_path: str):
    job.add_log(f"⚡ Starting official Nuclei engine: {bin_path}")
    job.add_log(f"🎯 Targets: {len(job.targets)} | Tags: {','.join(job.tags) if job.tags else 'api,misconfig'}")

    # Write targets to temp file
    tmp_dir = tempfile.mkdtemp(prefix="api_sentinel_nuclei_")
    targets_file = os.path.join(tmp_dir, "targets.txt")

    try:
        with open(targets_file, "w", encoding="utf-8") as tf:
            for t in job.targets:
                clean_t = t.strip()
                if clean_t:
                    if not clean_t.startswith("http://") and not clean_t.startswith("https://"):
                        clean_t = "https://" + clean_t
                    tf.write(clean_t + "\n")

        # Dynamic Rate Limiting & Concurrency (Anti-Ban / Stealth Control)
        rl = int(job.rate_limit or 15)
        if rl <= 5:
            concurrency = 2
        elif rl <= 15:
            concurrency = 5
        elif rl <= 30:
            concurrency = 10
        else:
            concurrency = 15

        cmd = [
            bin_path,
            "-list", targets_file,
            "-jsonl",
            "-type", "http",
            "-v",  # Stream real-time request probes
            "-stats",  # Periodic statistics
            "-stats-interval", "3",  # Every 3 seconds
            "-rate-limit", str(rl),
            "-concurrency", str(concurrency),
            "-retries", "2",
            "-timeout", str(job.timeout or 10),
            "-nmhe",  # Disable skipping host from scan based on errors/WAF drops
            "-no-interactsh",
        ]
        if rl <= 5:
            cmd.extend(["-rate-limit-duration", "1s"])

        # Check and attach global upstream proxy if configured
        try:
            import proxy_config
            pcfg = proxy_config.get_config()
            if pcfg.get("enabled") and pcfg.get("host"):
                proto = (pcfg.get("protocol") or "http").lower().strip()
                host = pcfg.get("host", "").strip()
                port = str(pcfg.get("port") or "").strip()
                auth = ""
                if pcfg.get("auth_enabled") and pcfg.get("username"):
                    u = pcfg.get("username")
                    p = pcfg.get("password", "")
                    auth = f"{u}:{p}@"
                # Nuclei Go runtime natively supports http:// and socks5://
                if proto == "socks4":
                    proto = "socks5"
                    job.add_log(f"ℹ️ Note: Nuclei requires SOCKS5/HTTP; automatically routing port {port} via socks5://{host}:{port}")

                proxy_url = f"{proto}://{auth}{host}" + (f":{port}" if port else "")
                cmd.extend(["-proxy", proxy_url])
                job.add_log(f"🌐 Upstream Proxy Active: {proto}://{host}:{port} (All scan traffic routed through proxy)")
        except Exception as pe:
            logger.warning(f"Could not read proxy config for Nuclei: {pe}")

        # Add custom headers
        for k, v in job.headers.items():
            k_clean = k.strip()
            v_clean = re.sub(r'[\r\n]+', ' ', str(v).strip())
            if k_clean and v_clean:
                cmd.extend(["-H", f"{k_clean}: {v_clean}"])

        if job.headers:
            masked = []
            for k, v in job.headers.items():
                if any(x in k.lower() for x in ("auth", "token", "key", "cookie")):
                    v_mask = v[:15] + "..." + v[-4:] if len(v) > 22 else v
                    masked.append(f"{k}: {v_mask}")
                else:
                    masked.append(f"{k}: {v}")
            job.add_log(f"🔑 Headers Attached to Engine ({len(job.headers)}): {', '.join(masked)}")

        # Add tags (expanded for complete coverage)
        expanded_tags = []
        for tag in (job.tags or ["api", "misconfig", "exposure"]):
            t = tag.strip().lower()
            if t == "tokens":
                expanded_tags.extend(["token", "tokens", "secrets"])
            else:
                expanded_tags.append(t)
        if expanded_tags:
            cmd.extend(["-tags", ",".join(dict.fromkeys(expanded_tags))])

        job.add_log(f"🚀 Running command: {' '.join(cmd[:6])} ... [flags]")

        job._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=os.environ.copy(),
        )

        # Thread for reading stderr (progress / info / verbose logs)
        def _read_stderr(proc: subprocess.Popen):
            if proc.stderr:
                for line in proc.stderr:
                    if job._stop_event.is_set():
                        break
                    l = line.strip()
                    if not l:
                        continue
                    clean_l = clean_ansi(l)

                    # 1. Stats line in JSON format (modern nuclei with -j/-jsonl)
                    if clean_l.startswith("{") and ("duration" in clean_l or "requests" in clean_l):
                        job.add_stats_tick(clean_l)
                        # Handled by stats ticker; do NOT dump raw JSON to main console log
                        continue

                    # 2. Stats ticker line: e.g. [0:00:03] | Templates: 60 | Hosts: 1 | RPS: 12 | Requests: 36/174 (20%)
                    if "|" in clean_l and ("Requests:" in clean_l or "Templates:" in clean_l or "RPS:" in clean_l):
                        job.add_stats_tick(clean_l)
                        job.add_verbose(clean_l)
                    # 3. Verbose probe request line
                    elif clean_l.startswith("[VER]") or "Sent HTTP request to" in clean_l:
                        job.add_verbose(clean_l)
                    # 4. Standard info / warnings / banners / errors
                    else:
                        job.add_log(f"[nuclei] {clean_l}")

        err_thread = threading.Thread(target=_read_stderr, args=(job._process,), daemon=True)
        err_thread.start()

        # Read stdout (JSONL findings + info)
        if job._process.stdout:
            for line in job._process.stdout:
                if job._stop_event.is_set():
                    break
                line_str = line.strip()
                if not line_str:
                    continue

                if line_str.startswith("{") and "template-id" in line_str:
                    try:
                        raw_json = json.loads(line_str)
                        info = raw_json.get("info", {}) or {}
                        f_item = {
                            "id": raw_json.get("template-id") or f"find_{uuid.uuid4().hex[:6]}",
                            "name": info.get("name") or raw_json.get("template-id") or "Finding",
                            "severity": (info.get("severity") or "info").upper(),
                            "description": info.get("description") or "",
                            "matched_at": raw_json.get("matched-at") or raw_json.get("host") or "",
                            "type": raw_json.get("type") or "http",
                            "tags": info.get("tags") or [],
                            "curl_command": raw_json.get("curl-command") or "",
                            "extracted_results": raw_json.get("extracted-results") or [],
                            "reference": info.get("reference") or [],
                            "timestamp": raw_json.get("timestamp") or time.strftime("%H:%M:%S"),
                        }
                        job.add_finding(f_item)
                        job.add_log(f"[{f_item['severity']}] {f_item['name']} -> {f_item['matched_at']}")
                    except Exception as pe:
                        job.add_log(f"[JSON parse error] {str(pe)}")
                else:
                    job.add_log(line_str)

        job._process.wait()

    except Exception as e:
        job.status = "failed"
        job.add_log(f"❌ Nuclei execution error: {str(e)}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Mode 2: Native Python API Security Baseline Engine (Fallback) ──────────────

# Curated High-Impact API Checks that run natively without any binary
NATIVE_API_PROBES = [
    {
        "id": "spring-actuator-env",
        "name": "Spring Boot Actuator Env Exposed",
        "severity": "HIGH",
        "path": "/actuator/env",
        "method": "GET",
        "description": "Spring Boot Actuator environment endpoint is publicly accessible, potentially exposing database credentials, API keys, and configuration properties.",
        "match_words": ["activeProfiles", "propertySources"],
        "match_status": [200],
    },
    {
        "id": "spring-actuator-health",
        "name": "Spring Boot Actuator Health Open",
        "severity": "LOW",
        "path": "/actuator/health",
        "method": "GET",
        "description": "Spring Boot Actuator health endpoint is accessible, exposing service health and disk/database status.",
        "match_words": ["\"status\":", "\"UP\""],
        "match_status": [200],
    },
    {
        "id": "swagger-docs-json",
        "name": "Swagger / OpenAPI Documentation Exposed",
        "severity": "MEDIUM",
        "path": "/v2/api-docs",
        "method": "GET",
        "description": "Full Swagger 2.0 API documentation is publicly accessible, exposing all internal routes, schemas, and parameters.",
        "match_words": ["\"swagger\":", "\"paths\":"],
        "match_status": [200],
    },
    {
        "id": "openapi-v3-docs",
        "name": "OpenAPI v3 JSON Specification Exposed",
        "severity": "MEDIUM",
        "path": "/openapi.json",
        "method": "GET",
        "description": "OpenAPI v3 specification is publicly accessible without authentication.",
        "match_words": ["\"openapi\":", "\"paths\":"],
        "match_status": [200],
    },
    {
        "id": "swagger-ui-html",
        "name": "Interactive Swagger UI Dashboard Exposed",
        "severity": "LOW",
        "path": "/swagger-ui.html",
        "method": "GET",
        "description": "Interactive Swagger UI page is accessible to unauthorized visitors.",
        "match_words": ["swagger-ui", "Swagger UI"],
        "match_status": [200],
    },
    {
        "id": "env-file-exposure",
        "name": "Environment (.env) Secrets File Leaked",
        "severity": "CRITICAL",
        "path": "/.env",
        "method": "GET",
        "description": "Environment configuration file (.env) is publicly downloadable, exposing database credentials, secret keys, and passwords.",
        "match_words": ["DB_PASSWORD", "APP_KEY", "AWS_SECRET", "SECRET_KEY", "PORT="],
        "match_status": [200],
    },
    {
        "id": "git-config-exposure",
        "name": "Git Repository (.git/config) Exposed",
        "severity": "HIGH",
        "path": "/.git/config",
        "method": "GET",
        "description": "Git repository configuration file is publicly accessible, allowing source code extraction and git metadata enumeration.",
        "match_words": ["[core]", "repositoryformatversion"],
        "match_status": [200],
    },
    {
        "id": "docker-compose-exposure",
        "name": "Docker Compose Configuration Leaked",
        "severity": "HIGH",
        "path": "/docker-compose.yml",
        "method": "GET",
        "description": "Docker compose configuration is exposed, leaking container architecture, internal ports, and environment passwords.",
        "match_words": ["version:", "services:", "image:"],
        "match_status": [200],
    },
    {
        "id": "graphql-introspection-open",
        "name": "GraphQL Schema Introspection Enabled",
        "severity": "MEDIUM",
        "path": "/graphql",
        "method": "POST",
        "json_body": {"query": "{ __schema { types { name } } }"},
        "description": "GraphQL Introspection query is enabled in production, allowing full extraction of internal data models and queries.",
        "match_words": ["__schema", "types"],
        "match_status": [200],
    },
]


def _run_native_baseline(job: ScanJob):
    job.add_log("💡 [NOTE] Nuclei binary not detected on system.")
    job.add_log("🛡️ Running API Sentinel Native Security Baseline Engine (10+ High-Impact API Checks)...")
    job.add_log("💡 (Install Nuclei via 'brew install nuclei' to enable 5,000+ community templates)")

    base_hosts = set()
    for t in job.targets:
        parsed = urllib.parse.urlparse(t)
        if parsed.scheme and parsed.netloc:
            base_hosts.add(f"{parsed.scheme}://{parsed.netloc}")
    if not base_hosts and job.base_url:
        base_hosts.add(job.base_url)

    job.add_log(f"🔍 Testing {len(base_hosts)} base target host(s) across {len(NATIVE_API_PROBES)} security rules...")

    session = requests.Session()
    session.verify = False

    total_native_probes = max(len(base_hosts) * (2 + len(NATIVE_API_PROBES)), 1)
    current_probe_num = 0

    for host in base_hosts:
        if job._stop_event.is_set():
            break

        current_probe_num += 1
        pct = int((current_probe_num / total_native_probes) * 100)
        job.add_stats_tick(f"Templates: 12 | RPS: 6 | Requests: {current_probe_num}/{total_native_probes} ({pct}%)")

        # 1. Check Missing Security Headers on Host
        try:
            r = session.get(host, headers=job.headers, timeout=job.timeout)
            sec_headers = {
                "Strict-Transport-Security": "HSTS header missing (Allows SSL-stripping)",
                "X-Content-Type-Options": "X-Content-Type-Options missing (MIME sniffing allowed)",
                "X-Frame-Options": "X-Frame-Options missing (Clickjacking risk)",
            }
            missing = [h for h, desc in sec_headers.items() if h not in r.headers]
            if missing:
                job.add_finding({
                    "id": "missing-security-headers",
                    "name": f"Missing Security Headers ({', '.join(missing)})",
                    "severity": "LOW",
                    "description": f"The API server does not send recommended protective HTTP headers: {', '.join(missing)}.",
                    "matched_at": host,
                    "type": "http",
                    "tags": ["headers", "misconfig"],
                    "curl_command": f"curl -i '{host}'",
                    "extracted_results": missing,
                    "reference": ["https://owasp.org/www-project-secure-headers/"],
                    "timestamp": time.strftime("%H:%M:%S"),
                })
                job.add_log(f"[LOW] Missing Security Headers on {host} ({', '.join(missing)})")
        except Exception as e:
            job.add_log(f"[Host probe notice] {host} -> {str(e)}")

        # 2. Check CORS Misconfiguration (Origin: https://evil.com)
        current_probe_num += 1
        pct = min(int((current_probe_num / total_native_probes) * 100), 99)
        job.add_stats_tick(f"Templates: 12 | RPS: 6 | Requests: {current_probe_num}/{total_native_probes} ({pct}%)")
        try:
            cors_headers = dict(job.headers)
            cors_headers["Origin"] = "https://evil.com"
            cr = session.get(host, headers=cors_headers, timeout=job.timeout)
            acao = cr.headers.get("Access-Control-Allow-Origin", "")
            acac = cr.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "https://evil.com" or (acao == "*" and acac == "true"):
                job.add_finding({
                    "id": "cors-arbitrary-origin",
                    "name": "Overly Permissive CORS (Arbitrary Origin Allowed)",
                    "severity": "HIGH",
                    "description": f"API reflects arbitrary Origin header '{acao}' allowing untrusted third-party sites to read sensitive API responses.",
                    "matched_at": host,
                    "type": "http",
                    "tags": ["cors", "misconfig"],
                    "curl_command": f"curl -i -H 'Origin: https://evil.com' '{host}'",
                    "extracted_results": [f"Access-Control-Allow-Origin: {acao}"],
                    "reference": ["https://portswigger.net/web-security/cors"],
                    "timestamp": time.strftime("%H:%M:%S"),
                })
                job.add_log(f"[HIGH] CORS Arbitrary Origin Vulnerability detected on {host}!")
        except Exception:
            pass

        # 3. Test Native API Probes (Actuator, Swagger, .env, git, GraphQL)
        for probe in NATIVE_API_PROBES:
            if job._stop_event.is_set():
                break

            current_probe_num += 1
            pct = min(int((current_probe_num / total_native_probes) * 100), 99)
            job.add_stats_tick(f"Templates: 12 | RPS: 6 | Requests: {current_probe_num}/{total_native_probes} ({pct}%)")

            target_url = host.rstrip("/") + probe["path"]
            method = probe.get("method", "GET").upper()
            job.add_verbose(f"[VER] [{probe['id']}] Sent HTTP {method} request to {target_url}")
            try:
                if method == "POST" and "json_body" in probe:
                    resp = session.post(target_url, json=probe["json_body"], headers=job.headers, timeout=job.timeout)
                else:
                    resp = session.get(target_url, headers=job.headers, timeout=job.timeout)

                status_ok = resp.status_code in probe.get("match_status", [200])
                words_ok = any(w in resp.text for w in probe.get("match_words", []))

                if status_ok and words_ok:
                    f_item = {
                        "id": probe["id"],
                        "name": probe["name"],
                        "severity": probe["severity"],
                        "description": probe["description"],
                        "matched_at": target_url,
                        "type": "http",
                        "tags": ["api", "misconfig", "exposure"],
                        "curl_command": f"curl -i -X {method} '{target_url}'",
                        "extracted_results": [f"Status: {resp.status_code}", f"Length: {len(resp.text)} bytes"],
                        "reference": [],
                        "timestamp": time.strftime("%H:%M:%S"),
                    }
                    job.add_finding(f_item)
                    job.add_log(f"[{probe['severity']}] 🚨 Found: {probe['name']} -> {target_url}")
                else:
                    job.add_log(f"[checked] {probe['name']} ({probe['path']}) -> HTTP {resp.status_code}")
            except Exception as pe:
                job.add_log(f"[skipped] {probe['path']} -> {str(pe)}")

            time.sleep(0.05)  # slight throttle

    if not job._stop_event.is_set():
        job.add_stats_tick(f"Templates: 12 | RPS: 6 | Requests: {total_native_probes}/{total_native_probes} (100%)")
