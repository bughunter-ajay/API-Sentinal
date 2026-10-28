"""
API Fuzzer Backend — Port 8796
Intelligent Auto-Fuzzing & Vulnerability Engine
"""

from __future__ import annotations

import copy
import json
import random
import re
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
from requests.adapters import HTTPAdapter

from fuzzer_backend.curl_parser import parse_curl_command

# Drop InsecureRequestWarning for testing targets with self-signed certs
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

app = FastAPI(title="API Fuzzer Backend", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory jobs store
jobs: Dict[str, dict] = {}
_jobs_lock = threading.Lock()
JOB_TTL = 3600
MAX_JOBS = 50


def _prune_jobs():
    now = time.time()
    with _jobs_lock:
        stale = [
            jid for jid, j in list(jobs.items())
            if j.get("status") not in ("running",) and now - float(j.get("finished_at") or j.get("created_at") or now) > JOB_TTL
        ]
        for jid in stale:
            jobs.pop(jid, None)
        if len(jobs) > MAX_JOBS:
            finished = sorted(
                (jid for jid, j in list(jobs.items()) if j.get("status") != "running"),
                key=lambda x: float(jobs[x].get("finished_at") or jobs[x].get("created_at") or 0),
            )
            for jid in finished[: max(0, len(jobs) - MAX_JOBS)]:
                jobs.pop(jid, None)


# ── Models ───────────────────────────────────────────────────────────────────

class TargetItem(BaseModel):
    id: Optional[str] = None
    type: str = "custom"  # 'marker', 'endpoint', 'path', 'query', 'json', 'header'
    key: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None
    label: Optional[str] = None
    enabled: bool = True

    @model_validator(mode="before")
    @classmethod
    def populate_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            k = data.get("key") or data.get("name") or data.get("id") or ""
            if not data.get("key"):
                data["key"] = k
            if not data.get("id"):
                data["id"] = data.get("id") or k or str(uuid.uuid4())
        return data


class ParseCurlRequest(BaseModel):
    curl: str


class FuzzStartRequest(BaseModel):
    curl: str
    targets: List[TargetItem] = []
    injection_payloads: List[str] = []
    endpoint_payloads: List[str] = []
    payloads: Optional[List[str]] = None
    threads: int = Field(default=5, ge=1, le=30)
    delay_ms: int = Field(default=0, ge=0, le=10000)
    randomize: bool = False
    url_encode: bool = True
    url_encode_chars: str = r".\=<>?+&*':;\"()|^`#"

    @model_validator(mode="before")
    @classmethod
    def normalize_payloads(cls, data: Any) -> Any:
        if isinstance(data, dict):
            p = data.get("payloads")
            if p and not data.get("injection_payloads"):
                data["injection_payloads"] = p
        return data


# ── Anomaly Signatures ────────────────────────────────────────────────────────

DBMS_PATTERNS = [
    # PostgreSQL
    (r"syntax error at or near", "PostgreSQL"),
    (r"unterminated quoted string", "PostgreSQL"),
    (r"psycopg2\.ProgrammingError", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    # MySQL / MariaDB
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"MySQL server version for the right syntax", "MySQL"),
    (r"com\.mysql\.jdbc\.exceptions", "MySQL"),
    (r"supplied argument is not a valid MySQL", "MySQL"),
    # SQLite
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"near \".*?\": syntax error", "SQLite"),
    (r"unrecognized token:", "SQLite"),
    # MSSQL
    (r"Driver\]\s*\[SQL Server\]", "MSSQL"),
    (r"Unclosed quotation mark before the character string", "MSSQL"),
    (r"Syntax error in string in query expression", "MSSQL"),
    # Oracle
    (r"ORA-01756", "Oracle"),
    (r"ORA-00933", "Oracle"),
    (r"ORA-00936", "Oracle"),
    # General / Generic
    (r"SQLSTATE\[\w+\]", "SQL"),
]

RCE_PATTERNS = [
    r"uid=\d+\(.*?\) gid=\d+",
    r"root:x:0:0:",
    r"Windows IP Configuration",
    r"\[extensions\]\s*[\r\n]+",
]

SECRET_PATTERNS = [
    (r"systemEnvironment", "Spring Environment Property Sources"),
    (r"propertySources", "Spring Boot Config Properties"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"\"AWS_SECRET_ACCESS_KEY\":\s*\"[^\"]+\"", "AWS Secret Key"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.", "Exposed JWT Token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "Private Key Disclosure"),
]


def detect_anomaly(
    payload: str,
    target: TargetItem,
    resp_status: int,
    resp_body: str,
    resp_time_ms: int,
    baseline: dict,
    endpoint_url: str
) -> Optional[dict]:
    """
    Evaluate response against baseline to identify security anomalies.
    Returns anomaly metadata dict or None.
    """
    baseline_status = baseline.get("status", 200)
    baseline_body = baseline.get("body", "")

    # 1. Database / SQL Error Leakage (Critical)
    for pat, db in DBMS_PATTERNS:
        if re.search(pat, resp_body, re.IGNORECASE) and not re.search(pat, baseline_body, re.IGNORECASE):
            return {
                "sev": "critical",
                "title": f"SQL Injection & {db} DBMS Error Leakage",
                "anomaly": f"{db} Syntax Error / Spiked",
                "evidence": f"Response explicitly leaked backend {db} driver error matching '{pat}'.",
            }

    # 2. Command Injection / OS Execution (Critical)
    for pat in RCE_PATTERNS:
        if re.search(pat, resp_body, re.IGNORECASE) and not re.search(pat, baseline_body, re.IGNORECASE):
            return {
                "sev": "critical",
                "title": "OS Command Injection / System File Disclosure",
                "anomaly": "Command Output / File Leak",
                "evidence": f"Injected command executed successfully. Detected system fingerprint matching '{pat}'.",
            }

    # 3. SSTI / Expression Evaluation (High)
    if any(expr in payload for expr in ("${7*7}", "{{7*7}}", "<%= 7*7 %>", "@(7*7)")):
        if "49" in resp_body and "49" not in baseline_body:
            return {
                "sev": "high",
                "title": "Server-Side Template / Expression Injection (SSTI Evaluated)",
                "anomaly": "Evaluated: '49' reflected",
                "evidence": "Injected mathematical expression '${7*7}' was evaluated server-side and returned '49'.",
            }

    # 4. Sensitive Administrative Endpoint / Secret Leaks (Critical)
    for pat, desc in SECRET_PATTERNS:
        if re.search(pat, resp_body) and not re.search(pat, baseline_body):
            return {
                "sev": "critical",
                "title": f"Exposed Endpoint Secret: {desc}",
                "anomaly": "Sensitive Secrets / Config Leak",
                "evidence": f"Target response exposed sensitive secrets or environment properties: {desc}.",
            }

    # 5. SSRF / Cloud Metadata
    if "169.254.169.254" in payload or "metadata.google" in payload:
        if resp_status == 200 and ("ami-id" in resp_body or "security-credentials" in resp_body or "instance-id" in resp_body):
            return {
                "sev": "critical",
                "title": "Cloud Instance Metadata Service Accessible (SSRF)",
                "anomaly": "Cloud Metadata Exposed",
                "evidence": "Target server fetched internal cloud metadata at 169.254.169.254.",
            }
        if resp_status in (504, 502) or resp_time_ms >= 4500:
            return {
                "sev": "high",
                "title": "Blind Server-Side Request Forgery (SSRF) / Cloud Timeout Delay",
                "anomaly": f"Time Delay ({resp_time_ms:,}ms) / SSRF Probe",
                "evidence": f"Server hung for {resp_time_ms}ms attempting to connect to private IP {payload}.",
            }

    # 6. Mass Assignment / Privilege Escalation
    tgt_key = (target.key or target.name or "").lower()
    if tgt_key in ("role", "admin", "is_admin", "is_superuser", "permissions", "user_type"):
        if resp_status == 200 and any(m in resp_body.lower() for m in ('"admin"', '"is_superuser": true', '"is_superuser":true', '"permissions":')):
            if '"admin"' not in baseline_body.lower():
                return {
                    "sev": "critical",
                    "title": "API Mass Assignment & Privilege Escalation (Role Fuzzing)",
                    "anomaly": "Role Changed to Admin",
                    "evidence": f"Target accepted '{target.key}: {payload}' and reflected administrative privileges.",
                }

    # 7. Authentication / Access Control Bypass (401/403 -> 200)
    if baseline_status in (401, 403) and resp_status == 200 and len(resp_body) > 80:
        return {
            "sev": "high",
            "title": "Authentication / Access Control Bypass",
            "anomaly": f"Status Changed: {baseline_status} -> 200 OK",
            "evidence": f"Baseline returned {baseline_status} Forbidden/Unauthorized, but fuzzing payload granted 200 OK.",
        }

    # 8. Unhandled Exception / 5xx Server Error Spikes
    if baseline_status in (200, 400, 404) and resp_status in (500, 502, 503):
        return {
            "sev": "medium",
            "title": f"HTTP {resp_status} Internal Server Error / Unhandled Exception",
            "anomaly": f"Server Error ({resp_status} Spike)",
            "evidence": f"Payload caused application server to crash with HTTP {resp_status}.",
        }

    # 9. Reflected Input / Potential XSS
    if any(tag in payload.lower() for tag in ("<script", "onerror=", "onload=", "javascript:")):
        if payload in resp_body:
            return {
                "sev": "medium",
                "title": "Reflected Input Vector / Potential XSS",
                "anomaly": "Payload Reflected in Response",
                "evidence": "Injected HTML/JS payload was reflected back in the HTTP response body without sanitization.",
            }

    return None


# ── Request Mutation Helper ──────────────────────────────────────────────────

def build_raw_http_request(method: str, url: str, headers: dict, body: str) -> str:
    """Format request raw string exactly like Intruder / Burp Suite without synthetic headers."""
    lines = [f"{(method or 'GET').upper()} {url or ''}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body and (method or "").upper() not in ("GET", "HEAD"):
        lines.append(body)
    return "\n".join(lines).rstrip()


def build_raw_http_response(status_code: int, reason: str, headers: dict, body: str) -> str:
    """Format an authentic HTTP/1.1 wire response representation."""
    lines = [f"HTTP/1.1 {status_code} {reason}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def sanitize_url_path(url: str) -> str:
    """
    Normalize multiple consecutive slashes in the path portion of a URL.
    Prevents accidental double slashes (e.g. https://api.com/v1//admin -> https://api.com/v1/admin)
    whether the user marked §path§ or §/path§, or payload has a leading slash.
    Preserves ../ traversal vectors.
    """
    if not url:
        return url
    try:
        p = urllib.parse.urlsplit(url)
        clean_path = re.sub(r"/+", "/", p.path)
        if not clean_path.startswith("/") and p.path:
            clean_path = "/" + clean_path
        return urllib.parse.urlunsplit((p.scheme, p.netloc, clean_path, p.query, p.fragment))
    except Exception:
        return url


def split_template_request(raw_template: str, default_method: str = "GET", default_headers: dict = None) -> tuple:
    """
    Template format (Burp Suite / Intruder raw HTTP):
      First line: METHOD URL
      Following lines: Header: Value
      Blank line
      Body (if any)
    """
    text = raw_template or ""
    lines = text.split("\n")
    if not lines:
        return default_method, "", default_headers or {}, ""

    first = lines[0].strip()
    m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$", first, re.IGNORECASE)
    if m:
        method = m.group(1).upper()
        raw_url = m.group(2).strip()
        url = re.sub(r"\s+HTTP\/[0-9.]+$", "", raw_url, flags=re.IGNORECASE).strip()
        rest = lines[1:]
    else:
        method = default_method
        url = re.sub(r"\s+HTTP\/[0-9.]+$", "", first, flags=re.IGNORECASE).strip()
        rest = lines[1:]

    # Ensure scheme if domain or host without scheme
    if url and not url.startswith("http://") and not url.startswith("https://"):
        if "://" not in url:
            url = f"https://{url}"

    hdrs = dict(default_headers or {})
    body_lines: List[str] = []
    in_body = False
    for line in rest:
        if not in_body and line.strip() == "":
            in_body = True
            continue
        if not in_body:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip()] = v.strip()
            continue
        body_lines.append(line)

    body = "\n".join(body_lines)
    return method, url, hdrs, body


def looks_like_curl(text: str) -> bool:
    t = (text or "").lstrip()
    return t.lower().startswith("curl") or bool(re.search(r"(?:^|\s)-H\s+['\"]", t) and re.search(r"(?:^|\s)-X\s+['\"]", t))


def parse_any_request(text: str) -> dict:
    """Parse either raw cURL or Burp-style raw HTTP into normalized request spec."""
    clean_text = re.sub(r"§([^§]+)§", r"\1", text or "").strip()
    if looks_like_curl(clean_text):
        try:
            return parse_curl_command(clean_text)
        except Exception:
            # Fallback to split_template_request if curl parser fails
            pass

    method, url, headers, body = split_template_request(clean_text)
    if url and not url.startswith("http://") and not url.startswith("https://"):
        if "://" not in url:
            url = f"https://{url}"
    query_params = {}
    try:
        p = urllib.parse.urlparse(url)
        for k, vs in urllib.parse.parse_qs(p.query, keep_blank_values=True).items():
            query_params[k] = vs[0] if vs else ""
    except Exception:
        pass

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body_raw": body if body else None,
        "body": body if body else None,
        "query_params": query_params,
        "cookies": {},
    }


def mutate_request(
    parsed_spec: dict,
    target: TargetItem,
    payload: str,
    raw_curl: str
) -> Tuple[str, str, dict, Optional[str]]:
    """
    Generate mutated (method, url, headers, body_str) for this target & payload.
    """
    method = (parsed_spec.get("method") or "GET").upper()
    url = parsed_spec.get("url") or ""
    headers = copy.deepcopy(parsed_spec.get("headers") or {})
    body = parsed_spec.get("body_raw") or ""

    # Strategy 1: Marker position in raw template / cURL
    if target.type == "marker":
        marker_token = f"§{target.key}§"
        if marker_token in raw_curl:
            # Replace only the active marker with payload, and strip other markers
            mutated_text = raw_curl.replace(marker_token, payload)
            mutated_text = re.sub(r"§([^§]+)§", r"\1", mutated_text)
            sub_spec = parse_any_request(mutated_text)
            sub_url = sanitize_url_path(sub_spec.get("url") or url)
            return (
                (sub_spec.get("method") or method).upper(),
                sub_url,
                sub_spec.get("headers") or headers,
                sub_spec.get("body_raw")
            )

    # Strategy 2: Sensitive Endpoint / Path Mutation
    if target.type == "endpoint":
        try:
            p = urllib.parse.urlparse(url)
            clean_path = p.path.rstrip("/")
            if payload.startswith("/"):
                new_path = f"{clean_path}{payload}"
            else:
                new_path = f"{clean_path}/{payload}"
            url = urllib.parse.urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, p.fragment))
        except Exception:
            url = f"{url.rstrip('/')}/{payload.lstrip('/')}"
        return (method, sanitize_url_path(url), headers, body)

    # Strategy 3: Individual Path Segment
    if target.type == "path":
        try:
            p = urllib.parse.urlparse(url)
            segments = p.path.split("/")
            new_segments = [payload if s == target.key else s for s in segments]
            new_path = "/".join(new_segments)
            url = urllib.parse.urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, p.fragment))
        except Exception:
            url = url.replace(target.key, urllib.parse.quote(payload))
        return (method, sanitize_url_path(url), headers, body)

    # Strategy 4: Query Parameter Mutation
    if target.type == "query":
        try:
            p = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
            qs[target.key] = [payload]
            new_query = urllib.parse.urlencode(qs, doseq=True, safe="%")
            url = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
        except Exception:
            pass
        return (method, sanitize_url_path(url), headers, body)

    # Strategy 5: Body JSON Parameter Mutation
    if target.type == "json":
        if not body or not str(body).strip():
            body = "{}"
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # Smart type assignment
                    val_to_insert = payload
                    if payload.lower() in ("true", "false"):
                        val_to_insert = payload.lower() == "true"
                    elif payload.isdigit():
                        val_to_insert = int(payload)
                    elif (payload.startswith("{") and payload.endswith("}")) or (payload.startswith("[") and payload.endswith("]")):
                        try:
                            val_to_insert = json.loads(payload)
                        except Exception:
                            val_to_insert = payload

                    data[target.key] = val_to_insert
                    body = json.dumps(data)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and target.key in item:
                            item[target.key] = payload
                    body = json.dumps(data)
            except Exception:
                # Form-urlencoded fallback
                kv_pairs = body.split("&")
                new_pairs = []
                for p in kv_pairs:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        if k == target.key:
                            new_pairs.append(f"{k}={urllib.parse.quote(payload)}")
                        else:
                            new_pairs.append(p)
                    else:
                        new_pairs.append(p)
                body = "&".join(new_pairs)
        return (method, sanitize_url_path(url), headers, body)

    # Strategy 6: Custom Header Mutation
    if target.type == "header":
        headers[target.key] = payload
        return (method, sanitize_url_path(url), headers, body)

    return (method, sanitize_url_path(url), headers, body)


def url_encode_selected(s: str, chars: str) -> str:
    """URL-encode selected characters in the final payload, for safe transmission in HTTP requests."""
    if not s:
        return s
    charset = set(chars or "")
    out = []
    for ch in s:
        if ch in charset:
            out.append(urllib.parse.quote(ch, safe=""))
        else:
            out.append(ch)
    return "".join(out)


# ── Execution Worker ─────────────────────────────────────────────────────────

def _run_fuzz_job(job_id: str, req_data: FuzzStartRequest):
    job = jobs.get(job_id)
    if not job:
        return

    session = requests.Session()
    adapter = HTTPAdapter(max_retries=1, pool_connections=req_data.threads, pool_maxsize=req_data.threads + 5)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    parsed_spec = job["parsed_spec"]
    raw_curl = req_data.curl
    cancel_event = job["cancel_event"]

    # 1. Fire Baseline Request (Burp Intruder style Request #0 with original values)
    baseline_info = {"status": 200, "len": 0, "time": 50, "body": ""}
    b_method = (parsed_spec.get("method") or "GET").upper()
    b_url = parsed_spec.get("url") or ""
    b_headers = parsed_spec.get("headers") or {}
    b_body = parsed_spec.get("body_raw")
    raw_base_req_str = build_raw_http_request(b_method, b_url, b_headers, b_body)
    raw_base_resp_str = ""
    sc_b = 200
    elapsed_b = 50
    resp_b_len = 0
    b_resp = None

    try:
        t0 = time.time()
        b_resp = session.request(
            method=b_method,
            url=b_url,
            headers=b_headers,
            data=b_body.encode("utf-8") if isinstance(b_body, str) else b_body,
            timeout=10,
            verify=False
        )
        elapsed_b = int((time.time() - t0) * 1000)
        sc_b = b_resp.status_code
        resp_b_len = len(b_resp.content)
        baseline_info = {
            "status": sc_b,
            "len": resp_b_len,
            "time": elapsed_b,
            "body": b_resp.text[:5000]
        }
        raw_base_resp_str = build_raw_http_response(
            b_resp.status_code,
            b_resp.reason or "OK",
            dict(b_resp.headers),
            b_resp.text
        )
    except Exception as e:
        baseline_info["error"] = str(e)
        sc_b = 0
        raw_base_resp_str = f"HTTP/1.1 000 Baseline Error\r\n\r\n{str(e)}"
        resp_b_len = len(raw_base_resp_str)

    job["baseline"] = baseline_info

    # Status badge class for baseline
    if 200 <= sc_b < 300:
        sc_b_class = "fuzz-status-2xx"
    elif 300 <= sc_b < 400:
        sc_b_class = "fuzz-status-3xx"
    elif 400 <= sc_b < 500:
        sc_b_class = "fuzz-status-4xx"
    elif sc_b >= 500:
        sc_b_class = "fuzz-status-5xx"
    else:
        sc_b_class = "fuzz-status-err"

    # Prepend Baseline Hit as Request #0 in results (Burp Intruder style blank/original hit)
    baseline_result_item = {
        "id": 0,
        "method": b_method,
        "url": b_url,
        "location": "[Baseline]",
        "payload": "",
        "status": sc_b,
        "statusClass": sc_b_class,
        "length": resp_b_len,
        "time": elapsed_b,
        "anomaly": "",
        "isAnomaly": False,
        "anomalySev": "low",
        "req": raw_base_req_str,
        "resp": raw_base_resp_str
    }
    job["results"].append(baseline_result_item)

    # 2. Prepare Task Queue (Deduplicated)
    active_targets = [t for t in req_data.targets if t.enabled]
    if not active_targets:
        job["status"] = "finished"
        job["finished_at"] = time.time()
        return

    def _dedup_list(items):
        seen = set()
        out = []
        for x in items or []:
            if isinstance(x, str):
                s = x.strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
        return out

    cleaned_ep = _dedup_list(req_data.endpoint_payloads)
    cleaned_inj = _dedup_list(req_data.injection_payloads)

    tasks = []
    seen_target_tasks = set()
    for tgt in active_targets:
        if tgt.type == "endpoint":
            p_list = cleaned_ep or cleaned_inj
        else:
            p_list = cleaned_inj or cleaned_ep

        for p in p_list:
            task_key = (tgt.type, tgt.key, p)
            if task_key not in seen_target_tasks:
                seen_target_tasks.add(task_key)
                tasks.append((tgt, p))

    if req_data.randomize:
        random.shuffle(tasks)

    job["total_planned"] = len(tasks) + 1  # 1 baseline + N payload tasks

    # 3. Fire Fuzzing Requests in ThreadPool
    hit_counter = 0
    results_lock = threading.Lock()

    def worker(task_idx: int, target: TargetItem, payload: str):
        if cancel_event.is_set():
            return None

        if req_data.delay_ms > 0:
            time.sleep(req_data.delay_ms / 1000.0)

        actual_payload = payload
        if req_data.url_encode and target.type != "endpoint":
            actual_payload = url_encode_selected(payload, req_data.url_encode_chars)

        mut_method, mut_url, mut_headers, mut_body = mutate_request(parsed_spec, target, actual_payload, raw_curl)
        raw_req_str = build_raw_http_request(mut_method, mut_url, mut_headers, mut_body)

        t_start = time.time()
        status_code = 0
        status_reason = "Error"
        resp_body = ""
        resp_headers = {}
        resp_len = 0

        try:
            r = session.request(
                method=mut_method,
                url=mut_url,
                headers=mut_headers,
                data=mut_body.encode("utf-8") if isinstance(mut_body, str) else mut_body,
                timeout=12,
                verify=False,
                allow_redirects=False
            )
            elapsed_ms = int((time.time() - t_start) * 1000)
            status_code = r.status_code
            status_reason = r.reason or "OK"
            resp_headers = dict(r.headers)
            resp_body = r.text
            resp_len = len(r.content)
        except requests.exceptions.Timeout:
            elapsed_ms = int((time.time() - t_start) * 1000)
            status_code = 504
            status_reason = "Gateway Timeout"
            resp_body = f"Connection timed out after {elapsed_ms}ms"
            resp_len = len(resp_body)
        except Exception as ex:
            elapsed_ms = int((time.time() - t_start) * 1000)
            status_code = 0
            status_reason = "Connection Failed"
            resp_body = f"Client Network Error: {str(ex)}"
            resp_len = len(resp_body)

        raw_resp_str = build_raw_http_response(status_code, status_reason, resp_headers, resp_body)

        # Status badge class
        sc = status_code
        if 200 <= sc < 300:
            sc_class = "fuzz-status-2xx"
        elif 300 <= sc < 400:
            sc_class = "fuzz-status-3xx"
        elif 400 <= sc < 500:
            sc_class = "fuzz-status-4xx"
        elif sc >= 500:
            sc_class = "fuzz-status-5xx"
        else:
            sc_class = "fuzz-status-err"

        # Heuristic Anomaly Evaluation
        anomaly_info = detect_anomaly(
            payload=actual_payload,
            target=target,
            resp_status=status_code,
            resp_body=resp_body,
            resp_time_ms=elapsed_ms,
            baseline=baseline_info,
            endpoint_url=mut_url
        )

        is_anomaly = anomaly_info is not None
        anomaly_desc = anomaly_info.get("anomaly", "") if is_anomaly else ""
        anomaly_sev = anomaly_info.get("sev", "low") if is_anomaly else "low"

        with results_lock:
            nonlocal hit_counter
            hit_counter += 1
            curr_id = hit_counter

            result_item = {
                "id": curr_id,
                "method": mut_method,
                "url": mut_url,
                "location": target.label or f"{target.type}: {target.key}",
                "payload": actual_payload,
                "status": status_code,
                "statusClass": sc_class,
                "length": resp_len,
                "time": elapsed_ms,
                "anomaly": anomaly_desc,
                "isAnomaly": is_anomaly,
                "anomalySev": anomaly_sev,
                "req": raw_req_str,
                "resp": raw_resp_str
            }

            job["results"].append(result_item)

            if is_anomaly:
                issue_item = {
                    "sev": anomaly_sev,
                    "title": anomaly_info["title"],
                    "location": target.label or f"{target.type}: {target.key}",
                    "payload": actual_payload,
                    "endpoint": f"{mut_method} {mut_url}",
                    "url": mut_url,
                    "evidence": anomaly_info["evidence"],
                    "resultIdx": len(job["results"]) - 1
                }
                job["issues"].append(issue_item)

        return curr_id

    max_workers = max(1, min(req_data.threads, 25))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, idx, tgt, p) for idx, (tgt, p) in enumerate(tasks)]
        for f in as_completed(futures):
            if cancel_event.is_set():
                break

    job["status"] = "stopped" if cancel_event.is_set() else "finished"
    job["finished_at"] = time.time()


# ── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "api_fuzzer", "port": 8796}


@app.post("/fuzzer/parse_curl")
def parse_curl_endpoint(req: ParseCurlRequest):
    """Convert raw cURL command into Burp-style raw HTTP template."""
    if not req.curl or not req.curl.strip():
        raise HTTPException(status_code=400, detail="Empty cURL command")
    try:
        parsed = parse_curl_command(req.curl)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse cURL: {str(e)}")

    lines = [f"{(parsed.get('method') or 'GET').upper()} {parsed.get('url') or ''}"]
    for k, v in (parsed.get("headers") or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("")
    body = parsed.get("body_raw")
    if body is not None and str(body) != "":
        lines.append(str(body))
    template = "\n".join(lines).rstrip()

    return {
        **parsed,
        "template": template
    }


@app.post("/fuzzer/start")
def start_fuzz(req: FuzzStartRequest):
    _prune_jobs()

    if not req.curl or not req.curl.strip():
        raise HTTPException(status_code=400, detail="Target request template is empty")

    active_targets = [t for t in req.targets if t.enabled]
    if not active_targets:
        raise HTTPException(status_code=400, detail="No active injection targets enabled for fuzzing")

    # Clean markers from cURL / template for base spec
    clean_curl = re.sub(r"§([^§]+)§", r"\1", req.curl)
    try:
        parsed_spec = parse_any_request(clean_curl)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse request: {str(e)}")

    job_id = str(uuid.uuid4())
    cancel_event = threading.Event()

    job_record = {
        "id": job_id,
        "status": "running",
        "created_at": time.time(),
        "finished_at": None,
        "total_planned": 0,
        "results": [],
        "issues": [],
        "baseline": {},
        "parsed_spec": parsed_spec,
        "cancel_event": cancel_event,
        "error": None
    }

    with _jobs_lock:
        jobs[job_id] = job_record

    # Start background executor thread
    t = threading.Thread(target=_run_fuzz_job, args=(job_id, req), daemon=True)
    t.start()

    return {
        "ok": True,
        "job_id": job_id,
        "status": "running"
    }


@app.get("/fuzzer/status/{job_id}")
def get_fuzz_status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "job_id": job_id,
        "status": job["status"],
        "completed": len(job["results"]),
        "total": job["total_planned"],
        "anomalies_count": len(job["issues"]),
        "error": job.get("error")
    }


@app.get("/fuzzer/results/{job_id}")
def get_fuzz_results(job_id: str, since: int = 0):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    all_res = job["results"]
    new_res = all_res[since:] if since < len(all_res) else []

    return {
        "job_id": job_id,
        "status": job["status"],
        "results": new_res,
        "issues": job["issues"],
        "total_so_far": len(all_res),
        "total_planned": job["total_planned"]
    }


@app.post("/fuzzer/stop/{job_id}")
def stop_fuzz(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    job["cancel_event"].set()
    job["status"] = "stopped"
    job["finished_at"] = time.time()

    return {"ok": True, "job_id": job_id, "status": "stopped"}


# ── Arjun HTTP Parameter Discovery Endpoints ─────────────────────────────────

class ArjunStartRequest(BaseModel):
    curl: str
    param_type: str = "query"  # 'query' | 'json' | 'header'
    wordlist_type: str = "quick"  # 'quick' | 'standard' | 'deep' | 'custom'
    custom_wordlist: Optional[List[str]] = None
    batch_size: int = Field(default=25, ge=5, le=50)
    threads: int = Field(default=5, ge=1, le=15)


@app.post("/fuzzer/arjun/start")
def start_arjun(req: ArjunStartRequest):
    try:
        from fuzzer_backend.arjun_engine import arjun_manager
    except ImportError:
        from arjun_engine import arjun_manager

    if not req.curl or not req.curl.strip():
        raise HTTPException(status_code=400, detail="Target request template is empty")

    job_id = arjun_manager.start_job(
        curl=req.curl,
        param_type=req.param_type,
        wordlist_type=req.wordlist_type,
        custom_wordlist=req.custom_wordlist,
        batch_size=req.batch_size,
        threads=req.threads,
    )
    return {"ok": True, "job_id": job_id, "status": "running"}


@app.get("/fuzzer/arjun/status/{job_id}")
def get_arjun_job_status(job_id: str, since: int = 0):
    try:
        from fuzzer_backend.arjun_engine import arjun_manager
    except ImportError:
        from arjun_engine import arjun_manager

    status = arjun_manager.get_status(job_id, since_log=since)
    if not status:
        raise HTTPException(status_code=404, detail="Arjun job not found")
    return status


@app.post("/fuzzer/arjun/stop/{job_id}")
def stop_arjun(job_id: str):
    try:
        from fuzzer_backend.arjun_engine import arjun_manager
    except ImportError:
        from arjun_engine import arjun_manager

    stopped = arjun_manager.stop_job(job_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="Arjun job not found")
    return {"ok": True, "job_id": job_id, "status": "stopped"}

