"""
Method Tampering Backend — Port 8767
Exposes: /mt/parse, /mt/scan, /mt/progress/{job_id}
"""

import json, csv, re, os, hashlib, time, uuid, threading, io
import urllib3
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Any
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

try:
    import requests as req_lib
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None

app = FastAPI(title="Method Tampering Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── Config ───────────────────────────────────────────────────────────────────
TIMEOUT        = 12
VERIFY_SSL     = False
THREADS        = 8
ALL_METHODS    = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE"]
STATE_CHANGING = {"POST","PUT","PATCH","DELETE"}
SUCCESS_CODES  = {200,201,202,204}
REDIRECT_CODES = {301,302,307,308}
STATIC_EXTS    = (".js",".css",".png",".jpg",".jpeg",".gif",".svg",".ico",
                  ".woff",".woff2",".ttf",".map",".webp",".pdf",".zip")

# ── In-memory job store ───────────────────────────────────────────────────────
jobs = {}   # job_id → {status, progress, total, findings, logs, errors, summary}

# ══════════════════════════ UTILS ════════════════════════════════════════════

def md5(text):
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest() if text else ""

def is_static(url):
    return urlparse(url).path.lower().endswith(STATIC_EXTS)

def is_meaningful(text, status_code):
    if status_code in REDIRECT_CODES or status_code < 100:
        return False
    if not text or not text.strip():
        return False
    s = text.strip()
    if s in ("{}", "[]", "null", '""', "''"):
        return False
    if len(s) < 2:
        return False
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict) and all(v is None for v in parsed.values()):
            return False
        if isinstance(parsed, list) and len(parsed) == 0:
            return False
    except Exception:
        pass
    return True

def extract_json_keys(text):
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return set(obj.keys())
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return set(obj[0].keys())
    except Exception:
        pass
    return set()

def _clean_token(raw):
    t = raw.strip().strip('"').strip("'").strip()
    if not t:
        return t
    lower = t.lower()
    # Already has a prefix — return as-is
    if lower.startswith(("bearer ", "basic ", "token ")):
        return t
    # Looks like a JWT (starts with eyJ) — add Bearer
    if t.startswith("eyJ"):
        return f"Bearer {t}"
    return t

def _normalize_url(url):
    p    = urlparse(url)
    path = re.sub(r"(/)(\d+)(/|$)", r"\1__ID__\3", p.path)
    q    = parse_qs(p.query, keep_blank_values=True)
    skip = {"offset","size","limit","page","sort","order","from","to","orderby","page_size"}
    fq   = {k: v for k, v in q.items() if k.lower() not in skip}
    qs   = urlencode({k: v[0] for k,v in sorted(fq.items())})
    return urlunparse(p._replace(path=path, query=qs))

def _replace_params(path_tpl, methods_obj):
    result, params = path_tpl, {}
    for m_obj in methods_obj.values():
        if not isinstance(m_obj, dict):
            continue
        for p in m_obj.get("parameters", []):
            if p.get("in") != "path":
                continue
            name    = p.get("name", "")
            example = p.get("x-example") or p.get("example") or p.get("default")
            schema  = p.get("schema") or {}
            ptype   = p.get("type") or schema.get("type","string")
            params[name] = (str(example) if example is not None
                            else ("1" if ptype in ("integer","number") else "test"))
    for n, v in params.items():
        result = result.replace("{"+n+"}", v)
    return re.sub(r"\{[^}]+\}", "1", result)

# ══════════════════════════ PARSERS ══════════════════════════════════════════

def parse_har(data: dict, url_filter: str = "") -> tuple:
    entries   = data.get("log", {}).get("entries", [])
    raw_count = len(entries)
    skipped   = 0
    auto_auth = {}

    # Extract auth from first 30 entries
    for entry in entries[:30]:
        for h in entry.get("request", {}).get("headers", []):
            n = h["name"].strip().lower()
            if n in ("authorization","x-auth-token","x-api-key","cookie"):
                auto_auth[h["name"].strip()] = h["value"].strip()

    raw_eps = []
    for entry in entries:
        rq  = entry.get("request", {})
        url = rq.get("url", "")
        method = rq.get("method","GET").upper()
        if not url.startswith("http") or is_static(url):
            skipped += 1
            continue
        req_headers = {
            h["name"]: h["value"]
            for h in rq.get("headers",[])
            if h["name"].lower() not in (
                "host","content-length","accept-encoding",
                ":authority",":scheme",":method",":path"
            )
        }
        # Extract body from postData
        body = None
        post_data = rq.get("postData", {})
        if post_data and post_data.get("text"):
            body_text = post_data["text"]
            try:
                body = json.loads(body_text)
            except Exception:
                body = body_text

        # Keep full URL including query string (needed for query-gated APIs)
        raw_eps.append({"url": url, "method": method, "headers": req_headers, "body": body})

    # Deduplicate by normalized URL, MERGE allowed methods (avoid false HIGH
    # when the same path was captured with GET and POST).
    unique_map = {}
    for ep in raw_eps:
        norm = _normalize_url(ep["url"])
        if norm not in unique_map:
            unique_map[norm] = {
                "url": ep["url"],
                "methods": [ep["method"]],
                "headers": ep["headers"],
                "body": ep.get("body"),
                "primary_method": ep["method"],
            }
            continue

        existing = unique_map[norm]
        if ep["method"] not in existing["methods"]:
            existing["methods"].append(ep["method"])

        # Prefer headers that carry Authorization
        if ("Authorization" not in existing["headers"]
                and "Authorization" in ep["headers"]):
            existing["headers"] = ep["headers"]

        # Prefer an entry that has a body (better POST/PUT/PATCH baseline)
        if existing.get("body") is None and ep.get("body") is not None:
            existing["body"] = ep["body"]
            existing["primary_method"] = ep["method"]
            existing["url"] = ep["url"]

    endpoints = []
    for ep in unique_map.values():
        methods = ep["methods"]
        primary = ep["primary_method"]
        # Put primary first so scan_endpoint baselines on the best method
        allowed = [primary] + [m for m in methods if m != primary]
        endpoints.append({
            "url"          : ep["url"],
            "path_template": urlparse(ep["url"]).path,
            "allowed"      : allowed,
            "source"       : "har",
            "har_headers"  : ep["headers"],
            "har_body"     : ep.get("body"),
        })

    if url_filter:
        before     = len(endpoints)
        endpoints  = [ep for ep in endpoints if url_filter in ep["url"]]
        skipped   += (before - len(endpoints))

    return endpoints, auto_auth, raw_count, skipped


def parse_swagger(data: dict, base_url: str) -> list:
    endpoints, seen = [], set()
    for path_tpl, methods_obj in data.get("paths", {}).items():
        allowed = [m.upper() for m in methods_obj
                   if m.lower() in ("get","post","put","patch","delete","options","head")]
        test_path = _replace_params(path_tpl, methods_obj)

        # Build query string from required query params
        query_parts = []
        for m_obj in methods_obj.values():
            if not isinstance(m_obj, dict):
                continue
            for p in m_obj.get("parameters", []):
                if p.get("in") != "query":
                    continue
                if not p.get("required", False):
                    continue
                name   = p.get("name", "")
                schema = p.get("schema") or {}
                ptype  = p.get("type") or schema.get("type", "string")
                # Use example if available, else sensible default by type
                example = (p.get("example") or schema.get("example")
                           or schema.get("default"))
                if example is None:
                    if ptype in ("integer", "number"): example = "0"
                    elif ptype == "boolean":            example = "false"
                    else:                               example = "test"
                query_parts.append(f"{name}={example}")
            break  # use first method's params

        qs       = "?" + "&".join(query_parts) if query_parts else ""
        full_url = base_url.rstrip("/") + test_path + qs

        if full_url in seen:
            continue
        seen.add(full_url)
        endpoints.append({
            "url"          : full_url,
            "path_template": path_tpl,
            "allowed"      : allowed,
            "source"       : "swagger",
            "har_headers"  : {},
        })
    return endpoints

# ══════════════════════════ CLASSIFY ═════════════════════════════════════════

def classify(method, status, allowed, baseline_meaningful,
             resp_meaningful, body_changed, same_keys):
    if method in allowed:
        return None, None
    if status in (405, 404, 501, 401, 403):
        return None, None

    # Empty / non-meaningful success still means the verb was accepted
    # (e.g. unexpected DELETE → 204 No Content). Previously ignored → FN.
    if status in SUCCESS_CODES and not resp_meaningful:
        if method in STATE_CHANGING:
            return "HIGH", f"Unexpected {method} accepted (status {status}, empty body)"
        if method == "OPTIONS":
            return "LOW", "OPTIONS accepted unexpectedly"
        if method == "HEAD":
            return "LOW", "HEAD accepted unexpectedly"
        if method == "TRACE":
            return "MEDIUM", "TRACE enabled — may leak internal headers"
        if method == "GET":
            return "MEDIUM", f"Unexpected GET accepted (status {status}, empty body)"
        return "MEDIUM", f"Unexpected {method} accepted (status {status})"

    if method == "OPTIONS":
        return (("LOW", "OPTIONS accepted unexpectedly") if status in SUCCESS_CODES else (None, None))
    if method == "HEAD":
        return (("LOW", "HEAD accepted unexpectedly") if status in SUCCESS_CODES else (None, None))
    if method == "TRACE" and status in SUCCESS_CODES:
        return "MEDIUM", "TRACE enabled — may leak internal headers"
    if method in STATE_CHANGING and status in SUCCESS_CODES and resp_meaningful:
        if body_changed:
            return "HIGH", f"Unexpected {method} accepted — state change detected"
        return "HIGH", f"Unexpected {method} accepted (status {status})"
    if method == "GET" and status in SUCCESS_CODES and resp_meaningful:
        return "MEDIUM", f"Unexpected GET returned data (status {status})"
    if status in SUCCESS_CODES and resp_meaningful:
        return "MEDIUM", f"Unexpected {method} returned {status}"
    if isinstance(status, int) and status >= 500:
        return "LOW", f"Server error {status} on unexpected {method}"
    return None, None

# ══════════════════════════ SCANNER ══════════════════════════════════════════

def scan_endpoint(ep, auth_token, stop_event):
    if stop_event.is_set():
        return [], [], 0, False

    url     = ep["url"]
    allowed = ep["allowed"]

    if ep["source"] == "har":
        h = dict(ep.get("har_headers", {}))
        if auth_token and not any(k.lower() == "authorization" for k in h):
            h["Authorization"] = auth_token
    else:
        # swagger — start with custom headers from har_headers, add auth
        h = dict(ep.get("har_headers", {}))  # contains extra_headers injected earlier
        h["Accept"] = "application/json, text/plain, */*"
        if auth_token:
            h["Authorization"] = auth_token

    orig_method      = allowed[0] if allowed else "GET"
    ep_body          = ep.get("har_body", None)  # original body for POST/PUT/PATCH
    baseline_text    = ""
    baseline_status  = 0
    baseline_hash    = ""
    baseline_meaning = False
    baseline_time_ms = 0

    def _req_meta(method, body=None):
        """Headers + body actually sent for this method (for Copy cURL)."""
        hdrs = dict(h)
        sent_body = None
        if body is not None and method in ("POST", "PUT", "PATCH"):
            if isinstance(body, (dict, list)):
                sent_body = json.dumps(body, ensure_ascii=False)
            else:
                sent_body = str(body)
            if "content-type" not in {k.lower() for k in hdrs}:
                hdrs["Content-Type"] = "application/json"
        return hdrs, sent_body

    def _fire(method, body=None):
        """Fire a single request with optional JSON body."""
        hdrs, _sent = _req_meta(method, body)
        kwargs = dict(headers=hdrs, timeout=TIMEOUT, verify=VERIFY_SSL, allow_redirects=False)
        if body is not None and method in ("POST", "PUT", "PATCH"):
            if isinstance(body, (dict, list)):
                kwargs["json"] = body
            else:
                kwargs["data"] = str(body)
        return req_lib.request(method, url, **kwargs)

    try:
        t0 = time.time()
        rb = _fire(orig_method, ep_body)
        baseline_time_ms = int((time.time()-t0)*1000)
        if rb.status_code == 401:
            stop_event.set()
            return [], [], 0, True
        baseline_status  = rb.status_code
        baseline_text    = rb.text or ""
        baseline_hash    = md5(baseline_text)
        baseline_meaning = is_meaningful(baseline_text, rb.status_code)
    except Exception as e:
        baseline_status = "TIMEOUT"
        baseline_text   = f"Connection error: {str(e)[:100]}"

    findings    = []
    all_logs    = []
    error_count = 0
    got_401     = False

    for method in ALL_METHODS:
        if stop_event.is_set():
            break
        try:
            t0   = time.time()
            resp = _fire(method, ep_body)
            resp_text    = resp.text or ""
            resp_time_ms = int((time.time()-t0)*1000)

            if resp.status_code == 401:
                stop_event.set()
                got_401 = True
                break

            resp_meaning = is_meaningful(resp_text, resp.status_code)
            resp_hash    = md5(resp_text)
            body_changed = bool(baseline_hash and resp_hash != baseline_hash and resp_meaning)
            base_keys    = extract_json_keys(baseline_text)
            resp_keys    = extract_json_keys(resp_text)
            same_keys    = bool(base_keys and resp_keys and base_keys == resp_keys)

            severity, reason = classify(method, resp.status_code, allowed,
                                        baseline_meaning, resp_meaning, body_changed, same_keys)

            tested_hdrs, tested_body = _req_meta(method, ep_body)
            orig_hdrs, orig_body = _req_meta(orig_method, ep_body)

            log_entry = {
                "url": url, "path_template": ep.get("path_template",""),
                "original_method": orig_method, "original_status": baseline_status,
                "original_response": baseline_text[:2000], "original_time_ms": baseline_time_ms,
                "tested_method": method, "tested_status": resp.status_code,
                "tested_response": resp_text[:2000], "tested_time_ms": resp_time_ms,
                "is_issue": "YES" if severity else "NO",
                "severity": severity or "", "reason": reason or "",
                "body_diff": "CHANGED" if body_changed else "SAME",
                "source": ep["source"],
                # Exact request material for UI "Copy cURL" (tested + original)
                "req_headers": tested_hdrs,
                "req_body": tested_body or "",
                "orig_req_headers": orig_hdrs,
                "orig_req_body": orig_body or "",
            }
            all_logs.append(log_entry)

            if severity:
                findings.append({
                    "url": url, "path_template": ep.get("path_template",""),
                    "method": method, "status": resp.status_code,
                    "allowed": ", ".join(allowed),
                    "severity": severity, "reason": reason,
                    "body_diff": "CHANGED" if body_changed else "SAME",
                    "response": resp_text[:3000],
                    "source": ep["source"], "resp_time_ms": resp_time_ms,
                })
        except Exception:
            error_count += 1
            tested_hdrs, tested_body = _req_meta(method, ep_body)
            orig_hdrs, orig_body = _req_meta(orig_method, ep_body)
            all_logs.append({
                "url": url, "path_template": ep.get("path_template",""),
                "original_method": orig_method, "original_status": baseline_status,
                "original_response": baseline_text[:2000], "original_time_ms": baseline_time_ms,
                "tested_method": method, "tested_status": "TIMEOUT",
                "tested_response": "Connection error / timeout", "tested_time_ms": 0,
                "is_issue": "NO", "severity": "", "reason": "timeout/error",
                "body_diff": "", "source": ep["source"],
                "req_headers": tested_hdrs,
                "req_body": tested_body or "",
                "orig_req_headers": orig_hdrs,
                "orig_req_body": orig_body or "",
            })

    return findings, all_logs, error_count, got_401

# ══════════════════════════ ENDPOINTS ════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "ok", "service": "Method Tampering Backend"}

@app.get("/mt/health")
def health():
    return {"status": "ok"}

@app.post("/mt/parse")
async def parse_file(
    file:     UploadFile = File(...),
    base_url: str        = Form(default=""),
    mode:     str        = Form(default="auto"),  # 'har' | 'swagger' | 'auto'
):
    """Parse HAR or Swagger JSON. Returns endpoints count + auto-extracted token."""
    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {e}")

    if mode == "har":
        is_har, is_swagger = True, False
    elif mode == "swagger":
        is_har, is_swagger = False, True
    else:
        is_har     = "log" in data
        is_swagger = "paths" in data

    if not is_har and not is_swagger:
        raise HTTPException(400, "File must be a HAR ('log' key) or Swagger/OpenAPI JSON ('paths' key)")

    def _pick_auto_token(auto_auth: dict) -> str:
        if not auto_auth:
            return ""
        # Prefer Authorization / API-key headers over Cookie
        for want in ("authorization", "x-auth-token", "x-api-key"):
            for k, v in auto_auth.items():
                if k.lower() == want and v:
                    return v
        return next(iter(auto_auth.values()), "")

    if is_har:
        endpoints, auto_auth, raw_count, skipped = parse_har(data)
        return {
            "type"          : "har",
            "raw_count"     : raw_count,
            "skipped"       : skipped,
            "ep_count"      : len(endpoints),
            "auto_token"    : _pick_auto_token(auto_auth),
            "needs_base_url": False,
            "endpoints"     : [
                {
                    "url": e["url"],
                    "method": e["allowed"][0] if e["allowed"] else "GET",
                    "allowed": e["allowed"],
                    "path_template": e.get("path_template", ""),
                    "source": "har",
                }
                for e in endpoints
            ],
        }
    else:
        # Swagger — need base_url
        if not base_url:
            return {
                "type"          : "swagger",
                "needs_base_url": True,
                "ep_count"      : len(data.get("paths", {})),
                "endpoints"     : [],
            }
        endpoints = parse_swagger(data, base_url)
        return {
            "type"          : "swagger",
            "ep_count"      : len(endpoints),
            "needs_base_url": False,
            "endpoints"     : [
                {
                    "url": e["url"],
                    "method": e["allowed"][0] if e["allowed"] else "GET",
                    "allowed": e["allowed"],
                    "path_template": e.get("path_template", ""),
                    "source": "swagger",
                }
                for e in endpoints
            ],
        }


@app.post("/mt/scan")
async def start_scan(
    file:          UploadFile = File(...),
    token:         str        = Form(default=""),
    base_url:      str        = Form(default=""),
    url_filter:    str        = Form(default=""),
    mode:          str        = Form(default="auto"),
    custom_headers:str        = Form(default=""),   # newline-separated "Key: Value"
):
    """Start scan as background job. Returns job_id immediately."""
    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {e}")

    # Use mode hint from frontend — more reliable than key detection
    if mode == "har":
        is_har, is_swagger = True, False
    elif mode == "swagger":
        is_har, is_swagger = False, True
    else:
        is_har     = "log" in data
        is_swagger = "paths" in data

    if not is_har and not is_swagger:
        raise HTTPException(400, "File must be HAR or Swagger JSON")

    auth_token = _clean_token(token) if token.strip() else ""

    # Parse custom headers (newline-separated "Key: Value")
    extra_headers = {}
    for line in custom_headers.splitlines():
        line = line.strip()
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip(); v = v.strip()
            if k:
                extra_headers[k] = v

    if is_har:
        endpoints, auto_auth, raw_count, skipped = parse_har(data, url_filter)
        if not auth_token and auto_auth:
            for want in ("authorization", "x-auth-token", "x-api-key"):
                for k, v in auto_auth.items():
                    if k.lower() == want and v:
                        auth_token = v
                        break
                if auth_token:
                    break
            if not auth_token:
                auth_token = next(iter(auto_auth.values()), "")
        file_type = "har"
    else:
        if not base_url:
            raise HTTPException(400, "base_url required for Swagger/JSON files")
        endpoints  = parse_swagger(data, base_url)
        # Inject extra_headers into all swagger endpoints
        if extra_headers:
            for ep in endpoints:
                ep["har_headers"].update(extra_headers)
        raw_count  = len(endpoints)
        skipped    = 0
        file_type  = "swagger"

    if not endpoints:
        raise HTTPException(400, "No testable endpoints found in file")

    job_id = str(uuid.uuid4())[:8]
    stop_event = threading.Event()
    jobs[job_id] = {
        "status"     : "running",
        "progress"   : 0,
        "total"      : len(endpoints),
        "completed"  : 0,
        "findings"   : [],
        "logs"       : [],
        "errors"     : 0,
        "aborted"    : False,
        "abort_reason": "",
        "raw_count"  : raw_count,
        "skipped"    : skipped,
        "file_type"  : file_type,
        "start_time" : time.time(),
        "elapsed"    : 0,
        "stop_event" : stop_event,
    }

    def run_scan():
        job = jobs[job_id]
        all_findings, all_logs, total_errors = [], [], 0
        completed = 0

        with ThreadPoolExecutor(max_workers=THREADS) as pool:
            futures = {pool.submit(scan_endpoint, ep, auth_token, stop_event): ep
                       for ep in endpoints}
            for future in as_completed(futures):
                try:
                    findings, logs, errs, hit_401 = future.result()
                except Exception:
                    completed += 1
                    continue
                completed     += 1
                total_errors  += errs
                all_findings.extend(findings)
                all_logs.extend(logs)
                if hit_401 and not job.get("abort_reason"):
                    job["aborted"] = True
                    job["abort_reason"] = "auth_401"
                job["completed"] = completed
                job["progress"]  = int(100 * completed / max(len(endpoints), 1))
                job["findings"]  = all_findings
                job["logs"]      = all_logs
                job["errors"]    = total_errors
                if stop_event.is_set():
                    # Drain remaining quickly — workers exit early via stop_event
                    pass

        # Sort findings
        sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        all_findings.sort(key=lambda r: sev_order.get(r["severity"], 9))

        job["elapsed"]  = round(time.time() - job["start_time"], 1)
        job["findings"] = all_findings
        job["logs"]     = all_logs
        job["errors"]   = total_errors
        job["status"]   = "done"
        job["progress"] = 100
        # drop non-serializable handle
        job.pop("stop_event", None)

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()

    return {"job_id": job_id, "total": len(endpoints)}


@app.post("/mt/abort/{job_id}")
def abort_scan(job_id: str):
    """Signal a running scan to stop after current in-flight requests."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    if job["status"] != "running":
        return {"ok": True, "status": job["status"], "aborted": job.get("aborted", False)}
    ev = job.get("stop_event")
    if ev:
        ev.set()
    job["aborted"] = True
    job["abort_reason"] = job.get("abort_reason") or "user"
    return {"ok": True, "status": "aborting"}


@app.get("/mt/progress/{job_id}")
def get_progress(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    return {
        "status"       : job["status"],
        "progress"     : job["progress"],
        "completed"    : job["completed"],
        "total"        : job["total"],
        "findings"     : job["findings"],
        "logs"         : job["logs"] if job["status"] == "done" else [],
        "errors"       : job["errors"],
        "aborted"      : job["aborted"],
        "abort_reason" : job.get("abort_reason", ""),
        "elapsed"      : round(time.time() - job["start_time"], 1) if job["status"] == "running"
                         else job.get("elapsed", 0),
        "raw_count"    : job["raw_count"],
        "file_type"    : job["file_type"],
    }


@app.get("/mt/csv/{job_id}")
def get_csv(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    output = io.StringIO()
    w = csv.writer(output, quoting=csv.QUOTE_ALL)
    w.writerow(["sr_no","url","path_template","original_method","original_status",
                "original_response","original_time_ms","tested_method","tested_status",
                "tested_response","tested_time_ms","is_issue","severity","reason",
                "body_diff","source"])
    for i, r in enumerate(job.get("logs",[]), 1):
        w.writerow([i, r["url"], r.get("path_template",""),
                    r["original_method"], r["original_status"],
                    r["original_response"], r.get("original_time_ms",""),
                    r["tested_method"], r["tested_status"],
                    r["tested_response"], r.get("tested_time_ms",""),
                    r["is_issue"], r["severity"], r["reason"],
                    r["body_diff"], r.get("source","")])

    output.seek(0)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=method_tampering_{ts}.csv"}
    )
