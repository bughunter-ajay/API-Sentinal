"""
Soft-Delete Filter Bypass Backend — Port 8769
"""
import json, re, time, uuid, threading, io, csv
from copy import deepcopy
from typing import Optional, Any
from urllib.parse import urlparse, urlunparse, quote, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import ssl as _ssl

try:
    import requests as req_lib
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None

app = FastAPI(title="Soft Delete Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TIMEOUT = 20
THREADS = 6

SOFT_DELETE_FILTERS = [
    {"original": "deleted==false",   "bypasses": [
        ("deleted==true",  "Logical Inversion"),
        ("deleted==*",     "Wildcard (*)"),
        ("deleted==**",    "Double Wildcard (**)"),
        ("deleted==null",  "Null Value"),
        ("deleted==_",     "Underscore/Blank"),
    ]},
    {"original": "isDeleted==false", "bypasses": [
        ("isDeleted==true",  "Logical Inversion"),
        ("isDeleted==*",     "Wildcard (*)"),
        ("isDeleted==**",    "Double Wildcard (**)"),
        ("isDeleted==null",  "Null Value"),
        ("isDeleted==_",     "Underscore/Blank"),
    ]},
]

jobs = {}

# ── SSL context ───────────────────────────────────────────────────────────────
_ssl_ctx = _ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = _ssl.CERT_NONE

# ── Query helpers ─────────────────────────────────────────────────────────────
def _split_segs(q): return q.split("&") if q else []

def query_to_segments(q):
    segs = []
    for seg in _split_segs(q):
        if "=" in seg:
            k, _, v = seg.partition("=")
            vd = unquote(v)
            segs.append({"key_raw": k, "val_raw": v, "val_decoded": vd, "was_encoded": v != vd})
        else:
            segs.append({"key_raw": seg, "val_raw": None, "val_decoded": None, "was_encoded": False})
    return segs

def segments_to_query(segs):
    parts = []
    for s in segs:
        if s["val_raw"] is None: parts.append(s["key_raw"])
        elif s["was_encoded"]:   parts.append(s["key_raw"] + "=" + quote(s["val_decoded"], safe=""))
        else:                    parts.append(s["key_raw"] + "=" + s["val_decoded"])
    return "&".join(parts)

def replace_in_segments(segs, old, new):
    r = deepcopy(segs)
    for s in r:
        if s["val_decoded"] and old in s["val_decoded"]:
            s["val_decoded"] = s["val_decoded"].replace(old, new)
    return r

def _b64_decode(s):
    import base64
    for pad in ("","=","==","==="):
        try: return base64.b64decode(s + pad).decode("utf-8")
        except: pass
    return None

def _b64_encode(s):
    import base64
    return base64.b64encode(s.encode()).decode()

# ── URL Analysis ──────────────────────────────────────────────────────────────
def analyse_url(url):
    parsed    = urlparse(url)
    raw_query = parsed.query
    segs      = query_to_segments(raw_query)

    # 1. Plain / URL-encoded
    for seg in segs:
        if not seg["val_decoded"]: continue
        for fc in SOFT_DELETE_FILTERS:
            if fc["original"] in seg["val_decoded"]:
                enc = "url_encoded" if any(s["was_encoded"] for s in segs) else "plain"
                return {"url": url, "parsed": parsed, "segs": segs,
                        "fc": fc, "enc": enc, "b64_whole": False, "b64_key": None}

    # 2. Double URL-encoded
    segs2 = query_to_segments(raw_query)
    for seg in segs2:
        if not seg["val_decoded"]: continue
        twice = unquote(seg["val_decoded"])
        if twice != seg["val_decoded"]:
            for fc in SOFT_DELETE_FILTERS:
                if fc["original"] in twice:
                    seg["val_decoded"] = twice; seg["was_encoded"] = True
                    return {"url": url, "parsed": parsed, "segs": segs2,
                            "fc": fc, "enc": "double_url_encoded", "b64_whole": False, "b64_key": None}

    # 3. Base64 param value
    for seg in segs:
        if not seg["val_raw"]: continue
        b64 = _b64_decode(seg["val_raw"])
        if b64:
            for fc in SOFT_DELETE_FILTERS:
                if fc["original"] in b64:
                    s2 = deepcopy(segs)
                    for s in s2:
                        if s["key_raw"] == seg["key_raw"]:
                            s["val_decoded"] = b64; s["val_raw"] = b64; s["was_encoded"] = False
                    return {"url": url, "parsed": parsed, "segs": s2,
                            "fc": fc, "enc": f"base64_param:{seg['key_raw']}",
                            "b64_whole": False, "b64_key": seg["key_raw"]}

    # 4. Base64 whole query
    b64q = _b64_decode(raw_query)
    if b64q:
        inner = query_to_segments(b64q)
        for seg in inner:
            if not seg["val_decoded"]: continue
            for fc in SOFT_DELETE_FILTERS:
                if fc["original"] in seg["val_decoded"]:
                    return {"url": url, "parsed": parsed, "segs": inner,
                            "fc": fc, "enc": "base64_whole_query", "b64_whole": True, "b64_key": None}
    return None

def build_bypass_url(analysis, bypass_value):
    fc, segs, parsed = analysis["fc"], analysis["segs"], analysis["parsed"]
    original = fc["original"]
    if analysis["b64_whole"]:
        inner = replace_in_segments(segs, original, bypass_value)
        new_q = _b64_encode(segments_to_query(inner))
    elif analysis["b64_key"]:
        import base64
        s2 = deepcopy(segs)
        for seg in s2:
            if seg["key_raw"] == analysis["b64_key"] and seg["val_decoded"]:
                seg["val_decoded"] = seg["val_decoded"].replace(original, bypass_value)
                seg["val_raw"] = _b64_encode(seg["val_decoded"]); seg["was_encoded"] = False
        new_q = "&".join(s["key_raw"] + "=" + s["val_raw"] if s["val_raw"] is not None else s["key_raw"] for s in s2)
    else:
        new_q = segments_to_query(replace_in_segments(segs, original, bypass_value))
    return urlunparse(parsed._replace(query=new_q))

def build_bypass_url_stripped(analysis, bypass_value):
    """Build a bypass URL keeping only the bypass_value in the segment,
    stripping any extra semicolon-separated clauses (e.g. 'deleted==false;id==6295' → 'deleted==true').
    Returns None if the original segment value has no extra content (nothing to strip)."""
    fc, segs, parsed = analysis["fc"], analysis["segs"], analysis["parsed"]
    original = fc["original"]

    if analysis["b64_whole"] or analysis["b64_key"]:
        return None  # Only applies to plain/url-encoded segments

    stripped_segs = deepcopy(segs)
    had_extra = False
    for seg in stripped_segs:
        if seg["val_decoded"] and original in seg["val_decoded"]:
            if seg["val_decoded"].strip() != original:
                had_extra = True
            seg["val_decoded"] = bypass_value
    if not had_extra:
        return None
    new_q = segments_to_query(stripped_segs)
    return urlunparse(parsed._replace(query=new_q))

# ── Parse HAR ─────────────────────────────────────────────────────────────────
def parse_har_for_sd(har):
    entries = har.get("log", {}).get("entries", [])
    seen, results, auto_auth = set(), [], {}
    for entry in entries[:30]:
        for h in entry.get("request",{}).get("headers",[]):
            if h["name"].lower() in ("authorization","x-auth-token"):
                auto_auth[h["name"]] = h.get("value", "")
    for entry in entries:
        rq = entry.get("request", {})
        if rq.get("method","").upper() != "GET": continue
        url = rq.get("url","")
        if url in seen: continue
        analysis = analyse_url(url)
        if not analysis: continue
        seen.add(url)
        hdrs = {h["name"]: h.get("value", "") for h in rq.get("headers",[])
                if not h["name"].startswith(":") and h["name"].lower() not in ("authorization","content-length")}
        analysis["har_headers"] = hdrs
        results.append(analysis)
    return results, auto_auth

# ── Compare ───────────────────────────────────────────────────────────────────
# Soft-delete evidence keys/values — BYPASS only when NEW evidence appears in mod
_DELETED_BOOL_KEYS = {"deleted", "isdeleted", "is_deleted"}
_DELETED_AT_KEYS = {
    "deletedat", "deleted_at", "deletedon", "deleted_on",
    "softdeletedat", "soft_deleted_at",
}
_STATUS_KEYS = {"status", "recordstatus", "record_status", "state"}
_STATUS_DELETED_VALUES = {"deleted", "soft_deleted", "softdeleted"}


def _is_empty(data):
    if data is None: return True
    if isinstance(data, (list, dict)) and len(data) == 0: return True
    if isinstance(data, (int, float)) and data == 0: return True
    if isinstance(data, str) and not data.strip(): return True
    return False


def _is_truthy_deleted_flag(v):
    if v is True:
        return True
    if isinstance(v, (int, float)) and v == 1:
        return True
    if isinstance(v, str) and v.strip().lower() in ("true", "1", "yes"):
        return True
    return False


def _soft_delete_evidence(data):
    """Collect soft-deleted markers in a JSON tree (paths as strings)."""
    findings = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                cp = f"{path}.{k}" if path else k
                kl = str(k).lower()
                if kl in _DELETED_BOOL_KEYS and _is_truthy_deleted_flag(v):
                    findings.append(f"{cp}={v}")
                elif kl in _STATUS_KEYS and isinstance(v, str):
                    if v.strip().lower() in _STATUS_DELETED_VALUES:
                        findings.append(f"{cp}={v}")
                elif kl in _DELETED_AT_KEYS:
                    if v is not None and v is not False and v != "":
                        findings.append(f"{cp}={v}")
                walk(v, cp)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(data)
    return len(findings) > 0, findings


# Back-compat alias used nowhere else after rename, keep for safety
def _has_deleted_true(data):
    return _soft_delete_evidence(data)


def compare(orig_resp, mod_resp):
    """BYPASS only when mod response shows NEW soft-delete evidence vs original.

    Size / array-growth alone are NOT enough (major FP source, esp. stripped
    RSQL clauses that drop sibling filters like id==…).
    """
    r = {"orig_status": None, "mod_status": None,
         "orig_body": "", "mod_body": "",
         "is_issue": False, "skip_reason": "", "diff_summary": "",
         "orig_len": 0, "mod_len": 0, "len_diff": 0}

    if orig_resp is None or mod_resp is None:
        r["skip_reason"] = "Network failure"
        r["diff_summary"] = "Network error — could not complete request"
        r["orig_status"] = "ERR" if orig_resp is None else orig_resp.status_code
        r["mod_status"]  = "ERR" if mod_resp  is None else mod_resp.status_code
        return r

    r.update(orig_status=orig_resp.status_code, mod_status=mod_resp.status_code,
             orig_body=orig_resp.text, mod_body=mod_resp.text,
             orig_len=len(orig_resp.text), mod_len=len(mod_resp.text))
    r["len_diff"] = r["mod_len"] - r["orig_len"]

    if orig_resp.status_code >= 400:
        r["skip_reason"] = f"Original error ({orig_resp.status_code})"; return r
    if mod_resp.status_code >= 400:
        r["skip_reason"] = f"Modified {mod_resp.status_code} — Secure"; return r

    # Identical responses — always safe
    if orig_resp.text == mod_resp.text:
        r["skip_reason"] = "Same response — Secure"; return r

    try:
        od = json.loads(orig_resp.text)
        md = json.loads(mod_resp.text)

        if _is_empty(md):
            r["skip_reason"] = "Modified empty — Secure"; return r

        _, orig_paths = _soft_delete_evidence(od)
        _, mod_paths  = _soft_delete_evidence(md)

        # Only flag if bypass response has NEW soft-delete evidence
        # that was NOT present in the original response
        orig_path_set = set(orig_paths)
        new_paths = [p for p in mod_paths if p not in orig_path_set]

        if new_paths:
            r["is_issue"] = True
            r["diff_summary"] = (
                f"Soft-deleted records exposed — NEW evidence: "
                f"{', '.join(new_paths[:3])}"
                + (" …" if len(new_paths) > 3 else "")
            )
            return r

        # Size / count changes without soft-delete evidence → NOT a bypass
        if isinstance(od, list) and isinstance(md, list):
            if len(md) > len(od):
                r["skip_reason"] = (
                    f"More records ({len(od)}→{len(md)}) but no soft-delete "
                    f"evidence — ignored"
                )
                return r
            if len(md) < len(od):
                r["skip_reason"] = "Fewer records returned — Secure"; return r

        pct = abs(r["len_diff"]) / max(r["orig_len"], 1) * 100
        if pct > 10:
            r["skip_reason"] = (
                f"Response size changed ({pct:.1f}%) but no soft-delete "
                f"evidence — ignored"
            )
        else:
            r["skip_reason"] = "Minor diff — Secure"

    except Exception:
        # Non-JSON: cannot prove soft-delete leak without field evidence
        pct = abs(r["len_diff"]) / max(r["orig_len"], 1) * 100
        if pct > 10:
            r["skip_reason"] = (
                f"Non-JSON size changed ({pct:.1f}%) — ignored (no evidence)"
            )
        else:
            r["skip_reason"] = "Same response — Secure"
    return r

def _build_curl(url: str, headers: dict) -> str:
    parts = [f"curl -X GET '{url}'"]
    for k, v in (headers or {}).items():
        if k.lower() in ("content-length", "host", "connection", "transfer-encoding"):
            continue
        v_safe = str(v).replace("'", "'\\''")
        parts.append(f"  -H '{k}: {v_safe}'")
    return " \\\n".join(parts)


def _fire(url, headers):
    try:
        resp = req_lib.get(url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=False)
        return resp
    except Exception:
        return None

# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/")
def root(): return {"status":"ok","service":"Soft Delete Backend"}

@app.post("/sd/parse")
async def sd_parse(file: UploadFile = File(...)):
    content = await file.read()
    try: har = json.loads(content)
    except: raise HTTPException(400, "Invalid JSON")
    eps, auto_auth = parse_har_for_sd(har)
    auto_token = list(auto_auth.values())[0] if auto_auth else ""
    return {"ep_count": len(eps), "auto_token": auto_token, "raw_count": len(har.get("log",{}).get("entries",[]))}

@app.post("/sd/scan")
async def sd_scan(file: UploadFile = File(...), token: str = Form(default="")):
    content = await file.read()
    try: har = json.loads(content)
    except: raise HTTPException(400, "Invalid JSON")

    analyses, auto_auth = parse_har_for_sd(har)
    if not analyses: raise HTTPException(400, "No soft-delete filter URLs found in HAR (looking for deleted==false or isDeleted==false)")

    auth_token = token.strip()
    if not auth_token and auto_auth:
        auth_token = list(auto_auth.values())[0]
    if auth_token and not auth_token.lower().startswith("bearer "):
        auth_token = f"Bearer {auth_token}"

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status": "running", "progress": 0, "completed": 0,
        "total": len(analyses), "results": [], "logs": [], "feed": [],
        "current_url": "",
        "errors": 0, "bypasses": 0, "start_time": time.time(), "elapsed": 0,
        "aborted": False, "abort_reason": "",
    }

    def _aborted(job):
        return bool(job.get("aborted")) or job.get("status") == "aborted"

    def run():
        job = jobs[job_id]
        all_results, all_logs = [], []
        completed = 0

        for analysis in analyses:
            if _aborted(job):
                break
            headers = dict(analysis.get("har_headers", {}))
            # Only set Authorization when a token was provided (avoid wiping session auth)
            if auth_token:
                headers["Authorization"] = auth_token
            job["current_url"] = analysis["url"]
            orig_resp = _fire(analysis["url"], headers)
            orig_curl = _build_curl(analysis["url"], headers)

            for bypass_val, bypass_label in analysis["fc"]["bypasses"]:
                if _aborted(job):
                    break
                bypass_url = build_bypass_url(analysis, bypass_val)
                mod_resp   = _fire(bypass_url, headers)
                bypass_curl = _build_curl(bypass_url, headers)
                # compare() only flags NEW soft-delete evidence (not size alone)
                diff       = compare(orig_resp, mod_resp)

                log_entry = {
                    "original_url": analysis["url"],
                    "bypass_url":   bypass_url,
                    "bypass_value": bypass_val,
                    "bypass_label": bypass_label,
                    "filter":       analysis["fc"]["original"],
                    "enc_type":     analysis["enc"],
                    "headers":      headers,
                    "orig_curl":    orig_curl,
                    "bypass_curl":  bypass_curl,
                    "orig_status":  diff["orig_status"],
                    "mod_status":   diff["mod_status"],
                    "is_issue":     diff["is_issue"],
                    "skip_reason":  diff["skip_reason"],
                    "diff_summary": diff["diff_summary"],
                    "orig_body":    diff["orig_body"],
                    "mod_body":     diff["mod_body"],
                    "orig_len":     diff["orig_len"],
                    "mod_len":      diff["mod_len"],
                    "len_diff":     diff["len_diff"],
                }
                all_logs.append(log_entry)
                if diff["is_issue"]:
                    all_results.append(log_entry)
                    job["bypasses"] += 1

                feed_item = {
                    "url":          analysis["url"],
                    "filter":       analysis["fc"]["original"],
                    "bypass_val":   bypass_val,
                    "bypass_label": bypass_label,
                    "orig_status":  diff["orig_status"],
                    "mod_status":   diff["mod_status"],
                    "is_issue":     diff["is_issue"],
                    "summary":      diff["diff_summary"] or diff["skip_reason"] or "Secure",
                    "time":         round(time.time() - job["start_time"], 1)
                }
                job.setdefault("feed", []).append(feed_item)
                if len(job["feed"]) > 80:
                    job["feed"] = job["feed"][-80:]

                # Stripped-clause test: same evidence-only rule (size FP blocked in compare)
                if _aborted(job):
                    break
                stripped_url = build_bypass_url_stripped(analysis, bypass_val)
                if stripped_url and stripped_url != bypass_url:
                    mod_resp_s = _fire(stripped_url, headers)
                    diff_s     = compare(orig_resp, mod_resp_s)
                    stripped_curl = _build_curl(stripped_url, headers)
                    log_entry_s = {
                        "original_url": analysis["url"],
                        "bypass_url":   stripped_url,
                        "bypass_value": bypass_val,
                        "bypass_label": bypass_label + " (Stripped)",
                        "filter":       analysis["fc"]["original"],
                        "enc_type":     analysis["enc"] + "+stripped",
                        "headers":      headers,
                        "orig_curl":    orig_curl,
                        "bypass_curl":  stripped_curl,
                        "orig_status":  diff_s["orig_status"],
                        "mod_status":   diff_s["mod_status"],
                        "is_issue":     diff_s["is_issue"],
                        "skip_reason":  diff_s["skip_reason"],
                        "diff_summary": diff_s["diff_summary"],
                        "orig_body":    diff_s["orig_body"],
                        "mod_body":     diff_s["mod_body"],
                        "orig_len":     diff_s["orig_len"],
                        "mod_len":      diff_s["mod_len"],
                        "len_diff":     diff_s["len_diff"],
                    }
                    all_logs.append(log_entry_s)
                    if diff_s["is_issue"]:
                        all_results.append(log_entry_s)
                        job["bypasses"] += 1

                    feed_item_s = {
                        "url":          analysis["url"],
                        "filter":       analysis["fc"]["original"],
                        "bypass_val":   bypass_val,
                        "bypass_label": bypass_label + " (Stripped)",
                        "orig_status":  diff_s["orig_status"],
                        "mod_status":   diff_s["mod_status"],
                        "is_issue":     diff_s["is_issue"],
                        "summary":      diff_s["diff_summary"] or diff_s["skip_reason"] or "Secure",
                        "time":         round(time.time() - job["start_time"], 1)
                    }
                    job.setdefault("feed", []).append(feed_item_s)
                    if len(job["feed"]) > 80:
                        job["feed"] = job["feed"][-80:]

            completed += 1
            job["completed"] = completed
            job["progress"]  = int(100 * completed / max(len(analyses), 1))
            job["results"]   = all_results
            job["logs"]      = all_logs

        job["elapsed"] = round(time.time() - job["start_time"], 1)
        job["status"]  = "done"
        job["progress"] = 100

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return {"job_id": job_id, "total": len(analyses)}


@app.post("/sd/abort/{job_id}")
def sd_abort(job_id: str):
    """Stop a running soft-delete scan after the current request finishes."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "running":
        return {"ok": True, "status": job["status"], "aborted": job.get("aborted", False)}
    job["aborted"] = True
    job["abort_reason"] = "user"
    job["status"] = "aborted"
    return {"ok": True, "status": "aborting"}


@app.get("/sd/progress/{job_id}")
def sd_progress(job_id: str):
    job = jobs.get(job_id)
    if not job: raise HTTPException(404, "Job not found")
    return {
        "status":       job["status"],
        "progress":     job["progress"],
        "completed":    job["completed"],
        "total":        job["total"],
        "results":      job["results"],
        "feed":         job.get("feed", []),
        "current_url":  job.get("current_url", ""),
        "logs":         job["logs"] if job["status"] == "done" else [],
        "bypasses":     job["bypasses"],
        "errors":       job["errors"],
        "aborted":      job.get("aborted", False),
        "abort_reason": job.get("abort_reason", ""),
        "elapsed":      round(time.time() - job["start_time"], 1) if job["status"] in ("running", "aborted")
                        else job["elapsed"],
    }

@app.get("/sd/csv/{job_id}")
def sd_csv(job_id: str):
    job = jobs.get(job_id)
    if not job: raise HTTPException(404, "Job not found")
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL)
    w.writerow(["#","Original URL","Bypass URL","Bypass Value","Bypass Label","Filter","Encoding",
                "Orig Status","Mod Status","Is Issue","Skip Reason","Diff Summary","Orig Len","Mod Len"])
    for i, r in enumerate(job.get("logs",[]), 1):
        w.writerow([i, r["original_url"], r["bypass_url"], r["bypass_value"], r["bypass_label"],
                    r["filter"], r["enc_type"], r["orig_status"], r["mod_status"],
                    "YES" if r["is_issue"] else "No", r["skip_reason"], r["diff_summary"],
                    r["orig_len"], r["mod_len"]])
    out.seek(0)
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=soft_delete_{ts}.csv"})