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

# ── Parse HAR ─────────────────────────────────────────────────────────────────
def parse_har_for_sd(har):
    entries = har.get("log", {}).get("entries", [])
    seen, results, auto_auth = set(), [], {}
    for entry in entries[:30]:
        for h in entry.get("request",{}).get("headers",[]):
            if h["name"].lower() in ("authorization","x-auth-token"):
                auto_auth[h["name"]] = h["value"]
    for entry in entries:
        rq = entry.get("request", {})
        if rq.get("method","").upper() != "GET": continue
        url = rq.get("url","")
        if url in seen: continue
        analysis = analyse_url(url)
        if not analysis: continue
        seen.add(url)
        hdrs = {h["name"]: h["value"] for h in rq.get("headers",[])
                if not h["name"].startswith(":") and h["name"].lower() not in ("authorization","content-length")}
        analysis["har_headers"] = hdrs
        results.append(analysis)
    return results, auto_auth

# ── Compare ───────────────────────────────────────────────────────────────────
def _is_empty(data):
    if data is None: return True
    if isinstance(data, (list, dict)) and len(data) == 0: return True
    if isinstance(data, (int, float)) and data == 0: return True
    if isinstance(data, str) and not data.strip(): return True
    return False

def _has_deleted_true(data):
    findings = []
    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                cp = f"{path}.{k}" if path else k
                if k in ("deleted","isDeleted") and (v is True or v == "true"):
                    findings.append(f"{cp}={v}")
                walk(v, cp)
        elif isinstance(node, list):
            for i, item in enumerate(node): walk(item, f"{path}[{i}]")
    walk(data)
    return len(findings) > 0, findings

def compare(orig_resp, mod_resp):
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
             orig_body=orig_resp.text[:3000], mod_body=mod_resp.text[:3000],
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

        # Check deleted=True in BOTH responses
        orig_found, orig_paths = _has_deleted_true(od)
        mod_found,  mod_paths  = _has_deleted_true(md)

        # Only flag if bypass response has NEW deleted=True paths
        # that were NOT present in the original response
        orig_path_set = set(orig_paths)
        new_deleted_paths = [p for p in mod_paths if p not in orig_path_set]

        if new_deleted_paths:
            r["is_issue"] = True
            r["diff_summary"] = (
                f"Soft-deleted records exposed — NEW deleted=true fields: "
                f"{', '.join(new_deleted_paths[:3])}"
                + (" …" if len(new_deleted_paths) > 3 else "")
            )
            return r

        # Check record count change (array length)
        if isinstance(od, list) and isinstance(md, list):
            if len(md) > len(od):
                r["is_issue"] = True
                r["diff_summary"] = f"More records returned: {len(od)} → {len(md)} (deleted records exposed)"
                return r
            if len(md) < len(od):
                r["skip_reason"] = "Fewer records returned — Secure"; return r

        # Check significant content diff
        pct = abs(r["len_diff"]) / max(r["orig_len"], 1) * 100
        if pct > 10:
            r["is_issue"] = True
            r["diff_summary"] = f"Response changed significantly: {r['len_diff']:+d} bytes ({pct:.1f}%)"
        else:
            r["skip_reason"] = "Minor diff — Secure"

    except Exception:
        pct = abs(r["len_diff"]) / max(r["orig_len"], 1) * 100
        if pct > 10:
            r["is_issue"] = True
            r["diff_summary"] = f"Non-JSON diff: {r['len_diff']:+d} bytes ({pct:.1f}%)"
        else:
            r["skip_reason"] = "Same response — Secure"
    return r

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
        "total": len(analyses), "results": [], "logs": [],
        "errors": 0, "bypasses": 0, "start_time": time.time(), "elapsed": 0,
    }

    def run():
        job = jobs[job_id]
        all_results, all_logs = [], []
        completed = 0

        for analysis in analyses:
            if job["status"] == "aborted": break
            headers = {**analysis.get("har_headers", {}), "Authorization": auth_token}
            orig_resp = _fire(analysis["url"], headers)

            for bypass_val, bypass_label in analysis["fc"]["bypasses"]:
                bypass_url = build_bypass_url(analysis, bypass_val)
                mod_resp   = _fire(bypass_url, headers)
                diff       = compare(orig_resp, mod_resp)

                log_entry = {
                    "original_url": analysis["url"],
                    "bypass_url":   bypass_url,
                    "bypass_value": bypass_val,
                    "bypass_label": bypass_label,
                    "filter":       analysis["fc"]["original"],
                    "enc_type":     analysis["enc"],
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

            completed += 1
            job["completed"] = completed
            job["progress"]  = int(100 * completed / len(analyses))
            job["results"]   = all_results
            job["logs"]      = all_logs

        job["elapsed"] = round(time.time() - job["start_time"], 1)
        job["status"]  = "done"
        job["progress"] = 100

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return {"job_id": job_id, "total": len(analyses)}

@app.get("/sd/progress/{job_id}")
def sd_progress(job_id: str):
    job = jobs.get(job_id)
    if not job: raise HTTPException(404, "Job not found")
    return {
        "status":   job["status"],
        "progress": job["progress"],
        "completed":job["completed"],
        "total":    job["total"],
        "results":  job["results"],
        "logs":     job["logs"] if job["status"] == "done" else [],
        "bypasses": job["bypasses"],
        "errors":   job["errors"],
        "elapsed":  round(time.time() - job["start_time"], 1) if job["status"] == "running" else job["elapsed"],
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
