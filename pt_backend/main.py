"""
Parameter Tampering Backend — Port 8772
Wraps Parameter_temper.py core logic in a FastAPI service.
"""

import importlib.util as _ilu
import os
import sys

_spec = _ilu.spec_from_file_location(
    "pt_core",
    os.path.join(os.path.dirname(__file__), "Parameter_temper.py")
)
_pt = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_pt)

import csv
import io
import json
import threading
import time
import uuid
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="Parameter Tampering Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Job store ──────────────────────────────────────────────────────────────────
jobs = {}          # job_id → job dict
jobs_lock = threading.Lock()

# ── Preflight / baseline cache ─────────────────────────────────────────────────
# Stores the full response snapshot fired by /preflight so the scan can use
# it as a fixed baseline instead of re-firing the original on every test.
# Key: stripped cURL string  →  {snap, request_repr}
_preflight_cache = {}
_preflight_lock  = threading.Lock()


# ── Pydantic models ────────────────────────────────────────────────────────────

class ParseRequest(BaseModel):
    curl: str


class ScanOptions(BaseModel):
    context_aware: bool = True
    threads: int = 8
    timeout: int = 10
    delay: float = 0.0


class ScanRequest(BaseModel):
    curl: str
    selected_params: List[List[str]]   # [[source, name], ...]
    options: ScanOptions = ScanOptions()
    random_formats: Optional[dict] = None  # {param_name: format_string}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _risk_order(r):
    return {"High Risk": 0, "Medium Risk": 1, "Possible": 2, "No Issue": 3}.get(r, 4)


def _summary_from_findings(findings):
    s = {"high": 0, "medium": 0, "possible": 0, "no_issue": 0}
    for f in findings:
        rl = f.get("risk_level", "")
        if rl == "High Risk":
            s["high"] += 1
        elif rl == "Medium Risk":
            s["medium"] += 1
        elif rl == "Possible":
            s["possible"] += 1
        else:
            s["no_issue"] += 1
    return s


def _live_entry(f):
    return {
        "param":       f.get("param_name", ""),
        "mutation":    f.get("mutation_type", ""),
        "risk":        f.get("risk_level", "No Issue"),
        "conf":        f.get("confidence", ""),
        "orig_status": f.get("orig_status"),
        "mut_status":  f.get("mut_status"),
        "evidence":    (f.get("evidence") or "")[:120],
    }


# ── Baseline-aware test runner ────────────────────────────────────────────────
def _run_test_with_baseline(task, baseline):
    """
    Same as _pt.run_test(task) but uses a pre-fired baseline snapshot instead
    of re-sending the original request on every test.  This prevents the
    "original was 422 → every mutation at 200 = false positive" problem.
    """
    (session, bearer, timeout, verbose, delay,
     entry, source, param_name, orig_value,
     mutation_label, mutated_value, mutated_entry,
     random_formats, csrf_refresher) = task

    if delay and delay > 0:
        time.sleep(delay)

    # Apply randomisation / CSRF only to the mutated entry
    mutated_entry = _pt.apply_random_formats(deepcopy(mutated_entry), random_formats)
    if csrf_refresher:
        mutated_entry = csrf_refresher.apply(deepcopy(mutated_entry))

    t1 = time.time()
    mut_resp = _pt.send_request(
        session, mutated_entry.method, mutated_entry.url,
        mutated_entry.headers, mutated_entry.query_params,
        mutated_entry.body, mutated_entry.body_type, bearer, timeout,
    )
    t2 = time.time()

    o = baseline["snap"]          # fixed, pre-fired original
    m = _pt.snap(mut_resp)

    c = _pt.compare(
        o, m,
        mutation_label=mutation_label,
        payload=str(mutated_value),
        # Use real baseline elapsed so slow APIs aren't false time-based hits
        elapsed_orig=float(baseline.get("elapsed") or 0.0),
        elapsed_mut=(t2 - t1),
        timeout=timeout,
    )

    orig_entry_for_repr = baseline.get("entry", entry)

    return {
        "url":            entry.url,
        "method":         entry.method,
        "param_name":     param_name,
        "param_source":   source,
        "orig_value":     str(orig_value),
        "mutation_type":  mutation_label,
        "mut_value":      str(mutated_value)[:300],
        "orig_status":    o["status"],
        "mut_status":     m["status"],
        "status_changed": c["status_changed"],
        "orig_length":    o["length"],
        "mut_length":     m["length"],
        "diff_pct":       c["diff_pct"],
        "body_changed":   c["body_changed"],
        "risk_level":     c["risk_level"],
        "confidence":     c["confidence"],
        "evidence":       c["evidence"],
        "time_delta":     c["time_delta"],
        "keywords":       c["keywords"],
        "sql_disclosure": bool(c.get("sql_disclosure")),
        "orig_request":   baseline["request_repr"],
        "mut_request":    _pt.req_repr(
            mutated_entry.method, mutated_entry.url,
            mutated_entry.headers, mutated_entry.body,
            mutated_entry.body_type,
        ),
        "orig_curl":      _pt.entry_to_curl(orig_entry_for_repr, bearer),
        "mut_curl":       _pt.entry_to_curl(mutated_entry, bearer),
        "orig_request_body_json": _pt.clip_dump(
            json.dumps(orig_entry_for_repr.body, indent=2)
            if orig_entry_for_repr.body_type == "json"
               and isinstance(orig_entry_for_repr.body, (dict, list))
            else str(orig_entry_for_repr.body or ""),
            _pt.REQ_BODY_LIMIT,
        ),
        "mut_request_body_json": _pt.clip_dump(
            json.dumps(mutated_entry.body, indent=2)
            if mutated_entry.body_type == "json"
               and isinstance(mutated_entry.body, (dict, list))
            else str(mutated_entry.body or ""),
            _pt.REQ_BODY_LIMIT,
        ),
        "orig_response":  o["text"][:2000],
        "mut_response":   m["text"][:2000],
    }


# ── Background scan runner ─────────────────────────────────────────────────────

def _run_scan(job_id: str, curl: str, selected_params, options: ScanOptions, random_formats: dict = None):
    job = jobs[job_id]
    stop_event = job.get("stop_event") or threading.Event()

    try:
        entry = _pt.parse_curl_text(curl)
    except Exception as e:
        with jobs_lock:
            job["status"] = "error"
            job["error"] = str(e)
        return

    bearer = entry.headers.get("Authorization") or entry.headers.get("authorization") or ""
    session = _pt.build_session(verify_ssl=False)

    try:
        tasks, _ = _pt.generate_tasks(
            session=session,
            bearer=bearer,
            timeout=options.timeout,
            verbose=False,
            delay=options.delay,
            entry=entry,
            selected_params=selected_params if selected_params else None,
            random_formats=random_formats or {},
            context_aware=options.context_aware,
        )
    except Exception as e:
        with jobs_lock:
            job["status"] = "error"
            job["error"] = f"Task generation failed: {e}"
        return

    total = len(tasks)
    with jobs_lock:
        job["total"] = total
        job["status"] = "scanning"

    # Check if a preflight baseline was fired for this exact cURL
    with _preflight_lock:
        baseline = _preflight_cache.get(curl.strip())

    if baseline:
        def _run_task(task):
            if stop_event.is_set():
                return None
            return _run_test_with_baseline(task, baseline)
    else:
        def _run_task(task):
            if stop_event.is_set():
                return None
            return _pt.run_test(task)

    findings = []
    done = 0
    aborted = False

    max_workers = max(1, min(options.threads, 32))
    # Delay only spaces requests reliably when sequential — concurrent
    # workers would still burst N requests after sleeping the same amount.
    if options.delay and options.delay > 0:
        max_workers = 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_run_task, task): task for task in tasks}

        for future in as_completed(future_map):
            if stop_event.is_set():
                aborted = True
                for f in future_map:
                    f.cancel()
                # Drain remaining completed futures without starting new work
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    findings.append(result)
                    done += 1
                    with jobs_lock:
                        job["findings"] = list(findings)
                        job["done"] = done
                        job["summary"] = _summary_from_findings(findings)
                break

            try:
                result = future.result()
            except Exception:
                result = None

            done += 1

            if result:
                findings.append(result)
                live = _live_entry(result)

                with jobs_lock:
                    feed = job["live_feed"]
                    feed.append(live)
                    if len(feed) > 8:
                        feed.pop(0)
                    # Publish incrementally so UI can stream Results mid-scan
                    job["findings"] = list(findings)
                    job["done"] = done
                    job["summary"] = _summary_from_findings(findings)
                    job["aborted"] = bool(job.get("aborted") or stop_event.is_set())
            else:
                with jobs_lock:
                    job["done"] = done

            if stop_event.is_set():
                aborted = True
                for f in future_map:
                    f.cancel()
                break

    # Post-process: suppress global false positives
    try:
        findings = _pt.suppress_global_fp(findings)
    except Exception:
        pass

    # Sort by risk level
    findings.sort(key=lambda f: _risk_order(f.get("risk_level", "No Issue")))

    with jobs_lock:
        job["findings"] = findings
        job["summary"] = _summary_from_findings(findings)
        job["done"] = done if aborted else total
        job["aborted"] = aborted or bool(job.get("aborted"))
        job["status"] = "done"
        job.pop("stop_event", None)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "Parameter Tampering Backend running", "port": 8772}


@app.post("/preflight")
def preflight(req: ParseRequest):
    """
    Fire the original cURL once and return the status + response snippet.
    Used by the UI to validate the baseline before starting a scan.
    """
    if not req.curl.strip():
        raise HTTPException(400, "curl field is required")
    try:
        entry = _pt.parse_curl_text(req.curl)
    except Exception as e:
        raise HTTPException(400, f"Could not parse cURL: {e}")

    session = _pt.build_session(verify_ssl=False)
    bearer = (
        entry.headers.get("Authorization")
        or entry.headers.get("authorization")
        or ""
    )
    t0 = time.time()
    try:
        resp = _pt.send_request(
            session, entry.method, entry.url,
            entry.headers, entry.query_params,
            entry.body, entry.body_type, bearer, timeout=10,
        )
    except Exception as e:
        return {"status": None, "ok": False, "method": entry.method,
                "body_snippet": "", "length": 0, "error": str(e)}
    elapsed = time.time() - t0

    if resp is None:
        return {"status": None, "ok": False, "method": entry.method,
                "body_snippet": "", "length": 0, "error": "No response (connection error)"}

    body_snippet = (resp.text or "")[:400]
    length = len(resp.content) if resp.content else 0
    ok = 200 <= resp.status_code < 300

    # Cache the full baseline snap so the scan can reuse it
    snap     = _pt.snap(resp)
    req_repr = _pt.req_repr(
        entry.method, entry.url, entry.headers,
        entry.body, entry.body_type,
    )
    with _preflight_lock:
        _preflight_cache[req.curl.strip()] = {
            "snap":         snap,
            "request_repr": req_repr,
            "entry":        entry,   # keep parsed entry for orig_request_body_json
            "elapsed":      elapsed, # real baseline timing for time-based compare
        }

    return {
        "status":       resp.status_code,
        "ok":           ok,
        "method":       entry.method,
        "body_snippet": body_snippet,
        "length":       length,
        "error":        None,
    }


@app.post("/parse")
def parse_curl(req: ParseRequest):
    if not req.curl.strip():
        raise HTTPException(400, "curl field is required")
    try:
        entry = _pt.parse_curl_text(req.curl)
    except Exception as e:
        raise HTTPException(400, str(e))

    params = entry.all_params()   # [(source, name, value), ...]
    parsed_url = entry.url
    try:
        from urllib.parse import urlparse
        endpoint = urlparse(parsed_url).path
    except Exception:
        endpoint = parsed_url

    return {
        "params": [
            {"source": s, "name": n, "value": str(v)[:200]}
            for s, n, v in params
        ],
        "method": entry.method,
        "url": parsed_url,
        "endpoint": endpoint,
        "param_count": len(params),
    }


@app.post("/scan/start")
def start_scan(req: ScanRequest):
    if not req.curl.strip():
        raise HTTPException(400, "curl field is required")

    job_id = str(uuid.uuid4())[:8]
    stop_event = threading.Event()
    job = {
        "status":     "pending",
        "total":      0,
        "done":       0,
        "live_feed":  [],
        "findings":   [],
        "summary":    {"high": 0, "medium": 0, "possible": 0, "no_issue": 0},
        "error":      None,
        "aborted":    False,
        "stop_event": stop_event,
    }
    with jobs_lock:
        jobs[job_id] = job

    selected = [list(p) for p in req.selected_params] if req.selected_params else []

    t = threading.Thread(
        target=_run_scan,
        args=(job_id, req.curl, selected, req.options, req.random_formats or {}),
        daemon=True,
    )
    t.start()
    return {"job_id": job_id}


@app.post("/scan/abort/{job_id}")
def abort_scan(job_id: str):
    """Stop a running scan after in-flight workers finish current tasks."""
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] not in ("pending", "scanning"):
        return {"ok": True, "status": job["status"], "aborted": job.get("aborted", False)}
    ev = job.get("stop_event")
    if ev:
        ev.set()
    with jobs_lock:
        job["aborted"] = True
    return {"ok": True, "status": "aborting"}


@app.get("/scan/status/{job_id}")
def scan_status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    total = job["total"] or 1
    done  = job["done"]
    pct   = round(done / total * 100) if job["total"] else 0

    return {
        "status":    job["status"],
        "total":     job["total"],
        "done":      done,
        "pct":       pct,
        "live_feed": list(job["live_feed"]),
        "summary":   dict(job["summary"]),
        "error":     job.get("error"),
        "aborted":   bool(job.get("aborted")),
    }


@app.get("/scan/results/{job_id}")
def scan_results(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "findings": list(job["findings"]),
        "summary":  dict(job["summary"]),
        "aborted":  bool(job.get("aborted")),
    }


@app.get("/export/csv/{job_id}")
def export_csv(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow([
        "param_name", "param_source", "mutation_type",
        "orig_value", "mut_value",
        "orig_status", "mut_status",
        "risk_level", "confidence", "evidence", "url",
    ])
    for f in job["findings"]:
        w.writerow([
            f.get("param_name", ""),
            f.get("param_source", ""),
            f.get("mutation_type", ""),
            f.get("orig_value", ""),
            f.get("mut_value", ""),
            f.get("orig_status", ""),
            f.get("mut_status", ""),
            f.get("risk_level", ""),
            f.get("confidence", ""),
            f.get("evidence", ""),
            f.get("url", ""),
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=pt_report.csv"},
    )


@app.get("/export/html/{job_id}")
def export_html(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    findings = job["findings"]
    summary  = job["summary"]
    total    = len(findings)
    high     = summary.get("high", 0)
    medium   = summary.get("medium", 0)
    possible = summary.get("possible", 0)
    no_issue = summary.get("no_issue", 0)

    # Health score: 100 - weighted penalty
    score = max(0, 100 - (high * 20) - (medium * 8) - (possible * 3))
    score_color = "#3fb950" if score >= 75 else ("#f97316" if score >= 40 else "#f85149")

    def esc(s):
        return str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

    def risk_badge(r):
        colors = {
            "High Risk":   ("rgba(248,81,73,.15)",   "#f85149"),
            "Medium Risk": ("rgba(249,115,22,.12)",  "#f97316"),
            "Possible":    ("rgba(234,179,8,.12)",   "#d4a217"),
            "No Issue":    ("rgba(63,185,80,.10)",   "#3fb950"),
        }
        bg, col = colors.get(r, ("rgba(200,200,200,.1)", "#aaa"))
        return f'<span style="background:{bg};color:{col};border:1px solid {col};border-radius:999px;padding:1px 8px;font-size:10px;font-weight:700">{esc(r)}</span>'

    rows_html = ""
    for i, f in enumerate(findings, 1):
        rl = f.get("risk_level", "")
        row_bg = ""
        if rl == "High Risk":
            row_bg = "background:rgba(248,81,73,.04);"
        elif rl == "Medium Risk":
            row_bg = "background:rgba(249,115,22,.03);"

        rows_html += f"""
        <tr style="{row_bg}">
          <td style="color:#8b949e;text-align:center">{i}</td>
          <td><code style="color:#79c0ff;font-size:10px">{esc(f.get("param_name",""))}</code></td>
          <td><span style="font-size:9px;padding:1px 6px;border-radius:999px;background:rgba(31,111,235,.1);border:1px solid rgba(31,111,235,.3);color:#79c0ff">{esc(f.get("param_source",""))}</span></td>
          <td style="font-size:10px;color:#8b949e;font-family:monospace">{esc(f.get("mutation_type",""))}</td>
          <td style="font-family:monospace;font-size:10px">{esc(f.get("orig_status",""))} → {esc(f.get("mut_status",""))}</td>
          <td>{risk_badge(rl)}</td>
          <td style="font-size:10px;color:#8b949e">{esc(f.get("confidence",""))}</td>
          <td style="font-size:10px;color:#8b949e;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(f.get("evidence",""))}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Parameter Tampering Report</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px; padding: 32px; }}
h1 {{ font-size: 22px; margin-bottom: 4px; }}
.sub {{ color: #8b949e; font-size: 12px; margin-bottom: 24px; }}
.score {{ display: inline-block; background: {score_color}22; border: 2px solid {score_color}; color: {score_color}; border-radius: 10px; padding: 10px 24px; font-size: 28px; font-weight: 800; margin-bottom: 20px; }}
.cards {{ display: flex; gap: 14px; margin-bottom: 24px; flex-wrap: wrap; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 14px 22px; text-align: center; min-width: 110px; }}
.card-val {{ font-size: 28px; font-weight: 800; display: block; }}
.card-lbl {{ font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .5px; }}
.c-high {{ border-top: 3px solid #f85149; }} .c-high .card-val {{ color: #f85149; }}
.c-med  {{ border-top: 3px solid #f97316; }} .c-med  .card-val {{ color: #f97316; }}
.c-pos  {{ border-top: 3px solid #d4a217; }} .c-pos  .card-val {{ color: #d4a217; }}
.c-ok   {{ border-top: 3px solid #3fb950; }} .c-ok   .card-val {{ color: #3fb950; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ background: #161b22; color: #8b949e; padding: 8px 10px; text-align: left; border-bottom: 1px solid #30363d; font-size: 10px; text-transform: uppercase; letter-spacing: .4px; position: sticky; top: 0; }}
td {{ padding: 6px 10px; border-bottom: 1px solid rgba(48,54,61,.5); vertical-align: middle; }}
tr:hover td {{ background: rgba(255,255,255,.015); }}
.tbl-wrap {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; overflow: auto; max-height: 70vh; }}
</style>
</head>
<body>
<h1>🎯 Parameter Tampering Report</h1>
<div class="sub">Generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} &nbsp;·&nbsp; {total} findings</div>

<div class="score">{score}/100 Health Score</div>

<div class="cards">
  <div class="card c-high"><span class="card-val">{high}</span><span class="card-lbl">High Risk</span></div>
  <div class="card c-med"> <span class="card-val">{medium}</span><span class="card-lbl">Medium Risk</span></div>
  <div class="card c-pos"> <span class="card-val">{possible}</span><span class="card-lbl">Possible</span></div>
  <div class="card c-ok">  <span class="card-val">{no_issue}</span><span class="card-lbl">No Issue</span></div>
</div>

<div class="tbl-wrap">
<table>
<thead><tr>
  <th>#</th><th>Param</th><th>Source</th><th>Mutation Type</th>
  <th>Status</th><th>Risk</th><th>Confidence</th><th>Evidence</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>
</body>
</html>"""

    return StreamingResponse(
        iter([html]),
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=pt_report.html"},
    )
