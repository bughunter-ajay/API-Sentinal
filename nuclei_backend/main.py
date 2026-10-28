"""
Nuclei Scanner Backend — Port 8797
Template-Based API Vulnerability & Misconfiguration Scanner
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.parse
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from nuclei_backend.binary_helper import get_nuclei_info
from nuclei_backend.curl_parser import parse_curl_command
from nuclei_backend.nuclei_engine import (
    create_job,
    get_job,
    run_scan_job,
)
from nuclei_backend.swagger_parser import parse_swagger_spec
from nuclei_backend.har_parser import parse_har_file

# Drop InsecureRequestWarning
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nuclei_backend")

app = FastAPI(title="API Sentinel Nuclei Scanner", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ──────────────────────────────────────────────────

class ParseCurlReq(BaseModel):
    curl: str


class ParseSwaggerReq(BaseModel):
    spec_url: Optional[str] = None
    spec_text: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class ParseHarReq(BaseModel):
    har_text: str = Field(default="", description="HAR file content as JSON string")


class StartScanReq(BaseModel):
    target_type: str = Field(default="single", description="single, swagger, or multi")
    base_url: str = Field(default="", description="Base target host/URL")
    targets: List[Any] = Field(default_factory=list, description="Target URLs list")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers or auth tokens")
    tags: List[str] = Field(default_factory=lambda: ["api", "misconfig", "exposure"])
    rate_limit: int = Field(default=50)
    timeout: int = Field(default=10)


class ExportReportReq(BaseModel):
    title: Optional[str] = "Nuclei API Vulnerability Report"
    target_url: Optional[str] = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.get("/")
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "nuclei_scanner",
        "port": 8797,
        "nuclei_info": get_nuclei_info(),
    }


@app.get("/api/binary-info")
def binary_info():
    return get_nuclei_info()


@app.post("/api/parse-curl")
def parse_curl(req: ParseCurlReq):
    raw = req.curl.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty cURL input.")

    parsed = parse_curl_command(raw)
    target_url = parsed.get("url") or ""
    headers = parsed.get("headers") or {}
    method = parsed.get("method") or "GET"

    base_url = ""
    if target_url:
        p = urllib.parse.urlparse(target_url)
        if p.scheme and p.netloc:
            base_url = f"{p.scheme}://{p.netloc}"

    return {
        "success": bool(target_url),
        "url": target_url,
        "base_url": base_url,
        "method": method,
        "headers": headers,
    }


@app.post("/api/parse-swagger")
def parse_swagger(req: ParseSwaggerReq):
    res = parse_swagger_spec(
        spec_text=req.spec_text,
        spec_url=req.spec_url,
        headers=req.headers,
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to parse Swagger specification."))
    return res


@app.post("/api/parse-har")
def parse_har(req: ParseHarReq):
    res = parse_har_file(req.har_text)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to parse HAR file."))
    return res


@app.post("/api/scan/start")
def start_scan(req: StartScanReq):
    raw_targets = req.targets or []
    cleaned_targets = []
    base_url_clean = req.base_url.strip().rstrip("/") if req.base_url else ""
    parsed_base = urlparse(base_url_clean) if base_url_clean else None

    for t in raw_targets:
        u = ""
        if isinstance(t, str) and t.strip():
            u = t.strip()
        elif isinstance(t, dict):
            u = (t.get("full_url") or t.get("url") or t.get("path") or "").strip()

        if not u:
            continue

        if (u.startswith("/") or (not u.startswith("http://") and not u.startswith("https://"))) and base_url_clean:
            u = base_url_clean + ("/" if not u.startswith("/") else "") + u
        elif req.target_type in ("swagger", "har") and parsed_base and parsed_base.netloc:
            try:
                tu = urlparse(u)
                if tu.netloc and tu.netloc != parsed_base.netloc:
                    path_part = tu.path
                    base_path = parsed_base.path.rstrip("/")
                    # If target path starts with an old base path (like /businesstrip) that is already in base_path, trim it
                    if base_path and "/" in base_path.strip("/"):
                        first_segment = "/" + base_path.strip("/").split("/")[0]
                        last_segment = "/" + base_path.strip("/").split("/")[-1]
                        # check if path_part starts with a segment that exists in base_path
                        for seg in base_path.strip("/").split("/"):
                            if path_part.startswith(f"/{seg}/"):
                                path_part = path_part[len(f"/{seg}"):]
                                break
                    u = base_url_clean + ("/" if not path_part.startswith("/") else "") + path_part
                    if tu.query:
                        u += "?" + tu.query
            except Exception:
                pass

        cleaned_targets.append(u)

    # Deduplicate targets while preserving order
    targets = list(dict.fromkeys([t for t in cleaned_targets if t]))
    if not targets and base_url_clean:
        targets = [base_url_clean]

    if not targets:
        raise HTTPException(status_code=400, detail="No scan targets provided.")

    sanitized_headers = {}
    for k, v in (req.headers or {}).items():
        if isinstance(k, str) and isinstance(v, str) and k.strip() and v.strip():
            sanitized_headers[k.strip()] = v.strip()

    job = create_job(
        target_type=req.target_type,
        base_url=req.base_url,
        targets=targets,
        headers=sanitized_headers,
        tags=req.tags,
        rate_limit=req.rate_limit,
        timeout=req.timeout,
    )

    t = threading.Thread(target=run_scan_job, args=(job,), daemon=True)
    t.start()

    return {
        "success": True,
        "job_id": job.job_id,
        "status": job.status,
        "total_targets": len(targets),
    }


@app.post("/api/scan/stop/{job_id}")
def stop_scan(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    job.stop()
    return {"success": True, "job_id": job_id, "status": job.status}


@app.get("/api/scan/status/{job_id}")
def scan_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {
        "job_id": job.job_id,
        "status": job.status,
        "stats": job.stats,
        "findings_count": len(job.findings),
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


@app.get("/api/scan/results/{job_id}")
def scan_results(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {
        "job_id": job.job_id,
        "status": job.status,
        "stats": job.stats,
        "findings": job.findings,
        "logs": job.logs[-200:],
    }


import asyncio
import shutil
import subprocess
from nuclei_backend.binary_helper import find_nuclei_binary

_install_lock = threading.Lock()
_install_status: Dict[str, Any] = {"status": "idle", "logs": []}


@app.post("/api/install-nuclei")
def install_nuclei():
    global _install_status
    with _install_lock:
        if _install_status.get("status") == "installing":
            return {"success": True, "status": "installing", "message": "Installation already in progress."}
        _install_status = {"status": "installing", "logs": ["🚀 Starting Nuclei installation via Homebrew..."]}

    def _worker():
        global _install_status
        brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
        if not os.path.isfile(brew_bin):
            brew_bin = "/usr/local/bin/brew"

        if os.path.isfile(brew_bin):
            try:
                proc = subprocess.Popen(
                    [brew_bin, "install", "nuclei"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                if proc.stdout:
                    for line in proc.stdout:
                        l = line.strip()
                        if l:
                            _install_status["logs"].append(l)
                proc.wait()
                if proc.returncode == 0:
                    _install_status["status"] = "completed"
                    _install_status["logs"].append("✅ Nuclei installed successfully! Engine is ready.")
                else:
                    _install_status["status"] = "failed"
                    _install_status["logs"].append(f"❌ Brew exited with code {proc.returncode}")
            except Exception as e:
                _install_status["status"] = "failed"
                _install_status["logs"].append(f"❌ Installation error: {str(e)}")
        else:
            _install_status["status"] = "failed"
            _install_status["logs"].append("❌ Homebrew not detected. Run 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'")

    threading.Thread(target=_worker, daemon=True).start()
    return {"success": True, "status": "installing"}


@app.get("/api/install-status")
def install_status():
    return _install_status


@app.post("/api/update-templates")
def update_templates():
    bin_path = find_nuclei_binary()
    if not bin_path:
        raise HTTPException(status_code=400, detail="Nuclei binary not installed.")
    try:
        proc = subprocess.run([bin_path, "-update-templates"], capture_output=True, text=True, timeout=60)
        return {"success": proc.returncode == 0, "output": (proc.stdout or proc.stderr or "").strip()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/stream/{job_id}")
async def scan_stream(job_id: str, request: Request):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    async def event_generator():
        q = job.subscribe()
        try:
            while True:
                # Disconnect check using await on coroutine
                if await request.is_disconnected():
                    break

                if q:
                    item = q.popleft()
                    yield f"data: {json.dumps(item)}\n\n"
                else:
                    if job.status in ("completed", "stopped", "failed"):
                        yield f"data: {json.dumps({'type': 'done', 'status': job.status, 'stats': dict(job.stats)})}\n\n"
                        break
                    await asyncio.sleep(0.15)
        finally:
            job.unsubscribe(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


def _generate_report_html(req: ExportReportReq) -> str:
    stats = req.stats or {}
    findings = req.findings or []

    rows_html = []
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        sev_class = sev.lower()
        name = f.get("name") or f.get("id") or "Finding"
        matched = f.get("matched_at") or "-"
        desc = f.get("description") or "-"
        curl = (f.get("curl_command") or "").replace("'", "\\'")
        matched_escaped = matched.replace("'", "\\'")
        tags = ", ".join(f.get("tags") or [])

        curl_btn = f'<button class="btn-copy" onclick="navigator.clipboard.writeText(\'{curl}\')">📋 Copy cURL</button>' if curl else ''
        copy_url_btn = f'<button class="btn-copy" onclick="navigator.clipboard.writeText(\'{matched_escaped}\')">🔗 Copy URL</button>'

        rows_html.append(f"""
        <tr class="sev-{sev_class}" data-sev="{sev}">
            <td><span class="badge badge-{sev_class}">{sev}</span></td>
            <td><strong>{name}</strong></td>
            <td><code class="matched-code">{matched}</code></td>
            <td><span class="tag-pill">{tags}</span></td>
            <td>{desc}</td>
            <td>
                {curl_btn}
                {copy_url_btn}
            </td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{req.title} - API Sentinel</title>
<style>
  :root {{
    --bg: #0b0f19; --surface: #111827; --surface-border: #1f2937;
    --text: #f9fafb; --text-dim: #9ca3af; --accent: #6366f1;
    --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #3b82f6; --info: #6b7280;
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--surface-border); padding-bottom: 16px; margin-bottom: 24px; }}
  .title {{ font-size: 22px; font-weight: 800; display: flex; align-items: center; gap: 10px; }}
  .stats-bar {{ display: flex; gap: 14px; margin-bottom: 20px; flex-wrap: wrap; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--surface-border); border-radius: 8px; padding: 12px 18px; min-width: 110px; }}
  .stat-val {{ font-size: 22px; font-weight: 800; }}
  .stat-lbl {{ font-size: 11px; text-transform: uppercase; color: var(--text-dim); margin-top: 4px; }}
  .filters {{ display: flex; gap: 8px; margin-bottom: 16px; align-items: center; }}
  .filter-pill {{ background: var(--surface); border: 1px solid var(--surface-border); color: var(--text-dim); padding: 6px 14px; border-radius: 999px; cursor: pointer; font-size: 13px; font-weight: 600; }}
  .filter-pill.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--surface-border); }}
  th, td {{ padding: 12px 14px; text-align: left; font-size: 13px; border-bottom: 1px solid var(--surface-border); vertical-align: top; }}
  th {{ background: #131d31; font-weight: 700; color: var(--text-dim); text-transform: uppercase; font-size: 11px; }}
  .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 800; display: inline-block; }}
  .badge-critical {{ background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid #ef4444; }}
  .badge-high {{ background: rgba(249,115,22,0.2); color: #f97316; border: 1px solid #f97316; }}
  .badge-medium {{ background: rgba(234,179,8,0.2); color: #eab308; border: 1px solid #eab308; }}
  .badge-low {{ background: rgba(59,130,246,0.2); color: #3b82f6; border: 1px solid #3b82f6; }}
  .badge-info {{ background: rgba(107,114,128,0.2); color: #9ca3af; border: 1px solid #9ca3af; }}
  .matched-code {{ font-family: monospace; font-size: 12px; color: #a5b4fc; word-break: break-all; }}
  .tag-pill {{ font-size: 11px; background: #1f2937; padding: 2px 6px; border-radius: 4px; color: #9ca3af; }}
  .btn-copy {{ background: #1f2937; color: #f9fafb; border: 1px solid #374151; border-radius: 4px; padding: 4px 8px; font-size: 11px; cursor: pointer; }}
  .btn-copy:hover {{ background: #374151; }}
</style>
</head>
<body>
<div class="header">
  <div class="title">🔬 {req.title}</div>
  <div style="font-size:13px; color:var(--text-dim);">Target: <strong>{req.target_url or 'N/A'}</strong> | Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</div>
</div>

<div class="stats-bar">
  <div class="stat-card"><div class="stat-val">{stats.get('findings', len(findings))}</div><div class="stat-lbl">Total Findings</div></div>
  <div class="stat-card" style="border-color: rgba(239,68,68,0.4);"><div class="stat-val" style="color:var(--crit);">{stats.get('critical', 0)}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-card" style="border-color: rgba(249,115,22,0.4);"><div class="stat-val" style="color:var(--high);">{stats.get('high', 0)}</div><div class="stat-lbl">High</div></div>
  <div class="stat-card" style="border-color: rgba(234,179,8,0.4);"><div class="stat-val" style="color:var(--med);">{stats.get('medium', 0)}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat-card" style="border-color: rgba(59,130,246,0.4);"><div class="stat-val" style="color:var(--low);">{stats.get('low', 0)}</div><div class="stat-lbl">Low</div></div>
  <div class="stat-card"><div class="stat-val" style="color:var(--info);">{stats.get('info', 0)}</div><div class="stat-lbl">Info</div></div>
</div>

<div class="filters">
  <span style="font-size:12px; font-weight:700; color:var(--text-dim); margin-right:6px;">FILTER:</span>
  <div class="filter-pill active" onclick="filterSev('ALL')">All ({len(findings)})</div>
  <div class="filter-pill" onclick="filterSev('CRITICAL')">Critical</div>
  <div class="filter-pill" onclick="filterSev('HIGH')">High</div>
  <div class="filter-pill" onclick="filterSev('MEDIUM')">Medium</div>
  <div class="filter-pill" onclick="filterSev('LOW')">Low</div>
  <div class="filter-pill" onclick="filterSev('INFO')">Info</div>
</div>

<table>
  <thead>
    <tr>
      <th style="width:90px;">Severity</th>
      <th style="width:220px;">Vulnerability / Rule</th>
      <th>Matched Target</th>
      <th style="width:140px;">Tags</th>
      <th>Description</th>
      <th style="width:170px;">Actions</th>
    </tr>
  </thead>
  <tbody id="findings-body">
    {''.join(rows_html) if rows_html else '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:30px;">No findings reported.</td></tr>'}
  </tbody>
</table>

<script>
function filterSev(sev) {{
  document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings-body tr').forEach(row => {{
    if (sev === 'ALL' || row.getAttribute('data-sev') === sev) {{
      row.style.display = '';
    }} else {{
      row.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"""


@app.post("/api/scan/export")
def export_report(req: ExportReportReq):
    html_content = _generate_report_html(req)
    return HTMLResponse(content=html_content)


@app.post("/api/scan/save-report")
def save_report(req: ExportReportReq):
    html_content = _generate_report_html(req)
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    os.makedirs(downloads, exist_ok=True)
    ts = int(time.time())
    filename = f"nuclei_security_report_{ts}.html"
    filepath = os.path.join(downloads, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    return {
        "success": True,
        "path": filepath,
        "filename": filename,
        "html": html_content,
    }


@app.post("/api/scan/open-file")
def open_file(payload: Dict[str, str]):
    path = payload.get("path")
    if path and os.path.exists(path):
        subprocess.run(["open", "-R", path])
        return {"success": True}
    return {"success": False, "error": "File not found"}
