#!/usr/bin/env python3
"""
FastAPI Service for Nikto Web Server Scanner (Port 8799)
Provides REST endpoints to control Nikto scanning, stream live logs,
inspect discovered vulnerabilities and misconfigurations, and export reports.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

_parent_dir = os.path.dirname(_cur_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from nikto_backend.binary_helper import (
    get_nikto_info,
    update_nikto_engine,
    verify_nikto_databases,
)
from nikto_backend.nikto_engine import (
    export_html_report,
    get_current_job,
    start_nikto_scan,
    stop_nikto_scan,
)

try:
    from curl_parser import parse_curl_command
except Exception:
    parse_curl_command = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nikto_backend")

app = FastAPI(title="Nikto Scanner Backend — API Sentinel", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Models ──────────────────────────────────────────────────────────

class StartScanReq(BaseModel):
    target: str = Field(..., description="Target URL or Hostname (e.g. https://api.target.com)")
    port: Optional[int] = Field(default=None, description="Target port override (80, 443, 8080)")
    ssl: Optional[bool] = Field(default=None, description="Force SSL mode")
    tuning: Optional[str] = Field(default="123bde", description="Nikto scan tuning categories")
    pause: Optional[int] = Field(default=0, description="Pause delay in seconds between tests (anti-ban)")
    evasion: Optional[str] = Field(default=None, description="Evasion technique encoding ID")
    maxtime: Optional[str] = Field(default="30m", description="Max scan duration (e.g. 15m, 30m, 1h)")
    user_agent: Optional[str] = Field(default=None, description="Custom User-Agent string")
    verbose: Optional[bool] = Field(default=False, description="Stream all HTTP hits and verbose logs")


class ParseCurlReq(BaseModel):
    curl: str


class ExportReportReq(BaseModel):
    target: Optional[str] = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
    banner: Optional[str] = "Unknown"


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/")
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "nikto_scanner",
        "port": 8799,
        "nikto_info": get_nikto_info(),
    }


@app.get("/api/info")
def get_info():
    return get_nikto_info()


@app.post("/api/engine/refresh")
def refresh_info():
    return get_nikto_info(force_refresh=True)


@app.post("/api/engine/update")
def update_engine():
    res = update_nikto_engine()
    return res


@app.post("/api/engine/verify")
def verify_engine():
    res = verify_nikto_databases()
    return res


@app.post("/api/scan/start")
def start_scan(req: StartScanReq):
    res = start_nikto_scan(
        target_url=req.target,
        port=req.port,
        ssl_mode=req.ssl,
        tuning=req.tuning,
        pause_sec=req.pause or 0,
        evasion=req.evasion,
        maxtime=req.maxtime or "30m",
        user_agent=req.user_agent,
        verbose=req.verbose or False,
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to start Nikto scan"))
    return res


@app.post("/api/scan/stop")
def stop_scan():
    return stop_nikto_scan()


@app.get("/api/scan/status")
def get_status():
    job = get_current_job()
    return job.get_status_dict()


@app.get("/api/scan/logs")
def get_logs(offset: int = 0):
    job = get_current_job()
    return job.get_logs_slice(offset)


@app.get("/api/scan/results")
def get_results():
    job = get_current_job()
    return job.get_results_dict()


@app.post("/api/scan/export")
def export_report(req: ExportReportReq):
    job = get_current_job()
    target = req.target or job.target or "Target"
    findings = req.findings or job.findings
    stats = req.stats or job.get_stats()
    banner = req.banner or job.server_banner

    report_html = export_html_report(target=target, findings=findings, stats=stats, banner=banner)
    return HTMLResponse(content=report_html)


@app.post("/api/scan/save-report")
def save_report(req: ExportReportReq):
    job = get_current_job()
    target = req.target or job.target or "Target"
    findings = req.findings or job.findings
    stats = req.stats or job.get_stats()
    banner = req.banner or job.server_banner

    report_html = export_html_report(target=target, findings=findings, stats=stats, banner=banner)

    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    os.makedirs(downloads, exist_ok=True)

    try:
        p = urlparse(target if "://" in target else f"http://{target}")
        clean_host = p.netloc or p.path or target
        clean_host = "".join(c if c.isalnum() or c in ".-" else "_" for c in clean_host).strip("._")
    except Exception:
        clean_host = "".join(c if c.isalnum() else "_" for c in target).strip("_")
    if not clean_host:
        clean_host = "target"

    ts = int(time.time())
    filename = f"nikto_security_report_{clean_host}_{ts}.html"
    filepath = os.path.join(downloads, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_html)

    return {
        "success": True,
        "path": filepath,
        "filename": filename,
        "html": report_html,
    }


@app.post("/api/scan/open-file")
def open_file(payload: Dict[str, str]):
    path = payload.get("path")
    if path and os.path.exists(path):
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", path])
        elif sys.platform == "win32":
            subprocess.run(["explorer", f"/select,{path}"])
        else:
            subprocess.run(["xdg-open", os.path.dirname(path)])
        return {"success": True}
    return {"success": False, "error": "File not found"}


@app.post("/api/parse-curl")
def parse_curl(req: ParseCurlReq):
    if not parse_curl_command:
        # Fallback simple URL regex
        import re
        m = re.search(r"curl\s+.*?['\"](https?://[^'\"]+)['\"]", req.curl)
        if m:
            url = m.group(1)
            parsed = urlparse(url)
            return {
                "success": True,
                "url": url,
                "hostname": parsed.hostname,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "ssl": parsed.scheme == "https",
                "headers": {},
            }
        return {"success": False, "error": "Could not extract URL from cURL"}

    try:
        parsed = parse_curl_command(req.curl)
        url = parsed.get("url", "")
        p_url = urlparse(url)
        return {
            "success": True,
            "url": url,
            "hostname": p_url.hostname or url,
            "port": p_url.port or (443 if p_url.scheme == "https" else 80),
            "ssl": p_url.scheme == "https",
            "headers": parsed.get("headers", {}),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8799)
