"""
Settings Backend — Port 8795
Handles global proxy configuration for all API Sentinel tools.
"""

import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

try:
    import proxy_config
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    import proxy_config

app = FastAPI(title="Settings Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ────────────────────────────────────────────────────────────────────

class ProxyConfig(BaseModel):
    enabled: bool = False
    protocol: str = "http"
    host: str = ""
    port: str = ""
    use_for_http: bool = True
    use_for_https: bool = True
    auth_enabled: bool = False
    username: str = ""
    password: str = ""
    bypass: str = ""


class ProxyTestRequest(BaseModel):
    test_url: Optional[str] = "https://httpbin.org/ip"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "settings", "status": "ok"}


@app.get("/settings/proxy")
def get_proxy():
    """Return current proxy configuration."""
    cfg = proxy_config.get_config()
    # Never send password in clear over even localhost GET — mask it
    if cfg.get("password"):
        cfg["password_set"] = True
        cfg["password"] = "••••••••"
    else:
        cfg["password_set"] = False
    return cfg


@app.post("/settings/proxy")
def set_proxy(body: ProxyConfig):
    """Update proxy configuration and apply to env vars."""
    cfg = body.model_dump()

    # If password is the masked placeholder, keep the existing password
    existing = proxy_config.get_config()
    if cfg.get("password") == "••••••••" and existing.get("password"):
        cfg["password"] = existing["password"]

    proxy_config.set_config(cfg)
    proxy_config.apply_env()

    return {
        "ok": True,
        "message": "Proxy settings applied" if cfg["enabled"] else "Proxy disabled",
        "proxies": proxy_config.get_proxies(),
    }


@app.post("/settings/proxy/test")
def test_proxy(body: ProxyTestRequest):
    """
    Test connectivity through the configured proxy.
    Fires a single GET to the test URL and reports success/failure.
    """
    proxies = proxy_config.get_proxies()
    if not proxies:
        return {
            "ok": False,
            "message": "Proxy is not enabled or not configured. Enable and save first.",
        }

    test_url = (body.test_url or "https://httpbin.org/ip").strip()
    if not test_url:
        test_url = "https://httpbin.org/ip"

    try:
        import requests as _req
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        t0 = time.time()
        resp = _req.get(
            test_url,
            proxies=proxies,
            timeout=10,
            verify=False,
        )
        elapsed_ms = int((time.time() - t0) * 1000)
        return {
            "ok": True,
            "status": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "message": f"✅ Connected via proxy — {resp.status_code} in {elapsed_ms}ms",
            "proxy_url": list(proxies.values())[0] if proxies else "",
        }
    except Exception as e:
        return {
            "ok": False,
            "message": f"❌ Proxy connection failed: {e}",
        }
