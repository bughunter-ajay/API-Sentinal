"""
proxy_config.py — Shared Global Proxy Configuration
All 15 backends run in the same process (threads from app.py).
This module stores the proxy state and exposes helpers for
requests (env-var based) and httpx (explicit dict).

Thread-safe: guarded by a threading.Lock.
"""

import os
import threading

_lock = threading.Lock()

_config = {
    "enabled": False,
    "protocol": "http",        # http | https | socks4 | socks5 | socks5h
    "host": "",
    "port": "",
    "use_for_http": True,
    "use_for_https": True,
    "auth_enabled": False,
    "username": "",
    "password": "",
    "bypass": "",              # comma-separated hosts (e.g. "127.0.0.1, localhost, *.internal.com")
}

# ── Public API ────────────────────────────────────────────────────────────────

def get_config() -> dict:
    """Return a shallow copy of the current proxy config."""
    with _lock:
        return dict(_config)


def set_config(cfg: dict):
    """Merge caller-supplied keys into the stored config."""
    with _lock:
        for k in _config:
            if k in cfg:
                _config[k] = cfg[k]


def _build_proxy_url() -> str:
    """Build a proxy URL string from current config (caller must hold _lock)."""
    proto = _config["protocol"] or "http"
    host  = (_config["host"] or "").strip()
    port  = (_config["port"] or "").strip()
    if not host:
        return ""
    auth = ""
    if _config["auth_enabled"] and _config.get("username"):
        user = _config["username"]
        pwd  = _config.get("password", "")
        auth = f"{user}:{pwd}@"
    if port:
        return f"{proto}://{auth}{host}:{port}"
    return f"{proto}://{auth}{host}"


def get_proxies() -> dict | None:
    """
    Return a requests-compatible proxies dict, or None if proxy is disabled.
    Example: {"http": "socks5h://user:pass@host:1080",
              "https": "socks5h://user:pass@host:1080"}
    """
    with _lock:
        if not _config["enabled"] or not _config["host"]:
            return None
        url = _build_proxy_url()
        if not url:
            return None
        proxies = {}
        if _config["use_for_http"]:
            proxies["http"] = url
        if _config["use_for_https"]:
            proxies["https"] = url
        return proxies if proxies else None


def apply_env():
    """
    Write proxy settings into os.environ so that `requests` and `httpx`
    pick them up automatically (trust_env=True, the default).

    NO_PROXY always includes 127.0.0.1 and localhost to protect
    internal backend-to-backend calls (ports 8765–8795).
    """
    with _lock:
        if not _config["enabled"] or not _config["host"]:
            # Proxy disabled → clear env vars
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                os.environ.pop(var, None)
            # Keep NO_PROXY pointing at localhost (belt-and-suspenders)
            os.environ["NO_PROXY"]  = "127.0.0.1,localhost"
            os.environ["no_proxy"]  = "127.0.0.1,localhost"
            return

        url = _build_proxy_url()
        if not url:
            return

        # Set env vars for requests/httpx
        if _config["use_for_http"]:
            os.environ["HTTP_PROXY"]  = url
            os.environ["http_proxy"]  = url
        else:
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("http_proxy", None)

        if _config["use_for_https"]:
            os.environ["HTTPS_PROXY"] = url
            os.environ["https_proxy"] = url
        else:
            os.environ.pop("HTTPS_PROXY", None)
            os.environ.pop("https_proxy", None)

        # NO_PROXY — always protect localhost; append user bypass list
        base = "127.0.0.1,localhost"
        user_bypass = (_config.get("bypass") or "").strip()
        if user_bypass:
            base = f"{base},{user_bypass}"
        os.environ["NO_PROXY"]  = base
        os.environ["no_proxy"]  = base
