#!/usr/bin/env python3
"""
APISphere Backend — FastAPI (port 8791)
Simple single-hit HTTP client backend (Postman-like).
"""

import time, json, re, base64
from typing import Optional, Dict, Any
from urllib.parse import unquote, urlparse

import requests as _req
from requests.utils import requote_uri
import urllib3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Headers that must never be forwarded (HTTP/2 pseudo-headers + hop-by-hop)
_SKIP_HEADERS = {
    ":authority", ":method", ":path", ":scheme",
    "content-length", "transfer-encoding", "connection",
    "keep-alive", "upgrade", "proxy-authorization",
}

def _clean_headers(h: dict) -> dict:
    return {k: str(v) for k, v in (h or {}).items()
            if k.lower() not in _SKIP_HEADERS and str(k).strip()}


def _sanitize_hdr_value(v: str) -> str:
    """HTTP header values must be latin-1 (requests/http.client)."""
    try:
        v.encode("latin-1")
        return v
    except (UnicodeEncodeError, UnicodeDecodeError):
        return v.encode("latin-1", errors="ignore").decode("latin-1")


def _ellipsis_location(url: str, headers: dict, params: dict):
    """UI truncation often pastes U+2026 (…) instead of the full value."""
    ell = "\u2026"
    if ell in (url or ""):
        return "URL"
    for k, v in (headers or {}).items():
        if ell in str(k) or ell in str(v):
            return f"header '{k}'"
    for k, v in (params or {}).items():
        if ell in str(k) or ell in str(v):
            return f"query param '{k}'"
    return None


_EXT_BY_CT = {
    "application/json": ".json",
    "application/javascript": ".js",
    "text/javascript": ".js",
    "text/html": ".html",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/xml": ".xml",
    "application/xml": ".xml",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/gzip": ".gz",
    "application/octet-stream": ".bin",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
}


def _header_ci(headers: dict, name: str) -> str:
    want = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == want:
            return str(v or "")
    return ""


def _filename_from_cd(cd: str) -> str:
    if not cd:
        return ""
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd, re.I)
    if m:
        return unquote(m.group(1).strip().strip('"').strip("'"))
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"filename\s*=\s*'([^']+)'", cd, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"filename\s*=\s*([^;]+)", cd, re.I)
    if m:
        return m.group(1).strip().strip('"').strip("'")
    return ""


def _ext_from_magic(raw: bytes) -> str:
    """Guess extension from magic bytes when Content-Type is generic."""
    if not raw:
        return ""
    if raw[:2] == b"PK":
        head = raw[:12000]
        if b"xl/" in head or b"workbook.xml" in head:
            return ".xlsx"
        if b"word/" in head:
            return ".docx"
        if b"ppt/" in head:
            return ".pptx"
        return ".zip"
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if raw[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if raw[:4] == b"%PDF":
        return ".pdf"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    return ""


def _suggest_filename(headers: dict, url: str, ct: str, is_binary: bool, raw: bytes = b"") -> str:
    name = _filename_from_cd(_header_ci(headers, "Content-Disposition"))
    if name:
        # strip path junk from disposition
        name = name.replace("\\", "/").split("/")[-1].strip()
        if name:
            return name
    path = urlparse(url or "").path or ""
    base = path.rstrip("/").split("/")[-1] if path else ""
    if base and "." in base and not base.endswith("."):
        return unquote(base)
    mime = (ct or "").split(";")[0].strip().lower()
    ext = _EXT_BY_CT.get(mime)
    if mime.startswith("image/") and not ext:
        ext = "." + (mime.split("/", 1)[-1] or "bin")
    # Prefer magic when CT is missing/generic (.bin / octet-stream)
    if not ext or ext == ".bin":
        magic = _ext_from_magic(raw or b"")
        if magic:
            ext = magic
    if not ext:
        if is_binary:
            ext = ".bin"
        elif "json" in mime:
            ext = ".json"
        elif "html" in mime:
            ext = ".html"
        else:
            ext = ".txt"
    return "response" + ext


class SendRequest(BaseModel):
    method:    str = "GET"
    url:       str
    headers:   Optional[Dict[str, str]] = {}
    params:    Optional[Dict[str, str]] = {}   # query params
    body:      Optional[Any]            = None
    # none | form | multipart | raw | binary | graphql | legacy json/text
    body_type: Optional[str]            = None
    raw_lang:  Optional[str]            = None  # json | text | javascript | html | xml
    auth:      Optional[Dict[str, str]] = {}   # {type, token} or {type, user, pass}


@app.get("/")
def root():
    return {"status": "ok", "service": "APISphere", "port": 8791}


class OpenApiParseBody(BaseModel):
    content: str
    filename: Optional[str] = ""


@app.post("/parse-openapi")
def parse_openapi(body: OpenApiParseBody):
    """Parse OpenAPI/Swagger JSON or YAML for collection import (UI)."""
    text = (body.content or "").strip()
    if not text:
        return {"ok": False, "error": "Empty content"}
    data = None
    try:
        data = json.loads(text)
    except Exception:
        try:
            import yaml  # often available via mitmproxy / system
            data = yaml.safe_load(text)
        except ImportError:
            return {
                "ok": False,
                "error": "YAML support unavailable on this build — convert the spec to JSON and retry.",
            }
        except Exception as e:
            return {"ok": False, "error": f"YAML parse failed: {e}"}
    if not isinstance(data, dict) or "paths" not in data:
        return {"ok": False, "error": "Not a valid OpenAPI/Swagger document (missing paths)."}
    return {"ok": True, "spec": data}


@app.post("/send")
def send_request(req: SendRequest):
    method  = (req.method or "GET").upper()
    url     = (req.url or "").strip()
    if not url:
        return {"error": "URL is required"}, 400

    headers = _clean_headers(req.headers or {})
    params = req.params or {}
    where = _ellipsis_location(url, headers, params)
    if where:
        return {
            "ok": False,
            "error": (
                f"{where} contains '…' (ellipsis). That is truncated UI text, not a real value. "
                "Paste the full URL / header — copying a shortened line (often at ~60 chars) causes this."
            ),
        }
    headers = {k: _sanitize_hdr_value(v) for k, v in headers.items()}
    try:
        url = requote_uri(url)
    except Exception:
        pass

    # Auth injection
    auth_cfg = req.auth or {}
    auth_type = auth_cfg.get("type", "none").lower()
    if auth_type == "bearer":
        token = auth_cfg.get("token", "").strip()
        if token:
            for k in list(headers.keys()):
                if k.lower() == "authorization":
                    del headers[k]
            headers["Authorization"] = f"Bearer {token}"
    elif auth_type == "basic":
        user = auth_cfg.get("username", "")
        pwd  = auth_cfg.get("password", "")
        encoded = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        for k in list(headers.keys()):
            if k.lower() == "authorization":
                del headers[k]
        headers["Authorization"] = f"Basic {encoded}"

    # Build request kwargs
    kwargs: Dict[str, Any] = {
        "headers": headers,
        "params":  params,
        "verify":  False,
        "timeout": 30,
        "allow_redirects": True,
    }

    body_type = (req.body_type or "none").lower()
    raw_lang  = (req.raw_lang or "text").lower()

    def _apply_json_body(payload):
        if isinstance(payload, str):
            try:
                kwargs["json"] = json.loads(payload)
            except Exception:
                kwargs["data"] = payload.encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
        else:
            kwargs["json"] = payload
        if "json" in kwargs and "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = "application/json"

    # Legacy aliases
    if body_type == "json":
        body_type, raw_lang = "raw", "json"
    elif body_type == "text":
        body_type, raw_lang = "raw", "text"

    if body_type == "raw" and req.body is not None:
        if raw_lang == "json":
            _apply_json_body(req.body)
        else:
            kwargs["data"] = str(req.body)
            ct_map = {
                "text": "text/plain",
                "javascript": "application/javascript",
                "html": "text/html",
                "xml": "application/xml",
            }
            headers.setdefault("Content-Type", ct_map.get(raw_lang, "text/plain"))
            kwargs["headers"] = headers
    elif body_type == "form" and req.body is not None:
        # x-www-form-urlencoded
        if isinstance(req.body, dict):
            kwargs["data"] = req.body
        else:
            kwargs["data"] = str(req.body)
    elif body_type == "multipart" and req.body is not None:
        # form-data — list-of-tuples so multiple files can share the same field name
        files, data = [], {}
        for field in (req.body if isinstance(req.body, list) else []):
            key = field.get("key", "")
            if field.get("type") == "file":
                raw_b64 = field.get("data", "")
                file_bytes = base64.b64decode(raw_b64) if raw_b64 else b""
                ct = field.get("contentType", "application/octet-stream")
                files.append((key, (field.get("filename", key), file_bytes, ct)))
            else:
                data[key] = field.get("value", "")
        kwargs["files"] = files
        if data:
            kwargs["data"] = data
        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        kwargs["headers"] = headers
    elif body_type == "binary" and req.body is not None:
        meta = req.body if isinstance(req.body, dict) else {}
        raw_b64 = meta.get("data", "")
        file_bytes = base64.b64decode(raw_b64) if raw_b64 else b""
        kwargs["data"] = file_bytes
        ct = meta.get("contentType") or "application/octet-stream"
        headers.setdefault("Content-Type", ct)
        kwargs["headers"] = headers
    elif body_type == "graphql" and req.body is not None:
        gql = req.body if isinstance(req.body, dict) else {"query": str(req.body)}
        payload = {"query": gql.get("query") or ""}
        if gql.get("variables") is not None:
            payload["variables"] = gql.get("variables")
        kwargs["json"] = payload
        headers.setdefault("Content-Type", "application/json")
        kwargs["headers"] = headers
    # none → no body kwarg

    t0 = time.time()
    try:
        resp = _req.request(method, url, **kwargs)
        wall_ms = round((time.time() - t0) * 1000)
        # requests' transfer timer (excludes local queueing)
        try:
            transfer_ms = int(round(resp.elapsed.total_seconds() * 1000))
        except Exception:
            transfer_ms = wall_ms
        elapsed_ms = wall_ms

        raw_bytes = resp.content or b""
        size_bytes = len(raw_bytes)

        # Detect content type for hint + binary download path
        ct = (resp.headers.get("Content-Type") or "").lower()
        mime = ct.split(";")[0].strip()
        is_binary = False
        if mime.startswith(("image/", "audio/", "video/", "font/")):
            is_binary = True
        elif any(x in mime for x in (
            "octet-stream", "zip", "gzip", "pdf", "msword", "ms-excel",
            "officedocument", "protobuf", "msgpack", "wasm",
        )):
            is_binary = True
        else:
            try:
                raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                is_binary = True

        if "application/json" in ct or mime.endswith("+json"):
            body_hint = "json"
        elif "text/html" in ct:
            body_hint = "html"
        elif is_binary:
            body_hint = "binary"
        else:
            body_hint = "text"

        # Text view (may be lossy for binary); body_b64 is exact for Download
        resp_body = raw_bytes.decode("utf-8", errors="replace")
        body_b64 = base64.b64encode(raw_bytes).decode("ascii")
        filename = _suggest_filename(
            dict(resp.headers), str(resp.request.url), ct, is_binary, raw_bytes
        )

        # Cookies from jar (Set-Cookie)
        cookies_out = []
        try:
            for c in resp.cookies:
                cookies_out.append({
                    "name": c.name,
                    "value": c.value,
                    "domain": getattr(c, "domain", "") or "",
                    "path": getattr(c, "path", "") or "/",
                })
        except Exception:
            cookies_out = []

        # Reconstruct sent cURL
        curl_parts = [f"curl -X {method} '{resp.request.url}'"]
        for k, v in (resp.request.headers or {}).items():
            if k.lower() in _SKIP_HEADERS: continue
            curl_parts.append(f"  -H '{k}: {v}'")
        if resp.request.body:
            body_str = resp.request.body
            if isinstance(body_str, bytes):
                body_str = body_str.decode("utf-8", errors="replace")
            body_safe = body_str.replace("'", "'\\''")
            curl_parts.append(f"  --data-raw '{body_safe}'")
        sent_curl = " \\\n".join(curl_parts)

        return {
            "ok":          True,
            "status_code": resp.status_code,
            "status_text": resp.reason or "",
            "elapsed_ms":  elapsed_ms,
            "timing": {
                "total_ms":    elapsed_ms,
                "transfer_ms": transfer_ms,
            },
            "size_bytes":  size_bytes,
            "body":        resp_body,
            "body_b64":    body_b64,
            "body_hint":   body_hint,
            "is_binary":   is_binary,
            "filename":    filename,
            "headers":     dict(resp.headers),
            "cookies":     cookies_out,
            "sent_url":    str(resp.request.url),
            "sent_curl":   sent_curl,
        }

    except _req.exceptions.ConnectionError as e:
        return {"ok": False, "error": "Connection refused — host unreachable.", "detail": str(e)[:200]}
    except _req.exceptions.Timeout:
        return {"ok": False, "error": "Request timed out (30s)."}
    except UnicodeEncodeError as e:
        return {
            "ok": False,
            "error": (
                "HTTP cannot encode a character in this request (latin-1). "
                "If the text has '…', a truncated URL or header was pasted — use the full value. "
                f"({e})"
            )[:400],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}
