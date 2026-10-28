"""
Intruder Backend — Port 8794
Burp-style attacks: Sniper, Battering ram, Pitchfork, Cluster bomb.
Mark §positions§, supply payload set(s), fire with optional threads/delay.
"""

from __future__ import annotations

import json
import re
import string
import threading
import time
import uuid
import random
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import ssl
import requests
from requests.adapters import HTTPAdapter
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Drop urllib3 InsecureRequestWarning noise for lab TLS
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

app = FastAPI(title="Intruder Backend")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

jobs: Dict[str, dict] = {}
_jobs_lock = threading.Lock()
JOB_TTL = 3600
MAX_JOBS = 40
MAX_PAYLOADS = 5000
MAX_THREADS = 20
MAX_REQUESTS = 25000
MAX_PROXY_URLS = 80
_PROXY_SCHEMES = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}

_FIRST = ["Alice", "Bob", "Carol", "Dave", "Eva", "Frank", "Grace", "Hank", "Iris", "Jack"]
_LAST = ["Smith", "Jones", "Brown", "Davis", "Wilson", "Moore", "Taylor", "Anderson"]


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


# ── Upstream proxy (HTTP / SOCKS). SOCKS uses remote DNS (socks5h / socks4a). ─

def normalize_proxy_url(raw: str) -> str:
    """Return a requests-ready proxy URL, or '' if blank. Raises ValueError if invalid."""
    s = (raw or "").strip()
    if not s or s.startswith("#"):
        return ""
    # FoxyProxy-style paste: "HTTP: http://127.0.0.1:8800"
    s = re.sub(
        r"^(https?|socks5h?|socks4a?|socks)\s*:\s+(?=(https?|socks5h?|socks4a?)://)",
        "",
        s,
        count=1,
        flags=re.I,
    ).strip()
    if "://" not in s:
        s = "http://" + s
    p = urlsplit(s)
    scheme = (p.scheme or "").lower()
    if scheme not in _PROXY_SCHEMES:
        raise ValueError(
            "Unsupported proxy scheme. Use http://host:port (not 'HTTP: http://…')"
        )
    if not p.hostname:
        shown = (raw or "").strip()[:80]
        raise ValueError(
            f"Proxy URL needs a host. Got '{shown}'. Example: http://127.0.0.1:8800"
        )
    if len(s) > 2048:
        raise ValueError("Proxy URL is too long")
    # Remote DNS: hostname is resolved by the proxy, not this machine
    if scheme == "socks5":
        scheme = "socks5h"
    elif scheme == "socks4":
        scheme = "socks4a"
    return urlunsplit((scheme, p.netloc, p.path or "", p.query, p.fragment))


def redact_proxy_url(raw: str) -> str:
    """Hide proxy password in stored/displayed URLs. Empty if no proxy."""
    s = (raw or "").strip()
    if not s:
        return ""
    p = urlsplit(s)
    host = p.hostname
    if not host:
        return s
    port = f":{p.port}" if p.port else ""
    user = p.username or ""
    if p.password is not None:
        auth = f"{user}:****@" if user else ":****@"
    elif user:
        auth = f"{user}@"
    else:
        auth = ""
    return urlunsplit((p.scheme, f"{auth}{host}{port}", p.path or "", p.query, p.fragment))


def collect_proxy_urls(proxy: str, proxy_list: Optional[List] = None) -> List[str]:
    items: List[str] = []
    if (proxy or "").strip():
        items.append(str(proxy).strip())
    for entry in proxy_list or []:
        for line in str(entry or "").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
    out: List[str] = []
    seen = set()
    for raw in items:
        n = normalize_proxy_url(raw)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
        if len(out) > MAX_PROXY_URLS:
            raise ValueError(f"Max {MAX_PROXY_URLS} proxies in the list")
    return out


class ProxyRotator:
    """Thread-safe. rotate=False always uses the first URL; True round-robins."""

    def __init__(self, urls: List[str], rotate: bool):
        self.urls = list(urls or [])
        self.rotate = bool(rotate) and len(self.urls) > 1
        self._i = 0
        self._lock = threading.Lock()

    def next(self) -> Tuple[Optional[str], Optional[dict]]:
        """Return (raw_url, requests proxies dict), or (None, None) if unused."""
        if not self.urls:
            return None, None
        with self._lock:
            if self.rotate:
                u = self.urls[self._i % len(self.urls)]
                self._i += 1
            else:
                u = self.urls[0]
        return u, {"http": u, "https": u}

    def next_dict(self) -> Optional[dict]:
        _, d = self.next()
        return d


# ── Random value generator (same tokens as API Validator Pro) ─────────────────

def generate_random_value(fmt: str) -> str:
    import uuid as _uuid

    def _replace(m):
        token = m.group(1).lower().strip()
        if token == "uuid":
            return str(_uuid.uuid4())
        if token == "email":
            user = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            return f"{user}@testapi.com"
        if token == "name":
            return f"{random.choice(_FIRST)} {random.choice(_LAST)}"
        parts = token.split(":")
        kind = parts[0]
        n = int(parts[1]) if len(parts) > 1 else 8
        if kind == "alpha":
            return "".join(random.choices(string.ascii_letters, k=n))
        if kind == "alphanum":
            return "".join(random.choices(string.ascii_letters + string.digits, k=n))
        if kind == "num":
            return "".join(random.choices(string.digits, k=n))
        return m.group(0)

    return re.sub(r"\{([^}]+)\}", _replace, fmt)


def expand_payload_line(line: str) -> str:
    """Expand {uuid}/{email}/… tokens in a payload line."""
    if "{" in line and "}" in line:
        return generate_random_value(line)
    return line


def url_encode_selected(s: str, chars: str) -> str:
    charset = set(chars or "")
    out = []
    for ch in s:
        if ch in charset:
            out.append(quote(ch, safe=""))
        else:
            out.append(ch)
    return "".join(out)


def apply_payload_pipeline(raw: str, processors: List[dict], url_encode: bool, chars: str):
    """Return processed payload, or None to skip sending."""
    s = expand_payload_line("" if raw is None else str(raw))
    for p in processors or []:
        t = str((p or {}).get("type") or "").lower()
        a = str((p or {}).get("a") or "")
        b = str((p or {}).get("b") or "")
        if t == "skip":
            if not a:
                continue
            try:
                if re.search(a, s):
                    return None
            except re.error:
                continue
        elif t == "match":
            s = s.replace(a, b)
        elif t == "regex_replace":
            try:
                s = re.sub(a, b, s)
            except re.error:
                pass
        elif t == "prefix":
            s = a + s
        elif t == "suffix":
            s = s + a
        elif t == "hash":
            data = s.encode("utf-8", errors="replace")
            if a == "sha1":
                s = hashlib.sha1(data).hexdigest()
            elif a == "sha256":
                s = hashlib.sha256(data).hexdigest()
            elif a == "sha512":
                s = hashlib.sha512(data).hexdigest()
            else:
                s = hashlib.md5(data).hexdigest()
        elif t == "base64":
            s = base64.b64encode(s.encode("utf-8", errors="replace")).decode("ascii")
        elif t == "urlencode_all":
            s = quote(s, safe="")
        elif t == "urldecode":
            s = unquote(s)
        elif t == "upper":
            s = s.upper()
        elif t == "lower":
            s = s.lower()
        elif t == "hex":
            s = s.encode("utf-8", errors="replace").hex()
    if url_encode:
        s = url_encode_selected(s, chars or "")
    return s


# ── cURL parse (lightweight) ──────────────────────────────────────────────────

def parse_curl(curl_cmd: str) -> dict:
    """Parse cURL → {method, url, headers, body} using shared AV-grade parser."""
    raw = (curl_cmd or "").strip()
    if not raw:
        raise ValueError("Empty cURL")
    try:
        from curl_parser import parse_curl_command
        d = parse_curl_command(raw)
    except ImportError:
        import importlib.util, os
        _here = os.path.dirname(os.path.abspath(__file__))
        for _p in (
            os.path.join(_here, "curl_parser.py"),
            os.path.join(os.path.dirname(_here), "curl_parser.py"),
        ):
            if os.path.isfile(_p):
                _spec = importlib.util.spec_from_file_location("_intr_curl_parser", _p)
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                d = _mod.parse_curl_command(raw)
                break
        else:
            raise ValueError("curl_parser module not found")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Could not parse cURL: {e}") from e

    body = d.get("body_raw")
    if body is None and d.get("body") is not None:
        b = d["body"]
        if isinstance(b, (dict, list)):
            body = json.dumps(b, ensure_ascii=False) if d.get("body_type") == "json" else (
                "&".join(f"{k}={'' if v is None else v}" for k, v in b.items()) if isinstance(b, dict) else json.dumps(b)
            )
        else:
            body = str(b)
    return {
        "method": d.get("method") or "GET",
        "url": d.get("url") or "",
        "headers": dict(d.get("headers") or {}),
        "body": body or "",
    }


# ── § position helpers ────────────────────────────────────────────────────────

_POS_RE = re.compile(r"§(.*?)§", re.DOTALL)


def extract_positions(template: str) -> List[str]:
    return _POS_RE.findall(template or "")


def _norm_unique_formats(raw, n: int) -> List[str]:
    out = [""] * max(0, n)
    seq = list(raw or [])
    for i in range(min(n, len(seq))):
        out[i] = str(seq[i] or "").strip()
    return out


def _attack_indices(n: int, unique_formats: List[str]) -> List[int]:
    return [i for i in range(n) if not (i < len(unique_formats) and unique_formats[i])]


def build_request_from_parts(method: str, url: str, headers: dict, body: str, replacements: List[str], base_values: List[str]) -> dict:
    """
    Apply Sniper replacements into a synthetic template built from URL+body+selected header values.
    Simpler approach: template string contains the full request material with §markers§.
    """
    raise NotImplementedError


def apply_sniper(template: str, position_index: int, payload: str) -> str:
    """
    Replace the Nth §…§ with payload; other markers restore their original inner text.
    """
    matches = list(_POS_RE.finditer(template or ""))
    if position_index < 0 or position_index >= len(matches):
        return template
    values = [m.group(1) for m in matches]
    values[position_index] = payload
    return apply_all_positions(template, values)


def apply_all_positions(template: str, values: List[str]) -> str:
    """Replace every §…§ marker in order with the corresponding value."""
    matches = list(_POS_RE.finditer(template or ""))
    out = []
    last = 0
    for i, m in enumerate(matches):
        out.append(template[last:m.start()])
        if i < len(values):
            out.append("" if values[i] is None else str(values[i]))
        else:
            out.append(m.group(1))
        last = m.end()
    out.append(template[last:])
    return "".join(out)


def apply_positions_for_display(template: str, values: List[str], wrap_indices) -> str:
    """
    Like apply_all_positions, but wrap selected inserted payloads in §…§
    so the Scanning UI can highlight them (delimiters stripped on render).
    """
    wrap = set(wrap_indices or [])
    matches = list(_POS_RE.finditer(template or ""))
    out = []
    last = 0
    for i, m in enumerate(matches):
        out.append(template[last:m.start()])
        if i < len(values):
            val = "" if values[i] is None else str(values[i])
        else:
            val = m.group(1)
        if i in wrap:
            # Avoid breaking the highlighter if payload itself contains §
            safe = val.replace("§", " ")
            out.append(f"§{safe}§")
        else:
            out.append(val)
        last = m.end()
    out.append(template[last:])
    return "".join(out)


def http_text_from_parts(method: str, url: str, headers: dict, body: str) -> str:
    lines = [f"{method or 'GET'} {url or ''}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def split_template_request(raw_template: str, method: str, headers: dict) -> tuple:
    """
    Template format (UI):
      First line: METHOD URL
      Then headers as Key: Value lines (optional)
      Blank line
      Body

    Markers § § may appear in URL, headers, or body.
    Returns method, url, headers, body after template is already expanded (no markers).
    """
    text = raw_template or ""
    lines = text.split("\n")
    if not lines:
        return method, "", headers or {}, ""
    first = lines[0].strip()
    m = re.match(r"^([A-Z]+)\s+(.+)$", first)
    if m:
        method = m.group(1).upper()
        url = m.group(2).strip()
        rest = lines[1:]
    else:
        url = first
        rest = lines[1:]

    hdrs = dict(headers or {})
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


def _looks_like_curl(text: str) -> bool:
    head = (text or "").lstrip()[:8].lower()
    return head.startswith("curl")


def materialize_request(rendered: str, fallback_method: str, fallback_headers: dict) -> tuple:
    """
    Turn an expanded template into method/url/headers/body.
    Supports raw cURL (preferred UI) or Burp-style HTTP request text.
    """
    text = rendered or ""
    if _looks_like_curl(text):
        try:
            parsed = parse_curl(text)
            return (
                parsed.get("method") or fallback_method or "GET",
                parsed.get("url") or "",
                parsed.get("headers") or {},
                parsed.get("body") or "",
            )
        except ValueError as e:
            raise ValueError(f"Expanded cURL invalid: {e}") from e
    return split_template_request(text, fallback_method or "GET", fallback_headers or {})


# ── Attack runner ─────────────────────────────────────────────────────────────

def _proxy_intercept_page(text: str, content_type: str) -> str:
    """Interceptor UI HTML (Burp/mitm/Charles/Fiddler/ZAP) — never flag JSON/API bodies."""
    ct = (content_type or "").lower()
    raw = text or ""
    stripped = raw.lstrip()
    if "json" in ct or stripped.startswith("{") or stripped.startswith("["):
        return ""
    blob = f"{ct}\n{raw}"[:8000].lower()
    looks_html = (
        "html" in ct
        or "<html" in blob
        or "<head" in blob
        or "<title" in blob
        or "<body" in blob
    )
    if not looks_html:
        return ""
    if "burp suite" in blob or "portswigger" in blob:
        return "burp"
    if "mitmproxy" in blob:
        return "mitmproxy"
    if "charles proxy" in blob:
        return "charles"
    if "fiddler" in blob:
        return "fiddler"
    if "owasp zap" in blob or "zaproxy" in blob:
        return "zap"
    return ""


class _HTTP11Adapter(HTTPAdapter):
    """TLS to an intercepting proxy: ALPN http/1.1 only.

    If the client offers h2 and the listener has HTTP/2 off (or mismatches),
    Burp/ZAP often answer with their HTML UI (200 "Burp Suite") instead of
    forwarding CONNECT to the target.
    """

    def _ssl_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except (NotImplementedError, ValueError):
            pass
        return ctx

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_context()
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._ssl_context()
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _create_session() -> requests.Session:
    sess = requests.Session()
    sess.trust_env = False
    sess.verify = False
    adapter = _HTTP11Adapter(pool_connections=25, pool_maxsize=25)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess


def _fire(method: str, url: str, headers: dict, body: str, timeout: float,
          proxies=None, session: Optional[requests.Session] = None) -> dict:
    t0 = time.time()
    own_sess = False
    sess = session
    if sess is None:
        sess = _create_session()
        own_sess = True

    try:
        url = (url or "").strip()
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError("Invalid request URL")

        # Strip hop-by-hop framing headers
        hdrs = {k: v for k, v in (headers or {}).items()
                if k.lower() not in ("content-length", "transfer-encoding", "connection")}

        # Target Host: preserve user/fuzzed Host header if specified; only default if absent
        has_host = any(k.lower() == "host" for k in hdrs)
        if not has_host:
            hdrs["Host"] = parsed.netloc

        data = body if body else None

        # Clean cookies between intruder requests to avoid cross-payload contamination
        sess.cookies.clear()

        # Proxies setup
        sess.proxies.clear()
        if proxies:
            sess.proxies.update(proxies)
        else:
            try:
                import proxy_config as _pc
                _global = _pc.get_proxies()
                if _global:
                    sess.proxies.update(_global)
            except Exception:
                pass

        resp = sess.request(
            method.upper(), url,
            headers=hdrs, data=data, timeout=timeout,
            allow_redirects=False, verify=False,
        )
        elapsed = int((time.time() - t0) * 1000)
        text = ""
        try:
            text = resp.text or ""
        except Exception:
            text = ""
        ctype = (resp.headers.get("Content-Type") or resp.headers.get("content-type") or "")
        out = {
            "ok": True,
            "status": resp.status_code,
            "length": len(resp.content or b""),
            "time_ms": elapsed,
            "error": "",
            "response_preview": text[:10000],  # Capped to 10KB to protect RAM on large attacks
            "response_headers": {str(k): str(v) for k, v in dict(resp.headers).items()},
            "content_type": ctype,
        }
        page = _proxy_intercept_page(text, ctype)
        if page:
            out["proxy_page"] = page
        return out
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        err = str(e)[:240]
        # Redact any embedded proxy credentials from error message
        err = re.sub(r'://([^:]+):([^@]+)@', r'://\1:****@', err)
        low = err.lower()
        if "socks" in low and ("missing" in low or "pysocks" in low or "no module" in low):
            err = "SOCKS proxy needs PySocks installed (pip install PySocks)"
        return {
            "ok": False,
            "status": 0,
            "length": 0,
            "time_ms": elapsed,
            "error": err,
            "response_preview": "",
            "response_headers": {},
            "content_type": "",
        }
    finally:
        if own_sess:
            try:
                sess.close()
            except Exception:
                pass
        else:
            sess.cookies.clear()


def _run_sniper(job_id: str):
    """Back-compat alias — all attack types run through _run_attack."""
    _run_attack(job_id)


def _build_attack_work(job: dict) -> Tuple[List[tuple], Optional[str]]:
    """
    Build work items: (req_id, values:List[str], payload_label:str, position_label).
    values are RAW (pre-pipeline); pipeline applied in worker.
    Returns (work, error_message).
    """
    template = job["template"]
    attack = (job.get("attack_type") or "sniper").lower().replace("-", "_").replace(" ", "_")
    bases = extract_positions(template)
    n = len(bases)
    if not n:
        return [], "No payload positions found. Wrap values with §like_this§"

    payloads = list(job.get("payloads") or [])
    payload_sets = list(job.get("payload_sets") or [])
    position_filter = int(job.get("position") or 0)
    unique_formats = _norm_unique_formats(job.get("unique_formats"), n)
    attack_idx = _attack_indices(n, unique_formats)
    if not attack_idx:
        return [], "Every §position§ is Unique format. Keep at least one position as a payload list so the attack can iterate."

    # Per-position sets: an explicit list (even empty) wins; only fall back to
    # `payloads` when that index was not sent at all.
    def _sets_for_positions() -> List[List[str]]:
        sets: List[List[str]] = []
        for i in range(n):
            if i < len(payload_sets) and isinstance(payload_sets[i], list):
                sets.append([str(x) for x in payload_sets[i]])
            elif payloads:
                sets.append([str(x) for x in payloads])
            else:
                sets.append([])
        return sets

    work: List[tuple] = []
    req_id = 0

    if attack in ("sniper",):
        sets = _sets_for_positions()
        if position_filter:
            if position_filter < 1 or position_filter > n:
                return [], "Invalid payload position"
            target = position_filter - 1
            if target not in attack_idx:
                return [], "That position is Unique format — it is not an attack variable. Pick a payload-list position."
            pos_indices = [target]
        else:
            pos_indices = list(attack_idx)
        for pos_i in pos_indices:
            for p in sets[pos_i]:
                req_id += 1
                work.append((req_id, "sniper", pos_i, str(p), list(bases)))
        if not work:
            return [], "No payloads for the selected position(s). Unique positions are skipped — add a list on at least one other position."

    elif attack in ("battering_ram", "battering", "ram"):
        if not payloads:
            return [], "No payloads provided"
        for p in payloads:
            req_id += 1
            work.append((req_id, "battering_ram", -1, str(p), list(bases)))

    elif attack in ("pitchfork",):
        sets = _sets_for_positions()
        if any(not sets[i] for i in attack_idx):
            return [], "Pitchfork needs a non-empty payload set for every list position (Unique format positions are skipped)"
        limit = min(len(sets[i]) for i in attack_idx)
        if limit <= 0:
            return [], "Pitchfork: payload sets are empty"
        for i in range(limit):
            req_id += 1
            raws: List[Optional[str]] = []
            parts = []
            for j in range(n):
                if j in attack_idx:
                    raws.append(str(sets[j][i]))
                    parts.append(str(sets[j][i]))
                else:
                    raws.append(None)
            work.append((req_id, "pitchfork", -1, " | ".join(parts), raws))

    elif attack in ("cluster_bomb", "cluster"):
        sets = _sets_for_positions()
        if any(not sets[i] for i in attack_idx):
            return [], "Cluster bomb needs a non-empty payload set for every list position (Unique format positions are skipped)"
        attack_sets = [sets[i] for i in attack_idx]
        total = 1
        for s in attack_sets:
            total *= len(s)
            if total > MAX_REQUESTS:
                return [], f"Cluster bomb would exceed {MAX_REQUESTS} requests — shrink payload sets"
        for combo in product(*attack_sets):
            req_id += 1
            raws = [None] * n
            for k, j in enumerate(attack_idx):
                raws[j] = str(combo[k])
            work.append((req_id, "cluster_bomb", -1, " | ".join(str(x) for x in combo), raws))

    else:
        return [], f"Unsupported attack type: {attack}"

    if len(work) > MAX_REQUESTS:
        return [], f"Max {MAX_REQUESTS} requests per attack"
    if not work:
        return [], "Nothing to attack — check positions and payloads"
    return work, None


def _run_attack(job_id: str):
    job = jobs[job_id]
    stop: threading.Event = job["_stop"]
    template = job["template"]
    base_headers = job.get("headers") or {}
    timeout = float(job.get("timeout") or 15)
    processors = job.get("processors") or []
    url_encode = bool(job.get("url_encode"))
    url_chars = job.get("url_encode_chars") or ""
    threads = max(1, min(MAX_THREADS, int(job.get("threads") or 1)))
    delay_ms = max(0.0, min(60_000.0, float(job.get("delay_ms") or 0)))
    delay_s = delay_ms / 1000.0
    bases = extract_positions(template)
    job["positions"] = [{"index": i, "base": v} for i, v in enumerate(bases)]

    work, err = _build_attack_work(job)
    if err:
        job["status"] = "error"
        job["error"] = err
        job["finished_at"] = time.time()
        job["progress"] = {"done": 0, "total": 0, "pct": 0}
        return

    total = len(work)
    job["progress"] = {"done": 0, "total": total, "pct": 0}
    results: List[dict] = job["results"]
    results_lock = threading.Lock()
    throttle_lock = threading.Lock()
    last_fire = [0.0]

    unique_formats = _norm_unique_formats(job.get("unique_formats"), len(bases))
    attack_idx = set(_attack_indices(len(bases), unique_formats))
    unique_idx = {i for i, fmt in enumerate(unique_formats) if fmt}
    proxy_pool = ProxyRotator(
        list(job.get("proxy_urls") or []),
        bool(job.get("proxy_rotate")),
    )

    _tls = threading.local()
    _all_sessions: List[requests.Session] = []
    _all_sessions_lock = threading.Lock()

    def _get_worker_session() -> requests.Session:
        sess = getattr(_tls, "session", None)
        if sess is None:
            sess = _create_session()
            _tls.session = sess
            with _all_sessions_lock:
                _all_sessions.append(sess)
        return sess

    def _apply_uniques(vals: List[str]) -> List[str]:
        out = list(vals)
        n = len(out)
        for i, fmt in enumerate(unique_formats):
            if not fmt or i >= n:
                continue
            raw = generate_random_value(fmt)
            encoded = apply_payload_pipeline(raw, [], url_encode, url_chars)
            out[i] = encoded if encoded is not None else raw
        return out

    def _throttle():
        if delay_s <= 0 or stop.is_set():
            return
        with throttle_lock:
            now = time.time()
            wait = delay_s - (now - last_fire[0])
            if wait > 0:
                end = time.time() + wait
                while time.time() < end:
                    if stop.is_set():
                        return
                    time.sleep(min(0.05, end - time.time()))
            last_fire[0] = time.time()

    def _expand_values(mode: str, pos_i: int, payload_or_list, bases_snap: List[str]) -> Optional[Tuple[List[str], str]]:
        """Return (final_values, label) or None if skipped by processor."""
        if mode == "sniper":
            expanded = apply_payload_pipeline(payload_or_list, processors, url_encode, url_chars)
            if expanded is None:
                return None
            vals = list(bases_snap)
            vals[pos_i] = expanded
            vals = _apply_uniques(vals)
            return vals, expanded
        if mode == "battering_ram":
            expanded = apply_payload_pipeline(payload_or_list, processors, url_encode, url_chars)
            if expanded is None:
                return None
            vals = list(bases_snap)
            for i in attack_idx:
                if i < len(vals):
                    vals[i] = expanded
            vals = _apply_uniques(vals)
            return vals, expanded
        # pitchfork / cluster_bomb — payload_or_list is list of raws (None = unique slot)
        raws = list(payload_or_list)
        vals = []
        labels = []
        for raw in raws:
            if raw is None:
                vals.append("")
                continue
            exp = apply_payload_pipeline(raw, processors, url_encode, url_chars)
            if exp is None:
                return None
            vals.append(exp)
            labels.append(exp)
        vals = _apply_uniques(vals)
        return vals, " | ".join(labels)

    def _one(item):
        if stop.is_set():
            return None
        rid, mode, pos_i, label, raw_data = item
        if mode in ("sniper", "battering_ram"):
            expanded = _expand_values(mode, pos_i, label, raw_data)
        else:
            # pitchfork / cluster — raw_data is the list of raw payloads per position
            expanded = _expand_values(mode, pos_i, raw_data, bases)
        if expanded is None:
            return {
                "id": rid,
                "position": (pos_i + 1) if mode == "sniper" else 0,
                "payload": str(label),
                "inserted_payloads": [],
                "request_display": "",
                "method": "",
                "url": "",
                "request_headers": {},
                "request_body": "",
                "ok": False,
                "status": 0,
                "length": 0,
                "time_ms": 0,
                "error": "skipped by processing rule",
                "response_preview": "",
                "response_headers": {},
                "content_type": "",
            }
        values, pay_label = expanded
        wrap_idx = set(unique_idx)
        if mode == "sniper" and pos_i >= 0:
            wrap_idx.add(pos_i)
            inserted = [values[i] for i in sorted(wrap_idx) if i < len(values)]
        elif mode == "battering_ram":
            wrap_idx |= set(attack_idx)
            inserted = [values[i] for i in sorted(wrap_idx) if i < len(values)]
        else:
            wrap_idx |= set(attack_idx)
            inserted = [values[i] for i in sorted(wrap_idx) if i < len(values)]
        if stop.is_set():
            return None
        _throttle()
        if stop.is_set():
            return None
        rendered = apply_all_positions(template, values)
        marked = apply_positions_for_display(template, values, wrap_idx)
        px_url = None
        sess = _get_worker_session()
        try:
            method, url, hdrs, body = materialize_request(
                rendered, job.get("method") or "GET", base_headers
            )
            px_url, px = proxy_pool.next()
            fired = _fire(method, url, hdrs, body, timeout, proxies=px, session=sess)
        except Exception as e:
            method, url, hdrs, body = job.get("method") or "GET", "", {}, ""
            fired = {
                "ok": False,
                "status": 0,
                "length": 0,
                "time_ms": 0,
                "error": str(e)[:240],
                "response_preview": "",
                "response_headers": {},
                "content_type": "",
            }
        shown_proxy = redact_proxy_url(px_url) if px_url else ""
        if shown_proxy:
            fired["proxy"] = shown_proxy
        try:
            d_method, d_url, d_hdrs, d_body = materialize_request(
                marked, job.get("method") or "GET", base_headers
            )
            request_display = http_text_from_parts(d_method, d_url, d_hdrs, d_body)
        except Exception:
            request_display = http_text_from_parts(method, url, hdrs, body)

        # Grep Match & Grep Extract checks
        resp_text = fired.get("response_preview") or ""
        matched = []
        for pat in (job.get("grep_match") or []):
            p_clean = str(pat or "").strip()
            if p_clean and p_clean.lower() in resp_text.lower():
                matched.append(p_clean)

        extracted = []
        for exp in (job.get("grep_extract") or []):
            e_clean = str(exp or "").strip()
            if e_clean:
                try:
                    m = re.search(e_clean, resp_text, re.IGNORECASE)
                    if m:
                        extracted.append(m.group(1) if m.groups() else m.group(0))
                except Exception:
                    pass

        return {
            "id": rid,
            "position": (pos_i + 1) if mode == "sniper" else 0,
            "payload": pay_label,
            "inserted_payloads": [str(x) for x in inserted],
            "request_display": request_display,
            "method": method,
            "url": url,
            "request_headers": hdrs,
            "request_body": body,
            "grep_match": matched,
            "grep_extract": extracted,
            **fired,
        }

    def _commit(entry):
        if entry is None:
            return
        with results_lock:
            results.append(entry)
            done = len(results)
            job["progress"] = {
                "done": done,
                "total": total,
                "pct": int(100 * done / total) if total else 0,
            }

    if threads <= 1:
        for item in work:
            if stop.is_set():
                break
            _commit(_one(item))
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(_one, item) for item in work]
            for fut in as_completed(futures):
                if stop.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    _commit(fut.result())
                except Exception as e:
                    _commit({
                        "id": 0,
                        "position": 0,
                        "payload": "error",
                        "inserted_payloads": [],
                        "request_display": "",
                        "method": "",
                        "url": "",
                        "request_headers": {},
                        "request_body": "",
                        "ok": False,
                        "status": 0,
                        "length": 0,
                        "time_ms": 0,
                        "error": f"Worker execution error: {str(e)[:180]}",
                        "response_preview": "",
                        "response_headers": {},
                        "content_type": "",
                    })

    # Cleanly close all pooled sessions
    with _all_sessions_lock:
        for s in _all_sessions:
            try:
                s.close()
            except Exception:
                pass
        _all_sessions.clear()

    with _jobs_lock:
        job["status"] = "stopped" if stop.is_set() else "done"
        job["finished_at"] = time.time()
        job["dashboard"] = _build_dashboard(results)


def _build_dashboard(results: List[dict]) -> dict:
    by_status: Dict[str, int] = {}
    times = []
    lengths = []
    errors = 0
    for r in results:
        st = str(r.get("status") or 0)
        by_status[st] = by_status.get(st, 0) + 1
        if r.get("error"):
            errors += 1
        if r.get("time_ms") is not None:
            times.append(int(r["time_ms"]))
        if r.get("length") is not None:
            lengths.append(int(r["length"]))
    def _pct(arr, p):
        if not arr:
            return 0
        s = sorted(arr)
        idx = min(len(s) - 1, max(0, int(round((p / 100) * (len(s) - 1)))))
        return s[idx]
    return {
        "total": len(results),
        "errors": errors,
        "by_status": by_status,
        "time_ms": {
            "min": min(times) if times else 0,
            "max": max(times) if times else 0,
            "avg": int(sum(times) / len(times)) if times else 0,
            "p95": _pct(times, 95),
        },
        "length": {
            "min": min(lengths) if lengths else 0,
            "max": max(lengths) if lengths else 0,
            "avg": int(sum(lengths) / len(lengths)) if lengths else 0,
        },
    }


# ── API models ────────────────────────────────────────────────────────────────

class ParseCurlReq(BaseModel):
    curl: str


class GeneratePayloadsReq(BaseModel):
    kind: str = "uuid"  # uuid|email|name|num|alpha|alphanum|numbers
    count: int = 20
    format: str = ""    # optional full format e.g. "{alphanum:8}@x.com"
    start: int = 1
    end: int = 100
    prefix: str = ""
    suffix: str = ""


class SingleHitReq(BaseModel):
    template: str
    method: str = "GET"
    headers: dict = Field(default_factory=dict)
    unique_formats: List[str] = Field(default_factory=list)
    timeout: float = 15
    url_encode: bool = False
    url_encode_chars: str = r".\=<>?+&*':;\"()|^`#"
    proxy: str = ""
    proxy_list: List[str] = Field(default_factory=list)
    proxy_rotate: bool = False
    grep_match: List[str] = Field(default_factory=list)
    grep_extract: List[str] = Field(default_factory=list)


class StartAttackReq(BaseModel):
    template: str
    method: str = "GET"
    headers: dict = Field(default_factory=dict)
    payloads: List[str] = Field(default_factory=list)
    payload_sets: List[List[str]] = Field(default_factory=list)
    unique_formats: List[str] = Field(default_factory=list)
    attack_type: str = "sniper"
    timeout: float = 15
    position: int = 0
    url_encode: bool = False
    url_encode_chars: str = r".\=<>?+&*':;\"()|^`#"
    processors: List[dict] = Field(default_factory=list)
    threads: int = 1
    delay_ms: float = 0
    proxy: str = ""
    proxy_list: List[str] = Field(default_factory=list)
    proxy_rotate: bool = False
    grep_match: List[str] = Field(default_factory=list)
    grep_extract: List[str] = Field(default_factory=list)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "intruder", "port": 8794}


@app.post("/intruder/parse_curl")
def api_parse_curl(req: ParseCurlReq):
    try:
        parsed = parse_curl(req.curl)
    except ValueError as e:
        raise HTTPException(400, str(e))
    # Build editable raw template (Burp-like)
    lines = [f"{parsed['method']} {parsed['url']}"]
    for k, v in (parsed.get("headers") or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(parsed.get("body") or "")
    template = "\n".join(lines)
    return {**parsed, "template": template}


@app.post("/intruder/single")
def api_single_hit(req: SingleHitReq):
    """Repeater-style: fire the editor request once. §markers§ unwrap to inner text.
    Unique-format positions get a fresh value. No payload-list iteration.
    """
    template = req.template or ""
    if not template.strip():
        raise HTTPException(400, "Empty request")
    if _looks_like_curl(template):
        raise HTTPException(400, "Request still looks like cURL — convert to raw HTTP first")

    timeout = max(1.0, min(float(req.timeout or 15), 120))
    try:
        proxy_urls = collect_proxy_urls(req.proxy, req.proxy_list)
    except ValueError as e:
        raise HTTPException(400, str(e))
    proxy_pool = ProxyRotator(proxy_urls, bool(req.proxy_rotate))
    bases = extract_positions(template)
    n = len(bases)
    unique_formats = _norm_unique_formats(req.unique_formats, n)
    values = list(bases)
    wrap_idx = set()
    for i, fmt in enumerate(unique_formats):
        if not fmt:
            continue
        raw = generate_random_value(fmt)
        encoded = apply_payload_pipeline(raw, [], bool(req.url_encode), req.url_encode_chars or "")
        values[i] = encoded if encoded is not None else raw
        wrap_idx.add(i)

    rendered = apply_all_positions(template, values) if n else template
    marked = apply_positions_for_display(template, values, wrap_idx) if n else template
    fallback_method = (req.method or "GET").upper()
    try:
        method, url, hdrs, body = materialize_request(rendered, fallback_method, req.headers or {})
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not (url or "").strip():
        raise HTTPException(400, "Could not parse URL from the request")

    px_url, px = proxy_pool.next()
    fired = _fire(method, url, hdrs, body, timeout, proxies=px)
    shown_proxy = redact_proxy_url(px_url) if px_url else ""
    if shown_proxy:
        fired["proxy"] = shown_proxy
    try:
        d_method, d_url, d_hdrs, d_body = materialize_request(marked, fallback_method, req.headers or {})
        request_display = http_text_from_parts(d_method, d_url, d_hdrs, d_body)
    except Exception:
        request_display = http_text_from_parts(method, url, hdrs, body)

    # Grep checks
    resp_text = fired.get("response_preview") or ""
    matched = [p for p in (req.grep_match or []) if p and p.lower() in resp_text.lower()]
    extracted = []
    for exp in (req.grep_extract or []):
        if exp:
            try:
                m = re.search(exp, resp_text, re.IGNORECASE)
                if m:
                    extracted.append(m.group(1) if m.groups() else m.group(0))
            except Exception:
                pass

    inserted = [values[i] for i in sorted(wrap_idx) if i < len(values)]
    label = " | ".join(str(x) for x in inserted) if inserted else "single"
    return {
        "id": 1,
        "position": 0,
        "payload": label,
        "inserted_payloads": [str(x) for x in inserted],
        "request_display": request_display,
        "method": method,
        "url": url,
        "request_headers": hdrs,
        "request_body": body,
        "grep_match": matched,
        "grep_extract": extracted,
        **fired,
    }


@app.post("/intruder/generate_payloads")
def api_generate_payloads(req: GeneratePayloadsReq):
    count = max(1, min(int(req.count or 1), 2000))
    kind = (req.kind or "uuid").lower()
    out: List[str] = []
    fmt = (req.format or "").strip()
    if fmt:
        for _ in range(count):
            out.append(generate_random_value(fmt))
        return {"payloads": out}
    if kind == "numbers":
        start, end = int(req.start), int(req.end)
        if end < start:
            start, end = end, start
        # inclusive range, capped
        vals = list(range(start, end + 1))[:count]
        pref, suf = req.prefix or "", req.suffix or ""
        out = [f"{pref}{n}{suf}" for n in vals]
        return {"payloads": out}
    token_map = {
        "uuid": "{uuid}",
        "email": "{email}",
        "name": "{name}",
        "num": "{num:8}",
        "alpha": "{alpha:8}",
        "alphanum": "{alphanum:8}",
    }
    token = token_map.get(kind, "{uuid}")
    pref, suf = req.prefix or "", req.suffix or ""
    for _ in range(count):
        out.append(f"{pref}{generate_random_value(token)}{suf}")
    return {"payloads": out}


@app.post("/intruder/start")
def start_attack(req: StartAttackReq):
    _prune_jobs()
    attack = (req.attack_type or "sniper").lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "battering": "battering_ram",
        "ram": "battering_ram",
        "cluster": "cluster_bomb",
    }
    attack = aliases.get(attack, attack)
    if attack not in ("sniper", "battering_ram", "pitchfork", "cluster_bomb"):
        raise HTTPException(
            400,
            "attack_type must be sniper | battering_ram | pitchfork | cluster_bomb",
        )
    template = req.template or ""
    if "§" not in template:
        raise HTTPException(400, "Mark at least one payload position with §value§")

    payloads = list(req.payloads or [])
    payload_sets = [list(s or []) for s in (req.payload_sets or [])]
    npos = len(extract_positions(template))
    unique_formats = _norm_unique_formats(req.unique_formats, npos)
    attack_idx = _attack_indices(npos, unique_formats)
    if not attack_idx:
        raise HTTPException(
            400,
            "Every §position§ is Unique format. Keep at least one position as a payload list.",
        )
    multi = attack in ("pitchfork", "cluster_bomb")
    if attack == "sniper":
        while len(payload_sets) < npos:
            payload_sets.append(list(payloads) if payloads else [])
        payload_sets = payload_sets[:npos]
        pos = int(req.position or 0)
        if pos:
            if pos < 1 or pos > npos:
                raise HTTPException(400, "Invalid payload position")
            if (pos - 1) not in attack_idx:
                raise HTTPException(400, "That position is Unique format — pick a payload-list position")
            slot = payload_sets[pos - 1]
            if not slot:
                raise HTTPException(400, "That position has no payloads — select it and add a list")
            if len(slot) > MAX_PAYLOADS:
                raise HTTPException(400, f"Max {MAX_PAYLOADS} payloads per position")
        else:
            if not any(payload_sets[i] for i in attack_idx) and not payloads:
                raise HTTPException(400, "Add payloads on at least one non-Unique position")
            for i in attack_idx:
                if len(payload_sets[i]) > MAX_PAYLOADS:
                    raise HTTPException(400, f"Max {MAX_PAYLOADS} payloads per position")
    elif multi:
        while len(payload_sets) < npos:
            payload_sets.append(list(payloads) if payloads else [])
        payload_sets = payload_sets[:npos]
        if any(not payload_sets[i] for i in attack_idx):
            raise HTTPException(
                400,
                f"{attack}: add a non-empty payload set for every list position (Unique format positions are skipped)",
            )
        for i in attack_idx:
            if len(payload_sets[i]) > MAX_PAYLOADS:
                raise HTTPException(400, f"Max {MAX_PAYLOADS} payloads per set")
    else:
        if not payloads:
            raise HTTPException(400, "Add at least one payload")
        if len(payloads) > MAX_PAYLOADS:
            raise HTTPException(400, f"Max {MAX_PAYLOADS} payloads")

    with _jobs_lock:
        for j in jobs.values():
            if j.get("status") == "running":
                raise HTTPException(409, "An Intruder attack is already running — stop it first")

    # Pre-validate work size (esp. cluster bomb)
    probe = {
        "template": template,
        "attack_type": attack,
        "payloads": payloads,
        "payload_sets": payload_sets,
        "unique_formats": unique_formats,
        "position": int(req.position or 0),
    }
    work, err = _build_attack_work(probe)
    if err:
        raise HTTPException(400, err)

    try:
        proxy_urls = collect_proxy_urls(req.proxy, req.proxy_list)
    except ValueError as e:
        raise HTTPException(400, str(e))

    job_id = str(uuid.uuid4())
    stop = threading.Event()
    job = {
        "id": job_id,
        "status": "running",
        "attack_type": attack,
        "template": template,
        "method": (req.method or "GET").upper(),
        "headers": req.headers or {},
        "payloads": payloads,
        "payload_sets": payload_sets,
        "unique_formats": unique_formats,
        "timeout": max(1.0, min(float(req.timeout or 15), 120)),
        "position": int(req.position or 0),
        "url_encode": bool(req.url_encode),
        "url_encode_chars": req.url_encode_chars or "",
        "processors": list(req.processors or []),
        "threads": max(1, min(MAX_THREADS, int(req.threads or 1))),
        "delay_ms": max(0.0, min(60_000.0, float(req.delay_ms or 0))),
        "proxy_urls": proxy_urls,
        "proxy_rotate": bool(req.proxy_rotate) and len(proxy_urls) > 1,
        "grep_match": [str(x).strip() for x in (req.grep_match or []) if str(x).strip()],
        "grep_extract": [str(x).strip() for x in (req.grep_extract or []) if str(x).strip()],
        "created_at": time.time(),
        "finished_at": None,
        "error": "",
        "results": [],
        "progress": {"done": 0, "total": len(work), "pct": 0},
        "dashboard": {},
        "positions": [],
        "_stop": stop,
    }
    with _jobs_lock:
        jobs[job_id] = job
    threading.Thread(target=_run_attack, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "running", "attack_type": attack, "total": len(work)}


@app.get("/intruder/status/{job_id}")
def get_status(job_id: str, since: int = 0):
    with _jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        status = job.get("status")
        error = job.get("error") or ""
        progress = dict(job.get("progress") or {})
        positions = list(job.get("positions") or [])
        dashboard = dict(job.get("dashboard") or {})
        results = list(job.get("results") or [])

    since = max(0, int(since or 0))
    return {
        "job_id": job_id,
        "status": status,
        "error": error,
        "progress": progress,
        "positions": positions,
        "new_results": results[since:],
        "result_count": len(results),
        "dashboard": dashboard,
    }


@app.get("/intruder/results/{job_id}")
def get_results(job_id: str):
    with _jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        status = job.get("status")
        results = list(job.get("results") or [])
        dashboard = job.get("dashboard") or _build_dashboard(results)
        progress = dict(job.get("progress") or {})
        positions = list(job.get("positions") or [])
        error = job.get("error") or ""

    return {
        "job_id": job_id,
        "status": status,
        "results": results,
        "dashboard": dashboard,
        "progress": progress,
        "positions": positions,
        "error": error,
    }


@app.post("/intruder/stop/{job_id}")
def stop_job(job_id: str):
    with _jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        ev = job.get("_stop")
        if ev:
            ev.set()
        if job.get("status") == "running":
            job["status"] = "stopping"
        status = job.get("status")
    return {"ok": True, "status": status}
