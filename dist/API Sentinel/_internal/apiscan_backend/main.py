"""
API Scan Backend — Port 8775
Wraps Scan.py (active security scanner) with a polling REST API.
"""

import os, re, sys, csv, json, time, uuid, shlex, importlib.util, threading, io, string as _string, types
import base64 as _base64
from queue import Queue as _ScanQueue, Empty as _ScanQueueEmpty
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, parse_qsl
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Any

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_scan_py() -> str:
    """
    Locate Scan.py for both:
      • Dev:   <repo>/Scan.py  (sibling of apiscan_backend/)
      • Build: apiscan_backend/Scan.py (copied by build.sh into the package)
    Also checks PyInstaller _MEIPASS / frozen app Resources layouts.
    """
    candidates = [
        # Packaged: ship beside this module (preferred)
        os.path.join(BASE_DIR, "Scan.py"),
        # Dev / source tree: repo root
        os.path.normpath(os.path.join(BASE_DIR, "..", "Scan.py")),
    ]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.extend([
            os.path.join(meipass, "apiscan_backend", "Scan.py"),
            os.path.join(meipass, "Scan.py"),
        ])
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.extend([
            os.path.join(exe_dir, "apiscan_backend", "Scan.py"),
            os.path.join(exe_dir, "Scan.py"),
            os.path.normpath(os.path.join(exe_dir, "..", "Resources", "apiscan_backend", "Scan.py")),
            os.path.normpath(os.path.join(exe_dir, "..", "Resources", "Scan.py")),
            os.path.normpath(os.path.join(exe_dir, "..", "_internal", "apiscan_backend", "Scan.py")),
            os.path.normpath(os.path.join(exe_dir, "..", "_internal", "Scan.py")),
        ])
    seen = set()
    for raw in candidates:
        path = os.path.normpath(raw)
        if path in seen:
            continue
        seen.add(path)
        if os.path.isfile(path):
            return path
    # Default path used in error messages when nothing found
    return os.path.normpath(os.path.join(BASE_DIR, "Scan.py"))


SCAN_PY = _resolve_scan_py()

app = FastAPI(title="API Scan Backend")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

jobs = {}   # job_id → job dict

# Finished jobs keep probes/issues in RAM for the process lifetime unless pruned.
# Mirror jsanalyser_backend: TTL + hard count cap (never drop a running job).
JOB_TTL  = 3600   # seconds a finished job stays available
MAX_JOBS = 50

# Session handling (Mode A): consecutive 401/403 → pause for fresh token
AUTH_FAIL_THRESHOLD = 6


def _prune_old_jobs():
    now = time.time()
    stale = [
        jid for jid, j in jobs.items()
        if j.get("status") != "running"
        and now - float(j.get("finished_at") or j.get("created_at") or now) > JOB_TTL
    ]
    for jid in stale:
        jobs.pop(jid, None)

    if len(jobs) > MAX_JOBS:
        finished = sorted(
            (jid for jid, j in jobs.items() if j.get("status") != "running"),
            key=lambda jid: float(
                jobs[jid].get("finished_at") or jobs[jid].get("created_at") or 0
            ),
        )
        for jid in finished[: max(0, len(jobs) - MAX_JOBS)]:
            jobs.pop(jid, None)


def _apply_auth_headers(base_headers: dict, overrides: dict) -> dict:
    """Merge auth overrides into a header dict (case-insensitive replace)."""
    out = dict(base_headers or {})
    for ok, ovv in (overrides or {}).items():
        if ovv is None or ovv == "":
            continue
        for k in list(out.keys()):
            if k.lower() == str(ok).lower():
                del out[k]
        out[str(ok)] = str(ovv)
    return out


def _sync_sender_auth(job: dict, sender) -> None:
    """Push job auth_headers onto RequestSender.base.headers."""
    ov = job.get("auth_headers") or {}
    if not ov or sender is None:
        return
    try:
        hdrs = getattr(sender.base, "headers", None)
        if hdrs is None:
            return
        merged = _apply_auth_headers(hdrs, ov)
        if hasattr(hdrs, "clear"):
            hdrs.clear()
            hdrs.update(merged)
        else:
            sender.base.headers = merged
    except Exception:
        pass


def _wait_while_auth_paused(job: dict, stop_event) -> bool:
    """
    Block probe threads while auth_paused. Returns False if aborted.
    """
    while job.get("auth_paused") and not job.get("stopped"):
        if stop_event is not None and stop_event.is_set():
            return False
        time.sleep(0.35)
    if job.get("stopped"):
        return False
    if stop_event is not None and stop_event.is_set():
        return False
    return True


def _note_probe_auth(job: dict, status_code: int) -> None:
    """Track consecutive 401/403; pause the job when threshold is hit."""
    if job.get("stopped") or job.get("auth_paused"):
        return
    # User chose Skip on the auth banner — treat further 401/403 as expected for this job
    if job.get("auth_pause_skipped"):
        return
    try:
        code = int(status_code or 0)
    except (TypeError, ValueError):
        return
    # If baseline itself was unauthorized, never auto-pause this entry
    bl = (job.get("_ctx") or {}).get("baseline_status")
    if bl in (401, 403):
        return
    if code in (401, 403):
        streak = int(job.get("_auth_fail_streak") or 0) + 1
        job["_auth_fail_streak"] = streak
        if streak >= AUTH_FAIL_THRESHOLD:
            job["auth_paused"] = True
            job["status"] = "paused_auth"
            job["auth_pause_reason"] = (
                f"{AUTH_FAIL_THRESHOLD}+ consecutive HTTP 401/403 responses — "
                "session likely expired. Paste a fresh Authorization (or Cookie) and Resume, "
                "or Skip if these are expected for this API."
            )
            try:
                job["logs"].append({
                    "text":  f"[⏸] Auth pause — {job['auth_pause_reason']}",
                    "level": "high",
                    "ts":    time.time(),
                })
                job["progress"]["api"] = "Paused — waiting for new token…"
            except Exception:
                pass
    elif 200 <= code < 400:
        job["_auth_fail_streak"] = 0


# ── Helpers ────────────────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mK]|\x1b\[[0-9;]*[A-Za-z]')

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s).strip()


def _get_scan_py() -> str:
    """Re-resolve on use so a late-bundled Scan.py is still found."""
    global SCAN_PY
    SCAN_PY = _resolve_scan_py()
    return SCAN_PY


# Compile Scan.py once; still exec into a fresh module per entry (isolation).
_SCAN_CODE = None          # compiled code object
_SCAN_CODE_KEY = None      # (path, mtime)


def _load_scan(uid: str):
    """Load a fresh copy of Scan.py as an isolated module (no state leakage)."""
    global _SCAN_CODE, _SCAN_CODE_KEY
    path = _get_scan_py()
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Scan.py not found (expected beside apiscan_backend/ or at repo root). "
            f"Tried resolve → {path}"
        )
    key = (path, os.path.getmtime(path))
    if _SCAN_CODE is None or _SCAN_CODE_KEY != key:
        with open(path, "rb") as fh:
            _SCAN_CODE = compile(fh.read(), path, "exec")
        _SCAN_CODE_KEY = key
    name = f"_scan_{uid}"
    m = types.ModuleType(name)
    m.__file__ = path
    m.__loader__ = None
    m.__package__ = None
    sys.modules[name] = m
    try:
        exec(_SCAN_CODE, m.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return m


def _unload_scan(uid: str):
    """Drop a per-entry Scan module so jobs don't accumulate in sys.modules."""
    sys.modules.pop(f"_scan_{uid}", None)


import random as _random

_REGEN_SKIP_HEADERS = {
    'host','content-length','transfer-encoding','connection','accept-encoding',
    'cache-control','pragma','accept','accept-language','sec-fetch-dest',
    'sec-fetch-mode','sec-fetch-site','sec-ch-ua','sec-ch-ua-mobile',
    'sec-ch-ua-platform','upgrade-insecure-requests','te','content-type',
    'authorization','cookie','origin','referer','user-agent','priority',
    'ngsw-bypass','x-module','sec-fetch-dest','sec-fetch-mode',
}
_INTERESTING_HDR_RE = re.compile(
    r'(id|user|customer|account|session|token|client|request|tenant|org|company)', re.I
)


def _regen_similar_val(original: str) -> str:
    """Generate a fresh value in the same format as the original (for per-probe regen)."""
    v = str(original or "")
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.I):
        return str(uuid.uuid4())
    if re.match(r'^\d+$', v) and 1 <= len(v) <= 12:
        digits = len(v)
        lo = 10 ** (digits - 1) if digits > 1 else 1
        hi = 10 ** digits - 1
        return str(_random.randint(lo, hi))
    if '@' in v:
        prefix = ''.join(_random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        return f"test_{prefix}@example.com"
    if re.match(r'^[0-9a-f]{16,}$', v, re.I):
        return ''.join(_random.choices('0123456789abcdef', k=len(v)))
    if v.lower() in ('true', 'false'):
        return 'false' if v.lower() == 'true' else 'true'
    return ''.join(_random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=max(6, len(v))))


def _generate_format_val(fmt: str) -> str:
    """
    Expand format tokens — identical to PT Tester's generate_random_value().
    Supported tokens: {uuid} {email} {alphanum:N} {alpha:N} {num:N} {hex:N}
    Anything outside tokens is kept as literal text.
    """
    def _rep(m):
        token = m.group(1).lower().strip()
        if token == "uuid":
            return str(uuid.uuid4())
        if token == "email":
            u = ''.join(_random.choices(_string.ascii_lowercase + _string.digits, k=8))
            return f"{u}@testapi.com"
        parts = token.split(":")
        kind  = parts[0]
        n     = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 8
        if kind == "alpha":
            return ''.join(_random.choices(_string.ascii_letters, k=n))
        if kind == "alphanum":
            return ''.join(_random.choices(_string.ascii_letters + _string.digits, k=n))
        if kind == "num":
            # No leading zeros
            first = _random.choice(_string.digits[1:])
            rest  = ''.join(_random.choices(_string.digits, k=max(0, n - 1)))
            return first + rest
        if kind in ("hex", "hexnum"):
            return ''.join(_random.choices('0123456789abcdef', k=n))
        return m.group(0)   # unknown token → keep as-is
    return re.sub(r'\{([^}]+)\}', _rep, fmt)


def _fresh_val(cv: dict) -> str:
    """
    Generate a per-probe fresh value for a regen custom param.
    If the stored value contains a format token ({num:N}, {uuid}, etc.) use
    _generate_format_val to expand it fresh.  Otherwise fall back to
    _regen_similar_val using the original value as the shape template.
    """
    val  = str(cv.get("value", "") or "")
    orig = str(cv.get("original_value", "") or "")
    if val and re.search(r'\{[^}]+\}', val):
        return _generate_format_val(val)
    return _regen_similar_val(orig or val)


class _ShadowBase:
    """Cloned base request object to isolate per-probe mutations (url, headers, body)
    to a single thread so network I/O executes concurrently without holding locks."""
    __slots__ = ("method", "url", "headers", "cookies", "body")
    def __init__(self, base):
        self.method  = getattr(base, "method", "GET")
        self.url     = getattr(base, "url", "")
        self.headers = dict(getattr(base, "headers", {}) or {})
        self.cookies = dict(getattr(base, "cookies", {}) or {})
        self.body    = getattr(base, "body", None)


class _ShadowSender:
    """Lightweight sender proxy delegating to the original RequestSender but with
    an isolated shadow base request for thread-safe mutation."""
    def __init__(self, orig_sender, shadow_base):
        self._orig = orig_sender
        self.base  = shadow_base

    def __getattr__(self, name):
        return getattr(self._orig, name)


# Lock kept for backward-compatibility if referenced elsewhere
_regen_base_lock = threading.Lock()


def _json_get_path(obj, path: str):
    """Get the value at a dot-notation / array-index path. Returns None if not found."""
    try:
        keys = re.split(r'\.(?![^\[]*\])', path)
        d = obj
        for k in keys:
            m = re.match(r'^(.*?)\[(\d+)\]$', k)
            if m:
                d = d[m.group(1)]
                if isinstance(d, list):
                    d = d[int(m.group(2))]
            else:
                d = d[k]
        return d
    except Exception:
        return None


def _json_set_path(obj, path: str, value) -> bool:
    """Set a value at a dot-notation / array-index path in a dict. Returns True if set."""
    try:
        keys = re.split(r'\.(?![^\[]*\])', path)
        d = obj
        for k in keys[:-1]:
            m = re.match(r'^(.*?)\[(\d+)\]$', k)
            if m:
                d = d[m.group(1)]
                if isinstance(d, list): d = d[int(m.group(2))]
            else:
                d = d[k]
        last = keys[-1]
        m = re.match(r'^(.*?)\[(\d+)\]$', last)
        if m:
            arr = d[m.group(1)]
            if isinstance(arr, list): arr[int(m.group(2))] = value
        else:
            if last in d:
                d[last] = value
        return True
    except Exception:
        return False


def _normalise_body(raw_body) -> Optional[str]:
    """Convert body from any format (str / dict / list / None) to a plain string."""
    if raw_body is None:
        return None
    if isinstance(raw_body, (dict, list)):
        s = json.dumps(raw_body)
        return s if s not in ("null", "{}", "[]", "null") else None
    if isinstance(raw_body, str):
        return raw_body.strip() or None
    return str(raw_body).strip() or None


def _build_curl(method: str, url: str, headers: dict, body: Optional[str]) -> str:
    """Build a curl command string from components."""
    parts = ["curl"]
    if method.upper() != "GET":
        parts += ["-X", method.upper()]
    skip = {"content-length", "transfer-encoding", "connection", "host"}
    for k, v in (headers or {}).items():
        if k.lower() not in skip:
            parts += ["-H", f"{k}: {v}"]
    if body:
        parts += ["--data-raw", body]
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


# ── Burp-like improvement: constants ──────────────────────────────────────────

_SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax",                 re.I),
    re.compile(r"unclosed quotation mark",                              re.I),
    re.compile(r"quoted string not properly terminated",                re.I),
    re.compile(r"ORA-\d{5}:",                                          re.I),
    re.compile(r"microsoft ole db provider for sql server",             re.I),
    re.compile(r"Warning: mysql_fetch|Warning: mysql_",                 re.I),
    re.compile(r"SQLite3::",                                            re.I),
    re.compile(r"com\.mysql\.jdbc\.exceptions",                         re.I),
    re.compile(r"org\.postgresql\.util\.PSQLException",                 re.I),
    re.compile(r"syntax error.*near|near.*syntax error",                re.I),
    re.compile(r"unterminated string literal",                          re.I),
    re.compile(r"Incorrect syntax near",                                re.I),
    re.compile(r"pg_query\(\).*failed",                                 re.I),
    re.compile(r"PG::SyntaxError:",                                     re.I),
    re.compile(r"SQLSTATE\[",                                           re.I),
]

# ── Base64-encoded parameter handling ─────────────────────────────────────────
# Some APIs wrap their JSON payload inside a base64-encoded field
# (e.g. {"encodedValue": "<base64_json>"}).  Scanning the encoded string
# directly is useless — we must decode → scan inner params → re-encode.

_B64_PARAM_RE = re.compile(r"encoded|base64|b64", re.I)


def _detect_expand_b64_params(body_str: str) -> tuple:
    """
    Find request body fields whose NAMES suggest base64 encoding
    (contain "encoded", "base64", or "b64") and whose VALUES decode
    to valid JSON objects.

    Returns (expanded_body_str, b64_map) where:
      • expanded_body_str — body with those fields replaced by decoded dicts
        so Scan.py can reach and test the inner parameters.
      • b64_map — { field_name: original_b64_string } for re-encoding.

    If no such fields are found, returns (original_body_str, {}).
    """
    b64_map: dict = {}
    if not body_str:
        return body_str, b64_map
    try:
        obj = json.loads(body_str)
        if not isinstance(obj, dict):
            return body_str, b64_map
        changed = False
        for key, val in obj.items():
            if not isinstance(val, str) or not _B64_PARAM_RE.search(key):
                continue
            try:
                # Pad to valid base64 length
                padded       = val + "=" * (-len(val) % 4)
                decoded_str  = _base64.b64decode(padded).decode("utf-8")
                inner        = json.loads(decoded_str)
                if isinstance(inner, dict):
                    b64_map[key] = val   # store original encoded string
                    obj[key]     = inner # replace with decoded dict
                    changed      = True
            except Exception:
                pass
        if changed:
            return json.dumps(obj), b64_map
    except Exception:
        pass
    return body_str, b64_map


def _reencode_b64_params(body_str: str, b64_map: dict) -> str:
    """
    After Scan.py has injected a payload into one of the decoded inner fields,
    re-encode any base64 fields back to their encoded form so the actual HTTP
    request reaches the server in the correct format.

    E.g. {"encodedValue": {"name": "{{7*7}}", ...}}
      →  {"encodedValue": "<base64 of inner JSON with {{7*7}} in name>"}
    """
    if not b64_map or not body_str:
        return body_str
    try:
        obj = json.loads(body_str)
        if not isinstance(obj, dict):
            return body_str
        changed = False
        for key in b64_map:
            if key in obj and isinstance(obj[key], (dict, list)):
                obj[key] = _base64.b64encode(
                    json.dumps(obj[key]).encode("utf-8")
                ).decode("utf-8")
                changed = True
        if changed:
            return json.dumps(obj)
    except Exception:
        pass
    return body_str


_NOSQL_ERROR_PATTERNS = [
    re.compile(r"BSON",                                    re.I),
    re.compile(r"MongoError|MongoServerError",             re.I),
    re.compile(r"MongoDB.*(?:error|exception)",            re.I),
    re.compile(r"E11000 duplicate key",                    re.I),
    re.compile(r"InvalidBSON|BSONTypeError",               re.I),
    re.compile(r"WriteError|BulkWriteError",               re.I),
    re.compile(r"CouchDB.*error",                          re.I),
    re.compile(r"\$where.*syntax|\$regex.*error",          re.I),
    re.compile(r"SyntaxError.*JSON",                       re.I),
    re.compile(r"Unexpected token.*JSON",                  re.I),
    re.compile(r"redis.*error|WRONGTYPE",                  re.I),
    re.compile(r"Cassandra.*error|DriverException",        re.I),
]

_WAF_SIGNATURES = [
    (re.compile(r"cloudflare",                          re.I), "Cloudflare"),
    (re.compile(r"sucuri",                              re.I), "Sucuri"),
    (re.compile(r"mod_security|NOYB",                   re.I), "ModSecurity"),
    (re.compile(r"incapsula",                           re.I), "Incapsula"),
    (re.compile(r"akamai",                              re.I), "Akamai"),
    (re.compile(r"imperva",                             re.I), "Imperva"),
    (re.compile(r"fortigate|fortiweb",                  re.I), "Fortinet"),
    (re.compile(r"barracuda",                           re.I), "Barracuda"),
    (re.compile(r"bigip|f5-trafficshield",              re.I), "F5 BIG-IP"),
    (re.compile(r"aws.{0,20}waf|x-amzn-waf",           re.I), "AWS WAF"),
    (re.compile(r"<title>Access Denied</title>",        re.I), "Generic WAF"),
    (re.compile(r"request rejected|illegal request",    re.I), "Generic WAF"),
]

_PARAM_SEMANTIC_GROUPS = [
    ("auth_token",    re.compile(r"(token|jwt|bearer|api.?key|secret|passw|auth(?!or)|session|cookie)",              re.I)),
    ("user_id",       re.compile(r"(user.?id|uid|user.?name|account.?id|customer.?id|member.?id|(?<!\w)sub(?!\w))", re.I)),
    ("resource_id",   re.compile(r"(^id$|[_\-]id$|resource.?id|object.?id|record.?id|item.?id|uuid|guid)",          re.I)),
    ("url_ref",       re.compile(r"(url|link|href|redirect|return.?url|callback|next|dest(?:ination)?|goto|referr?er|origin)", re.I)),
    ("file_path",     re.compile(r"(file|path|dir(?:ectory)?|folder|filename|upload|download|attachment|(?<!\w)src(?!\w)|source)", re.I)),
    ("email",         re.compile(r"(e.?mail)",                                                                        re.I)),
    ("numeric_id",    re.compile(r"(order.?id|product.?id|post.?id|page.?id|categor.{0,3}id|group.?id|doc.?id|thread.?id)", re.I)),
    ("tenant_org",    re.compile(r"(tenant|org(?:aniz)?|company|workspace|team|domain|site.?id)",                    re.I)),
    ("pagination",    re.compile(r"(^page$|^page_?num$|^page_?no$|limit|offset|skip|per.?page|cursor"
                                r"|^start$|^count$|^size$|^num$|^rows$|^length$|^top$|^from$|^take$"
                                r"|page.?size|page.?limit|page.?count|result.?size|result.?count)",  re.I)),
    ("search_filter", re.compile(r"(^search$|^query$|^q$|filter|sort|order.?by|keyword|term)",                       re.I)),
]


# SSTI differential verification: maps known probe payload → (alt_payload, alt_result)
# When confirming SSTI, we fire the alt_payload and verify alt_result appears in response
# but was NOT already present in the baseline — this eliminates coincidental number matches.
# Differential pairs use large/unique results (4+ digits) that are extremely
# unlikely to appear naturally in API response data (IDs, timestamps, etc.)
# This prevents false confirmations caused by common small numbers like "49" or "64"
# coincidentally appearing inside longer numeric fields.
_SSTI_DIFFERENTIAL_PAIRS: dict = {
    "{{7*7}}":        ("{{1777*1777}}", "3157729"),
    "${7*7}":         ("${1777*1777}", "3157729"),
    "#{7*7}":         ("#{1777*1777}", "3157729"),
    "<%= 7*7 %>":     ("<%= 1777*1777 %>", "3157729"),
    "{{7*'7'}}":      ("{{8*'8'}}", "88888888"),
    "${7*'7'}":       ("${8*'8'}", "88888888"),
    "#{7*'7'}":       ("#{8*'8'}", "88888888"),
    "%{7*7}":         ("%{1777*1777}", "3157729"),
    "@{7*7}":         ("@{1777*1777}", "3157729"),
    "[[7*7]]":        ("[[1777*1777]]", "3157729"),
    "{7*7}":          ("{1777*1777}", "3157729"),
    "*{7*7}":         ("*{1777*1777}", "3157729"),
    "{{2+2}}":        ("{{1777*1777}}", "3157729"),
    "${2+2}":         ("${1777*1777}", "3157729"),
    "{{1337*1337}}":  ("{{1777*1777}}", "3157729"),
    "${1337*1337}":   ("${1777*1777}", "3157729"),
    "#{1337*1337}":   ("#{1777*1777}", "3157729"),
    "<%= 1337*1337 %>": ("<%= 1777*1777 %>", "3157729"),
    "%{1337*1337}":   ("%{1777*1777}", "3157729"),
    "*{1337*1337}":   ("*{1777*1777}", "3157729"),
    "${{1337*1337}}": ("${{1777*1777}}", "3157729"),
    "#set($x=1337*1337)$x": ("#set($x=1777*1777)$x", "3157729"),
}


def _ssti_differential_payload(payload: str) -> tuple:
    """Return (alt_payload, expected_result) for a known SSTI probe, or (None, None)."""
    return _SSTI_DIFFERENTIAL_PAIRS.get(payload.strip(), (None, None))


def _token_in_text(text: str, token: str) -> bool:
    """
    Check if `token` appears in `text` as a STANDALONE value —
    i.e. NOT embedded inside a longer alphanumeric string.
    Example: _token_in_text("id=140492", "49") → False  (49 is inside 140492)
             _token_in_text('{"score":49}', "49") → True   (49 is standalone)
    This prevents false-positive confirmation when small numbers like "49"
    coincidentally appear inside larger IDs or timestamps.
    """
    if not text or not token:
        return False
    return bool(re.search(
        r'(?<![0-9A-Za-z_])' + re.escape(token) + r'(?![0-9A-Za-z_])',
        text
    ))


def _text_similarity(a: str, b: str) -> float:
    """Trigram-based Jaccard similarity. Returns 0.0–1.0."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    def _tgrams(s: str):
        s = s.lower()
        return set(s[i:i+3] for i in range(max(0, len(s) - 2)))
    ta, tb = _tgrams(a), _tgrams(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _get_semantic_group(param_name: str, value: str = "") -> str:
    """Return the semantic category for a request parameter."""
    for group, pattern in _PARAM_SEMANTIC_GROUPS:
        if pattern.search(param_name):
            return group
    # Value-shape hints when the name is generic
    if value:
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', value, re.I):
            return "resource_id"
        if re.match(r'^\d{1,10}$', value):
            return "numeric_id"
        if value.startswith(("http://", "https://")):
            return "url_ref"
        if "@" in value and "." in value.split("@")[-1]:
            return "email"
    return "generic"


def _collect_leaf_values(obj, _max: int = 40) -> list:
    """Flatten a JSON object/list to a list of primitive leaf string values."""
    out: list = []
    def _w(o):
        if len(out) >= _max:
            return
        if isinstance(o, dict):
            for v in o.values(): _w(v)
        elif isinstance(o, list):
            for v in o: _w(v)
        elif o is not None:
            s = str(o).strip()
            if len(s) >= 3:
                out.append(s)
    _w(obj)
    return out


def _detect_reflection_context(body: str, value: str) -> str:
    """
    Determine where *value* appears inside *body*.
    Returns one of: 'js_string' | 'attr_value' | 'html_tag' | 'text' | 'none'
    """
    if not body or not value or len(value) < 3:
        return "none"
    idx = body.find(value)
    if idx < 0:
        return "none"
    pre  = body[max(0, idx - 60): idx]
    post = body[idx + len(value): idx + len(value) + 60]
    # Inside a JS string / assignment
    if re.search(r'(var\s+\w+|const\s+\w+|let\s+\w+|=\s*)["\']?$', pre) \
            or re.search(r'^["\']', post):
        return "js_string"
    # Inside an HTML attribute value
    if re.search(r'["\'][^"\'<>]{0,30}$', pre) \
            and re.search(r'^[^"\'<>]{0,30}["\']', post):
        return "attr_value"
    # Inside an HTML tag
    if re.search(r'<[^>]{0,30}$', pre):
        return "html_tag"
    return "text"


def _run_baseline(method: str, url: str, hdrs: dict, body: Optional[str],
                  timeout: int = 10) -> dict:
    """
    Fire the original unmodified request to capture a baseline response.
    Used to compute per-probe deltas and detect WAF / SQL errors in the raw app.
    Never raises — returns an empty-sentinel dict on error.
    """
    empty: dict = {
        "status": 0, "resp_body": "", "resp_headers": {},
        "elapsed_ms": float(timeout * 1000), "error": None,
    }
    try:
        import urllib3 as _urllib3
        _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
        import requests as _req
        skip = {"transfer-encoding", "connection", "host", "content-length"}
        req_hdrs = {k: v for k, v in (hdrs or {}).items() if k.lower() not in skip}
        t0   = time.time()
        resp = _req.request(
            method.upper(), url,
            headers         = req_hdrs,
            data            = body.encode("utf-8") if body else None,
            timeout         = timeout,
            allow_redirects = False,
            verify          = False,
            proxies         = {},   # bypass system proxy (mitmproxy / AV Capture)
        )
        elapsed_ms = (time.time() - t0) * 1000
        return {
            "status":       resp.status_code,
            "resp_body":    resp.text[:4000],
            "resp_headers": dict(resp.headers),
            "elapsed_ms":   elapsed_ms,
            "error":        None,
        }
    except Exception as exc:
        empty["error"] = str(exc)
        return empty


def _analyze_context(baseline: dict, body_raw, url: str) -> dict:
    """
    Analyse the baseline response and request payload to produce context hints.
    The result is stored as job["_ctx"] so probe-level delta logic can use it.
    """
    resp_body = baseline.get("resp_body", "") or ""
    ctx: dict = {
        "sql_error_baseline":       False,
        "redirect_baseline":        False,
        "waf_detected":             False,
        "waf_name":                 "",
        "reflects_input":           False,
        "input_reflection_context": "none",
        "baseline_status":          baseline.get("status", 0),
        "baseline_len":             len(resp_body),
        "baseline_elapsed_ms":      baseline.get("elapsed_ms", 0.0),
        # Full baseline body — used by confirmation step to detect coincidental evidence matches
        "baseline_body":            resp_body,
    }
    resp_hdrs = baseline.get("resp_headers", {}) or {}
    status    = baseline.get("status", 0)

    # Redirect in baseline
    if status in (301, 302, 303, 307, 308):
        ctx["redirect_baseline"] = True

    # SQL errors already present in raw response (misconfigured app)
    for pat in _SQL_ERROR_PATTERNS:
        if pat.search(resp_body):
            ctx["sql_error_baseline"] = True
            break

    # WAF detection via body + header values
    hdr_str  = " ".join(f"{k}: {v}" for k, v in resp_hdrs.items())
    combined = resp_body[:2000] + " " + hdr_str
    for pat, name in _WAF_SIGNATURES:
        if pat.search(combined):
            ctx["waf_detected"] = True
            ctx["waf_name"]     = name
            break

    # Input-reflection: do request body values appear in the response?
    if body_raw:
        try:
            if isinstance(body_raw, str) and body_raw.strip().startswith(("{", "[")):
                obj = json.loads(body_raw)
            elif isinstance(body_raw, dict):
                obj = body_raw
            else:
                obj = None
            if obj:
                for leaf in _collect_leaf_values(obj):
                    if len(leaf) >= 4 and leaf in resp_body:
                        ctx["reflects_input"]           = True
                        ctx["input_reflection_context"] = _detect_reflection_context(resp_body, leaf)
                        break
        except Exception:
            pass

    return ctx


def _confirm_issue(iss_dict: dict, probes: list, timeout: int = 10,
                   baseline_ctx: Optional[dict] = None) -> bool:
    """
    Re-fire the probe that triggered a CRITICAL/HIGH issue to reduce false positives.

    Applies to ALL vulnerability types:

      Layer 1 — Baseline evidence pre-check (universal)
        If the scanner's "expected result" was already present in the baseline
        response BEFORE any injection (e.g. "49" already in a JSON field),
        the match is coincidental → FP. Applies to SSTI, SQLi errors, XSS
        reflection markers, path traversal fragments, etc.

      Layer 2 — SSTI differential probe (SSTI-specific)
        For SSTI, re-fire with a different arithmetic expression ({{8*8}}).
        If "64" appears in the new response but was NOT in the baseline,
        template execution is confirmed. Otherwise → FP.

      Layer 3 — Header injection validation (universal for header params)
        If the parameter is a request header, the server must either:
          (a) reflect the injected value in the response body, OR
          (b) show a measurable status/length change vs. baseline
        If neither → the scanner matched pre-existing data → FP.
        Now uses real baseline_status and baseline_len from the baseline ctx.

      Layer 4 — Standard re-fire (universal)
        Re-fires the probe and checks: status match, body similarity ≥ 0.45,
        payload still reflected (if it was reflected originally).

    Returns True (confirmed real) or False (likely FP).
    On network error → True (conservative: keep the issue).
    """
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
    import requests as _req

    # Unpack baseline context (safe defaults if not provided)
    _bctx         = baseline_ctx or {}
    baseline_body = _bctx.get("baseline_body", "") or ""
    bl_status     = _bctx.get("baseline_status", 0)
    bl_len        = _bctx.get("baseline_len", 0)

    payload  = (iss_dict.get("payload")       or "").strip()
    param    = (iss_dict.get("parameter")     or "").strip()
    vuln     = (iss_dict.get("vulnerability") or "").upper()
    evidence = (iss_dict.get("evidence")      or "")

    # Baseline-only findings (no extra HTTP / no injection probe).
    # Do not bind to a later probe by coincidental payload text.
    if "EXCESSIVE DATA" in vuln:
        return True

    # ── Layer 0: No-observable-change pre-filter (fastest check, runs first) ──
    # If the probe response is essentially IDENTICAL to the baseline
    # (same HTTP status + ≤5% body-length change + ≥80% body similarity),
    # the injection had no effect on the server → always a false positive.
    # This is the primary guard for:
    #   • SSTI/XSS on ignored headers (ngsw-bypass, crutag, content-type, etc.)
    #   • NoSQL/SQLi payloads silently swallowed by the server
    #   • Any probe where the server returned identical data regardless of payload
    #
    # We find the matching probe by checking ALL recorded probes for a
    # status/length match — using fuzzy param matching to handle Scan.py
    # capitalisation variants (e.g. "Ngsw-Bypass" vs "ngsw-bypass").
    _INJECTION_VULN_KEYWORDS = {"SSTI", "SQLI", "SQL", "NOSQL", "XSS",
                                 "INJECTION", "CMDI", "TEMPLATE", "SSRF"}
    _is_injection = any(kw in vuln.replace(" ", "").replace("-", "").replace("(", "")
                        for kw in _INJECTION_VULN_KEYWORDS)
    if _is_injection and bl_status and bl_len:
        # Find ANY probe for this parameter (fuzzy: check param name + payload separately
        # in case Scan.py stores them with different capitalisation)
        _matching_probe: Optional[dict] = None
        _param_lower = param.lower()
        _pl_lower    = payload.lower()
        for _pr in reversed(probes):
            _pr_param = (_pr.get("param") or "").strip().lower()
            _pr_pl    = (_pr.get("payload") or "").strip().lower()
            if _pr_param == _param_lower and _pr_pl == _pl_lower:
                _matching_probe = _pr
                break
        # Fallback: match only by payload if param lookup failed
        if _matching_probe is None and payload:
            for _pr in reversed(probes):
                if (_pr.get("payload") or "").strip().lower() == _pl_lower:
                    _matching_probe = _pr
                    break

        if _matching_probe:
            _p_status   = _matching_probe.get("status", 0)
            _p_body     = _matching_probe.get("resp_body", "") or ""
            _p_len      = len(_p_body)
            _same_status = _p_status == bl_status
            _len_ratio   = abs(_p_len - bl_len) / max(bl_len, 1)
            _len_close   = _len_ratio < 0.05   # within 5% of baseline length
            if _same_status and _len_close:
                _sim = _text_similarity(baseline_body[:400], _p_body[:400])
                if _sim > 0.78:
                    return False   # response identical to baseline → injection had no effect → FP

    # ── Layer 1: Baseline evidence pre-check (ALL vulnerability types) ────────
    # Regex captures the evaluated/matched token from arrow-style evidence:
    #   "Template evaluated: {{7*7}} → 49"   (SSTI)
    #   "SQL error: ... → near syntax"        (SQLi)
    #   "Reflected: <script>alert(1)</script> → found"  (XSS)
    # Uses WORD-BOUNDARY check (_token_in_text) so "49" inside "140492" or
    # "configurationJson...49..." does NOT trigger a false FP dismissal.
    # Only marks as FP if the token appears as a STANDALONE value in baseline.
    if baseline_body:
        ev_match = re.search(r'[→>＞]\s*([0-9A-Za-z_\-]+)\s*$', evidence, re.M)
        if ev_match:
            expected_result = ev_match.group(1)
            # Require minimum length ≥ 3 to avoid trivial single-char matches
            if expected_result and len(expected_result) >= 3 \
                    and _token_in_text(baseline_body, expected_result):
                return False   # result pre-existed as standalone token in baseline → FP

    # ── Find best-matching probe (fuzzy: case-insensitive param + payload) ──────
    best: Optional[dict] = None
    _pl_low  = payload.lower()
    _prm_low = param.lower()
    for pr in reversed(probes):
        if (pr.get("payload") or "").strip().lower() == _pl_low \
                and (pr.get("param") or "").strip().lower() == _prm_low:
            best = pr
            break
    # Fallback: match only by payload (handles param-name capitalisation mismatch)
    if best is None and payload:
        for pr in reversed(probes):
            if (pr.get("payload") or "").strip().lower() == _pl_low:
                best = pr
                break

    if best is None:
        return True   # no recorded probe → conservatively keep

    _skip_hdrs = {"transfer-encoding", "connection", "host"}

    # ── 2. SSTI differential probe ────────────────────────────────────────────
    # Replace the original payload with an alternative arithmetic expression.
    # If the NEW expected result appears in the response but NOT in the baseline,
    # template execution is confirmed. Otherwise mark as FP.
    if "SSTI" in vuln and payload:
        diff_pl, diff_result = _ssti_differential_payload(payload)
        if diff_pl and diff_result:
            try:
                hdrs = {k: v for k, v in (best.get("req_headers") or {}).items()
                        if k.lower() not in _skip_hdrs}
                body = best.get("req_body") or ""

                # Substitute diff_pl for original payload in URL query / header / body
                probe_url   = best.get("url", "")
                substituted = False

                # (a) URL query-param substitution
                try:
                    from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
                    pu = urlparse(probe_url)
                    qp = dict(parse_qsl(pu.query, keep_blank_values=True))
                    if param in qp and qp[param] == payload:
                        qp[param]  = diff_pl
                        probe_url  = urlunparse(pu._replace(query=urlencode(qp)))
                        substituted = True
                except Exception:
                    pass

                # (b) Header substitution
                if not substituted:
                    for hk in list(hdrs):
                        if hk.lower() == param.lower() and str(hdrs[hk]).strip() == payload:
                            hdrs[hk]    = diff_pl
                            substituted = True
                            break

                # (c) JSON body substitution
                if not substituted and body and payload in body:
                    body        = body.replace(payload, diff_pl, 1)
                    substituted = True

                if substituted:
                    bdata = body.encode("utf-8") if isinstance(body, str) and body else None
                    resp  = _req.request(
                        best.get("method", "GET").upper(),
                        probe_url,
                        headers=hdrs, data=bdata,
                        timeout=timeout, allow_redirects=False,
                        verify=False, proxies={},
                    )
                    new_body = resp.text[:3000]
                    # Differential result must appear as STANDALONE token in new response
                    # AND must NOT appear (even as standalone) in the baseline.
                    # Using _token_in_text prevents "3157729" inside "31577290" from matching.
                    diff_in_new      = _token_in_text(new_body, diff_result)
                    diff_in_baseline = _token_in_text(baseline_body or "", diff_result)
                    if diff_in_new and not diff_in_baseline:
                        return True
                    else:
                        return False   # differential failed → FP
            except Exception:
                pass   # network error → fall through to standard check

    # ── Layer 3: Header injection validation (ALL vulnerability types) ──────────
    # Applies whenever the tested parameter is a request HEADER (origin, referer,
    # content-type, x-forwarded-for, user-agent, …).
    # For a header injection to be real, the server must show at least ONE of:
    #   (a) payload reflected somewhere in the response body
    #   (b) HTTP status code different from baseline
    #   (c) Response body length meaningfully different from baseline (> 100 bytes)
    # If NONE of (a/b/c) → the evidence came from pre-existing data → FP.
    #
    # Uses real bl_status / bl_len from baseline_ctx (not hardcoded zeros).
    if param and best:
        req_hdrs_lower  = {k.lower() for k in (best.get("req_headers") or {})}
        param_is_header = param.lower() in req_hdrs_lower
        if param_is_header and payload:
            orig_resp_body   = best.get("resp_body", "") or ""
            orig_status_code = best.get("status", 0)
            orig_body_len    = len(orig_resp_body)
            # (a) payload reflected?
            payload_reflected = payload in orig_resp_body
            # (b) status changed from baseline?
            status_changed    = bool(bl_status) and orig_status_code != bl_status
            # (c) length changed significantly from baseline?
            len_changed       = bool(bl_len) and abs(orig_body_len - bl_len) > 100
            if not payload_reflected and not status_changed and not len_changed:
                return False   # no observable impact → FP

    # ── Layer 3a: IDOR on pagination parameters → always FP ─────────────────
    # `offset`, `size`, `limit`, `page` etc. control which slice of data is
    # returned. Changing them gives a different page — expected behaviour,
    # not an access-control bypass.  Real IDOR params (userId, orderId …)
    # have semantic groups like user_id / resource_id / numeric_id and are
    # unaffected by this check.
    _vuln_flat_idor = vuln.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if "IDOR" in _vuln_flat_idor or "BOLA" in _vuln_flat_idor or "BROKENOBJECT" in _vuln_flat_idor:
        if _get_semantic_group(param, payload) == "pagination":
            return False   # pagination parameter → FP

    # ── Layer 3b: NoSQL Error-Based differential ─────────────────────────────
    # For error-based NoSQL injection to be real, the server must show BOTH:
    #   (a) Inject `'`  → NoSQL error pattern in response (error triggered)
    #   (b) Inject `''` → response similar to baseline (server recovers)
    # If only (a) without (b), or if the probe response is identical to baseline,
    # it is a false positive (server ignores/escapes the quote silently).
    if "NOSQL" in vuln.replace(" ", "").replace("-", "").upper() and best:
        try:
            probe_url = best.get("url", "")
            hdrs_ns   = {k: v for k, v in (best.get("req_headers") or {}).items()
                         if k.lower() not in _skip_hdrs}
            body_ns   = best.get("req_body") or ""
            orig_probe_body = best.get("resp_body", "") or ""

            def _nosql_sub(url, hdrs, body, new_val):
                """Substitute new_val for the tested param. Returns (url, hdrs, body)."""
                u, h, b = url, dict(hdrs), body
                # URL query param
                try:
                    from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
                    pu = urlparse(u)
                    qp = dict(parse_qsl(pu.query, keep_blank_values=True))
                    if param in qp:
                        qp[param] = new_val
                        u = urlunparse(pu._replace(query=urlencode(qp)))
                        return u, h, b
                except Exception:
                    pass
                # Header
                for hk in list(h):
                    if hk.lower() == param.lower():
                        h[hk] = new_val
                        return u, h, b
                # JSON body
                if b and payload in b:
                    b = b.replace(payload, new_val, 1)
                return u, h, b

            # (a) Re-fire with `'` — must produce a NoSQL error
            u_a, h_a, b_a = _nosql_sub(probe_url, hdrs_ns, body_ns, "'")
            resp_a = _req.request(best.get("method", "GET").upper(), u_a,
                                  headers=h_a, data=b_a.encode() if isinstance(b_a, str) and b_a else None,
                                  timeout=timeout, allow_redirects=False, verify=False, proxies={})
            body_a = resp_a.text[:3000]
            has_error = any(p.search(body_a) for p in _NOSQL_ERROR_PATTERNS)

            # (b) Re-fire with `''` — must return a NORMAL response (no error, similar to probe)
            u_b, h_b, b_b = _nosql_sub(probe_url, hdrs_ns, body_ns, "''")
            resp_b = _req.request(best.get("method", "GET").upper(), u_b,
                                  headers=h_b, data=b_b.encode() if isinstance(b_b, str) and b_b else None,
                                  timeout=timeout, allow_redirects=False, verify=False, proxies={})
            body_b   = resp_b.text[:3000]
            no_error = not any(p.search(body_b) for p in _NOSQL_ERROR_PATTERNS)
            recovers = _text_similarity(baseline_body[:500] or orig_probe_body[:500], body_b[:500]) > 0.6

            if has_error and no_error and recovers:
                return True    # differential confirmed: error with ' and recovery with ''
            else:
                return False   # no differential → FP

        except Exception:
            pass   # network error → fall through to standard check

    # ── Layer 3c: SSRF confirmation ───────────────────────────────────────────
    # Re-fire the probe and verify the response contains genuine internal-resource
    # indicators (AWS IMDS, GCP/Azure metadata, /etc/passwd, etc.).
    # Covers all injection locations — query params, headers (referer/origin/host),
    # and JSON body fields.
    # If the probe response has NO indicators → server never fetched the URL → FP.
    _ssrf_flat = vuln.replace(" ", "").replace("-", "").upper()
    if "SSRF" in _ssrf_flat and "TIMEBASED" not in _ssrf_flat and best:
        try:
            _orig_probe_body = best.get("resp_body", "") or ""
            # Fast path: if the original probe already lacks real indicators → FP
            if not _SSRF_REAL_INDICATORS.search(_orig_probe_body):
                return False   # no internal resource content → FP

            # Re-fire to verify it's reproducible
            hdrs_sf = {k: v for k, v in (best.get("req_headers") or {}).items()
                       if k.lower() not in _skip_hdrs}
            bdata_sf = best.get("req_body") or None
            if isinstance(bdata_sf, str) and bdata_sf:
                bdata_sf = bdata_sf.encode("utf-8")
            else:
                bdata_sf = None
            resp_sf = _req.request(
                best.get("method", "GET").upper(), best.get("url", ""),
                headers=hdrs_sf, data=bdata_sf,
                timeout=timeout, allow_redirects=False, verify=False, proxies={},
            )
            new_body_sf = resp_sf.text[:3000]
            if _SSRF_REAL_INDICATORS.search(new_body_sf):
                return True   # confirmed: internal resource indicators reproduced
            else:
                return False  # indicators not reproducible → FP
        except Exception:
            pass   # network error → fall through

    # ── 4. Standard confirmation re-fire ─────────────────────────────────────
    try:
        hdrs  = {k: v for k, v in (best.get("req_headers") or {}).items()
                 if k.lower() not in _skip_hdrs}
        bdata = best.get("req_body") or None
        if isinstance(bdata, str) and bdata:
            bdata = bdata.encode("utf-8")
        else:
            bdata = None

        resp = _req.request(
            best.get("method", "GET").upper(),
            best.get("url", ""),
            headers         = hdrs,
            data            = bdata,
            timeout         = timeout,
            allow_redirects = False,
            verify          = False,
            proxies         = {},
        )

        orig_status = best.get("status", 0)
        orig_body   = best.get("resp_body", "") or ""
        new_body    = resp.text[:3000]

        if resp.status_code != orig_status:
            return False

        sim = _text_similarity(orig_body[:500], new_body[:500])
        if sim < 0.45:
            return False

        # If payload was reflected in original, it must still be reflected
        # Use word-boundary check so partial embedding in longer strings doesn't count
        if payload and len(payload) >= 3 and _token_in_text(orig_body, payload):
            return _token_in_text(new_body, payload)

        return sim > 0.65

    except Exception:
        return True   # network error → keep issue


_INLINE_FP_VULN_KEYWORDS = frozenset({
    "SSTI", "SQLI", "SQL", "NOSQL", "XSS", "INJECTION", "CMDI", "TEMPLATE", "SSRF",
    "IDOR", "BOLA", "BROKENOBJECT",
})

# Keywords that indicate genuine SSRF — these appear in real internal resource responses
# (AWS IMDS, GCP metadata, Azure IMDS, local service responses).
# If NONE of these appear in the probe response, the "evidence" came from
# coincidental data (e.g. "iam" inside a normal JSON field/URL).
_SSRF_REAL_INDICATORS = re.compile(
    r'ami\-id|instance\-id|local\-ipv4|public\-hostname|public\-ipv4'
    r'|computeMetadata|project\-id|subscriptionId|resourceGroupName'
    r'|169\.254\.169\.254|metadata\.google\.internal'
    r'|root:x:0:0|/etc/passwd|/etc/shadow'  # LFI via SSRF
    r'|aws_access_key|aws_secret|ec2metadata|ec2ws|imdsv2'
    r'|x-aws-ec2-metadata-token'
    r'|AccessKeyId|instanceProfileArn|azEnvironment'
    r'|Missing Metadata|Metadata header is required',
    re.I
)


def _inline_fp_check(iss_dict: dict, probes: list, ctx: dict) -> bool:
    """
    Lightweight Layer-0 FP check — runs INLINE during scan (no network calls).
    Returns True if the issue is almost certainly a false positive and should be
    suppressed immediately from live results.

    Logic: if the probe that triggered this issue produced a response that is
    essentially identical to the baseline (same status + <5% length change +
    >78% body similarity), the injection had no observable effect → FP.

    Called from _live_issue_ctor so FPs never appear on screen even briefly.
    """
    payload   = (iss_dict.get("payload")       or "").strip()
    param     = (iss_dict.get("parameter")     or "").strip()
    vuln_raw  = (iss_dict.get("vulnerability") or "").upper()
    vuln_flat = vuln_raw.replace(" ", "").replace("-", "").replace("(", "")

    bl_status = ctx.get("baseline_status", 0)
    bl_len    = ctx.get("baseline_len", 0)
    bl_body   = ctx.get("baseline_body", "") or ""

    # Only apply to injection-type vulnerabilities
    if not any(kw in vuln_flat for kw in _INLINE_FP_VULN_KEYWORDS):
        return False
    # Time-based / blind findings prove themselves with latency, not body diff.
    if "TIMEBASED" in vuln_flat:
        return False
    if not bl_status or not bl_len:
        return False   # no baseline → can't compare

    # Find the most recent probe matching this payload + param (fuzzy / case-insensitive)
    pl_low  = payload.lower()
    prm_low = param.lower()
    matching: Optional[dict] = None
    for pr in reversed(probes):
        if (pr.get("payload") or "").strip().lower() == pl_low \
                and (pr.get("param") or "").strip().lower() == prm_low:
            matching = pr
            break
    # Fallback: match only by payload if param name casing differs
    if matching is None and payload:
        for pr in reversed(probes):
            if (pr.get("payload") or "").strip().lower() == pl_low:
                matching = pr
                break

    if matching is None:
        return False   # no probe found → can't judge → keep issue

    p_status = matching.get("status", 0)
    p_body   = matching.get("resp_body", "") or ""
    p_len    = len(p_body)

    if p_status != bl_status:
        return False   # status changed → real impact, keep issue

    len_ratio = abs(p_len - bl_len) / max(bl_len, 1)
    if len_ratio >= 0.05:
        return False   # >5% length change → real impact, keep issue

    sim = _text_similarity(bl_body[:400], p_body[:400])
    return sim > 0.78   # highly similar → injection had no effect → FP


# ── Direct param extractor ─────────────────────────────────────────────────────
# Bypasses Scan.py / CurlParser so dict bodies (from AV Capture) work too.

def _flatten_json_params(obj, prefix: str, entry_id: str, result: list,
                         depth: int = 0, max_depth: int = 4):
    """Recursively flatten a parsed JSON object into param dicts."""
    if depth > max_depth:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                _flatten_json_params(v, path, entry_id, result, depth + 1, max_depth)
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        _flatten_json_params(item, f"{path}[{i}]", entry_id, result, depth + 1, max_depth)
                    else:
                        result.append({
                            "entry_id":      entry_id,
                            "param_name":    f"{path}[{i}]",
                            "location":      "body_json",
                            "current_value": str(item) if item is not None else "",
                        })
            else:
                result.append({
                    "entry_id":      entry_id,
                    "param_name":    path,
                    "location":      "body_json",
                    "current_value": str(v) if v is not None else "",
                })
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, dict):
                _flatten_json_params(item, f"[{i}]", entry_id, result, depth + 1, max_depth)


def _extract_entry_params(entry: dict) -> list:
    """
    Extract testable parameters from an entry dict (handles str / dict / list body).
    Returns list of {entry_id, param_name, location, current_value, entry_method, entry_url}.
    """
    entry_id = entry.get("id", "")
    method   = entry.get("method", "GET").upper()
    url      = entry.get("url", "")
    hdrs     = entry.get("headers") or {}
    body_raw = entry.get("body")

    result = []

    # ── 1. URL query params ──────────────────────────────────────────────
    try:
        parsed = urlparse(url)
        for name, vals in parse_qs(parsed.query, keep_blank_values=True).items():
            result.append({
                "entry_id":      entry_id,
                "param_name":    name,
                "location":      "query",
                "current_value": vals[0] if vals else "",
            })
    except Exception:
        pass

    # ── 2. Body params ───────────────────────────────────────────────────
    if body_raw is not None and body_raw not in ("", {}, []):
        # Already a parsed dict / list (AV Capture stores body as Python object)
        if isinstance(body_raw, dict):
            _flatten_json_params(body_raw, "", entry_id, result)
        elif isinstance(body_raw, list) and body_raw:
            first = body_raw[0]
            if isinstance(first, dict):
                _flatten_json_params(first, "", entry_id, result)
        elif isinstance(body_raw, str):
            body_str = body_raw.strip()
            if body_str:
                ct = ""
                for k, v in hdrs.items():
                    if str(k).lower() == "content-type":
                        ct = str(v).lower()
                        break

                is_json = body_str.startswith(("{", "[")) or "application/json" in ct
                if is_json:
                    try:
                        obj = json.loads(body_str)
                        if isinstance(obj, dict):
                            _flatten_json_params(obj, "", entry_id, result)
                        elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                            _flatten_json_params(obj[0], "", entry_id, result)
                    except Exception:
                        pass
                else:
                    try:
                        form_params = parse_qs(body_str, keep_blank_values=True)
                        for name, vals in form_params.items():
                            # Skip false-positive: entire JSON blob parsed as one key
                            if name.strip().startswith(("{", "[")):
                                continue
                            result.append({
                                "entry_id":      entry_id,
                                "param_name":    name,
                                "location":      "body_form",
                                "current_value": vals[0] if vals else "",
                            })
                    except Exception:
                        pass

    # ── 3. Interesting custom headers (userid, customerid, session, etc.) ────
    for hdr_name, hdr_val in hdrs.items():
        hl = hdr_name.lower()
        if hl in _REGEN_SKIP_HEADERS:
            continue
        val_str = str(hdr_val or "").strip()
        # Only include headers whose name suggests an ID/token and whose value
        # looks like a numeric ID, UUID, or short token (not a mega JWT)
        if len(val_str) > 128:
            continue
        if _INTERESTING_HDR_RE.search(hl) and val_str:
            result.append({
                "entry_id":      entry_id,
                "param_name":    hdr_name,
                "location":      "header",
                "current_value": val_str,
            })

    # Fill in entry metadata + semantic grouping on every param
    for p in result:
        p["entry_method"]    = method
        p["entry_url"]       = url
        p["semantic_group"]  = _get_semantic_group(p["param_name"], p.get("current_value", ""))

    return result


def _issue_to_dict(iss, entry_url: str) -> dict:
    d = vars(iss).copy()
    if not d.get("url"):
        d["url"] = entry_url
    return d


def _find_attack_probe(d: dict, entry: dict, probes: list) -> Optional[dict]:
    """
    Best probe that represents the request which triggered this issue.
    Used so Results → Copy cURL can paste the exact attack request (not baseline).
    """
    if not probes:
        return None
    iss_pl   = (d.get("payload") or "").strip()
    iss_pm   = (d.get("parameter") or "").strip()
    iss_url  = (d.get("url") or entry.get("url") or "").split("?")[0].rstrip("/")
    pl_low   = iss_pl.lower()
    pm_low   = iss_pm.lower()
    base_hdr = {str(k).lower(): str(v) for k, v in (entry.get("headers") or {}).items()}

    # 1) Exact payload + param
    if iss_pl:
        for pr in reversed(probes):
            if (pr.get("payload") or "").strip().lower() == pl_low \
                    and (pr.get("param") or "").strip().lower() == pm_low:
                return pr

    # 1b) Param name (mass-assign uses path labels like icon / creator.customerId;
    #     issue.payload is "icon='MA_icon'" which never equals probe.payload '"MA_icon"').
    _GENERIC_PM = {"", "body_json", "request body", "endpoint", "query", "header"}
    param_names = [p.strip().lower() for p in re.split(r"[,;]", iss_pm) if p.strip()]
    param_names = [p for p in param_names if p not in _GENERIC_PM]
    if param_names:
        for pr in reversed(probes):
            pr_pm = (pr.get("param") or "").strip().lower()
            if pr_pm and pr_pm in param_names:
                return pr
        # Canary in this probe's body (e.g. MA_icon)
        needles = []
        for raw in (iss_pl,):
            m = re.search(r"['\"]([A-Za-z0-9_.+-]+)['\"]", raw)
            if m:
                needles.append(m.group(1).lower())
            m2 = re.search(r"=\s*(.+)$", raw)
            if m2:
                needles.append(m2.group(1).strip(" '\"").lower())
        for pr in reversed(probes):
            blob = ((pr.get("payload") or "") + " " + (pr.get("req_body") or "")).lower()
            if any(n and n in blob for n in needles):
                return pr

    # 2) Payload only
    if iss_pl:
        for pr in reversed(probes):
            if (pr.get("payload") or "").strip().lower() == pl_low:
                return pr

    vuln = (d.get("vulnerability") or "").lower()
    mod_hints = []
    if "jwt" in vuln:
        mod_hints.append("jwt")
    if "cors" in vuln:
        mod_hints.append("cors")
    if "graphql" in vuln:
        mod_hints.append("graphql")
    if "mass" in vuln:
        mod_hints.append("massassign")

    # 3) Header mutation (JWT alg:none, CORS, …): issue.payload may be a label
    #    like "alg=none" while the probe carries the real forged header value.
    #    Prefer same module when known, so a later unrelated header probe loses.
    if iss_pm:
        candidates = []
        for pr in reversed(probes):
            pr_url = (pr.get("url") or "").split("?")[0].rstrip("/")
            if iss_url and pr_url and pr_url != iss_url:
                continue
            for hk, hv in (pr.get("req_headers") or {}).items():
                if str(hk).lower() != pm_low:
                    continue
                if str(hv) and str(hv) != base_hdr.get(pm_low, ""):
                    candidates.append(pr)
                    break
        if candidates:
            if mod_hints:
                for pr in candidates:
                    if (pr.get("module") or "").lower() in mod_hints:
                        return pr
            return candidates[0]  # most recent differing header

    # 4) Module hint + same URL base (CORS / GraphQL / JWT endpoint checks).
    #    Skip for mass-assign when a specific field is named — otherwise the
    #    last privilege-inject probe wins and Copy cURL hides icon/deleted/…
    if not param_names:
        for hint in mod_hints:
            for pr in reversed(probes):
                if (pr.get("module") or "").lower() != hint:
                    continue
                pr_url = (pr.get("url") or "").split("?")[0].rstrip("/")
                if iss_url and pr_url and pr_url != iss_url:
                    continue
                return pr
    return None


def _attach_attack_request(d: dict, entry: dict, probes: list) -> None:
    """
    Attach attack_request {method,url,headers,body} — entry baseline with the
    probe's mutated fields overlaid — so UI Copy cURL is Postman-ready.
    """
    if d.get("attack_request"):
        return
    pr = _find_attack_probe(d, entry, probes)
    method = (entry.get("method") or (pr or {}).get("method") or "GET")
    url    = entry.get("url") or d.get("url") or ""
    body   = (d.get("attack_body") or "").strip() or (entry.get("body") or "")
    hdrs   = dict(entry.get("headers") or {})

    if pr:
        method = pr.get("method") or method
        if pr.get("url"):
            url = pr["url"]
        # Overlay headers that actually changed; keep browser UA / cookies from entry
        _skip = {"content-length", "host", "transfer-encoding", "connection",
                 "accept-encoding"}
        base_l = {str(k).lower(): str(v) for k, v in hdrs.items()}
        for k, v in (pr.get("req_headers") or {}).items():
            kl = str(k).lower()
            if kl in _skip:
                continue
            if kl == "user-agent" and "python-requests" in str(v).lower():
                continue
            if str(v) != base_l.get(kl, ""):
                ek = next((x for x in hdrs if str(x).lower() == kl), k)
                hdrs[ek] = v
        pr_body = pr.get("req_body") or ""
        if not (d.get("attack_body") or "").strip() and pr_body and pr_body != (body or ""):
            body = pr_body

    # No probe and nothing useful — still expose baseline so Copy never empty
    d["attack_request"] = {
        "method":  method,
        "url":     url,
        "headers": hdrs,
        "body":    body or "",
    }


def _augment_response_snippet(d: dict, entry_url: str, probes: list) -> None:
    """
    If the Issue has no response_snippet (common for IDOR / Business Logic /
    passive checks), find the best-matching probe and build a Burp-style
    snippet:  HTTP <status>\\n<response-headers>\\n\\n<response-body>
    Matching strategy:
      1. Payload match — probe.payload == iss.payload  (active injection)
      2. URL match     — probe.url base == entry_url   (passive / no payload)
    """
    if d.get("response_snippet"):
        return   # already populated by Scan.py

    iss_pl  = (d.get("payload") or "").strip()
    iss_url = (d.get("url") or entry_url or "").split("?")[0].rstrip("/")

    for pr in reversed(probes):
        pr_body = pr.get("resp_body") or ""
        if not pr_body:
            continue
        pr_pl  = (pr.get("payload") or "").strip()
        pr_url = pr.get("url", "").split("?")[0].rstrip("/")

        matched = (
            (iss_pl  and pr_pl  == iss_pl)                       # active: payload matches
            or (not iss_pl and pr_url and pr_url == iss_url)      # passive: URL base matches
        )
        if not matched:
            continue

        status    = pr.get("status", "?")
        resp_hdrs = "\n".join(
            f"{k}: {v}" for k, v in (pr.get("resp_headers") or {}).items()
        )
        snippet = f"HTTP {status}"
        if resp_hdrs:
            snippet += f"\n{resp_hdrs}"
        snippet += f"\n\n{pr_body}"
        d["response_snippet"] = snippet[:6000]
        break


# ── Scan runner ────────────────────────────────────────────────────────────────

def _do_scan_entry(job_id: str, entry: dict, entry_idx: int, total: int):
    """Run Scan.py against a single entry and update the job dict."""
    job    = jobs[job_id]
    if job.get("stopped"):
        return

    method = entry.get("method", "GET").upper()
    url    = entry.get("url", "")
    hdrs   = dict(entry.get("headers") or {})
    # Mid-scan token refresh (session handling Mode A)
    if job.get("auth_headers"):
        hdrs = _apply_auth_headers(hdrs, job["auth_headers"])
    # Normalise body: AV Capture may store a dict/list instead of a raw string
    body   = _normalise_body(entry.get("body"))

    logs         = job["logs"]
    profile      = job["profile"]
    threads      = job["threads"]
    timeout      = job["timeout"]
    delay_sec    = float(job.get("delay_sec") or 0)
    modules      = job.get("modules") or []
    skip_modules = job.get("skip_modules") or []
    oob_server   = job.get("oob_server")    # None unless OOB enabled in the UI
    oob_token    = job.get("oob_token")
    stop_event   = job.get("_stop_event")   # threading.Event for mid-probe abort
    entry_id     = entry.get("id", "")
    customs_all  = job.get("custom_values", [])
    # Only this entry's custom values
    customs = [c for c in customs_all if c.get("entry_id") == entry_id]

    # Split: static values substituted once; regen values re-applied per probe
    static_customs = [c for c in customs if not c.get("regen_per_probe")]
    regen_customs  = [c for c in customs if c.get("regen_per_probe")]

    # Apply static custom values once into the base request
    method, url, hdrs, body = _apply_custom_values(method, url, hdrs, body or "", static_customs)
    if not body:
        body = None

    # ── Base64-encoded param expansion ────────────────────────────────────────
    # If the body contains fields like "encodedValue" whose values are
    # base64-encoded JSON, expand them so Scan.py can test the inner parameters.
    # The original (encoded) body is kept for the baseline request.
    # _patched_send will re-encode the modified inner JSON back to base64
    # before each probe is sent to the server, so the server always receives
    # the correctly encoded payload.
    _b64_fields: dict = {}
    _baseline_body    = body   # always use original encoded body for baseline
    if body:
        _expanded_body, _b64_fields = _detect_expand_b64_params(body)
        if _b64_fields:
            body = _expanded_body
            logs.append({
                "text":  f"[i] Base64 param(s) detected: {list(_b64_fields.keys())} — expanding for deep scan",
                "level": "info",
                "ts":    time.time(),
            })

    # ── Baseline request + context pre-analysis ───────────────────────────────
    # Fire the original un-modified request first to:
    #   • establish baseline status / length / timing for delta comparison
    #   • detect WAF signatures before probing starts
    #   • flag SQL errors already present in the raw app response
    #   • detect input reflection (XSS/injection risk signal)
    _bl = _run_baseline(method, url, hdrs, _baseline_body, timeout)
    _ctx = _analyze_context(_bl, body, url)
    job["_ctx"] = _ctx   # shared by _patched_send for per-probe delta

    _bl_note = (
        f"[i] Baseline → HTTP {_ctx['baseline_status']} · "
        f"{_ctx['baseline_len']}b · {_ctx['baseline_elapsed_ms']:.0f}ms"
    )
    if _bl.get("error"):
        _bl_note += f" (err: {_bl['error']})"
    logs.append({"text": _bl_note, "level": "info", "ts": time.time()})

    if _ctx["waf_detected"]:
        logs.append({"text": f"[!] WAF detected: {_ctx['waf_name']}", "level": "high", "ts": time.time()})
    if _ctx["sql_error_baseline"]:
        logs.append({"text": "[!] SQL errors in baseline response — injection results may be noisy", "level": "high", "ts": time.time()})
    if _ctx["redirect_baseline"]:
        logs.append({"text": f"[i] Baseline redirects (HTTP {_ctx['baseline_status']}) — redirect-based checks enabled", "level": "info", "ts": time.time()})
    if _ctx["reflects_input"]:
        logs.append({"text": f"[i] Input reflected in baseline ({_ctx['input_reflection_context']}) — XSS/injection risk elevated", "level": "info", "ts": time.time()})

    # Update progress label.
    # Use job["total_queued"] as the denominator so the % is correct even when
    # the user adds more entries mid-scan via /apiscan/queue/{job_id}.
    live_total = job.get("total_queued", total) or total
    job["progress"]["api"]            = f"{method} {url}"
    job["progress"]["current"]        = entry_idx + 1
    job["progress"]["total"]          = live_total
    job["progress"]["pct"]            = int(entry_idx / live_total * 100)
    # Store the full entry so the partial live-results entry carries real headers/body
    job["progress"]["current_entry"]  = entry

    # Load a fresh Scan module (compiled once; unloaded in _run_job finally)
    uid = uuid.uuid4().hex
    try:
        scan = _load_scan(uid)
        job["_active_scan_uid"] = uid
    except Exception as e:
        logs.append({"text": f"[!] Failed to import Scan.py: {e}", "level": "high", "ts": time.time()})
        return

    # ── Bypass system proxy for ALL scan probes ───────────────────────────────
    # When AV Capture is active, macOS system proxy is set to mitmproxy
    # (127.0.0.1:8768). Python's requests library respects the system proxy,
    # so every scan probe would flow through mitmproxy and appear in AV Capture.
    # Fix: clear proxies + disable trust_env on RequestSender's session so scan
    # traffic never touches mitmproxy. This is per-module-instance — no global
    # side effects on other threads or tools.
    try:
        _rs_orig_init = scan.RequestSender.__init__
        def _rs_no_proxy_init(self_rs, *_a, **_kw):
            _rs_orig_init(self_rs, *_a, **_kw)
            # Cooperative abort from UI Stop → Scan.py _raw / run_task checks this
            if stop_event is not None:
                self_rs._stop_event = stop_event
            # RequestSender may store its session under different attribute names
            for _attr in ('session', '_session', 'http', 'client', 'sess', 's'):
                _sess = getattr(self_rs, _attr, None)
                if _sess is not None and hasattr(_sess, 'proxies'):
                    _sess.proxies.clear()        # remove any system/mitmproxy URL
                    _sess.trust_env = False       # stop reading HTTP_PROXY / system proxy
                    # Apply global Settings proxy if user configured one
                    try:
                        import proxy_config as _pc
                        _global = _pc.get_proxies()
                        if _global:
                            _sess.proxies.update(_global)
                    except Exception:
                        pass
                    break
        scan.RequestSender.__init__ = _rs_no_proxy_init
    except Exception:
        pass   # never break the scan if patching fails

    # ── Patch tprint ──────────────────────────────────────────────────────────
    # Also extracts the total-task count from Scan.py's "Active Scan — N …"
    # line so we can show accurate per-task % progress.
    _total_tasks = [0]   # filled once run_scan() logs the active-scan header
    _done_tasks  = [0]   # incremented by the module.scan wrapper below

    def _tprint(*args, **kwargs):
        raw   = " ".join(str(a) for a in args)
        clean = _strip_ansi(raw)
        if not clean:
            return
        # "Active Scan — 142 context-filtered checks | 6 threads"
        m = re.search(r'Active Scan\s*[—\-]\s*(\d+)\s+context', clean, re.I)
        if m:
            _total_tasks[0] = int(m.group(1))
            _done_tasks[0]  = 0
        lvl = "info"
        if "CRITICAL" in clean:
            lvl = "critical"
        elif any(x in clean for x in ["[!]", "HIGH"]):
            lvl = "high"
        elif "MEDIUM" in clean:
            lvl = "medium"
        elif "LOW" in clean:
            lvl = "low"
        elif "[✓]" in clean:
            lvl = "ok"
        logs.append({"text": clean, "level": lvl, "ts": time.time()})

    scan.tprint = _tprint
    scan.vprint = _tprint   # also capture verbose prints

    # ── Track which scanner module is currently running (per-thread) ─────────
    # Each (point, mk, module) task runs in its own ThreadPoolExecutor worker,
    # so a thread-local lets _patched_send tag every recorded probe with the
    # module that triggered it — used by the UI's Module/Category probe filter.
    _scan_module_ctx = threading.local()

    # ── Patch RequestSender.send — probe list + per-probe regen ─────────────
    _orig_send = scan.RequestSender.send

    def _patched_send(self_r, point, payload, retry=1, allow_redirects=True):
        # Abort mid-entry: skip further probes immediately
        if job.get("stopped") or (stop_event is not None and stop_event.is_set()):
            return None
        # Session expired — block until user pastes a fresh token (or Stop)
        if not _wait_while_auth_paused(job, stop_event):
            return None
        _sync_sender_auth(job, self_r)

        # ── Per-probe unique value regeneration ───────────────────────────────
        #
        # body_json probes: point['_root_json'] is present.
        #   → shadow the point dict with a fresh root (thread-safe, no lock needed).
        #
        # query / header / cookie / path_segment probes: _root_json is None.
        #   Scan.py sends self.base.body as-is for these probe types.
        #   → We must patch self_r.base.body / url / headers under a lock.
        #
        # body_form / body_raw probes: also use self_r.base.body.
        #   → Same lock approach.
        #
        # All cases add a small inter-probe delay to prevent API uniqueness races.

        actual_point  = point
        sender_to_use = self_r

        # If base request params or b64 fields need per-probe customization,
        # use an isolated shadow sender so threads never mutate shared state
        # or block each other during network I/O.
        if regen_customs or _b64_fields:
            shadow_base   = _ShadowBase(self_r.base)
            sender_to_use = _ShadowSender(self_r, shadow_base)

        if regen_customs:
            tested_name = point.get("name", "")
            has_root    = point.get("_root_json") is not None

            # Separate what each cv wants
            json_cvs  = [c for c in regen_customs
                         if c.get("location") == "body_json"
                         and c.get("param_name", "") != tested_name]
            other_cvs = [c for c in regen_customs
                         if c.get("location") in ("query", "body_form", "header")
                         and c.get("param_name", "") != tested_name]

            # ── Case A: body_json probe — shadow _root_json
            if json_cvs and has_root:
                try:
                    shadow_root = json.loads(json.dumps(point["_root_json"]))
                    for cv in json_cvs:
                        pname = cv.get("param_name", "")
                        if not pname:
                            continue
                        fresh_str = _fresh_val(cv)
                        orig_at   = _json_get_path(shadow_root, pname)
                        fresh     = _coerce_val(fresh_str, orig_at) \
                                    if orig_at is not None else fresh_str
                        _json_set_path(shadow_root, pname, fresh)
                    actual_point = dict(point)
                    actual_point["_root_json"] = shadow_root
                except Exception:
                    pass

            # ── Case B: non-body_json probe OR query/header/form cvs
            base_body_cvs = json_cvs if not has_root else []
            all_base_cvs  = other_cvs + base_body_cvs

            if all_base_cvs:
                for cv in all_base_cvs:
                    pname = cv.get("param_name", "")
                    loc   = cv.get("location", "")
                    if not pname:
                        continue
                    fresh = _fresh_val(cv)

                    if loc == "body_json":
                        try:
                            raw = sender_to_use.base.body or "{}"
                            parsed = json.loads(raw)
                            orig_at = _json_get_path(parsed, pname)
                            fv = _coerce_val(fresh, orig_at) \
                                 if orig_at is not None else fresh
                            _json_set_path(parsed, pname, fv)
                            sender_to_use.base.body = json.dumps(parsed)
                        except Exception:
                            pass

                    elif loc == "query" and sender_to_use.base.url:
                        try:
                            parsed_url = urlparse(sender_to_use.base.url)
                            pars = dict(parse_qsl(parsed_url.query,
                                                  keep_blank_values=True))
                            pars[pname] = fresh
                            sender_to_use.base.url = urlunparse(
                                parsed_url._replace(query=urlencode(pars)))
                        except Exception:
                            pass

                    elif loc == "body_form" and sender_to_use.base.body is not None:
                        try:
                            pars = dict(parse_qsl(sender_to_use.base.body or "",
                                                  keep_blank_values=True))
                            pars[pname] = fresh
                            sender_to_use.base.body = urlencode(pars)
                        except Exception:
                            pass

                    elif loc == "header":
                        try:
                            sender_to_use.base.headers[pname] = fresh
                        except Exception:
                            pass

        # ── Re-encode base64 params before sending
        if _b64_fields:
            try:
                # (1) Re-encode in sender_to_use.base.body (covers non-_root_json probes)
                if sender_to_use.base.body:
                    _new_b = _reencode_b64_params(sender_to_use.base.body, _b64_fields)
                    if _new_b != sender_to_use.base.body:
                        sender_to_use.base.body = _new_b
                # (2) Re-encode in actual_point["_root_json"] (covers JSON body probes)
                if actual_point.get("_root_json") is not None:
                    _rj = json.loads(json.dumps(actual_point["_root_json"]))
                    _rj_changed = False
                    for _bk in _b64_fields:
                        if _bk in _rj and isinstance(_rj[_bk], (dict, list)):
                            _rj[_bk] = _base64.b64encode(
                                json.dumps(_rj[_bk]).encode("utf-8")
                            ).decode("utf-8")
                            _rj_changed = True
                    if _rj_changed:
                        actual_point = dict(actual_point)
                        actual_point["_root_json"] = _rj
            except Exception:
                pass

        resp = _orig_send(sender_to_use, actual_point, payload, retry, allow_redirects)
        if resp is not None:
            try:
                rb = resp.request.body or ""
                if isinstance(rb, bytes):
                    rb = rb.decode("utf-8", errors="replace")
                _rb_text  = resp.text[:3000]
                _pl_str   = str(payload)[:300] if payload is not None else ""
                _bctx     = job.get("_ctx") or {}
                _elapsed  = resp.elapsed.total_seconds() * 1000 \
                            if hasattr(resp, "elapsed") and resp.elapsed else 0.0
                _bl_ms    = _bctx.get("baseline_elapsed_ms", 0.0) or 1.0
                _bl_st    = _bctx.get("baseline_status", 0)
                _bl_ln    = _bctx.get("baseline_len", 0)
                _bl_bd    = _bctx.get("baseline_body", "") or ""
                _likely_fp = bool(
                    _bl_st and _bl_ln
                    and resp.status_code == _bl_st
                    and abs(len(_rb_text) - _bl_ln) / max(_bl_ln, 1) < 0.05
                    and _text_similarity(_bl_bd[:400], _rb_text[:400]) > 0.78
                )
                job["probes"].append({
                    "id":              len(job["probes"]),
                    "method":          resp.request.method,
                    "url":             resp.url,
                    "req_headers":     dict(resp.request.headers),
                    "req_body":        rb[:2000],
                    "status":          resp.status_code,
                    "resp_headers":    dict(resp.headers),
                    "resp_body":       _rb_text,
                    "payload":         _pl_str,
                    "param":           point.get("name", ""),
                    "module":          getattr(_scan_module_ctx, "current", "") or "",
                    "ts":              time.time(),
                    # ── Burp-like response delta fields ───────────────────────
                    "elapsed_ms":      _elapsed,
                    "time_ratio":      round(_elapsed / _bl_ms, 2),
                    "status_changed":  resp.status_code != _bl_st,
                    "len_delta":       len(_rb_text) - _bl_ln,
                    "reflects_payload": bool(_pl_str and _pl_str in _rb_text),
                    # ── Pre-computed FP flag for _live_issue_ctor ─────────────
                    "likely_fp":       _likely_fp,
                })
                _note_probe_auth(job, resp.status_code)
            except Exception:
                pass
        return resp

    scan.RequestSender.send = _patched_send

    # ── Patch send_raw — endpoint-level modules (api_version, cors, jwt, graphql) ──
    # send_raw() calls self._raw() directly, so it bypasses _patched_send entirely.
    # We intercept it here so those probes are visible in the Probes panel.
    _orig_send_raw = scan.RequestSender.send_raw

    def _patched_send_raw(self_r, method=None, url=None, headers=None, cookies=None,
                          body=None, json_body=None, allow_redirects=True,
                          fresh_session=False, **kwargs):
        if job.get("stopped") or (stop_event is not None and stop_event.is_set()):
            return None
        if not _wait_while_auth_paused(job, stop_event):
            return None
        _sync_sender_auth(job, self_r)
        if job.get("auth_headers"):
            headers = _apply_auth_headers(headers or getattr(self_r.base, "headers", {}),
                                          job["auth_headers"])
        # Cookieless CSRF replay: do not put Cookie back from auth overrides.
        if fresh_session:
            headers = {k: v for k, v in (headers or {}).items() if k.lower() != "cookie"}
            cookies = {}
        resp = _orig_send_raw(self_r, method=method, url=url, headers=headers,
                              cookies=cookies, body=body, json_body=json_body,
                              allow_redirects=allow_redirects,
                              fresh_session=fresh_session, **kwargs)
        if resp is not None:
            try:
                rb = resp.request.body or ""
                if isinstance(rb, bytes):
                    rb = rb.decode("utf-8", errors="replace")
                _rb_text   = resp.text[:3000]
                # payload / param: describe what changed vs the base request
                _param = ""
                if url is not None and url != self_r.base.url:
                    _payload = url                          # variant URL (api_version etc.)
                elif json_body is not None:
                    _payload = json.dumps(json_body)[:300]  # graphql / mass-assign
                elif body is not None:
                    _payload = (body if isinstance(body, str) else "")[:300]
                else:
                    # Header-only probes (JWT alg:none, CORS Origin, …)
                    _payload = ""
                    _base_h = {str(k).lower(): str(v)
                               for k, v in (getattr(self_r.base, "headers", {}) or {}).items()}
                    _sent_h = headers if headers is not None else {}
                    for _hk, _hv in (_sent_h or {}).items():
                        if str(_hv) != _base_h.get(str(_hk).lower(), ""):
                            _param   = str(_hk)
                            _payload = str(_hv)[:500]
                            break
                _bctx      = job.get("_ctx") or {}
                _elapsed   = resp.elapsed.total_seconds() * 1000 \
                             if hasattr(resp, "elapsed") and resp.elapsed else 0.0
                _bl_ms     = _bctx.get("baseline_elapsed_ms", 0.0) or 1.0
                _bl_st     = _bctx.get("baseline_status", 0)
                _bl_ln     = _bctx.get("baseline_len", 0)
                _bl_bd     = _bctx.get("baseline_body", "") or ""
                _likely_fp = bool(
                    _bl_st and _bl_ln
                    and resp.status_code == _bl_st
                    and abs(len(_rb_text) - _bl_ln) / max(_bl_ln, 1) < 0.05
                    and _text_similarity(_bl_bd[:400], _rb_text[:400]) > 0.78
                )
                job["probes"].append({
                    "id":              len(job["probes"]),
                    "method":          resp.request.method,
                    "url":             resp.url,
                    "req_headers":     dict(resp.request.headers),
                    "req_body":        rb[:2000],
                    "status":          resp.status_code,
                    "resp_headers":    dict(resp.headers),
                    "resp_body":       _rb_text,
                    "payload":         _payload,
                    "param":           _param,
                    "module":          getattr(_scan_module_ctx, "current", "") or "",
                    "ts":              time.time(),
                    "elapsed_ms":      _elapsed,
                    "time_ratio":      round(_elapsed / _bl_ms, 2),
                    "status_changed":  resp.status_code != _bl_st,
                    "len_delta":       len(_rb_text) - _bl_ln,
                    "reflects_payload": False,
                    "likely_fp":       _likely_fp,
                })
                _note_probe_auth(job, resp.status_code)
            except Exception:
                pass
        return resp

    scan.RequestSender.send_raw = _patched_send_raw

    # ── Patch send_full_json — graphql / prototype-pollution / mass-assign ──────
    # send_full_json() also calls self._raw() directly, same issue.
    _orig_send_full_json = scan.RequestSender.send_full_json

    def _patched_send_full_json(self_r, body: dict):
        if job.get("stopped") or (stop_event is not None and stop_event.is_set()):
            return None
        if not _wait_while_auth_paused(job, stop_event):
            return None
        _sync_sender_auth(job, self_r)
        resp = _orig_send_full_json(self_r, body)
        if resp is not None:
            try:
                rb = resp.request.body or ""
                if isinstance(rb, bytes):
                    rb = rb.decode("utf-8", errors="replace")
                _rb_text   = resp.text[:3000]
                _meta      = getattr(scan, "_PROBE_META", None)
                _payload   = (getattr(_meta, "payload", None) or "") or json.dumps(body)[:300]
                _param     = (getattr(_meta, "param", None) or "") if _meta is not None else ""
                _bctx      = job.get("_ctx") or {}
                _elapsed   = resp.elapsed.total_seconds() * 1000 \
                             if hasattr(resp, "elapsed") and resp.elapsed else 0.0
                _bl_ms     = _bctx.get("baseline_elapsed_ms", 0.0) or 1.0
                _bl_st     = _bctx.get("baseline_status", 0)
                _bl_ln     = _bctx.get("baseline_len", 0)
                _bl_bd     = _bctx.get("baseline_body", "") or ""
                _likely_fp = bool(
                    _bl_st and _bl_ln
                    and resp.status_code == _bl_st
                    and abs(len(_rb_text) - _bl_ln) / max(_bl_ln, 1) < 0.05
                    and _text_similarity(_bl_bd[:400], _rb_text[:400]) > 0.78
                )
                job["probes"].append({
                    "id":              len(job["probes"]),
                    "method":          resp.request.method,
                    "url":             resp.url,
                    "req_headers":     dict(resp.request.headers),
                    "req_body":        rb[:2000],
                    "status":          resp.status_code,
                    "resp_headers":    dict(resp.headers),
                    "resp_body":       _rb_text,
                    "payload":         _payload,
                    "param":           _param,
                    "module":          getattr(_scan_module_ctx, "current", "") or "",
                    "ts":              time.time(),
                    "elapsed_ms":      _elapsed,
                    "time_ratio":      round(_elapsed / _bl_ms, 2),
                    "status_changed":  resp.status_code != _bl_st,
                    "len_delta":       len(_rb_text) - _bl_ln,
                    "reflects_payload": False,
                    "likely_fp":       _likely_fp,
                })
                _note_probe_auth(job, resp.status_code)
            except Exception:
                pass
        return resp

    scan.RequestSender.send_full_json = _patched_send_full_json

    # ── Patch Issue constructor — live-stream issues as they're detected ──────
    # Scan.py creates Issue(...) objects inside module.scan() calls which run
    # concurrently in a ThreadPoolExecutor.  By replacing scan.Issue with our
    # wrapper we capture every issue the moment it's created and push it into
    # job["live_issues"] so the /status poll can return partial results in real
    # time, even while run_scan() is still running.
    job["live_issues"] = []
    _orig_Issue_cls = scan.Issue

    def _live_issue_ctor(*args, **kwargs):
        iss = _orig_Issue_cls(*args, **kwargs)
        try:
            d = {k: getattr(iss, k, "") for k in (
                "severity", "vulnerability", "parameter", "payload",
                "evidence", "url", "param_type", "response_snippet",
                "confidence", "cwe", "remediation", "request_info",
                "attack_body",
            )}
            d["url"] = d["url"] or url   # fill in URL if Issue left it blank
            _augment_response_snippet(d, url, job["probes"])
            _attach_attack_request(d, {
                "method": method, "url": url, "headers": hdrs, "body": body or "",
            }, job["probes"])

            # ── Inline FP pre-filter ──────────────────────────────────────────
            # Three independent checks, applied in order.
            # All operate on the probe response directly — no extra network calls.
            _iss_pl    = (d.get("payload")       or "").strip().lower()
            _iss_pm    = (d.get("parameter")     or "").strip().lower()
            _vuln_flat = (d.get("vulnerability") or "").upper() \
                          .replace(" ","").replace("-","").replace("(","").replace(")","")

            if _iss_pl and any(kw in _vuln_flat for kw in _INLINE_FP_VULN_KEYWORDS):
                # ── Find best-matching probe (payload + param, case-insensitive) ──
                _snap = list(job["probes"])   # snapshot to avoid mid-iteration append
                _mp: Optional[dict] = None
                for _pr in reversed(_snap):
                    _pr_pl = (_pr.get("payload") or "").strip().lower()
                    _pr_pm = (_pr.get("param")   or "").strip().lower()
                    if _pr_pl == _iss_pl and _pr_pm == _iss_pm:
                        _mp = _pr; break
                if _mp is None:            # param-name casing mismatch fallback
                    for _pr in reversed(_snap):
                        if (_pr.get("payload") or "").strip().lower() == _iss_pl:
                            _mp = _pr; break

                if _mp is not None:
                    _pr_body = _mp.get("resp_body", "") or ""

                    # ── Check 1: likely_fp flag (requires valid baseline) ─────
                    # Time-based findings are latency-proven; body may match baseline.
                    if _mp.get("likely_fp", False) and "TIMEBASED" not in _vuln_flat:
                        d["confirmed"] = False; return iss

                    # ── Check 2: SSTI — evaluated result must be a STANDALONE
                    #    token in the response body, not embedded in a larger
                    #    numeric field like "140492" or a timestamp.
                    #    Baseline-independent: only looks at the probe response.
                    if "SSTI" in _vuln_flat or "TEMPLATE" in _vuln_flat:
                        _ev_m = re.search(r'[→>＞]\s*(\d+)\s*$',
                                          d.get("evidence") or "", re.M)
                        if _ev_m:
                            _expected = _ev_m.group(1)
                            # Standalone = NOT preceded/followed by another digit
                            _standalone = bool(re.search(
                                r'(?<!\d)' + re.escape(_expected) + r'(?!\d)',
                                _pr_body
                            ))
                            if not _standalone:
                                d["confirmed"] = False; return iss   # FP

                    # ── Check 3: NoSQL Error-Based — must have an actual NoSQL
                    #    error pattern in the response body.
                    #    Single quote `'` on a non-NoSQL field returns the
                    #    normal response → no error → FP.
                    if "NOSQL" in _vuln_flat:
                        _has_err = any(p.search(_pr_body)
                                       for p in _NOSQL_ERROR_PATTERNS)
                        if not _has_err:
                            d["confirmed"] = False; return iss   # FP

                    # ── Check 5: IDOR / BOLA — pagination parameters are never IDOR.
                    #    Changing `offset`, `size`, `limit`, `page`, etc. returns
                    #    different pages of data by design — this is expected behaviour,
                    #    NOT an access-control bypass.
                    #    Real IDOR would be: changing userId/orderId/resourceId and
                    #    receiving another user's private data → those parameters have
                    #    semantic groups like user_id / resource_id / numeric_id, not
                    #    pagination, so they are NOT suppressed here.
                    if "IDOR" in _vuln_flat or "BOLA" in _vuln_flat or "BROKENOBJECT" in _vuln_flat:
                        _param_orig = (d.get("parameter") or "").strip()
                        _sem = _get_semantic_group(_param_orig, (d.get("payload") or ""))
                        if _sem == "pagination":
                            d["confirmed"] = False; return iss   # pagination → FP

                    # ── Check 4: SSRF — probe response must contain real internal
                    #    resource indicators (AWS IMDS keys, GCP/Azure metadata,
                    #    /etc/passwd content, etc.).
                    #    Applies to all injection locations (query, header, body):
                    #    • Query param (orderType=http://...) — server almost never
                    #      fetches the sort-field value as a URL → FP
                    #    • Header (referer/origin/host) — server rarely makes
                    #      outbound requests based on these → FP unless indicators found
                    #    • Body params — same principle
                    #    If response is identical to baseline → also FP (caught by
                    #    Check 1 above). This check adds the content-based filter
                    #    for cases where baseline comparison is unreliable.
                    if "SSRF" in _vuln_flat and "TIMEBASED" not in _vuln_flat:
                        _real_ssrf = bool(_SSRF_REAL_INDICATORS.search(_pr_body))
                        if not _real_ssrf:
                            d["confirmed"] = False; return iss   # FP

            job["live_issues"].append(d)
            job["issues_so_far"] = (
                sum(e["issue_count"] for e in job["entries_done"])
                + len(job["live_issues"])
            )
        except Exception:
            pass
        return iss

    scan.Issue = _live_issue_ctor

    # ── Patch scanner module .scan() for per-task % progress ─────────────────
    # _ALL_MODULES contains every active scanner (sqli, xss, idor, …).
    # Wrapping each module's .scan() lets us count completed tasks and derive
    # an accurate percentage: done_tasks / total_tasks (total is set from the
    # log line captured in _tprint above).
    def _make_scan_wrapper(orig_fn, mk):
        def _wrapped_scan(sender, point, base):
            if job.get("stopped") or (stop_event is not None and stop_event.is_set()):
                _done_tasks[0] += 1
                return []
            _prev = getattr(_scan_module_ctx, "current", None)
            _scan_module_ctx.current = mk   # tag probes recorded during this call
            try:
                result = orig_fn(sender, point, base)
            finally:
                _scan_module_ctx.current = _prev
            _done_tasks[0] += 1
            t = _total_tasks[0]
            if t > 0:
                pct = min(95, int(_done_tasks[0] / t * 100))
                if pct > job["progress"]["pct"]:
                    job["progress"]["pct"] = pct
            return result
        return _wrapped_scan

    for _mk, _mod in scan._ALL_MODULES.items():
        try:
            if hasattr(_mod, 'scan') and callable(_mod.scan):
                _mod.scan = _make_scan_wrapper(_mod.scan, _mk)
        except Exception:
            pass   # never let a bad module break the scan

    # ── Patch RequestSmugglingScanner._raw_probe — surface raw-socket probes ──
    # This scanner crafts/sends its CL.TE / TE.CL / obfuscated-TE desync probes
    # over hand-rolled raw sockets (socket/ssl), deliberately bypassing
    # RequestSender.send — urllib3/requests would normalise away the malformed
    # framing it needs to test. That means none of its traffic ever passes
    # through _patched_send, so it was previously invisible in the Probes list
    # and the Module/Category filter (and the detail panel kept showing
    # whichever unrelated probe was selected before it). We wrap _raw_probe to
    # reconstruct the exact request it sent, parse the raw response, and record
    # both as a probe entry tagged module="smuggling" — same shape the UI
    # already renders, so the real desync request/response now shows up.
    _smug_mod = scan._ALL_MODULES.get('smuggling')
    if _smug_mod is not None and hasattr(_smug_mod, '_raw_probe'):
        _orig_raw_probe = _smug_mod._raw_probe

        def _parse_raw_http_response(data):
            """Best-effort split of a raw HTTP/1.x response into (status, headers, body)."""
            status, headers, body = 0, {}, ""
            if not data:
                return status, headers, body
            try:
                text = data.decode("latin-1", errors="replace")
                head, _, rest = text.partition("\r\n\r\n")
                lines = head.split("\r\n")
                if lines:
                    m = re.match(r'HTTP/\d\.\d\s+(\d{3})', lines[0])
                    if m:
                        status = int(m.group(1))
                    for line in lines[1:]:
                        if ":" in line:
                            k, _, v = line.partition(":")
                            headers[k.strip()] = v.strip()
                body = rest[:3000]
            except Exception:
                pass
            return status, headers, body

        def _headers_for_display(extra_headers, host):
            """Build a display-friendly dict from either a dict or a list of
            (name, value) pairs. Some smuggling probes deliberately send
            duplicate/conflicting header lines (e.g. two Content-Length
            values, or two Transfer-Encoding values) which a plain dict can't
            represent — repeats get a "(#2)" suffix so the UI shows BOTH
            conflicting lines instead of silently collapsing to the last one
            (important for manual validation of CL.CL / duplicate-TE probes)."""
            _items = list(extra_headers.items()) if isinstance(extra_headers, dict) \
                     else list(extra_headers or [])
            out, seen = {}, {}
            for k, v in _items:
                if k in seen:
                    seen[k] += 1
                    out[f"{k} (#{seen[k]})"] = v
                else:
                    seen[k] = 1
                    out[k] = v
            out.setdefault("Host", host)
            return out

        def _patched_smug_raw_probe(scheme, host, port, path, extra_headers, body,
                                    timeout, _orig=_orig_raw_probe):
            if job.get("stopped") or (stop_event is not None and stop_event.is_set()):
                return 0.0, b""
            elapsed, data = _orig(scheme, host, port, path, extra_headers, body, timeout)
            try:
                _status, _resp_hdrs, _resp_body = _parse_raw_http_response(data)
                _hdrs = _headers_for_display(extra_headers, host)
                _hdrs.setdefault("Host", host)
                _hdrs.setdefault("Connection", "close")
                _scheme_default = (port == 443) if scheme == 'https' else (port == 80)
                job["probes"].append({
                    "id":              len(job["probes"]),
                    "method":          "POST",
                    "url":             f"{scheme}://{host}" + ("" if _scheme_default else f":{port}") + path,
                    "req_headers":     _hdrs,
                    "req_body":        (body or "")[:2000],
                    "status":          _status,
                    "resp_headers":    _resp_hdrs,
                    "resp_body":       _resp_body,
                    "payload":         (body or "")[:300],
                    "param":           "",
                    "module":          "smuggling",
                    "ts":              time.time(),
                    "elapsed_ms":      elapsed * 1000.0,
                    "time_ratio":      0,
                    "status_changed":  False,
                    "len_delta":       0,
                    "reflects_payload": bool(body and _resp_body and body in _resp_body),
                    "likely_fp":       False,
                })
            except Exception:
                pass
            return elapsed, data

        _smug_mod._raw_probe = _patched_smug_raw_probe

    # ── Build curl command ────────────────────────────────────────────────────
    curl_cmd = _build_curl(method, url, hdrs, body)
    logs.append({"text": f"[→] Scanning: {method} {url}", "level": "info", "ts": time.time()})

    # ── Run scan ──────────────────────────────────────────────────────────────
    _aborted_entry = bool(job.get("stopped"))
    try:
        profile_arg = None if profile == "full" else profile
        mod_filter = set(modules) if modules else None
        skip_set = set(skip_modules) if skip_modules else None
        # Explicit module list overrides profile (CLI --module parity)
        if mod_filter:
            profile_arg = None
        req_obj, issues, scan_time, waf_info = scan.run_scan(
            curl_cmd,
            timeout=timeout,
            threads=threads,
            delay=max(0.0, min(delay_sec, 30.0)),
            profile=profile_arg,
            module_filter=mod_filter,
            skip_modules=skip_set,
            oob_server=oob_server,   # None = OOB disabled (default)
            oob_token=oob_token,
        )
    except Exception as e:
        logs.append({"text": f"[!] Scan error for {url}: {e}", "level": "high", "ts": time.time()})
        issues = []
        scan_time = 0.0
        waf_info  = ""

    _aborted_entry = _aborted_entry or bool(job.get("stopped")) or (
        stop_event is not None and stop_event.is_set()
    )

    # Summarise
    issue_count = len(issues)
    if _aborted_entry:
        logs.append({
            "text":  f"[⏹] Aborted: {url} — {issue_count} issue(s) so far "
                     f"({scan_time:.1f}s)",
            "level": "info",
            "ts":    time.time(),
        })
    else:
        logs.append({
            "text":  f"[✓] Done: {url} — {issue_count} issue(s) in {scan_time:.1f}s"
                     + (f" [WAF: {waf_info}]" if waf_info else ""),
            "level": "ok",
            "ts":    time.time(),
        })

    # Serialise issues
    serialised = []
    for iss in issues:
        d = _issue_to_dict(iss, url)
        _augment_response_snippet(d, url, job["probes"])
        _attach_attack_request(d, {
            "method": method, "url": url, "headers": hdrs, "body": body or "",
        }, job["probes"])
        serialised.append(d)

    # ── Deduplication by (vulnerability, parameter, payload) triple ───────────
    _seen_dk: set = set()
    _deduped: list = []
    for _d in serialised:
        _dk = (
            (_d.get("vulnerability") or "").lower().strip(),
            (_d.get("parameter")    or "").lower().strip(),
            (_d.get("payload")      or "")[:100].strip(),
        )
        if _dk not in _seen_dk:
            _seen_dk.add(_dk)
            _deduped.append(_d)
    if len(_deduped) < len(serialised):
        _nd = len(serialised) - len(_deduped)
        logs.append({"text": f"[i] {_nd} duplicate issue(s) removed", "level": "info", "ts": time.time()})
    serialised = _deduped

    # ── Known-FP pre-filter (ALL severities) ─────────────────────────────────
    # Catches structural false positives that the scanner cannot avoid:
    #   • IDOR/BOLA on pagination params (offset, size, limit, page, …):
    #     changing page params returns different pages of authorized data —
    #     this is expected behaviour, not an access-control bypass.
    # Runs BEFORE the CRITICAL/HIGH confirmation loop because these issues
    # are often MEDIUM/LOW and would otherwise escape with confirmed=None.
    for _d in serialised:
        if _d.get("confirmed") is not None:
            continue   # already determined (e.g. by inline FP check)
        _d_vf = (_d.get("vulnerability") or "").upper() \
                 .replace(" ","").replace("-","").replace("(","").replace(")","")
        # Pagination IDOR check
        if "IDOR" in _d_vf or "BOLA" in _d_vf or "BROKENOBJECT" in _d_vf:
            _d_param   = (_d.get("parameter") or "").strip()
            _d_payload = (_d.get("payload")   or "").strip()
            if _get_semantic_group(_d_param, _d_payload) == "pagination":
                _d["confirmed"] = False
                logs.append({"text": f"[i] FP (pagination param): IDOR [{_d_param}]",
                             "level": "info", "ts": time.time()})

    # ── Confirmation step: re-probe CRITICAL / HIGH findings ──────────────────
    # Re-fires the matching probe once to verify the response is reproducible,
    # which dramatically cuts false positives on flaky / rate-limited endpoints.
    # Skip entirely when the user aborted — no more outbound traffic.
    _confirm_cache: dict = {}
    if _aborted_entry:
        for _d in serialised:
            if _d.get("confirmed") is None:
                _d["confirmed"] = None
    else:
        for _d in serialised:
            if _d.get("confirmed") is not None:
                continue   # already set by pre-filter or inline check — skip
            _sev = (_d.get("severity") or "").upper()
            if _sev not in ("CRITICAL", "HIGH"):
                _d["confirmed"] = None   # N/A for lower severities
                continue
            if job.get("stopped"):
                _d["confirmed"] = None
                continue
            _ck = (
                (_d.get("vulnerability") or "").lower(),
                (_d.get("parameter")    or "").lower(),
                (_d.get("payload")      or "")[:60],
            )
            if _ck in _confirm_cache:
                _d["confirmed"] = _confirm_cache[_ck]
            else:
                _ok = _confirm_issue(_d, job["probes"], timeout, baseline_ctx=_ctx)
                _d["confirmed"]    = _ok
                _confirm_cache[_ck] = _ok
                if _ok:
                    logs.append({"text": f"[✓] Confirmed: {_d.get('vulnerability')} [{_d.get('parameter')}]",
                                 "level": "ok", "ts": time.time()})
                else:
                    logs.append({"text": f"[~] Unconfirmed (possible FP): {_d.get('vulnerability')} [{_d.get('parameter')}]",
                                 "level": "info", "ts": time.time()})

    issue_count = len(serialised)

    job["entries_done"].append({
        "entry":       {"method": method, "url": url, "headers": hdrs, "body": body or ""},
        "issues":      serialised,
        "scan_time":   scan_time,
        "waf_info":    waf_info or (_ctx.get("waf_name") if _ctx.get("waf_detected") else ""),
        "issue_count": issue_count,
        # ── Burp-like context summary for the UI ──────────────────────────────
        "context": {
            "baseline_status":          _ctx.get("baseline_status", 0),
            "baseline_len":             _ctx.get("baseline_len", 0),
            "baseline_elapsed_ms":      _ctx.get("baseline_elapsed_ms", 0.0),
            "waf_detected":             _ctx.get("waf_detected", False),
            "waf_name":                 _ctx.get("waf_name", ""),
            "sql_error_baseline":       _ctx.get("sql_error_baseline", False),
            "redirect_baseline":        _ctx.get("redirect_baseline", False),
            "reflects_input":           _ctx.get("reflects_input", False),
            "input_reflection_context": _ctx.get("input_reflection_context", "none"),
            # baseline_body intentionally excluded from API response (large / sensitive)
        },
    })
    job["issues_so_far"] = sum(e["issue_count"] for e in job["entries_done"])


def _drain_scan_queue(q):
    """Drop remaining queued entries after Abort."""
    while True:
        try:
            q.get_nowait()
        except _ScanQueueEmpty:
            break


def _run_job(job_id: str):
    """
    Consume entries from job["_scan_q"] until:
      • job["stopped"] is set  (Stop button / Reset), OR
      • the queue is empty for QUEUE_IDLE_TIMEOUT seconds with no new entries.

    New entries can be pushed into _scan_q at any time via /apiscan/queue/{job_id}
    while the job is still "running" — this gives Burp-like "add more while scanning"
    behaviour without creating a new job.
    """
    QUEUE_IDLE_TIMEOUT = 5.0   # seconds to wait for new entries before auto-completing

    job = jobs[job_id]
    q   = job["_scan_q"]

    while True:
        if job.get("stopped"):
            _drain_scan_queue(q)
            with job["_q_lock"]:
                job["status"] = "done"
                job["aborted"] = True
            break

        # Hold between entries while waiting for a fresh token
        if job.get("auth_paused"):
            job["status"] = "paused_auth"
            time.sleep(0.4)
            continue

        try:
            entry = q.get(timeout=QUEUE_IDLE_TIMEOUT)
        except _ScanQueueEmpty:
            # Don't auto-complete while paused for auth
            if job.get("auth_paused"):
                continue
            # Queue has been empty for QUEUE_IDLE_TIMEOUT — no more entries expected.
            # Atomically mark done so the /queue endpoint can reject late arrivals.
            with job["_q_lock"]:
                if job.get("auth_paused") or job.get("stopped"):
                    pass
                else:
                    job["status"] = "done"
            if job.get("status") == "done":
                break
            continue

        # Stop may have been pressed while waiting on the queue
        if job.get("stopped"):
            _drain_scan_queue(q)
            with job["_q_lock"]:
                job["status"] = "done"
                job["aborted"] = True
            break

        # Apply any refreshed auth onto this entry before scanning
        _ov = job.get("auth_headers") or {}
        if _ov:
            entry = dict(entry)
            entry["headers"] = _apply_auth_headers(entry.get("headers") or {}, _ov)

        idx   = len(job["entries_done"])          # position within this session
        total = job["total_queued"]               # may grow if user adds more mid-scan
        try:
            _do_scan_entry(job_id, entry, idx, total)
        finally:
            _uid = job.pop("_active_scan_uid", None)
            if _uid:
                _unload_scan(_uid)

        if job.get("stopped"):
            _drain_scan_queue(q)
            with job["_q_lock"]:
                job["status"] = "done"
                job["aborted"] = True
            break

    job["progress"]["pct"] = 100
    job["finished_at"] = time.time()


# ── Pydantic models ────────────────────────────────────────────────────────────

def _coerce_val(new_str: str, original):
    """Try to keep the same type as the original JSON value when substituting."""
    if isinstance(original, bool):
        return new_str.lower() not in ("", "0", "false", "no", "null")
    if isinstance(original, int):
        try:
            return int(new_str)
        except (ValueError, TypeError):
            return new_str
    if isinstance(original, float):
        try:
            return float(new_str)
        except (ValueError, TypeError):
            return new_str
    return new_str


def _apply_custom_values(method: str, url: str, hdrs: dict, body: str, customs: list) -> tuple:
    """Substitute user-specified unique values into request before scanning."""
    if not customs:
        return method, url, hdrs, body

    for cv in customs:
        loc  = cv.get("location", "")
        name = cv.get("param_name", "")
        val  = str(cv.get("value", ""))
        if not name or not val:
            continue

        if loc == "query":
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if name in params:
                    params[name] = [val]
                    url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            except Exception:
                pass

        elif loc in ("body_json",):
            if body:
                try:
                    obj = json.loads(body)
                    # Support dot-notation for nested keys e.g. "bankDetails.id"
                    # Also handle array notation e.g. "companyIds[0]"
                    import re as _re
                    keys_raw = _re.split(r'\.(?![^\[]*\])', name)  # split on dot outside brackets
                    d = obj
                    for k in keys_raw[:-1]:
                        m = _re.match(r'^(.*?)\[(\d+)\]$', k)
                        if m and isinstance(d, dict):
                            d = d.get(m.group(1), {})
                            if isinstance(d, list):
                                idx_ = int(m.group(2))
                                d = d[idx_] if idx_ < len(d) else {}
                        elif isinstance(d, dict):
                            d = d.get(k, d)
                    last_key_raw = keys_raw[-1]
                    m = _re.match(r'^(.*?)\[(\d+)\]$', last_key_raw)
                    if m and isinstance(d, dict):
                        arr = d.get(m.group(1))
                        idx_ = int(m.group(2))
                        if isinstance(arr, list) and idx_ < len(arr):
                            # Preserve original type
                            orig = arr[idx_]
                            arr[idx_] = _coerce_val(val, orig)
                    elif isinstance(d, dict) and last_key_raw in d:
                        orig = d[last_key_raw]
                        d[last_key_raw] = _coerce_val(val, orig)
                    body = json.dumps(obj)
                except Exception:
                    pass

        elif loc == "body_form":
            if body:
                try:
                    params = parse_qs(body, keep_blank_values=True)
                    if name in params:
                        params[name] = [val]
                        body = urlencode(params, doseq=True)
                except Exception:
                    pass

    return method, url, hdrs, body


class StartRequest(BaseModel):
    entries:       List[dict]
    profile:       str        = "full"
    threads:       int        = 6
    timeout:       int        = 10
    delay_sec:     float      = 0.0
    # CLI parity: --module / --skip-module (modules non-empty overrides profile)
    modules:       List[str]  = []
    skip_modules:  List[str]  = []
    custom_values: List[dict] = []   # [{entry_id, param_name, location, value}]
    # ── Out-of-Band (blind) detection — interactsh / Collaborator equivalent ──
    oob_enabled:   bool       = False
    oob_server:    Optional[str] = None   # private interactsh host; blank → public fallback
    oob_token:     Optional[str] = None


class ParseCurlRequest(BaseModel):
    curl_cmd: str


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "API Scan Backend", "port": 8775}


@app.get("/apiscan/modules")
def list_modules():
    """Module keys + profile presets for the Configure UI (mirrors Scan.py)."""
    uid = "meta"
    try:
        scan = _load_scan(uid)
        all_keys = sorted(scan._ALL_MODULES.keys())
        profiles = {}
        for name, mods in scan.SCAN_PROFILES.items():
            if mods is None:
                profiles[name] = all_keys
            else:
                profiles[name] = list(mods)
        return {"modules": all_keys, "profiles": profiles}
    except Exception as e:
        raise HTTPException(500, f"Could not load module catalog: {e}")
    finally:
        _unload_scan(uid)


@app.get("/apiscan/module/{mod_key}/payloads")
def get_module_payloads_endpoint(mod_key: str):
    """Return dynamic payloads and vectors for a specific module directly from Scan.py."""
    uid = "meta"
    try:
        scan = _load_scan(uid)
        if mod_key not in scan._ALL_MODULES:
            raise HTTPException(404, f"Module '{mod_key}' not found")
        mod = scan._ALL_MODULES[mod_key]
        vectors = []
        seen_vals = set()

        def _add_vec(tag, val):
            s = str(val).strip()
            if s and s not in seen_vals:
                seen_vals.add(s)
                vectors.append({"tag": tag, "val": s})

        # Known attribute mappings
        attr_map = [
            ("PAYLOADS", "PAYLOAD"),
            ("ALL_PAYLOADS", "PAYLOAD"),
            ("ERROR_PAYLOADS", "ERROR-BASED"),
            ("TIME_PAYLOADS", "TIME-BASED"),
            ("UNION_PAYLOADS", "UNION SELECT"),
            ("DETECT_PAYLOADS", "DETECTION"),
            ("RCE_PAYLOADS", "RCE / EXEC"),
            ("OUTPUT_PAYLOADS", "COMMAND"),
            ("PROBES", "PROBE"),
            ("ERROR_PROBES", "ERROR PROBE"),
            ("TEST_METHODS", "HTTP VERB"),
            ("OVERRIDE_HEADERS", "OVERRIDE HEADER"),
            ("HEADERS_TO_TEST", "TEST HEADER"),
            ("PROBE_PARAMS", "DEBUG PARAM"),
            ("JSON_OPS", "JSON OPERATOR"),
            ("BRACKET_OPS", "BRACKET OPERATOR"),
            ("INJECT_FIELDS", "FIELD INJECTION"),
            ("QUERY_KEYS", "PARAM POLLUTION"),
        ]

        for attr_name, default_tag in attr_map:
            items = getattr(mod, attr_name, None)
            if not items:
                continue
            if isinstance(items, (list, tuple)):
                for item in items:
                    if isinstance(item, tuple) and len(item) == 2:
                        _add_vec(default_tag, f"{item[0]} = {item[1]}")
                    elif isinstance(item, dict):
                        for dk, dv in item.items():
                            _add_vec(default_tag, f"{dk}: {dv}")
                    else:
                        _add_vec(default_tag, item)
            elif isinstance(items, dict):
                for dk, dv in items.items():
                    _add_vec(default_tag, f"{dk}: {dv}")

        # Boolean pairs handling
        raw_pairs = getattr(mod, "BOOL_PAIRS", None)
        if isinstance(raw_pairs, (list, tuple)):
            for pair in raw_pairs:
                if isinstance(pair, tuple) and len(pair) == 2:
                    _add_vec("BOOLEAN PAIR", f"TRUE: {pair[0]}  |  FALSE: {pair[1]}")

        return {
            "key": mod_key,
            "name": getattr(mod, "NAME", mod_key),
            "vectors": vectors
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error inspecting module payloads: {e}")
    finally:
        _unload_scan(uid)


@app.post("/apiscan/start")
def start_scan(req: StartRequest):
    if not req.entries:
        raise HTTPException(400, "No entries provided")

    if not os.path.isfile(_get_scan_py()):
        raise HTTPException(
            500,
            f"Scan.py not found at {_get_scan_py()}. "
            "Rebuild with build.sh (it bundles Scan.py into apiscan_backend/).",
        )

    _prune_old_jobs()

    # One active job at a time — queue more APIs via /apiscan/queue/{job_id}.
    # Jobs with stopped=True are aborting and do not block a new start / Resume.
    # paused_auth still owns the target (waiting for token).
    running = [
        jid for jid, j in jobs.items()
        if j.get("status") in ("running", "paused_auth") and not j.get("stopped")
    ]
    if running:
        raise HTTPException(
            409,
            "A scan is already in progress. Stop it or wait for it to finish "
            "(or add APIs to the current queue).",
        )

    job_id = str(uuid.uuid4())

    # Build a thread-safe queue pre-populated with the initial entries.
    # Additional entries can be pushed in later via /apiscan/queue/{job_id}.
    scan_q = _ScanQueue()
    for e in req.entries:
        scan_q.put(e)

    stop_event = threading.Event()
    delay_sec = max(0.0, min(float(req.delay_sec or 0), 30.0))
    # Normalise module lists (strip empties / unknown keys applied later by Scan.py)
    modules = [m.strip() for m in (req.modules or []) if isinstance(m, str) and m.strip()]
    skip_modules = [m.strip() for m in (req.skip_modules or []) if isinstance(m, str) and m.strip()]
    jobs[job_id] = {
        "status":        "running",
        "aborted":       False,
        "stopped":       False,
        "auth_paused":   False,
        "auth_pause_reason": "",
        "auth_pause_skipped": False,  # Skip on banner → no more 401/403 pauses this job
        "auth_headers":  {},          # refreshed Authorization / Cookie mid-scan
        "_auth_fail_streak": 0,
        "logs":          [],
        "probes":        [],          # ALL fired probes — [{id, method, url, status, ...}]
        "entries_done":  [],
        "live_issues":   [],          # partial issues for the currently-running entry
        "issues_so_far": 0,
        "progress":      {"current": 0, "total": len(req.entries), "pct": 0, "api": ""},
        "entries":       req.entries,
        "custom_values": req.custom_values,
        "profile":       req.profile,
        "threads":       req.threads,
        "timeout":       req.timeout,
        "delay_sec":     delay_sec,
        "modules":       modules,
        "skip_modules":  skip_modules,
        # OOB: only pass a server through when the user explicitly enabled it.
        # Empty server + enabled → "" triggers Scan.py's public-server fallback.
        "oob_server":    (req.oob_server or "") if req.oob_enabled else None,
        "oob_token":     req.oob_token,
        "created_at":    time.time(),
        # ── Queue-based scanning (Burp-like "add more while running") ──────
        "_scan_q":       scan_q,
        "_q_lock":       threading.Lock(),   # guards status ↔ queue additions
        "_stop_event":   stop_event,         # mid-probe cooperative abort
        "total_queued":  len(req.entries),   # grows when /queue endpoint is called
    }
    threading.Thread(target=_run_job, args=(job_id,), daemon=True).start()
    return {"job_id": job_id}


@app.post("/apiscan/queue/{job_id}")
def queue_entries(job_id: str, req: StartRequest):
    """
    Add more entries to a running scan without starting a new job.
    Returns 409 if the job already completed (frontend should start a new job).
    """
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    with job["_q_lock"]:
        if job["status"] not in ("running", "paused_auth") or job.get("stopped"):
            raise HTTPException(409, "Job already completed — start a new scan")
        for entry in req.entries:
            job["_scan_q"].put(entry)
        job["total_queued"] += len(req.entries)
        job["progress"]["total"] = job["total_queued"]

    return {"ok": True, "added": len(req.entries), "total_queued": job["total_queued"]}


@app.get("/apiscan/status/{job_id}")
def get_status(job_id: str, since: int = 0, since_probe: int = 0):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    all_logs    = job["logs"]
    all_probes  = job["probes"]
    live_issues = job.get("live_issues", [])

    # Build entries_done for the response.
    # If a scan is still running we inject a partial "in-progress" entry so the
    # frontend can render live results without waiting for run_scan() to finish.
    entries_done = job["entries_done"]
    if live_issues and job["status"] in ("running", "paused_auth"):
        cur_entry = job["progress"].get("current_entry") or {}
        entries_done_resp = list(entries_done) + [{
            "entry": {
                "method":  cur_entry.get("method", ""),
                "url":     cur_entry.get("url", "") or job["progress"].get("api", ""),
                "headers": cur_entry.get("headers", {}),
                "body":    cur_entry.get("body", ""),
            },
            "issues":      list(live_issues),        # snapshot (safe to list())
            "scan_time":   0,
            "waf_info":    "",
            "issue_count": len(live_issues),
            "partial":     True,
        }]
    else:
        entries_done_resp = entries_done

    return {
        "status":        job["status"],
        "aborted":       bool(job.get("aborted") or job.get("stopped")),
        "auth_paused":   bool(job.get("auth_paused")),
        "auth_pause_reason": job.get("auth_pause_reason") or "",
        "auth_pause_skipped": bool(job.get("auth_pause_skipped")),
        "progress":      job["progress"],
        "logs":          all_logs[since:],
        "log_count":     len(all_logs),
        "new_probes":    all_probes[since_probe:],  # delta since last poll
        "probe_count":   len(all_probes),
        "issues_so_far": job["issues_so_far"],
        "entries_done":  entries_done_resp,
    }


@app.get("/apiscan/results/{job_id}")
def get_results(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "status":       job["status"],
        "entries_done": job["entries_done"],
        "issues_so_far": job["issues_so_far"],
        "progress":     job["progress"],
    }


@app.post("/apiscan/export/csv/{job_id}")
def export_csv(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    buf = io.StringIO()
    w   = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["#", "Severity", "Vulnerability", "Parameter", "Payload",
                "Evidence", "URL", "Method", "Param Type", "Response Snippet"])

    row_num = 1
    for entry_done in job["entries_done"]:
        entry   = entry_done["entry"]
        method  = entry.get("method", "")
        for iss in entry_done["issues"]:
            if iss.get("confirmed") is False:
                continue   # skip false positives
            w.writerow([
                row_num,
                iss.get("severity", ""),
                iss.get("vulnerability", ""),
                iss.get("parameter", ""),
                iss.get("payload", ""),
                iss.get("evidence", ""),
                iss.get("url", entry.get("url", "")),
                method,
                iss.get("param_type", ""),
                (iss.get("response_snippet", "") or "")[:500],
            ])
            row_num += 1

    buf.seek(0)
    return {"csv": buf.getvalue()}


@app.post("/apiscan/export/html/{job_id}")
def export_html(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    # Gather all issues flat — exclude confirmed false positives
    all_issues = []
    for entry_done in job["entries_done"]:
        entry  = entry_done["entry"]
        method = entry.get("method", "")
        for iss in entry_done["issues"]:
            if iss.get("confirmed") is False:
                continue   # skip false positives
            all_issues.append({**iss, "_method": method, "_entry_url": entry.get("url", "")})

    # Severity counts
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts    = {s: 0 for s in sev_order}
    for iss in all_issues:
        sev = iss.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    sev_color = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#44aaff",
        "INFO":     "#8b949e",
    }
    sev_bg = {
        "CRITICAL": "rgba(248,81,73,.2)",
        "HIGH":     "rgba(255,136,0,.15)",
        "MEDIUM":   "rgba(255,204,0,.12)",
        "LOW":      "rgba(68,170,255,.12)",
        "INFO":     "rgba(139,148,158,.1)",
    }

    total_apis   = len(job["entries_done"])
    total_issues = len(all_issues)

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    # Summary cards HTML
    cards_html = ""
    for sev in sev_order:
        c  = sev_color.get(sev, "#8b949e")
        bg = sev_bg.get(sev, "rgba(139,148,158,.1)")
        cards_html += f'<div style="background:{bg};border:1px solid {c}40;border-radius:8px;padding:12px 20px;text-align:center;min-width:90px"><div style="font-size:22px;font-weight:700;color:{c}">{counts.get(sev, 0)}</div><div style="font-size:10px;color:{c};font-weight:600;margin-top:2px">{sev}</div></div>'

    # Table rows
    rows_html = ""
    for i, iss in enumerate(all_issues, 1):
        sev    = (iss.get("severity") or "INFO").upper()
        c      = sev_color.get(sev, "#8b949e")
        bg_s   = sev_bg.get(sev, "rgba(139,148,158,.1)")
        m      = iss.get("_method", "")
        url    = esc(iss.get("url") or iss.get("_entry_url", ""))
        vuln   = esc(iss.get("vulnerability", ""))
        param  = esc(iss.get("parameter", ""))
        pl     = esc((iss.get("payload") or "")[:80])
        ev     = esc((iss.get("evidence") or "")[:120])
        rs     = esc((iss.get("response_snippet") or "")[:200])
        rows_html += f'''<tr>
          <td style="color:#8b949e;font-family:monospace">{i}</td>
          <td><span style="background:{bg_s};color:{c};border:1px solid {c}40;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px">{sev}</span></td>
          <td>{vuln}</td>
          <td style="font-family:monospace;font-size:11px">{param}</td>
          <td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{esc(iss.get("payload",""))}">{pl}</td>
          <td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{esc(iss.get("evidence",""))}">{ev}</td>
          <td><span style="font-size:10px;padding:1px 6px;border-radius:3px;background:#21262d">{esc(m)}</span></td>
          <td style="font-family:monospace;font-size:10px;color:#8b949e;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{url}">{url}</td>
        </tr>
        <tr style="display:none" class="expand-row" id="expand-{i}">
          <td colspan="8" style="background:#0d1117;padding:8px 16px">
            <pre style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px;font-size:11px;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto">{rs}</pre>
          </td>
        </tr>'''

    if not rows_html:
        rows_html = '<tr><td colspan="8" style="text-align:center;padding:30px;color:#6e7681">No issues found</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Scan Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',Inter,-apple-system,sans-serif;font-size:13px;padding:24px}}
  h1{{font-size:20px;font-weight:700;margin-bottom:4px}}
  .meta{{color:#8b949e;font-size:12px;margin-bottom:20px}}
  .cards{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}}
  .filters{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}}
  .fbtn{{background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:4px;padding:4px 12px;font-size:11px;cursor:pointer}}
  .fbtn.active{{background:#1f6feb;border-color:#1f6feb}}
  table{{width:100%;border-collapse:collapse}}
  th{{padding:8px;background:#21262d;color:#6e7681;font-size:10px;text-transform:uppercase;letter-spacing:.5px;text-align:left;position:sticky;top:0;z-index:1;border-bottom:1px solid #30363d}}
  td{{padding:7px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
  tr:hover td{{background:#161b22;cursor:pointer}}
  ::-webkit-scrollbar{{width:5px;height:5px}}
  ::-webkit-scrollbar-track{{background:#0d1117}}
  ::-webkit-scrollbar-thumb{{background:#30363d;border-radius:3px}}
</style>
</head>
<body>
<h1>🛡️ API Scan Report</h1>
<div class="meta">APIs scanned: {total_apis} &nbsp;|&nbsp; Issues found: {total_issues} &nbsp;|&nbsp; Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</div>
<div class="cards">{cards_html}</div>
<div class="filters">
  <button class="fbtn active" onclick="filterTable('ALL',this)">All ({total_issues})</button>
  {''.join(f'<button class="fbtn" onclick="filterTable(&quot;{s}&quot;,this)">{s} ({counts.get(s,0)})</button>' for s in sev_order if counts.get(s,0)>0)}
</div>
<div style="overflow:auto;border:1px solid #30363d;border-radius:8px">
<table id="issues-table">
<thead><tr><th>#</th><th>Severity</th><th>Vulnerability</th><th>Parameter</th><th>Payload</th><th>Evidence</th><th>Method</th><th>URL</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>
<script>
function filterTable(sev, btn) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#issues-table tbody tr:not(.expand-row)').forEach(function(tr) {{
    var badge = tr.querySelector('span');
    var rowSev = badge ? badge.textContent.trim() : '';
    tr.style.display = (sev === 'ALL' || rowSev === sev) ? '' : 'none';
  }});
}}
document.querySelectorAll('#issues-table tbody tr:not(.expand-row)').forEach(function(tr, i) {{
  tr.addEventListener('click', function() {{
    var expRow = document.getElementById('expand-' + (i+1));
    if (expRow) expRow.style.display = expRow.style.display === 'none' ? '' : 'none';
  }});
}});
</script>
</body>
</html>"""

    return {"html": html}


@app.post("/apiscan/detect_params")
def detect_params(body: dict):
    """
    Extract testable parameters from each selected entry using direct parsing
    (handles string bodies, dict bodies from AV Capture, and JSON/form-encoded).
    Returns params for the 'unique value' modal.
    """
    entries = body.get("entries", [])
    if not entries:
        return {"params": []}

    result = []
    seen   = set()

    for entry in entries:
        try:
            params = _extract_entry_params(entry)
            for p in params:
                # Only show body_json params — headers are not user-configurable
                # in the Unique Values modal (they are set at capture time).
                if p["location"] != "body_json":
                    continue
                key = f"{p['entry_id']}:{p['location']}:{p['param_name']}"
                if key in seen:
                    continue
                seen.add(key)
                result.append(p)
        except Exception:
            pass

    return {"params": result}


@app.post("/apiscan/parse_curl")
def parse_curl(req: ParseCurlRequest):
    if not os.path.isfile(_get_scan_py()):
        raise HTTPException(
            500,
            f"Scan.py not found at {_get_scan_py()}. "
            "Rebuild with build.sh (it bundles Scan.py into apiscan_backend/).",
        )
    uid = uuid.uuid4().hex
    try:
        scan = _load_scan(uid)
        sr   = scan.CurlParser.parse(req.curl_cmd)
        return {
            "method":  sr.method,
            "url":     sr.url,
            "headers": sr.headers or {},
            "body":    sr.body or "",
        }
    except Exception as e:
        raise HTTPException(400, f"Could not parse curl: {e}")
    finally:
        _unload_scan(uid)


class UpdateAuthRequest(BaseModel):
    """Refresh Authorization / Cookie (or arbitrary headers) while a scan is paused."""
    authorization: Optional[str] = None
    cookie:        Optional[str] = None
    headers:       Optional[dict] = None


@app.post("/apiscan/update_auth/{job_id}")
def update_auth(job_id: str, req: UpdateAuthRequest):
    """
    Apply a fresh token/cookie and clear auth_paused so probes continue.
    Call when status == paused_auth (also allowed while running to pre-empt expiry).
    """
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("stopped") or job.get("status") == "done":
        raise HTTPException(409, "Job already finished — start a new scan")

    ov = dict(job.get("auth_headers") or {})
    if req.authorization is not None:
        tok = (req.authorization or "").strip()
        if tok:
            # Accept raw JWT — prefix Bearer when it looks like one
            if (not tok.lower().startswith("bearer ")
                    and len(tok.split(".")) == 3 and tok.startswith("eyJ")):
                tok = "Bearer " + tok
            ov["Authorization"] = tok
    if req.cookie is not None and (req.cookie or "").strip():
        ov["Cookie"] = req.cookie.strip()
    if req.headers:
        for k, v in req.headers.items():
            if k and v is not None and str(v).strip():
                ov[str(k)] = str(v).strip()

    if not ov:
        raise HTTPException(400, "Provide authorization, cookie, or headers")

    job["auth_headers"] = ov
    job["auth_paused"] = False
    job["_auth_fail_streak"] = 0
    job["auth_pause_reason"] = ""
    if job.get("status") == "paused_auth":
        job["status"] = "running"
    # Refresh headers on the in-flight entry snapshot (live results / progress)
    cur = job.get("progress", {}).get("current_entry")
    if isinstance(cur, dict):
        cur["headers"] = _apply_auth_headers(cur.get("headers") or {}, ov)
    try:
        which = ", ".join(sorted(ov.keys()))
        job["logs"].append({
            "text":  f"[▶] Auth updated ({which}) — resuming probes",
            "level": "ok",
            "ts":    time.time(),
        })
        job["progress"]["api"] = job["progress"].get("api") or "Resuming…"
        if str(job["progress"].get("api", "")).startswith("Paused"):
            job["progress"]["api"] = "Resuming with new token…"
    except Exception:
        pass
    return {"ok": True, "status": job["status"], "headers_set": list(ov.keys())}


@app.post("/apiscan/skip_auth/{job_id}")
def skip_auth_pause(job_id: str):
    """
    Resume without changing token and disable further auth-pause for this job.
    Use when 401/403 (e.g. scope/permission codes like 900910) are expected.
    """
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("stopped") or job.get("status") == "done":
        raise HTTPException(409, "Job already finished — start a new scan")

    job["auth_pause_skipped"] = True
    job["auth_paused"] = False
    job["_auth_fail_streak"] = 0
    job["auth_pause_reason"] = ""
    if job.get("status") == "paused_auth":
        job["status"] = "running"
    try:
        job["logs"].append({
            "text":  "[⏭] Auth pause skipped — continuing; further 401/403 will not pause this job",
            "level": "info",
            "ts":    time.time(),
        })
        if str(job.get("progress", {}).get("api", "")).startswith("Paused"):
            job["progress"]["api"] = "Resuming (auth pause skipped)…"
    except Exception:
        pass
    return {"ok": True, "status": job["status"], "auth_pause_skipped": True}


@app.post("/apiscan/stop/{job_id}")
def stop_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    job["stopped"] = True
    job["aborted"] = True
    job["auth_paused"] = False  # unblock waiting probe threads so they can exit
    ev = job.get("_stop_event")
    if ev is not None:
        ev.set()  # cooperative abort inside Scan.py workers / RequestSender
    # Best-effort: drop not-yet-started queue items immediately
    q = job.get("_scan_q")
    if q is not None:
        _drain_scan_queue(q)
    try:
        job["logs"].append({
            "text":  "[⏹] Abort requested — stopping probes and draining queue…",
            "level": "info",
            "ts":    time.time(),
        })
    except Exception:
        pass
    return {"ok": True, "aborted": True}
