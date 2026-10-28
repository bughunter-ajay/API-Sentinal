"""
Swagger Scan — OpenAPI Spec Auditor Backend  (Port 8771)
Wraps OOScope logic: finds unsecured endpoints, duplicates, broken $refs, multi-method paths,
and dangerous-by-design endpoints (arbitrary code/SQL execution, admin/IAM proxies, destructive
bulk mutations, deserialization, debug surfaces) via naming-pattern heuristics.
"""

import json, csv, io, uuid, os, time, re, socket, ipaddress
from html import escape as _h
from datetime import datetime
from collections import defaultdict
from typing import List
from urllib.parse import urlparse
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

try:
    import yaml
    _YAML = True
except ImportError:
    _YAML = False

app = FastAPI(title="Swagger Scan Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

VALID_METHODS = ["get", "post", "put", "delete", "patch", "options", "head"]

# ── In-memory job store ───────────────────────────────────────────────────────
jobs = {}   # job_id → audit result dict
_job_created_at = {}  # job_id → unix timestamp (for TTL prune)
JOB_TTL = 3600
MAX_JOBS = 50
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB OpenAPI upload cap


def _prune_old_jobs():
    """Drop stale / excess scan jobs so memory cannot grow unbounded."""
    now = time.time()
    stale = [
        jid for jid in list(jobs.keys())
        if now - float(_job_created_at.get(jid, now)) > JOB_TTL
    ]
    for jid in stale:
        jobs.pop(jid, None)
        _job_created_at.pop(jid, None)
    if len(jobs) > MAX_JOBS:
        ordered = sorted(
            jobs.keys(),
            key=lambda jid: float(_job_created_at.get(jid, 0)),
        )
        for jid in ordered[: max(0, len(jobs) - MAX_JOBS)]:
            jobs.pop(jid, None)
            _job_created_at.pop(jid, None)


def _is_blocked_ip(ip) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    # Cloud metadata / CGNAT
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return True
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            return True
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in ipaddress.ip_network("fd00::/8"):
            return True
    return False


_BLOCKED_PROBE_HOSTS = frozenset({
    "localhost", "localhost.localdomain",
    "metadata", "metadata.google.internal",
    "metadata.goog", "instance-data",
})


def _assert_safe_probe_base(base_url: str) -> str:
    """
    SSRF guard for live probes: only http(s), and host must not resolve to
    loopback / private / link-local / metadata addresses.
    Returns normalized base URL or raises ValueError.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("Empty base URL")
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https probe URLs are allowed")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("Missing host")
    if host in _BLOCKED_PROBE_HOSTS or host.endswith(".localhost"):
        raise ValueError(f"Blocked probe host: {host}")
    # Literal IP in the URL
    try:
        if _is_blocked_ip(ipaddress.ip_address(host)):
            raise ValueError(f"Blocked probe IP: {host}")
        return base
    except ValueError as e:
        if str(e).startswith("Blocked"):
            raise
        # Not a literal IP — DNS resolve all A/AAAA
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"DNS lookup failed for {host}: {e}") from e
    if not infos:
        raise ValueError(f"No addresses for host: {host}")
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            raise ValueError(f"Blocked probe target ({host} → {ip})")
    return base


@app.get("/")
def root():
    return {"status": "ok", "service": "swagger-scan"}


# ─────────────────────────────────────────────────────────────────────────────
# CORE AUDIT LOGIC  (OOScope internals)
# ─────────────────────────────────────────────────────────────────────────────

def _iter_endpoints(spec):
    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        # Resolve paths./x → {$ref: #/components/pathItems/...} (defined below)
        methods = _expand_path_item(spec, methods)
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() in VALID_METHODS and isinstance(details, dict):
                yield path, method.upper(), details


def _is_security_empty(security):
    """
    OOScope parity: a security requirement counts as "present" only when at
    least one scheme lists a non-empty scope array.

    So `[{ "bearerAuth": [] }]` / `[{ "apiKey": [] }]` are treated as empty —
    same as the original OOScope CLI. (OpenAPI-strict reading would treat those
    as secured for http/apiKey; we intentionally match OOScope here.)
    """
    if security is None:
        return True
    if isinstance(security, list):
        for entry in security:
            if isinstance(entry, dict) and any(v for v in entry.values()):
                return False
            elif entry and not isinstance(entry, dict):
                return False
        return True
    return False


def _global_security_present(spec):
    return not _is_security_empty(spec.get("security"))


def _count_unique_apis(spec):
    seen = set()
    for path, method, _ in _iter_endpoints(spec):
        seen.add(f"{method} {path}")
    return sorted(seen)


# Intentional public surfaces — excluded from "Unsecured" unless strict mode.
# Matched against path segments + operationId (not summary/description).
_PUBLIC_PATH_TOKENS = frozenset({
    "health", "healthz", "healthcheck", "ready", "readyz", "readiness",
    "live", "livez", "liveness", "ping", "pong", "status", "heartbeat",
    "login", "logout", "logon", "signin", "signout", "signup", "register",
    "registration", "token", "tokens", "refresh", "authorize", "authorization",
    "oauth", "oauth2", "oidc", "callback", "sso", "saml", "jwks",
    "swagger", "swagger-ui", "api-docs", "openapi", "redoc", "favicon",
    "well-known", "version", "versions", "metrics", "prometheus",
})
_PUBLIC_PATH_SUFFIXES = (
    "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
    "/ping", "/status", "/login", "/logout", "/signin", "/signup",
    "/register", "/token", "/oauth", "/oauth2", "/authorize", "/callback",
    "/.well-known", "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
    "/openapi.yaml", "/favicon.ico", "/version", "/metrics",
)


def _is_expected_public(path, method, details):
    """True if this unauthenticated endpoint is a normal public surface."""
    pl = str(path or "").lower()
    op = str((details or {}).get("operationId") or "").lower()
    # Suffix / exact-ish public routes
    for suf in _PUBLIC_PATH_SUFFIXES:
        if pl == suf or pl.endswith(suf) or pl.rstrip("/").endswith(suf):
            return True
    # Path segment token match (e.g. /api/v1/health, /auth/login)
    segs = [s.strip("{}").lower() for s in pl.split("/") if s]
    if any(seg in _PUBLIC_PATH_TOKENS for seg in segs):
        return True
    # operationId like getHealth, loginUser, oauthCallback
    for tok in _PUBLIC_PATH_TOKENS:
        if re.search(r'(?<![a-z0-9])' + re.escape(tok) + r'(?![a-z0-9])', op):
            return True
    return False


def _find_unsecured_paths(spec):
    """Return every operation with empty/missing security (no allowlist)."""
    has_global = _global_security_present(spec)
    unsecured = []
    for path, method, details in _iter_endpoints(spec):
        sec = details.get("security", "__inherit__")
        if sec == "__inherit__":
            if not has_global:
                unsecured.append(f"{method} {path}")
        elif _is_security_empty(sec):
            unsecured.append(f"{method} {path}")
    return unsecured


def _split_unsecured(spec, strict=False):
    """
    Split raw unsecured endpoints into:
      - unsecured: real findings (or all, if strict=True)
      - public_expected: intentional public routes (empty when strict)
    """
    raw = _find_unsecured_paths(spec)
    if strict:
        return raw, []
    # Need details per endpoint for operationId check
    detail_map = {}
    for path, method, details in _iter_endpoints(spec):
        detail_map[f"{method} {path}"] = (path, method, details)

    unsecured, public_expected = [], []
    for ep in raw:
        path, method, details = detail_map.get(ep, ("", "", {}))
        if path and _is_expected_public(path, method, details):
            public_expected.append(ep)
        else:
            unsecured.append(ep)
    return unsecured, public_expected


def _find_duplicate_paths(spec):
    api_map = defaultdict(int)
    for path, method, _ in _iter_endpoints(spec):
        api_map[f"{method} {path}"] += 1
    return [f"{k} (x{v})" for k, v in api_map.items() if v > 1]


def _find_multi_method_paths(spec):
    path_methods = defaultdict(list)
    for path, method, _ in _iter_endpoints(spec):
        path_methods[path].append(method)
    return [
        f"{path}  →  {', '.join(sorted(methods))}"
        for path, methods in path_methods.items()
        if len(methods) > 1
    ]


def _unescape_json_pointer_token(token: str) -> str:
    return str(token).replace("~1", "/").replace("~0", "~")


_POINTER_MISSING = object()


def _follow_pointer(spec, ref):
    """
    Follow a local JSON Pointer (#/a/b/c), including nested schema paths
    like #/components/schemas/User/properties/email. Returns the target
    node, or _POINTER_MISSING if any segment is absent.
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return _POINTER_MISSING
    node = spec
    for raw in ref[2:].split("/"):
        part = _unescape_json_pointer_token(raw)
        if isinstance(node, dict):
            if part not in node:
                return _POINTER_MISSING
            node = node[part]
        elif isinstance(node, list):
            try:
                idx = int(part)
            except (TypeError, ValueError):
                return _POINTER_MISSING
            if idx < 0 or idx >= len(node):
                return _POINTER_MISSING
            node = node[idx]
        else:
            return _POINTER_MISSING
    return node


def _find_undefined_param_refs(spec):
    """
    Walk the whole spec for local $refs (parameters, schemas, requestBody,
    responses, headers, links, path-level params, …).
    Returns list of "where ($ref: …)" strings for broken local refs.
    External refs are collected separately via _find_external_refs.
    """
    issues = []
    seen_issue = set()

    def _note(where, ref):
        key = f"{where}|{ref}"
        if key in seen_issue:
            return
        seen_issue.add(key)
        issues.append(f"{where}  ($ref: {ref})")

    def walk(node, where, depth=0):
        if depth > 40 or node is None:
            return
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                if ref.startswith("#/"):
                    # Full pointer resolve — supports nested …/properties/x
                    if _follow_pointer(spec, ref) is _POINTER_MISSING:
                        _note(where, ref)
                # external refs handled elsewhere
            for k, v in node.items():
                if k == "$ref":
                    continue
                walk(v, where, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, where, depth + 1)

    # Path-level + operation-level
    paths = spec.get("paths") or {}
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            # Validate pathItem $ref, then walk the expanded operations
            if "$ref" in methods:
                walk({"$ref": methods["$ref"]}, f"PATH {path}", 0)
            methods = _expand_path_item(spec, methods)
            if not isinstance(methods, dict):
                continue
            walk(methods.get("parameters"), f"PATH {path} parameters", 0)
            for method, details in methods.items():
                if method.lower() not in VALID_METHODS or not isinstance(details, dict):
                    continue
                where = f"{method.upper()} {path}"
                walk(details, where, 0)

    # Components / OAS2 definitions
    walk(spec.get("components"), "components", 0)
    walk(spec.get("definitions"), "definitions", 0)
    walk(spec.get("parameters"), "parameters", 0)
    walk(spec.get("responses"), "responses", 0)

    issues.sort()
    return issues


def _find_external_refs(spec):
    """Local inventory of non-#/ $refs (not resolved — reported as INFO)."""
    found = []
    seen = set()

    def walk(node, where, depth=0):
        if depth > 40 or node is None:
            return
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#/") and ref not in seen:
                seen.add(ref)
                found.append(f"{where}  ($ref: {ref})")
            for k, v in node.items():
                if k == "$ref":
                    continue
                walk(v, where, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, where, depth + 1)

    paths = spec.get("paths") or {}
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            walk(methods, f"PATH {path}", 0)
            for method, details in methods.items():
                if method.lower() in VALID_METHODS and isinstance(details, dict):
                    walk(details, f"{method.upper()} {path}", 0)
    walk(spec.get("components"), "components", 0)
    found.sort()
    return found


def _find_missing_responses(spec):
    """Endpoints with no responses block defined."""
    issues = []
    for path, method, details in _iter_endpoints(spec):
        if not details.get("responses"):
            issues.append(f"{method} {path}")
    return issues


def _find_no_operation_id(spec):
    """Endpoints missing operationId."""
    issues = []
    for path, method, details in _iter_endpoints(spec):
        if not details.get("operationId"):
            issues.append(f"{method} {path}")
    return issues


def _get_security_schemes(spec):
    return list(
        ((((spec.get("components") or {}).get("securitySchemes")) or {})).keys()
    )


# ─────────────────────────────────────────────────────────────────────────────
# DANGEROUS-ENDPOINT DETECTION
#   Flags endpoints that are dangerous BY DESIGN — the kind of thing a human
#   reviewer would spot by reading endpoint names/descriptions in a harvested
#   OpenAPI spec: arbitrary code execution, raw SQL execution, admin/IAM
#   privilege-escalation proxies, destructive bulk mutations, deserialization
#   / dynamic code loading, and debug/internal diagnostic surfaces.
#
#   This is a static NAMING-PATTERN heuristic over path + operationId +
#   summary + description + tags — it does NOT prove exploitability (no
#   requests are sent). Every match should be manually verified, ideally by
#   actually invoking the endpoint (e.g. via APISphere / API Scan) with a
#   valid token to confirm real impact.
# ─────────────────────────────────────────────────────────────────────────────
DANGEROUS_KEYWORDS = {
    # Balanced FP policy:
    # - NO generic config/query/test/tool/root (NiFi flood).
    # - Prefer compound keywords; some short tokens use MUTATING_ONLY or
    #   PATH_SEGMENT rules in _find_dangerous_endpoints (see below).
    # - Match on path + operationId only.
    "Arbitrary Code Execution": ("CRITICAL", [
        "execute-js", "executejs", "execute-script", "executescript",
        "execute-code", "executecode", "execute-command", "executecommand",
        "execute-groovy", "executegroovy", "execute-python", "executepython",
        "eval", "eval-script", "evalscript",
        "run-script", "runscript", "run-code", "runcode",
        "run-js", "runjs", "run-command", "runcommand",
        "invoke-script", "invokescript", "invoke-code", "invokecode",
        "subprocess", "powershell", "sandbox-exec",
        "code-runner", "coderunner", "script-runner", "scriptrunner",
        "js-adhoc", "run-adhoc", "remote-exec", "remoteexec", "rce",
        "shell-exec", "shellexec", "cmd-exec", "cmdexec",
    ]),
    "Arbitrary SQL / Database Execution": ("CRITICAL", [
        "execute-query", "executequery", "raw-query", "rawquery",
        "run-query", "runquery", "raw-sql", "rawsql",
        "execute-sql", "executesql", "db-query", "dbquery",
        "database-query", "native-query", "nativequery",
        "query-executor", "queryexecutor", "query-runner", "queryrunner",
        "adhoc-query", "adhocquery", "sql-exec", "sqlexec",
        "sql-console", "sqlconsole", "sql-query", "sqlquery",
        "jdbc-query", "jdbquery",
    ]),
    "Admin / IAM Privilege Escalation": ("HIGH", [
        # "admin" re-added as PATH_SEGMENT only ( /admin/... ) — not substring.
        # "root" stays OUT (NiFi /process-groups/root ID).
        "admin",
        "superadmin", "super-admin", "keycloak-admin", "keycloakadmin",
        "impersonate", "sudo", "elevate", "grant-role", "grantrole",
        "assign-role", "assignrole", "escalate", "masquerade",
        "act-as", "actas", "switch-user", "switchuser",
        "wildcard-proxy", "wildcardproxy", "pass-through", "passthrough",
        "permission-override", "role-override", "become-user", "becomeuser",
        "privilege-escalation", "privesc",
    ]),
    "Dangerous File / Config Operations": ("HIGH", [
        "vendor-config", "config-upload", "upload-plugin", "install-plugin",
        "plugin-install", "export-all", "exportall", "import-all", "importall",
        "sftp-upload", "arbitrary-file", "file-write", "filewrite",
        "write-file", "writefile", "delete-file", "deletefile",
        "overwrite-file", "overwritefile",
        "upload-file", "uploadfile", "download-file", "downloadfile",
        "read-file", "readfile", "fetch-file", "fetchfile",
        "system-backup", "systembackup", "restore-backup", "restorebackup",
    ]),
    "Destructive / Mass Mutation": ("HIGH", [
        # "purge"/"wipe"/"truncate" = MUTATING_ONLY (POST/PUT/PATCH/DELETE).
        # reset-password stays OUT (normal auth).
        "reset-all", "resetall", "delete-all", "deleteall",
        "drop-table", "droptable", "truncate", "wipe", "purge",
        "purge-all", "purgeall", "hard-delete", "harddelete",
        "bulk-delete", "bulkdelete", "mass-delete", "massdelete",
        "factory-reset", "factoryreset", "force-delete", "forcedelete",
        "drop-requests", "droprequests",
    ]),
    "Deserialization / Dynamic Code Loading": ("CRITICAL", [
        "deserialize", "unserialize", "load-class", "loadclass",
        "dynamic-load", "dynamicload", "unpickle", "yaml-load", "yamlload", "xxe",
    ]),
    "Debug / Internal Diagnostic Surface": ("MEDIUM", [
        # "actuator" alone is noisy (/actuator/health) — use specific surfaces.
        "debug", "internal-only", "internalonly",
        "heapdump", "heap-dump", "thread-dump", "threaddump",
        "env-vars", "envvars", "secrets", "credentials",
        "dev-only", "devonly", "test-only", "testonly",
        "swagger-internal", "actuator/env", "actuator/heapdump",
        "actuator/threaddump", "actuator/logfile", "actuator/beans",
    ]),
}

# Short tokens that only count on mutating HTTP methods (avoids GET …/purge status).
_MUTATING_ONLY_KEYWORDS = frozenset({
    "purge", "wipe", "truncate", "drop-requests", "droprequests",
    "upload-file", "uploadfile", "write-file", "writefile",
    "delete-file", "deletefile", "overwrite-file", "overwritefile",
})

# Must appear as a full path segment ( /admin/… ), not inside longer words.
_PATH_SEGMENT_KEYWORDS = frozenset({
    "admin", "purge", "secrets", "credentials", "debug",
})


# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY META — CWE / OWASP mapping + impact/recommendation boilerplate +
# a template CVSS 3.1 vector per category, split by whether the endpoint
# requires authentication or not. Used to auto-draft a Burp/report-style
# write-up per finding (see _find_dangerous_endpoints below).
#
# The CVSS vector/score here is a SUGGESTED DEFAULT for that category, not a
# calculated score — Scope/Impact genuinely depends on what the endpoint does
# in your specific system. Treat it as a starting point for the analyst, not
# an authoritative number to paste into a report unreviewed.
# ─────────────────────────────────────────────────────────────────────────────
CATEGORY_META = {
    "Arbitrary Code Execution": {
        "cwe": "CWE-94", "owasp": "API8:2023 Security Misconfiguration",
        "impact": "Allows execution of attacker-supplied code on the server — full system "
                  "compromise, data exfiltration, and lateral movement into internal networks.",
        "recommendation": "Remove or tightly restrict arbitrary-code-execution endpoints to a "
                          "narrow admin role with allow-listed operations; never expose them via "
                          "the public/partner gateway.",
        "cvss_unauth": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        "cvss_auth":   ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"),
    },
    "Arbitrary SQL / Database Execution": {
        "cwe": "CWE-89", "owasp": "API8:2023 Security Misconfiguration",
        "impact": "Allows execution of arbitrary SQL against the backing datastore — full "
                  "database read/write, mass data exfiltration, and potential RCE via "
                  "database-level command execution features.",
        "recommendation": "Remove raw-query execution endpoints; use parameterized queries only. "
                          "If a query-builder API is a genuine requirement, allow-list tables, "
                          "columns and operations server-side.",
        "cvss_unauth": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        "cvss_auth":   ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"),
    },
    "Admin / IAM Privilege Escalation": {
        "cwe": "CWE-269", "owasp": "API5:2023 Broken Function Level Authorization",
        "impact": "Exposes admin/IAM management or proxy functionality. Any authenticated "
                  "caller reaching this endpoint — even a low-privilege one — may be able to "
                  "escalate their own privileges or manage other users' access.",
        "recommendation": "Enforce strict per-role authorization on admin/IAM endpoints "
                          "server-side; remove wildcard proxy routes to identity-provider admin "
                          "APIs from the public gateway entirely.",
        "cvss_unauth": ("9.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
        "cvss_auth":   ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"),
    },
    "Dangerous File / Config Operations": {
        "cwe": "CWE-668", "owasp": "API1:2023 Broken Object Level Authorization",
        "impact": "Allows reading, writing or restoring server-side files/configuration — can "
                  "leak secrets, corrupt application state, or plant malicious config/plugins.",
        "recommendation": "Restrict file/config read-write endpoints to trusted internal "
                          "automation only; validate and allow-list file paths server-side.",
        "cvss_unauth": ("8.6", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"),
        "cvss_auth":   ("6.5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"),
    },
    "Destructive / Mass Mutation": {
        "cwe": "CWE-840", "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
        "impact": "Allows bulk/irreversible destructive operations (mass delete, factory reset, "
                  "reset-all-passwords) — a single call can cause a wide-blast-radius outage or "
                  "data-loss incident.",
        "recommendation": "Require step-up authentication (re-auth/MFA) and a confirmation "
                          "workflow for destructive bulk operations; log and rate-limit them.",
        "cvss_unauth": ("8.2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"),
        "cvss_auth":   ("6.5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"),
    },
    "Deserialization / Dynamic Code Loading": {
        "cwe": "CWE-502", "owasp": "API8:2023 Security Misconfiguration",
        "impact": "Deserializing attacker-controlled data or dynamically loading classes/plugins "
                  "can lead directly to remote code execution.",
        "recommendation": "Never deserialize untrusted data; use signed/allow-listed formats "
                          "(strict-schema JSON) instead of native object (de)serialization.",
        "cvss_unauth": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        "cvss_auth":   ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"),
    },
    "Debug / Internal Diagnostic Surface": {
        "cwe": "CWE-489", "owasp": "API9:2023 Improper Inventory Management",
        "impact": "Debug/diagnostic endpoints can leak stack traces, environment variables, "
                  "credentials, or internal topology — valuable recon for a follow-on attack.",
        "recommendation": "Disable debug/diagnostic endpoints in production; if genuinely "
                          "needed, restrict to an internal-only network segment with separate auth.",
        "cvss_unauth": ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "cvss_auth":   ("5.3", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    },
}


def _endpoint_search_blob(path, details):
    """Build the lowercase text blob a keyword match is run against.

    Path + operationId only — summary/description/tags caused heavy FPs
    (docs mentioning "configuration", "query", "admin", …). Naming heuristics
    should follow the route name, not marketing copy.
    """
    parts = [
        str(path or ""),
        str(details.get("operationId") or "") if isinstance(details, dict) else "",
    ]
    return " ".join(parts).lower()


def _kw_matches(text, keyword):
    """Boundary-aware substring match — 'sql' won't match inside 'results',
    but 'execute-query' / 'sql' / 'admin' etc. match their own naming variants
    (hyphen/underscore/slash already act as natural boundaries in URLs)."""
    pattern = r'(?<![a-z0-9])' + re.escape(keyword.lower()) + r'(?![a-z0-9])'
    return re.search(pattern, text) is not None


# Precompiled once at import time — a spec can have thousands of endpoints,
# and re-compiling ~150 keyword patterns from scratch for every single one
# would add up. `re` already caches compiled patterns, but building this list
# once avoids re.escape() + string-concat work being redone every call too.
_DANGEROUS_PATTERNS = [
    (category, severity, kw, re.compile(r'(?<![a-z0-9])' + re.escape(kw.lower()) + r'(?![a-z0-9])'))
    for category, (severity, keywords) in DANGEROUS_KEYWORDS.items()
    for kw in keywords
]

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _path_segments(path: str):
    """Lowercase path segments, ignoring {param} placeholders' braces content."""
    segs = []
    for raw in str(path or "").split("/"):
        if not raw:
            continue
        # {id} / {groupId} → keep placeholder name as segment token
        segs.append(raw.strip("{}").lower())
    return segs


def _keyword_allowed(kw, method, path, blob):
    """Extra gates so restored short tokens don't re-flood FPs."""
    if kw in _MUTATING_ONLY_KEYWORDS and method not in _MUTATING_METHODS:
        return False
    if kw in _PATH_SEGMENT_KEYWORDS:
        segs = _path_segments(path)
        if kw not in segs:
            # Also allow hyphenated compound segments: admin-users, purge-all
            if not any(seg == kw or seg.startswith(kw + "-") or seg.endswith("-" + kw)
                       for seg in segs):
                return False
    return True


def _find_dangerous_endpoints(spec, unsecured_set=None):
    """Return dangerous-by-design endpoints, highest severity first.
    `unsecured_set` can be passed in (already computed by the caller) to avoid
    walking the spec a second time just to know which endpoints lack auth."""
    if unsecured_set is None:
        unsecured_set = set(_find_unsecured_paths(spec))
    findings = []
    seen = set()

    for path, method, details in _iter_endpoints(spec):
        endpoint = f"{method} {path}"
        if endpoint in seen:
            continue
        blob = _endpoint_search_blob(path, details)

        matched_by_category = {}   # category -> severity
        all_hits = set()           # union of matched keywords across ALL categories
        for category, severity, kw, pattern in _DANGEROUS_PATTERNS:
            if not pattern.search(blob):
                continue
            if not _keyword_allowed(kw, method, path, blob):
                continue
            if category not in matched_by_category or _SEV_RANK[severity] < _SEV_RANK[matched_by_category[category]]:
                matched_by_category[category] = severity
            all_hits.add(kw)

        if not matched_by_category:
            continue

        # Most severe matching category wins the headline label, but
        # matched_keywords/all_categories still list EVERY category hit —
        # nothing gets buried just because a more severe category also matched.
        best_category = min(matched_by_category, key=lambda c: _SEV_RANK[matched_by_category[c]])
        severity = matched_by_category[best_category]

        seen.add(endpoint)
        is_unauth = endpoint in unsecured_set
        meta = CATEGORY_META.get(best_category, {})
        cvss_score, cvss_vector = meta.get("cvss_unauth" if is_unauth else "cvss_auth", ("-", "-"))
        exploitation_note = (
            "No authentication required — endpoint can be invoked directly with no token. "
            "Confirm real impact by sending a live request."
            if is_unauth else
            "Requires a valid bearer/API token per the spec's security requirement — not "
            "invoked during this static scan. Spec-confirmed only; verify with a valid token "
            "to turn this into a confirmed finding."
        )
        findings.append({
            "endpoint":         endpoint,
            "category":         best_category,
            "severity":         severity,
            "matched_keywords": sorted(all_hits),
            "all_categories":   sorted(matched_by_category.keys()),
            "unauthenticated":  is_unauth,
            "summary":          details.get("summary") or details.get("description") or "",
            "cwe":              meta.get("cwe", "-"),
            "owasp":            meta.get("owasp", "-"),
            "impact":           meta.get("impact", ""),
            "recommendation":   meta.get("recommendation", ""),
            "cvss_score":       cvss_score,
            "cvss_vector":      cvss_vector,
            "exploitation_note": exploitation_note,
        })

    findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 9), 0 if f["unauthenticated"] else 1))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL OWASP-API-TOP-10-ALIGNED STATIC CHECKS
#   Everything below is derived purely from the spec's declared schemas —
#   no requests are sent. Same "verify manually" caveat as the dangerous-
#   endpoint heuristic: a name/field match is a lead, not proof.
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_ref(spec, ref):
    """Resolve a local '#/components/schemas/Foo' style $ref to a dict.
    Returns None for external/malformed/non-object targets."""
    node = _follow_pointer(spec, ref)
    if node is _POINTER_MISSING or not isinstance(node, dict):
        return None
    return node


def _expand_path_item(spec, methods):
    """Inline paths./x → {$ref: #/components/pathItems/Foo} for iteration."""
    if not isinstance(methods, dict):
        return methods
    ref = methods.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return methods
    resolved = _resolve_ref(spec, ref)
    if not isinstance(resolved, dict):
        return methods
    merged = dict(resolved)
    for k, v in methods.items():
        if k == "$ref":
            continue
        if k == "parameters" and isinstance(v, list):
            base = merged.get("parameters") if isinstance(merged.get("parameters"), list) else []
            merged["parameters"] = list(v) + list(base)
        elif k not in merged:
            merged[k] = v
    return merged


def _deref_obj(spec, node, _depth=0, _seen=None):
    """If node is a local $ref wrapper (response / requestBody / …), resolve it."""
    if _depth > 6 or not isinstance(node, dict):
        return node if isinstance(node, dict) else {}
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    if _seen is None:
        _seen = set()
    if ref in _seen:
        return node
    resolved = _resolve_ref(spec, ref)
    if not resolved:
        return node
    out = dict(resolved)
    for k, v in node.items():
        if k != "$ref":
            out.setdefault(k, v)
    if isinstance(out.get("$ref"), str):
        return _deref_obj(spec, out, _depth + 1, _seen | {ref})
    return out


def _walk_schema_props(schema, spec, _depth=0, _seen=None):
    """Yield every property name reachable from an OpenAPI schema object,
    following $ref / items / allOf / oneOf / anyOf. Depth-capped and
    ref-cycle-guarded so a self-referential schema can't hang the scan."""
    if _depth > 6 or not isinstance(schema, dict):
        return
    if _seen is None:
        _seen = set()

    ref = schema.get("$ref")
    if ref:
        if ref in _seen:
            return
        _seen = _seen | {ref}
        resolved = _resolve_ref(spec, ref)
        if resolved:
            yield from _walk_schema_props(resolved, spec, _depth + 1, _seen)
        return

    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            yield name
            yield from _walk_schema_props(sub, spec, _depth + 1, _seen)

    items = schema.get("items")
    if isinstance(items, dict):
        yield from _walk_schema_props(items, spec, _depth + 1, _seen)

    for combo_key in ("allOf", "oneOf", "anyOf"):
        for sub in (schema.get(combo_key) or []):
            yield from _walk_schema_props(sub, spec, _depth + 1, _seen)


def _norm_field(name: str) -> str:
    return re.sub(r'[-_\s]', '', str(name).lower())


# High-signal sensitive response fields only.
# Dropped bare token/secret/pin/otp — pagination CSRF tokens, secretName, PIN UI, etc.
_SENSITIVE_FIELD_NAMES = {
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
}
_SENSITIVE_FIELD_NORM = {_norm_field(f) for f in _SENSITIVE_FIELD_NAMES}

# Compound substrings that still indicate real exposure (userPassword, awsAccessToken…)
_SENSITIVE_COMPOUND_NEEDLES = (
    "password", "passwd", "clientsecret", "privatekey",
    "accesstoken", "refreshtoken", "sessiontoken", "authtoken",
    "creditcard", "cardnumber", "socialsecurity", "bankaccount",
)

# Bare/compound names that look sensitive but are usually inventory noise
_SENSITIVE_FIELD_DENY = {
    "token", "secret", "pin", "otp", "securitycode",
    "nexttoken", "continuationtoken", "pagetoken",
    "csrftoken", "xsrftoken", "requesttoken",
    "secretname", "secrettype", "secretref", "secretreference",
    "tokentype", "tokenurl", "tokenendpoint", "tokenuri",
}


def _is_sensitive_field(name: str) -> bool:
    """True for high-signal sensitive property names; skips common FPs."""
    n = _norm_field(name)
    if not n or n in _SENSITIVE_FIELD_DENY:
        return False
    if n in _SENSITIVE_FIELD_NORM:
        return True
    if any(needle in n for needle in _SENSITIVE_COMPOUND_NEEDLES):
        # still skip pagination/CSRF-style compounds
        if any(bad in n for bad in ("nexttoken", "pagetoken", "csrftoken", "xsrftoken",
                                      "secretname", "secrettype", "tokenurl", "tokenendpoint")):
            return False
        return True
    return False

# High-signal privilege / ownership fields only.
# Dropped: permissions, role, status, enabled, plan, tier, scope, verified —
# extremely common in enterprise specs (e.g. NiFi) and not mass-assign proof.
_PRIVILEGE_FIELD_NAMES = {
    "isadmin", "is_admin", "superuser", "issuperuser", "is_superuser",
    "globaladmin", "isroot", "rootuser",
    "ownerid", "owner_id", "accountownerid",
    "accesslevel", "access_level", "privilegelevel",
    "creditlimit", "credit_limit", "balance", "credits",
    "permissionoverride", "roleoverride", "rolesoverride",
    "canimpersonate", "impersonate", "forcepasswordreset",
}
_PRIVILEGE_FIELD_NORM = {_norm_field(f) for f in _PRIVILEGE_FIELD_NAMES}


def _iter_content_schemas(content_block, spec):
    """Yield property names across every media-type schema in a
    requestBody/response `content` block."""
    if not isinstance(content_block, dict):
        return
    for media_obj in content_block.values():
        schema = (media_obj or {}).get("schema") if isinstance(media_obj, dict) else None
        yield from _walk_schema_props(schema, spec)


def _schema_has_open_additional(schema, spec, _depth=0, _seen=None):
    """True if schema allows arbitrary extra properties (mass-assign vector)."""
    if _depth > 6 or not isinstance(schema, dict):
        return False
    if _seen is None:
        _seen = set()
    ref = schema.get("$ref")
    if ref:
        if ref in _seen:
            return False
        resolved = _resolve_ref(spec, ref)
        if not resolved:
            return False
        return _schema_has_open_additional(resolved, spec, _depth + 1, _seen | {ref})
    ap = schema.get("additionalProperties")
    if ap is True:
        return True
    if isinstance(ap, dict) and len(ap) == 0:
        return True
    for combo_key in ("allOf", "oneOf", "anyOf"):
        for sub in (schema.get(combo_key) or []):
            if _schema_has_open_additional(sub, spec, _depth + 1, _seen):
                return True
    return False


def _iter_content_schemas_full(content_block, spec):
    """Yield (prop_name_or_None, schema) media schemas for deeper flags."""
    if not isinstance(content_block, dict):
        return
    for media_obj in content_block.values():
        if not isinstance(media_obj, dict):
            continue
        schema = media_obj.get("schema")
        if isinstance(schema, dict):
            yield schema


def _is_success_response_code(code) -> bool:
    """Only treat 2xx (and OAS '2XX') as exposure surfaces — skip 4xx/5xx noise."""
    s = str(code).strip().upper()
    if s in ("DEFAULT",):
        return False
    if s.endswith("XX"):
        return s.startswith("2")
    try:
        return 200 <= int(s) < 300
    except ValueError:
        return False


def _find_sensitive_data_exposure(spec):
    """OWASP API3:2023 — 2xx response schemas that expose high-signal sensitive
    field names (password, accessToken, SSN, credit card…). A lead at excessive
    data exposure, not proof the field is populated at runtime."""
    findings = []
    for path, method, details in _iter_endpoints(spec):
        responses = details.get("responses")
        if not isinstance(responses, dict):
            continue
        hits = set()
        for code, resp in responses.items():
            if not _is_success_response_code(code):
                continue
            if not isinstance(resp, dict):
                continue
            resp = _deref_obj(spec, resp)
            for prop in _iter_content_schemas(resp.get("content"), spec):
                if _is_sensitive_field(prop):
                    hits.add(prop)
        if hits:
            findings.append({"endpoint": f"{method} {path}", "fields": sorted(hits)})
    findings.sort(key=lambda f: f["endpoint"])
    return findings


def _find_mass_assignment_risk(spec):
    """OWASP API6:2023 — POST/PUT/PATCH request bodies that accept
    high-signal privileged fields, or declare open additionalProperties."""
    findings = []
    for path, method, details in _iter_endpoints(spec):
        if method not in ("POST", "PUT", "PATCH"):
            continue
        rb = details.get("requestBody")
        if not isinstance(rb, dict):
            continue
        rb = _deref_obj(spec, rb)
        content = rb.get("content")
        hits = set()
        open_additional = False
        for prop in _iter_content_schemas(content, spec):
            if _norm_field(prop) in _PRIVILEGE_FIELD_NORM:
                hits.add(prop)
        for schema in _iter_content_schemas_full(content, spec):
            if _schema_has_open_additional(schema, spec):
                open_additional = True
                hits.add("additionalProperties:true")
                break
        if hits:
            findings.append({
                "endpoint": f"{method} {path}",
                "fields": sorted(hits),
                "open_additional": open_additional,
            })
    findings.sort(key=lambda f: f["endpoint"])
    return findings


def _find_insecure_servers(spec):
    """Plaintext HTTP server URLs — credentials/tokens travel unencrypted."""
    servers = spec.get("servers")
    if not isinstance(servers, list):
        return []
    return sorted({
        str(s.get("url"))
        for s in servers
        if isinstance(s, dict) and str(s.get("url", "")).strip().lower().startswith("http://")
    })


def _find_deprecated_endpoints(spec):
    """OWASP API9:2023 — endpoints marked deprecated in the spec but still
    live/routable. Classic 'zombie API' improper-inventory risk."""
    return sorted(
        f"{method} {path}"
        for path, method, details in _iter_endpoints(spec)
        if details.get("deprecated") is True
    )


def _find_weak_apikey_schemes(spec):
    """apiKey auth transmitted via query string or cookie instead of a
    header — leaks into server/proxy access logs, browser history, and
    Referer headers."""
    schemes = ((spec.get("components") or {}).get("securitySchemes")) or {}
    if not isinstance(schemes, dict):
        return []
    return sorted(
        f"{name} (apiKey in {s.get('in')})"
        for name, s in schemes.items()
        if isinstance(s, dict) and s.get("type") == "apiKey" and s.get("in") in ("query", "cookie")
    )


def _find_get_with_body(spec):
    """GET requests that declare a requestBody — non-standard, and a common
    sign the endpoint actually causes a side effect despite the 'safe' verb
    (breaks caching/idempotency assumptions and can bypass GET-only auth
    middleware)."""
    return sorted(
        f"{method} {path}"
        for path, method, details in _iter_endpoints(spec)
        if method == "GET" and details.get("requestBody")
    )


_SPEC_SECRET_PATTERNS = [
    ("AWS Access Key",    re.compile(r'AKIA[0-9A-Z]{16}')),
    ("Generic JWT",        re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ("Slack Token",        re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}')),
    ("Private Key Block",  re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("Hardcoded Secret Assignment",
     re.compile(r'(?i)(api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']')),
]

def _find_leaked_secrets_in_spec(spec):
    """Real credentials/tokens accidentally left in `example`/`default`
    values are a surprisingly common find in harvested/dev-portal specs —
    someone pastes a working token into an example and it ships."""
    findings = []

    def _check_value(val, where):
        if not isinstance(val, str):
            return
        for name, pattern in _SPEC_SECRET_PATTERNS:
            if pattern.search(val):
                findings.append({"type": name, "location": where, "value": val[:60]})
                return

    def walk(node, where):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("example", "default"):
                    _check_value(v, where)
                elif k == "examples" and isinstance(v, dict):
                    for ex in v.values():
                        _check_value(ex.get("value") if isinstance(ex, dict) else ex, where)
                else:
                    walk(v, where)
        elif isinstance(node, list):
            for item in node:
                walk(item, where)

    for path, method, details in _iter_endpoints(spec):
        walk(details, f"{method} {path}")
    walk(spec.get("components") or {}, "components")
    return findings


def _health_score(audit):
    total = len(audit["unique_apis"])
    if total == 0:
        return 100
    # Dangerous endpoints are weighted by their OWN severity, not a flat
    # per-item rate — a pile of MEDIUM debug matches must not crater the
    # score as hard as the same number of CRITICAL execute/SQL findings.
    dangerous_item_weight = {"CRITICAL": 4.0, "HIGH": 2.5, "MEDIUM": 1.0}
    dangerous_penalty = sum(
        dangerous_item_weight.get(item["severity"], 1.0)
        for item in audit["dangerous_endpoints"]
    )
    # A leaked real secret is its own category of bad — weight it heavily
    # even though it's usually only 1-2 hits per spec.
    leaked_secrets_penalty = len(audit["leaked_secrets"]) * 5.0
    weights = {
        "unsecured":               3.0,
        # High-signal privilege fields / open additionalProperties only
        "mass_assignment_risk":    2.5,
        "sensitive_data_exposure": 2.0,
        "undefined_refs":          2.0,
        "weak_apikey_schemes":     1.5,
        "insecure_servers":        1.5,
        # Spec-style lint — lightly weighted so inventory noise doesn't tank score
        "duplicates":              0.3,
        "get_with_body":           0.5,
        "missing_responses":       0.2,
        "deprecated_endpoints":    0.3,
    }
    penalty = (
        dangerous_penalty + leaked_secrets_penalty
        + sum(len(audit[k]) * w for k, w in weights.items())
    )
    return max(0, round(100 - (penalty / total) * 10))


def _convert_oas2_security_scheme(sdef):
    """Best-effort OAS2 securityDefinitions entry → OAS3 securitySchemes shape."""
    if not isinstance(sdef, dict):
        return sdef
    out = dict(sdef)
    t = (out.get("type") or "").lower()
    if t == "basic":
        out["type"] = "http"
        out["scheme"] = "basic"
    elif t == "oauth2":
        flow = (out.pop("flow", None) or "implicit").lower()
        flows = {}
        flow_obj = {}
        if out.get("authorizationUrl"):
            flow_obj["authorizationUrl"] = out.pop("authorizationUrl")
        if out.get("tokenUrl"):
            flow_obj["tokenUrl"] = out.pop("tokenUrl")
        if isinstance(out.get("scopes"), dict):
            flow_obj["scopes"] = out.pop("scopes")
        else:
            flow_obj["scopes"] = {}
        flow_key = {
            "implicit": "implicit",
            "password": "password",
            "application": "clientCredentials",
            "accesscode": "authorizationCode",
            "access_code": "authorizationCode",
        }.get(flow, "implicit")
        flows[flow_key] = flow_obj
        out["type"] = "oauth2"
        out["flows"] = flows
    return out


def _rewrite_oas2_refs(node):
    """Rewrite #/definitions/X → #/components/schemas/X (in-place)."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/definitions/"):
            node["$ref"] = "#/components/schemas/" + ref[len("#/definitions/"):]
        for v in node.values():
            _rewrite_oas2_refs(v)
    elif isinstance(node, list):
        for item in node:
            _rewrite_oas2_refs(item)


def _convert_oas2_body_params(spec):
    """Move in:body / in:formData parameters into requestBody (OAS3 shape)."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in list(methods.items()):
            if method.lower() not in VALID_METHODS or not isinstance(details, dict):
                continue
            params = details.get("parameters")
            if not isinstance(params, list):
                continue
            keep, body_schema, form_props, consumes = [], None, {}, None
            consumes = details.get("consumes") or spec.get("consumes") or ["application/json"]
            if isinstance(consumes, str):
                consumes = [consumes]
            for p in params:
                if not isinstance(p, dict):
                    keep.append(p)
                    continue
                # Skip unresolved $ref params here — ref walker still sees them
                if "$ref" in p:
                    keep.append(p)
                    continue
                loc = (p.get("in") or "").lower()
                if loc == "body":
                    body_schema = p.get("schema") or {"type": "object"}
                elif loc == "formdata":
                    name = p.get("name") or "field"
                    prop = {k: v for k, v in p.items() if k not in ("in", "name")}
                    form_props[name] = prop
                else:
                    keep.append(p)
            details["parameters"] = keep
            if body_schema is not None and "requestBody" not in details:
                ctype = consumes[0] if consumes else "application/json"
                details["requestBody"] = {
                    "content": {ctype: {"schema": body_schema}}
                }
            elif form_props and "requestBody" not in details:
                ctype = "multipart/form-data"
                if any(str(c).startswith("application/x-www-form") for c in consumes):
                    ctype = "application/x-www-form-urlencoded"
                details["requestBody"] = {
                    "content": {
                        ctype: {
                            "schema": {"type": "object", "properties": form_props}
                        }
                    }
                }


def normalize_spec(spec):
    """
    Normalize OpenAPI 2.0 (swagger: '2.0') into an OAS3-shaped dict so the
    rest of the auditor can run unchanged. OAS3 specs are returned as a
    deep copy with no structural change.
    """
    from copy import deepcopy
    if not isinstance(spec, dict):
        return spec
    out = deepcopy(spec)
    oas = str(out.get("openapi") or "")
    swagger = str(out.get("swagger") or "")
    if oas.startswith("3"):
        out["_normalized_from"] = "openapi3"
        return out
    if not swagger.startswith("2"):
        out["_normalized_from"] = "unknown"
        return out

    components = dict(out.get("components") or {})

    # definitions → components.schemas
    defs = out.pop("definitions", None)
    if isinstance(defs, dict):
        schemas = dict(components.get("schemas") or {})
        schemas.update(defs)
        components["schemas"] = schemas

    # securityDefinitions → components.securitySchemes
    secdefs = out.pop("securityDefinitions", None)
    if isinstance(secdefs, dict):
        schemes = dict(components.get("securitySchemes") or {})
        for name, sdef in secdefs.items():
            schemes[name] = _convert_oas2_security_scheme(sdef)
        components["securitySchemes"] = schemes

    # top-level parameters / responses
    for key, dest in (("parameters", "parameters"), ("responses", "responses")):
        block = out.pop(key, None)
        if isinstance(block, dict):
            merged = dict(components.get(dest) or {})
            merged.update(block)
            components[dest] = merged

    out["components"] = components

    # servers from host / basePath / schemes
    if not out.get("servers"):
        host = (out.get("host") or "localhost").strip()
        base = out.get("basePath") or ""
        if base and not str(base).startswith("/"):
            base = "/" + str(base)
        schemes = out.get("schemes") or ["https"]
        if not isinstance(schemes, list) or not schemes:
            schemes = ["https"]
        out["servers"] = [
            {"url": f"{sch}://{host}{base}"} for sch in schemes if sch
        ]

    _convert_oas2_body_params(out)
    _rewrite_oas2_refs(out)

    out["openapi"] = out.get("openapi") or "3.0.0"
    out.pop("swagger", None)
    out["_normalized_from"] = "swagger2"
    return out


def run_audit(spec, filename="spec", strict_unsecured=True):
    spec = normalize_spec(spec)
    info_block = spec.get("info", {})
    # Raw unsecured (incl. public) drives "unauthenticated" on dangerous findings
    raw_unsecured = _find_unsecured_paths(spec)
    unsecured, public_expected = _split_unsecured(spec, strict=strict_unsecured)
    audit = {
        "filename":          filename,
        "spec_title":        info_block.get("title", filename),
        "spec_version":      info_block.get("version", "-"),
        "spec_format":       spec.get("_normalized_from") or "unknown",
        "scanned_at":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "unique_apis":       _count_unique_apis(spec),
        "dangerous_endpoints": _find_dangerous_endpoints(
            spec, unsecured_set=set(raw_unsecured)
        ),
        "unsecured":         unsecured,
        "public_expected":   public_expected,
        "strict_unsecured":  bool(strict_unsecured),
        "duplicates":        _find_duplicate_paths(spec),
        "multi_methods":     _find_multi_method_paths(spec),
        "undefined_refs":    _find_undefined_param_refs(spec),
        "external_refs":     _find_external_refs(spec),
        "missing_responses": _find_missing_responses(spec),
        "no_operation_id":   _find_no_operation_id(spec),
        "security_schemes":  _get_security_schemes(spec),
        "global_security":   _global_security_present(spec),
        # OWASP-API-Top-10-aligned static checks
        "sensitive_data_exposure": _find_sensitive_data_exposure(spec),
        "mass_assignment_risk":    _find_mass_assignment_risk(spec),
        "insecure_servers":        _find_insecure_servers(spec),
        "deprecated_endpoints":    _find_deprecated_endpoints(spec),
        "weak_apikey_schemes":     _find_weak_apikey_schemes(spec),
        "get_with_body":           _find_get_with_body(spec),
        "leaked_secrets":          _find_leaked_secrets_in_spec(spec),
    }
    audit["health_score"] = _health_score(audit)
    return audit


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT-SAFETY HELPERS
#   The uploaded spec's own filename/paths/titles are untrusted input that
#   flows straight into HTTP headers and exported files — guard both.
# ─────────────────────────────────────────────────────────────────────────────
def _safe_filename(name: str) -> str:
    """Strip characters that could break a Content-Disposition header value
    or produce a hidden/path-traversal-ish filename on save."""
    name = re.sub(r'[\r\n"\\/\x00-\x1f]', "_", str(name or "spec"))
    return name.strip() or "spec"


_CSV_FORMULA_LEAD_CHARS = ("=", "+", "-", "@", "\t", "\r")

def _csv_safe(value) -> str:
    """OWASP CSV-injection guard: a cell starting with =/+/-/@ can be
    interpreted as a formula by Excel/Sheets when the export is opened.
    Prefixing with a single quote neutralises it without changing what's
    displayed. Spec-derived strings (endpoint paths, descriptions) are
    exactly the kind of untrusted text this needs to cover."""
    s = str(value)
    return "'" + s if s and s[0] in _CSV_FORMULA_LEAD_CHARS else s


# ─────────────────────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

def _fill_path_template(path: str) -> str:
    """Replace {param} placeholders with harmless probe values."""
    def _repl(m):
        name = (m.group(1) or "").lower()
        if "uuid" in name or name.endswith("id") or name == "id":
            return "1"
        if "email" in name:
            return "probe@example.com"
        return "test"
    return re.sub(r"\{([^}/]+)\}", _repl, path or "")


def _classify_probe_status(code, error=None):
    if error:
        return "unreachable"
    if code in (401, 403):
        return "auth_required"
    if code == 404:
        return "not_found"
    if 200 <= code < 300:
        return "open_ok"
    if 500 <= code < 600:
        return "server_error"
    return "other"


def run_live_probes(base_url, audit, auth_header="", timeout=5, max_probes=40):
    """
    Light verification: safe probes only.
    - GET/HEAD/OPTIONS endpoints → same method
    - POST/PUT/PATCH/DELETE → OPTIONS only (never send destructive bodies)
    Targets: Unsecured + Dangerous endpoints (deduped, capped).
    """
    try:
        import requests
    except ImportError:
        return [{"endpoint": "(probe)", "error": "requests not installed", "verdict": "unreachable"}]

    try:
        base = _assert_safe_probe_base(base_url)
    except ValueError as e:
        return [{
            "endpoint": "(probe)",
            "probe_method": "-",
            "url": (base_url or "").strip(),
            "status": None,
            "verdict": "unreachable",
            "error": f"SSRF blocked: {e}",
        }]

    targets = []
    seen = set()
    for ep in (audit.get("unsecured") or []):
        if ep not in seen:
            seen.add(ep)
            targets.append(ep)
    for item in (audit.get("dangerous_endpoints") or []):
        ep = item.get("endpoint") if isinstance(item, dict) else str(item)
        if ep and ep not in seen:
            seen.add(ep)
            targets.append(ep)

    headers = {"User-Agent": "API-Sentinel-SwaggerScan-Probe/1.0", "Accept": "*/*"}
    auth = (auth_header or "").strip()
    if auth:
        if not auth.lower().startswith(("bearer ", "basic ")):
            headers["Authorization"] = f"Bearer {auth}"
        else:
            headers["Authorization"] = auth

    results = []
    for ep in targets[:max_probes]:
        parts = str(ep).split(" ", 1)
        if len(parts) != 2:
            continue
        method, path = parts[0].upper(), parts[1]
        # Never fire mutating methods — OPTIONS only
        probe_method = method if method in ("GET", "HEAD", "OPTIONS") else "OPTIONS"
        url = base + _fill_path_template(path)
        entry = {
            "endpoint": ep,
            "probe_method": probe_method,
            "url": url,
            "status": None,
            "verdict": "unreachable",
            "error": "",
        }
        try:
            resp = requests.request(
                probe_method, url, headers=headers,
                timeout=timeout, allow_redirects=False, verify=False,
            )
            entry["status"] = resp.status_code
            entry["verdict"] = _classify_probe_status(resp.status_code)
        except Exception as e:
            entry["error"] = str(e)[:160]
            entry["verdict"] = "unreachable"
        results.append(entry)
    return results


def _as_bool(val, default=False) -> bool:
    """Form fields arrive as strings; coerce reliably."""
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


@app.post("/scan")
async def scan(
    file: UploadFile = File(...),
    strict_unsecured: str = Form("true"),
    live_probe: str = Form("false"),
    base_url: str = Form(""),
    auth_header: str = Form(""),
):
    _prune_old_jobs()

    filename = file.filename or "spec"
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Spec too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).",
        )

    # Parse
    try:
        if filename.endswith(".json"):
            spec = json.loads(content)
        elif filename.endswith((".yaml", ".yml")):
            if not _YAML:
                raise HTTPException(status_code=400, detail="PyYAML not installed — upload .json instead.")
            spec = yaml.safe_load(content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format — use .json / .yaml / .yml")
    except HTTPException:
        raise
    except (json.JSONDecodeError, Exception) as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {str(e)}")

    if not isinstance(spec, dict) or "paths" not in spec:
        raise HTTPException(status_code=400, detail="Not a valid OpenAPI spec — 'paths' key missing.")

    strict = _as_bool(strict_unsecured, default=True)
    do_probe = _as_bool(live_probe, default=False)

    # Run audit
    audit = run_audit(spec, filename, strict_unsecured=strict)

    # Optional light live probe (safe methods only + SSRF guard)
    if do_probe and (base_url or "").strip():
        try:
            audit["live_probes"] = run_live_probes(
                base_url, audit, auth_header=auth_header or ""
            )
        except Exception as e:
            audit["live_probes"] = [{
                "endpoint": "(probe)", "verdict": "unreachable",
                "error": str(e)[:160], "status": None, "probe_method": "-", "url": "",
            }]
    else:
        audit["live_probes"] = []

    # Store for export
    job_id = str(uuid.uuid4())
    jobs[job_id] = audit
    _job_created_at[job_id] = time.time()

    # Return slim JSON (unique_apis list can be large — include it)
    return {"job_id": job_id, **audit}


@app.get("/export/csv")
def export_csv(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    audit = jobs[job_id]

    rows = []
    for item in audit.get("dangerous_endpoints", []):
        auth_tag = " [UNAUTHENTICATED]" if item["unauthenticated"] else ""
        detail = (f"{item['endpoint']} — {item['category']} "
                  f"(matched: {', '.join(item['matched_keywords'])}){auth_tag} "
                  f"| CWE: {item['cwe']} | OWASP: {item['owasp']} "
                  f"| CVSS: {item['cvss_score']} ({item['cvss_vector']}) "
                  f"| Spec description: {item['summary'] or '(none)'} "
                  f"| Recommendation: {item['recommendation']} "
                  f"| Note: {item['exploitation_note']}")
        rows.append({
            "Category":  "Dangerous Endpoint",
            "Severity":  item["severity"].lower(),
            "Detail":    _csv_safe(detail),
            "Timestamp": audit["scanned_at"],
        })

    categories = [
        ("Unique API",          audit["unique_apis"],        "info"),
        ("Unsecured",           audit["unsecured"],          "critical"),
        ("Expected Public (allowlisted)", audit.get("public_expected") or [], "info"),
        ("Live Probe", [
            f"{p.get('endpoint')} [{p.get('probe_method')}] → {p.get('status')} ({p.get('verdict')})"
            for p in (audit.get("live_probes") or [])
         ], "info"),
        ("Duplicate",           audit["duplicates"],         "warning"),
        ("Multi-Method Path",   audit["multi_methods"],      "info"),
        ("Broken $ref",         audit["undefined_refs"],     "high"),
        ("External $ref (unresolved)", audit.get("external_refs") or [], "info"),
        ("Missing Responses",   audit["missing_responses"],  "medium"),
        ("No OperationId",      audit["no_operation_id"],    "low"),
        ("Deprecated Endpoint (still live)", audit["deprecated_endpoints"], "low"),
        ("GET With Request Body",            audit["get_with_body"],       "medium"),
        ("Insecure Server (http://)",        audit["insecure_servers"],    "high"),
        ("Weak apiKey Placement",            audit["weak_apikey_schemes"], "medium"),
    ]
    for category, items, severity in categories:
        for item in items:
            rows.append({
                "Category":  category,
                "Severity":  severity,
                "Detail":    _csv_safe(item),
                "Timestamp": audit["scanned_at"],
            })

    for item in audit.get("sensitive_data_exposure", []):
        rows.append({
            "Category":  "Sensitive Data Exposure (response)",
            "Severity":  "high",
            "Detail":    _csv_safe(f"{item['endpoint']} — fields: {', '.join(item['fields'])}"),
            "Timestamp": audit["scanned_at"],
        })

    for item in audit.get("mass_assignment_risk", []):
        rows.append({
            "Category":  "Mass Assignment Risk (request body)",
            "Severity":  "high",
            "Detail":    _csv_safe(f"{item['endpoint']} — writable fields: {', '.join(item['fields'])}"),
            "Timestamp": audit["scanned_at"],
        })

    for item in audit.get("leaked_secrets", []):
        rows.append({
            "Category":  "Leaked Secret in Spec Example",
            "Severity":  "critical",
            "Detail":    _csv_safe(f"{item['type']} at {item['location']} — {item['value']}"),
            "Timestamp": audit["scanned_at"],
        })

    if not rows:
        rows.append({"Category": "-", "Severity": "-", "Detail": "No issues found.", "Timestamp": audit["scanned_at"]})

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["Category", "Severity", "Detail", "Timestamp"])
    writer.writeheader()
    writer.writerows(rows)

    filename = _safe_filename(audit["filename"]).rsplit(".", 1)[0] + ".csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/export/html")
def export_html(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    audit = jobs[job_id]

    score       = audit["health_score"]
    total       = len(audit["unique_apis"])
    score_color = "#22c55e" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")

    def sev_badge(s):
        colors = {
            "critical": ("#fef2f2","#ef4444","#7f1d1d"),
            "high":     ("#fff7ed","#f97316","#7c2d12"),
            "warning":  ("#fefce8","#eab308","#713f12"),
            "medium":   ("#f0fdf4","#22c55e","#14532d"),
            "low":      ("#f8fafc","#94a3b8","#334155"),
            "info":     ("#eff6ff","#3b82f6","#1e3a5f"),
        }
        bg, border, text = colors.get(s, colors["info"])
        return (f'<span style="background:{bg};color:{text};border:1px solid {border};'
                f'padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600">'
                f'{s.upper()}</span>')

    def make_table(items, sev):
        if not items:
            return '<p style="color:#22c55e;margin:0 0 20px;font-size:13px">&#10003; No issues found.</p>'
        rows_html = "".join(
            f"<tr><td style='color:#64748b;width:40px'>{i+1}</td>"
            f"<td><code>{_h(str(item))}</code></td>"
            f"<td>{sev_badge(sev)}</td></tr>"
            for i, item in enumerate(items)
        )
        return (
            "<table><thead><tr><th>#</th><th>Detail</th><th>Severity</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
        )

    def make_dangerous_table(items):
        if not items:
            return '<p style="color:#22c55e;margin:0 0 20px;font-size:13px">&#10003; No dangerous-by-design endpoints detected.</p>'
        rows = []
        for i, item in enumerate(items):
            auth_html = (
                '<span style="color:#ef4444;font-weight:700">NO AUTH REQUIRED</span>'
                if item["unauthenticated"] else
                '<span style="color:#94a3b8">Secured</span>'
            )
            uid = f"dz-{i}"
            # endpoint / summary are spec-controlled (attacker could name a
            # path "<script>...") and must be escaped; category / recommendation
            # / cwe / owasp / cvss come from our own fixed CATEGORY_META table,
            # not the spec, so they're inherently safe to render as-is.
            rows.append(
                f"<tr class='clickable' onclick=\"toggleRow('{uid}')\">"
                f"<td style='color:#64748b;width:32px'>{i+1}</td>"
                f"<td><code>{_h(item['endpoint'])}</code></td>"
                f"<td style='font-size:11px'>{item['category']}</td>"
                f"<td style='color:#7dd3fc;font-size:11px'>{', '.join(item['matched_keywords'])}</td>"
                f"<td>{auth_html}</td>"
                f"<td>{sev_badge(item['severity'].lower())}</td>"
                f"<td style='font-family:monospace;font-size:11px;color:#f0abfc'>{item['cvss_score']}</td>"
                f"<td style='color:#64748b;font-size:16px;text-align:center'>▾</td></tr>"
                f"<tr id='{uid}' class='detail-row' style='display:none'>"
                f"<td colspan='8' style='background:#0f172a'>"
                f"<div style='padding:14px 18px'>"
                f"<p style='margin-bottom:6px'><strong style='color:#94a3b8'>Spec description:</strong> "
                f"<em>{_h(item['summary']) if item['summary'] else '(none provided in spec)'}</em></p>"
                f"<p style='margin-bottom:6px'><strong style='color:#94a3b8'>Impact:</strong> {item['impact']}</p>"
                f"<p style='margin-bottom:6px'><strong style='color:#94a3b8'>Recommendation:</strong> {item['recommendation']}</p>"
                f"<p style='margin-bottom:6px'><strong style='color:#94a3b8'>CWE:</strong> {item['cwe']} "
                f"&nbsp;|&nbsp; <strong style='color:#94a3b8'>OWASP:</strong> {item['owasp']}</p>"
                f"<p style='margin-bottom:6px'><strong style='color:#94a3b8'>Suggested CVSS 3.1:</strong> "
                f"{item['cvss_score']} — <code>{item['cvss_vector']}</code> "
                f"<span style='color:#f59e0b;font-size:11px'>(template default for this category — verify against actual business impact)</span></p>"
                f"<p><strong style='color:#94a3b8'>Exploitation note:</strong> {item['exploitation_note']}</p>"
                f"</div></td></tr>"
            )
        return (
            "<table><thead><tr><th>#</th><th>Endpoint</th><th>Category</th>"
            "<th>Matched Keywords</th><th>Auth</th><th>Severity</th><th>CVSS</th><th></th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def make_fields_table(items, sev, field_label):
        """Renders {endpoint, fields:[...]} lists — sensitive-data-exposure
        and mass-assignment findings share this shape."""
        if not items:
            return '<p style="color:#22c55e;margin:0 0 20px;font-size:13px">&#10003; None found.</p>'
        rows_html = "".join(
            f"<tr><td style='color:#64748b;width:32px'>{i+1}</td>"
            f"<td><code>{_h(item['endpoint'])}</code></td>"
            f"<td style='color:#f0abfc;font-size:11px'>{_h(', '.join(item['fields']))}</td>"
            f"<td>{sev_badge(sev)}</td></tr>"
            for i, item in enumerate(items)
        )
        return (
            f"<table><thead><tr><th>#</th><th>Endpoint</th><th>{field_label}</th><th>Severity</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
        )

    def make_secrets_table(items):
        if not items:
            return '<p style="color:#22c55e;margin:0 0 20px;font-size:13px">&#10003; No hardcoded secrets found in spec examples.</p>'
        rows_html = "".join(
            f"<tr><td style='color:#64748b;width:32px'>{i+1}</td>"
            f"<td>{_h(item['type'])}</td>"
            f"<td><code>{_h(item['location'])}</code></td>"
            f"<td style='color:#f87171;font-family:monospace;font-size:11px'>{_h(item['value'])}</td>"
            f"<td>{sev_badge('critical')}</td></tr>"
            for i, item in enumerate(items)
        )
        return (
            "<table><thead><tr><th>#</th><th>Type</th><th>Location</th><th>Value (truncated)</th><th>Severity</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
        )

    dangerous_count_pill = (
        f'<span style="background:#334155;color:#e2e8f0;padding:2px 10px;'
        f'border-radius:9999px;font-size:12px;font-weight:700;margin-left:8px">'
        f'{len(audit["dangerous_endpoints"])}</span>'
    )
    dangerous_section_html = (
        "<section>"
        f"<h2>💀 Dangerous Endpoints (Code/SQL Execution, Admin Proxy, etc.){dangerous_count_pill}</h2>"
        '<p class="desc">Endpoints whose path / operationId / summary / description / tags match naming '
        "patterns for arbitrary code execution, raw SQL execution, admin/IAM privilege escalation, "
        "destructive mutation, deserialization or debug surfaces. This is a static naming heuristic — "
        "verify each match manually (ideally by invoking it with a valid token) before reporting it as exploited. "
        "<strong style='color:#f0abfc'>Click any row for the full write-up</strong> (impact, CWE/OWASP, suggested CVSS, recommendation).</p>"
        f"{make_dangerous_table(audit['dangerous_endpoints'])}"
        "</section>"
    )

    def _count_pill(n):
        return (f'<span style="background:#334155;color:#e2e8f0;padding:2px 10px;'
                f'border-radius:9999px;font-size:12px;font-weight:700;margin-left:8px">{n}</span>')

    owasp_section_html = (
        "<section>"
        f"<h2>🕵️ Sensitive Data Exposure — Response Schemas{_count_pill(len(audit['sensitive_data_exposure']))}</h2>"
        '<p class="desc">OWASP API3:2023 — 2xx response schemas with high-signal sensitive fields '
        "(password, accessToken, SSN, credit card…). Bare token/secret/pin skipped to cut FPs. "
        "A lead that the field may be returned to clients, not proof it's populated at runtime.</p>"
        f"{make_fields_table(audit['sensitive_data_exposure'], 'high', 'Sensitive Fields')}"
        "</section>"
        "<section>"
        f"<h2>✍️ Mass Assignment Risk — Request Bodies{_count_pill(len(audit['mass_assignment_risk']))}</h2>"
        '<p class="desc">OWASP API6:2023 — POST/PUT/PATCH bodies accepting high-signal privilege fields '
        "(isAdmin, superuser, ownerId, balance…) or open additionalProperties. "
        "Common fields like permissions/status/role are ignored to reduce false positives.</p>"
        f"{make_fields_table(audit['mass_assignment_risk'], 'high', 'Writable Privileged Fields')}"
        "</section>"
        "<section>"
        f"<h2>🔑 Leaked Secrets in Spec Examples{_count_pill(len(audit['leaked_secrets']))}</h2>"
        '<p class="desc">Hardcoded credentials/tokens accidentally left in example/default values — a surprisingly '
        "common find in harvested or dev-portal specs.</p>"
        f"{make_secrets_table(audit['leaked_secrets'])}"
        "</section>"
    )

    sections_cfg = [
        ("📋 All Unique Endpoints",         audit["unique_apis"],        "info",     f"All {total} unique endpoints discovered."),
        ("🔓 Unsecured Endpoints",           audit["unsecured"],          "critical", "No security definition and not covered by global policy (public allowlist applied unless strict mode)."),
        ("🌐 Expected Public Endpoints",     audit.get("public_expected") or [], "info",
         "Unauthenticated but allowlisted as intentional public surfaces (health, login, oauth, docs…). Not scored as Unsecured."),
        ("🌐 Insecure Servers (http://)",    audit["insecure_servers"],   "high",     "Server URLs using plaintext HTTP — credentials/tokens travel unencrypted."),
        ("🗝️ Weak apiKey Placement",         audit["weak_apikey_schemes"], "medium",  "apiKey auth carried in the query string or a cookie instead of a header — leaks into logs/history."),
        ("📡 GET With Request Body",         audit["get_with_body"],      "medium",   "GET operations that declare a requestBody — non-standard and often hides a real side effect."),
        ("🧟 Deprecated Endpoints (still live)", audit["deprecated_endpoints"], "low", "Marked deprecated in the spec but still routable — classic zombie-API inventory risk."),
        ("🔁 Duplicate Endpoints",           audit["duplicates"],         "warning",  "Spec lint — same METHOD + path defined more than once."),
        ("🔀 Multiple Methods on Same Path", audit["multi_methods"],      "info",     "Spec lint / inventory — normal REST often uses multiple methods on one path."),
        ("🔗 Broken \$refs",                 audit["undefined_refs"],     "high",
         "Local \$refs pointing to undefined components (parameters, schemas, requestBodies, responses, …)."),
        ("📎 External \$refs (unresolved)",  audit.get("external_refs") or [], "info",
         "Non-local \$refs (other files/URLs) — not fetched during this static scan."),
        ("📭 Missing Response Definitions",  audit["missing_responses"],  "medium",   "Spec lint — endpoints with no 'responses' block defined."),
        ("🏷️ Missing operationId",           audit["no_operation_id"],    "low",      "Spec lint — endpoints without an operationId field."),
    ]

    sec_html = ""
    for heading, items, sev, desc in sections_cfg:
        sec_html += (
            f"<section>"
            f"<h2>{heading}{_count_pill(len(items))}</h2>"
            f'<p class="desc">{desc}</p>'
            f"{make_table(items, sev)}"
            "</section>"
        )

    summary_rows = [
        ("💀 Dangerous Endpoints",  len(audit["dangerous_endpoints"]), "#dc2626"),
        ("🔑 Leaked Secrets",       len(audit["leaked_secrets"]),      "#b91c1c"),
        ("Total Unique Endpoints", total,                             "#3b82f6"),
        ("Unsecured Endpoints",    len(audit["unsecured"]),           "#ef4444"),
        ("Sensitive Data Exposure", len(audit["sensitive_data_exposure"]), "#f97316"),
        ("Mass Assignment Risk",   len(audit["mass_assignment_risk"]), "#f97316"),
        ("Duplicate Endpoints",    len(audit["duplicates"]),          "#f59e0b"),
        ("Broken \$refs",          len(audit["undefined_refs"]),      "#ef4444"),
        ("Missing Responses",      len(audit["missing_responses"]),   "#f97316"),
        ("No OperationId",         len(audit["no_operation_id"]),     "#94a3b8"),
    ]
    sum_rows_html = ""
    for lbl, cnt, col in summary_rows:
        dot = f'<span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:{col};margin-right:7px"></span>'
        sum_rows_html += f"<tr><td>{dot}{lbl}</td><td style='font-weight:700;color:{col}'>{cnt}</td></tr>"

    # security_schemes / spec_title / spec_version / filename all come straight
    # from the uploaded (untrusted) spec — must be HTML-escaped before going
    # into the report, or a malicious spec becomes stored XSS the moment
    # someone opens the exported report in a browser.
    scheme_pills = "".join(
        f'<span style="background:#1e3a5f;color:#7dd3fc;border:1px solid #1d4ed8;padding:2px 10px;border-radius:999px;font-size:12px;margin-right:6px">{_h(s)}</span>'
        for s in audit["security_schemes"]
    ) or '<span style="color:#94a3b8;font-size:13px">None defined</span>'

    global_sec_html = (
        '<span style="color:#22c55e">&#10003; Global security policy is present</span>'
        if audit["global_security"] else
        '<span style="color:#f59e0b">&#9888; No global security policy set</span>'
    )

    spec_title_safe   = _h(str(audit["spec_title"]))
    spec_version_safe = _h(str(audit["spec_version"]))
    filename_safe      = _h(str(audit["filename"]))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Swagger Scan Report — {spec_title_safe}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
header{{background:linear-gradient(135deg,#1a2744,#1e293b);padding:36px 48px 28px;border-bottom:1px solid #1e293b}}
header h1{{font-size:26px;font-weight:800;color:#f8fafc;letter-spacing:-.4px}}
header .meta{{font-size:12px;color:#94a3b8;margin-top:5px}}
main{{max-width:1100px;margin:0 auto;padding:28px 24px 64px}}
.score-card{{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:22px 28px;margin-bottom:28px;display:flex;align-items:center;gap:28px;flex-wrap:wrap}}
.score-ring{{font-size:48px;font-weight:900;color:{score_color};line-height:1}}
.score-bar-bg{{background:#334155;border-radius:999px;height:12px;overflow:hidden;margin-top:6px}}
.score-bar-fill{{height:100%;width:{score}%;background:{score_color};border-radius:999px}}
.summary-table table{{width:100%;border-collapse:collapse;font-size:13px}}
.summary-table td{{padding:4px 10px;border-bottom:1px solid #1e293b}}
.summary-table tr:last-child td{{border-bottom:none}}
section{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px 24px;margin-bottom:18px}}
section h2{{font-size:15px;font-weight:700;color:#f1f5f9;margin-bottom:5px}}
.desc{{font-size:12px;color:#94a3b8;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#0f172a;color:#94a3b8;text-align:left;padding:8px 10px;border-bottom:2px solid #334155;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.5px}}
td{{padding:8px 10px;border-bottom:1px solid #1e293b;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#ffffff06}}
code{{background:#0f172a;color:#7dd3fc;padding:2px 5px;border-radius:4px;font-size:11px;word-break:break-all}}
footer{{text-align:center;font-size:11px;color:#475569;padding:20px}}
tr.clickable{{cursor:pointer}}
tr.clickable:hover td{{background:#1a2744}}
tr.detail-row td{{border-bottom:2px solid #334155}}
tr.detail-row p{{font-size:12px;color:#cbd5e1;margin-bottom:6px}}
</style>
<script>
function toggleRow(id){{
  var row = document.getElementById(id);
  if (!row) return;
  row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</head>
<body>
<header>
  <h1>🔍 Swagger Scan — OpenAPI Audit Report</h1>
  <div class="meta">
    Spec: <strong style="color:#e2e8f0">{spec_title_safe}</strong>
    &nbsp;|&nbsp; Version: {spec_version_safe}
    &nbsp;|&nbsp; File: {filename_safe}
    &nbsp;|&nbsp; Generated: {audit['scanned_at']}
  </div>
</header>
<main>
  <div class="score-card">
    <div>
      <div class="score-ring">{score}%</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:3px">API Health Score</div>
    </div>
    <div style="flex:1;min-width:180px">
      <div style="font-size:12px;color:#94a3b8;font-weight:600">Overall Quality</div>
      <div class="score-bar-bg" style="margin-top:6px"><div class="score-bar-fill"></div></div>
      <div style="font-size:11px;color:#64748b;margin-top:4px">Weighted: security × 3, broken refs × 2, duplicates × 1.5</div>
    </div>
    <div class="summary-table" style="flex:1;min-width:220px">
      <table>{sum_rows_html}</table>
    </div>
  </div>
  <section>
    <h2>🛡️ Security Configuration</h2>
    <p class="desc">Security schemes defined and global policy status.</p>
    <p style="font-size:13px;margin-bottom:8px"><strong style="color:#94a3b8">Schemes:</strong> &nbsp;{scheme_pills}</p>
    <p style="font-size:13px">{global_sec_html}</p>
  </section>
  {dangerous_section_html}
  {owasp_section_html}
  {sec_html}
</main>
<footer>Generated by <strong>Swagger Scan</strong> (OOScope engine) &bull; {audit['scanned_at']}</footer>
</body>
</html>"""

    filename = _safe_filename(audit["filename"]).rsplit(".", 1)[0] + ".html"
    return StreamingResponse(
        iter([html]),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
