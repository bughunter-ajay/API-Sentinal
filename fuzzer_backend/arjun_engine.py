"""
Arjun Engine — Native HTTP Parameter Discovery
Implements differential response analysis to detect hidden GET/POST/JSON parameters.
"""

from __future__ import annotations

import copy
import json
import os
import random
import re
import string
import threading
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

# Drop InsecureRequestWarning for self-signed SSL targets
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# Curated High-Impact API Parameter Wordlist (~1,000 top parameters)
ARJUN_DEFAULT_WORDLIST: List[str] = [
    # Top Critical & Administrative
    "debug", "test", "admin", "adm", "root", "role", "roles", "privilege", "privileges",
    "superuser", "su", "sudo", "impersonate", "switch_user", "act_as", "masquerade",
    "as_user", "on_behalf_of", "internal", "private", "hidden", "beta", "preview",
    "dev", "development", "staging", "sandbox", "dry_run", "test_mode", "mock",
    
    # Auth, Tokens & Keys
    "token", "access_token", "auth_token", "session_token", "api_token", "bearer",
    "jwt", "key", "api_key", "apikey", "secret", "secret_key", "private_key",
    "client_id", "client_secret", "signature", "sig", "hash", "code", "otp",
    "pin", "password", "pass", "pwd", "auth", "authorize", "authenticated",
    "csrf", "csrf_token", "xsrf", "xsrf_token", "nonce", "ticket", "session",
    "session_id", "sid", "jwt_token", "refresh_token", "grant_type", "scope",
    "kid", "jwk", "jku", "cert", "certificate", "salt", "pepper", "passphrase",

    # Identity & Account Objects
    "id", "user", "username", "user_id", "userid", "uid", "account", "account_id",
    "profile", "profile_id", "member", "member_id", "customer", "customer_id",
    "client", "tenant", "tenant_id", "org", "org_id", "organization", "company",
    "company_id", "group", "group_id", "team", "team_id", "project", "project_id",
    "app", "app_id", "application", "service", "partner", "vendor", "entity",

    # Routing, Redirection & SSRF
    "redirect", "redirect_uri", "redirect_url", "url", "uri", "dest", "destination",
    "next", "return", "return_url", "forward", "forward_url", "target", "target_url",
    "go", "goto", "out", "link", "domain", "host", "hostname", "origin", "site",
    "callback", "cb", "jsonp", "webhook", "hook", "endpoint", "route", "handler",
    "upstream", "proxy", "gateway", "backend", "remote", "server", "ip", "client_ip",
    "forwarded", "forwarded_for", "via", "x_forwarded_for", "x_real_ip",

    # File, Path & Traversal
    "file", "filename", "filepath", "path", "dir", "directory", "folder", "doc",
    "document", "attachment", "upload", "download", "include", "require", "page",
    "template", "layout", "view", "theme", "source", "src", "ref", "reference",
    "img", "image", "media", "avatar", "icon", "logo", "asset", "blob", "raw",

    # Command Execution & Operations
    "cmd", "command", "exec", "execute", "run", "do", "action", "act", "op",
    "operation", "task", "job", "process", "proc", "step", "event", "trigger",
    "invoke", "call", "handler", "eval", "expression", "expr", "code_eval",

    # Querying, Filtering & Pagination
    "q", "query", "search", "filter", "filters", "find", "keyword", "keywords",
    "term", "terms", "s", "limit", "offset", "count", "size", "page_size",
    "per_page", "rows", "max", "min", "sort", "sort_by", "order", "order_by",
    "direction", "dir", "fields", "field", "select", "columns", "include_fields",
    "exclude", "exclude_fields", "populate", "expand", "deep", "nested",

    # Data Formats & Render
    "format", "output", "type", "content_type", "render", "display", "export",
    "dump", "json", "xml", "csv", "yaml", "html", "text", "pdf", "pretty",
    "verbose", "verbosity", "debug_output", "raw_output", "silent", "quiet",

    # State & Toggles
    "status", "state", "active", "enabled", "disabled", "enable", "disable",
    "is_active", "is_admin", "is_valid", "is_verified", "verified", "approved",
    "confirmed", "locked", "blocked", "banned", "deleted", "archived", "draft",
    "published", "pending", "success", "failed", "error", "mode", "env", "v",
    "version", "api_version", "lang", "language", "locale", "tz", "timezone",

    # Actions / Verbs
    "create", "add", "new", "insert", "update", "modify", "edit", "change",
    "set", "put", "patch", "delete", "del", "remove", "drop", "clean", "clear",
    "purge", "flush", "reset", "refresh", "sync", "reload", "restart", "rebuild",
    "reindex", "reboot", "boot", "init", "install", "setup", "upgrade", "backup",
    "restore", "rollback", "revert", "publish", "unpublish", "approve", "reject",
    "send", "submit", "post", "dispatch", "broadcast", "notify", "alert", "ping",
    "health", "healthcheck", "metrics", "stats", "info", "diag", "diagnostic",

    # Personal Information / Forms
    "email", "mail", "username", "name", "first_name", "last_name", "full_name",
    "fname", "lname", "phone", "mobile", "cell", "telephone", "address", "city",
    "state_name", "country", "zip", "zipcode", "postal", "postal_code", "age",
    "gender", "dob", "birth", "ssn", "aadhaar", "pan", "national_id",

    # Financial & Commerce
    "amount", "price", "cost", "total", "subtotal", "currency", "curr", "balance",
    "credit", "debit", "card", "card_number", "card_type", "cvv", "cvc", "exp",
    "exp_month", "exp_year", "order_id", "cart_id", "item_id", "product_id",
    "sku", "qty", "quantity", "discount", "coupon", "coupon_code", "voucher",
    "promo", "promo_code", "tax", "fee", "shipping", "payment", "payment_method",
    "transaction", "transaction_id", "tx_id", "invoice", "invoice_id", "receipt"
]

# Quick wordlist (top 250)
ARJUN_QUICK_WORDLIST = ARJUN_DEFAULT_WORDLIST[:250]

# Deep wordlist expansion (adds additional microservice & cloud names)
_EXPANSION_PARAMS = [
    "access", "account_type", "acl", "activation", "activation_code", "actor",
    "algorithm", "allow", "allow_anonymous", "allow_credentials", "allow_headers",
    "allow_methods", "allow_origin", "analytics", "apikey_id", "app_key",
    "app_secret", "append", "application_id", "archive", "args", "arguments",
    "assertion", "audience", "audit_log", "auth_code", "authenticate", "author",
    "authorization", "auto", "avatar_url", "back", "background", "badge",
    "base", "base_url", "batch", "batch_size", "before", "after", "billing",
    "billing_address", "binary", "bind", "body", "bookmark", "boolean",
    "bucket", "bulk", "bundle", "bypass_cache", "cache", "cache_control",
    "cancel", "captcha", "category", "certificate_id", "channel", "charset",
    "checksum", "claim", "claims", "class", "cleanup", "clone", "code_verifier",
    "comment", "comments", "commit", "condition", "configuration", "connection",
    "consent", "contact", "context", "continue", "controller", "conversation",
    "cookie", "coordinates", "copy", "created_at", "cron", "crypto", "csr",
    "csv_export", "custom", "custom_fields", "data", "database", "datasource",
    "date", "date_format", "day", "debug_bar", "declaration", "default",
    "delay", "delegate", "deny", "dependency", "deploy_key", "description",
    "device", "device_id", "device_token", "diff", "digest", "disable_cache",
    "disable_csrf", "disable_ssl", "dns", "domain_id", "dryrun", "dump_data",
    "duration", "echo", "editor", "element", "emergency", "encoding", "encrypt",
    "encryption", "end_date", "engine", "entity_id", "enum", "envelope",
    "environment_id", "error_code", "error_log", "event_id", "exception",
    "exec_path", "execution", "expire", "expires", "expires_in", "export_format",
    "extension", "external", "extra", "factory", "fail", "fallback", "false",
    "feature", "feature_flag", "features", "feed", "file_name", "file_path",
    "file_size", "file_type", "filter_by", "flags", "flush_cache", "force",
    "force_login", "format_type", "forum", "fragment", "framework", "fresh",
    "from_date", "full", "gateway_url", "generate", "geo", "global", "grant",
    "guid", "hash_alg", "hash_type", "header", "headers", "help", "hex",
    "high", "hook_url", "host_header", "hour", "html_format", "http_code",
    "http_method_override", "hybrid", "icon_url", "identity", "ignore",
    "image_url", "immediate", "import_data", "include_all", "index", "init_vector",
    "input_data", "instance", "instrumentation", "integration", "intercept",
    "interface", "intermediate", "interval", "invitation", "ip_address",
    "is_debug", "is_enabled", "is_public", "issue", "issuer", "iteration",
    "json_data", "json_format", "keep_alive", "key_id", "kms", "label",
    "latitude", "latest", "level_id", "license", "line", "link_id", "listener",
    "load", "location", "lock", "log_level", "logger_name", "login", "longitude",
    "lookup", "low", "mac", "machine", "maintain", "manual", "mapping",
    "master", "max_results", "mechanism", "medium", "merge", "metadata",
    "meta", "method", "metric", "migration", "mimetype", "min_results",
    "module", "month", "more", "mutation", "namespace", "native", "network",
    "next_page", "node", "normalization", "notifier", "null", "number",
    "oauth", "oauth_token", "object", "object_id", "old", "open", "operation_name",
    "operator", "optimize", "order_direction", "override_header", "owner",
    "packet", "page_number", "param", "parameter", "parameters", "parse",
    "partial", "passcode", "path_info", "pause", "peer", "period", "permission_level",
    "persist", "plugin", "policy", "poll", "port", "position", "prefix",
    "priority", "probe", "protocol", "public", "push", "queue", "quota",
    "random", "rate", "raw_data", "read_only", "reader", "reason", "reboot_system",
    "receiver", "record", "recovery", "redis", "reduce", "refresh_cache",
    "regenerate", "region", "register", "registration", "release_id", "remote_addr",
    "remote_host", "render_mode", "renew", "repeat", "replace", "report",
    "repository", "request_id", "require_auth", "reset_password", "resource",
    "resource_id", "response", "restore_backup", "result", "retry", "revocation",
    "revoke", "root_dir", "rule", "runtime", "safe", "schema", "scope_id",
    "screenshot", "script", "search_term", "secret_token", "security", "segment",
    "selector", "sender", "server_id", "session_key", "set_cookie", "shard",
    "share", "show", "show_all", "signal", "silent_mode", "simple", "sink",
    "size_limit", "snapshot", "socket", "soft_delete", "sort_order", "span",
    "sql_query", "ssl", "ssl_verify", "stage_id", "start_date", "statistic",
    "status_code", "stream", "strict", "string", "struct", "subdomain",
    "subject", "subscribe", "suffix", "summary", "suppress", "switch",
    "system_id", "table", "tag_name", "target_host", "telemetry", "temp",
    "terminal", "terminate", "text_format", "thread", "threshold", "thumbnail",
    "timeout", "timestamp", "tls", "token_type", "total_count", "trace_id",
    "tracking", "transform", "transmit", "tunnel", "type_id", "universal",
    "unknown", "unlock", "unregister", "unrestricted", "unsubscribe", "update_all",
    "uri_path", "url_redirect", "usage", "user_agent", "user_group", "user_level",
    "user_token", "uuid", "val", "value", "variable", "variation", "vault",
    "vector", "verification", "viewer", "virtual", "visibility", "vulnerability",
    "wait", "warning", "webhook_url", "whitelist", "wide", "widget", "wildcard",
    "window", "worker", "workflow", "wrapper", "write_mode", "ws", "year", "zone"
]

ARJUN_DEEP_WORDLIST = list(dict.fromkeys(ARJUN_DEFAULT_WORDLIST + _EXPANSION_PARAMS))

# Load full 1,000 (Standard) and 3,000 (Deep) wordlists if available
_WORDLISTS_FILE = os.path.join(os.path.dirname(__file__), "wordlists.json")
try:
    if os.path.exists(_WORDLISTS_FILE):
        with open(_WORDLISTS_FILE, "r", encoding="utf-8") as _wlf:
            _wl_data = json.load(_wlf)
            if "quick" in _wl_data and len(_wl_data["quick"]) >= 250:
                ARJUN_QUICK_WORDLIST = _wl_data["quick"]
            if "standard" in _wl_data and len(_wl_data["standard"]) >= 1000:
                ARJUN_DEFAULT_WORDLIST = _wl_data["standard"]
            if "deep" in _wl_data and len(_wl_data["deep"]) >= 3000:
                ARJUN_DEEP_WORDLIST = _wl_data["deep"]
except Exception:
    pass


class ArjunJobManager:
    """Manages Arjun parameter discovery background tasks with live logs."""

    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def start_job(
        self,
        curl: str,
        param_type: str = "query",  # 'query' | 'json' | 'header'
        wordlist_type: str = "quick",  # 'quick' | 'standard' | 'deep' | 'custom'
        custom_wordlist: Optional[List[str]] = None,
        batch_size: int = 25,
        threads: int = 5,
    ) -> str:
        job_id = str(uuid.uuid4())
        cancel_event = threading.Event()

        # Select wordlist
        if wordlist_type == "custom" and custom_wordlist:
            candidates = [w.strip() for w in custom_wordlist if w.strip()]
        elif wordlist_type == "deep":
            candidates = list(ARJUN_DEEP_WORDLIST)
        elif wordlist_type == "standard":
            candidates = list(ARJUN_DEFAULT_WORDLIST)
        else:  # quick
            candidates = list(ARJUN_QUICK_WORDLIST)

        job_record = {
            "id": job_id,
            "status": "running",
            "curl": curl,
            "param_type": param_type.lower(),
            "wordlist_type": wordlist_type,
            "batch_size": max(5, min(50, batch_size)),
            "threads": max(1, min(15, threads)),
            "created_at": time.time(),
            "finished_at": None,
            "cancel_event": cancel_event,
            "total_candidates": len(candidates),
            "tested_count": 0,
            "discovered_params": [],
            "logs": [],
            "baseline": {},
            "error": None,
        }

        with self.lock:
            self.jobs[job_id] = job_record

        # Spawn worker thread
        t = threading.Thread(
            target=self._run_discovery,
            args=(job_id, candidates),
            daemon=True,
        )
        t.start()
        return job_id

    def get_status(self, job_id: str, since_log: int = 0) -> Optional[Dict[str, Any]]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            logs = job["logs"]
            new_logs = logs[since_log:] if since_log < len(logs) else []
            return {
                "id": job_id,
                "status": job["status"],
                "total": job["total_candidates"],
                "tested": job["tested_count"],
                "percent": int((job["tested_count"] / max(1, job["total_candidates"])) * 100),
                "discovered_count": len(job["discovered_params"]),
                "discovered_params": job["discovered_params"],
                "baseline": job["baseline"],
                "new_logs": new_logs,
                "total_logs": len(logs),
                "error": job.get("error"),
            }

    def stop_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            job["cancel_event"].set()
            job["status"] = "stopped"
            job["finished_at"] = time.time()
            self._log(job, "warn", "⏹ Arjun discovery stopped by user.")
            return True

    def _log(self, job: Dict[str, Any], level: str, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = {"time": ts, "level": level, "msg": msg}
        job["logs"].append(entry)

    def _run_discovery(self, job_id: str, candidates: List[str]):
        job = self.jobs.get(job_id)
        if not job:
            return

        cancel_event = job["cancel_event"]
        param_type = job["param_type"]
        batch_size = job["batch_size"]

        try:
            from fuzzer_backend.main import parse_any_request
        except ImportError:
            from main import parse_any_request

        # 1. Parse target request
        try:
            clean_curl = re.sub(r"§([^§]+)§", r"\1", job["curl"])
            parsed_spec = parse_any_request(clean_curl)
        except Exception as e:
            job["status"] = "error"
            job["error"] = f"Failed to parse request template: {str(e)}"
            self._log(job, "error", f"Failed to parse request: {str(e)}")
            return

        method = (parsed_spec.get("method") or "GET").upper()
        url = (parsed_spec.get("url") or "").strip()
        if url and not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        if not url:
            job["status"] = "error"
            job["error"] = "No target URL found. Please provide a valid URL or cURL command."
            self._log(job, "error", "❌ Target URL is empty or invalid. Please provide a valid URL or cURL.")
            return

        base_headers = parsed_spec.get("headers") or {}
        base_body = parsed_spec.get("body_raw") or ""

        self._log(job, "info", f"🎯 Target Initialized: {method} {url}")
        self._log(job, "info", f"⚙ Mode: {param_type.upper()} Discovery | Total Candidates: {len(candidates):,} words")

        # Exclude parameters already present in the request
        present_params = set()
        try:
            p_url = urllib.parse.urlparse(url)
            for k in urllib.parse.parse_qs(p_url.query).keys():
                present_params.add(k.lower())
            if base_body:
                try:
                    b_json = json.loads(base_body)
                    if isinstance(b_json, dict):
                        for k in b_json.keys():
                            present_params.add(str(k).lower())
                except Exception:
                    pass
        except Exception:
            pass

        active_candidates = [c for c in candidates if c.lower() not in present_params]
        job["total_candidates"] = len(active_candidates)

        if len(candidates) != len(active_candidates):
            self._log(job, "info", f"ℹ Filtered out {len(candidates) - len(active_candidates)} parameters already present in request.")

        # 2. Establish Baseline
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=1, pool_connections=5, pool_maxsize=10)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        self._log(job, "info", "⚡ Establishing baseline response profile...")
        try:
            t0 = time.time()
            resp = session.request(
                method=method,
                url=url,
                headers=base_headers,
                data=base_body.encode("utf-8") if isinstance(base_body, str) else base_body,
                timeout=10,
                verify=False,
            )
            base_time = int((time.time() - t0) * 1000)
            baseline_full_body = resp.text
            base_len = len(resp.content)
            baseline = {
                "status": resp.status_code,
                "len": base_len,
                "time": base_time,
                "body": resp.text[:4000],
                "headers": dict(resp.headers),
            }
            job["baseline"] = baseline
            self._log(
                job,
                "info",
                f"📊 Baseline Established: {resp.status_code} {resp.reason} | Length: {base_len:,} bytes | Time: {base_time}ms",
            )
        except Exception as e:
            job["status"] = "error"
            job["error"] = f"Baseline request failed: {str(e)}"
            self._log(job, "error", f"❌ Target connection failed during baseline: {str(e)}")
            return

        # 3. Batch Testing Loop
        # We generate a unique random token for reflection tracking
        probe_token = "arj" + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
        self._log(job, "info", f"🚀 Starting differential scanning in batches of {batch_size} (Probe Val: '{probe_token}')...")

        # Chunk active candidates
        batches = [
            active_candidates[i : i + batch_size]
            for i in range(0, len(active_candidates), batch_size)
        ]

        total_batches = len(batches)

        def _send_probe(param_dict: Dict[str, str]) -> Optional[Dict[str, Any]]:
            """Injects parameters and sends request."""
            try:
                mut_url = url
                mut_body = base_body
                mut_headers = copy.deepcopy(base_headers)

                if param_type == "query":
                    p = urllib.parse.urlparse(mut_url)
                    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
                    for pk, pv in param_dict.items():
                        qs[pk] = [pv]
                    new_query = urllib.parse.urlencode(qs, doseq=True)
                    mut_url = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
                elif param_type == "json":
                    try:
                        data = json.loads(mut_body) if mut_body else {}
                        if not isinstance(data, dict):
                            data = {}
                    except Exception:
                        data = {}
                    data.update(param_dict)
                    mut_body = json.dumps(data)
                elif param_type == "header":
                    for pk, pv in param_dict.items():
                        mut_headers[pk] = pv

                t0 = time.time()
                r = session.request(
                    method=method,
                    url=mut_url,
                    headers=mut_headers,
                    data=mut_body.encode("utf-8") if isinstance(mut_body, str) else mut_body,
                    timeout=8,
                    verify=False,
                )
                return {
                    "status": r.status_code,
                    "len": len(r.content),
                    "time": int((time.time() - t0) * 1000),
                    "body": r.text,
                    "headers": dict(r.headers),
                }
            except Exception:
                return None

        def _check_deviation(test_resp: Dict[str, Any]) -> Tuple[bool, str, str]:
            """Compares test response against baseline."""
            if not test_resp:
                return (False, "", "")

            # 1. Status Code Deviation
            if test_resp["status"] != baseline["status"]:
                return (
                    True,
                    f"Status Code Shifted: {baseline['status']} -> {test_resp['status']}",
                    f"Server returned HTTP {test_resp['status']} instead of baseline {baseline['status']}.",
                )

            # 2. Reflection Deviation
            if probe_token in test_resp["body"] and probe_token not in baseline_full_body:
                return (
                    True,
                    f"Value Reflection: '{probe_token}' echoed in body",
                    f"Parameter value '{probe_token}' was reflected inside server response body.",
                )

            # 3. Content Length Deviation (tolerance +/- 20 bytes)
            test_len = test_resp.get("len", len(test_resp.get("body", "")))
            diff_len = test_len - base_len
            if abs(diff_len) > 20:
                direction = f"+{diff_len}" if diff_len > 0 else f"{diff_len}"
                return (
                    True,
                    f"Content Length Delta: {direction} bytes",
                    f"Response length shifted from {base_len:,} to {test_len:,} bytes.",
                )

            # 4. New Header Deviation (e.g. Set-Cookie, X-Debug)
            b_hdrs = baseline.get("headers", {})
            for hk, hv in test_resp.get("headers", {}).items():
                if hk.lower() in ("date", "age", "x-request-id", "x-amz-request-id"):
                    continue
                if hk.lower() not in [k.lower() for k in b_hdrs.keys()]:
                    return (
                        True,
                        f"New Header Injected: '{hk}'",
                        f"Server added response header '{hk}: {hv}'.",
                    )

            return (False, "", "")

        # Process batches
        for b_idx, batch in enumerate(batches, start=1):
            if cancel_event.is_set():
                break

            # Build batch dict
            batch_dict = {p: probe_token for p in batch}
            test_resp = _send_probe(batch_dict)

            is_dev, reason, evidence = _check_deviation(test_resp)

            if not is_dev:
                # Normal response
                job["tested_count"] += len(batch)
                if b_idx % 5 == 0 or b_idx == total_batches:
                    self._log(
                        job,
                        "info",
                        f"⏳ Batch {b_idx}/{total_batches} ({batch[0]}..{batch[-1]}): Normal (Status: {test_resp['status'] if test_resp else 'Err'}, Len: {test_resp['len'] if test_resp else 0})",
                    )
                time.sleep(0.04)
                continue

            # Deviation detected! Bisect to isolate parameter(s)
            self._log(
                job,
                "warn",
                f"🚨 Deviation in Batch {b_idx}/{total_batches}! ({reason}). Bisecting {len(batch)} parameters...",
            )

            # Bisection queue
            queue = [batch]
            isolated_params = []

            while queue and not cancel_event.is_set():
                sub = queue.pop(0)
                if len(sub) == 1:
                    # Single parameter candidate! Verify individually
                    cand = sub[0]
                    verify_resp = _send_probe({cand: probe_token})
                    v_dev, v_reason, v_evidence = _check_deviation(verify_resp)
                    if v_dev:
                        isolated_params.append((cand, v_reason, v_evidence, verify_resp))
                    continue

                mid = len(sub) // 2
                left_half = sub[:mid]
                right_half = sub[mid:]

                # Test left half
                left_resp = _send_probe({p: probe_token for p in left_half})
                l_dev, _, _ = _check_deviation(left_resp)
                if l_dev:
                    queue.append(left_half)

                # Test right half
                right_resp = _send_probe({p: probe_token for p in right_half})
                r_dev, _, _ = _check_deviation(right_resp)
                if r_dev:
                    queue.append(right_half)

                time.sleep(0.02)

            for cand, v_reason, v_evidence, v_resp in isolated_params:
                # Avoid duplicate entries
                if any(p["name"] == cand for p in job["discovered_params"]):
                    continue

                discovered_item = {
                    "name": cand,
                    "type": param_type,
                    "reason": v_reason,
                    "evidence": v_evidence,
                    "status": v_resp["status"] if v_resp else 200,
                    "length": v_resp["len"] if v_resp else 0,
                    "sample_val": probe_token,
                }
                job["discovered_params"].append(discovered_item)
                self._log(
                    job,
                    "success",
                    f"✨ DISCOVERED HIDDEN PARAMETER: '{cand}' ({param_type.upper()}) — {v_reason}",
                )

            job["tested_count"] += len(batch)
            time.sleep(0.04)

        if not cancel_event.is_set():
            job["status"] = "finished"
            job["finished_at"] = time.time()
            found_count = len(job["discovered_params"])
            if found_count > 0:
                self._log(
                    job,
                    "success",
                    f"🎉 Scan Complete! Found {found_count} hidden parameter(s) ready to inject into Fuzzer.",
                )
            else:
                self._log(
                    job,
                    "info",
                    "✓ Scan Complete. No hidden parameter deviations detected on tested endpoints.",
                )


# Global singleton instance
arjun_manager = ArjunJobManager()
