"""
HAR Parser Module for Nuclei Scanner — API Sentinel
Extracts live API endpoints, methods, parameters, and authentication tokens from HTTP Archive (.har) files.
Detects JWT token expiration and filters out static web assets.
Includes smart route-level deduplication to eliminate repeated endpoint calls.
"""

import json
import base64
import time
import re
import urllib.parse
from typing import Dict, Any, List

STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".wav", ".avi", ".map", ".xml", ".txt",
    ".js", ".jsx", ".ts", ".tsx"
)

JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]+")

AUTH_HEADER_NAMES = (
    "authorization", "authtoken", "auth-token", "x-auth-token",
    "x-access-token", "access-token", "accesstoken", "token",
    "bearer", "apikey", "x-api-key", "api-key", "x-jwt-assertion",
    "session-token", "x-session-id", "securitytoken", "x-csrf-token", "x-xsrf-token"
)

AUTH_COOKIE_KEYWORDS = ("session", "token", "jwt", "auth", "jsessionid", "sid", "connect.sid")


def _inspect_jwt_token(token_str: str) -> Dict[str, Any]:
    """Inspects a JWT token string to check expiration without requiring verification key."""
    if not token_str or not isinstance(token_str, str):
        return {"is_jwt": False, "expired": False}
    
    clean_token = token_str.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()
        
    parts = clean_token.split(".")
    if len(parts) != 3:
        # Check if JWT is embedded inside quotes or string
        match = JWT_REGEX.search(clean_token)
        if match:
            clean_token = match.group(0)
            parts = clean_token.split(".")
        else:
            return {"is_jwt": False, "expired": False}
        
    try:
        payload_b64 = parts[1]
        rem = len(payload_b64) % 4
        if rem > 0:
            payload_b64 += "=" * (4 - rem)
        decoded_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(decoded_bytes.decode("utf-8", errors="replace"))
        
        exp = payload.get("exp")
        if exp is not None and isinstance(exp, (int, float)):
            now = time.time()
            is_expired = now > exp
            return {
                "is_jwt": True,
                "expired": is_expired,
                "exp_timestamp": int(exp),
                "exp_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp)),
                "seconds_remaining": int(exp - now) if not is_expired else int(now - exp)
            }
        return {"is_jwt": True, "expired": False, "has_exp_claim": False}
    except Exception:
        return {"is_jwt": False, "expired": False}


def normalize_route_pattern(netloc: str, path: str) -> str:
    """
    Normalizes path to a canonical route pattern so that identical APIs
    with different IDs or repeated query params are recognized as the same endpoint.
    Example:
    /apim/hrcore/1.0/rest/generic-change-requests/920 -> /apim/hrcore/1.0/rest/generic-change-requests/{id}
    /apim/fb/1.0/rest/attachments/resources/01a12ef8-7dec-7392-b076-4c712bf2df10 -> /apim/fb/1.0/rest/attachments/resources/{uuid}
    """
    clean = path.strip()
    if not clean.startswith("/"):
        clean = "/" + clean
    clean = clean.rstrip("/") or "/"

    # 1. UUIDs
    clean = re.sub(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)', '/{uuid}', clean)
    # 2. Long hex hashes (24-64 chars)
    clean = re.sub(r'/[0-9a-fA-F]{24,64}(?=/|$)', '/{hash}', clean)
    # 3. Numeric IDs
    clean = re.sub(r'/\d+(?=/|$)', '/{id}', clean)

    return f"{netloc.lower()}::{clean.lower()}"


def parse_har_file(har_text: str) -> Dict[str, Any]:
    """
    Parses HAR text content, extracts clean API endpoints, headers, and detected base URL.
    Performs smart route-level deduplication to eliminate repeated endpoint calls.
    Detects and inspects authentication tokens (JWTs, custom auth headers, session cookies).
    """
    if not har_text or not har_text.strip():
        return {"success": False, "error": "Empty HAR content provided."}

    try:
        data = json.loads(har_text)
    except json.JSONDecodeError as je:
        return {"success": False, "error": f"Invalid JSON format: {str(je)}"}

    entries = data.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        return {"success": False, "error": "Invalid HAR structure: 'log.entries' array not found."}

    seen_routes = set()
    seen_exact_urls = set()
    endpoints: List[Dict[str, Any]] = []
    base_url_counts: Dict[str, int] = {}
    detected_headers: Dict[str, str] = {}
    
    # Token extraction state
    best_jwt = ""
    best_jwt_inspection = {"is_jwt": False, "expired": False}
    raw_auth_headers: List[str] = []
    custom_auth_headers: Dict[str, str] = {}
    raw_cookies: List[str] = []
    cookie_auth_map: Dict[str, str] = {}
    
    duplicates_removed = 0
    static_filtered = 0

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request", {})
        if not isinstance(req, dict):
            continue

        raw_url = req.get("url", "").strip()
        method = (req.get("method") or "GET").upper().strip()

        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            continue

        try:
            parsed = urllib.parse.urlsplit(raw_url)
        except Exception:
            continue

        # 1. Filter out static web assets
        path_lower = (parsed.path or "").lower()
        if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
            static_filtered += 1
            continue

        # 2. Extract Authentication Tokens across request & response
        # 2a. Request Headers
        headers_list = req.get("headers", [])
        if isinstance(headers_list, list):
            for h in headers_list:
                if not isinstance(h, dict):
                    continue
                h_name = (h.get("name") or "").strip()
                h_val = (h.get("value") or "").strip()
                if not h_name or not h_val:
                    continue

                h_lower = h_name.lower()

                # Check if value contains a JWT
                jwt_match = JWT_REGEX.search(h_val)
                if jwt_match:
                    found_jwt = jwt_match.group(0)
                    insp = _inspect_jwt_token(found_jwt)
                    if not best_jwt or (best_jwt_inspection.get("expired", False) and not insp.get("expired", False)):
                        best_jwt = found_jwt
                        best_jwt_inspection = insp

                if h_lower == "authorization":
                    raw_auth_headers.append(h_val)
                elif h_lower in AUTH_HEADER_NAMES:
                    custom_auth_headers[h_name] = h_val
                elif h_lower == "cookie":
                    raw_cookies.append(h_val)
                    for c_part in h_val.split(";"):
                        if "=" in c_part:
                            ck, cv = c_part.split("=", 1)
                            ck, cv = ck.strip(), cv.strip()
                            if any(k in ck.lower() for k in AUTH_COOKIE_KEYWORDS):
                                cookie_auth_map[ck] = cv

        # 2b. Request Cookies Array (standard in Chrome/Firefox HAR)
        cookies_list = req.get("cookies", [])
        if isinstance(cookies_list, list):
            for c in cookies_list:
                if not isinstance(c, dict):
                    continue
                c_name = (c.get("name") or "").strip()
                c_val = (c.get("value") or "").strip()
                if not c_name or not c_val:
                    continue
                if any(k in c_name.lower() for k in AUTH_COOKIE_KEYWORDS):
                    cookie_auth_map[c_name] = c_val
                jwt_match = JWT_REGEX.search(c_val)
                if jwt_match:
                    found_jwt = jwt_match.group(0)
                    insp = _inspect_jwt_token(found_jwt)
                    if not best_jwt or (best_jwt_inspection.get("expired", False) and not insp.get("expired", False)):
                        best_jwt = found_jwt
                        best_jwt_inspection = insp

        # 2c. Check Response Headers for returned tokens or set-cookie
        resp = entry.get("response", {})
        if isinstance(resp, dict):
            resp_headers = resp.get("headers", [])
            if isinstance(resp_headers, list):
                for rh in resp_headers:
                    if not isinstance(rh, dict):
                        continue
                    rh_val = (rh.get("value") or "").strip()
                    jwt_match = JWT_REGEX.search(rh_val)
                    if jwt_match:
                        found_jwt = jwt_match.group(0)
                        insp = _inspect_jwt_token(found_jwt)
                        if not best_jwt or (best_jwt_inspection.get("expired", False) and not insp.get("expired", False)):
                            best_jwt = found_jwt
                            best_jwt_inspection = insp

        # 3. Base URL counting
        base = f"{parsed.scheme}://{parsed.netloc}"
        base_url_counts[base] = base_url_counts.get(base, 0) + 1

        # 4. Smart Route-level Deduplication
        # Exact URL check
        if raw_url in seen_exact_urls:
            duplicates_removed += 1
            continue
        seen_exact_urls.add(raw_url)

        # Route pattern check (e.g. /resource/1 vs /resource/2 or repeated query calls)
        route_key = normalize_route_pattern(parsed.netloc, parsed.path or "/")
        if route_key in seen_routes:
            duplicates_removed += 1
            continue
        seen_routes.add(route_key)

        endpoints.append({
            "method": method,
            "url": raw_url,
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "base_url": base,
        })

    # Pick dominant Base URL
    dominant_base = ""
    if base_url_counts:
        dominant_base = max(base_url_counts.items(), key=lambda x: x[1])[0]

    # Resolve Authentication
    detected_auth = ""
    token_found = False
    token_type = "none"
    auth_status = {"is_jwt": False, "expired": False}

    if best_jwt:
        detected_auth = f"Bearer {best_jwt}"
        detected_headers["Authorization"] = detected_auth
        token_found = True
        token_type = "Bearer JWT"
        auth_status = best_jwt_inspection
    elif raw_auth_headers:
        detected_auth = raw_auth_headers[0]
        detected_headers["Authorization"] = detected_auth
        token_found = True
        token_type = "Authorization Header"
        auth_status = _inspect_jwt_token(detected_auth)
    elif custom_auth_headers:
        first_k = list(custom_auth_headers.keys())[0]
        first_v = custom_auth_headers[first_k]
        detected_auth = f"{first_k}: {first_v}"
        detected_headers[first_k] = first_v
        token_found = True
        token_type = first_k
        auth_status = _inspect_jwt_token(first_v)
    elif raw_cookies or cookie_auth_map:
        cookie_str = raw_cookies[0] if raw_cookies else "; ".join(f"{k}={v}" for k, v in cookie_auth_map.items())
        detected_headers["Cookie"] = cookie_str
        detected_auth = cookie_str
        token_found = True
        token_type = "Session Cookie"
        auth_status = _inspect_jwt_token(cookie_str)

    # If Cookie was found alongside Authorization, preserve it
    if raw_cookies and "Cookie" not in detected_headers:
        detected_headers["Cookie"] = raw_cookies[0]

    return {
        "success": True,
        "total_entries": len(entries),
        "total_endpoints": len(endpoints),
        "duplicates_removed": duplicates_removed,
        "static_filtered": static_filtered,
        "detected_base_url": dominant_base,
        "token_found": token_found,
        "token_expired": auth_status.get("expired", False),
        "token_type": token_type,
        "detected_auth": detected_auth,
        "auth_inspection": auth_status,
        "headers": detected_headers,
        "endpoints": endpoints,
    }
