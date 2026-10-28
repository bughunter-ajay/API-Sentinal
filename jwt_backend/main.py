#!/usr/bin/env python3
"""
FastAPI Service for JWT Tool & Security Testing (Port 8798)
Exposes endpoints for token decoding, passive security audit, attack suite generation,
secret brute-force, and automated live endpoint vulnerability scanning with dual PoC generation.
Enhanced with geeknik/jwt-scanner and dr34mhacks/jwtauditor capabilities.
"""

import sys
import os
import json
import threading
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

_parent_dir = os.path.dirname(_cur_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

try:
    from curl_parser import parse_curl_command
except Exception:
    parse_curl_command = None

from jwt_engine import (
    parse_jwt,
    audit_jwt_security,
    forge_token,
    generate_jwt_attacks,
    crack_hmac_secret,
    probe_jwt_attack,
    generate_python_poc,
    COMMON_JWT_SECRETS
)

app = FastAPI(title="JWT Tool API Sentinel", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Request Models ──────────────────────────────────────────────────

class JwtDecodeRequest(BaseModel):
    token: str


class JwtAttackGenRequest(BaseModel):
    token: str
    custom_claims: Optional[Dict[str, Any]] = None
    public_key: Optional[str] = None


class JwtCrackRequest(BaseModel):
    token: str
    custom_wordlist: Optional[List[str]] = None


class JwtScanRequest(BaseModel):
    url: str
    method: str = "GET"
    token: str
    headers: Optional[Dict[str, str]] = {}
    body: Optional[str] = None
    custom_claims: Optional[Dict[str, Any]] = None
    selected_attacks: Optional[List[str]] = None
    timeout: int = 20
    public_key: Optional[str] = None
    expected_success_string: Optional[str] = None
    expected_failure_string: Optional[str] = None


class JwtSingleProbeRequest(BaseModel):
    url: str
    method: str = "GET"
    attack_token: str
    headers: Optional[Dict[str, str]] = {}
    body: Optional[str] = None
    timeout: int = 20
    expected_success_string: Optional[str] = None
    expected_failure_string: Optional[str] = None


class JwtForgeRequest(BaseModel):
    header: Dict[str, Any]
    payload: Dict[str, Any]
    secret: str = ""
    alg: Optional[str] = None
    custom_signature: Optional[str] = None


class JwtCurlParseRequest(BaseModel):
    curl: str


# ── Routes ───────────────────────────────────────────────────────────────────

@app.post("/jwt/probe-single")
def probe_single_endpoint(req: JwtSingleProbeRequest):
    """Probes a single attack token against target URL in real-time."""
    if not req.url or not req.url.strip():
        raise HTTPException(400, "Target URL is required.")
    if not req.attack_token or not req.attack_token.strip():
        raise HTTPException(400, "Attack token is required.")

    return probe_jwt_attack(
        url=req.url,
        method=req.method,
        attack_token=req.attack_token,
        headers=req.headers,
        body=req.body,
        timeout=req.timeout,
        expected_success_string=req.expected_success_string,
        expected_failure_string=req.expected_failure_string
    )

@app.post("/jwt/parse-curl")
def parse_curl_endpoint(req: JwtCurlParseRequest):
    """
    Parse a cURL command into structured fields:
    Extracts Bearer token, target URL, HTTP method, headers, and request body.
    """
    if not req.curl or not req.curl.strip():
        raise HTTPException(400, "cURL command string is empty.")

    if not parse_curl_command:
        raise HTTPException(500, "curl_parser engine is not available.")

    try:
        parsed = parse_curl_command(req.curl)
    except Exception as e:
        raise HTTPException(400, f"Failed to parse cURL: {str(e)}")

    headers = parsed.get("headers") or {}
    token = ""
    clean_headers_lines = []

    for k, v in headers.items():
        val = str(v).strip()
        if k.lower() == "authorization":
            if val.lower().startswith("bearer "):
                token = val[7:].strip()
            else:
                token = val
        elif not token and val.startswith("eyJ") and val.count(".") >= 2:
            token = val
        elif not token and any(w in k.lower() for w in ("token", "jwt", "auth")) and "eyJ" in val:
            token = val.split()[-1]
        else:
            clean_headers_lines.append(f"{k}: {v}")

    # Fallback 1: check cookies
    if not token and parsed.get("cookies"):
        for ck_name, ck_val in parsed["cookies"].items():
            sv = str(ck_val).strip()
            if sv.startswith("eyJ") and sv.count(".") >= 2:
                token = sv
                break
            elif any(w in ck_name.lower() for w in ("token", "jwt", "auth", "access")):
                token = sv
                break

    # Fallback 2: check query parameters
    if not token and parsed.get("query_params"):
        for qk, qv in parsed["query_params"].items():
            sqv = str(qv).strip()
            if sqv.startswith("eyJ") and sqv.count(".") >= 2:
                token = sqv
                break
            elif any(w in qk.lower() for w in ("token", "jwt", "access")):
                token = sqv
                break

    # Fallback 3: search entire cURL text for raw JWT pattern
    if not token and req.curl:
        jwt_match = re.search(r'\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b', req.curl)
        if jwt_match:
            token = jwt_match.group(1)

    body_content = parsed.get("body_raw") or parsed.get("body") or ""
    if isinstance(body_content, (dict, list)):
        body_str = json.dumps(body_content, indent=2)
    else:
        body_str = str(body_content) if body_content else ""

    return {
        "success": True,
        "token": token,
        "url": parsed.get("url") or "",
        "method": (parsed.get("method") or "GET").upper(),
        "headers_text": "\n".join(clean_headers_lines),
        "headers": {k: v for k, v in headers.items() if k.lower() != "authorization"},
        "body": body_str
    }


@app.get("/")
@app.get("/jwt/health")
def health():
    return {
        "status": "online",
        "service": "JWT Tool & Security Lab",
        "version": "2.0.0",
        "port": 8798,
        "supported_attacks": [
            "alg_none_lower",
            "alg_none_title",
            "alg_none_upper",
            "alg_none_nodot",
            "sig_stripped",
            "sig_tampered",
            "sig_appended",
            "empty_secret_hs256",
            "common_secret_hs256",
            "key_confusion_rs256_hs256",
            "jwk_embedded_key",
            "jku_remote_spoof",
            "role_escalation_none",
            "exp_removed_none",
            "exp_future_none",
            "kid_path_traversal",
            "kid_path_win",
            "kid_null_byte",
            "kid_sqli",
            "kid_sqli_or",
            "kid_cmd_injection"
        ],
        "wordlist_size": len(COMMON_JWT_SECRETS)
    }


@app.post("/jwt/decode")
def decode_token(req: JwtDecodeRequest):
    """
    Decode a raw or Bearer JWT token into JSON without verification,
    and simultaneously run passive security heuristics (inspired by jwtauditor).
    """
    if not req.token or not req.token.strip():
        raise HTTPException(400, "Token string is empty.")
    res = parse_jwt(req.token)
    if not res.get("valid_jwt"):
        raise HTTPException(400, res.get("error", "Invalid JWT format."))
    
    # Run passive security audit
    res["audit"] = audit_jwt_security(req.token)
    return res


@app.post("/jwt/audit")
def audit_token(req: JwtDecodeRequest):
    """Run passive security analyzer heuristics on token."""
    if not req.token or not req.token.strip():
        raise HTTPException(400, "Token string is empty.")
    return audit_jwt_security(req.token)


@app.post("/jwt/generate-attacks")
def generate_attacks(req: JwtAttackGenRequest):
    """Generate all OWASP, jwt_tool, and jwtauditor attack token variants."""
    if not req.token or not req.token.strip():
        raise HTTPException(400, "Token string is empty.")
    attacks = generate_jwt_attacks(req.token, custom_claims=req.custom_claims, public_key=req.public_key)
    return {
        "total": len(attacks),
        "attacks": attacks
    }


@app.post("/jwt/forge")
def forge_custom_jwt(req: JwtForgeRequest):
    """Forge a new JWT with custom header, payload, secret, algorithm, or custom signature."""
    token = forge_token(
        req.header,
        req.payload,
        secret=req.secret,
        alg=req.alg,
        custom_signature=req.custom_signature
    )
    return {
        "token": token,
        "algorithm": req.alg or req.header.get("alg", "none")
    }


@app.post("/jwt/crack-secret")
def crack_secret(req: JwtCrackRequest):
    """Attempt offline HMAC secret recovery via high-performance dictionary brute-force."""
    if not req.token or not req.token.strip():
        raise HTTPException(400, "Token string is empty.")
    res = crack_hmac_secret(req.token, custom_wordlist=req.custom_wordlist)
    return res


@app.post("/jwt/scan")
def run_live_jwt_scan(req: JwtScanRequest):
    """
    Executes live JWT attack probe against target API URL.
    Tests baseline response and compares against each tampered token to evaluate vulnerabilities.
    Generates both reproducible cURL and standalone Python requests PoC scripts.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(400, "Target URL is required.")
    if not req.token or not req.token.strip():
        raise HTTPException(400, "Token is required.")

    # 1. Parse token
    parsed = parse_jwt(req.token)
    if not parsed.get("valid_jwt"):
        raise HTTPException(400, parsed.get("error", "Invalid JWT format."))

    # 2. Generate attacks
    all_attacks = generate_jwt_attacks(req.token, custom_claims=req.custom_claims, public_key=req.public_key)
    if req.selected_attacks and len(req.selected_attacks) > 0:
        attacks_to_run = [a for a in all_attacks if a["id"] in req.selected_attacks or a["id"] == "baseline_original"]
    else:
        attacks_to_run = all_attacks

    results: List[Dict[str, Any]] = []
    baseline_status = None
    baseline_len = None

    # Run baseline first to establish reference
    for attack in attacks_to_run:
        probe = probe_jwt_attack(
            url=req.url,
            method=req.method,
            attack_token=attack["token"],
            headers=req.headers,
            body=req.body,
            timeout=req.timeout,
            expected_success_string=req.expected_success_string,
            expected_failure_string=req.expected_failure_string
        )

        status = probe.get("status_code", 0)
        c_len = probe.get("content_length", 0)

        # Baseline record
        if attack["id"] == "baseline_original":
            baseline_status = status
            baseline_len = c_len
            if status == 0:
                verdict = "ERROR"
                vulnerable = False
                err_text = probe.get("error", "Network error")
                if probe.get("is_timeout"):
                    notes = f"⏱️ Baseline request TIMED OUT after {probe.get('elapsed_seconds', req.timeout)}s (target response was too slow; timeout limit was {req.timeout}s)."
                else:
                    notes = f"⚠️ Baseline request failed (HTTP ERR): {err_text}"
            else:
                verdict = "BASELINE"
                vulnerable = False
                notes = f"Baseline reference: HTTP {status} ({c_len} bytes)"
        else:
            # Vulnerability Evaluation Logic:
            if status == 0:
                verdict = "ERROR"
                vulnerable = False
                err_text = probe.get("error", "Network error")
                if probe.get("is_timeout"):
                    notes = f"⏱️ Request TIMED OUT after {probe.get('elapsed_seconds', req.timeout)}s (timeout limit was {req.timeout}s)."
                else:
                    notes = f"Request failed: {err_text}"
            elif req.expected_success_string and req.expected_success_string.strip():
                # String Matching filter enabled
                if probe.get("success_string_matched") is True:
                    verdict = "VULNERABLE"
                    vulnerable = True
                    notes = f"⚠️ Server accepted tampered token (HTTP {status}) AND expected success string '{req.expected_success_string}' matched!"
                elif status in (200, 201, 204):
                    verdict = "SOFT_FAIL"
                    vulnerable = False
                    notes = f"HTTP {status} returned, but expected success string '{req.expected_success_string}' was missing (potential soft fail or error body)."
                elif status in (401, 403):
                    verdict = "SECURE"
                    vulnerable = False
                    notes = f"Protected: Server rejected tampered token with HTTP {status}."
                else:
                    verdict = "SUSPICIOUS"
                    vulnerable = False
                    notes = f"Server returned HTTP {status} without success string match."
            else:
                # Standard status code evaluation
                if status in (200, 201, 204) or (baseline_status and status == baseline_status and status < 400):
                    verdict = "VULNERABLE"
                    vulnerable = True
                    notes = f"⚠️ Server accepted tampered token (HTTP {status})! Authentication/Signature bypassed!"
                elif status in (401, 403):
                    verdict = "SECURE"
                    vulnerable = False
                    notes = f"Protected: Server rejected tampered token with HTTP {status}."
                else:
                    verdict = "SUSPICIOUS"
                    vulnerable = False
                    notes = f"Server returned HTTP {status} ({probe.get('reason', '')}). Manual review recommended."

        # Build PoC cURL command
        auth_hdr = f"Authorization: Bearer {attack['token']}"
        curl_poc = f"curl -i -s -k -X {req.method.upper()} \"{req.url}\" \\\n  -H \"{auth_hdr}\""
        for k, v in (req.headers or {}).items():
            if k.lower() != "authorization":
                curl_poc += f" \\\n  -H \"{k}: {v}\""
        if req.body and req.method.upper() in ("POST", "PUT", "PATCH"):
            curl_poc += f" \\\n  --data '{req.body}'"

        # Build PoC Python script
        python_poc = generate_python_poc(
            url=req.url,
            method=req.method,
            attack_token=attack["token"],
            headers=req.headers,
            body=req.body
        )

        results.append({
            "attack_id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "description": attack["description"],
            "severity": attack["severity"],
            "tampered_aspect": attack["tampered_aspect"],
            "attack_token": attack["token"],
            "status_code": status,
            "reason": probe.get("reason", ""),
            "elapsed_seconds": probe.get("elapsed_seconds", 0),
            "content_length": c_len,
            "response_snippet": probe.get("response_snippet", ""),
            "verdict": verdict,
            "vulnerable": vulnerable,
            "notes": notes,
            "curl_poc": curl_poc,
            "python_poc": python_poc
        })

    vulnerable_count = sum(1 for r in results if r.get("vulnerable"))

    return {
        "success": True,
        "target_url": req.url,
        "method": req.method.upper(),
        "baseline_status": baseline_status,
        "total_tested": len(results),
        "vulnerable_count": vulnerable_count,
        "verdict_summary": f"{vulnerable_count} Vulnerabilities Discovered!" if vulnerable_count > 0 else "All Tested Vectors Rejected (Secure).",
        "results": results
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8798)
