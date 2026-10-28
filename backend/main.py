#!/usr/bin/env python3
"""
API Validator Backend — FastAPI
Chrome Extension ke saath kaam karta hai
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import Any, Optional
import json, csv, io, copy, re, random, string, time, warnings, urllib.parse, base64, zipfile, uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlencode, parse_qs
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

app = FastAPI(title="API Validator Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
#  DATASETS  (same as API_Valid_Test.py)
# ─────────────────────────────────────────────────────────────────────────────

DATASETS = {
    "string_general": {
        "label": "String — General / Title",
        "hint": "Use for: title, label, subject, tag, code fields",
        "cases": [
            ("POS","valid_standard","Standard text","Project Meeting"),
            ("POS","valid_alphanumeric","Letters + numbers","Report 2024"),
            ("POS","valid_single_char","Single character","A"),
            ("POS","valid_with_spaces","Text with spaces","My Project Title"),
            ("POS","valid_with_hyphen","Hyphenated text","Year-End Report"),
            ("POS","valid_with_apostrophe","Apostrophe in text","Manager's Report"),
            ("POS","valid_unicode","Unicode / accented","Réunion Générale"),
            ("POS","valid_numbers_mixed","Numbers mixed","Version 3.1 Update"),
            ("POS","valid_max_typical","Max typical length","A"*100),
            ("NEG","empty_string","Empty string",""),
            ("NEG","only_spaces","Only whitespace","     "),
            ("NEG","null_value","Null / None",None),
            ("NEG","too_long_1001","Exceeds 1000 chars","A"*1001),
            ("NEG","only_numbers","Only digits","1234567890"),
            ("NEG","only_special_chars","Only special chars","!@#$%^&*()"),
            ("NEG","newline_inside","Newline in value","Line1\nLine2"),
            ("NEG","tab_inside","Tab in value","Col1\tCol2"),
            ("NEG","html_basic","HTML tags","<b>bold</b>"),
            ("NEG","integer_type","Integer instead",123),
            ("NEG","boolean_type","Boolean instead",True),
            ("NEG","sql_injection","SQL injection","' OR 1=1--"),
            ("NEG","xss_script_tag","XSS script tag","<script>alert(1)</script>"),
        ],
    },
    "string_name": {
        "label": "String — Person Name",
        "hint": "Use for: name, full_name, first_name, last_name",
        "cases": [
            ("POS","valid_full_name","Full name","Rahul Sharma"),
            ("POS","valid_first_only","First name only","Priya"),
            ("POS","valid_with_apostrophe","Name with apostrophe","O'Brien"),
            ("POS","valid_hyphenated","Hyphenated name","Mary-Jane"),
            ("POS","valid_with_initials","Name with initials","A. K. Singh"),
            ("POS","valid_long_name","Long but valid name","Christopher Alexander William"),
            ("POS","valid_two_word","Two-word name","John Smith"),
            ("NEG","empty_string","Empty string",""),
            ("NEG","only_spaces","Only spaces","   "),
            ("NEG","null_value","Null",None),
            ("NEG","numbers_only","Numbers only","12345"),
            ("NEG","special_chars_only","Special chars only","@#$%!"),
            ("NEG","too_long","Too long (256 chars)","A"*256),
            ("NEG","emoji","Emoji in name","John 😊 Doe"),
            ("NEG","html_tag","HTML tag","<script>name</script>"),
            ("NEG","integer_type","Integer type",42),
            ("NEG","sql_injection","SQL injection","' OR '1'='1"),
        ],
    },
    "string_email": {
        "label": "String — Email Address",
        "hint": "Use for: email, email_address, contact_email",
        "cases": [
            ("POS","valid_standard","Standard email","user@example.com"),
            ("POS","valid_subdomain","Subdomain email","user@mail.example.com"),
            ("POS","valid_plus_alias","Plus alias","user+test@example.com"),
            ("POS","valid_dot_local","Dot in local part","first.last@example.com"),
            ("POS","valid_numbers","Numbers in email","user123@example123.com"),
            ("POS","valid_uppercase","Uppercase letters","User@Example.COM"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","missing_at","No @ symbol","userexample.com"),
            ("NEG","missing_domain","No domain","user@"),
            ("NEG","missing_tld","No TLD","user@example"),
            ("NEG","missing_local","No local part","@example.com"),
            ("NEG","double_at","Double @","user@@example.com"),
            ("NEG","spaces_inside","Spaces inside","user @example.com"),
            ("NEG","plain_text","Plain text, no @","notanemail"),
            ("NEG","integer_type","Integer type",12345),
            ("NEG","sql_injection","SQL injection","' OR 1=1--@x.com"),
        ],
    },
    "string_phone": {
        "label": "String — Phone / Mobile Number",
        "hint": "Use for: phone, phone_number, mobile, contact",
        "cases": [
            ("POS","valid_10_digits","10-digit number","9876543210"),
            ("POS","valid_with_country","With country code","+919876543210"),
            ("POS","valid_with_dashes","With dashes","987-654-3210"),
            ("POS","valid_with_spaces","With spaces","987 654 3210"),
            ("POS","valid_intl_format","International format","+1-800-555-0100"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","too_short","Too short (5 digits)","12345"),
            ("NEG","too_long","Too long (20 digits)","12345678901234567890"),
            ("NEG","alphabets","Alphabets","abcdefghij"),
            ("NEG","all_zeros","All zeros","0000000000"),
            ("NEG","float_type","Float type",9876543210.5),
            ("NEG","negative_number","Negative number",-9876543210),
        ],
    },
    "string_date": {
        "label": "String — Date (YYYY-MM-DD)",
        "hint": "Use for: date, calendar, dob, start_date, end_date",
        "cases": [
            ("POS","valid_standard","Standard date","2024-05-15"),
            ("POS","valid_today","Today's date",datetime.now().strftime("%Y-%m-%d")),
            ("POS","valid_past","Past date","2000-01-01"),
            ("POS","valid_future","Future date","2030-12-31"),
            ("POS","valid_leap_day","Leap year day","2024-02-29"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","wrong_format_dmy","DD-MM-YYYY format","15-05-2024"),
            ("NEG","wrong_format_slash","DD/MM/YYYY format","15/05/2024"),
            ("NEG","invalid_month_13","Month = 13","2024-13-01"),
            ("NEG","invalid_day_32","Day = 32","2024-05-32"),
            ("NEG","plain_text","Plain text","today"),
            ("NEG","integer_type","Integer type",20240515),
        ],
    },
    "string_datetime": {
        "label": "String — DateTime (ISO 8601)",
        "hint": "Use for: datetime, created_at, scheduled_at, timestamp",
        "cases": [
            ("POS","valid_iso_full","Full ISO datetime","2024-05-15T10:30:00"),
            ("POS","valid_iso_with_tz","With timezone Z","2024-05-15T10:30:00Z"),
            ("POS","valid_iso_offset","With offset +05:30","2024-05-15T10:30:00+05:30"),
            ("POS","valid_iso_ms","With milliseconds","2024-05-15T10:30:00.000Z"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","date_only","Date only (no time)","2024-05-15"),
            ("NEG","wrong_separator","Space instead of T","2024-05-15 10:30:00"),
            ("NEG","invalid_hour_25","Hour = 25","2024-05-15T25:00:00"),
            ("NEG","plain_text","Plain text","now"),
            ("NEG","unix_timestamp","Unix timestamp integer",1715770200),
        ],
    },
    "string_url": {
        "label": "String — URL / Link",
        "hint": "Use for: url, link, website, callback_url, redirect_url",
        "cases": [
            ("POS","valid_https","HTTPS URL","https://www.example.com"),
            ("POS","valid_http","HTTP URL","http://example.com"),
            ("POS","valid_with_path","With path","https://example.com/path/page"),
            ("POS","valid_with_query","With query string","https://example.com/page?id=1"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","missing_scheme","No http/https","www.example.com"),
            ("NEG","plain_text","Plain text","example"),
            ("NEG","spaces_in_url","Spaces inside URL","https://example .com"),
            ("NEG","javascript_scheme","JavaScript scheme","javascript:void(0)"),
            ("NEG","integer_type","Integer type",12345),
        ],
    },
    "string_password": {
        "label": "String — Password",
        "hint": "Use for: password, new_password, confirm_password",
        "cases": [
            ("POS","valid_strong","Strong password","P@ssw0rd!2024"),
            ("POS","valid_long","Long password","MyStr0ng#Pass!2024XYZ"),
            ("POS","valid_special_chars","With special chars","Tr0ub4dor&3"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","too_short","Too short (5 chars)","Ab1!"),
            ("NEG","no_uppercase","No uppercase","password123!"),
            ("NEG","no_number","No number","Password!"),
            ("NEG","no_special","No special char","Password123"),
            ("NEG","all_same","All same chars","AAAAAAAAAA"),
            ("NEG","integer_type","Integer type",12345678),
        ],
    },
    "string_text": {
        "label": "String — Long Text / Description",
        "hint": "Use for: description, note, comment, remark, body, content",
        "cases": [
            ("POS","valid_sentence","Normal sentence","This is a valid description."),
            ("POS","valid_multiline","Multiline text","Line one.\nLine two."),
            ("POS","valid_long","Long text","Lorem ipsum " * 20),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","too_long","Exceeds 10000 chars","A"*10001),
            ("NEG","html_basic","HTML injection","<b>bold</b>"),
            ("NEG","sql_injection","SQL injection","'; DROP TABLE users;--"),
            ("NEG","xss_tag","XSS attack","<script>alert(1)</script>"),
            ("NEG","integer_type","Integer type",123),
        ],
    },
    "string_enum": {
        "label": "String — Enum / Dropdown",
        "hint": "Use for: priority, status, type, category, role, level",
        "cases": [
            ("POS","valid_high","High","High"),
            ("POS","valid_medium","Medium","Medium"),
            ("POS","valid_low","Low","Low"),
            ("POS","valid_active","Active","Active"),
            ("POS","valid_inactive","Inactive","Inactive"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","random_string","Random string","xyzabc123"),
            ("NEG","number_type","Number type",1),
            ("NEG","mixed_case","Wrong case","HIGH"),
            ("NEG","with_space","With extra space","High "),
            ("NEG","numeric_string","Numeric string","123"),
        ],
    },
    "string_hex": {
        "label": "String — Hexadecimal",
        "hint": "Use for: hex, hexadecimal, color_hex, hash, checksum fields",
        "cases": [
            ("POS","valid_uppercase","Uppercase hex","A1B2C3D4"),
            ("POS","valid_lowercase","Lowercase hex","deadbeef"),
            ("POS","valid_prefixed","0x-prefixed hex","0x1A2B3C"),
            ("POS","valid_short_color","Short CSS color hex","#FFF"),
            ("POS","valid_long_color","Long CSS color hex","#1a2b3c"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","invalid_char_g","Contains non-hex char","12AG"),
            ("NEG","binary_like","Binary-looking value","10101010"),
            ("NEG","odd_length","Odd length without prefix","ABC"),
            ("NEG","only_prefix","Prefix only","0x"),
            ("NEG","integer_type","Integer type",255),
        ],
    },
    "string_binary": {
        "label": "String — Binary",
        "hint": "Use for: binary, bitmask, bits, flags_binary fields",
        "cases": [
            ("POS","valid_single_bit","Single bit","1"),
            ("POS","valid_byte","8-bit binary","10101010"),
            ("POS","valid_with_leading_zeroes","Leading zeroes","00001111"),
            ("POS","valid_16_bit","16-bit binary","1100110011001100"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","contains_two","Contains digit 2","101201"),
            ("NEG","contains_alpha","Contains alphabet","10A01"),
            ("NEG","prefixed_form","0b-prefixed value","0b1010"),
            ("NEG","only_spaces","Only spaces","   "),
            ("NEG","integer_type","Integer type",101010),
        ],
    },
    "string_ip": {
        "label": "String — IP Address",
        "hint": "Use for: ip, ip_address, ipv4, ipv6, host_ip fields",
        "cases": [
            ("POS","valid_ipv4_private","Private IPv4","192.168.1.10"),
            ("POS","valid_ipv4_public","Public IPv4","8.8.8.8"),
            ("POS","valid_ipv4_loopback","Loopback IPv4","127.0.0.1"),
            ("POS","valid_ipv6_full","Full IPv6","2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            ("POS","valid_ipv6_short","Short IPv6","2001:db8::1"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","ipv4_octet_overflow","IPv4 octet > 255","256.100.50.1"),
            ("NEG","ipv4_too_short","IPv4 missing octet","10.0.0"),
            ("NEG","ipv6_double_compression","Double :: in IPv6","2001::db8::1"),
            ("NEG","hostname_instead","Hostname instead","example.com"),
            ("NEG","integer_type","Integer type",3232235777),
        ],
    },
    "string_id": {
        "label": "String — ID / Code / Reference",
        "hint": "Use for: id, uuid, guid, code, ref, token, key",
        "cases": [
            ("POS","valid_uuid","Valid UUID","550e8400-e29b-41d4-a716-446655440000"),
            ("POS","valid_alphanumeric","Alphanumeric ID","ABC123XYZ"),
            ("POS","valid_numeric_string","Numeric string ID","123456"),
            ("NEG","empty_string","Empty",""),
            ("NEG","null_value","Null",None),
            ("NEG","only_spaces","Only spaces","   "),
            ("NEG","integer_type","Integer type",123456),
            ("NEG","sql_injection","SQL injection","1'; DROP TABLE--"),
            ("NEG","too_long","Too long (300 chars)","A"*300),
        ],
    },
    "numeric_integer": {
        "label": "Numeric — Integer",
        "hint": "Use for: integer-only numeric fields",
        "cases": [
            ("POS","valid_positive","Positive integer",1),
            ("POS","valid_zero","Zero",0),
            ("POS","valid_large","Large number",999999),
            ("POS","valid_small","Small number",1),
            ("NEG","empty_string","Empty string",""),
            ("NEG","null_value","Null",None),
            ("NEG","float_value","Float value",1.5),
            ("NEG","string_value","String value","abc"),
            ("NEG","negative","Negative integer",-1),
            ("NEG","boolean_type","Boolean type",True),
            ("NEG","array_type","Array type",[1,2,3]),
        ],
    },
    "numeric_float": {
        "label": "Numeric — Float / Decimal",
        "hint": "Use for: float, decimal, amount fields",
        "cases": [
            ("POS","valid_decimal","Valid decimal",99.99),
            ("POS","valid_integer_as_float","Integer as float",100.0),
            ("POS","valid_zero","Zero",0.0),
            ("POS","valid_small","Small decimal",0.01),
            ("NEG","empty_string","Empty string",""),
            ("NEG","null_value","Null",None),
            ("NEG","string_value","String value","abc"),
            ("NEG","negative","Negative float",-1.5),
            ("NEG","boolean_type","Boolean type",True),
            ("NEG","too_large","Too large",999999999999.99),
        ],
    },
    "boolean": {
        "label": "Boolean — True / False",
        "hint": "Use for: boolean, status, flag fields",
        "cases": [
            ("POS","valid_true","True",True),
            ("POS","valid_false","False",False),
            ("NEG","string_true","String 'true'","true"),
            ("NEG","string_false","String 'false'","false"),
            ("NEG","integer_1","Integer 1",1),
            ("NEG","integer_0","Integer 0",0),
            ("NEG","null_value","Null",None),
            ("NEG","empty_string","Empty string",""),
            ("NEG","random_string","Random string","yes"),
        ],
    },
    "array": {
        "label": "Array / List",
        "hint": "Use for: array, list fields",
        "cases": [
            ("POS","valid_single","Single item",["item1"]),
            ("POS","valid_multiple","Multiple items",["a","b","c"]),
            ("POS","valid_empty","Empty array",[]),
            ("NEG","null_value","Null",None),
            ("NEG","string_type","String instead","value"),
            ("NEG","integer_type","Integer instead",123),
            ("NEG","boolean_type","Boolean type",True),
            ("NEG","too_many_items","Too many items (101)",list(range(101))),
        ],
    },
}

IGNORED_FIELDS = {
    "modifiedtime","createdtime","creator","creatorid",
    "lastmodifier","lastmodifierid",
}

_IDEMPOTENCY_HEADERS = {
    "requestid","x-request-id","x-requestid",
    "x-correlation-id","correlation-id",
    "idempotency-key","x-idempotency-key",
}

# ─────────────────────────────────────────────────────────────────────────────
#  TYPE AUTO-DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

_HEX_RE = re.compile(r'^(?:#?[0-9a-fA-F]{3}|#?[0-9a-fA-F]{6}|0x[0-9a-fA-F]+|[0-9a-fA-F]{4,})$')
_BINARY_RE = re.compile(r'^[01]{1,64}$')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_IPV4_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$')
_IPV6_RE = re.compile(r'^(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}$|^(?:[0-9A-Fa-f]{1,4}:){0,6}::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{0,4}$')


def detect_type(key: str, value: Any) -> str:
    k = key.lower()
    v = str(value) if value is not None else ""

    if isinstance(value, bool):
        return "boolean"
    if any(x in k for x in ["email", "mail"]):
        return "string_email"
    if any(x in k for x in ["phone", "mobile", "contact", "cell"]):
        return "string_phone"
    if any(x in k for x in ["password", "passwd", "pwd", "secret"]):
        return "string_password"
    if any(x in k for x in ["ip_address", "ipaddress", "ipv4", "ipv6", "client_ip", "server_ip", "host_ip"]):
        return "string_ip"
    if "ip" == k or k.endswith("_ip") or k.startswith("ip_"):
        return "string_ip"
    if any(x in k for x in ["url", "link", "website", "callback", "redirect", "endpoint"]):
        return "string_url"
    if any(x in k for x in ["date", "calendar", "dob", "birthday", "expiry"]) and "time" not in k:
        return "string_date"
    if any(x in k for x in ["datetime", "timestamp", "created_at", "updated_at", "scheduled"]):
        return "string_datetime"
    if any(x in k for x in ["description", "desc", "note", "comment", "remark", "message",
                              "body", "content", "detail", "summary", "bio", "about"]):
        return "string_text"
    if any(x in k for x in ["appname", "app_name", "appid", "app_id", "typename",
                              "type_name", "entityname", "entity_name"]):
        return "string_id"
    if any(x in k for x in ["priority", "status", "type", "category", "role",
                              "level", "mode", "state", "kind", "gender", "plan"]):
        return "string_enum"
    if any(x in k for x in ["name", "fullname", "full_name", "first_name", "last_name",
                              "author", "owner"]):
        return "string_name"
    if any(x in k for x in ["title", "label", "subject", "tag", "heading"]):
        return "string_general"
    if any(x in k for x in ["hex", "hexadecimal", "checksum", "hash", "color_hex"]):
        return "string_hex"
    if any(x in k for x in ["binary", "bitmask", "bits", "flags_binary"]):
        return "string_binary"
    if any(x in k for x in ["id", "uuid", "guid", "code", "ref", "token", "key",
                              "voucher", "coupon", "serial"]):
        return "string_id"

    if isinstance(value, list):
        return "array"
    if isinstance(value, int):
        return "numeric_integer"
    if isinstance(value, float):
        return "numeric_float"
    if isinstance(value, str):
        if re.match(r'^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$', v):
            return "string_email"
        if re.match(r'^\d{4}-\d{2}-\d{2}$', v):
            return "string_date"
        if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}', v):
            return "string_datetime"
        if v.startswith(("http://", "https://")):
            return "string_url"
        if re.match(r'^[\d\s\-\+\(\)]{7,15}$', v) and any(c.isdigit() for c in v):
            return "string_phone"
        if _UUID_RE.match(v):
            return "string_id"
        if _IPV4_RE.match(v) or _IPV6_RE.match(v):
            return "string_ip"
        if _BINARY_RE.match(v) and len(v) >= 4:
            return "string_binary"
        if _HEX_RE.match(v):
            return "string_hex"
        if len(v) > 80:
            return "string_text"

    return "string_general"


_PATH_TOKEN_RE = re.compile(r"\[(\d+)\]|([^.\[\]]+)")


def _parse_path(path: str) -> list:
    """Parse 'items[0].name' / '[0].id' / 'a.b' → ['items', 0, 'name'] / [0, 'id'] / ['a', 'b']."""
    if not path:
        return []
    tokens = []
    for m in _PATH_TOKEN_RE.finditer(path):
        if m.group(1) is not None:
            tokens.append(int(m.group(1)))
        else:
            tokens.append(m.group(2))
    return tokens


def _join_path(prefix: str, key: str) -> str:
    if not prefix:
        return key
    if prefix.endswith("]"):
        return f"{prefix}.{key}"
    return f"{prefix}.{key}"


def flatten_params(body: dict, prefix: str = "") -> list:
    """Flatten nested dict/list-of-dicts to param entries with indexed paths.

    Array-of-objects uses explicit indices: items[0].name, items[1].name
    so set_nested_value can target the correct element (no path collision).
    """
    result = []

    for k, v in body.items():
        if k.lower() in IGNORED_FIELDS:
            continue
        path = _join_path(prefix, k)
        if isinstance(v, dict) and v:
            result.extend(flatten_params(v, path))
        elif isinstance(v, list) and v and any(isinstance(item, dict) for item in v):
            for idx, item in enumerate(v):
                if not isinstance(item, dict):
                    continue
                result.extend(flatten_params(item, f"{path}[{idx}]"))
        else:
            detected = detect_type(k, v)
            result.append({
                "path": path,
                "value": v,
                "detected": detected,
                "detected_label": DATASETS[detected]["label"],
                "datasets": [{"key": dk, "label": dv["label"], "hint": dv["hint"]}
                             for dk, dv in DATASETS.items()],
            })
    return result


def flatten_body(body: Any) -> list:
    """Flatten request body whether dict or top-level JSON array.

    Top-level fields like encodedValue (base64 JSON) are expanded so inner
    paths (encodedValue.name) show up as testable params. The live request
    body is left encoded; set/get_nested_value re-wrap on send.
    """
    expanded, b64_fields = _expand_b64_json_fields(body)
    if isinstance(expanded, list):
        params = []
        for idx, item in enumerate(expanded):
            if isinstance(item, dict):
                params.extend(flatten_params(item, f"[{idx}]"))
    elif isinstance(expanded, dict):
        params = flatten_params(expanded)
    else:
        params = []
    if b64_fields:
        for p in params:
            tokens = _parse_path(p.get("path") or "")
            if tokens and isinstance(tokens[0], str) and tokens[0] in b64_fields:
                p["encoding"] = "b64_json"
                p["b64_field"] = tokens[0]
    return params


# ── Base64-encoded JSON body fields (e.g. {"encodedValue": "<b64>"}) ──────────
_B64_PARAM_NAME_RE = re.compile(r"encoded|base64|b64", re.I)


def _b64_decode_bytes(s: str):
    padded = s + "=" * (-len(s) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except Exception:
        pass
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def _try_decode_b64_json(val: Any):
    """Return parsed JSON object/array, or None."""
    if not isinstance(val, str):
        return None
    s = val.strip()
    if len(s) < 8:
        return None
    raw = _b64_decode_bytes(s)
    if not raw:
        return None
    try:
        inner = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if isinstance(inner, (dict, list)):
        return inner
    return None


def _b64_json_field_meta(body: Any) -> dict:
    """Top-level keys whose names look encoded and whose values are b64 JSON."""
    out = {}
    if not isinstance(body, dict):
        return out
    for k, v in body.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        if not _B64_PARAM_NAME_RE.search(k):
            continue
        if _try_decode_b64_json(v) is None:
            continue
        out[k] = {
            "urlsafe": ("-" in v or "_" in v) and ("+" not in v and "/" not in v),
            "strip_pad": "=" not in v,
        }
    return out


def _encode_b64_json(obj: Any, urlsafe: bool = False, strip_pad: bool = False) -> str:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    enc = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
    s = enc.decode("ascii")
    if strip_pad:
        s = s.rstrip("=")
    return s


def _expand_b64_json_fields(body: Any):
    """Copy of body with b64 JSON fields replaced by decoded objects. Original untouched."""
    fields = _b64_json_field_meta(body)
    if not fields:
        return body, fields
    expanded = copy.deepcopy(body)
    for k in fields:
        inner = _try_decode_b64_json(expanded.get(k))
        if inner is not None:
            expanded[k] = inner
    return expanded, fields


def _tokens_to_path(tokens: list) -> str:
    out = ""
    for t in tokens:
        if isinstance(t, int):
            out += f"[{t}]"
        else:
            out += t if not out else f".{t}"
    return out


def _split_b64_inner_path(path: str, b64_fields: dict):
    """If path is inside a b64 wrapper, return (field, inner_path); else None."""
    if not path or not b64_fields:
        return None
    tokens = _parse_path(path)
    if not tokens or not isinstance(tokens[0], str) or tokens[0] not in b64_fields:
        return None
    if len(tokens) < 2:
        return None
    return tokens[0], _tokens_to_path(tokens[1:])


# ─────────────────────────────────────────────────────────────────────────────
#  REQUEST ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def build_session():
    s = requests.Session()
    r = Retry(total=2, backoff_factor=0.5, status_forcelist=[502, 503], read=0)
    a = HTTPAdapter(max_retries=r)
    s.mount("http://", a)
    s.mount("https://", a)
    s.verify = False
    return s


def _try_json_container(val: Any):
    """Parse a JSON object/array stored as a string. Returns (parsed, converted)."""
    if isinstance(val, (dict, list)):
        return val, False
    if not isinstance(val, str):
        return val, False
    s = val.strip()
    if not s or s[0] not in "{[":
        return val, False
    try:
        parsed = json.loads(s)
    except Exception:
        return val, False
    if isinstance(parsed, (dict, list)):
        return parsed, True
    return val, False


def _set_nested_value_raw(body: Any, path: str, value: Any) -> bool:
    """Set a value at a dotted/indexed path. Returns True if the write landed.

    Supports: 'a.b', 'items[0].name', '[0].id'
    Legacy paths like 'items.name' (no index) still target the first dict in a list.
    Top-level JSON array body + string path (no leading [i]) targets body[0].
    JSON-encoded string fields along the path are parsed, mutated, and stored
    back as objects (fire_request JSON-encodes the whole body).
    """
    tokens = _parse_path(path)
    if not tokens or body is None or isinstance(body, str):
        return False

    # Top-level array: path may still be wrapper[0].field (e.g. data[0].name)
    if isinstance(body, list) and isinstance(tokens[0], str):
        if len(tokens) >= 2 and isinstance(tokens[1], int):
            if _set_nested_value_raw(body, _tokens_to_path(tokens[1:]), value):
                return True
        if body and isinstance(body[0], dict):
            return _set_nested_value_raw(body[0], path, value)
        return False

    obj = body
    for i, tok in enumerate(tokens[:-1]):
        next_tok = tokens[i + 1]
        if isinstance(tok, int):
            if not isinstance(obj, list) or not (0 <= tok < len(obj)):
                return False
            child = obj[tok]
            parsed, conv = _try_json_container(child)
            if conv:
                obj[tok] = parsed
                child = parsed
            obj = child
            continue

        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            obj = obj[0]

        if not isinstance(obj, dict) or tok not in obj:
            return False
        nxt = obj[tok]
        parsed, conv = _try_json_container(nxt)
        if conv:
            obj[tok] = parsed
            nxt = parsed
        # Legacy: path has no [i] before a string key → use first object in list
        if (isinstance(nxt, list) and nxt and isinstance(next_tok, str)
                and isinstance(nxt[0], dict)):
            obj = nxt[0]
        else:
            obj = nxt

    last = tokens[-1]
    parsed, conv = _try_json_container(obj)
    if conv:
        return False
    if isinstance(obj, list) and obj and isinstance(obj[0], dict) and isinstance(last, str):
        obj = obj[0]
    if isinstance(last, int):
        if isinstance(obj, list) and 0 <= last < len(obj):
            obj[last] = value
            return True
        return False
    if isinstance(obj, dict):
        existing = obj.get(last)
        if isinstance(existing, list) and not isinstance(value, list):
            obj[last] = [value]
        else:
            obj[last] = value
        return True
    return False


def set_nested_value(body: Any, path: str, value: Any) -> bool:
    """Set path, decoding/re-encoding base64 JSON wrappers when needed."""
    if not path or body is None:
        return False
    if isinstance(body, dict):
        fields = _b64_json_field_meta(body)
        split = _split_b64_inner_path(path, fields)
        if split:
            field, inner = split
            decoded = _try_decode_b64_json(body.get(field, ""))
            if decoded is not None:
                ok = _set_nested_value_raw(decoded, inner, value)
                if ok:
                    meta = fields[field]
                    body[field] = _encode_b64_json(
                        decoded,
                        urlsafe=meta.get("urlsafe", False),
                        strip_pad=meta.get("strip_pad", False),
                    )
                return ok
    if _set_nested_value_raw(body, path, value):
        return True
    # Fallback: data[0].x on a top-level array body → [0].x
    tokens = _parse_path(path)
    if (isinstance(body, list) and tokens and isinstance(tokens[0], str)
            and len(tokens) >= 2 and isinstance(tokens[1], int)):
        return _set_nested_value_raw(body, _tokens_to_path(tokens[1:]), value)
    return False


# HTTP/2 pseudo-headers and other headers that Python requests cannot send
_INVALID_HEADERS = {
    # HTTP/2 pseudo-headers — start with ":" — always invalid for HTTP/1.1
    ":authority", ":method", ":path", ":scheme", ":status",
    # Browser-only / hop-by-hop headers
    "host", "content-length", "transfer-encoding",
    "connection", "upgrade", "keep-alive", "proxy-connection",
    "accept-encoding",  # requests manages this itself
}

def _is_invalid_header(name: str) -> bool:
    n = name.lower().strip()
    # Skip all HTTP/2 pseudo-headers (start with colon)
    if n.startswith(":"):
        return True
    # Skip known problematic headers
    if n in _INVALID_HEADERS:
        return True
    # Skip any header with whitespace / control chars in name
    if any(c in name for c in (" ", "\t", "\n", "\r")):
        return True
    return False

def _sanitize_hdr_value(v: str) -> str:
    """Strip non-latin-1 chars from header values — requests lib requires latin-1."""
    try:
        v.encode("latin-1")
        return v
    except (UnicodeEncodeError, UnicodeDecodeError):
        return v.encode("latin-1", errors="ignore").decode("latin-1")

# Small pause between validation cases + limited 429 backoff (avoid hammering APIs)
_CASE_PACING_SEC = 0.05
_MAX_429_RETRIES = 2


def fire_request(session, method, url, headers, query, body, body_type, timeout=30):
    # Filter out HTTP/2 pseudo-headers; sanitize values to latin-1 (requests lib requirement)
    hdrs = {k: _sanitize_hdr_value(str(v))
            for k, v in headers.items() if not _is_invalid_header(k)}

    for hdr_key in list(hdrs.keys()):
        if hdr_key.lower() in _IDEMPOTENCY_HEADERS:
            hdrs[hdr_key] = str(random.randint(10**15, 10**16 - 1))

    # Strip query string from URL — let requests handle params to avoid double-encoding
    parsed = urlparse(url)
    base_url = parsed._replace(query="").geturl()

    kw = {"headers": hdrs, "timeout": timeout}
    if query is not None:
        # Explicit query dict (may be empty). None values are omitted — never "None".
        from urllib.parse import unquote
        params = {}
        for k, v in query.items():
            if v is None:
                continue
            params[k] = unquote(str(v)) if isinstance(v, str) else v
        kw["params"] = params
    elif parsed.query:
        # No override — keep original URL with its query string untouched
        kw["params"] = None
        base_url = url

    bt = (body_type or "").lower().strip()
    if bt == "form" and body is not None:
        kw["data"] = body
    elif isinstance(body, (dict, list)) and bt != "multipart":
        kw["json"] = body
    elif bt in ("json", "application/json") and body is not None:
        if isinstance(body, str):
            jbody, conv = _try_json_container(body)
            kw["json" if conv else "data"] = jbody if conv else body
        else:
            kw["json"] = body
    elif body is not None and bt == "raw":
        kw["data"] = body

    try:
        last_status, last_text, last_elapsed = "ERROR", "", 0
        for attempt in range(_MAX_429_RETRIES + 1):
            resp = session.request(method, base_url, **kw)
            elapsed = int(resp.elapsed.total_seconds() * 1000)
            try:
                text = resp.text[:3000]
            except Exception:
                text = ""
            last_status, last_text, last_elapsed = resp.status_code, text, elapsed
            if resp.status_code != 429 or attempt >= _MAX_429_RETRIES:
                break
            time.sleep(min(2 ** attempt, 4))
        return last_status, last_text, last_elapsed
    except requests.exceptions.Timeout:
        return "TIMEOUT", "", 0
    except Exception as e:
        return "ERROR", str(e)[:200], 0


def _normalize_json_body(body: Any, body_type: Optional[str]):
    """Parse JSON-text bodies so nested unique-list writes can mutate them."""
    bt = (body_type or "").strip()
    btl = bt.lower()
    if isinstance(body, str) and btl in ("", "json", "raw", "application/json"):
        parsed, conv = _try_json_container(body)
        if conv:
            return parsed, "json"
    if isinstance(body, (dict, list)) and btl not in ("form", "multipart"):
        return body, "json"
    return body, body_type


def _compose_request_url(url: str, query: Optional[dict]) -> str:
    """Rebuild the URL the same way fire_request sends it (base + query dict)."""
    parsed = urlparse(url or "")
    base = parsed._replace(query="").geturl()
    if query is None:
        return url or ""
    from urllib.parse import unquote
    items = []
    for k, v in query.items():
        if v is None:
            continue
        val = unquote(str(v)) if isinstance(v, str) else v
        items.append((str(k), val))
    if not items:
        return base
    return base + "?" + urlencode(items, doseq=True)


def _curl_shell_arg(s: str) -> str:
    """POSIX single-quote. Do not emit \\n inside double quotes (Postman sends literal backslash-n)."""
    s = "" if s is None else str(s)
    return "'" + s.replace("'", "'\\''") + "'"


def _curl_payload(body: Any) -> str:
    """Compact JSON body for cURL so Postman imports valid JSON."""
    if body is None or body in ("", "(no body)", "null", "None"):
        return ""
    if not isinstance(body, str):
        try:
            return json.dumps(body, separators=(",", ":"), ensure_ascii=False, default=str)
        except Exception:
            return str(body)
    s = body
    t = s.strip()
    if t[:1] in "{[":
        try:
            return json.dumps(json.loads(s), separators=(",", ":"), ensure_ascii=False)
        except Exception:
            pass
    return s


_CURL_SKIP_HEADERS = {
    "content-length", "host", "connection", "transfer-encoding",
    "accept-encoding", "content-encoding", "keep-alive", "proxy-connection",
    "te", "trailer", "upgrade", "http2-settings", "upgrade-insecure-requests",
}


def _build_curl_command(method: str, url: str, headers: Optional[dict], body: Any) -> str:
    """Postman-safe folded cURL for a single test case."""
    method = (method or "GET").upper()
    lines = [f"curl --http1.1 -X {method} {_curl_shell_arg(url or '')}"]
    seen = set()
    for k, v in (headers or {}).items():
        if not k or str(k).startswith(":"):
            continue
        lk = str(k).lower()
        if lk in _CURL_SKIP_HEADERS or lk.startswith("sec-ch-") or lk.startswith("sec-fetch-") or lk.startswith("sec-gpc"):
            continue
        if lk in seen:
            continue
        seen.add(lk)
        lines.append(f"  -H {_curl_shell_arg(f'{k}: {v}')}")
    body_str = _curl_payload(body)
    if body_str:
        if "content-type" not in seen and body_str.lstrip()[:1] in ("{", "["):
            lines.append(f"  -H {_curl_shell_arg('Content-Type: application/json')}")
        lines.append(f"  --data-raw {_curl_shell_arg(body_str)}")
    return " \\\n".join(lines)


def _parse_status_code(status) -> Optional[int]:
    try:
        return int(status)
    except (ValueError, TypeError):
        return None


def determine_result(category: str, status) -> str:
    """Status-only verdict (kept for compatibility / simple cases)."""
    code = _parse_status_code(status)
    if code is None:
        return "ERROR"
    if category == "POS":
        return "PASS" if 200 <= code < 300 else "FAIL"
    else:
        if 400 <= code < 500:
            return "PASS"
        elif 200 <= code < 300:
            return "FAIL"
        elif code >= 500:
            return "WARN"
        return "WARN"


def _is_auth_status(status) -> bool:
    """401 = clear auth failure. (403 left alone — often business forbidden, not expiry.)"""
    return _parse_status_code(status) == 401


def _looks_like_error_json(text: str) -> tuple:
    """Detect error-shaped JSON on HTTP 2xx (POS false success). Returns (is_error, reason)."""
    if not text or not str(text).strip():
        return False, ""
    try:
        data = json.loads(text)
    except Exception:
        return False, ""
    if not isinstance(data, dict):
        return False, ""

    if data.get("success") is False:
        return True, "JSON success=false"
    st = str(data.get("status", "")).strip().upper()
    if st in ("FAIL", "FAILED", "ERROR", "UNAUTHORIZED", "FORBIDDEN"):
        return True, f"JSON status={data.get('status')}"

    # Explicit error fields with a non-OK code
    err_code = data.get("errorCode", data.get("error_code", data.get("code")))
    has_err_payload = bool(data.get("error") or data.get("errors"))
    if has_err_payload and err_code not in (None, "", 0, "0", 200, "200", "OK", "ok", "SUCCESS"):
        return True, "JSON error payload with error code"

    # HTTP-ish error code inside body
    if isinstance(err_code, int) and err_code >= 400:
        return True, f"JSON code={err_code}"
    if isinstance(err_code, str) and err_code.isdigit() and int(err_code) >= 400:
        return True, f"JSON code={err_code}"

    return False, ""


def _bodies_equivalent(a: str, b: str) -> bool:
    if not a or not b:
        return False
    try:
        return json.loads(a) == json.loads(b)
    except Exception:
        return str(a).strip() == str(b).strip()


def _baseline_was_json(text: str) -> bool:
    if not text or not str(text).strip():
        return False
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def evaluate_test_result(
    category: str,
    status,
    resp_text: str,
    baseline_status,
    baseline_body: str,
    baseline_ok: bool,
) -> tuple:
    """Status + response assertions.

    Returns (result, fail_reason, assertions).
    - Auth: mid-run 401 after a healthy baseline → ERROR (not NEG PASS).
    - POS 2xx with error-shaped JSON → FAIL.
    - NEG 4xx with body identical to success baseline → FAIL.
    Status rules otherwise match determine_result (no surprise conflicts).
    """
    code = _parse_status_code(status)
    assertions = []

    # ── Auth expiry (never treat mid-run 401 as a successful NEG) ───────────
    if baseline_ok and _is_auth_status(status):
        detail = "HTTP 401 while baseline was OK — token expired or session ended"
        assertions.append({"check": "auth", "passed": False, "detail": detail})
        return "ERROR", detail, assertions

    if code is None:
        detail = f"Request error: {status}"
        assertions.append({"check": "transport", "passed": False, "detail": detail})
        return "ERROR", detail, assertions

    status_result = determine_result(category, status)

    # ── POS ─────────────────────────────────────────────────────────────────
    if category == "POS":
        if status_result == "PASS":
            is_err, reason = _looks_like_error_json(resp_text or "")
            if is_err:
                assertions.append({"check": "response_body", "passed": False, "detail": reason})
                return "FAIL", f"HTTP {code} but error body ({reason})", assertions

            if _baseline_was_json(baseline_body or ""):
                try:
                    json.loads(resp_text or "")
                    assertions.append({"check": "json_parse", "passed": True, "detail": "Valid JSON"})
                except Exception:
                    assertions.append({
                        "check": "json_parse", "passed": False,
                        "detail": "Baseline was JSON; response is not",
                    })
                    return "WARN", "HTTP 2xx but response is not JSON (baseline was JSON)", assertions

            assertions.append({
                "check": "status", "passed": True,
                "detail": f"HTTP {code} OK for POS",
            })
            return "PASS", "", assertions

        assertions.append({
            "check": "status", "passed": False,
            "detail": f"HTTP {code} — expected 2xx for POS",
        })
        return "FAIL", f"Expected 2xx, got {status}", assertions

    # ── NEG ─────────────────────────────────────────────────────────────────
    if status_result == "PASS":
        # 4xx as expected — body should not be a copy of the success baseline
        if baseline_ok and baseline_body and _bodies_equivalent(resp_text or "", baseline_body):
            assertions.append({
                "check": "body_differs", "passed": False,
                "detail": "Got 4xx but body matches success baseline",
            })
            return "FAIL", "Rejected status but success body returned", assertions
        assertions.append({
            "check": "status", "passed": True,
            "detail": f"HTTP {code} rejected as expected",
        })
        return "PASS", "", assertions

    if status_result == "FAIL":
        assertions.append({
            "check": "status", "passed": False,
            "detail": f"HTTP {code} — invalid value was accepted",
        })
        return "FAIL", f"Expected 4xx, got {status}", assertions

    assertions.append({"check": "status", "passed": False, "detail": f"HTTP {code}"})
    return status_result, f"HTTP {status}", assertions


# ─────────────────────────────────────────────────────────────────────────────
#  PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str
    method: str
    headers: dict
    query: dict = {}
    body: Optional[Any] = None
    body_type: Optional[str] = None

class ParamDataset(BaseModel):
    path: str
    dataset_key: str
    unique_format: Optional[str] = None  # e.g. "{uuid}" or "{alphanum:8}@test.com"
    # Overrides per case_id: "POS" | "NEG" | "SKIP"
    # None = dataset defaults; "SKIP" = do not run that case
    case_selections: Optional[dict] = None
    # Extra user-defined test values [{value, cat}] run after dataset cases
    custom_cases: Optional[list] = None


def _get_nested_value_raw(body: Any, path: str) -> Any:
    """Read value at dotted/indexed path (mirrors set_nested_value navigation)."""
    tokens = _parse_path(path)
    if not tokens or body is None:
        return None
    obj = body
    if isinstance(obj, str):
        parsed, conv = _try_json_container(obj)
        if not conv:
            return None
        obj = parsed
    if isinstance(obj, list) and isinstance(tokens[0], str):
        if len(tokens) >= 2 and isinstance(tokens[1], int):
            got = _get_nested_value_raw(obj, _tokens_to_path(tokens[1:]))
            if got is not None:
                return got
        if obj and isinstance(obj[0], dict):
            obj = obj[0]
        else:
            return None
    for i, tok in enumerate(tokens):
        if isinstance(tok, int):
            if not isinstance(obj, list) or not (0 <= tok < len(obj)):
                return None
            obj = obj[tok]
            parsed, conv = _try_json_container(obj)
            if conv:
                obj = parsed
            continue
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            obj = obj[0]
        parsed, conv = _try_json_container(obj)
        if conv:
            obj = parsed
        if not isinstance(obj, dict) or tok not in obj:
            return None
        nxt = obj[tok]
        parsed, conv = _try_json_container(nxt)
        if conv:
            nxt = parsed
        next_tok = tokens[i + 1] if i + 1 < len(tokens) else None
        if (isinstance(nxt, list) and nxt and isinstance(next_tok, str)
                and isinstance(nxt[0], dict)):
            obj = nxt[0]
        else:
            obj = nxt
    return obj


def get_nested_value(body: Any, path: str) -> Any:
    """Read path, decoding base64 JSON wrappers when needed."""
    if isinstance(body, dict):
        fields = _b64_json_field_meta(body)
        split = _split_b64_inner_path(path, fields)
        if split:
            field, inner = split
            decoded = _try_decode_b64_json(body.get(field, ""))
            if decoded is not None:
                return _get_nested_value_raw(decoded, inner)
    return _get_nested_value_raw(body, path)


def _cases_with_captured_seed(dataset: dict, original_value: Any) -> list:
    """Prepend POS case from captured value so enums/IDs aren't only hardcoded."""
    cases = list(dataset.get("cases") or [])
    if original_value is None or original_value == "":
        return cases
    if any(c[1] == "captured_original" for c in cases):
        return cases
    seed = ("POS", "captured_original", "Captured original value", original_value)
    return [seed] + cases


_STANDARD_TITLES_POOL = [
    "Project Meeting", "Quarterly Review", "Sprint Planning", "Status Brief",
    "Team Standup", "Hello World", "Client Onboarding", "System Audit",
    "Design Workshop", "Feature Roadmap", "Strategic Alignment", "Market Analysis",
    "Performance Review", "Security Patch", "Workflow Optimization", "Milestone Target",
    "Budget Forecast", "Resource Allocation", "Executive Summary", "Platform Architecture",
    "Customer Journey", "Product Backlog", "Operations Sync", "Release Checklist",
    "Data Pipeline", "Quality Benchmark", "Sprint Retro", "Technical Assessment",
    "Business Case Study", "Architecture Overview", "Service Integration", "Deployment Plan",
    "User Research", "Incident Postmortem", "Partner Evaluation", "Compliance Check",
    "Capacity Planning", "DevOps Milestone", "API Specification", "Knowledge Transfer",
]

_TITLE_ADJECTIVES = [
    "Project", "Quarterly", "Sprint", "System", "Client", "Product", "Strategic",
    "Team", "Resource", "Market", "Design", "Security", "Workflow", "Milestone",
    "Budget", "Performance", "Operational", "Financial", "Technical", "Executive",
    "Digital", "Enterprise", "Global", "Customer", "Platform", "Cloud", "Business",
    "Agile", "Core", "Dynamic", "Internal", "External", "Annual", "Weekly", "Monthly",
]

_TITLE_NOUNS = [
    "Meeting", "Review", "Planning", "Audit", "Sync", "Roadmap", "Summary",
    "Report", "Analysis", "Briefing", "Allocation", "Workshop", "Patch", "Pipeline",
    "Target", "Matrix", "Overview", "Session", "Tracker", "Initiative",
    "Update", "Discussion", "Evaluation", "Assessment", "Proposal", "Strategy", "Release",
]

_FIRST_NAMES_POOL = [
    "Rahul", "Priya", "Aarav", "Ananya", "David", "Sarah", "Michael", "Emma",
    "Vikram", "Sneha", "James", "Olivia", "Alex", "Sophia", "Carlos", "Maria",
    "Kenji", "Fatima", "Arjun", "Rohan", "Kavita", "Daniel", "Lucas", "Elena",
    "Liam", "Chloe", "Marcus", "Zoe", "Alice", "Bob", "Carol", "Dave",
    "Eva", "Frank", "Grace", "Hank", "Iris", "Jack", "Deepak", "Neha",
]

_LAST_NAMES_POOL = [
    "Sharma", "Patel", "Smith", "Jones", "Brown", "Davis", "Wilson", "Moore",
    "Taylor", "Anderson", "Gupta", "Verma", "Williams", "Jackson", "White", "Harris",
    "Martin", "Rao", "Malhotra", "Mehta", "Singh", "Fernandez", "Tanaka", "Sato",
    "Khan", "Al-Mansoor", "Kumar", "Das", "Joshi", "Mishra", "Reddy", "Nair",
]

_SAMPLE_WORDS = [
    "alpha", "beta", "gamma", "delta", "sigma", "omega", "matrix", "nexus",
    "vortex", "quantum", "stellar", "beacon", "apex", "horizon", "zenith",
]


def generate_dynamic_case_value(dataset_key: str, case_id: str, default_val: Any, cat: str = "POS") -> Any:
    """Generate dynamic, unique, and semantic-matching values for POS business cases.
    NOTE: Negative (NEG) cases strictly remain static / hardcoded as specified by the user.
    Captured original values also remain exact.
    """
    # 1. Negative cases strictly remain static/hardcoded
    if cat == "NEG":
        return default_val

    # 2. Captured original values remain exact
    if case_id == "captured_original":
        return default_val

    dk = (dataset_key or "").lower()
    cid = (case_id or "").lower()

    if dk == "string_general":
        if cid == "valid_standard":
            title = random.choice(_STANDARD_TITLES_POOL)
            return f"{title} {random.randint(100, 999)}"
        elif cid == "valid_alphanumeric":
            prefix = random.choice(["Report", "Update", "Batch", "Sprint", "Release", "Ticket", "Item", "Doc", "Audit"])
            return f"{prefix} {random.randint(2025, 2099)}"
        elif cid == "valid_single_char":
            return random.choice(string.ascii_letters)
        elif cid == "valid_with_spaces":
            adj = random.choice(_TITLE_ADJECTIVES)
            noun = random.choice(_TITLE_NOUNS)
            return f"My {adj} {noun} {random.randint(10, 99)}"
        elif cid == "valid_with_hyphen":
            prefix = random.choice(["Year-End", "Follow-Up", "High-Priority", "Semi-Annual", "Full-Scale", "Multi-Tenant", "Real-Time", "Cross-Platform"])
            noun = random.choice(["Report", "Review", "Analysis", "Sync", "Task", "Audit", "Summary"])
            return f"{prefix} {noun} {random.randint(10, 99)}"
        elif cid == "valid_with_apostrophe":
            role = random.choice(["Manager", "Director", "Auditor", "Lead", "Client", "Developer", "Supervisor", "Officer"])
            noun = random.choice(["Report", "Review", "Note", "Update", "Brief", "Log", "Request"])
            return f"{role}'s {noun} {random.randint(10, 99)}"
        elif cid == "valid_unicode":
            acc = random.choice(["Réunion Générale", "Café Résumé", "Conférence Équipe", "Séance Première", "Projet Spécial", "Événement Déjà Vu", "Protocole Sécurisé", "Système Déployé"])
            return f"{acc} {random.randint(10, 99)}"
        elif cid == "valid_numbers_mixed":
            return f"Version {random.randint(1, 9)}.{random.randint(0, 9)}.{random.randint(1, 99)} Update"
        elif cid == "valid_max_typical":
            seed = uuid.uuid4().hex
            base = f"DynamicText_{seed}_"
            return (base + ("A" * 100))[:100]

    elif dk == "string_name":
        if cid == "valid_full_name":
            return f"{random.choice(_FIRST_NAMES_POOL)} {random.choice(_LAST_NAMES_POOL)}"
        elif cid == "valid_first_only":
            return random.choice(_FIRST_NAMES_POOL)
        elif cid == "valid_with_apostrophe":
            return random.choice(["O'Brien", "O'Connor", "D'Souza", "O'Neil", "M'Donald", "O'Reilly", "D'Angelo", "O'Keefe", "D'Cruz"])
        elif cid == "valid_hyphenated":
            return random.choice(["Mary-Jane", "Jean-Luc", "Anne-Marie", "Claire-Louise", "John-Paul", "Marc-Andre", "Pierre-Louis", "Marie-Claire"])
        elif cid == "valid_with_initials":
            i1 = random.choice(string.ascii_uppercase)
            i2 = random.choice(string.ascii_uppercase)
            return f"{i1}. {i2}. {random.choice(_LAST_NAMES_POOL)}"
        elif cid == "valid_long_name":
            return f"{random.choice(_FIRST_NAMES_POOL)} {random.choice(_FIRST_NAMES_POOL)} {random.choice(_LAST_NAMES_POOL)}"
        elif cid == "valid_two_word":
            return f"{random.choice(_FIRST_NAMES_POOL)} {random.choice(_LAST_NAMES_POOL)}"

    elif dk == "string_email":
        num = random.randint(1000, 99999)
        tag = random.choice(_SAMPLE_WORDS)
        if cid == "valid_standard":
            return f"user_{num}_{tag}@example.com"
        elif cid == "valid_subdomain":
            return f"user_{num}@mail.{tag}api.org"
        elif cid == "valid_plus_alias":
            return f"user+test{num}@example.com"
        elif cid == "valid_dot_local":
            fn = random.choice(_FIRST_NAMES_POOL).lower()
            ln = random.choice(_LAST_NAMES_POOL).lower()
            return f"{fn}.{ln}{random.randint(10, 999)}@example.com"
        elif cid == "valid_numbers":
            return f"user{num}@example{random.randint(10, 99)}.com"
        elif cid == "valid_uppercase":
            return f"User_{num}@Example.COM"

    elif dk == "string_phone":
        lead = random.choice(["9", "8", "7", "6"])
        rest = random.randint(100000000, 999999999)
        num10 = f"{lead}{rest}"
        if cid == "valid_10_digits":
            return num10
        elif cid == "valid_with_country":
            return f"+91{num10}"
        elif cid == "valid_with_dashes":
            return f"{num10[:3]}-{num10[3:6]}-{num10[6:]}"
        elif cid == "valid_with_spaces":
            return f"{num10[:3]} {num10[3:6]} {num10[6:]}"
        elif cid == "valid_intl_format":
            return f"+1-{random.randint(200, 899)}-{random.randint(100, 999)}-{random.randint(1000, 9999)}"

    elif dk == "string_date":
        if cid == "valid_standard":
            return (datetime.now() - timedelta(days=random.randint(1, 180))).strftime("%Y-%m-%d")
        elif cid == "valid_today":
            return datetime.now().strftime("%Y-%m-%d")
        elif cid == "valid_past":
            return (datetime.now() - timedelta(days=random.randint(365, 3650))).strftime("%Y-%m-%d")
        elif cid == "valid_future":
            return (datetime.now() + timedelta(days=random.randint(30, 1825))).strftime("%Y-%m-%d")
        elif cid == "valid_leap_day":
            return random.choice(["2024-02-29", "2028-02-29", "2032-02-29"])

    elif dk == "string_datetime":
        dt = datetime.now() - timedelta(minutes=random.randint(1, 10000), seconds=random.randint(1, 59))
        if cid == "valid_iso_full":
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        elif cid == "valid_iso_with_tz":
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif cid == "valid_iso_offset":
            return dt.strftime("%Y-%m-%dT%H:%M:%S+05:30")
        elif cid == "valid_iso_ms":
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    elif dk == "string_url":
        tag = random.choice(_SAMPLE_WORDS)
        n = random.randint(100, 9999)
        if cid == "valid_https":
            return f"https://www.{tag}-{n}.example.com"
        elif cid == "valid_http":
            return f"http://api-{tag}-{n}.example.org"
        elif cid == "valid_with_path":
            return f"https://example.com/{tag}/item_{n}"
        elif cid == "valid_with_query":
            return f"https://example.com/search?ref={n}&tag={tag}"

    elif dk == "string_password":
        h = uuid.uuid4().hex[:6].capitalize()
        n = random.randint(100, 999)
        if cid == "valid_strong":
            return f"P@ss{n}!{h}"
        elif cid == "valid_long":
            return f"Str0ng#Pass!{n}{h}XYZ"
        elif cid == "valid_special_chars":
            return f"Tr{random.randint(10, 99)}&oub4dor%{n}!"

    elif dk == "string_text":
        n = random.randint(1000, 9999)
        if cid == "valid_sentence":
            return f"This is an operational description record #{n}."
        elif cid == "valid_multiline":
            return f"Section line one for record #{n}.\nSection line two verification notes."
        elif cid == "valid_long":
            return f"Detailed record #{n} description notes: " + ("Lorem ipsum test context " * 15)

    elif dk == "string_enum":
        return default_val

    elif dk == "string_hex":
        h = uuid.uuid4().hex
        if cid == "valid_uppercase":
            return h[:8].upper()
        elif cid == "valid_lowercase":
            return h[:8].lower()
        elif cid == "valid_prefixed":
            return f"0x{h[:6].upper()}"
        elif cid == "valid_short_color":
            return f"#{h[:3].upper()}"
        elif cid == "valid_long_color":
            return f"#{h[:6].lower()}"

    elif dk == "string_binary":
        if cid == "valid_single_bit":
            return random.choice(["1", "0"])
        elif cid == "valid_byte":
            return ''.join(random.choices(['0', '1'], k=8))
        elif cid == "valid_with_leading_zeroes":
            return '0000' + ''.join(random.choices(['0', '1'], k=4))
        elif cid == "valid_16_bit":
            return ''.join(random.choices(['0', '1'], k=16))

    elif dk == "string_ip":
        o1 = random.randint(1, 250)
        o2 = random.randint(1, 250)
        if cid == "valid_ipv4_private":
            return f"192.168.{o1}.{o2}"
        elif cid == "valid_ipv4_public":
            return f"{random.randint(11, 190)}.{o1}.{o2}.{random.randint(1, 250)}"
        elif cid == "valid_ipv4_loopback":
            return f"127.0.0.{o1}"
        elif cid == "valid_ipv6_full":
            return f"2001:0db8:85a3:{random.randint(1000, 9999):04x}:{random.randint(1000, 9999):04x}:8a2e:0370:{random.randint(1000, 9999):04x}"
        elif cid == "valid_ipv6_short":
            return f"2001:db8::{random.randint(1, 999):x}"

    elif dk == "string_id":
        if cid == "valid_uuid":
            return str(uuid.uuid4())
        elif cid == "valid_alphanumeric":
            chars = ''.join(random.choices(string.ascii_uppercase, k=4))
            return f"ID{random.randint(100, 999)}{chars}"
        elif cid == "valid_numeric_string":
            return str(random.randint(100000, 999999))

    elif dk == "numeric_integer":
        if cid == "valid_positive":
            return random.randint(1, 9999)
        elif cid == "valid_zero":
            return 0
        elif cid == "valid_large":
            return random.randint(100000, 9999999)
        elif cid == "valid_small":
            return random.randint(1, 20)

    elif dk == "numeric_float":
        if cid == "valid_decimal":
            return round(random.uniform(10.0, 999.0), 2)
        elif cid == "valid_integer_as_float":
            return float(random.randint(10, 500))
        elif cid == "valid_zero":
            return 0.0
        elif cid == "valid_small":
            return round(random.uniform(0.01, 0.99), 2)

    elif dk == "boolean":
        return default_val

    elif dk == "array":
        if cid == "valid_single":
            return [f"item_{random.randint(100, 999)}"]
        elif cid == "valid_multiple":
            return [f"tag_{random.randint(10, 99)}", f"tag_{random.randint(10, 99)}"]
        elif cid == "valid_empty":
            return []

    return default_val


def _iter_dataset_cases(param_cfg: ParamDataset, dataset: dict, original_value: Any = None, dynamic: bool = True):
    """Yield (effective_cat, default_cat, case_id, case_desc, test_val); skips SKIP."""
    dataset_key = param_cfg.dataset_key or ""
    for cat, case_id, case_desc, test_val in _cases_with_captured_seed(dataset, original_value):
        sel = None
        if param_cfg.case_selections:
            sel = param_cfg.case_selections.get(case_id)
        if sel == "SKIP":
            continue
        effective_cat = sel if sel in ("POS", "NEG") else cat
        actual_val = generate_dynamic_case_value(dataset_key, case_id, test_val, cat=effective_cat) if dynamic else test_val
        yield effective_cat, cat, case_id, case_desc, actual_val

class RunTestRequest(BaseModel):
    url: str
    method: str
    headers: dict
    query: dict = {}
    body: Optional[Any] = None
    body_type: Optional[str] = None
    selected_params: list[ParamDataset] = []  # body params; may be empty for query-only runs
    query_selected_params: list[ParamDataset] = []  # GET query params to test
    all_unique_formats: dict = Field(default_factory=dict)  # path → format string — ALL params ke liye
    unique_pools: dict = Field(default_factory=dict)  # path → list of unused valid values (CSV/XLSX)
    dynamic_values: bool = True  # Fresh dynamic POS values per hit to prevent 409/422
    delay_ms: int = 0  # Delay in ms between requests (pacing)


# ─────────────────────────────────────────────────────────────────────────────
#  RANDOM VALUE GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

_FIRST_NAMES = ["Alice","Bob","Carol","Dave","Eva","Frank","Grace","Hank","Iris","Jack"]
_LAST_NAMES  = ["Smith","Jones","Brown","Davis","Wilson","Moore","Taylor","Anderson"]

def generate_random_value(fmt: str) -> str:
    import uuid as _uuid
    def _replace(m):
        token = m.group(1).lower().strip()
        if token == "uuid":
            return str(_uuid.uuid4())
        if token == "email":
            user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            return f"{user}@testapi.com"
        if token == "name":
            return f"{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}"
        parts = token.split(":")
        kind  = parts[0]
        n     = int(parts[1]) if len(parts) > 1 else 8
        if kind == "alpha":
            return ''.join(random.choices(string.ascii_letters, k=n))
        if kind == "alphanum":
            return ''.join(random.choices(string.ascii_letters + string.digits, k=n))
        if kind == "num":
            return ''.join(random.choices(string.digits, k=n))
        return m.group(0)
    return re.sub(r'\{([^}]+)\}', _replace, fmt)


# ─────────────────────────────────────────────────────────────────────────────
#  UNIQUE VALUE POOL (CSV / XLSX — consume on 2xx, reuse on 4xx/5xx)
# ─────────────────────────────────────────────────────────────────────────────

_UNIQ_HINTS = (
    "already exist", "already exists", "already taken", "already used",
    "already_exist", "already_exists", "alreadyexists",
    "duplicate", "not unique", "unique constraint", "must be unique",
    "conflict",
)
_POOL_FILE_MAX_BYTES = 5 * 1024 * 1024


class UniquePoolExhausted(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _pool_header_key(header: str) -> str:
    """Normalize CSV headers / param paths so `field.0.name` matches `field[0].name`."""
    s = re.sub(r"\s+", "", (header or "").strip().lower())
    s = re.sub(r"\[(\d+)\]", r".\1", s)
    return re.sub(r"\.+", ".", s).strip(".")


def _param_match_keys(path: str) -> list:
    p = (path or "").strip()
    if not p:
        return []
    keys = [_pool_header_key(p)]
    rest = p[6:] if p.lower().startswith("query.") else p
    if rest:
        keys.append(_pool_header_key(rest))
    segs = re.split(r"\.(?![^\[]*\])", rest)
    for i in range(len(segs)):
        keys.append(_pool_header_key(".".join(segs[i:])))
    out, seen = [], set()
    for k in keys:
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _bind_pool_headers(headers: list, param_paths: list, target_path: Optional[str] = None) -> dict:
    """header index → [param path]. Exact/suffix first, then unique last-segment."""
    paths = [p for p in (param_paths or []) if p]
    header_keys = [_pool_header_key(h) for h in headers]
    assigned = {}  # col index → [path]
    target = (target_path or "").strip()

    exact_map = {}
    last_map = {}
    for p in paths:
        keys = _param_match_keys(p)
        for k in keys[:-1]:
            exact_map.setdefault(k, []).append(p)
        if keys:
            last_map.setdefault(keys[-1], []).append(p)

    used_paths = set()
    for i, hk in enumerate(header_keys):
        if not hk:
            continue
        hits = [p for p in exact_map.get(hk, []) if p not in used_paths]
        if not hits:
            cand = [p for p in last_map.get(hk, []) if p not in used_paths]
            uniq = list(dict.fromkeys(cand))
            if len(uniq) == 1:
                hits = uniq
            elif target and target in uniq:
                hits = [target]
        if hits:
            pick = hits[0]
            assigned[i] = [pick]
            used_paths.add(pick)
    return assigned


def _xlsx_col_index(ref: str) -> int:
    col = 0
    for ch in (ref or ""):
        if ch.isalpha():
            col = col * 26 + (ord(ch.upper()) - 64)
        else:
            break
    return max(col - 1, 0)


def _parse_xlsx_rows(data: bytes) -> list:
    ns_skip = lambda tag: tag.split("}")[-1] if "}" in tag else tag
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        shared = []
        ss_name = next((n for n in names if n.lower().endswith("sharedstrings.xml")), None)
        if ss_name:
            root = ET.fromstring(zf.read(ss_name))
            for si in root.iter():
                if ns_skip(si.tag) != "si":
                    continue
                texts = [t.text or "" for t in si.iter() if ns_skip(t.tag) == "t"]
                shared.append("".join(texts))
        sheet_name = next(
            (n for n in names if n.lower().startswith("xl/worksheets/sheet") and n.lower().endswith(".xml")),
            None,
        )
        if not sheet_name:
            raise HTTPException(400, "No worksheet found in the XLSX file")
        root = ET.fromstring(zf.read(sheet_name))
        rows = []
        for row_el in root.iter():
            if ns_skip(row_el.tag) != "row":
                continue
            cells = {}
            max_i = -1
            for c in row_el:
                if ns_skip(c.tag) != "c":
                    continue
                ref = c.get("r") or ""
                idx = _xlsx_col_index(ref)
                max_i = max(max_i, idx)
                ctype = (c.get("t") or "").lower()
                v_el = next((x for x in c if ns_skip(x.tag) == "v"), None)
                is_el = next((x for x in c if ns_skip(x.tag) == "is"), None)
                val = ""
                if ctype == "s" and v_el is not None and (v_el.text or "").isdigit():
                    si = int(v_el.text)
                    val = shared[si] if 0 <= si < len(shared) else ""
                elif ctype == "inlineStr" and is_el is not None:
                    val = "".join(t.text or "" for t in is_el.iter() if ns_skip(t.tag) == "t")
                elif v_el is not None and v_el.text is not None:
                    val = v_el.text
                    if re.fullmatch(r"-?\d+\.0+", val):
                        val = val.split(".")[0]
                cells[idx] = val
            if max_i < 0:
                rows.append([])
            else:
                rows.append([cells.get(i, "") for i in range(max_i + 1)])
        return rows


def _parse_csv_rows(text: str) -> list:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
    except Exception:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    return [[(c if c is not None else "") for c in row] for row in reader]


def _json_error_fields(data) -> list:
    fields = []
    if not isinstance(data, dict):
        return fields

    def add(v):
        if v is None:
            return
        if isinstance(v, list):
            for x in v:
                add(x)
        else:
            s = str(v).strip()
            if s:
                fields.append(s)

    for key in ("errors", "details", "violations", "error"):
        item = data.get(key)
        if isinstance(item, list):
            for it in item:
                if isinstance(it, dict):
                    for fk in ("field", "param", "name", "path", "property", "loc", "key"):
                        add(it.get(fk))
                elif isinstance(it, str):
                    add(it)
        elif isinstance(item, dict):
            for k, v in item.items():
                add(k)
                if isinstance(v, dict):
                    for fk in ("field", "param", "name", "path"):
                        add(v.get(fk))
    return fields


def _pool_uniqueness_attributed(resp_text: str, applied: dict) -> bool:
    """True when 409/422 is about THIS imported param's value (not some other field)."""
    if not applied:
        return False
    raw = resp_text or ""
    text = _uniq_match_text(raw)
    has_hint = any(h in text for h in _UNIQ_HINTS)
    data = None
    try:
        data = json.loads(raw) if raw.strip()[:1] in "{[" else None
    except Exception:
        data = None
    err_fields = [f.lower() for f in _json_error_fields(data)] if data else []

    this_names = set()
    this_vals = set()
    for path, val in applied.items():
        for k in _param_match_keys(str(path)):
            this_names.add(k)
        if val is not None and str(val).strip():
            this_vals.add(str(val).strip().lower())

    other_field_hit = False
    this_field_hit = False
    for f in err_fields:
        fk = _pool_header_key(f)
        if fk in this_names or any(n and n in f for n in this_names if len(n) >= 2):
            this_field_hit = True
        elif fk:
            other_field_hit = True

    if this_field_hit and (has_hint or other_field_hit is False):
        return True
    if other_field_hit and not this_field_hit:
        return False
    if this_vals and has_hint and any(v in text for v in this_vals if len(v) >= 2):
        return True
    if this_names and has_hint and any(n in text for n in this_names if len(n) >= 2):
        return True
    return False


class UniqueValuePool:
    def __init__(self, pools: Optional[dict] = None):
        self.pools: dict = {}
        if isinstance(pools, str):
            try:
                pools = json.loads(pools)
            except Exception:
                pools = {}
        if not isinstance(pools, dict):
            pools = {}
        for path, vals in pools.items():
            if not path:
                continue
            if isinstance(vals, str):
                vals = [vals]
            elif not isinstance(vals, (list, tuple)):
                vals = [] if vals is None else [vals]
            cleaned = [str(v).strip() for v in vals if v is not None and str(v).strip()]
            if cleaned:
                self.pools[str(path)] = cleaned
        self.index = 0
        self._ambig_hits = 0

    @property
    def active(self) -> bool:
        return bool(self.pools)

    def width(self) -> int:
        if not self.pools:
            return 0
        return min(len(v) for v in self.pools.values())

    def current(self) -> dict:
        if not self.active:
            return {}
        w = self.width()
        if w == 0:
            return {}
        # Cycle through rows so if test cases exceed pool rows, tests continue smoothly
        idx = self.index % w
        return {p: vals[idx] for p, vals in self.pools.items()}

    def apply_to(self, req_body, query: dict) -> dict:
        applied = self.current()
        q = query if isinstance(query, dict) else {}
        for path, val in applied.items():
            sp = str(path)
            if sp.startswith("query."):
                key = sp[6:]
                if key:
                    q[key] = val
            elif req_body is not None:
                set_nested_value(req_body, sp, val)
        return applied

    def note_response(self, status, resp_text: str, applied: dict):
        if not self.active or not applied:
            return
        is_success = 200 <= status < 300
        is_dup = status == 409 or _pool_uniqueness_attributed(resp_text, applied)
        if is_success or is_dup:
            self._advance()

    def _advance(self):
        self.index += 1
        self._ambig_hits = 0


def _unique_skip_keys(skip_path: Optional[str]) -> set:
    skip = set()
    if not skip_path:
        return skip
    sp = str(skip_path)
    skip.add(sp)
    if sp.startswith("query."):
        skip.add(sp[6:])
    else:
        skip.add("query." + sp)
    return skip


def _unique_path_skipped(path: Optional[str], skip_path: Optional[str]) -> bool:
    if not path or not skip_path:
        return False
    return str(path) in _unique_skip_keys(skip_path)


def _pool_has_path(pool, path: str) -> bool:
    if not pool or not getattr(pool, "pools", None) or not path:
        return False
    return any(k in pool.pools for k in _unique_skip_keys(path))


def _merge_run_unique_formats(req, pool) -> dict:
    """Sidecar unique formats for this run.

    Checked params keep their format in this map. Per hit, skip_path is the
    current fuzz target so that param gets dataset/custom cases; every other
    param with Unique Format still receives a fresh generated value.
    CSV/XLSX pool paths win over {uuid}-style formats.
    """
    out = {}

    def add(path, fmt):
        if not path or fmt is None:
            return
        p = str(path).strip()
        f = str(fmt).strip()
        if not p or not f or _pool_has_path(pool, p):
            return
        out[p] = f

    for k, v in (getattr(req, "all_unique_formats", None) or {}).items():
        add(k, v)
    for cfg in getattr(req, "selected_params", None) or []:
        add(getattr(cfg, "path", None), getattr(cfg, "unique_format", None))
    for cfg in getattr(req, "query_selected_params", None) or []:
        qpath = str(getattr(cfg, "path", None) or "").strip()
        fmt = getattr(cfg, "unique_format", None)
        if not qpath:
            continue
        add(qpath if qpath.startswith("query.") else "query." + qpath, fmt)
    return out


def _collect_unique_applied(formats, pool_applied, skip_path, req_body, test_query) -> list:
    """Values injected this hit from CSV/XLSX list or {uuid}-style unique formats."""
    skip = _unique_skip_keys(skip_path)
    out = []
    seen = set()

    def add(path, val, source):
        if val is None or val == "":
            return
        s = str(val).strip()
        if len(s) < 2 or s.lower() in ("true", "false", "null", "{}", "[]"):
            return
        if s in seen:
            return
        seen.add(s)
        out.append({"path": str(path), "value": val, "source": source})

    for path, val in (pool_applied or {}).items():
        if str(path) in skip:
            continue
        add(path, val, "list")

    for path, fmt in (formats or {}).items():
        if not fmt or str(path) in skip:
            continue
        if str(path).startswith("query."):
            val = (test_query or {}).get(str(path)[6:])
        else:
            val = get_nested_value(req_body, path) if req_body is not None else None
        add(path, val, "format")
    return out


def _flatten_response_text(resp_text: str) -> str:
    """Body text plus nested / stringified JSON so uniqueness hints are not missed."""
    parts = [resp_text or ""]

    def walk(obj, depth=0):
        if depth > 5:
            return
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v, depth + 1)
        elif isinstance(obj, list):
            for v in obj[:40]:
                walk(v, depth + 1)
        elif isinstance(obj, str):
            parts.append(obj)
            s = obj.strip()
            if s[:1] in "{[":
                try:
                    walk(json.loads(s), depth + 1)
                except Exception:
                    pass

    raw = (resp_text or "").strip()
    if raw[:1] in "{[":
        try:
            walk(json.loads(raw), 0)
        except Exception:
            pass
    return "\n".join(parts).lower()


def _uniq_match_text(resp_text: str) -> str:
    """Haystack so ALREADY_EXISTS / already-exists still match 'already exist'."""
    flat = _flatten_response_text(resp_text)
    spaced = re.sub(r"[^a-z0-9]+", " ", flat)
    compact = re.sub(r"[^a-z0-9]+", "", flat)
    return f"{flat}\n{spaced}\n{compact}"


def _response_has_uniqueness_hint(resp_text: str) -> bool:
    text = _uniq_match_text(resp_text)
    return any(h in text for h in _UNIQ_HINTS)


def _already_exists_misconfig(status, resp_text: str, unique_applied=None) -> Optional[dict]:
    """Tag 409/422 only when the response body actually says already-exists/duplicate."""
    code = _parse_status_code(status)
    if code not in (409, 422):
        return None
    raw = resp_text or ""
    if not _response_has_uniqueness_hint(raw):
        return None
    applied = {}
    sources = set()
    for item in (unique_applied or []):
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if path:
            applied[str(path)] = item.get("value")
        if item.get("source"):
            sources.add(str(item["source"]))
    attributed = _pool_uniqueness_attributed(raw, applied) if applied else False
    if "list" in sources and attributed:
        detail = "unique list value is already in the database"
    elif "format" in sources and attributed:
        detail = "unique format value collided with an existing record"
    else:
        detail = "response indicates this value already exists"
    return {
        "tag": "case misconfig",
        "reason": f"Already exists ({code}) — {detail}",
        "code": code,
    }


def _misconfig_fields(status, resp_text: str, unique_applied=None) -> dict:
    info = _already_exists_misconfig(status, resp_text, unique_applied)
    if not info:
        return {"case_misconfig": False, "misconfig_tag": "", "misconfig_reason": ""}
    return {
        "case_misconfig": True,
        "misconfig_tag": info["tag"],
        "misconfig_reason": info["reason"],
    }



def _get_api_differentiator_label(item: dict) -> str:
    if not item:
        return ""
    b = item.get("body") if item.get("body") is not None else item.get("payload")
    if b is None and item.get("request_body") is not None:
        b = item.get("request_body")
    obj = b
    if isinstance(obj, str):
        trimmed = obj.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                obj = json.loads(trimmed)
            except Exception:
                pass
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        obj = obj[0]
    if isinstance(obj, dict):
        em = obj.get("entityMap")
        if isinstance(em, dict):
            for k in ["identifier2", "entityType", "identifier1", "identifier3"]:
                if em.get(k) and not isinstance(em[k], (dict, list)):
                    return str(em[k]).strip()
        for k in ["entityType", "entity_type", "action", "operationName", "operation"]:
            if obj.get(k) and not isinstance(obj[k], (dict, list)):
                return str(obj[k]).strip()
        for k in ["formName", "form_name"]:
            if obj.get(k) and not isinstance(obj[k], (dict, list)):
                fn = str(obj[k]).strip()
                return f"form: {fn[:8]}…" if len(fn) > 12 else f"form: {fn}"
    return ""


# ─────────────────────────────────────────────────────────────────────────────
#  HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(results: list, summary: dict, tested_url: str = "", method: str = "", headers: Optional[dict] = None, is_bulk: bool = False) -> str:
    def esc(s):
        return (str(s)
                .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace('"',"&quot;").replace("'","&#39;"))

    def highlight_val(escaped_text, test_value, unique_applied=None):
        def needles_for(val):
            if val is None or val == "":
                return []
            cands = [str(val)]
            if isinstance(val, str):
                inner = json.dumps(val, ensure_ascii=False)[1:-1]
                inner_ascii = json.dumps(val)[1:-1]
                for item in (inner, inner_ascii):
                    if item and item not in cands:
                        cands.append(item)
            return [esc(c) for c in cands if c]

        def wrap(out, val, cls):
            for needle in sorted(needles_for(val), key=len, reverse=True):
                if needle and needle in out:
                    out = out.replace(needle, f'<mark class="{cls}">{needle}</mark>')
                    break
            return out

        out = escaped_text
        test_s = None if test_value is None or test_value == "" else str(test_value)
        for item in (unique_applied or []):
            uval = item.get("value") if isinstance(item, dict) else item
            if uval is None or (test_s is not None and str(uval) == test_s):
                continue
            src = (item.get("source") if isinstance(item, dict) else "") or "list"
            cls = "uniq-fmt-mark" if src == "format" else "uniq-list-mark"
            out = wrap(out, uval, cls)
        if test_s is not None:
            out = wrap(out, test_s, "val-mark")
        return out
    unique_apis = []
    seen_api_keys = set()
    for r in results:
        if not is_bulk and tested_url:
            row_url = str(r.get("api_url") or tested_url or r.get("endpoint") or r.get("tested_url") or "").strip()
        else:
            row_url = str(r.get("api_url") or r.get("endpoint") or tested_url or r.get("tested_url") or "").strip()
        row_method = (r.get("api_method") or r.get("method") or method or "GET").upper()

        api_sig = str(r.get("api_signature") or "").strip()
        api_id = str(r.get("api_id") or "").strip()
        api_label = str(r.get("api_label") or "").strip()
        if not api_label and r.get("request_body"):
            api_label = _get_api_differentiator_label(r)

        key = str(r.get("api_key") or "").strip()
        if not key:
            if not is_bulk and (tested_url or row_url):
                key = f"{row_method} {tested_url or row_url}"
            elif api_sig and api_id:
                key = f"{api_sig}::{api_id}"
            elif api_sig:
                key = api_sig
            elif api_id:
                key = f"{row_method} {row_url}::{api_id}"
            elif api_label:
                key = f"{row_method} {row_url} [{api_label}]"
            else:
                key = f"{row_method} {row_url}"
        r["api_key"] = key

        if row_url and key not in seen_api_keys:
            seen_api_keys.add(key)
            short_path = row_url
            try:
                from urllib.parse import urlparse
                pu = urlparse(row_url)
                short_path = (pu.path or row_url) + (("?" + pu.query) if pu.query else "")
            except Exception:
                pass
            
            api_results = [
                x for x in results
                if (x.get("api_key") or f"{(x.get('api_method') or x.get('method') or method or 'GET').upper()} {str(x.get('api_url') or (tested_url if not is_bulk else '') or x.get('endpoint') or x.get('tested_url') or tested_url).strip()}") == key
            ]
            count = len(api_results)
            passed = sum(1 for x in api_results if x.get("result") == "PASS")
            failed = sum(1 for x in api_results if x.get("result") == "FAIL")
            warned = sum(1 for x in api_results if x.get("result") == "WARN")
            pass_rate = int((passed / count) * 100) if count else 0
            total_lat = sum(int(x.get("elapsed_ms") or 0) for x in api_results)
            avg_latency = int(total_lat / count) if count else 0

            unique_apis.append({
                "key": key,
                "method": row_method,
                "url": row_url,
                "short_path": short_path,
                "label": api_label,
                "count": count,
                "passed": passed,
                "failed": failed,
                "warned": warned,
                "pass_rate": pass_rate,
                "avg_latency": avg_latency,
            })
    is_multi_api = len(unique_apis) > 1 or method.upper() == "BULK" or is_bulk

    api_dropdown_html = ""
    apis_listing_html = ""
    if is_multi_api and unique_apis:
        options = [f'<option value="ALL">All APIs ({len(unique_apis)} APIs · {len(results)} cases)</option>']
        for idx, a in enumerate(unique_apis, 1):
            disc_text = f" [{a['label']}]" if a['label'] else (f" (API {idx})" if sum(1 for x in unique_apis if x['short_path'] == a['short_path']) > 1 else "")
            options.append(f'<option value="{esc(a["key"])}">[{esc(a["method"])}] {esc(a["short_path"])}{esc(disc_text)} ({a["count"]} cases)</option>')
        api_dropdown_html = f"""
<div id='report-api-filter-wrap' style='display:flex;align-items:center;gap:8px'>
  <label for='report-api-select' style='font-size:11px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px'>API:</label>
  <select id='report-api-select' onchange='onReportApiChange(this.value)' style='background:#161b22;border:1px solid #30363d;color:#e6edf3;font-size:12px;padding:5px 10px;border-radius:6px;max-width:380px;outline:none;cursor:pointer'>
    {''.join(options)}
  </select>
</div>
"""
        api_rows = []
        for idx, a in enumerate(unique_apis, 1):
            m_cls = a['method'] if a['method'] in ["GET","POST","PUT","PATCH","DELETE"] else "OTHER"
            rate_color = "#3fb950" if a['pass_rate'] >= 80 else ("#d29922" if a['pass_rate'] >= 50 else "#f85149")
            lbl_tag = f"<span style='display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600;background:rgba(56,139,253,0.2);color:#58a6ff;border:1px solid rgba(56,139,253,0.35);margin-left:6px'>{esc(a['label'])}</span>" if a['label'] else ""
            api_rows.append(f"""
<tr style='border-bottom:1px solid #21262d'>
  <td style='color:#6e7681;font-size:11px'>{idx}</td>
  <td><span class='m-badge m-{m_cls}'>{esc(a['method'])}</span></td>
  <td>
    <div style='display:flex;align-items:center;flex-wrap:wrap;gap:4px'>
      <span style='font-weight:600;color:#e6edf3;font-family:monospace;font-size:11px;word-break:break-all'>{esc(a['url'])}</span>
      {lbl_tag}
    </div>
  </td>
  <td style='text-align:center;font-weight:700;font-family:monospace;color:#58a6ff'>{a['count']}</td>
  <td style='text-align:center;font-weight:700;color:#3fb950'>{a['passed']}</td>
  <td style='text-align:center;font-weight:700;color:#f85149'>{a['failed']}</td>
  <td style='text-align:center;font-weight:700;color:#d29922'>{a['warned']}</td>
  <td style='text-align:center;font-weight:700;color:{rate_color}'>{a['pass_rate']}%</td>
  <td style='text-align:center;color:#8b949e;font-family:monospace;font-size:11px'>{a['avg_latency']}ms</td>
  <td style='text-align:center'>
    <button type='button' class='det-btn' style='color:#58a6ff;border-color:rgba(56,139,253,0.4);background:rgba(31,111,235,0.12)' onclick='viewCases("{esc(a["key"])}")'>🔍 View Cases</button>
  </td>
</tr>
""")
        apis_listing_html = f"""
<div id='apis-listing-table-wrap' style='display:none;overflow-x:auto;border:1px solid #21262d;border-radius:6px;margin-top:10px'>
  <table>
    <thead>
      <tr>
        <th style='width:40px'>#</th>
        <th style='width:70px'>METHOD</th>
        <th>TESTED API ENDPOINT</th>
        <th style='text-align:center;width:80px'>TOTAL</th>
        <th style='text-align:center;width:70px'>PASSED</th>
        <th style='text-align:center;width:70px'>FAILED</th>
        <th style='text-align:center;width:70px'>WARNINGS</th>
        <th style='text-align:center;width:100px'>PASS RATE</th>
        <th style='text-align:center;width:90px'>AVG TIME</th>
        <th style='text-align:center;width:110px'>ACTION</th>
      </tr>
    </thead>
    <tbody>
      {''.join(api_rows)}
    </tbody>
  </table>
</div>
"""
    tested_apis_tab_html = f"<button class='filter-pill' data-f='APIS' onclick='filterRows(\"APIS\")'>🌐 Tested APIs ({len(unique_apis)})</button>" if is_multi_api else ""

    rows = ""
    for i, r in enumerate(results, 1):
        result = r["result"]
        cat = r["case_cat"]
        color = {"PASS":"#3fb950","FAIL":"#f85149","WARN":"#d29922","ERROR":"#6e7681"}.get(result,"#888")
        cat_color = "#1f6feb" if cat == "POS" else "#da3633"
        val = r.get("test_value","")
        val_str = "null" if val is None else esc(str(val)[:60])
        sc = str(r['status_code'])
        sc_color = "#3fb950" if sc.startswith("2") else ("#d29922" if sc.startswith("4") else ("#f85149" if sc.startswith("5") else "#6e7681"))
        detail_id = f"dr{i}"
        ua = r.get("unique_applied") or []
        raw_req = r.get('request_body')
        if raw_req is None or raw_req == '':
            req_body_str = '(no body)'
        elif isinstance(raw_req, (dict, list)):
            try:
                req_body_str = json.dumps(raw_req, indent=2)
            except Exception:
                req_body_str = str(raw_req)
        else:
            try:
                parsed = json.loads(str(raw_req))
                if isinstance(parsed, (dict, list)):
                    req_body_str = json.dumps(parsed, indent=2)
                else:
                    req_body_str = str(raw_req)
            except Exception:
                req_body_str = str(raw_req)

        raw_resp = r.get('response')
        if raw_resp is None or raw_resp == '':
            resp_str = '(no response)'
        elif isinstance(raw_resp, (dict, list)):
            try:
                resp_str = json.dumps(raw_resp, indent=2)
            except Exception:
                resp_str = str(raw_resp)
        else:
            try:
                parsed = json.loads(str(raw_resp))
                if isinstance(parsed, (dict, list)):
                    resp_str = json.dumps(parsed, indent=2)
                else:
                    resp_str = str(raw_resp)
            except Exception:
                resp_str = str(raw_resp)

        req_body_esc = highlight_val(
            esc(req_body_str), r.get('test_value'), ua,
        )
        resp_esc = highlight_val(
            esc(resp_str), r.get('test_value'), ua,
        )
        row_url = r.get("tested_url") or r.get("api_url") or r.get("endpoint") or tested_url
        row_method = (r.get("api_method") or r.get("method") or method or "GET").upper()
        row_key = r.get("api_key") or f"{row_method} {row_url}"

        row_curl = r.get("curl") or _build_curl_command(
            row_method, row_url, headers, r.get("request_body")
        )
        curl_esc = esc(row_curl)
        is_mis = bool(r.get("case_misconfig"))
        mis_reason = r.get("misconfig_reason") or "Already exists (409/422)"
        mis_tag = (
            f'<span class="misconfig-tag" title="{esc(mis_reason)}">case misconfig</span>'
            if is_mis else ""
        )
        row_cls = "main-row misconfig-row" if is_mis else "main-row"
        rows += f"""
<tr class="{row_cls}" data-result="{result}" data-cat="{cat}" data-misconfig="{'1' if is_mis else '0'}" data-api-key="{esc(row_key)}" onclick="toggleDetail('{detail_id}',this)">
  <td style="color:#6e7681">{i}</td>
  <td style="color:#e6edf3;font-weight:600;font-family:monospace;font-size:11px">{esc(r['param'])}</td>
  <td style="color:#8b949e;font-size:11px">{esc(r['dataset'])}</td>
  <td><span style="color:{cat_color};font-weight:700;font-size:11px">{cat}</span></td>
  <td style="color:#8b949e;font-size:11px;font-family:monospace">{esc(r['case_id'])}</td>
  <td style="color:#8b949e">{esc(r['case_desc'])}</td>
  <td style="font-family:monospace;font-size:11px;color:#79c0ff">{val_str}</td>
  <td style="font-weight:700;color:{sc_color};font-family:monospace">{esc(r['status_code'])}</td>
  <td><span style="color:{color};font-weight:700">{result}</span> {mis_tag}</td>
  <td style="color:#6e7681;font-size:11px">{r['elapsed_ms']}ms</td>
  <td><button class="det-btn" id="btn-{detail_id}" onclick="event.stopPropagation();toggleDetail('{detail_id}',document.getElementById('btn-{detail_id}').closest('tr'))">▼ Detail</button></td>
</tr>
<tr id="{detail_id}" class="detail-row" style="display:none">
  <td colspan="11" style="padding:0;background:#080c10;border-bottom:2px solid #30363d">
    <textarea id="curl-{detail_id}" style="position:absolute;left:-9999px;height:0">{curl_esc}</textarea>
    <div style="padding:8px 12px 0;font-family:monospace;font-size:11px;color:#79c0ff">🌐 <b>Endpoint:</b> {esc(row_method)} {esc(row_url)}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:10px">
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden">
        <div class="panel-hdr">📤 Request Body Sent <button class="curl-btn" onclick="event.stopPropagation();copyCurl('curl-{detail_id}',this)">📋 Copy cURL</button></div>
        <pre style="padding:10px;font-family:monospace;font-size:11px;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin:0">{req_body_esc}</pre>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden">
        <div class="panel-hdr">📥 Response Body <button class="curl-btn" onclick="event.stopPropagation();copyCurl('curl-{detail_id}',this)">📋 Copy cURL</button></div>
        <pre style="padding:10px;font-family:monospace;font-size:11px;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin:0">{resp_esc}</pre>
      </div>
    </div>
  </td>
</tr>"""

    t = summary or {}
    total_val = t.get('total', 0)
    passed_val = t.get('passed', 0)
    failed_val = t.get('failed', 0)
    warned_val = t.get('warned', 0)
    pos_pass_val = t.get('pos_pass', 0)
    pos_fail_val = t.get('pos_fail', 0)
    neg_pass_val = t.get('neg_pass', 0)
    neg_fail_val = t.get('neg_fail', 0)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    health_pct = int((passed_val / total_val) * 100) if total_val else 0
    url_block = ""
    if tested_url:
        method_bit = f"{esc(str(method).upper())} " if method else ""
        url_block = (
            f"<p class='tested-url'><b>Tested URL:</b> "
            f"<code>{method_bit}{esc(tested_url)}</code></p>"
        )

    return f"""<!DOCTYPE html><html><head>
<meta charset='utf-8'><title>API Validation Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Space+Grotesk:wght@400;600;700&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Space Grotesk',sans-serif;background:#080c10;color:#c9d1d9;padding:24px}}
  .wrap{{max-width:1600px;margin:0 auto}}
  h1{{font-size:22px;font-weight:700;margin-bottom:4px;
      background:linear-gradient(135deg,#1f6feb,#58a6ff,#79c0ff);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  .sub{{color:#6e7681;font-size:12px;font-family:'IBM Plex Mono',monospace;margin-bottom:10px}}
  .tested-url{{margin:0 0 16px;font-size:13px;color:#8b949e;word-break:break-all}}
  .tested-url b{{color:#c9d1d9;margin-right:6px}}
  .tested-url code{{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#58a6ff}}
  .panel-hdr{{padding:6px 10px;background:#161b22;font-size:11px;font-weight:700;color:#58a6ff;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px}}
  .curl-btn{{margin-left:0;background:rgba(31,111,235,.12);border:1px solid rgba(31,111,235,.3);color:#58a6ff;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:10px;font-weight:600;font-family:inherit;white-space:nowrap}}
  .curl-btn:hover{{border-color:#58a6ff;background:rgba(31,111,235,.22)}}
  mark.val-mark{{background:rgba(210,153,34,.32);color:#e3b341;border-radius:2px;padding:0 2px;font-weight:700}}
  mark.uniq-list-mark{{background:rgba(163,113,247,.30);color:#d2a8ff;border-radius:2px;padding:0 2px;font-weight:700}}
  mark.uniq-fmt-mark{{background:rgba(57,197,178,.28);color:#7eeadb;border-radius:2px;padding:0 2px;font-weight:700}}
  .cards{{display:flex;gap:12px;margin-bottom:22px;flex-wrap:wrap}}
  .card{{background:#0d1117;border:1px solid #21262d;border-radius:10px;
         padding:14px 20px;text-align:center;min-width:100px;position:relative;overflow:hidden}}
  .card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
  .card.tot::before{{background:#58a6ff}}.card.ps::before{{background:#238636}}
  .card.fl::before{{background:#da3633}}.card.wn::before{{background:#d29922}}
  .card h3{{font-size:26px;font-weight:700;margin-bottom:2px}}
  .card p{{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:1px}}
  .card.tot h3{{color:#58a6ff}}.card.ps h3{{color:#3fb950}}.card.fl h3{{color:#f85149}}.card.wn h3{{color:#d29922}}
  .health{{margin-bottom:20px;font-size:13px}}
  .health span{{color:#58a6ff;font-weight:700}}
  hr{{border:none;border-top:1px solid #21262d;margin:18px 0}}
  table{{border-collapse:collapse;width:100%;background:#0d1117;font-size:12px}}
  .main-row{{cursor:pointer}}
  .main-row:hover td{{background:#161b22!important}}
  th{{padding:8px 10px;background:#161b22;color:#6e7681;font-size:10px;text-align:left;white-space:nowrap;border-bottom:2px solid #30363d}}
  td{{padding:7px 10px;border-bottom:1px solid #161b22;vertical-align:middle}}
  .det-btn{{background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:4px;
            padding:3px 8px;cursor:pointer;font-size:10px;font-family:monospace;white-space:nowrap;transition:all .15s}}
  .det-btn:hover{{border-color:#58a6ff;color:#58a6ff}}
  .det-btn.open{{border-color:#d29922;color:#d29922}}
  .detail-row{{display:none}}
  .misconfig-row td{{background:rgba(210,153,34,.08)!important}}
  .misconfig-row td:first-child{{box-shadow:inset 3px 0 0 #d29922}}
  .misconfig-tag{{display:inline-block;margin-left:6px;font-size:9px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;color:#e3b341;background:rgba(210,153,34,.15);border:1px solid rgba(210,153,34,.45);border-radius:3px;padding:1px 6px;vertical-align:middle;white-space:nowrap}}
  .legend{{font-size:11px;color:#6e7681;margin-bottom:14px}}
  .legend b{{margin-right:8px}}
  .filters{{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}}
  .filter-pill{{background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:12px;
                padding:4px 12px;cursor:pointer;font-size:11px;font-family:inherit;transition:all .15s}}
  .filter-pill:hover{{border-color:#58a6ff;color:#58a6ff}}
  .filter-pill.active{{background:#1f6feb;border-color:#58a6ff;color:white}}
  .api-tabs-container{{margin-bottom:16px;background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 14px}}
  .api-tabs-header{{font-size:11px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px}}
  .api-tabs-list{{display:flex;gap:8px;flex-wrap:wrap}}
  .api-filter-pill{{background:#161b22;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:11px;font-family:inherit;display:inline-flex;align-items:center;gap:6px;transition:all .15s}}
  .api-filter-pill:hover{{border-color:#58a6ff;color:#58a6ff}}
  .api-filter-pill.active{{background:#1f6feb;border-color:#58a6ff;color:#ffffff;font-weight:600}}
  .badge-cnt{{background:rgba(255,255,255,0.15);border-radius:10px;padding:1px 6px;font-size:10px;font-weight:700}}
  .m-badge{{font-size:9px;font-weight:700;padding:1px 4px;border-radius:3px}}
  .m-GET{{background:rgba(56,139,253,.2);color:#58a6ff}}
  .m-POST{{background:rgba(63,185,80,.2);color:#3fb950}}
  .m-PUT{{background:rgba(210,153,34,.2);color:#d29922}}
  .m-PATCH{{background:rgba(163,113,247,.2);color:#d2a8ff}}
  .m-DELETE{{background:rgba(248,81,73,.2);color:#f85149}}
  .m-OTHER{{background:rgba(110,118,129,.2);color:#8b949e}}
</style>
<script>
var currentStatusFilter = 'ALL';
var currentApiFilter = 'ALL';

function toggleDetail(id, row) {{
  var dr = document.getElementById(id);
  var btn = document.getElementById('btn-' + id);
  var open = dr.style.display !== 'none';
  dr.style.display = open ? 'none' : 'table-row';
  if (btn) {{ btn.textContent = open ? '▼ Detail' : '▲ Close'; btn.classList.toggle('open', !open); }}
}}

function applyAllFilters() {{
  var total = 0, passed = 0, failed = 0, warned = 0;
  var posPass = 0, posFail = 0, negPass = 0, negFail = 0;
  
  document.querySelectorAll('.main-row').forEach(function(tr) {{
    var result = tr.dataset.result;
    var cat = tr.dataset.cat;
    var apiKey = tr.dataset.apiKey;
    
    var matchStatus = currentStatusFilter === 'ALL' || result === currentStatusFilter || cat === currentStatusFilter;
    var matchApi = currentApiFilter === 'ALL' || apiKey === currentApiFilter;
    
    var show = matchStatus && matchApi;
    tr.style.display = show ? '' : 'none';
    
    var detId = tr.querySelector('.det-btn');
    if (!show && detId) {{
      var dr = document.getElementById(detId.id.replace('btn-',''));
      if (dr) dr.style.display = 'none';
      detId.textContent = '▼ Detail';
      detId.classList.remove('open');
    }}
    
    if (matchApi) {{
      total++;
      if (result === 'PASS') passed++;
      else if (result === 'FAIL') failed++;
      else if (result === 'WARN') warned++;
      
      if (cat === 'POS') {{
        if (result === 'PASS') posPass++; else posFail++;
      }} else if (cat === 'NEG') {{
        if (result === 'PASS') negPass++; else negFail++;
      }}
    }}
  }});

  var elTot = document.querySelector('.card.tot h3');
  var elPs = document.querySelector('.card.ps h3');
  var elFl = document.querySelector('.card.fl h3');
  var elWn = document.querySelector('.card.wn h3');
  var elHealth = document.querySelector('.health');
  if (elTot) elTot.textContent = total;
  if (elPs) elPs.textContent = passed;
  if (elFl) elFl.textContent = failed;
  if (elWn) elWn.textContent = warned;
  if (elHealth) {{
    var pct = total > 0 ? Math.round((passed / total) * 100) : 0;
    elHealth.innerHTML = 'Pass Rate: <span>' + pct + '%</span> &nbsp;|&nbsp; POS: ' + posPass + ' passed / ' + posFail + ' failed &nbsp;|&nbsp; NEG: ' + negPass + ' passed / ' + negFail + ' failed';
  }}
}}

function onReportApiChange(val) {{
  currentApiFilter = val;
  if (currentStatusFilter === 'APIS') {{
    filterRows('ALL');
  }} else {{
    applyAllFilters();
  }}
}}

function viewCases(apiKey) {{
  var sel = document.getElementById('report-api-select');
  if (sel) sel.value = apiKey;
  currentApiFilter = apiKey;
  filterRows('ALL');
}}

function filterRows(f) {{
  currentStatusFilter = f;
  document.querySelectorAll('.filter-pill').forEach(function(b) {{ b.classList.toggle('active', b.dataset.f === f); }});

  var casesWrap = document.getElementById('cases-table-wrap');
  var apisWrap = document.getElementById('apis-listing-table-wrap');
  var legendEl = document.querySelector('.legend');

  if (f === 'APIS') {{
    if (casesWrap) casesWrap.style.display = 'none';
    if (apisWrap) apisWrap.style.display = 'block';
    if (legendEl) legendEl.style.display = 'none';
  }} else {{
    if (casesWrap) casesWrap.style.display = 'block';
    if (apisWrap) apisWrap.style.display = 'none';
    if (legendEl) legendEl.style.display = 'block';
    applyAllFilters();
  }}
}}

function copyCurl(id, btn) {{
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.value;
  var orig = btn ? btn.textContent : '';
  var done = function() {{
    if (btn) {{ btn.textContent = '✓ Copied!'; setTimeout(function() {{ btn.textContent = orig; }}, 1400); }}
  }};
  var fallback = function() {{
    el.style.position = 'fixed'; el.style.left = '0'; el.style.height = '1px';
    el.select(); document.execCommand('copy');
    el.style.position = 'absolute'; el.style.left = '-9999px'; el.style.height = '0';
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallback(); done(); }});
  }} else {{
    fallback(); done();
  }}
}}
</script>
</head><body><div class='wrap'>
<h1>✅ API Validation Test Report</h1>
<p class='sub'>Generated: {now_str} &nbsp;|&nbsp; API Validator Pro</p>
{url_block}
<div class='cards'>
  <div class='card tot'><h3>{total_val}</h3><p>Total</p></div>
  <div class='card ps'><h3>{passed_val}</h3><p>Passed</p></div>
  <div class='card fl'><h3>{failed_val}</h3><p>Failed</p></div>
  <div class='card wn'><h3>{warned_val}</h3><p>Warnings</p></div>
</div>
<div class='health'>Pass Rate: <span>{health_pct}%</span> &nbsp;|&nbsp;
  POS: {pos_pass_val} passed / {pos_fail_val} failed &nbsp;|&nbsp;
  NEG: {neg_pass_val} passed / {neg_fail_val} failed
</div>
<hr>
<div style='display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px'>
  <div class='filters' style='margin-bottom:0'>
    <button class='filter-pill active' data-f='ALL' onclick='filterRows("ALL")'>All</button>
    <button class='filter-pill' data-f='PASS' onclick='filterRows("PASS")'>✓ PASS</button>
    <button class='filter-pill' data-f='FAIL' onclick='filterRows("FAIL")'>✗ FAIL</button>
    <button class='filter-pill' data-f='WARN' onclick='filterRows("WARN")'>⚠ WARN</button>
    <button class='filter-pill' data-f='POS' onclick='filterRows("POS")'>POS</button>
    <button class='filter-pill' data-f='NEG' onclick='filterRows("NEG")'>NEG</button>
    {tested_apis_tab_html}
  </div>
  {api_dropdown_html}
</div>
<p class='legend'>
  <b style='color:#3fb950'>PASS</b> = Expected response &nbsp;
  <b style='color:#f85149'>FAIL</b> = Unexpected response &nbsp;
  <b style='color:#d29922'>WARN</b> = 5xx on negative case &nbsp;
  <b style='color:#1f6feb'>POS</b> = Should succeed &nbsp;
  <b style='color:#da3633'>NEG</b> = Should fail
  &nbsp;|&nbsp; <small style='color:#6e7681'>Click any row or ▼ Detail to expand</small>
</p>
<div id='cases-table-wrap' style='overflow-x:auto;border:1px solid #21262d;border-radius:6px;margin-top:10px'>
<table>
  <tr><th>#</th><th>PARAM</th><th>DATASET</th><th>TYPE</th>
      <th>CASE ID</th><th>DESCRIPTION</th><th>VALUE SENT</th>
      <th>STATUS</th><th>RESULT</th><th>TIME</th><th></th></tr>
  {rows}
</table>
</div>
{apis_listing_html}
</div></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "API Validator Backend is running", "version": "1.0.0"}

@app.get("/datasets")
def get_datasets():
    return {
        k: {
            "label":     v["label"],
            "hint":      v["hint"],
            "pos_count": sum(1 for c in v["cases"] if c[0] == "POS"),
            "neg_count": sum(1 for c in v["cases"] if c[0] == "NEG"),
            # Full case list so frontend can show checklist modal
            "cases": [
                {"cat": c[0], "id": c[1], "desc": c[2], "val": str(c[3])[:80]}
                for c in v["cases"]
            ],
        }
        for k, v in DATASETS.items()
    }

@app.post("/analyze")
def analyze_api(req: AnalyzeRequest):
    """Parse API and return detected parameters with types"""
    body, _bt = _normalize_json_body(req.body, req.body_type)
    # Always return proper query_params format (not just keys)
    proper_qp = [
        {"path": k, "value": v, "detected": detect_type(k, v),
         "detected_label": DATASETS[detect_type(k, v)]["label"]}
        for k, v in req.query.items()
    ]

    body_is_array = isinstance(body, list)
    if body is not None and not isinstance(body, (dict, list)):
        return {
            "method": req.method, "url": req.url,
            "params": [], "query_params": proper_qp,
            "header_count": len(req.headers), "body_type": req.body_type,
            "body_is_array": False,
        }

    params = flatten_body(body) if body is not None else []
    return {
        "method": req.method,
        "url": req.url,
        "params": params,
        "query_params": proper_qp,
        "header_count": len(req.headers),
        "body_type": req.body_type,
        "body_is_array": body_is_array,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  SINGLE HIT MODEL + ROUTE
# ─────────────────────────────────────────────────────────────────────────────

class SingleRunRequest(BaseModel):
    url: str
    method: str
    headers: dict
    query: dict = {}
    body: Optional[Any] = None
    body_type: Optional[str] = None
    unique_formats: dict = Field(default_factory=dict)   # path → format string to apply before firing
    unique_pools: dict = Field(default_factory=dict)     # path → list of unused valid values


class UniquePoolParseRequest(BaseModel):
    filename: str
    content_b64: str
    param_paths: list[str] = Field(default_factory=list)
    target_path: Optional[str] = None


@app.post("/parse-unique-pool")
def parse_unique_pool(req: UniquePoolParseRequest):
    """Map CSV/XLSX header row to param names; return unused-value columns."""
    name = (req.filename or "data.csv").strip()
    raw = (req.content_b64 or "").strip()
    try:
        data = base64.b64decode(raw, validate=False)
    except Exception:
        raise HTTPException(400, "Could not decode file")
    if len(data) > _POOL_FILE_MAX_BYTES:
        raise HTTPException(400, "File too large (max 5 MB)")
    if not data:
        raise HTTPException(400, "Empty file")

    lower = name.lower()
    try:
        if lower.endswith(".xlsx"):
            rows = _parse_xlsx_rows(data)
        elif lower.endswith(".xls"):
            raise HTTPException(400, "Old .xls not supported — save as .xlsx or .csv")
        else:
            text = data.decode("utf-8-sig", errors="replace")
            rows = _parse_csv_rows(text)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Could not parse file: {e}")

    if not rows or not any(str(c).strip() for c in rows[0]):
        raise HTTPException(400, "Missing header row")

    headers = [str(c).strip() if c is not None else "" for c in rows[0]]
    body = rows[1:]
    assigned = _bind_pool_headers(headers, req.param_paths or [], req.target_path)
    if not assigned:
        raise HTTPException(
            400,
            "No header matched a param name. First row must be titles like ID, email, fromDate.",
        )

    matched = {}
    for col_i, paths in assigned.items():
        col_vals = []
        for row in body:
            cell = row[col_i] if col_i < len(row) else ""
            col_vals.append("" if cell is None else str(cell).strip())
        for p in paths:
            matched[p] = col_vals

    n = min(len(v) for v in matched.values()) if matched else 0
    keep = [
        i for i in range(n)
        if all(matched[p][i] for p in matched)
    ]
    matched = {p: [matched[p][i] for i in keep] for p in matched}
    if not keep:
        raise HTTPException(400, "No data rows with values in every matched column")

    unmatched = [
        h for i, h in enumerate(headers)
        if h and i not in assigned
    ]
    return {
        "ok": True,
        "filename": name,
        "headers": headers,
        "matched": matched,
        "unmatched_headers": unmatched,
        "row_count": len(keep),
    }


@app.post("/run-single")
def run_single(req: SingleRunRequest):
    """Single static hit — optionally with unique values applied.
    Like clicking Send in Postman once."""
    session  = build_session()
    req_body, run_body_type = _normalize_json_body(req.body, req.body_type)
    req_body = copy.deepcopy(req_body) if req_body is not None else None

    # Apply unique formats to body + query.* paths
    test_query = dict(req.query or {})
    pool = UniqueValuePool(req.unique_pools)
    for path, fmt in req.unique_formats.items():
        if not fmt or (pool.active and path in pool.pools):
            continue
        if str(path).startswith("query."):
            key = str(path)[6:]
            if key:
                test_query[key] = generate_random_value(fmt)
        elif req_body is not None:
            set_nested_value(req_body, path, generate_random_value(fmt))

    try:
        applied_pool = pool.apply_to(req_body, test_query) if pool.active else {}
    except UniquePoolExhausted as ex:
        raise HTTPException(400, ex.message)

    status, resp_text, elapsed = fire_request(
        session, req.method, req.url, req.headers,
        test_query, req_body, run_body_type
    )
    pool.note_response(status, resp_text, applied_pool)

    # Determine simple PASS/FAIL
    try:
        code = int(status)
        result = "PASS" if 200 <= code < 300 else "FAIL"
    except Exception:
        result = "ERROR"

    has_unique = bool(req.unique_formats)
    mode_label = "Single Hit (with unique values)" if has_unique else "Single Static Hit"

    try:
        req_body_str = json.dumps(req_body, indent=2, default=str)
    except Exception:
        req_body_str = str(req_body)

    passed = 1 if result == "PASS" else 0
    ua = _collect_unique_applied(
        {k: v for k, v in (req.unique_formats or {}).items() if v and k not in pool.pools},
        applied_pool, None, req_body, test_query,
    )
    row = {
            "param":        "—",
            "dataset":      mode_label,
            "case_cat":     "POS",
            "case_id":      "single_hit",
            "case_desc":    mode_label,
            "test_value":   None,
            "status_code":  status,
            "result":       result,
            "elapsed_ms":   elapsed,
            "request_body": req_body_str,
            "response":     resp_text,
            "tested_url":   _compose_request_url(req.url, test_query),
            "unique_applied": ua,
    }
    row.update(_misconfig_fields(status, resp_text or "", ua))
    return {
        "results": [row],
        "summary": {
            "total":          1,
            "passed":         passed,
            "failed":         1 - passed,
            "warned":         0,
            "pos_pass":       passed,
            "pos_fail":       1 - passed,
            "neg_pass":       0,
            "neg_fail":       0,
            "health_pct":     passed * 100,
            "baseline_status": status,
            "baseline_ms":    elapsed,
        },
        "pool_index": pool.index,
        "pool_exhausted": bool(pool.active and pool.index >= pool.width()),
    }


def _apply_unique_formats(req_body: Any, unique_formats: dict, skip_path: Optional[str] = None):
    """Apply unique/random formats to body sidecar paths (ignore query.*).

    skip_path is the param currently under test — it keeps dataset/custom
    case values. Other checked (or unchecked) Unique Format fields still
    get a fresh value so uniqueness constraints do not collide.
    """
    if req_body is None or not unique_formats:
        return
    for path, fmt in unique_formats.items():
        if not fmt or _unique_path_skipped(path, skip_path) or str(path).startswith("query."):
            continue
        set_nested_value(req_body, path, generate_random_value(fmt))


def _apply_query_unique_formats(
    query: dict,
    unique_formats: dict,
    skip_path: Optional[str] = None,
) -> dict:
    """Apply unique formats for query.* paths. Returns a new query dict."""
    out = dict(query or {})
    if not unique_formats:
        return out
    skip = _unique_skip_keys(skip_path)
    for path, fmt in unique_formats.items():
        if not fmt or not str(path).startswith("query."):
            continue
        key = str(path)[6:]
        if not key or key in skip or str(path) in skip:
            continue
        out[key] = generate_random_value(fmt)
    return out


def _build_test_query(
    base_query: dict,
    unique_formats: dict,
    *,
    set_key: Optional[str] = None,
    set_val: Any = None,
    skip_unique_path: Optional[str] = None,
) -> dict:
    """Clone query, apply unique formats, then set/omit the tested param."""
    q = _apply_query_unique_formats(base_query, unique_formats, skip_path=skip_unique_path)
    if set_key is None:
        return q
    if set_val is None:
        # Null case → omit query key (missing param), not literal "None"
        q.pop(set_key, None)
    else:
        q[set_key] = set_val
    return q


def _empty_summary() -> dict:
    return {
        "total": 0, "passed": 0, "failed": 0, "warned": 0, "errors": 0,
        "pos_pass": 0, "pos_fail": 0, "neg_pass": 0, "neg_fail": 0,
    }


def _bump_summary(summary: dict, effective_cat: str, result: str):
    summary["total"] += 1
    if result == "PASS":
        summary["passed"] += 1
    elif result == "FAIL":
        summary["failed"] += 1
    elif result == "WARN":
        summary["warned"] += 1
    elif result == "ERROR":
        # Auth/transport failures count against health (not as NEG PASS)
        summary["failed"] += 1
        summary["errors"] = summary.get("errors", 0) + 1
    if effective_cat == "POS":
        if result == "PASS":
            summary["pos_pass"] += 1
        elif result in ("FAIL", "ERROR"):
            summary["pos_fail"] += 1
    else:
        if result == "PASS":
            summary["neg_pass"] += 1
        elif result in ("FAIL", "ERROR"):
            summary["neg_fail"] += 1


def _finalize_summary(summary: dict, b_status, b_ms, *, auth_expired: bool = False) -> dict:
    total = summary["total"]
    summary["health_pct"] = int((summary["passed"] / total) * 100) if total else 0
    summary["baseline_status"] = b_status
    summary["baseline_ms"] = b_ms
    summary["auth_expired"] = bool(auth_expired)
    summary.setdefault("errors", 0)
    return summary


def _count_expected_cases(req: RunTestRequest) -> int:
    n = 0
    for param_cfg in req.selected_params:
        ds = DATASETS.get(param_cfg.dataset_key)
        if ds:
            orig = get_nested_value(req.body, param_cfg.path) if req.body is not None else None
            n += sum(1 for _ in _iter_dataset_cases(param_cfg, ds, orig, dynamic=False))
        n += len(param_cfg.custom_cases or [])
    for param_cfg in req.query_selected_params:
        ds = DATASETS.get(param_cfg.dataset_key)
        if ds:
            orig = (req.query or {}).get(param_cfg.path)
            n += sum(1 for _ in _iter_dataset_cases(param_cfg, ds, orig, dynamic=False))
        n += len(param_cfg.custom_cases or [])
    return n


def _body_to_str(req_body: Any) -> str:
    try:
        return json.dumps(req_body, indent=2, default=str)
    except Exception:
        return str(req_body)


_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _is_write_method(method: str) -> bool:
    return str(method or "GET").upper() in _WRITE_METHODS


def iter_run_test_events(req: RunTestRequest):
    """Yield NDJSON events: start → case* → done. Shared by /run-tests and stream."""
    if not req.selected_params and not req.query_selected_params:
        raise HTTPException(400, "No parameters selected for testing")

    session = build_session()
    body_template, run_body_type = _normalize_json_body(req.body, req.body_type)
    body_template = copy.deepcopy(body_template) if body_template is not None else {}
    total_expected = _count_expected_cases(req)

    # POST/PUT/PATCH/DELETE: do not fire a hidden extra request. That call
    # consumes one-shot unique IDs (objectName, email, …), so the first
    # visible case looks like Postman's *second* hit (422 already exists).
    # Auth expiry is still caught on the first case (401 → stop).
    if _is_write_method(req.method):
        b_status, b_body, b_ms = "skipped", "", 0
        baseline_ok = True
    else:
        b_status, b_body, b_ms = fire_request(
            session, req.method, req.url, req.headers,
            req.query, copy.deepcopy(body_template), run_body_type
        )
        b_code = _parse_status_code(b_status)
        baseline_ok = b_code is not None and 200 <= b_code < 300
    auth_expired = False

    results = []
    summary = _empty_summary()
    pool = UniqueValuePool(req.unique_pools or {})
    formats = _merge_run_unique_formats(req, pool)

    yield {
        "type": "start",
        "total_expected": total_expected,
        "baseline_status": b_status,
        "baseline_ms": b_ms,
        "baseline_ok": baseline_ok,
        "auth_expired": _is_auth_status(b_status),
    }

    def emit_case(row: dict):
        results.append(row)
        _bump_summary(summary, row["case_cat"], row["result"])
        return {
            "type": "case",
            "done": len(results),
            "total_expected": total_expected,
            "result": row,
            "summary": dict(summary),
        }

    def score_and_row(*, param, dataset, effective_cat, cat_default, case_id, case_desc,
                      test_val, status, resp_text, elapsed, req_body_str, tested_url="",
                      unique_applied=None):
        result, fail_reason, assertions = evaluate_test_result(
            effective_cat, status, resp_text or "",
            b_status, b_body or "", baseline_ok,
        )
        ua = unique_applied or []
        row = {
            "param": param,
            "dataset": dataset,
            "case_cat": effective_cat,
            "case_cat_default": cat_default,
            "case_id": case_id,
            "case_desc": case_desc,
            "test_value": test_val,
            "status_code": status,
            "result": result,
            "fail_reason": fail_reason or "",
            "assertions": assertions,
            "elapsed_ms": elapsed,
            "request_body": req_body_str,
            "response": resp_text,
            "tested_url": tested_url or req.url,
            "unique_applied": ua,
        }
        row.update(_misconfig_fields(status, resp_text or "", ua))
        return row, result

    # ── Baseline auth hard-stop: do not run cases (avoids fake NEG PASS on 401) ─
    if _is_auth_status(b_status):
        auth_expired = True
        reason = (
            "Baseline returned 401 Unauthorized — update Bearer token in Details and re-run"
        )
        yield emit_case({
            "param": "—",
            "dataset": "Auth Check",
            "case_cat": "POS",
            "case_cat_default": "POS",
            "case_id": "baseline_auth",
            "case_desc": "Baseline request (auth check)",
            "test_value": None,
            "status_code": b_status,
            "result": "ERROR",
            "fail_reason": reason,
            "assertions": [{"check": "auth", "passed": False, "detail": reason}],
            "elapsed_ms": b_ms,
            "request_body": (
                _body_to_str(body_template) if req.body is not None else "(no body)"
            ),
            "response": b_body,
            "tested_url": _compose_request_url(req.url, req.query),
        })
        yield {
            "type": "done",
            "aborted": True,
            "auth_expired": True,
            "pool_index": pool.index,
            "summary": _finalize_summary(summary, b_status, b_ms, auth_expired=True),
            "results": results,
        }
        return

    pace_sec = max(0.0, float(req.delay_ms) / 1000.0) if getattr(req, "delay_ms", 0) > 0 else _CASE_PACING_SEC

    def _pace():
        if pace_sec > 0:
            time.sleep(pace_sec)

    last_pool_applied = {}

    def run_one(req_body, test_query, overlay_path=None, overlay_val=None):
        nonlocal last_pool_applied
        applied = pool.apply_to(req_body, test_query) if pool.active else {}
        last_pool_applied = applied
        if overlay_path is not None:
            set_nested_value(req_body, overlay_path, overlay_val)
        status, resp_text, elapsed = fire_request(
            session, req.method, req.url, req.headers,
            test_query, req_body, run_body_type
        )
        pool.note_response(status, resp_text, applied)
        return status, resp_text, elapsed

    def pool_done(*, aborted, auth_expired=False, pool_exhausted=False, message=""):
        ev = {
            "type": "done",
            "aborted": aborted,
            "auth_expired": auth_expired,
            "pool_exhausted": pool_exhausted,
            "pool_index": pool.index,
            "summary": _finalize_summary(summary, b_status, b_ms, auth_expired=auth_expired),
            "results": results,
        }
        if message:
            ev["message"] = message
        return ev

    for param_cfg in req.selected_params:
        dataset = DATASETS.get(param_cfg.dataset_key)
        ds_label = dataset["label"] if dataset else (param_cfg.dataset_key or "custom")
        orig_val = get_nested_value(body_template, param_cfg.path) if body_template is not None else None

        if dataset:
            for effective_cat, default_cat, case_id, case_desc, test_val in _iter_dataset_cases(
                param_cfg, dataset, orig_val, dynamic=req.dynamic_values
            ):
                req_body = copy.deepcopy(body_template)
                _apply_unique_formats(req_body, formats, skip_path=param_cfg.path)
                test_query = _build_test_query(
                    req.query, formats, skip_unique_path=param_cfg.path
                )

                try:
                    status, resp_text, elapsed = run_one(
                        req_body, test_query,
                        overlay_path=param_cfg.path, overlay_val=test_val,
                    )
                except UniquePoolExhausted as ex:
                    yield pool_done(aborted=True, pool_exhausted=True, message=ex.message)
                    return
                row, result = score_and_row(
                    param=param_cfg.path, dataset=ds_label,
                    effective_cat=effective_cat, cat_default=default_cat,
                    case_id=case_id, case_desc=case_desc, test_val=test_val,
                    status=status, resp_text=resp_text, elapsed=elapsed,
                    req_body_str=_body_to_str(req_body),
                    tested_url=_compose_request_url(req.url, test_query),
                    unique_applied=_collect_unique_applied(
                        formats, last_pool_applied, param_cfg.path, req_body, test_query
                    ),
                )
                yield emit_case(row)
                _pace()
                if result == "ERROR" and baseline_ok and _is_auth_status(status):
                    auth_expired = True
                    yield pool_done(aborted=True, auth_expired=True)
                    return

        for cc in (param_cfg.custom_cases or []):
            cc_val = str(cc.get("value", ""))
            cc_cat = cc.get("cat", "POS")
            req_body = copy.deepcopy(body_template)
            _apply_unique_formats(req_body, formats, skip_path=param_cfg.path)
            test_query = _build_test_query(
                req.query, formats, skip_unique_path=param_cfg.path
            )

            try:
                status, resp_text, elapsed = run_one(
                    req_body, test_query,
                    overlay_path=param_cfg.path, overlay_val=cc_val,
                )
            except UniquePoolExhausted as ex:
                yield pool_done(aborted=True, pool_exhausted=True, message=ex.message)
                return
            row, result = score_and_row(
                param=param_cfg.path, dataset=ds_label + " [custom]",
                effective_cat=cc_cat, cat_default=cc_cat,
                case_id="custom", case_desc=f"Custom: {cc_val[:40]}", test_val=cc_val,
                status=status, resp_text=resp_text, elapsed=elapsed,
                req_body_str=_body_to_str(req_body),
                tested_url=_compose_request_url(req.url, test_query),
                unique_applied=_collect_unique_applied(
                    formats, last_pool_applied, param_cfg.path, req_body, test_query
                ),
            )
            yield emit_case(row)
            _pace()
            if result == "ERROR" and baseline_ok and _is_auth_status(status):
                auth_expired = True
                yield pool_done(aborted=True, auth_expired=True)
                return

    for param_cfg in req.query_selected_params:
        dataset = DATASETS.get(param_cfg.dataset_key)
        ds_label = dataset["label"] if dataset else (param_cfg.dataset_key or "custom")
        orig_val = (req.query or {}).get(param_cfg.path)
        skip_q = "query." + param_cfg.path

        if dataset:
            for effective_cat, default_cat, case_id, case_desc, test_val in _iter_dataset_cases(
                param_cfg, dataset, orig_val, dynamic=req.dynamic_values
            ):
                test_query = _build_test_query(
                    req.query, formats,
                    set_key=param_cfg.path, set_val=test_val,
                    skip_unique_path=skip_q,
                )
                req_body = copy.deepcopy(body_template)
                _apply_unique_formats(req_body, formats)

                try:
                    status, resp_text, elapsed = run_one(req_body, test_query)
                except UniquePoolExhausted as ex:
                    yield pool_done(aborted=True, pool_exhausted=True, message=ex.message)
                    return
                row, result = score_and_row(
                    param="query." + param_cfg.path, dataset=ds_label,
                    effective_cat=effective_cat, cat_default=default_cat,
                    case_id=case_id, case_desc=case_desc, test_val=test_val,
                    status=status, resp_text=resp_text, elapsed=elapsed,
                    req_body_str=_body_to_str(req_body) if req.body is not None else "(no body)",
                    tested_url=_compose_request_url(req.url, test_query),
                    unique_applied=_collect_unique_applied(
                        formats, last_pool_applied, skip_q, req_body, test_query
                    ),
                )
                yield emit_case(row)
                _pace()
                if result == "ERROR" and baseline_ok and _is_auth_status(status):
                    auth_expired = True
                    yield pool_done(aborted=True, auth_expired=True)
                    return

        for cc in (param_cfg.custom_cases or []):
            cc_val = str(cc.get("value", ""))
            cc_cat = cc.get("cat", "POS")
            test_query = _build_test_query(
                req.query, formats,
                set_key=param_cfg.path, set_val=cc_val,
                skip_unique_path=skip_q,
            )
            req_body = copy.deepcopy(body_template)
            _apply_unique_formats(req_body, formats)
            try:
                status, resp_text, elapsed = run_one(req_body, test_query)
            except UniquePoolExhausted as ex:
                yield pool_done(aborted=True, pool_exhausted=True, message=ex.message)
                return
            row, result = score_and_row(
                param="query." + param_cfg.path, dataset=ds_label + " [custom]",
                effective_cat=cc_cat, cat_default=cc_cat,
                case_id="custom", case_desc=f"Custom: {cc_val[:40]}", test_val=cc_val,
                status=status, resp_text=resp_text, elapsed=elapsed,
                req_body_str=_body_to_str(req_body) if req.body is not None else "(no body)",
                tested_url=_compose_request_url(req.url, test_query),
                unique_applied=_collect_unique_applied(
                    formats, last_pool_applied, skip_q, req_body, test_query
                ),
            )
            yield emit_case(row)
            _pace()
            if result == "ERROR" and baseline_ok and _is_auth_status(status):
                auth_expired = True
                yield pool_done(aborted=True, auth_expired=True)
                return

    yield pool_done(aborted=False, auth_expired=auth_expired)


@app.post("/run-tests")
def run_tests(req: RunTestRequest):
    """Run validation tests for selected params (full response)."""
    final = None
    for ev in iter_run_test_events(req):
        if ev.get("type") == "done":
            final = ev
    if not final:
        raise HTTPException(500, "Test run produced no results")
    return {
        "summary": final["summary"],
        "results": final["results"],
        "aborted": bool(final.get("aborted")),
        "pool_exhausted": bool(final.get("pool_exhausted")),
        "pool_index": final.get("pool_index", 0),
        "message": final.get("message") or "",
    }


@app.post("/run-tests-stream")
async def run_tests_stream(req: RunTestRequest, request: Request):
    """Stream test cases as NDJSON so the UI can show a live feed + abort early."""

    async def event_gen():
        results = []
        summary = _empty_summary()
        b_status = None
        b_ms = None
        aborted = False
        gen = iter_run_test_events(req)
        try:
            for ev in gen:
                if await request.is_disconnected():
                    aborted = True
                    gen.close()
                    break

                et = ev.get("type")
                if et == "start":
                    b_status = ev.get("baseline_status")
                    b_ms = ev.get("baseline_ms")
                elif et == "case":
                    results.append(ev["result"])
                    summary = dict(ev.get("summary") or summary)
                elif et == "done":
                    yield json.dumps(ev, default=str) + "\n"
                    return

                yield json.dumps(ev, default=str) + "\n"
        except GeneratorExit:
            aborted = True
            try:
                gen.close()
            except Exception:
                pass
        except Exception as e:
            yield json.dumps({"type": "error", "message": str(e)}, default=str) + "\n"
            return

        if aborted:
            auth_exp = bool(summary.get("auth_expired")) or any(
                r.get("result") == "ERROR" and "401" in str(r.get("fail_reason", ""))
                for r in results
            )
            yield json.dumps({
                "type": "done",
                "aborted": True,
                "auth_expired": auth_exp,
                "summary": _finalize_summary(summary, b_status, b_ms, auth_expired=auth_exp),
                "results": results,
            }, default=str) + "\n"

    return StreamingResponse(
        event_gen(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/export/csv")
def export_csv(payload: dict):
    results = payload.get("results", [])
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "method","endpoint","param","dataset","case_cat","case_id","case_desc",
        "test_value","status_code","result","fail_reason",
        "elapsed_ms","request_body","response"
    ])
    writer.writeheader()
    for r in results:
        row = {k: r.get(k,"") for k in writer.fieldnames}
        if not row["method"]:
            row["method"] = r.get("api_method") or payload.get("method","")
        if not row["endpoint"]:
            row["endpoint"] = r.get("tested_url") or payload.get("url","")
        row["test_value"] = str(row["test_value"]) if row["test_value"] is not None else "null"
        writer.writerow(row)
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=api_validation_report.csv"}
    )


@app.post("/export/html")
def export_html(payload: dict):
    results = payload.get("results", [])
    summary = payload.get("summary", {})
    html = generate_html_report(
        results,
        summary,
        tested_url=str(payload.get("url") or ""),
        method=str(payload.get("method") or ""),
        headers=payload.get("headers") if isinstance(payload.get("headers"), dict) else {},
        is_bulk=bool(payload.get("isBulk")),
    )
    return StreamingResponse(
        io.BytesIO(html.encode()),
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=api_validation_report.html"}
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CAPTURE ENDPOINTS  (Mac App — mitmproxy proxy ke through)
# ─────────────────────────────────────────────────────────────────────────────

import subprocess
import platform
import threading
import asyncio

PROXY_PORT = 8768
_proxy_thread = None
_proxy_loop = None
_proxy_master = None


def _set_macos_proxy(enable: bool):
    """macOS system proxy set/unset karo (networksetup)."""
    if platform.system() != "Darwin":
        return
    try:
        ifaces_raw = subprocess.check_output(
            ["networksetup", "-listallnetworkservices"], text=True
        )
        ifaces = [
            line.strip()
            for line in ifaces_raw.splitlines()[1:]
            if line.strip() and not line.startswith("*")
        ]
        for iface in ifaces:
            if enable:
                subprocess.run(
                    ["networksetup", "-setwebproxy", iface, "127.0.0.1", str(PROXY_PORT)],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["networksetup", "-setsecurewebproxy", iface, "127.0.0.1", str(PROXY_PORT)],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["networksetup", "-setwebproxystate", iface, "on"],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["networksetup", "-setsecurewebproxystate", iface, "on"],
                    check=False, capture_output=True,
                )
            else:
                subprocess.run(
                    ["networksetup", "-setwebproxystate", iface, "off"],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["networksetup", "-setsecurewebproxystate", iface, "off"],
                    check=False, capture_output=True,
                )
    except Exception as e:
        print(f"[proxy] networksetup error: {e}")


def _run_proxy_thread():
    """mitmproxy Python API ko alag thread mein chalao — no subprocess, no PATH issues."""
    global _proxy_master

    async def _async_run():
        global _proxy_master
        try:
            from mitmproxy import options
            from mitmproxy.tools import dump
            import proxy_addon as _addon

            opts = options.Options(
                listen_host="127.0.0.1",
                listen_port=PROXY_PORT,
                ssl_insecure=True,
            )
            _proxy_master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
            _proxy_master.addons.add(_addon.CaptureAddon())
            print(f"[proxy] mitmproxy started on port {PROXY_PORT}")
            await _proxy_master.run()
        except Exception as e:
            print(f"[proxy] error: {e}")

    asyncio.run(_async_run())


def _start_proxy():
    """mitmproxy ko background thread mein start karo."""
    global _proxy_thread
    if _proxy_thread and _proxy_thread.is_alive():
        return  # already running
    _proxy_thread = threading.Thread(target=_run_proxy_thread, daemon=True)
    _proxy_thread.start()


def _stop_proxy():
    global _proxy_master, _proxy_loop
    try:
        if _proxy_master:
            _proxy_master.shutdown()
            _proxy_master = None
        print("[proxy] mitmproxy stopped")
    except Exception as e:
        print(f"[proxy] stop error: {e}")


# In-memory store (FastAPI process mein — proxy_addon HTTP POST se fill karta hai)
_capture_store: list = []
_is_capturing: bool = False


@app.post("/capture/add")
async def add_captured_request(request: Request):
    """proxy_addon.py se captured request receive karo (inter-process IPC via HTTP POST)."""
    global _capture_store, _is_capturing
    if not _is_capturing:
        return {"ok": False, "reason": "not capturing"}
    data = await request.json()
    req_id = data.get("id")
    if req_id and not any(r["id"] == req_id for r in _capture_store):
        item = dict(data)
        if isinstance(item.get("headers"), dict):
            item["headers"] = dict(item["headers"])
        if isinstance(item.get("queryParams"), dict):
            item["queryParams"] = dict(item["queryParams"])
        _capture_store.insert(0, item)
        if len(_capture_store) > 5000:
            _capture_store.pop()
    return {"ok": True}


def _hash_string(s: str) -> str:
    if not s:
        return "0"
    h = 5381
    for ch in s:
        h = (((h << 5) + h) + ord(ch)) & 0xFFFFFFFF
    return hex(h)[2:]


def _normalize_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    try:
        without_query = raw_url.split("?")[0].split("#")[0].strip()
        parsed = urlparse(without_query)
        if parsed.scheme and parsed.netloc:
            path = parsed.path.rstrip("/") or "/"
            return f"{parsed.scheme}://{parsed.netloc.lower()}{path}"
        return without_query.rstrip("/")
    except Exception:
        without_query = raw_url.split("?")[0].split("#")[0].strip()
        return without_query.rstrip("/")


def _extract_query_keys(req_item: dict) -> list:
    keys = set()
    if req_item and isinstance(req_item.get("queryParams"), dict):
        for k in req_item["queryParams"].keys():
            if k and isinstance(k, str):
                keys.add(k.strip())
    raw_url = req_item.get("url") or ""
    if "?" in raw_url:
        try:
            search = raw_url.split("?", 1)[1].split("#", 1)[0]
            for k, _ in urllib.parse.parse_qsl(search, keep_blank_values=True):
                if k:
                    keys.add(k.strip())
        except Exception:
            pass
    return sorted(list(filter(None, keys)))


def _extract_body_paths(body, prefix="", depth=0):
    if depth > 12 or body is None:
        return []
    if isinstance(body, str):
        trimmed = body.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                body = json.loads(trimmed)
            except Exception:
                return [prefix or "_raw"]
        elif "=" in trimmed and "\n" not in trimmed and not trimmed.startswith("<"):
            try:
                pairs = urllib.parse.parse_qsl(trimmed, keep_blank_values=True)
                keys = [f"{prefix}.{k}" if prefix else k for k, _ in pairs if k]
                if keys:
                    return keys
            except Exception:
                pass
            return [prefix or "_raw"]
        else:
            return [prefix or "_raw"]
    if not isinstance(body, (dict, list)):
        return [prefix] if prefix else []
    paths = []
    if isinstance(body, list):
        if not body:
            if prefix:
                paths.append(prefix)
        else:
            for idx, item in enumerate(body):
                sub_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                if isinstance(item, (dict, list)):
                    paths.extend(_extract_body_paths(item, sub_prefix, depth + 1))
                else:
                    paths.append(sub_prefix)
    elif isinstance(body, dict):
        if not body:
            if prefix:
                paths.append(prefix)
        else:
            for k, v in body.items():
                sub_prefix = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    paths.extend(_extract_body_paths(v, sub_prefix, depth + 1))
                else:
                    paths.append(sub_prefix)
    return paths


def _find_discriminator(body):
    if not body:
        return ""
    obj = body
    if isinstance(obj, str):
        trimmed = obj.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                obj = json.loads(trimmed)
            except Exception:
                return ""
        else:
            return ""
    if not isinstance(obj, (dict, list)) or obj is None:
        return ""

    if isinstance(obj, list):
        if obj and isinstance(obj[0], dict):
            obj = obj[0]
        else:
            return ""

    disc_keys = [
        "formName", "form_name", "entityType", "entity_type",
        "action", "operationName", "command", "cmd", "type"
    ]

    for k in disc_keys:
        if k in obj and not isinstance(obj[k], (dict, list)):
            val = str(obj[k]).strip()
            if val:
                return f"{k}={val}"

    entity_map = obj.get("entityMap")
    if isinstance(entity_map, dict):
        for k in ["identifier2", "entityType", "identifier1", "identifier3"]:
            if k in entity_map and not isinstance(entity_map[k], (dict, list)):
                val = str(entity_map[k]).strip()
                if val:
                    return f"entityMap.{k}={val}"
    return ""


def _get_request_signature(req_item: dict) -> str:
    if not req_item:
        return ""
    m = (req_item.get("method") or "GET").upper().strip()
    raw_url = (req_item.get("url") or "").strip()
    if not raw_url:
        return ""

    u = _normalize_url(raw_url)
    q_keys = _extract_query_keys(req_item)
    q_sig = f"?{'&'.join(q_keys)}" if q_keys else ""

    paths = []
    cfg = req_item.get("config")
    if isinstance(cfg, dict) and isinstance(cfg.get("currentParams"), list) and cfg["currentParams"]:
        paths = [p.get("path") for p in cfg["currentParams"] if isinstance(p, dict) and p.get("path")]
    elif isinstance(req_item.get("currentParams"), list) and req_item["currentParams"]:
        paths = [p.get("path") for p in req_item["currentParams"] if isinstance(p, dict) and p.get("path")]
    elif req_item.get("body") is not None or req_item.get("payload") is not None:
        b = req_item.get("body") if req_item.get("body") is not None else req_item.get("payload")
        paths = _extract_body_paths(b)

    unique_sorted_paths = sorted(list(set(filter(None, paths))))
    paths_count = len(unique_sorted_paths)
    paths_hash = _hash_string(",".join(unique_sorted_paths)) if paths_count > 0 else ""

    b = req_item.get("body") if req_item.get("body") is not None else req_item.get("payload")
    disc = _find_discriminator(b)

    if not q_sig and paths_count == 0 and not disc:
        return f"{m} {u}"

    parts = [f"{m} {u}{q_sig}"]
    if paths_count > 0:
        parts.append(f"params:{paths_count}:{paths_hash}")
    if disc:
        parts.append(f"disc:{disc}")
    return "|".join(parts)


@app.post("/capture/import")
async def import_captured_requests(request: Request):
    """HAR/cURL/JSON import ke liye — capturing check ke bina directly add/update karo.
    Deduplication is an on-demand filter, so do NOT overwrite duplicate signatures on import."""
    global _capture_store
    data = await request.json()
    reqs = data if isinstance(data, list) else [data]
    added = 0
    existing_store_map = {r.get("id"): i for i, r in enumerate(_capture_store) if r.get("id")}
    to_insert = []
    to_insert_map = {}

    for item in reqs:
        item = dict(item)
        req_id = item.get("id")
        if not req_id:
            req_id = f"import-{int(time.time()*1000)}-{added}"
            item["id"] = req_id
        if isinstance(item.get("headers"), dict):
            item["headers"] = dict(item["headers"])
        if isinstance(item.get("queryParams"), dict):
            item["queryParams"] = dict(item["queryParams"])
        
        if req_id in existing_store_map:
            _capture_store[existing_store_map[req_id]] = item
        elif req_id in to_insert_map:
            to_insert[to_insert_map[req_id]] = item
        else:
            to_insert_map[req_id] = len(to_insert)
            to_insert.append(item)
        added += 1

    if to_insert:
        _capture_store = to_insert + _capture_store
    return {"ok": True, "added": added}


@app.post("/capture/update")
async def update_captured_request(request: Request):
    """Update a single captured request (headers/body/query) by id — never touches others."""
    global _capture_store
    data = await request.json()
    req_id = data.get("id")
    if not req_id:
        raise HTTPException(400, "id required")

    for i, r in enumerate(_capture_store):
        if r.get("id") != req_id:
            continue
        updated = dict(r)
        if "headers" in data and isinstance(data["headers"], dict):
            updated["headers"] = dict(data["headers"])
        if "queryParams" in data and isinstance(data["queryParams"], dict):
            updated["queryParams"] = dict(data["queryParams"])
        if "body" in data:
            updated["body"] = data["body"]
        if "body_type" in data:
            updated["body_type"] = data["body_type"]
        if "payload" in data:
            updated["payload"] = data["payload"]
        if "url" in data and data["url"]:
            updated["url"] = data["url"]
        if "method" in data and data["method"]:
            updated["method"] = data["method"]
        if "status" in data:
            updated["status"] = data["status"]
        if "statusText" in data:
            updated["statusText"] = data["statusText"]
        _capture_store[i] = updated
        return {"ok": True, "request": updated}

    raise HTTPException(404, f"request not found: {req_id}")


@app.post("/capture/delete")
async def delete_captured_request(request: Request):
    """Delete an individual captured request by id from the in-memory buffer."""
    global _capture_store
    data = await request.json()
    req_id = data.get("id")
    if not req_id:
        raise HTTPException(400, "id required")
    initial_len = len(_capture_store)
    _capture_store = [r for r in _capture_store if r.get("id") != req_id]
    return {"ok": True, "deleted": initial_len > len(_capture_store)}


@app.get("/capture/status")
def capture_status():
    return {"capturing": _is_capturing}


@app.get("/capture/requests")
def get_captured_requests():
    return {
        "requests": _capture_store,
        "capturing": _is_capturing,
    }


@app.post("/capture/start")
def start_capture():
    global _is_capturing
    _is_capturing = True
    _start_proxy()
    _set_macos_proxy(True)
    return {"ok": True, "message": "Capture started. Browser proxy: 127.0.0.1:8768"}


@app.post("/capture/stop")
def stop_capture():
    global _is_capturing
    _is_capturing = False
    _set_macos_proxy(False)
    return {"ok": True, "message": "Capture stopped"}


@app.post("/capture/clear")
def clear_capture():
    global _capture_store
    _capture_store.clear()
    return {"ok": True}


@app.get("/capture/proxy-port")
def get_proxy_port():
    return {"port": PROXY_PORT}


import atexit

@atexit.register
def _cleanup():
    global _is_capturing
    _is_capturing = False
    _stop_proxy()
    _set_macos_proxy(False)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, reload=False)
