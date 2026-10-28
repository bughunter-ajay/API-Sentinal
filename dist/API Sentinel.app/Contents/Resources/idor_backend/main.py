"""
IDOR Tester Backend — Port 8773
Phase 1 : Detect & deduplicate weak endpoints (numeric IDs / UUIDs / ID keywords / DSL filters)
Phase 2 : Test each weak URL with User-1 (owner) vs User-2 (attacker) tokens
          Auto mode: ±20 numeric IDs around the detected ID
          UUID mode: harvest other UUIDs from the capture and swap them
"""

import json, csv, re, time, uuid, threading, io, base64
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote, unquote
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Any, Optional, Union
import urllib3

try:
    import requests as req_lib
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None

app = FastAPI(title="IDOR Tester Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TIMEOUT     = 15
VERIFY_SSL  = False
AUTO_RANGE  = 20   # test current_id ± AUTO_RANGE  →  up to 41 numeric IDs per weak point
# Cap how many harvested UUIDs we swap onto a UUID weak point (besides current).
MAX_UUID_SWAPS = 20
# Small pacing gap between sweep requests. A ±20 sweep fires up to 41 IDs ×
# 2 tokens back-to-back per weak point; some targets rate-limit or WAF-block
# bursty traffic and respond 401/403/429, which would otherwise get misread
# as "properly authorized" instead of "throttled".
REQUEST_DELAY = 0.12
# Max response-body chars kept per request. Large enough to hold a full API
# JSON response (the UI panel scrolls); still bounded so a huge file download
# can't blow up memory.
MAX_RESP_CHARS = 200_000
# Standard UUID (any version) — used for detection + harvest/swap.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_UUID_FIND_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_NIL_UUID = "00000000-0000-0000-0000-000000000000"

jobs = {}   # job_id → {...}

# ── Keyword sets (from Sens_Idor.py) ─────────────────────────────────────────
HIGH_ID_KEYWORDS = [
    "id","ids","uid","uuid","caseid","case_id","servicerequestid","service_request_id",
    "srid","requestid","request_id","entityid","entity_id","customerid","customer_id",
    "cust_id","custid","vendorid","vendor_id","companyid","company_id",
    "chartofaccountsid","chart_of_accounts_id","costcenterid","cost_center_id",
    "profitcenterid","profit_center_id","parentid","parent_id","documentid",
    "document_id","doc_id","docid","attachmentid","attachment_id","taskid","task_id",
    "commentid","comment_id","locationid","location_id","projectid","project_id",
    "invoiceid","invoice_id","orderid","order_id","ticketid","ticket_id","reportid",
    "report_id","profileid","profile_id","accountid","account_id","subscriptionid",
    "subscription_id","contractid","contract_id","billingid","billing_id","paymentid",
    "payment_id","transactionid","transaction_id","txnid","txn_id","fileid","file_id",
    "imageid","image_id","assetid","asset_id","resourceid","resource_id","roleid",
    "role_id","groupid","group_id","orgid","org_id","organisationid","organization_id",
    "branchid","branch_id","departmentid","department_id","employeeid","employee_id",
    "empid","emp_id","studentid","student_id","memberid","member_id","applicationid",
    "application_id","appid","app_id","sessionid","session_id","workflowid","workflow_id",
    "formid","form_id","categoryid","category_id","catid","productid","product_id",
    "campaignid","campaign_id","eventid","event_id","leadid","lead_id","opportunityid",
    "opportunity_id","quoteid","quote_id","claimid","claim_id","policyid","policy_id",
    "incidentid","incident_id","issueid","issue_id","bugid","bug_id","featureid",
    "feature_id","messageid","message_id","msgid","notificationid","notification_id",
    "alertid","alert_id","logid","log_id","auditid","audit_id","recordid","record_id",
    "entryid","entry_id","itemid","item_id","nodeid","node_id","siteid","site_id",
    "tenantid","tenant_id","workspaceid","workspace_id","projectmasterid","master_id",
    "primaryid","primary_id",
]
MEDIUM_ID_KEYWORDS = [
    "referenceid","reference_id","ref_id","refid","referencevalue","reference_value",
    "objectid","object_id","ownerid","owner_id","assignedto","assigned_to","assigneeid",
    "assignee_id","userid","user_id","requestedby","requested_by","submittedby",
    "submitted_by","createdby","created_by","modifiedby","modified_by","updatedby",
    "updated_by","approvedby","approved_by","reviewedby","reviewed_by","managedby",
    "managed_by","target","targetid","target_id","source","sourceid","source_id",
    "relatedid","related_id","linkedid","linked_id","externalid","external_id","ext_id",
    "internalid","internal_id","int_id","foreignid","foreign_id","pk","fk","key","keys",
    "num","number","no","code","codes","correlationid","correlation_id","traceid",
    "trace_id","batchid","batch_id","jobid","job_id","runid","run_id","instanceid",
    "instance_id","channelid","channel_id","conversationid","conversation_id","threadid",
    "thread_id","postid","post_id","groupby","filterid",
]
ALL_ID_KEYWORDS = set(k.lower() for k in HIGH_ID_KEYWORDS + MEDIUM_ID_KEYWORDS)
HIGH_ID_SET     = set(k.lower() for k in HIGH_ID_KEYWORDS)

# Some APIs expose a string-formatted twin of an ID field (e.g. the classic
# id / id_str pattern), or a display/code variant. Stripping these suffixes
# lets "employeeIdStr" resolve to the known "employeeid" keyword instead of
# being silently ignored as an unrecognized field name.
_ID_KEY_STRIP_SUFFIXES = ("str", "text", "txt", "code", "val", "value")

def _match_id_keyword(k):
    """Return the canonical ID keyword this field name matches, or None."""
    kl = k.lower()
    if kl in ALL_ID_KEYWORDS:
        return kl
    for suf in _ID_KEY_STRIP_SUFFIXES:
        if kl.endswith(suf) and len(kl) > len(suf):
            stripped = kl[:-len(suf)]
            if stripped in ALL_ID_KEYWORDS:
                return stripped
    return None


def _match_header_id_keyword(k):
    """HTTP header names conventionally use kebab-case with an optional
    X- prefix (X-User-Id, Customer-Id) as well as flat lowercase
    (customerid) — normalize both shapes before matching against
    ALL_ID_KEYWORDS."""
    bare = re.sub(r"[-_\s]", "", k.lower())
    canon = _match_id_keyword(bare)
    if canon:
        return canon
    if bare.startswith("x") and len(bare) > 1:
        return _match_id_keyword(bare[1:])
    return None

# Prefixed/zero-padded IDs like "H-0190", "EMP0190", "INV-24001" — a plain
# \d{1,15} check misses these entirely, but they're an extremely common
# real-world ID format (letter prefix + zero-padded sequence number).
_FORMATTED_ID_RE = re.compile(r"^([A-Za-z]{1,12}-?)(\d{1,15})$")

def _parse_formatted_id(value):
    """Returns (prefix, numeric_value, zero-pad width) or None."""
    m = _FORMATTED_ID_RE.fullmatch(str(value))
    if not m:
        return None
    prefix, digits = m.group(1), m.group(2)
    n = int(digits)
    return (prefix, n, len(digits)) if n >= 1 else None


def _format_id(prefix, new_id, width):
    return f"{prefix}{new_id:0{width}d}"

# A numeric ID embedded inside a larger path segment — e.g.
# /reports/download/invoice_1042.pdf or /files/report-1042-final.xlsx —
# where the segment as a WHOLE isn't purely numeric so the plain PATH_ID
# check misses it. Requires 3+ digits bounded by _/-/./start/end to avoid
# matching small step/version-like numbers (e.g. "step-1", "v2").
_COMPOUND_SEG_ID_RE = re.compile(r"(?:^|[_\-.])(\d{3,15})(?:[_\-.]|$)")

def _sub_compound_id(segment, new_id):
    """Replace just the digit run _COMPOUND_SEG_ID_RE matched, preserving
    the surrounding prefix/suffix and zero-padding width."""
    m = _COMPOUND_SEG_ID_RE.search(segment)
    if not m:
        return segment
    width = len(m.group(1))
    return segment[:m.start(1)] + f"{new_id:0{width}d}" + segment[m.end(1):]


def _try_base64_id(value):
    """Some APIs opaque-ify an ID by base64-encoding it (standard or
    URL-safe alphabet, with or without '=' padding) instead of sending it
    plain — e.g. cursor=MTA0Mg== decodes to "1042". Returns
    (numeric_value, urlsafe, had_padding, fmt) if `value` is base64 that
    decodes to a plain-numeric or formatted ID, else None. `fmt` is
    (prefix, width) for a formatted decoded ID (e.g. "H-0190"), else None
    for a plain-numeric decoded ID."""
    s = str(value)
    if len(s) < 2 or not re.fullmatch(r"[A-Za-z0-9+/_=-]+", s):
        return None
    for urlsafe in (False, True):
        try:
            decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
            padded  = s + "=" * (-len(s) % 4)
            decoded = decoder(padded).decode("utf-8")
        except Exception:
            continue
        if re.fullmatch(r"\d{1,15}", decoded) and int(decoded) >= 1:
            return (int(decoded), urlsafe, s.endswith("="), None)
        fp = _parse_formatted_id(decoded)
        if fp:
            return (fp[1], urlsafe, s.endswith("="), (fp[0], fp[2]))
    return None


def _encode_base64_id(new_id, urlsafe, had_padding, fmt):
    plain   = _format_id(fmt[0], new_id, fmt[1]) if fmt else str(new_id)
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out     = encoder(plain.encode()).decode()
    return out if had_padding else out.rstrip("=")

IGNORE_Q_KEYS = {
    "offset","size","limit","page","pagesize","page_size","orderby","order_by",
    "ordertype","order_type","sortby","sort_by","sortorder","sort_order","sort",
    "from","to","startdate","enddate","format","locale","lang","timezone",
    "callback","_","timestamp","ts","nocache","v","version","fields","include","exclude",
}
STATIC_EXTS = (".js",".css",".png",".jpg",".jpeg",".gif",".svg",".ico",
               ".woff",".woff2",".ttf",".map",".webp",".zip",".mp4",".mp3")

# ── Core detection & mutation (ported from Sens_Idor.py) ─────────────────────

def _is_static(url):
    return urlparse(url).path.lower().endswith(STATIC_EXTS)


def _is_uuid(value) -> bool:
    return bool(value) and bool(_UUID_RE.fullmatch(str(value).strip()))


def _harvest_uuids_from_text(text) -> set:
    if not text:
        return set()
    return {m.group(0) for m in _UUID_FIND_RE.finditer(str(text))}


def _harvest_uuids_from_entries(entries) -> list:
    """Collect distinct UUIDs seen in captured URLs / bodies / headers.
    Order is stable (first-seen) so Auto UUID swaps are deterministic."""
    seen, ordered = set(), []
    for entry in entries or []:
        blobs = [entry.get("url") or "", entry.get("body") or ""]
        hdrs = entry.get("headers") or {}
        if isinstance(hdrs, dict):
            blobs.extend(str(v) for v in hdrs.values())
        for blob in blobs:
            for u in _harvest_uuids_from_text(blob):
                if u not in seen and u != _NIL_UUID:
                    seen.add(u)
                    ordered.append(u)
    return ordered


def _parse_json_body(body):
    """Best-effort JSON body parse. Returns a dict, or None if body is
    missing/not-a-JSON-object (e.g. raw text, XML, multipart)."""
    if not body:
        return None
    try:
        obj = json.loads(body) if isinstance(body, str) else body
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def detect_weak_point(url, body=None, headers=None):
    """Return list of weak-point descriptors or None if URL/body/headers is
    not injectable."""
    parsed = urlparse(url)
    points = []

    # 1. Numeric / UUID path segment(s)  /api/customers/1042  or  /users/{uuid}
    #    unquote() first — a percent-encoded segment would otherwise never match.
    #    Every injectable segment is flagged separately (by position).
    segs = parsed.path.split("/")
    for i, seg in enumerate(segs):
        useg = unquote(seg)
        if re.fullmatch(r"\d{1,15}", useg) and int(useg) >= 1:
            points.append(f"PATH_ID:{i}")
        elif _is_uuid(useg):
            points.append(f"PATH_UUID:{i}")
        else:
            # Filename-style segment with an embedded ID, e.g. invoice_1042.pdf
            m = _COMPOUND_SEG_ID_RE.search(useg)
            if m and int(m.group(1)) >= 1:
                points.append(f"PATH_ID_COMPOUND:{i}")

    q = parse_qs(parsed.query, keep_blank_values=True)

    # 2. ID-keyword query param with numeric / formatted / UUID / base64 value
    for k, v in q.items():
        canon = _match_id_keyword(k)
        if not canon or not v:
            continue
        val = v[0]
        is_plain_num = bool(re.fullmatch(r"\d{1,15}", val)) and int(val) >= 1
        is_formatted = _parse_formatted_id(val) is not None
        sev = "HIGH" if canon in HIGH_ID_SET else "MEDIUM"
        if is_plain_num or is_formatted:
            points.append(f"QUERY_ID:{k}:{sev}")
        elif _is_uuid(val):
            points.append(f"QUERY_ID:{k}:{sev}:UUID")
        elif _try_base64_id(val) is not None:
            points.append(f"QUERY_ID:{k}:{sev}:B64")

    # 3. DSL / RSQL filter expression  filter=customerId==1042  (or =='uuid')
    for k, v in q.items():
        for item in v:
            for m in re.finditer(
                r"(?<![=!<>])([a-zA-Z_][a-zA-Z0-9_]*)(?<![=!<>])==(?!=)['\"]?(\d+)['\"]?", item
            ):
                field, val = m.group(1), int(m.group(2))
                if "." in item[max(0, m.start()-2): m.end()]:
                    continue
                fl = field.lower()
                if not (fl.endswith("id") or fl in ALL_ID_KEYWORDS):
                    continue
                if val < 1 or len(fl) < 2:
                    continue
                points.append(f"DSL_ID:{field}")
            for m in re.finditer(
                r"(?<![=!<>])([a-zA-Z_][a-zA-Z0-9_]*)(?<![=!<>])==(?!=)['\"]?"
                r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
                r"['\"]?",
                item,
            ):
                field = m.group(1)
                fl = field.lower()
                if not (fl.endswith("id") or fl in ALL_ID_KEYWORDS) or len(fl) < 2:
                    continue
                points.append(f"DSL_UUID:{field}")

    # 4. Path template params  /api/{customerId}
    for seg in parsed.path.split("/"):
        m = re.match(r"\{([^}]+)\}", seg)
        if m and any(kw in m.group(1).lower() for kw in ["id","uid","uuid","key","num","no"]):
            points.append(f"PATH_PARAM:{m.group(1)}")

    # 5. JSON request-body field with an ID-keyword name
    bobj = _parse_json_body(body)
    if bobj:
        for k, v in bobj.items():
            canon = _match_id_keyword(k)
            if not canon:
                continue
            sev = "HIGH" if canon in HIGH_ID_SET else "MEDIUM"
            if isinstance(v, int) and not isinstance(v, bool) and v >= 1:
                points.append(f"BODY_ID:{k}:{sev}")
            elif isinstance(v, str) and _is_uuid(v):
                points.append(f"BODY_ID:{k}:{sev}:UUID")
            elif isinstance(v, str) and _parse_formatted_id(v) is not None:
                points.append(f"BODY_ID:{k}:{sev}")
            elif isinstance(v, str) and _try_base64_id(v) is not None:
                points.append(f"BODY_ID:{k}:{sev}:B64")
            elif (isinstance(v, list) and v
                  and all(isinstance(i, int) and not isinstance(i, bool) for i in v)
                  and v[0] >= 1):
                points.append(f"BODY_ID_LIST:{k}:{sev}")

    # 6. ID-keyword custom HEADER
    if headers:
        for k, v in headers.items():
            canon = _match_header_id_keyword(k)
            if not canon:
                continue
            val = str(v)
            is_plain_num = bool(re.fullmatch(r"\d{1,15}", val)) and int(val) >= 1
            is_formatted = _parse_formatted_id(val) is not None
            sev = "HIGH" if canon in HIGH_ID_SET else "MEDIUM"
            if is_plain_num or is_formatted:
                points.append(f"HEADER_ID:{k}:{sev}")
            elif _is_uuid(val):
                points.append(f"HEADER_ID:{k}:{sev}:UUID")
            elif _try_base64_id(val) is not None:
                points.append(f"HEADER_ID:{k}:{sev}:B64")

    return points or None


def normalize_for_dedup(url):
    parsed = urlparse(url)
    path   = re.sub(r"/count/?$", "", parsed.path)
    path   = re.sub(r"(/)(\d{1,15})(/?)", r"\1__ID__\3", path)
    path   = re.sub(
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "/__ID__",
        path,
    )
    path   = re.sub(r"\{[^}]+\}", "__PARAM__", path)
    q      = parse_qs(parsed.query, keep_blank_values=True)
    norm_q = {}
    for k, v in q.items():
        if k.lower() in IGNORE_Q_KEYS:
            continue
        nv = []
        for item in v:
            if k.lower() in ALL_ID_KEYWORDS and re.fullmatch(r"\d{1,15}", item):
                nv.append("__ID__")
            else:
                nv.append(re.sub(
                    r"([a-zA-Z_.]*[Ii][Dd])\s*==\s*['\"]?\d+['\"]?", r"\1==__ID__", item
                ))
        norm_q[k] = nv
    qs = urlencode({k: v[0] for k, v in sorted(norm_q.items())})
    return urlunparse(parsed._replace(path=path, query=qs))


def priority_score(url):
    u = url.lower()
    if re.search(r"/\d{2,}(/|$)", u) or re.search(r"\{[^}]+\}", u):
        return "HIGH"
    high_terms = ["invoice","payment","transaction","account","subscription","billing",
                  "contract","policy","claim","document","attachment","customer","vendor",
                  "employee","profile","user","order","ticket","report","audit","record",
                  "export","download","file","asset"]
    if any(t in u for t in high_terms):
        return "HIGH"
    med_terms = ["service","request","case","task","project","form","event",
                 "message","notification","comment","issue","lead","campaign"]
    if any(t in u for t in med_terms):
        return "MEDIUM"
    return "LOW"


def extract_current_id(url, weak_points, body=None, headers=None) -> Optional[Union[int, str]]:
    """Return the current ID for a weak point — int for numeric/formatted,
    UUID string for UUID weak points, or None if unreadable."""
    parsed = urlparse(url)
    bobj   = None
    for wp in weak_points:
        is_b64  = wp.endswith(":B64")
        is_uuid = wp.endswith(":UUID")
        if wp.startswith("PATH_ID:"):
            idx  = int(wp.split(":")[1])
            segs = parsed.path.split("/")
            if 0 <= idx < len(segs):
                useg = unquote(segs[idx])
                if re.fullmatch(r"\d{1,15}", useg) and int(useg) >= 1:
                    return int(useg)
        elif wp.startswith("PATH_UUID:"):
            idx  = int(wp.split(":")[1])
            segs = parsed.path.split("/")
            if 0 <= idx < len(segs):
                useg = unquote(segs[idx])
                if _is_uuid(useg):
                    return useg
        elif wp.startswith("PATH_ID_COMPOUND:"):
            idx  = int(wp.split(":")[1])
            segs = parsed.path.split("/")
            if 0 <= idx < len(segs):
                m = _COMPOUND_SEG_ID_RE.search(unquote(segs[idx]))
                if m:
                    return int(m.group(1))
        elif wp.startswith("QUERY_ID:"):
            key = wp.split(":")[1]
            q   = parse_qs(parsed.query, keep_blank_values=True)
            if key in q:
                val = q[key][0]
                if is_uuid and _is_uuid(val):
                    return val
                if is_b64:
                    b64 = _try_base64_id(val)
                    if b64:
                        return b64[0]
                elif val.isdigit():
                    return int(val)
                elif _is_uuid(val):
                    return val
                else:
                    fmt = _parse_formatted_id(val)
                    if fmt:
                        return fmt[1]
        elif wp.startswith("DSL_ID:"):
            field = wp.split(":", 1)[1]
            q     = parse_qs(parsed.query, keep_blank_values=True)
            for v_list in q.values():
                for item in v_list:
                    m = re.search(rf"{re.escape(field)}\s*==\s*['\"]?(\d+)['\"]?", item)
                    if m:
                        return int(m.group(1))
        elif wp.startswith("DSL_UUID:"):
            field = wp.split(":", 1)[1]
            q     = parse_qs(parsed.query, keep_blank_values=True)
            for v_list in q.values():
                for item in v_list:
                    m = re.search(
                        rf"{re.escape(field)}\s*==\s*['\"]?"
                        rf"({_UUID_FIND_RE.pattern})['\"]?",
                        item,
                    )
                    if m:
                        return m.group(1)
        elif wp.startswith("BODY_ID:") or wp.startswith("BODY_ID_LIST:"):
            if bobj is None:
                bobj = _parse_json_body(body) or {}
            key = wp.split(":")[1]
            v   = bobj.get(key)
            if isinstance(v, int) and not isinstance(v, bool):
                return v
            if isinstance(v, str):
                if is_uuid and _is_uuid(v):
                    return v
                if is_b64:
                    b64 = _try_base64_id(v)
                    if b64:
                        return b64[0]
                elif _is_uuid(v):
                    return v
                else:
                    fmt = _parse_formatted_id(v)
                    if fmt:
                        return fmt[1]
            if isinstance(v, list) and v and isinstance(v[0], int) and not isinstance(v[0], bool):
                return v[0]
        elif wp.startswith("HEADER_ID:"):
            key = wp.split(":")[1]
            if headers and key in headers:
                val = str(headers[key])
                if is_uuid and _is_uuid(val):
                    return val
                if is_b64:
                    b64 = _try_base64_id(val)
                    if b64:
                        return b64[0]
                elif val.isdigit():
                    return int(val)
                elif _is_uuid(val):
                    return val
                else:
                    fmt = _parse_formatted_id(val)
                    if fmt:
                        return fmt[1]
    return None


def apply_mutations(url, weak_points, new_id, body=None, headers=None):
    """Returns (mutated_url, mutated_body_json_str, mutated_headers) — any
    part can be unchanged (== the original) if this weak point doesn't
    touch that half at all. Returns
    (None, None, None) if nothing was actually mutated. `headers` is a
    plain dict of the endpoint's original headers; a mutated copy is
    returned so header-carried IDs can be tested without touching path/
    query/body."""
    parsed  = urlparse(url)
    path    = parsed.path.split("/")
    q       = parse_qs(parsed.query, keep_blank_values=True)
    changed = False

    bobj         = _parse_json_body(body)
    body_changed = False

    hdrs_out        = dict(headers) if headers else None
    headers_changed = False

    for wp in weak_points:
        is_b64  = wp.endswith(":B64")
        is_uuid = wp.endswith(":UUID") or wp.startswith("PATH_UUID:") or wp.startswith("DSL_UUID:")
        if wp.startswith("PATH_ID:"):
            idx = int(wp.split(":")[1])
            if 0 <= idx < len(path):
                path[idx] = str(new_id); changed = True
        elif wp.startswith("PATH_UUID:"):
            idx = int(wp.split(":")[1])
            if 0 <= idx < len(path):
                path[idx] = str(new_id); changed = True
        elif wp.startswith("PATH_ID_COMPOUND:"):
            idx = int(wp.split(":")[1])
            if 0 <= idx < len(path) and isinstance(new_id, int):
                path[idx] = _sub_compound_id(unquote(path[idx]), new_id)
                changed = True
        elif wp.startswith("PATH_PARAM:"):
            pn = wp.split(":", 1)[1]
            for i, seg in enumerate(path):
                if seg == f"{{{pn}}}":
                    path[i] = str(new_id); changed = True
        elif wp.startswith("QUERY_ID:"):
            key = wp.split(":")[1]
            if key in q and q[key]:
                vals = list(q[key])
                orig_val = vals[0]
                if is_uuid or _is_uuid(orig_val):
                    vals[0] = str(new_id)
                elif is_b64:
                    b64 = _try_base64_id(orig_val)
                    vals[0] = (
                        _encode_base64_id(new_id, b64[1], b64[2], b64[3])
                        if b64 and isinstance(new_id, int) else str(new_id)
                    )
                else:
                    fmt = _parse_formatted_id(orig_val)
                    # Preserve prefix + zero-padding, e.g. H-0190 → H-0200
                    if fmt and isinstance(new_id, int):
                        vals[0] = _format_id(fmt[0], new_id, fmt[2])
                    else:
                        vals[0] = str(new_id)
                q[key] = vals  # keep extra multi-values intact
                changed = True
        elif wp.startswith("DSL_ID:"):
            key = wp.split(":", 1)[1]
            # Preserve operator spacing + quote style (userId=='140723')
            def _swap_num(mm):
                return f"{mm.group(1)}{mm.group(2)}{new_id}{mm.group(3)}"
            pat = rf"({re.escape(key)}\s*==\s*)(['\"]?)\d+(['\"]?)"
            for k, v in q.items():
                q[k] = [re.sub(pat, _swap_num, item) for item in v]
            changed = True
        elif wp.startswith("DSL_UUID:"):
            key = wp.split(":", 1)[1]
            def _swap_uuid(mm):
                return f"{mm.group(1)}{mm.group(2)}{new_id}{mm.group(3)}"
            pat = (
                rf"({re.escape(key)}\s*==\s*)(['\"]?)"
                rf"{_UUID_FIND_RE.pattern}(['\"]?)"
            )
            for k, v in q.items():
                q[k] = [re.sub(pat, _swap_uuid, item, flags=re.I) for item in v]
            changed = True
        elif wp.startswith("BODY_ID:"):
            key = wp.split(":")[1]
            if bobj is not None and key in bobj:
                orig_val = bobj[key]
                if is_uuid or (isinstance(orig_val, str) and _is_uuid(orig_val)):
                    bobj[key] = str(new_id)
                elif is_b64 and isinstance(orig_val, str):
                    b64 = _try_base64_id(orig_val)
                    bobj[key] = (
                        _encode_base64_id(new_id, b64[1], b64[2], b64[3])
                        if b64 and isinstance(new_id, int) else str(new_id)
                    )
                elif isinstance(orig_val, str):
                    fmt = _parse_formatted_id(orig_val)
                    bobj[key] = (
                        _format_id(fmt[0], new_id, fmt[2])
                        if fmt and isinstance(new_id, int) else str(new_id)
                    )
                else:
                    bobj[key] = new_id
                body_changed = True
        elif wp.startswith("BODY_ID_LIST:"):
            key = wp.split(":")[1]
            if bobj is not None and isinstance(bobj.get(key), list) and bobj[key]:
                bobj[key] = [new_id]; body_changed = True
        elif wp.startswith("HEADER_ID:"):
            key = wp.split(":")[1]
            if hdrs_out is not None and key in hdrs_out:
                orig_val = str(hdrs_out[key])
                if is_uuid or _is_uuid(orig_val):
                    hdrs_out[key] = str(new_id)
                elif is_b64:
                    b64 = _try_base64_id(orig_val)
                    hdrs_out[key] = (
                        _encode_base64_id(new_id, b64[1], b64[2], b64[3])
                        if b64 and isinstance(new_id, int) else str(new_id)
                    )
                else:
                    fmt = _parse_formatted_id(orig_val)
                    hdrs_out[key] = (
                        _format_id(fmt[0], new_id, fmt[2])
                        if fmt and isinstance(new_id, int) else str(new_id)
                    )
                headers_changed = True

    if not changed and not body_changed and not headers_changed:
        return None, None, None

    if changed:
        # Preserve ALL multi-value query params (doseq); quote spaces as %20
        pairs = [(k, item) for k, vals in q.items() for item in vals]
        new_qs = urlencode(pairs, doseq=False, quote_via=quote)
        mutated_url = urlunparse(parsed._replace(path="/".join(path), query=new_qs))
    else:
        mutated_url = url

    mutated_body    = json.dumps(bobj) if body_changed else body
    mutated_headers = hdrs_out if headers_changed else headers
    return mutated_url, mutated_body, mutated_headers


# ── Response analysis ─────────────────────────────────────────────────────────

# A response shaped entirely from these keys (e.g. {"error": "not found"},
# {"success": false}) is a failure/error envelope wearing a 200 status —
# not real resource data — even though it's syntactically valid non-empty
# JSON. Kept small and high-confidence on purpose: a real resource object
# almost always has several OTHER fields alongside any of these, so the
# "every key is in this set" check below won't fire on genuine data.
_ERROR_ENVELOPE_KEYS = {"error", "errors", "message", "success"}

def is_meaningful(text, status):
    if status != 200 or not text or not text.strip():
        return False
    s = text.strip()
    if s in ("{}", "[]", '""', "null"):
        return False
    try:
        p = json.loads(s)
        if isinstance(p, dict):
            if all(v is None for v in p.values()):
                return False
            keys = set(k.lower() for k in p.keys())
            if keys and keys.issubset(_ERROR_ENVELOPE_KEYS):
                return False
            if p.get("success") is False:
                return False
        if isinstance(p, list) and len(p) == 0:
            return False
    except Exception:
        pass
    return True


def response_similarity(text1, text2):
    if text1 == text2:
        return 1.0
    if not text1 or not text2:
        return 0.0

    def value_tokens(t):
        # Quoted string VALUES only — a quoted string immediately preceded
        # by ':' (i.e. not a JSON key). Field/schema names trivially match
        # across ANY two responses from the same endpoint regardless of
        # whose data it is, so comparing keys would inflate similarity for
        # genuinely different records that just share a schema. Comparing
        # actual values is what tells us whether this is the same record.
        return set(re.findall(r':\s*"([^"]{2,})"', t))
    t1, t2 = value_tokens(text1), value_tokens(text2)

    if t1 and t2:
        # Classic union overlap — good when both responses are roughly the
        # same shape/size.
        union_sim = len(t1 & t2) / max(len(t1), len(t2))
        # Subset overlap — a much SHORTER response whose values are almost
        # entirely contained in the longer one is very likely the SAME
        # underlying record with some fields filtered out (e.g. role-based
        # field redaction), not a different/unrelated object. A raw
        # length-ratio check would wrongly punish this case as "different
        # data" purely because one side has extra fields.
        smaller, larger = (t1, t2) if len(t1) <= len(t2) else (t2, t1)
        subset_sim = len(smaller & larger) / len(smaller)
        return max(union_sim, subset_sim)

    # No quoted-string tokens to compare (non-JSON / plain-text bodies) —
    # fall back to a length-ratio heuristic.
    ratio = min(len(text1), len(text2)) / max(len(text1), len(text2))
    return 0.8 if ratio > 0.9 else ratio * 0.5


def _clean_headers(hdrs):
    """
    Remove headers that Python's requests/urllib3 cannot send:
      - HTTP/2 pseudo-headers  (:authority, :method, :path, :scheme)
      - Empty or non-string keys
      - Values containing bare \r or \n (header injection guard)
    Also strip Accept-Encoding so requests handles decompression itself.
    """
    skip = {"accept-encoding", "content-length"}
    clean = {}
    for k, v in hdrs.items():
        if not isinstance(k, str) or not k.strip():
            continue
        if k.startswith(":"):          # HTTP/2 pseudo-headers
            continue
        if k.lower() in skip:
            continue
        sv = str(v)
        if "\r" in sv or "\n" in sv:   # header injection guard
            continue
        clean[k] = sv
    return clean


def _strip_session_cookies(hdrs: dict) -> dict:
    """Drop Cookie from attacker (User-2) headers so a captured owner
    session cannot keep authenticating after Authorization is swapped."""
    out = {}
    for k, v in (hdrs or {}).items():
        if k.lower() == "cookie":
            continue
        out[k] = v
    return out


def _probe_id_for(current_id: Union[int, str]):
    """Nonsense ID used to detect public/shared endpoints (same body for any ID)."""
    if isinstance(current_id, int):
        probe = current_id + 1_000_000
        if probe == current_id or probe > 2_000_000_000:
            probe = 1 if current_id != 1 else 2
        return probe
    return _NIL_UUID


def _looks_public_endpoint(method, url, wp, current_id, body, headers, token1, u1_real_body):
    """True when User-1 gets nearly the same meaningful body for a nonsense
    probe ID — i.e. the endpoint is public/shared, not an object-scoped IDOR."""
    if current_id is None or not u1_real_body:
        return False
    probe = _probe_id_for(current_id)
    if probe == current_id:
        return False
    mu, mb, mh = apply_mutations(url, [wp], probe, body, headers)
    if not mu:
        return False
    h1 = {**_clean_headers(mh if mh is not None else headers), "Authorization": token1}
    body_kw = {"data": mb.encode()} if mb else {}
    try:
        rp = req_lib.request(
            method, mu, headers=h1, timeout=TIMEOUT, verify=VERIFY_SSL, **body_kw
        )
    except Exception:
        return False
    pb = rp.text or ""
    if not is_meaningful(pb, rp.status_code):
        return False
    return response_similarity(u1_real_body, pb) >= 0.85


def idor_test(method, url, headers, t1, t2, body=None):
    """Fire request with User-1 and User-2 tokens, classify result.

    User-2 never receives the captured Cookie header — only token2 —
    so session-bleed cannot fake a CONFIRMED_IDOR.
    """
    base = _clean_headers(headers)
    h1 = {**base, "Authorization": t1}
    h2 = {**_strip_session_cookies(base), "Authorization": t2}
    # requests' `data=` wants bytes/str, not a dict — body is already a JSON
    # string here (either the original captured text or apply_mutations'
    # json.dumps output), so pass it straight through unchanged.
    body_kw = {"data": body.encode()} if body else {}

    try:
        r1 = req_lib.request(method, url, headers=h1, timeout=TIMEOUT, verify=VERIFY_SSL, **body_kw)
    except Exception as e:
        return {"result": "REQUEST_ERROR", "u1_status": 0, "u2_status": 0,
                "u1_len": 0, "u2_len": 0, "u1_resp": f"[ERR] {e}", "u2_resp": "", "similarity": 0.0}

    try:
        r2 = req_lib.request(method, url, headers=h2, timeout=TIMEOUT, verify=VERIFY_SSL, **body_kw)
    except Exception as e:
        return {"result": "REQUEST_ERROR", "u1_status": r1.status_code, "u2_status": 0,
                "u1_len": len(r1.text), "u2_len": 0,
                "u1_resp": r1.text[:MAX_RESP_CHARS], "u2_resp": f"[ERR] {e}", "similarity": 0.0}

    b1, b2 = r1.text or "", r2.text or ""
    m1, m2 = is_meaningful(b1, r1.status_code), is_meaningful(b2, r2.status_code)
    sim    = response_similarity(b1, b2) if (m1 and m2) else 0.0

    if   r1.status_code != 200:                       result = "NOT_APPLICABLE"
    elif not m1:                                      result = "EMPTY_RESPONSE"
    elif r2.status_code == 200 and m2 and sim >= 0.85: result = "CONFIRMED_IDOR"
    elif r2.status_code == 200 and m2 and sim >= 0.6:  result = "POTENTIAL_IDOR"
    elif r2.status_code in (200, 201) and not m2:     result = "EMPTY_RESPONSE_U2"
    elif r2.status_code in (401, 403):                result = "SAFE"
    elif r2.status_code == 404:                       result = "SAFE_NOT_FOUND"
    else:                                             result = f"INCONCLUSIVE_{r2.status_code}"

    return {
        "result":     result,
        "u1_status":  r1.status_code,
        "u2_status":  r2.status_code,
        "u1_len":     len(b1),
        "u2_len":     len(b2),
        "u1_resp":    b1[:MAX_RESP_CHARS],
        "u2_resp":    b2[:MAX_RESP_CHARS],
        "similarity": round(sim, 3),
    }


def _describe_tested_field(wp, mutated_url, mutated_body, mutated_hdrs):
    """Return (field_label, literal_value_actually_sent) for a weak point —
    the literal value can differ from the raw tested_id (e.g. a formatted
    ID like H-0195, or a re-encoded base64 string), so this re-reads it
    from the actual mutated request rather than assuming str(new_id)."""
    parts = wp.split(":")
    wtype = parts[0]

    if wtype in ("PATH_ID", "PATH_ID_COMPOUND", "PATH_UUID"):
        idx  = int(parts[1])
        segs = urlparse(mutated_url).path.split("/")
        return (f"path segment #{idx}", unquote(segs[idx]) if 0 <= idx < len(segs) else "")
    if wtype == "PATH_PARAM":
        return (parts[1], None)
    if wtype in ("QUERY_ID", "DSL_ID", "DSL_UUID"):
        key = parts[1]
        q   = parse_qs(urlparse(mutated_url).query, keep_blank_values=True)
        return (key, q.get(key, [""])[0])
    if wtype in ("BODY_ID", "BODY_ID_LIST"):
        key  = parts[1]
        bobj = _parse_json_body(mutated_body) or {}
        return (key, bobj.get(key))
    if wtype == "HEADER_ID":
        key = parts[1]
        return (key, (mutated_hdrs or {}).get(key))
    return (wp, None)


# ── Scan runner (background thread) ──────────────────────────────────────────

def _run_scan(job_id, entries, token1, token2, manual_ids=None, include_headers=True, include_body=False):
    job = jobs[job_id]
    t0  = time.time()
    uuid_pool = _harvest_uuids_from_entries(entries)

    # ── Phase 1: detect weak endpoints ───────────────────────────────────────
    seen_norm, seen_raw = set(), set()
    weak_rows = []

    for entry in entries:
        url    = entry.get("url", "")
        method = entry.get("method", "GET").upper()
        body   = entry.get("body") or None
        if not url.startswith("http") or _is_static(url):
            continue
        raw_key = (method, url)
        if raw_key in seen_raw:
            continue
        seen_raw.add(raw_key)

        headers_in = entry.get("headers", {})
        wps = detect_weak_point(url, body if include_body else None, headers_in if include_headers else None)
        if not wps:
            continue
        norm_key = (method, normalize_for_dedup(url))
        if norm_key in seen_norm:
            continue
        seen_norm.add(norm_key)

        weak_rows.append({
            "priority"   : priority_score(url),
            "method"     : method,
            "url"        : url,
            "headers"    : entry.get("headers", {}),
            "body"       : body,
            "weak_points": wps,
        })

    # Sort HIGH → MEDIUM → LOW
    weak_rows.sort(key=lambda r: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(r["priority"], 9))
    job["weak_rows"] = weak_rows
    job["total"]     = len(weak_rows)
    job["total_eps"] = len(weak_rows)

    if not weak_rows:
        job.update({"status": "done", "elapsed": round(time.time()-t0, 1), "progress": 100})
        return

    # ── Phase 2: IDOR testing ─────────────────────────────────────────────────
    logs, findings = [], []

    for idx, row in enumerate(weak_rows):
        if job.get("stopped"):
            break

        method = row["method"]
        url    = row["url"]
        pr     = row["priority"]
        wps    = row["weak_points"]
        hdrs   = dict(row.get("headers", {}))
        body   = row.get("body")

        # Test each detected weak point INDEPENDENTLY — mutate only that one
        # field per request, leaving every other field at its original
        # captured value. A nested-resource URL like /companies/42/employees/1001
        # has two weak points (two PATH_IDs); each gets its own full sweep so
        # the deeper/more-specific ID isn't silently skipped.
        for wp in wps:
            if job.get("stopped"):
                break

            current_id = extract_current_id(url, [wp], body, hdrs)

            if manual_ids:
                # Manual mode: numeric ranges from UI (UUID harvest is Auto-only)
                id_list = [i for i in manual_ids if i != current_id]
            else:
                if current_id is None:
                    # Auto mode but no ID found for this weak point — skip it
                    continue
                if isinstance(current_id, str):
                    # UUID: test current first, then swap other harvested UUIDs
                    others = [u for u in uuid_pool if u != current_id][:MAX_UUID_SWAPS]
                    # Grow pool from this URL itself (nested resources)
                    for u in _harvest_uuids_from_text(url):
                        if u != current_id and u not in others and u != _NIL_UUID:
                            others.append(u)
                    id_list = [current_id] + others[:MAX_UUID_SWAPS]
                else:
                    auto_start = max(1, current_id - AUTO_RANGE)
                    auto_end   = current_id + AUTO_RANGE
                    # Include current_id FIRST — most critical test:
                    # can attacker (User 2) access owner's (User 1) exact resource?
                    others  = [i for i in range(auto_start, auto_end + 1) if i != current_id]
                    id_list = [current_id] + others

            for nid in id_list:
                if job.get("stopped"):
                    break

                mutated_url, mutated_body, mutated_hdrs = apply_mutations(url, [wp], nid, body, hdrs)
                if not mutated_url:
                    continue

                res = idor_test(method, mutated_url, mutated_hdrs, token1, token2, mutated_body)
                time.sleep(REQUEST_DELAY)

                # Harvest more UUIDs from User-1 response for later weak points
                if res.get("u1_resp"):
                    for u in _harvest_uuids_from_text(res["u1_resp"]):
                        if u not in uuid_pool and u != _NIL_UUID:
                            uuid_pool.append(u)

                # Public/shared catalog APIs return the same body for any ID —
                # demote would-be CONFIRMED to avoid false positives.
                if res["result"] == "CONFIRMED_IDOR" and _looks_public_endpoint(
                    method, url, wp, current_id, body, hdrs, token1, res.get("u1_resp") or ""
                ):
                    res = {**res, "result": "SAFE_PUBLIC"}
                    time.sleep(REQUEST_DELAY)

                tested_field, tested_value = _describe_tested_field(wp, mutated_url, mutated_body, mutated_hdrs)
                log_entry = {
                    "priority"    : pr,
                    "method"      : method,
                    "url"         : mutated_url,
                    "original_url": url,
                    "tested_id"   : nid,
                    "current_id"  : current_id,
                    "weak_points" : [wp],
                    "tested_field": tested_field,
                    "tested_value": tested_value,
                    **res,
                }
                logs.append(log_entry)
                job["logs"] = logs[:]

                if res["result"] in ("CONFIRMED_IDOR", "POTENTIAL_IDOR"):
                    findings.append(log_entry)
                    job["findings"] = findings[:]

                # Stop sweeping IDs for THIS weak point once confirmed —
                # still move on to test the endpoint's other weak points.
                # Public endpoints: stop too (further IDs won't change the verdict).
                if res["result"] in ("CONFIRMED_IDOR", "SAFE_PUBLIC"):
                    break

        job["completed"] = idx + 1
        job["elapsed"]   = round(time.time()-t0, 1)
        job["progress"]  = int((idx+1) / len(weak_rows) * 100)

    job.update({
        "status"  : "done",
        "findings": findings,
        "logs"    : logs,
        "elapsed" : round(time.time()-t0, 1),
        "progress": 100,
    })


# ── CSV export safety ─────────────────────────────────────────────────────────

_CSV_FORMULA_LEAD_CHARS = ("=", "+", "-", "@", "\t", "\r")

def _csv_safe(value) -> str:
    """OWASP CSV-injection guard: a cell starting with =/+/-/@ can be
    interpreted as a formula by Excel/Sheets when the export is opened.
    Prefixing with a single quote neutralises it without changing what's
    displayed. URLs and response bodies here come straight from the target
    API under test, so treat them as untrusted."""
    s = str(value)
    return "'" + s if s and s[0] in _CSV_FORMULA_LEAD_CHARS else s


# ── API models & routes ───────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    entries        : list   # [{method, url, headers, body}]  body is a raw JSON string or None
    token1         : str
    token2         : str
    manual_ids     : list = []   # optional explicit IDs to test (empty = Auto ±20 / UUID harvest)
    include_headers: bool = True  # detect+mutate ID-bearing custom headers (customerid, X-User-Id, ...)
    include_body   : bool = False # detect+mutate ID-bearing JSON body fields — off by default:
                                   # real-world request bodies are often large/noisy, making it hard
                                   # to tell which fields are genuine resource IDs worth injecting.


@app.get("/")
def root():
    return {"status": "IDOR Tester Backend running", "port": 8773}


@app.post("/idor/scan")
async def start_scan(req: ScanRequest):
    if not req_lib:
        raise HTTPException(500, "requests library not available")

    t1 = req.token1.strip()
    t2 = req.token2.strip()
    if not t1 or not t2:
        raise HTTPException(400, "Both token1 and token2 are required")

    def norm_token(t):
        if not t:
            return t
        if t.lower().startswith(("bearer ", "basic ", "token ")):
            return t
        return f"Bearer {t}" if t.startswith("eyJ") else t

    t1 = norm_token(t1)
    t2 = norm_token(t2)

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status"   : "scanning",
        "progress" : 0,
        "completed": 0,
        "total"    : len(req.entries),
        "total_eps": 0,
        "findings" : [],
        "logs"     : [],
        "weak_rows": [],
        "elapsed"  : 0,
    }
    threading.Thread(
        target=_run_scan,
        args=(job_id, req.entries, t1, t2, req.manual_ids or []),
        kwargs={"include_headers": req.include_headers, "include_body": req.include_body},
        daemon=True,
    ).start()
    return {"job_id": job_id, "total": len(req.entries)}


@app.post("/idor/stop/{job_id}")
def stop_scan(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    job["stopped"] = True
    return {"status": "stopping"}


@app.get("/idor/progress/{job_id}")
def get_progress(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "status"   : job["status"],
        "progress" : job["progress"],
        "completed": job["completed"],
        "total"    : job.get("total_eps", job["total"]),
        "findings" : job["findings"],
        "logs"     : job["logs"],
        "weak_rows": job.get("weak_rows", []),
        "elapsed"  : job["elapsed"],
    }


@app.get("/idor/csv/{job_id}")
def download_csv(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    buf = io.StringIO()
    w   = csv.writer(buf, quoting=csv.QUOTE_ALL)

    w.writerow(["=== WEAK ENDPOINTS ==="])
    w.writerow(["#", "Priority", "Method", "URL", "Weak Points"])
    for i, r in enumerate(job.get("weak_rows", []), 1):
        wps = ", ".join(r["weak_points"]) if isinstance(r["weak_points"], list) else str(r["weak_points"])
        w.writerow([i, r["priority"], r["method"], _csv_safe(r["url"]), _csv_safe(wps)])

    w.writerow([])
    w.writerow(["=== IDOR TEST RESULTS ==="])
    w.writerow(["#", "Result", "Priority", "Method", "URL", "Tested ID", "Current ID",
                "U1 Status", "U2 Status", "U1 Len", "U2 Len", "Similarity%",
                "U1 Response", "U2 Response"])
    for i, r in enumerate(job.get("logs", []), 1):
        w.writerow([
            i, r["result"], r["priority"], r["method"], _csv_safe(r["url"]),
            r["tested_id"], r["current_id"],
            r["u1_status"], r["u2_status"],
            r["u1_len"], r["u2_len"],
            f"{int(r['similarity']*100)}%",
            _csv_safe(r["u1_resp"][:500]), _csv_safe(r["u2_resp"][:500]),
        ])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=idor_report.csv"},
    )
