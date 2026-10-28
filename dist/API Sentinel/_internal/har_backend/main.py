#!/usr/bin/env python3
"""
HAR Runner Backend — FastAPI
Port: 8766
Chrome Extension ke saath kaam karta hai
HAR.py ki logic use karta hai
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Any, Optional
import json, csv, io, re, time, warnings, urllib.parse
from datetime import datetime
from urllib.parse import urlparse
import httpx

warnings.filterwarnings("ignore")

app = FastAPI(title="HAR Runner Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS  (same logic as HAR.py)
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_header_value(value: str) -> str:
    """Remove non-Latin-1 chars from header values (same as HAR.py)"""
    if isinstance(value, str):
        return value.encode("latin-1", errors="replace").decode("latin-1")
    return str(value)


def build_session() -> httpx.Client:
    # Check if a global proxy is configured in Settings
    _proxy_url = None
    try:
        import proxy_config as _pc
        _px = _pc.get_proxies()
        if _px:
            _proxy_url = _px.get("https") or _px.get("http")
    except Exception:
        pass
    transport = httpx.HTTPTransport(http2=True, retries=2, verify=False)
    if _proxy_url:
        return httpx.Client(proxy=_proxy_url, transport=transport, timeout=30, verify=False)
    return httpx.Client(transport=transport, timeout=30)


def get_status_class(code) -> str:
    try:
        c = int(code)
        if c < 300: return "2xx"
        if c < 400: return "3xx"
        if c < 500: return "4xx"
        return "5xx"
    except Exception:
        return "error"


def clean_string(val):
    """Remove illegal control characters (same as HAR.py clean_excel_string)"""
    if isinstance(val, str):
        return re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F]", "", val)
    return val


# HTTP/2 pseudo-headers + hop-by-hop headers that requests library cannot send
_HAR_INVALID_HEADERS = {
    "host", "content-length", "accept-encoding",
    "connection", "authorization", "transfer-encoding",
    "upgrade", "keep-alive", "proxy-connection",
}

def _har_invalid_header(name: str) -> bool:
    """Return True for headers that must be stripped before firing request."""
    n = name.lower().strip()
    if n.startswith(":"):       # HTTP/2 pseudo-headers: :authority :method :path :scheme
        return True
    if n in _HAR_INVALID_HEADERS:
        return True
    if any(c in name for c in (" ", "\t", "\n", "\r")):  # control chars in name
        return True
    return False


def _header_pop_ci(headers: dict, name: str):
    """Remove every key that matches name, case-insensitively."""
    target = name.lower()
    for k in [k for k in headers if k.lower() == target]:
        headers.pop(k, None)


def _header_has_ci(headers: dict, name: str) -> bool:
    target = name.lower()
    return any(k.lower() == target for k in headers)


def _header_set_ci(headers: dict, name: str, value: str):
    """Set a header once — drop any existing case-variant so httpx cannot send duplicates."""
    _header_pop_ci(headers, name)
    headers[name] = value


def _guess_content_type(payload: str) -> str:
    s = (payload or "").lstrip()
    if s.startswith("{") or s.startswith("["):
        return "application/json"
    if "=" in (payload or "") and not s.startswith("<"):
        return "application/x-www-form-urlencoded"
    return "application/json"


def _build_fire_headers(extra_headers: dict, bearer_token: str, payload: str) -> dict:
    """Single-copy request headers. HAR values win; defaults only fill gaps."""
    headers: dict = {}
    for k, v in (extra_headers or {}).items():
        if not k or _har_invalid_header(k):
            continue
        _header_set_ci(headers, k, sanitize_header_value(v))

    if not _header_has_ci(headers, "accept"):
        _header_set_ci(headers, "Accept", "application/json, text/plain, */*")
    if not _header_has_ci(headers, "user-agent"):
        _header_set_ci(headers, "User-Agent", "Mozilla/5.0")

    has_body = bool(payload)
    if has_body and not _header_has_ci(headers, "content-type"):
        _header_set_ci(headers, "Content-Type", _guess_content_type(payload))

    _header_pop_ci(headers, "authorization")
    if bearer_token:
        clean_tok = str(bearer_token).strip()
        if clean_tok.lower().startswith("bearer "):
            clean_tok = clean_tok[7:].strip()
        if clean_tok:
            _header_set_ci(headers, "Authorization", f"Bearer {clean_tok}")
    return headers


_MAX_BODY_CHARS = 1_048_576  # 1 MB — keep the UI/report from eating RAM


def _decode_response_body(resp) -> str:
    """Pretty-print JSON when possible; never squash newlines or clip at 2 KB."""
    try:
        body = json.dumps(resp.json(), ensure_ascii=False, indent=2)
    except Exception:
        body = (resp.text or "").strip()
    if len(body) > _MAX_BODY_CHARS:
        return body[:_MAX_BODY_CHARS] + "\n… [truncated at 1 MB]"
    return body


def fire_api(session: httpx.Client, method: str, url: str,
             payload: str, bearer_token: str, extra_headers: dict,
             timeout: int = 10):
    """Execute one API call with HTTP/2 support via httpx."""
    headers = _build_fire_headers(extra_headers, bearer_token, payload)

    # Sanitize payload
    if payload and isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace").decode("utf-8")

    start = time.time()
    try:
        resp = session.request(
            method, url,
            headers=headers,
            content=payload.encode("utf-8") if payload else None,
            timeout=timeout,
        )
        elapsed = int((time.time() - start) * 1000)
        return resp.status_code, _decode_response_body(resp), elapsed, headers
    except httpx.TimeoutException:
        return "TIMEOUT", "Request timed out", int((time.time() - start) * 1000), headers
    except Exception as e:
        return "ERROR", str(e)[:500], int((time.time() - start) * 1000), headers


# ─────────────────────────────────────────────────────────────────────────────
#  HTML REPORT  (same style as HAR.py save_results_to_html)
# ─────────────────────────────────────────────────────────────────────────────

def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def fmt_size(n):
    if not isinstance(n, (int, float)):
        return "0 B"
    if n < 1024:
        return f"{int(n)} B"
    if n < 1024 * 1024:
        return f"{n/1024:.1f} KB"
    return f"{n/(1024*1024):.2f} MB"

def generate_html_report(results: list, meta: dict) -> str:
    total      = len(results)
    success    = sum(1 for r in results if isinstance(r.get("status_code"), int) and 200 <= r["status_code"] < 300)
    redirect   = sum(1 for r in results if isinstance(r.get("status_code"), int) and 300 <= r["status_code"] < 400)
    client_err = sum(1 for r in results if isinstance(r.get("status_code"), int) and 400 <= r["status_code"] < 500)
    server_err = sum(1 for r in results if isinstance(r.get("status_code"), int) and r["status_code"] >= 500)
    errors     = sum(1 for r in results if not isinstance(r.get("status_code"), int))

    # Group requests by endpoint (METHOD URL)
    grouped = {}
    for idx, r in enumerate(results):
        m = (r.get("method") or "GET").upper()
        u = (r.get("url") or "").strip()
        key = f"{m} {u}"
        grouped.setdefault(key, []).append((idx, r))

    diff_indices = set()
    diff_keys = set()
    same_indices = set()
    same_keys = set()
    for key, items in grouped.items():
        if len(items) >= 2:
            sizes = [
                item[1].get("response_size") if item[1].get("response_size") is not None 
                else (len(item[1].get("response", "").encode("utf-8")) if item[1].get("response") else 0)
                for item in items
            ]
            if len(set(sizes)) > 1:
                diff_keys.add(key)
                for item in items:
                    diff_indices.add(item[0])

            ok_items = [
                (item[0], item[1], sizes[s_idx])
                for s_idx, item in enumerate(items)
                if isinstance(item[1].get("status_code"), int) and 200 <= item[1]["status_code"] < 300
            ]
            if len(ok_items) >= 2 and len(set(x[2] for x in ok_items)) == 1:
                same_keys.add(key)
                for x in ok_items:
                    same_indices.add(x[0])

    unique_users = []
    seen_users = set()
    for r in results:
        u_name = r.get("user_name") or (f"User {r.get('user_id')}" if r.get("user_id") else r.get("mode", "authorized"))
        if u_name not in seen_users:
            seen_users.add(u_name)
            unique_users.append(u_name)

    user_options = "".join(f'<option value="{esc(u)}">👤 {esc(u)}</option>' for u in unique_users)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    token_mode   = meta.get("token_mode", "authorized")
    token_label  = {"authorized": "✅ Authorized", "unauthorized": "❌ Unauthorized", "both": "🔄 Both", "multi_user": f"👥 Multi-User ({meta.get('users_count', '')} Users)"}.get(token_mode, token_mode)

    rows_html = ""
    for i, r in enumerate(results, 1):
        code = r.get("status_code")
        sc   = str(code)
        if sc.startswith("2"):   bc = "badge-2xx"
        elif sc.startswith("3"): bc = "badge-3xx"
        elif sc.startswith("4"): bc = "badge-4xx"
        elif sc.startswith("5"): bc = "badge-5xx"
        else:                    bc = "badge-error"

        method = r.get("method","GET")
        mc     = method.lower()
        url    = esc(r.get("url",""))
        req_b  = esc(r.get("request_body","") or "(no body)")
        resp_b = esc(r.get("response","") or "(no response)")
        elapsed= r.get("elapsed_ms", 0)
        mode   = r.get("mode", "authorized")
        user_name = r.get("user_name") or (f"User {r.get('user_id')}" if r.get("user_id") else mode)
        is_r_unauth = bool(r.get("is_unauth") or r.get("mode") == "unauthorized")
        is_r_2xx = isinstance(code, int) and 200 <= code < 300
        is_r_blocked = isinstance(code, int) and code >= 400
        bypass_badge = ""
        if is_r_unauth and is_r_2xx:
            bypass_badge = '<span style="font-size:9.5px;padding:2px 7px;border-radius:4px;background:rgba(248,81,73,0.25);color:#f85149;font-weight:700;border:1px solid rgba(248,81,73,0.45);white-space:nowrap">🚨 AUTH BYPASS</span>'
        elif is_r_unauth and is_r_blocked:
            bypass_badge = f'<span style="font-size:9.5px;padding:2px 7px;border-radius:4px;background:rgba(248,81,73,0.18);color:#f85149;font-weight:700;white-space:nowrap">🛡️ Blocked ({sc})</span>'
        user_badge = f'<span class="badge" style="background:rgba(88,166,255,0.15);color:#58a6ff;font-size:10px;white-space:nowrap">👤 {esc(user_name)}</span>{bypass_badge}'
        detail_id  = f"d{i}"

        resp_size = r.get("response_size")
        if resp_size is None:
            resp_size = len(r.get("response", "").encode("utf-8")) if r.get("response") else 0

        is_diff = (i - 1) in diff_indices
        is_same = (i - 1) in same_indices

        size_badges = []
        if is_diff:
            size_badges.append('<span style="font-size:9px;padding:1px 5px;border-radius:4px;background:rgba(163,113,247,0.2);color:#d2a8ff;font-weight:700">DIFF</span>')
        if is_same:
            size_badges.append('<span style="font-size:9px;padding:1px 5px;border-radius:4px;background:rgba(56,189,248,0.2);color:#7dd3fc;font-weight:700">SAME</span>')
        size_badge = (' ' + ' '.join(size_badges)) if size_badges else ''

        row_classes = []
        if is_diff: row_classes.append("is-diff-row")
        if is_same: row_classes.append("is-same-row")
        if is_r_unauth and is_r_2xx: row_classes.append("is-diff-row")
        row_class = (" " + " ".join(row_classes)) if row_classes else ""

        # Build Multi-User Matrix if endpoint has multiple runs/users
        ep_key = f"{(r.get('method') or 'GET').upper()} {(r.get('url') or '').strip()}"
        ep_items = grouped.get(ep_key, [])
        matrix_html = ""
        if len(ep_items) > 1:
            base_idx, base_item = ep_items[0]
            base_size = base_item.get("response_size")
            if base_size is None:
                base_size = len(base_item.get("response", "").encode("utf-8")) if base_item.get("response") else 0
            base_user = base_item.get("user_name") or (f"User {base_item.get('user_id')}" if base_item.get("user_id") else base_item.get("mode", "authorized"))

            m_rows = []
            for item_idx, (orig_i, item_r) in enumerate(ep_items):
                i_uname = item_r.get("user_name") or (f"User {item_r.get('user_id')}" if item_r.get("user_id") else item_r.get("mode", "authorized"))
                i_sc = item_r.get("status_code")
                i_sc_str = str(i_sc)
                if i_sc_str.startswith("2"):   i_bc = "badge-2xx"
                elif i_sc_str.startswith("4"): i_bc = "badge-4xx"
                elif i_sc_str.startswith("5"): i_bc = "badge-5xx"
                else:                          i_bc = "badge-error"

                i_size = item_r.get("response_size")
                if i_size is None:
                    i_size = len(item_r.get("response", "").encode("utf-8")) if item_r.get("response") else 0
                i_time = item_r.get("elapsed_ms", 0)

                is_curr = (orig_i == (i - 1))
                curr_badge = '<span class="matrix-curr-badge" style="font-size:9px;padding:1px 6px;border-radius:3px;background:rgba(88,166,255,0.25);color:#58a6ff;font-weight:700;display:inline-flex;align-items:center;white-space:nowrap">● Current</span>' if is_curr else ''

                is_i_unauth = bool(item_r.get("is_unauth") or item_r.get("mode") == "unauthorized")
                is_i_2xx = isinstance(i_sc, int) and 200 <= i_sc < 300

                if item_idx == 0:
                    delta_str = '<span style="color:#8b949e">Baseline</span>'
                    if is_i_unauth and is_i_2xx:
                        sig_tag = f'<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(248,81,73,0.22);color:#f85149;border:1px solid rgba(248,81,73,0.45);font-weight:700;white-space:nowrap">🚨 AUTH BYPASS (Expected 403, got {i_sc})</span>'
                    elif is_i_unauth and isinstance(i_sc, int) and i_sc >= 400:
                        sig_tag = f'<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(248,81,73,0.18);color:#f85149;font-weight:700;white-space:nowrap">🛡️ Protected ({i_sc})</span>'
                    else:
                        sig_tag = '<span style="color:#8b949e;font-size:10px;white-space:nowrap">Primary Reference</span>'
                else:
                    if is_i_unauth and is_i_2xx:
                        sig_tag = f'<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(248,81,73,0.22);color:#f85149;border:1px solid rgba(248,81,73,0.45);font-weight:700;white-space:nowrap">🚨 AUTH BYPASS (Expected 403, got {i_sc})</span>'
                    elif is_i_unauth and isinstance(i_sc, int) and i_sc >= 400:
                        sig_tag = f'<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(248,81,73,0.18);color:#f85149;font-weight:700;white-space:nowrap">🛡️ Protected ({i_sc})</span>'
                    else:
                        delta = i_size - base_size
                        if delta == 0:
                            delta_str = '<span style="color:#7dd3fc;font-weight:600">±0 B (0%)</span>'
                            is_2xx_both = (isinstance(i_sc, int) and 200 <= i_sc < 300 and isinstance(base_item.get("status_code"), int) and 200 <= base_item["status_code"] < 300)
                            if is_2xx_both:
                                sig_tag = '<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(56,189,248,0.2);color:#7dd3fc;font-weight:700;white-space:nowrap">⚠️ SAME SIZE (Potential IDOR)</span>'
                            else:
                                sig_tag = '<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(255,255,255,0.06);color:#8b949e;white-space:nowrap">Identical Size</span>'
                        else:
                            sign = "+" if delta > 0 else ""
                            pct = f" ({sign}{(delta/base_size)*100:.1f}%)" if base_size > 0 else ""
                            delta_str = f'<span style="color:#d2a8ff;font-weight:600">{sign}{fmt_size(delta)}{pct}</span>'
                            is_2xx_both = (isinstance(i_sc, int) and 200 <= i_sc < 300 and isinstance(base_item.get("status_code"), int) and 200 <= base_item["status_code"] < 300)
                            if is_2xx_both:
                                sig_tag = '<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(163,113,247,0.2);color:#d2a8ff;font-weight:700;white-space:nowrap">✓ SIZE DIFF (Different Data)</span>'
                            elif isinstance(i_sc, int) and i_sc >= 400:
                                sig_tag = f'<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(248,81,73,0.18);color:#f85149;font-weight:700;white-space:nowrap">🛡️ Blocked ({i_sc})</span>'
                            else:
                                sig_tag = '<span style="font-size:9.5px;padding:3px 8px;border-radius:4px;background:rgba(163,113,247,0.2);color:#d2a8ff;white-space:nowrap">Size Diff</span>'
                    if item_idx > 0 and (is_i_unauth and (is_i_2xx or (isinstance(i_sc, int) and i_sc >= 400))):
                        delta = i_size - base_size
                        sign = "+" if delta > 0 else ""
                        pct = f" ({sign}{(delta/base_size)*100:.1f}%)" if base_size > 0 else ""
                        delta_str = f'<span style="color:#8b949e">{sign}{fmt_size(delta)}{pct}</span>' if delta != 0 else '<span style="color:#8b949e">±0 B</span>'

                m_row_bg = "background:rgba(88,166,255,0.08);" if is_curr else ""
                curr_cls = " is-curr-matrix-row" if is_curr else ""
                m_rows.append(f"""
                <tr class="matrix-item-row{curr_cls}" data-orig-idx="{orig_i}" style="{m_row_bg};height:46px;cursor:pointer" onclick="switchMatrixUser({orig_i}, '{detail_id}', this)" title="Click to view User {esc(i_uname)} request & response">
                  <td style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.06);border-left:none!important;white-space:nowrap">
                    <div style="display:inline-flex;align-items:center;gap:6px">
                      <span class="badge" style="background:rgba(88,166,255,0.15);color:#58a6ff;font-size:10.5px">👤 {esc(i_uname)}</span>
                      <span class="matrix-curr-slot">{curr_badge}</span>
                      <button type="button" class="btn-jump-row" onclick="event.stopPropagation(); jumpToTableRow({orig_i}, '{detail_id}')" title="Jump to row #{orig_i+1} in table" style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);color:#8b949e;font-size:10px;padding:1px 6px;border-radius:4px;cursor:pointer;font-family:monospace">↗ #{orig_i+1}</button>
                    </div>
                  </td>
                  <td style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.06);border-left:none!important;white-space:nowrap"><span class="badge {i_bc}">{esc(i_sc_str)}</span></td>
                  <td style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.06);border-left:none!important;font-family:Consolas,monospace;white-space:nowrap">{fmt_size(i_size)} <span style="font-size:9.5px;color:#8b949e">({i_size} B)</span></td>
                  <td style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.06);border-left:none!important;font-family:Consolas,monospace;white-space:nowrap">{delta_str}</td>
                  <td style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.06);border-left:none!important;font-family:Consolas,monospace;color:#8b949e;white-space:nowrap">{i_time}ms</td>
                  <td style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.06);border-left:none!important;white-space:nowrap">{sig_tag}</td>
                </tr>""")

            matrix_table_rows = "".join(m_rows)
            matrix_html = f"""
            <div style="background:#070b12;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-bottom:14px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #21262d">
                <span style="font-size:11px;font-weight:700;color:#e6edf3">⚖️ Multi-User Response Size Matrix ({len(ep_items)} Users Tested)</span>
                <span style="font-size:10px;color:#8b949e;font-family:Consolas,monospace">{esc(method)} {esc(url)}</span>
              </div>
              <div style="overflow-x:auto">
                <table style="width:100%;border-collapse:collapse;font-size:11.5px;background:#0d1117">
                  <thead>
                    <tr style="background:#161b22">
                      <th style="padding:11px 16px;text-align:left;font-size:10.5px;color:#8b949e;border-bottom:1px solid #30363d;border-left:none!important;white-space:nowrap;width:22%">User</th>
                      <th style="padding:11px 16px;text-align:left;font-size:10.5px;color:#8b949e;border-bottom:1px solid #30363d;border-left:none!important;white-space:nowrap;width:10%">Status</th>
                      <th style="padding:11px 16px;text-align:left;font-size:10.5px;color:#8b949e;border-bottom:1px solid #30363d;border-left:none!important;white-space:nowrap;width:18%">Response Size</th>
                      <th style="padding:11px 16px;text-align:left;font-size:10.5px;color:#8b949e;border-bottom:1px solid #30363d;border-left:none!important;white-space:nowrap;width:18%" title="Baseline: {esc(base_user)}">Delta vs Base</th>
                      <th style="padding:11px 16px;text-align:left;font-size:10.5px;color:#8b949e;border-bottom:1px solid #30363d;border-left:none!important;white-space:nowrap;width:12%">Latency</th>
                      <th style="padding:11px 16px;text-align:left;font-size:10.5px;color:#8b949e;border-bottom:1px solid #30363d;border-left:none!important;white-space:nowrap;width:20%">Comparison / Signal</th>
                    </tr>
                  </thead>
                  <tbody>{matrix_table_rows}</tbody>
                </table>
              </div>
            </div>"""

        rows_html += f"""
<tr class="main-row{row_class}" data-code="{esc(sc)}" data-mode="{mode}" data-user="{esc(user_name)}" data-diff="{'1' if is_diff else '0'}" data-same="{'1' if is_same else '0'}" data-detail="{detail_id}" onclick="toggleDet('{detail_id}',this)">
  <td>{i}</td>
  <td><span class="badge {bc}">{esc(sc)}</span></td>
  <td><span class="method-badge m-{mc}">{esc(method)}</span></td>
  <td style="white-space:nowrap"><div style="display:inline-flex;align-items:center;gap:6px">{user_badge}</div></td>
  <td class="url-cell" title="{url}">{url}</td>
  <td style="color:#718096;font-size:11px;font-family:monospace" data-val="{elapsed}">{elapsed}ms</td>
  <td style="color:#8b949e;font-size:11px;font-family:monospace" data-val="{resp_size}">{fmt_size(resp_size)}{size_badge}</td>
</tr>
<tr id="{detail_id}" class="detail-row" style="display:none">
  <td colspan="7" style="padding:12px;background:#0a0e18;border-bottom:2px solid #2d3748">
    {matrix_html}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div class="rep-panel rep-req-panel" style="background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden">
        <div style="padding:6px 10px;background:#161b22;font-size:11px;font-weight:700;color:#58a6ff;border-bottom:1px solid #21262d">📤 Request Body</div>
        <pre class="rep-req-pre" style="padding:10px;font-size:11px;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow-y:auto;margin:0;font-family:Consolas,monospace">{req_b}</pre>
      </div>
      <div class="rep-panel rep-resp-panel" style="background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden">
        <div class="rep-resp-title" style="padding:6px 10px;background:#161b22;font-size:11px;font-weight:700;color:#58a6ff;border-bottom:1px solid #21262d">📥 Response Body ({fmt_size(resp_size)})</div>
        <pre class="rep-resp-pre" style="padding:10px;font-size:11px;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow-y:auto;margin:0;font-family:Consolas,monospace">{resp_b}</pre>
      </div>
    </div>
  </td>
</tr>"""

    safe_results_json = json.dumps(results, ensure_ascii=False).replace("</script>", "<\\/script>").replace("<!--", "<\\!--")

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Auth Validator Pro Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Space+Grotesk:wght@400;600;700&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  ::-webkit-scrollbar{{width:6px;height:6px}} ::-webkit-scrollbar-track{{background:#0d1117}} ::-webkit-scrollbar-thumb{{background:#30363d;border-radius:3px}}
  body{{font-family:'Space Grotesk',sans-serif;background:#080c10;color:#c9d1d9;padding:0;min-height:100vh;display:flex;flex-direction:column}}
  body.diff-mode{{height:100vh;max-height:100vh;overflow:hidden}}
  body.diff-mode .footer{{display:none}}
  body.diff-mode #diffViewWrap{{display:flex;flex:1 1 auto;min-height:0;height:calc(100vh - 210px);max-height:calc(100vh - 210px);overflow:hidden}}
  .header{{padding:20px 32px 14px;border-bottom:1px solid #21262d;background:#0d1117}}
  h1{{font-size:20px;font-weight:700;background:linear-gradient(135deg,#1f6feb,#58a6ff,#79c0ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}}
  .meta{{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:#6e7681}}
  .meta span b{{color:#8b949e}}
  .stats{{display:flex;gap:10px;padding:14px 32px;flex-wrap:wrap;background:#080c10}}
  .card{{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px 16px;text-align:center;min-width:85px;position:relative;overflow:hidden}}
  .card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
  .card.total::before{{background:#58a6ff}}.card.ok::before{{background:#238636}}.card.redir::before{{background:#6f42c1}}
  .card.warn::before{{background:#d29922}}.card.fail::before{{background:#da3633}}.card.err::before{{background:#6e7681}}
  .card.diff::before{{background:#a371f7}}.card.same::before{{background:#38bdf8}}
  .num{{font-size:20px;font-weight:700;margin-bottom:2px}}
  .lbl{{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.5px}}
  .card.total .num{{color:#58a6ff}}.card.ok .num{{color:#3fb950}}.card.redir .num{{color:#bc8cff}}
  .card.warn .num{{color:#d29922}}.card.fail .num{{color:#f85149}}.card.err .num{{color:#6e7681}}
  .card.diff .num{{color:#d2a8ff}}.card.same .num{{color:#7dd3fc}}

  .view-toggle-bar{{display:flex;gap:8px;padding:12px 32px 0;background:#0d1117;border-bottom:1px solid #21262d}}
  .view-btn{{padding:8px 16px;border-radius:6px 6px 0 0;border:1px solid transparent;background:transparent;color:#8b949e;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s;margin-bottom:-1px}}
  .view-btn:hover{{color:#e6edf3}}
  .view-btn.active{{background:#080c10;border-color:#30363d;border-bottom-color:#080c10;color:#58a6ff}}

  .toolbar{{padding:10px 32px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;border-bottom:1px solid #21262d;background:#080c10}}
  .toolbar input{{flex:1;min-width:200px;padding:6px 12px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:11.5px;outline:none}}
  .toolbar input:focus{{border-color:#58a6ff}}
  .toolbar select{{padding:6px 10px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:11px;cursor:pointer;outline:none}}
  .toolbar select:focus{{border-color:#58a6ff}}
  .filter-btns{{display:flex;gap:6px;flex-wrap:wrap}}
  .fbtn{{padding:5px 11px;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#8b949e;font-size:11px;cursor:pointer;transition:all .15s}}
  .fbtn:hover,.fbtn.active{{background:#21262d;color:#fff;border-color:#58a6ff}}
  .fbtn.f-2xx.active{{background:#238636;border-color:#3fb950;color:#fff}}
  .fbtn.f-3xx.active{{background:#6f42c1;border-color:#bc8cff;color:#fff}}
  .fbtn.f-4xx.active{{background:#7b341e;border-color:#f85149;color:#fff}}
  .fbtn.f-5xx.active{{background:#742a2a;border-color:#da3633;color:#fff}}
  .fbtn.f-err.active{{background:#3d1515;border-color:#6e7681;color:#fff}}
  .fbtn.f-diff.active{{background:rgba(163,113,247,0.25);border-color:#a371f7;color:#d2a8ff}}
  .fbtn.f-same.active{{background:rgba(56,189,248,0.22);border-color:#38bdf8;color:#7dd3fc}}

  .table-wrap{{padding:0 32px 32px;overflow-x:auto;margin-top:12px;flex:1}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  thead tr{{background:#161b22}}
  th{{padding:9px 12px;text-align:left;color:#6e7681;font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:.5px;border-bottom:2px solid #30363d;white-space:nowrap}}
  th.sortable{{cursor:pointer;user-select:none;transition:color .15s}}
  th.sortable:hover{{color:#58a6ff}}
  td{{padding:8px 12px;border-bottom:1px solid #161b22;vertical-align:middle;transition:background .15s}}
  tr.main-row{{cursor:pointer}}
  tr.main-row:hover td{{background:#0d1117}}
  tr.main-row.is-diff-row td{{background:rgba(163,113,247,0.05)}}
  tr.main-row.is-diff-row:hover td{{background:rgba(163,113,247,0.12)}}
  tr.main-row.is-same-row td{{background:rgba(56,189,248,0.04)}}
  tr.main-row.is-same-row:hover td{{background:rgba(56,189,248,0.1)}}
  tr.main-row.is-expanded td{{background:rgba(88,166,255,0.12)!important;border-bottom-color:rgba(88,166,255,0.35)!important}}
  tr.main-row.is-expanded td:first-child{{border-left:3px solid #58a6ff!important;color:#58a6ff!important;font-weight:700}}
  tr.main-row.is-expanded .url-cell{{color:#ffffff!important;font-weight:600;text-shadow:0 0 8px rgba(88,166,255,0.4)}}
  tr.detail-row > td{{border-left:3px solid #58a6ff!important}}
  tr.hidden{{display:none}}
  .url-cell{{max-width:380px;word-break:break-all;color:#79c0ff;font-size:11px;font-family:monospace}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;white-space:nowrap;font-family:monospace}}
  .badge-2xx{{background:rgba(35,134,54,.2);color:#3fb950}}.badge-3xx{{background:rgba(111,66,193,.2);color:#bc8cff}}
  .badge-4xx{{background:rgba(218,54,51,.2);color:#f85149}}.badge-5xx{{background:rgba(248,81,73,.2);color:#f85149}}
  .badge-error{{background:rgba(110,118,129,.2);color:#6e7681}}
  .method-badge{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;white-space:nowrap;font-family:monospace}}
  .m-get{{background:rgba(31,111,235,.15);color:#58a6ff}}.m-post{{background:rgba(35,134,54,.15);color:#3fb950}}
  .m-put{{background:rgba(210,153,34,.15);color:#d29922}}.m-patch{{background:rgba(188,140,255,.15);color:#bc8cff}}
  .m-delete{{background:rgba(248,81,73,.15);color:#f85149}}
  .no-results{{text-align:center;color:#4a5568;padding:40px;font-size:14px}}

  /* Split Compare View */
  #diffViewWrap{{display:none;flex:1;min-height:0;height:calc(100vh - 210px);max-height:calc(100vh - 210px);overflow:hidden;background:#080c10}}
  .diff-split-container{{display:flex;width:100%;height:100%;min-height:0;max-height:100%;overflow:hidden}}
  .diff-sidebar{{width:340px;min-width:280px;max-width:420px;height:100%;max-height:100%;border-right:1px solid #21262d;display:flex;flex-direction:column;background:#0d1117;flex-shrink:0;overflow:hidden}}
  .diff-sidebar-head{{padding:10px;border-bottom:1px solid #21262d;display:flex;flex-direction:column;gap:8px}}
  .diff-sidebar-head input{{width:100%;background:#080c10;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:11px;outline:none}}
  .diff-sidebar-head input:focus{{border-color:#58a6ff}}
  .diff-filter-pills{{display:flex;gap:4px}}
  .diff-pill{{background:#161b22;border:1px solid #30363d;color:#8b949e;font-size:10px;padding:3px 8px;border-radius:12px;cursor:pointer;transition:all .15s}}
  .diff-pill:hover{{color:#e6edf3;border-color:#8b949e}}
  .diff-pill.active{{background:rgba(88,166,255,0.15);border-color:#58a6ff;color:#58a6ff;font-weight:700}}
  .diff-api-list{{flex:1;overflow-y:auto;padding:8px;display:flex;flex-direction:column;gap:6px}}
  .diff-api-item{{padding:8px 10px;border-radius:6px;border:1px solid #21262d;background:#080c10;cursor:pointer;transition:all .15s;display:flex;flex-direction:column;gap:4px}}
  .diff-api-item:hover{{border-color:rgba(88,166,255,0.4);background:rgba(88,166,255,0.05)}}
  .diff-api-item.active{{border-color:#58a6ff;background:rgba(88,166,255,0.12);box-shadow:0 0 10px rgba(88,166,255,0.15)}}
  .diff-api-item-top{{display:flex;align-items:center;justify-content:space-between;gap:6px}}
  .diff-api-item-url{{font-family:Consolas,monospace;font-size:11px;color:#c9d1d9;word-break:break-all;line-height:1.3}}
  .diff-api-item-meta{{display:flex;align-items:center;justify-content:space-between;font-size:10px;color:#8b949e}}
  .diff-tag{{display:inline-block;font-size:9.5px;padding:1px 6px;border-radius:4px;font-weight:700;white-space:nowrap}}
  .diff-tag.same{{background:rgba(56,189,248,0.2);color:#7dd3fc}}
  .diff-tag.diff{{background:rgba(163,113,247,0.2);color:#d2a8ff}}
  .diff-tag.neutral{{background:rgba(255,255,255,0.06);color:#8b949e}}
  .diff-tag.bypass{{background:rgba(248,81,73,0.22);color:#f85149;border:1px solid rgba(248,81,73,0.45)}}

  .diff-main{{flex:1;display:flex;flex-direction:column;min-height:0;height:100%;max-height:100%;overflow:hidden;background:#080c10}}
  .diff-header{{padding:12px 16px;border-bottom:1px solid #21262d;background:#0d1117;display:flex;flex-direction:column;gap:10px;flex-shrink:0}}
  .diff-title-row{{display:flex;align-items:center;gap:10px;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px;box-shadow:inset 0 1px 3px rgba(0,0,0,0.3);overflow:hidden}}
  .diff-title-row .method-badge{{font-size:11px;padding:3px 8px;border-radius:4px;flex-shrink:0}}
  .diff-url-text{{font-family:Consolas,'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:#79c0ff;word-break:normal;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}}
  .diff-controls-row{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
  .diff-user-sel{{display:flex;align-items:center;gap:6px}}
  .diff-user-sel label{{font-size:11px;color:#8b949e;font-weight:600}}
  .diff-user-sel select{{background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:600;outline:none;cursor:pointer;max-width:220px}}
  .diff-swap-btn{{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;transition:all .15s}}
  .diff-swap-btn:hover{{border-color:#58a6ff;color:#58a6ff}}

  .diff-banner{{padding:8px 12px;border-radius:6px;font-size:11.5px;display:flex;align-items:center;justify-content:space-between;gap:10px;font-weight:600;border:1px solid #30363d;background:#161b22}}
  .diff-banner.idor{{background:rgba(56,189,248,0.12);border-color:rgba(56,189,248,0.4);color:#7dd3fc}}
  .diff-banner.diff{{background:rgba(163,113,247,0.12);border-color:rgba(163,113,247,0.4);color:#d2a8ff}}
  .diff-banner.blocked{{background:rgba(248,81,73,0.12);border-color:rgba(248,81,73,0.4);color:#f85149}}
  .diff-banner.match{{background:rgba(88,166,255,0.1);border-color:rgba(88,166,255,0.35);color:#79c0ff}}

  .diff-panels-grid{{flex:1 1 0;display:grid;grid-template-columns:1fr 1fr;grid-template-rows:1fr;gap:12px;padding:12px;min-height:0;height:100%;max-height:100%;overflow:hidden;box-sizing:border-box}}
  .diff-panel{{display:flex;flex-direction:column;background:#0d1117;border:1px solid #30363d;border-radius:8px;min-height:0;height:100%;max-height:100%;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.3)}}
  .diff-panel-title{{padding:8px 12px;background:#161b22;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:8px;font-size:11px;font-weight:600;flex-shrink:0}}
  .diff-pre-scroll{{flex:1 1 0;min-height:0;height:100%;max-height:100%;overflow:auto;background:#090d13}}
  .diff-pre{{min-height:100%;padding:14px;box-sizing:border-box;margin:0;font-family:Consolas,monospace;font-size:11px;line-height:1.5;color:#c9d1d9;white-space:pre-wrap;word-break:break-all}}
  .btn-sm-rep{{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:600;cursor:pointer;flex-shrink:0;transition:all .15s}}
  .btn-sm-rep:hover{{border-color:#58a6ff;color:#58a6ff;background:#161b22}}
  .matrix-item-row:hover td {{ background: rgba(88,166,255,0.06); }}
  .matrix-item-row.is-curr-matrix-row td {{ background: rgba(88,166,255,0.1) !important; }}
  .matrix-item-row.is-curr-matrix-row:hover td {{ background: rgba(88,166,255,0.14) !important; }}
  .btn-jump-row {{ transition: all .15s; }}
  .btn-jump-row:hover {{ background: rgba(88,166,255,0.2) !important; border-color: rgba(88,166,255,0.45) !important; color: #58a6ff !important; }}
  @keyframes repPulse {{
    0% {{ opacity: 0.6; }}
    100% {{ opacity: 1; }}
  }}
  .rep-panel-updated {{
    animation: repPulse 0.25s ease-out;
  }}
  .footer{{text-align:center;padding:14px;color:#484f58;font-size:11px;border-top:1px solid #161b22;margin-top:auto}}
</style>
<script>
var RAW_RESULTS = {safe_results_json};

function formatPreBody(b) {{
  if (b == null || b === '') return '(empty)';
  if (typeof b === 'object') {{
    try {{ return JSON.stringify(b, null, 2); }} catch(e) {{ return String(b); }}
  }}
  try {{
    var p = JSON.parse(b);
    return JSON.stringify(p, null, 2);
  }} catch(e) {{
    return String(b);
  }}
}}

function switchMatrixUser(origIdx, detId, clickedRow) {{
  var detRow = document.getElementById(detId);
  if (!detRow) return;
  var r = RAW_RESULTS[origIdx];
  if (!r) return;

  var allMRows = detRow.querySelectorAll('.matrix-item-row');
  allMRows.forEach(function(mr) {{
    mr.style.background = '';
    mr.classList.remove('is-curr-matrix-row');
    var slot = mr.querySelector('.matrix-curr-slot');
    if (slot) slot.innerHTML = '';
  }});

  clickedRow.style.background = 'rgba(88,166,255,0.12)';
  clickedRow.classList.add('is-curr-matrix-row');
  var mySlot = clickedRow.querySelector('.matrix-curr-slot');
  if (mySlot) {{
    mySlot.innerHTML = '<span class="matrix-curr-badge" style="font-size:9px;padding:1px 6px;border-radius:3px;background:rgba(88,166,255,0.25);color:#58a6ff;font-weight:700;display:inline-flex;align-items:center;white-space:nowrap">● Current</span>';
  }}

  var reqPre = detRow.querySelector('.rep-req-pre');
  var respPre = detRow.querySelector('.rep-resp-pre');
  var respTitle = detRow.querySelector('.rep-resp-title');

  if (reqPre) reqPre.textContent = formatPreBody(r.request_body);
  var sz = r.response_size != null ? r.response_size : (r.response ? (typeof r.response === 'string' ? r.response.length : JSON.stringify(r.response).length) : 0);
  if (respTitle) respTitle.textContent = '📥 Response Body (' + formatBytes(sz) + ')';
  if (respPre) respPre.textContent = formatPreBody(r.response == null || r.response === '' ? '(no response)' : r.response);

  detRow.querySelectorAll('.rep-panel').forEach(function(p) {{
    p.classList.remove('rep-panel-updated');
    void p.offsetWidth;
    p.classList.add('rep-panel-updated');
  }});
}}

function jumpToTableRow(origIdx, curDetId) {{
  var targetDetId = 'd' + (origIdx + 1);
  var targetMainRow = document.querySelector('tr.main-row[data-detail="' + targetDetId + '"]');
  var curDetRow = document.getElementById(curDetId);
  var curMainRow = curDetRow ? curDetRow.previousElementSibling : null;
  if (targetMainRow) {{
    if (curDetRow && curDetRow.style.display !== 'none' && targetDetId !== curDetId && curMainRow) {{
      toggleDet(curDetId, curMainRow);
    }}
    var trgDet = document.getElementById(targetDetId);
    if (trgDet && trgDet.style.display === 'none') {{
      toggleDet(targetDetId, targetMainRow);
    }}
    targetMainRow.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
  }}
}}

function toggleDet(id, row){{
  var dr=document.getElementById(id);
  if(!dr) return;
  var open=dr.style.display!=='none';
  dr.style.display=open?'none':'table-row';
  row.classList.toggle('is-expanded',!open);
}}

var currentFilter='all';
function setFilter(f,btn){{
  currentFilter=f;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}}

function switchView(view){{
  var isTable = (view === 'table');
  document.body.classList.toggle('diff-mode', !isTable);
  document.getElementById('viewBtnTable').classList.toggle('active', isTable);
  document.getElementById('viewBtnDiff').classList.toggle('active', !isTable);
  document.getElementById('tableToolbar').style.display = isTable ? 'flex' : 'none';
  document.getElementById('tableContainer').style.display = isTable ? 'block' : 'none';
  document.getElementById('diffViewWrap').style.display = isTable ? 'none' : 'flex';
  if(!isTable && !window._diffInitialized){{
    window._diffInitialized = true;
    initDiffView();
  }}
}}

function applyFilters(){{
  var q=(document.getElementById('searchBox').value||'').toLowerCase().trim();
  var uEl=document.getElementById('userFilter');
  var uVal=uEl?uEl.value:'all';
  var cEl=document.getElementById('compFilter');
  var compVal=cEl?cEl.value:'all';

  var rows=document.querySelectorAll('tr.main-row');
  var visible=0;
  rows.forEach(function(row){{
    var code=row.dataset.code||'';
    var user=row.dataset.user||'';
    var isDiff=row.dataset.diff==='1';
    var isSame=row.dataset.same==='1';
    var text=row.textContent.toLowerCase();
    var dr=row.nextElementSibling;
    var detailText=(dr&&dr.classList.contains('detail-row'))?dr.textContent.toLowerCase():'';
    
    var mf=true;
    if(currentFilter==='2xx') mf=/^2/.test(code);
    else if(currentFilter==='3xx') mf=/^3/.test(code);
    else if(currentFilter==='4xx') mf=/^4/.test(code);
    else if(currentFilter==='5xx') mf=/^5/.test(code);
    else if(currentFilter==='error') mf=!/^[0-9]/.test(code);
    else if(currentFilter==='diff') mf=isDiff;
    else if(currentFilter==='same') mf=isSame;
    
    var mu=uVal==='all'||user===uVal;
    var mc=true;
    if(compVal==='any_diff') mc=isDiff;
    else if(compVal==='all_same') mc=isSame;

    var ms=!q||text.includes(q)||detailText.includes(q);
    var show=mf&&mu&&mc&&ms;
    row.classList.toggle('hidden',!show);
    if(dr&&dr.classList.contains('detail-row')&&!show) dr.style.display='none';
    if(show) visible++;
  }});
  document.getElementById('noResults').style.display=visible===0?'block':'none';
}}

var sortField = null, sortDir = 'asc';
function sortTable(field) {{
  if (sortField === field) {{
    sortDir = sortDir === 'asc' ? 'desc' : 'asc';
  }} else {{
    sortField = field;
    sortDir = 'asc';
  }}
  var tbody = document.getElementById('tableBody');
  var rows = Array.from(tbody.querySelectorAll('tr.main-row'));
  var colIndex = field === 'time' ? 5 : 6;
  rows.sort(function(a, b) {{
    var aCell = a.children[colIndex];
    var bCell = b.children[colIndex];
    var aVal = parseFloat(aCell.getAttribute('data-val') || '0');
    var bVal = parseFloat(bCell.getAttribute('data-val') || '0');
    return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
  }});
  rows.forEach(function(row) {{
    var drId = row.getAttribute('data-detail');
    var dr = drId ? document.getElementById(drId) : null;
    tbody.appendChild(row);
    if (dr) tbody.appendChild(dr);
  }});
  document.getElementById('timeArrow').textContent = sortField === 'time' ? (sortDir === 'asc' ? '▲' : '▼') : '⬍';
  document.getElementById('sizeArrow').textContent = sortField === 'size' ? (sortDir === 'asc' ? '▲' : '▼') : '⬍';
}}

/* Interactive Compare Diff View Logic */
var diffEpMap = {{}};
var diffActiveKey = null;
var diffFilterPill = 'all';

function formatBytes(n) {{
  if (typeof n !== 'number' || isNaN(n)) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}}

function initDiffView() {{
  diffEpMap = {{}};
  RAW_RESULTS.forEach(function(r, idx) {{
    var m = (r.method || 'GET').toUpperCase();
    var u = (r.url || '').trim();
    var key = m + ' ' + u;
    if (!diffEpMap[key]) {{
      diffEpMap[key] = {{ key: key, method: m, url: u, rows: [] }};
    }}
    var sz = r.response_size != null ? r.response_size : ((r.response || '').length);
    var sc = r.status_code;
    var is2xx = typeof sc === 'number' && sc >= 200 && sc < 300;
    var uname = r.user_name || (r.user_id ? ('User ' + r.user_id) : 'User');
    diffEpMap[key].rows.push({{
      idx: idx,
      r: r,
      sc: sc,
      size: sz,
      userName: uname,
      userId: r.user_id || ('u_' + idx),
      is2xx: is2xx,
      isUnauth: !!(r.is_unauth || r.mode === 'unauthorized')
    }});
  }});

  renderDiffSidebar();
  var keys = Object.keys(diffEpMap);
  if (keys.length > 0) {{
    selectDiffEndpoint(keys[0]);
  }}
}}

function setDiffPill(pill, btn) {{
  diffFilterPill = pill;
  document.querySelectorAll('.diff-pill').forEach(function(p) {{ p.classList.remove('active'); }});
  btn.classList.add('active');
  renderDiffSidebar();
}}

function filterDiffList() {{
  renderDiffSidebar();
}}

function renderDiffSidebar() {{
  var container = document.getElementById('diffApiList');
  if (!container) return;
  var q = (document.getElementById('diffSearch').value || '').toLowerCase().trim();
  var html = '';
  var keys = Object.keys(diffEpMap);

  keys.forEach(function(epKey) {{
    var ep = diffEpMap[epKey];
    var sizes = ep.rows.map(function(x) {{ return x.size; }});
    var isDiff = ep.rows.length >= 2 && (new Set(sizes)).size > 1;
    var okSizes = ep.rows.filter(function(x) {{ return x.is2xx; }}).map(function(x) {{ return x.size; }});
    var isSame = okSizes.length >= 2 && (new Set(okSizes)).size === 1;
    var hasBypass = ep.rows.some(function(x) {{ return x.isUnauth && x.is2xx; }});

    if (diffFilterPill === 'diff' && !isDiff) return;
    if (diffFilterPill === 'same' && !isSame) return;
    if (q && !epKey.toLowerCase().includes(q)) return;

    var tagHtml = '';
    if (hasBypass) tagHtml = '<span class="diff-tag bypass">🚨 Bypass</span>';
    else if (isSame) tagHtml = '<span class="diff-tag same">⚠️ IDOR Risk</span>';
    else if (isDiff) tagHtml = '<span class="diff-tag diff">⚖️ Diff</span>';
    else tagHtml = '<span class="diff-tag neutral">● Normal</span>';

    var minSz = Math.min.apply(null, sizes);
    var maxSz = Math.max.apply(null, sizes);
    var szLabel = minSz === maxSz ? formatBytes(minSz) : (formatBytes(minSz) + ' ~ ' + formatBytes(maxSz));
    var isSel = (diffActiveKey === epKey);

    html += '<div class="diff-api-item' + (isSel ? ' active' : '') + '" onclick="selectDiffEndpoint(\\'' + encodeURIComponent(epKey) + '\\')">' +
      '<div class="diff-api-item-top">' +
        '<span class="method-badge m-' + ep.method.toLowerCase() + '">' + ep.method + '</span>' +
        '<span class="diff-api-item-url">' + ep.url + '</span>' +
        tagHtml +
      '</div>' +
      '<div class="diff-api-item-meta">' +
        '<span>👥 ' + ep.rows.length + ' Users</span>' +
        '<span>' + szLabel + '</span>' +
      '</div>' +
    '</div>';
  }});

  if (!html) html = '<div style="padding:20px;text-align:center;color:#6e7681;font-size:11px">No matching APIs.</div>';
  container.innerHTML = html;
}}

function selectDiffEndpoint(encodedKey) {{
  var key = decodeURIComponent(encodedKey);
  diffActiveKey = key;
  renderDiffSidebar();
  var ep = diffEpMap[key];
  if (!ep) return;

  document.getElementById('diffPlaceholder').style.display = 'none';
  document.getElementById('diffContent').style.display = 'flex';
  document.getElementById('diffMethodBadge').textContent = ep.method;
  document.getElementById('diffMethodBadge').className = 'method-badge m-' + ep.method.toLowerCase();
  document.getElementById('diffUrlText').textContent = ep.url;
  document.getElementById('diffUrlText').title = ep.url;

  var selA = document.getElementById('diffSelectA');
  var selB = document.getElementById('diffSelectB');
  var opts = '';
  ep.rows.forEach(function(row, idx) {{
    opts += '<option value="' + idx + '">👤 ' + row.userName + ' (' + row.sc + ', ' + formatBytes(row.size) + ')</option>';
  }});
  selA.innerHTML = opts;
  selB.innerHTML = opts;
  selA.value = '0';
  selB.value = ep.rows.length > 1 ? '1' : '0';

  updateDiffPanels();
}}

function swapDiffUsers() {{
  var selA = document.getElementById('diffSelectA');
  var selB = document.getElementById('diffSelectB');
  var vA = selA.value;
  selA.value = selB.value;
  selB.value = vA;
  updateDiffPanels();
}}

function updateDiffPanels() {{
  var ep = diffEpMap[diffActiveKey];
  if (!ep) return;
  var selA = document.getElementById('diffSelectA');
  var selB = document.getElementById('diffSelectB');
  var idxA = parseInt(selA.value || '0', 10);
  var idxB = parseInt(selB.value || '0', 10);
  var itemA = ep.rows[idxA] || ep.rows[0];
  var itemB = ep.rows[idxB] || ep.rows[ep.rows.length - 1];
  if (!itemA || !itemB) return;

  document.getElementById('diffPanelTitleA').innerHTML = '👤 ' + itemA.userName;
  document.getElementById('diffPanelMetaA').innerHTML = 'Status: <b style="color:' + (itemA.is2xx ? '#3fb950' : '#f85149') + '">' + itemA.sc + '</b> · Size: <b>' + formatBytes(itemA.size) + '</b> (' + itemA.size + ' B) · ' + itemA.r.elapsed_ms + 'ms';

  document.getElementById('diffPanelTitleB').innerHTML = '👤 ' + itemB.userName;
  document.getElementById('diffPanelMetaB').innerHTML = 'Status: <b style="color:' + (itemB.is2xx ? '#3fb950' : '#f85149') + '">' + itemB.sc + '</b> · Size: <b>' + formatBytes(itemB.size) + '</b> (' + itemB.size + ' B) · ' + itemB.r.elapsed_ms + 'ms';

  var banner = document.getElementById('diffBanner');
  var isBoth2xx = itemA.is2xx && itemB.is2xx;
  var isOneBlocked = (!itemA.is2xx && itemB.is2xx) || (itemA.is2xx && !itemB.is2xx);
  var delta = itemB.size - itemA.size;
  var isBypassA = itemA.isUnauth && itemA.is2xx;
  var isBypassB = itemB.isUnauth && itemB.is2xx;

  if (itemA.userId === itemB.userId) {{
    banner.className = 'diff-banner match';
    banner.innerHTML = '<span>ℹ️ Same user selected for both sides. Select 2 different users to compare responses.</span>';
  }} else if (isBypassA || isBypassB) {{
    banner.className = 'diff-banner idor';
    var bpUser = isBypassA ? itemA : itemB;
    var otherUser = isBypassA ? itemB : itemA;
    banner.innerHTML = '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:18px">🚨</span><div><div><b>CRITICAL AUTH BYPASS:</b> ' + bpUser.userName + ' was marked Unauthorized (Expected 403), but received <b>HTTP ' + bpUser.sc + ' OK</b>!</div><div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Endpoint returned full payload (' + formatBytes(bpUser.size) + ') without proper authorization enforcement. Baseline ' + otherUser.userName + ' received ' + otherUser.sc + ' (' + formatBytes(otherUser.size) + ').</div></div></div><span class="diff-tag bypass">🚨 AUTH BYPASS</span>';
  }} else if (isBoth2xx && delta === 0) {{
    banner.className = 'diff-banner idor';
    banner.innerHTML = '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:18px">⚠️</span><div><div><b>POTENTIAL IDOR / DATA LEAK:</b> Both users received identical 200 OK responses (' + formatBytes(itemA.size) + ')</div><div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Both ' + itemA.userName + ' and ' + itemB.userName + ' accessed the exact same payload size. Verify tenant isolation.</div></div></div><span class="diff-tag same">IDOR SIGNAL</span>';
  }} else if (isBoth2xx && delta !== 0) {{
    banner.className = 'diff-banner diff';
    var sign = delta > 0 ? '+' : '';
    banner.innerHTML = '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:18px">✓</span><div><div><b>RESPONSE SIZE DIFF:</b> Different data returned (' + formatBytes(itemA.size) + ' vs ' + formatBytes(itemB.size) + ')</div><div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">Delta: <b>' + sign + formatBytes(delta) + '</b> · Both returned 2xx OK</div></div></div><span class="diff-tag diff">SIZE DIFF</span>';
  }} else if (isOneBlocked) {{
    banner.className = 'diff-banner blocked';
    var blkUser = !itemA.is2xx ? itemA : itemB;
    var okUser = itemA.is2xx ? itemA : itemB;
    var isExp = blkUser.isUnauth;
    var bTitle = isExp ? 'PROTECTED (ACCESS CONTROL ENFORCED)' : 'ACCESS CONTROL ENFORCED';
    banner.innerHTML = '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:18px">🛡️</span><div><div><b>' + bTitle + ':</b> ' + blkUser.userName + ' was blocked (' + blkUser.sc + ') as expected</div><div style="font-size:10px;opacity:0.85;font-weight:400;margin-top:2px">' + okUser.userName + ' received ' + okUser.sc + ' (' + formatBytes(okUser.size) + '), while ' + blkUser.userName + ' received HTTP ' + blkUser.sc + '.</div></div></div><span class="diff-tag" style="background:rgba(248,81,73,0.18);color:#f85149">BLOCKED (' + blkUser.sc + ')</span>';
  }} else {{
    banner.className = 'diff-banner match';
    banner.innerHTML = '<span>Status: ' + itemA.sc + ' vs ' + itemB.sc + ' · Size: ' + formatBytes(itemA.size) + ' vs ' + formatBytes(itemB.size) + '</span>';
  }}

  document.getElementById('diffPreA').textContent = itemA.r.response || '(no response)';
  document.getElementById('diffPreB').textContent = itemB.r.response || '(no response)';
}}

function copyCurUrl() {{
  var u = document.getElementById('diffUrlText').textContent || '';
  navigator.clipboard.writeText(u).then(function() {{
    var btn = document.getElementById('diffCopyUrlBtn');
    btn.textContent = '✓ Copied!';
    setTimeout(function() {{ btn.textContent = 'Copy URL'; }}, 1400);
  }});
}}

function copyPanelText(preId, btn) {{
  var txt = document.getElementById(preId).textContent || '';
  navigator.clipboard.writeText(txt).then(function() {{
    var orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(function() {{ btn.textContent = orig; }}, 1400);
  }});
}}

function searchDiffPre(preId, query) {{
  var pre = document.getElementById(preId);
  if (!pre) return;
  var ep = diffEpMap[diffActiveKey];
  if (!ep) return;
  var sel = preId === 'diffPreA' ? document.getElementById('diffSelectA') : document.getElementById('diffSelectB');
  var idx = parseInt(sel.value || '0', 10);
  var row = ep.rows[idx] || ep.rows[0];
  var raw = row ? (row.r.response || '(no response)') : '';
  var q = (query || '').trim();
  if (!q) {{ pre.textContent = raw; return; }}
  var escQ = q.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&');
  var safeRaw = raw.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  pre.innerHTML = safeRaw.replace(new RegExp(escQ, 'gi'), function(m) {{
    return '<mark style="background:#58a6ff;color:#000;border-radius:2px">' + m + '</mark>';
  }});
}}

window.addEventListener('DOMContentLoaded', applyFilters);
</script>
</head>
<body>
<div class="header">
  <h1>🔍 Auth Validator Pro — Execution Report</h1>
  <div class="meta">
    <span><b>Generated:</b> {generated_at}</span>
    <span><b>Total APIs:</b> {total}</span>
    <span><b>Token Mode:</b> {token_label}</span>
  </div>
</div>
<div class="stats">
  <div class="card total"><div class="num">{total}</div><div class="lbl">Total</div></div>
  <div class="card ok"><div class="num">{success}</div><div class="lbl">2xx OK</div></div>
  <div class="card diff"><div class="num">{len(diff_keys)}</div><div class="lbl">Size Diff</div></div>
  <div class="card same"><div class="num">{len(same_keys)}</div><div class="lbl">Size Same</div></div>
  <div class="card redir"><div class="num">{redirect}</div><div class="lbl">3xx</div></div>
  <div class="card warn"><div class="num">{client_err}</div><div class="lbl">4xx</div></div>
  <div class="card fail"><div class="num">{server_err}</div><div class="lbl">5xx</div></div>
  <div class="card err"><div class="num">{errors}</div><div class="lbl">Errors</div></div>
</div>
<div class="view-toggle-bar">
  <button type="button" class="view-btn active" id="viewBtnTable" onclick="switchView('table')">📋 All Requests ({total})</button>
  <button type="button" class="view-btn" id="viewBtnDiff" onclick="switchView('diff')">⚖️ Compare APIs &amp; Responses ({len(grouped)} unique)</button>
</div>
<div class="toolbar" id="tableToolbar">
  <div class="filter-btns">
    <button class="fbtn active" onclick="setFilter('all',this)">All</button>
    <button class="fbtn f-2xx" onclick="setFilter('2xx',this)">✓ 2xx</button>
    <button class="fbtn f-4xx" onclick="setFilter('4xx',this)">⚠ 4xx</button>
    <button class="fbtn f-5xx" onclick="setFilter('5xx',this)">✗ 5xx</button>
    <button class="fbtn f-err" onclick="setFilter('error',this)">⚡ Error</button>
    <button class="fbtn f-diff" onclick="setFilter('diff',this)">⚖️ Any Size Diff ({len(diff_keys)})</button>
    <button class="fbtn f-same" onclick="setFilter('same',this)">📋 All Sizes Same ({len(same_keys)})</button>
  </div>
  <select id="userFilter" onchange="applyFilters()">
    <option value="all">👥 All Users ({total})</option>
    {user_options}
  </select>
  <select id="compFilter" onchange="applyFilters()">
    <option value="all">⚖️ All Comparisons</option>
    <option value="any_diff">⚖️ Any Size Diff ({len(diff_keys)})</option>
    <option value="all_same">📋 All Sizes Same ({len(same_keys)})</option>
  </select>
  <input type="text" id="searchBox" placeholder="🔍 Search URL or response…" oninput="applyFilters()">
</div>
<div class="table-wrap" id="tableContainer">
  <table>
    <thead><tr>
      <th style="width:40px">#</th>
      <th style="width:90px">Status</th>
      <th style="width:80px">Method</th>
      <th style="width:165px">User</th>
      <th>URL</th>
      <th class="sortable" style="width:75px" onclick="sortTable('time')" title="Click to sort by Time">Time <span id="timeArrow">⬍</span></th>
      <th class="sortable" style="width:85px" onclick="sortTable('size')" title="Click to sort by Response Size">Size <span id="sizeArrow">⬍</span></th>
    </tr></thead>
    <tbody id="tableBody">{rows_html}</tbody>
  </table>
  <div class="no-results" id="noResults" style="display:none">No matching results.</div>
</div>

<!-- Split Compare APIs & Responses View Container -->
<div id="diffViewWrap">
  <div class="diff-split-container">
    <div class="diff-sidebar">
      <div class="diff-sidebar-head">
        <input type="text" id="diffSearch" placeholder="🔍 Search API endpoints..." oninput="filterDiffList()">
        <div class="diff-filter-pills">
          <button type="button" class="diff-pill active" data-p="all" onclick="setDiffPill('all',this)">All</button>
          <button type="button" class="diff-pill" data-p="diff" onclick="setDiffPill('diff',this)">⚖️ Diff Only</button>
          <button type="button" class="diff-pill" data-p="same" onclick="setDiffPill('same',this)">⚠️ Same Only</button>
        </div>
      </div>
      <div class="diff-api-list" id="diffApiList"></div>
    </div>
    <div class="diff-main" id="diffMain">
      <div id="diffPlaceholder" style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#6e7681;text-align:center;padding:40px">
        <div style="font-size:32px;margin-bottom:8px">⚖️</div>
        <div style="font-size:14px;font-weight:600;color:#c9d1d9">Select an API from the list to compare user responses</div>
        <div style="font-size:11px;color:#8b949e;margin-top:4px">Compare full response bodies, HTTP status codes, and payload sizes between any 2 users</div>
      </div>
      <div id="diffContent" style="display:none;flex:1;flex-direction:column;height:100%;min-height:0;overflow:hidden">
        <div class="diff-header">
          <div class="diff-title-row">
            <span class="method-badge" id="diffMethodBadge">GET</span>
            <span class="diff-url-text" id="diffUrlText"></span>
            <button type="button" class="btn-sm-rep" id="diffCopyUrlBtn" style="margin-left:auto" onclick="copyCurUrl()">Copy URL</button>
          </div>
          <div class="diff-controls-row">
            <div class="diff-user-sel">
              <label>User A (Baseline):</label>
              <select id="diffSelectA" onchange="updateDiffPanels()"></select>
            </div>
            <button type="button" class="diff-swap-btn" onclick="swapDiffUsers()" title="Swap users">⇄ Swap</button>
            <div class="diff-user-sel">
              <label>User B (Compare):</label>
              <select id="diffSelectB" onchange="updateDiffPanels()"></select>
            </div>
          </div>
          <div class="diff-banner" id="diffBanner"></div>
        </div>
        <div class="diff-panels-grid">
          <div class="diff-panel">
            <div class="diff-panel-title">
              <span id="diffPanelTitleA">👤 User A</span>
              <span id="diffPanelMetaA" style="font-size:10px;color:#8b949e;font-family:Consolas,monospace"></span>
              <div style="display:flex;gap:4px;margin-left:auto;align-items:center">
                <button type="button" class="btn-sm-rep" onclick="copyPanelText('diffPreA',this)">Copy</button>
                <input type="text" style="width:120px;padding:2px 6px;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#e6edf3;font-size:10px" placeholder="🔍 Search..." oninput="searchDiffPre('diffPreA',this.value)">
              </div>
            </div>
            <div class="diff-pre-scroll"><pre class="diff-pre" id="diffPreA"></pre></div>
          </div>
          <div class="diff-panel">
            <div class="diff-panel-title">
              <span id="diffPanelTitleB">👤 User B</span>
              <span id="diffPanelMetaB" style="font-size:10px;color:#8b949e;font-family:Consolas,monospace"></span>
              <div style="display:flex;gap:4px;margin-left:auto;align-items:center">
                <button type="button" class="btn-sm-rep" onclick="copyPanelText('diffPreB',this)">Copy</button>
                <input type="text" style="width:120px;padding:2px 6px;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#e6edf3;font-size:10px" placeholder="🔍 Search..." oninput="searchDiffPre('diffPreB',this.value)">
              </div>
            </div>
            <div class="diff-pre-scroll"><pre class="diff-pre" id="diffPreB"></pre></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<div class="footer">Auth Validator Pro — API Sentinel Auto-generated report</div>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────

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


def _extract_query_keys(raw_url: str) -> list:
    keys = set()
    if not raw_url:
        return []
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


def _get_api_signature(method: str, url: str, payload: Optional[str] = None) -> str:
    m = (method or "GET").upper().strip()
    raw_url = (url or "").strip()
    if not raw_url:
        return ""

    u = _normalize_url(raw_url)
    q_keys = _extract_query_keys(raw_url)
    q_sig = f"?{'&'.join(q_keys)}" if q_keys else ""

    paths = _extract_body_paths(payload) if payload else []
    unique_sorted_paths = sorted(list(set(filter(None, paths))))
    paths_count = len(unique_sorted_paths)
    paths_hash = _hash_string(",".join(unique_sorted_paths)) if paths_count > 0 else ""

    disc = _find_discriminator(payload)

    if not q_sig and paths_count == 0 and not disc:
        return f"{m} {u}"

    parts = [f"{m} {u}{q_sig}"]
    if paths_count > 0:
        parts.append(f"params:{paths_count}:{paths_hash}")
    if disc:
        parts.append(f"disc:{disc}")
    return "|".join(parts)


class UserConfig(BaseModel):
    id: str = "user_1"
    name: str = "User 1"
    token: Optional[str] = ""
    is_unauth: bool = False

class ApiEntry(BaseModel):
    id: Optional[str] = None
    method: str
    url: str
    headers: dict = {}
    payload: Optional[str] = None   # raw body string

class RunRequest(BaseModel):
    apis: list[ApiEntry]
    users: Optional[list[UserConfig]] = None
    bearer_token: Optional[str] = ""                # backward compatibility
    unauth_token: Optional[str] = ""                # backward compatibility
    token_mode: Optional[str] = "authorized"        # backward compatibility
    url_filter: Optional[str] = ""                  # e.g. "apim" — filter APIs by URL substring
    deduplicate: bool = True


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "HAR Runner Backend running", "version": "1.0.0", "port": 8766}


def _prepare_apis(req: RunRequest) -> list[ApiEntry]:
    """Apply URL filter + dedupe."""
    apis = list(req.apis)

    if req.url_filter:
        apis = [a for a in apis if req.url_filter.lower() in a.url.lower()]

    if req.deduplicate:
        seen = set()
        deduped = []
        for a in apis:
            key = _get_api_signature(a.method, a.url, a.payload)
            if key not in seen:
                seen.add(key)
                deduped.append(a)
        apis = deduped

    return apis


def _count_planned(apis: list[ApiEntry], req: RunRequest) -> int:
    if req.users and len(req.users) > 0:
        return len(apis) * len(req.users)
    per = 2 if req.token_mode == "both" else 1
    return len(apis) * per


def _summarize_results(results: list, apis_run: int, token_mode: str = "multi_user", users_count: int = 1) -> dict:
    total = len(results)
    success = sum(1 for r in results if isinstance(r["status_code"], int) and 200 <= r["status_code"] < 300)
    client_err = sum(1 for r in results if isinstance(r["status_code"], int) and 400 <= r["status_code"] < 500)
    server_err = sum(1 for r in results if isinstance(r["status_code"], int) and r["status_code"] >= 500)
    errors = sum(1 for r in results if not isinstance(r["status_code"], int))
    return {
        "total": total,
        "success": success,
        "client_errors": client_err,
        "server_errors": server_err,
        "network_errors": errors,
        "apis_run": apis_run,
        "token_mode": token_mode,
        "users_count": users_count,
    }


def _fire_one(session: httpx.Client, api: ApiEntry, token: str, mode: str, user_id: str = "user_1", user_name: str = "User 1", is_unauth: bool = False) -> dict:
    code, body, elapsed, headers = fire_api(
        session, api.method.upper(), api.url,
        api.payload or "", token, api.headers
    )
    size_bytes = 0
    if body:
        size_bytes = len(body.encode("utf-8", errors="replace")) if isinstance(body, str) else len(body)
    return {
        "method": api.method.upper(),
        "url": api.url,
        "request_body": clean_string(api.payload or ""),
        "status_code": code,
        "response": clean_string(body),
        "response_size": size_bytes,
        "elapsed_ms": elapsed,
        "mode": mode,
        "user_id": user_id,
        "user_name": user_name,
        "is_unauth": is_unauth,
        "status_class": get_status_class(code),
        "headers": headers or {},
    }


def _iter_run_jobs(apis: list[ApiEntry], req: RunRequest):
    """Yield (api, token, mode, user_id, user_name, is_unauth) for each planned request."""
    if req.users and len(req.users) > 0:
        for api in apis:
            for u in req.users:
                tok = (u.token or "").strip()
                name = u.name or f"User {u.id}"
                mode = "unauthorized" if u.is_unauth else "authorized"
                yield api, tok, mode, u.id, name, bool(u.is_unauth)
    else:
        for api in apis:
            if req.token_mode in ("authorized", "both"):
                yield api, req.bearer_token, "authorized", "user_1", "Authorized", False
            if req.token_mode in ("unauthorized", "both"):
                yield api, req.unauth_token or "", "unauthorized", "user_2", "Unauthorized", True


@app.post("/run")
def run_apis(req: RunRequest):
    """Fire all selected APIs with given bearer token(s)"""
    apis = _prepare_apis(req)
    if not apis:
        raise HTTPException(400, "No APIs to run after filtering/deduplication")

    session = build_session()
    results = []
    users_cnt = len(req.users) if req.users else (2 if req.token_mode == "both" else 1)
    try:
        for api, token, mode, uid, uname, is_unauth in _iter_run_jobs(apis, req):
            results.append(_fire_one(session, api, token, mode, uid, uname, is_unauth))
            time.sleep(0.12)
    finally:
        session.close()

    return {
        "results": results,
        "summary": _summarize_results(results, len(apis), req.token_mode, users_cnt),
        "aborted": False,
    }


@app.post("/run-stream")
async def run_apis_stream(req: RunRequest, request: Request):
    """Stream each API result as NDJSON for live feed + early abort."""
    apis = _prepare_apis(req)
    if not apis:
        raise HTTPException(400, "No APIs to run after filtering/deduplication")

    total_expected = _count_planned(apis, req)
    users_cnt = len(req.users) if req.users else (2 if req.token_mode == "both" else 1)

    async def event_gen():
        session = build_session()
        results = []
        aborted = False
        try:
            yield json.dumps({
                "type": "start",
                "total_expected": total_expected,
                "apis_run": len(apis),
                "token_mode": req.token_mode,
                "users_count": users_cnt,
            }) + "\n"

            for api, token, mode, uid, uname, is_unauth in _iter_run_jobs(apis, req):
                if await request.is_disconnected():
                    aborted = True
                    break

                row = _fire_one(session, api, token, mode, uid, uname, is_unauth)
                results.append(row)
                summary = _summarize_results(results, len(apis), req.token_mode, users_cnt)
                yield json.dumps({
                    "type": "result",
                    "result": row,
                    "done": len(results),
                    "total_expected": total_expected,
                    "summary": summary,
                }, default=str) + "\n"

                if await request.is_disconnected():
                    aborted = True
                    break

                time.sleep(0.12)

            yield json.dumps({
                "type": "done",
                "aborted": aborted,
                "results": results,
                "summary": _summarize_results(results, len(apis), req.token_mode, users_cnt),
            }, default=str) + "\n"
        except GeneratorExit:
            pass
        except Exception as e:
            yield json.dumps({"type": "error", "message": str(e)}, default=str) + "\n"
        finally:
            session.close()

    return StreamingResponse(
        event_gen(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/export/html")
def export_html(payload: dict):
    results = payload.get("results", [])
    meta    = payload.get("summary", {})
    html    = generate_html_report(results, meta)
    return StreamingResponse(
        io.BytesIO(html.encode("utf-8")),
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=har_runner_report.html"}
    )


@app.post("/export/csv")
def export_csv(payload: dict):
    results = payload.get("results", [])
    output  = io.StringIO()
    fields  = ["id", "status_code", "method", "user_name", "diff_status", "url", "elapsed_ms", "response_size", "request_body", "response"]
    writer  = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()

    # Precalculate diff statuses
    grouped = {}
    for idx, r in enumerate(results):
        m = (r.get("method") or "GET").upper()
        u = (r.get("url") or "").strip()
        grouped.setdefault(f"{m} {u}", []).append(r)

    diff_status_map = {}
    for key, items in grouped.items():
        if len(items) >= 2:
            sizes = [
                item.get("response_size") if item.get("response_size") is not None
                else (len(item.get("response", "").encode("utf-8")) if item.get("response") else 0)
                for item in items
            ]
            ok_items = [
                (item, sizes[s_idx])
                for s_idx, item in enumerate(items)
                if isinstance(item.get("status_code"), int) and 200 <= item["status_code"] < 300
            ]
            if len(set(sizes)) > 1:
                diff_status_map[key] = "SIZE_DIFF"
            elif len(ok_items) >= 2 and len(set(x[1] for x in ok_items)) == 1:
                diff_status_map[key] = "SAME_SIZE_IDOR"

    for i, r in enumerate(results, 1):
        m = (r.get("method") or "GET").upper()
        u = (r.get("url") or "").strip()
        key = f"{m} {u}"
        d_status = diff_status_map.get(key, "-")

        raw_req = str(r.get("request_body") or "")
        raw_res = str(r.get("response") or "")

        # Flatten newlines so spreadsheet software (WPS / Excel) keeps each row strictly on 1 line!
        clean_req = re.sub(r'[\r\n]+', ' ', raw_req).strip()
        clean_res = re.sub(r'[\r\n]+', ' ', raw_res).strip()
        if len(clean_res) > 3000:
            clean_res = clean_res[:3000] + " ...[truncated]"

        user_name = r.get("user_name") or (f"User {r.get('user_id')}" if r.get("user_id") else r.get("mode", "authorized"))

        row = {
            "id": i,
            "status_code": r.get("status_code", ""),
            "method": m,
            "user_name": user_name,
            "diff_status": d_status,
            "url": u,
            "elapsed_ms": r.get("elapsed_ms", 0),
            "response_size": r.get("response_size", 0),
            "request_body": clean_req,
            "response": clean_res,
        }
        writer.writerow(row)

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=har_runner_report.csv"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8766, reload=True)
