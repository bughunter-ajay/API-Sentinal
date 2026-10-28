"""
Shared cURL command parser — mirrors the upgraded API Validator / APISphere JS parser.

Postman-grade robustness:
  • Handles any cURL format (Bash, Zsh, CMD, PowerShell, DevTools, Swagger, Postman, Charles, Proxyman).
  • Strips markdown code blocks (```bash ... ```), leading comments (# / //), shell prompts ($, #, PS>, cmd>).
  • Handles line continuations with trailing spaces (\\, `, ^).
  • Preserves large (4500+ lines) multi-line JSON/GraphQL/Form bodies without quote corruption or premature termination.
  • Smart quote handling (apostrophes inside double-quoted JSON strings never close outer single quotes).
  • Supports trailing commas, control chars, and single-quoted Python-dict JSON payloads.
  • Supports short option values (-H..., -d..., -u..., -b...), long option equals (--flag=value with re.DOTALL),
    clustered flags (-kLsS), and empty semicolon headers (--header 'crutag;').
  • Supports OAuth2 Bearer tokens (--oauth2-bearer <token>).
"""

from __future__ import annotations

import ast
import base64
import json
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, unquote_plus, urlparse, parse_qs


_SKIP_NO_ARG = {
    "--compressed", "--insecure", "-k", "--location", "-L", "--location-trusted",
    "--silent", "-s", "--show-error", "-S", "--verbose", "-v", "--no-buffer", "-N",
    "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3",
    "--fail", "-f", "--remote-name", "-O", "--remote-header-name", "-J",
    "--include", "-i", "--raw", "--globoff", "-g",
    "--path-as-is", "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3",
    "--ssl", "--ssl-reqd",
}

_SKIP_ONE_ARG = {
    "-o", "--output", "-m", "--max-time", "--connect-timeout", "--retry",
    "--retry-delay", "--retry-max-time",
    "--proxy", "-x", "--cert", "--key", "--cacert", "--capath", "--passwd",
    "--write-out", "-w", "--stderr", "--trace", "--trace-ascii",
    "--resolve", "--connect-to", "--unix-socket", "--abstract-unix-socket",
    "--cert-type", "--key-type", "--engine", "--ciphers", "--tls-max",
    "--limit-rate", "--keepalive-time", "--max-redirs", "--proto", "--proto-redir",
    "-E", "--cookie-jar", "-c",
    "-T", "--upload-file",
}

_ARG_SHORT = set("XHdFuAomxbceTwE")


def normalize_curl_text(text: str) -> str:
    """Normalize pasted cURLs: strip markdown, BOM, prompt junk, line continuations."""
    s = str(text or "")
    # Strip BOM and zero-width / invisible characters
    s = s.lstrip("\ufeff").replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    # Non-breaking space
    s = s.replace("\u00a0", " ").replace("\u202f", " ")
    # Line endings
    s = s.replace("\r\n", "\n").replace("\r", "\n")

    # Strip markdown code blocks: ```bash ... ``` or ```curl ... ```
    s = re.sub(r"^\s*```[a-zA-Z0-9_-]*\s*\n", "", s)
    s = re.sub(r"\n\s*```\s*$", "", s)

    # Clean shell line continuations (\ at end of line, with optional spaces before/after)
    s = re.sub(r"[ \t]*\\[ \t]*\n[ \t]*", " ", s)
    # PowerShell line continuations (` at end of line)
    s = re.sub(r"[ \t]*`[ \t]*\n[ \t]*", " ", s)
    # Windows CMD line continuations (^ at end of line)
    s = re.sub(r"[ \t]*\^[ \t]*\n[ \t]*", " ", s)

    # Normalize smart hyphens/dashes for option flags: –-location -> --location, −X -> -X
    s = re.sub(r"(^|\s)[\u2013\u2014]{1,2}([a-zA-Z0-9\-])", r"\1--\2", s)
    s = re.sub(r"(^|\s)[\u2212]([a-zA-Z0-9\-])", r"\1-\2", s)

    # Strip leading shell comments before the curl command
    s = re.sub(r"^(?:\s*#[^\n]*\n|\s*\/\/[^\n]*\n)+", "", s)

    # Strip shell prompts like: user@host:~$ / PS C:\...> / cmd> / $ / #
    s = re.sub(
        r"^\s*(?:[\w\.\-]+@[\w\.\-]+:[~\w\/\.\-]+\$?\s*|PS\s+[^\n>]*>\s*|cmd>\s*|[A-Za-z]:\\[^\n>]*>\s*|\$\s*|#\s*)",
        "",
        s,
        flags=re.I,
    )
    # Strip sudo or environment variable prefixes before curl
    s = re.sub(r"^\s*(?:sudo\s+|(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)+)", "", s)
    s = s.strip()

    # Locate 'curl' keyword
    m = re.search(r"\bcurl(?:\.exe)?\b", s, re.I)
    if m:
        s = s[m.start():]
        s = re.sub(r"^curl(?:\.exe)?\b", "curl", s, count=1, flags=re.I)
    elif s.startswith("http://") or s.startswith("https://"):
        s = "curl " + s
    else:
        # Fallback if command didn't start with curl explicitly
        s = "curl " + s

    return s.strip()


def _ansi_c_unescape(inner: str) -> str:
    out = []
    i = 0
    while i < len(inner):
        if inner[i] == "\\" and i + 1 < len(inner):
            i += 1
            c = inner[i]
            if c == "n":
                out.append("\n"); i += 1
            elif c == "t":
                out.append("\t"); i += 1
            elif c == "r":
                out.append("\r"); i += 1
            elif c in ("'", '"', "\\"):
                out.append(c); i += 1
            elif c == "u" and re.match(r"[0-9a-fA-F]{4}", inner[i + 1:i + 5]):
                out.append(chr(int(inner[i + 1:i + 5], 16))); i += 5
            elif c == "U" and re.match(r"[0-9a-fA-F]{8}", inner[i + 1:i + 9]):
                out.append(chr(int(inner[i + 1:i + 9], 16))); i += 9
            elif c == "x" and re.match(r"[0-9a-fA-F]{2}", inner[i + 1:i + 3]):
                out.append(chr(int(inner[i + 1:i + 3], 16))); i += 3
            else:
                out.append(c); i += 1
        else:
            out.append(inner[i]); i += 1
    return "".join(out)


def tokenize_curl(s: str) -> List[str]:
    """
    Robust tokenizer:
      • Correctly preserves large 4500+ line JSON payloads.
      • Apostrophes inside JSON double-quoted strings never close outer single quotes.
      • Quotes embedded in tokens (--data='{...}', -H'...') are joined seamlessly.
      • Skips shell comments (#) at token boundaries.
      • Supports Windows cmd double-quote escaping (\" and \"\").
    """
    tokens: List[str] = []
    i = 0
    n = len(s)

    def is_ws(c: str) -> bool:
        return c in " \t\n\r"

    while i < n:
        while i < n and is_ws(s[i]):
            i += 1
        if i >= n:
            break

        # Check for shell comment (#) or JS/C++ comment (//, /* */) at token boundary
        if s[i] == "#":
            while i < n and s[i] not in "\r\n":
                i += 1
            continue

        if s[i:i+2] == "//":
            # Check if this is a protocol-relative URL (e.g. //domain.com/path)
            j = i + 2
            while j < n and not is_ws(s[j]):
                j += 1
            tok = s[i:j]
            is_proto_url = bool(re.match(r"^//(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/.*)?$", tok) or re.match(r"^//localhost(?::\d+)?(?:/.*)?$", tok))
            if not is_proto_url:
                while i < n and s[i] not in "\r\n":
                    i += 1
                continue

        if s[i:i+2] == "/*":
            i += 2
            while i + 1 < n and not (s[i] == "*" and s[i + 1] == "/"):
                i += 1
            i += 2
            continue

        cur: List[str] = []
        while i < n and not is_ws(s[i]):
            # 1. ANSI-C quoting: $'...'
            if s[i] == "$" and i + 1 < n and s[i + 1] == "'":
                i += 2
                start_ansi = i
                while i < n and s[i] != "'":
                    if s[i] == "\\" and i + 1 < n:
                        i += 2
                    else:
                        i += 1
                cur.append(_ansi_c_unescape(s[start_ansi:i]))
                if i < n:
                    i += 1

            # 2. Single quotes: '...'
            elif s[i] == "'":
                i += 1
                in_dq = False
                while i < n:
                    # Track if we are inside a double-quoted JSON string
                    if s[i] == '"' and (i == 0 or s[i - 1] != "\\"):
                        in_dq = not in_dq
                        cur.append(s[i])
                        i += 1
                    elif s[i] == "'":
                        if in_dq:
                            # Apostrophe inside a JSON string ("User's account", "Don't")
                            cur.append("'")
                            i += 1
                        elif s[i:i + 4] == "'\\''":
                            cur.append("'")
                            i += 4
                        elif s[i:i + 5] == "'\"'\"'":
                            cur.append("'")
                            i += 5
                        elif i > 0 and s[i - 1] == "\\":
                            cur.append("'")
                            i += 1
                        else:
                            # Closing quote of shell token
                            i += 1
                            break
                    else:
                        cur.append(s[i])
                        i += 1

            # 3. Double quotes: "..."
            elif s[i] == '"':
                i += 1
                while i < n:
                    if s[i] == "\\" and i + 1 < n:
                        i += 1
                        c = s[i]
                        if c in ('"', "\\", "n", "t", "r"):
                            if c == "n": cur.append("\n")
                            elif c == "t": cur.append("\t")
                            elif c == "r": cur.append("\r")
                            else: cur.append(c)
                        else:
                            cur.append("\\")
                            cur.append(c)
                        i += 1
                    elif s[i] == '"' and i + 1 < n and s[i + 1] == '"':
                        # Windows CMD double-quote escape ("")
                        cur.append('"')
                        i += 2
                    elif s[i] == '"':
                        i += 1
                        break
                    else:
                        cur.append(s[i])
                        i += 1

            # 4. Smart single quotes as outer delimiters
            elif s[i] in ("\u2018", "\u2019", "\u201a", "\u201b"):
                i += 1
                while i < n:
                    if s[i] in ("\u2018", "\u2019", "\u201a", "\u201b", "'"):
                        i += 1
                        break
                    else:
                        cur.append(s[i])
                        i += 1

            # 5. Smart double quotes as outer delimiters
            elif s[i] in ("\u201c", "\u201d", "\u201e", "\u201f"):
                i += 1
                while i < n:
                    if s[i] in ("\u201c", "\u201d", "\u201e", "\u201f", '"'):
                        i += 1
                        break
                    else:
                        cur.append(s[i])
                        i += 1

            # 6. Windows CMD caret escape ^"
            elif s[i] == "^" and i + 1 < n:
                i += 1
                cur.append(s[i])
                i += 1

            # 7. Escaped space or char outside quotes
            elif s[i] == "\\":
                if i + 1 < n:
                    i += 1
                    cur.append(s[i])
                    i += 1
                else:
                    cur.append(s[i])
                    i += 1
            else:
                cur.append(s[i])
                i += 1

        tokens.append("".join(cur))
    return tokens


def expand_curl_tokens(raw_tokens: List[str]) -> List[str]:
    """Expand clustered options (-kLsS), --flag=val with DOTALL, attached options (-H..., -d...)."""
    out: List[str] = []
    # DOTALL is essential so --data-raw='{\n...4500 lines...\n}' splits across newlines
    long_eq = re.compile(r"^(--[^=]+)=([\s\S]*)$")
    for t in raw_tokens:
        if not t:
            continue
        if re.match(r"^curl$", t, re.I):
            out.append("curl")
            continue
        m = long_eq.match(t)
        if m:
            out.extend([m.group(1), m.group(2)])
            continue
        if re.match(r"^-X[A-Za-z]+$", t) and len(t) > 2:
            out.extend(["-X", t[2:].upper()])
            continue
        # Split short flags attached to values: -H..., -d..., -u..., -b..., -A..., -e...
        if len(t) > 2 and t[0] == "-" and t[1] in "HduAbce":
            out.extend([t[:2], t[2:]])
            continue
        if re.match(r"^-[a-zA-Z]{2,}$", t) and not t.startswith("--"):
            chars = list(t[1:])
            if not any(ch in _ARG_SHORT for ch in chars):
                out.extend(["-" + ch for ch in chars])
                continue
        out.append(t)
    return out


def _set_header_ci(headers: Dict[str, str], key: str, value: str) -> None:
    found = next((k for k in headers if k.lower() == key.lower()), None)
    if found:
        headers[found] = value
    else:
        headers[key] = value


def _get_header_ci(headers: Dict[str, str], key: str) -> str:
    found = next((k for k in headers if k.lower() == key.lower()), None)
    return headers[found] if found else ""


def _safe_unquote(s: str) -> str:
    try:
        return unquote_plus(str(s))
    except Exception:
        return str(s)


def _parse_urlencoded(body: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in parse_qsl(str(body or ""), keep_blank_values=True):
        if k:
            out[_safe_unquote(k)] = _safe_unquote(v)
    return out


def _looks_like_urlencoded(s: str) -> bool:
    t = str(s or "").strip()
    if not t or t.startswith("{") or t.startswith("["):
        return False
    if "=" not in t:
        return False
    if re.search(r"Content-Disposition:", t, re.I) or t.startswith("<"):
        return False
    return bool(re.match(
        r"^(?:[^=&\s]+(?:=[^&\s]*)?)(?:&[^=&\s]+(?:=[^&\s]*)?)*$", t
    ))


def _looks_like_json(s: str) -> bool:
    t = str(s or "").strip()
    return (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]"))


def _data_urlencode_part(part: str) -> Tuple[str, str, str]:
    s = str(part or "")
    if "@" in s and "=" not in s:
        name = s.split("@", 1)[0]
        return name, "", quote(name, safe="") + "="
    eq = s.find("=")
    if eq < 0:
        return "", s, quote(s, safe="")
    name, value = s[:eq], s[eq + 1:]
    return name, value, quote(name, safe="") + "=" + quote(value, safe="")


def _parse_form_arg(arg: str) -> Optional[Dict[str, Any]]:
    s = str(arg or "")
    eq = s.find("=")
    if eq < 0:
        return None
    key = s[:eq].strip()
    rest = s[eq + 1:]
    if not key:
        return None

    if (key.startswith('"') and key.endswith('"')) or (key.startswith("'") and key.endswith("'")):
        key = key[1:-1].strip()

    # Extract ;type= and ;filename= before stripping them
    content_type = None
    m_type_q = re.search(r''';\s*type=["']([^"']+)["']''', rest, flags=re.I)
    if m_type_q:
        content_type = m_type_q.group(1).strip()
    else:
        m_type = re.search(r";\s*type=([^;]+)", rest, flags=re.I)
        if m_type:
            content_type = m_type.group(1).strip().strip("\"'")

    explicit_filename = None
    m_fn_q = re.search(r''';\s*filename=["']([^"']+)["']''', rest, flags=re.I)
    if m_fn_q:
        explicit_filename = m_fn_q.group(1).strip()
    else:
        m_fn = re.search(r";\s*filename=([^;]+)", rest, flags=re.I)
        if m_fn:
            explicit_filename = m_fn.group(1).strip().strip("\"'")

    rest = re.sub(r";\s*type=[^;]+", "", rest, flags=re.I)
    rest = re.sub(r";\s*filename=[^;]+", "", rest, flags=re.I)

    if rest.startswith("@") or rest.startswith("<"):
        path = rest[1:].strip().strip("\"'")
        filename = explicit_filename or (path.replace("\\", "/").split("/")[-1] or "file")
        return {
            "key": key,
            "value": filename,
            "is_file": True,
            "filename": filename,
            "path": path,
            "content_type": content_type,
            "is_json": False,
        }

    val = rest.strip()
    # Postman and curl often quote/escape form values e.g. policy="{\"foo\":\"bar\"}"
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        if val.startswith('"'):
            try:
                unquoted = json.loads(val)
                if isinstance(unquoted, (str, dict, list)):
                    val = unquoted if isinstance(unquoted, str) else json.dumps(unquoted)
            except Exception:
                inner = val[1:-1]
                val = inner.replace(r'\"', '"') if r'\"' in inner else inner
        else:
            inner = val[1:-1]
            val = inner.replace(r"\'", "'") if r"\'" in inner else inner

    # Detect if the value is JSON
    is_json = False
    try:
        p_json = json.loads(val)
        if isinstance(p_json, (dict, list)):
            is_json = True
            if not content_type:
                content_type = "application/json"
    except Exception:
        pass

    return {
        "key": key,
        "value": val,
        "is_file": False,
        "filename": None,
        "path": None,
        "content_type": content_type,
        "is_json": is_json,
    }


def strip_json_comments(s: str) -> str:
    """
    Remove single-line (//...) and multi-line (/*...*/) comments from JSON strings
    while safely preserving all string literals, URLs (http://, https://), and escaped quotes.
    """
    if not s or not isinstance(s, str) or ("//" not in s and "/*" not in s):
        return s

    out = []
    i = 0
    n = len(s)
    in_str = False
    quote_char = ""

    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if c == "\\":
                i += 1
                if i < n:
                    out.append(s[i])
            elif c == quote_char:
                in_str = False
                quote_char = ""
            i += 1
        else:
            if c in ('"', "'"):
                in_str = True
                quote_char = c
                out.append(c)
                i += 1
            elif c == "/" and i + 1 < n and s[i + 1] == "/":
                i += 2
                while i < n and s[i] not in "\r\n":
                    i += 1
            elif c == "/" and i + 1 < n and s[i + 1] == "*":
                i += 2
                while i + 1 < n and not (s[i] == "*" and s[i + 1] == "/"):
                    i += 1
                i += 2
            else:
                out.append(c)
                i += 1

    return "".join(out)


def _normalize_json5_literals(s: str) -> str:
    """Replace unquoted JS literals true->True, false->False, null->None outside quotes for ast.literal_eval."""
    out = []
    i = 0
    n = len(s)
    in_str = False
    quote_char = ""
    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if c == "\\":
                i += 1
                if i < n:
                    out.append(s[i])
            elif c == quote_char:
                in_str = False
                quote_char = ""
            i += 1
        else:
            if c in ('"', "'"):
                in_str = True
                quote_char = c
                out.append(c)
                i += 1
            elif s[i:i+4] == "true" and (i + 4 == n or not (s[i+4].isalnum() or s[i+4] == "_")) and (i == 0 or not (s[i-1].isalnum() or s[i-1] == "_")):
                out.append("True")
                i += 4
            elif s[i:i+5] == "false" and (i + 5 == n or not (s[i+5].isalnum() or s[i+5] == "_")) and (i == 0 or not (s[i-1].isalnum() or s[i-1] == "_")):
                out.append("False")
                i += 5
            elif s[i:i+4] == "null" and (i + 4 == n or not (s[i+4].isalnum() or s[i+4] == "_")) and (i == 0 or not (s[i-1].isalnum() or s[i-1] == "_")):
                out.append("None")
                i += 4
            else:
                out.append(c)
                i += 1
    return "".join(out)


def parse_robust_json(payload: str) -> Tuple[Any, bool]:
    """
    Robust JSON parser for real-world enterprise payloads (including 4500+ lines).
    Returns (parsed_object, is_json_boolean).
    Handles:
      • Standard strict JSON
      • Unescaped control chars / literal newlines in strings (strict=False)
      • Single-line (//...) and multi-line (/*...*/) comments (Postman / JS / JSON5)
      • Trailing commas in objects/arrays (e.g. {"a": 1,})
      • Double-escaped JSON strings ("{\"key\":\"val\"}")
      • Python dict syntax ({'key': 'val', 'valid': True})
      • Unquoted JS literals (true, false, null) with single quotes
      • Escaped quotes repair
    """
    if not payload or not isinstance(payload, str):
        return None, False

    p = payload.strip()
    if not p:
        return None, False

    # Check if wrapped in double quotes as a serialized JSON string
    if (p.startswith('"{') and p.endswith('}"')) or (p.startswith('"[') and p.endswith(']"')):
        try:
            unwrapped = json.loads(p)
            if isinstance(unwrapped, str):
                p = unwrapped.strip()
        except Exception:
            pass

    # Prepare parse candidates: raw, unescaped single-quotes, and stripped comments
    candidates = []
    for base in [p, p.replace(r"\'", "'") if r"\'" in p else p]:
        if base and base not in candidates:
            candidates.append(base)
        if "//" in base or "/*" in base:
            c = strip_json_comments(base).strip()
            if c and c not in candidates:
                candidates.append(c)

    # Fast check if any candidate looks like JSON object or array
    if not any(c.startswith("{") or c.startswith("[") for c in candidates):
        return None, False

    # 1. Standard strict parse
    for cand in candidates:
        try:
            return json.loads(cand), True
        except Exception:
            pass

    # 2. Relaxed parse (strict=False permits control characters/newlines inside string values)
    for cand in candidates:
        try:
            return json.loads(cand, strict=False), True
        except Exception:
            pass

    # 3. Clean trailing commas in objects and arrays
    for cand in candidates:
        try:
            p_no_commas = re.sub(r",\s*([\]}])", r"\1", cand)
            return json.loads(p_no_commas, strict=False), True
        except Exception:
            pass

    # 4. Safe Python literal eval for single-quoted dicts ({'a': 1, 'b': 'val'})
    # and JS literals (true, false, null)
    for cand in candidates:
        try:
            data = ast.literal_eval(cand)
            if isinstance(data, (dict, list)):
                return data, True
        except Exception:
            pass
        try:
            cand_norm = _normalize_json5_literals(cand)
            data = ast.literal_eval(cand_norm)
            if isinstance(data, (dict, list)):
                return data, True
        except Exception:
            pass
        # Unquoted keys fallback (e.g. { status: "Accepted" })
        try:
            cand_keys = re.sub(r'([{\[,]\s*)([a-zA-Z_$][a-zA-Z0-9_$-]*)\s*:', r'\1"\2":', cand)
            cand_keys_norm = _normalize_json5_literals(cand_keys)
            data = ast.literal_eval(cand_keys_norm)
            if isinstance(data, (dict, list)):
                return data, True
        except Exception:
            pass

    # 5. Repair common double-backslash quotes
    for cand in candidates:
        try:
            p_unesc = cand.replace(r'\"', '"')
            return json.loads(p_unesc, strict=False), True
        except Exception:
            pass

    return None, False


def _tokenize_fallback(s: str) -> List[str]:
    try:
        return shlex.split(s, posix=True)
    except ValueError:
        try:
            return shlex.split(s.replace("'", '"'), posix=True)
        except ValueError as e:
            raise ValueError(f"Cannot tokenize cURL: {e}") from e


def parse_curl_command(text: str) -> Dict[str, Any]:
    """
    Parse any cURL command string into structured API specification.
    Returns:
      method, url, headers, cookies,
      body (dict/list/str|None), body_raw, body_type,
      form_parts, query_params
    """
    curl_str = normalize_curl_text(text)
    try:
        tokens = expand_curl_tokens(tokenize_curl(curl_str))
    except Exception:
        tokens = expand_curl_tokens(_tokenize_fallback(curl_str))

    method: Optional[str] = None
    url = ""
    as_get = False
    headers: Dict[str, str] = {}
    data_parts: List[str] = []
    form_fields_from_data: List[Dict[str, str]] = []
    data_is_urlencode = False
    data_is_json_flag = False
    data_is_binary = False
    form_parts: List[Dict[str, Any]] = []
    basic_user: Optional[str] = None
    basic_pass: Optional[str] = None
    cookies: Dict[str, str] = {}

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if not t:
            i += 1
            continue
        if i == 0 and re.match(r"^curl$", t, re.I):
            i += 1
            continue

        if t in ("-G", "--get"):
            as_get = True; i += 1; continue
        if t in ("-I", "--head"):
            method = "HEAD"; i += 1; continue
        if t in _SKIP_NO_ARG:
            i += 1; continue

        if t in ("-X", "--request"):
            i += 1
            method = str(tokens[i] if i < len(tokens) else "GET").upper()
            i += 1; continue

        if t == "--url":
            i += 1
            if i < len(tokens):
                url = tokens[i]
            i += 1; continue

        if t in ("-H", "--header"):
            i += 1
            h = tokens[i] if i < len(tokens) else ""
            ci = h.find(":")
            if ci > 0:
                k, v = h[:ci].strip().rstrip(";,").strip(), h[ci + 1:].strip()
                if k:
                    if k.lower() == "cookie":
                        for ck in v.split(";"):
                            ck = ck.strip()
                            if "=" in ck:
                                a, b = ck.split("=", 1)
                                cookies[a.strip()] = b.strip()
                        prev = _get_header_ci(headers, "Cookie")
                        _set_header_ci(headers, "Cookie", (prev + "; " + v) if prev else v)
                    else:
                        _set_header_ci(headers, k, v)
            elif h.endswith(";") and ci < 0:
                # Semicolon empty header (e.g. -H 'crutag;')
                k = h[:-1].strip()
                if k:
                    _set_header_ci(headers, k, "")
            i += 1; continue

        if t in ("--oauth2-bearer",):
            i += 1
            token = tokens[i] if i < len(tokens) else ""
            if token:
                _set_header_ci(headers, "Authorization", f"Bearer {token}")
            i += 1; continue

        if t in ("-u", "--user"):
            i += 1
            cred = tokens[i] if i < len(tokens) else ""
            ci = cred.find(":")
            basic_user = cred[:ci] if ci >= 0 else cred
            basic_pass = cred[ci + 1:] if ci >= 0 else ""
            i += 1; continue

        if t in ("-A", "--user-agent"):
            i += 1
            _set_header_ci(headers, "User-Agent", tokens[i] if i < len(tokens) else "")
            i += 1; continue

        if t in ("-e", "--referer"):
            i += 1
            _set_header_ci(headers, "Referer", tokens[i] if i < len(tokens) else "")
            i += 1; continue

        if t in ("-b", "--cookie"):
            i += 1
            c = tokens[i] if i < len(tokens) else ""
            if not c.startswith("@"):
                for ck in c.split(";"):
                    ck = ck.strip()
                    if "=" in ck:
                        a, b = ck.split("=", 1)
                        cookies[a.strip()] = b.strip()
                prev = _get_header_ci(headers, "Cookie")
                _set_header_ci(headers, "Cookie", (prev + "; " + c) if prev else c)
            i += 1; continue

        if t == "--json":
            i += 1
            part = tokens[i] if i < len(tokens) else ""
            data_is_json_flag = True
            data_parts.append("" if part.startswith("@") else part)
            _set_header_ci(headers, "Content-Type", "application/json")
            if not _get_header_ci(headers, "Accept"):
                _set_header_ci(headers, "Accept", "application/json")
            i += 1; continue

        if t in ("-d", "--data", "--data-raw", "--data-ascii", "--data-urlencode", "--data-binary"):
            i += 1
            part = tokens[i] if i < len(tokens) else ""
            if part.startswith("@"):
                part = f"[File: {part[1:]}]"
            if t == "--data-binary":
                data_is_binary = True
            if t == "--data-urlencode":
                data_is_urlencode = True
                key, value, encoded = _data_urlencode_part(part)
                data_parts.append(encoded)
                if key:
                    form_fields_from_data.append({"key": key, "value": value})
                i += 1; continue
            data_parts.append(part)
            if part and not part.startswith("{") and not part.startswith("[") and "=" in part:
                for k, v in _parse_urlencoded(part).items():
                    form_fields_from_data.append({"key": k, "value": v})
            i += 1; continue

        if t in ("-F", "--form", "--form-string"):
            i += 1
            part = tokens[i] if i < len(tokens) else ""
            row = _parse_form_arg(part)
            if row:
                form_parts.append(row)
            i += 1; continue

        if t in _SKIP_ONE_ARG:
            i += 2; continue

        if t.startswith("--") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            nxt = tokens[i + 1] or ""
            if not re.match(r"^https?://", nxt, re.I) and "://" not in nxt:
                i += 2; continue

        # Recognize URL anywhere in arguments
        if not url:
            if re.match(r"^https?://", t, re.I) or (t.startswith("//") and "." in t and "/" in t[2:]):
                url = t
                i += 1; continue
            if not t.startswith("-") and not t.startswith("//") and not t.startswith("/*") and ("." in t or "localhost" in t) and ("/" in t or ":" in t):
                url = t if "://" in t else ("http://" + t)
                i += 1; continue

        i += 1

    if not url:
        raise ValueError("No valid URL found in cURL command")

    if as_get and data_parts:
        query_extra = "&".join(p for p in data_parts if p)
        data_parts = []
        form_fields_from_data = []
        if query_extra:
            url += ("&" if "?" in url else "?") + query_extra

    if basic_user is not None:
        token = base64.b64encode(f"{basic_user}:{basic_pass or ''}".encode("utf-8")).decode("ascii")
        _set_header_ci(headers, "Authorization", "Basic " + token)

    body_joined: Optional[str] = None
    if data_parts:
        filtered = [p for idx, p in enumerate(data_parts) if not (p == "" and len(data_parts) > 1)]
        body_joined = "&".join(filtered)
    has_body = bool(form_parts) or (body_joined is not None and body_joined != "") or data_is_json_flag

    if not method:
        if as_get:
            method = "GET"
        elif has_body:
            method = "POST"
        else:
            method = "GET"

    body: Any = None
    body_type: Optional[str] = None
    body_raw: Optional[str] = None
    ct = _get_header_ci(headers, "Content-Type").lower()

    if form_parts:
        form_obj = {f["key"]: f["value"] for f in form_parts}
        body = form_obj
        body_type = "form"
        body_raw = "&".join(
            quote(str(k), safe="") + "=" + quote("" if v is None else str(v), safe="")
            for k, v in form_obj.items()
        )
        if not ct:
            _set_header_ci(headers, "Content-Type", "multipart/form-data")
    elif body_joined is not None or data_is_json_flag:
        payload = body_joined or ""
        body_raw = payload

        # Try robust JSON parsing first
        json_obj, is_json = parse_robust_json(payload)
        if is_json:
            body = json_obj
            body_type = "json"
            try:
                body_raw = json.dumps(json_obj, ensure_ascii=False)
            except Exception:
                body_raw = payload
            if not ct:
                _set_header_ci(headers, "Content-Type", "application/json")
        elif (
            "x-www-form-urlencoded" in ct
            or data_is_urlencode
            or (form_fields_from_data and (len(data_parts) > 1 or data_is_urlencode or "x-www-form-urlencoded" in ct))
            or (len(data_parts) > 1 and not data_is_binary)
            or (not ct and _looks_like_urlencoded(payload) and not data_is_binary)
        ):
            body_type = "form"
            if form_fields_from_data:
                body = {f["key"]: f["value"] for f in form_fields_from_data}
            else:
                body = _parse_urlencoded(payload)
            if not ct:
                _set_header_ci(headers, "Content-Type", "application/x-www-form-urlencoded")
        else:
            body = payload
            body_type = "raw"

    query_params: Dict[str, str] = {}
    try:
        for k, vs in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            query_params[k] = vs[0] if vs else ""
    except Exception:
        pass

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "body": body,
        "body_raw": body_raw,
        "body_type": body_type,
        "form_parts": form_parts,
        "query_params": query_params,
    }
