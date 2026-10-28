"""
Swagger / OpenAPI Parser for JS & Secret Analyser
Parses Swagger 2.0 and OpenAPI 3.0+ specs (JSON and YAML).
Extracts endpoints formatted for JsaEndpoint consumption.
"""

from __future__ import annotations

import re
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin
import requests

try:
    import yaml
except ImportError:
    yaml = None

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def parse_devtools_or_raw_headers(raw_text: str) -> Tuple[Optional[str], Dict[str, str]]:
    raw = (raw_text or "").strip()
    if not raw:
        return None, {}
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    if len(lines) == 1 and not (":" in lines[0] and not lines[0].startswith("http")) and not lines[0].lower().startswith("authorization"):
        return lines[0], {}
    token = None
    headers: Dict[str, str] = {}
    has_colons = any(":" in l and not l.startswith(":") for l in lines)
    if has_colons:
        for l in lines:
            if l.startswith(":"):
                continue
            if ":" in l:
                k, v = l.split(":", 1)
                k, v = k.strip(), v.strip()
                if k.lower() == "authorization":
                    token = v
                else:
                    headers[k] = v
    else:
        i = 0
        while i < len(lines):
            key = lines[i]
            if key.startswith(":"):
                i += 2
                continue
            val = lines[i + 1] if (i + 1 < len(lines)) else ""
            i += 2
            if key.lower() == "authorization":
                token = val
            else:
                headers[key] = val
    return token, headers


def resolve_ref(ref_str: str, root: dict) -> dict:
    if not ref_str or not isinstance(ref_str, str):
        return {}
    parts = ref_str.lstrip("#/").split("/")
    curr = root
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return {}
    return curr if isinstance(curr, dict) else {}


def generate_mock_from_schema(schema: dict, root: dict, depth: int = 0, seen: Optional[set] = None) -> Any:
    if seen is None:
        seen = set()
    if depth > 4 or not isinstance(schema, dict):
        return {}

    if "$ref" in schema:
        ref_val = schema["$ref"]
        if ref_val in seen:
            return {}
        seen.add(ref_val)
        resolved = resolve_ref(ref_val, root)
        return generate_mock_from_schema(resolved, root, depth + 1, seen.copy())

    if "example" in schema:
        return schema["example"]
    if "examples" in schema:
        exs = schema["examples"]
        if isinstance(exs, list) and len(exs) > 0:
            return exs[0]
        elif isinstance(exs, dict) and len(exs) > 0:
            first_v = next(iter(exs.values()))
            return first_v.get("value") if isinstance(first_v, dict) and "value" in first_v else first_v

    stype = schema.get("type")
    props = schema.get("properties")

    if props or stype == "object":
        obj = {}
        for k, v in (props or {}).items():
            if not isinstance(v, dict):
                continue
            if "$ref" in v:
                v_ref = v["$ref"]
                v_resolved = resolve_ref(v_ref, root)
                if v_ref in seen:
                    obj[k] = {}
                    continue
                v = v_resolved

            vtype = v.get("type")
            if "example" in v:
                obj[k] = v["example"]
            elif "default" in v:
                obj[k] = v["default"]
            elif v.get("enum"):
                obj[k] = v["enum"][0]
            elif vtype in ("integer", "number"):
                obj[k] = 1
            elif vtype == "boolean":
                obj[k] = True
            elif vtype == "array":
                item_schema = v.get("items", {})
                if depth < 2:
                    sub = generate_mock_from_schema(item_schema, root, depth + 1, seen.copy())
                    obj[k] = [sub] if sub is not None else []
                else:
                    obj[k] = []
            elif vtype == "string":
                fmt = v.get("format", "")
                if "date" in fmt:
                    obj[k] = "2026-10-13T00:00:00Z"
                elif fmt == "email":
                    obj[k] = "test@example.com"
                elif fmt == "uuid":
                    obj[k] = "00000000-0000-0000-0000-000000000001"
                else:
                    obj[k] = k
            elif "$ref" in v or "properties" in v:
                obj[k] = generate_mock_from_schema(v, root, depth + 1, seen.copy())
            else:
                obj[k] = "test"
        return obj
    elif stype == "array":
        item_schema = schema.get("items", {})
        sub = generate_mock_from_schema(item_schema, root, depth + 1, seen.copy())
        return [sub] if sub is not None else []
    elif stype in ("integer", "number"):
        return 1
    elif stype == "boolean":
        return True
    elif stype == "string":
        return "test"
    return {}


def extract_swagger_request_body(op_data: dict, root: dict) -> str:
    # 1. OpenAPI 3.x requestBody
    rb = op_data.get("requestBody")
    if isinstance(rb, dict):
        if "$ref" in rb:
            rb = resolve_ref(rb["$ref"], root)
        content = rb.get("content", {})
        json_media = content.get("application/json") or content.get("*/*")
        if not json_media:
            for k, v in content.items():
                if "json" in k.lower():
                    json_media = v
                    break
            if not json_media and content:
                json_media = next(iter(content.values()))
        if isinstance(json_media, dict):
            if "example" in json_media:
                return json.dumps(json_media["example"], indent=2, ensure_ascii=False)
            if "examples" in json_media:
                exs = json_media["examples"]
                if isinstance(exs, dict) and exs:
                    first_ex = next(iter(exs.values()))
                    if isinstance(first_ex, dict) and "value" in first_ex:
                        return json.dumps(first_ex["value"], indent=2, ensure_ascii=False)
                elif isinstance(exs, list) and exs:
                    return json.dumps(exs[0], indent=2, ensure_ascii=False)
            schema = json_media.get("schema")
            if isinstance(schema, dict):
                mock = generate_mock_from_schema(schema, root)
                if mock:
                    return json.dumps(mock, indent=2, ensure_ascii=False)

    # 2. Swagger 2.0 parameters with in: body
    for p in op_data.get("parameters", []):
        if isinstance(p, dict) and p.get("in") == "body":
            if "example" in p:
                return json.dumps(p["example"], indent=2, ensure_ascii=False)
            schema = p.get("schema")
            if isinstance(schema, dict):
                mock = generate_mock_from_schema(schema, root)
                if mock:
                    return json.dumps(mock, indent=2, ensure_ascii=False)

    return "{}"


def fetch_swagger_from_url(spec_url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 15) -> str:
    """Fetch raw spec content from URL."""
    u = spec_url.strip()
    req_headers = {"Accept": "application/json, application/yaml, text/yaml, */*"}
    if headers:
        req_headers.update(headers)
    resp = requests.get(u, headers=req_headers, timeout=timeout, verify=False)
    if resp.status_code >= 400:
        raise ValueError(f"HTTP {resp.status_code} ({resp.reason}) fetching Swagger URL")
    return resp.text


def parse_swagger_spec(
    spec_text: Optional[str] = None,
    spec_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    custom_base_url: Optional[str] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    raw_content = ""
    source_origin = ""

    # 1. Fetch from URL if provided
    if spec_url and spec_url.strip():
        u = spec_url.strip()
        parsed_u = urlparse(u)
        source_origin = f"{parsed_u.scheme}://{parsed_u.netloc}"
        try:
            raw_content = fetch_swagger_from_url(u, headers=headers, timeout=timeout)
        except Exception as e:
            return {"success": False, "error": f"Failed to fetch Swagger URL: {str(e)}"}
    elif spec_text and spec_text.strip():
        raw_content = spec_text.strip()
    else:
        return {"success": False, "error": "No Swagger URL or specification content provided."}

    # 2. Parse JSON or YAML
    data = None
    try:
        data = json.loads(raw_content)
    except Exception:
        if yaml is not None:
            try:
                data = yaml.safe_load(raw_content)
            except Exception as ye:
                return {"success": False, "error": f"Failed to parse Swagger JSON/YAML: {str(ye)}"}
        else:
            return {"success": False, "error": "YAML parser not available and JSON decode failed."}

    if not isinstance(data, dict):
        return {"success": False, "error": "Invalid specification format: root element must be a JSON object."}

    # 3. Detect Swagger 2.0 vs OpenAPI 3.x
    spec_type = "unknown"
    detected_base_url = ""

    if "swagger" in data:
        spec_type = "swagger_2"
        host = data.get("host", "").strip()
        base_path = data.get("basePath", "").strip()
        schemes = data.get("schemes", [])
        scheme = schemes[0] if (schemes and isinstance(schemes, list)) else "https"
        if host:
            detected_base_url = f"{scheme}://{host}"
            if base_path and base_path != "/":
                detected_base_url = detected_base_url.rstrip("/") + ("/" + base_path.lstrip("/"))
        elif source_origin:
            detected_base_url = source_origin + ("/" + base_path.lstrip("/") if base_path and base_path != "/" else "")
    elif "openapi" in data:
        spec_type = "openapi_3"
        servers = data.get("servers", [])
        if servers and isinstance(servers, list):
            first_srv = servers[0]
            if isinstance(first_srv, dict):
                srv_url = (first_srv.get("url") or "").strip()
                if srv_url:
                    if srv_url.startswith("http://") or srv_url.startswith("https://"):
                        detected_base_url = srv_url
                    elif source_origin:
                        detected_base_url = urljoin(source_origin, srv_url)

    if not detected_base_url and source_origin:
        detected_base_url = source_origin

    # 4. Extract Paths and Endpoints
    paths = data.get("paths", {})
    if not isinstance(paths, dict):
        return {"success": False, "error": "Specification contains no valid 'paths' definition."}

    endpoints: List[Dict[str, Any]] = []
    effective_base = custom_base_url.strip().rstrip("/") if (custom_base_url and custom_base_url.strip()) else (detected_base_url or "").rstrip("/")

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        clean_path = path_str if path_str.startswith("/") else "/" + path_str
        # Replace template placeholders like {id}, {referenceId} with dummy '1' so live URLs don't hit literal {id} (404)
        exec_path = re.sub(r'\{[^\}]+\}', '1', clean_path)

        for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
            if method not in path_item:
                continue
            op_data = path_item[method]
            if not isinstance(op_data, dict):
                continue

            full_url = (effective_base + exec_path) if effective_base else exec_path
            summary = op_data.get("summary") or op_data.get("operationId") or f"{method.upper()} {clean_path}"

            ep_headers = dict(headers) if headers else {}
            m_upper = method.upper()
            if m_upper in ("POST", "PUT", "PATCH"):
                if not any(k.lower() == "content-type" for k in ep_headers):
                    ep_headers["Content-Type"] = "application/json"
                ep_body = extract_swagger_request_body(op_data, data)
            else:
                ep_body = None

            endpoints.append({
                "url": full_url,
                "method": m_upper,
                "path": clean_path,
                "summary": summary,
                "headers": ep_headers,
                "body": ep_body,
            })

    info = data.get("info", {})
    title = info.get("title", "Swagger API")
    version = info.get("version", "1.0.0")

    return {
        "success": True,
        "title": title,
        "version": version,
        "spec_type": spec_type,
        "detected_base_url": detected_base_url,
        "effective_base_url": effective_base,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
        "raw_spec_text": raw_content,
    }
