"""
Swagger / OpenAPI Parser for Nuclei Scanner & API Sentinel
Supports Swagger 2.0 and OpenAPI 3.0+ specs (JSON and YAML).
Extracts endpoints, operations, and auto-detects Base URLs with host fallback.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import requests

try:
    import yaml
except ImportError:
    yaml = None

# Suppress insecure request warnings for local/self-signed testing
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

logger = logging.getLogger("swagger_parser")


def parse_swagger_spec(
    spec_text: Optional[str] = None,
    spec_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """
    Parses a Swagger/OpenAPI specification from raw text or a remote URL.
    Returns:
      {
        "success": bool,
        "error": Optional[str],
        "title": str,
        "version": str,
        "description": str,
        "spec_type": "swagger_2" | "openapi_3" | "unknown",
        "detected_base_url": str,
        "total_endpoints": int,
        "endpoints": List[dict],
        "tags": List[str]
      }
    """
    data = None
    source_origin = ""

    # 1. Fetch from URL if provided
    if spec_url and spec_url.strip():
        u = spec_url.strip()
        parsed_u = urlparse(u)
        source_origin = f"{parsed_u.scheme}://{parsed_u.netloc}"
        try:
            req_headers = {"Accept": "application/json, application/yaml, text/yaml, */*"}
            if headers:
                req_headers.update(headers)
            resp = requests.get(u, headers=req_headers, timeout=timeout, verify=False)
            if resp.status_code >= 400:
                return {
                    "success": False,
                    "error": f"Failed to fetch Swagger URL: HTTP {resp.status_code} ({resp.reason})",
                }
            raw_content = resp.text
        except Exception as e:
            return {"success": False, "error": f"Network error fetching Swagger URL: {str(e)}"}
    elif spec_text and spec_text.strip():
        raw_content = spec_text.strip()
    else:
        return {"success": False, "error": "No Swagger URL or specification content provided."}

    # 2. Parse JSON or YAML
    try:
        data = json.loads(raw_content)
    except Exception:
        if yaml:
            try:
                data = yaml.safe_load(raw_content)
            except Exception as ye:
                return {"success": False, "error": f"Failed to parse as JSON or YAML: {str(ye)}"}
        else:
            return {
                "success": False,
                "error": "Failed to parse spec as JSON, and YAML parser (PyYAML) is not installed.",
            }

    if not isinstance(data, dict):
        return {"success": False, "error": "Invalid specification format: Root must be a JSON/YAML object."}

    # 3. Detect Spec Type & Metadata
    info = data.get("info", {})
    if not isinstance(info, dict):
        info = {}
    title = str(info.get("title") or "API Specification")
    version = str(info.get("version") or "1.0.0")
    description = str(info.get("description") or "")

    spec_type = "unknown"
    detected_base_url = ""

    # OpenAPI 3.x detection
    if "openapi" in data:
        spec_type = "openapi_3"
        servers = data.get("servers") or []
        if isinstance(servers, list) and servers:
            s0 = servers[0]
            if isinstance(s0, dict) and s0.get("url"):
                surl = s0["url"].strip()
                # Resolve relative URL against source_origin if available
                if surl.startswith("/") and source_origin:
                    detected_base_url = source_origin + surl.rstrip("/")
                elif surl.startswith("http://") or surl.startswith("https://"):
                    detected_base_url = surl.rstrip("/")
                else:
                    detected_base_url = surl

    # Swagger 2.0 detection
    elif "swagger" in data:
        spec_type = "swagger_2"
        host = data.get("host")
        base_path = data.get("basePath", "")
        schemes = data.get("schemes") or ["https"]
        scheme = schemes[0] if schemes else "https"
        if host:
            detected_base_url = f"{scheme}://{host}"
            if base_path and base_path != "/":
                detected_base_url += "/" + base_path.strip("/")
        elif source_origin:
            detected_base_url = source_origin
            if base_path and base_path != "/":
                detected_base_url += "/" + base_path.strip("/")

    # Fallback to source origin if detected_base_url is still empty or relative
    if (not detected_base_url or detected_base_url.startswith("/")) and source_origin:
        rel = detected_base_url if detected_base_url.startswith("/") else ""
        detected_base_url = source_origin + rel

    # 4. Extract Paths and Endpoints
    paths = data.get("paths", {})
    if not isinstance(paths, dict):
        paths = {}

    endpoints: List[Dict[str, Any]] = []
    unique_tags = set()
    methods = {"get", "post", "put", "delete", "patch", "options", "head"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        # Parameter summary at path level
        path_params = path_item.get("parameters") or []

        for m in methods:
            if m in path_item:
                op = path_item[m]
                if not isinstance(op, dict):
                    continue

                op_summary = str(op.get("summary") or "")
                op_desc = str(op.get("description") or "")
                op_id = str(op.get("operationId") or "")
                op_tags = op.get("tags") or []
                if isinstance(op_tags, list):
                    for t in op_tags:
                        unique_tags.add(str(t))
                else:
                    op_tags = []

                # Clean path formatting
                norm_path = path if path.startswith("/") else ("/" + path)
                full_url = ""
                if detected_base_url:
                    full_url = detected_base_url.rstrip("/") + norm_path

                endpoints.append({
                    "method": m.upper(),
                    "path": norm_path,
                    "full_url": full_url,
                    "summary": op_summary,
                    "description": op_desc,
                    "operation_id": op_id,
                    "tags": op_tags,
                })

    return {
        "success": True,
        "title": title,
        "version": version,
        "description": description,
        "spec_type": spec_type,
        "base_url": detected_base_url,
        "detected_base_url": detected_base_url,
        "source_origin": source_origin,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
        "tags": sorted(list(unique_tags)),
    }
