"""
proxy_addon.py — mitmproxy addon
Ab same process mein chalta hai (Python API via thread),
isliye directly main.py ka _capture_store update karta hai.
"""

import json
from urllib.parse import urlparse, parse_qs

SKIP_EXTENSIONS = {
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.woff', '.woff2', '.ttf', '.otf', '.map', '.webp',
    '.mp4', '.mp3', '.zip',
}
SKIP_HOSTS = {
    'fonts.googleapis.com', 'fonts.gstatic.com',
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
}
STATUS_TEXT = {
    200: 'OK', 201: 'Created', 204: 'No Content',
    301: 'Moved', 302: 'Found', 304: 'Not Modified',
    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
    404: 'Not Found', 405: 'Method Not Allowed', 409: 'Conflict',
    422: 'Unprocessable', 429: 'Too Many Requests',
    500: 'Server Error', 502: 'Bad Gateway', 503: 'Unavailable',
}


def should_capture(flow) -> bool:
    url = flow.request.pretty_url
    if url.startswith(('data:', 'chrome:', 'chrome-extension:', 'safari-extension:')):
        return False
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return False
    if parsed.netloc in SKIP_HOSTS:
        return False

    # Skip internal Sentinel backend ports (8765 to 8799)
    netloc = parsed.netloc
    if any(f"127.0.0.1:{p}" in netloc or f"localhost:{p}" in netloc for p in range(8765, 8800)):
        return False

    # Skip binary media responses (images, fonts, audio, video, css)
    if flow.response and flow.response.headers:
        resp_ct = flow.response.headers.get('content-type', '').lower()
        if any(t in resp_ct for t in ('image/', 'audio/', 'video/', 'font/', 'text/css')):
            return False

    # All API endpoints, web pages, XHR/Fetch, forms, and browser traffic should be captured
    return True


class CaptureAddon:
    def response(self, flow):
        self._record(flow)

    def error(self, flow):
        self._record(flow)

    def _record(self, flow):
        try:
            import main as _main
            if not _main._is_capturing:
                return
        except Exception:
            return

        if not should_capture(flow):
            return

        req = flow.request
        url = req.pretty_url
        headers = dict(req.headers)

        body, body_type, raw_body = None, None, None
        try:
            if req.content:
                raw_body = req.content.decode('utf-8', errors='replace')
                try:
                    body = json.loads(raw_body)
                    body_type = 'json'
                except Exception:
                    ct = headers.get('content-type', '')
                    if 'application/x-www-form-urlencoded' in ct:
                        form = {}
                        for pair in raw_body.split('&'):
                            if '=' in pair:
                                k, v = pair.split('=', 1)
                                form[k] = v
                        body = form
                        body_type = 'form'
                    else:
                        body = raw_body
                        body_type = 'raw'
        except Exception:
            pass

        query_params = {}
        try:
            for k, v in parse_qs(urlparse(url).query).items():
                query_params[k] = v[0] if v else ''
        except Exception:
            pass

        status = flow.response.status_code if flow.response else 'ERR'
        status_text = STATUS_TEXT.get(status, str(status)) if flow.response else getattr(flow, 'error', 'ERR')
        req_id = str(id(flow))

        captured = {
            'id': req_id,
            'method': req.method,
            'url': url,
            'headers': headers,
            'queryParams': query_params,
            'body': body,
            'body_type': body_type,
            'rawBody': raw_body,
            'status': status,
            'statusText': str(status_text),
            'timestamp': int(req.timestamp_start * 1000),
        }

        try:
            store = _main._capture_store
            if not any(r['id'] == req_id for r in store):
                store.insert(0, captured)
                if len(store) > 500:
                    store.pop()
        except Exception:
            pass


addons = [CaptureAddon()]
