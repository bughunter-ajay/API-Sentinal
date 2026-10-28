import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from nuclei_backend.main import app

def test_full_nuclei_flow():
    client = TestClient(app)

    # 1. Health & Binary check
    h = client.get("/health").json()
    assert h["status"] == "ok"
    assert h["port"] == 8797
    print("✅ Health endpoint check: OK")

    # 2. Parse cURL
    c_res = client.post("/api/parse-curl", json={
        "curl": "curl -X PUT 'https://api.sentinel-test.com/v1/policies' -H 'Authorization: Bearer test_token_xyz' -H 'Accept: application/json'"
    }).json()
    assert c_res["success"] is True
    assert c_res["base_url"] == "https://api.sentinel-test.com"
    assert "Authorization" in c_res["headers"]
    print(f"✅ cURL parser check: OK (Base URL: {c_res['base_url']}, Method: {c_res['method']})")

    # 3. Parse Swagger
    swagger_yaml = """
openapi: 3.0.0
info:
  title: Sample Sentinel API
  version: 1.0.0
servers:
  - url: https://api.staging.sentinel.com/v1
paths:
  /auth/login:
    post:
      summary: User Login
  /users/me:
    get:
      summary: Get Profile
  /admin/roles:
    get:
      summary: List Roles
"""
    swag_res = client.post("/api/parse-swagger", json={"spec_text": swagger_yaml}).json()
    assert swag_res["success"] is True
    assert swag_res["detected_base_url"] == "https://api.staging.sentinel.com/v1"
    assert swag_res["total_endpoints"] == 3
    print(f"✅ Swagger parser check: OK (Found {swag_res['total_endpoints']} endpoints, Base: {swag_res['detected_base_url']})")

    # 4. Start Scan Job with Swagger endpoints (dict format & strings)
    scan_res = client.post("/api/scan/start", json={
        "target_type": "swagger",
        "base_url": swag_res["detected_base_url"],
        "targets": swag_res["endpoints"],
        "headers": {"User-Agent": "APISentinel-Tester/1.0"},
        "tags": ["api"],
        "timeout": 5
    }).json()
    assert scan_res["success"] is True
    jid = scan_res["job_id"]
    print(f"✅ Scan start with Swagger endpoints check: OK (Job ID: {jid})")

    # 5. Wait or test clean stop
    time.sleep(2)
    st = client.get(f"/api/scan/status/{jid}").json()
    assert st["status"] in ("running", "completed", "queued")
    print(f"✅ Scan running status: {st['status']}")

    # Stop scan gracefully
    stop_res = client.post(f"/api/scan/stop/{jid}").json()
    assert stop_res["success"] is True
    print("✅ Scan stop check: OK")

    time.sleep(1)
    st_after = client.get(f"/api/scan/status/{jid}").json()
    assert st_after["status"] in ("stopped", "completed")
    print(f"✅ Scan stopped status confirmed: {st_after['status']}")

    # 6. Check results
    res = client.get(f"/api/scan/results/{jid}").json()
    assert "findings" in res
    assert "logs" in res
    print(f"✅ Results check: OK ({len(res['findings'])} findings, {len(res['logs'])} log lines)")

    # 7. HTML Report Export & Safe Save
    rep = client.post("/api/scan/export", json={
        "title": "Test Security Report",
        "target_url": "https://httpbin.org",
        "findings": res["findings"],
        "stats": res["stats"]
    })
    assert rep.status_code == 200
    assert "Test Security Report" in rep.text
    assert "<table" in rep.text
    print("✅ HTML Report generation check: OK")

    # 8. Safe Report Save Check (Downloads)
    save_rep = client.post("/api/scan/save-report", json={
        "title": "Test Security Report",
        "target_url": "https://httpbin.org",
        "findings": res["findings"],
        "stats": res["stats"]
    }).json()
    assert save_rep["success"] is True
    assert os.path.exists(save_rep["path"])
    print(f"✅ Safe save report check: OK (Saved to {save_rep['path']})")

    # 9. Binary Info Check
    b_info = client.get("/api/binary-info").json()
    assert "installed" in b_info
    print(f"✅ Binary Info check: OK (Installed: {b_info['installed']}, Version: {b_info.get('version')})")

    print("🎉 ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_full_nuclei_flow()
