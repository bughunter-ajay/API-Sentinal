import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from fuzzer_backend.main import app

client = TestClient(app)

def test_fuzzer_root():
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["service"] == "api_fuzzer"
    assert res.json()["port"] == 8796
    print("✓ GET / test passed")

def test_fuzzer_start():
    req_payload = {
        "curl": "curl -X POST 'https://httpbin.org/post?filter=active' -H 'Content-Type: application/json' -d '{\"id\": 42, \"role\": \"user\"}'",
        "targets": [
            {"id": "query:filter", "type": "query", "key": "filter", "enabled": True},
            {"id": "json:role", "type": "json", "key": "role", "enabled": True}
        ],
        "injection_payloads": ["admin", "${7*7}"],
        "endpoint_payloads": [],
        "threads": 2,
        "delay_ms": 0,
        "randomize": False
    }
    res = client.post("/fuzzer/start", json=req_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert "job_id" in data
    job_id = data["job_id"]
    print(f"✓ POST /fuzzer/start test passed, job_id={job_id}")

    # Check status
    res_st = client.get(f"/fuzzer/status/{job_id}")
    assert res_st.status_code == 200
    print(f"✓ GET /fuzzer/status test passed: {res_st.json()}")

    # Check results
    res_res = client.get(f"/fuzzer/results/{job_id}?since=0")
    assert res_res.status_code == 200
    print(f"✓ GET /fuzzer/results test passed: {res_res.json()['status']}")

if __name__ == "__main__":
    test_fuzzer_root()
    test_fuzzer_start()
    print("ALL FUZZER BACKEND TESTS PASSED SUCCESSFULLY!")
