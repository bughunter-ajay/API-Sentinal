import sys
import time
from fastapi.testclient import TestClient
from fuzzer_backend.main import app

def test_arjun_endpoints():
    client = TestClient(app)
    
    # 1. Test root
    r = client.get("/")
    assert r.status_code == 200, f"Root failed: {r.text}"
    print("✓ Backend root responding.")

    # 2. Start an Arjun job
    test_curl = "curl -X GET 'https://httpbin.org/get'"
    r = client.post("/fuzzer/arjun/start", json={
        "curl": test_curl,
        "param_type": "query",
        "wordlist_type": "custom",
        "custom_wordlist": ["debug", "test", "admin"],
        "batch_size": 5,
        "threads": 2
    })
    assert r.status_code == 200, f"Start failed: {r.text}"
    job_data = r.json()
    job_id = job_data["job_id"]
    print(f"✓ Arjun job started: {job_id}")

    # 3. Check status
    time.sleep(0.5)
    r = client.get(f"/fuzzer/arjun/status/{job_id}")
    assert r.status_code == 200, f"Status failed: {r.text}"
    st = r.json()
    print(f"✓ Status retrieved: status={st['status']}, logs={len(st['new_logs'])}, total={st['total']}")

    # 4. Stop job
    r = client.post(f"/fuzzer/arjun/stop/{job_id}")
    assert r.status_code == 200, f"Stop failed: {r.text}"
    assert r.json().get("status") == "stopped"
    print("✓ Arjun job stopped successfully.")

if __name__ == "__main__":
    test_arjun_endpoints()
    print("\nALL ARJUN TESTS PASSED PERFECTLY!")
