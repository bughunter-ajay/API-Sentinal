import os, sys, time
from fastapi.testclient import TestClient

sys.path.insert(0, ".")
from fuzzer_backend.main import app, parse_any_request
from fuzzer_backend.arjun_engine import ArjunJobManager

def test_url_formats():
    test_cases = [
        "https://dev.visionwaves.com",
        "dev.visionwaves.com",
        "GET https://dev.visionwaves.com HTTP/1.1\nHost: dev.visionwaves.com",
        "curl -X GET 'https://dev.visionwaves.com'",
        "curl 'https://dev.visionwaves.com'",
    ]

    for tc in test_cases:
        parsed = parse_any_request(tc)
        print(f"Input: {tc!r}")
        print(f"  -> Method: {parsed['method']}, URL: {parsed['url']}")
        assert parsed["url"].startswith("http"), f"Failed to get valid URL for {tc!r}: {parsed}"
        assert parsed["method"] in ("GET", "POST"), f"Invalid method for {tc!r}: {parsed}"

    print("✓ All request formats parsed successfully!")

def test_arjun_job_with_plain_url():
    client = TestClient(app)
    # Start Arjun with plain URL!
    r = client.post("/fuzzer/arjun/start", json={
        "curl": "https://httpbin.org/get",
        "param_type": "query",
        "wordlist_type": "custom",
        "custom_wordlist": ["debug", "test"],
        "batch_size": 5,
        "threads": 1
    })
    assert r.status_code == 200, f"Start failed: {r.text}"
    job_id = r.json()["job_id"]
    time.sleep(0.5)
    
    st = client.get(f"/fuzzer/arjun/status/{job_id}").json()
    print("Status for plain URL job:", st["status"])
    print("Logs:", [l["msg"] for l in st.get("new_logs", [])])
    assert st["status"] in ("running", "finished"), f"Job failed unexpectedly: {st}"
    client.post(f"/fuzzer/arjun/stop/{job_id}")
    print("✓ Arjun successfully processed plain URL target!")

if __name__ == "__main__":
    test_url_formats()
    test_arjun_job_with_plain_url()
    print("\nALL URL FORMAT TESTS PASSED!")
