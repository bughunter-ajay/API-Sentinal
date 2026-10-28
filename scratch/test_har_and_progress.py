#!/usr/bin/env python3
"""
Test Suite for HAR Import & Live Progress Bar Implementation
"""
import sys
import os
import json
import time
import base64

# Add workspace to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from nuclei_backend.har_parser import parse_har_file, _inspect_jwt_token
from nuclei_backend.nuclei_engine import create_job, ScanJob

def test_jwt_expiry_check():
    print("[1] Testing JWT Token Expiration Detection...")
    now = time.time()
    
    # 1. Expired JWT
    expired_payload = {"sub": "12345", "exp": int(now - 3600), "user": "admin"}
    p_b64 = base64.urlsafe_b64encode(json.dumps(expired_payload).encode()).decode().rstrip("=")
    expired_jwt = f"eyJhbGciOiJIUzI1NiJ9.{p_b64}.c2lnbmF0dXJl"
    
    res1 = _inspect_jwt_token(f"Bearer {expired_jwt}")
    assert res1["is_jwt"] is True, "Should identify as JWT"
    assert res1["expired"] is True, "Should identify expired token"
    print("   ✓ Expired token properly flagged as expired: True")

    # 2. Fresh / Valid JWT
    valid_payload = {"sub": "67890", "exp": int(now + 7200), "user": "tester"}
    p2_b64 = base64.urlsafe_b64encode(json.dumps(valid_payload).encode()).decode().rstrip("=")
    valid_jwt = f"eyJhbGciOiJIUzI1NiJ9.{p2_b64}.c2lnbmF0dXJl"
    
    res2 = _inspect_jwt_token(valid_jwt)
    assert res2["is_jwt"] is True, "Should identify as JWT"
    assert res2["expired"] is False, "Should identify valid token as non-expired"
    print("   ✓ Valid token properly flagged as expired: False")


def test_har_parsing():
    print("\n[2] Testing HAR Parsing & Static Asset Filtering...")
    now = time.time()
    expired_payload = {"exp": int(now - 1800)}
    p_b64 = base64.urlsafe_b64encode(json.dumps(expired_payload).encode()).decode().rstrip("=")
    expired_jwt = f"Bearer eyJhbGciOiJIUzI1NiJ9.{p_b64}.sig"

    sample_har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.sentinel-test.com/assets/logo.png",
                        "headers": []
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.sentinel-test.com/styles/theme.css",
                        "headers": []
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.sentinel-test.com/api/v1/profile",
                        "headers": [
                            {"name": "Authorization", "value": expired_jwt},
                            {"name": "Accept", "value": "application/json"}
                        ]
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.sentinel-test.com/api/v1/orders?filter=active",
                        "headers": [
                            {"name": "Authorization", "value": expired_jwt},
                            {"name": "Content-Type", "value": "application/json"}
                        ]
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.sentinel-test.com/api/v1/profile", # Duplicate
                        "headers": []
                    }
                }
            ]
        }
    }

    res = parse_har_file(json.dumps(sample_har))
    assert res["success"] is True, f"Parsing failed: {res.get('error')}"
    assert res["total_entries"] == 5, f"Expected 5 entries, got {res['total_entries']}"
    assert res["total_endpoints"] == 2, f"Expected 2 API endpoints after filtering static assets and duplicates, got {res['total_endpoints']}"
    assert res["detected_base_url"] == "https://api.sentinel-test.com", f"Expected base URL, got {res['detected_base_url']}"
    assert res["token_found"] is True, "Token should be flagged as found"
    assert res["token_expired"] is True, "Token should be flagged as expired"
    assert "Authorization" in res["headers"], "Authorization header should be extracted"
    
    print(f"   ✓ Extracted {res['total_endpoints']} clean endpoints (filtered .png and .css)")
    print(f"   ✓ Dominant Base URL detected: {res['detected_base_url']}")
    print(f"   ✓ Expired token alert status: {res['token_expired']}")


def test_missing_token_and_deduplication():
    print("\n[3] Testing Missing Token Detection & Route-Level Deduplication...")
    # HAR with NO token and multiple calls to the same endpoint with dynamic IDs & query params
    sample_har = {
        "log": {
            "version": "1.2",
            "entries": [
                # Endpoint 1: Count (called 3 times with different query filters)
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/approval-request/count?filter=all"}},
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/approval-request/count?filter=pending"}},
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/approval-request/count"}},
                # Endpoint 2: Resource with dynamic numeric IDs (called 3 times with IDs 920, 921, 922)
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/generic-change-requests/920"}},
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/generic-change-requests/921"}},
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/generic-change-requests/922"}},
                # Endpoint 3: Resource with UUIDs
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/attachments/01a12ef8-7dec-7392-b076-4c712bf2df10"}},
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/attachments/01a12ef8-7dec-7392-b076-4c712bf2df11"}},
                # Endpoint 4: Distinct endpoint
                {"request": {"method": "GET", "url": "https://api.visionwaves.com/rest/notifications/counts"}},
            ]
        }
    }

    res = parse_har_file(json.dumps(sample_har))
    assert res["success"] is True
    # Out of 9 entries, 5 are duplicates (2 for count, 2 for change-requests, 1 for attachments), so only 4 unique endpoints
    assert res["token_found"] is False, "Should detect that NO token was present"
    assert res["token_expired"] is False, "Should be False when no token"
    assert res["total_endpoints"] == 4, f"Expected 4 unique endpoints, got {res['total_endpoints']}"
    assert res["duplicates_removed"] == 5, f"Expected 5 duplicates removed, got {res['duplicates_removed']}"
    
    print(f"   ✓ Accurately detected Token Found: {res['token_found']} (Token missing from HAR)")
    print(f"   ✓ Smart Deduplication: Removed {res['duplicates_removed']} duplicate API calls out of {res['total_entries']} entries")
    print(f"   ✓ Final unique endpoints ready to scan: {res['total_endpoints']}")


def test_progress_bar_tick():
    print("\n[4] Testing Scanning Progress Bar Stats Ticker...")
    job = create_job(
        target_type="har",
        base_url="https://api.example.com",
        targets=["https://api.example.com/api/v1/test"],
        headers={},
        tags=["api", "misconfig"],
    )
    
    # Simulate Nuclei stderr stats line
    test_tick = "[INF] [2026-10-12 16:00:00] Templates: 140 | RPS: 24 | Requests: 84/200 (42%)"
    job.add_stats_tick(test_tick)
    
    assert job.stats["progress_percent"] == 42, f"Expected 42%, got {job.stats['progress_percent']}"
    assert job.stats["requests_probed"] == 84, f"Expected 84, got {job.stats['requests_probed']}"
    assert job.stats["requests_total"] == 200, f"Expected 200, got {job.stats['requests_total']}"
    assert job.stats["rps"] == 24, f"Expected 24 RPS, got {job.stats['rps']}"
    
    print("   ✓ Progress percentage correctly parsed: 42%")
    print(f"   ✓ Current/Total probes parsed: {job.stats['requests_probed']}/{job.stats['requests_total']}")
    print(f"   ✓ RPS parsed: {job.stats['rps']}")


if __name__ == "__main__":
    test_jwt_expiry_check()
    test_har_parsing()
    test_missing_token_and_deduplication()
    test_progress_bar_tick()
    print("\n🎉 ALL TESTS PASSED SUCCESSFULLY! ZERO CONFLICTS DETECTED.")
