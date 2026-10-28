import sys
import os
import json

sys.path.insert(0, os.path.abspath("har_backend"))

# Let's test the new implementation by mocking or running directly
from main import esc, fmt_size

def test_full_report_generation():
    dummy_results = [
        {
            "method": "GET",
            "url": "https://api.example.com/api/v1/user/profile",
            "status_code": 200,
            "response": '{"id": 1, "name": "Pooja", "email": "pooja@example.com"}',
            "request_body": "",
            "response_size": 56,
            "elapsed_ms": 120,
            "mode": "multi_user",
            "user_id": "user_1",
            "user_name": "Pooja.lohiya",
            "is_unauth": False
        },
        {
            "method": "GET",
            "url": "https://api.example.com/api/v1/user/profile",
            "status_code": 200,
            "response": '{"id": 1, "name": "Pooja", "email": "pooja@example.com"}',
            "request_body": "",
            "response_size": 56,
            "elapsed_ms": 115,
            "mode": "multi_user",
            "user_id": "user_2",
            "user_name": "Priyanshi.Gupta",
            "is_unauth": False
        },
        {
            "method": "GET",
            "url": "https://api.example.com/api/v1/user/profile",
            "status_code": 200,
            "response": '{"id": 1, "name": "Pooja", "email": "pooja@example.com"}',
            "request_body": "",
            "response_size": 56,
            "elapsed_ms": 95,
            "mode": "multi_user",
            "user_id": "user_3",
            "user_name": "Guest.Unauth",
            "is_unauth": True
        }
    ]
    # Import and test
    from main import generate_html_report
    html = generate_html_report(dummy_results, {"token_mode": "multi_user", "users_count": 3})
    assert "f-auth" not in html, "f-auth should not be in html"
    assert "f-unauth" not in html, "f-unauth should not be in html"
    assert "AUTH BYPASS" in html
    assert "Compare APIs & Responses" in html or "Compare APIs" in html
    print("Report test passed!")

if __name__ == "__main__":
    test_full_report_generation()
