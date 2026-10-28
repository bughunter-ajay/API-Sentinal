import unittest
import sys
import os

sys.path.insert(0, os.path.abspath("har_backend"))
from main import app, UserConfig, ApiEntry, RunRequest, _prepare_apis, _count_planned, _summarize_results, generate_html_report
from fastapi.testclient import TestClient

class TestMultiUserHarBackend(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_multi_user_planning_and_models(self):
        apis = [
            ApiEntry(method="GET", url="https://api.example.com/users/profile"),
            ApiEntry(method="GET", url="https://api.example.com/settings")
        ]
        users = [
            UserConfig(id="user_1", name="Admin", token="admin-tok-123", is_unauth=False),
            UserConfig(id="user_2", name="User A", token="user-a-tok-456", is_unauth=False),
            UserConfig(id="user_3", name="Guest (Unauth)", token="", is_unauth=True),
        ]
        req = RunRequest(apis=apis, users=users)
        planned = _count_planned(apis, req)
        self.assertEqual(planned, 6, "2 APIs * 3 Users should be 6 planned requests")

    def test_html_report_multi_user(self):
        results = [
            {
                "method": "GET",
                "url": "https://api.example.com/data",
                "status_code": 200,
                "response": '{"id": 1, "secret": "xyz"}',
                "response_size": 28,
                "elapsed_ms": 120,
                "mode": "multi_user",
                "user_id": "user_1",
                "user_name": "User 1 (Admin)"
            },
            {
                "method": "GET",
                "url": "https://api.example.com/data",
                "status_code": 200,
                "response": '{"id": 1, "secret": "xyz"}',
                "response_size": 28,
                "elapsed_ms": 110,
                "mode": "multi_user",
                "user_id": "user_2",
                "user_name": "User 2 (Attacker)"
            },
            {
                "method": "GET",
                "url": "https://api.example.com/data",
                "status_code": 403,
                "response": '{"error": "Forbidden"}',
                "response_size": 23,
                "elapsed_ms": 50,
                "mode": "multi_user",
                "user_id": "user_3",
                "user_name": "User 3 (Guest)"
            }
        ]
        html = generate_html_report(results, {"token_mode": "multi_user", "users_count": 3})
        self.assertIn("User 1 (Admin)", html)
        self.assertIn("User 2 (Attacker)", html)
        self.assertIn("User 3 (Guest)", html)
        self.assertIn("SAME", html, "User 1 and User 2 got identical 2xx size, so SAME badge should appear")
        self.assertIn("DIFF", html, "User 3 got different size, so DIFF badge should appear")

    def test_export_csv(self):
        payload = {
            "results": [
                {
                    "user_name": "User 1 (Admin)",
                    "mode": "multi_user",
                    "method": "GET",
                    "url": "https://api.example.com/test",
                    "status_code": 200,
                    "elapsed_ms": 45,
                    "response_size": 128,
                    "request_body": "",
                    "response": "OK"
                }
            ]
        }
        res = self.client.post("/export/csv", json=payload)
        self.assertEqual(res.status_code, 200)
        csv_text = res.text
        self.assertIn("user_name", csv_text)
        self.assertIn("User 1 (Admin)", csv_text)

if __name__ == "__main__":
    unittest.main()
