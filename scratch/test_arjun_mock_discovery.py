import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from fuzzer_backend.arjun_engine import ArjunJobManager

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        
        # Secret parameter 'secret_admin_token' changes response!
        if "secret_admin_token" in qs:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Debug-Mode", "Enabled")
            self.end_headers()
            self.wfile.write(b'{"status":"admin_access_granted","debug":true}')
        elif "echo_param" in qs:
            val = qs["echo_param"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Echo response: {val}".encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"normal","data":[]}')

    def log_message(self, format, *args):
        pass

def run_test():
    server = HTTPServer(("127.0.0.1", 19283), MockHandler)
    st = threading.Thread(target=server.serve_forever, daemon=True)
    st.start()

    manager = ArjunJobManager()
    curl = "curl -X GET 'http://127.0.0.1:19283/api/v1/test'"
    
    # Custom wordlist with 2 real ones and dummy ones
    wordlist = ["foo", "bar", "secret_admin_token", "baz", "echo_param", "qux"]
    
    job_id = manager.start_job(
        curl=curl,
        param_type="query",
        wordlist_type="custom",
        custom_wordlist=wordlist,
        batch_size=3,
        threads=2
    )

    print(f"Started Arjun test job {job_id}")
    for _ in range(50):
        time.sleep(0.1)
        st_data = manager.get_status(job_id)
        if st_data["status"] in ("finished", "stopped"):
            break

    st_data = manager.get_status(job_id)
    print("Job status:", st_data["status"])
    print("Tested:", st_data["tested"], "/", st_data["total"])
    print("Discovered count:", st_data["discovered_count"])
    for d in st_data["discovered_params"]:
        print(f"  -> Discovered: {d['name']} | Reason: {d['reason']}")

    assert st_data["discovered_count"] >= 2, f"Expected at least 2 discovered params, got {st_data['discovered_count']}"
    found_names = [d["name"] for d in st_data["discovered_params"]]
    assert "secret_admin_token" in found_names, "secret_admin_token should be discovered!"
    assert "echo_param" in found_names, "echo_param should be discovered!"

    print("\n✓ ARJUN DIFFERENTIAL DETECTION TEST VERIFIED 100% SUCCEEDED!")
    server.shutdown()

if __name__ == "__main__":
    run_test()
