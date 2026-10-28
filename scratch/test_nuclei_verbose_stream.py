import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nuclei_backend.nuclei_engine import ScanJob

def test_verbose_and_stats_queues():
    job = ScanJob(
        job_id="test_verb_123",
        target_type="curl",
        base_url="https://test.api",
        targets=["https://test.api/v1/user"],
        headers={},
        tags=["api"]
    )

    q = job.subscribe()

    # Emit standard log
    job.add_log("[INF] Scan initialized")
    # Emit verbose probe
    job.add_verbose("[VER] [swagger-enum] Sent HTTP request to https://test.api/v1/user")
    # Emit stats tick
    job.add_stats_tick("Templates: 12 | RPS: 4 | Requests: 8/24 (33%)")

    items = list(q)
    assert len(items) == 3, f"Expected 3 items in queue, got {len(items)}"

    log_item = items[0]
    assert log_item["type"] == "log"
    assert "Scan initialized" in log_item["message"]

    verb_item = items[1]
    assert verb_item["type"] == "verbose"
    assert "Sent HTTP request" in verb_item["message"]

    stat_item = items[2]
    assert stat_item["type"] == "stats_tick"
    assert "RPS: 4" in stat_item["message"]

    job.unsubscribe(q)
    print("✅ Verbose and stats queue dispatch tested successfully!")

if __name__ == "__main__":
    test_verbose_and_stats_queues()
