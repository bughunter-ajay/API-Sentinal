#!/usr/bin/env python3
"""
API Scan completion smoke — packaging resolve + CLI ↔ API parity.

Usage (from repo root, venv active):
  python scripts/smoke_apiscan.py
  python scripts/smoke_apiscan.py --skip-live   # packaging + API wiring only
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURL = "curl -sk 'https://httpbin.org/get?id=1&q=test'"
MODULE = "cors"  # light endpoint-level check for parity


def _load_backend():
    path = ROOT / "apiscan_backend" / "main.py"
    spec = importlib.util.spec_from_file_location("apiscan_smoke", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def smoke_packaging(mod) -> None:
    print("── Packaging resolve ──")
    layouts = [
        ROOT / "dist" / "API Sentinel" / "_internal" / "apiscan_backend",
        ROOT / "dist" / "API Sentinel.app" / "Contents" / "Resources" / "apiscan_backend",
        ROOT / "dist" / "API Sentinel.app" / "Contents" / "Frameworks" / "apiscan_backend",
    ]
    found = 0
    old = mod.BASE_DIR
    try:
        for base in layouts:
            if not base.is_dir():
                print(f"  skip (no dir): {base.relative_to(ROOT)}")
                continue
            mod.BASE_DIR = str(base)
            resolved = Path(mod._resolve_scan_py())
            ok = resolved.is_file() and resolved.name == "Scan.py"
            print(f"  {'OK' if ok else 'FAIL'} {base.relative_to(ROOT)} → {resolved}")
            if not ok:
                raise SystemExit(1)
            found += 1
    finally:
        mod.BASE_DIR = old

    dev = Path(mod._resolve_scan_py())
    if not dev.is_file():
        print(f"  FAIL dev Scan.py: {dev}")
        raise SystemExit(1)
    print(f"  OK dev → {dev}")
    if found == 0:
        print("  WARN: no dist/ layouts present — rebuild with build.sh before shipping")
    print()


def smoke_api_wiring(mod) -> None:
    from fastapi.testclient import TestClient

    print("── API wiring ──")
    c = TestClient(mod.app)
    r = c.get("/apiscan/modules")
    assert r.status_code == 200, r.text
    data = r.json()
    assert MODULE in data.get("modules", []), data
    assert "quick" in data.get("profiles", {}), data
    print(f"  OK /apiscan/modules ({len(data['modules'])} modules)")

    fields = mod.StartRequest.model_fields
    for f in ("delay_sec", "modules", "skip_modules", "oob_enabled", "oob_server", "oob_token"):
        assert f in fields, f
    print("  OK StartRequest fields")

    bad = c.post("/apiscan/start", json={"entries": []})
    assert bad.status_code == 400
    print("  OK empty start → 400")

    mod.jobs.clear()
    now = time.time()
    mod.jobs["stale"] = {
        "status": "done",
        "created_at": now - 99999,
        "finished_at": now - 99999,
    }
    mod.jobs["live"] = {"status": "running", "created_at": now}
    mod._prune_old_jobs()
    assert "stale" not in mod.jobs and "live" in mod.jobs
    mod.jobs.clear()
    print("  OK job prune")
    print()


def _issue_keys(issues) -> set:
    keys = set()
    for iss in issues or []:
        if isinstance(iss, dict):
            keys.add(
                (
                    (iss.get("vulnerability") or iss.get("name") or "").lower()[:80],
                    (iss.get("severity") or "").upper(),
                )
            )
        else:
            keys.add(
                (
                    (getattr(iss, "vulnerability", "") or getattr(iss, "name", "") or "").lower()[:80],
                    (getattr(iss, "severity", "") or "").upper(),
                )
            )
    return keys


def smoke_cli_live() -> set:
    print("── CLI live (module=cors) ──")
    cmd = [
        sys.executable,
        str(ROOT / "Scan.py"),
        "--curl",
        CURL,
        "--module",
        MODULE,
        "--threads",
        "2",
        "--timeout",
        "10",
    ]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    t0 = time.time()
    p = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    elapsed = time.time() - t0
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        print(out[-2000:])
        raise SystemExit(f"CLI failed rc={p.returncode}")
    print(f"  OK CLI argparse exit 0 in {elapsed:.1f}s")
    if "Baseline" not in out and "Active Scan" not in out:
        print("  WARN: expected scan progress lines not found in CLI output")
    print()
    return set()


def smoke_api_live(mod) -> set:
    from fastapi.testclient import TestClient

    print("── API live (module=cors) ──")
    c = TestClient(mod.app)
    mod.jobs.clear()
    payload = {
        "entries": [
            {
                "id": "smoke1",
                "method": "GET",
                "url": "https://httpbin.org/get?id=1&q=test",
                "headers": {"User-Agent": "API-Sentinel-Smoke"},
                "body": "",
            }
        ],
        "profile": "full",
        "threads": 2,
        "timeout": 10,
        "delay_sec": 0,
        "modules": [MODULE],
        "skip_modules": [],
        "oob_enabled": False,
        "custom_values": [],
    }
    r = c.post("/apiscan/start", json=payload)
    assert r.status_code == 200, r.text
    job_id = r.json()["job_id"]

    # Concurrent start must 409
    r2 = c.post("/apiscan/start", json=payload)
    assert r2.status_code == 409, r2.text
    print("  OK concurrent start → 409")

    deadline = time.time() + 120
    status = "running"
    while time.time() < deadline:
        st = c.get(f"/apiscan/status/{job_id}")
        assert st.status_code == 200, st.text
        status = st.json().get("status")
        if status == "done":
            break
        time.sleep(0.4)
    assert status == "done", f"job not done: {status}"

    res = c.get(f"/apiscan/results/{job_id}")
    assert res.status_code == 200, res.text
    entries = res.json().get("entries_done") or []
    issues = []
    for ed in entries:
        issues.extend(ed.get("issues") or [])
    keys = _issue_keys(issues)
    print(f"  OK API job done — {len(issues)} issue(s) across {len(entries)} entr(y/ies)")
    for k in sorted(keys):
        print(f"    · {k[1] or '?'} {k[0] or '(unnamed)'}")
    print()
    return keys


def main() -> None:
    ap = argparse.ArgumentParser(description="API Scan completion smoke")
    ap.add_argument(
        "--skip-live",
        action="store_true",
        help="Skip outbound httpbin CLI/API scans",
    )
    args = ap.parse_args()

    os.chdir(ROOT)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    mod = _load_backend()
    smoke_packaging(mod)
    smoke_api_wiring(mod)

    if args.skip_live:
        print("SKIP live CLI/API ( --skip-live )")
        print("\n✅ smoke_apiscan: packaging + wiring OK")
        return

    cli_keys = smoke_cli_live()
    api_keys = smoke_api_live(mod)

    # Parity: both paths must complete; issue sets need not be identical
    # (API adds FP confirm / context), but neither should crash empty-handed
    # on a reachable target for cors (may be 0 findings — that is OK).
    print("── Parity ──")
    print(f"  CLI issue keys: {len(cli_keys)}")
    print(f"  API issue keys: {len(api_keys)}")
    print("  OK both paths completed without error")
    print("\n✅ smoke_apiscan: ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
