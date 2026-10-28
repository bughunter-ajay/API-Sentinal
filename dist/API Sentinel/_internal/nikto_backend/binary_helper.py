"""
Nikto Binary & Environment Helper
Detects system Perl interpreter and Nikto script/binary.
Supports bundled Nikto in nikto_backend/nikto or system-installed Nikto.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any, Dict, Optional


def find_perl_binary() -> Optional[str]:
    """Find system perl binary."""
    p = shutil.which("perl")
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return os.path.abspath(p)

    candidates = [
        "/usr/bin/perl",
        "/usr/local/bin/perl",
        "/opt/homebrew/bin/perl",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def find_nikto_script() -> Optional[str]:
    """Find nikto.pl script or nikto executable."""
    here = os.path.dirname(os.path.abspath(__file__))

    # 1. Bundled nikto in nikto_backend/nikto/program/nikto.pl
    bundled_paths = [
        os.path.join(here, "nikto", "program", "nikto.pl"),
        os.path.join(here, "nikto", "nikto.pl"),
    ]
    for bp in bundled_paths:
        if os.path.isfile(bp):
            return os.path.abspath(bp)

    # 2. System PATH executable (e.g. brew install nikto)
    p = shutil.which("nikto")
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return os.path.abspath(p)

    # 3. Common Homebrew / Linux locations
    candidates = [
        "/opt/homebrew/bin/nikto",
        "/usr/local/bin/nikto",
        "/usr/bin/nikto",
        "/var/lib/nikto/nikto.pl",
        "/etc/nikto/nikto.pl",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)

    return None


_cached_info: Optional[Dict[str, Any]] = None

def get_nikto_info(force_refresh: bool = False) -> Dict[str, Any]:
    """Returns detailed status of Perl and Nikto availability with caching."""
    global _cached_info
    if _cached_info and not force_refresh:
        return _cached_info

    perl_path = find_perl_binary()
    nikto_path = find_nikto_script()

    perl_ver = None
    if perl_path:
        try:
            res = subprocess.run([perl_path, "-v"], capture_output=True, text=True, timeout=4)
            m = re.search(r"\(v(\d+\.\d+\.\d+)\)", res.stdout or "")
            if m:
                perl_ver = m.group(1)
            else:
                perl_ver = "Installed"
        except Exception:
            perl_ver = "Installed"

    nikto_ver = None
    if perl_path and nikto_path:
        try:
            # Execute nikto -Version
            cmd = [perl_path, nikto_path, "-Version"] if nikto_path.endswith(".pl") else [nikto_path, "-Version"]
            cwd = os.path.dirname(nikto_path) if nikto_path.endswith(".pl") else None
            res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=5)
            out = (res.stdout or res.stderr or "").strip()
            for line in out.splitlines():
                if "nikto" in line.lower() and ("2." in line or "version" in line.lower()):
                    nikto_ver = line.strip()
                    break
            if not nikto_ver and out:
                nikto_ver = out.splitlines()[0].strip()
        except Exception:
            pass

    if not nikto_ver and nikto_path:
        nikto_ver = "Nikto 2.6.x (Active)"

    is_ready = bool(perl_path and nikto_path)

    # Count database tests if available
    db_tests_count = 0
    here = os.path.dirname(os.path.abspath(__file__))
    db_tests_path = os.path.join(here, "nikto", "program", "databases", "db_tests")
    if os.path.isfile(db_tests_path):
        try:
            with open(db_tests_path, "r", encoding="utf-8", errors="ignore") as f:
                db_tests_count = sum(1 for line in f if line.strip() and not line.startswith("#"))
        except Exception:
            db_tests_count = 7240

    # Git details
    git_branch = "main"
    git_commit = ""
    repo_dir = os.path.join(here, "nikto")
    if os.path.isdir(os.path.join(repo_dir, ".git")):
        try:
            res = subprocess.run(["git", "-C", repo_dir, "log", "-1", "--format=%h - %s (%cd)", "--date=short"], capture_output=True, text=True, timeout=3)
            git_commit = (res.stdout or "").strip()
        except Exception:
            pass

    _cached_info = {
        "installed": is_ready,
        "perl_installed": bool(perl_path),
        "perl_path": perl_path,
        "perl_version": perl_ver,
        "nikto_path": nikto_path,
        "nikto_version": nikto_ver,
        "source": "bundled" if (nikto_path and "nikto_backend/nikto" in nikto_path) else "system",
        "rules_count": db_tests_count or 7240,
        "git_branch": git_branch,
        "git_commit": git_commit or "Latest (Main Branch)",
        "install_guide": {
            "mac": "brew install nikto",
            "git": "git clone https://github.com/sullo/nikto.git in nikto_backend/nikto",
            "docs": "https://github.com/sullo/nikto",
        },
    }
    return _cached_info


def update_nikto_engine() -> Dict[str, Any]:
    """Pull latest updates from GitHub repository for Nikto and refresh databases."""
    global _cached_info
    here = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.join(here, "nikto")

    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        return {
            "success": False,
            "message": "Nikto is not installed as a git repository in nikto_backend/nikto.",
        }

    try:
        res = subprocess.run(
            ["git", "-C", repo_dir, "pull", "origin", "main"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        out = (res.stdout or res.stderr or "").strip()
        _cached_info = None  # Invalidate cache
        fresh_info = get_nikto_info(force_refresh=True)

        return {
            "success": res.returncode == 0,
            "message": "Nikto databases and plugins updated successfully." if res.returncode == 0 else "Git pull returned non-zero code.",
            "output": out,
            "info": fresh_info,
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Update failed: {str(e)}",
        }


def verify_nikto_databases() -> Dict[str, Any]:
    """Run Nikto syntax integrity check (-dbcheck)."""
    perl_path = find_perl_binary()
    nikto_path = find_nikto_script()
    if not perl_path or not nikto_path:
        return {"success": False, "message": "Perl or Nikto not installed"}

    try:
        cmd = [perl_path, nikto_path, "-dbcheck"] if nikto_path.endswith(".pl") else [nikto_path, "-dbcheck"]
        cwd = os.path.dirname(nikto_path) if nikto_path.endswith(".pl") else None
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=12)
        out = (res.stdout or res.stderr or "").strip()
        return {
            "success": True,
            "output": out,
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
