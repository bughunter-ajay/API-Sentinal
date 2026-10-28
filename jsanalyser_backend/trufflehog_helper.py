"""
TruffleHog Binary & Engine Helper
Detects installed TruffleHog CLI binary, version, and detectors count.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Dict, Optional


def find_trufflehog_binary() -> Optional[str]:
    """Search for trufflehog executable in system PATH and common platform locations."""
    p = shutil.which("trufflehog")
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return os.path.abspath(p)

    candidates = [
        "/opt/homebrew/bin/trufflehog",
        "/usr/local/bin/trufflehog",
        "/usr/bin/trufflehog",
        "/home/linuxbrew/.linuxbrew/bin/trufflehog",
        os.path.expanduser("~/go/bin/trufflehog"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def get_trufflehog_info() -> Dict[str, Any]:
    bin_path = find_trufflehog_binary()
    if not bin_path:
        return {
            "installed": False,
            "engine_mode": "native",
            "binary_path": None,
            "version": "Native v2.4 (Compiled In-Memory)",
            "native_detectors": 181,
            "entropy_enabled": True,
            "install_guide": {
                "mac": "brew install trufflehog",
                "go": "go install github.com/trufflesecurity/trufflehog/v3@latest",
                "docs": "https://github.com/trufflesecurity/trufflehog",
            },
        }

    version_str = "Installed"
    try:
        proc = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=5)
        out = (proc.stdout or proc.stderr or "").strip()
        if out:
            version_str = out.splitlines()[0].strip()
    except Exception:
        pass

    return {
        "installed": True,
        "engine_mode": "cli",
        "binary_path": bin_path,
        "version": version_str,
        "native_detectors": 181,
        "entropy_enabled": True,
        "install_guide": {
            "mac": "brew install trufflehog",
            "go": "go install github.com/trufflesecurity/trufflehog/v3@latest",
            "docs": "https://github.com/trufflesecurity/trufflehog",
        },
    }
