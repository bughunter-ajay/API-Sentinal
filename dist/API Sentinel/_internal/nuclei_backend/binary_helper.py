"""
Nuclei Binary & Environment Helper
Detects installed Nuclei CLI binary, templates directory, and version.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional


def find_nuclei_binary() -> Optional[str]:
    """Search for nuclei executable in system PATH and common platform locations."""
    # 1. System PATH
    p = shutil.which("nuclei")
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return os.path.abspath(p)

    # 2. Local app bin directory
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "bin", "nuclei"),
        os.path.join(os.path.dirname(here), "bin", "nuclei"),
        # Mac Homebrew standard paths
        "/opt/homebrew/bin/nuclei",
        "/usr/local/bin/nuclei",
        # Linux standard paths
        "/usr/bin/nuclei",
        "/home/linuxbrew/.linuxbrew/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
    ]

    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)

    return None


def get_nuclei_info() -> Dict[str, Any]:
    """Returns detailed status of Nuclei binary, version, and templates."""
    bin_path = find_nuclei_binary()
    if not bin_path:
        return {
            "installed": False,
            "binary_path": None,
            "version": None,
            "templates_dir": None,
            "templates_count": 0,
            "install_guide": {
                "mac": "brew install nuclei",
                "go": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "docs": "https://github.com/projectdiscovery/nuclei#install-nuclei",
            },
        }

    version_str = "Installed"
    try:
        proc = subprocess.run([bin_path, "-version"], capture_output=True, text=True, timeout=5)
        out = (proc.stdout or proc.stderr or "").strip()
        import re
        out_clean = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", out)
        for line in out_clean.splitlines():
            if "version:" in line.lower() or "nuclei" in line.lower():
                # Extract e.g. "v3.11.1" or "Nuclei Engine Version: v3.11.1"
                version_str = line.strip().lstrip("[").rstrip("]").strip()
                if "version:" in version_str.lower():
                    parts = version_str.split(":", 1)
                    if len(parts) > 1:
                        version_str = parts[1].strip()
                break
    except Exception:
        pass

    # Check templates path
    templates_dir = None
    templates_count = 0
    t_candidates = [
        os.path.expanduser("~/.local/nuclei-templates"),
        os.path.expanduser("~/nuclei-templates"),
    ]
    for tc in t_candidates:
        if os.path.isdir(tc):
            templates_dir = tc
            # Estimate count
            try:
                c = 0
                for _, _, files in os.walk(tc):
                    c += sum(1 for f in files if f.endswith(".yaml") or f.endswith(".yml"))
                templates_count = c
            except Exception:
                pass
            break

    return {
        "installed": True,
        "binary_path": bin_path,
        "version": version_str,
        "templates_dir": templates_dir,
        "templates_count": templates_count,
        "install_guide": None,
    }
