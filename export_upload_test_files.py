#!/usr/bin/env python3
"""Regenerate upload_manual_test_files/ from the live test suite."""
import os, sys, shutil

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "upload_backend"))
from main import export_test_files  # noqa: E402

OUT = os.path.join(ROOT, "upload_manual_test_files")
PROFILE = sys.argv[1] if len(sys.argv) > 1 else "generic"

if os.path.isdir(OUT):
    shutil.rmtree(OUT)
info = export_test_files(OUT, profile=PROFILE)
print(f"✅ Wrote {info['count']} files → {info['out_dir']}")
print(f"   Manifest: {info['manifest']}")
print(f"   Profile : {info['profile']}")
