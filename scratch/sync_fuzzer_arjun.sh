#!/bin/bash
set -e

echo "Syncing fuzzer_backend..."
if [ -d "dist/API Sentinel/_internal/fuzzer_backend" ]; then
  cp -v fuzzer_backend/arjun_engine.py fuzzer_backend/main.py fuzzer_backend/wordlists.json "dist/API Sentinel/_internal/fuzzer_backend/"
fi

echo "Syncing UI files..."
# dist/_internal/ui
if [ -d "dist/API Sentinel/_internal/ui" ]; then
  cp -v ui/index.html "dist/API Sentinel/_internal/ui/index.html"
  cp -v ui/css/fuzzer.css "dist/API Sentinel/_internal/ui/css/fuzzer.css"
  cp -v ui/css/fuzzer.css "dist/API Sentinel/_internal/ui/fuzzer.css"
  cp -v ui/js/fuzzer.js "dist/API Sentinel/_internal/ui/js/fuzzer.js"
  cp -v ui/js/fuzzer.js "dist/API Sentinel/_internal/ui/js/fuzzer.js"
fi

# dist.app/Contents/Resources/ui
if [ -d "dist/API Sentinel.app/Contents/Resources/ui" ]; then
  cp -v ui/index.html "dist/API Sentinel.app/Contents/Resources/ui/index.html"
  cp -v ui/css/fuzzer.css "dist/API Sentinel.app/Contents/Resources/ui/css/fuzzer.css"
  cp -v ui/css/fuzzer.css "dist/API Sentinel.app/Contents/Resources/ui/fuzzer.css"
  cp -v ui/js/fuzzer.js "dist/API Sentinel.app/Contents/Resources/ui/js/fuzzer.js"
  cp -v ui/js/fuzzer.js "dist/API Sentinel.app/Contents/Resources/ui/fuzzer.js"
fi

echo "All mirrors synchronized successfully!"
