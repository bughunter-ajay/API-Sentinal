#!/bin/bash
set -e

echo "Syncing jsanalyser_backend files..."
for dir in \
  "dist/API Sentinel/_internal/jsanalyser_backend" \
  "dist/API Sentinel.app/Contents/Resources/jsanalyser_backend"; do
  if [ -d "$dir" ]; then
    echo "Copying to $dir..."
    cp -v jsanalyser_backend/*.py "$dir/"
  fi
done

echo "Syncing UI files..."
# index.html
for f in \
  "dist/API Sentinel/_internal/ui/index.html" \
  "dist/API Sentinel.app/Contents/Resources/ui/index.html"; do
  if [ -f "$f" ]; then
    echo "Updating $f..."
    cp -v ui/index.html "$f"
  fi
done

# jsanalyser_tester.js
for f in \
  "dist/API Sentinel/_internal/ui/js/jsanalyser_tester.js" \
  "dist/API Sentinel.app/Contents/Resources/ui/js/jsanalyser_tester.js"; do
  if [ -f "$f" ]; then
    echo "Updating $f..."
    cp -v ui/js/jsanalyser_tester.js "$f"
  fi
done

echo "JS & Secret Analyser synchronization completed across all mirrors!"
