#!/bin/bash
set -e

echo "Syncing jwt_backend files..."
for base in \
  "dist/API Sentinel/_internal" \
  "dist/API Sentinel.app/Contents/Resources"; do
  if [ -d "$base" ]; then
    dir="$base/jwt_backend"
    echo "Ensuring $dir exists..."
    mkdir -p "$dir"
    echo "Copying to $dir..."
    cp -v jwt_backend/*.py "$dir/"
    cp -v curl_parser.py "$base/" 2>/dev/null || true
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

# jwt.js
for f in \
  "dist/API Sentinel/_internal/ui/js/jwt.js" \
  "dist/API Sentinel.app/Contents/Resources/ui/js/jwt.js"; do
  if [ -f "$f" ]; then
    echo "Updating $f..."
    cp -v ui/js/jwt.js "$f"
  fi
done

# jwt.css
for f in \
  "dist/API Sentinel/_internal/ui/css/jwt.css" \
  "dist/API Sentinel.app/Contents/Resources/ui/css/jwt.css"; do
  if [ -f "$f" ]; then
    echo "Updating $f..."
    cp -v ui/css/jwt.css "$f"
  fi
done

echo "JWT Tool synchronization completed successfully!"
