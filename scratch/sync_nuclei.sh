#!/bin/bash
set -e

echo "Syncing nuclei_backend..."
mkdir -p "3_Apps/nuclei_backend"
cp -v nuclei_backend/*.py "3_Apps/nuclei_backend/"

if [ -d "dist/API Sentinel/_internal/nuclei_backend" ]; then
  cp -v nuclei_backend/*.py "dist/API Sentinel/_internal/nuclei_backend/"
fi

if [ -d "3_Apps/dist/API Sentinel/_internal/nuclei_backend" ]; then
  cp -v nuclei_backend/*.py "3_Apps/dist/API Sentinel/_internal/nuclei_backend/"
fi

if [ -d "3_Apps/dist/API Sentinel.app/Contents/Resources/nuclei_backend" ]; then
  cp -v nuclei_backend/*.py "3_Apps/dist/API Sentinel.app/Contents/Resources/nuclei_backend/"
fi

if [ -d "3_Apps/dist/API Sentinel.app/Contents/Frameworks/nuclei_backend" ]; then
  cp -v nuclei_backend/*.py "3_Apps/dist/API Sentinel.app/Contents/Frameworks/nuclei_backend/"
fi

echo "Syncing UI files..."
# 3_Apps/ui
cp -v ui/index.html "3_Apps/ui/index.html"
cp -v ui/css/nuclei.css "3_Apps/ui/css/nuclei.css"
cp -v ui/css/nuclei.css "3_Apps/ui/nuclei.css"
cp -v ui/js/nuclei.js "3_Apps/ui/js/nuclei.js"
cp -v ui/js/nuclei.js "3_Apps/ui/nuclei.js"

# dist/_internal/ui
if [ -d "dist/API Sentinel/_internal/ui" ]; then
  cp -v ui/index.html "dist/API Sentinel/_internal/ui/index.html"
  cp -v ui/css/nuclei.css "dist/API Sentinel/_internal/ui/css/nuclei.css"
  cp -v ui/css/nuclei.css "dist/API Sentinel/_internal/ui/nuclei.css"
  cp -v ui/js/nuclei.js "dist/API Sentinel/_internal/ui/js/nuclei.js"
  cp -v ui/js/nuclei.js "dist/API Sentinel/_internal/ui/nuclei.js"
fi

# dist.app/Contents/Resources/ui
if [ -d "dist/API Sentinel.app/Contents/Resources/ui" ]; then
  cp -v ui/index.html "dist/API Sentinel.app/Contents/Resources/ui/index.html"
  cp -v ui/css/nuclei.css "dist/API Sentinel.app/Contents/Resources/ui/css/nuclei.css"
  cp -v ui/css/nuclei.css "dist/API Sentinel.app/Contents/Resources/ui/nuclei.css"
  cp -v ui/js/nuclei.js "dist/API Sentinel.app/Contents/Resources/ui/js/nuclei.js"
  cp -v ui/js/nuclei.js "dist/API Sentinel.app/Contents/Resources/ui/nuclei.js"
fi

# 3_Apps/dist/_internal/ui
if [ -d "3_Apps/dist/API Sentinel/_internal/ui" ]; then
  cp -v ui/index.html "3_Apps/dist/API Sentinel/_internal/ui/index.html"
  cp -v ui/css/nuclei.css "3_Apps/dist/API Sentinel/_internal/ui/css/nuclei.css"
  cp -v ui/css/nuclei.css "3_Apps/dist/API Sentinel/_internal/ui/nuclei.css"
  cp -v ui/js/nuclei.js "3_Apps/dist/API Sentinel/_internal/ui/js/nuclei.js"
  cp -v ui/js/nuclei.js "3_Apps/dist/API Sentinel/_internal/ui/nuclei.js"
fi

# 3_Apps/dist.app/Contents/Resources/ui
if [ -d "3_Apps/dist/API Sentinel.app/Contents/Resources/ui" ]; then
  cp -v ui/index.html "3_Apps/dist/API Sentinel.app/Contents/Resources/ui/index.html"
  cp -v ui/css/nuclei.css "3_Apps/dist/API Sentinel.app/Contents/Resources/ui/css/nuclei.css"
  cp -v ui/css/nuclei.css "3_Apps/dist/API Sentinel.app/Contents/Resources/ui/nuclei.css"
  cp -v ui/js/nuclei.js "3_Apps/dist/API Sentinel.app/Contents/Resources/ui/js/nuclei.js"
  cp -v ui/js/nuclei.js "3_Apps/dist/API Sentinel.app/Contents/Resources/ui/nuclei.js"
fi

# 3_Apps/dist.app/Contents/Frameworks/ui
if [ -d "3_Apps/dist/API Sentinel.app/Contents/Frameworks/ui" ]; then
  cp -v ui/index.html "3_Apps/dist/API Sentinel.app/Contents/Frameworks/ui/index.html"
  cp -v ui/css/nuclei.css "3_Apps/dist/API Sentinel.app/Contents/Frameworks/ui/css/nuclei.css"
  cp -v ui/css/nuclei.css "3_Apps/dist/API Sentinel.app/Contents/Frameworks/ui/nuclei.css"
  cp -v ui/js/nuclei.js "3_Apps/dist/API Sentinel.app/Contents/Frameworks/ui/js/nuclei.js"
  cp -v ui/js/nuclei.js "3_Apps/dist/API Sentinel.app/Contents/Frameworks/ui/nuclei.js"
fi

echo "Nuclei synchronization completed across all mirrors!"
