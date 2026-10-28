#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
#  build.sh — API Validator Pro + HAR Runner Pro
#  Obfuscated Build (PyArmor + JS Obfuscator)
# ──────────────────────────────────────────────────────────────────────────────

APP_NAME="API Sentinel"
DIST_DIR="dist"
WORK_DIR=".build_work"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ⚡ API Sentinel — Full Build"
echo "  ⚡ API Validator Pro  |  🔐 Auth Validator Pro"
echo "  🔀 Method Tampering  |  🗑️  Soft Delete"
echo "  🔍 IDOR Tester       |  🚧 Swagger Scan"
echo "  🎯 Params Tamper     |  🌐 APISphere"
echo "  🧠 LLM Cmd           |  📜 JS Analyser"
echo "  Secure Build (Obfuscated)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Check venv ──────────────────────────────────────────────────────────────
if [ -z "$VIRTUAL_ENV" ]; then
  echo "⚠️  Activate venv first: source venv/bin/activate"
  exit 1
fi

# Prefer the venv's python3.11 (avoid accidental python3.14 / broken pip pins)
if [ -x "$VIRTUAL_ENV/bin/python3.11" ]; then
  PYTHON="$VIRTUAL_ENV/bin/python3.11"
elif command -v python3.11 &>/dev/null; then
  PYTHON="$(command -v python3.11)"
else
  PYTHON="$(command -v python3 || command -v python)"
fi
echo "🐍 Using: $PYTHON ($($PYTHON -V 2>&1))"

# ── 2. Install tools ───────────────────────────────────────────────────────────
echo "📦 Installing dependencies..."
"$PYTHON" -m pip install -r requirements.txt -q || \
  echo "  ⚠️  requirements.txt install had errors — continuing with existing packages"
"$PYTHON" -m pip install "pyinstaller>=6.6.0,<7" pyarmor -q
if ! "$PYTHON" -c "import PyInstaller" 2>/dev/null; then
  echo "❌ PyInstaller not available for $PYTHON"
  exit 1
fi

# ── 3. Clean ───────────────────────────────────────────────────────────────────
echo "🧹 Cleaning old build..."
rm -rf build dist __pycache__ *.spec "$WORK_DIR" .pyarmor_tmp

# ── 4. Copy sources to work dir ────────────────────────────────────────────────
echo "📁 Preparing work directory..."
mkdir -p "$WORK_DIR"
cp -r backend har_backend mt_backend sd_backend idor_backend oos_backend pt_backend rsql_backend apiscan_backend upload_backend xss_backend apisphere_backend jsanalyser_backend llmcmd_backend intruder_backend settings_backend fuzzer_backend nuclei_backend jwt_backend nikto_backend ui app.py proxy_config.py "$WORK_DIR/"

# API Scan engine — must ship inside apiscan_backend/ (loaded via importlib, not imported)
if [ ! -f "Scan.py" ]; then
  echo "❌ Scan.py missing at repo root — required for API Scan backend"
  exit 1
fi
cp "Scan.py" "$WORK_DIR/apiscan_backend/Scan.py"
echo "  ✅ Scan.py bundled into apiscan_backend/"

# Shared cURL parser (Param Temper / XSS / Intruder / Upload / API Scan)
if [ -f "curl_parser.py" ]; then
  cp "curl_parser.py" "$WORK_DIR/curl_parser.py"
  cp "curl_parser.py" "$WORK_DIR/apiscan_backend/curl_parser.py"
  for _bd in pt_backend xss_backend intruder_backend upload_backend fuzzer_backend; do
    cp "curl_parser.py" "$WORK_DIR/$_bd/curl_parser.py"
  done
  echo "  ✅ curl_parser.py bundled into backends"
fi

# ── 5. Obfuscate Python files (graceful — skip if pyarmor fails) ───────────────
echo "🔒 Obfuscating Python source files..."

obfuscate_file() {
  local src="$1"    # e.g. .build_work/app.py
  local tmp=".pyarmor_tmp_$$"
  mkdir -p "$tmp"
  if pyarmor gen --output "$tmp" "$src" > /dev/null 2>&1; then
    # Copy obfuscated .py back (pyarmor keeps same filename)
    local fname
    fname=$(basename "$src")
    if [ -f "$tmp/$fname" ]; then
      cp "$tmp/$fname" "$src"
      # Copy runtime package if present (needed for import)
      for rt in "$tmp"/pyarmor_runtime_*; do
        [ -d "$rt" ] && cp -r "$rt" "$(dirname "$src")/"
      done
      echo "  ✅ $fname obfuscated"
    fi
  else
    echo "  ⚠️  $(basename $src) — PyArmor skipped (using original)"
  fi
  rm -rf "$tmp"
}

obfuscate_file "$WORK_DIR/app.py"
obfuscate_file "$WORK_DIR/backend/main.py"
obfuscate_file "$WORK_DIR/backend/proxy_addon.py"
obfuscate_file "$WORK_DIR/har_backend/main.py"
obfuscate_file "$WORK_DIR/mt_backend/main.py"
obfuscate_file "$WORK_DIR/sd_backend/main.py"
obfuscate_file "$WORK_DIR/idor_backend/main.py"
obfuscate_file "$WORK_DIR/oos_backend/main.py"
obfuscate_file "$WORK_DIR/pt_backend/main.py"
obfuscate_file "$WORK_DIR/rsql_backend/main.py"
obfuscate_file "$WORK_DIR/apiscan_backend/main.py"
# Do NOT obfuscate Scan.py — apiscan_backend loads it dynamically via importlib.
obfuscate_file "$WORK_DIR/upload_backend/main.py"
obfuscate_file "$WORK_DIR/xss_backend/main.py"
obfuscate_file "$WORK_DIR/apisphere_backend/main.py"
obfuscate_file "$WORK_DIR/jsanalyser_backend/main.py"
obfuscate_file "$WORK_DIR/llmcmd_backend/main.py"
obfuscate_file "$WORK_DIR/intruder_backend/main.py"
obfuscate_file "$WORK_DIR/settings_backend/main.py"
obfuscate_file "$WORK_DIR/fuzzer_backend/main.py"
obfuscate_file "$WORK_DIR/nuclei_backend/main.py"
obfuscate_file "$WORK_DIR/jwt_backend/main.py"
obfuscate_file "$WORK_DIR/nikto_backend/main.py"
obfuscate_file "$WORK_DIR/proxy_config.py"

# ── 6. Obfuscate JS files (optional — skip if npm missing) ────────────────────
if command -v javascript-obfuscator &>/dev/null; then
  echo "🔒 Obfuscating JavaScript files..."
  for jsfile in "$WORK_DIR/ui/js/"*.js; do
    javascript-obfuscator "$jsfile" --output "$jsfile" \
      --compact true \
      --self-defending true \
      --identifier-names-generator hexadecimal \
      --string-array true \
      --string-array-encoding rc4 \
      --rotate-string-array true \
      --split-strings true \
      > /dev/null 2>&1 \
      && echo "  ✅ $(basename $jsfile) obfuscated" \
      || echo "  ⚠️  $(basename $jsfile) skipped"
  done
else
  echo "  ℹ️  javascript-obfuscator not found — JS skipped"
  echo "     (npm install -g javascript-obfuscator)"
fi

# ── 7. PyInstaller ────────────────────────────────────────────────────────────
echo "🔨 Building with PyInstaller..."
cd "$WORK_DIR"

"$PYTHON" -m PyInstaller \
  --name "$APP_NAME" \
  --windowed \
  --onedir \
  --icon "../icon.icns" \
  --clean \
  --noconfirm \
  --add-data "backend:backend" \
  --add-data "har_backend:har_backend" \
  --add-data "mt_backend:mt_backend" \
  --add-data "sd_backend:sd_backend" \
  --add-data "idor_backend:idor_backend" \
  --add-data "oos_backend:oos_backend" \
  --add-data "pt_backend:pt_backend" \
  --add-data "rsql_backend:rsql_backend" \
  --add-data "apiscan_backend:apiscan_backend" \
  --add-data "upload_backend:upload_backend" \
  --add-data "xss_backend:xss_backend" \
  --add-data "apisphere_backend:apisphere_backend" \
  --add-data "jsanalyser_backend:jsanalyser_backend" \
  --add-data "llmcmd_backend:llmcmd_backend" \
  --add-data "intruder_backend:intruder_backend" \
  --add-data "settings_backend:settings_backend" \
  --add-data "fuzzer_backend:fuzzer_backend" \
  --add-data "nuclei_backend:nuclei_backend" \
  --add-data "jwt_backend:jwt_backend" \
  --add-data "nikto_backend:nikto_backend" \
  --add-data "proxy_config.py:." \
  --add-data "ui:ui" \
  --hidden-import "uvicorn.logging" \
  --hidden-import "uvicorn.loops" \
  --hidden-import "uvicorn.loops.auto" \
  --hidden-import "uvicorn.protocols" \
  --hidden-import "uvicorn.protocols.http" \
  --hidden-import "uvicorn.protocols.http.auto" \
  --hidden-import "uvicorn.protocols.websockets" \
  --hidden-import "uvicorn.protocols.websockets.auto" \
  --hidden-import "uvicorn.lifespan" \
  --hidden-import "uvicorn.lifespan.on" \
  --hidden-import "fastapi" \
  --hidden-import "fastapi.middleware" \
  --hidden-import "fastapi.middleware.cors" \
  --hidden-import "fastapi.responses" \
  --hidden-import "fastapi.routing" \
  --hidden-import "fastapi.encoders" \
  --hidden-import "fastapi.exceptions" \
  --hidden-import "starlette" \
  --hidden-import "starlette.middleware" \
  --hidden-import "starlette.middleware.cors" \
  --hidden-import "starlette.middleware.base" \
  --hidden-import "starlette.routing" \
  --hidden-import "starlette.responses" \
  --hidden-import "starlette.requests" \
  --hidden-import "starlette.background" \
  --hidden-import "starlette.concurrency" \
  --hidden-import "starlette.datastructures" \
  --hidden-import "starlette.exceptions" \
  --hidden-import "starlette.status" \
  --hidden-import "starlette.types" \
  --hidden-import "starlette.websockets" \
  --hidden-import "pydantic" \
  --hidden-import "pydantic_core" \
  --hidden-import "anyio" \
  --hidden-import "anyio.abc" \
  --hidden-import "anyio._backends._asyncio" \
  --hidden-import "sniffio" \
  --hidden-import "requests" \
  --hidden-import "urllib3" \
  --hidden-import "certifi" \
  --hidden-import "charset_normalizer" \
  --hidden-import "idna" \
  --hidden-import "mitmproxy" \
  --hidden-import "mitmproxy.tools" \
  --hidden-import "mitmproxy.tools.dump" \
  --hidden-import "mitmproxy.options" \
  --hidden-import "mitmproxy.proxy" \
  --hidden-import "mitmproxy.proxy.server" \
  --hidden-import "webview" \
  --hidden-import "webview.platforms" \
  --hidden-import "webview.platforms.cocoa" \
  --hidden-import "socks" \
  --hidden-import "socksio" \
  --hidden-import "urllib3.contrib.socks" \
  --collect-all "fastapi" \
  --collect-all "starlette" \
  --collect-all "pydantic" \
  --collect-all "uvicorn" \
  --collect-all "mitmproxy" \
  --collect-all "webview" \
  --collect-all "anyio" \
  app.py

cd ..

# ── 8. Move output ─────────────────────────────────────────────────────────────
echo "📦 Moving build output..."
mv "$WORK_DIR/dist" ./dist
mv "$WORK_DIR/build" ./build 2>/dev/null || true

# ── 9. Gatekeeper bypass ──────────────────────────────────────────────────────
echo "🔓 Removing quarantine..."
xattr -cr "$DIST_DIR/$APP_NAME"     2>/dev/null || true
xattr -cr "$DIST_DIR/$APP_NAME.app" 2>/dev/null || true

# ── 10. Cleanup ───────────────────────────────────────────────────────────────
echo "🧹 Cleaning temp files..."
rm -rf "$WORK_DIR" build __pycache__ *.spec

# ── 11. Verify API Scan engine shipped ────────────────────────────────────────
FOUND_SCAN=""
for cand in \
  "$DIST_DIR/$APP_NAME.app/Contents/Resources/apiscan_backend/Scan.py" \
  "$DIST_DIR/$APP_NAME.app/Contents/Frameworks/apiscan_backend/Scan.py" \
  "$DIST_DIR/$APP_NAME/_internal/apiscan_backend/Scan.py"
do
  if [ -f "$cand" ]; then
    echo "  ✅ Packaged Scan.py: $cand"
    FOUND_SCAN=1
  fi
done
if [ -z "$FOUND_SCAN" ]; then
  echo "❌ Scan.py missing from dist — API Scan backend will 500 at runtime"
  exit 1
fi

# ── 12. Done ──────────────────────────────────────────────────────────────────
echo ""
if [ -d "$DIST_DIR/$APP_NAME.app" ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ✅ Build successful!"
  echo "  📁 $DIST_DIR/$APP_NAME.app"
  echo "  🔒 Code is obfuscated"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Run: open dist/$APP_NAME.app"
elif [ -d "$DIST_DIR/$APP_NAME" ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ✅ Build successful!"
  echo "  📁 $DIST_DIR/$APP_NAME/"
  echo "  🔒 Code is obfuscated"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Run: ./$DIST_DIR/$APP_NAME/$APP_NAME"
else
  echo "  ❌ Build failed — check output above"
  exit 1
fi
