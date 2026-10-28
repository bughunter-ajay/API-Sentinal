#!/usr/bin/env python3
"""
Merged App — API Validator Pro + HAR Runner Pro + Method Tampering + Soft Delete + IDOR Tester + Swagger Scan + Params Tamper + RSQL Tester
Ports: 8765 AV | 8766 HAR | 8767 MT | 8768 mitmproxy | 8769 SD | 8773 IDOR | 8771 OOS | 8772 PT | 8774 RSQL
       8775 API Scan | 8776 File Upload | 8790 XSS | 8791 APISphere | 8792 JS Analyser | 8793 LLM/Command Injection | 8794 Intruder
       8795 Settings
"""

import sys, os, threading, time

BASE_DIR    = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
HAR_DIR     = os.path.join(BASE_DIR, 'har_backend')
MT_DIR      = os.path.join(BASE_DIR, 'mt_backend')
SD_DIR      = os.path.join(BASE_DIR, 'sd_backend')
IDOR_DIR    = os.path.join(BASE_DIR, 'idor_backend')
OOS_DIR     = os.path.join(BASE_DIR, 'oos_backend')
PT_DIR      = os.path.join(BASE_DIR, 'pt_backend')
RSQL_DIR    = os.path.join(BASE_DIR, 'rsql_backend')
AS_DIR      = os.path.join(BASE_DIR, 'apiscan_backend')
UPLOAD_DIR  = os.path.join(BASE_DIR, 'upload_backend')
XSS_DIR     = os.path.join(BASE_DIR, 'xss_backend')
ASP_DIR     = os.path.join(BASE_DIR, 'apisphere_backend')
JSA_DIR     = os.path.join(BASE_DIR, 'jsanalyser_backend')
LC_DIR      = os.path.join(BASE_DIR, 'llmcmd_backend')
INTR_DIR    = os.path.join(BASE_DIR, 'intruder_backend')
SETT_DIR    = os.path.join(BASE_DIR, 'settings_backend')
FUZZ_DIR    = os.path.join(BASE_DIR, 'fuzzer_backend')
NUCLEI_DIR  = os.path.join(BASE_DIR, 'nuclei_backend')
JWT_DIR     = os.path.join(BASE_DIR, 'jwt_backend')
NIKTO_DIR   = os.path.join(BASE_DIR, 'nikto_backend')
UI_DIR      = os.path.join(BASE_DIR, 'ui')

# BASE_DIR first so every backend can `import proxy_config`
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, BACKEND_DIR)

# Ensure local venv site-packages are available even if app is launched with global python
for _py_ver in [f"python{sys.version_info.major}.{sys.version_info.minor}", "python3.11", "python3.12"]:
    _vsp = os.path.join(BASE_DIR, 'venv', 'lib', _py_ver, 'site-packages')
    if os.path.isdir(_vsp) and _vsp not in sys.path:
        sys.path.append(_vsp)

# Initialise proxy env (NO_PROXY = localhost from the start)
import proxy_config
proxy_config.apply_env()


def start_av_backend():
    import uvicorn
    from main import app
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="error", access_log=False)

def start_har_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("har_main", os.path.join(HAR_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["har_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8766, log_level="error", access_log=False)

def start_mt_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("mt_main", os.path.join(MT_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["mt_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8767, log_level="error", access_log=False)

def start_sd_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("sd_main", os.path.join(SD_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["sd_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8769, log_level="error", access_log=False)

def start_idor_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("idor_main", os.path.join(IDOR_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["idor_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8773, log_level="error", access_log=False)

def start_oos_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("oos_main", os.path.join(OOS_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["oos_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8771, log_level="error", access_log=False)

def start_pt_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("pt_main", os.path.join(PT_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["pt_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8772, log_level="error", access_log=False)

def start_rsql_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("rsql_main", os.path.join(RSQL_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["rsql_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8774, log_level="error", access_log=False)

def start_apiscan_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("apiscan_main", os.path.join(AS_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["apiscan_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8775, log_level="error", access_log=False)


def start_upload_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("upload_main", os.path.join(UPLOAD_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["upload_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8776, log_level="error", access_log=False)

def start_xss_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("xss_main", os.path.join(XSS_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["xss_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8790, log_level="error", access_log=False)


def start_apisphere_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("asp_main", os.path.join(ASP_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["asp_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8791, log_level="error", access_log=False)


def start_jsanalyser_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("jsa_main", os.path.join(JSA_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["jsa_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8792, log_level="error", access_log=False)


def start_llmcmd_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("llmcmd_main", os.path.join(LC_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["llmcmd_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8793, log_level="error", access_log=False)


def start_intruder_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("intruder_main", os.path.join(INTR_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["intruder_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8794, log_level="error", access_log=False)

def start_settings_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("settings_main", os.path.join(SETT_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["settings_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8795, log_level="error", access_log=False)

def start_fuzzer_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("fuzzer_main", os.path.join(FUZZ_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["fuzzer_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8796, log_level="error", access_log=False)

def start_nuclei_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("nuclei_main", os.path.join(NUCLEI_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["nuclei_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8797, log_level="error", access_log=False)

def start_jwt_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("jwt_main", os.path.join(JWT_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["jwt_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8798, log_level="error", access_log=False)

def start_nikto_backend():
    import importlib.util, uvicorn, sys
    spec = importlib.util.spec_from_file_location("nikto_main", os.path.join(NIKTO_DIR, "main.py"))
    m = importlib.util.module_from_spec(spec); sys.modules["nikto_main"] = m; spec.loader.exec_module(m)
    uvicorn.run(m.app, host="127.0.0.1", port=8799, log_level="error", access_log=False)


def wait_for(port: int, timeout: int = 12) -> bool:
    import urllib.request
    url = f"http://127.0.0.1:{port}/"
    for _ in range(timeout * 2):
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    t1 = threading.Thread(target=start_av_backend,   daemon=True)
    t2 = threading.Thread(target=start_har_backend,  daemon=True)
    t3 = threading.Thread(target=start_mt_backend,   daemon=True)
    t4 = threading.Thread(target=start_sd_backend,   daemon=True)
    t5 = threading.Thread(target=start_idor_backend, daemon=True)
    t6 = threading.Thread(target=start_oos_backend,  daemon=True)
    t7 = threading.Thread(target=start_pt_backend,   daemon=True)
    t8 = threading.Thread(target=start_rsql_backend,  daemon=True)
    t9 = threading.Thread(target=start_apiscan_backend, daemon=True)
    t10 = threading.Thread(target=start_upload_backend, daemon=True)
    t11 = threading.Thread(target=start_xss_backend,       daemon=True)
    t12 = threading.Thread(target=start_apisphere_backend, daemon=True)
    t13 = threading.Thread(target=start_jsanalyser_backend, daemon=True)
    t14 = threading.Thread(target=start_llmcmd_backend, daemon=True)
    t15 = threading.Thread(target=start_intruder_backend, daemon=True)
    t16 = threading.Thread(target=start_settings_backend,  daemon=True)
    t17 = threading.Thread(target=start_fuzzer_backend,    daemon=True)
    t18 = threading.Thread(target=start_nuclei_backend,    daemon=True)
    t19 = threading.Thread(target=start_jwt_backend,       daemon=True)
    t20 = threading.Thread(target=start_nikto_backend,     daemon=True)
    t1.start(); t2.start(); t3.start(); t4.start(); t5.start(); t6.start(); t7.start(); t8.start(); t9.start(); t10.start(); t11.start(); t12.start(); t13.start(); t14.start(); t15.start(); t16.start(); t17.start(); t18.start(); t19.start(); t20.start()

    print("⏳ Waiting for backends...")
    ok1 = wait_for(8765); ok2 = wait_for(8766); ok3 = wait_for(8767)
    ok4 = wait_for(8769); ok5 = wait_for(8773); ok6 = wait_for(8771)
    ok7 = wait_for(8772); ok8 = wait_for(8774); ok9 = wait_for(8775)
    ok10 = wait_for(8776); ok11 = wait_for(8790); ok12 = wait_for(8791)
    ok13 = wait_for(8792); ok14 = wait_for(8793); ok15 = wait_for(8794)
    ok16 = wait_for(8795); ok17 = wait_for(8796); ok18 = wait_for(8797)
    ok19 = wait_for(8798); ok20 = wait_for(8799)

    if not ok1: print("❌ API Validator (8765) failed!"); sys.exit(1)
    if not ok2: print("❌ HAR Runner (8766) failed!"); sys.exit(1)
    if not ok3: print("❌ Method Tampering (8767) failed!"); sys.exit(1)
    if not ok4: print("❌ Soft Delete (8769) failed!"); sys.exit(1)
    if not ok5: print("❌ IDOR Tester (8773) failed!"); sys.exit(1)
    if not ok6: print("❌ Swagger Scan (8771) failed!"); sys.exit(1)
    if not ok7: print("❌ Params Tamper (8772) failed!"); sys.exit(1)
    if not ok8: print("❌ RSQL Tester (8774) failed!"); sys.exit(1)
    if not ok9: print("❌ API Scan (8775) failed!"); sys.exit(1)
    if not ok10: print("❌ File Upload (8776) failed!"); sys.exit(1)
    if not ok11: print("❌ XSS Tester (8790) failed!"); sys.exit(1)
    if not ok12: print("❌ APISphere (8791) failed!"); sys.exit(1)
    if not ok13: print("❌ JS Analyser (8792) failed!"); sys.exit(1)
    if not ok14: print("❌ LLM/Command Injection (8793) failed!"); sys.exit(1)
    if not ok15: print("❌ Intruder (8794) failed!"); sys.exit(1)
    if not ok16: print("❌ Settings (8795) failed!"); sys.exit(1)
    if not ok17: print("❌ API Fuzzer (8796) failed!"); sys.exit(1)
    if not ok18: print("❌ Nuclei Scanner (8797) failed!"); sys.exit(1)
    if not ok19: print("❌ JWT Tool (8798) failed!"); sys.exit(1)
    if not ok20: print("❌ Nikto Scanner (8799) failed!"); sys.exit(1)

    print("✅ API Validator ready on port 8765")
    print("✅ HAR Runner ready on port 8766")
    print("✅ Method Tampering ready on port 8767")
    print("✅ Soft Delete ready on port 8769")
    print("✅ IDOR Tester ready on port 8773")
    print("✅ Swagger Scan ready on port 8771")
    print("✅ Params Tamper ready on port 8772")
    print("✅ RSQL Tester ready on port 8774")
    print("✅ API Scan ready on port 8775")
    print("✅ File Upload ready on port 8776")
    print("✅ XSS Tester ready on port 8790")
    print("✅ APISphere ready on port 8791")
    print("✅ JS Analyser ready on port 8792")
    print("✅ LLM/Command Injection ready on port 8793")
    print("✅ Intruder ready on port 8794")
    print("✅ Settings ready on port 8795")
    print("✅ API Fuzzer ready on port 8796")
    print("✅ Nuclei Scanner ready on port 8797")
    print("✅ JWT Tool ready on port 8798")
    print("✅ Nikto Scanner ready on port 8799")

    try:
        import webview
    except ImportError:
        print("❌ pywebview not installed: pip install pywebview")
        sys.exit(1)

    ui_path = os.path.join(UI_DIR, 'index.html')
    if not os.path.exists(ui_path):
        print(f"❌ UI not found: {ui_path}")
        sys.exit(1)

    class JSApi:
        """pywebview JS API — js_api= pe pass hogi, window baad mein set hogi."""
        def __init__(self):
            self._win = None   # set_window() se assign hoga

        def set_window(self, win):
            self._win = win

        def close_window(self):
            if self._win:
                self._win.destroy()

        def _save_dialog_path(self, filename: str):
            """Show native Save dialog; return path or None if cancelled."""
            import webview as _wv
            if not self._win:
                raise RuntimeError("window not ready")
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
            type_labels = {
                "csv":  "CSV Files (*.csv)",
                "html": "HTML Files (*.html)",
                "json": "JSON Files (*.json)",
                "txt":  "Text Files (*.txt)",
                "pdf":  "PDF Files (*.pdf)",
                "zip":  "ZIP Files (*.zip)",
                "xlsx": "Excel Files (*.xlsx)",
                "xls":  "Excel Files (*.xls)",
                "docx": "Word Files (*.docx)",
                "png":  "PNG Images (*.png)",
                "jpg":  "JPEG Images (*.jpg)",
                "jpeg": "JPEG Images (*.jpg)",
                "bin":  "Binary Files (*.bin)",
            }
            file_type_label = type_labels.get(ext, f"{ext.upper()} Files (*.{ext})")
            result = self._win.create_file_dialog(
                dialog_type=_wv.SAVE_DIALOG,
                directory=os.path.expanduser("~/Downloads"),
                save_filename=filename,
                file_types=(file_type_label, "All Files (*.*)"),
            )
            if not result:
                return None
            return result[0] if isinstance(result, (list, tuple)) else result

        def _fallback_downloads_path(self, filename: str) -> str:
            downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(downloads, exist_ok=True)
            base, dotex = os.path.splitext(filename)
            save_path = os.path.join(downloads, filename)
            c = 1
            while os.path.exists(save_path):
                save_path = os.path.join(downloads, f"{base}_{c}{dotex}")
                c += 1
            return save_path

        def save_file(self, content_str: str, filename: str):
            """Native save dialog for text — user apna folder choose kare."""
            try:
                save_path = self._save_dialog_path(filename)
                if not save_path:
                    return {"ok": False, "reason": "cancelled"}
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(content_str if content_str is not None else "")
                return {"ok": True, "path": save_path,
                        "filename": os.path.basename(save_path)}
            except Exception:
                # Dialog failed — fallback: auto-save to Downloads
                try:
                    save_path = self._fallback_downloads_path(filename)
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(content_str if content_str is not None else "")
                    return {"ok": True, "path": save_path,
                            "filename": os.path.basename(save_path)}
                except Exception as e2:
                    return {"ok": False, "reason": str(e2)}

        def save_bytes_b64(self, content_b64: str, filename: str):
            """Native save dialog for binary (base64) — Download response."""
            import base64 as _b64
            try:
                data = _b64.b64decode(content_b64 or "", validate=False)
            except Exception as e:
                return {"ok": False, "reason": f"invalid base64: {e}"}
            try:
                save_path = self._save_dialog_path(filename or "response.bin")
                if not save_path:
                    return {"ok": False, "reason": "cancelled"}
                with open(save_path, "wb") as f:
                    f.write(data)
                return {"ok": True, "path": save_path,
                        "filename": os.path.basename(save_path)}
            except Exception:
                try:
                    save_path = self._fallback_downloads_path(filename or "response.bin")
                    with open(save_path, "wb") as f:
                        f.write(data)
                    return {"ok": True, "path": save_path,
                            "filename": os.path.basename(save_path)}
                except Exception as e2:
                    return {"ok": False, "reason": str(e2)}

    # Create API instance FIRST, pass to create_window, then set window ref
    api = JSApi()

    window = webview.create_window(
        title="⚡ API Sentinel ",
        url=f"file://{os.path.abspath(ui_path)}",
        width=1280,
        height=800,
        min_size=(900, 620),
        background_color="#0d1117",
        text_select=True,
        js_api=api,
    )
    api.set_window(window)

    def on_loaded():
        try:
            window.maximize()
        except Exception:
            pass

    print("🚀 Launching window...")
    webview.start(on_loaded, debug="--debug" in sys.argv, private_mode=False)
    print("👋 App closed.")


if __name__ == "__main__":
    main()
