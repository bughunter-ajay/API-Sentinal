import re

with open("/Users/ent-00338/Documents/API+HAR-QA/Nikto_Nuclei.py", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Update candidates in find_nuclei_binary
old_nuclei_candidates = """    candidates = [
        "/opt/homebrew/bin/nuclei",
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        "/home/linuxbrew/.linuxbrew/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
    ]"""

new_nuclei_candidates = """    candidates = [
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        "/opt/homebrew/bin/nuclei",
        "/home/linuxbrew/.linuxbrew/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/.local/bin/nuclei"),
        os.path.expanduser("~/bin/nuclei"),
    ]"""

code = code.replace(old_nuclei_candidates, new_nuclei_candidates)

# 2. Add Linux auto-installer before prepare_nuclei
linux_nuclei_installer = '''
def _auto_install_nuclei_linux() -> Optional[str]:
    """Downloads official static Nuclei release binary for Linux (amd64/arm64) with custom User-Agent to prevent 403 Forbidden."""
    import platform, urllib.request, zipfile
    arch = "amd64"
    mach = platform.machine().lower()
    if mach in ("aarch64", "arm64"):
        arch = "arm64"

    # Pinned stable release - direct asset URL (no GitHub API rate limit)
    version = "3.3.7"
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_{arch}.zip"

    # Determine writable target directory
    target_dir = None
    for d in ["/usr/local/bin", os.path.expanduser("~/.local/bin"), os.path.expanduser("~/bin")]:
        try:
            os.makedirs(d, exist_ok=True)
            test_f = os.path.join(d, ".write_test")
            with open(test_f, "w") as tf: tf.write("1")
            os.remove(test_f)
            target_dir = d
            break
        except Exception:
            continue

    if not target_dir:
        return None

    log_step(f"Downloading pre-compiled Nuclei v{version} (linux/{arch}) directly...")
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False).name
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NiktoNucleiScanner/1.0 (Linux)"})
        with urllib.request.urlopen(req, timeout=45) as resp, open(tmp_zip, "wb") as out_f:
            shutil.copyfileobj(resp, out_f)

        with zipfile.ZipFile(tmp_zip, "r") as zf:
            for member in zf.namelist():
                if member == "nuclei" or member.endswith("/nuclei"):
                    extracted = zf.extract(member, path=tempfile.gettempdir())
                    dest = os.path.join(target_dir, "nuclei")
                    shutil.move(extracted, dest)
                    os.chmod(dest, 0o755)
                    log_success(f"Nuclei installed successfully to: {dest}")
                    return dest
    except Exception as e:
        log_warn(f"Direct download note: {e}")
    finally:
        if os.path.exists(tmp_zip):
            try: os.remove(tmp_zip)
            except Exception: pass
    return None
'''

if "_auto_install_nuclei_linux" not in code:
    code = code.replace("def prepare_nuclei(", linux_nuclei_installer + "\ndef prepare_nuclei(")

# 3. Update prepare_nuclei auto-install block
old_nuclei_install = """        if auto_install:
            brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
            if os.path.isfile(brew_bin):
                log_step("Attempting auto-installation via Homebrew (`brew install nuclei`)...")
                try:
                    res = subprocess.run([brew_bin, "install", "nuclei"], check=False, capture_output=True, text=True)
                    if res.returncode == 0:
                        log_success("Nuclei installed successfully via Homebrew!")
                        nuclei_bin = find_nuclei_binary()
                    else:
                        log_error(f"Homebrew install failed: {res.stderr.strip()[:200]}")
                except Exception as e:
                    log_error(f"Auto-install error: {e}")

        if not nuclei_bin:
            return False, None, "Nuclei not installed. Install via: 'brew install nuclei' or 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'\""""

new_nuclei_install = """        if auto_install:
            # A. Try Homebrew (macOS / Linuxbrew)
            brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
            if os.path.isfile(brew_bin):
                log_step("Attempting auto-installation via Homebrew (`brew install nuclei`)...")
                try:
                    res = subprocess.run([brew_bin, "install", "nuclei"], check=False, capture_output=True, text=True)
                    if res.returncode == 0:
                        log_success("Nuclei installed successfully via Homebrew!")
                        nuclei_bin = find_nuclei_binary()
                except Exception as e:
                    log_warn(f"Homebrew install error: {e}")

            # B. Try Linux Direct Download (Ubuntu / Debian / Docker)
            if not nuclei_bin and sys.platform.startswith("linux"):
                nuclei_bin = _auto_install_nuclei_linux()

            # C. Try Go install if go toolchain exists
            if not nuclei_bin and shutil.which("go"):
                log_step("Attempting auto-installation via Go (`go install nuclei@latest`)...")
                try:
                    res = subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], check=False, capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        nuclei_bin = find_nuclei_binary()
                except Exception as e:
                    log_warn(f"Go install error: {e}")

        if not nuclei_bin:
            return False, None, "Nuclei not installed. Install via: 'apt-get install -y nuclei' or 'brew install nuclei' or 'docker run projectdiscovery/nuclei'\""""

code = code.replace(old_nuclei_install, new_nuclei_install)

# 4. Update prepare_nikto to support apt-get on Linux
old_nikto_install = """        if auto_install:
            brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
            if os.path.isfile(brew_bin):
                log_step("Attempting auto-installation via Homebrew (`brew install nikto`)...")
                try:
                    res = subprocess.run([brew_bin, "install", "nikto"], check=False, capture_output=True, text=True)
                    if res.returncode == 0:
                        log_success("Nikto installed successfully via Homebrew!")
                        perl_bin, nikto_script = find_nikto_components()
                except Exception as e:
                    log_error(f"Auto-install error: {e}")

        if not nikto_script:
            return False, None, None, "Nikto not found. Install via 'brew install nikto'.\""""

new_nikto_install = """        if auto_install:
            # A. Try Homebrew (macOS)
            brew_bin = shutil.which("brew") or "/opt/homebrew/bin/brew"
            if os.path.isfile(brew_bin):
                log_step("Attempting auto-installation via Homebrew (`brew install nikto`)...")
                try:
                    res = subprocess.run([brew_bin, "install", "nikto"], check=False, capture_output=True, text=True)
                    if res.returncode == 0:
                        log_success("Nikto installed successfully via Homebrew!")
                        perl_bin, nikto_script = find_nikto_components()
                except Exception as e:
                    log_warn(f"Homebrew install error: {e}")

            # B. Try apt-get (Ubuntu / Debian / Docker)
            if not nikto_script and sys.platform.startswith("linux") and shutil.which("apt-get"):
                log_step("Attempting auto-installation via APT (`apt-get install -y nikto`)...")
                try:
                    res = subprocess.run(["apt-get", "update", "-qq"], check=False, capture_output=True, text=True, timeout=60)
                    res2 = subprocess.run(["apt-get", "install", "-y", "-qq", "nikto", "perl"], check=False, capture_output=True, text=True, timeout=120)
                    if res2.returncode == 0:
                        log_success("Nikto installed successfully via APT!")
                        perl_bin, nikto_script = find_nikto_components()
                except Exception as e:
                    log_warn(f"APT install note: {e}")

        if not nikto_script:
            return False, None, None, "Nikto not found. Install via 'apt-get install -y nikto' or 'brew install nikto'.\""""

code = code.replace(old_nikto_install, new_nikto_install)

# 5. Update PipelineProgress for non-TTY / Docker / Kubernetes logging
old_progress_init = """    def __init__(self, total_steps: int):
        self.total_steps = max(1, total_steps)
        self.completed_steps = 0
        self.active_tasks: Dict[str, str] = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.rendered_lines = 0
        self.done_event = threading.Event()
        self.ticker = threading.Thread(target=self._ticker, daemon=True)
        self.ticker.start()

    def _ticker(self):
        while not self.done_event.is_set():
            time.sleep(1)
            with self.lock:
                if self.active_tasks:
                    self._render()

    def start_step(self, host: str, tool: str):
        with self.lock:
            self.active_tasks[host] = tool
            self._render()

    def finish_step(self, host: str, tool: str, log_msg: str = ""):
        with self.lock:
            if host in self.active_tasks:
                del self.active_tasks[host]
            self.completed_steps += 1
            if log_msg:
                if self.rendered_lines > 0:
                    sys.stdout.write("\\r\\x1b[2K\\x1b[A\\r\\x1b[2K")
                    self.rendered_lines = 0
                sys.stdout.write(log_msg + "\\n")
            self._render()

    def close(self):
        self.done_event.set()
        with self.lock:
            if self.rendered_lines > 0:
                sys.stdout.write("\\r\\x1b[2K\\x1b[A\\r\\x1b[2K")
                self.rendered_lines = 0
            sys.stdout.write("\\n")
            sys.stdout.flush()"""

new_progress_init = """    def __init__(self, total_steps: int):
        self.total_steps = max(1, total_steps)
        self.completed_steps = 0
        self.active_tasks: Dict[str, str] = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.rendered_lines = 0
        self.is_tty = sys.stdout.isatty()
        self.done_event = threading.Event()
        if self.is_tty:
            self.ticker = threading.Thread(target=self._ticker, daemon=True)
            self.ticker.start()

    def _ticker(self):
        while not self.done_event.is_set():
            time.sleep(1)
            with self.lock:
                if self.active_tasks and self.is_tty:
                    self._render()

    def start_step(self, host: str, tool: str):
        with self.lock:
            self.active_tasks[host] = tool
            if self.is_tty:
                self._render()
            else:
                elapsed = int(time.time() - self.start_time)
                mins, secs = divmod(elapsed, 60)
                hrs, mins = divmod(mins, 60)
                time_str = f"{hrs:02d}h {mins:02d}m {secs:02d}s"
                sys.stdout.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ➔ [{tool}] Starting scan on {host} (Elapsed: {time_str})\\n")
                sys.stdout.flush()

    def finish_step(self, host: str, tool: str, log_msg: str = ""):
        with self.lock:
            if host in self.active_tasks:
                del self.active_tasks[host]
            self.completed_steps += 1
            pct = int((self.completed_steps / self.total_steps) * 100)
            elapsed = int(time.time() - self.start_time)
            mins, secs = divmod(elapsed, 60)
            hrs, mins = divmod(mins, 60)
            time_str = f"{hrs:02d}h {mins:02d}m {secs:02d}s"

            if self.is_tty:
                if log_msg:
                    if self.rendered_lines > 0:
                        sys.stdout.write("\\r\\x1b[2K\\x1b[A\\r\\x1b[2K")
                        self.rendered_lines = 0
                    sys.stdout.write(log_msg + "\\n")
                self._render()
            else:
                if log_msg:
                    sys.stdout.write(log_msg + "\\n")
                sys.stdout.write(f"[PROGRESS {pct:>3}%] Completed {self.completed_steps}/{self.total_steps} tasks | Elapsed: {time_str}\\n")
                sys.stdout.flush()

    def close(self):
        self.done_event.set()
        with self.lock:
            if self.is_tty and self.rendered_lines > 0:
                sys.stdout.write("\\r\\x1b[2K\\x1b[A\\r\\x1b[2K\\n")
            sys.stdout.flush()"""

code = code.replace(old_progress_init, new_progress_init)

# 6. Add output_dir support to run_pipeline
old_run_pipe_sig = """def run_pipeline(
    hosts: List[str],
    skip_nuclei: bool = False,
    skip_nikto: bool = False,
    check_only: bool = False,
    rate_limit: int = 15,
    concurrency: int = 2,
    timeout: int = 7200,
):"""

new_run_pipe_sig = """def run_pipeline(
    hosts: List[str],
    skip_nuclei: bool = False,
    skip_nikto: bool = False,
    check_only: bool = False,
    rate_limit: int = 15,
    concurrency: int = 2,
    timeout: int = 7200,
    output_dir: str = "reports",
):"""

code = code.replace(old_run_pipe_sig, new_run_pipe_sig)

old_pipe_out_dir = """    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.abspath(os.path.join("reports", f"pipeline_{timestamp}"))
    os.makedirs(out_dir, exist_ok=True)
    log_step(f"Pipeline output directory created: {out_dir}")
    log_step(f"Execution Timeout: {timeout}s (2 Hours) | Rate Limit: {rate_limit} req/s | Parallel Workers: {concurrency}\\n")"""

new_pipe_out_dir = """    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.abspath(os.path.join(output_dir, f"pipeline_{timestamp}"))
    os.makedirs(out_dir, exist_ok=True)
    log_step(f"Pipeline output directory created: {out_dir}")
    log_step(f"Execution Timeout: {timeout}s (2 Hours) | Rate Limit: {rate_limit} req/s | Parallel Workers: {concurrency}\\n")"""

code = code.replace(old_pipe_out_dir, new_pipe_out_dir)

old_html_gen = """    html_report_file = os.path.join(out_dir, "pipeline_report.html")
    latest_html_file = os.path.abspath(os.path.join("reports", "latest_pipeline_report.html"))
    try:
        generate_pipeline_html_report(summary_data, html_report_file)
        shutil.copyfile(html_report_file, latest_html_file)
        log_success(f"Interactive HTML Report generated successfully: {html_report_file}")"""

new_html_gen = """    html_report_file = os.path.join(out_dir, "pipeline_report.html")
    latest_html_file = os.path.abspath(os.path.join(output_dir, "latest_pipeline_report.html"))
    try:
        os.makedirs(os.path.dirname(latest_html_file), exist_ok=True)
        generate_pipeline_html_report(summary_data, html_report_file)
        shutil.copyfile(html_report_file, latest_html_file)
        log_success(f"Interactive HTML Report generated successfully: {html_report_file}")"""

code = code.replace(old_html_gen, new_html_gen)

# 7. Update __main__ to handle --output-dir and all env vars
old_main = """    parser.add_argument(
        "--timeout",
        type=int,
        default=7200,
        help="Max execution timeout per tool in seconds (default: 7200 / 2 hours)",
    )
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scans")
    parser.add_argument("--skip-nikto", action="store_true", help="Skip Nikto scans")
    parser.add_argument("--check-only", action="store_true", help="Only check and update tool installations")

    args = parser.parse_args()

    # Determine hosts
    if args.hosts.strip():
        targets = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        # Check environment variable or fallback to DEFAULT_TARGET_HOSTS
        env_hosts = os.environ.get("TARGET_HOSTS", "").strip()
        if env_hosts:
            targets = [h.strip() for h in env_hosts.replace("\\n", ",").split(",") if h.strip()]
        else:
            targets = DEFAULT_TARGET_HOSTS

    run_pipeline(
        hosts=targets,
        skip_nuclei=args.skip_nuclei,
        skip_nikto=args.skip_nikto,
        check_only=args.check_only,
        rate_limit=args.rate_limit,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )"""

new_main = """    parser.add_argument(
        "--timeout",
        type=int,
        default=7200,
        help="Max execution timeout per tool in seconds (default: 7200 / 2 hours)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=os.environ.get("OUTPUT_DIR", "reports"),
        help="Directory to store HTML reports (default: reports or $OUTPUT_DIR)",
    )
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scans")
    parser.add_argument("--skip-nikto", action="store_true", help="Skip Nikto scans")
    parser.add_argument("--check-only", action="store_true", help="Only check and update tool installations")

    args = parser.parse_args()

    # Determine hosts (CLI --hosts > env TARGET_HOSTS > DEFAULT_TARGET_HOSTS)
    if args.hosts.strip():
        targets = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        env_hosts = os.environ.get("TARGET_HOSTS", "").strip()
        if env_hosts:
            targets = [h.strip() for h in env_hosts.replace("\\n", ",").split(",") if h.strip()]
        else:
            targets = DEFAULT_TARGET_HOSTS

    # Environment variable overrides for container configurations
    concurrency = int(os.environ.get("CONCURRENCY", str(args.concurrency))) if os.environ.get("CONCURRENCY", "").isdigit() else args.concurrency
    rate_limit = int(os.environ.get("RATE_LIMIT", str(args.rate_limit))) if os.environ.get("RATE_LIMIT", "").isdigit() else args.rate_limit
    timeout = int(os.environ.get("TIMEOUT", str(args.timeout))) if os.environ.get("TIMEOUT", "").isdigit() else args.timeout
    skip_nuclei = args.skip_nuclei or os.environ.get("SKIP_NUCLEI", "").lower() in ("true", "1", "yes")
    skip_nikto = args.skip_nikto or os.environ.get("SKIP_NIKTO", "").lower() in ("true", "1", "yes")

    run_pipeline(
        hosts=targets,
        skip_nuclei=skip_nuclei,
        skip_nikto=skip_nikto,
        check_only=args.check_only,
        rate_limit=rate_limit,
        concurrency=concurrency,
        timeout=timeout,
        output_dir=args.output_dir,
    )"""

code = code.replace(old_main, new_main)

with open("/Users/ent-00338/Documents/API+HAR-QA/Nikto_Nuclei.py", "w", encoding="utf-8") as f:
    f.write(code)

# Keep pipeline.py in sync as well
with open("pipeline.py", "w", encoding="utf-8") as f:
    f.write(code)

print("Successfully updated Nikto_Nuclei.py and pipeline.py!")
