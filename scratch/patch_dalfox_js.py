with open("UltronScan/ui/js/dalfox.js", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Update maxVerboseLines
code = code.replace("maxVerboseLines: 500,", "maxVerboseLines: 2000,")

# 2. Add formatScanTime and updateAutoScrollUI
format_funcs = '''  function formatScanTime(sec) {
    if (sec == null || isNaN(sec)) return "0s";
    const totalSec = Math.floor(sec);
    if (totalSec < 60) return `${totalSec}s`;
    const mins = Math.floor(totalSec / 60);
    const remSec = totalSec % 60;
    if (mins < 60) return `${mins}m ${remSec < 10 ? '0' : ''}${remSec}s`;
    const hrs = Math.floor(mins / 60);
    const remMin = mins % 60;
    return `${hrs}h ${remMin < 10 ? '0' : ''}${remMin}m`;
  }

  function updateAutoScrollUI() {
    if (!btnAutoScroll) return;
    if (state.autoScroll) {
      btnAutoScroll.textContent = "Scroll: ON";
      btnAutoScroll.style.color = "var(--neon-green)";
      btnAutoScroll.style.borderColor = "var(--neon-green)";
    } else {
      btnAutoScroll.textContent = "Scroll: OFF";
      btnAutoScroll.style.color = "var(--text-muted)";
      btnAutoScroll.style.borderColor = "var(--border-dim)";
    }
  }
'''

if "function formatScanTime(" not in code:
    code = code.replace("  function setupEvents() {", format_funcs + "\n  function setupEvents() {")

# 3. Update btnAutoScroll event and add user scroll listeners
old_scroll_event = '''    // 4. Output Bar Controls
    if (btnAutoScroll) {
      btnAutoScroll.addEventListener("click", () => {
        state.autoScroll = !state.autoScroll;
        btnAutoScroll.style.color = state.autoScroll ? "var(--neon-green)" : "var(--text-muted)";
        window.showToast(state.autoScroll ? "Auto-scroll Enabled" : "Auto-scroll Disabled", "info");
      });
    }'''

new_scroll_event = '''    // 4. Output Bar Controls
    if (btnAutoScroll) {
      updateAutoScrollUI();
      btnAutoScroll.addEventListener("click", () => {
        state.autoScroll = !state.autoScroll;
        updateAutoScrollUI();
        window.showToast(state.autoScroll ? "Auto-scroll ON" : "Auto-scroll OFF", "info");
      });
    }

    const handleUserScroll = (box) => {
      if (!box) return;
      const atBottom = (box.scrollHeight - box.scrollTop - box.clientHeight) < 40;
      if (!atBottom && state.autoScroll) {
        state.autoScroll = false;
        updateAutoScrollUI();
      } else if (atBottom && !state.autoScroll) {
        state.autoScroll = true;
        updateAutoScrollUI();
      }
    };

    if (terminalBox) {
      terminalBox.addEventListener("scroll", () => {
        if (state.activeTab === "terminal") handleUserScroll(terminalBox);
      }, { passive: true });
    }
    if (verboseBox) {
      verboseBox.addEventListener("scroll", () => {
        if (state.activeTab === "verbose") handleUserScroll(verboseBox);
      }, { passive: true });
    }'''

assert old_scroll_event in code, "Could not find old_scroll_event in dalfox.js"
code = code.replace(old_scroll_event, new_scroll_event)

# 4. Update scan progress pill text formatting
old_pill_text = 'scanProgressBadge.textContent = `${s.scanned_endpoints}/${s.total_endpoints} | ${s.elapsed_seconds}s`;'
new_pill_text = 'scanProgressBadge.textContent = `${s.scanned_endpoints}/${s.total_endpoints} · ${formatScanTime(s.elapsed_seconds)}`;'

assert old_pill_text in code, "Could not find old_pill_text in dalfox.js"
code = code.replace(old_pill_text, new_pill_text)

# 5. Overhaul appendVerboseLogs
old_append_verbose = '''  function appendVerboseLogs(vLogs) {
    if (!verboseBox) return;
    const frag = document.createDocumentFragment();

    vLogs.forEach(v => {
      state.verboseLogs.push(v);
      if (state.verboseLogs.length > state.maxVerboseLines) {
        state.verboseLogs.shift();
        if (verboseBox.firstChild) verboseBox.removeChild(verboseBox.firstChild);
      }

      const item = document.createElement("div");
      item.className = "verbose-item";

      const tagUpper = (v.tag || "PROBE").toUpperCase();
      let badgeClass = "probe";
      if (tagUpper === "VULN" || tagUpper === "POC" || tagUpper === "VERIFIED") badgeClass = "vuln";
      else if (tagUpper === "DOM" || tagUpper === "AST") badgeClass = "testing";
      else if (tagUpper === "WAF" || tagUpper === "PARAM") badgeClass = "testing";

      item.innerHTML = `
        <div class="v-main-line">
          <span class="v-time">[${window.escapeHtml(v.time || '')}]</span>
          <span class="v-tag">[DFX]</span>
          <span class="v-badge ${badgeClass}">[${window.escapeHtml(v.tag || 'PROBE')}]</span>
          <span class="v-action">${window.escapeHtml(v.action || '')}</span>
          <span class="v-url">${window.escapeHtml(v.target || '')}</span>
        </div>
      `;

      if (v.detail && v.detail.trim().length > 0) {
        const sub = document.createElement("div");
        sub.className = "v-sub-line";
        sub.innerHTML = `
          <span class="v-sub-arrow">↳</span>
          <span class="v-sub-text">${window.escapeHtml(v.detail)}</span>
        `;
        item.appendChild(sub);
      }

      frag.appendChild(item);
    });

    verboseBox.appendChild(frag);

    if (state.autoScroll && state.activeTab === "verbose") {
      verboseBox.scrollTop = verboseBox.scrollHeight;
    }
  }'''

new_append_verbose = '''  function appendVerboseLogs(vLogs) {
    if (!verboseBox) return;
    const frag = document.createDocumentFragment();

    vLogs.forEach(v => {
      state.verboseLogs.push(v);
      // Only prune when autoScroll is active to prevent jumping while user is reading logs
      if (state.autoScroll && verboseBox.children.length > state.maxVerboseLines) {
        verboseBox.removeChild(verboseBox.firstChild);
      }

      const item = document.createElement("div");
      item.className = "verbose-item";

      const tagUpper = (v.tag || "PROBE").toUpperCase();
      let badgeClass = "probe";
      if (tagUpper.includes("VULN") || tagUpper.includes("POC") || tagUpper.includes("VERIFIED")) badgeClass = "vuln";
      else if (tagUpper.includes("PARAM")) badgeClass = "param";
      else if (tagUpper.includes("CSP")) badgeClass = "csp";
      else if (tagUpper.includes("DOM") || tagUpper.includes("AST") || tagUpper.includes("WAF")) badgeClass = "testing";

      item.innerHTML = `
        <div class="v-main-line">
          <span class="v-time">[${window.escapeHtml(v.time || '')}]</span>
          <span class="v-tag">[DFX]</span>
          <span class="v-badge ${badgeClass}">[${window.escapeHtml(v.tag || 'PROBE')}]</span>
          <span class="v-action">${window.escapeHtml(v.action || '')}</span>
          ${v.target ? `<span class="v-url">${window.escapeHtml(v.target)}</span>` : ''}
        </div>
      `;

      if (v.payload && v.payload.trim().length > 0) {
        const sub = document.createElement("div");
        sub.className = "v-sub-line";
        sub.innerHTML = `
          <span class="v-sub-arrow">🎯</span>
          <span class="v-sub-text" style="color:var(--neon-green); border-left-color:var(--neon-green);">Payload: <code>${window.escapeHtml(v.payload)}</code></span>
        `;
        item.appendChild(sub);
      }

      if (v.detail && v.detail.trim().length > 0) {
        const sub = document.createElement("div");
        sub.className = "v-sub-line";
        sub.innerHTML = `
          <span class="v-sub-arrow">↳</span>
          <span class="v-sub-text">${window.escapeHtml(v.detail)}</span>
        `;
        item.appendChild(sub);
      }

      frag.appendChild(item);
    });

    verboseBox.appendChild(frag);

    if (state.autoScroll && state.activeTab === "verbose") {
      verboseBox.scrollTop = verboseBox.scrollHeight;
    }
  }'''

assert old_append_verbose in code, "Could not find old_append_verbose in dalfox.js"
code = code.replace(old_append_verbose, new_append_verbose)

with open("UltronScan/ui/js/dalfox.js", "w", encoding="utf-8") as f:
    f.write(code)

print("dalfox.js patched successfully!")
