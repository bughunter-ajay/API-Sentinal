/**
 * ULTRONSCAN - Core App Coordinator
 */

const API_BASE = "http://127.0.0.1:8731";

window.appState = {
  activeTool: "sqlmap",
  health: null,
  isScanning: false
};

// Toast notification helper
window.showToast = function(message, type = "info") {
  let toastContainer = document.getElementById("toast-container");
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.id = "toast-container";
    toastContainer.style.position = "fixed";
    toastContainer.style.bottom = "20px";
    toastContainer.style.right = "20px";
    toastContainer.style.zIndex = "99999";
    toastContainer.style.display = "flex";
    toastContainer.style.flexDirection = "column";
    toastContainer.style.gap = "8px";
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement("div");
  toast.style.background = "#0c1520";
  toast.style.border = type === "error" ? "1px solid #ff3366" : (type === "success" ? "1px solid #00ff66" : "1px solid #00e5ff");
  toast.style.color = type === "error" ? "#ff3366" : (type === "success" ? "#00ff66" : "#e6edf3");
  toast.style.boxShadow = "0 4px 16px rgba(0,0,0,0.6)";
  toast.style.padding = "10px 16px";
  toast.style.borderRadius = "4px";
  toast.style.fontFamily = "'JetBrains Mono', monospace";
  toast.style.fontSize = "12px";
  toast.style.display = "flex";
  toast.style.alignItems = "center";
  toast.style.gap = "8px";
  toast.style.opacity = "0";
  toast.style.transform = "translateY(10px)";
  toast.style.transition = "all 0.2s ease";

  const icon = type === "error" ? "❌" : (type === "success" ? "✅" : "⚡");
  toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
  toastContainer.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 250);
  }, 3500);
};

// Modal helpers
window.openModal = function(modalId) {
  if (modalId === "curl-modal" && window.isUltronScanning && window.isUltronScanning()) {
    window.showToast("Cannot import cURL while scan is in progress! Please stop the scan first.", "error");
    return;
  }
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add("open");
};

window.closeModal = function(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove("open");
};

// Clipboard helper
window.copyToClipboard = function(text, successMsg = "Copied to clipboard!") {
  const content = String(text != null ? text : "");
  if (!content) {
    window.showToast("Nothing to copy", "info");
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(content).then(() => {
      window.showToast(successMsg, "success");
    }).catch(() => {
      fallbackCopy(content, successMsg);
    });
  } else {
    fallbackCopy(content, successMsg);
  }
};

function fallbackCopy(text, successMsg) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "-9999px";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand("copy");
    window.showToast(successMsg, "success");
  } catch (err) {
    window.showToast(successMsg, "success");
  }
  document.body.removeChild(ta);
}

// Health check and initialization
async function checkBackendHealth() {
  const statusEl = document.getElementById("system-status-text");
  const dotEl = document.getElementById("system-status-dot");

  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error("Backend offline");
    const data = await res.json();
    window.appState.health = data;

    if (statusEl) {
      const sqlmapVer = data.sqlmap?.version || "Ready";
      const commixVer = data.commix?.version || "Ready";
      statusEl.textContent = `SYSTEM ONLINE | SQLMAP ${sqlmapVer} | COMMIX ${commixVer}`;
      statusEl.style.color = "var(--neon-green)";
    }
    if (dotEl) {
      dotEl.style.background = "var(--neon-green)";
      dotEl.style.boxShadow = "0 0 8px var(--neon-green)";
    }
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = "CONNECTING TO ENGINE (PORT 8731)...";
      statusEl.style.color = "var(--neon-amber)";
    }
    if (dotEl) {
      dotEl.style.background = "var(--neon-amber)";
      dotEl.style.boxShadow = "0 0 8px var(--neon-amber)";
    }
    setTimeout(checkBackendHealth, 2000);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  checkBackendHealth();
});

// Top App View Switcher
window.switchAppView = function(viewName) {
  window.appState.activeTool = viewName;

  const btnSqlmap = document.getElementById("nav-btn-sqlmap");
  const btnCommix = document.getElementById("nav-btn-commix");
  const btnSettings = document.getElementById("nav-btn-settings");

  const paneSqlmap = document.getElementById("tool-sqlmap");
  const paneCommix = document.getElementById("tool-commix");
  const paneSettings = document.getElementById("tool-settings");

  // Deactivate all nav buttons first
  if (btnSqlmap) btnSqlmap.classList.remove("active");
  if (btnCommix) btnCommix.classList.remove("active");
  if (btnSettings) btnSettings.classList.remove("active");

  // Hide all panes
  if (paneSqlmap) paneSqlmap.style.display = "none";
  if (paneCommix) paneCommix.style.display = "none";
  if (paneSettings) paneSettings.style.display = "none";

  if (viewName === "sqlmap") {
    if (btnSqlmap) btnSqlmap.classList.add("active");
    if (paneSqlmap) paneSqlmap.style.display = "flex";
  } else if (viewName === "commix") {
    if (btnCommix) btnCommix.classList.add("active");
    if (paneCommix) paneCommix.style.display = "flex";
  } else if (viewName === "settings") {
    if (btnSettings) btnSettings.classList.add("active");
    if (paneSettings) paneSettings.style.display = "flex";
    if (window.switchSettingsTab) window.switchSettingsTab("hub");
  }
};

// Global shortcut listener: Drag-select any text and Cmd+C / Ctrl+C to copy
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && (e.key === 'c' || e.key === 'C')) {
    const isInput = ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName);
    if (isInput) return; // Allow native input copying

    const sel = window.getSelection();
    if (sel && sel.toString().trim().length > 0) {
      const textToCopy = sel.toString();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          window.showToast('Copied selected text', 'success');
        }).catch(() => {
          fallbackCopy(textToCopy, 'Copied selected text');
        });
      } else {
        fallbackCopy(textToCopy, 'Copied selected text');
      }
    }
  }
});
