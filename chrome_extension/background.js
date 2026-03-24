/* background.js — Service worker for the phishing detector extension */

const API_BASE = "http://127.0.0.1:8000";

// ── Tab navigation listener ────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only check when a page finishes loading
  if (changeInfo.status !== "complete") return;
  const url = tab.url ?? "";
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  try {
    const resp = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!resp.ok) return;
    const result = await resp.json();

    // Store latest result so popup can read it
    chrome.storage.local.set({ lastResult: result });

    if (result.verdict === "phishing") {
      _showWarning(tabId, url, result.confidence);
    } else if (result.verdict === "suspicious") {
      _showSuspiciousNotice(tabId);
    }
  } catch (_) {
    // API unavailable — silent fail; user sees "not connected" in popup
  }
});

// ── Message from popup ─────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "PHISHING_DETECTED") {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "🚨 Cảnh báo Phishing!",
      message: `URL này có thể là lừa đảo!\n${message.url.slice(0, 80)}`,
      priority: 2,
    });
  }
});

// ── Helpers ────────────────────────────────────────────────────────────────

function _showWarning(tabId, url, confidence) {
  const pct = Math.round(confidence * 100);

  chrome.notifications.create(`phishing-${tabId}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "🚨 Cảnh báo: URL Phishing!",
    message: `Trang này bị phát hiện là lừa đảo (${pct}% chắc chắn). Hãy đóng tab ngay!`,
    priority: 2,
  });

  // Inject a warning banner into the page
  chrome.scripting.executeScript({
    target: { tabId },
    func: _injectWarningBanner,
    args: [url, pct],
  }).catch(() => {/* scripting not available on special pages */});
}

function _showSuspiciousNotice(tabId) {
  chrome.action.setBadgeText({ tabId, text: "⚠️" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#ffc107" });
}

// This function is serialised and injected into the page — keep self-contained
function _injectWarningBanner(url, pct) {
  if (document.getElementById("phishing-warning-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishing-warning-banner";
  banner.style.cssText = [
    "position:fixed", "top:0", "left:0", "width:100%", "z-index:2147483647",
    "background:#dc3545", "color:#fff", "font-family:Arial,sans-serif",
    "font-size:14px", "padding:10px 16px", "display:flex",
    "justify-content:space-between", "align-items:center",
    "box-shadow:0 2px 6px rgba(0,0,0,.4)",
  ].join(";");

  // Build content using DOM methods to avoid XSS with user-controlled url/pct
  const msgSpan = document.createElement("span");
  const boldEl = document.createElement("strong");
  boldEl.textContent = "Cảnh báo:";
  msgSpan.appendChild(boldEl);
  msgSpan.appendChild(document.createTextNode(
    ` 🚨 Trang này có thể là PHISHING (${Number(pct)}% nguy cơ). Không nhập thông tin cá nhân!`
  ));

  const closeBtn = document.createElement("button");
  closeBtn.textContent = "Đóng";
  closeBtn.style.cssText =
    "background:transparent;border:1px solid #fff;color:#fff;" +
    "padding:4px 10px;cursor:pointer;border-radius:4px;font-size:12px;margin-left:12px";
  closeBtn.addEventListener("click", () => banner.remove());

  banner.appendChild(msgSpan);
  banner.appendChild(closeBtn);
  document.body.prepend(banner);
}
