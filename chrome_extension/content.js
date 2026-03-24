/* content.js — Content script injected into every page */

(function () {
  "use strict";

  // Avoid running twice
  if (window.__phishingDetectorLoaded) return;
  window.__phishingDetectorLoaded = true;

  /**
   * Listen for messages from the background service worker.
   * Currently used to trigger a visible warning banner if needed.
   */
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "SHOW_WARNING") {
      _showBanner(message.confidence ?? 0);
    }
  });

  function _showBanner(confidence) {
    if (document.getElementById("pd-content-banner")) return;

    const pct = Math.round(confidence * 100);
    const banner = document.createElement("div");
    banner.id = "pd-content-banner";
    banner.style.cssText = [
      "position:fixed", "top:0", "left:0", "width:100%",
      "z-index:2147483647", "background:#dc3545", "color:#fff",
      "font-family:Arial,sans-serif", "font-size:14px",
      "padding:10px 16px", "display:flex", "align-items:center",
      "box-shadow:0 2px 6px rgba(0,0,0,.35)",
    ].join(";");

    const msgSpan = document.createElement("span");
    msgSpan.style.flex = "1";
    const boldEl = document.createElement("strong");
    boldEl.textContent = `Cảnh báo Phishing (${pct}%):`;
    msgSpan.appendChild(boldEl);
    msgSpan.appendChild(document.createTextNode(
      " Trang này có dấu hiệu lừa đảo. Không nhập thông tin cá nhân!"
    ));

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Đóng";
    closeBtn.style.cssText =
      "margin-left:12px;background:transparent;border:1px solid #fff;" +
      "color:#fff;padding:2px 8px;cursor:pointer;border-radius:4px";
    closeBtn.addEventListener("click", () => banner.remove());

    banner.appendChild(msgSpan);
    banner.appendChild(closeBtn);
    document.body.prepend(banner);
  }
})();
