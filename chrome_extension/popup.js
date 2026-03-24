/* popup.js — UI logic for the phishing detector popup */

const API_BASE = "http://127.0.0.1:8000";

// ── DOM references ─────────────────────────────────────────────────────────
const urlDisplay      = document.getElementById("url-display");
const verdictCard     = document.getElementById("verdict-card");
const verdictIcon     = document.getElementById("verdict-icon");
const verdictText     = document.getElementById("verdict-text");
const confidenceText  = document.getElementById("confidence-text");
const confidenceFill  = document.getElementById("confidence-fill");
const checkBtn        = document.getElementById("check-btn");
const errorMsg        = document.getElementById("error-msg");
const apiDot          = document.getElementById("api-dot");
const apiStatus       = document.getElementById("api-status");

// ── Helpers ────────────────────────────────────────────────────────────────

function setVerdictUI(verdict, confidence) {
  const pct = Math.round(confidence * 100);
  const icons = { phishing: "🚨", suspicious: "⚠️", safe: "✅", loading: "🔍" };

  verdictCard.className = `verdict-card ${verdict}`;
  verdictIcon.textContent = icons[verdict] ?? "🔍";
  confidenceFill.style.width = `${pct}%`;

  switch (verdict) {
    case "phishing":
      verdictText.textContent = "NGUY HIỂM — URL Phishing!";
      break;
    case "suspicious":
      verdictText.textContent = "Đáng ngờ — hãy thận trọng";
      break;
    case "safe":
      verdictText.textContent = "An toàn";
      break;
    default:
      verdictText.textContent = "Chưa kiểm tra";
  }

  confidenceText.textContent =
    verdict === "loading" ? "Đang phân tích…" : `Độ tin cậy: ${pct}%`;
}

function showError(msg) {
  errorMsg.textContent = msg;
}

function clearError() {
  errorMsg.textContent = "";
}

// ── API calls ──────────────────────────────────────────────────────────────

async function checkApiHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const resp = await fetch(`${API_BASE}/health`, { signal: controller.signal });
    clearTimeout(timer);
    if (resp.ok) {
      apiDot.className = "status-dot connected";
      apiStatus.textContent = "đang chạy";
      return true;
    }
  } catch (_) {
    clearTimeout(timer);
  }
  apiDot.className = "status-dot error";
  apiStatus.textContent = "không kết nối được";
  return false;
}

async function predictUrl(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const resp = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) {
      const detail = await resp.json().catch(() => ({}));
      throw new Error(detail.detail ?? `Lỗi HTTP ${resp.status}`);
    }
    return resp.json();
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ── Main flow ──────────────────────────────────────────────────────────────

async function run() {
  clearError();

  // Get active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url ?? "";
  urlDisplay.textContent = url || "(Không có URL)";

  // Health check
  const healthy = await checkApiHealth();
  if (!healthy) {
    showError("Không thể kết nối đến API. Hãy chắc chắn backend đang chạy.");
    return;
  }

  // Auto-check on popup open
  if (url && (url.startsWith("http://") || url.startsWith("https://"))) {
    await doCheck(url);
  }
}

async function doCheck(url) {
  clearError();
  checkBtn.disabled = true;
  setVerdictUI("loading", 0);

  try {
    const result = await predictUrl(url);
    setVerdictUI(result.verdict, result.confidence);

    // Notify if phishing
    if (result.verdict === "phishing") {
      chrome.runtime.sendMessage({
        type: "PHISHING_DETECTED",
        url,
        confidence: result.confidence,
      });
    }

    // Persist last result
    chrome.storage.local.set({ lastResult: result });
  } catch (err) {
    showError(`Lỗi: ${err.message}`);
    setVerdictUI("loading", 0);
  } finally {
    checkBtn.disabled = false;
  }
}

// ── Event listeners ────────────────────────────────────────────────────────

checkBtn.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url ?? "";
  if (!url) {
    showError("Không lấy được URL của tab hiện tại.");
    return;
  }
  await doCheck(url);
});

// Kick off on load
run();
