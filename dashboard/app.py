"""
Web Phishing Detection — Streamlit Dashboard
Run: streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import altair as alt
import pandas as pd
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API_BASE = "http://127.0.0.1:8000"
PAGE_TITLE = "🛡️ Web Phishing Detection Dashboard"

st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

@st.cache_data(ttl=5)
def get_health() -> Optional[Dict[str, Any]]:
    try:
        resp = requests.get(f"{API_BASE}/health", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def predict_url(url: str) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.post(
            f"{API_BASE}/predict",
            json={"url": url},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        detail = exc.response.json().get("detail", str(exc)) if exc.response else str(exc)
        st.error(f"API error: {detail}")
    except Exception as exc:
        st.error(f"Không thể kết nối đến API: {exc}")
    return None


# ---------------------------------------------------------------------------
# Sidebar — health status
# ---------------------------------------------------------------------------

def render_sidebar(health: Optional[Dict[str, Any]]) -> None:
    st.sidebar.header("⚙️ Trạng thái hệ thống")

    if health:
        status_color = "🟢" if health.get("status") == "ok" else "🔴"
        st.sidebar.success(f"{status_color} API đang hoạt động")
        st.sidebar.metric("Model loaded", "✅ Có" if health.get("model_loaded") else "⚠️ Dùng heuristic")

        thresholds = health.get("thresholds", {})
        st.sidebar.caption("**Ngưỡng phân loại**")
        st.sidebar.json(thresholds)
        st.sidebar.caption(f"Cập nhật: {health.get('time', '—')}")
    else:
        st.sidebar.error("🔴 Không kết nối được API\nHãy chạy: `uvicorn backend.app:app --reload`")

    st.sidebar.divider()
    st.sidebar.markdown(
        "**Phishing Detector** v1.0.0\n\n"
        "[GitHub](https://github.com/vutranthanhthu/LAB_AI) | "
        "[API Docs](http://127.0.0.1:8000/docs)"
    )


# ---------------------------------------------------------------------------
# Single URL check panel
# ---------------------------------------------------------------------------

def render_single_check() -> Optional[Dict[str, Any]]:
    st.subheader("🔍 Kiểm tra URL")

    col1, col2 = st.columns([4, 1])
    with col1:
        url_input = st.text_input(
            "Nhập URL cần kiểm tra",
            placeholder="https://example.com",
            label_visibility="collapsed",
        )
    with col2:
        check_pressed = st.button("Kiểm tra", type="primary", use_container_width=True)

    result = None
    if check_pressed and url_input.strip():
        with st.spinner("Đang phân tích…"):
            result = predict_url(url_input.strip())

    if result:
        _render_verdict(result)

    return result


def _render_verdict(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "unknown")
    confidence = result.get("confidence", 0.0)
    pct = round(confidence * 100, 1)

    color_map = {
        "phishing":   ("#dc3545", "🚨 PHISHING"),
        "suspicious": ("#ffc107", "⚠️  Đáng ngờ"),
        "safe":       ("#28a745", "✅ An toàn"),
    }
    color, label = color_map.get(verdict, ("#6c757d", "❓ Không xác định"))

    st.markdown(
        f"""
        <div style="border-left:5px solid {color};background:{color}18;
                    padding:12px 16px;border-radius:6px;margin-bottom:12px">
            <h3 style="margin:0;color:{color}">{label}</h3>
            <p style="margin:4px 0 0;font-size:13px">
                Độ tin cậy: <strong>{pct}%</strong> &nbsp;|&nbsp;
                URL: <code>{result.get('url','')}</code>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Feature table
    features = result.get("features")
    if features:
        with st.expander("📊 Chi tiết đặc trưng URL", expanded=False):
            df_feat = pd.DataFrame(
                {"Đặc trưng": list(features.keys()), "Giá trị": list(features.values())}
            )
            st.dataframe(df_feat, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Batch URL check panel
# ---------------------------------------------------------------------------

def render_batch_check() -> None:
    st.subheader("📋 Kiểm tra hàng loạt")

    uploaded = st.file_uploader(
        "Upload file TXT (mỗi dòng một URL) hoặc CSV (cột 'url')",
        type=["txt", "csv"],
    )

    urls_text = st.text_area(
        "Hoặc dán URL vào đây (mỗi dòng một URL)",
        height=120,
        placeholder="https://url1.com\nhttps://url2.com",
    )

    run_batch = st.button("Chạy kiểm tra hàng loạt", type="secondary")

    if not run_batch:
        return

    # Collect URLs
    urls: List[str] = []
    if uploaded:
        raw = uploaded.read().decode("utf-8", errors="ignore")
        if uploaded.name.endswith(".csv"):
            df_up = pd.read_csv(pd.io.common.StringIO(raw))
            if "url" in df_up.columns:
                urls = df_up["url"].dropna().tolist()
            else:
                st.warning("CSV phải có cột 'url'.")
                return
        else:
            urls = [line.strip() for line in raw.splitlines() if line.strip()]
    elif urls_text.strip():
        urls = [line.strip() for line in urls_text.splitlines() if line.strip()]

    if not urls:
        st.warning("Không tìm thấy URL nào.")
        return

    # Run predictions
    progress = st.progress(0, text="Đang kiểm tra…")
    results: List[Dict[str, Any]] = []
    for i, url in enumerate(urls):
        r = predict_url(url)
        if r:
            results.append(r)
        progress.progress((i + 1) / len(urls), text=f"{i+1}/{len(urls)}")
    progress.empty()

    if not results:
        st.error("Không nhận được kết quả nào từ API.")
        return

    df_res = pd.DataFrame(
        [
            {
                "URL": r["url"],
                "Verdict": r["verdict"],
                "Confidence %": round(r["confidence"] * 100, 1),
                "Phishing": r["is_phishing"],
            }
            for r in results
        ]
    )

    # Summary metrics
    n_phish = df_res["Phishing"].sum()
    n_safe = (df_res["Verdict"] == "safe").sum()
    n_sus = (df_res["Verdict"] == "suspicious").sum()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Tổng URL", len(df_res))
    c2.metric("🚨 Phishing", int(n_phish))
    c3.metric("⚠️ Đáng ngờ", int(n_sus))
    c4.metric("✅ An toàn", int(n_safe))

    # Verdict distribution chart
    dist = df_res["Verdict"].value_counts().reset_index()
    dist.columns = ["Verdict", "Count"]
    color_scale = alt.Scale(
        domain=["phishing", "suspicious", "safe"],
        range=["#dc3545", "#ffc107", "#28a745"],
    )
    chart = (
        alt.Chart(dist)
        .mark_bar()
        .encode(
            x=alt.X("Verdict:N", title="Phân loại"),
            y=alt.Y("Count:Q", title="Số lượng"),
            color=alt.Color("Verdict:N", scale=color_scale),
            tooltip=["Verdict", "Count"],
        )
        .properties(title="Phân bố kết quả", height=220)
    )
    st.altair_chart(chart, use_container_width=True)

    # Full results table
    st.dataframe(
        df_res.style.map(
            lambda v: "background-color:#ffe8e8" if v == "phishing"
            else ("background-color:#fff3cd" if v == "suspicious" else ""),
            subset=["Verdict"],
        ),
        use_container_width=True,
        hide_index=True,
    )

    # Download
    st.download_button(
        "⬇️ Tải kết quả (CSV)",
        data=df_res.to_csv(index=False).encode("utf-8"),
        file_name=f"phishing_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )


# ---------------------------------------------------------------------------
# History panel (stored in session state)
# ---------------------------------------------------------------------------

def render_history(new_result: Optional[Dict[str, Any]]) -> None:
    if "history" not in st.session_state:
        st.session_state.history = []

    if new_result:
        st.session_state.history.insert(0, new_result)

    history = st.session_state.history[:50]  # keep last 50
    if not history:
        return

    st.subheader("🕑 Lịch sử kiểm tra (phiên này)")
    df_hist = pd.DataFrame(
        [
            {
                "URL": r["url"],
                "Verdict": r["verdict"],
                "Confidence %": round(r["confidence"] * 100, 1),
            }
            for r in history
        ]
    )
    st.dataframe(df_hist, use_container_width=True, hide_index=True)

    if st.button("Xoá lịch sử"):
        st.session_state.history = []
        st.rerun()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.title(PAGE_TITLE)
    st.caption("Phát hiện URL lừa đảo (phishing) bằng Machine Learning — chạy hoàn toàn local")

    health = get_health()
    render_sidebar(health)

    tab1, tab2 = st.tabs(["🔍 Kiểm tra URL", "📋 Hàng loạt"])

    with tab1:
        result = render_single_check()
        render_history(result)

    with tab2:
        render_batch_check()


if __name__ == "__main__":
    main()
