#!/usr/bin/env bash
# start.sh — Khởi động toàn bộ dự án Web Phishing Detection (local)
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "=== Web Phishing Detection — Local Launcher ==="
echo ""

# 1. Backend FastAPI
echo "[1/2] Khởi động FastAPI backend tại http://127.0.0.1:8000 …"
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
echo "      PID: $BACKEND_PID"

# 2. Streamlit dashboard
echo "[2/2] Khởi động Streamlit dashboard tại http://127.0.0.1:8501 …"
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501 &
DASHBOARD_PID=$!
echo "      PID: $DASHBOARD_PID"

echo ""
echo "Nhấn Ctrl+C để dừng tất cả dịch vụ."

# Wait and forward SIGINT/SIGTERM
trap "kill $BACKEND_PID $DASHBOARD_PID 2>/dev/null; exit 0" INT TERM
wait
