# 🛡️ Web Phishing Detection

Hệ thống phát hiện URL lừa đảo (phishing) chạy **hoàn toàn local**, gồm:

| Thành phần | Công nghệ | URL |
|---|---|---|
| **Backend API** | FastAPI + scikit-learn | http://127.0.0.1:8000 |
| **Dashboard** | Streamlit + Altair | http://127.0.0.1:8501 |
| **Chrome Extension** | Manifest V3 | — |
| **Model Training** | Random Forest | `training/train.py` |

---

## 📁 Cấu trúc dự án

```
LAB_AI/
├── backend/
│   ├── app.py               # FastAPI app (GET /health, POST /predict)
│   ├── schemas.py           # Pydantic request/response models
│   ├── feature_extractor.py # Trích xuất đặc trưng URL (32 features)
│   └── model.py             # Wrapper load model + heuristic fallback
├── training/
│   ├── train.py             # Script huấn luyện mô hình
│   └── data/
│       └── sample_data.csv  # Dataset mẫu (VN-focused)
├── chrome_extension/
│   ├── manifest.json        # Manifest V3
│   ├── popup.html / popup.js
│   ├── background.js        # Service worker — tự động kiểm tra URL
│   └── content.js           # Content script — hiện banner cảnh báo
├── dashboard/
│   └── app.py               # Streamlit dashboard
├── models/                  # Thư mục lưu model (.joblib)
├── requirements.txt
└── start.sh                 # Khởi động nhanh (backend + dashboard)
```

---

## 🚀 Cài đặt & Chạy

### 1. Cài dependencies

```bash
pip install -r requirements.txt
```

### 2. (Tuỳ chọn) Huấn luyện mô hình

Dùng dataset mẫu có sẵn hoặc thay bằng CSV của bạn:

```bash
python -m training.train
# Kết quả: models/phishing_model.joblib
```

> Nếu chưa train, API vẫn hoạt động bằng **heuristic rules** — không cần model.

### 3. Khởi động toàn bộ hệ thống

```bash
bash start.sh
```

Hoặc chạy từng phần:

```bash
# Terminal 1 — Backend
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 — Dashboard
streamlit run dashboard/app.py
```

---

## 🌐 API Endpoints

### `GET /health`

```json
{
  "status": "ok",
  "model_loaded": true,
  "time": "2024-01-01T00:00:00+00:00",
  "thresholds": {
    "phishing": 0.6,
    "suspicious": 0.4
  }
}
```

### `POST /predict`

**Request:**
```json
{ "url": "http://vietcombank-secure.tk/login" }
```

**Response:**
```json
{
  "url": "http://vietcombank-secure.tk/login",
  "is_phishing": true,
  "confidence": 0.87,
  "verdict": "phishing",
  "features": { "url_length": 42, "is_https": 0, ... },
  "model_version": "1.0.0"
}
```

Xem API docs đầy đủ tại: http://127.0.0.1:8000/docs

---

## 🧩 Chrome Extension

1. Mở Chrome → `chrome://extensions/`
2. Bật **Developer mode**
3. Chọn **Load unpacked** → chọn thư mục `chrome_extension/`
4. Extension tự động kiểm tra URL mỗi khi bạn truy cập trang mới

> ⚠️ Cần thêm icon PNG vào `chrome_extension/icons/` (16×16, 48×48, 128×128).

---

## 📊 Features được trích xuất

| # | Feature | Mô tả |
|---|---|---|
| 1 | `url_length` | Độ dài URL |
| 2 | `has_ip` | Host là địa chỉ IP |
| 3 | `is_https` | Dùng HTTPS |
| 4 | `is_suspicious_tld` | TLD đáng ngờ (.tk, .ml, .xyz…) |
| 5 | `brand_in_subdomain` | Tên thương hiệu VN trong subdomain |
| 6 | `has_punycode` | IDN homograph (xn--) |
| 7 | `domain_entropy` | Shannon entropy của domain |
| 8 | `redirect_count` | Số lần redirect trong URL |
| … | … | Tổng 32 đặc trưng |

---

## 📄 License

MIT
