"""
Model training script for Web Phishing Detection.

Usage:
    python -m training.train [--data PATH] [--model-out PATH] [--test-size 0.2]

The script:
1. Loads a labelled CSV (url, label) — defaults to training/data/sample_data.csv
2. Extracts URL features (see backend/feature_extractor.py)
3. Trains a Random-Forest classifier (works well with hand-crafted features)
4. Evaluates and prints a classification report
5. Saves the trained model to models/phishing_model.joblib
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path so `backend` package is importable
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import joblib  # type: ignore
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.feature_extractor import extract_features

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_DATA = _ROOT / "training" / "data" / "sample_data.csv"
_DEFAULT_MODEL_OUT = _ROOT / "models" / "phishing_model.joblib"


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def build_feature_matrix(urls: pd.Series) -> np.ndarray:
    """Extract features for each URL and return a 2-D NumPy array."""
    logger.info("Extracting features for %d URLs …", len(urls))
    rows = []
    for url in urls:
        try:
            feat = extract_features(str(url))
            rows.append(list(feat.values()))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Feature extraction failed for %s: %s", url, exc)
            # Fill with zeros if extraction fails
            rows.append([0] * 32)
    return np.array(rows, dtype=float)


def get_feature_names() -> list[str]:
    """Return feature names (same order as extract_features output)."""
    from backend.feature_extractor import extract_features as _ef
    return list(_ef("http://example.com").keys())


# ---------------------------------------------------------------------------
# Model definition
# ---------------------------------------------------------------------------

def build_pipeline() -> Pipeline:
    """Return a scikit-learn Pipeline ready for fitting."""
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=200,
                    max_depth=12,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )


# ---------------------------------------------------------------------------
# Training entry-point
# ---------------------------------------------------------------------------

def train(
    data_path: Path = _DEFAULT_DATA,
    model_out: Path = _DEFAULT_MODEL_OUT,
    test_size: float = 0.2,
    random_state: int = 42,
) -> None:
    """Load data → extract features → train → evaluate → save model."""

    # 1. Load dataset
    logger.info("Loading dataset from %s", data_path)
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must have 'url' and 'label' columns.")
    df = df.dropna(subset=["url", "label"])
    logger.info("Dataset: %d samples (%d phishing, %d legitimate)",
                len(df), df["label"].sum(), (df["label"] == 0).sum())

    # 2. Feature extraction
    X = build_feature_matrix(df["url"])
    y = df["label"].astype(int).values

    # 3. Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )
    logger.info("Train size: %d  |  Test size: %d", len(X_train), len(X_test))

    # 4. Cross-validation on training set
    pipeline = build_pipeline()
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="roc_auc")
    logger.info("CV ROC-AUC: %.4f ± %.4f", cv_scores.mean(), cv_scores.std())

    # 5. Fit on full training set
    pipeline.fit(X_train, y_train)

    # 6. Evaluate on held-out test set
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 60)
    print("CLASSIFICATION REPORT (Test Set)")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    if len(np.unique(y_test)) > 1:
        print(f"\nROC-AUC (test): {roc_auc_score(y_test, y_prob):.4f}")
    print("=" * 60 + "\n")

    # 7. Feature importance
    rf = pipeline.named_steps["clf"]
    feature_names = get_feature_names()
    importances = sorted(
        zip(feature_names, rf.feature_importances_), key=lambda x: x[1], reverse=True
    )
    print("Top-10 Feature Importances:")
    for name, imp in importances[:10]:
        print(f"  {name:<30s} {imp:.4f}")
    print()

    # 8. Save model
    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_out)
    logger.info("Model saved to %s", model_out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train phishing detection model")
    parser.add_argument("--data", type=Path, default=_DEFAULT_DATA,
                        help="Path to labelled CSV (url, label)")
    parser.add_argument("--model-out", type=Path, default=_DEFAULT_MODEL_OUT,
                        help="Output path for trained model (.joblib)")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Fraction of data for testing (default: 0.2)")
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    train(
        data_path=args.data,
        model_out=args.model_out,
        test_size=args.test_size,
        random_state=args.random_state,
    )
