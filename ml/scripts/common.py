"""实验脚本共用：数据读取、模型输入、评价指标、低误报阈值。

所有实验（基线、泛化、DistilBERT）都用这里的同一套指标定义，保证论文表格可比。
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

SEED = 42
TARGET_FPR = 0.01
DATA = "ml/data/processed/emails.csv"


def load_emails(path: str = DATA) -> pd.DataFrame:
    return pd.read_csv(path, dtype={"subject": str, "body": str, "sender": str}, keep_default_na=False)


def model_input(df: pd.DataFrame, max_chars: int = 20_000) -> pd.Series:
    """模型输入统一为：主题 + 换行 + 正文。"""
    return (df["subject"].fillna("") + "\n" + df["body"].fillna("")).str.slice(0, max_chars)


def metrics(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    """s 为"越大越可能恶意"的分数；只有一个类别时 AUC 记为 None。"""
    y = np.asarray(y)
    pred = (np.asarray(s) >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    both = len(np.unique(y)) == 2
    return {
        "n": int(len(y)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, s)) if both else None,
        "pr_auc": float(average_precision_score(y, s)) if both else None,
        "fpr": float(fp / (fp + tn)) if (fp + tn) else None,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def threshold_at_fpr(y: np.ndarray, s: np.ndarray, target: float = TARGET_FPR) -> float:
    """在给定数据上选阈值，使负样本中被判为恶意的比例不超过 target。"""
    neg = np.sort(np.asarray(s)[np.asarray(y) == 0])
    k = int(np.floor(target * len(neg)))
    idx = len(neg) - k - 1
    return float(np.nextafter(neg[idx], np.inf)) if idx >= 0 else float(neg.min())


def save_json(obj: dict, path: Path) -> None:
    def conv(o):
        if isinstance(o, (np.floating, np.integer)):
            return o.item()
        raise TypeError(type(o))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=conv), encoding="utf-8")


def fmt(v, nd: int = 4) -> str:
    return "—" if v is None else f"{v:.{nd}f}"
