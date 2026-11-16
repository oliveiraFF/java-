"""汇总所有实验结果，生成论文用的对比表：ml/reports/comparison.md

读取：baseline_metrics.json、generalization_metrics.json、distilbert_*.json
用法（仓库根目录）：python ml/scripts/compare_models.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import fmt  # noqa: E402

REP = Path("ml/reports")
SOURCES = ["ceas", "enron", "spamassassin", "ling"]
ZH = {"naive_bayes": "朴素贝叶斯", "logistic_regression": "逻辑回归", "linear_svm": "线性 SVM", "random_forest": "随机森林"}


def load(name: str):
    p = REP / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main() -> None:
    base, gen, bert = load("baseline_metrics.json"), load("generalization_metrics.json"), load("distilbert_standard.json")
    L = ["# 模型对比汇总", "", "所有模型使用同一份数据划分与同一套指标定义（`ml/scripts/common.py`）。", ""]

    L += ["## 1. 标准划分（测试集 16,376 封）", "",
          "| 模型 | 全量 F1 | 精确率 | 召回率 | 误报率 | ROC-AUC | 钓鱼专项 F1 | 钓鱼专项精确率 | FPR≤1% 时召回 | 推理 (ms/封) |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    if base:
        for k, r in base["models"].items():
            t, f, lo = r["test"], r["test_focus"], r["test_at_fpr1"]
            L.append(f"| {ZH[k]} | {t['f1']:.4f} | {t['precision']:.4f} | {t['recall']:.4f} | {t['fpr']:.4f} | {t['roc_auc']:.4f} | "
                     f"{f['f1']:.4f} | {f['precision']:.4f} | {lo['recall']:.4f} | {r['infer_ms_per_email']} |")
    if bert:
        t, f, lo = bert["test"], bert["test_focus"], bert["test_at_fpr1"]
        L.append(f"| DistilBERT | {t['f1']:.4f} | {t['precision']:.4f} | {t['recall']:.4f} | {t['fpr']:.4f} | {t['roc_auc']:.4f} | "
                 f"{f['f1']:.4f} | {f['precision']:.4f} | {lo['recall']:.4f} | {bert['infer_ms_per_email']}（GPU） |")

    L += ["", "## 2. 留一来源（训练时完全没见过该来源，在该来源全部邮件上测试）", "",
          "| 留出来源 | 指标 | 线性 SVM | 逻辑回归 | DistilBERT |", "|---|---|---|---|---|"]
    for src in SOURCES:
        b = load(f"distilbert_loso_{src}.json")
        g = gen["original"]["loso"][src] if gen else {}
        for metric, label in (("f1", "F1"), ("fpr", "误报率"), ("roc_auc", "ROC-AUC")):
            svm = fmt(g.get("linear_svm", {}).get(metric)) if g else "—"
            lr = fmt(g.get("logistic_regression", {}).get(metric)) if g else "—"
            bv = fmt(b["test"].get(metric)) if b else "（未运行）"
            L.append(f"| {src} | {label} | {svm} | {lr} | {bv} |")

    if gen:
        L += ["", "## 3. 留一来源平均（四个来源）", "", "| 模型 | 平均 F1 | 平均误报率 |", "|---|---|---|"]
        for k in ("linear_svm", "logistic_regression", "naive_bayes"):
            f1s = [gen["original"]["loso"][s][k]["f1"] for s in SOURCES]
            fprs = [gen["original"]["loso"][s][k]["fpr"] for s in SOURCES]
            L.append(f"| {ZH[k]} | {sum(f1s) / 4:.4f} | {sum(fprs) / 4:.4f} |")
        bl = [load(f"distilbert_loso_{s}.json") for s in SOURCES]
        if all(bl):
            L.append(f"| DistilBERT | {sum(b['test']['f1'] for b in bl) / 4:.4f} | {sum(b['test']['fpr'] for b in bl) / 4:.4f} |")
    L.append("")
    (REP / "comparison.md").write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
