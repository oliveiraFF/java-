"""中文能力评估：在手写的独立中文测试集上比较各模型。

测试集 ml/testsets/zh_handwritten.csv：20 封中文钓鱼（含模板中没有的场景）+ 20 封中文正常邮件，
全部人工编写、虚构，不参与任何训练。另报告混合数据测试划分中 trec06c 正常/垃圾邮件的误报率。

用法（仓库根目录）：ml/.venv/Scripts/python ml/scripts/eval_zh.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from common import save_json  # noqa: E402
from phishguard_detector.engine import BaselineModel  # noqa: E402

ART = Path("ml/artifacts")
MODELS = [
    ("tfidf_phish", "TF-IDF（英文，钓鱼 vs 非钓鱼）", "tfidf", ART / "baseline_tfidf_phish.joblib"),
    ("tfidf_phish_mixed", "TF-IDF（中英混合，钓鱼 vs 非钓鱼）", "tfidf", ART / "baseline_tfidf_phish_mixed.joblib"),
    ("bert_phish", "DistilBERT（英文，钓鱼 vs 非钓鱼）", "bert", ART / "distilbert_phish"),
    ("bert_phish_mixed", "DistilBERT（中英混合，钓鱼 vs 非钓鱼）", "bert", ART / "distilbert_phish_mixed"),
]


def scores(kind: str, path: Path, df: pd.DataFrame) -> np.ndarray:
    if kind == "tfidf":
        return np.array(BaselineModel(path).predict_proba((df["subject"] + "\n" + df["body"]).tolist()))
    from eval_real import bert_scores

    return bert_scores(path, df)


def main() -> None:
    hw = pd.read_csv("ml/testsets/zh_handwritten.csv", keep_default_na=False)
    mixed_path = Path("ml/data/processed/emails_mixed.csv")
    zt = None
    if mixed_path.exists():
        m = pd.read_csv(mixed_path, dtype=str, keep_default_na=False)
        zt = m[(m["split"] == "test") & (m["source"] == "trec06c")].reset_index(drop=True)
        synth = m[(m["split"] == "test") & (m["source"] == "synth_zh")].reset_index(drop=True)

    res: dict = {"handwritten": {"phish": int((hw.label == 1).sum()), "ham": int((hw.label == 0).sum())}, "models": {}}
    for key, label, kind, path in MODELS:
        if not path.exists():
            print(f"跳过 {label}：缺少 {path}")
            continue
        s = scores(kind, path, hw)
        r = {"label": label,
             "hw_phish_recall": float((s[hw.label == 1] >= 0.5).mean()),
             "hw_ham_fpr": float((s[hw.label == 0] >= 0.5).mean()),
             "hw_missed": hw.loc[(hw.label == 1) & (s < 0.5), "category"].tolist(),
             "hw_false_alarms": hw.loc[(hw.label == 0) & (s >= 0.5), "category"].tolist()}
        if zt is not None and len(zt):
            st = scores(kind, path, zt)
            r["trec06c_ham_fpr"] = float((st[(zt.kind == "ham").to_numpy()] >= 0.5).mean())
            r["trec06c_spam_fpr"] = float((st[(zt.kind == "spam").to_numpy()] >= 0.5).mean())
            r["synth_phish_recall"] = float((scores(kind, path, synth) >= 0.5).mean()) if len(synth) else None
        res["models"][key] = r
        print(f"{label:<30} 手写钓鱼召回 {r['hw_phish_recall']:.2f}  手写正常误报 {r['hw_ham_fpr']:.2f}"
              + (f"  trec06c 正常误报 {r['trec06c_ham_fpr']:.3f}  中文广告误报 {r['trec06c_spam_fpr']:.3f}" if "trec06c_ham_fpr" in r else ""))

    save_json(res, Path("ml/reports/zh_eval.json"))
    L = ["# 中文能力评估", "",
         f"手写独立测试集：中文钓鱼 {res['handwritten']['phish']} 封、中文正常 {res['handwritten']['ham']} 封（人工编写、虚构，不参与训练）。阈值 0.5。", "",
         "| 模型 | 手写钓鱼召回 | 手写正常误报 | trec06c 正常误报 | trec06c 广告误报 | 模板钓鱼召回（仅参考） | 漏掉的钓鱼类型 | 误报的正常类型 |",
         "|---|---|---|---|---|---|---|---|"]
    f = lambda v: "—" if v is None else f"{v:.3f}"  # noqa: E731
    for r in res["models"].values():
        L.append(f"| {r['label']} | {r['hw_phish_recall']:.2f} | {r['hw_ham_fpr']:.2f} | {f(r.get('trec06c_ham_fpr'))} | "
                 f"{f(r.get('trec06c_spam_fpr'))} | {f(r.get('synth_phish_recall'))} | {'、'.join(r['hw_missed']) or '—'} | {'、'.join(r['hw_false_alarms']) or '—'} |")
    L.append("")
    Path("ml/reports/zh_eval.md").write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    main()
