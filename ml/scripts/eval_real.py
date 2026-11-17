"""真实邮箱评估：用各模型给真实邮件打分，统计被标记的数量。

输入：从本地数据库导出的 CSV（id, subject, body, rule_score, critical），
     规则分沿用系统检测时的结果（那时用的是完整邮件头）。
输出：ml/reports/real_mailbox.md / .json —— **只包含统计数字，不包含任何邮件内容、主题或地址**，
     因为报告会提交到公开仓库。

这批邮件经人工核对发件域名与主题，全部是正常邮件（通知、招聘推荐、营销、安全验证码等），
因此任何被标记为可疑/钓鱼的都是误报。

用法（仓库根目录）：
    ml/.venv/Scripts/python ml/scripts/eval_real.py <导出的 csv> --name "QQ 邮箱最近 50 封"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from common import save_json  # noqa: E402
from phishguard_detector.engine import BaselineModel  # noqa: E402
from phishguard_detector.fusion import combine  # noqa: E402

ART = Path("ml/artifacts")
MODELS = [
    ("tfidf_malicious", "TF-IDF（恶意 vs 正常，原始标签）", "tfidf", ART / "baseline_tfidf.joblib"),
    ("tfidf_phish", "TF-IDF（钓鱼 vs 非钓鱼）", "tfidf", ART / "baseline_tfidf_phish.joblib"),
    ("bert_malicious", "DistilBERT（恶意 vs 正常，原始标签）", "bert", ART / "distilbert_standard"),
    ("bert_phish", "DistilBERT（钓鱼 vs 非钓鱼）", "bert", ART / "distilbert_phish"),
    ("tfidf_phish_mixed", "TF-IDF（中英混合，钓鱼 vs 非钓鱼）", "tfidf", ART / "baseline_tfidf_phish_mixed.joblib"),
    ("bert_phish_mixed", "DistilBERT（中英混合，钓鱼 vs 非钓鱼）", "bert", ART / "distilbert_phish_mixed"),
]


def bert_scores(path: Path, df: pd.DataFrame) -> np.ndarray:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    from train_distilbert import make_loader, predict

    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(path)
    model = AutoModelForSequenceClassification.from_pretrained(path).to(dev)
    return predict(model, make_loader(df.assign(label=0), tok, 256, 32, False), dev)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--name", default="真实邮箱")
    args = ap.parse_args()
    df = pd.read_csv(args.csv, keep_default_na=False)
    df["critical"] = df["critical"].astype(str).str.lower().isin(["t", "true", "1"])
    texts = (df["subject"] + "\n" + df["body"]).tolist()
    n = len(df)

    res = {"name": args.name, "n": n, "all_legitimate": True,
           "rules_only": {"flag_ge50": int((df["rule_score"] >= 50).sum()), "flag_ge80": int((df["rule_score"] >= 80).sum()),
                          "any_hit": int((df["rule_score"] > 0).sum())},
           "models": {}}
    for key, label, kind, path in MODELS:
        if not path.exists():
            print(f"跳过 {label}：缺少 {path}")
            continue
        p = np.array(BaselineModel(path).predict_proba(texts)) if kind == "tfidf" else bert_scores(path, df)
        fused = np.array([combine(int(r), float(pi), critical=bool(c)) for r, pi, c in zip(df["rule_score"], p, df["critical"])])
        res["models"][key] = {
            "label": label,
            "model_ge50": int((p >= 0.5).sum()), "model_ge80": int((p >= 0.8).sum()), "model_median": float(np.median(p)),
            # 系统判定口径：融合分 ≥50 可疑，≥80 钓鱼
            "system_suspicious_or_more": int((fused >= 0.5).sum()), "system_phishing": int((fused >= 0.8).sum()),
        }
        m = res["models"][key]
        print(f"{label:<34} 模型≥0.5: {m['model_ge50']:>2}/{n}  系统判可疑及以上: {m['system_suspicious_or_more']:>2}/{n}  判钓鱼: {m['system_phishing']:>2}/{n}")

    out = Path("ml/reports")
    save_json(res, out / "real_mailbox.json")
    L = [f"# 真实邮箱评估：{args.name}", "",
         f"共 {n} 封，经人工核对全部为正常邮件（通知、招聘推荐、营销、安全验证码等），所以下表中被标记的数量**全部是误报**。",
         "报告只记录统计数字，不包含任何邮件内容。规则分沿用系统检测时基于完整邮件头的结果。", "",
         f"仅规则：有规则命中 {res['rules_only']['any_hit']} 封，规则分 ≥50 的 {res['rules_only']['flag_ge50']} 封，≥80 的 {res['rules_only']['flag_ge80']} 封。", "",
         "| 模型 | 模型单独 ≥0.5 | 模型单独 ≥0.8 | 模型分中位数 | 系统判可疑及以上（规则+模型 ≥50） | 系统判钓鱼（≥80） |",
         "|---|---|---|---|---|---|"]
    for m in res["models"].values():
        L.append(f"| {m['label']} | {m['model_ge50']}/{n} | {m['model_ge80']}/{n} | {m['model_median']:.3f} | "
                 f"{m['system_suspicious_or_more']}/{n} | {m['system_phishing']}/{n} |")
    L.append("")
    (out / "real_mailbox.md").write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    main()
