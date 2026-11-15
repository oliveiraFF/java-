"""规则引擎在公开数据集上的表现：每条规则在正常/恶意邮件上的命中率，以及规则分的整体区分能力。

说明：公开数据集只有发件人、主题、正文，没有完整邮件头、HTML 和附件，
所以认证类、链接显示文本类、附件类规则在这里基本不会触发，这部分要靠系统实测验证。

用法（仓库根目录）：
    python ml/scripts/eval_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

from common import load_emails, metrics, save_json  # noqa: E402
from phishguard_detector import parse_text  # noqa: E402
from phishguard_detector.rules import RULES, evaluate  # noqa: E402


def main() -> None:
    df = load_emails()
    te = df[df["split"] == "test"].reset_index(drop=True)
    results = [evaluate(parse_text(s, b, snd)) for s, b, snd in zip(te["subject"], te["body"], te["sender"])]
    score = np.array([r.score for r in results], dtype=float)
    hit_sets = [{h.rule_id for h in r.hits} for r in results]
    y = te["label"].to_numpy()
    kinds = te["kind"].to_numpy()

    per_rule = {}
    for r in RULES:
        hit = np.array([r.rule_id in s for s in hit_sets])
        row = {"name": r.name, "weight": r.weight, "hits": int(hit.sum())}
        for k in ("ham", "spam", "phishing", "fraud"):
            mask = kinds == k
            row[f"rate_{k}"] = float(hit[mask].mean()) if mask.any() else 0.0
        row["precision"] = float(y[hit].mean()) if hit.any() else None
        per_rule[r.rule_id] = row

    focus = np.isin(kinds, ["phishing", "fraud", "ham"])
    res = {
        "n_test": int(len(te)),
        "score_auc_all": float(roc_auc_score(y, score)),
        "score_auc_focus": float(roc_auc_score(y[focus], score[focus])),
        "at_threshold": {str(t): metrics(y, score, t) for t in (10, 20, 30, 50)},
        "zero_score_rate": {k: float((score[kinds == k] == 0).mean()) for k in ("ham", "spam", "phishing", "fraud")},
        "per_rule": per_rule,
    }
    out = Path("ml/reports")
    save_json(res, out / "rules_metrics.json")

    L = ["# 规则引擎在公开数据集测试集上的表现", "",
         f"测试集 {res['n_test']} 封。规则分的 ROC-AUC：全量 {res['score_auc_all']:.4f}，钓鱼专项 {res['score_auc_focus']:.4f}。", "",
         "公开数据集没有完整邮件头、HTML 和附件，认证类、链接显示文本类、附件类规则在这里基本不触发。", "",
         "## 各规则命中率", "",
         "| 规则 | 权重 | 正常邮件 | 垃圾 | 钓鱼 | 诈骗 | 命中邮件中恶意比例 |", "|---|---|---|---|---|---|---|"]
    for rid, r in sorted(per_rule.items(), key=lambda kv: -kv[1]["hits"]):
        if r["hits"] == 0:
            continue
        p = "—" if r["precision"] is None else f"{r['precision']:.3f}"
        L.append(f"| {r['name']}（{rid}） | {r['weight']} | {r['rate_ham']:.3%} | {r['rate_spam']:.3%} | {r['rate_phishing']:.3%} | {r['rate_fraud']:.3%} | {p} |")
    silent = [f"{r['name']}" for r in per_rule.values() if r["hits"] == 0]
    L += ["", f"未触发的规则（{len(silent)} 条）：{'、'.join(silent)}", "",
          "## 规则分单独作为分类器", "", "| 阈值 | 精确率 | 召回率 | F1 | 误报率 |", "|---|---|---|---|---|"]
    for t, m in res["at_threshold"].items():
        L.append(f"| ≥{t} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['fpr']:.4f} |")
    z = res["zero_score_rate"]
    L += ["", f"规则分为 0 的比例：正常 {z['ham']:.1%}、垃圾 {z['spam']:.1%}、钓鱼 {z['phishing']:.1%}、诈骗 {z['fraud']:.1%}。", ""]
    (out / "rules.md").write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
