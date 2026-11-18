"""实验 9：大模型改写的鲁棒性与增强训练。

对比每组邮件改写前后：钓鱼组看召回率下降多少，正常组看误报率是否上升
（检验模型会不会把"大模型写作风格"本身当成可疑）。阈值统一使用训练时在验证集上选出的阈值。

  python ml/scripts/exp_rewrite.py --build-aug   # 用训练组改写样本生成 emails_mixed3.csv（增强训练数据）
  python ml/scripts/exp_rewrite.py               # 评估所有可用模型，输出 ml/reports/rewrite.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from common import save_json  # noqa: E402
from llm_rewrite import OUT, build_plan  # noqa: E402
from phishguard_detector import parse_text  # noqa: E402
from phishguard_detector.engine import BaselineModel  # noqa: E402
from phishguard_detector.fusion import combine  # noqa: E402
from phishguard_detector.rules import evaluate  # noqa: E402

ART = Path("ml/artifacts")
GROUPS = [("test_en_phish", "英文钓鱼", 1), ("test_zh_phish", "中文钓鱼（手写）", 1), ("test_en_ham", "英文正常", 0), ("test_zh_ham", "中文正常（手写）", 0)]
MODELS = [
    ("tfidf_v2", "TF-IDF v2", "tfidf", ART / "baseline_tfidf_phish_mixed2.joblib", None),
    ("bert_v2", "DistilBERT v2", "bert", ART / "distilbert_phish_mixed2", "ml/reports/distilbert_phish_mixed2.json"),
    ("tfidf_v3", "TF-IDF v3（+改写增强）", "tfidf", ART / "baseline_tfidf_phish_mixed3.joblib", None),
    ("bert_v3", "DistilBERT v3（+改写增强）", "bert", ART / "distilbert_phish_mixed3", "ml/reports/distilbert_phish_mixed3.json"),
]


def rewrites() -> pd.DataFrame:
    rows = [json.loads(l) for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()]
    df = pd.DataFrame(rows)
    return df[df["status"] == "ok"].drop_duplicates("id", keep="last")


def build_aug() -> None:
    rw = rewrites()
    tr = rw[rw["group"].str.startswith("train_")].copy()
    base = pd.read_csv("ml/data/processed/emails_mixed2.csv", dtype=str, keep_default_na=False)
    add = pd.DataFrame({"id": "rw_" + tr["id"], "source": "llm_rewrite", "kind": np.where(tr["y"] == 1, "phishing", "ham"),
                        "label": tr["y"].astype(str), "split": "train", "has_header": "False", "sender": "", "date": "",
                        "n_urls": "0", "subject": tr["subject"], "body": tr["body"]})
    out = pd.concat([base, add[base.columns]], ignore_index=True)
    out.to_csv("ml/data/processed/emails_mixed3.csv", index=False, encoding="utf-8")
    print(f"增强样本 {len(add)} 封（钓鱼 {int((tr.y == 1).sum())} / 正常 {int((tr.y == 0).sum())}），合计 {len(out)} → emails_mixed3.csv")


def score(kind, path, rep, df):
    if kind == "tfidf":
        b = joblib.load(path)
        p = np.array(BaselineModel(path).predict_proba((df["subject"] + "\n" + df["body"]).tolist()))
        t = float(b["threshold_fpr1"])
        thr = t if hasattr(b["model"], "predict_proba") else 1 / (1 + np.exp(-2 * t))
    else:
        from eval_real import bert_scores

        p = bert_scores(path, df.assign(label=0))
        thr = json.load(open(rep, encoding="utf-8"))["val_threshold_fpr1"]
    return p, thr


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-aug", action="store_true")
    args = ap.parse_args()
    if args.build_aug:
        build_aug()
        return

    plan = build_plan().set_index("id")
    rw = rewrites().set_index("id")
    res: dict = {"refused": {}, "groups": {}}
    for g, label, y in GROUPS:
        ids = [i for i in plan.index[plan["group"] == g] if i in rw.index]
        total = int((plan["group"] == g).sum())
        res["refused"][g] = total - len(ids)
        orig = plan.loc[ids, ["subject", "body"]].reset_index()
        new = rw.loc[ids, ["subject", "body"]].reset_index()
        out = {"label": label, "y": y, "n": len(ids), "models": {}}

        # 规则层（无邮件头）与系统判定（校准后的 TF-IDF v2 + 规则融合，≥50 为可疑及以上）
        sysm = BaselineModel(ART / "baseline_tfidf_phish_mixed2.joblib", calibrated=True)
        for name, d in (("orig", orig), ("rewrite", new)):
            rr = [evaluate(parse_text(s, b)) for s, b in zip(d["subject"], d["body"])]
            pc = sysm.predict_proba((d["subject"] + "\n" + d["body"]).tolist())
            fused = np.array([combine(r.score, float(x), critical=r.critical) for r, x in zip(rr, pc)])
            out.setdefault("rules", {})[name] = float(np.mean([r.score >= 50 for r in rr]))
            out.setdefault("system", {})[name] = float((fused >= 0.5).mean())

        for key, mlabel, kind, path, rep in MODELS:
            if not Path(path).exists():
                continue
            po, thr = score(kind, path, rep, orig)
            pn, _ = score(kind, path, rep, new)
            out["models"][key] = {"label": mlabel, "orig": float((po >= thr).mean()), "rewrite": float((pn >= thr).mean()),
                                  "median_orig": float(np.median(po)), "median_rewrite": float(np.median(pn))}
        res["groups"][g] = out
        print(f"[{label}] n={len(ids)}  系统 {out['system']['orig']:.2f}→{out['system']['rewrite']:.2f}  " +
              "  ".join(f"{m['label']} {m['orig']:.2f}→{m['rewrite']:.2f}" for m in out["models"].values()))

    save_json(res, Path("ml/reports/rewrite_metrics.json"))
    L = ["# 实验 9：大模型改写的鲁棒性", "",
         "用 DeepSeek（deepseek-chat）把邮件改写成语气自然、像真人写的版本，保持原意、请求和链接不变。",
         "钓鱼组的数字是**召回率**（越高越好），正常组的数字是**误报率**（越低越好）。阈值为各模型在验证集上选出的阈值（误报率 ≤ 1%）。", "",
         f"被模型拒绝改写的样本：{res['refused']}", ""]
    for g, out in res["groups"].items():
        what = "召回率" if out["y"] == 1 else "误报率"
        L += [f"## {out['label']}（{out['n']} 封，{what}）", "", "| 方法 | 原始邮件 | 改写后 | 变化 |", "|---|---|---|---|"]
        for nm, key in (("规则层（≥50，无邮件头）", "rules"), ("系统判定（TF-IDF v2 校准 + 规则，≥50）", "system")):
            a, b = out[key]["orig"], out[key]["rewrite"]
            L.append(f"| {nm} | {a:.3f} | {b:.3f} | {b - a:+.3f} |")
        for m in out["models"].values():
            L.append(f"| {m['label']} | {m['orig']:.3f} | {m['rewrite']:.3f} | {m['rewrite'] - m['orig']:+.3f} |")
        L.append("")
    Path("ml/reports/rewrite.md").write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    main()
