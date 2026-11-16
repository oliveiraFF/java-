"""实验 4：未见恶意类型识别 + 规则融合。

训练时完全去掉某一类真实恶意邮件（nazario = 钓鱼，nigerian = 诈骗），
测试集 = 该来源全部邮件 + 标准测试集中的正常邮件。

公平比较：每种方法都在验证集（同样不含该来源）上选阈值，使正常邮件误报率 ≤ 1%，
再在测试集上报告召回率与误报率。这样所有方法处在同一误报水平，不受各自分数刻度影响。
同时报告 ROC-AUC（与阈值无关）。

对比：TF-IDF 基线、DistilBERT（读取 train_distilbert.py --unseen 和 predict_distilbert.py 保存的分数）、
规则层单独使用、规则 + 各模型融合（调用检测引擎的 fuse()，与线上逻辑完全一致）。

用法（仓库根目录）：python ml/scripts/exp_unseen.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.naive_bayes import MultinomialNB  # noqa: E402
from sklearn.svm import LinearSVC  # noqa: E402

from common import TARGET_FPR, fmt, load_emails, metrics, model_input, save_json, threshold_at_fpr  # noqa: E402
from phishguard_detector import parse_text  # noqa: E402
from phishguard_detector.fusion import combine  # noqa: E402
from phishguard_detector.rules import evaluate  # noqa: E402

UNSEEN = {"nazario": "钓鱼（Nazario）", "nigerian": "诈骗（Nigerian Fraud）"}
ZH = {"rules": "仅规则", "naive_bayes": "朴素贝叶斯", "logistic_regression": "逻辑回归", "linear_svm": "线性 SVM", "distilbert": "DistilBERT"}
REP = Path("ml/reports")
SCORES = Path("ml/artifacts/scores")


def prob(model, X) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return 1.0 / (1.0 + np.exp(-2.0 * model.decision_function(X)))  # 与 engine.BaselineModel 一致


def rules_of(df: pd.DataFrame):
    return [evaluate(parse_text(s, b, snd)) for s, b, snd in zip(df["subject"], df["body"], df["sender"])]


def fused(rule_results, p) -> np.ndarray:
    # 用连续融合值评估（不取整），见 fusion.combine 的说明
    return np.array([combine(r.score, float(pi), critical=r.critical) for r, pi in zip(rule_results, p)], dtype=float)


def platt(p_val: np.ndarray, y_val: np.ndarray):
    """Platt 校准：在验证集上用逻辑回归把模型分数映射成校准后的概率。

    noisy-OR 融合假设输入是校准过的概率；DistilBERT 的原始输出高度饱和
    （正常邮件大量 0.001），直接融合时规则层的微弱信号会被放大。
    """
    eps = 1e-6
    to_logit = lambda p: np.log(np.clip(p, eps, 1 - eps) / (1 - np.clip(p, eps, 1 - eps)))  # noqa: E731
    lr = LogisticRegression(C=1e6, max_iter=1000).fit(to_logit(p_val).reshape(-1, 1), y_val)
    return lambda p: lr.predict_proba(to_logit(p).reshape(-1, 1))[:, 1]


def evaluate_method(y_val, s_val, y_te, s_te) -> dict:
    thr = threshold_at_fpr(y_val, s_val, TARGET_FPR)
    m = metrics(y_te, s_te, thr)
    return {"threshold": thr, "recall_unseen": m["recall"], "fpr_ham": m["fpr"], "precision": m["precision"],
            "f1": m["f1"], "roc_auc": m["roc_auc"]}


def load_scores(path: Path, ids: pd.Series) -> np.ndarray | None:
    if not path.exists():
        return None
    s = pd.read_csv(path).set_index("id")["score"]
    out = ids.map(s).to_numpy(dtype=float)
    if np.isnan(out).any():
        raise ValueError(f"{path} 的 id 与数据不对应")
    return out


def run(df: pd.DataFrame, src: str) -> dict:
    tr = df[(df["split"] == "train") & (df["source"] != src)]
    va = df[(df["split"] == "val") & (df["source"] != src)].reset_index(drop=True)
    te = pd.concat([df[df["source"] == src], df[(df["split"] == "test") & (df["label"] == 0)]]).reset_index(drop=True)
    yv, yt = va["label"].to_numpy(), te["label"].to_numpy()
    print(f"[{src}] 训练 {len(tr)} / 验证 {len(va)} / 测试 {len(te)}（未见恶意 {int(yt.sum())} + 正常 {int((yt == 0).sum())}）")

    vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=3, max_df=0.9, max_features=100_000,
                          sublinear_tf=True, strip_accents="unicode", token_pattern=r"(?u)\b\w\w+\b", dtype=np.float32)
    Xtr = vec.fit_transform(model_input(tr))
    Xv, Xt = vec.transform(model_input(va)), vec.transform(model_input(te))
    probs: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    for name, m in {"naive_bayes": MultinomialNB(alpha=0.1),
                    "logistic_regression": LogisticRegression(C=8.0, max_iter=2000, solver="liblinear"),
                    "linear_svm": LinearSVC(C=0.5)}.items():
        m.fit(Xtr, tr["label"].to_numpy())
        probs[name] = (prob(m, Xv), prob(m, Xt))

    bv = load_scores(SCORES / f"distilbert_unseen_{src}_val.csv", va["id"])
    bt = load_scores(SCORES / f"distilbert_unseen_{src}.csv", te["id"])
    if bv is not None and bt is not None:
        probs["distilbert"] = (bv, bt)
    else:
        print("  （缺少 DistilBERT 分数文件，跳过 DistilBERT）")

    t = time.perf_counter()
    rv, rt = rules_of(va), rules_of(te)
    print(f"  规则引擎 {len(va) + len(te)} 封用时 {time.perf_counter() - t:.1f}s")

    out: dict = {"n_unseen": int(yt.sum()), "n_ham": int((yt == 0).sum()), "methods": {}}
    out["methods"]["rules"] = evaluate_method(yv, np.array([r.score for r in rv]) / 100, yt, np.array([r.score for r in rt]) / 100)
    for name, (pv, pt) in probs.items():
        out["methods"][name] = evaluate_method(yv, pv, yt, pt)
        out["methods"][f"fusion_{name}"] = evaluate_method(yv, fused(rv, pv), yt, fused(rt, pt))
        cal = platt(pv, yv)
        out["methods"][f"fusioncal_{name}"] = evaluate_method(yv, fused(rv, cal(pv)), yt, fused(rt, cal(pt)))
        a, f, c = out["methods"][name], out["methods"][f"fusion_{name}"], out["methods"][f"fusioncal_{name}"]
        print(f"  {name:<20} 模型 召回={a['recall_unseen']:.4f} 误报={a['fpr_ham']:.4f} | "
              f"融合 召回={f['recall_unseen']:.4f} | 校准后融合 召回={c['recall_unseen']:.4f} 误报={c['fpr_ham']:.4f} AUC={fmt(c['roc_auc'])}")
    return out


def write_report(res: dict) -> None:
    L = ["# 实验 4：未见恶意类型识别与规则融合", "",
         "训练时去掉某一类真实恶意邮件，测试该类邮件能被识别出多少（召回率）。",
         "每种方法都在验证集上选阈值使误报率 ≤ 1%，再在测试集上评估，所有方法处于同一误报水平。", ""]
    for src, r in res.items():
        L += [f"## 留出 {UNSEEN[src]}：未见恶意 {r['n_unseen']} 封，正常 {r['n_ham']} 封", "",
              "| 方法 | 未见恶意召回率 | 测试集误报率 | 精确率 | F1 | ROC-AUC |", "|---|---|---|---|---|---|"]
        for key, m in r["methods"].items():
            if key.startswith("fusioncal_"):
                label = f"规则 + {ZH[key[10:]]}（Platt 校准后融合）"
            elif key.startswith("fusion_"):
                label = f"规则 + {ZH[key[7:]]}（直接融合）"
            else:
                label = ZH[key]
            L.append(f"| {label} | {m['recall_unseen']:.4f} | {m['fpr_ham']:.4f} | {m['precision']:.4f} | {m['f1']:.4f} | {fmt(m['roc_auc'])} |")
        L.append("")
    (REP / "unseen.md").write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))


def main() -> None:
    df = load_emails()
    res = {src: run(df, src) for src in UNSEEN}
    save_json(res, REP / "unseen_metrics.json")
    write_report(res)


if __name__ == "__main__":
    main()
